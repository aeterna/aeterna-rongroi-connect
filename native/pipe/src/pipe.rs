// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The named-pipe server used between Connect and the scanner sidecar.
//!
//! Everything in this module is plain Rust. `lib.rs` adds only the thin N-API
//! wrappers, so the tests do not need Node or a JavaScript runtime.
//!
//! The ADR fixes the shape of a pipe name:
//! `\\.\pipe\rongroi-<32 lowercase hex>`.  This module deliberately avoids a
//! regular-expression crate: the form is small enough to check by hand, and
//! the native crate should stay free of network and parsing dependencies.

use std::fmt;

/// The fixed start of every Connect pipe name.
pub const PIPE_PREFIX: &str = r"\\.\pipe\rongroi-";

/// A short, stable error code for the JavaScript layer.
///
/// `Failed` holds an HRESULT.  Its text is always `failed:<eight hex digits>`,
/// never a free-form Windows message, so callers can branch on it safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeError {
    Unsupported,
    Exists,
    Denied,
    Timeout,
    TooLarge,
    Closed,
    BadName,
    BadHandle,
    Failed(u32),
}

impl PipeError {
    /// The short code exposed to callers.
    pub fn code(&self) -> String {
        match self {
            Self::Unsupported => "unsupported".to_owned(),
            Self::Exists => "exists".to_owned(),
            Self::Denied => "denied".to_owned(),
            Self::Timeout => "timeout".to_owned(),
            Self::TooLarge => "too_large".to_owned(),
            Self::Closed => "closed".to_owned(),
            Self::BadName => "bad_name".to_owned(),
            Self::BadHandle => "bad_handle".to_owned(),
            Self::Failed(hresult) => format!("failed:{hresult:08x}"),
        }
    }
}

impl fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.code())
    }
}

impl std::error::Error for PipeError {}

/// Build `\\.\pipe\rongroi-<32 lowercase hex>` from exactly 16 bytes.
pub fn pipe_name(random_16_bytes: &[u8]) -> Result<String, PipeError> {
    if random_16_bytes.len() != 16 {
        return Err(PipeError::BadName);
    }

    let mut name = String::with_capacity(PIPE_PREFIX.len() + 32);
    name.push_str(PIPE_PREFIX);
    for byte in random_16_bytes {
        // Inline hex avoids a dependency just for formatting.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let byte = *byte;
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(name)
}

/// Check the exact form required by ADR 0001 section 4.
///
/// This rejects a UNC path to another machine, uppercase hex, the wrong
/// length, and any trailing text.
pub fn is_valid_name(name: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let Some(suffix) = name.strip_prefix(PIPE_PREFIX) else {
        return false;
    };
    if suffix.len() != 32 {
        return false;
    }
    suffix.bytes().all(|byte| HEX.contains(&byte))
}

/// Build the DACL text: the current user and the Administrators group may use
/// the pipe fully; no other access is granted.
///
/// Keeping this a pure function makes the exact SDDL testable on every
/// platform, where the real descriptor cannot be created.
pub fn sddl_for_user(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;{user_sid})(A;;GA;;;BA)")
}

#[cfg(windows)]
mod platform {
    use super::{is_valid_name, sddl_for_user, PipeError};

    use std::collections::HashMap;
    use std::mem::size_of;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant};

    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
        ERROR_INVALID_DATA, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::{
        ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        PIPE_ACCESS_DUPLEX,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
        WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    // A `HANDLE` wraps a raw pointer and is therefore not `Send`, so it cannot
    // live in the process-wide registry.  The registry stores only the opaque
    // kernel handle value; a `HANDLE` is rebuilt for the duration of one call.
    //
    // `active` counts calls that copied the value out and are still using it.
    // `close` marks `closed` and cancels pending work, but the handle itself is
    // closed by whichever side finishes last: `close` when no call is active,
    // or the last active call when it releases.  Windows may reuse a handle
    // value as soon as `CloseHandle` returns, so a late call must never receive
    // a value that has already been closed.
    struct HandleState {
        handle: Mutex<Option<isize>>,
        closed: AtomicBool,
        active: AtomicUsize,
    }

    type HandleEntry = Arc<HandleState>;

    fn registry() -> &'static Mutex<HashMap<u32, HandleEntry>> {
        static REGISTRY: OnceLock<Mutex<HashMap<u32, HandleEntry>>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn next_id() -> u32 {
        static NEXT_ID: AtomicU32 = AtomicU32::new(1);
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        // A panic while an operation is in flight must not turn every later
        // call into a panic as well.  The handle entry stays consistent.
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn entry_for(id: u32) -> Result<HandleEntry, PipeError> {
        lock(registry())
            .get(&id)
            .cloned()
            .ok_or(PipeError::BadHandle)
    }

    /// One call's claim on a handle value.
    ///
    /// The value is copied out while the entry mutex is held, then the mutex is
    /// released for the rest of the wait.  Keeping the lease alive prevents
    /// `close` from calling `CloseHandle` under the running call.
    struct HandleLease {
        entry: HandleEntry,
        handle: HANDLE,
    }

    impl HandleLease {
        fn acquire(entry: HandleEntry) -> Result<Self, PipeError> {
            // The same mutex guards the handle slot and the transition to
            // closed.  Checking and incrementing `active` under it means close
            // cannot decide that no call is using the handle in between.
            let value = {
                let guard = lock(&entry.handle);
                if entry.closed.load(Ordering::SeqCst) {
                    return Err(PipeError::Closed);
                }
                let value = (*guard).ok_or(PipeError::Closed)?;
                entry.active.fetch_add(1, Ordering::SeqCst);
                value
            };
            Ok(Self {
                entry,
                handle: HANDLE(value as *mut core::ffi::c_void),
            })
        }

        fn is_closed(&self) -> bool {
            self.entry.closed.load(Ordering::SeqCst)
        }
    }

    impl Drop for HandleLease {
        fn drop(&mut self) {
            if self.entry.active.fetch_sub(1, Ordering::SeqCst) == 1 {
                // This is the last call using the handle.  If close already
                // requested cancellation, it left the actual CloseHandle to us.
                if self.entry.closed.load(Ordering::SeqCst) {
                    let mut guard = lock(&self.entry.handle);
                    if let Some(value) = guard.take() {
                        // SAFETY: the slot still owned a live handle and this
                        // lease is the last user, so this is the only close.
                        unsafe {
                            let _ = CloseHandle(HANDLE(value as *mut core::ffi::c_void));
                        }
                    }
                }
            }
        }
    }

    fn hresult_from_win32(code: u32) -> u32 {
        (code & 0x0000_ffff) | 0x8007_0000
    }

    fn win32_code(error: &windows::core::Error) -> Option<u32> {
        let hresult = error.code().0 as u32;
        if hresult & 0xffff_0000 == 0x8007_0000 {
            Some(hresult & 0x0000_ffff)
        } else {
            None
        }
    }

    fn is_closed_code(error: &windows::core::Error) -> bool {
        matches!(
            win32_code(error),
            Some(code)
                if code == ERROR_BROKEN_PIPE.0
                    || code == ERROR_NO_DATA.0
                    || code == ERROR_PIPE_NOT_CONNECTED.0
                    || code == ERROR_OPERATION_ABORTED.0
        )
    }

    fn map_error(error: windows::core::Error) -> PipeError {
        match win32_code(&error) {
            Some(code) if code == ERROR_ACCESS_DENIED.0 => PipeError::Denied,
            Some(code)
                if code == ERROR_BROKEN_PIPE.0
                    || code == ERROR_NO_DATA.0
                    || code == ERROR_PIPE_NOT_CONNECTED.0
                    || code == ERROR_OPERATION_ABORTED.0 =>
            {
                PipeError::Closed
            }
            _ => PipeError::Failed(error.code().0 as u32),
        }
    }

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: this guard owns a live handle and is dropped exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct LocalFreeGuard(*mut core::ffi::c_void);

    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            // SAFETY: the pointer came from an API that allocates with LocalAlloc
            // and is freed here once, on every return path.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }

    fn current_user_sid() -> Result<String, PipeError> {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that must not be
        // closed; OpenProcessToken writes a real token handle into `token`.
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(map_error)?;
        }
        let _token = HandleGuard(token);

        let mut needed = 0u32;
        // SAFETY: a null buffer with length zero is the documented way to ask
        // for the required size.  ERROR_INSUFFICIENT_BUFFER is expected here.
        let first = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        if needed == 0 {
            return Err(match first {
                Err(error) => map_error(error),
                Ok(()) => PipeError::Failed(hresult_from_win32(ERROR_INVALID_DATA.0)),
            });
        }

        // TOKEN_USER and SID_AND_ATTRIBUTES contain pointers, so the buffer must
        // be pointer-aligned.  A Vec<u64> gives at least that alignment.
        let words = (needed as usize).div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; words];
        // SAFETY: the buffer is at least `needed` bytes and suitably aligned.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
            .map_err(map_error)?;

            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut sid_string = PWSTR::null();
            ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string).map_err(map_error)?;
            let _sid = LocalFreeGuard(sid_string.0.cast());

            sid_string
                .to_string()
                .map_err(|_| PipeError::Failed(hresult_from_win32(ERROR_INVALID_DATA.0)))
        }
    }

    fn create_event() -> Result<HANDLE, PipeError> {
        // SAFETY: the arguments request an auto-reset, non-signalled, unnamed
        // event.  An auto-reset event is enough because each operation waits
        // exactly once.  `Default::default()` works for the bool parameter
        // and expresses false in this windows-rs binding.
        unsafe {
            CreateEventW(None, Default::default(), Default::default(), PCWSTR::null())
                .map_err(map_error)
        }
    }

    fn wait_timeout_ms(deadline: Instant, timeout_ms: u32) -> u32 {
        if timeout_ms == 0 {
            return 0;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        remaining.as_millis().min(u32::MAX as u128) as u32
    }

    /// Cancel a pending overlapped operation and wait until the kernel has
    /// finished with the `OVERLAPPED`, its event and its buffer.
    ///
    /// `GetOverlappedResult(..., true)` is required here: after
    /// `ERROR_IO_PENDING` the stack objects must not be freed while the I/O
    /// manager could still write to them.
    fn cancel_pending(handle: HANDLE, overlapped: &OVERLAPPED) {
        // SAFETY: `handle` and `overlapped` are the same pair passed to the
        // pending operation and both stay alive until the wait returns.
        unsafe {
            let _ = CancelIoEx(handle, Some(overlapped));
            let mut transferred = 0u32;
            let _ = GetOverlappedResult(handle, overlapped, &mut transferred, true);
        }
    }

    enum PendingOutcome {
        Completed(u32),
        Timeout,
        WaitFailed(u32),
        Io(windows::core::Error),
    }

    /// Wait for an operation that returned `ERROR_IO_PENDING`.
    ///
    /// Every path that is not a completed operation cancels the I/O and waits
    /// for it to be reaped, so the caller's stack `OVERLAPPED`, event and
    /// buffer are safe to drop no matter why the wait ended.
    fn wait_pending(
        handle: HANDLE,
        overlapped: &OVERLAPPED,
        event: HANDLE,
        timeout_ms: u32,
    ) -> PendingOutcome {
        // SAFETY: `event` belongs to `overlapped`.
        let wait = unsafe { WaitForSingleObject(event, timeout_ms) };
        if wait == WAIT_OBJECT_0 {
            let mut transferred = 0u32;
            // SAFETY: the event is signalled, so the operation has completed.
            // Waiting is harmless here and reaps the completion.
            return match unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, true) }
            {
                Ok(()) => PendingOutcome::Completed(transferred),
                Err(error) => PendingOutcome::Io(error),
            };
        }

        // Capture the wait error before cancelling, because the cleanup calls
        // may overwrite the thread's last-error value.
        let wait_error = if wait == WAIT_TIMEOUT {
            None
        } else {
            // SAFETY: reading the thread's last error has no preconditions.
            Some(unsafe { GetLastError() }.0)
        };

        cancel_pending(handle, overlapped);

        match wait_error {
            Some(code) => PendingOutcome::WaitFailed(code),
            None => PendingOutcome::Timeout,
        }
    }

    pub fn create(name: &str) -> Result<u32, PipeError> {
        if !is_valid_name(name) {
            return Err(PipeError::BadName);
        }

        let sid = current_user_sid()?;
        let sddl = HSTRING::from(sddl_for_user(&sid));

        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut descriptor_size = 0u32;
        // SAFETY: `sddl` is a valid NUL-terminated HSTRING and the two out
        // parameters are valid for the duration of the call.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                Some(&mut descriptor_size),
            )
            .map_err(|_| PipeError::Denied)?;
        }
        // SAFETY: `PSECURITY_DESCRIPTOR` is a transparent pointer wrapper (or a
        // raw-pointer alias), so this preserves the allocation that
        // `LocalFreeGuard` must release.
        #[allow(clippy::useless_transmute, clippy::transmute_ptr_to_ptr)]
        let descriptor_raw: *mut core::ffi::c_void = unsafe { core::mem::transmute(descriptor) };
        let _descriptor = LocalFreeGuard(descriptor_raw);

        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: Default::default(),
        };

        let name = HSTRING::from(name);
        // SAFETY: all arguments are valid for the call.  The descriptor stays
        // alive until CreateNamedPipeW has copied it.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                Some(&attributes),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: reading the thread's last error has no preconditions.
            let code = unsafe { GetLastError() }.0;
            return Err(if code == ERROR_ACCESS_DENIED.0 {
                // FILE_FLAG_FIRST_PIPE_INSTANCE reports an existing instance
                // this way.
                PipeError::Exists
            } else {
                PipeError::Failed(hresult_from_win32(code))
            });
        }

        let id = next_id();
        lock(registry()).insert(
            id,
            Arc::new(HandleState {
                handle: Mutex::new(Some(handle.0 as isize)),
                closed: AtomicBool::new(false),
                active: AtomicUsize::new(0),
            }),
        );
        Ok(id)
    }

    pub fn accept(id: u32, timeout_ms: u32) -> Result<(), PipeError> {
        let lease = HandleLease::acquire(entry_for(id)?)?;
        let handle = lease.handle;

        let event = create_event()?;
        let _event = HandleGuard(event);
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };

        // SAFETY: `handle` is an overlapped named-pipe instance and
        // `overlapped` outlives the call and any wait.
        let result = unsafe { ConnectNamedPipe(handle, Some(&mut overlapped)) };
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let code = win32_code(&error);
                if code == Some(ERROR_PIPE_CONNECTED.0) {
                    return Ok(());
                }
                if code != Some(ERROR_IO_PENDING.0) {
                    if lease.is_closed() {
                        return Err(PipeError::Closed);
                    }
                    return Err(map_error(error));
                }

                // close may have cancelled before ConnectNamedPipe queued its
                // I/O, in which case that CancelIoEx could not see it yet.
                if lease.is_closed() {
                    cancel_pending(handle, &overlapped);
                    return Err(PipeError::Closed);
                }

                let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
                match wait_pending(
                    handle,
                    &overlapped,
                    event,
                    wait_timeout_ms(deadline, timeout_ms),
                ) {
                    PendingOutcome::Completed(_) => Ok(()),
                    PendingOutcome::Io(error) => {
                        if lease.is_closed() {
                            Err(PipeError::Closed)
                        } else if win32_code(&error) == Some(ERROR_PIPE_CONNECTED.0) {
                            Ok(())
                        } else {
                            Err(map_error(error))
                        }
                    }
                    PendingOutcome::Timeout => Err(PipeError::Timeout),
                    PendingOutcome::WaitFailed(code) => {
                        Err(PipeError::Failed(hresult_from_win32(code)))
                    }
                }
            }
        }
    }

    pub fn client_image(id: u32) -> Result<Option<String>, PipeError> {
        let lease = HandleLease::acquire(entry_for(id)?)?;
        let handle = lease.handle;

        let mut process_id = 0u32;
        // SAFETY: `handle` is a connected server-side pipe and `process_id` is
        // a valid out pointer.
        if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) }.is_err()
            || process_id == 0
        {
            return Ok(None);
        }

        // SAFETY: opening for a limited query never grants write access.
        let process = match unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                Default::default(),
                process_id,
            )
        } {
            Ok(process) => process,
            Err(_) => return Ok(None),
        };
        let _process = HandleGuard(process);

        // The API takes a size in UTF-16 code units and writes back the number
        // used, excluding the terminating NUL.
        let mut buffer = vec![0u16; 32 * 1024];
        let mut size = buffer.len() as u32;
        // SAFETY: the buffer is valid for `size` UTF-16 units.
        let result = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };
        if result.is_err() || size == 0 {
            // Whether a medium-integrity server can read an elevated client's
            // image is unverified, so a failure is not an error.
            return Ok(None);
        }

        Ok(Some(String::from_utf16_lossy(&buffer[..size as usize])))
    }

    fn write_all(lease: &HandleLease, data: &[u8], timeout_ms: u32) -> Result<(), PipeError> {
        let handle = lease.handle;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let mut written_total = 0usize;

        while written_total < data.len() {
            if lease.is_closed() {
                return Err(PipeError::Closed);
            }

            let event = create_event()?;
            let _event = HandleGuard(event);
            let mut overlapped = OVERLAPPED {
                hEvent: event,
                ..Default::default()
            };

            let chunk = &data[written_total..];
            let length = chunk.len().min(u32::MAX as usize) as u32;
            let mut written = 0u32;
            // SAFETY: the buffer, length and overlapped structure are valid
            // for the duration of the operation and its wait.
            let result = unsafe {
                WriteFile(
                    handle,
                    Some(&chunk[..length as usize]),
                    Some(&mut written),
                    Some(&mut overlapped),
                )
            };

            let this_time = match result {
                Ok(()) => written as usize,
                Err(error) => {
                    if win32_code(&error) != Some(ERROR_IO_PENDING.0) {
                        if lease.is_closed() {
                            return Err(PipeError::Closed);
                        }
                        return Err(map_error(error));
                    }

                    // close may have cancelled before WriteFile queued its I/O.
                    if lease.is_closed() {
                        cancel_pending(handle, &overlapped);
                        return Err(PipeError::Closed);
                    }

                    match wait_pending(
                        handle,
                        &overlapped,
                        event,
                        wait_timeout_ms(deadline, timeout_ms),
                    ) {
                        PendingOutcome::Completed(transferred) => transferred as usize,
                        PendingOutcome::Io(error) => {
                            if lease.is_closed() {
                                return Err(PipeError::Closed);
                            }
                            return Err(map_error(error));
                        }
                        PendingOutcome::Timeout => return Err(PipeError::Timeout),
                        PendingOutcome::WaitFailed(code) => {
                            return Err(PipeError::Failed(hresult_from_win32(code)));
                        }
                    }
                }
            };

            if this_time == 0 {
                return Err(PipeError::Closed);
            }
            written_total += this_time;
        }

        Ok(())
    }

    pub fn write_line(id: u32, text: &str, timeout_ms: u32) -> Result<(), PipeError> {
        let lease = HandleLease::acquire(entry_for(id)?)?;

        let mut line = Vec::with_capacity(text.len() + 1);
        line.extend_from_slice(text.as_bytes());
        line.push(b'\n');
        write_all(&lease, &line, timeout_ms)
    }

    pub fn read_until_close(
        id: u32,
        max_bytes: u32,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, PipeError> {
        let lease = HandleLease::acquire(entry_for(id)?)?;
        let handle = lease.handle;

        let maximum = max_bytes as usize;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let mut collected: Vec<u8> = Vec::new();

        loop {
            if lease.is_closed() {
                return Err(PipeError::Closed);
            }

            let room = maximum.saturating_sub(collected.len());
            // One byte over the cap is enough to notice a too-large record
            // without ever accumulating more than the caller allowed.
            let chunk_size = (room + 1).clamp(1, 64 * 1024);
            let mut buffer = vec![0u8; chunk_size];

            let event = create_event()?;
            let _event = HandleGuard(event);
            let mut overlapped = OVERLAPPED {
                hEvent: event,
                ..Default::default()
            };

            let mut read = 0u32;
            // SAFETY: the buffer and overlapped structure are valid for the
            // duration of the operation and its wait.
            let result = unsafe {
                ReadFile(
                    handle,
                    Some(buffer.as_mut_slice()),
                    Some(&mut read),
                    Some(&mut overlapped),
                )
            };

            let this_time = match result {
                Ok(()) => read as usize,
                Err(error) => {
                    if win32_code(&error) != Some(ERROR_IO_PENDING.0) {
                        if lease.is_closed() {
                            return Err(PipeError::Closed);
                        }
                        if is_closed_code(&error) {
                            break;
                        }
                        return Err(map_error(error));
                    }

                    // close may have cancelled before ReadFile queued its I/O.
                    if lease.is_closed() {
                        cancel_pending(handle, &overlapped);
                        return Err(PipeError::Closed);
                    }

                    match wait_pending(
                        handle,
                        &overlapped,
                        event,
                        wait_timeout_ms(deadline, timeout_ms),
                    ) {
                        PendingOutcome::Completed(transferred) => transferred as usize,
                        PendingOutcome::Io(error) => {
                            if lease.is_closed() {
                                return Err(PipeError::Closed);
                            }
                            if is_closed_code(&error) {
                                break;
                            }
                            return Err(map_error(error));
                        }
                        PendingOutcome::Timeout => return Err(PipeError::Timeout),
                        PendingOutcome::WaitFailed(code) => {
                            return Err(PipeError::Failed(hresult_from_win32(code)));
                        }
                    }
                }
            };

            if this_time == 0 {
                if lease.is_closed() {
                    return Err(PipeError::Closed);
                }
                break;
            }
            if this_time > room {
                return Err(PipeError::TooLarge);
            }
            collected.extend_from_slice(&buffer[..this_time]);
        }

        Ok(collected)
    }

    pub fn close(id: u32) -> Result<(), PipeError> {
        let entry = entry_for(id)?;
        // The mutex is held only for this state transition.  Waiting calls no
        // longer hold it, so the cancel below never waits for their timeout.
        let mut guard = lock(&entry.handle);
        if entry.closed.swap(true, Ordering::SeqCst) {
            // Already closed; a second close is harmless.
            return Ok(());
        }

        let Some(value) = *guard else {
            return Ok(());
        };
        let handle = HANDLE(value as *mut core::ffi::c_void);

        // Wake every call that is waiting on this handle.  A call that has not
        // queued its I/O yet notices `closed` after the call and cancels
        // itself before waiting.
        // SAFETY: `active` leases keep the handle value alive, so it cannot
        // have been closed or reused underneath this call.
        unsafe {
            let _ = CancelIoEx(handle, None);
        }

        if entry.active.load(Ordering::SeqCst) == 0 {
            // No call can acquire the handle now: acquisition checks `closed`
            // under this same mutex.  Close it here and clear the slot so a
            // later call can never see the reused value.
            let _ = guard.take();
            // SAFETY: this is the only remaining owner of the handle.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
        // Otherwise the last active lease closes it when it releases.

        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::PipeError;

    pub fn create(_name: &str) -> Result<u32, PipeError> {
        Err(PipeError::Unsupported)
    }

    pub fn accept(_id: u32, _timeout_ms: u32) -> Result<(), PipeError> {
        Err(PipeError::Unsupported)
    }

    pub fn client_image(_id: u32) -> Result<Option<String>, PipeError> {
        Err(PipeError::Unsupported)
    }

    pub fn write_line(_id: u32, _text: &str, _timeout_ms: u32) -> Result<(), PipeError> {
        Err(PipeError::Unsupported)
    }

    pub fn read_until_close(
        _id: u32,
        _max_bytes: u32,
        _timeout_ms: u32,
    ) -> Result<Vec<u8>, PipeError> {
        Err(PipeError::Unsupported)
    }

    pub fn close(_id: u32) -> Result<(), PipeError> {
        Err(PipeError::Unsupported)
    }
}

pub use platform::{accept, client_image, close, create, read_until_close, write_line};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_uses_every_byte_as_lowercase_hex() {
        let bytes: Vec<u8> = (0u8..16).collect();
        assert_eq!(
            pipe_name(&bytes).expect("16 bytes are enough"),
            r"\\.\pipe\rongroi-000102030405060708090a0b0c0d0e0f"
        );

        let filled = [0xabu8; 16];
        assert_eq!(
            pipe_name(&filled).expect("16 bytes are enough"),
            r"\\.\pipe\rongroi-abababababababababababababababab"
        );
    }

    #[test]
    fn pipe_name_refuses_any_other_length() {
        assert_eq!(pipe_name(&[]).unwrap_err(), PipeError::BadName);
        assert_eq!(pipe_name(&[0u8; 15]).unwrap_err(), PipeError::BadName);
        assert_eq!(pipe_name(&[0u8; 17]).unwrap_err(), PipeError::BadName);
    }

    #[test]
    fn generated_name_always_validates() {
        let name = pipe_name(&[0x5au8; 16]).unwrap();
        assert!(is_valid_name(&name));
    }

    #[test]
    fn valid_name_is_exactly_the_adr_form() {
        assert!(is_valid_name(
            r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef"
        ));
        assert!(is_valid_name(
            r"\\.\pipe\rongroi-00000000000000000000000000000000"
        ));
    }

    #[test]
    fn invalid_name_rejects_other_machines_and_spelling_variants() {
        let valid = r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef";

        // A UNC path to another machine.
        assert!(!is_valid_name(
            r"\\server\pipe\rongroi-0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_valid_name(
            r"\\?\pipe\rongroi-0123456789abcdef0123456789abcdef"
        ));
        // Uppercase hex.
        assert!(!is_valid_name(
            r"\\.\pipe\rongroi-0123456789ABCDEF0123456789abcdef"
        ));
        // Wrong length.
        assert!(!is_valid_name(
            r"\\.\pipe\rongroi-0123456789abcdef0123456789abcde"
        ));
        assert!(!is_valid_name(
            r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdef0"
        ));
        // Trailing text.
        assert!(!is_valid_name(&format!("{valid}x")));
        // Non-hex character.
        assert!(!is_valid_name(
            r"\\.\pipe\rongroi-0123456789abcdef0123456789abcdeg"
        ));
    }

    #[test]
    fn sddl_names_the_user_and_administrators_only() {
        assert_eq!(
            sddl_for_user("S-1-5-21-1-2-3-1001"),
            "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)(A;;GA;;;BA)"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn every_platform_call_is_unsupported_off_windows() {
        let name = pipe_name(&[0u8; 16]).expect("16 bytes are enough");
        assert_eq!(create(&name), Err(PipeError::Unsupported));
        assert_eq!(accept(1, 1), Err(PipeError::Unsupported));
        assert_eq!(client_image(1), Err(PipeError::Unsupported));
        assert_eq!(write_line(1, "x", 1), Err(PipeError::Unsupported));
        assert_eq!(read_until_close(1, 1, 1), Err(PipeError::Unsupported));
        assert_eq!(close(1), Err(PipeError::Unsupported));
    }

    #[test]
    fn every_error_has_a_short_stable_code() {
        let cases = [
            (PipeError::Unsupported, "unsupported"),
            (PipeError::Exists, "exists"),
            (PipeError::Denied, "denied"),
            (PipeError::Timeout, "timeout"),
            (PipeError::TooLarge, "too_large"),
            (PipeError::Closed, "closed"),
            (PipeError::BadName, "bad_name"),
            (PipeError::BadHandle, "bad_handle"),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), code);
        }

        assert_eq!(PipeError::Failed(0x8007_0005).code(), "failed:80070005");
        assert_eq!(PipeError::Failed(0x0000_0000).code(), "failed:00000000");
    }
}
