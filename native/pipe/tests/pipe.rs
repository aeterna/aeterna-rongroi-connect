// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A real client, not a mock: it connects with CreateFileW, receives the line
//! Connect writes, sends a record and closes.  The tests also prove the single
//! instance, the `max_bytes` cap, the accept timeout and that `close` wakes a
//! blocked `accept` instead of waiting for its timeout.

#![cfg(windows)]

use std::thread;
use std::time::{Duration, Instant};

use rongroi_connect_pipe::pipe::{
    accept, client_image, close, create, is_valid_name, pipe_name, read_until_close, write_line,
    PipeError,
};

use windows::core::{Result as WindowsResult, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};

fn open_client(name: &str) -> WindowsResult<HANDLE> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated and lives until CreateFileW returns.
    unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
}

fn read_line(pipe: HANDLE) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let mut read = 0u32;
        // SAFETY: the client handle is synchronous and `byte` is valid.
        unsafe {
            ReadFile(pipe, Some(&mut byte[..]), Some(&mut read), None).expect("client read");
        }
        if read == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).expect("server wrote UTF-8")
}

fn write_bytes(pipe: HANDLE, data: &[u8]) {
    let mut written = 0u32;
    // SAFETY: `data` is valid for the duration of the synchronous write.
    unsafe {
        WriteFile(pipe, Some(data), Some(&mut written), None).expect("client write");
    }
    assert_eq!(written as usize, data.len());
}

#[test]
fn real_client_round_trip() {
    // A normal duplex exchange, plus the second client being refused.
    let name = pipe_name(&[7u8; 16]).expect("fixed random bytes");
    assert!(is_valid_name(&name));
    let handle = create(&name).expect("pipe is created");

    let client_name = name.clone();
    let client = thread::spawn(move || {
        let pipe = open_client(&client_name).expect("the client connects");
        let line = read_line(pipe);
        write_bytes(pipe, br#"{"binding":"b","policy":"p"}"#);
        // SAFETY: this thread owns the client handle.
        unsafe {
            let _ = CloseHandle(pipe);
        }
        line
    });

    accept(handle, 5_000).expect("the client is accepted");

    // The first client is still connected, so the only instance is busy and a
    // second client must not get in.
    assert!(
        open_client(&name).is_err(),
        "a second client must be refused"
    );

    // Reading the image may fail across integrity levels; it must not fail the
    // connection.
    let image = client_image(handle).expect("querying the image does not error");
    if let Some(path) = image {
        assert!(!path.is_empty());
    }

    write_line(handle, "hello sidecar", 5_000).expect("the line is written");
    let record = read_until_close(handle, 1024, 5_000).expect("the record is read");
    assert_eq!(record.as_slice(), &br#"{"binding":"b","policy":"p"}"#[..]);

    let line = client.join().expect("the client thread finishes");
    assert_eq!(line, "hello sidecar");

    close(handle).expect("the pipe closes");
    close(handle).expect("closing again is harmless");

    // A record past max_bytes is refused and nothing beyond the cap is kept.
    let large_name = pipe_name(&[8u8; 16]).expect("fixed random bytes");
    let large = create(&large_name).expect("pipe is created");
    let client_name = large_name.clone();
    let writer = thread::spawn(move || {
        let pipe = open_client(&client_name).expect("the client connects");
        write_bytes(pipe, &[b'x'; 32]);
        // SAFETY: this thread owns the client handle.
        unsafe {
            let _ = CloseHandle(pipe);
        }
    });
    accept(large, 5_000).expect("the client is accepted");
    assert_eq!(read_until_close(large, 16, 5_000), Err(PipeError::TooLarge));
    writer.join().expect("the writer thread finishes");
    close(large).expect("the pipe closes");

    // No client arrives: accept must return timeout rather than block.
    let timeout_name = pipe_name(&[9u8; 16]).expect("fixed random bytes");
    let timeout_handle = create(&timeout_name).expect("pipe is created");
    let started = Instant::now();
    assert_eq!(
        accept(timeout_handle, 100),
        Err(PipeError::Timeout),
        "an unused pipe times out"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    close(timeout_handle).expect("the pipe closes");
}

#[test]
fn close_wakes_a_blocked_accept_promptly() {
    let name = pipe_name(&[10u8; 16]).expect("fixed random bytes");
    let handle = create(&name).expect("pipe is created");

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let waiter = thread::spawn(move || {
        started_tx.send(()).expect("test thread still listening");
        accept(handle, 60_000)
    });

    started_rx.recv().expect("accept thread started");
    // Let the accept call issue ConnectNamedPipe and block on the event.
    thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    close(handle).expect("the pipe closes");
    let result = waiter.join().expect("the accept thread finishes");

    assert_eq!(
        result,
        Err(PipeError::Closed),
        "a closed pipe reports closed instead of timing out"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "close must wake accept promptly, took {:?}",
        started.elapsed()
    );

    // A call that starts after the close must not use the old handle value.
    assert_eq!(
        accept(handle, 0),
        Err(PipeError::Closed),
        "a late call reports closed"
    );
}
