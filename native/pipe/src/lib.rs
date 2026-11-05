// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! N-API wrappers for the named-pipe module.
//!
//! All real work lives in `pipe.rs`.  Blocking calls are exposed as
//! `AsyncTask`s so Node's event loop is never held while the server waits for
//! a connection or for the sidecar to finish sending its record.  There is no
//! async runtime here: napi's libuv thread pool runs the blocking function.
//!
//! The wrappers are left out of the crate's own unit-test binary.  N-API
//! symbols are supplied by the host Node process, not by a normal test
//! executable, so this keeps `cargo test` usable on a machine without Node.

pub mod pipe;

#[cfg(not(test))]
mod napi_api {
    use napi::bindgen_prelude::{AsyncTask, Buffer};
    use napi::{Env, Error, Result, Status, Task};
    use napi_derive::napi;

    use crate::pipe;

    fn to_napi_error(error: pipe::PipeError) -> Error {
        Error::new(Status::GenericFailure, error.code())
    }

    pub struct CreateTask {
        name: String,
    }

    impl Task for CreateTask {
        type Output = u32;
        type JsValue = u32;

        fn compute(&mut self) -> Result<Self::Output> {
            pipe::create(&self.name).map_err(to_napi_error)
        }

        fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
            Ok(output)
        }
    }

    pub struct AcceptTask {
        handle: u32,
        timeout_ms: u32,
    }

    impl Task for AcceptTask {
        type Output = ();
        type JsValue = ();

        fn compute(&mut self) -> Result<Self::Output> {
            pipe::accept(self.handle, self.timeout_ms).map_err(to_napi_error)
        }

        fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
            Ok(())
        }
    }

    pub struct ClientImageTask {
        handle: u32,
    }

    impl Task for ClientImageTask {
        type Output = Option<String>;
        type JsValue = Option<String>;

        fn compute(&mut self) -> Result<Self::Output> {
            pipe::client_image(self.handle).map_err(to_napi_error)
        }

        fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
            Ok(output)
        }
    }

    pub struct WriteLineTask {
        handle: u32,
        text: String,
        timeout_ms: u32,
    }

    impl Task for WriteLineTask {
        type Output = ();
        type JsValue = ();

        fn compute(&mut self) -> Result<Self::Output> {
            pipe::write_line(self.handle, &self.text, self.timeout_ms).map_err(to_napi_error)
        }

        fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
            Ok(())
        }
    }

    pub struct ReadUntilCloseTask {
        handle: u32,
        max_bytes: u32,
        timeout_ms: u32,
    }

    impl Task for ReadUntilCloseTask {
        type Output = Vec<u8>;
        type JsValue = Buffer;

        fn compute(&mut self) -> Result<Self::Output> {
            pipe::read_until_close(self.handle, self.max_bytes, self.timeout_ms)
                .map_err(to_napi_error)
        }

        fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
            Ok(Buffer::from(output))
        }
    }

    pub struct CloseTask {
        handle: u32,
    }

    impl Task for CloseTask {
        type Output = ();
        type JsValue = ();

        fn compute(&mut self) -> Result<Self::Output> {
            pipe::close(self.handle).map_err(to_napi_error)
        }

        fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
            Ok(())
        }
    }

    /// Build a pipe name from exactly 16 random bytes.
    #[napi(js_name = "pipeName")]
    pub fn pipe_name(random_16_bytes: Buffer) -> Result<String> {
        pipe::pipe_name(&random_16_bytes).map_err(to_napi_error)
    }

    /// Check the exact `\\.\pipe\rongroi-<32 lowercase hex>` form.
    #[napi(js_name = "isValidName")]
    pub fn is_valid_name(name: String) -> bool {
        pipe::is_valid_name(&name)
    }

    /// Create the single server instance and return its handle id.
    #[napi(js_name = "create")]
    pub fn create(name: String) -> AsyncTask<CreateTask> {
        AsyncTask::new(CreateTask { name })
    }

    /// Wait for the sidecar to connect, with a timeout.
    #[napi(js_name = "accept")]
    pub fn accept(handle: u32, timeout_ms: u32) -> AsyncTask<AcceptTask> {
        AsyncTask::new(AcceptTask { handle, timeout_ms })
    }

    /// Read the client's executable path, or `null` when it cannot be read.
    #[napi(js_name = "clientImage")]
    pub fn client_image(handle: u32) -> AsyncTask<ClientImageTask> {
        AsyncTask::new(ClientImageTask { handle })
    }

    /// Write one UTF-8 line, terminated by `\n`.
    #[napi(js_name = "writeLine")]
    pub fn write_line(handle: u32, text: String, timeout_ms: u32) -> AsyncTask<WriteLineTask> {
        AsyncTask::new(WriteLineTask {
            handle,
            text,
            timeout_ms,
        })
    }

    /// Read until the client closes, failing with `too_large` above `max_bytes`.
    #[napi(js_name = "readUntilClose")]
    pub fn read_until_close(
        handle: u32,
        max_bytes: u32,
        timeout_ms: u32,
    ) -> AsyncTask<ReadUntilCloseTask> {
        AsyncTask::new(ReadUntilCloseTask {
            handle,
            max_bytes,
            timeout_ms,
        })
    }

    /// Close the instance.  Closing an already closed id succeeds.
    #[napi(js_name = "close")]
    pub fn close(handle: u32) -> AsyncTask<CloseTask> {
        AsyncTask::new(CloseTask { handle })
    }
}
