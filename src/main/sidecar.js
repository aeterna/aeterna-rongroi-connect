// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const MAX_RECORD_BYTES = 2 * 1024 * 1024;

class SidecarError extends Error {
  constructor(code, message, options) {
    super(message === undefined ? code : message, options);
    this.name = 'SidecarError';
    this.code = code;
  }
}

// Lane 3c replaces this with the bundled-sidecar SHA-256 check. Keeping it a
// named hook now means the flow has one obvious place to put that check and a
// test can see that it runs before the process is spawned.
function verifySidecar() {}

function isTimeout(error) {
  if (error === null || error === undefined) return false;
  if (error.code === 'timeout') return true;
  return /timeout/i.test(String(error.message ?? ''));
}

function isTooLarge(error) {
  if (error === null || error === undefined) return false;
  if (error.code === 'too_large') return true;
  return /too_large|too large/i.test(String(error.message ?? error));
}

function recordText(value) {
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  return String(value);
}

function recordBytes(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value.length;
  return Buffer.byteLength(String(value), 'utf8');
}

function createSidecarRunner(options = {}) {
  const pipe = options.pipe;
  const spawn = options.spawn;
  const randomBytes = options.randomBytes;
  const sidecarCommand = options.sidecarCommand;
  const timeouts = options.timeouts ?? {};
  const connectTimeout = timeouts.connect ?? 60_000;
  const recordTimeout = timeouts.record ?? 120_000;
  const writeTimeout = timeouts.write ?? connectTimeout;
  const exitGrace = timeouts.exit ?? 2_000;
  const verify = typeof options.verifySidecar === 'function'
    ? options.verifySidecar
    : (typeof module.exports.verifySidecar === 'function'
      ? module.exports.verifySidecar
      : verifySidecar);

  async function runSidecar(input = {}) {
    const { binding, policy, producer, elevate, onCancel, onElevationPending } = input;

    let handle;
    let child = null;
    let exited = false;
    let exitCode = null;
    let connected = false;
    let closed = false;
    let cancelled = false;
    let signalExit = null;
    let signalError = null;
    let signalCancel = null;
    let resolveProcessExit = null;

    const exitSignal = new Promise((resolve) => {
      signalExit = resolve;
    });
    const errorSignal = new Promise((resolve) => {
      signalError = resolve;
    });
    const cancelSignal = new Promise((resolve) => {
      signalCancel = resolve;
    });
    const processExit = new Promise((resolve) => {
      resolveProcessExit = resolve;
    });

    async function close() {
      if (closed) return;
      const id = handle;
      handle = undefined;
      if (id === undefined) return;
      closed = true;
      try {
        await pipe.close(id);
      } catch {
        // Closing is cleanup on every path; the original error is the one the
        // caller needs.
      }
    }

    function killIfOurs() {
      if (child === null || exited) return;
      try {
        if (typeof child.kill === 'function') child.kill();
      } catch {
        // The process may already be gone.
      }
    }

    function cancel() {
      if (cancelled) return;
      cancelled = true;
      killIfOurs();
      if (signalCancel !== null) {
        const resolve = signalCancel;
        signalCancel = null;
        resolve();
      }
      // Closing is asynchronous, but the close starts before this returns so a
      // second cancel cannot open another window.
      void close();
    }

    function throwIfCancelled() {
      if (cancelled) {
        throw new SidecarError('sidecar_cancelled', 'the scan was canceled');
      }
    }

    function waitForExit(millis) {
      if (!exited && child !== null && typeof child.exitCode === 'number') {
        exited = true;
        exitCode = child.exitCode;
      }
      if (exited) return Promise.resolve(exitCode);
      return new Promise((resolve) => {
        let settled = false;
        let timer = null;
        const finish = (value) => {
          if (settled) return;
          settled = true;
          if (timer !== null) clearTimeout(timer);
          resolve(value);
        };
        timer = setTimeout(() => finish(undefined), millis);
        processExit.then(finish);
        cancelSignal.then(() => finish(undefined));
      });
    }

    if (typeof onCancel === 'function') onCancel(cancel);

    const name = await pipe.pipeName(randomBytes(16));
    handle = await pipe.create(name);

    try {
      throwIfCancelled();

      if (typeof verify === 'function') await verify();
      throwIfCancelled();

      const command = sidecarCommand();
      if (command === null || command === undefined || typeof command.file !== 'string') {
        throw new Error('sidecarCommand did not return a file');
      }
      const baseArgs = Array.isArray(command.args) ? command.args : [];
      const args = [...baseArgs, '--pipe', name];
      if (elevate) {
        args.push('--elevate');
        if (typeof onElevationPending === 'function') onElevationPending();
      }

      child = spawn(command.file, args, { windowsHide: true });
      if (child === null || child === undefined || typeof child.on !== 'function') {
        throw new Error('spawn did not return a child process');
      }
      throwIfCancelled();

      child.on('exit', (code) => {
        exited = true;
        exitCode = code;
        if (resolveProcessExit !== null) {
          const resolve = resolveProcessExit;
          resolveProcessExit = null;
          resolve(code);
        }
        if (connected) return;
        if (code === 3) {
          signalExit({ declined: true });
        } else if (code !== 0) {
          signalExit({ error: new Error(`sidecar exited with code ${code}`) });
        }
      });

      // A missing or quarantined executable arrives as an `error` event, not
      // as a thrown spawn call.  Treat it as the sidecar failing so the flow
      // reaches `sidecar_failed` instead of the process-level handler.
      child.on('error', (error) => {
        if (exited) return;
        exited = true;
        if (resolveProcessExit !== null) {
          const resolve = resolveProcessExit;
          resolveProcessExit = null;
          resolve(null);
        }
        const failure = error instanceof Error ? error : new Error('sidecar process failed');
        signalExit({ error: failure });
        signalError({ error: failure });
      });

      const acceptResult = Promise.resolve()
        .then(() => pipe.accept(handle, connectTimeout))
        .then(
          () => {
            connected = true;
            return { accepted: true };
          },
          (error) => ({ acceptError: error }),
        );

      const decision = await Promise.race([acceptResult, exitSignal, cancelSignal]);
      throwIfCancelled();

      if (decision.declined === true) {
        await close();
        return { declined: true };
      }
      if (decision.error !== undefined) {
        await close();
        throw decision.error;
      }
      if (decision.acceptError !== undefined) {
        if (isTimeout(decision.acceptError)) killIfOurs();
        await close();
        throw decision.acceptError;
      }

      try {
        const exchange = (async () => {
          const line = JSON.stringify({ binding, policy, producer });
          await pipe.writeLine(handle, line, writeTimeout);
          throwIfCancelled();
          const record = await pipe.readUntilClose(handle, MAX_RECORD_BYTES, recordTimeout);
          if (recordBytes(record) > MAX_RECORD_BYTES) {
            throw new SidecarError(
              'too_large',
              `the sidecar record exceeds ${MAX_RECORD_BYTES} bytes`,
            );
          }

          if (record === null || record === undefined) {
            throw new SidecarError('sidecar_failed', 'the sidecar wrote an empty record');
          }
          const text = recordText(record);
          if (text.trim().length === 0) {
            throw new SidecarError('sidecar_failed', 'the sidecar wrote an empty record');
          }

          // A child that connected and then failed is not a bad record. Give it
          // the ADR's 2 s to report its exit, but do not hold a live elevated
          // sidecar's relaunching parent to that rule.
          const code = await waitForExit(exitGrace);
          throwIfCancelled();
          if (typeof code === 'number' && code !== 0) {
            throw new SidecarError('sidecar_failed', `sidecar exited with code ${code}`);
          }

          return { recordText: text };
        })().then(
          (value) => ({ value }),
          (error) => ({ exchangeError: error }),
        );

        const outcome = await Promise.race([exchange, errorSignal, cancelSignal]);
        throwIfCancelled();
        if (outcome.error !== undefined) throw outcome.error;
        if (outcome.exchangeError !== undefined) throw outcome.exchangeError;

        await close();
        return outcome.value;
      } catch (error) {
        if (isTimeout(error)) killIfOurs();
        await close();
        if (isTooLarge(error)) {
          throw new SidecarError(
            'too_large',
            `the sidecar record exceeds ${MAX_RECORD_BYTES} bytes`,
            { cause: error },
          );
        }
        throw error;
      }
    } catch (error) {
      await close();
      throw error;
    }
  }

  return runSidecar;
}

module.exports = createSidecarRunner;
module.exports.createSidecarRunner = createSidecarRunner;
module.exports.SidecarError = SidecarError;
module.exports.verifySidecar = verifySidecar;
module.exports.MAX_RECORD_BYTES = MAX_RECORD_BYTES;
