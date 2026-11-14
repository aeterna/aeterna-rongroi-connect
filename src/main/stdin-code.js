// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// ADR 0002 section 2, the stdin half of the launcher handoff.  The launcher
// writes one pairing code: at most MAX_CODE_BYTES bytes plus one terminating
// '\n', or EOF, within DEFAULT_TIMEOUT_MS.  Connect reads stdin once and
// refuses — the run then ends with exit 12 and no code — when the line is
// longer than the limit, carries a carriage return, starts with a UTF-8 BOM,
// holds a NUL or any other control byte, arrives too late, is empty, holds
// data after the line, or the stream itself fails.  The bytes become a string
// and nothing else, handed to the same parseCode path a pasted code takes.

const MAX_CODE_BYTES = 4096;
const DEFAULT_TIMEOUT_MS = 5000;
const NEWLINE = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const DEL = 0x7f;
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
// The same control characters flow.js refuses in a policy's server name,
// checked on the decoded code so a multi-byte sequence cannot hide one.
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001F\u007F-\u009F]/;

function refusal(reason) {
  return { ok: false, code: null, reason };
}

function accepted(code) {
  return { ok: true, code, reason: null };
}

// A carriage return or a byte below 0x20 (the terminating newline is not part
// of a line) or DEL is refused on sight.  Continuation bytes of multi-byte
// UTF-8 sequences are 0x80 or above and never match here; the C1 range is
// checked on the decoded text instead.
function hasForbiddenByte(bytes) {
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index];
    if (byte === CARRIAGE_RETURN) return 'carriage_return';
    if (byte < 0x20 || byte === DEL) return 'control_character';
  }
  return null;
}

function startsWithBom(buffer) {
  if (buffer.length < BOM.length) return false;
  return BOM.compare(buffer.subarray(0, BOM.length)) === 0;
}

function readCodeFromStream(stream, options = {}) {
  const maxBytes = typeof options.maxBytes === 'number' && options.maxBytes > 0
    ? options.maxBytes
    : MAX_CODE_BYTES;
  const requested = typeof options.timeoutMs === 'number' && Number.isFinite(options.timeoutMs)
    ? options.timeoutMs
    : DEFAULT_TIMEOUT_MS;
  const timeoutMs = requested >= 0 ? requested : DEFAULT_TIMEOUT_MS;
  const scheduleTimeout = typeof options.setTimeout === 'function'
    ? options.setTimeout
    : setTimeout;
  const cancelTimeout = typeof options.clearTimeout === 'function'
    ? options.clearTimeout
    : clearTimeout;

  return new Promise((resolve) => {
    let buffer = Buffer.alloc(0);
    let settled = false;
    let timer = null;

    function finish(result) {
      if (settled) return;
      settled = true;
      if (timer !== null) {
        cancelTimeout(timer);
        timer = null;
      }
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
      // After the handoff settled, the launcher's pipe is no longer ours: a
      // later error on it must not become an unhandled 'error' event.
      stream.on('error', () => {});
      if (typeof stream.pause === 'function') stream.pause();
      resolve(result);
    }

    // The buffer holds the line's bytes without the terminator, so an empty
    // buffer here is an empty line.
    function complete() {
      if (buffer.length === 0) return finish(refusal('empty'));
      const code = buffer.toString('utf8');
      if (CONTROL_CHARACTER_PATTERN.test(code)) {
        return finish(refusal('control_character'));
      }
      return finish(accepted(code));
    }

    function onData(chunk) {
      if (settled) return;
      const bytes = typeof chunk === 'string'
        ? Buffer.from(chunk, 'utf8')
        : Buffer.from(chunk);
      const newline = bytes.indexOf(NEWLINE);
      const portion = newline === -1 ? bytes : bytes.subarray(0, newline);

      const forbidden = hasForbiddenByte(portion);
      if (forbidden !== null) return finish(refusal(forbidden));

      if (portion.length > 0) buffer = Buffer.concat([buffer, portion]);
      if (startsWithBom(buffer)) return finish(refusal('byte_order_mark'));
      if (buffer.length > maxBytes) return finish(refusal('too_long'));

      if (newline !== -1) {
        if (bytes.length > newline + 1) return finish(refusal('trailing_data'));
        return complete();
      }
    }

    function onEnd() {
      if (settled) return;
      complete();
    }

    function onError() {
      if (settled) return;
      finish(refusal('read_error'));
    }

    if (timeoutMs > 0) {
      timer = scheduleTimeout(() => {
        timer = null;
        finish(refusal('timeout'));
      }, timeoutMs);
      // The reader must never keep an app or a test runner alive by itself.
      if (timer !== null && typeof timer.unref === 'function') timer.unref();
    }

    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onError);
  });
}

module.exports = {
  MAX_CODE_BYTES,
  DEFAULT_TIMEOUT_MS,
  readCodeFromStream,
};
