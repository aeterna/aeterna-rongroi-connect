// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');
const { MAX_CODE_BYTES, readCodeFromStream } = require('../src/main/stdin-code');

const CODE = 'rr1.AbCdEf1234567890';

function stream() {
  return new PassThrough();
}

async function readChunks(chunks, options = {}) {
  const source = stream();
  const pending = readCodeFromStream(source, options);
  for (const chunk of chunks) source.write(chunk);
  source.end();
  return pending;
}

function assertAccepted(result, expected) {
  assert.deepEqual(result, { ok: true, code: expected, reason: null });
}

function assertRefused(result, reason, message) {
  assert.deepEqual(result, { ok: false, code: null, reason }, message);
}

test('a code with one terminating newline is accepted without the newline', async () => {
  assertAccepted(await readChunks([`${CODE}\n`]), CODE);
});

test('a code at EOF without a newline is accepted', async () => {
  assertAccepted(await readChunks([CODE]), CODE);
});

test('a code arriving in several chunks is accepted whole', async () => {
  assertAccepted(
    await readChunks(['rr1.', 'AbCdEf', '1234567890', '\n']),
    CODE,
  );
});

test(`exactly ${MAX_CODE_BYTES} bytes are accepted, with a newline and at EOF`, async () => {
  const code = 'a'.repeat(MAX_CODE_BYTES);
  assertAccepted(await readChunks([`${code}\n`]), code);
  assertAccepted(await readChunks([code]), code);
  // Split so the limit is met exactly across chunk boundaries.
  assertAccepted(
    await readChunks([code.slice(0, 100), code.slice(100), '\n']),
    code,
  );
});

test(`${MAX_CODE_BYTES + 1} bytes are refused, with a newline and at EOF`, async () => {
  const code = 'a'.repeat(MAX_CODE_BYTES + 1);
  assertRefused(await readChunks([`${code}\n`]), 'too_long');
  assertRefused(await readChunks([code]), 'too_long');
});

test('the first byte past the limit is refused before any newline', async () => {
  const code = 'a'.repeat(MAX_CODE_BYTES);
  assertRefused(await readChunks([code, 'b\n']), 'too_long');
  assertRefused(await readChunks([Buffer.alloc(MAX_CODE_BYTES, 0x61), Buffer.from('b')]), 'too_long');
});

test('a carriage return anywhere is refused', async () => {
  assertRefused(await readChunks([`${CODE}\r\n`]), 'carriage_return');
  assertRefused(await readChunks(['co\rde\n']), 'carriage_return');
  assertRefused(await readChunks(['\r']), 'carriage_return');
  assertRefused(await readChunks(['\r', 'rest\n']), 'carriage_return');
});

test('a UTF-8 BOM is refused, whole and split across chunks', async () => {
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  assertRefused(
    await readChunks([Buffer.concat([bom, Buffer.from(`${CODE}\n`)])]),
    'byte_order_mark',
  );
  assertRefused(
    await readChunks([Buffer.from([0xef]), Buffer.from([0xbb, 0xbf, 0x72, 0x72]), '\n']),
    'byte_order_mark',
  );
});

test('a NUL byte is refused', async () => {
  assertRefused(await readChunks([`${CODE}\u0000\n`]), 'control_character');
});

test('any other control byte is refused', async () => {
  const cases = [
    ['\t', 'a tab'],
    ['\u0001', '0x01'],
    ['\u000B', 'a vertical tab'],
    ['\u001F', '0x1F'],
    ['\u007F', 'DEL'],
  ];
  for (const [character, label] of cases) {
    assertRefused(
      await readChunks([`${CODE.slice(0, 4)}${character}${CODE.slice(4)}\n`]),
      'control_character',
      label,
    );
  }
});

test('a C1 control hidden in a multi-byte sequence is refused', async () => {
  // U+0085 travels as the bytes C2 85, which no single-byte scan may mistake
  // for a control byte; the decoded text is what is checked for it.
  assertRefused(
    await readChunks([Buffer.from('rr1.\u0085x\n', 'utf8')]),
    'control_character',
  );
});

test('an empty line is refused at EOF and after a lone newline', async () => {
  assertRefused(await readChunks([]), 'empty');
  assertRefused(await readChunks(['\n']), 'empty');
});

test('data after the terminating newline is refused', async () => {
  assertRefused(await readChunks([`${CODE}\nextra`]), 'trailing_data');
  assertRefused(await readChunks([`${CODE}\n\n`]), 'trailing_data');
});

test('multi-byte characters that are not control bytes are accepted', async () => {
  assertAccepted(await readChunks(['rr1.\u00E9x\n']), 'rr1.\u00E9x');
});

test('an empty stdin that stays silent past the limit is refused as a timeout', async () => {
  const source = stream();
  const pending = readCodeFromStream(source, { timeoutMs: 25 });
  const settled = await pending;
  assertRefused(settled, 'timeout');
});

test('a stream that errors instead of ending is refused', async () => {
  const source = stream();
  const pending = readCodeFromStream(source, { timeoutMs: 1000 });
  source.destroy(new Error('the pipe broke'));
  assertRefused(await pending, 'read_error');
});

test('the first refusal wins and the reader stops listening', async () => {
  const source = stream();
  const pending = readCodeFromStream(source, { timeoutMs: 200 });
  source.write('rr1.\r');
  source.write('more\n');
  source.end();
  assertRefused(await pending, 'carriage_return');
});
