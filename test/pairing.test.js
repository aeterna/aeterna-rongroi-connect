// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PairingError, isLocalAddress, parsePairingCode } = require('../src/core/pairing');

const BASE = {
  server_origin: 'http://203.0.113.10:30130',
  ticket: '9f82c4e1b07a412891d604e38a291bf0',
  nonce: 'c4b82e91024a',
  expires_at: '2026-10-31T14:35:00Z',
  policy_hash: 'a1b2c3d4e5f60718',
  kit_public_key: Buffer.alloc(32, 7).toString('base64url'),
};
const encode = (value) => `rr1.${Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')}`;
const parse = (patch = {}) => parsePairingCode(encode({ ...BASE, ...patch }));
const isPairingError = (code) => (error) => error instanceof PairingError && error.code === code;

test('parses a valid rr1 code and returns the ASCII host', () => {
  const parsed = parse();
  assert.equal(parsed.version, 1);
  assert.equal(parsed.serverOrigin, 'http://203.0.113.10:30130');
  assert.equal(parsed.host, '203.0.113.10');
  assert.equal(parsed.hostAscii, '203.0.113.10');
  assert.equal(parsed.isLocalAddress, false);
  assert.equal(parsed.ticket, BASE.ticket);
  assert.equal(parsed.nonce, BASE.nonce);
  assert.equal(parsed.expiresAt, BASE.expires_at);
  assert.equal(parsed.policyHash, BASE.policy_hash);
  assert.equal(parsed.kitPublicKey, BASE.kit_public_key);
});

test('returns the punycode host for a non-ASCII name', () => {
  const parsed = parse({ server_origin: 'http://münich.example:30130' });
  assert.equal(parsed.host, 'münich.example');
  assert.equal(parsed.hostAscii, 'xn--mnich-kva.example');
  assert.equal(parsed.serverOrigin, 'http://xn--mnich-kva.example:30130');
});

test('flags loopback and private-range origins', () => {
  const local = [
    'http://127.0.0.1:30130',
    'http://127.255.0.1:30130',
    'http://[::1]:30130',
    'http://10.1.2.3',
    'http://172.16.0.1',
    'http://172.31.255.255',
    'http://192.168.1.1',
    'http://169.254.1.1',
    'http://[fc00::1]',
    'http://[fd12::1]:30130',
    'http://[::ffff:192.168.1.1]',
    'http://localhost:30130',
    'http://app.localhost',
    'http://deep.app.localhost:30130',
  ];
  for (const origin of local) assert.equal(parse({ server_origin: origin }).isLocalAddress, true, origin);

  const remote = ['http://203.0.113.10', 'http://8.8.8.8', 'http://172.32.0.1', 'http://[fe80::1]'];
  for (const origin of remote) assert.equal(parse({ server_origin: origin }).isLocalAddress, false, origin);
  assert.equal(isLocalAddress('fdff::1'), true);
  assert.equal(isLocalAddress('fc::1'), false);
  assert.equal(isLocalAddress('LOCALHOST'), true);
  assert.equal(isLocalAddress('notlocalhost'), false);
});

test('refuses hostile or non-canonical origins', () => {
  const origins = [
    'http://user@example.com',
    'https://example.com/path',
    'https://example.com?query=1',
    'https://example.com#fragment',
    'ftp://example.com',
    'javascript:alert(1)',
    'http://example.com:99999',
    'http://example.com:80',
    'http://example.com:',
    'http:///missing-host',
    'http://exa mple.com',
    'http://127.1',
    'http://0x7f.1',
    'http://2130706433',
    'http://0177.0.0.1',
    'http://127.0.0.01',
    'http://256.0.0.1',
    'http://1.2.3.4.5',
    'http://127.0.0.1.',
  ];
  for (const origin of origins) {
    assert.throws(() => parse({ server_origin: origin }), isPairingError('BAD_ORIGIN'), origin);
  }
});

test('refuses malformed codes and members', () => {
  assert.throws(() => parsePairingCode('rr3.abc'), isPairingError('BAD_PREFIX'));
  assert.throws(() => parsePairingCode('rr1.!!!!'), isPairingError('BAD_BASE64'));
  assert.throws(() => parsePairingCode(`${encode(BASE)}=`), isPairingError('BAD_BASE64'));
  assert.throws(() => parsePairingCode('rr1.' + Buffer.from([0xff]).toString('base64url')), isPairingError('BAD_JSON'));
  assert.throws(() => parsePairingCode(encode([])), isPairingError('BAD_SHAPE'));
  assert.throws(() => parse({ extra: true }), isPairingError('BAD_SHAPE'));
  assert.throws(() => parse({
    server_origin: 'http://example.com', ticket: 'A'.repeat(32),
  }), isPairingError('BAD_TICKET'));
  assert.throws(() => parse({ nonce: '' }), isPairingError('BAD_NONCE'));
  assert.throws(() => parse({ expires_at: '2026-02-30T00:00:00Z' }), isPairingError('BAD_EXPIRY'));
  assert.throws(() => parse({ expires_at: '2026-10-31T14:35:00' }), isPairingError('BAD_EXPIRY'));
  assert.throws(() => parse({ policy_hash: 'A1B2C3D4E5F60718' }), isPairingError('BAD_POLICY_HASH'));
  assert.throws(() => parse({ kit_public_key: Buffer.alloc(31).toString('base64url') }), isPairingError('BAD_KIT_KEY'));
});

test('strips whitespace and zero-width characters anywhere in a pasted code', () => {
  const code = encode(BASE);
  const middle = Math.floor(code.length / 2);
  const variants = {
    'CRLF inside': `${code.slice(0, middle)}\r\n${code.slice(middle)}`,
    'thin space and NBSP between groups': `${code.slice(0, middle)}\u2009\u00A0${code.slice(middle)}`,
    'zero-width space at start, middle and end': `\u200B${code.slice(0, middle)}\u200B${code.slice(middle)}\u200B`,
    'BOM prefix': `\uFEFF${code}`,
    'word joiner inside': `${code.slice(0, middle)}\u2060${code.slice(middle)}`,
  };
  const expected = parsePairingCode(code);
  for (const [label, variant] of Object.entries(variants)) {
    assert.deepEqual(parsePairingCode(variant), expected, label);
  }
});

test('still refuses visible non-base64url characters inside a pasted code', () => {
  const code = encode(BASE);
  const middle = Math.floor(code.length / 2);
  assert.throws(
    () => parsePairingCode(`${code.slice(0, middle)}!${code.slice(middle)}`),
    isPairingError('BAD_BASE64'),
  );
});

test('refuses a pairing code that is only whitespace', () => {
  assert.throws(
    () => parsePairingCode(' \t\r\n\u00A0\u2009\u200B\uFEFF'),
    isPairingError('BAD_PREFIX'),
  );
});

// rr2 codes (ADR 0003, aeterna-rongroi ADR 0097 section 2).
function rr2(changes = {}) {
  const payload = {
    server_origin: 'https://relay.example.org', base_path: 'srv1', transport: 'relay',
    ticket: '7a1c9e3f5b2d8a4c6e0f1b3d5a7c9e2f', nonce: 'n-01', expires_at: '2026-11-21T12:00:00Z',
    policy_hash: '0123456789abcdef', kit_public_key: 'ovol0Vile5zOPb8MVWv4hi3YXxnWwdhDWs2VxaLj5yA', ...changes,
  };
  for (const key of Object.keys(payload)) if (payload[key] === undefined) delete payload[key];
  return `rr2.${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}`;
}

test('rr2: parses base_path and transport and returns the v2 binding', () => {
  const parsed = parsePairingCode(rr2());
  assert.equal(parsed.version, 2);
  assert.equal(parsed.basePath, 'srv1');
  assert.equal(parsed.transport, 'relay');
  assert.deepEqual(parsed.binding, { base_path: 'srv1', policy_hash: '0123456789abcdef',
    server_origin: 'https://relay.example.org', ticket: '7a1c9e3f5b2d8a4c6e0f1b3d5a7c9e2f', transport: 'relay' });
});

test('rr1 keeps base_path nakara_rongroi, transport direct and no binding', () => {
  const p = { server_origin: 'http://203.0.113.10:30120', ticket: '7a1c9e3f5b2d8a4c6e0f1b3d5a7c9e2f', nonce: 'n',
    expires_at: '2026-11-21T12:00:00Z', policy_hash: '0123456789abcdef', kit_public_key: 'ovol0Vile5zOPb8MVWv4hi3YXxnWwdhDWs2VxaLj5yA' };
  const parsed = parsePairingCode(`rr1.${Buffer.from(JSON.stringify(p)).toString('base64url')}`);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.basePath, 'nakara_rongroi');
  assert.equal(parsed.transport, 'direct');
  assert.equal(parsed.binding, null);
});

test('rr2: refuses unknown or missing members, bad base_path, bad transport, http relay, unnormalised origin', () => {
  assert.throws(() => parsePairingCode(rr2({ extra: 'x' })), isPairingError('BAD_SHAPE'));
  assert.throws(() => parsePairingCode(rr2({ base_path: undefined })), isPairingError('BAD_SHAPE'));
  for (const base_path of ['v1', 'Srv', '', 'a/b', 'x'.repeat(65)]) {
    assert.throws(() => parsePairingCode(rr2({ base_path })), isPairingError('BAD_BASE_PATH'), base_path);
  }
  assert.throws(() => parsePairingCode(rr2({ transport: 'smoke' })), isPairingError('BAD_TRANSPORT'));
  assert.throws(() => parsePairingCode(rr2({ server_origin: 'http://relay.example.org' })), isPairingError('BAD_ORIGIN'));
  assert.throws(() => parsePairingCode(rr2({ server_origin: 'https://Relay.example.org' })), isPairingError('BAD_ORIGIN'));
  assert.equal(parsePairingCode(rr2({ server_origin: 'http://203.0.113.10:30120', transport: 'direct' })).transport, 'direct');
});
