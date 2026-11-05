// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  sealEnvelope, openEnvelope, deriveKey, deriveSharedSecret,
} = require('../src/core/envelope');

const TICKET = '9f82c4e1b07a412891d604e38a291bf0';
const kit = crypto.generateKeyPairSync('x25519');
const kitPublic = kit.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
const vector = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'envelope-v1.json'), 'utf8'));

test('seal then open returns the same UTF-8 text', () => {
  const plaintext = '{"kind":"rongroi-saved-report","schema":2,"note":"é😀"}';
  const envelope = sealEnvelope(plaintext, kitPublic, TICKET);

  assert.deepEqual(Object.keys(envelope), ['v', 'epk', 'iv', 'ct']);
  assert.equal(envelope.v, 1);
  assert.match(envelope.epk, /^[A-Za-z0-9_-]{43}$/);
  assert.match(envelope.iv, /^[A-Za-z0-9_-]{16}$/);
  assert.equal(
    Buffer.from(envelope.ct, 'base64url').length,
    Buffer.byteLength(plaintext, 'utf8') + 16,
  );
  assert.equal(openEnvelope(envelope, kit.privateKey, TICKET), plaintext);
});

test('uses a fresh ephemeral key and iv for every report', () => {
  const first = sealEnvelope('same', kitPublic, TICKET);
  const second = sealEnvelope('same', kitPublic, TICKET);
  assert.notEqual(first.epk, second.epk);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.ct, second.ct);
});

test('rejects a tampered envelope, wrong ticket or wrong key', () => {
  const envelope = sealEnvelope('secret', kitPublic, TICKET);
  const tampered = Buffer.from(envelope.ct, 'base64url');
  tampered[0] ^= 1;

  assert.throws(() => openEnvelope({ ...envelope, ct: tampered.toString('base64url') }, kit.privateKey, TICKET));
  assert.throws(() => openEnvelope(envelope, kit.privateKey, '0'.repeat(32)));
  const other = crypto.generateKeyPairSync('x25519');
  assert.throws(() => openEnvelope(envelope, other.privateKey, TICKET));
  assert.throws(() => openEnvelope({ ...envelope, v: 2 }, kit.privateKey, TICKET));
});

test('validates the kit key and ticket before sealing', () => {
  assert.throws(() => sealEnvelope('x', Buffer.alloc(31).toString('base64url'), TICKET));
  assert.throws(() => sealEnvelope('x', kitPublic, 'A'.repeat(32)));
});

test('matches the shared envelope v1 vector', () => {
  const kitPrivate = crypto.createPrivateKey({
    key: {
      kty: 'OKP',
      crv: 'X25519',
      d: vector.kit.privateKey,
      x: vector.kit.publicKey,
    },
    format: 'jwk',
  });
  const ephemeralPrivate = crypto.createPrivateKey({
    key: {
      kty: 'OKP',
      crv: 'X25519',
      d: vector.ephemeral.privateKey,
      x: vector.ephemeral.publicKey,
    },
    format: 'jwk',
  });
  const kitRaw = Buffer.from(vector.kit.publicKey, 'base64url');
  const epkRaw = Buffer.from(vector.ephemeral.publicKey, 'base64url');

  const shared = deriveSharedSecret(ephemeralPrivate, kitRaw);
  assert.equal(shared.toString('base64url'), vector.sharedSecret);

  const key = deriveKey(shared, kitRaw, epkRaw, vector.ticket);
  assert.equal(key.toString('base64url'), vector.derivedKey);

  const envelope = sealEnvelope(vector.plaintext, vector.kit.publicKey, vector.ticket, {
    ephemeralPrivate: vector.ephemeral.privateKey,
    iv: Buffer.from(vector.iv, 'base64url'),
  });
  assert.deepEqual(envelope, vector.envelope);
  assert.equal(openEnvelope(vector.envelope, kitPrivate, vector.ticket), vector.plaintext);
});
