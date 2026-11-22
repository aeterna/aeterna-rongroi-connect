// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Envelope v2 against the shared vector made by the Server Kit (nakara-oss packages/rongroi): this is an
// independent implementation, so matching bytes is a cross-check of both.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { sealEnvelopeV2, bindingAad, deriveKey, deriveSharedSecret } = require('../src/core/envelope');

const v = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'envelope-v2.json'), 'utf8'));

test('v2 additional data matches the vector', () => {
  assert.equal(bindingAad(v.binding).toString('utf8'), v.aad);
});

test('v2 sealing reproduces the vector envelope', () => {
  const env = sealEnvelopeV2(v.plaintext, v.kit.publicKey, v.binding, { ephemeralPrivate: v.ephemeral.privateKey, iv: v.iv });
  assert.deepEqual(env, v.envelope);
});

test('v2 key derivation uses the v2 label', () => {
  const crypto = require('node:crypto');
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(v.kit.privateKey, 'base64url')]);
  const kitPriv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const shared = deriveSharedSecret(kitPriv, Buffer.from(v.ephemeral.publicKey, 'base64url'));
  assert.equal(shared.toString('base64url'), v.sharedSecret);
  const key = deriveKey(shared, Buffer.from(v.kit.publicKey, 'base64url'), Buffer.from(v.ephemeral.publicKey, 'base64url'), v.binding.ticket, 2);
  assert.equal(key.toString('base64url'), v.derivedKey);
});

test('a binding with a missing or extra member is refused', () => {
  const { transport, ...missing } = v.binding;
  assert.equal(transport, 'relay');
  assert.throws(() => bindingAad(missing), TypeError);
  assert.throws(() => bindingAad({ ...v.binding, extra: 'x' }), TypeError);
});
