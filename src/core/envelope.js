// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const crypto = require('node:crypto');

const INFO_PREFIX = 'rongroi-connect report v1';
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function ticketBytes(ticket) {
  if (typeof ticket !== 'string' || !/^[0-9a-f]{32}$/.test(ticket)) {
    throw new TypeError('ticket must be 32 lowercase hex characters');
  }
  return Buffer.from(ticket, 'ascii');
}

function base64urlBytes(value, length, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError(`${label} must be unpadded base64url`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw new TypeError(`${label} is not canonical base64url`);
  if (length !== undefined && bytes.length !== length) throw new RangeError(`${label} must be ${length} bytes`);
  return bytes;
}

function rawPublicKey(key) {
  const der = key.export({ format: 'der', type: 'spki' });
  if (der.length < 32) throw new TypeError('not an X25519 public key');
  return der.subarray(der.length - 32);
}

function importPublicKey(raw) {
  const der = Buffer.concat([SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function deriveKey(shared, kitRaw, epkRaw, ticket) {
  const info = Buffer.concat([Buffer.from(INFO_PREFIX, 'utf8'), kitRaw, epkRaw]);
  const key = crypto.hkdfSync('sha256', shared, Buffer.from(ticket, 'ascii'), info, 32);
  return Buffer.from(key);
}

function sealEnvelope(plaintextUtf8, kitPublicB64u, ticket) {
  const kitRaw = base64urlBytes(kitPublicB64u, 32, 'kit public key');
  const salt = ticketBytes(ticket);
  if (typeof plaintextUtf8 !== 'string' && !Buffer.isBuffer(plaintextUtf8)) {
    throw new TypeError('plaintext must be a UTF-8 string or a Buffer');
  }
  const plaintext = Buffer.isBuffer(plaintextUtf8) ? plaintextUtf8 : Buffer.from(plaintextUtf8, 'utf8');

  const ephemeral = crypto.generateKeyPairSync('x25519');
  const epkRaw = rawPublicKey(ephemeral.publicKey);
  const shared = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: importPublicKey(kitRaw),
  });
  const key = deriveKey(shared, kitRaw, epkRaw, ticket);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(salt);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  return {
    v: 1,
    epk: epkRaw.toString('base64url'),
    iv: iv.toString('base64url'),
    ct: ciphertext.toString('base64url'),
  };
}

function openEnvelope(envelope, kitPrivateKey, ticket) {
  if (envelope === null || typeof envelope !== 'object' || envelope.v !== 1) {
    throw new TypeError('envelope must be version 1');
  }
  if (kitPrivateKey === null || typeof kitPrivateKey !== 'object' || kitPrivateKey.type !== 'private') {
    throw new TypeError('kit private key must be a private KeyObject');
  }
  const epkRaw = base64urlBytes(envelope.epk, 32, 'epk');
  const iv = base64urlBytes(envelope.iv, 12, 'iv');
  const ctAndTag = base64urlBytes(envelope.ct, undefined, 'ct');
  if (ctAndTag.length < 16) throw new RangeError('ct must include a 16-byte authentication tag');
  const salt = ticketBytes(ticket);

  const kitRaw = rawPublicKey(crypto.createPublicKey(kitPrivateKey));
  const shared = crypto.diffieHellman({
    privateKey: kitPrivateKey,
    publicKey: importPublicKey(epkRaw),
  });
  const key = deriveKey(shared, kitRaw, epkRaw, ticket);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(salt);
  decipher.setAuthTag(ctAndTag.subarray(ctAndTag.length - 16));
  return Buffer.concat([
    decipher.update(ctAndTag.subarray(0, ctAndTag.length - 16)),
    decipher.final(),
  ]).toString('utf8');
}

module.exports = { sealEnvelope, openEnvelope };
