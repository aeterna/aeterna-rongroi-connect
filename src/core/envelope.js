// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const crypto = require('node:crypto');

const INFO_PREFIX = 'rongroi-connect report v1';
const INFO_PREFIX_V2 = 'rongroi-connect report v2';
const BINDING_KEYS = ['base_path', 'policy_hash', 'server_origin', 'ticket', 'transport'];
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

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

function importPrivateKey(value) {
  if (value !== null && typeof value === 'object' && value.type === 'private') return value;
  const raw = base64urlBytes(value, 32, 'ephemeral private key');
  const der = Buffer.concat([PKCS8_PREFIX, raw]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

function deriveSharedSecret(privateKey, peerRaw) {
  return crypto.diffieHellman({
    privateKey,
    publicKey: importPublicKey(peerRaw),
  });
}

function deriveKey(shared, kitRaw, epkRaw, ticket, version = 1) {
  const label = version === 2 ? INFO_PREFIX_V2 : INFO_PREFIX;
  const info = Buffer.concat([Buffer.from(label, 'utf8'), kitRaw, epkRaw]);
  const key = crypto.hkdfSync('sha256', shared, Buffer.from(ticket, 'ascii'), info, 32);
  return Buffer.from(key);
}

function fixedIv(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const iv = Buffer.from(value);
    if (iv.length !== 12) throw new RangeError('iv must be 12 bytes');
    return iv;
  }
  return base64urlBytes(value, 12, 'iv');
}

/**
 * Seal a report into an envelope v1.
 *
 * The optional `fixed` argument is a test seam for the shared vector. Pass
 * `{ ephemeralPrivate, iv }` to use a known X25519 private key (a KeyObject or
 * a 32-byte base64url raw key) and a known 12-byte IV (a Buffer or base64url).
 * Production code must omit it, so every report gets a fresh key and IV.
 */
function sealEnvelope(plaintextUtf8, kitPublicB64u, ticket, fixed) {
  const kitRaw = base64urlBytes(kitPublicB64u, 32, 'kit public key');
  const salt = ticketBytes(ticket);
  if (typeof plaintextUtf8 !== 'string' && !Buffer.isBuffer(plaintextUtf8)) {
    throw new TypeError('plaintext must be a UTF-8 string or a Buffer');
  }
  if (fixed !== undefined && fixed !== null
      && (typeof fixed !== 'object' || Array.isArray(fixed))) {
    throw new TypeError('fixed must be an object');
  }
  const plaintext = Buffer.isBuffer(plaintextUtf8) ? plaintextUtf8 : Buffer.from(plaintextUtf8, 'utf8');

  const ephemeralPrivate = fixed && fixed.ephemeralPrivate !== undefined
    ? importPrivateKey(fixed.ephemeralPrivate)
    : crypto.generateKeyPairSync('x25519').privateKey;
  const epkRaw = rawPublicKey(crypto.createPublicKey(ephemeralPrivate));
  const shared = deriveSharedSecret(ephemeralPrivate, kitRaw);
  const key = deriveKey(shared, kitRaw, epkRaw, ticket);
  const iv = fixed && fixed.iv !== undefined ? fixedIv(fixed.iv) : crypto.randomBytes(12);
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

/**
 * Envelope v2 additional data (ADR 0003, aeterna-rongroi ADR 0097 section 4): the JCS form of the five binding
 * members, each a string, keys in code-point order. For flat string members JCS equals JSON.stringify of the
 * sorted object.
 */
function bindingAad(binding) {
  if (binding === null || typeof binding !== 'object' || Array.isArray(binding)) {
    throw new TypeError('binding must be an object');
  }
  const keys = Object.keys(binding).sort();
  if (keys.length !== BINDING_KEYS.length || keys.some((key, i) => key !== BINDING_KEYS[i])) {
    throw new TypeError('binding must have exactly base_path, policy_hash, server_origin, ticket, transport');
  }
  const ordered = {};
  for (const key of BINDING_KEYS) {
    if (typeof binding[key] !== 'string' || binding[key].length === 0) {
      throw new TypeError(`binding.${key} must be a non-empty string`);
    }
    ordered[key] = binding[key];
  }
  ticketBytes(binding.ticket);
  return Buffer.from(JSON.stringify(ordered), 'utf8');
}

/** Seal a report into an envelope v2, bound to an rr2 code. `fixed` is the same test seam as v1. */
function sealEnvelopeV2(plaintextUtf8, kitPublicB64u, binding, fixed) {
  const kitRaw = base64urlBytes(kitPublicB64u, 32, 'kit public key');
  const aad = bindingAad(binding);
  if (typeof plaintextUtf8 !== 'string' && !Buffer.isBuffer(plaintextUtf8)) {
    throw new TypeError('plaintext must be a UTF-8 string or a Buffer');
  }
  const plaintext = Buffer.isBuffer(plaintextUtf8) ? plaintextUtf8 : Buffer.from(plaintextUtf8, 'utf8');
  const ephemeralPrivate = fixed && fixed.ephemeralPrivate !== undefined
    ? importPrivateKey(fixed.ephemeralPrivate)
    : crypto.generateKeyPairSync('x25519').privateKey;
  const epkRaw = rawPublicKey(crypto.createPublicKey(ephemeralPrivate));
  const shared = deriveSharedSecret(ephemeralPrivate, kitRaw);
  const key = deriveKey(shared, kitRaw, epkRaw, binding.ticket, 2);
  const iv = fixed && fixed.iv !== undefined ? fixedIv(fixed.iv) : crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return {
    v: 2,
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
  const shared = deriveSharedSecret(kitPrivateKey, epkRaw);
  const key = deriveKey(shared, kitRaw, epkRaw, ticket);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(salt);
  decipher.setAuthTag(ctAndTag.subarray(ctAndTag.length - 16));
  return Buffer.concat([
    decipher.update(ctAndTag.subarray(0, ctAndTag.length - 16)),
    decipher.final(),
  ]).toString('utf8');
}

module.exports = { sealEnvelope, sealEnvelopeV2, bindingAad, openEnvelope, deriveKey, deriveSharedSecret };
