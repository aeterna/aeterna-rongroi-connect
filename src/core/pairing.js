// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const net = require('node:net');
const { domainToASCII } = require('node:url');
const { TextDecoder } = require('node:util');

class PairingError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PairingError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new PairingError(code, message);
}

function isLocalAddress(host) {
  if (typeof host !== 'string') return false;
  const name = host.toLowerCase().replace(/\.$/, '');
  if (name === 'localhost' || name.endsWith('.localhost')) return true;

  const family = net.isIP(host);
  if (family === 4) {
    const [first, second] = host.split('.').map(Number);
    return first === 127 || first === 10
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 169 && second === 254);
  }
  if (family === 6) {
    const value = host.toLowerCase();
    if (value === '::1') return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(value);
    if (mapped) return isLocalAddress(mapped[1]);
    // fc00::/7: the first hextet must be 0xfc00 through 0xfdff.
    return /^f[cd][0-9a-f]{2}(?::|$)/.test(value);
  }
  return false;
}

function isCanonicalIpv4(host) {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(host)) return false;
  return host.split('.').every((part) => Number(part) <= 255);
}

function isIpv4Looking(host) {
  const candidate = host.endsWith('.') ? host.slice(0, -1) : host;
  return candidate !== ''
    && candidate.split('.').every((part) => /^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(part));
}

function parseOrigin(value) {
  if (typeof value !== 'string') fail('BAD_ORIGIN', 'server_origin must be a string');
  const match = /^(https?):\/\/([^/?#@\\\s]+)$/.exec(value);
  if (!match) fail('BAD_ORIGIN', 'server_origin must be exactly http(s)://host[:port]');

  let url;
  try {
    url = new URL(value);
  } catch {
    fail('BAD_ORIGIN', 'server_origin is not a valid origin');
  }
  if (url.protocol !== `${match[1]}:` || url.username || url.password) {
    fail('BAD_ORIGIN', 'server_origin must not carry user information');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    fail('BAD_ORIGIN', 'server_origin must not carry a path, query or fragment');
  }

  const authority = match[2];
  let host;
  let port = null;
  if (authority.startsWith('[')) {
    const ipv6 = /^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$/.exec(authority);
    if (!ipv6 || net.isIP(ipv6[1]) !== 6) fail('BAD_ORIGIN', 'server_origin has an invalid IPv6 host');
    host = ipv6[1];
    port = ipv6[2] ?? null;
  } else {
    const parts = authority.split(':');
    if (parts.length > 2) fail('BAD_ORIGIN', 'server_origin has an invalid host or port');
    [host] = parts;
    port = parts[1] ?? null;
  }
  const portNumber = port === null ? null : Number(port);
  if (!host || (port !== null && (!/^\d{1,5}$/.test(port) || portNumber < 1 || portNumber > 65535))) {
    fail('BAD_ORIGIN', 'server_origin has an invalid host or port');
  }
  if (url.port !== (port ?? '')) fail('BAD_ORIGIN', 'server_origin must not spell a default port');

  const urlHost = url.hostname.replace(/^\[|\]$/g, '');
  let hostAscii;
  if (isIpv4Looking(host) || net.isIP(urlHost) === 4) {
    if (!isCanonicalIpv4(host) || urlHost !== host) {
      fail('BAD_ORIGIN', 'server_origin must use a canonical dotted-quad IPv4 host');
    }
    hostAscii = host;
  } else if (net.isIP(host)) {
    hostAscii = urlHost;
  } else {
    try {
      hostAscii = domainToASCII(host);
    } catch {
      fail('BAD_ORIGIN', 'server_origin host cannot be converted to ASCII');
    }
    if (!hostAscii) fail('BAD_ORIGIN', 'server_origin host cannot be converted to ASCII');
    if (urlHost.toLowerCase() !== hostAscii.toLowerCase()) {
      fail('BAD_ORIGIN', 'server_origin host is not a valid DNS name or IP address');
    }
  }

  return {
    serverOrigin: url.origin,
    host,
    hostAscii,
    isLocalAddress: isLocalAddress(host),
  };
}

function parseExpiry(value) {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) {
    fail('BAD_EXPIRY', 'expires_at must be ISO-8601 UTC ending in Z');
  }
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) fail('BAD_EXPIRY', 'expires_at is not a valid instant');
  const [date, time] = value.slice(0, -1).split('T');
  const [year, month, day] = date.split('-').map(Number);
  const [hour, minute, second] = time.split('.')[0].split(':').map(Number);
  const parsed = new Date(millis);
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() + 1 !== month
      || parsed.getUTCDate() !== day || parsed.getUTCHours() !== hour
      || parsed.getUTCMinutes() !== minute || parsed.getUTCSeconds() !== second) {
    fail('BAD_EXPIRY', 'expires_at is not a real date and time');
  }
  return value;
}

function base64urlBytes(value, code, label, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail(code, `${label} must be unpadded base64url`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) fail(code, `${label} is not canonical base64url`);
  if (length !== undefined && bytes.length !== length) fail(code, `${label} must be ${length} bytes`);
  return bytes;
}

// JavaScript's \s covers spaces, tabs, line breaks, NBSP, the Unicode space
// separators (including U+2009 thin space) and U+FEFF. The remaining
// zero-width and format characters are listed explicitly.
const CODE_NOISE = /[\s\u180E\u200B\u200C\u200D\u2060]/g;

function parsePairingCode(code) {
  if (typeof code !== 'string') fail('BAD_PREFIX', 'pairing code must be a string');
  const text = code.replace(CODE_NOISE, '');
  if (!text.startsWith('rr1.')) fail('BAD_PREFIX', 'pairing code must start with rr1.');
  const body = text.slice(4);
  if (body.length > 8192) fail('BAD_BASE64', 'pairing payload is too large');
  const raw = base64urlBytes(body, 'BAD_BASE64', 'pairing payload');

  let payload;
  try {
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    fail('BAD_JSON', 'pairing payload is not valid UTF-8 JSON');
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    fail('BAD_SHAPE', 'pairing payload must be a JSON object');
  }
  const expectedMembers = ['expires_at', 'kit_public_key', 'nonce', 'policy_hash', 'server_origin', 'ticket'];
  const members = Object.keys(payload).sort();
  if (members.length !== expectedMembers.length || members.some((key, index) => key !== expectedMembers[index])) {
    fail('BAD_SHAPE', 'pairing payload has missing or unexpected members');
  }

  const origin = parseOrigin(payload.server_origin);
  const { ticket } = payload;
  if (typeof ticket !== 'string' || !/^[0-9a-f]{32}$/.test(ticket)) {
    fail('BAD_TICKET', 'ticket must be 32 lowercase hex characters');
  }
  if (typeof payload.nonce !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(payload.nonce)) {
    fail('BAD_NONCE', 'nonce must be 1 to 128 printable ASCII characters');
  }
  const expiresAt = parseExpiry(payload.expires_at);
  if (typeof payload.policy_hash !== 'string' || !/^[0-9a-f]{16}$/.test(payload.policy_hash)) {
    fail('BAD_POLICY_HASH', 'policy_hash must be 16 lowercase hex characters');
  }
  const kitPublicKey = base64urlBytes(payload.kit_public_key, 'BAD_KIT_KEY', 'kit_public_key', 32);

  return {
    version: 1,
    serverOrigin: origin.serverOrigin,
    host: origin.host,
    hostAscii: origin.hostAscii,
    isLocalAddress: origin.isLocalAddress,
    ticket,
    nonce: payload.nonce,
    expiresAt,
    policyHash: payload.policy_hash,
    kitPublicKey: kitPublicKey.toString('base64url'),
  };
}

module.exports = { PairingError, isLocalAddress, parsePairingCode };
