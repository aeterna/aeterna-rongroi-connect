// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { createHash } = require('node:crypto');

function compareUtf16(a, b) {
  // ECMAScript string comparison is lexicographic over UTF-16 code units,
  // which is the ordering RFC 8785 requires.
  return a < b ? -1 : a > b ? 1 : 0;
}

function canonicalize(value) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('JCS cannot serialize a non-finite number');
    // rongroi-core refuses numbers that are not integers. JSON.stringify
    // would silently print 1.5, so refuse it here too; integers keep the
    // ECMAScript number formatting required by RFC 8785.
    if (!Number.isInteger(value)) throw new TypeError('JCS cannot serialize a non-integer number');
    return JSON.stringify(value);
  }
  if (type === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (type === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('JCS requires plain objects');
    const members = Object.keys(value).sort(compareUtf16).map((key) => {
      return `${JSON.stringify(key)}:${canonicalize(value[key])}`;
    });
    return `{${members.join(',')}}`;
  }
  throw new TypeError(`JCS cannot serialize a ${type}`);
}

function withoutMember(value, member) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('a hash target must be an object');
  }
  const copy = {};
  for (const [key, entry] of Object.entries(value)) {
    if (key !== member) copy[key] = entry;
  }
  return copy;
}

function hash16(value, member) {
  const bytes = Buffer.from(canonicalize(withoutMember(value, member)), 'utf8');
  return createHash('sha256').update(bytes).digest('hex').slice(0, 16);
}

function policyHash(policy) {
  return hash16(policy, 'policy_hash');
}

function visualHash(record) {
  return hash16(record, 'visual_hash');
}

module.exports = { canonicalize, policyHash, visualHash };
