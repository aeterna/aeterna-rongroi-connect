// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { canonicalize, policyHash, visualHash } = require('../src/core/canonical');

test('orders keys by UTF-16 code units and escapes JSON strings', () => {
  const value = {
    '😀': 'emoji',
    '\uE000': 'private',
    'é': 'accent',
    'a': 'a',
    'Z': 'Z',
    'ctl': '\u0001\t\n"\\',
  };
  assert.equal(
    canonicalize(value),
    '{"Z":"Z","a":"a","ctl":"\\u0001\\t\\n\\"\\\\","é":"accent","😀":"emoji","\uE000":"private"}',
  );
  assert.equal(canonicalize('\u0001\t\n"\\'), '"\\u0001\\t\\n\\"\\\\"');
  assert.equal(canonicalize('é😀/'), '"é😀/"');
});

test('uses ECMAScript number formatting', () => {
  assert.equal(canonicalize({ n: [1, -0, 1e21, 1e-7] }), '{"n":[1,0,1e+21,1e-7]}');
});

test('policyHash covers the canonical policy without policy_hash', () => {
  const policy = {
    profile: 'posture',
    required_collectors: ['posture', 'os_image'],
    require_elevation: true,
    server_name: 'Example City',
    policy_hash: '1111111111111111',
  };
  const canonical = '{"profile":"posture","require_elevation":true,'
    + '"required_collectors":["posture","os_image"],"server_name":"Example City"}';
  const expected = createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16);

  assert.equal(policyHash(policy), expected);
  assert.equal(policyHash({ ...policy, policy_hash: '2222222222222222' }), expected);
  assert.notEqual(policyHash({ ...policy, server_name: 'Other City' }), expected);
  assert.equal(policy.policy_hash, '1111111111111111');
});

test('visualHash covers the canonical record without visual_hash', () => {
  const record = { schema: 2, visual_hash: 'aaaaaaaaaaaaaaaa', case_code: '7K9M-2X4P' };
  const canonical = '{"case_code":"7K9M-2X4P","schema":2}';
  const expected = createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16);

  assert.equal(visualHash(record), expected);
  assert.equal(visualHash({ ...record, visual_hash: 'bbbbbbbbbbbbbbbb' }), expected);
  assert.equal(record.visual_hash, 'aaaaaaaaaaaaaaaa');
});
