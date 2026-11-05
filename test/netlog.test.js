// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { checkNetlog } = require('../scripts/check-netlog');

const ALLOWED = '127.0.0.1:30120';

function netlog(events) {
  return JSON.stringify({
    constants: {
      logEventTypes: {
        1: 'URL_REQUEST_START_JOB',
        2: 'HOST_RESOLVER_IMPL_REQUEST',
        3: 'TCP_CONNECT',
      },
    },
    events,
  });
}

function event(type, params) {
  return { type, params };
}

test('a log that names only the allowed host and port passes', () => {
  const result = checkNetlog(netlog([
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policy/abc' }),
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policy/abc' }),
    event(2, { host: '127.0.0.1', dns_query_type: 0, port: 30120 }),
    event(3, { address: '127.0.0.1', port: 30120 }),
    event(3, { remote_address: '127.0.0.1:30120' }),
    event(3, { remote_address: '127.0.0.1', remote_port: 30120 }),
    event(1, { url: 'file:///C:/Rongroi/resources/app.asar/index.html' }),
  ]), ALLOWED);

  assert.equal(result.ok, true);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.names, ['127.0.0.1:30120']);
});

test('a wpad host resolution fails', () => {
  const result = checkNetlog(netlog([
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policy/abc' }),
    event(2, { host: 'wpad', dns_query_type: 0 }),
    event(2, { host: 'wpad', dns_query_type: 0 }),
  ]), ALLOWED);

  assert.equal(result.ok, false);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.unexpected, ['wpad']);
});

test('a redirector.gvt1.com request fails', () => {
  const result = checkNetlog(netlog([
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policy/abc' }),
    event(1, { url: 'http://redirector.gvt1.com/edgedl/chrome/dict/en-us-8-0.bdic' }),
  ]), ALLOWED);

  assert.equal(result.ok, false);
  assert.ok(result.unexpected.some((name) => name.startsWith('redirector.gvt1.com')));
});

test('an empty log fails because the allowed host never appears', () => {
  const result = checkNetlog(netlog([]), ALLOWED);

  assert.equal(result.ok, false);
  assert.equal(result.allowedSeen, false);
  assert.deepEqual(result.names, []);
  assert.deepEqual(result.unexpected, []);

  assert.equal(checkNetlog('', ALLOWED).ok, false);
});

test('a truncated log is repaired by closing the brackets', () => {
  const full = netlog([
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policy/abc' }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]);
  const truncated = full.slice(0, -2);

  assert.equal(truncated.endsWith(']}'), false);
  const result = checkNetlog(truncated, ALLOWED);

  assert.equal(result.ok, true);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.names, ['127.0.0.1:30120']);
});

test('a different port on the allowed host fails', () => {
  const result = checkNetlog(netlog([
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policy/abc' }),
    event(3, { address: '127.0.0.1', port: 30121 }),
  ]), ALLOWED);

  assert.equal(result.ok, false);
  assert.ok(result.unexpected.includes('127.0.0.1:30121'));
});
