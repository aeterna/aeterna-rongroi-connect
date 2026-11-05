// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { checkNetlog, splitHostPort } = require('../scripts/check-netlog');

const ALLOWED = '127.0.0.1:30120';
const REQUIRED_PATHS = ['/nakara_rongroi/policy/', '/nakara_rongroi/report/'];
const POLICY_URL = 'http://127.0.0.1:30120/nakara_rongroi/policy/abc';
const REPORT_URL = 'http://127.0.0.1:30120/nakara_rongroi/report';

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

function baseEvents() {
  return [
    event(1, { url: POLICY_URL }),
    event(1, { url: REPORT_URL }),
  ];
}

test('a log that names only the allowed host and port passes', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(2, { host: '127.0.0.1', dns_query_type: 0, port: 30120 }),
    event(3, { address: '127.0.0.1', port: 30120 }),
    event(3, { remote_address: '127.0.0.1:30120' }),
    event(3, { remote_address: '127.0.0.1', remote_port: 30120 }),
    event(1, { url: 'file:///C:/Rongroi/resources/app.asar/index.html' }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.unexpectedDetails, []);
  assert.deepEqual(result.names, ['127.0.0.1:30120']);
  assert.deepEqual(result.missingPaths, []);
});

test('scheme, path and brackets normalise to the paired host', () => {
  assert.deepEqual(splitHostPort('http://127.0.0.1:50932/nakara_rongroi/policy/abc'), {
    host: '127.0.0.1',
    port: '50932',
  });
  assert.deepEqual(splitHostPort('127.0.0.1:50932/nakara_rongroi/report'), {
    host: '127.0.0.1',
    port: '50932',
  });
  assert.deepEqual(splitHostPort('127.0.0.1'), { host: '127.0.0.1', port: null });
  assert.deepEqual(splitHostPort('[::1]:50932/path'), { host: '::1', port: '50932' });

  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(1, { request_url: '127.0.0.1:30120/nakara_rongroi/report' }),
    event(2, { host: '127.0.0.1', port: 30120 }),
    event(3, { address: '127.0.0.1', port: 30120 }),
    event(3, { remote_address: '[127.0.0.1]:30120' }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.ok(result.names.includes('127.0.0.1:30120'));
});

test('bracketed IPv6 with a port normalises to the paired host', () => {
  const result = checkNetlog(netlog([
    event(1, { url: 'http://[::1]:50932/nakara_rongroi/policy/abc' }),
    event(1, { url: 'http://[::1]:50932/nakara_rongroi/report' }),
    event(3, { remote_address: '[::1]:50932' }),
  ]), '[::1]:50932', REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.names, ['::1:50932']);
});

test('address_list, group_id, proxy_server, request_url and location are read', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event('HOST_RESOLVER_IMPL_JOB', { address_list: ['evil.example:1234'] }),
    event('TCP_CONNECT', { group_id: 'other.example:1234' }),
    event('PROXY_CONFIG_CHANGED', { proxy_server: 'http://proxy.example:8080' }),
    event('PROXY_CONFIG_CHANGED', { proxy_server: 'DIRECT' }),
    event('URL_REQUEST_START_JOB', { request_url: 'http://request.example/x' }),
    event('URL_REQUEST_REDIRECTED', { location: 'http://location.example/x' }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.unexpected, [
    'evil.example:1234',
    'location.example:80',
    'other.example:1234',
    'proxy.example:8080',
    'request.example:80',
  ]);

  const details = new Map(result.unexpectedDetails.map((detail) => [detail.name, detail]));
  assert.deepEqual(details.get('evil.example:1234').eventTypes, ['HOST_RESOLVER_IMPL_JOB']);
  assert.deepEqual(details.get('other.example:1234').eventTypes, ['TCP_CONNECT']);
  assert.deepEqual(details.get('proxy.example:8080').eventTypes, ['PROXY_CONFIG_CHANGED']);
  assert.deepEqual(details.get('request.example:80').eventTypes, ['URL_REQUEST_START_JOB']);
  assert.deepEqual(details.get('location.example:80').eventTypes, ['URL_REQUEST_REDIRECTED']);
  for (const detail of details.values()) assert.equal(detail.byteTransfer, false);
});

test('each unexpected name reports its event types and whether bytes moved', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event('TCP_CONNECT', { remote_address: 'evil.example:4444' }),
    event('SSL_BYTES_SENT', { remote_address: 'evil.example:4444' }),
    event('URL_REQUEST_START_JOB', { url: 'http://evil.example:4444/x' }),
    event('HOST_RESOLVER_IMPL_REQUEST', { host: 'wpad' }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.unexpected, ['evil.example:4444', 'wpad']);
  assert.equal(result.unexpectedByteTransfer, true);

  const bytes = result.unexpectedDetails.find((detail) => detail.name === 'evil.example:4444');
  assert.deepEqual(bytes.eventTypes, [
    'SSL_BYTES_SENT',
    'TCP_CONNECT',
    'URL_REQUEST_START_JOB',
  ]);
  assert.equal(bytes.byteTransfer, true);
  assert.deepEqual(bytes.byteTransferTypes, ['SSL_BYTES_SENT']);

  const nameOnly = result.unexpectedDetails.find((detail) => detail.name === 'wpad');
  assert.deepEqual(nameOnly.eventTypes, ['HOST_RESOLVER_IMPL_REQUEST']);
  assert.equal(nameOnly.byteTransfer, false);
});

test('a wpad host resolution fails', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(2, { host: 'wpad', dns_query_type: 0 }),
    event(2, { host: 'wpad', dns_query_type: 0 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.unexpected, ['wpad']);
  assert.deepEqual(result.unexpectedDetails[0].eventTypes, ['HOST_RESOLVER_IMPL_REQUEST']);
});

test('a redirector.gvt1.com request fails', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(1, { url: 'http://redirector.gvt1.com/edgedl/chrome/dict/en-us-8-0.bdic' }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.ok(result.unexpected.some((name) => name.startsWith('redirector.gvt1.com')));
});

test('an empty log fails because the allowed host never appears', () => {
  const result = checkNetlog(netlog([]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.equal(result.allowedSeen, false);
  assert.deepEqual(result.names, []);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.missingPaths, REQUIRED_PATHS);

  assert.equal(checkNetlog('', ALLOWED, REQUIRED_PATHS).ok, false);
});

test('a truncated log is repaired by closing the brackets', () => {
  const full = netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]);
  const truncated = full.slice(0, -2);

  assert.equal(truncated.endsWith(']}'), false);
  const result = checkNetlog(truncated, ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.names, ['127.0.0.1:30120']);
});

test('a different port on the allowed host fails', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30121 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.ok(result.unexpected.includes('127.0.0.1:30121'));
});

test('the policy and report paths are both required', () => {
  const onlyPolicy = checkNetlog(netlog([
    event(1, { url: POLICY_URL }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);
  assert.equal(onlyPolicy.ok, false);
  assert.deepEqual(onlyPolicy.seenPaths, ['/nakara_rongroi/policy/']);
  assert.deepEqual(onlyPolicy.missingPaths, ['/nakara_rongroi/report/']);

  const onlyReport = checkNetlog(netlog([
    event(1, { url: REPORT_URL }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);
  assert.equal(onlyReport.ok, false);
  assert.deepEqual(onlyReport.seenPaths, ['/nakara_rongroi/report/']);
  assert.deepEqual(onlyReport.missingPaths, ['/nakara_rongroi/policy/']);

  const neither = checkNetlog(netlog([
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);
  assert.equal(neither.ok, false);
  assert.deepEqual(neither.missingPaths, REQUIRED_PATHS);
});

test('the required paths can arrive through request_url and location', () => {
  const result = checkNetlog(netlog([
    event('URL_REQUEST_START_JOB', { request_url: POLICY_URL }),
    event('URL_REQUEST_REDIRECTED', { location: REPORT_URL }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.missingPaths, []);
});
