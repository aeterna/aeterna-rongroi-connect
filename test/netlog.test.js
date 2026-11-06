// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  checkNetlog,
  splitHostPort,
  KNOWN_IPV6_CHECK,
} = require('../scripts/check-netlog');
const {
  searchLeftovers,
  searchLeftoversDetailed,
  leftoverFailure,
  negativeControlMutations,
  reportFileNames,
  runSucceeded,
  runSpecs,
  REAL_RUNS,
  parseArguments,
  kitEnvironment,
  applicationEnv,
  parseHookStates,
  summarizeHookStates,
  listTempTopLevel,
  newTempEntries,
  captureNewTempEntries,
  LEFTOVER_MAX_BYTES,
} = require('../scripts/run-e2e');
const {
  DEFAULT_STATE_TIMEOUT_MS,
  parseStateTimeoutMs,
} = require('../test/hook/test-hook');
const { STANDARD_COLLECTORS } = require('./mock/kit');

const ALLOWED = '127.0.0.1:30120';
const REQUIRED_PATHS = [
  { prefix: '/nakara_rongroi/policy/' },
  { exact: '/nakara_rongroi/report' },
];
const POLICY_URL = 'http://127.0.0.1:30120/nakara_rongroi/policy/abc';
const REPORT_URL = 'http://127.0.0.1:30120/nakara_rongroi/report';
const IPV6_CHECK = '[2001:4860:4860::8888]:443';

function netlog(events) {
  return JSON.stringify({
    constants: {
      logEventTypes: {
        URL_REQUEST_START_JOB: 1,
        HOST_RESOLVER_IMPL_REQUEST: 2,
        TCP_CONNECT: 3,
      },
    },
    events,
  });
}

function event(type, params, source) {
  return source === undefined ? { type, params } : { type, params, source };
}

function baseEvents() {
  return [
    event(1, { url: POLICY_URL }),
    event(1, { url: REPORT_URL }),
  ];
}

function ipv6CheckEvents({
  sourceType = 'UDP_SOCKET',
  sourceId = 77,
  eventType = 'UDP_CONNECT',
  connect = { address: '2001:4860:4860::8888', port: 443 },
  extraEvents = [],
  reachability = true,
  phase,
} = {}) {
  const events = [
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ];

  if (reachability) {
    events.push({
      type: 'HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK',
      params: {},
      source: { id: 88, type: 'HOST_RESOLVER_MANAGER' },
    });
  }

  if (connect !== null) {
    const connectEvent = {
      type: eventType,
      params: connect,
      source: { id: sourceId, type: sourceType },
    };
    if (phase !== undefined) connectEvent.phase = phase;
    events.push(connectEvent);
  }

  return [...events, ...extraEvents];
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

test('destination and logical_destination are read as names', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30120 }),
    event('HTTP_TRANSACTION', { destination: 'http://destination.example:1234' }),
    event('HTTP_TRANSACTION', { logical_destination: 'http://logical.example:5678' }),
    event('HTTP_TRANSACTION', { destination: 'http://127.0.0.1:30120' }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.unexpected, [
    'destination.example:1234',
    'logical.example:5678',
  ]);
  assert.ok(result.names.includes('127.0.0.1:30120'));
  const details = new Map(result.unexpectedDetails.map((detail) => [detail.name, detail]));
  assert.deepEqual(details.get('destination.example:1234').eventTypes, ['HTTP_TRANSACTION']);
  assert.deepEqual(details.get('logical.example:5678').eventTypes, ['HTTP_TRANSACTION']);
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
  assert.equal(result.repaired, true);
  assert.equal(result.allowedSeen, true);
  assert.deepEqual(result.names, ['127.0.0.1:30120']);
});

test('repaired is false when the log parses normally or fails', () => {
  const full = netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]);

  assert.equal(checkNetlog(full, ALLOWED, REQUIRED_PATHS).repaired, false);
  assert.equal(checkNetlog('', ALLOWED, REQUIRED_PATHS).repaired, false);
  assert.equal(checkNetlog('{not json', ALLOWED, REQUIRED_PATHS).repaired, false);
  assert.equal(checkNetlog('null', ALLOWED, REQUIRED_PATHS).repaired, false);
});

test('a different port on the allowed host fails', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30121 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.ok(result.unexpected.includes('127.0.0.1:30121'));
});

test('the known IPv6 reachability check passes with an error result', () => {
  assert.equal(KNOWN_IPV6_CHECK, IPV6_CHECK);

  const result = checkNetlog(netlog(ipv6CheckEvents({
    connect: {
      address: '2001:4860:4860::8888',
      port: 443,
      net_error: -101,
    },
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: false });
  assert.equal(result.names.includes('2001:4860:4860::8888:443'), false);
});

test('the known IPv6 reachability check passes with a successful connect', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    sourceType: 'UDP_CLIENT_SOCKET',
    connect: { address: '[2001:4860:4860::8888]:443' },
    phase: 2,
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: true });
  assert.equal(result.names.includes('2001:4860:4860::8888:443'), false);
});

test('only an end-phase connect with no net_error counts as connected', () => {
  const begin = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: '[2001:4860:4860::8888]:443' },
    phase: 0,
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(begin.ok, true);
  assert.deepEqual(begin.acceptedIpv6Check, { sources: 1, connected: false });

  const end = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: '[2001:4860:4860::8888]:443' },
    phase: 2,
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(end.ok, true);
  assert.deepEqual(end.acceptedIpv6Check, { sources: 1, connected: true });
});

test('a real failed IPv6 probe leaves two accepted sources but is not connected', () => {
  const result = checkNetlog(netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30120 }),
    {
      type: 'HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK',
      params: {},
      source: { id: 88, type: 'HOST_RESOLVER_MANAGER' },
    },
    {
      type: 'UDP_CONNECT',
      params: { address: '[2001:4860:4860::8888]:443' },
      source: { id: 22, type: 'UDP_SOCKET' },
      phase: 1,
    },
    {
      type: 'UDP_CONNECT',
      params: { net_error: -109 },
      source: { id: 22, type: 'UDP_SOCKET' },
      phase: 2,
    },
    {
      type: 'SOCKET_CONNECT',
      params: { address: '[2001:4860:4860::8888]:443', net_error: -109 },
      source: { id: 21, type: 'UDP_SOCKET' },
      phase: 0,
    },
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 2, connected: false });
});

test('the known IPv6 source is not accepted when any allowed event names another address', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    extraEvents: [
      {
        type: 'SOCKET_OPEN',
        params: { address: '192.0.2.10', port: 443 },
        source: { id: 77, type: 'UDP_SOCKET' },
      },
      {
        type: 'SOCKET_OPEN',
        params: { remote_address: '198.51.100.7', remote_port: 443 },
        source: { id: 77, type: 'UDP_SOCKET' },
      },
    ],
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2001:4860:4860::8888:443'));
  assert.ok(result.unexpected.includes('192.0.2.10:443'));
  assert.ok(result.unexpected.includes('198.51.100.7:443'));
});

test('the IPv6 source allowlist keeps only the silent probe event types', () => {
  const extraEvents = [
    'SOCKET_ALIVE',
    'SOCKET_OPEN',
    'SOCKET_CONNECT',
    'UDP_CONNECT',
    'UDP_LOCAL_ADDRESS',
  ].map((type) => ({
    type,
    params: { address: IPV6_CHECK },
    source: { id: 77, type: 'UDP_SOCKET' },
  }));

  const result = checkNetlog(netlog(ipv6CheckEvents({
    extraEvents,
    phase: 2,
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: true });
});

test('a connected probe is accepted when UDP_LOCAL_ADDRESS names the socket local address', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: IPV6_CHECK },
    phase: 2,
    extraEvents: [{
      type: 'UDP_LOCAL_ADDRESS',
      params: { address: '[2600:1f18::5]:50000' },
      source: { id: 77, type: 'UDP_SOCKET' },
    }],
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: true });
});

test('a UDP_CONNECT to another address on the same source is still rejected', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: IPV6_CHECK },
    phase: 2,
    extraEvents: [{
      type: 'UDP_CONNECT',
      params: { address: '[2600:1f18::5]:443' },
      source: { id: 77, type: 'UDP_SOCKET' },
      phase: 2,
    }],
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2600:1f18::5:443'));
});

test('a foreign remote_address on UDP_LOCAL_ADDRESS is still rejected', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: IPV6_CHECK },
    phase: 2,
    extraEvents: [{
      type: 'UDP_LOCAL_ADDRESS',
      params: {
        address: '[2600:1f18::5]:50000',
        remote_address: '198.51.100.7',
        remote_port: 443,
      },
      source: { id: 77, type: 'UDP_SOCKET' },
    }],
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('198.51.100.7:443'));
});

test('IPv6 socket error events are not accepted and are marked as byte transfers', () => {
  for (const type of [
    'UDP_SEND_ERROR',
    'UDP_RECEIVE_ERROR',
    'SOCKET_WRITE_ERROR',
    'SOCKET_READ_ERROR',
  ]) {
    const result = checkNetlog(netlog(ipv6CheckEvents({
      extraEvents: [{
        type,
        params: { address: '2001:4860:4860::8888', port: 443 },
        source: { id: 77, type: 'UDP_SOCKET' },
      }],
    })), ALLOWED, REQUIRED_PATHS);

    assert.equal(result.ok, false, type);
    assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false }, type);
    assert.ok(result.unexpected.includes('2001:4860:4860::8888:443'), type);
    assert.equal(result.unexpectedByteTransfer, true, type);
    assert.ok(result.unexpectedByName['2001:4860:4860::8888:443'].byteTransferTypes
      .includes(type), type);
  }
});

test('the IPv6 address on the wrong port is unexpected', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: '2001:4860:4860::8888', port: 53 },
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2001:4860:4860::8888:53'));
});

test('the known IPv6 address over TCP is unexpected', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    sourceType: 'TCP_SOCKET',
    eventType: 'TCP_CONNECT',
    connect: { address: '2001:4860:4860::8888', port: 443 },
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2001:4860:4860::8888:443'));
});

test('another IPv6 address is unexpected', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    connect: { address: '2001:4860:4860::8889', port: 443 },
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2001:4860:4860::8889:443'));
});

test('the known IPv6 socket is unexpected when it sends bytes', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    extraEvents: [{
      type: 'UDP_BYTES_SENT',
      params: { address: '2001:4860:4860::8888', port: 443 },
      source: { id: 77, type: 'UDP_SOCKET' },
    }],
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2001:4860:4860::8888:443'));
  assert.equal(result.unexpectedByteTransfer, true);
  assert.ok(result.unexpectedDetails.some((detail) => (
    detail.name === '2001:4860:4860::8888:443'
    && detail.byteTransferTypes.includes('UDP_BYTES_SENT')
  )));
});

test('the known IPv6 socket is unexpected without a reachability-check event', () => {
  const result = checkNetlog(netlog(ipv6CheckEvents({
    reachability: false,
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(result.unexpected.includes('2001:4860:4860::8888:443'));
});

test('the policy and report paths are both required', () => {
  const onlyPolicy = checkNetlog(netlog([
    event(1, { url: POLICY_URL }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);
  assert.equal(onlyPolicy.ok, false);
  assert.deepEqual(onlyPolicy.seenPaths, [REQUIRED_PATHS[0]]);
  assert.deepEqual(onlyPolicy.missingPaths, [REQUIRED_PATHS[1]]);

  const onlyReport = checkNetlog(netlog([
    event(1, { url: REPORT_URL }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);
  assert.equal(onlyReport.ok, false);
  assert.deepEqual(onlyReport.seenPaths, [REQUIRED_PATHS[1]]);
  assert.deepEqual(onlyReport.missingPaths, [REQUIRED_PATHS[0]]);

  const neither = checkNetlog(netlog([
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);
  assert.equal(neither.ok, false);
  assert.deepEqual(neither.missingPaths, REQUIRED_PATHS);
});

test('another path under /nakara_rongroi/ satisfies neither requirement', () => {
  const result = checkNetlog(netlog([
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/report/extra' }),
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/policies/abc' }),
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/other' }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.seenPaths, []);
  assert.deepEqual(result.missingPaths, REQUIRED_PATHS);
});

test('the report path must end exactly at /report', () => {
  const result = checkNetlog(netlog([
    event(1, { url: POLICY_URL }),
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/report/' }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, false);
  assert.deepEqual(result.seenPaths, [REQUIRED_PATHS[0]]);
  assert.deepEqual(result.missingPaths, [REQUIRED_PATHS[1]]);
});

test('the chunked report path is the report upload plane', () => {
  const result = checkNetlog(netlog([
    event(1, { url: POLICY_URL }),
    event(1, { url: 'http://127.0.0.1:30120/nakara_rongroi/report/chunk' }),
    event(3, { address: '127.0.0.1', port: 30120 }),
  ]), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.missingPaths, []);
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

test('numeric source and event types resolve through the netlog constants', () => {
  const result = checkNetlog(JSON.stringify({
    constants: {
      logEventTypes: {
        URL_REQUEST_START_JOB: 1,
        HOST_RESOLVER_IMPL_REQUEST: 2,
        TCP_CONNECT: 3,
        UDP_CONNECT: 10,
        HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK: 11,
      },
      logSourceType: {
        UDP_SOCKET: 1,
        HOST_RESOLVER_MANAGER: 2,
      },
    },
    events: [
      event(1, { url: POLICY_URL }),
      event(1, { url: REPORT_URL }),
      event(3, { address: '127.0.0.1', port: 30120 }),
      event(11, {}, { id: 2, type: 2 }),
      { ...event(10, { address: '2001:4860:4860::8888', port: 443 }, { id: 1, type: 1 }), phase: 2 },
    ],
  }), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: true });
});

test('a numeric UDP_SOCKET source is accepted but a numeric TCP_SOCKET source is not', () => {
  const events = [
    event(1, { url: POLICY_URL }),
    event(1, { url: REPORT_URL }),
    event(3, { address: '127.0.0.1', port: 30120 }),
    event(11, {}, { id: 2, type: 2 }),
    { ...event(10, { address: '2001:4860:4860::8888', port: 443 }, { id: 1, type: 1 }), phase: 2 },
  ];
  const constants = (sourceTypeName) => ({
    logEventTypes: {
      URL_REQUEST_START_JOB: 1,
      TCP_CONNECT: 3,
      UDP_CONNECT: 10,
      HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK: 11,
    },
    logSourceType: {
      [sourceTypeName]: 1,
      HOST_RESOLVER_MANAGER: 2,
    },
  });

  const udp = checkNetlog(JSON.stringify({
    constants: constants('UDP_SOCKET'),
    events,
  }), ALLOWED, REQUIRED_PATHS);
  assert.equal(udp.ok, true);
  assert.deepEqual(udp.acceptedIpv6Check, { sources: 1, connected: true });

  const tcp = checkNetlog(JSON.stringify({
    constants: constants('TCP_SOCKET'),
    events,
  }), ALLOWED, REQUIRED_PATHS);
  assert.equal(tcp.ok, false);
  assert.deepEqual(tcp.acceptedIpv6Check, { sources: 0, connected: false });
  assert.ok(tcp.unexpected.includes('2001:4860:4860::8888:443'));
});

test('the leftover search reads UTF-8 and UTF-16LE and skips files over 1 MiB', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leftover-search-'));

  try {
    const text = 'ticket abc123 nonce n-1 key key-1 origin 127.0.0.1:30120';
    const utf8File = path.join(root, 'utf8.txt');
    fs.writeFileSync(utf8File, text, 'utf8');

    const nested = path.join(root, 'nested');
    fs.mkdirSync(nested);
    const utf16File = path.join(nested, 'utf16.bin');
    fs.writeFileSync(utf16File, Buffer.from(text, 'utf16le'));

    const atLimitFile = path.join(root, 'at-limit.bin');
    const atLimit = Buffer.alloc(LEFTOVER_MAX_BYTES);
    atLimit.write('nonce n-1', 0, 'utf8');
    fs.writeFileSync(atLimitFile, atLimit);

    const tooBigFile = path.join(root, 'too-big.bin');
    const tooBig = Buffer.alloc(LEFTOVER_MAX_BYTES + 1);
    tooBig.write('ticket abc123', 0, 'utf8');
    fs.writeFileSync(tooBigFile, tooBig);

    const hits = searchLeftovers([root], {
      ticket: 'abc123',
      nonce: 'n-1',
      kitPublicKey: 'key-1',
      origin: '127.0.0.1:30120',
    });

    const found = hits.map((hit) => {
      const relative = path.relative(root, hit.file).split(path.sep).join('/');
      return `${relative}:${hit.what}`;
    }).sort();
    assert.deepEqual(found, [
      'at-limit.bin:nonce',
      'nested/utf16.bin:kitPublicKey',
      'nested/utf16.bin:nonce',
      'nested/utf16.bin:origin',
      'nested/utf16.bin:ticket',
      'utf8.txt:kitPublicKey',
      'utf8.txt:nonce',
      'utf8.txt:origin',
      'utf8.txt:ticket',
    ]);
    assert.equal(hits.some((hit) => hit.file === tooBigFile), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the leftover search records files it could not search', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'leftover-skip-'));
  const tooBigFile = path.join(root, 'too-big.bin');
  const unreadableFile = path.join(root, 'unreadable.bin');

  try {
    fs.writeFileSync(tooBigFile, Buffer.alloc(LEFTOVER_MAX_BYTES + 1));
    fs.writeFileSync(unreadableFile, 'ticket abc123', 'utf8');

    const originalReadFileSync = fs.readFileSync;
    fs.readFileSync = function readFileSyncWithFailure(file, ...args) {
      if (path.resolve(String(file)) === path.resolve(unreadableFile)) {
        const error = new Error('EACCES: permission denied');
        error.code = 'EACCES';
        throw error;
      }
      return originalReadFileSync.call(fs, file, ...args);
    };

    try {
      const result = searchLeftoversDetailed([root], { ticket: 'abc123' });
      assert.equal(result.searchRan, true);
      assert.deepEqual(result.hits, []);
      assert.deepEqual(result.notSearched, [
        { path: tooBigFile, reason: 'too-large' },
        { path: unreadableFile, reason: 'unreadable' },
      ]);
    } finally {
      fs.readFileSync = originalReadFileSync;
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the leftover search reports whether it built any needles', () => {
  const empty = searchLeftoversDetailed([], {});
  assert.deepEqual(empty, { hits: [], notSearched: [], searchRan: false });

  const options = {};
  assert.deepEqual(searchLeftovers([], {}, options), []);
  assert.equal(options.searchRan, false);
});

test('negative-control mode uses separate report files', () => {
  assert.deepEqual(reportFileNames(false), {
    report: 'e2e-report.json',
    netlog: 'e2e-netlog.json',
  });
  assert.deepEqual(reportFileNames(true), {
    report: 'e2e-negative-report.json',
    netlog: 'e2e-negative-netlog.json',
  });
});

test('a run fails when the netlog was repaired or a leftover search did not run', () => {
  const run = { error: null, timedOut: false, exitCode: 0 };
  const report = {
    kitReceived: true,
    kitHashEqualsRecord: true,
    netlogOk: true,
    netlogRepaired: false,
    leftoverSearchRan: true,
    newTempSearchRan: true,
    negativeControlOk: true,
    leftoverHits: [],
    newTempHits: [],
  };

  assert.equal(runSucceeded(run, report), true);
  assert.equal(runSucceeded(run, { ...report, netlogRepaired: true }), false);
  assert.equal(runSucceeded(run, { ...report, leftoverSearchRan: false }), false);
  assert.equal(runSucceeded(run, { ...report, newTempSearchRan: false }), false);
  assert.equal(runSucceeded({ ...run, exitCode: 1 }, report), false);
});

test('a mismatching Kit hash fails the run', () => {
  const run = { error: null, timedOut: false, exitCode: 0 };
  const report = {
    kitReceived: true,
    kitHashEqualsRecord: true,
    netlogOk: true,
    netlogRepaired: false,
    leftoverSearchRan: true,
    newTempSearchRan: true,
    negativeControlOk: true,
    leftoverHits: [],
    newTempHits: [],
  };

  assert.equal(runSucceeded(run, report), true);
  assert.equal(runSucceeded(run, { ...report, kitHashEqualsRecord: false }), false);
});

function successfulReport(overrides = {}) {
  return {
    sidecar: 'mock',
    kitReceived: true,
    kitHashEqualsRecord: true,
    netlogOk: true,
    netlogRepaired: false,
    leftoverSearchRan: true,
    newTempSearchRan: true,
    negativeControlOk: true,
    leftoverHits: [],
    newTempHits: [],
    ...overrides,
  };
}

test('a real run requires a saved report that matches the run policy', () => {
  const run = { error: null, timedOut: false, exitCode: 0 };
  const posture = successfulReport({
    sidecar: 'real',
    name: 'posture',
    profile: 'posture',
    requireElevation: false,
    collectorCount: 2,
    recordKind: 'rongroi-saved-report',
    rongroi_version: '0.3.0',
    policyProfile: 'posture',
    policyRequireElevation: false,
    policyCollectorCount: 2,
  });

  assert.equal(runSucceeded(run, posture), true);

  // A real-run report that still carries the mock marker proves nothing.
  assert.equal(runSucceeded(run, { ...posture, rongroi_version: 'mock' }), false);
  assert.equal(runSucceeded(run, { ...posture, rongroi_version: '' }), false);
  assert.equal(runSucceeded(run, { ...posture, recordKind: null }), false);

  // The record's policy must be the one the run asked for.
  assert.equal(runSucceeded(run, { ...posture, policyCollectorCount: 3 }), false);
  assert.equal(runSucceeded(run, { ...posture, policyProfile: 'standard' }), false);
  assert.equal(runSucceeded(run, { ...posture, policyRequireElevation: true }), false);

  const standard = {
    ...posture,
    name: 'standard',
    profile: 'standard',
    requireElevation: true,
    collectorCount: 20,
    policyProfile: 'standard',
    policyRequireElevation: true,
    policyCollectorCount: 20,
  };

  assert.equal(runSucceeded(run, standard), true);
  assert.equal(runSucceeded(run, { ...standard, policyCollectorCount: 19 }), false);
});

test('a mock run keeps the existing checks without the real report facts', () => {
  const run = { error: null, timedOut: false, exitCode: 0 };

  assert.equal(runSucceeded(run, successfulReport()), true);
});

test('a ticket in a new top-level temp entry fails the run', () => {
  const run = { error: null, timedOut: false, exitCode: 0 };
  const report = {
    kitReceived: true,
    kitHashEqualsRecord: true,
    netlogOk: true,
    netlogRepaired: false,
    leftoverSearchRan: true,
    newTempSearchRan: true,
    negativeControlOk: true,
    leftoverHits: [],
    newTempHits: [],
  };

  assert.equal(runSucceeded(run, report), true);
  assert.equal(runSucceeded(run, {
    ...report,
    newTempHits: [{ file: 'new-file', what: 'nonce' }],
  }), false);
  // An origin hit in a new file is recorded but does not fail the job.
  assert.equal(runSucceeded(run, {
    ...report,
    newTempHits: [{ file: 'new-file', what: 'origin' }],
  }), true);
});

test('new top-level temp entries are the difference between the before and after listings', () => {
  const first = path.join(os.tmpdir(), 'e2e-before-entry');
  const second = path.join(os.tmpdir(), 'e2e-after-entry');
  const netlog = path.join(os.tmpdir(), 'e2e-netlog-entry');

  assert.deepEqual(newTempEntries([first], [first, second]), [second]);
  assert.deepEqual(newTempEntries(
    [{ path: first }],
    [{ path: first }, { path: second }],
  ), [second]);
  assert.deepEqual(newTempEntries([first], [second, first], [netlog]), [second]);
  assert.deepEqual(newTempEntries([first], [first, netlog], [netlog]), []);
});

test('a new temp file holding a ticket is found and fails the run', () => {
  const ticket = 'c5e2e0123456789abcdef0123456789';
  const before = listTempTopLevel(os.tmpdir());
  const entry = path.join(os.tmpdir(), `e2e-new-entry-${process.pid}-${Date.now()}`);
  const report = {};

  try {
    fs.writeFileSync(entry, `ticket ${ticket}`, 'utf8');
    captureNewTempEntries(report, before, { ticket });

    assert.ok(report.newTempEntries.includes(path.resolve(entry)));
    assert.equal(report.newTempSearchRan, true);
    assert.deepEqual(
      report.newTempHits.filter((hit) => hit.file === path.resolve(entry)),
      [{ file: path.resolve(entry), what: 'ticket' }],
    );
    assert.equal(runSucceeded(
      { error: null, timedOut: false, exitCode: 0 },
      {
        kitReceived: true,
        kitHashEqualsRecord: true,
        netlogOk: true,
        netlogRepaired: false,
        leftoverSearchRan: true,
        newTempSearchRan: report.newTempSearchRan,
        negativeControlOk: true,
        leftoverHits: [],
        newTempHits: report.newTempHits,
      },
    ), false);
  } finally {
    fs.rmSync(entry, { force: true });
  }
});

test('real mode runs posture and Standard without elevation in CI', () => {
  assert.equal(REAL_RUNS.length, 2);
  assert.deepEqual(REAL_RUNS.map((run) => run.name), ['posture', 'standard']);

  const [posture, standard] = REAL_RUNS;
  assert.equal(posture.policy.profile, 'posture');
  assert.equal(posture.policy.required_collectors.length, 2);
  assert.equal(posture.policy.require_elevation, false);

  assert.equal(standard.policy.profile, 'standard');
  assert.equal(standard.policy.required_collectors.length, 20);
  assert.deepEqual(standard.policy.required_collectors, STANDARD_COLLECTORS);
  // A hosted CI runner cannot answer a UAC prompt, so the elevated path is
  // checked by hand on a real PC (lane 3c M1).
  assert.equal(standard.policy.require_elevation, false);
});

test('real mode runs posture and the Standard policy without elevation', () => {
  const specs = runSpecs('real', false);
  assert.deepEqual(specs.map((spec) => spec.name), ['posture', 'standard']);
  assert.equal(specs[0].policy.require_elevation, false);
  assert.equal(specs[1].policy.profile, 'standard');
  assert.equal(specs[1].policy.require_elevation, false);
  assert.deepEqual(specs[1].policy.required_collectors, STANDARD_COLLECTORS);
  assert.equal(STANDARD_COLLECTORS.length, 20);

  assert.deepEqual(runSpecs('mock', false).map((spec) => spec.name), ['mock']);
  assert.deepEqual(runSpecs('real', true).map((spec) => spec.name), ['posture']);
});

test('the Kit child environment carries the policy only when one is given', () => {
  const policy = {
    profile: 'standard',
    required_collectors: STANDARD_COLLECTORS,
    require_elevation: true,
  };

  const withPolicy = kitEnvironment({ policy });
  assert.equal(withPolicy.RONGROI_MOCK_KIT_POLICY, JSON.stringify(policy));
  assert.deepEqual(JSON.parse(withPolicy.RONGROI_MOCK_KIT_POLICY), {
    profile: 'standard',
    required_collectors: STANDARD_COLLECTORS,
    require_elevation: true,
  });

  assert.equal('RONGROI_MOCK_KIT_POLICY' in kitEnvironment({}), false);
  assert.equal('RONGROI_MOCK_KIT_POLICY' in kitEnvironment(), false);
});

test('the Kit child environment drops a policy inherited from the parent', () => {
  const original = process.env.RONGROI_MOCK_KIT_POLICY;
  process.env.RONGROI_MOCK_KIT_POLICY = '{"profile":"posture"}';

  try {
    const env = kitEnvironment({});
    assert.equal('RONGROI_MOCK_KIT_POLICY' in env, false);
  } finally {
    if (original === undefined) {
      delete process.env.RONGROI_MOCK_KIT_POLICY;
    } else {
      process.env.RONGROI_MOCK_KIT_POLICY = original;
    }
  }
});

test('a real run gives the test hook five minutes for a Standard scan', () => {
  const original = process.env.CONNECT_TEST_STATE_TIMEOUT_MS;
  process.env.CONNECT_TEST_STATE_TIMEOUT_MS = '1';

  try {
    const env = applicationEnv({ code: 'pair-code' }, 'real');
    assert.equal(env.CONNECT_TEST_STATE_TIMEOUT_MS, '300000');
    assert.equal(env.CONNECT_TEST_CODE, 'pair-code');
    assert.equal('CONNECT_TEST_NODE' in env, false);
    assert.equal('CONNECT_TEST_SIDECAR' in env, false);
  } finally {
    if (original === undefined) {
      delete process.env.CONNECT_TEST_STATE_TIMEOUT_MS;
    } else {
      process.env.CONNECT_TEST_STATE_TIMEOUT_MS = original;
    }
  }
});

test('a mock run leaves the test hook on its default timeout', () => {
  const original = process.env.CONNECT_TEST_STATE_TIMEOUT_MS;
  process.env.CONNECT_TEST_STATE_TIMEOUT_MS = '1';

  try {
    const env = applicationEnv({ code: 'pair-code' }, 'mock');
    assert.equal('CONNECT_TEST_STATE_TIMEOUT_MS' in env, false);
    assert.equal(env.CONNECT_TEST_NODE, process.execPath);
    assert.ok(env.CONNECT_TEST_SIDECAR.endsWith(path.join('test', 'mock', 'sidecar.js')));
  } finally {
    if (original === undefined) {
      delete process.env.CONNECT_TEST_STATE_TIMEOUT_MS;
    } else {
      process.env.CONNECT_TEST_STATE_TIMEOUT_MS = original;
    }
  }
});

test('the test hook reads a positive integer state timeout', () => {
  assert.equal(DEFAULT_STATE_TIMEOUT_MS, 60 * 1000);
  assert.equal(parseStateTimeoutMs('300000'), 300000);
  assert.equal(parseStateTimeoutMs('1'), 1);
  assert.equal(parseStateTimeoutMs(' 45000 '), 45000);
});

test('an invalid state timeout falls back to the sixty second default', () => {
  for (const value of [
    undefined,
    null,
    '',
    ' ',
    'not-a-number',
    '0',
    '000',
    '-1',
    '-60000',
    '1.5',
    'NaN',
    'Infinity',
    '12x',
  ]) {
    assert.equal(parseStateTimeoutMs(value), 60 * 1000, String(value));
  }
});

test('the hook state lines measure a scan that left the scanning state', () => {
  const states = parseHookStates([
    '{"name":"consent","observedAt":1000}',
    '[hook] a line that is not a state',
    '{"name":"scanning","observedAt":2000}',
    '{"name":"hash","observedAt":32000}',
  ].join('\n'));

  assert.deepEqual(summarizeHookStates(states), {
    scanningSeconds: 30,
    lastState: 'hash',
  });
});

test('a failed scan is measured up to the hook failure line', () => {
  const states = parseHookStates([
    '{"name":"scanning","observedAt":2000}',
    '{"name":"scanning","observedAt":62000,"failed":true}',
  ].join('\n'));

  assert.deepEqual(summarizeHookStates(states), {
    scanningSeconds: 60,
    lastState: 'scanning',
  });
});

test('a run with no observed scanning state records null seconds', () => {
  assert.deepEqual(summarizeHookStates([]), {
    scanningSeconds: null,
    lastState: null,
  });
  assert.deepEqual(summarizeHookStates([
    { name: 'done', observedAt: 5, failed: false },
  ]), {
    scanningSeconds: null,
    lastState: 'done',
  });
});

test('--sidecar selects real by default and accepts real or mock', () => {
  const fallback = parseArguments(['dist/test']);
  assert.equal(fallback.error, null);
  assert.equal(fallback.sidecar, 'real');
  assert.equal(fallback.buildDir, 'dist/test');
  assert.equal(fallback.negativeControl, false);

  const mock = parseArguments(['dist/test', '--sidecar', 'mock']);
  assert.equal(mock.error, null);
  assert.equal(mock.sidecar, 'mock');
  assert.equal(mock.buildDir, 'dist/test');

  const real = parseArguments(['--sidecar=real', 'dist/test']);
  assert.equal(real.error, null);
  assert.equal(real.sidecar, 'real');
  assert.equal(real.buildDir, 'dist/test');

  const negative = parseArguments(['dist/test', '--sidecar', 'mock', '--negative-control']);
  assert.equal(negative.error, null);
  assert.equal(negative.sidecar, 'mock');
  assert.equal(negative.negativeControl, true);

  assert.notEqual(parseArguments(['dist/test', '--sidecar']).error, null);
  assert.notEqual(parseArguments(['dist/test', '--sidecar', 'tape']).error, null);
  assert.notEqual(parseArguments(['dist/test', '--sidecar=']).error, null);
  assert.notEqual(parseArguments([]).error, null);
});

test('negative-control mutations change every probe port and paired host', () => {
  const text = `first ${IPV6_CHECK} second ${IPV6_CHECK} host 127.0.0.1 and 127.0.0.1`;
  const result = negativeControlMutations(text);

  assert.equal(result.ipv6, text.split(IPV6_CHECK).join('[2001:4860:4860::8888]:444'));
  assert.equal(result.host, text.split('127.0.0.1').join('127.0.0.2'));
  assert.equal(result.ipv6.includes(IPV6_CHECK), false);
  assert.equal(result.host.includes('127.0.0.1'), false);
  assert.ok(result.ipv6.includes('127.0.0.1'));
  assert.ok(result.host.includes(IPV6_CHECK));
});

test('the negative-control mutations turn a passing netlog into a failure', () => {
  const log = netlog([
    ...baseEvents(),
    event(3, { address: '127.0.0.1', port: 30120 }),
    {
      type: 'HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK',
      params: {},
      source: { id: 88, type: 'HOST_RESOLVER_MANAGER' },
    },
    {
      type: 'UDP_CONNECT',
      params: { address: IPV6_CHECK },
      source: { id: 77, type: 'UDP_SOCKET' },
      phase: 2,
    },
  ]);

  assert.equal(checkNetlog(log, ALLOWED, REQUIRED_PATHS).ok, true);

  const mutations = negativeControlMutations(log);
  assert.equal(checkNetlog(mutations.ipv6, ALLOWED, REQUIRED_PATHS).ok, false);
  assert.equal(checkNetlog(mutations.host, ALLOWED, REQUIRED_PATHS).ok, false);
});

test('a leftover hit fails only for a ticket, nonce or kit key', () => {
  assert.equal(leftoverFailure([{ file: 'a', what: 'ticket' }]), true);
  assert.equal(leftoverFailure([{ file: 'a', what: 'nonce' }]), true);
  assert.equal(leftoverFailure([{ file: 'a', what: 'kitPublicKey' }]), true);
  assert.equal(leftoverFailure([{ file: 'a', what: 'origin' }]), false);
  assert.equal(leftoverFailure([]), false);
});
