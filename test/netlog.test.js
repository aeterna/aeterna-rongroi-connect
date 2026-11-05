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
  leftoverFailure,
  LEFTOVER_MAX_BYTES,
} = require('../scripts/run-e2e');

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
        1: 'URL_REQUEST_START_JOB',
        2: 'HOST_RESOLVER_IMPL_REQUEST',
        3: 'TCP_CONNECT',
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
    events.push({
      type: eventType,
      params: connect,
      source: { id: sourceId, type: sourceType },
    });
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
  })), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.unexpected, []);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: true });
  assert.equal(result.names.includes('2001:4860:4860::8888:443'), false);
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
        1: 'URL_REQUEST_START_JOB',
        2: 'HOST_RESOLVER_IMPL_REQUEST',
        3: 'TCP_CONNECT',
        10: 'UDP_CONNECT',
        11: 'HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK',
      },
      logSourceType: {
        1: 'UDP_SOCKET',
        2: 'HOST_RESOLVER_MANAGER',
      },
    },
    events: [
      event(1, { url: POLICY_URL }),
      event(1, { url: REPORT_URL }),
      event(3, { address: '127.0.0.1', port: 30120 }),
      event(11, {}, { id: 2, type: 2 }),
      event(10, { address: '2001:4860:4860::8888', port: 443 }, { id: 1, type: 1 }),
    ],
  }), ALLOWED, REQUIRED_PATHS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.acceptedIpv6Check, { sources: 1, connected: true });
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

test('a leftover hit fails only for a ticket, nonce or kit key', () => {
  assert.equal(leftoverFailure([{ file: 'a', what: 'ticket' }]), true);
  assert.equal(leftoverFailure([{ file: 'a', what: 'nonce' }]), true);
  assert.equal(leftoverFailure([{ file: 'a', what: 'kitPublicKey' }]), true);
  assert.equal(leftoverFailure([{ file: 'a', what: 'origin' }]), false);
  assert.equal(leftoverFailure([]), false);
});
