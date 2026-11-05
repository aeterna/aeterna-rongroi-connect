// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Read Chromium's netlog JSON and list every host it names.  The proof in ADR
// 0001 section 2 fails when a name other than the paired host and port appears,
// when the paired host never appears, or when the flow did not request both the
// policy and the report paths.  The owner accepted one narrow exception:
// Chromium's silent UDP probe of the fixed IPv6 reachability address.

const DEFAULT_PORTS = {
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
};

const DEFAULT_REQUIRED_PATHS = [
  { prefix: '/nakara_rongroi/policy/' },
  { exact: '/nakara_rongroi/report' },
];
const KNOWN_IPV6_CHECK = '[2001:4860:4860::8888]:443';
const KNOWN_IPV6_HOST = '2001:4860:4860::8888';
const KNOWN_IPV6_PORT = '443';
const CHUNKED_REPORT_PATH = '/nakara_rongroi/report/chunk';
const UDP_SOURCE_TYPES = new Set(['UDP_SOCKET', 'UDP_CLIENT_SOCKET']);
const REACHABILITY_CHECK_TYPE = 'HOST_RESOLVER_MANAGER_IPV6_REACHABILITY_CHECK';
const BYTE_TRANSFER_TYPE = /(?:^|_)BYTES(?:_|$)/;

function normalizeHost(value) {
  return String(value)
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

// Strip a scheme, a path, a query, a fragment and IPv6 brackets before
// comparing.  http://127.0.0.1:50932/p, 127.0.0.1:50932 and 127.0.0.1 all
// leave the paired host behind.
function splitHostPort(value) {
  let text = String(value ?? '').trim();
  if (text === '') return null;

  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text);
  if (scheme !== null) {
    try {
      const parsed = new URL(text);
      if (parsed.hostname !== '') {
        const host = normalizeHost(parsed.hostname);
        const port = parsed.port !== ''
          ? parsed.port
          : (DEFAULT_PORTS[parsed.protocol] ?? null);
        return { host, port };
      }
    } catch {
      // Fall through and strip the scheme by hand.
    }
    text = text.slice(scheme[0].length);
  }

  if (text.startsWith('//')) text = text.slice(2);

  const cut = text.search(/[\/?#]/);
  if (cut !== -1) text = text.slice(0, cut);
  if (text === '') return null;

  if (text.startsWith('[')) {
    const match = /^\[([^\]]+)\](?::(\d+))?$/.exec(text);
    if (match !== null) {
      return { host: normalizeHost(match[1]), port: match[2] ?? null };
    }
    return { host: normalizeHost(text), port: null };
  }

  const colons = (text.match(/:/g) || []).length;
  if (colons === 1) {
    const [host, port] = text.split(':');
    if (host !== '' && /^\d+$/.test(port)) {
      return { host: normalizeHost(host), port };
    }
    return { host: normalizeHost(text), port: null };
  }

  // No colon, or an IPv6 address with several: treat the whole value as a host.
  return { host: normalizeHost(text), port: null };
}

function formatName(host, port) {
  if (host === null || host === undefined || host === '') return null;
  return port === null || port === undefined || port === '' ? host : `${host}:${port}`;
}

function normalizeAllowedHostPort(value) {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return { host: '127.0.0.1', port: String(value), display: `127.0.0.1:${value}` };
  }

  const parts = splitHostPort(value);
  if (parts === null) throw new Error('host is required');

  if (parts.port !== null) {
    return {
      host: parts.host,
      port: parts.port,
      display: formatName(parts.host, parts.port),
    };
  }

  if (/^\d+$/.test(parts.host)) {
    return {
      host: '127.0.0.1',
      port: parts.host,
      display: `127.0.0.1:${parts.host}`,
    };
  }

  return { host: parts.host, port: null, display: parts.host };
}

function isAllowedName(name, allowed) {
  const candidates = [];
  const parts = splitHostPort(name);
  if (parts !== null) candidates.push(parts);

  // A bracketless IPv6 address followed by a port is ambiguous with a plain
  // IPv6 address.  Try the trailing-port reading as well.
  const text = String(name ?? '').trim();
  const lastColon = text.lastIndexOf(':');
  if (lastColon > 0 && /^\d+$/.test(text.slice(lastColon + 1))) {
    candidates.push({
      host: normalizeHost(text.slice(0, lastColon)),
      port: text.slice(lastColon + 1),
    });
  }

  for (const candidate of candidates) {
    if (candidate.host !== allowed.host) continue;
    if (allowed.port === null) return true;
    // A HOST_RESOLVER event often names only the host; that is still the
    // paired host and is not a different destination.
    if (candidate.port === null || candidate.port === allowed.port) return true;
  }
  return false;
}

function urlName(value) {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    return null;
  }
  if (parsed.protocol === 'file:') return null;
  if (parsed.hostname === '') return null;

  const host = normalizeHost(parsed.hostname);
  const port = parsed.port !== '' ? parsed.port : (DEFAULT_PORTS[parsed.protocol] ?? null);
  return formatName(host, port);
}

function hostName(value, port) {
  if (typeof value !== 'string') return null;
  const parts = splitHostPort(value);
  if (parts === null) return null;
  const effectivePort = parts.port !== null
    ? parts.port
    : (port === undefined || port === null ? null : String(port));
  return formatName(parts.host, effectivePort);
}

function addressName(value, port) {
  return hostName(value, port);
}

function endpointName(value, port) {
  if (typeof value !== 'string') return null;
  let text = value.trim();
  if (/^direct$/i.test(text)) return null;

  // Chromium names a proxy as "PROXY host:port" (or SOCKS/HTTP ...); read the
  // endpoint and ignore the directive word.
  const proxy = /^(?:PROXY|HTTP|HTTPS|SOCKS|SOCKS4|SOCKS5)\s+(.+)$/i.exec(text);
  if (proxy !== null) text = proxy[1].split(';')[0].trim();

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const fromUrl = urlName(text);
    return fromUrl;
  }
  // Reject non-network schemes such as data: and file: without mistaking a
  // host:port pair (wpad:80) for a scheme.
  if (/^[a-z][a-z0-9+.-]*:/i.test(text)
      && !/^[a-z][a-z0-9+.-]*:\d+(?:[\/?#].*)?$/i.test(text)) {
    return null;
  }
  return hostName(text, port);
}

function eventTypeName(constants, type) {
  if (typeof type === 'string') return type;
  const types = constants && constants.logEventTypes;
  if (Array.isArray(types)) return types[type] ?? String(type);
  if (types !== null && typeof types === 'object') {
    return types[type] ?? types[String(type)] ?? String(type);
  }
  return String(type);
}

function sourceTypeName(constants, type) {
  if (typeof type === 'string') return type;
  const types = constants && constants.logSourceType;
  if (Array.isArray(types)) return types[type] ?? String(type);
  if (types !== null && typeof types === 'object') {
    return types[type] ?? types[String(type)] ?? String(type);
  }
  return String(type);
}

function sourceKey(source) {
  if (source === null || typeof source !== 'object') return null;
  const type = source.type === undefined || source.type === null ? '' : source.type;
  if (source.id !== undefined && source.id !== null) return `id:${source.id}:type:${type}`;
  try {
    return `source:${JSON.stringify(source)}`;
  } catch {
    return null;
  }
}

function pathnameOf(value) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (text === '') return null;

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    try {
      return new URL(text).pathname;
    } catch {
      // Fall through to the hand parser.
    }
  }

  let rest = text;
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(rest);
  if (scheme !== null) rest = rest.slice(scheme[0].length);
  else if (rest.startsWith('//')) rest = rest.slice(2);

  // A non-hierarchical scheme such as data: has no pathname to match.
  if (/^[a-z][a-z0-9+.-]*:/i.test(rest)
      && !/^[a-z][a-z0-9+.-]*:\d+(?:[\/?#]|$)/i.test(rest)) {
    return null;
  }

  const slash = rest.search(/[\/?#]/);
  if (slash === -1) return '/';
  const path = rest.slice(slash);
  const end = path.search(/[?#]/);
  return end === -1 ? path : path.slice(0, end);
}

function pathRuleKey(rule) {
  return typeof rule.exact === 'string'
    ? `exact:${rule.exact}`
    : `prefix:${rule.prefix}`;
}

function pathMatches(rule, pathname) {
  if (typeof pathname !== 'string') return false;
  if (typeof rule.exact === 'string') {
    if (pathname === rule.exact) return true;
    // upload-plan.js sends report/chunk when the sealed report is too large
    // for one POST; that is the report endpoint, not a different path.
    return rule.exact === '/nakara_rongroi/report' && pathname === CHUNKED_REPORT_PATH;
  }
  if (typeof rule.prefix === 'string') {
    const prefix = rule.prefix;
    if (pathname === prefix) return true;
    // A prefix without a trailing slash still stops at a segment boundary, so
    // /report does not accept /report-other.
    return prefix.endsWith('/')
      ? pathname.startsWith(prefix)
      : pathname.startsWith(`${prefix}/`);
  }
  return false;
}

function normalizePathRule(value) {
  if (typeof value === 'string') {
    return value.endsWith('/') ? { prefix: value } : { exact: value };
  }
  if (value !== null && typeof value === 'object') {
    if (typeof value.exact === 'string') return { exact: value.exact };
    if (typeof value.prefix === 'string') return { prefix: value.prefix };
  }
  return { exact: String(value) };
}

function parseNetlog(input) {
  if (Buffer.isBuffer(input)) input = input.toString('utf8');
  if (input !== null && typeof input === 'object') return input;

  const text = typeof input === 'string' ? input : String(input ?? '');
  if (text.trim() === '') return { constants: {}, events: [] };

  try {
    return JSON.parse(text);
  } catch {
    // Chromium may exit before it writes the closing brackets.  Close them
    // and try again; a trailing comma is dropped first for the same reason.
  }

  const trimmed = text.trimEnd();
  const base = trimmed.endsWith(',') ? trimmed.slice(0, -1) : trimmed;
  for (const suffix of [']}', '}', ']']) {
    try {
      return JSON.parse(base + suffix);
    } catch {
      // Try the next closing shape.
    }
  }

  throw new Error('netlog is not valid JSON');
}

function requiredPathList(requiredPaths) {
  if (requiredPaths === undefined || requiredPaths === null) {
    return DEFAULT_REQUIRED_PATHS.map(normalizePathRule);
  }
  const values = Array.isArray(requiredPaths) ? requiredPaths : [requiredPaths];
  return values.map(normalizePathRule);
}

function emptyResult(allowed, paths, error) {
  return {
    ok: false,
    allowedHostPort: allowed === null ? null : allowed.display,
    acceptedIpv6Check: { sources: 0, connected: false },
    names: [],
    unexpected: [],
    unexpectedDetails: [],
    unexpectedEvents: [],
    unexpectedByName: {},
    unexpectedByteTransfer: false,
    byteTransfer: false,
    allowedSeen: false,
    requestUrls: [],
    requiredPaths: paths,
    seenPaths: [],
    missingPaths: paths.slice(),
    error,
  };
}

function endpointFromValue(value, port) {
  const parts = splitHostPort(value);
  if (parts === null) return null;
  return {
    host: parts.host,
    port: parts.port !== null
      ? parts.port
      : (port === undefined || port === null ? null : String(port)),
  };
}

function isConnectEvent(typeName) {
  return /(?:^|_)CONNECT(?:_|$)/.test(typeName);
}

function connectSucceeded(params) {
  const value = params.net_error;
  if (value === undefined || value === null) return true;
  if (typeof value === 'number') return value === 0;
  if (typeof value === 'string') return value === '' || value === '0' || /^OK$/i.test(value);
  return false;
}

function connectEndpoints(params) {
  const eventPort = params.port ?? params.remote_port ?? null;
  const values = [];

  if (typeof params.address === 'string') {
    values.push([params.address, params.port ?? eventPort]);
  }
  if (typeof params.remote_address === 'string') {
    values.push([params.remote_address, params.remote_port ?? eventPort]);
  }
  if (typeof params.host === 'string') values.push([params.host, eventPort]);
  if (typeof params.ip === 'string') values.push([params.ip, eventPort]);

  if (params.address_list !== undefined) {
    const items = Array.isArray(params.address_list) ? params.address_list : [params.address_list];
    for (const item of items) {
      if (typeof item === 'string') {
        values.push([item, eventPort]);
      } else if (item !== null && typeof item === 'object') {
        const port = item.port ?? eventPort;
        for (const key of ['address', 'ip', 'host', 'name', 'value']) {
          if (typeof item[key] === 'string') {
            values.push([item[key], port]);
            break;
          }
        }
      }
    }
  }

  const endpoints = [];
  for (const [value, port] of values) {
    const endpoint = endpointFromValue(value, port);
    if (endpoint !== null) endpoints.push(endpoint);
  }
  return endpoints;
}

function isKnownIpv6Endpoint(endpoint) {
  return endpoint !== null
    && endpoint.host === KNOWN_IPV6_HOST
    && endpoint.port === KNOWN_IPV6_PORT;
}

// Pure check of one netlog.  json is the file text (or an already parsed
// object); host is "127.0.0.1:<port>" or just the port.  requiredPaths are the
// URL paths the flow must have requested.
function checkNetlog(json, host, requiredPaths) {
  const paths = requiredPathList(requiredPaths);

  let allowed;
  try {
    allowed = normalizeAllowedHostPort(host);
  } catch (error) {
    return emptyResult(null, paths, error.message);
  }

  let netlog;
  try {
    netlog = parseNetlog(json);
  } catch (error) {
    return emptyResult(allowed, paths, error.message);
  }

  const constants = netlog.constants ?? {};
  const events = Array.isArray(netlog.events) ? netlog.events : [];
  const names = new Set();
  const unexpected = new Set();
  const nameEvents = new Map();
  const requestUrls = new Set();
  const seenPaths = new Set();
  let allowedSeen = false;

  function notePath(value) {
    const pathname = pathnameOf(value);
    if (pathname === null) return;
    for (const rule of paths) {
      if (pathMatches(rule, pathname)) seenPaths.add(pathRuleKey(rule));
    }
  }

  function record(name, typeName, byteTransfer) {
    if (typeof name !== 'string' || name === '') return;
    names.add(name);
    let entry = nameEvents.get(name);
    if (entry === undefined) {
      entry = { eventTypes: new Set(), byteTypes: new Set() };
      nameEvents.set(name, entry);
    }
    entry.eventTypes.add(typeName);
    if (byteTransfer) entry.byteTypes.add(typeName);

    if (isAllowedName(name, allowed)) {
      allowedSeen = true;
    } else {
      unexpected.add(name);
    }
  }

  function recordAddressList(value, typeName, byteTransfer, eventPort) {
    const items = Array.isArray(value) ? value : [value];
    for (const item of items) {
      if (typeof item === 'string') {
        record(endpointName(item, eventPort), typeName, byteTransfer);
      } else if (item !== null && typeof item === 'object') {
        const port = item.port ?? eventPort;
        for (const key of ['address', 'ip', 'host', 'name', 'value']) {
          if (typeof item[key] === 'string') {
            record(endpointName(item[key], port), typeName, byteTransfer);
            break;
          }
        }
      }
    }
  }

  // The one accepted non-paired destination: Chromium's host resolver opens a
  // UDP socket, connects it to a fixed IPv6 address to learn whether IPv6 is
  // reachable, and sends no packet.  Identify that source before walking the
  // events for names, so only a complete, silent source is exempted.
  const sourceInfo = new Map();
  let hasReachabilityCheck = false;

  for (const event of events) {
    if (event === null || typeof event !== 'object') continue;
    const typeName = eventTypeName(constants, event.type);
    if (typeName === REACHABILITY_CHECK_TYPE) hasReachabilityCheck = true;

    const key = sourceKey(event.source);
    let entry = null;
    if (key !== null) {
      entry = sourceInfo.get(key);
      if (entry === undefined) {
        entry = {
          key,
          sourceType: sourceTypeName(constants, event.source.type),
          byteTransfer: false,
          knownConnect: false,
          otherConnect: false,
          connectSuccess: false,
        };
        sourceInfo.set(key, entry);
      }
      if (BYTE_TRANSFER_TYPE.test(typeName)) entry.byteTransfer = true;
    }

    const params = event.params;
    if (params === null || typeof params !== 'object' || Array.isArray(params)) continue;

    if (entry !== null && isConnectEvent(typeName)) {
      const endpoints = connectEndpoints(params);
      if (endpoints.some(isKnownIpv6Endpoint)) {
        entry.knownConnect = true;
        if (connectSucceeded(params)) entry.connectSuccess = true;
      }
      if (endpoints.some((endpoint) => !isKnownIpv6Endpoint(endpoint))) {
        entry.otherConnect = true;
      }
    }
  }

  const acceptedSources = [...sourceInfo.values()].filter((entry) => (
    UDP_SOURCE_TYPES.has(entry.sourceType)
    && entry.knownConnect
    && !entry.otherConnect
    && !entry.byteTransfer
    && hasReachabilityCheck
  ));
  const acceptedSourceKeys = new Set(acceptedSources.map((entry) => entry.key));
  const acceptedIpv6Check = {
    sources: acceptedSources.length,
    connected: acceptedSources.some((entry) => entry.connectSuccess),
  };

  for (const event of events) {
    if (event === null || typeof event !== 'object') continue;
    const eventSourceKey = sourceKey(event.source);
    if (eventSourceKey !== null && acceptedSourceKeys.has(eventSourceKey)) continue;

    const params = event.params;
    if (params === null || typeof params !== 'object' || Array.isArray(params)) continue;

    const typeName = eventTypeName(constants, event.type);
    const byteTransfer = BYTE_TRANSFER_TYPE.test(typeName);
    const isHostResolver = /^HOST_RESOLVER_/.test(typeName);
    const eventPort = params.port ?? null;

    if (typeof params.url === 'string') {
      record(endpointName(params.url, eventPort), typeName, byteTransfer);
      requestUrls.add(params.url);
      notePath(params.url);
    }
    if (typeof params.request_url === 'string') {
      record(endpointName(params.request_url, eventPort), typeName, byteTransfer);
      requestUrls.add(params.request_url);
      notePath(params.request_url);
    }
    if (typeof params.host === 'string') {
      // HOST_RESOLVER_* events carry the port beside the host; the other
      // events that name a host use the remote port member.
      record(
        hostName(params.host, isHostResolver ? eventPort : (params.remote_port ?? eventPort)),
        typeName,
        byteTransfer,
      );
    }
    if (typeof params.address === 'string') {
      record(addressName(params.address, eventPort), typeName, byteTransfer);
    }
    if (typeof params.remote_address === 'string') {
      record(
        addressName(params.remote_address, params.remote_port ?? eventPort),
        typeName,
        byteTransfer,
      );
    }
    if (params.address_list !== undefined) {
      recordAddressList(params.address_list, typeName, byteTransfer, eventPort);
    }
    if (typeof params.group_id === 'string' && !/^\s*\d+\s*$/.test(params.group_id)) {
      record(endpointName(params.group_id, eventPort), typeName, byteTransfer);
    }
    if (typeof params.proxy_server === 'string') {
      record(endpointName(params.proxy_server, eventPort), typeName, byteTransfer);
    }
    if (typeof params.location === 'string') {
      record(endpointName(params.location, eventPort), typeName, byteTransfer);
      requestUrls.add(params.location);
      notePath(params.location);
    }
  }

  const unexpectedNames = [...unexpected].sort();
  const unexpectedDetails = unexpectedNames.map((name) => {
    const entry = nameEvents.get(name);
    const eventTypes = [...entry.eventTypes].sort();
    return {
      name,
      eventTypes,
      events: eventTypes,
      byteTransfer: entry.byteTypes.size > 0,
      byteTransferTypes: [...entry.byteTypes].sort(),
    };
  });

  const missingPaths = paths.filter((path) => !seenPaths.has(pathRuleKey(path)));
  const anyByteTransfer = unexpectedDetails.some((detail) => detail.byteTransfer);

  return {
    ok: unexpectedNames.length === 0 && allowedSeen && missingPaths.length === 0,
    allowedHostPort: allowed.display,
    acceptedIpv6Check,
    names: [...names].sort(),
    unexpected: unexpectedNames,
    unexpectedDetails,
    unexpectedEvents: unexpectedDetails,
    unexpectedByName: Object.fromEntries(unexpectedDetails.map((detail) => [
      detail.name,
      {
        eventTypes: detail.eventTypes,
        byteTransfer: detail.byteTransfer,
        byteTransferTypes: detail.byteTransferTypes,
      },
    ])),
    unexpectedByteTransfer: anyByteTransfer,
    byteTransfer: anyByteTransfer,
    allowedSeen,
    requestUrls: [...requestUrls].sort(),
    requiredPaths: paths,
    seenPaths: paths.filter((path) => seenPaths.has(pathRuleKey(path))),
    missingPaths,
    error: null,
  };
}

function main(argv) {
  const [file, host, ...requiredPaths] = argv.filter((value) => value !== '--');
  if (file === undefined || host === undefined) {
    console.error('usage: node scripts/check-netlog.js <netlog.json> <127.0.0.1:port> [requiredPath …]');
    process.exitCode = 2;
    return;
  }

  const fs = require('node:fs');
  const result = checkNetlog(
    fs.readFileSync(file, 'utf8'),
    host,
    requiredPaths.length === 0 ? undefined : requiredPaths,
  );
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exitCode = 1;
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}

module.exports = {
  DEFAULT_REQUIRED_PATHS,
  KNOWN_IPV6_CHECK,
  CHUNKED_REPORT_PATH,
  checkNetlog,
  parseNetlog,
  splitHostPort,
  normalizeAllowedHostPort,
  isAllowedName,
  eventTypeName,
  sourceTypeName,
};
