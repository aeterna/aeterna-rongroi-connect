// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Read Chromium's netlog JSON and list every host it names.  The proof in ADR
// 0001 section 2 fails when a name other than the paired host and port appears,
// when the paired host never appears, or when the flow did not request both the
// policy and the report paths.

const DEFAULT_PORTS = {
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
};

const DEFAULT_REQUIRED_PATHS = ['/nakara_rongroi/policy/', '/nakara_rongroi/report/'];
const BYTE_TRANSFER_TYPE = /_BYTES_(?:SENT|RECEIVED)$/;

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
  if (requiredPaths === undefined || requiredPaths === null) return [...DEFAULT_REQUIRED_PATHS];
  const values = Array.isArray(requiredPaths) ? requiredPaths : [requiredPaths];
  return values.map((value) => String(value));
}

function emptyResult(allowed, paths, error) {
  return {
    ok: false,
    allowedHostPort: allowed === null ? null : allowed.display,
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
    if (typeof value !== 'string') return;
    for (const path of paths) {
      if (value.includes(path)) {
        seenPaths.add(path);
        continue;
      }
      // The direct report request ends at /report, which has no trailing
      // slash; accept that exact path as the required /report/ prefix.
      if (path.endsWith('/')) {
        const withoutSlash = path.slice(0, -1);
        const index = value.indexOf(withoutSlash);
        if (index !== -1) {
          const next = value[index + withoutSlash.length];
          if (next === undefined || next === '/' || next === '?' || next === '#') {
            seenPaths.add(path);
          }
        }
      }
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

  for (const event of events) {
    if (event === null || typeof event !== 'object') continue;
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

  const missingPaths = paths.filter((path) => !seenPaths.has(path));
  const anyByteTransfer = unexpectedDetails.some((detail) => detail.byteTransfer);

  return {
    ok: unexpectedNames.length === 0 && allowedSeen && missingPaths.length === 0,
    allowedHostPort: allowed.display,
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
    seenPaths: paths.filter((path) => seenPaths.has(path)),
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
  checkNetlog,
  parseNetlog,
  splitHostPort,
  normalizeAllowedHostPort,
  isAllowedName,
  eventTypeName,
};
