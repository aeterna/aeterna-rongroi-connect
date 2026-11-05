// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Read Chromium's netlog JSON and list every host it names.  The proof in ADR
// 0001 section 2 fails when a name other than the paired host and port appears,
// and also when the paired host never appears (the flow did not run).

const DEFAULT_PORTS = {
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
};

function splitHostPort(value) {
  let text = String(value).trim();
  if (text === '') return null;

  if (text.startsWith('[')) {
    const match = /^\[([^\]]+)\](?::(\d+))?$/.exec(text);
    if (match !== null) {
      return { host: match[1].toLowerCase().replace(/\.$/, ''), port: match[2] ?? null };
    }
    return { host: text.toLowerCase(), port: null };
  }

  const colons = (text.match(/:/g) || []).length;
  if (colons === 1) {
    const [host, port] = text.split(':');
    if (host !== '' && /^\d+$/.test(port)) {
      return { host: host.toLowerCase().replace(/\.$/, ''), port };
    }
    return { host: text.toLowerCase().replace(/\.$/, ''), port: null };
  }

  // No colon, or an IPv6 address with several: treat the whole value as a host.
  text = text.toLowerCase().replace(/\.$/, '');
  return { host: text, port: null };
}

function formatName(host, port) {
  if (host === null || host === undefined || host === '') return null;
  return port === null || port === undefined || port === '' ? host : `${host}:${port}`;
}

function normalizeAllowedHostPort(value) {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return { host: '127.0.0.1', port: String(value), display: `127.0.0.1:${value}` };
  }

  let text = String(value ?? '').trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    try {
      text = new URL(text).host;
    } catch {
      // Keep the original text so the error below names what was passed.
    }
  }

  const parts = splitHostPort(text);
  if (parts === null) throw new Error('allowedHostPort is required');

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
  const parts = splitHostPort(name);
  if (parts === null) return false;
  if (parts.host !== allowed.host) return false;
  if (allowed.port === null) return true;
  // A HOST_RESOLVER event often names only the host; that is still the
  // paired host and is not a different destination.
  if (parts.port === null) return true;
  return parts.port === allowed.port;
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

  const host = parsed.hostname
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.$/, '')
    .toLowerCase();
  const port = parsed.port !== '' ? parsed.port : (DEFAULT_PORTS[parsed.protocol] ?? null);
  return formatName(host, port);
}

function hostName(value, port) {
  if (typeof value !== 'string') return null;
  const parts = splitHostPort(value);
  if (parts === null) return null;
  const effectivePort = parts.port !== null ? parts.port : (port === undefined || port === null ? null : String(port));
  return formatName(parts.host, effectivePort);
}

function addressName(value, port) {
  return hostName(value, port);
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

// Pure check of one netlog.  json is the file text (or an already parsed
// object); allowedHostPort is "127.0.0.1:<port>".  Returns the distinct names
// seen, the ones that are not allowed, and whether the paired host was named.
function checkNetlog(json, allowedHostPort) {
  const allowed = normalizeAllowedHostPort(allowedHostPort);

  let netlog;
  try {
    netlog = parseNetlog(json);
  } catch (error) {
    return {
      ok: false,
      allowedHostPort: allowed.display,
      names: [],
      unexpected: [],
      allowedSeen: false,
      error: error.message,
    };
  }

  const constants = netlog.constants ?? {};
  const events = Array.isArray(netlog.events) ? netlog.events : [];
  const names = new Set();
  const unexpected = new Set();
  let allowedSeen = false;

  function record(name) {
    if (typeof name !== 'string' || name === '') return;
    names.add(name);
    if (isAllowedName(name, allowed)) {
      allowedSeen = true;
    } else {
      unexpected.add(name);
    }
  }

  for (const event of events) {
    if (event === null || typeof event !== 'object') continue;
    const params = event.params;
    if (params === null || typeof params !== 'object' || Array.isArray(params)) continue;

    const typeName = eventTypeName(constants, event.type);
    const isHostResolver = /^HOST_RESOLVER_/.test(typeName);
    const eventPort = params.port ?? null;

    if (typeof params.url === 'string') record(urlName(params.url));
    if (typeof params.host === 'string') {
      // HOST_RESOLVER_* events carry the port beside the host; the other
      // events that name a host use the remote port member.
      record(hostName(params.host, isHostResolver ? eventPort : (params.remote_port ?? eventPort)));
    }
    if (typeof params.address === 'string') record(addressName(params.address, eventPort));
    if (typeof params.remote_address === 'string') {
      record(addressName(params.remote_address, params.remote_port ?? eventPort));
    }
  }

  return {
    ok: unexpected.size === 0 && allowedSeen,
    allowedHostPort: allowed.display,
    names: [...names].sort(),
    unexpected: [...unexpected].sort(),
    allowedSeen,
    error: null,
  };
}

function main(argv) {
  const [file, allowedHostPort] = argv.filter((value) => value !== '--');
  if (file === undefined || allowedHostPort === undefined) {
    console.error('usage: node scripts/check-netlog.js <netlog.json> <127.0.0.1:port>');
    process.exitCode = 2;
    return;
  }

  const fs = require('node:fs');
  const result = checkNetlog(fs.readFileSync(file, 'utf8'), allowedHostPort);
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
  checkNetlog,
  parseNetlog,
  splitHostPort,
  normalizeAllowedHostPort,
  isAllowedName,
};
