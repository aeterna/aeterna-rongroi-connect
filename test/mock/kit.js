// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// The mock Server Kit for the 2c proof.  It issues one valid rr1 pairing code,
// serves the matching policy, opens the sealed report and recomputes the
// visual hash exactly as the real server does.  It is plain Node, and it is
// never part of a release build.

const http = require('node:http');
const crypto = require('node:crypto');
const { createHash } = require('node:crypto');
const { openEnvelope } = require('../../src/core/envelope');
const { policyHash, visualHash } = require('../../src/core/canonical');
const { KNOWN_COLLECTORS } = require('../../src/main/collectors');

const HOST = '127.0.0.1';
const PREFIX = '/nakara_rongroi';
const MAX_BODY_BYTES = 4 * 1024 * 1024;

// The Standard tier is exactly the 20 collectors this client knows.  The e2e
// run asks the Kit for the same list the real Standard policy names.
const STANDARD_COLLECTORS = Object.freeze([...KNOWN_COLLECTORS]);

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function rawPublicKey(key) {
  const der = key.export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32).toString('base64url');
}

function encodeCode(payload) {
  return `rr1.${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}`;
}

function statusQueue(status) {
  if (status === undefined || status === null || status === '') return [];
  const values = Array.isArray(status) ? status : [status];
  return values
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599 && value !== 200);
}

function reportRoute(pathname) {
  if (pathname === `${PREFIX}/report`) return { kind: 'direct', ticket: null };
  if (pathname === `${PREFIX}/report/chunk`) return { kind: 'chunk', ticket: null };

  const direct = new RegExp(`^${PREFIX}/report/([0-9a-f]{32})$`).exec(pathname);
  if (direct !== null) return { kind: 'direct', ticket: direct[1] };

  const chunk = new RegExp(`^${PREFIX}/report/([0-9a-f]{32})/chunk$`).exec(pathname);
  if (chunk !== null) return { kind: 'chunk', ticket: chunk[1] };

  return null;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;

    request.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        done = true;
        const error = new Error('too_large');
        error.code = 'too_large';
        reject(error);
        request.resume();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (!done) resolve(Buffer.concat(chunks, size));
    });
    request.on('error', (error) => {
      if (!done) {
        done = true;
        reject(error);
      }
    });
  });
}

async function startKit(options = {}) {
  const print = options.print !== false;
  const statuses = statusQueue(options.status);
  const kitKeys = crypto.generateKeyPairSync('x25519');
  const kitPublicKey = rawPublicKey(kitKeys.publicKey);
  const ticket = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(8).toString('hex');
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const policyOptions = options.policy !== null && typeof options.policy === 'object'
    ? options.policy
    : {};

  // The real Kit's policy has exactly five members: the four below plus the
  // policy_hash added after hashing.  The expiry stays in the pairing code.
  const basePolicy = {
    profile: policyOptions.profile ?? 'posture',
    required_collectors: Array.isArray(policyOptions.required_collectors)
      ? [...policyOptions.required_collectors]
      : ['posture', 'os_image'],
    require_elevation: policyOptions.require_elevation ?? false,
    server_name: 'Mock Server Kit',
  };
  const hash = policyHash(basePolicy);
  const policy = { ...basePolicy, policy_hash: hash };

  const uploads = new Map();
  const hashes = new Map();
  let storedRecord = null;
  let storedDeclined = false;
  let storedHash = null;
  let storedRecordVisualHash = null;
  let storedRecordBytes = null;
  let storedRecordVersion = null;
  let storedRecordKind = null;
  let storedOfficialBuild = null;
  let storedPolicyProfile = null;
  let storedPolicyRequireElevation = null;
  let storedPolicyCollectorCount = null;
  let storedScanSeconds = null;
  let policyServedAt = null;
  let received = 0;
  let requests = 0;

  function takeStatus() {
    return statuses.length === 0 ? null : statuses.shift();
  }

  function sendStatus(response, status) {
    const headers = {};
    if (status === 429) headers['Retry-After'] = '0';
    response.writeHead(status, headers);
    response.end();
  }

  function acceptEnvelope(envelope, uploadTicket) {
    if (uploadTicket !== ticket) return null;

    let text;
    try {
      text = openEnvelope(envelope, kitKeys.privateKey, ticket);
    } catch {
      return null;
    }

    let record;
    try {
      record = JSON.parse(text);
    } catch {
      return null;
    }
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      return null;
    }
    // The real Kit validates the binding for reports and declined answers
    // alike: it must be an object naming both the ticket and the nonce.
    if (record.binding === null || typeof record.binding !== 'object'
        || Array.isArray(record.binding)
        || record.binding.ticket !== ticket
        || record.binding.nonce !== nonce) {
      return null;
    }

    const declined = record.scan === 'declined';
    if (!declined && record.schema !== 2) {
      return null;
    }

    if (declined) {
      // A declined answer carries no report: there is nothing to hash and the
      // stored report and policy facts stay exactly as they were.
      storedDeclined = true;
      received += 1;
      if (print) console.log(JSON.stringify({ received: true, declined: true }));
      return true;
    }

    storedDeclined = false;

    let computed;
    try {
      computed = visualHash(record);
    } catch {
      return null;
    }

    // The server recomputes the hash from the record it received; the value
    // in the record is the one the player saw and is not trusted here.
    storedRecord = record;
    storedHash = computed;
    storedRecordVisualHash = typeof record.visual_hash === 'string'
      ? record.visual_hash
      : null;
    storedRecordBytes = Buffer.byteLength(text, 'utf8');
    storedRecordVersion = typeof record.rongroi_version === 'string'
      ? record.rongroi_version
      : null;
    storedRecordKind = typeof record.kind === 'string' ? record.kind : null;
    storedOfficialBuild = typeof record.official_build === 'boolean'
      ? record.official_build
      : null;
    const recordPolicy = record.policy !== null && typeof record.policy === 'object'
      ? record.policy
      : {};
    storedPolicyProfile = typeof recordPolicy.profile === 'string'
      ? recordPolicy.profile
      : null;
    storedPolicyRequireElevation = typeof recordPolicy.require_elevation === 'boolean'
      ? recordPolicy.require_elevation
      : null;
    storedPolicyCollectorCount = Array.isArray(recordPolicy.required_collectors)
      ? recordPolicy.required_collectors.length
      : null;
    storedScanSeconds = policyServedAt === null
      ? null
      : (Date.now() - policyServedAt) / 1000;
    hashes.set(ticket, computed);
    received += 1;
    if (print) {
      console.log(JSON.stringify({
        received: true,
        visual_hash: computed,
        record_visual_hash: storedRecordVisualHash,
        record_bytes: storedRecordBytes,
        rongroi_version: storedRecordVersion,
        kind: storedRecordKind,
        official_build: storedOfficialBuild,
        policy_profile: storedPolicyProfile,
        policy_require_elevation: storedPolicyRequireElevation,
        policy_collector_count: storedPolicyCollectorCount,
        scan_seconds: storedScanSeconds,
      }));
    }
    return computed;
  }

  let port = 0;
  const server = http.createServer(async (request, response) => {
    try {
      const requestUrl = new URL(request.url || '/', `http://${HOST}:${port}`);
      const { pathname } = requestUrl;

      if (request.method === 'GET' && pathname.startsWith(`${PREFIX}/policy/`)) {
        const requested = pathname.slice(`${PREFIX}/policy/`.length);
        if (requested !== ticket) {
          response.writeHead(404, { Date: new Date().toUTCString() });
          response.end();
          return;
        }
        policyServedAt = Date.now();
        response.writeHead(200, {
          'Content-Type': 'application/json',
          Date: new Date().toUTCString(),
        });
        response.end(JSON.stringify(policy));
        return;
      }

      if (request.method !== 'POST') {
        response.writeHead(404);
        response.end();
        return;
      }

      const route = reportRoute(pathname);
      if (route === null) {
        response.writeHead(404);
        response.end();
        return;
      }

      requests += 1;
      const body = await readBody(request);
      const prescribed = takeStatus();
      if (prescribed !== null) {
        sendStatus(response, prescribed);
        return;
      }

      const headerTicket = request.headers['x-rongroi-upload-id'];
      const uploadTicket = route.ticket
        || (typeof headerTicket === 'string' ? headerTicket : null)
        || ticket;

      if (route.kind === 'direct') {
        let envelope;
        try {
          envelope = JSON.parse(body.toString('utf8'));
        } catch {
          response.writeHead(400);
          response.end();
          return;
        }
        const accepted = acceptEnvelope(envelope, uploadTicket);
        response.writeHead(accepted === null ? 400 : 200);
        response.end(accepted === null ? '' : 'ok');
        return;
      }

      const index = Number(request.headers['x-rongroi-chunk-index']);
      const total = Number(request.headers['x-rongroi-chunk-total']);
      if (!Number.isInteger(index) || !Number.isInteger(total)
          || index < 0 || total <= 0 || index >= total) {
        response.writeHead(400);
        response.end();
        return;
      }
      if (request.headers['x-rongroi-chunk-sha256'] !== sha256Hex(body)) {
        response.writeHead(400);
        response.end();
        return;
      }

      const reportSha256 = request.headers['x-rongroi-report-sha256'];
      if (typeof reportSha256 !== 'string') {
        response.writeHead(400);
        response.end();
        return;
      }
      const key = `${uploadTicket}:${reportSha256}`;
      let upload = uploads.get(key);
      if (upload === undefined) {
        upload = {
          total,
          chunks: new Array(total),
          reportSha256,
          completed: null,
        };
        uploads.set(key, upload);
      }
      if (upload.total !== total) {
        uploads.delete(key);
        response.writeHead(400);
        response.end();
        return;
      }

      if (upload.chunks[index] === undefined) upload.chunks[index] = body;

      if (upload.completed !== null) {
        response.writeHead(200);
        response.end('ok');
        return;
      }

      let complete = true;
      for (let slice = 0; slice < upload.total; slice += 1) {
        if (upload.chunks[slice] === undefined) {
          complete = false;
          break;
        }
      }
      if (!complete) {
        response.writeHead(200);
        response.end('ok');
        return;
      }

      const envelopeBytes = Buffer.concat(upload.chunks);
      if (sha256Hex(envelopeBytes) !== reportSha256) {
        uploads.delete(key);
        response.writeHead(400);
        response.end();
        return;
      }

      let envelope;
      try {
        envelope = JSON.parse(envelopeBytes.toString('utf8'));
      } catch {
        uploads.delete(key);
        response.writeHead(400);
        response.end();
        return;
      }
      const accepted = acceptEnvelope(envelope, uploadTicket);
      if (accepted === null) {
        uploads.delete(key);
        response.writeHead(400);
        response.end();
        return;
      }
      upload.completed = accepted;
      response.writeHead(200);
      response.end('ok');
    } catch {
      try {
        response.writeHead(400);
        response.end();
      } catch {
        // The connection may already be gone.
      }
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, HOST, resolve);
  });
  const address = server.address();
  port = address && typeof address === 'object' ? address.port : 0;

  const origin = `http://${HOST}:${port}`;
  const code = encodeCode({
    expires_at: expiresAt,
    kit_public_key: kitPublicKey,
    nonce,
    policy_hash: hash,
    server_origin: origin,
    ticket,
  });

  if (print) console.log(JSON.stringify({ code, port }));

  function close() {
    return new Promise((resolve) => {
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      server.close(() => resolve());
    });
  }

  return {
    code,
    port,
    origin,
    server,
    ticket,
    nonce,
    expiresAt,
    policy,
    publicKey: kitPublicKey,
    get visualHash() {
      return storedHash;
    },
    get recordVisualHash() {
      return storedRecordVisualHash;
    },
    get recordBytes() {
      return storedRecordBytes;
    },
    get rongroiVersion() {
      return storedRecordVersion;
    },
    get recordKind() {
      return storedRecordKind;
    },
    get officialBuild() {
      return storedOfficialBuild;
    },
    get policyProfile() {
      return storedPolicyProfile;
    },
    get policyRequireElevation() {
      return storedPolicyRequireElevation;
    },
    get policyCollectorCount() {
      return storedPolicyCollectorCount;
    },
    get scanSeconds() {
      return storedScanSeconds;
    },
    get record() {
      return storedRecord;
    },
    get declined() {
      return storedDeclined;
    },
    get received() {
      return received;
    },
    get requests() {
      return requests;
    },
    get hashes() {
      return new Map(hashes);
    },
    close,
  };
}

function statusFromArguments(argv) {
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--status') {
      const value = Number(argv[index + 1]);
      return Number.isInteger(value) ? value : undefined;
    }
    if (token.startsWith('--status=')) {
      const value = Number(token.slice('--status='.length));
      return Number.isInteger(value) ? value : undefined;
    }
  }
  return undefined;
}

// The e2e runner hands the per-run policy to this child process.  A broken
// value must stop the child instead of silently serving the default posture.
function policyFromEnvironment(environment = process.env) {
  const raw = environment.RONGROI_MOCK_KIT_POLICY;
  if (raw === undefined) return undefined;

  const policy = JSON.parse(raw);
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('RONGROI_MOCK_KIT_POLICY must contain a JSON object');
  }
  return policy;
}

const kitArguments = process.argv.slice(2);
const kitRequested = kitArguments
  .some((token) => token === '--status' || token.startsWith('--status='));
if (require.main === module
    && (!process.env.NODE_TEST_CONTEXT || kitRequested)) {
  let policy;
  try {
    policy = policyFromEnvironment();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }

  startKit({ status: statusFromArguments(kitArguments), policy, print: true })
    .then((kit) => {
      const stop = () => {
        kit.close().then(() => process.exit(0));
      };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
    })
    .catch(() => {
      process.exit(1);
    });
}

module.exports = startKit;
module.exports.startKit = startKit;
module.exports.encodeCode = encodeCode;
module.exports.policyFromEnvironment = policyFromEnvironment;
module.exports.STANDARD_COLLECTORS = STANDARD_COLLECTORS;
