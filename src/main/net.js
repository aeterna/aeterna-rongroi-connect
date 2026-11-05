// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { policyHash } = require('../core/canonical');
const { actionForStatus, planUpload } = require('../core/upload-plan');

const PATH_PREFIX = '/nakara_rongroi/';
const MAX_RATE_LIMIT_WAITS = 4;
const MAX_RESPONSE_BYTES = 64 * 1024;
const POLICY_TIMEOUT_MS = 10_000;
const UPLOAD_TIMEOUT_MS = 15_000;
const MAX_CLOCK_OFFSET_MS = 24 * 60 * 60 * 1000;
const STATUS_CODES = Object.freeze({
  400: 'bad_request',
  404: 'unknown_ticket',
  409: 'ticket_used',
  410: 'expired',
  413: 'too_large',
  422: 'upload_refused',
});

class ConnectError extends Error {
  constructor(code, message, options) {
    super(message === undefined ? code : message, options);
    this.name = 'ConnectError';
    this.code = code;
  }
}

function fail(code, message, options) {
  throw new ConnectError(code, message, options);
}

function originText(value) {
  if (typeof value === 'string') return value;
  if (value !== null && typeof value === 'object') {
    return value.serverOrigin ?? value.server_origin ?? value.origin ?? null;
  }
  return null;
}

// Validate an origin, and return it exactly as URL normalises it. This is
// called in the constructor and again for every request path.
function pinOrigin(value) {
  const text = originText(value);
  if (typeof text !== 'string' || text.length === 0) {
    fail('bad_origin', 'origin must be a non-empty http(s) origin');
  }
  let url;
  try {
    url = new URL(text);
  } catch {
    fail('bad_origin', 'origin is not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    fail('bad_origin', 'origin must use http or https');
  }
  if (url.username || url.password) {
    fail('bad_origin', 'origin must not carry user information');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    fail('bad_origin', 'origin must not carry a path, query or fragment');
  }
  return url.origin;
}

function buildUrl(origin, path) {
  const base = pinOrigin(origin);
  if (typeof path !== 'string' || path.length === 0) {
    fail('bad_path', 'request path must be a non-empty string');
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(path) || path.startsWith('/') || path.includes('\\')
      || path.includes('?') || path.includes('#') || path.includes('@')) {
    fail('bad_path', 'request path must stay below the paired origin');
  }
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') {
      fail('bad_path', 'request path must not escape /nakara_rongroi');
    }
  }

  const url = new URL(`${base}${PATH_PREFIX}${path}`);
  if (url.origin !== base || url.username || url.password
      || !url.pathname.startsWith(PATH_PREFIX)) {
    fail('foreign_origin', 'request would leave the paired origin');
  }
  return url;
}

function expiresMillis(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const millis = Date.parse(value);
    if (Number.isFinite(millis)) return millis;
  }
  fail('bad_expiry', 'expiresAt must be an ISO-8601 time or epoch milliseconds');
}

function statusCode(status) {
  if (STATUS_CODES[status]) return STATUS_CODES[status];
  if (Number.isInteger(status) && status >= 500 && status <= 599) return 'server_error';
  return 'unexpected_status';
}

function defaultSleep(millis) {
  return new Promise((resolve) => setTimeout(resolve, millis));
}

function saysRedirect(value) {
  if (typeof value === 'string') return /redirect/i.test(value);
  if (value === null || typeof value !== 'object') return false;
  for (const field of [value.code, value.name, value.message]) {
    if (typeof field === 'string' && /redirect/i.test(field)) return true;
  }
  return saysRedirect(value.cause);
}

async function cancelResponseBody(body) {
  if (body === null || body === undefined) return;
  try {
    if (typeof body.cancel === 'function') {
      await body.cancel();
    } else if (typeof body.getReader === 'function') {
      await body.getReader().cancel();
    }
  } catch {
    // The body is already unusable; the caller's error is the important one.
  }
}

async function readResponseBody(response, url) {
  const body = response.body;
  if (body !== null && body !== undefined && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === null || value === undefined) continue;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > MAX_RESPONSE_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The stream is already closing; the size is still an error.
        }
        fail('response_too_large', `response from ${url.pathname} exceeds ${MAX_RESPONSE_BYTES} bytes`);
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, total);
  }

  const array = await response.arrayBuffer();
  if (array.byteLength > MAX_RESPONSE_BYTES) {
    fail('response_too_large', `response from ${url.pathname} exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  return Buffer.from(array);
}

class PairedClient {
  constructor({
    origin,
    ticket,
    fetchImpl,
    now,
    sleep = defaultSleep,
    timeoutMs,
    policyTimeoutMs,
    uploadTimeoutMs,
    expiresAt,
    expires_at,
  } = {}) {
    Object.defineProperty(this, 'origin', {
      value: pinOrigin(origin),
      enumerable: true,
    });
    if (typeof ticket !== 'string' || !/^[0-9a-f]{32}$/.test(ticket)) {
      fail('bad_ticket', 'ticket must be 32 lowercase hex characters');
    }
    if (typeof fetchImpl !== 'function') fail('bad_fetch', 'fetchImpl must be a function');
    const clock = now === undefined ? () => Date.now() : now;
    if (typeof clock !== 'function') fail('bad_clock', 'now must be a function');
    if (typeof sleep !== 'function') fail('bad_sleep', 'sleep must be a function');

    // Section 4's table: a policy GET gets 10 s, each upload POST gets 15 s.
    // `timeoutMs` remains the single override used by older callers and tests.
    const policyTimeout = policyTimeoutMs === undefined
      ? (timeoutMs === undefined ? POLICY_TIMEOUT_MS : timeoutMs)
      : policyTimeoutMs;
    const uploadTimeout = uploadTimeoutMs === undefined
      ? (timeoutMs === undefined ? UPLOAD_TIMEOUT_MS : timeoutMs)
      : uploadTimeoutMs;
    if (!Number.isFinite(policyTimeout) || policyTimeout <= 0) {
      fail('bad_timeout', 'policyTimeoutMs must be a positive number');
    }
    if (!Number.isFinite(uploadTimeout) || uploadTimeout <= 0) {
      fail('bad_timeout', 'uploadTimeoutMs must be a positive number');
    }

    this.ticket = ticket;
    this.fetchImpl = fetchImpl;
    this.now = clock;
    this.correctClockFromServer = now === undefined;
    this.sleep = sleep;
    this.policyTimeoutMs = policyTimeout;
    this.uploadTimeoutMs = uploadTimeout;
    this.timeoutMs = uploadTimeout;

    const suppliedExpiry = expiresAt ?? expires_at
      ?? (origin !== null && typeof origin === 'object' ? origin.expiresAt ?? origin.expires_at : undefined);
    this.expiresAtMs = suppliedExpiry === undefined || suppliedExpiry === null
      ? null
      : expiresMillis(suppliedExpiry);
  }

  // Resolve a request path without fetching. The fetch path calls this too, so
  // an attempted departure from the paired origin fails before any request.
  urlFor(path) {
    return buildUrl(this.origin, path);
  }

  hasTime(at = this.now()) {
    return this.expiresAtMs === null || at < this.expiresAtMs;
  }

  async request(path, init, timeoutMs = this.timeoutMs) {
    const url = this.urlFor(path);
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    try {
      const options = {
        ...init,
        redirect: 'error',
        signal: controller.signal,
      };
      const method = typeof options.method === 'string' ? options.method.toUpperCase() : 'GET';
      if (method === 'POST' && options.body !== undefined && options.body !== null
          && !Buffer.isBuffer(options.body)) {
        options.body = Buffer.from(options.body);
      }

      const response = await this.fetchImpl(url.href, options);

      if (response.type === 'opaqueredirect'
          || (response.status >= 300 && response.status < 400)) {
        await cancelResponseBody(response.body);
        fail('redirect_refused', `redirect from ${url.pathname} refused`);
      }

      const bytes = await readResponseBody(response, url);
      return { status: response.status, headers: response.headers, bytes };
    } catch (error) {
      if (error instanceof ConnectError) throw error;
      if (saysRedirect(error)) {
        fail('redirect_refused', `redirect from ${url.pathname} refused`, { cause: error });
      }
      if (timedOut || (error !== null && error !== undefined && error.name === 'AbortError')) {
        fail('timeout', `request to ${url.pathname} timed out`);
      }
      fail('network', `request to ${url.pathname} failed`, { cause: error });
    } finally {
      clearTimeout(timer);
    }
  }

  async getPolicy(expectedPolicyHash) {
    const response = await this.request(
      `policy/${this.ticket}`,
      { method: 'GET' },
      this.policyTimeoutMs,
    );
    if (response.status === 404) fail('unknown_ticket', 'the server does not know this ticket');
    if (response.status === 410) fail('expired', 'the ticket expired');
    if (response.status !== 200) {
      fail(statusCode(response.status), `policy request refused with status ${response.status}`);
    }

    let policy;
    try {
      policy = JSON.parse(response.bytes.toString('utf8'));
    } catch {
      fail('bad_policy', 'the policy response is not valid JSON');
    }

    let actual;
    try {
      actual = policyHash(policy);
    } catch {
      fail('bad_policy', 'the policy response is not a hashable object');
    }
    if (actual !== expectedPolicyHash) {
      fail('policy_mismatch', 'the policy hash does not match the pairing code');
    }

    this.rememberExpiry(policy, response.headers.get('date'));
    return policy;
  }

  async upload(envelopeBytes) {
    let plan;
    try {
      plan = planUpload(envelopeBytes, this.ticket);
    } catch (error) {
      fail('bad_envelope', error.message, { cause: error });
    }

    let restarted = false;
    for (;;) {
      const outcome = await this.sendPlan(plan);
      if (outcome.action === 'ok') return { status: 'accepted' };
      if (restarted) {
        const options = outcome.cause === undefined ? undefined : { cause: outcome.cause };
        fail(outcome.code, outcome.message, options);
      }
      if (!this.hasTime()) fail('expired', 'the ticket expired before the upload could restart');
      restarted = true;
    }
  }

  async decline(sealedBytes) {
    await this.upload(sealedBytes);
    return { status: 'declined' };
  }

  rememberExpiry(policy, dateHeader) {
    if (policy === null || typeof policy !== 'object' || typeof policy.expires_at !== 'string') return;
    const expires = Date.parse(policy.expires_at);
    if (!Number.isFinite(expires)) return;

    let offset = 0;
    if (this.correctClockFromServer && typeof dateHeader === 'string') {
      const serverNow = Date.parse(dateHeader);
      if (Number.isFinite(serverNow)) {
        offset = serverNow - this.now();
        // A header that disagrees by more than a day is more likely a wrong
        // server clock or a proxy than a useful correction.
        if (Math.abs(offset) > MAX_CLOCK_OFFSET_MS) offset = 0;
      }
    }
    this.expiresAtMs = expires - offset;
  }

  async sendPlan(plan) {
    if (plan.mode === 'direct') {
      return this.send(plan.endpoint, plan.data, plan.headers, plan.retryDelaysMs);
    }
    for (const slice of plan.slices) {
      const outcome = await this.send(plan.endpoint, slice.data, slice.headers, plan.retryDelaysMs);
      if (outcome.action === 'restart') return outcome;
    }
    return { action: 'ok' };
  }

  async send(endpoint, data, headers, retryDelaysMs) {
    let backoff = 0;
    let rateLimitWaits = 0;
    const body = Buffer.isBuffer(data) ? data : Buffer.from(data);

    for (;;) {
      let response;
      try {
        response = await this.request(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/octet-stream', ...headers },
          body,
        }, this.uploadTimeoutMs);
      } catch (error) {
        const retryable = error instanceof ConnectError
          && (error.code === 'network' || error.code === 'timeout');
        if (!retryable) throw error;
        if (backoff >= retryDelaysMs.length) {
          return {
            action: 'restart',
            code: error.code,
            message: `upload failed after ${retryDelaysMs.length} retries`,
            cause: error,
          };
        }
        await this.sleep(retryDelaysMs[backoff]);
        backoff += 1;
        continue;
      }

      const action = actionForStatus(response.status, response.headers.get('retry-after'));
      if (action.action === 'continue') return { action: 'ok' };
      if (action.action === 'restart') {
        return {
          action: 'restart',
          code: 'upload_refused',
          message: 'the server asked to restart the upload',
        };
      }

      if (action.action === 'wait') {
        const delay = action.retryAfterMs === null ? 1000 : action.retryAfterMs;
        if (!this.hasTime(this.now() + delay)) {
          fail('expired', 'the ticket expires before the Retry-After wait ends');
        }
        if (rateLimitWaits >= MAX_RATE_LIMIT_WAITS) {
          fail('rate_limited', 'the server kept asking to retry later');
        }
        rateLimitWaits += 1;
        await this.sleep(delay);
        continue;
      }

      if (action.action === 'retry') {
        if (backoff >= retryDelaysMs.length) {
          return {
            action: 'restart',
            code: 'server_error',
            message: `upload failed with status ${response.status}`,
          };
        }
        await this.sleep(retryDelaysMs[backoff]);
        backoff += 1;
        continue;
      }

      fail(statusCode(response.status), `upload refused with status ${response.status}`);
    }
  }
}

module.exports = PairedClient;
module.exports.PairedClient = PairedClient;
module.exports.ConnectError = ConnectError;
module.exports.buildUrl = buildUrl;
module.exports.MAX_RESPONSE_BYTES = MAX_RESPONSE_BYTES;
module.exports.POLICY_TIMEOUT_MS = POLICY_TIMEOUT_MS;
module.exports.UPLOAD_TIMEOUT_MS = UPLOAD_TIMEOUT_MS;
module.exports.MAX_CLOCK_OFFSET_MS = MAX_CLOCK_OFFSET_MS;
