// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { canonicalize } = require('../core/canonical');
const { ConnectError } = require('./net');

const MAX_RECORD_BYTES = 2 * 1024 * 1024;
const RETRYABLE_CODES = new Set(['network', 'timeout', 'server_error', 'upload_refused']);
const COUNTDOWN_STATES = new Set(['consent', 'scanning', 'hash']);

function noop() {}

function isConnectError(error) {
  if (error === null || error === undefined) return false;
  if (error instanceof ConnectError || error.name === 'ConnectError') return true;
  return typeof error.code === 'string' && /^[a-z][a-z0-9_]*$/.test(error.code);
}

function errorKey(error) {
  return typeof error.code === 'string' && error.code.length > 0 ? error.code : 'internal';
}

function isOriginError(error) {
  const code = error && typeof error.code === 'string' ? error.code : '';
  const message = error && typeof error.message === 'string' ? error.message : '';
  return /origin/i.test(code) || /origin/i.test(message);
}

function sameCanonical(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function redactRecord(record, secrets) {
  const values = new Set(secrets.filter((value) => typeof value === 'string' && value.length > 0));

  function walk(value) {
    if (typeof value === 'string') return values.has(value) ? '[redacted]' : value;
    if (Array.isArray(value)) return value.map(walk);
    if (value !== null && typeof value === 'object') {
      const copy = {};
      for (const [key, entry] of Object.entries(value)) copy[key] = walk(entry);
      return copy;
    }
    return value;
  }

  let text;
  try {
    text = JSON.stringify(walk(record));
  } catch {
    text = String(record);
  }

  // A secret can appear inside a larger string in a hand-written record. Replace
  // longer secrets as substrings too; short nonces stay exact-match only so a
  // one-character nonce cannot make the display unreadable.
  for (const secret of values) {
    if (secret.length >= 4) text = text.split(secret).join('[redacted]');
  }
  return text;
}

function createFlow(options = {}) {
  const parseCode = options.parseCode;
  const makeClient = options.makeClient;
  const sealEnvelope = options.sealEnvelope;
  const runSidecar = options.runSidecar;
  const now = typeof options.now === 'function' ? options.now : Date.now;
  const emit = typeof options.emit === 'function' ? options.emit : noop;
  const version = options.version;

  let current = { name: 'paste' };
  let parsed = null;
  let client = null;
  let policy = null;
  let recordText = null;
  let displayRecord = null;
  let visualHash = null;
  let accepted = false;
  let exit = null;
  let busy = false;
  let sent = null;

  function publish(state) {
    current = state;
    emit(state);
  }

  function expiryMs() {
    if (client !== null && Number.isFinite(client.expiresAtMs)) return client.expiresAtMs;
    if (policy !== null && typeof policy.expires_at === 'string') {
      const millis = Date.parse(policy.expires_at);
      if (Number.isFinite(millis)) return millis;
    }
    if (parsed !== null && parsed.expiresAt !== undefined && parsed.expiresAt !== null) {
      if (Number.isFinite(parsed.expiresAt)) return parsed.expiresAt;
      const millis = Date.parse(parsed.expiresAt);
      if (Number.isFinite(millis)) return millis;
    }
    return null;
  }

  function hasTime() {
    const expiry = expiryMs();
    // Without a known expiry there is no evidence the ticket has run out; keep
    // the retry available rather than inventing an expiry.
    if (expiry === null) return true;
    return now() < expiry;
  }

  function secondsLeft() {
    const expiry = expiryMs();
    if (expiry === null) return null;
    return Math.ceil((expiry - now()) / 1000);
  }

  function withCountdown(state) {
    const left = secondsLeft();
    if (left === null) return state;
    return { ...state, secondsLeft: left };
  }

  function fail(key, sentFlag, code, canRetry = false) {
    exit = code;
    publish({
      name: 'error',
      error: { key, sent: sentFlag === true },
      canRetry: canRetry === true,
    });
  }

  function failConnect(error, exitCode, sentFlag) {
    const key = errorKey(error);
    const retry = RETRYABLE_CODES.has(key) && hasTime();
    fail(key, sentFlag, exitCode, retry);
  }

  function consentState() {
    return withCountdown({
      name: 'consent',
      serverOrigin: parsed.serverOrigin,
      serverName: policy.server_name,
      collectors: [...policy.required_collectors],
      elevation: policy.require_elevation === true,
      localAddress: parsed.isLocalAddress === true,
    });
  }

  function scanningState(elevationPending) {
    return withCountdown({
      name: 'scanning',
      elevationPending: elevationPending === true,
    });
  }

  function hashState() {
    return withCountdown({
      name: 'hash',
      visualHash,
      recordText: displayRecord,
    });
  }

  function validPolicy(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    if (!Array.isArray(value.required_collectors)) return false;
    if (value.required_collectors.some((collector) => typeof collector !== 'string')) return false;
    return typeof value.server_name === 'string';
  }

  function checkRecord(text) {
    if (typeof text !== 'string') return { ok: false, key: 'record_refused' };
    if (Buffer.byteLength(text, 'utf8') > MAX_RECORD_BYTES) {
      return { ok: false, key: 'record_refused' };
    }

    let record;
    try {
      record = JSON.parse(text);
    } catch {
      return { ok: false, key: 'record_refused' };
    }
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      return { ok: false, key: 'record_refused' };
    }

    if (!sameCanonical(record.binding, sent.binding)
        || !sameCanonical(record.policy, sent.policy)
        || !sameCanonical(record.producer, sent.producer)) {
      return { ok: false, key: 'record_refused' };
    }
    if (typeof record.visual_hash !== 'string' || !/^[0-9a-f]{16}$/.test(record.visual_hash)) {
      return { ok: false, key: 'record_refused' };
    }

    let envelope;
    try {
      envelope = sealEnvelope(text, parsed.kitPublicKey, parsed.ticket);
    } catch {
      return { ok: false, key: 'record_refused' };
    }
    let envelopeBytes;
    try {
      envelopeBytes = Buffer.from(JSON.stringify(envelope), 'utf8');
    } catch {
      return { ok: false, key: 'record_refused' };
    }
    if (envelopeBytes.length > MAX_RECORD_BYTES) {
      return { ok: false, key: 'too_large' };
    }

    return {
      ok: true,
      visualHash: record.visual_hash,
      recordText: redactRecord(record, [parsed.ticket, parsed.nonce, parsed.kitPublicKey]),
    };
  }

  async function doSubmitCode(code) {
    busy = true;
    try {
      let candidate;
      try {
        candidate = parseCode(code);
      } catch (error) {
        fail(isOriginError(error) ? 'bad_origin' : 'bad_code', false, 12, false);
        return true;
      }
      if (candidate === null || candidate === undefined
          || typeof candidate !== 'object'
          || typeof candidate.serverOrigin !== 'string'
          || typeof candidate.ticket !== 'string') {
        fail('bad_code', false, 12, false);
        return true;
      }

      parsed = candidate;
      client = null;
      policy = null;
      recordText = null;
      displayRecord = null;
      visualHash = null;
      accepted = false;
      exit = null;
      sent = null;

      publish({ name: 'checking', serverOrigin: parsed.serverOrigin });

      try {
        client = await makeClient({ origin: parsed.serverOrigin, ticket: parsed.ticket });
        const received = await client.getPolicy(parsed.policyHash);
        if (!validPolicy(received)) {
          fail('policy_mismatch', false, 12, false);
          return true;
        }
        policy = received;
      } catch (error) {
        if (isConnectError(error)) {
          const key = errorKey(error);
          const code = key === 'policy_mismatch' || key === 'bad_policy' ? 12 : 15;
          fail(key, false, code, false);
        } else {
          fail('internal', false, 10, false);
        }
        return true;
      }

      publish(consentState());
      return true;
    } finally {
      busy = false;
    }
  }

  function submitCode(code) {
    if (busy) return false;
    const retryingWithoutCode = current.name === 'error' && parsed === null;
    if (current.name !== 'paste' && !retryingWithoutCode) return false;
    return doSubmitCode(code);
  }

  async function doConsent() {
    busy = true;
    try {
      const binding = { ticket: parsed.ticket, nonce: parsed.nonce };
      const producer = { name: 'rongroi-connect', version, mode: 'single-shot' };
      sent = { binding, policy, producer };
      const elevate = policy.require_elevation === true;

      publish(scanningState(false));

      let answer;
      try {
        answer = await runSidecar({
          binding,
          policy,
          producer,
          elevate,
          onElevationPending() {
            if (current.name === 'scanning' && current.elevationPending !== true) {
              publish(scanningState(true));
            }
          },
        });
      } catch {
        fail('sidecar_failed', false, 13, false);
        return true;
      }

      if (current.name !== 'scanning') return false;

      if (answer !== null && answer !== undefined && answer.declined === true) {
        return doDecline(binding);
      }

      const checked = checkRecord(answer === null || answer === undefined ? undefined : answer.recordText);
      if (!checked.ok) {
        fail(checked.key, false, 14, false);
        return true;
      }

      recordText = answer.recordText;
      displayRecord = checked.recordText;
      visualHash = checked.visualHash;
      publish(hashState());
      return true;
    } finally {
      busy = false;
    }
  }

  function consent() {
    if (busy || current.name !== 'consent') return false;
    return doConsent();
  }

  async function doSend() {
    busy = true;
    try {
      publish({ name: 'uploading' });

      let envelope;
      try {
        envelope = sealEnvelope(recordText, parsed.kitPublicKey, parsed.ticket);
      } catch {
        fail('internal', false, 10, false);
        return true;
      }
      let bytes;
      try {
        bytes = Buffer.from(JSON.stringify(envelope), 'utf8');
      } catch {
        fail('internal', false, 10, false);
        return true;
      }

      try {
        await client.upload(bytes);
      } catch (error) {
        if (isConnectError(error)) {
          failConnect(error, 15, false);
        } else {
          fail('internal', false, 10, false);
        }
        return true;
      }

      accepted = true;
      exit = 0;
      publish({ name: 'done', serverOrigin: parsed.serverOrigin, visualHash });
      return true;
    } finally {
      busy = false;
    }
  }

  function send() {
    if (busy || current.name !== 'hash') return false;
    return doSend();
  }

  async function doDecline(binding) {
    busy = true;
    try {
      const plaintext = JSON.stringify({
        scan: 'declined',
        binding: { ticket: binding.ticket, nonce: binding.nonce },
      });

      let envelope;
      try {
        envelope = sealEnvelope(plaintext, parsed.kitPublicKey, parsed.ticket);
      } catch {
        fail('internal', false, 10, false);
        return true;
      }
      let bytes;
      try {
        bytes = Buffer.from(JSON.stringify(envelope), 'utf8');
      } catch {
        fail('internal', false, 10, false);
        return true;
      }

      try {
        await client.decline(bytes);
      } catch (error) {
        if (isConnectError(error)) {
          fail(errorKey(error), false, 15, false);
        } else {
          fail('internal', false, 10, false);
        }
        return true;
      }

      accepted = true;
      exit = 0;
      publish({ name: 'declined', serverOrigin: parsed.serverOrigin });
      return true;
    } finally {
      busy = false;
    }
  }

  function decline() {
    if (busy || current.name !== 'consent') return false;
    return doDecline({ ticket: parsed.ticket, nonce: parsed.nonce });
  }

  function retry() {
    if (busy || current.name !== 'error' || current.canRetry !== true) return false;
    if (parsed === null || recordText === null || visualHash === null) return false;
    exit = null;
    publish(hashState());
    return true;
  }

  function quit() {
    const code = accepted ? 0 : 11;
    exit = code;
    return code;
  }

  function tick() {
    if (parsed === null || !COUNTDOWN_STATES.has(current.name)) return false;
    const expiry = expiryMs();
    if (expiry === null) return false;

    const left = Math.ceil((expiry - now()) / 1000);
    if (left <= 0) {
      fail('expired', false, 15, false);
      return true;
    }

    if (current.name === 'consent') {
      publish(consentState());
    } else if (current.name === 'scanning') {
      publish(scanningState(current.elevationPending === true));
    } else {
      publish(hashState());
    }
    return true;
  }

  function state() {
    return current;
  }

  function exitCode() {
    return exit;
  }

  return {
    submitCode,
    consent,
    decline,
    send,
    quit,
    retry,
    tick,
    state,
    exitCode,
  };
}

module.exports = createFlow;
module.exports.createFlow = createFlow;
module.exports.MAX_RECORD_BYTES = MAX_RECORD_BYTES;
