// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { canonicalize } = require('../src/core/canonical');
const { ConnectError } = require('../src/main/net');
const { createFlow } = require('../src/main/flow');
const { KNOWN_COLLECTORS } = require('../src/main/collectors');
const { SidecarError } = require('../src/main/sidecar');

const TICKET = '9f82c4e1b07a412891d604e38a291bf0';
const NONCE = 'nonce-abc-123';
const KIT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const HASH = '0123456789abcdef';
const ORIGIN = 'http://127.0.0.1:30120';
const VERSION = '0.1.0';
const MAX_RECORD_BYTES = 2 * 1024 * 1024;
const EXPIRES_AT = '2099-01-01T00:00:00Z';

const POLICY = {
  profile: 'posture',
  required_collectors: ['posture', 'os_image'],
  require_elevation: false,
  server_name: 'Example City',
  policy_hash: '0123456789abcdef',
};
const PRODUCER = { name: 'rongroi-connect', version: VERSION, mode: 'single-shot' };
const CODE = {
  serverOrigin: ORIGIN,
  ticket: TICKET,
  nonce: NONCE,
  expiresAt: EXPIRES_AT,
  policyHash: '0123456789abcdef',
  kitPublicKey: KIT,
  isLocalAddress: true,
};

function makeRecord(overrides = {}) {
  return {
    schema: 2,
    binding: { ticket: TICKET, nonce: NONCE },
    policy: POLICY,
    producer: PRODUCER,
    visual_hash: HASH,
    case_code: '7K9M-2X4P',
    ...overrides,
  };
}

function makeHarness(options = {}) {
  let clock = options.startNow ?? 1_700_000_000_000;
  const expiresAtMs = options.expiresAtMs ?? clock + 300_000;
  const emitted = [];
  const uploadCalls = [];
  const declineCalls = [];
  const sealCalls = [];
  const sidecarCalls = [];
  const makeClientCalls = [];
  const parseCalls = [];

  let uploadCount = 0;
  let declineCount = 0;
  let pendingUpload = null;

  const client = {
    expiresAtMs,
    async getPolicy() {
      if (options.policyError) throw options.policyError;
      return options.policy ?? POLICY;
    },
    async upload(bytes) {
      uploadCalls.push(bytes);
      uploadCount += 1;
      if (options.uploadError) {
        const error = typeof options.uploadError === 'function'
          ? options.uploadError(uploadCount)
          : options.uploadError;
        if (error) throw error;
      }
      if (pendingUpload === null && options.pendingUpload === true && uploadCount === 1) {
        return new Promise((resolve) => { pendingUpload = resolve; });
      }
      return { status: 'accepted' };
    },
    async decline(bytes) {
      declineCalls.push(bytes);
      declineCount += 1;
      if (options.declineError) {
        const error = typeof options.declineError === 'function'
          ? options.declineError(declineCount)
          : options.declineError;
        if (error) throw error;
      }
      return { status: 'declined' };
    },
  };

  const flow = createFlow({
    parseCode(code) {
      parseCalls.push(code);
      if (options.parseError) throw options.parseError;
      return options.parsedCode ?? CODE;
    },
    makeClient(input) {
      makeClientCalls.push(input);
      if (options.makeClientError) throw options.makeClientError;
      return client;
    },
    sealEnvelope(plaintext, kit, ticket) {
      sealCalls.push({ plaintext, kit, ticket });
      if (options.sealEnvelope) {
        return options.sealEnvelope(plaintext, kit, ticket);
      }
      return { v: 1, epk: 'epk', iv: 'iv', ct: plaintext };
    },
    async runSidecar(input) {
      sidecarCalls.push(input);
      if (options.sidecarError) throw options.sidecarError;
      if (typeof options.sidecar === 'function') return options.sidecar(input);
      return options.sidecarResult ?? { recordText: JSON.stringify(makeRecord(options.recordOverrides)) };
    },
    now: () => clock,
    emit(state) {
      emitted.push(state);
    },
    version: VERSION,
  });

  function releasePendingUpload() {
    if (pendingUpload !== null) {
      const resolve = pendingUpload;
      pendingUpload = null;
      resolve({ status: 'accepted' });
    }
  }

  return {
    flow,
    client,
    emitted,
    uploadCalls,
    declineCalls,
    sealCalls,
    sidecarCalls,
    makeClientCalls,
    parseCalls,
    setNow(value) { clock = value; },
    now: () => clock,
    releasePendingUpload,
  };
}

async function reachConsent(harness) {
  await harness.flow.submitCode('rr1.test');
  assert.equal(harness.flow.state().name, 'consent');
}

async function reachHash(harness) {
  await reachConsent(harness);
  await harness.flow.consent();
  assert.equal(harness.flow.state().name, 'hash');
}

function lastState(harness) {
  return harness.emitted[harness.emitted.length - 1];
}

test('the happy path moves from paste to done with one upload', async () => {
  const h = makeHarness();
  const names = () => h.emitted.map((state) => state.name);

  assert.equal(h.flow.state().name, 'paste');
  assert.deepEqual(names(), []);
  assert.equal(await h.flow.submitCode('rr1.test'), true);
  assert.deepEqual(names(), ['checking', 'consent']);

  assert.deepEqual(h.makeClientCalls[0], {
    origin: ORIGIN,
    ticket: TICKET,
    expiresAt: EXPIRES_AT,
  });
  const consent = lastState(h);
  assert.equal(consent.serverOrigin, ORIGIN);
  assert.equal(consent.serverName, POLICY.server_name);
  assert.deepEqual(consent.collectors, POLICY.required_collectors);
  assert.equal(consent.elevation, false);
  assert.equal(consent.localAddress, true);
  assert.equal(consent.secondsLeft, 300);

  assert.equal(await h.flow.consent(), true);
  assert.equal(h.sidecarCalls.length, 1);
  assert.deepEqual(h.sidecarCalls[0].binding, { ticket: TICKET, nonce: NONCE });
  assert.deepEqual(h.sidecarCalls[0].policy, POLICY);
  assert.deepEqual(h.sidecarCalls[0].producer, PRODUCER);
  assert.equal(h.sidecarCalls[0].elevate, false);
  assert.equal(typeof h.sidecarCalls[0].onCancel, 'function');
  assert.equal(h.sidecarCalls[0].registerCancel, undefined);
  assert.equal(h.sidecarCalls[0].cancel, undefined);
  assert.equal(h.sidecarCalls[0].cancelToken, undefined);
  assert.deepEqual(names(), ['checking', 'consent', 'scanning', 'hash']);

  const hash = lastState(h);
  assert.equal(hash.visualHash, HASH);
  assert.equal(hash.secondsLeft, 300);
  assert.equal(typeof hash.recordText, 'string');
  assert.equal(hash.recordText.includes(TICKET), false);
  assert.equal(hash.recordText.includes(NONCE), false);
  assert.equal(hash.recordText.includes(KIT), false);

  assert.equal(await h.flow.send(), true);
  assert.deepEqual(names(), ['checking', 'consent', 'scanning', 'hash', 'uploading', 'done']);
  assert.equal(h.uploadCalls.length, 1);
  assert.ok(Buffer.isBuffer(h.uploadCalls[0]));
  const sentEnvelope = JSON.parse(h.uploadCalls[0].toString('utf8'));
  assert.equal(sentEnvelope.v, 1);

  const done = lastState(h);
  assert.equal(done.serverOrigin, ORIGIN);
  assert.equal(done.visualHash, HASH);
  assert.equal(h.flow.exitCode(), 0);
  assert.equal(h.flow.quit(), 0);
});

test('parseCode failures become bad_code or bad_origin with exit code 12', async () => {
  const cases = [
    [{ name: 'PairingError', code: 'BAD_PREFIX', message: 'bad prefix' }, 'bad_code'],
    [{ name: 'PairingError', code: 'BAD_ORIGIN', message: 'origin is bad' }, 'bad_origin'],
    [{ name: 'Error', message: 'the server_origin is not usable' }, 'bad_origin'],
    [new Error('anything else'), 'bad_code'],
  ];

  for (const [error, key] of cases) {
    const h = makeHarness({ parseError: error });
    assert.equal(await h.flow.submitCode('rr1.test'), true);
    assert.equal(h.flow.state().name, 'error');
    assert.deepEqual(lastState(h).error, { key, sent: false });
    assert.equal(lastState(h).canRetry, false);
    assert.equal(h.flow.exitCode(), 12);
  }
});

test('a policy with a bad collectors list or server name is refused before consent', async () => {
  const cases = [
    { ...POLICY, required_collectors: 'posture' },
    { ...POLICY, required_collectors: ['posture', 7] },
    { ...POLICY, required_collectors: ['posture', 'not_a_collector'] },
    { ...POLICY, server_name: 7 },
  ];

  for (const policy of cases) {
    const h = makeHarness({ policy });
    await h.flow.submitCode('rr1.test');
    assert.equal(h.flow.state().name, 'error');
    assert.deepEqual(lastState(h).error, { key: 'policy_mismatch', sent: false });
    assert.equal(h.flow.exitCode(), 12);
    assert.equal(h.emitted.some((state) => state.name === 'consent'), false);
  }
});

test('a policy is refused before consent unless it has exactly the five sidecar members', async () => {
  const withoutPolicyHash = { ...POLICY };
  delete withoutPolicyHash.policy_hash;
  const sixtyFiveCollectors = Array.from(
    { length: 65 },
    (_, index) => KNOWN_COLLECTORS[index % KNOWN_COLLECTORS.length],
  );
  const cases = [
    ['a sixth member', { ...POLICY, expires_at: EXPIRES_AT }],
    ['a missing member', withoutPolicyHash],
    ['an unknown profile', { ...POLICY, profile: 'full' }],
    ['a non-boolean elevation flag', { ...POLICY, require_elevation: 'yes' }],
    ['an empty collector list', { ...POLICY, required_collectors: [] }],
    ['65 collectors', { ...POLICY, required_collectors: sixtyFiveCollectors }],
    ['a repeated collector', { ...POLICY, required_collectors: ['posture', 'posture'] }],
    ['an unknown collector', { ...POLICY, required_collectors: ['posture', 'not_a_collector'] }],
    ['an empty server name', { ...POLICY, server_name: '' }],
    ['a 129-code-point server name', { ...POLICY, server_name: 'x'.repeat(129) }],
    ['a control character in the server name', { ...POLICY, server_name: 'Example\u0007City' }],
    ['an uppercase policy hash', { ...POLICY, policy_hash: '0123456789ABCDEF' }],
  ];

  for (const [label, policy] of cases) {
    const h = makeHarness({ policy });
    await h.flow.submitCode('rr1.test');
    assert.equal(h.flow.state().name, 'error', label);
    assert.deepEqual(lastState(h).error, { key: 'policy_mismatch', sent: false }, label);
    assert.equal(lastState(h).canRetry, false, label);
    assert.equal(h.flow.exitCode(), 12, label);
    assert.equal(h.emitted.some((state) => state.name === 'consent'), false, label);
    assert.equal(h.flow.consent(), false, label);
    assert.equal(h.sidecarCalls.length, 0, label);
  }
});

test('a valid custom policy reaches consent without running the sidecar', async () => {
  const wideName = '\u{1F600}'.repeat(128);
  assert.equal([...wideName].length, 128);
  const policy = {
    ...POLICY,
    profile: 'custom',
    required_collectors: ['posture', 'os_image', 'defender_exclusion'],
    require_elevation: true,
    server_name: wideName,
  };
  const h = makeHarness({ policy });
  await h.flow.submitCode('rr1.test');
  assert.equal(h.flow.state().name, 'consent');
  const consent = lastState(h);
  assert.equal(consent.serverName, wideName);
  assert.deepEqual(consent.collectors, policy.required_collectors);
  assert.equal(consent.elevation, true);
  assert.equal(h.sidecarCalls.length, 0);
  assert.equal(h.flow.exitCode(), null);
});

test('the known collector list is frozen and holds every locale collector id', () => {
  const en = require('../src/locales/en.json');
  const localeIds = Object.keys(en)
    .filter((key) => key.startsWith('collector.'))
    .map((key) => key.slice('collector.'.length))
    .sort();

  assert.equal(Object.isFrozen(KNOWN_COLLECTORS), true);
  assert.deepEqual([...KNOWN_COLLECTORS].sort(), localeIds);
});

test('ConnectError from makeClient and getPolicy maps by code, exit code and retry', async () => {
  const cases = [
    ['makeClient', 'bad_ticket', 15, false],
    ['makeClient', 'policy_mismatch', 12, false],
    ['policy', 'bad_policy', 12, false],
    ['policy', 'policy_mismatch', 12, false],
    ['policy', 'unknown_ticket', 15, false],
    ['policy', 'network', 15, true],
    ['policy', 'timeout', 15, true],
    ['policy', 'server_error', 15, true],
  ];

  for (const [where, code, exit, canRetry] of cases) {
    const error = new ConnectError(code, code);
    const h = makeHarness(where === 'makeClient' ? { makeClientError: error } : { policyError: error });
    await h.flow.submitCode('rr1.test');
    assert.equal(h.flow.state().name, 'error');
    assert.deepEqual(lastState(h).error, { key: code, sent: false });
    assert.equal(lastState(h).canRetry, canRetry, code);
    assert.equal(h.flow.exitCode(), exit);
    assert.equal(h.emitted.some((state) => state.name === 'consent'), false);
  }
});

test('a retryable policy failure repeats the policy request and reaches consent', async () => {
  let attempts = 0;
  const h = makeHarness({
    policyError: new ConnectError('timeout', 'slow'),
  });
  h.client.getPolicy = async () => {
    attempts += 1;
    if (attempts === 1) throw new ConnectError('timeout', 'slow');
    return POLICY;
  };

  await h.flow.submitCode('rr1.test');
  assert.equal(h.flow.state().name, 'error');
  assert.equal(lastState(h).canRetry, true);
  assert.equal(lastState(h).error.sent, false);
  assert.equal(h.flow.exitCode(), 15);

  assert.equal(await h.flow.retry(), true);
  assert.equal(attempts, 2);
  assert.equal(h.flow.state().name, 'consent');
  assert.equal(h.flow.exitCode(), null);
});

test('a policy retry at the ticket expiry is refused', async () => {
  const h = makeHarness({
    startNow: 1_700_000_000_000,
    expiresAtMs: 1_700_000_001_000,
    policyError: new ConnectError('network', 'offline'),
  });
  h.setNow(1_700_000_002_000);
  await h.flow.submitCode('rr1.test');
  assert.equal(h.flow.state().name, 'error');
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.retry(), false);
});

test('an unexpected internal failure becomes internal with exit code 10', async () => {
  const policyFailure = makeHarness({ policyError: new Error('boom') });
  await policyFailure.flow.submitCode('rr1.test');
  assert.equal(policyFailure.flow.state().name, 'error');
  assert.deepEqual(lastState(policyFailure).error, { key: 'internal', sent: false });
  assert.equal(policyFailure.flow.exitCode(), 10);

  const uploadFailure = makeHarness({ uploadError: new Error('boom') });
  await reachHash(uploadFailure);
  await uploadFailure.flow.send();
  assert.equal(uploadFailure.flow.state().name, 'error');
  assert.deepEqual(lastState(uploadFailure).error, { key: 'internal', sent: false });
  assert.equal(uploadFailure.flow.exitCode(), 10);

  const declineFailure = makeHarness({ declineError: new Error('boom') });
  await reachConsent(declineFailure);
  await declineFailure.flow.decline();
  assert.deepEqual(lastState(declineFailure).error, { key: 'internal', sent: false });
  assert.equal(declineFailure.flow.exitCode(), 10);
});

test('the policy elevation flag and local-address warning are shown as received', async () => {
  const h = makeHarness({
    policy: { ...POLICY, require_elevation: true },
    parsedCode: { ...CODE, isLocalAddress: false },
  });
  await reachConsent(h);
  const consent = lastState(h);
  assert.equal(consent.elevation, true);
  assert.equal(consent.localAddress, false);
});

test('the scanning state reports a pending elevation prompt', async () => {
  const policy = { ...POLICY, require_elevation: true };
  const h = makeHarness({
    policy,
    sidecar(input) {
      assert.equal(input.elevate, true);
      input.onElevationPending();
      return { recordText: JSON.stringify(makeRecord({ policy })) };
    },
  });
  await reachConsent(h);
  await h.flow.consent();

  const scanning = h.emitted.filter((state) => state.name === 'scanning');
  assert.equal(scanning.length, 2);
  assert.equal(scanning[0].elevationPending, false);
  assert.equal(scanning[1].elevationPending, true);
  assert.equal(h.flow.state().name, 'hash');
});

test('a sidecar rejection becomes sidecar_failed with exit code 13 and sends nothing', async () => {
  const h = makeHarness({ sidecarError: new Error('scan failed') });
  await reachConsent(h);
  assert.equal(await h.flow.consent(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'sidecar_failed', sent: false });
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.exitCode(), 13);
  assert.equal(h.uploadCalls.length, 0);
  assert.equal(h.declineCalls.length, 0);
});

test('a record that is not in the expected form is refused before the hash', async () => {
  const cases = [
    { recordText: 'not json' },
    { recordText: 7 },
    { recordText: JSON.stringify(makeRecord({ binding: { ticket: TICKET, nonce: 'other' } })) },
    { recordText: JSON.stringify(makeRecord({ policy: { ...POLICY, server_name: 'Other' } })) },
    { recordText: JSON.stringify(makeRecord({ producer: { ...PRODUCER, version: '9.9.9' } })) },
    { recordText: JSON.stringify(makeRecord({ visual_hash: '0123456789ABCDEF' })) },
    { recordText: JSON.stringify(makeRecord({ visual_hash: '0123456789abcde' })) },
  ];

  for (const sidecarResult of cases) {
    const h = makeHarness({ sidecarResult });
    await reachConsent(h);
    assert.equal(await h.flow.consent(), true);
    assert.equal(h.flow.state().name, 'error');
    assert.deepEqual(lastState(h).error, { key: 'record_refused', sent: false });
    assert.equal(lastState(h).canRetry, false);
    assert.equal(h.flow.exitCode(), 14);
    assert.equal(h.emitted.some((state) => state.name === 'hash'), false);
    assert.equal(h.uploadCalls.length, 0);
    assert.equal(h.declineCalls.length, 0);
  }
});

test('a raw record over 2 MiB becomes too_large with exit code 14', async () => {
  const big = { ...makeRecord(), pad: 'x'.repeat(MAX_RECORD_BYTES) };
  const h = makeHarness({ sidecarResult: { recordText: JSON.stringify(big) } });
  await reachConsent(h);
  assert.equal(await h.flow.consent(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'too_large', sent: false });
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.exitCode(), 14);
  assert.equal(h.emitted.some((state) => state.name === 'hash'), false);
  assert.equal(h.uploadCalls.length, 0);
  assert.equal(h.declineCalls.length, 0);
});

test('a typed too-large sidecar failure becomes too_large, not sidecar_failed', async () => {
  const h = makeHarness({
    sidecarError: new SidecarError('too_large', 'the sidecar record exceeds 2 MiB'),
  });
  await reachConsent(h);
  assert.equal(await h.flow.consent(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'too_large', sent: false });
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.exitCode(), 14);
  assert.equal(h.uploadCalls.length, 0);
});

test('a request_too_large sidecar failure is sidecar_failed with exit code 13', async () => {
  const h = makeHarness({
    sidecarError: new SidecarError(
      'request_too_large',
      'the sidecar request is too large (request_too_large, 16384 bytes)',
    ),
  });
  await reachConsent(h);
  assert.equal(await h.flow.consent(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'sidecar_failed', sent: false });
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.exitCode(), 13);
  assert.equal(h.emitted.some((state) => state.name === 'hash'), false);
  assert.equal(h.uploadCalls.length, 0);
});

test('a record whose sealed envelope is over 2 MiB becomes too_large with exit code 14', async () => {
  const h = makeHarness({
    sealEnvelope: () => ({ v: 1, epk: 'e', iv: 'i', ct: 'x'.repeat(MAX_RECORD_BYTES + 1) }),
  });
  await reachConsent(h);
  assert.equal(await h.flow.consent(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'too_large', sent: false });
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.exitCode(), 14);
  assert.equal(h.emitted.some((state) => state.name === 'hash'), false);
  assert.equal(h.uploadCalls.length, 0);
  assert.equal(h.declineCalls.length, 0);
});

test('declining on consent seals and sends the declined answer without scanning', async () => {
  const h = makeHarness();
  await reachConsent(h);
  assert.equal(await h.flow.decline(), true);
  assert.equal(h.flow.state().name, 'declined');
  assert.equal(h.sidecarCalls.length, 0);
  assert.equal(h.declineCalls.length, 1);
  assert.ok(Buffer.isBuffer(h.declineCalls[0]));
  assert.equal(h.sealCalls.length, 1);
  assert.deepEqual(JSON.parse(h.sealCalls[0].plaintext), {
    scan: 'declined',
    binding: { ticket: TICKET, nonce: NONCE },
  });
  assert.equal(h.flow.exitCode(), 16);
  assert.equal(h.flow.quit(), 16);
});

test('the sidecar decline answer follows the same decline path', async () => {
  const h = makeHarness({ sidecarResult: { declined: true } });
  await reachConsent(h);
  assert.equal(await h.flow.consent(), true);
  assert.equal(h.flow.state().name, 'declined');
  assert.equal(h.declineCalls.length, 1);
  assert.equal(h.sealCalls.length, 1);
  assert.deepEqual(JSON.parse(h.sealCalls[0].plaintext), {
    scan: 'declined',
    binding: { ticket: TICKET, nonce: NONCE },
  });
  assert.equal(h.uploadCalls.length, 0);
  assert.equal(h.flow.exitCode(), 16);
  assert.equal(h.flow.quit(), 16);
});

test('a declined answer the server refuses becomes an upload error with exit code 15', async () => {
  const h = makeHarness({ declineError: new ConnectError('server_error', 'no') });
  await reachConsent(h);
  assert.equal(await h.flow.decline(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'server_error', sent: 'maybe' });
  assert.equal(h.flow.exitCode(), 15);
});

test('send twice does one upload', async () => {
  const h = makeHarness({ pendingUpload: true });
  await reachHash(h);

  const first = h.flow.send();
  assert.equal(h.flow.state().name, 'uploading');
  assert.equal(h.flow.send(), false);
  assert.equal(h.uploadCalls.length, 1);

  h.releasePendingUpload();
  assert.equal(await first, true);
  assert.equal(h.flow.state().name, 'done');
  assert.equal(h.uploadCalls.length, 1);
});

test('a retryable upload error can retry through hash and send again', async () => {
  const h = makeHarness({
    uploadError: (attempt) => (attempt === 1 ? new ConnectError('network', 'offline') : null),
  });
  await reachHash(h);

  assert.equal(await h.flow.send(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'network', sent: 'maybe' });
  assert.equal(lastState(h).canRetry, true);
  assert.equal(h.flow.exitCode(), 15);

  assert.equal(h.flow.retry(), true);
  assert.equal(h.flow.state().name, 'hash');
  assert.equal(lastState(h).name, 'hash');

  assert.equal(await h.flow.send(), true);
  assert.equal(h.flow.state().name, 'done');
  assert.equal(h.uploadCalls.length, 2);
  assert.equal(h.flow.exitCode(), 0);
});

test('retry is allowed for the four recoverable codes and never for the rest', async () => {
  const recoverable = ['network', 'timeout', 'server_error', 'upload_refused'];
  const terminal = ['ticket_used', 'expired', 'too_large', 'unknown_ticket', 'bad_request', 'redirect_refused'];
  const lostAnswer = new Set(['network', 'timeout', 'server_error']);

  for (const code of [...recoverable, ...terminal]) {
    const h = makeHarness({ uploadError: new ConnectError(code, code) });
    await reachHash(h);
    assert.equal(await h.flow.send(), true);
    assert.equal(h.flow.state().name, 'error');
    assert.deepEqual(lastState(h).error, {
      key: code,
      sent: lostAnswer.has(code) ? 'maybe' : false,
    });
    assert.equal(lastState(h).canRetry, recoverable.includes(code), code);
    assert.equal(h.flow.exitCode(), 15);
    assert.equal(h.flow.retry(), recoverable.includes(code), code);
  }
});

test('sent is false for a refusal or a bad envelope and maybe for a lost answer', async () => {
  const firstRefusal = new ConnectError('ticket_used', 'used');
  firstRefusal.sent = false;
  const refused = makeHarness({ uploadError: firstRefusal });
  await reachHash(refused);
  await refused.flow.send();
  assert.deepEqual(lastState(refused).error, { key: 'ticket_used', sent: false });
  assert.equal(refused.flow.exitCode(), 15);

  const badEnvelope = new ConnectError('bad_envelope', 'bad envelope');
  badEnvelope.sent = false;
  const bad = makeHarness({ uploadError: badEnvelope });
  await reachHash(bad);
  await bad.flow.send();
  assert.deepEqual(lastState(bad).error, { key: 'bad_envelope', sent: false });
  assert.equal(bad.flow.exitCode(), 15);

  const lost = new ConnectError('network', 'offline');
  lost.sent = true;
  const maybe = makeHarness({ uploadError: lost });
  await reachHash(maybe);
  await maybe.flow.send();
  assert.deepEqual(lastState(maybe).error, { key: 'network', sent: 'maybe' });
  assert.equal(maybe.flow.exitCode(), 15);
});

test('an upload error at the ticket expiry cannot retry', async () => {
  const h = makeHarness({
    expiresAtMs: 1_700_000_001_000,
    uploadError: new ConnectError('network', 'offline'),
  });
  await reachHash(h);
  h.setNow(1_700_000_002_000);
  assert.equal(await h.flow.send(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.equal(lastState(h).canRetry, false);
});

test('tick counts down and expires consent, scanning and hash at zero', async () => {
  const start = 1_700_000_000_000;
  const h = makeHarness({ startNow: start, expiresAtMs: start + 2_000 });
  await reachConsent(h);
  assert.equal(lastState(h).secondsLeft, 2);

  h.setNow(start + 1_000);
  assert.equal(h.flow.tick(), true);
  assert.equal(lastState(h).secondsLeft, 1);
  assert.equal(h.flow.state().name, 'consent');

  h.setNow(start + 2_500);
  assert.equal(h.flow.tick(), true);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'expired', sent: false });
  assert.equal(lastState(h).canRetry, false);
  assert.equal(h.flow.exitCode(), 15);
});

test('tick expires a scanning state and a hash state', async () => {
  const start = 1_700_000_000_000;

  let releaseScan;
  const scanning = makeHarness({
    startNow: start,
    expiresAtMs: start + 2_000,
    sidecar: () => new Promise((resolve) => { releaseScan = resolve; }),
  });
  await reachConsent(scanning);
  const pending = scanning.flow.consent();
  assert.equal(scanning.flow.state().name, 'scanning');
  scanning.setNow(start + 2_500);
  assert.equal(scanning.flow.tick(), true);
  assert.equal(scanning.flow.state().name, 'error');
  assert.deepEqual(lastState(scanning).error, { key: 'expired', sent: false });
  assert.equal(scanning.flow.exitCode(), 15);
  releaseScan({ recordText: JSON.stringify(makeRecord()) });
  await pending;
  assert.equal(scanning.flow.state().name, 'error');

  const hashing = makeHarness({ startNow: start, expiresAtMs: start + 2_000 });
  await reachHash(hashing);
  assert.equal(lastState(hashing).secondsLeft, 2);
  hashing.setNow(start + 1_000);
  assert.equal(hashing.flow.tick(), true);
  assert.equal(lastState(hashing).secondsLeft, 1);
  hashing.setNow(start + 2_500);
  assert.equal(hashing.flow.tick(), true);
  assert.equal(hashing.flow.state().name, 'error');
  assert.deepEqual(lastState(hashing).error, { key: 'expired', sent: false });
  assert.equal(hashing.flow.exitCode(), 15);
});

test('quit during a scan cancels it and a late result changes nothing', async () => {
  let cancelCalls = 0;
  let release = null;
  const h = makeHarness({
    sidecar(input) {
      input.onCancel(() => { cancelCalls += 1; });
      return new Promise((resolve) => { release = resolve; });
    },
  });
  await reachConsent(h);
  const pending = h.flow.consent();
  assert.equal(h.flow.state().name, 'scanning');
  assert.equal(cancelCalls, 0);

  assert.equal(h.flow.quit(), 11);
  assert.equal(cancelCalls, 1);
  assert.equal(h.flow.quit(), 11);
  assert.equal(cancelCalls, 1);

  release({ recordText: JSON.stringify(makeRecord()) });
  assert.equal(await pending, false);
  assert.equal(h.flow.state().name, 'scanning');
  assert.equal(h.flow.exitCode(), 11);
});

test('tick expiry during a scan cancels it and a late result keeps the expired error', async () => {
  const start = 1_700_000_000_000;
  let cancelCalls = 0;
  let release = null;
  const h = makeHarness({
    startNow: start,
    expiresAtMs: start + 2_000,
    sidecar(input) {
      input.onCancel(() => { cancelCalls += 1; });
      return new Promise((resolve) => { release = resolve; });
    },
  });
  await reachConsent(h);
  const pending = h.flow.consent();
  assert.equal(h.flow.state().name, 'scanning');

  h.setNow(start + 2_500);
  assert.equal(h.flow.tick(), true);
  assert.equal(cancelCalls, 1);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'expired', sent: false });
  assert.equal(h.flow.exitCode(), 15);

  release({ recordText: JSON.stringify(makeRecord()) });
  assert.equal(await pending, false);
  assert.equal(h.flow.state().name, 'error');
  assert.deepEqual(lastState(h).error, { key: 'expired', sent: false });
  assert.equal(h.flow.exitCode(), 15);
});

test('quit returns 11 in every state before anything failed or was sent', async () => {
  const cases = ['paste', 'checking', 'consent', 'scanning', 'hash'];

  for (const state of cases) {
    let harness;
    let pending = null;
    let release = null;
    if (state === 'paste') {
      harness = makeHarness();
    } else if (state === 'checking') {
      harness = makeHarness();
      let resolveClient;
      const waiting = new Promise((resolve) => { resolveClient = resolve; });
      const flow = createFlow({
        parseCode: () => CODE,
        makeClient: async () => {
          await waiting;
          return harness.client;
        },
        sealEnvelope: () => ({ v: 1 }),
        runSidecar: async () => ({ recordText: JSON.stringify(makeRecord()) }),
        now: () => 1_700_000_000_000,
        emit: (value) => harness.emitted.push(value),
        version: VERSION,
      });
      harness.flow = flow;
      pending = flow.submitCode('rr1.test');
      assert.equal(flow.state().name, 'checking');
      assert.equal(flow.quit(), 11);
      resolveClient();
      await pending;
    } else if (state === 'consent') {
      harness = makeHarness();
      await reachConsent(harness);
    } else if (state === 'scanning') {
      harness = makeHarness({ sidecar: () => new Promise((resolve) => { release = resolve; }) });
      await reachConsent(harness);
      pending = harness.flow.consent();
      assert.equal(harness.flow.state().name, 'scanning');
    } else {
      harness = makeHarness();
      await reachHash(harness);
    }

    assert.equal(harness.flow.quit(), 11, state);
    assert.equal(harness.uploadCalls.length, 0, state);
    assert.equal(harness.declineCalls.length, 0, state);

    if (state === 'scanning') {
      release({ recordText: JSON.stringify(makeRecord()) });
      await pending;
    }
  }
});

test('quit during an upload returns 15 because part may have gone out', async () => {
  const h = makeHarness({ pendingUpload: true });
  await reachHash(h);
  const pending = h.flow.send();
  assert.equal(h.flow.state().name, 'uploading');
  assert.equal(h.uploadCalls.length, 1);

  assert.equal(h.flow.quit(), 15);

  h.releasePendingUpload();
  await pending;
  assert.equal(h.flow.state().name, 'done');
  assert.equal(h.flow.exitCode(), 15);
  assert.equal(h.flow.quit(), 15);
});

test('quit keeps an exit code an earlier error set, from 12 to 15', async () => {
  const parse = makeHarness({ parseError: new Error('bad') });
  await parse.flow.submitCode('rr1.test');
  assert.equal(parse.flow.exitCode(), 12);
  assert.equal(parse.flow.quit(), 12);

  const sidecar = makeHarness({ sidecarError: new Error('scan failed') });
  await reachConsent(sidecar);
  await sidecar.flow.consent();
  assert.equal(sidecar.flow.exitCode(), 13);
  assert.equal(sidecar.flow.quit(), 13);

  const record = makeHarness({ sidecarResult: { recordText: 'not json' } });
  await reachConsent(record);
  await record.flow.consent();
  assert.equal(record.flow.exitCode(), 14);
  assert.equal(record.flow.quit(), 14);

  const upload = makeHarness({ uploadError: new ConnectError('ticket_used', 'used') });
  await reachHash(upload);
  await upload.flow.send();
  assert.equal(upload.flow.exitCode(), 15);
  assert.equal(upload.flow.quit(), 15);

  const policy = makeHarness({ policyError: new ConnectError('network', 'offline') });
  await policy.flow.submitCode('rr1.test');
  assert.equal(policy.flow.exitCode(), 15);
  assert.equal(policy.flow.quit(), 15);
});

test('quit returns 0 after a report was accepted and 16 after a declined answer', async () => {
  const done = makeHarness();
  await reachHash(done);
  await done.flow.send();
  assert.equal(done.flow.quit(), 0);

  const declined = makeHarness();
  await reachConsent(declined);
  await declined.flow.decline();
  assert.equal(declined.flow.exitCode(), 16);
  assert.equal(declined.flow.quit(), 16);
});

test('wrong-state calls do nothing and return false', async () => {
  const h = makeHarness();
  assert.equal(h.flow.consent(), false);
  assert.equal(h.flow.decline(), false);
  assert.equal(h.flow.send(), false);
  assert.equal(h.flow.retry(), false);
  assert.equal(h.flow.tick(), false);

  await reachConsent(h);
  assert.equal(h.flow.submitCode('rr1.again'), false);
  assert.equal(h.flow.send(), false);
  assert.equal(h.flow.retry(), false);

  await h.flow.consent();
  assert.equal(h.flow.submitCode('rr1.again'), false);
  assert.equal(h.flow.decline(), false);

  await h.flow.send();
  assert.equal(h.flow.submitCode('rr1.again'), false);
  assert.equal(h.flow.send(), false);
  assert.equal(h.flow.consent(), false);

  const failed = makeHarness({
    uploadError: new ConnectError('ticket_used', 'used'),
  });
  await reachHash(failed);
  await failed.flow.send();
  assert.equal(failed.flow.retry(), false);
  assert.equal(failed.flow.send(), false);
});

test('submitCode from an error before a code was accepted tries again', async () => {
  const h = makeHarness({ parseError: new Error('bad') });
  await h.flow.submitCode('rr1.bad');
  assert.equal(h.flow.state().name, 'error');

  const retry = makeHarness();
  const flow = createFlow({
    parseCode: (code) => (code === 'rr1.good' ? CODE : null),
    makeClient: () => retry.client,
    sealEnvelope: () => ({ v: 1 }),
    runSidecar: async () => ({ recordText: JSON.stringify(makeRecord()) }),
    now: () => 1_700_000_000_000,
    emit: (state) => retry.emitted.push(state),
    version: VERSION,
  });
  await flow.submitCode('rr1.bad');
  assert.equal(flow.state().name, 'error');
  await flow.submitCode('rr1.good');
  assert.equal(flow.state().name, 'consent');
});

test('no emitted state carries the ticket, the nonce or the kit key', async () => {
  const h = makeHarness();
  await reachHash(h);
  await h.flow.send();

  for (const state of [...h.emitted, h.flow.state()]) {
    const json = JSON.stringify(state);
    assert.equal(json.includes(TICKET), false, json);
    assert.equal(json.includes(NONCE), false, json);
    assert.equal(json.includes(KIT), false, json);
  }
});

test('the record displayed on hash is the record redacted for the renderer', async () => {
  const record = makeRecord();
  const original = JSON.stringify(record);
  const h = makeHarness({ sidecarResult: { recordText: original } });
  await reachHash(h);

  const hash = lastState(h);
  assert.equal(hash.recordText.includes(TICKET), false);
  assert.equal(hash.recordText.includes(NONCE), false);
  assert.equal(hash.recordText.includes('[redacted]'), true);
  assert.equal(JSON.parse(hash.recordText).visual_hash, HASH);
  assert.equal(JSON.parse(hash.recordText).binding.ticket, '[redacted]');
  assert.equal(JSON.parse(hash.recordText).binding.nonce, '[redacted]');

  // The record handed to the envelope is the original text, not the display copy.
  assert.equal(h.sealCalls[h.sealCalls.length - 1].plaintext, original);
});

test('the canonical comparison accepts objects with the same members in another order', async () => {
  const policy = {
    server_name: POLICY.server_name,
    policy_hash: POLICY.policy_hash,
    require_elevation: POLICY.require_elevation,
    required_collectors: POLICY.required_collectors,
    profile: POLICY.profile,
  };
  const h = makeHarness({ policy, recordOverrides: { policy } });
  await reachHash(h);
  assert.equal(canonicalize(policy), canonicalize(POLICY));
  assert.equal(h.flow.state().name, 'hash');
});
