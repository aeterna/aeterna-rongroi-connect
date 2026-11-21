// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// rr2 codes and the relay transport in the flow (ADR 0003): envelope v2, client options, the waiting state, exit 17.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createFlow, RELAY_WAITING_EXIT_CODE } = require('../src/main/flow');

const TICKET = '9f82c4e1b07a412891d604e38a291bf0';
const NONCE = 'nonce-abc-123';
const KIT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const POLICY = { profile: 'posture', required_collectors: ['posture'], require_elevation: false, server_name: 'Relay City', policy_hash: '0123456789abcdef' };
const BINDING = { base_path: 'srv1', policy_hash: '0123456789abcdef', server_origin: 'https://relay.example.org', ticket: TICKET, transport: 'relay' };
const CODE = { version: 2, basePath: 'srv1', transport: 'relay', binding: BINDING, serverOrigin: 'https://relay.example.org',
  ticket: TICKET, nonce: NONCE, expiresAt: '2099-01-01T00:00:00Z', policyHash: '0123456789abcdef', kitPublicKey: KIT, isLocalAddress: false };

function harness(uploadResult) {
  const emitted = [];
  const clientInputs = [];
  const seals = { v1: 0, v2: [] };
  const flow = createFlow({
    parseCode: () => CODE,
    makeClient: (input) => {
      clientInputs.push(input);
      return {
        expiresAtMs: Date.now() + 300000,
        getPolicy: async () => POLICY,
        upload: async () => uploadResult,
        decline: async () => (uploadResult.status === 'waiting' ? uploadResult : { status: 'declined' }),
      };
    },
    sealEnvelope: () => { seals.v1 += 1; return { v: 1 }; },
    sealEnvelopeV2: (plain, kit, binding) => { seals.v2.push(binding); return { v: 2, epk: 'e', iv: 'i', ct: 'c' }; },
    runSidecar: async (input) => ({ recordText: JSON.stringify({ schema: 2, binding: input.binding, policy: input.policy,
      producer: input.producer, visual_hash: '0123456789abcdef', facts: [] }) }),
    emit: (s) => emitted.push(s),
    version: '0.1.0',
  });
  return { flow, emitted, clientInputs, seals };
}

test('an rr2 relay code passes base path and transport to the client and shows the relay line', async () => {
  const h = harness({ status: 'accepted' });
  await h.flow.submitCode('rr2.x');
  assert.deepEqual(h.clientInputs[0], { origin: 'https://relay.example.org', ticket: TICKET, expiresAt: '2099-01-01T00:00:00Z',
    basePath: 'srv1', transport: 'relay' });
  assert.equal(h.emitted.at(-1).name, 'consent');
  assert.equal(h.emitted.at(-1).viaRelay, true);
});

test('an rr2 code seals envelope v2 with the code binding; accepted ends in done and exit 0', async () => {
  const h = harness({ status: 'accepted' });
  await h.flow.submitCode('rr2.x');
  await h.flow.consent();
  await h.flow.send();
  assert.equal(h.seals.v1, 0);
  assert.deepEqual(h.seals.v2.at(-1), BINDING);
  assert.equal(h.emitted.at(-1).name, 'done');
  assert.equal(h.flow.exitCode(), 0);
});

test('no confirmation from the server ends in waiting with exit 17, never done', async () => {
  const h = harness({ status: 'waiting' });
  await h.flow.submitCode('rr2.x');
  await h.flow.consent();
  await h.flow.send();
  assert.equal(h.emitted.at(-1).name, 'waiting');
  assert.equal(h.flow.exitCode(), RELAY_WAITING_EXIT_CODE);
  assert.equal(RELAY_WAITING_EXIT_CODE, 17);
  assert.ok(!h.emitted.some((s) => s.name === 'done'));
});

test('a declined answer through a relay that is not confirmed is also waiting with exit 17', async () => {
  const h = harness({ status: 'waiting' });
  await h.flow.submitCode('rr2.x');
  await h.flow.decline();
  assert.equal(h.emitted.at(-1).name, 'waiting');
  assert.equal(h.emitted.at(-1).declined, true);
  assert.equal(h.flow.exitCode(), 17);
});
