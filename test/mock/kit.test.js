// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const PairedClient = require('../../src/main/net');
const { ConnectError } = PairedClient;
const { sealEnvelope } = require('../../src/core/envelope');
const { policyHash, visualHash } = require('../../src/core/canonical');
const { DIRECT_LIMIT, SLICE_SIZE } = require('../../src/core/upload-plan');
const { parsePairingCode } = require('../../src/core/pairing');
const { startKit } = require('./kit');

const isCode = (code) => (error) => error instanceof ConnectError && error.code === code;

function clientFor(kit, options = {}) {
  return new PairedClient({
    origin: kit.origin,
    ticket: kit.ticket,
    fetchImpl: fetch,
    ...options,
  });
}

function recordFor(kit, mutate) {
  const record = {
    schema: 2,
    binding: { nonce: kit.nonce, ticket: kit.ticket },
    policy: kit.policy,
    producer: { name: 'rongroi-connect', version: '0.1.0', mode: 'single-shot' },
    rongroi_version: 'mock',
    scan: { mock: true },
  };
  if (typeof mutate === 'function') mutate(record);
  record.visual_hash = visualHash(record);
  return record;
}

function sealedBytes(kit, record) {
  const envelope = sealEnvelope(JSON.stringify(record), kit.publicKey, kit.ticket);
  return Buffer.from(JSON.stringify(envelope), 'utf8');
}

test('issues a parseable code and serves the five-member policy it hashes', async () => {
  const kit = await startKit({ print: false });
  try {
    const parsed = parsePairingCode(kit.code);
    assert.equal(parsed.serverOrigin, kit.origin);
    assert.equal(parsed.ticket, kit.ticket);
    assert.equal(parsed.nonce, kit.nonce);
    assert.equal(parsed.policyHash, policyHash(kit.policy));
    assert.equal(parsed.policyHash, kit.policy.policy_hash);
    assert.equal(parsed.expiresAt, kit.expiresAt);
    assert.deepEqual(Object.keys(kit.policy).sort(), [
      'policy_hash',
      'profile',
      'require_elevation',
      'required_collectors',
      'server_name',
    ]);

    const response = await fetch(`${kit.origin}/nakara_rongroi/policy/${kit.ticket}`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('date') || '', /GMT$/);
    const served = await response.json();
    assert.deepEqual(served, kit.policy);
    assert.equal(served.policy_hash, parsed.policyHash);

    const client = clientFor(kit);
    const policy = await client.getPolicy(parsed.policyHash);
    assert.equal(policy.server_name, kit.policy.server_name);
    assert.equal(kit.requests, 0);
  } finally {
    await kit.close();
  }
});

test('serves policy overrides and hashes them into the pairing code', async () => {
  const kit = await startKit({
    print: false,
    policy: {
      profile: 'custom',
      required_collectors: ['posture', 'os_image', 'defender_exclusion'],
      require_elevation: true,
    },
  });
  try {
    const parsed = parsePairingCode(kit.code);
    assert.equal(kit.policy.profile, 'custom');
    assert.deepEqual(
      kit.policy.required_collectors,
      ['posture', 'os_image', 'defender_exclusion'],
    );
    assert.equal(kit.policy.require_elevation, true);
    assert.equal(kit.policy.policy_hash, policyHash(kit.policy));
    assert.equal(parsed.policyHash, kit.policy.policy_hash);

    const response = await fetch(`${kit.origin}/nakara_rongroi/policy/${kit.ticket}`);
    assert.deepEqual(await response.json(), kit.policy);

    const client = clientFor(kit);
    const policy = await client.getPolicy(parsed.policyHash);
    assert.equal(policy.profile, 'custom');
    assert.deepEqual(policy.required_collectors, kit.policy.required_collectors);
    assert.equal(policy.require_elevation, true);
  } finally {
    await kit.close();
  }
});

test('accepts an envelope, stores the recomputed hash and accepts it again', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = recordFor(kit);
    const bytes = sealedBytes(kit, record);
    const client = clientFor(kit);

    assert.deepEqual(await client.upload(bytes), { status: 'accepted' });
    assert.equal(kit.received, 1);
    assert.equal(kit.visualHash, visualHash(record));
    assert.equal(kit.record.scan.mock, true);

    // A retry after a lost answer carries the same accepted envelope.
    assert.deepEqual(await client.upload(bytes), { status: 'accepted' });
    assert.equal(kit.received, 2);
    assert.equal(kit.visualHash, visualHash(record));
  } finally {
    await kit.close();
  }
});

test('refuses a record whose binding nonce does not match the code', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = recordFor(kit, (candidate) => {
      candidate.binding.nonce = 'not-the-code-nonce';
    });
    await assert.rejects(
      clientFor(kit).upload(sealedBytes(kit, record)),
      isCode('bad_request'),
    );
    assert.equal(kit.requests, 1);
    assert.equal(kit.visualHash, null);
  } finally {
    await kit.close();
  }
});

test('recomputes the visual hash instead of trusting the record', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = recordFor(kit);
    const expected = visualHash(record);
    record.visual_hash = '0000000000000000';

    await assert.doesNotReject(clientFor(kit).upload(sealedBytes(kit, record)));
    assert.equal(kit.visualHash, expected);
    assert.notEqual(kit.visualHash, record.visual_hash);
  } finally {
    await kit.close();
  }
});

test('reassembles the slices of a chunked envelope', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = recordFor(kit, (candidate) => {
      candidate.scan.padding = 'x'.repeat(9000);
    });
    const bytes = sealedBytes(kit, record);
    assert.ok(bytes.length > DIRECT_LIMIT);

    assert.deepEqual(await clientFor(kit).upload(bytes), { status: 'accepted' });
    assert.equal(kit.requests, Math.ceil(bytes.length / SLICE_SIZE));
    assert.equal(kit.visualHash, visualHash(record));
  } finally {
    await kit.close();
  }
});

const failing = [
  [400, 'bad_request'],
  [404, 'unknown_ticket'],
  [409, 'ticket_used'],
  [410, 'expired'],
  [413, 'too_large'],
];

for (const [status, code] of failing) {
  test(`answers ${status} once and makes the client stop`, async () => {
    const kit = await startKit({ status, print: false });
    try {
      const bytes = sealedBytes(kit, recordFor(kit));
      await assert.rejects(clientFor(kit).upload(bytes), isCode(code));
      assert.equal(kit.requests, 1);
      assert.equal(kit.visualHash, null);
    } finally {
      await kit.close();
    }
  });
}

test('answers 422 once and lets the client restart the upload', async () => {
  const kit = await startKit({ status: 422, print: false });
  try {
    const record = recordFor(kit);
    const sleeps = [];
    const client = clientFor(kit, { sleep: async (millis) => { sleeps.push(millis); } });

    assert.deepEqual(await client.upload(sealedBytes(kit, record)), { status: 'accepted' });
    assert.equal(kit.requests, 2);
    assert.deepEqual(sleeps, []);
    assert.equal(kit.visualHash, visualHash(record));
  } finally {
    await kit.close();
  }
});

test('honours Retry-After on a one-shot 429', async () => {
  const kit = await startKit({ status: 429, print: false });
  try {
    const record = recordFor(kit);
    const sleeps = [];
    const client = clientFor(kit, { sleep: async (millis) => { sleeps.push(millis); } });

    assert.deepEqual(await client.upload(sealedBytes(kit, record)), { status: 'accepted' });
    assert.equal(kit.requests, 2);
    assert.deepEqual(sleeps, [0]);
    assert.equal(kit.visualHash, visualHash(record));
  } finally {
    await kit.close();
  }
});

for (const status of [500, 503, 599]) {
  test(`retries a one-shot ${status} on the 500 ms schedule`, async () => {
    const kit = await startKit({ status, print: false });
    try {
      const record = recordFor(kit);
      const sleeps = [];
      const client = clientFor(kit, { sleep: async (millis) => { sleeps.push(millis); } });

      assert.deepEqual(await client.upload(sealedBytes(kit, record)), { status: 'accepted' });
      assert.equal(kit.requests, 2);
      assert.deepEqual(sleeps, [500]);
      assert.equal(kit.visualHash, visualHash(record));
    } finally {
      await kit.close();
    }
  });
}
