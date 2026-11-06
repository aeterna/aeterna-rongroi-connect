// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const PairedClient = require('../../src/main/net');
const { ConnectError } = PairedClient;
const { sealEnvelope } = require('../../src/core/envelope');
const { policyHash, visualHash } = require('../../src/core/canonical');
const { DIRECT_LIMIT, SLICE_SIZE } = require('../../src/core/upload-plan');
const { parsePairingCode } = require('../../src/core/pairing');
const { startKit, STANDARD_COLLECTORS } = require('./kit');

const ROOT = path.resolve(__dirname, '..', '..');
const KIT_PATH = path.join(__dirname, 'kit.js');

const isCode = (code) => (error) => error instanceof ConnectError && error.code === code;

function spawnKitChild(environment = {}) {
  const env = { ...process.env, ...environment };
  delete env.NODE_TEST_CONTEXT;

  const child = spawn(process.execPath, [KIT_PATH], {
    cwd: ROOT,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });

  const exited = new Promise((resolve) => {
    const finish = (result) => {
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish({
        code: null,
        signal: null,
        error: new Error(`the mock kit child did not exit: ${stderr}`),
      });
    }, 5000);

    child.on('error', (error) => finish({ code: null, signal: null, error }));
    child.on('exit', (code, signal) => finish({ code, signal, error: null }));
  });

  function firstMessage() {
    return new Promise((resolve, reject) => {
      let buffered = '';
      let settled = false;

      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        callback(value);
      };

      const timer = setTimeout(() => {
        finish(reject, new Error(`the mock kit child did not print a code: ${stderr}`));
      }, 5000);

      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk) => {
        if (settled) return;
        buffered += chunk;
        let newline = buffered.indexOf('\n');
        while (newline !== -1) {
          const line = buffered.slice(0, newline).trim();
          buffered = buffered.slice(newline + 1);
          if (line !== '') {
            try {
              const message = JSON.parse(line);
              if (message !== null && typeof message === 'object'
                  && typeof message.code === 'string' && Number.isInteger(message.port)) {
                finish(resolve, message);
                return;
              }
            } catch {
              // A non-JSON line is not the pairing code.
            }
          }
          newline = buffered.indexOf('\n');
        }
      });
      child.on('error', (error) => finish(reject, error));
      child.on('exit', (code, signal) => {
        finish(reject, new Error(
          `the mock kit child exited before printing a code (${code ?? signal}): ${stderr}`,
        ));
      });
    });
  }

  return { child, exited, firstMessage, stderr: () => stderr };
}

async function stopKitChild(handle) {
  if (handle.child.exitCode === null && handle.child.signalCode === null) {
    handle.child.kill();
  }
  return handle.exited;
}

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

function declinedRecordFor(kit, mutate) {
  // The real declined answer carries only the scan marker and the binding;
  // it has no schema and no visual hash.
  const record = {
    scan: 'declined',
    binding: { ticket: kit.ticket, nonce: kit.nonce },
  };
  if (typeof mutate === 'function') mutate(record);
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

test('the child process serves the policy from RONGROI_MOCK_KIT_POLICY', async () => {
  const policy = {
    profile: 'standard',
    required_collectors: STANDARD_COLLECTORS,
    require_elevation: true,
  };
  const handle = spawnKitChild({
    RONGROI_MOCK_KIT_POLICY: JSON.stringify(policy),
  });

  try {
    const message = await handle.firstMessage();
    const parsed = parsePairingCode(message.code);
    assert.equal(parsed.serverOrigin, `http://127.0.0.1:${message.port}`);

    const response = await fetch(
      `${parsed.serverOrigin}/nakara_rongroi/policy/${parsed.ticket}`,
    );
    assert.equal(response.status, 200);
    const served = await response.json();

    assert.equal(served.profile, 'standard');
    assert.deepEqual(served.required_collectors, [...STANDARD_COLLECTORS]);
    assert.equal(served.required_collectors.length, 20);
    assert.equal(served.require_elevation, true);
    assert.equal(served.policy_hash, parsed.policyHash);
    assert.deepEqual(Object.keys(served).sort(), [
      'policy_hash',
      'profile',
      'require_elevation',
      'required_collectors',
      'server_name',
    ]);
  } finally {
    await stopKitChild(handle);
  }
});

test('the child process refuses an invalid RONGROI_MOCK_KIT_POLICY', async () => {
  for (const raw of ['not-json', '[]', 'null']) {
    const handle = spawnKitChild({ RONGROI_MOCK_KIT_POLICY: raw });
    try {
      const result = await handle.exited;
      assert.equal(result.error, null, raw);
      assert.notEqual(result.code, 0, raw);
    } finally {
      await stopKitChild(handle);
    }
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

test('captures the report kind, official build and policy facts instead of elevation', async () => {
  const kit = await startKit({
    print: false,
    policy: {
      profile: 'standard',
      required_collectors: ['posture', 'os_image'],
      require_elevation: true,
    },
  });
  try {
    const record = recordFor(kit, (candidate) => {
      candidate.kind = 'rongroi-saved-report';
      candidate.official_build = true;
    });
    await clientFor(kit).upload(sealedBytes(kit, record));

    assert.equal(kit.recordKind, 'rongroi-saved-report');
    assert.equal(kit.officialBuild, true);
    assert.equal(kit.policyProfile, kit.policy.profile);
    assert.equal(kit.policyRequireElevation, kit.policy.require_elevation);
    assert.equal(kit.policyCollectorCount, kit.policy.required_collectors.length);
    // The real saved report has no `elevated` member, so the mock must not
    // pretend to measure elevation either.
    assert.equal('elevated' in kit, false);
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

test('refuses a record whose binding ticket does not match the code', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = recordFor(kit, (candidate) => {
      candidate.binding.ticket = 'not-the-code-ticket';
    });
    await assert.rejects(
      clientFor(kit).upload(sealedBytes(kit, record)),
      isCode('bad_request'),
    );
    assert.equal(kit.requests, 1);
    assert.equal(kit.received, 0);
    assert.equal(kit.visualHash, null);
  } finally {
    await kit.close();
  }
});

test('accepts a sealed declined answer without a schema or a visual hash', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = declinedRecordFor(kit);
    assert.equal('schema' in record, false);
    assert.equal('visual_hash' in record, false);

    assert.deepEqual(
      await clientFor(kit).decline(sealedBytes(kit, record)),
      { status: 'declined' },
    );
    assert.equal(kit.declined, true);
    assert.equal(kit.received, 1);
    assert.equal(kit.record, null);
    assert.equal(kit.visualHash, null);
  } finally {
    await kit.close();
  }
});

test('refuses a declined answer whose binding nonce does not match the code', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = declinedRecordFor(kit, (candidate) => {
      candidate.binding.nonce = 'not-the-code-nonce';
    });
    await assert.rejects(
      clientFor(kit).decline(sealedBytes(kit, record)),
      isCode('bad_request'),
    );
    assert.equal(kit.declined, false);
    assert.equal(kit.received, 0);
  } finally {
    await kit.close();
  }
});

test('refuses a declined answer whose binding ticket does not match the code', async () => {
  const kit = await startKit({ print: false });
  try {
    const record = declinedRecordFor(kit, (candidate) => {
      candidate.binding.ticket = 'not-the-code-ticket';
    });
    await assert.rejects(
      clientFor(kit).decline(sealedBytes(kit, record)),
      isCode('bad_request'),
    );
    assert.equal(kit.declined, false);
    assert.equal(kit.received, 0);
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
