// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createHash } = require('node:crypto');
const { policyHash } = require('../src/core/canonical');
const { PairedClient, ConnectError } = require('../src/main/net');

const TICKET = '9f82c4e1b07a412891d604e38a291bf0';
const POLICY = {
  profile: 'posture',
  required_collectors: ['posture', 'os_image'],
  require_elevation: false,
  server_name: 'Example City',
  expires_at: '2099-01-01T00:00:00Z',
};
const POLICY_HASH = policyHash(POLICY);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const isCode = (code) => (error) => error instanceof ConnectError && error.code === code;

function policyBody(overrides = {}) {
  const policy = { ...POLICY, ...overrides };
  policy.policy_hash = policyHash(policy);
  return policy;
}

function makeClient(origin, options = {}) {
  return new PairedClient({
    origin,
    ticket: TICKET,
    fetchImpl: options.fetchImpl,
    now: options.now,
    sleep: options.sleep,
    timeoutMs: options.timeoutMs ?? 5000,
  });
}

async function withServer(handler, run) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const entry = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks),
      };
      requests.push(entry);
      handler(req, res, entry, requests);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await run(`http://127.0.0.1:${server.address().port}`, requests);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test('fetches the policy and verifies its hash', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(policyBody()));
  }, async (origin, requests) => {
    const client = makeClient(origin);
    const policy = await client.getPolicy(POLICY_HASH);

    assert.equal(policy.server_name, POLICY.server_name);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'GET');
    assert.equal(requests[0].url, `/nakara_rongroi/policy/${TICKET}`);
  });
});

test('refuses a policy whose hash does not match', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(policyBody()));
  }, async (origin) => {
    const client = makeClient(origin);
    await assert.rejects(client.getPolicy('0000000000000000'), isCode('policy_mismatch'));
  });
});

test('maps an unknown or expired policy ticket', async () => {
  for (const [status, code] of [[404, 'unknown_ticket'], [410, 'expired']]) {
    await withServer((req, res) => {
      res.writeHead(status);
      res.end();
    }, async (origin) => {
      const client = makeClient(origin);
      await assert.rejects(client.getPolicy(POLICY_HASH), isCode(code));
    });
  }
});

test('refuses a redirect instead of following it', async () => {
  await withServer((req, res) => {
    res.writeHead(302, { Location: `/nakara_rongroi/policy/${TICKET}` });
    res.end();
  }, async (origin, requests) => {
    const client = makeClient(origin);
    await assert.rejects(client.getPolicy(POLICY_HASH), isCode('redirect_refused'));
    assert.equal(requests.length, 1);
  });
});

test('refuses another origin in the constructor and on every call', async () => {
  assert.throws(
    () => new PairedClient({ origin: 'http://example.com/path', ticket: TICKET }),
    isCode('bad_origin'),
  );
  assert.throws(
    () => new PairedClient({ origin: 'ftp://example.com', ticket: TICKET }),
    isCode('bad_origin'),
  );

  let fetched = false;
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: () => { fetched = true; throw new Error('must not fetch'); },
  });
  assert.throws(() => client.urlFor('https://evil.example/steal'), isCode('bad_path'));
  assert.throws(() => client.urlFor('//evil.example/steal'), isCode('bad_path'));
  assert.throws(() => client.urlFor('../admin'), isCode('bad_path'));
  await assert.rejects(client.request('https://evil.example/steal'), isCode('bad_path'));
  assert.equal(fetched, false);
  assert.equal(
    client.urlFor(`policy/${TICKET}`).href,
    `http://127.0.0.1:9/nakara_rongroi/policy/${TICKET}`,
  );
});

test('uploads a small envelope directly', async () => {
  const envelope = Buffer.from('a small sealed envelope');
  await withServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    const result = await client.upload(envelope);

    assert.deepEqual(result, { status: 'accepted' });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].url, '/nakara_rongroi/report');
    assert.equal(requests[0].headers['x-rongroi-upload-id'], TICKET);
    assert.equal(requests[0].headers['x-rongroi-report-sha256'], sha256(envelope));
    assert.deepEqual(requests[0].body, envelope);
  });
});

test('chunks 9000 bytes into 3 slices with the required headers', async () => {
  const envelope = Buffer.alloc(9000);
  for (let index = 0; index < envelope.length; index += 1) envelope[index] = index % 251;

  await withServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    const result = await client.upload(envelope);

    assert.deepEqual(result, { status: 'accepted' });
    assert.equal(requests.length, 3);
    assert.deepEqual(requests.map((request) => request.body.length), [4096, 4096, 808]);
    assert.deepEqual(
      requests.map((request) => request.headers['x-rongroi-chunk-index']),
      ['0', '1', '2'],
    );
    for (const request of requests) {
      assert.equal(request.url, '/nakara_rongroi/report/chunk');
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['x-rongroi-upload-id'], TICKET);
      assert.equal(request.headers['x-rongroi-chunk-total'], '3');
      assert.equal(request.headers['x-rongroi-chunk-sha256'], sha256(request.body));
      assert.equal(request.headers['x-rongroi-report-sha256'], sha256(envelope));
    }
    assert.deepEqual(Buffer.concat(requests.map((request) => request.body)), envelope);
  });
});

test('restarts the whole upload once after a 422', async () => {
  const envelope = Buffer.alloc(9000, 3);
  await withServer((req, res, entry, all) => {
    if (all.length === 1) {
      res.writeHead(422);
      res.end('restart');
      return;
    }
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    const result = await client.upload(envelope);

    assert.deepEqual(result, { status: 'accepted' });
    assert.equal(requests.length, 4);
    assert.deepEqual(
      requests.map((request) => request.headers['x-rongroi-chunk-index']),
      ['0', '0', '1', '2'],
    );
  });
});

test('does not restart a second time after a 422', async () => {
  await withServer((req, res) => {
    res.writeHead(422);
    res.end('restart');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    await assert.rejects(client.upload(Buffer.alloc(9000)), isCode('upload_refused'));
    assert.equal(requests.length, 2);
  });
});

test('honours Retry-After on a 429 with the injected sleep', async () => {
  const sleeps = [];
  await withServer((req, res, entry, all) => {
    if (all.length === 1) {
      res.writeHead(429, { 'Retry-After': '2' });
      res.end();
      return;
    }
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin, { sleep: async (ms) => { sleeps.push(ms); } });
    const result = await client.upload(Buffer.from('direct'));

    assert.deepEqual(result, { status: 'accepted' });
    assert.deepEqual(sleeps, [2000]);
    assert.equal(requests.length, 2);
  });
});

test('stops on a 409 without retrying', async () => {
  await withServer((req, res) => {
    res.writeHead(409);
    res.end('used');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    await assert.rejects(client.upload(Buffer.from('direct')), isCode('ticket_used'));
    assert.equal(requests.length, 1);
  });
});

test('times out a policy request', async () => {
  await withServer(() => {}, async (origin) => {
    const client = makeClient(origin, { timeoutMs: 100 });
    await assert.rejects(client.getPolicy(POLICY_HASH), isCode('timeout'));
  });
});

test('retries upload timeouts on the schedule, then fails', async () => {
  const sleeps = [];
  await withServer(() => {}, async (origin, requests) => {
    const client = makeClient(origin, {
      timeoutMs: 100,
      sleep: async (ms) => { sleeps.push(ms); },
    });
    await assert.rejects(client.upload(Buffer.from('direct')), isCode('timeout'));

    assert.deepEqual(sleeps, [500, 1500, 3000]);
    assert.equal(requests.length, 4);
  });
});
