// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createHash } = require('node:crypto');
const { policyHash } = require('../src/core/canonical');
const {
  PairedClient,
  ConnectError,
  MAX_RESPONSE_BYTES,
  POLICY_TIMEOUT_MS,
  UPLOAD_TIMEOUT_MS,
} = require('../src/main/net');

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
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
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

test('asks fetch for redirect: error and maps a rejected redirect', async () => {
  let seen;
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: async (url, init) => {
      seen = init;
      const error = new TypeError('fetch failed');
      error.cause = Object.assign(new Error('unexpected redirect'), {
        code: 'unexpected-redirect',
      });
      throw error;
    },
  });

  await assert.rejects(client.request(`policy/${TICKET}`), isCode('redirect_refused'));
  assert.equal(seen.redirect, 'error');
});

test('refuses a 3xx response that still arrives and cancels its body', async () => {
  let cancelled = false;
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: async () => ({
      status: 302,
      headers: new Headers(),
      body: new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
    }),
  });

  await assert.rejects(client.request(`policy/${TICKET}`), isCode('redirect_refused'));
  assert.equal(cancelled, true);
});

test('requires an injected fetch implementation', () => {
  assert.throws(
    () => new PairedClient({ origin: 'http://127.0.0.1:9', ticket: TICKET }),
    isCode('bad_fetch'),
  );
});

test('reads the body stream and refuses more than 64 KiB', async () => {
  let cancelled = false;
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers(),
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES));
          controller.enqueue(new Uint8Array(1));
          // Stay open so the reader's cancel reaches the source.
        },
        cancel() {
          cancelled = true;
        },
      }),
    }),
  });

  await assert.rejects(client.request(`policy/${TICKET}`), isCode('response_too_large'));
  assert.equal(cancelled, true);
});

test('falls back to arrayBuffer for a body without a stream and applies the cap', async () => {
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers(),
      body: null,
      arrayBuffer: async () => new ArrayBuffer(MAX_RESPONSE_BYTES + 1),
    }),
  });

  await assert.rejects(client.request(`policy/${TICKET}`), isCode('response_too_large'));
});

test('accepts a body of exactly 64 KiB', async () => {
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers(),
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES));
          controller.close();
        },
      }),
    }),
  });

  const response = await client.request(`policy/${TICKET}`);
  assert.equal(response.bytes.length, MAX_RESPONSE_BYTES);
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
    assert.equal(requests[0].headers['content-length'], String(envelope.length));
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
      assert.equal(request.headers['content-length'], String(request.body.length));
    }
    assert.deepEqual(Buffer.concat(requests.map((request) => request.body)), envelope);
  });
});

test('passes every POST body as a Buffer and never sets Content-Length itself', async () => {
  const bodies = [];
  const headerSets = [];
  const fetchImpl = (url, init) => {
    bodies.push(init.body);
    headerSets.push(init.headers);
    return globalThis.fetch(url, init);
  };

  await withServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
  }, async (origin) => {
    const client = makeClient(origin, { fetchImpl });
    await client.upload(Buffer.alloc(9000, 7));

    assert.equal(bodies.length, 3);
    for (const body of bodies) assert.ok(Buffer.isBuffer(body));
    for (const headers of headerSets) {
      assert.equal(
        Object.keys(headers).some((name) => name.toLowerCase() === 'content-length'),
        false,
      );
    }
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

test('restarts the whole upload once after a 5xx uses up its retries', async () => {
  const sleeps = [];
  const envelope = Buffer.alloc(9000, 3);

  await withServer((req, res, entry, all) => {
    const index = entry.headers['x-rongroi-chunk-index'];
    const firstAttempts = all.filter(
      (request) => request.headers['x-rongroi-chunk-index'] === '0',
    ).length;
    if (firstAttempts === 1 && index === '2') {
      res.writeHead(500);
      res.end('save failed');
      return;
    }
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin, { sleep: async (ms) => { sleeps.push(ms); } });
    const result = await client.upload(envelope);

    assert.deepEqual(result, { status: 'accepted' });
    assert.equal(requests.length, 9);
    assert.deepEqual(
      requests.map((request) => request.headers['x-rongroi-chunk-index']),
      ['0', '1', '2', '2', '2', '2', '0', '1', '2'],
    );
    assert.deepEqual(sleeps, [500, 1500, 3000]);
  });
});

test('fails with server_error after exactly one restart when a 5xx never clears', async () => {
  const envelope = Buffer.alloc(9000, 3);

  await withServer((req, res) => {
    res.writeHead(500);
    res.end('save failed');
  }, async (origin, requests) => {
    const client = makeClient(origin, { sleep: async () => {} });
    await assert.rejects(client.upload(envelope), isCode('server_error'));

    assert.equal(requests.length, 8);
    assert.deepEqual(
      requests.map((request) => request.headers['x-rongroi-chunk-index']),
      ['0', '0', '0', '0', '0', '0', '0', '0'],
    );
  });
});

test('uploads a sealed declined answer through the same plan', async () => {
  const sealed = Buffer.from('a sealed declined answer');

  await withServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    const result = await client.decline(sealed);

    assert.deepEqual(result, { status: 'declined' });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].url, '/nakara_rongroi/report');
    assert.equal(requests[0].headers['x-rongroi-upload-id'], TICKET);
    assert.deepEqual(requests[0].body, sealed);
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

test('a refusal on the first request carries sent false', async () => {
  for (const [status, code] of [[409, 'ticket_used'], [413, 'too_large']]) {
    await withServer((req, res) => {
      res.writeHead(status);
      res.end('no');
    }, async (origin, requests) => {
      const client = makeClient(origin);
      await assert.rejects(client.upload(Buffer.from('direct')), (error) => {
        assert.equal(error.code, code);
        assert.equal(error.sent, false);
        return true;
      });
      assert.equal(requests.length, 1);
    });
  }
});

test('a bad envelope carries sent false before any request', async () => {
  let fetched = false;
  const client = makeClient('http://127.0.0.1:9', {
    fetchImpl: async () => {
      fetched = true;
      throw new Error('must not fetch');
    },
  });

  await assert.rejects(client.upload(Buffer.alloc(0)), (error) => {
    assert.equal(error.code, 'bad_envelope');
    assert.equal(error.sent, false);
    return true;
  });
  assert.equal(fetched, false);
});

test('a 5xx carries sent true even when no slice was accepted', async () => {
  await withServer((req, res) => {
    res.writeHead(500);
    res.end('save failed');
  }, async (origin, requests) => {
    const client = makeClient(origin, { sleep: async () => {} });
    await assert.rejects(client.upload(Buffer.from('direct')), (error) => {
      assert.equal(error.code, 'server_error');
      assert.equal(error.sent, true);
      return true;
    });
    assert.ok(requests.length > 1);
  });
});

test('a lost first answer carries sent true', async () => {
  await withServer(() => {}, async (origin) => {
    const client = makeClient(origin, {
      timeoutMs: 100,
      sleep: async () => {},
    });
    await assert.rejects(client.upload(Buffer.from('direct')), (error) => {
      assert.equal(error.code, 'timeout');
      assert.equal(error.sent, true);
      return true;
    });
  });
});

test('a refusal after an accepted slice carries sent true', async () => {
  const envelope = Buffer.alloc(9000, 3);
  await withServer((req, res, entry) => {
    if (entry.headers['x-rongroi-chunk-index'] === '1') {
      res.writeHead(409);
      res.end('used');
      return;
    }
    res.writeHead(200);
    res.end('ok');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    await assert.rejects(client.upload(envelope), (error) => {
      assert.equal(error.code, 'ticket_used');
      assert.equal(error.sent, true);
      return true;
    });
    assert.equal(requests.length, 2);
  });
});

test('a 422 restart before any 2xx carries sent false', async () => {
  await withServer((req, res) => {
    res.writeHead(422);
    res.end('restart');
  }, async (origin, requests) => {
    const client = makeClient(origin);
    await assert.rejects(client.upload(Buffer.from('direct')), (error) => {
      assert.equal(error.code, 'upload_refused');
      assert.equal(error.sent, false);
      return true;
    });
    assert.equal(requests.length, 2);
  });
});

test('times out a policy request', async () => {
  await withServer(() => {}, async (origin) => {
    const client = makeClient(origin, { timeoutMs: 100 });
    await assert.rejects(client.getPolicy(POLICY_HASH), isCode('timeout'));
  });
});

test('retries lost answers on the schedule, restarts once, then fails', async () => {
  const sleeps = [];
  await withServer(() => {}, async (origin, requests) => {
    const client = makeClient(origin, {
      timeoutMs: 100,
      sleep: async (ms) => { sleeps.push(ms); },
    });
    await assert.rejects(client.upload(Buffer.from('direct')), isCode('timeout'));

    assert.deepEqual(sleeps, [500, 1500, 3000, 500, 1500, 3000]);
    assert.equal(requests.length, 8);
  });
});

test('refuses a policy holding a non-integer number', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ...POLICY, policy_hash: '1111111111111111', score: 1.5 }));
  }, async (origin) => {
    const client = makeClient(origin);
    await assert.rejects(client.getPolicy(POLICY_HASH), isCode('bad_policy'));
  });
});

test('the policy GET uses 10 s and upload POSTs use 15 s', async () => {
  assert.equal(POLICY_TIMEOUT_MS, 10_000);
  assert.equal(UPLOAD_TIMEOUT_MS, 15_000);

  const client = new PairedClient({
    origin: 'http://127.0.0.1:9',
    ticket: TICKET,
    fetchImpl: async () => ({}),
  });
  assert.equal(client.policyTimeoutMs, POLICY_TIMEOUT_MS);
  assert.equal(client.uploadTimeoutMs, UPLOAD_TIMEOUT_MS);

  const seen = [];
  client.request = async (path, init, timeoutMs) => {
    seen.push({ path, method: init.method, timeoutMs });
    if (init.method === 'GET') {
      return {
        status: 200,
        headers: new Headers({ date: new Date().toUTCString() }),
        bytes: Buffer.from(JSON.stringify(policyBody())),
      };
    }
    return { status: 200, headers: new Headers(), bytes: Buffer.alloc(0) };
  };

  await client.getPolicy(POLICY_HASH);
  await client.upload(Buffer.from('small envelope'));

  assert.deepEqual(seen.map((entry) => entry.timeoutMs), [
    POLICY_TIMEOUT_MS,
    UPLOAD_TIMEOUT_MS,
  ]);
});

test('a Date header offset over 24 hours in either direction is ignored', () => {
  const nowMs = Date.parse('2026-01-01T00:00:00Z');
  const expiresAt = '2026-01-01T00:10:00Z';
  const expiresMs = Date.parse(expiresAt);

  function clientWithServerDate(headerMs) {
    const client = new PairedClient({
      origin: 'http://127.0.0.1:9',
      ticket: TICKET,
      fetchImpl: async () => ({}),
    });
    client.now = () => nowMs;
    client.rememberExpiry({ expires_at: expiresAt }, new Date(headerMs).toUTCString());
    return client;
  }

  const oneHour = 60 * 60 * 1000;
  const oneDay = 24 * oneHour;

  assert.equal(clientWithServerDate(nowMs + oneHour).expiresAtMs, expiresMs - oneHour);
  assert.equal(clientWithServerDate(nowMs - oneHour).expiresAtMs, expiresMs + oneHour);
  assert.equal(clientWithServerDate(nowMs + oneDay).expiresAtMs, expiresMs - oneDay);
  assert.equal(clientWithServerDate(nowMs - oneDay).expiresAtMs, expiresMs + oneDay);

  // Over the clamp: the header is treated as a bad clock and ignored.
  assert.equal(clientWithServerDate(nowMs + oneDay + 1000).expiresAtMs, expiresMs);
  assert.equal(clientWithServerDate(nowMs - oneDay - 1000).expiresAtMs, expiresMs);
});
