// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Relay transport and base_path (ADR 0003).
const test = require('node:test');
const assert = require('node:assert/strict');
const PairedClient = require('../src/main/net');
const { buildUrl } = require('../src/main/net');

const T = '7a1c9e3f5b2d8a4c6e0f1b3d5a7c9e2f';
const ORIGIN = 'https://relay.example.org';

function client(responses, options = {}) {
  let ms = 1_000_000;
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers });
    const next = responses.shift();
    if (!next) throw new Error('no response queued');
    if (next.throws) throw Object.assign(new Error('net'), { name: 'TypeError' });
    const body = Buffer.from(next.body === undefined ? '' : JSON.stringify(next.body));
    return {
      status: next.status, type: 'basic', headers: new Map(Object.entries(next.headers || {})),
      body: null, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
    };
  };
  const c = new PairedClient({ origin: ORIGIN, ticket: T, fetchImpl, now: () => ms, sleep: async (d) => { ms += d; },
    expiresAt: ms + 300000, basePath: 'srv1', transport: 'relay', ...options });
  return { c, calls, advance: (d) => { ms += d; } };
}

test('base_path decides the request prefix; v1 and odd segments are refused', () => {
  assert.equal(buildUrl(ORIGIN, `policy/${T}`, 'srv1').href, `${ORIGIN}/srv1/policy/${T}`);
  assert.equal(buildUrl('http://203.0.113.10:30120', `policy/${T}`).pathname, `/nakara_rongroi/policy/${T}`);
  for (const bad of ['v1', 'A', 'a/b', '']) assert.throws(() => buildUrl(ORIGIN, 'policy', bad));
});

test('relay upload: one POST with envelope 2 headers, then the status poll returns accepted', async () => {
  const { c, calls } = client([{ status: 202, body: { status: 202 } }, { status: 200, body: { result: 'pending' } },
    { status: 200, body: { result: 'accepted' } }]);
  assert.deepEqual(await c.upload(Buffer.from('envelope')), { status: 'accepted' });
  assert.equal(calls[0].url, `${ORIGIN}/srv1/report`);
  assert.equal(calls[0].headers['X-Rongroi-Envelope'], '2');
  assert.equal(calls[0].headers['X-Rongroi-Upload-Id'], T);
  assert.match(calls[1].url, new RegExp(`/srv1/status/${T}/[0-9a-f]{64}$`));
  assert.equal(calls.length, 3);
});

test('a result code from the server is final: no restart, sent is true', async () => {
  const { c, calls } = client([{ status: 202 }, { status: 200, body: { result: 422 } }]);
  await assert.rejects(c.upload(Buffer.from('envelope')), (e) => e.code === 'upload_refused' && e.sent === true);
  assert.equal(calls.length, 2);
});

test('a 200 on upload is a repeat of an accepted envelope', async () => {
  const { c } = client([{ status: 200 }]);
  assert.deepEqual(await c.upload(Buffer.from('envelope')), { status: 'accepted' });
});

test('a refused upload (409, 410, 404) fails before anything was stored', async () => {
  for (const [status, code] of [[409, 'ticket_used'], [410, 'expired'], [404, 'unknown_ticket']]) {
    const { c } = client([{ status }]);
    await assert.rejects(c.upload(Buffer.from('e')), (e) => e.code === code && e.sent === false, String(status));
  }
});

test('no result by expires_at plus 10 minutes resolves waiting; network errors while polling are tolerated', async () => {
  const pending = Array.from({ length: 80 }, (_, i) => (i % 5 === 0 ? { throws: true } : { status: 200, body: { result: 'pending' } }));
  const { c } = client([{ status: 202 }, ...pending]);
  assert.deepEqual(await c.upload(Buffer.from('envelope')), { status: 'waiting' });
});

test('decline through the relay passes waiting through', async () => {
  const pending = Array.from({ length: 80 }, () => ({ status: 200, body: { result: 'pending' } }));
  const { c } = client([{ status: 202 }, ...pending]);
  assert.deepEqual(await c.decline(Buffer.from('envelope')), { status: 'waiting' });
});

test('an envelope over 2 MiB is refused locally', async () => {
  const { c, calls } = client([]);
  await assert.rejects(c.upload(Buffer.alloc(2 * 1024 * 1024 + 1)), (e) => e.code === 'bad_envelope');
  assert.equal(calls.length, 0);
});
