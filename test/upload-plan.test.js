// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  DIRECT_LIMIT,
  SLICE_SIZE,
  actionForStatus,
  planUpload,
} = require('../src/core/upload-plan');

const TICKET = '9f82c4e1b07a412891d604e38a291bf0';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('7168 bytes is direct and carries the required headers', () => {
  const bytes = Buffer.alloc(DIRECT_LIMIT, 7);
  const plan = planUpload(bytes, TICKET);

  assert.equal(plan.mode, 'direct');
  assert.equal(plan.endpoint, 'report');
  assert.equal(plan.size, DIRECT_LIMIT);
  assert.deepEqual(plan.retryDelaysMs, [500, 1500, 3000]);
  assert.equal(plan.reportSha256, sha256(bytes));
  assert.equal(plan.headers['X-Rongroi-Upload-Id'], TICKET);
  assert.equal(plan.headers['X-Rongroi-Report-Sha256'], sha256(bytes));
  assert.equal(plan.headers['X-Rongroi-Chunk-Index'], undefined);
});

test('7169 bytes is chunked into 4096-byte slices', () => {
  const bytes = Buffer.alloc(DIRECT_LIMIT + 1, 9);
  const plan = planUpload(bytes, TICKET);

  assert.equal(plan.mode, 'chunked');
  assert.equal(plan.endpoint, 'report/chunk');
  assert.equal(plan.slices.length, 2);
  assert.deepEqual(plan.slices.map((slice) => slice.length), [SLICE_SIZE, DIRECT_LIMIT + 1 - SLICE_SIZE]);
  assert.deepEqual(plan.slices.map((slice) => slice.index), [0, 1]);
  assert.deepEqual(plan.slices.map((slice) => slice.total), [2, 2]);
  assert.equal(plan.slices[0].headers['X-Rongroi-Chunk-Index'], '0');
  assert.equal(plan.slices[1].headers['X-Rongroi-Chunk-Index'], '1');
  assert.equal(plan.slices[1].headers['X-Rongroi-Chunk-Total'], '2');
  assert.equal(plan.slices[1].headers['X-Rongroi-Chunk-Sha256'], sha256(bytes.subarray(SLICE_SIZE)));
  assert.equal(plan.slices[0].sha256, plan.slices[0].headers['X-Rongroi-Chunk-Sha256']);
  for (const slice of plan.slices) {
    assert.equal(slice.headers['X-Rongroi-Upload-Id'], TICKET);
    assert.equal(slice.headers['X-Rongroi-Report-Sha256'], sha256(bytes));
  }
  assert.deepEqual(Buffer.concat(plan.slices.map((slice) => slice.data)), bytes);
});

test('exactly two slices ends on a 4096-byte boundary', () => {
  const plan = planUpload(Buffer.alloc(SLICE_SIZE * 2, 1), TICKET);
  assert.equal(plan.slices.length, 2);
  assert.equal(plan.slices[1].length, SLICE_SIZE);
});

test('maps every section 4 status to an action', () => {
  assert.equal(actionForStatus(200).action, 'continue');
  for (const status of [400, 404, 409, 410, 413]) assert.equal(actionForStatus(status).action, 'fail', status);
  assert.equal(actionForStatus(422).action, 'restart');
  assert.deepEqual(actionForStatus(429, '2'), { action: 'wait', retryAfterMs: 2000 });
  assert.equal(actionForStatus(429).action, 'wait');
  for (const status of [0, 500, 503, 599, null, undefined]) assert.equal(actionForStatus(status).action, 'retry', String(status));
});

test('rejects an empty envelope or a malformed ticket', () => {
  assert.throws(() => planUpload(Buffer.alloc(0), TICKET), RangeError);
  assert.throws(() => planUpload(Buffer.alloc(1), 'A'.repeat(32)), TypeError);
});
