// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { createHash } = require('node:crypto');

const DIRECT_LIMIT = 7168;
const SLICE_SIZE = 4096;
const RETRY_DELAYS_MS = Object.freeze([500, 1500, 3000]);

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function planUpload(envelopeBytes, ticket) {
  if (!Buffer.isBuffer(envelopeBytes) && !(envelopeBytes instanceof Uint8Array)) {
    throw new TypeError('envelopeBytes must be a Buffer or Uint8Array');
  }
  if (typeof ticket !== 'string' || !/^[0-9a-f]{32}$/.test(ticket)) {
    throw new TypeError('ticket must be 32 lowercase hex characters');
  }
  const bytes = Buffer.from(envelopeBytes);
  if (bytes.length === 0) throw new RangeError('envelope must not be empty');

  const reportSha256 = sha256Hex(bytes);
  const retryDelaysMs = [...RETRY_DELAYS_MS];
  if (bytes.length <= DIRECT_LIMIT) {
    return {
      mode: 'direct',
      endpoint: 'report',
      size: bytes.length,
      reportSha256,
      data: bytes,
      headers: {
        'X-Rongroi-Upload-Id': ticket,
        'X-Rongroi-Report-Sha256': reportSha256,
      },
      retryDelaysMs,
    };
  }

  const total = Math.ceil(bytes.length / SLICE_SIZE);
  const slices = [];
  for (let index = 0; index < total; index += 1) {
    const data = bytes.subarray(index * SLICE_SIZE, (index + 1) * SLICE_SIZE);
    slices.push({
      index,
      total,
      offset: index * SLICE_SIZE,
      length: data.length,
      sha256: sha256Hex(data),
      data,
      headers: {
        'X-Rongroi-Upload-Id': ticket,
        'X-Rongroi-Chunk-Index': String(index),
        'X-Rongroi-Chunk-Total': String(total),
        'X-Rongroi-Chunk-Sha256': sha256Hex(data),
        'X-Rongroi-Report-Sha256': reportSha256,
      },
    });
  }

  return {
    mode: 'chunked',
    endpoint: 'report/chunk',
    size: bytes.length,
    reportSha256,
    sliceSize: SLICE_SIZE,
    retryDelaysMs,
    slices,
  };
}

function actionForStatus(status, retryAfter) {
  if (status === 200) return { action: 'continue' };
  if (status === 422) return { action: 'restart' };
  if (status === 429) {
    const seconds = Number(retryAfter);
    const hasDelay = retryAfter !== undefined && retryAfter !== null && retryAfter !== ''
      && Number.isFinite(seconds) && seconds >= 0;
    return { action: 'wait', retryAfterMs: hasDelay ? Math.round(seconds * 1000) : null };
  }
  if (status === 400 || status === 404 || status === 409 || status === 410 || status === 413) {
    return { action: 'fail' };
  }
  if (status === 0 || status === null || status === undefined
      || (Number.isInteger(status) && status >= 500 && status <= 599)) {
    return { action: 'retry' };
  }
  return { action: 'fail' };
}

module.exports = {
  DIRECT_LIMIT,
  SLICE_SIZE,
  RETRY_DELAYS_MS,
  actionForStatus,
  planUpload,
};
