// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// The mock sidecar for the 2c proof.  It speaks the same one-line-in,
// one-line-out protocol as the real rongroi-scan.exe but performs no scan.
// It is plain Node and is never part of a release build.

const net = require('node:net');
const { visualHash } = require('../../src/core/canonical');

const MAX_LINE_BYTES = 16 * 1024;

function argumentsFromEnvironment() {
  const text = process.env.CONNECT_TEST_SIDECAR_ARGS || '';
  return text.split(/\s+/).filter((token) => token.length > 0);
}

function readOption(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return null;
  const value = argv[index + 1];
  return typeof value === 'string' ? value : null;
}

function buildRecord(line) {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return null;
  }
  if (request === null || typeof request !== 'object' || Array.isArray(request)) {
    return null;
  }
  if (request.binding === null || typeof request.binding !== 'object'
      || request.policy === null || typeof request.policy !== 'object'
      || request.producer === null || typeof request.producer !== 'object') {
    return null;
  }

  const record = {
    schema: 2,
    binding: request.binding,
    policy: request.policy,
    producer: request.producer,
    rongroi_version: 'mock',
    scan: { mock: true },
  };
  record.visual_hash = visualHash(record);
  return record;
}

function main() {
  const argv = [...process.argv.slice(2), ...argumentsFromEnvironment()];
  if (argv.includes('--decline')) {
    process.exit(3);
  }

  const pipeName = readOption(argv, '--pipe');
  if (typeof pipeName !== 'string' || pipeName.length === 0) {
    process.exit(1);
  }

  const socket = net.connect(pipeName);
  let buffered = '';
  let finished = false;

  function finish(line) {
    if (finished) return;
    finished = true;
    socket.pause();

    const record = buildRecord(line);
    if (record === null) {
      process.exitCode = 1;
      socket.destroy();
      return;
    }

    socket.once('close', () => {
      process.exit(0);
    });
    socket.end(`${JSON.stringify(record)}\n`);
  }

  socket.setEncoding('utf8');
  socket.on('data', (chunk) => {
    if (finished) return;
    buffered += chunk;
    if (Buffer.byteLength(buffered, 'utf8') > MAX_LINE_BYTES) {
      finished = true;
      process.exitCode = 1;
      socket.destroy();
      return;
    }
    const newline = buffered.indexOf('\n');
    if (newline !== -1) {
      const line = buffered.slice(0, newline);
      buffered = '';
      finish(line);
    }
  });

  socket.on('error', () => {
    if (!finished) process.exit(1);
  });
}

// A test runner may load every file under test/.  Only run the sidecar when
// this file is the process entry point and either no test runner is loading
// it or it was given real sidecar arguments (as a spawned helper would be).
const sidecarArguments = [...process.argv.slice(2), ...argumentsFromEnvironment()]
  .some((token) => token === '--pipe' || token === '--elevate' || token === '--decline');
if (require.main === module
    && (!process.env.NODE_TEST_CONTEXT || sidecarArguments)) {
  main();
}

module.exports = { buildRecord, main };
