// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createSidecarVerifier } = require('../src/main/verify-sidecar');
const { SidecarError } = require('../src/main/sidecar');

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function writeVerifierFixture(root, exeBytes, record) {
  fs.mkdirSync(root, { recursive: true });
  const exe = path.join(root, 'rongroi-scan.exe');
  if (exeBytes !== null) fs.writeFileSync(exe, exeBytes);
  const recordFile = path.join(root, 'src', 'sidecar.json');
  if (record !== null) {
    fs.mkdirSync(path.dirname(recordFile), { recursive: true });
    fs.writeFileSync(
      recordFile,
      typeof record === 'string' ? record : `${JSON.stringify(record, null, 2)}\n`,
      'utf8',
    );
  }
  return { exe, recordFile };
}

function verifierFor(fixture) {
  return createSidecarVerifier({
    file: fixture.exe,
    expected: fixture.recordFile,
    readFile: fs.readFileSync,
    createHash: crypto.createHash,
  });
}

test('the verifier passes when the bundled sidecar matches the record', async () => {
  const fixture = writeVerifierFixture(
    fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-ok-')),
    Buffer.alloc(2048, 0x52),
    { sha256: sha256Hex(Buffer.alloc(2048, 0x52)), commit: '0'.repeat(40) },
  );
  const root = path.dirname(fixture.exe);

  try {
    await assert.doesNotReject(verifierFor(fixture)());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the uppercase hex in the record is accepted', async () => {
  const bytes = Buffer.alloc(64, 0x01);
  const fixture = writeVerifierFixture(
    fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-upper-')),
    bytes,
    { sha256: sha256Hex(bytes).toUpperCase(), commit: '0'.repeat(40) },
  );
  const root = path.dirname(fixture.exe);

  try {
    await assert.doesNotReject(verifierFor(fixture)());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the verifier refuses the bundled sidecar after one changed byte', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-byte-'));
  const good = Buffer.alloc(1024, 0x00);
  const bad = Buffer.from(good);
  bad[512] = 0x01;
  const fixture = writeVerifierFixture(root, bad, { sha256: sha256Hex(good) });

  try {
    const verify = verifierFor(fixture);
    await assert.rejects(verify(), (error) => {
      assert.equal(error instanceof SidecarError, true);
      assert.equal(error.code, 'sidecar_hash');
      assert.match(error.message, /sidecar_hash/);
      return true;
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the verifier refuses a missing bundled sidecar', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-missing-exe-'));
  const fixture = writeVerifierFixture(
    root,
    null,
    { sha256: sha256Hex(Buffer.alloc(1)), commit: '0'.repeat(40) },
  );

  try {
    const verify = verifierFor({ ...fixture, exe: path.join(root, 'absent.exe') });
    await assert.rejects(verify(), (error) => {
      assert.equal(error instanceof SidecarError, true);
      assert.equal(error.code, 'sidecar_hash');
      assert.match(error.message, /absent\.exe/);
      return true;
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the verifier refuses a missing sidecar.json', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-missing-json-'));
  const bytes = Buffer.alloc(512, 0x33);
  const fixture = writeVerifierFixture(root, bytes, null);

  try {
    const verify = verifierFor(fixture);
    await assert.rejects(verify(), (error) => {
      assert.equal(error instanceof SidecarError, true);
      assert.equal(error.code, 'sidecar_hash');
      assert.match(error.message, /sidecar\.json/);
      return true;
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the verifier refuses a malformed sidecar.json', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-junk-'));
  const bytes = Buffer.alloc(512, 0x44);
  const fixture = writeVerifierFixture(root, bytes, 'not JSON at all {');

  try {
    const verify = verifierFor(fixture);
    await assert.rejects(verify(), (error) => {
      assert.equal(error instanceof SidecarError, true);
      assert.equal(error.code, 'sidecar_hash');
      assert.match(error.message, /sidecar\.json/);
      return true;
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the verifier refuses a 64-character sha256 that is not hex', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-non-hex-'));
  const bytes = Buffer.alloc(512, 0x66);
  const fixture = writeVerifierFixture(root, bytes, {
    sha256: 'g'.repeat(64),
    commit: '0'.repeat(40),
  });

  try {
    const verify = verifierFor(fixture);
    await assert.rejects(verify(), (error) => {
      assert.equal(error instanceof SidecarError, true);
      assert.equal(error.code, 'sidecar_hash');
      assert.match(error.message, /sha256/);
      return true;
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the verifier refuses a record without a sha256 string', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-sidecar-no-hash-'));
  const bytes = Buffer.alloc(512, 0x55);
  const fixture = writeVerifierFixture(root, bytes, { commit: '0'.repeat(40) });

  try {
    const verify = verifierFor(fixture);
    await assert.rejects(verify(), (error) => {
      assert.equal(error instanceof SidecarError, true);
      assert.equal(error.code, 'sidecar_hash');
      assert.match(error.message, /sha256/);
      return true;
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
