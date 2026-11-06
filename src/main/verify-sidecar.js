// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// ADR 0001 section 4: immediately before every sidecar launch, Connect hashes
// the bundled file and compares it with the SHA-256 the release build embedded
// in `src/sidecar.json` (staged by scripts/build.js).  A mismatch is the
// `sidecar_hash` SidecarError, which the flow maps to the exit-13 error state.
// The verifier always hashes the file the build staged under
// process.resourcesPath, so a test-hook sidecarCommand override cannot weaken
// the release path.

const nodeFs = require('node:fs');
const nodePath = require('node:path');
const nodeCrypto = require('node:crypto');

const { SidecarError } = require('./sidecar');

const SIDECAR_NAME = 'rongroi-scan.exe';

function hashError(message, cause) {
  const options = cause === undefined ? undefined : { cause };
  return new SidecarError('sidecar_hash', `sidecar_hash: ${message}`, options);
}

// The bundled file is the one beside app.asar, unless a caller injects the
// path (tests) or a getter for it.  Without any of those and without
// process.resourcesPath there is nothing to hash, so every call reports that.
function sidecarFileFor(file) {
  if (typeof file === 'function') return file;
  if (typeof file === 'string' && file.length > 0) return () => file;
  if (typeof process !== 'undefined' && typeof process.resourcesPath === 'string'
      && process.resourcesPath.length > 0) {
    return () => nodePath.join(process.resourcesPath, SIDECAR_NAME);
  }
  return () => {
    throw hashError(
      `process.resourcesPath is not available, so the bundled ${SIDECAR_NAME} cannot be found`,
    );
  };
}

// `file` is the bundled sidecar (path, or getter); `expected` is the path of
// the staged `src/sidecar.json` record.  readFile and createHash are
// injectable so the tests never touch the real resources of an install.
function createSidecarVerifier(options = {}) {
  const file = sidecarFileFor(options.file);
  const expected = options.expected;
  const readFile = typeof options.readFile === 'function'
    ? options.readFile
    : nodeFs.readFileSync;
  const createHash = typeof options.createHash === 'function'
    ? options.createHash
    : nodeCrypto.createHash;

  return async function verifySidecar() {
    const target = file();

    let bytes;
    try {
      bytes = readFile(target);
    } catch (error) {
      throw hashError(`cannot read the bundled sidecar ${target}`, error);
    }

    let record;
    try {
      record = JSON.parse(readFile(expected, 'utf8'));
    } catch (error) {
      throw hashError(`cannot read the sidecar hash record ${expected}`, error);
    }
    if (record === null || typeof record !== 'object' || Array.isArray(record)
        || typeof record.sha256 !== 'string' || record.sha256.length !== 64) {
      throw hashError(`the sidecar hash record ${expected} has no sha256`);
    }

    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== record.sha256.toLowerCase()) {
      throw hashError(
        `the bundled sidecar ${target} does not match the pinned build (expected ${record.sha256})`,
      );
    }
  };
}

module.exports = createSidecarVerifier;
module.exports.createSidecarVerifier = createSidecarVerifier;
module.exports.SIDECAR_NAME = SIDECAR_NAME;
