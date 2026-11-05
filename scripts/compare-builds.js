// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Compare the release and test builds of ADR 0001 section 2.  The pure part is
// compareTrees(); the command line only turns two folders into file maps and
// gives compareTrees a way to read the two app.asar archives.

const fs = require('node:fs');
const path = require('node:path');

const ASAR_PATH = 'resources/app.asar';
const EXE_PATH = 'rongroi-connect.exe';
const TEST_HOOK_PATH = 'src/test-hook.js';

function normalizePath(value) {
  return String(value)
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '');
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (value === undefined || value === null) return Buffer.alloc(0);
  return Buffer.from(String(value), 'utf8');
}

function normalizeTree(tree) {
  const files = new Map();
  if (tree === null || tree === undefined) return files;
  if (Array.isArray(tree)) return normalizeAsarList(tree);
  const entries = tree instanceof Map ? tree.entries() : Object.entries(tree);
  for (const [name, value] of entries) files.set(normalizePath(name), toBuffer(value));
  return files;
}

function normalizeAsarList(list) {
  const files = new Map();
  if (list === null || list === undefined) return files;

  if (list instanceof Map) {
    for (const [name, value] of list) files.set(normalizePath(name), toBuffer(value));
    return files;
  }

  if (Array.isArray(list)) {
    for (const entry of list) {
      if (typeof entry === 'string') {
        files.set(normalizePath(entry), Buffer.alloc(0));
      } else if (Array.isArray(entry) && entry.length >= 1) {
        files.set(normalizePath(entry[0]), toBuffer(entry[1]));
      } else if (entry !== null && typeof entry === 'object') {
        const name = entry.path ?? entry.name ?? entry.file;
        const data = entry.data ?? entry.contents ?? entry.bytes;
        if (name !== undefined) files.set(normalizePath(name), toBuffer(data));
      }
    }
    return files;
  }

  for (const [name, value] of Object.entries(list)) {
    files.set(normalizePath(name), toBuffer(value));
  }
  return files;
}

function compareAsar(rel, leftBytes, rightBytes, listAsar, differences) {
  let left;
  let right;
  try {
    left = normalizeAsarList(listAsar(leftBytes, 'release', rel));
    right = normalizeAsarList(listAsar(rightBytes, 'test', rel));
  } catch (error) {
    differences.push(`${rel}: cannot read the archive: ${error.message}`);
    return;
  }

  const names = new Set([...left.keys(), ...right.keys()]);
  for (const name of [...names].sort()) {
    const inLeft = left.has(name);
    const inRight = right.has(name);
    if (!inLeft || !inRight) {
      differences.push(`${rel}:${name}: only in ${inLeft ? 'release' : 'test'}`);
      continue;
    }
    // The test hook is the one file the two builds are meant to differ in.
    if (name === TEST_HOOK_PATH) continue;
    if (!left.get(name).equals(right.get(name))) {
      differences.push(`${rel}:${name}: differs`);
    }
  }
}

// Pure comparison of two trees.  Each tree is a Map or plain object of
// relative path -> Buffer/string.  listAsar(bytes, side, rel) returns the
// files inside that asar as a Map, array or plain object.  It is injected so
// this function itself never touches the file system.
function compareTrees(a, b, listAsar) {
  const left = normalizeTree(a);
  const right = normalizeTree(b);
  const differences = [];
  const notes = [];

  const names = new Set([...left.keys(), ...right.keys()]);
  for (const rel of [...names].sort()) {
    const inLeft = left.has(rel);
    const inRight = right.has(rel);
    if (!inLeft || !inRight) {
      differences.push(`${rel}: only in ${inLeft ? 'release' : 'test'}`);
      continue;
    }

    if (rel === EXE_PATH || rel.endsWith(`/${EXE_PATH}`)) {
      notes.push(`${rel}: allowed to differ (fuses and embedded asar integrity)`);
      continue;
    }

    if (rel === ASAR_PATH || rel.endsWith(`/${ASAR_PATH}`)) {
      if (typeof listAsar === 'function') {
        compareAsar(rel, left.get(rel), right.get(rel), listAsar, differences);
      } else if (!left.get(rel).equals(right.get(rel))) {
        differences.push(`${rel}: differs (no asar lister)`);
      }
      continue;
    }

    if (!left.get(rel).equals(right.get(rel))) differences.push(`${rel}: differs`);
  }

  return { ok: differences.length === 0, differences, notes };
}

function readTree(directory) {
  const root = path.resolve(directory);
  const files = new Map();

  function walk(current, prefix) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(absolute, rel);
      } else {
        files.set(normalizePath(rel), fs.readFileSync(absolute));
      }
    }
  }

  walk(root, '');
  return files;
}

async function loadAsar() {
  let loaded;
  try {
    loaded = require('@electron/asar');
  } catch (error) {
    if (error && (error.code === 'ERR_REQUIRE_ESM' || error.code === 'ERR_REQUIRE_ASYNC_MODULE')) {
      loaded = await import('@electron/asar');
    } else {
      throw error;
    }
  }

  const asar = loaded && typeof loaded.listPackage === 'function'
    ? loaded
    : loaded && loaded.default;
  if (!asar || typeof asar.listPackage !== 'function' || typeof asar.extractFile !== 'function') {
    throw new Error('@electron/asar did not export listPackage and extractFile');
  }
  return asar;
}

function extractAsarFile(asar, archivePath, entry) {
  const candidates = [entry, normalizePath(entry), `/${normalizePath(entry)}`];
  let lastError = null;
  for (const candidate of candidates) {
    try {
      return asar.extractFile(archivePath, candidate);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

function listAsarFromDisk(asar, archivePath) {
  const files = new Map();
  for (const entry of asar.listPackage(archivePath)) {
    const name = normalizePath(entry);
    try {
      files.set(name, extractAsarFile(asar, archivePath, entry));
    } catch {
      // An unpacked file (the native .node) has only its entry in the asar;
      // its bytes live in app.asar.unpacked and are compared by readTree().
      // Keep a stable placeholder so the asar comparison only checks presence.
      files.set(name, Buffer.from(`unpacked:${name}`, 'utf8'));
    }
  }
  return files;
}

async function main(argv) {
  const directories = argv.filter((value) => value !== '--');
  if (directories.length !== 2) {
    console.error('usage: node scripts/compare-builds.js <releaseDir> <testDir>');
    process.exitCode = 2;
    return;
  }

  const [releaseDir, testDir] = directories;
  const asar = await loadAsar();
  const listAsar = (bytes, side, rel) => {
    const directory = side === 'release' ? releaseDir : testDir;
    return listAsarFromDisk(asar, path.join(directory, rel));
  };

  const result = compareTrees(readTree(releaseDir), readTree(testDir), listAsar);
  for (const note of result.notes) console.log(`note: ${note}`);

  if (!result.ok) {
    console.error('builds differ:');
    for (const difference of result.differences) console.error(`  ${difference}`);
    process.exitCode = 1;
    return;
  }

  console.log(
    'builds match: every file is byte-identical except resources/app.asar and the exe; '
      + 'inside the asars only src/test-hook.js may differ.',
  );
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  });
}

module.exports = {
  ASAR_PATH,
  EXE_PATH,
  TEST_HOOK_PATH,
  compareTrees,
  readTree,
  listAsarFromDisk,
  main,
};
