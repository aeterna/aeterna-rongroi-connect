// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Compare the release and test builds of ADR 0001 section 2.  The pure part is
// compareTrees(); the command line turns two folders into file maps, gives
// compareTrees a way to read the two app.asar archives, and reads the fuses of
// both executables.

const fs = require('node:fs');
const path = require('node:path');

const ASAR_PATH = 'resources/app.asar';
const EXE_PATH = 'rongroi-connect.exe';
const TEST_HOOK_PATH = 'src/test-hook.js';
const ROOT = path.resolve(__dirname, '..');

const SECTION_1_FUSES = [
  { name: 'RunAsNode', value: false },
  { name: 'EnableNodeOptionsEnvironmentVariable', value: false },
  { name: 'EnableNodeCliInspectArguments', value: false },
  { name: 'OnlyLoadAppFromAsar', value: true },
  { name: 'EnableEmbeddedAsarIntegrityValidation', value: true },
  { name: 'EnableCookieEncryption', value: true },
];

// The fuse wire stores each fuse as the ASCII byte for '0' (off), '1' (on) or
// 'r' (removed).  These are the fallbacks when @electron/fuses does not export
// its FuseState enum.
const FUSE_STATE_BYTES = {
  DISABLE: 48,
  ENABLE: 49,
  REMOVED: 114,
  INVALID: 63,
};

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

function repositoryHookCopies(root = ROOT) {
  return {
    release: fs.readFileSync(path.join(root, 'src', 'test-hook.js')),
    test: fs.readFileSync(path.join(root, 'test', 'hook', 'test-hook.js')),
  };
}

function compareAsar(rel, leftBytes, rightBytes, listAsar, expectedHooks, differences) {
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

    // The test hook is the one file the two builds are meant to differ in,
    // but each copy must still be exactly the file the build should have put
    // there.  A stub in a test build (or the driving hook in release) is a
    // failure, not an allowed difference.
    if (name === TEST_HOOK_PATH) {
      if (!left.get(name).equals(toBuffer(expectedHooks.release))) {
        differences.push(`${rel}:${name}: release copy differs from src/test-hook.js`);
      }
      if (!right.get(name).equals(toBuffer(expectedHooks.test))) {
        differences.push(`${rel}:${name}: test copy differs from test/hook/test-hook.js`);
      }
      continue;
    }

    if (!left.get(name).equals(right.get(name))) {
      differences.push(`${rel}:${name}: differs`);
    }
  }
}

// Pure comparison of two trees.  Each tree is a Map or plain object of
// relative path -> Buffer/string.  listAsar(bytes, side, rel) returns the
// files inside that asar as a Map, array or plain object.  It is injected so
// this function itself never touches the archives on disk.  expectedHooks is
// { release, test } as Buffers; by default the repository's two hook files are
// used, because each build must carry exactly its own copy.
function compareTrees(a, b, listAsar, expectedHooks) {
  const hooks = expectedHooks ?? repositoryHookCopies();
  const left = normalizeTree(a);
  const right = normalizeTree(b);
  const differences = [];
  const notes = [];

  if (left.size === 0) differences.push('the release tree is empty');
  if (right.size === 0) differences.push('the test tree is empty');

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
      if (left.get(rel).equals(right.get(rel))) {
        // If the two archives are the same bytes, the test build did not
        // differ at all and the comparison proved nothing.
        differences.push(`${rel}: identical in both builds; the test build must differ`);
      } else if (typeof listAsar === 'function') {
        compareAsar(rel, left.get(rel), right.get(rel), listAsar, hooks, differences);
      } else {
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
  let stats;
  try {
    stats = fs.statSync(root);
  } catch {
    throw new Error(`the build folder is missing: ${root}`);
  }
  if (!stats.isDirectory()) {
    throw new Error(`the build folder is not a directory: ${root}`);
  }

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

  if (files.size === 0) {
    throw new Error(`the build folder is empty: ${root}`);
  }
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

async function loadFuses() {
  let loaded;
  try {
    loaded = require('@electron/fuses');
  } catch (error) {
    if (error && (error.code === 'ERR_REQUIRE_ESM' || error.code === 'ERR_REQUIRE_ASYNC_MODULE')) {
      loaded = await import('@electron/fuses');
    } else {
      throw error;
    }
  }

  const fuses = [loaded, loaded && loaded.default]
    .find((candidate) => candidate && typeof candidate.getCurrentFuseWire === 'function')
    ?? loaded;
  const { getCurrentFuseWire, FuseV1Options } = fuses ?? {};
  if (typeof getCurrentFuseWire !== 'function' || !FuseV1Options) {
    throw new Error('@electron/fuses did not export getCurrentFuseWire and FuseV1Options');
  }
  const FuseState = fuses?.FuseState
    ?? loaded?.FuseState
    ?? loaded?.default?.FuseState;
  return { getCurrentFuseWire, FuseV1Options, FuseState };
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

function statAsarFile(asar, archivePath, entry) {
  const candidates = [entry, normalizePath(entry), `/${normalizePath(entry)}`];
  let lastError = null;
  for (const candidate of candidates) {
    try {
      return asar.statFile(archivePath, candidate);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

function listAsarFromDisk(asar, archivePath) {
  const entries = asar.listPackage(archivePath);
  if (!Array.isArray(entries)) {
    throw new Error(`@electron/asar listPackage did not return an array for ${archivePath}`);
  }
  if (entries.length === 0) {
    throw new Error(`the asar is empty: ${archivePath}`);
  }

  const files = new Map();
  for (const entry of entries) {
    const name = normalizePath(entry);

    // listPackage() returns folders and links as well as files.  A folder is
    // covered by the files inside it, and a link has no bytes of its own, so
    // neither may be passed to extractFile().
    let stats = null;
    if (typeof asar.statFile === 'function') {
      try {
        stats = statAsarFile(asar, archivePath, entry);
      } catch {
        // Without a stat we can still try to extract a real file below.
      }
    }
    if (stats && (stats.files !== undefined || stats.link)) continue;

    try {
      files.set(name, extractAsarFile(asar, archivePath, entry));
    } catch (error) {
      if (stats && stats.unpacked === true) {
        // An unpacked file (the native .node) has only its entry in the asar;
        // its bytes live in app.asar.unpacked and are compared by readTree().
        // Keep a stable placeholder so the asar comparison only checks presence.
        files.set(name, Buffer.from(`unpacked:${name}`, 'utf8'));
        continue;
      }
      throw new Error(`cannot extract ${name} from ${archivePath}: ${error.message}`);
    }
  }
  return files;
}

function expectedFuseEntries(FuseV1Options) {
  return SECTION_1_FUSES.map(({ name, value }) => {
    const option = FuseV1Options[name];
    if (option === undefined) {
      throw new Error(`@electron/fuses has no FuseV1Options.${name}`);
    }
    return { name, option, value };
  });
}

function wireBytes(wire) {
  if (Buffer.isBuffer(wire)) return wire;
  if (wire instanceof Uint8Array) return wire;
  if (wire !== null && typeof wire === 'object') {
    for (const candidate of [wire.wire, wire.buffer, wire.bytes]) {
      if (Buffer.isBuffer(candidate) || candidate instanceof Uint8Array) return candidate;
    }
  }
  return null;
}

function fuseStateValues(FuseState) {
  const exported = FuseState !== null && typeof FuseState === 'object' ? FuseState : {};
  return {
    disable: exported.DISABLE ?? FUSE_STATE_BYTES.DISABLE,
    enable: exported.ENABLE ?? FUSE_STATE_BYTES.ENABLE,
    removed: exported.REMOVED ?? FUSE_STATE_BYTES.REMOVED,
    invalid: exported.INVALID ?? FUSE_STATE_BYTES.INVALID,
  };
}

function normalizeFuseState(value, states) {
  if (value === true || value === false) return value;
  if (value === undefined || value === null) return null;

  if (typeof value === 'string') {
    const text = value.trim().toLowerCase();
    if (text === '0' || text === 'off' || text === 'disabled' || text === 'false') return false;
    if (text === '1' || text === 'on' || text === 'enabled' || text === 'true') return true;
    if (text === 'r' || text === 'removed') return 'removed';
    if (text === '?' || text === 'invalid') return 'invalid';
    return null;
  }

  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  if (numeric === states.enable) return true;
  if (numeric === states.disable) return false;
  if (numeric === states.removed) return 'removed';
  if (numeric === states.invalid) return 'invalid';
  // Also accept a plain 0/1 wire, for callers that already decoded the bytes.
  if (numeric === 0) return false;
  if (numeric === 1) return true;
  return null;
}

function readWireState(bytes, option) {
  const index = Number(option);
  if (!Number.isInteger(index) || index < 0 || index >= bytes.length) return undefined;
  return bytes[index];
}

function readFuseState(wire, option, name, states) {
  const stateFor = (value) => normalizeFuseState(value, states);

  if (wire !== null && typeof wire === 'object' && typeof wire.getFuseState === 'function') {
    const value = wire.getFuseState(option);
    const state = stateFor(value);
    if (state !== null) return state;
    throw new Error(`the ${name} fuse is missing or has an unrecognised state: ${String(value)}`);
  }

  if (wire !== null && typeof wire === 'object') {
    for (const container of [wire.fuses, wire.options, wire.states, wire]) {
      if (container === null || typeof container !== 'object') continue;
      for (const key of [option, String(option), name]) {
        if (!Object.prototype.hasOwnProperty.call(container, key)) continue;
        const state = stateFor(container[key]);
        if (state !== null) return state;
        throw new Error(
          `the ${name} fuse has an unrecognised state: ${String(container[key])}`,
        );
      }
    }
  }

  const bytes = wireBytes(wire);
  if (bytes !== null) {
    const state = stateFor(readWireState(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes), option));
    if (state !== null) return state;
  }

  throw new Error(`the ${name} fuse is missing from the fuse wire`);
}

function checkFuseWire(wire, FuseV1Options, FuseStateOrLabel, maybeLabel) {
  let FuseState = FuseStateOrLabel;
  let label = maybeLabel ?? 'executable';
  if (typeof FuseStateOrLabel === 'string') {
    label = FuseStateOrLabel;
    FuseState = maybeLabel !== null && typeof maybeLabel === 'object' ? maybeLabel : undefined;
  }
  const states = fuseStateValues(FuseState);
  const differences = [];
  for (const { name, option, value } of expectedFuseEntries(FuseV1Options)) {
    let actual;
    try {
      actual = readFuseState(wire, option, name, states);
    } catch (error) {
      differences.push(`${label}: cannot read fuse ${name}: ${error.message}`);
      continue;
    }
    const expected = value ? 'on' : 'off';
    if (actual === 'removed') {
      differences.push(`${label}: fuse ${name} is removed, expected ${expected}`);
    } else if (actual === 'invalid') {
      differences.push(`${label}: fuse ${name} is invalid, expected ${expected}`);
    } else if (actual !== value) {
      differences.push(`${label}: fuse ${name} is ${actual ? 'on' : 'off'}, expected ${expected}`);
    }
  }
  return differences;
}

function executableKey(tree) {
  return [...tree.keys()].find(
    (rel) => rel === EXE_PATH || rel.endsWith(`/${EXE_PATH}`),
  );
}

async function compareExecutableFuses(directory, tree, fuses) {
  const rel = executableKey(tree);
  if (rel === undefined) {
    return [`${EXE_PATH}: missing`];
  }
  const { getCurrentFuseWire, FuseV1Options, FuseState } = fuses;
  const wire = await getCurrentFuseWire(path.join(path.resolve(directory), rel));
  return checkFuseWire(wire, FuseV1Options, FuseState, rel);
}

async function main(argv) {
  const directories = argv.filter((value) => value !== '--');
  if (directories.length !== 2) {
    console.error('usage: node scripts/compare-builds.js <releaseDir> <testDir>');
    process.exitCode = 2;
    return;
  }

  const [releaseDir, testDir] = directories;
  const releaseTree = readTree(releaseDir);
  const testTree = readTree(testDir);
  const asar = await loadAsar();
  const listAsar = (bytes, side, rel) => {
    const directory = side === 'release' ? releaseDir : testDir;
    return listAsarFromDisk(asar, path.join(directory, rel));
  };

  const result = compareTrees(releaseTree, testTree, listAsar);
  try {
    const fuses = await loadFuses();
    result.differences.push(
      ...await compareExecutableFuses(releaseDir, releaseTree, fuses),
      ...await compareExecutableFuses(testDir, testTree, fuses),
    );
  } catch (error) {
    result.differences.push(`cannot read the executable fuses: ${error.message}`);
  }
  result.ok = result.differences.length === 0;

  for (const note of result.notes) console.log(`note: ${note}`);

  if (!result.ok) {
    console.error('builds differ:');
    for (const difference of result.differences) console.error(`  ${difference}`);
    process.exitCode = 1;
    return;
  }

  console.log(
    'builds match: every file is byte-identical except resources/app.asar and the exe; '
      + 'inside the asars only src/test-hook.js may differ, and both exes hold the section 1 fuses.',
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
  SECTION_1_FUSES,
  compareTrees,
  readTree,
  listAsarFromDisk,
  repositoryHookCopies,
  expectedFuseEntries,
  checkFuseWire,
  main,
};
