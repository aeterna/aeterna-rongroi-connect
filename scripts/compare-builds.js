// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Compare the release and test builds of ADR 0001 section 2.  The pure parts are
// compareExecutables() and compareTrees(); the command line turns two folders
// into file maps, gives compareTrees a way to read the two app.asar archives,
// and reads the fuses of both executables.  Both folders must carry the pinned
// sidecar at resources/rongroi-scan.exe.

const fs = require('node:fs');
const path = require('node:path');

const ASAR_PATH = 'resources/app.asar';
const EXE_PATH = 'rongroi-connect.exe';
const SIDECAR_EXE_PATH = 'resources/rongroi-scan.exe';
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

const ASAR_LINK = Symbol('asar-link');
const ASAR_DIRECTORY = Symbol('asar-directory');

function asarLink(target) {
  const value = String(target);
  return { [ASAR_LINK]: true, kind: 'link', link: value, target: value };
}

function asarDirectory() {
  return { [ASAR_DIRECTORY]: true, kind: 'directory', directory: true };
}

function isAsarLink(value) {
  return value !== null && typeof value === 'object'
    && (value[ASAR_LINK] === true || typeof value.link === 'string');
}

function isAsarDirectory(value) {
  return value !== null && typeof value === 'object'
    && (value[ASAR_DIRECTORY] === true || value.directory === true || value.files !== undefined);
}

function normalizeAsarValue(value) {
  if (isAsarLink(value)) return asarLink(value.target ?? value.link);
  if (isAsarDirectory(value)) return asarDirectory();
  return toBuffer(value);
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
    for (const [name, value] of list) {
      files.set(normalizePath(name), normalizeAsarValue(value));
    }
    return files;
  }

  if (Array.isArray(list)) {
    for (const entry of list) {
      if (typeof entry === 'string') {
        files.set(normalizePath(entry), Buffer.alloc(0));
      } else if (Array.isArray(entry) && entry.length >= 1) {
        files.set(normalizePath(entry[0]), normalizeAsarValue(entry[1]));
      } else if (entry !== null && typeof entry === 'object') {
        const name = entry.path ?? entry.name ?? entry.file;
        if (name === undefined) continue;
        if (typeof entry.link === 'string') {
          files.set(normalizePath(name), asarLink(entry.link));
          continue;
        }
        if (entry.directory === true || entry.files !== undefined) {
          files.set(normalizePath(name), asarDirectory());
          continue;
        }
        const data = entry.data ?? entry.contents ?? entry.bytes;
        files.set(normalizePath(name), normalizeAsarValue(data));
      }
    }
    return files;
  }

  for (const [name, value] of Object.entries(list)) {
    files.set(normalizePath(name), normalizeAsarValue(value));
  }
  return files;
}

function repositoryHookCopies(root = ROOT) {
  return {
    release: fs.readFileSync(path.join(root, 'src', 'test-hook.js')),
    test: fs.readFileSync(path.join(root, 'test', 'hook', 'test-hook.js')),
  };
}

function asarEntryKind(value) {
  if (isAsarLink(value)) return 'link';
  if (isAsarDirectory(value)) return 'directory';
  return 'file';
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

    const leftEntry = left.get(name);
    const rightEntry = right.get(name);
    const leftKind = asarEntryKind(leftEntry);
    const rightKind = asarEntryKind(rightEntry);

    // The test hook is the one file the two builds are meant to differ in,
    // but each copy must still be exactly the file the build should have put
    // there.  A stub in a test build (or the driving hook in release) is a
    // failure, not an allowed difference.
    if (name === TEST_HOOK_PATH) {
      if (leftKind !== 'file' || !leftEntry.equals(toBuffer(expectedHooks.release))) {
        differences.push(`${rel}:${name}: release copy differs from src/test-hook.js`);
      }
      if (rightKind !== 'file' || !rightEntry.equals(toBuffer(expectedHooks.test))) {
        differences.push(`${rel}:${name}: test copy differs from test/hook/test-hook.js`);
      }
      continue;
    }

    if (leftKind !== rightKind) {
      differences.push(
        `${rel}:${name}: is a ${leftKind} in release but a ${rightKind} in test`,
      );
      continue;
    }

    if (leftKind === 'directory') continue;

    if (leftKind === 'link') {
      if (leftEntry.target !== rightEntry.target) {
        differences.push(
          `${rel}:${name}: link target differs (${leftEntry.target} vs ${rightEntry.target})`,
        );
      }
      continue;
    }

    if (!leftEntry.equals(rightEntry)) {
      differences.push(`${rel}:${name}: differs`);
    }
  }
}

function isLowercaseHexByte(byte) {
  return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66);
}

function lowercaseHexRuns(buffer) {
  const runs = new Map();
  let index = 0;
  while (index < buffer.length) {
    if (!isLowercaseHexByte(buffer[index])) {
      index += 1;
      continue;
    }
    const start = index;
    while (index < buffer.length && isLowercaseHexByte(buffer[index])) index += 1;
    const length = index - start;
    if (length === 64) runs.set(start, length);
  }
  return runs;
}

function integrityHashRanges(left, right) {
  const ranges = [];
  const leftRuns = lowercaseHexRuns(left);
  if (leftRuns.size === 0) return ranges;
  const rightRuns = lowercaseHexRuns(right);
  for (const [start, length] of leftRuns) {
    if (rightRuns.get(start) !== 64) continue;
    ranges.push([start, start + length]);
  }
  return ranges;
}

// The two executables are built from the same Electron distribution with the
// same fuses, so they must be identical except for the embedded asar integrity
// hash.  That hash is a run of exactly 64 lowercase hex characters at the same
// offset in both files.  Any other differing byte range is a failure.
function compareExecutables(leftBuffer, rightBuffer) {
  const left = toBuffer(leftBuffer);
  const right = toBuffer(rightBuffer);
  if (left.length !== right.length) {
    return [`lengths differ (release ${left.length} bytes, test ${right.length} bytes)`];
  }
  if (left.equals(right)) {
    return ['identical in both builds; the test build must differ'];
  }

  const allowedRanges = integrityHashRanges(left, right);
  const differences = [];
  let index = 0;
  while (index < left.length && differences.length < 10) {
    if (left[index] === right[index]) {
      index += 1;
      continue;
    }

    const start = index;
    while (index < left.length && left[index] !== right[index]) index += 1;
    const length = index - start;

    const insideIntegrityHash = allowedRanges.some(
      ([rangeStart, rangeEnd]) => start >= rangeStart && index <= rangeEnd,
    );
    if (!insideIntegrityHash) {
      differences.push(`bytes differ at offset ${start} (length ${length})`);
    }
  }
  return differences;
}

// Pure comparison of two trees.  Each tree is a Map or plain object of
// relative path -> Buffer/string.  listAsar(bytes, side, rel) returns the
// entries inside that asar as a Map, array or plain object; entries may be
// files, links or directories.  It is injected so this function itself never
// touches the archives on disk.  expectedHooks is { release, test } as Buffers;
// by default the repository's two hook files are used, because each build must
// carry exactly its own copy.
function compareTrees(a, b, listAsar, expectedHooks) {
  const hooks = expectedHooks ?? repositoryHookCopies();
  const left = normalizeTree(a);
  const right = normalizeTree(b);
  const differences = [];
  const notes = [];

  if (left.size === 0) differences.push('the release tree is empty');
  if (right.size === 0) differences.push('the test tree is empty');

  // Both builds must carry the pinned sidecar beside the asar (C4): the app
  // hashes that very file before every launch.  Its bytes must then be equal
  // like every other shared file below.
  const present = (tree) => [...tree.keys()].some(
    (rel) => rel === SIDECAR_EXE_PATH || rel.endsWith(`/${SIDECAR_EXE_PATH}`),
  );
  if (!present(left)) differences.push(`${SIDECAR_EXE_PATH}: missing from the release build`);
  if (!present(right)) differences.push(`${SIDECAR_EXE_PATH}: missing from the test build`);

  const names = new Set([...left.keys(), ...right.keys()]);
  for (const rel of [...names].sort()) {
    const inLeft = left.has(rel);
    const inRight = right.has(rel);
    if (!inLeft || !inRight) {
      differences.push(`${rel}: only in ${inLeft ? 'release' : 'test'}`);
      continue;
    }

    if (rel === EXE_PATH || rel.endsWith(`/${EXE_PATH}`)) {
      const exeDifferences = compareExecutables(left.get(rel), right.get(rel));
      for (const difference of exeDifferences) {
        differences.push(`${rel}: ${difference}`);
      }
      notes.push(
        `${rel}: compared byte for byte (only the embedded asar integrity hash may differ); `
          + 'the fuse wire is checked separately',
      );
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

// listPackage() returns entries with a leading separator, which is a backslash
// on Windows.  extractFile() and statFile() want the path relative to the
// archive root, so strip the leading separator while keeping the separator
// style listPackage used.
function archiveEntryName(entry) {
  return String(entry).replace(/^[\\/]+/, '');
}

function extractAsarFile(asar, archivePath, entry) {
  return asar.extractFile(archivePath, archiveEntryName(entry));
}

function statAsarFile(asar, archivePath, entry) {
  return asar.statFile(archivePath, archiveEntryName(entry));
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

    // listPackage() returns folders and links as well as files.  A link has a
    // target but no bytes, and a folder may be empty, so record both instead of
    // passing them to extractFile().
    let stats = null;
    if (typeof asar.statFile === 'function') {
      try {
        stats = statAsarFile(asar, archivePath, entry);
      } catch {
        // Without a stat we can still try to extract a real file below.
      }
    }
    if (stats && stats.link !== undefined && stats.link !== null && stats.link !== false) {
      files.set(name, asarLink(stats.link));
      continue;
    }
    if (stats && (stats.files !== undefined || stats.directory === true)) {
      files.set(name, asarDirectory());
      continue;
    }

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
  if (Array.isArray(wire)) return Uint8Array.from(wire);
  if (wire !== null && typeof wire === 'object') {
    for (const candidate of [
      wire.wire,
      wire.buffer,
      wire.bytes,
      wire.fuseWire,
      wire.fuses,
      wire.data,
    ]) {
      if (Buffer.isBuffer(candidate) || candidate instanceof Uint8Array) return candidate;
      if (Array.isArray(candidate)) return Uint8Array.from(candidate);
    }
  }
  return null;
}

function stateByte(value, fallback) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const text = value.trim().toLowerCase();
    if (text === '0' || text === 'off' || text === 'disabled' || text === 'disable') {
      return FUSE_STATE_BYTES.DISABLE;
    }
    if (text === '1' || text === 'on' || text === 'enabled' || text === 'enable') {
      return FUSE_STATE_BYTES.ENABLE;
    }
    if (text === 'r' || text === 'removed') return FUSE_STATE_BYTES.REMOVED;
    if (text === '?' || text === 'invalid') return FUSE_STATE_BYTES.INVALID;
  }
  return fallback;
}

function fuseStateValues(FuseState) {
  const exported = FuseState !== null && typeof FuseState === 'object' ? FuseState : {};
  return {
    disable: stateByte(exported.DISABLE, FUSE_STATE_BYTES.DISABLE),
    enable: stateByte(exported.ENABLE, FUSE_STATE_BYTES.ENABLE),
    removed: stateByte(exported.REMOVED, FUSE_STATE_BYTES.REMOVED),
    invalid: stateByte(exported.INVALID, FUSE_STATE_BYTES.INVALID),
  };
}

function fuseStateByte(state, states) {
  if (state === true) return states.enable;
  if (state === false) return states.disable;
  if (state === 'removed') return states.removed;
  return states.invalid;
}

// Turn any supported fuse-wire shape into the raw bytes.  Normally the fuses
// library hands us the wire bytes directly; when it gives an object instead,
// rebuild the wire from its option keys so the two wires can still be compared
// byte for byte.
function fuseWireBuffer(wire, FuseV1Options, FuseState) {
  const raw = wireBytes(wire);
  if (raw !== null) return Buffer.from(raw);
  if (wire === null || typeof wire !== 'object') return null;

  const states = fuseStateValues(FuseState);
  const values = new Map();
  const remember = (option, value) => {
    const state = normalizeFuseState(value, states);
    values.set(
      option,
      state === null ? stateByte(value, states.invalid) : fuseStateByte(state, states),
    );
  };

  if (typeof wire.getFuseState === 'function') {
    const options = Object.values(FuseV1Options ?? {}).filter((value) => Number.isInteger(value));
    if (options.length === 0) return null;
    for (const option of options) remember(option, wire.getFuseState(option));
  } else {
    for (const [key, value] of Object.entries(wire)) {
      let option;
      if (/^\d+$/.test(key)) {
        option = Number(key);
      } else if (Object.prototype.hasOwnProperty.call(FuseV1Options ?? {}, key)) {
        option = FuseV1Options[key];
      } else {
        continue;
      }
      remember(option, value);
    }
  }

  if (values.size === 0) return null;
  const last = Math.max(...values.keys());
  const bytes = Buffer.alloc(last + 1, states.invalid);
  for (const [option, byte] of values) bytes[option] = byte;
  return bytes;
}

function compareFuseWires(leftWire, rightWire, label = 'executable') {
  const left = wireBytes(leftWire) ?? fuseWireBuffer(leftWire);
  const right = wireBytes(rightWire) ?? fuseWireBuffer(rightWire);
  if (left === null || right === null) {
    return [`${label}: cannot read the fuse wire bytes`];
  }
  const a = Buffer.isBuffer(left) ? left : Buffer.from(left);
  const b = Buffer.isBuffer(right) ? right : Buffer.from(right);
  if (a.length !== b.length) {
    return [`${label}: fuse wire lengths differ (${a.length} vs ${b.length})`];
  }

  const differences = [];
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] !== b[index]) {
      differences.push(
        `${label}: fuse wire byte ${index} differs (${a[index]} vs ${b[index]})`,
      );
    }
  }
  return differences;
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
  if (numeric === states.enable || numeric === FUSE_STATE_BYTES.ENABLE) return true;
  if (numeric === states.disable || numeric === FUSE_STATE_BYTES.DISABLE) return false;
  if (numeric === states.removed || numeric === FUSE_STATE_BYTES.REMOVED) return 'removed';
  if (numeric === states.invalid || numeric === FUSE_STATE_BYTES.INVALID) return 'invalid';
  // Also accept the ordinal and plain 0/1 forms, for callers that already
  // decoded the wire instead of handing over its bytes.
  if (numeric === 0) return false;
  if (numeric === 1) return true;
  if (numeric === 2) return 'removed';
  if (numeric === 3) return 'invalid';
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

async function compareExecutableFuses(
  releaseDirectory,
  releaseTree,
  testDirectory,
  testTree,
  fuses,
) {
  const { getCurrentFuseWire, FuseV1Options, FuseState } = fuses;
  const differences = [];
  const wires = {};

  for (const [side, directory, tree] of [
    ['release', releaseDirectory, releaseTree],
    ['test', testDirectory, testTree],
  ]) {
    const rel = executableKey(tree);
    if (rel === undefined) {
      differences.push(`${EXE_PATH}: missing`);
      continue;
    }
    const wire = await getCurrentFuseWire(path.join(path.resolve(directory), rel));
    wires[side] = wire;
    differences.push(...checkFuseWire(wire, FuseV1Options, FuseState, rel));
  }

  if (wires.release !== undefined && wires.test !== undefined) {
    const releaseBytes = fuseWireBuffer(wires.release, FuseV1Options, FuseState);
    const testBytes = fuseWireBuffer(wires.test, FuseV1Options, FuseState);
    differences.push(...compareFuseWires(
      releaseBytes ?? wires.release,
      testBytes ?? wires.test,
      executableKey(releaseTree) ?? EXE_PATH,
    ));
  }

  return differences;
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
      ...await compareExecutableFuses(releaseDir, releaseTree, testDir, testTree, fuses),
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
    'builds match: every file is byte-identical except resources/app.asar, and the exes differ '
      + 'only in their embedded asar integrity hash; inside the asars only src/test-hook.js may '
      + 'differ, and both exes hold the section 1 fuses and the same fuse wire.  Both builds '
      + 'carry the pinned resources/rongroi-scan.exe.',
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
  SIDECAR_EXE_PATH,
  TEST_HOOK_PATH,
  SECTION_1_FUSES,
  compareTrees,
  compareExecutables,
  compareFuseWires,
  compareExecutableFuses,
  readTree,
  listAsarFromDisk,
  repositoryHookCopies,
  expectedFuseEntries,
  checkFuseWire,
  main,
};
