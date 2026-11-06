// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  SECTION_1_FUSES,
  compareTrees,
  compareExecutables,
  compareFuseWires,
  compareExecutableFuses,
  readTree,
  listAsarFromDisk,
  repositoryHookCopies,
  checkFuseWire,
  sidecarRecordDifferences,
  checkSidecarRecords,
  SIDECAR_EXE_PATH,
  SIDECAR_RECORD_PATH,
} = require('../scripts/compare-builds');
const { stagedPackageJson, stage } = require('../scripts/build');

const HOOKS = repositoryHookCopies();
const RELEASE_HOOK = HOOKS.release;
const TEST_HOOK = HOOKS.test;

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

// The exe embeds the 64-character asar integrity hash.  Deriving it from the
// asar bytes gives every pair of different builds a realistic differing hash.
function executableFor(asarBytes) {
  return Buffer.from(`exe header ${sha256Hex(asarBytes)} exe footer`, 'utf8');
}

function baseTree(asarBytes = 'release asar bytes') {
  return {
    'rongroi-connect.exe': executableFor(asarBytes),
    'resources/app.asar': asarBytes,
    'resources/rongroi-scan.exe': 'the same pinned sidecar',
    'resources/other.pak': 'the same pak',
    LICENSE: 'the same license',
  };
}

function asar(files) {
  return new Map(Object.entries(files));
}

function lister(releaseFiles, testFiles) {
  return (bytes, side) => (side === 'release' ? releaseFiles : testFiles);
}

function asarPair(releaseFiles = {}, testFiles = {}) {
  return lister(
    asar({
      'src/main/main.js': 'same main',
      'src/test-hook.js': RELEASE_HOOK,
      ...releaseFiles,
    }),
    asar({
      'src/main/main.js': 'same main',
      'src/test-hook.js': TEST_HOOK,
      ...testFiles,
    }),
  );
}

test('identical builds pass, including a differing exe hash and test hook', () => {
  const release = baseTree('release asar bytes');
  const testTree = {
    ...baseTree('test asar bytes'),
    'rongroi-connect.exe': executableFor('the test executable'),
  };

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.differences, []);
  assert.ok(result.notes.some(
    (note) => note.includes('rongroi-connect.exe') && note.includes('compared'),
  ));
  assert.equal(result.notes.some((note) => note.includes('allowed to differ')), false);
});

test('compareExecutables allows only the 64-character asar hash to differ', () => {
  const left = Buffer.from(`head:${'a'.repeat(64)}:tail`, 'utf8');
  const right = Buffer.from(`head:${'b'.repeat(64)}:tail`, 'utf8');

  assert.deepEqual(compareExecutables(left, right), []);
});

test('compareExecutables reports a differing byte outside the asar hash', () => {
  const differences = compareExecutables(
    Buffer.from('0123456789', 'utf8'),
    Buffer.from('012345678X', 'utf8'),
  );

  assert.equal(differences.length, 1);
  assert.match(differences[0], /offset 9/);
  assert.match(differences[0], /length 1/);
});

test('compareExecutables requires the asar hash run to be exactly 64 hex characters', () => {
  const left = Buffer.from('a'.repeat(63), 'utf8');
  const right = Buffer.from('b'.repeat(63), 'utf8');

  const differences = compareExecutables(left, right);

  assert.equal(differences.length, 1);
  assert.match(differences[0], /offset 0/);
  assert.match(differences[0], /length 63/);
});

test('compareExecutables reports a length difference', () => {
  const differences = compareExecutables(Buffer.from('abc'), Buffer.from('ab'));

  assert.equal(differences.length, 1);
  assert.match(differences[0], /lengths differ/i);
});

test('compareExecutables treats identical executables as a failed comparison', () => {
  const exe = Buffer.from(`head:${'a'.repeat(64)}:tail`, 'utf8');

  const differences = compareExecutables(exe, Buffer.from(exe));

  assert.equal(differences.length, 1);
  assert.match(differences[0], /identical/);
});

test('compareExecutables reports at most the first 10 differing byte ranges', () => {
  const left = Buffer.alloc(24);
  const right = Buffer.alloc(24);
  for (let index = 0; index < right.length; index += 2) right[index] = 1;

  const differences = compareExecutables(left, right);

  assert.equal(differences.length, 10);
  assert.match(differences[0], /offset 0/);
  assert.match(differences[9], /offset 18/);
});

test('a differing exe byte outside the asar hash fails the comparison', () => {
  const release = baseTree('release asar bytes');
  const changedExe = Buffer.from(baseTree('test asar bytes')['rongroi-connect.exe']);
  changedExe[0] ^= 0xff;
  const testTree = { ...baseTree('test asar bytes'), 'rongroi-connect.exe': changedExe };

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('rongroi-connect.exe') && /offset 0/.test(entry),
  ));
});

test('a file in only one tree fails', () => {
  const release = baseTree('release asar bytes');
  const testTree = { ...baseTree('test asar bytes'), 'resources/extra.pak': 'extra' };

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('resources/extra.pak')));
});

test('a differing src/main/main.js inside the asar fails', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair({ 'src/main/main.js': 'release main' }, { 'src/main/main.js': 'test main' }),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('src/main/main.js')));
});

test('a differing resources/other.pak fails', () => {
  const release = baseTree('release asar bytes');
  const testTree = { ...baseTree('test asar bytes'), 'resources/other.pak': 'a different pak' };

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('resources/other.pak')));
});

test('a file in only one asar fails, even when it is the test hook', () => {
  const releaseFiles = asar({ 'src/main/main.js': 'same' });
  const testFiles = asar({
    'src/main/main.js': 'same',
    'src/test-hook.js': TEST_HOOK,
  });

  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    lister(releaseFiles, testFiles),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('src/test-hook.js')));
});

test('the release test hook must equal src/test-hook.js byte for byte', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair({ 'src/test-hook.js': Buffer.from('not the release stub') }),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('release copy differs from src/test-hook.js'),
  ));
});

test('the test test hook must equal test/hook/test-hook.js byte for byte', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair({}, { 'src/test-hook.js': Buffer.from('not the driving hook') }),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('test copy differs from test/hook/test-hook.js'),
  ));
});

test('a differing symlink target inside an asar fails', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair(
      { 'src/link.js': { link: 'src/release-target.js' } },
      { 'src/link.js': { link: 'src/test-target.js' } },
    ),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('src/link.js') && entry.includes('link target'),
  ));
});

test('the same symlink target inside both asars passes', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair(
      { 'src/link.js': { link: 'src/main/main.js' } },
      { 'src/link.js': { link: 'src/main/main.js' } },
    ),
    HOOKS,
  );

  assert.equal(result.ok, true);
  assert.deepEqual(result.differences, []);
});

test('a symlink in only one asar fails', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair({ 'src/link.js': { link: 'src/main/main.js' } }, {}),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('src/link.js') && entry.includes('only in release'),
  ));
});

test('a directory in only one asar fails', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair({ 'src/empty': { directory: true } }, {}),
    HOOKS,
  );

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('src/empty') && entry.includes('only in release'),
  ));
});

test('the same empty directory in both asars passes', () => {
  const result = compareTrees(
    baseTree('release asar bytes'),
    baseTree('test asar bytes'),
    asarPair(
      { 'src/empty': { directory: true } },
      { 'src/empty': { directory: true } },
    ),
    HOOKS,
  );

  assert.equal(result.ok, true);
  assert.deepEqual(result.differences, []);
});

test('two identical app.asar files fail because the builds did not differ', () => {
  const tree = baseTree('the same asar bytes');

  const result = compareTrees(tree, { ...tree }, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.ok(result.differences.some(
    (entry) => entry.includes('resources/app.asar') && entry.includes('identical'),
  ));
});

test('empty and missing build folders fail', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'compare-builds-test-'));

  try {
    assert.throws(() => readTree(path.join(root, 'missing')), /missing/);

    const empty = path.join(root, 'empty');
    fs.mkdirSync(empty);
    assert.throws(() => readTree(empty), /empty/);

    const one = path.join(root, 'one');
    fs.mkdirSync(one);
    fs.writeFileSync(path.join(one, 'file.bin'), 'bytes');
    assert.equal(readTree(one).size, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('empty trees fail the comparison', () => {
  const result = compareTrees({}, {}, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('release tree is empty')));
  assert.ok(result.differences.some((entry) => entry.includes('test tree is empty')));
});

test('listAsarFromDisk uses the unpacked placeholder only for unpacked entries', () => {
  const archive = path.join('C:', 'app', 'resources', 'app.asar');
  const asarFile = {
    listPackage: () => ['/native/pipe/rongroi_connect_pipe.node', '/src/main/main.js'],
    extractFile: (file, entry) => {
      if (String(entry).endsWith('rongroi_connect_pipe.node')) {
        throw new Error('the file is unpacked');
      }
      return Buffer.from('main bytes');
    },
    statFile: (file, entry) => ({
      unpacked: String(entry).endsWith('rongroi_connect_pipe.node'),
    }),
  };

  const files = listAsarFromDisk(asarFile, archive);

  assert.equal(
    files.get('native/pipe/rongroi_connect_pipe.node').toString('utf8'),
    'unpacked:native/pipe/rongroi_connect_pipe.node',
  );
  assert.equal(files.get('src/main/main.js').toString('utf8'), 'main bytes');
});

test('listAsarFromDisk strips the leading separator listPackage returns', () => {
  const archive = path.join('C:', 'app', 'resources', 'app.asar');
  const contents = new Map([
    ['native\\pipe\\index.js', Buffer.from('pipe bytes')],
    ['src/a.js', Buffer.from('a bytes')],
  ]);
  const resolve = (entry) => {
    const name = String(entry);
    assert.equal(
      /^[\\/]/.test(name),
      false,
      `extractFile/statFile received a leading separator: ${name}`,
    );
    assert.equal(contents.has(name), true, `unexpected archive path: ${name}`);
    return name;
  };
  const asarFile = {
    listPackage: () => ['\\native\\pipe\\index.js', '/src/a.js'],
    statFile: (file, entry) => ({ unpacked: false, name: resolve(entry) }),
    extractFile: (file, entry) => contents.get(resolve(entry)),
  };

  const files = listAsarFromDisk(asarFile, archive);

  assert.deepEqual([...files.keys()], ['native/pipe/index.js', 'src/a.js']);
  assert.equal(files.get('native/pipe/index.js').toString('utf8'), 'pipe bytes');
  assert.equal(files.get('src/a.js').toString('utf8'), 'a bytes');
});

test('listAsarFromDisk records folders and links without extracting them', () => {
  const archive = path.join('C:', 'app', 'resources', 'app.asar');
  const extracted = [];
  const asarFile = {
    listPackage: () => [
      '/native',
      '/src/link.js',
      '/src/main/main.js',
      '/native/pipe/rongroi_connect_pipe.node',
    ],
    statFile: (file, entry) => {
      const name = String(entry).replace(/^\/+/, '');
      if (name === 'native') return { files: { pipe: {} }, unpacked: false };
      if (name === 'src/link.js') return { link: 'src/main/main.js', unpacked: false };
      if (name.endsWith('.node')) return { unpacked: true };
      return { unpacked: false };
    },
    extractFile: (file, entry) => {
      const name = String(entry).replace(/^\/+/, '');
      extracted.push(name);
      if (name === 'native') throw new Error('cannot extract native');
      if (name === 'src/link.js') throw new Error('cannot extract a link');
      if (name.endsWith('.node')) throw new Error('the file is unpacked');
      return Buffer.from('main bytes');
    },
  };

  const files = listAsarFromDisk(asarFile, archive);

  assert.equal(files.get('native').directory, true);
  assert.equal(files.get('src/link.js').link, 'src/main/main.js');
  assert.equal(extracted.includes('native'), false);
  assert.equal(extracted.includes('src/link.js'), false);
  assert.equal(files.get('src/main/main.js').toString('utf8'), 'main bytes');
  assert.equal(
    files.get('native/pipe/rongroi_connect_pipe.node').toString('utf8'),
    'unpacked:native/pipe/rongroi_connect_pipe.node',
  );
});

test('listAsarFromDisk throws for an extract error that is not unpacked', () => {
  const asarFile = {
    listPackage: () => ['/src/broken.js'],
    extractFile: () => {
      throw new Error('corrupt archive');
    },
    statFile: () => ({ unpacked: false }),
  };

  assert.throws(
    () => listAsarFromDisk(asarFile, '/app/resources/app.asar'),
    /cannot extract src\/broken\.js/,
  );
});

test('listAsarFromDisk throws for an empty archive', () => {
  const asarFile = {
    listPackage: () => [],
    extractFile: () => Buffer.alloc(0),
    statFile: () => ({ unpacked: false }),
  };

  assert.throws(
    () => listAsarFromDisk(asarFile, '/app/resources/app.asar'),
    /empty/,
  );
});

const FUSE_OPTIONS = {
  RunAsNode: 1,
  EnableCookieEncryption: 2,
  EnableNodeOptionsEnvironmentVariable: 3,
  EnableNodeCliInspectArguments: 4,
  EnableEmbeddedAsarIntegrityValidation: 5,
  OnlyLoadAppFromAsar: 6,
};

// The fuse wire holds the ASCII byte for '0' (off), '1' (on) or 'r' (removed).
const FUSE_OFF = 48;
const FUSE_ON = 49;
const FUSE_REMOVED = 114;

function fuseWire(overrides = {}) {
  const states = {};
  for (const { name, value } of SECTION_1_FUSES) {
    states[FUSE_OPTIONS[name]] = value ? FUSE_ON : FUSE_OFF;
  }
  for (const [name, value] of Object.entries(overrides)) states[FUSE_OPTIONS[name]] = value;
  return { getFuseState: (option) => states[option] };
}

test('the section 1 fuse values are enforced', () => {
  assert.deepEqual(checkFuseWire(fuseWire(), FUSE_OPTIONS), []);

  // The raw wire is a byte per fuse, so an off fuse is the truthy byte 48.
  const bytes = new Uint8Array(8);
  for (const { name, value } of SECTION_1_FUSES) {
    bytes[FUSE_OPTIONS[name]] = value ? FUSE_ON : FUSE_OFF;
  }
  assert.deepEqual(checkFuseWire(bytes, FUSE_OPTIONS), []);
});

test('a wrong fuse value fails and names the fuse', () => {
  const differences = checkFuseWire(
    fuseWire({ OnlyLoadAppFromAsar: FUSE_OFF }),
    FUSE_OPTIONS,
  );

  assert.equal(differences.length, 1);
  assert.match(differences[0], /OnlyLoadAppFromAsar/);
});

test('a removed fuse fails and names the fuse', () => {
  const differences = checkFuseWire(
    fuseWire({ EnableCookieEncryption: FUSE_REMOVED }),
    FUSE_OPTIONS,
  );

  assert.equal(differences.length, 1);
  assert.match(differences[0], /EnableCookieEncryption/);
  assert.match(differences[0], /removed/i);
});

test('a fuse missing from the wire fails and names the fuse', () => {
  const wire = fuseWire();
  const missing = {
    getFuseState: (option) => (
      option === FUSE_OPTIONS.RunAsNode ? undefined : wire.getFuseState(option)
    ),
  };

  const differences = checkFuseWire(missing, FUSE_OPTIONS);

  assert.equal(differences.length, 1);
  assert.match(differences[0], /RunAsNode/);
});

function rawFuseWire(overrides = {}) {
  const bytes = Buffer.alloc(16, FUSE_OFF);
  for (const { name, value } of SECTION_1_FUSES) {
    bytes[FUSE_OPTIONS[name]] = value ? FUSE_ON : FUSE_OFF;
  }
  for (const [index, value] of Object.entries(overrides)) bytes[Number(index)] = value;
  return bytes;
}

test('the two executable fuse wires must be equal byte for byte', () => {
  assert.deepEqual(compareFuseWires(rawFuseWire(), rawFuseWire()), []);

  const differences = compareFuseWires(rawFuseWire(), rawFuseWire({ 12: FUSE_ON }));

  assert.equal(differences.length, 1);
  assert.match(differences[0], /byte 12/);
});

test('compareExecutableFuses compares both whole fuse wires', async () => {
  const releaseWire = rawFuseWire();
  const testWire = rawFuseWire({ 12: FUSE_ON });
  const fuses = {
    getCurrentFuseWire: async (file) => (
      file.includes('release-build') ? releaseWire : testWire
    ),
    FuseV1Options: FUSE_OPTIONS,
    FuseState: undefined,
  };
  const tree = new Map([['rongroi-connect.exe', Buffer.from('exe')]]);
  const releaseDir = path.join(os.tmpdir(), 'release-build');
  const testDir = path.join(os.tmpdir(), 'test-build');

  const differences = await compareExecutableFuses(releaseDir, tree, testDir, tree, fuses);

  assert.equal(differences.length, 1);
  assert.match(differences[0], /byte 12/);
});

test('the staged package.json drops devDependencies without changing the input', () => {
  const pkg = {
    name: 'aeterna-rongroi-connect',
    version: '0.1.0',
    main: 'src/main/main.js',
    scripts: { test: 'node --test' },
    devDependencies: { electron: '44.7.1' },
  };

  const staged = stagedPackageJson(pkg);

  assert.deepEqual(staged, {
    name: 'aeterna-rongroi-connect',
    version: '0.1.0',
    main: 'src/main/main.js',
    scripts: { test: 'node --test' },
  });
  assert.equal('devDependencies' in staged, false);
  assert.equal(pkg.devDependencies.electron, '44.7.1');
});

test('sidecar.lock.json pins the source build of rongroi-scan', () => {
  const lockFile = path.join(__dirname, '..', 'sidecar.lock.json');
  const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));

  assert.deepEqual(lock, {
    source: 'build',
    repository: 'aeterna/aeterna-rongroi',
    commit: '3a08e2dcabd940780dd314579f6345306eae7143',
    package: 'rongroi-scan',
  });
  assert.equal(fs.existsSync(`${lockFile}.license`), true);
});

test('the pinned sidecar travels next to the asar in both builds', () => {
  const release = baseTree('release asar bytes');
  const testTree = baseTree('test asar bytes');

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.differences, []);
});

test('a missing resources/rongroi-scan.exe in the test build fails', () => {
  const release = baseTree('release asar bytes');
  const testTree = baseTree('test asar bytes');
  delete testTree[SIDECAR_EXE_PATH];

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.equal(result.differences.some((entry) => (
    entry.includes(SIDECAR_EXE_PATH) && entry.includes('missing from the test build')
  )), true);
  assert.equal(result.differences.some((entry) => (
    entry.includes(SIDECAR_EXE_PATH) && entry.includes('missing from the release build')
  )), false);
});

test('a missing resources/rongroi-scan.exe in the release build fails', () => {
  const release = baseTree('release asar bytes');
  const testTree = baseTree('test asar bytes');
  delete release[SIDECAR_EXE_PATH];

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.equal(result.differences.some((entry) => (
    entry.includes(SIDECAR_EXE_PATH) && entry.includes('missing from the release build')
  )), true);
});

test('a missing resources/rongroi-scan.exe in both builds fails twice', () => {
  const release = baseTree('release asar bytes');
  const testTree = baseTree('test asar bytes');
  delete release[SIDECAR_EXE_PATH];
  delete testTree[SIDECAR_EXE_PATH];

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, false);
  assert.equal(result.differences.some((entry) => (
    entry.includes(SIDECAR_EXE_PATH) && entry.includes('missing from the release build')
  )), true);
  assert.equal(result.differences.some((entry) => (
    entry.includes(SIDECAR_EXE_PATH) && entry.includes('missing from the test build')
  )), true);
});

test('a sidecar record that matches its bundled exe and commit passes', () => {
  const exe = Buffer.from('the pinned sidecar bytes');
  const record = {
    sha256: crypto.createHash('sha256').update(exe).digest('hex'),
    commit: 'a'.repeat(40),
  };

  assert.deepEqual(sidecarRecordDifferences(record, exe, 'release'), []);
  assert.deepEqual(
    sidecarRecordDifferences(JSON.stringify(record), exe, 'test'),
    [],
  );
});

test('a sidecar record with a wrong sha256 or a bad commit fails', () => {
  const exe = Buffer.from('the pinned sidecar bytes');
  const digest = crypto.createHash('sha256').update(exe).digest('hex');

  const wrongHash = sidecarRecordDifferences(
    { sha256: '0'.repeat(64), commit: 'a'.repeat(40) },
    exe,
    'release',
  );
  assert.equal(wrongHash.length, 1);
  assert.match(wrongHash[0], /sha256/);

  for (const commit of ['A'.repeat(40), 'a'.repeat(39), 'a'.repeat(41), 'g'.repeat(40)]) {
    const differences = sidecarRecordDifferences(
      { sha256: digest, commit },
      exe,
      'test',
    );
    assert.equal(differences.length, 1, commit);
    assert.match(differences[0], /commit/);
    assert.match(differences[0], /40 lowercase hex/);
  }
});

test('checkSidecarRecords reads src/sidecar.json from each asar and its own exe', () => {
  const releaseExe = Buffer.from('release sidecar bytes');
  const testExe = Buffer.from('test sidecar bytes');
  const releaseTree = {
    'resources/app.asar': Buffer.from('release archive'),
    [SIDECAR_EXE_PATH]: releaseExe,
  };
  const testTree = {
    'resources/app.asar': Buffer.from('test archive'),
    [SIDECAR_EXE_PATH]: testExe,
  };
  const recordFor = (exe) => Buffer.from(JSON.stringify({
    sha256: crypto.createHash('sha256').update(exe).digest('hex'),
    commit: 'b'.repeat(40),
  }));
  const records = {
    release: recordFor(releaseExe),
    test: recordFor(testExe),
  };
  const lister = (bytes, side) => asar({ [SIDECAR_RECORD_PATH]: records[side] });

  const matching = [];
  checkSidecarRecords(releaseTree, testTree, lister, matching);
  assert.deepEqual(matching, []);

  const mismatched = [];
  checkSidecarRecords(
    releaseTree,
    testTree,
    (bytes, side) => asar({
      [SIDECAR_RECORD_PATH]: side === 'release' ? records.release : records.release,
    }),
    mismatched,
  );
  assert.equal(mismatched.length, 1);
  assert.match(mismatched[0], /test/);
  assert.match(mismatched[0], /sha256/);
});

test('checkSidecarRecords reports a record missing from an asar', () => {
  const exe = Buffer.from('sidecar bytes');
  const tree = {
    'resources/app.asar': Buffer.from('archive'),
    [SIDECAR_EXE_PATH]: exe,
  };

  const differences = [];
  checkSidecarRecords(tree, tree, () => asar({}), differences);

  assert.equal(differences.length, 2);
  for (const difference of differences) {
    assert.equal(difference.includes(SIDECAR_RECORD_PATH), true);
    assert.equal(difference.includes('missing'), true);
  }
});

function stageFixtures(root) {
  const lockFile = path.join(root, 'lock', 'sidecar.lock.json');
  fs.mkdirSync(path.dirname(lockFile), { recursive: true });
  fs.writeFileSync(lockFile, `${JSON.stringify({
    source: 'build',
    repository: 'aeterna/aeterna-rongroi',
    commit: '0'.repeat(40),
    package: 'rongroi-scan',
  }, null, 2)}\n`, 'utf8');
  return lockFile;
}

test('stage() fails without vendor/rongroi-scan.exe, naming the lock file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sidecar-stage-missing-'));

  try {
    const lockFile = stageFixtures(root);

    assert.throws(
      () => stage({ vendorExe: path.join(root, 'vendor', 'rongroi-scan.exe'), lockFile }),
      (error) => {
        assert.equal(
          error.message.includes('rongroi-scan.exe'),
          true,
          `the error should name the sidecar: ${error.message}`,
        );
        assert.equal(
          error.message.includes('sidecar.lock.json'),
          true,
          `the error should name the lock file: ${error.message}`,
        );
        assert.equal(
          error.message.includes('\n'),
          false,
          `the error should be one line: ${error.message}`,
        );
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('stage() writes src/sidecar.json with the vendor SHA-256 and the lock commit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sidecar-stage-record-'));

  try {
    const lockFile = stageFixtures(root);
    const vendorExe = path.join(root, 'rongroi-scan.exe');
    fs.writeFileSync(vendorExe, Buffer.alloc(4096, 0x52));
    // A stand-in for the native module, whose absence the stage reports
    // separately from the sidecar (the real build may not exist in the tree).
    const nativeModule = path.join(root, 'rongroi_connect_pipe.node');
    fs.writeFileSync(nativeModule, Buffer.alloc(16, 0x01));

    const { stageDir, sidecarExe } = stage({ vendorExe, lockFile, nativeModule });
    try {
      assert.equal(sidecarExe, vendorExe);
      const record = JSON.parse(
        fs.readFileSync(path.join(stageDir, 'src', 'sidecar.json'), 'utf8'),
      );
      const digest = crypto
        .createHash('sha256')
        .update(fs.readFileSync(vendorExe))
        .digest('hex');
      assert.deepEqual(record, { sha256: digest, commit: '0'.repeat(40) });
    } finally {
      fs.rmSync(stageDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
