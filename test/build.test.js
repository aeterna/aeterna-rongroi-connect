// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  SECTION_1_FUSES,
  compareTrees,
  readTree,
  listAsarFromDisk,
  repositoryHookCopies,
  checkFuseWire,
} = require('../scripts/compare-builds');
const { stagedPackageJson } = require('../scripts/build');

const HOOKS = repositoryHookCopies();
const RELEASE_HOOK = HOOKS.release;
const TEST_HOOK = HOOKS.test;

function baseTree(asarBytes = 'release asar bytes') {
  return {
    'rongroi-connect.exe': 'release executable',
    'resources/app.asar': asarBytes,
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

test('identical builds pass, including a differing exe and test hook', () => {
  const release = baseTree('release asar bytes');
  const testTree = { ...baseTree('test asar bytes'), 'rongroi-connect.exe': 'test executable' };

  const result = compareTrees(release, testTree, asarPair(), HOOKS);

  assert.equal(result.ok, true);
  assert.deepEqual(result.differences, []);
  assert.ok(result.notes.some((note) => note.includes('rongroi-connect.exe')));
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

test('listAsarFromDisk skips folders and links without extracting them', () => {
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

  assert.equal(files.has('native'), false);
  assert.equal(files.has('src/link.js'), false);
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
