// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { compareTrees } = require('../scripts/compare-builds');
const { stagedPackageJson } = require('../scripts/build');

function baseTree() {
  return {
    'rongroi-connect.exe': 'release executable',
    'resources/app.asar': 'release asar bytes',
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

test('identical builds pass, including a differing exe and test hook', () => {
  const releaseFiles = asar({
    'src/main/main.js': 'same main',
    'src/renderer/index.html': 'same page',
    'src/test-hook.js': 'release stub',
  });
  const testFiles = asar({
    'src/main/main.js': 'same main',
    'src/renderer/index.html': 'same page',
    'src/test-hook.js': 'test hook',
  });

  const release = baseTree();
  const testTree = { ...baseTree(), 'rongroi-connect.exe': 'test executable' };

  const result = compareTrees(release, testTree, lister(releaseFiles, testFiles));

  assert.equal(result.ok, true);
  assert.deepEqual(result.differences, []);
  assert.ok(result.notes.some((note) => note.includes('rongroi-connect.exe')));
});

test('a file in only one tree fails', () => {
  const files = asar({ 'src/main/main.js': 'same' });
  const release = baseTree();
  const testTree = { ...baseTree(), 'resources/extra.pak': 'extra' };

  const result = compareTrees(release, testTree, lister(files, files));

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('resources/extra.pak')));
});

test('a differing src/main/main.js inside the asar fails', () => {
  const releaseFiles = asar({
    'src/main/main.js': 'release main',
    'src/test-hook.js': 'release stub',
  });
  const testFiles = asar({
    'src/main/main.js': 'test main',
    'src/test-hook.js': 'test hook',
  });

  const result = compareTrees(baseTree(), baseTree(), lister(releaseFiles, testFiles));

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('src/main/main.js')));
});

test('a differing resources/other.pak fails', () => {
  const files = asar({ 'src/main/main.js': 'same' });
  const release = baseTree();
  const testTree = { ...baseTree(), 'resources/other.pak': 'a different pak' };

  const result = compareTrees(release, testTree, lister(files, files));

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('resources/other.pak')));
});

test('a file in only one asar fails, even when it is the test hook', () => {
  const releaseFiles = asar({ 'src/main/main.js': 'same' });
  const testFiles = asar({ 'src/main/main.js': 'same', 'src/test-hook.js': 'test hook' });

  const result = compareTrees(baseTree(), baseTree(), lister(releaseFiles, testFiles));

  assert.equal(result.ok, false);
  assert.ok(result.differences.some((entry) => entry.includes('src/test-hook.js')));
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
