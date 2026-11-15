// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { buildReadme, layout } = require('../scripts/package');

function writeTree(baseDir, entries) {
  for (const [rel, value] of Object.entries(entries)) {
    const target = path.join(baseDir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (Buffer.isBuffer(value)) {
      fs.writeFileSync(target, value);
    } else {
      fs.writeFileSync(target, String(value), 'utf8');
    }
  }
}

function makeFixtures(tempDir, {
  version = '0.1.0',
  lock = {
    source: 'release',
    repository: 'aeterna/aeterna-rongroi',
    tag: 'v2026.11.13-0.15.0',
    version: '0.15.0',
    asset: 'rongroi-scan-0.15.0-windows-x64.exe',
    sha256: '8a268639527fafd530166ce3c592526ef256ecd362c3a3e7ecb40896427b6d93',
    commit: 'd8d17f0c3322e35e4d94dc9cc797f8b423f1669d',
    package: 'rongroi-scan',
  },
  releaseOverrides = {},
  omitReleaseFiles = [],
} = {}) {
  const root = path.join(tempDir, 'root');
  const releaseFolder = path.join(tempDir, 'release');
  const outDir = path.join(tempDir, 'out');
  fs.mkdirSync(root, { recursive: true });
  fs.mkdirSync(releaseFolder, { recursive: true });

  const rootLicense = Buffer.from('GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007\n', 'utf8');
  writeTree(root, {
    'package.json': `${JSON.stringify({ name: 'aeterna-rongroi-connect', version }, null, 2)}\n`,
    LICENSE: rootLicense,
    'sidecar.lock.json': `${JSON.stringify(lock, null, 2)}\n`,
  });

  const releaseFiles = {
    'rongroi-connect.exe': Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03]),
    'resources/app.asar': Buffer.from('asar archive bytes', 'utf8'),
    'resources/app.asar.unpacked/native/pipe/rongroi_connect_pipe.node': Buffer.from([0x01, 0x02, 0x03]),
    'resources/rongroi-scan.exe': Buffer.from('pinned sidecar binary', 'utf8'),
    LICENSE: Buffer.from('MIT License - Electron contributors\n', 'utf8'),
    'LICENSES.chromium.html': Buffer.from('<!doctype html><title>Chromium Licenses</title>', 'utf8'),
    'locales/en-US.pak': Buffer.from('en-US locale pak', 'utf8'),
    'chrome_100_percent.pak': Buffer.from([0xca, 0xfe, 0xba, 0xbe]),
    ...releaseOverrides,
  };
  for (const omitted of omitReleaseFiles) {
    delete releaseFiles[omitted];
  }
  writeTree(releaseFolder, releaseFiles);

  return {
    root,
    releaseFolder,
    outDir,
    rootLicense,
    releaseFiles,
  };
}

test('layout creates one top folder with GPL LICENSE, LICENSE.electron.txt, CRLF README.txt, and byte-identical runtime files', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'package-layout-'));

  try {
    const {
      root,
      releaseFolder,
      outDir,
      rootLicense,
      releaseFiles,
    } = makeFixtures(tempDir);

    const created = layout({ releaseFolder, outDir, root });
    assert.equal(created, path.join(outDir, 'rongroi-connect-0.1.0'));

    const topEntries = fs.readdirSync(outDir);
    assert.deepEqual(topEntries, ['rongroi-connect-0.1.0']);

    assert.deepEqual(
      fs.readFileSync(path.join(created, 'LICENSE')),
      rootLicense,
    );
    assert.deepEqual(
      fs.readFileSync(path.join(created, 'LICENSE.electron.txt')),
      releaseFiles.LICENSE,
    );

    for (const [rel, expectedBytes] of Object.entries(releaseFiles)) {
      if (rel === 'LICENSE') continue;
      const actualBytes = fs.readFileSync(path.join(created, ...rel.split('/')));
      assert.deepEqual(actualBytes, expectedBytes, `mismatch in ${rel}`);
    }

    const readmeBytes = fs.readFileSync(path.join(created, 'README.txt'));
    assert.equal(
      readmeBytes.length >= 3 && readmeBytes[0] === 0xef && readmeBytes[1] === 0xbb && readmeBytes[2] === 0xbf,
      false,
      'README.txt must not have a UTF-8 BOM',
    );
    const readme = readmeBytes.toString('utf8');
    assert.equal(readme.includes('\r\n'), true, 'README.txt must use CRLF');
    assert.equal(/(?<!\r)\n/.test(readme), false, 'README.txt must not contain bare LF');

    const orderedSnippets = [
      'sends a rongroi report to the one FiveM server the player paired it with, only after the player agrees',
      'https://github.com/aeterna/aeterna-rongroi-connect/tree/v0.1.0',
      'rongroi-scan 0.15.0',
      '1.',
      'Releases',
      '2.',
      'certutil -hashfile <zip> SHA256',
      'SHA256SUMS',
      '3.',
      'Properties -> Unblock -> OK',
      '4.',
      'Extract All',
      "Windows' extractor",
      '5.',
      'rongroi-connect.exe (no install, no admin)',
      '6.',
      'SmartScreen',
      'More info -> Run anyway',
      '7.',
      'paste the code from the game',
    ];

    let cursor = -1;
    for (const snippet of orderedSnippets) {
      const next = readme.toLowerCase().indexOf(snippet.toLowerCase(), cursor + 1);
      assert.notEqual(next, -1, `README.txt is missing "${snippet}" after index ${cursor}`);
      cursor = next;
    }
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('layout fails naming each missing required file', () => {
  const requiredFiles = [
    'rongroi-connect.exe',
    'resources/app.asar',
    'resources/rongroi-scan.exe',
    'LICENSE',
    'LICENSES.chromium.html',
  ];

  for (const missingFile of requiredFiles) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'package-missing-'));
    try {
      const { root, releaseFolder, outDir } = makeFixtures(tempDir, {
        omitReleaseFiles: [missingFile],
      });

      assert.throws(
        () => layout({ releaseFolder, outDir, root }),
        (error) => {
          assert.equal(
            error.message.includes(missingFile),
            true,
            `error should name ${missingFile}: ${error.message}`,
          );
          assert.equal(
            error.message.includes('\n'),
            false,
            `error should be one line: ${error.message}`,
          );
          return true;
        },
        missingFile,
      );
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
});

test('layout refuses an existing target folder and refuses a build-source lock', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'package-refuse-'));

  try {
    const { root, releaseFolder, outDir } = makeFixtures(tempDir);
    const existingTarget = path.join(outDir, 'rongroi-connect-0.1.0');
    fs.mkdirSync(existingTarget, { recursive: true });

    assert.throws(
      () => layout({ releaseFolder, outDir, root }),
      (error) => {
        assert.equal(error.message.includes('rongroi-connect-0.1.0'), true);
        assert.equal(error.message.includes('\n'), false);
        return true;
      },
    );

    const buildTemp = path.join(tempDir, 'build-lock');
    const buildFixtures = makeFixtures(buildTemp, {
      lock: {
        source: 'build',
        repository: 'aeterna/aeterna-rongroi',
        commit: '3a08e2dcabd940780dd314579f6345306eae7143',
        package: 'rongroi-scan',
      },
    });

    assert.throws(
      () => layout({
        releaseFolder: buildFixtures.releaseFolder,
        outDir: buildFixtures.outDir,
        root: buildFixtures.root,
      }),
      (error) => {
        assert.equal(error.message.includes('sidecar.lock.json'), true);
        assert.equal(error.message.includes('\n'), false);
        return true;
      },
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('buildReadme contains none of clean, verified, or safe', () => {
  const readme = buildReadme({
    version: '0.1.0',
    sidecarVersion: '0.15.0',
    tag: 'v0.1.0',
  });

  assert.equal(/\b(clean|verified|safe)\b/i.test(readme), false);
  assert.equal(/clean|verified|safe/i.test(readme), false);
  assert.equal(/7-zip|winrar|peazip|bandizip/i.test(readme), false);
});
