// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Lay out the release zip folder of ADR 0001 section 7:
//   node scripts/package.js <releaseFolder> <outDir>
// Copies every file of <releaseFolder> into <outDir>/rongroi-connect-<version>/
// with Electron's LICENSE moved to LICENSE.electron.txt, the repository's
// GPL-3.0-or-later LICENSE at LICENSE, and a CRLF README.txt with the source
// URL, bundled sidecar version, and the seven player steps of section 7.

const fs = require('node:fs');
const path = require('node:path');

const { readSidecarLock } = require('./build');

const ROOT = path.resolve(__dirname, '..');

const REQUIRED_RELEASE_FILES = [
  'rongroi-connect.exe',
  'resources/app.asar',
  'resources/rongroi-scan.exe',
  'LICENSE',
  'LICENSES.chromium.html',
];

function oneLine(text) {
  return String(text).replace(/\r?\n/g, ' ');
}

function readJson(file, label) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    const reason = oneLine(error && error.message ? error.message : error);
    throw new Error(`cannot read ${label} at ${file}: ${reason}`);
  }
}

function buildReadme({ version, sidecarVersion, tag } = {}) {
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error('buildReadme requires a non-empty version');
  }
  if (typeof sidecarVersion !== 'string' || sidecarVersion.length === 0) {
    throw new Error('buildReadme requires a non-empty sidecarVersion');
  }
  const releaseTag = typeof tag === 'string' && tag.length > 0 ? tag : `v${version}`;
  const lines = [
    `Rongroi Connect ${version}`,
    '',
    'Rongroi Connect sends a rongroi report to the one FiveM server the player paired it with, only after the player agrees.',
    '',
    `Source: https://github.com/aeterna/aeterna-rongroi-connect/tree/${releaseTag}`,
    `Bundled sidecar: rongroi-scan ${sidecarVersion}`,
    '',
    'Player steps:',
    '1. Download the zip from Releases.',
    '2. In Command Prompt run `certutil -hashfile <zip> SHA256` and compare with the line in SHA256SUMS.',
    '3. Only on a match, open Properties -> Unblock -> OK on the zip.',
    '4. Use "Extract All" with Windows\' extractor.',
    '5. Run rongroi-connect.exe (no install, no admin).',
    '6. If SmartScreen warns, choose More info -> Run anyway.',
    '7. Paste the code from the game.',
    '',
  ];
  return lines.join('\r\n');
}

function assertFileExists(baseDir, relPath) {
  const fullPath = path.join(baseDir, ...relPath.split('/'));
  let stats;
  try {
    stats = fs.statSync(fullPath);
  } catch {
    throw new Error(`release folder ${baseDir} is missing required file ${relPath}`);
  }
  if (!stats.isFile()) {
    throw new Error(`release folder ${baseDir} entry ${relPath} is not a file`);
  }
}

function copyReleaseTree(sourceRoot, targetRoot) {
  function walk(currentSource, relPrefix) {
    const entries = fs.readdirSync(currentSource, { withFileTypes: true });
    for (const entry of entries) {
      const sourcePath = path.join(currentSource, entry.name);
      const relPath = relPrefix === '' ? entry.name : `${relPrefix}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(sourcePath, relPath);
      } else {
        const destRel = relPath === 'LICENSE' ? 'LICENSE.electron.txt' : relPath;
        const destPath = path.join(targetRoot, ...destRel.split('/'));
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
        fs.copyFileSync(sourcePath, destPath);
      }
    }
  }
  walk(sourceRoot, '');
}

function layout({ releaseFolder, outDir, root = ROOT } = {}) {
  if (typeof releaseFolder !== 'string' || releaseFolder === '') {
    throw new Error('releaseFolder is required');
  }
  if (typeof outDir !== 'string' || outDir === '') {
    throw new Error('outDir is required');
  }

  const resolvedRoot = path.resolve(root);
  const resolvedRelease = path.resolve(releaseFolder);
  const resolvedOut = path.resolve(outDir);

  let releaseStats;
  try {
    releaseStats = fs.statSync(resolvedRelease);
  } catch {
    throw new Error(`release folder is missing: ${resolvedRelease}`);
  }
  if (!releaseStats.isDirectory()) {
    throw new Error(`release folder is not a directory: ${resolvedRelease}`);
  }

  for (const requiredFile of REQUIRED_RELEASE_FILES) {
    assertFileExists(resolvedRelease, requiredFile);
  }

  const pkg = readJson(path.join(resolvedRoot, 'package.json'), 'package.json');
  if (!pkg || typeof pkg.version !== 'string' || pkg.version.length === 0) {
    throw new Error(`package.json at ${resolvedRoot} must have a non-empty version`);
  }

  const rootLicense = path.join(resolvedRoot, 'LICENSE');
  let licenseStats;
  try {
    licenseStats = fs.statSync(rootLicense);
  } catch {
    throw new Error(`missing repository LICENSE at ${rootLicense}`);
  }
  if (!licenseStats.isFile()) {
    throw new Error(`repository LICENSE at ${rootLicense} is not a file`);
  }

  const lockFile = path.join(resolvedRoot, 'sidecar.lock.json');
  const sidecar = readSidecarLock(lockFile);
  if (sidecar.source !== 'release') {
    throw new Error(
      `sidecar.lock.json (${lockFile}) must have source "release" to package a release zip`,
    );
  }

  const targetDir = path.join(resolvedOut, `rongroi-connect-${pkg.version}`);
  if (fs.existsSync(targetDir)) {
    throw new Error(`target folder already exists: ${targetDir}`);
  }

  fs.mkdirSync(targetDir, { recursive: true });
  copyReleaseTree(resolvedRelease, targetDir);
  fs.copyFileSync(rootLicense, path.join(targetDir, 'LICENSE'));

  const readme = buildReadme({
    version: pkg.version,
    sidecarVersion: sidecar.version,
    tag: `v${pkg.version}`,
  });
  fs.writeFileSync(path.join(targetDir, 'README.txt'), Buffer.from(readme, 'utf8'));

  return targetDir;
}

function main(argv) {
  const args = argv.filter((arg) => arg !== '--');
  if (args.length !== 2 || args[0] === '' || args[1] === '') {
    console.error('usage: node scripts/package.js <releaseFolder> <outDir>');
    process.exitCode = 2;
    return;
  }

  try {
    const created = layout({ releaseFolder: args[0], outDir: args[1] });
    console.log(created);
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    console.error(oneLine(message));
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = {
  buildReadme,
  layout,
  main,
};
