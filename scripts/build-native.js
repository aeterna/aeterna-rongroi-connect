// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Build the Windows N-API pipe module and give it the name native/pipe/index.js
// loads: native/pipe/rongroi_connect_pipe.node.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const MANIFEST = path.join(ROOT, 'native', 'pipe', 'Cargo.toml');
const RELEASE_DIR = path.join(ROOT, 'native', 'pipe', 'target', 'release');
const BUILT = path.join(RELEASE_DIR, 'rongroi_connect_pipe.dll');
const DESTINATION = path.join(ROOT, 'native', 'pipe', 'rongroi_connect_pipe.node');

function findBuiltDll() {
  if (fs.existsSync(BUILT)) return BUILT;
  if (!fs.existsSync(RELEASE_DIR)) return null;

  // Cargo's lib name is the crate name with hyphens replaced by underscores,
  // but keep a small fallback in case the target directory is configured
  // differently.
  for (const name of fs.readdirSync(RELEASE_DIR)) {
    if (name.toLowerCase().endsWith('.dll')) return path.join(RELEASE_DIR, name);
  }
  return null;
}

function main() {
  const result = spawnSync(
    'cargo',
    ['build', '--release', '--locked', '--manifest-path', MANIFEST],
    { cwd: ROOT, stdio: 'inherit' },
  );

  if (result.error) {
    console.error(result.error.message);
    process.exitCode = 1;
    return;
  }
  if (result.status !== 0) {
    process.exitCode = result.status === null ? 1 : result.status;
    return;
  }

  const built = findBuiltDll();
  if (built === null) {
    console.error(`cargo built no .dll in ${RELEASE_DIR}`);
    process.exitCode = 1;
    return;
  }

  fs.copyFileSync(built, DESTINATION);
  console.log(`copied ${built} to ${DESTINATION}`);
}

if (require.main === module) main();

module.exports = { main, findBuiltDll, BUILT, DESTINATION };
