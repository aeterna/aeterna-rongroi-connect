// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Build one of the two folders of ADR 0001 section 2 from the same source:
//   node scripts/build.js <outDir> [--test]
// The release folder gets src/test-hook.js (the stub); --test replaces it with
// test/hook/test-hook.js.  Nothing else differs between the two staged trees.
// Both folders carry the pinned sidecar next to their asar: build.js requires
// vendor/rongroi-scan.exe, hashes it into staged src/sidecar.json, and copies
// the exe to <output>/resources/rongroi-scan.exe.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const PACKAGE_JSON = path.join(ROOT, 'package.json');
const NATIVE_MODULE = path.join(ROOT, 'native', 'pipe', 'rongroi_connect_pipe.node');
const LOCK_FILE = path.join(ROOT, 'sidecar.lock.json');
const VENDOR_EXE = path.join(ROOT, 'vendor', 'rongroi-scan.exe');
const SIDECAR_EXE_NAME = 'rongroi-scan.exe';
const SIDECAR_RECORD = path.join('src', 'sidecar.json');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sha256Hex(file) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(file));
  return hash.digest('hex');
}

// sidecar.lock.json pins which sidecar the build must carry.  Every failure
// here is one line that names the lock file, per C4.
function readSidecarLock(lockFile) {
  let lock;
  try {
    lock = readJson(lockFile);
  } catch (error) {
    throw new Error(`cannot read sidecar.lock.json at ${lockFile}: ${error.message}`);
  }
  if (lock === null || typeof lock !== 'object' || Array.isArray(lock)
      || typeof lock.commit !== 'string' || lock.commit.length === 0) {
    throw new Error(`sidecar.lock.json (${lockFile}) must record the pinned sidecar commit`);
  }
  return lock;
}

function requireVendorSidecar(vendorExe, lockFile) {
  if (fs.existsSync(vendorExe)) return;
  throw new Error(
    `missing ${vendorExe}; build the sidecar pinned by sidecar.lock.json (${lockFile}) into vendor/ first`,
  );
}

function stagedPackageJson(pkg) {
  const staged = JSON.parse(JSON.stringify(pkg));
  delete staged.devDependencies;
  return staged;
}

function copyFile(from, to) {
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
}

function removeStaging(directory) {
  try {
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  } catch {
    // The build result is already on disk; a locked temporary file is not fatal.
  }
}

function stage({
  test,
  vendorExe = VENDOR_EXE,
  lockFile = LOCK_FILE,
  nativeModule = NATIVE_MODULE,
} = {}) {
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rongroi-connect-build-'));
  const pkg = readJson(PACKAGE_JSON);

  try {
    const sidecar = readSidecarLock(lockFile);
    requireVendorSidecar(vendorExe, lockFile);

    fs.writeFileSync(
      path.join(stageDir, 'package.json'),
      `${JSON.stringify(stagedPackageJson(pkg), null, 2)}\n`,
      'utf8',
    );

    fs.cpSync(path.join(ROOT, 'src'), path.join(stageDir, 'src'), { recursive: true });

    fs.writeFileSync(
      path.join(stageDir, SIDECAR_RECORD),
      `${JSON.stringify(
        { sha256: sha256Hex(vendorExe), commit: sidecar.commit },
        null,
        2,
      )}\n`,
      'utf8',
    );

    copyFile(
      path.join(ROOT, 'native', 'pipe', 'index.js'),
      path.join(stageDir, 'native', 'pipe', 'index.js'),
    );
    if (!fs.existsSync(nativeModule)) {
      throw new Error(`missing ${nativeModule}; run npm run build:native first`);
    }
    copyFile(nativeModule, path.join(stageDir, 'native', 'pipe', 'rongroi_connect_pipe.node'));

    if (test) {
      copyFile(
        path.join(ROOT, 'test', 'hook', 'test-hook.js'),
        path.join(stageDir, 'src', 'test-hook.js'),
      );
    }

    return { stageDir, pkg, sidecarExe: vendorExe };
  } catch (error) {
    removeStaging(stageDir);
    throw error;
  }
}

async function requireOrImport(name) {
  try {
    return require(name);
  } catch (error) {
    if (error && (error.code === 'ERR_REQUIRE_ESM' || error.code === 'ERR_REQUIRE_ASYNC_MODULE')) {
      return import(name);
    }
    throw error;
  }
}

async function loadPackager() {
  const loaded = await requireOrImport('@electron/packager');
  const packager = typeof loaded === 'function'
    ? loaded
    : loaded.packager ?? loaded.default;
  if (typeof packager !== 'function') {
    throw new Error('@electron/packager did not export a packager function');
  }
  return packager;
}

async function loadFuses() {
  const loaded = await requireOrImport('@electron/fuses');
  const fuses = [loaded, loaded.default]
    .find((candidate) => candidate && typeof candidate.flipFuses === 'function') ?? loaded;
  const { flipFuses, FuseVersion, FuseV1Options } = fuses;
  if (typeof flipFuses !== 'function' || FuseVersion === undefined || FuseV1Options === undefined) {
    throw new Error('@electron/fuses did not export flipFuses, FuseVersion and FuseV1Options');
  }
  return { flipFuses, FuseVersion, FuseV1Options };
}

async function main(argv) {
  const test = argv.includes('--test');
  const outArg = argv.find((value) => value !== '--test' && value !== '--');
  if (outArg === undefined || outArg === '') {
    console.error('usage: node scripts/build.js <outDir> [--test]');
    process.exitCode = 2;
    return;
  }

  const outDir = path.resolve(outArg);
  fs.mkdirSync(outDir, { recursive: true });
  const { stageDir, pkg, sidecarExe } = stage({ test });

  try {
    const electronVersion = pkg.devDependencies && pkg.devDependencies.electron;
    if (typeof electronVersion !== 'string' || electronVersion === '') {
      throw new Error('package.json devDependencies.electron must pin the Electron version');
    }

    const packager = await loadPackager();
    const packaged = await packager({
      dir: stageDir,
      out: outDir,
      platform: 'win32',
      arch: 'x64',
      electronVersion,
      asar: { unpack: '**/*.node' },
      name: 'rongroi-connect',
      executableName: 'rongroi-connect',
      prune: false,
      overwrite: true,
    });

    const firstOutput = Array.isArray(packaged) ? packaged[0] : packaged;
    if (typeof firstOutput !== 'string' || firstOutput === '') {
      throw new Error('@electron/packager produced no output folder');
    }
    const output = path.resolve(firstOutput);
    const executable = path.join(output, 'rongroi-connect.exe');
    if (!fs.existsSync(executable)) {
      throw new Error(`the packaged executable is missing: ${executable}`);
    }

    // ADR 0001 section 4: the sidecar lives beside the asar, outside it, so the
    // app can hash the very file it is about to run before every launch.
    copyFile(sidecarExe, path.join(output, 'resources', SIDECAR_EXE_NAME));

    const { flipFuses, FuseVersion, FuseV1Options } = await loadFuses();
    await flipFuses(executable, {
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.EnableCookieEncryption]: true,
    });

    console.log(output);
  } finally {
    removeStaging(stageDir);
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  });
}

module.exports = {
  stagedPackageJson,
  stage,
  main,
};
