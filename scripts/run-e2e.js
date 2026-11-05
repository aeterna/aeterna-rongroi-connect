// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Drive the test build through the whole flow against the mock Server Kit and
// the mock sidecar, then check Chromium's netlog and write e2e-report.json.
//   node scripts/run-e2e.js <testBuildDir>

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { checkNetlog } = require('./check-netlog');

const ROOT = path.resolve(__dirname, '..');
const TEMP_PREFIX = 'rongroi-connect-';
const APP_LIMIT_MS = 120 * 1000;

function withTimeout(promise, millis, message) {
  let timer = null;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), millis);
    if (typeof timer.unref === 'function') timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== null) clearTimeout(timer);
  });
}

function readLines(stream, onLine) {
  let buffered = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buffered += chunk;
    let newline = buffered.indexOf('\n');
    while (newline !== -1) {
      const line = buffered.slice(0, newline).trim();
      buffered = buffered.slice(newline + 1);
      if (line !== '') onLine(line);
      newline = buffered.indexOf('\n');
    }
  });
  stream.on('end', () => {
    const line = buffered.trim();
    if (line !== '') onLine(line);
    buffered = '';
  });
}

function startKit() {
  const kitPath = path.join(ROOT, 'test', 'mock', 'kit.js');
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;

  const child = spawn(process.execPath, [kitPath], {
    cwd: ROOT,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let resolveInfo;
  let rejectInfo;
  let infoSettled = false;
  const info = new Promise((resolve, reject) => {
    resolveInfo = resolve;
    rejectInfo = reject;
  });

  let received = false;
  let visualHash = null;
  let resolveReceived;
  const receivedPromise = new Promise((resolve) => {
    resolveReceived = resolve;
  });

  readLines(child.stdout, (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      process.stderr.write(`[kit] ${line}\n`);
      return;
    }

    if (message !== null && typeof message === 'object'
        && typeof message.code === 'string' && Number.isInteger(message.port)) {
      infoSettled = true;
      resolveInfo({ code: message.code, port: message.port, host: '127.0.0.1' });
      return;
    }

    if (message !== null && typeof message === 'object' && message.received === true) {
      received = true;
      visualHash = typeof message.visual_hash === 'string' ? message.visual_hash : null;
      resolveReceived(true);
      return;
    }

    process.stderr.write(`[kit] ${line}\n`);
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => process.stderr.write(`[kit] ${chunk}`));

  child.on('error', (error) => {
    if (!infoSettled) {
      infoSettled = true;
      rejectInfo(error);
    }
  });

  child.on('exit', (code, signal) => {
    if (!infoSettled) {
      infoSettled = true;
      rejectInfo(new Error(`the mock kit exited before printing its code (${code ?? signal})`));
    }
  });

  return {
    child,
    info,
    receivedPromise,
    get received() {
      return received;
    },
    get visualHash() {
      return visualHash;
    },
  };
}

function findExecutable(input) {
  const target = path.resolve(input);
  if (!fs.existsSync(target)) throw new Error(`the test build does not exist: ${target}`);
  if (fs.statSync(target).isFile()) return target;

  const found = [];
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(absolute);
      } else if (entry.isFile() && entry.name.toLowerCase() === 'rongroi-connect.exe') {
        found.push(absolute);
      }
    }
  }
  walk(target);

  if (found.length === 0) throw new Error(`no rongroi-connect.exe under ${target}`);
  found.sort((left, right) => left.length - right.length || left.localeCompare(right));
  return found[0];
}

function listTempMatches() {
  return fs.readdirSync(os.tmpdir())
    .filter((name) => name.startsWith(TEMP_PREFIX))
    .map((name) => path.join(os.tmpdir(), name))
    .sort();
}

function listFilesUnder(entries) {
  const files = [];

  function walk(target) {
    let stats;
    try {
      stats = fs.statSync(target);
    } catch {
      return;
    }
    if (stats.isDirectory()) {
      for (const name of fs.readdirSync(target)) walk(path.join(target, name));
    } else if (stats.isFile()) {
      files.push({ path: target, size: stats.size });
    }
  }

  for (const entry of entries) walk(entry);
  files.sort((left, right) => left.path.localeCompare(right.path));
  return files;
}

function captureLeftovers(report) {
  report.tempAfter = listTempMatches();
  report.leftoverFiles = listFilesUnder(report.tempAfter);
}

function runApplication(executable, args, env) {
  return new Promise((resolve) => {
    const child = spawn(executable, args, {
      env,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    let killTimer = null;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
      // A process that ignores the kill must not hang the whole proof.
      killTimer = setTimeout(() => {
        finish({ exitCode: null, signal: null, error: new Error('the app exceeded its 120 s limit') });
      }, 5 * 1000);
      if (typeof killTimer.unref === 'function') killTimer.unref();
    }, APP_LIMIT_MS);

    function finish(result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer !== null) clearTimeout(killTimer);
      resolve({ stdout, stderr, timedOut, ...result });
    }

    child.on('error', (error) => finish({ exitCode: null, signal: null, error }));
    child.on('exit', (code, signal) => finish({ exitCode: code, signal, error: null }));
  });
}

async function main(argv) {
  const buildArg = argv.find((value) => value !== '--');
  if (buildArg === undefined || buildArg === '') {
    console.error('usage: node scripts/run-e2e.js <testBuildDir>');
    process.exitCode = 2;
    return;
  }

  const buildDir = path.resolve(buildArg);
  const report = {
    ok: false,
    exitCode: null,
    signal: null,
    seconds: 0,
    timedOut: false,
    kitReceived: false,
    kitVisualHash: null,
    netlogOk: false,
    netlogNames: [],
    netlogUnexpected: [],
    netlogError: null,
    tempBefore: listTempMatches(),
    tempAfter: [],
    leftoverFiles: [],
    error: null,
  };

  let kit = null;
  let netlogPath = null;

  try {
    const executable = findExecutable(buildDir);
    kit = startKit();
    const kitInfo = await withTimeout(kit.info, 10 * 1000, 'the mock kit did not print its code');

    netlogPath = path.join(
      os.tmpdir(),
      `rongroi-e2e-netlog-${process.pid}-${Date.now()}.json`,
    );

    const env = {
      ...process.env,
      CONNECT_TEST_CODE: kitInfo.code,
      CONNECT_TEST_NODE: process.execPath,
      CONNECT_TEST_SIDECAR: path.join(ROOT, 'test', 'mock', 'sidecar.js'),
    };
    delete env.NODE_TEST_CONTEXT;

    const started = Date.now();
    const run = await runApplication(executable, [`--log-net-log=${netlogPath}`], env);
    report.seconds = (Date.now() - started) / 1000;
    report.exitCode = run.exitCode;
    report.signal = run.signal;
    report.timedOut = run.timedOut;
    report.error = run.error === null ? null : run.error.message;

    if (!run.error && !run.timedOut && run.exitCode === 0 && !kit.received) {
      try {
        await withTimeout(kit.receivedPromise, 5 * 1000, 'the mock kit did not report received');
      } catch {
        // The report below says received: false and fails.
      }
    }
    report.kitReceived = kit.received;
    report.kitVisualHash = kit.visualHash;

    try {
      const netlogText = fs.readFileSync(netlogPath, 'utf8');
      const netlog = checkNetlog(netlogText, `${kitInfo.host}:${kitInfo.port}`);
      report.netlogOk = netlog.ok;
      report.netlogNames = netlog.names;
      report.netlogUnexpected = netlog.unexpected;
      report.netlogError = netlog.error;
    } catch (error) {
      report.netlogError = error.message;
    }

    captureLeftovers(report);
    report.ok = run.error === null
      && !run.timedOut
      && run.exitCode === 0
      && report.kitReceived
      && report.netlogOk;

    if (run.stdout !== '') process.stdout.write(run.stdout);
    if (run.stderr !== '') process.stderr.write(run.stderr);
  } catch (error) {
    report.error = error.message;
    captureLeftovers(report);
  } finally {
    if (kit !== null) kit.child.kill();
    if (netlogPath !== null) {
      try {
        fs.unlinkSync(netlogPath);
      } catch {
        // The netlog may not have been created.
      }
    }
  }

  fs.writeFileSync(
    path.join(process.cwd(), 'e2e-report.json'),
    `${JSON.stringify(report, null, 2)}\n`,
    'utf8',
  );
  console.log(JSON.stringify(report, null, 2));

  if (!report.ok) process.exitCode = 1;
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  });
}

module.exports = {
  findExecutable,
  listTempMatches,
  listFilesUnder,
  captureLeftovers,
  runApplication,
  main,
};
