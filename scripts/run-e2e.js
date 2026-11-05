// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Drive the test build through the whole flow against the mock Server Kit and
// the mock sidecar, then check Chromium's netlog and write e2e-report.json.
// Negative-control runs write e2e-negative-report.json instead.
//   node scripts/run-e2e.js <testBuildDir> [--negative-control]
//   node scripts/run-e2e.js --release-smoke <releaseDir>

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { checkNetlog, DEFAULT_REQUIRED_PATHS, KNOWN_IPV6_CHECK } = require('./check-netlog');
const { parsePairingCode } = require('../src/core/pairing');

const ROOT = path.resolve(__dirname, '..');
const TEMP_PREFIX = 'rongroi-connect-';
const APP_LIMIT_MS = 120 * 1000;
const RELEASE_SMOKE_MS = 8 * 1000;
const REQUIRED_PATHS = [...DEFAULT_REQUIRED_PATHS];
const LEFTOVER_MAX_BYTES = 1024 * 1024;
const NEGATIVE_IPV6_CHECK = '[2001:4860:4860::8888]:444';
const NEGATIVE_HOST = '127.0.0.2';
const LEFTOVER_FAILURE_KINDS = new Set([
  'ticket',
  'nonce',
  'kitPublicKey',
  'kit_public_key',
  'publicKey',
  'public_key',
  'key',
]);

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

function searchLeftoversDetailed(entries, values) {
  const rawRoots = entries === undefined || entries === null
    ? []
    : (Array.isArray(entries) ? entries : [entries]);
  const roots = rawRoots.map((entry) => (
    entry !== null && typeof entry === 'object' && typeof entry.path === 'string'
      ? entry.path
      : entry
  ));

  const items = [];
  if (Array.isArray(values)) {
    for (const value of values) {
      if (Array.isArray(value) && value.length >= 2) {
        if (typeof value[0] === 'string' && typeof value[1] === 'string') {
          items.push([value[0], value[1]]);
        }
      } else if (typeof value === 'string') {
        items.push([value, value]);
      } else if (value !== null && typeof value === 'object') {
        const what = value.what ?? value.name ?? value.kind ?? value.label;
        const text = value.text ?? value.value ?? value.needle ?? value.secret;
        if (what !== undefined && typeof text === 'string') items.push([String(what), text]);
      }
    }
  } else if (values instanceof Map) {
    for (const [what, text] of values) {
      if (typeof text === 'string') items.push([String(what), text]);
    }
  } else if (values !== null && typeof values === 'object') {
    for (const [what, text] of Object.entries(values)) {
      if (typeof text === 'string') items.push([what, text]);
    }
  }

  const needles = [];
  for (const [what, text] of items) {
    if (text === '') continue;
    needles.push({
      what,
      utf8: Buffer.from(text, 'utf8'),
      utf16le: Buffer.from(text, 'utf16le'),
    });
  }

  const result = { hits: [], notSearched: [], searchRan: false };
  if (needles.length === 0) return result;
  result.searchRan = true;

  for (const file of listFilesUnder(roots)) {
    if (file.size > LEFTOVER_MAX_BYTES) {
      result.notSearched.push({ path: file.path, reason: 'too-large' });
      continue;
    }

    let bytes;
    try {
      bytes = fs.readFileSync(file.path);
    } catch {
      result.notSearched.push({ path: file.path, reason: 'unreadable' });
      continue;
    }

    for (const needle of needles) {
      if (bytes.includes(needle.utf8) || bytes.includes(needle.utf16le)) {
        result.hits.push({ file: file.path, what: needle.what });
      }
    }
  }
  return result;
}

function searchLeftovers(entries, values, options) {
  const result = searchLeftoversDetailed(entries, values);
  if (options !== null && typeof options === 'object') {
    options.searchRan = result.searchRan;
    if (Array.isArray(options.notSearched)) {
      options.notSearched.push(...result.notSearched);
    } else {
      options.notSearched = result.notSearched;
    }
  }
  return result.hits;
}

const findLeftoverHits = searchLeftovers;
const scanLeftovers = searchLeftovers;
const scanLeftoverFiles = searchLeftovers;
const searchLeftoverFiles = searchLeftovers;

function negativeControlMutations(text) {
  const source = typeof text === 'string' ? text : String(text ?? '');
  return {
    ipv6: source.split(KNOWN_IPV6_CHECK).join(NEGATIVE_IPV6_CHECK),
    host: source.split('127.0.0.1').join(NEGATIVE_HOST),
  };
}

const mutateNegativeControlNetlog = negativeControlMutations;

function reportFileNames(negativeControl) {
  return negativeControl
    ? { report: 'e2e-negative-report.json', netlog: 'e2e-negative-netlog.json' }
    : { report: 'e2e-report.json', netlog: 'e2e-netlog.json' };
}

function leftoverFailure(hits) {
  return hits.some((hit) => LEFTOVER_FAILURE_KINDS.has(hit.what));
}

const hasLeftoverFailure = leftoverFailure;

function captureLeftovers(report, values) {
  report.tempAfter = listTempMatches();
  report.leftoverFiles = listFilesUnder(report.tempAfter);
  const leftovers = searchLeftoversDetailed(report.tempAfter, values ?? {});
  report.leftoverHits = leftovers.hits;
  report.leftoverNotSearched = leftovers.notSearched;
  report.leftoverSearchRan = leftovers.searchRan;
}

function runSucceeded(run, report) {
  return run.error === null
    && !run.timedOut
    && run.exitCode === 0
    && report.kitReceived
    && report.netlogOk
    && !report.netlogRepaired
    && report.leftoverSearchRan
    && report.negativeControlOk
    && !leftoverFailure(report.leftoverHits);
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

// Start the release executable with no test code.  A build whose embedded
// asar-integrity resource is wrong exits by itself almost immediately; the
// smoke run passes only when it is still alive after eight seconds.
function releaseSmoke(executable, runForMs = RELEASE_SMOKE_MS) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    delete env.CONNECT_TEST_CODE;
    delete env.CONNECT_TEST_NODE;
    delete env.CONNECT_TEST_SIDECAR;
    delete env.NODE_TEST_CONTEXT;

    let child;
    try {
      child = spawn(executable, [], {
        env,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      resolve({
        ok: false,
        exitedEarly: false,
        seconds: 0,
        exitCode: null,
        signal: null,
        stdout: '',
        stderr: '',
        error: error.message,
      });
      return;
    }

    const started = Date.now();
    let stdout = '';
    let stderr = '';
    let settled = false;

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, ...result });
    };

    const timer = setTimeout(() => {
      if (settled) return;
      child.kill();
      finish({
        ok: true,
        exitedEarly: false,
        seconds: (Date.now() - started) / 1000,
        exitCode: null,
        signal: null,
        error: null,
      });
    }, runForMs);
    if (typeof timer.unref === 'function') timer.unref();

    child.on('error', (error) => {
      finish({
        ok: false,
        exitedEarly: false,
        seconds: (Date.now() - started) / 1000,
        exitCode: null,
        signal: null,
        error: error.message,
      });
    });

    child.on('exit', (code, signal) => {
      finish({
        ok: false,
        exitedEarly: true,
        seconds: (Date.now() - started) / 1000,
        exitCode: code,
        signal,
        error: `the release exe exited before ${runForMs / 1000} s (${code ?? signal})`,
      });
    });
  });
}

function writeJsonReport(report, file) {
  fs.writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
}

async function main(argv) {
  const smokeEquals = argv.find((value) => value.startsWith('--release-smoke='));
  const smokeIndex = argv.indexOf('--release-smoke');

  if (smokeIndex !== -1 || smokeEquals !== undefined) {
    const releaseArg = smokeEquals !== undefined
      ? smokeEquals.slice('--release-smoke='.length)
      : argv[smokeIndex + 1];
    if (releaseArg === undefined || releaseArg === '' || releaseArg.startsWith('--')) {
      console.error('usage: node scripts/run-e2e.js --release-smoke <releaseDir>');
      process.exitCode = 2;
      return;
    }

    try {
      const executable = findExecutable(releaseArg);
      const smoke = await releaseSmoke(executable);
      const smokeReport = {
        mode: 'release-smoke',
        ok: smoke.ok,
        executable,
        seconds: smoke.seconds,
        exitedEarly: smoke.exitedEarly,
        exitCode: smoke.exitCode,
        signal: smoke.signal,
        error: smoke.error,
      };
      if (smoke.stdout !== '') process.stdout.write(smoke.stdout);
      if (smoke.stderr !== '') process.stderr.write(smoke.stderr);
      console.log(JSON.stringify(smokeReport, null, 2));
      if (!smoke.ok) process.exitCode = 1;
    } catch (error) {
      console.error(error && error.stack ? error.stack : String(error));
      process.exitCode = 1;
    }
    return;
  }

  const negativeControl = argv.includes('--negative-control');
  const buildArg = argv.find(
    (value) => value !== '--' && value !== '--negative-control',
  );
  if (buildArg === undefined || buildArg === '') {
    console.error('usage: node scripts/run-e2e.js <testBuildDir> [--negative-control]');
    console.error('       node scripts/run-e2e.js --release-smoke <releaseDir>');
    process.exitCode = 2;
    return;
  }

  const buildDir = path.resolve(buildArg);
  const reportNames = reportFileNames(negativeControl);
  const reportPath = path.join(process.cwd(), reportNames.report);
  const netlogCopyPath = path.join(process.cwd(), reportNames.netlog);
  const report = {
    mode: negativeControl ? 'e2e-negative-control' : 'e2e',
    ok: false,
    exitCode: null,
    signal: null,
    seconds: 0,
    timedOut: false,
    kitReceived: false,
    kitVisualHash: null,
    netlogOk: false,
    netlogRepaired: false,
    netlogNames: [],
    acceptedIpv6Check: { sources: 0, connected: false },
    netlogUnexpected: [],
    netlogUnexpectedDetails: [],
    netlogUnexpectedByName: {},
    netlogUnexpectedByteTransfer: false,
    netlogByteTransfer: false,
    netlogRequestUrls: [],
    netlogRequiredPaths: [...REQUIRED_PATHS],
    netlogMissingPaths: [],
    netlogError: null,
    netlogCopied: false,
    netlogCopyError: null,
    negativeControl: null,
    negativeControlIpv6: null,
    negativeControlHost: null,
    negativeControlOk: !negativeControl,
    tempBefore: listTempMatches(),
    tempAfter: [],
    leftoverFiles: [],
    leftoverHits: [],
    leftoverNotSearched: [],
    leftoverSearchRan: false,
    error: null,
  };

  let kit = null;
  let netlogPath = null;
  let leftoverValues = {};

  try {
    const executable = findExecutable(buildDir);
    kit = startKit();
    const kitInfo = await withTimeout(kit.info, 10 * 1000, 'the mock kit did not print its code');

    try {
      const parsed = parsePairingCode(kitInfo.code);
      leftoverValues = {
        ticket: parsed.ticket,
        nonce: parsed.nonce,
        kitPublicKey: parsed.kitPublicKey,
        origin: `${kitInfo.host}:${kitInfo.port}`,
      };
    } catch {
      // The netlog and kit checks below still report the run's real outcome.
    }

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

    if (fs.existsSync(netlogPath)) {
      try {
        fs.copyFileSync(netlogPath, netlogCopyPath);
        report.netlogCopied = true;
      } catch (error) {
        report.netlogCopyError = error.message;
      }
    }

    try {
      const netlogText = fs.readFileSync(netlogPath, 'utf8');
      const pairedHost = `${kitInfo.host}:${kitInfo.port}`;
      const netlog = checkNetlog(
        netlogText,
        pairedHost,
        REQUIRED_PATHS,
      );
      report.netlogOk = netlog.ok;
      report.netlogRepaired = netlog.repaired === true;
      report.netlogNames = netlog.names;
      report.acceptedIpv6Check = netlog.acceptedIpv6Check;
      report.netlogUnexpected = netlog.unexpected;
      report.netlogUnexpectedDetails = netlog.unexpectedDetails;
      report.netlogUnexpectedByName = netlog.unexpectedByName;
      report.netlogUnexpectedByteTransfer = netlog.unexpectedByteTransfer;
      report.netlogByteTransfer = netlog.byteTransfer;
      report.netlogRequestUrls = netlog.requestUrls;
      report.netlogRequiredPaths = netlog.requiredPaths;
      report.netlogMissingPaths = netlog.missingPaths;
      report.netlogError = netlog.error;

      if (negativeControl) {
        const wrongPort = kitInfo.port === 65535 ? kitInfo.port - 1 : kitInfo.port + 1;
        const mutations = negativeControlMutations(netlogText);
        const summarize = (check) => ({
          allowedHostPort: check.allowedHostPort,
          ok: check.ok,
          unexpected: check.unexpected,
          missingPaths: check.missingPaths,
          error: check.error,
        });
        const negative = checkNetlog(
          netlogText,
          `${kitInfo.host}:${wrongPort}`,
          REQUIRED_PATHS,
        );
        const negativeIpv6 = checkNetlog(
          mutations.ipv6,
          pairedHost,
          REQUIRED_PATHS,
        );
        const negativeHost = checkNetlog(
          mutations.host,
          pairedHost,
          REQUIRED_PATHS,
        );
        report.negativeControl = summarize(negative);
        report.negativeControlIpv6 = summarize(negativeIpv6);
        report.negativeControlHost = summarize(negativeHost);
        // A checker that cannot see the port, the probe address or the paired
        // host would wrongly pass one of these mutations, so the job fails.
        report.negativeControlOk = negative.ok === false
          && negativeIpv6.ok === false
          && negativeHost.ok === false;
      }
    } catch (error) {
      report.netlogError = error.message;
    }

    captureLeftovers(report, leftoverValues);
    report.ok = runSucceeded(run, report);

    if (run.stdout !== '') process.stdout.write(run.stdout);
    if (run.stderr !== '') process.stderr.write(run.stderr);
  } catch (error) {
    report.error = error.message;
    captureLeftovers(report, leftoverValues);
  } finally {
    if (kit !== null) kit.child.kill();
    if (netlogPath !== null) {
      try {
        if (!report.netlogCopied && fs.existsSync(netlogPath)) {
          fs.copyFileSync(netlogPath, netlogCopyPath);
          report.netlogCopied = true;
          report.netlogCopyError = null;
        }
      } catch (error) {
        report.netlogCopyError = error.message;
      }
      try {
        fs.unlinkSync(netlogPath);
      } catch {
        // The netlog may not have been created.
      }
    }
  }

  if (!report.netlogCopied) {
    report.ok = false;
    if (report.netlogCopyError === null) {
      report.netlogCopyError = `the netlog was not available to copy to ${reportNames.netlog}`;
    }
  }

  writeJsonReport(report, reportPath);
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
  LEFTOVER_MAX_BYTES,
  findExecutable,
  listTempMatches,
  listFilesUnder,
  searchLeftovers,
  searchLeftoversDetailed,
  findLeftoverHits,
  scanLeftovers,
  scanLeftoverFiles,
  searchLeftoverFiles,
  negativeControlMutations,
  mutateNegativeControlNetlog,
  reportFileNames,
  leftoverFailure,
  hasLeftoverFailure,
  captureLeftovers,
  runSucceeded,
  runApplication,
  releaseSmoke,
  main,
};
