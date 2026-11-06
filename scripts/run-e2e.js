// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Drive the test build through the whole flow against the mock Server Kit and
// the bundled real sidecar (two runs), then check Chromium's netlog, the
// record's hash and the temp folder, and write e2e-report.json.  --sidecar mock
// keeps the quick mock-sidecar run, and negative-control runs write
// e2e-negative-report.json instead.
//   node scripts/run-e2e.js <testBuildDir> [--sidecar real|mock] [--negative-control]
//   node scripts/run-e2e.js --release-smoke <releaseDir>

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { checkNetlog, DEFAULT_REQUIRED_PATHS, KNOWN_IPV6_CHECK } = require('./check-netlog');
const { parsePairingCode } = require('../src/core/pairing');
const { STANDARD_COLLECTORS } = require('../test/mock/kit');

const ROOT = path.resolve(__dirname, '..');
const TEMP_PREFIX = 'rongroi-connect-';
const SIDECAR_MODES = Object.freeze(['real', 'mock']);
const DEFAULT_SIDECAR_MODE = 'real';
const REAL_RUNS = Object.freeze([
  Object.freeze({
    name: 'posture',
    policy: Object.freeze({
      profile: 'posture',
      required_collectors: Object.freeze(['posture', 'os_image']),
      require_elevation: false,
    }),
  }),
  Object.freeze({
    name: 'standard',
    policy: Object.freeze({
      profile: 'standard',
      required_collectors: STANDARD_COLLECTORS,
      require_elevation: true,
    }),
  }),
]);
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

// The Kit child can only serve the run's policy if the parent hands it over in
// the environment, and it must never inherit an unrelated policy from us.
function kitEnvironment(options = {}) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  delete env.RONGROI_MOCK_KIT_POLICY;

  const policy = options !== null && typeof options === 'object'
    ? options.policy
    : undefined;
  if (policy !== undefined && policy !== null) {
    env.RONGROI_MOCK_KIT_POLICY = JSON.stringify(policy);
  }
  return env;
}

function startKit(options = {}) {
  const kitPath = path.join(ROOT, 'test', 'mock', 'kit.js');
  const env = kitEnvironment(options);

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
  let recordVisualHash = null;
  let recordBytes = null;
  let rongroiVersion = null;
  let recordKind = null;
  let officialBuild = null;
  let policyProfile = null;
  let policyRequireElevation = null;
  let policyCollectorCount = null;
  let scanSeconds = null;
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
      recordVisualHash = typeof message.record_visual_hash === 'string'
        ? message.record_visual_hash
        : null;
      recordBytes = Number.isInteger(message.record_bytes) ? message.record_bytes : null;
      rongroiVersion = typeof message.rongroi_version === 'string'
        ? message.rongroi_version
        : null;
      recordKind = typeof message.kind === 'string' ? message.kind : null;
      officialBuild = typeof message.official_build === 'boolean'
        ? message.official_build
        : null;
      policyProfile = typeof message.policy_profile === 'string'
        ? message.policy_profile
        : null;
      policyRequireElevation = typeof message.policy_require_elevation === 'boolean'
        ? message.policy_require_elevation
        : null;
      policyCollectorCount = Number.isInteger(message.policy_collector_count)
        ? message.policy_collector_count
        : null;
      scanSeconds = typeof message.scan_seconds === 'number' ? message.scan_seconds : null;
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
    get recordVisualHash() {
      return recordVisualHash;
    },
    get recordBytes() {
      return recordBytes;
    },
    get rongroiVersion() {
      return rongroiVersion;
    },
    get recordKind() {
      return recordKind;
    },
    get officialBuild() {
      return officialBuild;
    },
    get policyProfile() {
      return policyProfile;
    },
    get policyRequireElevation() {
      return policyRequireElevation;
    },
    get policyCollectorCount() {
      return policyCollectorCount;
    },
    get scanSeconds() {
      return scanSeconds;
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

function listTempTopLevel(directory = os.tmpdir()) {
  return fs.readdirSync(directory)
    .map((name) => path.join(directory, name))
    .sort();
}

function tempEntryPath(entry) {
  if (entry !== null && typeof entry === 'object' && typeof entry.path === 'string') {
    return path.resolve(entry.path);
  }
  return path.resolve(String(entry));
}

function newTempEntries(before, after, exclude) {
  const existing = new Set((before ?? []).map(tempEntryPath));
  const ignored = new Set((exclude ?? []).map(tempEntryPath));
  return (after ?? [])
    .map(tempEntryPath)
    .filter((entry) => !existing.has(entry) && !ignored.has(entry))
    .sort();
}

function captureNewTempEntries(report, before, values, exclude) {
  report.tempEntriesBefore = [...(before ?? [])];
  report.tempEntriesAfter = listTempTopLevel();
  report.newTempEntries = newTempEntries(
    report.tempEntriesBefore,
    report.tempEntriesAfter,
    exclude,
  );
  report.newTempFiles = listFilesUnder(report.newTempEntries);
  const found = searchLeftoversDetailed(report.newTempEntries, values ?? {});
  report.newTempHits = found.hits;
  report.newTempNotSearched = found.notSearched;
  report.newTempSearchRan = found.searchRan;
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

const USAGE = [
  'usage: node scripts/run-e2e.js <testBuildDir> [--sidecar real|mock] [--negative-control]',
  '       node scripts/run-e2e.js --release-smoke <releaseDir>',
].join('\n');

function argumentError(message, state) {
  return {
    error: `${message}\n${USAGE}`,
    releaseSmoke: null,
    buildDir: null,
    negativeControl: state.negativeControl,
    sidecar: state.sidecar,
    sidecarMode: state.sidecar,
  };
}

function parseArguments(argv) {
  const args = Array.isArray(argv) ? argv : [];
  const state = { negativeControl: false, sidecar: DEFAULT_SIDECAR_MODE };
  const positional = [];
  let releaseSmoke = null;

  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];

    if (value === '--') continue;
    if (value === '--negative-control') {
      state.negativeControl = true;
      continue;
    }

    if (value === '--sidecar') {
      const mode = args[index + 1];
      if (typeof mode !== 'string' || !SIDECAR_MODES.includes(mode)) {
        return argumentError('--sidecar must be real or mock', state);
      }
      state.sidecar = mode;
      index += 1;
      continue;
    }

    if (value.startsWith('--sidecar=')) {
      const mode = value.slice('--sidecar='.length);
      if (!SIDECAR_MODES.includes(mode)) {
        return argumentError('--sidecar must be real or mock', state);
      }
      state.sidecar = mode;
      continue;
    }

    if (value === '--release-smoke') {
      const directory = args[index + 1];
      if (typeof directory !== 'string' || directory === '' || directory.startsWith('--')) {
        return argumentError('--release-smoke needs a release folder', state);
      }
      releaseSmoke = directory;
      index += 1;
      continue;
    }

    if (value.startsWith('--release-smoke=')) {
      const directory = value.slice('--release-smoke='.length);
      if (directory === '') {
        return argumentError('--release-smoke needs a release folder', state);
      }
      releaseSmoke = directory;
      continue;
    }

    if (!value.startsWith('--')) positional.push(value);
  }

  if (releaseSmoke !== null) {
    return {
      error: null,
      releaseSmoke,
      buildDir: null,
      negativeControl: state.negativeControl,
      sidecar: state.sidecar,
      sidecarMode: state.sidecar,
    };
  }

  if (positional.length === 0) {
    return argumentError('a test build folder is required', state);
  }

  return {
    error: null,
    releaseSmoke: null,
    buildDir: positional[0],
    negativeControl: state.negativeControl,
    sidecar: state.sidecar,
    sidecarMode: state.sidecar,
  };
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

function isRealRunReport(report) {
  if (report.sidecar === 'real' || report.sidecarMode === 'real') return true;
  if (report.sidecar === 'mock' || report.sidecarMode === 'mock') return false;
  // Older reports carry no mode, so the run name decides.  A mock run is
  // named 'mock' and never matches either real spec.
  return report.name === 'posture' || report.name === 'standard';
}

function realRunReportSucceeded(report) {
  return report.recordKind === 'rongroi-saved-report'
    && typeof report.rongroi_version === 'string'
    && report.rongroi_version !== ''
    && report.rongroi_version !== 'mock'
    && typeof report.profile === 'string'
    && report.profile !== ''
    && typeof report.requireElevation === 'boolean'
    && Number.isInteger(report.collectorCount)
    && report.policyProfile === report.profile
    && report.policyRequireElevation === report.requireElevation
    && report.policyCollectorCount === report.collectorCount;
}

function runSucceeded(run, report) {
  const ok = run.error === null
    && !run.timedOut
    && run.exitCode === 0
    && report.kitReceived
    && report.kitHashEqualsRecord === true
    && report.netlogOk
    && !report.netlogRepaired
    && report.leftoverSearchRan
    && report.newTempSearchRan
    && report.negativeControlOk
    && !leftoverFailure(report.leftoverHits)
    && !leftoverFailure(report.newTempHits);
  if (!ok) return false;
  return isRealRunReport(report) ? realRunReportSucceeded(report) : true;
}

function runSpecs(sidecarMode, negativeControl) {
  if (negativeControl) {
    if (sidecarMode === 'real') return [REAL_RUNS[0]];
    return [{ name: 'mock', policy: null }];
  }
  if (sidecarMode === 'real') return REAL_RUNS;
  return [{ name: 'mock', policy: null }];
}

function runNetlogCopyPath(baseName, index, total, name) {
  if (total <= 1 || index === total - 1) return baseName;
  return baseName.replace(/\.json$/, `-${name}.json`);
}

function applicationEnv(kitInfo, sidecarMode) {
  const env = {
    ...process.env,
    CONNECT_TEST_CODE: kitInfo.code,
  };
  delete env.NODE_TEST_CONTEXT;

  if (sidecarMode === 'mock') {
    env.CONNECT_TEST_NODE = process.execPath;
    env.CONNECT_TEST_SIDECAR = path.join(ROOT, 'test', 'mock', 'sidecar.js');
  } else {
    // Real mode uses the bundled resources/rongroi-scan.exe, so the test hook
    // must see no override at all.  The hash and image checks stay active.
    delete env.CONNECT_TEST_NODE;
    delete env.CONNECT_TEST_SIDECAR;
  }
  return env;
}

function createRunReport(name, policy, negativeControl, sidecarMode) {
  return {
    name,
    sidecar: sidecarMode,
    profile: policy === null ? null : policy.profile,
    requireElevation: policy === null ? false : policy.require_elevation === true,
    collectorCount: policy === null || !Array.isArray(policy.required_collectors)
      ? null
      : policy.required_collectors.length,
    ok: false,
    done: false,
    error: null,
    exitCode: null,
    signal: null,
    timedOut: false,
    seconds: 0,
    kitReceived: false,
    kitVisualHash: null,
    recordVisualHash: null,
    kitHashEqualsRecord: false,
    recordBytes: null,
    scanSeconds: null,
    rongroi_version: null,
    recordKind: null,
    officialBuild: null,
    policyProfile: null,
    policyRequireElevation: null,
    policyCollectorCount: null,
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
    netlogCopyPath: null,
    netlogCopyError: null,
    netlogPath: null,
    negativeControl: null,
    negativeControlIpv6: null,
    negativeControlHost: null,
    negativeControlOk: !negativeControl,
    leftoverSearchRan: false,
    newTempSearchRan: false,
    leftoverHits: [],
    newTempHits: [],
  };
}

function applyNetlogReport(target, netlog) {
  target.netlogOk = netlog.ok;
  target.netlogRepaired = netlog.repaired === true;
  target.netlogNames = netlog.names;
  target.acceptedIpv6Check = netlog.acceptedIpv6Check;
  target.netlogUnexpected = netlog.unexpected;
  target.netlogUnexpectedDetails = netlog.unexpectedDetails;
  target.netlogUnexpectedByName = netlog.unexpectedByName;
  target.netlogUnexpectedByteTransfer = netlog.unexpectedByteTransfer;
  target.netlogByteTransfer = netlog.byteTransfer;
  target.netlogRequestUrls = netlog.requestUrls;
  target.netlogRequiredPaths = netlog.requiredPaths;
  target.netlogMissingPaths = netlog.missingPaths;
  target.netlogError = netlog.error;
}

function applyNegativeControl(target, netlogText, kitInfo, pairedHost) {
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
  target.negativeControl = summarize(negative);
  target.negativeControlIpv6 = summarize(negativeIpv6);
  target.negativeControlHost = summarize(negativeHost);
  // A checker that cannot see the port, the probe address or the paired host
  // would wrongly pass one of these mutations, so the job fails.
  target.negativeControlOk = negative.ok === false
    && negativeIpv6.ok === false
    && negativeHost.ok === false;
}

function mergeLeftoverValues(list) {
  const pairs = [];
  const seen = new Set();
  for (const values of list) {
    if (values === null || typeof values !== 'object') continue;
    for (const [what, text] of Object.entries(values)) {
      if (typeof text !== 'string' || text === '') continue;
      const key = `${what}\u0000${text}`;
      if (seen.has(key)) continue;
      seen.add(key);
      pairs.push([what, text]);
    }
  }
  return pairs;
}

async function runOnce(options) {
  const {
    executable,
    spec,
    sidecarMode,
    negativeControl,
    netlogCopyPath,
  } = options;
  const runReport = createRunReport(spec.name, spec.policy, negativeControl, sidecarMode);
  let kit = null;
  let netlogPath = null;
  let leftoverValues = {};
  const started = Date.now();

  try {
    kit = startKit(spec.policy === null ? undefined : { policy: spec.policy });
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
      `rongroi-e2e-netlog-${spec.name}-${process.pid}-${Date.now()}.json`,
    );
    runReport.netlogPath = netlogPath;

    const run = await runApplication(
      executable,
      [`--log-net-log=${netlogPath}`],
      applicationEnv(kitInfo, sidecarMode),
    );
    runReport.seconds = (Date.now() - started) / 1000;
    runReport.exitCode = run.exitCode;
    runReport.signal = run.signal;
    runReport.timedOut = run.timedOut;
    runReport.error = run.error === null ? null : run.error.message;

    if (!run.error && !run.timedOut && run.exitCode === 0 && !kit.received) {
      try {
        await withTimeout(kit.receivedPromise, 5 * 1000, 'the mock kit did not report received');
      } catch {
        // The report below says received: false and fails.
      }
    }
    runReport.kitReceived = kit.received;
    runReport.kitVisualHash = kit.visualHash;
    runReport.recordVisualHash = kit.recordVisualHash;
    runReport.kitHashEqualsRecord = typeof kit.visualHash === 'string'
      && typeof kit.recordVisualHash === 'string'
      && kit.visualHash === kit.recordVisualHash;
    runReport.recordBytes = kit.recordBytes;
    runReport.scanSeconds = kit.scanSeconds;
    runReport.rongroi_version = kit.rongroiVersion;
    runReport.recordKind = kit.recordKind;
    runReport.officialBuild = kit.officialBuild;
    runReport.policyProfile = kit.policyProfile;
    runReport.policyRequireElevation = kit.policyRequireElevation;
    runReport.policyCollectorCount = kit.policyCollectorCount;
    runReport.done = runReport.kitReceived
      && runReport.error === null
      && !runReport.timedOut
      && runReport.exitCode === 0;

    runReport.netlogCopyPath = netlogCopyPath;
    if (fs.existsSync(netlogPath)) {
      try {
        fs.copyFileSync(netlogPath, netlogCopyPath);
        runReport.netlogCopied = true;
      } catch (error) {
        runReport.netlogCopyError = error.message;
      }
    }

    try {
      const netlogText = fs.readFileSync(netlogPath, 'utf8');
      const pairedHost = `${kitInfo.host}:${kitInfo.port}`;
      applyNetlogReport(runReport, checkNetlog(netlogText, pairedHost, REQUIRED_PATHS));
      if (negativeControl) {
        applyNegativeControl(runReport, netlogText, kitInfo, pairedHost);
      }
    } catch (error) {
      runReport.netlogError = error.message;
    }

    if (run.stdout !== '') process.stdout.write(run.stdout);
    if (run.stderr !== '') process.stderr.write(run.stderr);
  } catch (error) {
    runReport.error = error.message;
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

  return { report: runReport, leftoverValues };
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

function firstMessage(runs, key) {
  for (const run of runs) {
    const value = run[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  return null;
}

async function main(argv) {
  const parsedArgs = parseArguments(argv);
  if (parsedArgs.error !== null) {
    console.error(parsedArgs.error);
    process.exitCode = 2;
    return;
  }

  if (parsedArgs.releaseSmoke !== null) {
    try {
      const executable = findExecutable(parsedArgs.releaseSmoke);
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

  const buildDir = path.resolve(parsedArgs.buildDir);
  const negativeControl = parsedArgs.negativeControl;
  const sidecarMode = parsedArgs.sidecar;
  const reportNames = reportFileNames(negativeControl);
  const reportPath = path.join(process.cwd(), reportNames.report);
  const tempEntriesBefore = listTempTopLevel();
  const report = {
    mode: negativeControl ? 'e2e-negative-control' : 'e2e',
    sidecar: sidecarMode,
    ok: false,
    runs: [],
    done: false,
    exitCode: null,
    signal: null,
    seconds: 0,
    timedOut: false,
    kitReceived: false,
    kitVisualHash: null,
    recordVisualHash: null,
    kitHashEqualsRecord: false,
    recordBytes: null,
    scanSeconds: null,
    rongroi_version: null,
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
    tempEntriesBefore,
    tempEntriesAfter: [],
    newTempEntries: [],
    newTempFiles: [],
    newTempHits: [],
    newTempNotSearched: [],
    newTempSearchRan: false,
    leftoverFiles: [],
    leftoverHits: [],
    leftoverNotSearched: [],
    leftoverSearchRan: false,
    error: null,
  };

  const runs = [];
  const valuesList = [];
  const netlogPaths = [];
  const startedAll = Date.now();

  try {
    const executable = findExecutable(buildDir);
    const specs = runSpecs(sidecarMode, negativeControl);

    for (let index = 0; index < specs.length; index += 1) {
      const spec = specs[index];
      const result = await runOnce({
        executable,
        spec,
        sidecarMode,
        negativeControl,
        netlogCopyPath: runNetlogCopyPath(
          reportNames.netlog,
          index,
          specs.length,
          spec.name,
        ),
      });
      runs.push(result.report);
      valuesList.push(result.leftoverValues);
      if (typeof result.report.netlogPath === 'string') {
        netlogPaths.push(result.report.netlogPath);
      }
    }
  } catch (error) {
    report.error = error.message;
  }

  report.runs = runs;
  report.seconds = (Date.now() - startedAll) / 1000;

  const leftoverValues = mergeLeftoverValues(valuesList);
  captureLeftovers(report, leftoverValues);
  captureNewTempEntries(report, tempEntriesBefore, leftoverValues, netlogPaths);

  const search = {
    leftoverSearchRan: report.leftoverSearchRan,
    newTempSearchRan: report.newTempSearchRan,
    leftoverHits: report.leftoverHits,
    newTempHits: report.newTempHits,
  };
  for (const run of runs) {
    Object.assign(run, search);
    run.ok = runSucceeded(run, run);
  }

  const last = runs.length === 0 ? null : runs[runs.length - 1];
  report.done = runs.length > 0 && runs.every((run) => run.done === true);
  report.exitCode = last === null ? null : last.exitCode;
  report.signal = last === null ? null : last.signal;
  report.timedOut = runs.some((run) => run.timedOut);
  report.kitReceived = runs.length > 0 && runs.every((run) => run.kitReceived);
  report.kitVisualHash = last === null ? null : last.kitVisualHash;
  report.recordVisualHash = last === null ? null : last.recordVisualHash;
  report.kitHashEqualsRecord = runs.length > 0
    && runs.every((run) => run.kitHashEqualsRecord === true);
  report.recordBytes = last === null ? null : last.recordBytes;
  report.scanSeconds = last === null ? null : last.scanSeconds;
  report.rongroi_version = last === null ? null : last.rongroi_version;
  report.netlogOk = runs.length > 0 && runs.every((run) => run.netlogOk);
  report.netlogRepaired = runs.some((run) => run.netlogRepaired);
  report.netlogNames = [...new Set(runs.flatMap((run) => run.netlogNames ?? []))];
  report.acceptedIpv6Check = last === null
    ? { sources: 0, connected: false }
    : last.acceptedIpv6Check;
  report.netlogUnexpected = last === null ? [] : last.netlogUnexpected;
  report.netlogUnexpectedDetails = last === null ? [] : last.netlogUnexpectedDetails;
  report.netlogUnexpectedByName = last === null ? {} : last.netlogUnexpectedByName;
  report.netlogUnexpectedByteTransfer = runs.some(
    (run) => run.netlogUnexpectedByteTransfer,
  );
  report.netlogByteTransfer = runs.some((run) => run.netlogByteTransfer);
  report.netlogRequestUrls = last === null ? [] : last.netlogRequestUrls;
  report.netlogMissingPaths = [...new Set(
    runs.flatMap((run) => run.netlogMissingPaths ?? []),
  )];
  report.netlogError = firstMessage(runs, 'netlogError')
    ?? (report.error === null ? null : report.error);
  report.netlogCopied = runs.length > 0 && runs.every((run) => run.netlogCopied === true);
  report.netlogCopyError = firstMessage(runs, 'netlogCopyError');
  report.negativeControl = last === null ? null : last.negativeControl;
  report.negativeControlIpv6 = last === null ? null : last.negativeControlIpv6;
  report.negativeControlHost = last === null ? null : last.negativeControlHost;
  report.negativeControlOk = runs.length > 0
    ? runs.every((run) => run.negativeControlOk === true)
    : !negativeControl;
  report.error = firstMessage(runs, 'error') ?? report.error;
  report.ok = runs.length > 0 && runs.every((run) => run.ok === true);

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
  listTempTopLevel,
  newTempEntries,
  listNewTempEntries: newTempEntries,
  diffTempEntries: newTempEntries,
  diffNewTempEntries: newTempEntries,
  tempEntryPath,
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
  parseArguments,
  parseArgs: parseArguments,
  leftoverFailure,
  hasLeftoverFailure,
  captureLeftovers,
  captureNewTempEntries,
  runSucceeded,
  runSpecs,
  kitEnvironment,
  runApplication,
  releaseSmoke,
  main,
};
