// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const {
  WEB_PREFERENCES,
  applySwitches,
  lockSession,
  lockContents,
} = require('./quarantine');
const {
  createTempUserData,
  removeTempUserData,
  sweepStale,
} = require('./userdata');
const { parsePairingCode } = require('../core/pairing');
const { sealEnvelope } = require('../core/envelope');
const PairedClient = require('./net');
const testHook = require('../test-hook');
const { createFlow } = require('./flow');
const { createSidecarRunner } = require('./sidecar');
const { createSidecarVerifier } = require('./verify-sidecar');

let userDataDirectory = null;
let flow = null;
let ticker = null;
let finishStarted = false;
let inBeforeQuit = false;
let tempRemoved = false;
let desiredExitCode = null;

// Every exit path asks here for its final code.  Without an explicit code the
// flow decides, so an earlier error survives a later Quit.  The folder itself
// is removed once, in `will-quit`, because `app.exit()` skips that event.
function finish(code) {
  if (finishStarted) return;
  finishStarted = true;

  if (ticker !== null) {
    clearInterval(ticker);
    ticker = null;
  }

  let finalCode = code;
  if (typeof finalCode !== 'number') {
    finalCode = 11;
    if (flow !== null && typeof flow.quit === 'function') {
      try {
        const result = flow.quit();
        if (typeof result === 'number') {
          finalCode = result;
        } else if (typeof flow.exitCode === 'function') {
          const earlier = flow.exitCode();
          if (typeof earlier === 'number') finalCode = earlier;
        }
      } catch {
        finalCode = 10;
      }
    }
  }

  desiredExitCode = finalCode;
  // When Electron is already in `before-quit`, let that quit continue; asking
  // again from inside the event would re-enter it.
  if (!inBeforeQuit) app.quit();
}

process.on('uncaughtException', () => {
  // Before ready, app.quit() cannot run the normal quit path. This covers a
  // failure at load time, such as createTempUserData throwing.
  if (typeof app.isReady === 'function' && app.isReady()) {
    finish(10);
  } else {
    app.exit(10);
  }
});

// ADR 0001 sections 2 and 3: the temporary userData comes first, then the
// stale sweep, then the Chromium switches and the sandbox, all before ready.
userDataDirectory = createTempUserData(app);
sweepStale();
applySwitches(app);

app.on('before-quit', () => {
  inBeforeQuit = true;
  try {
    finish();
  } finally {
    inBeforeQuit = false;
  }
});

app.on('will-quit', () => {
  if (tempRemoved) return;
  tempRemoved = true;
  if (typeof userDataDirectory === 'string' && userDataDirectory.length > 0) {
    removeTempUserData(userDataDirectory);
  }
  if (typeof desiredExitCode === 'number') app.exit(desiredExitCode);
});

app.on('window-all-closed', () => {
  finish();
});

const PAGE_PATH = path.join(__dirname, '..', 'renderer', 'index.html');
const PAGE_URL = pathToFileURL(PAGE_PATH).href;
const PRELOAD_PATH = path.join(__dirname, '..', 'preload.js');
const SIDECAR_NAME = 'rongroi-scan.exe';

function sidecarCommand() {
  const override = testHook.sidecarCommand;
  if (typeof override === 'function') {
    const answer = override();
    if (answer !== null && typeof answer === 'object'
        && typeof answer.file === 'string' && answer.file.length > 0) {
      return {
        file: answer.file,
        args: Array.isArray(answer.args) ? answer.args.map(String) : [],
      };
    }
  }
  return { file: path.join(process.resourcesPath, SIDECAR_NAME), args: [] };
}

let sidecarRunner = null;

// The runner and the native pipe module are both built on the first scan, not
// at startup, so the window opens on a platform where the module has not been
// built.
function runSidecar(...args) {
  if (sidecarRunner === null) {
    sidecarRunner = createSidecarRunner({
      pipe: require('../../native/pipe'),
      spawn,
      randomBytes: crypto.randomBytes,
      sidecarCommand,
      // ADR 0001 section 4: hash the bundled sidecar before every launch, no
      // matter what test-hook lets sidecarCommand() spawn.  The hash record
      // lives in the asar at src/sidecar.json, written by the build from
      // vendor/rongroi-scan.exe (see sidecar.lock.json).  A mismatch is a
      // SidecarError('sidecar_hash'), which the flow maps to exit 13.
      verifySidecar: createSidecarVerifier({
        file: path.join(process.resourcesPath, SIDECAR_NAME),
        expected: path.join(__dirname, '..', 'sidecar.json'),
        readFile: fs.readFileSync,
        createHash: crypto.createHash,
      }),
      timeouts: { connect: 60000, record: 540000 },
    });
  }
  if (sidecarRunner && typeof sidecarRunner.then === 'function') {
    return sidecarRunner.then((runner) => runner(...args));
  }
  return sidecarRunner(...args);
}

function isOwnPage(url) {
  if (typeof url !== 'string') return false;
  try {
    return new URL(url).href === PAGE_URL;
  } catch {
    return false;
  }
}

function isOwnSender(event) {
  try {
    const frame = event && event.senderFrame;
    return Boolean(frame && typeof frame.url === 'string' && isOwnPage(frame.url));
  } catch {
    return false;
  }
}

async function start() {
  const ses = session.fromPartition('connect');
  const asarPath = app.getAppPath();

  // Only a successful parse reaches makeClient, and makeClient is the one
  // place that publishes the origin to the request gate, before the policy
  // request is constructed.
  let serverOrigin = null;
  const getOrigin = () => serverOrigin;

  lockSession(ses, getOrigin, asarPath);
  lockSession(session.defaultSession, getOrigin, asarPath);
  lockContents(app, isOwnPage);

  const win = new BrowserWindow({
    width: 640,
    height: 720,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    autoHideMenuBar: true,
    webPreferences: {
      ...WEB_PREFERENCES,
      partition: 'connect',
      preload: PRELOAD_PATH,
    },
  });
  if (typeof win.setMenuBarVisibility === 'function') win.setMenuBarVisibility(false);

  const makeClient = (pairing, ticket, expiresAt) => {
    const parsed = pairing && typeof pairing === 'object' ? pairing : {};
    const origin = typeof pairing === 'string'
      ? pairing
      : parsed.serverOrigin ?? parsed.server_origin ?? parsed.origin;
    if (typeof origin !== 'string' || origin.length === 0) {
      throw new TypeError('a pairing result with an origin is required');
    }

    serverOrigin = origin;
    return new PairedClient({
      origin,
      ticket: typeof pairing === 'string' ? ticket : parsed.ticket,
      expiresAt: typeof pairing === 'string'
        ? expiresAt
        : parsed.expiresAt ?? parsed.expires_at,
      fetchImpl: (...a) => ses.fetch(...a),
    });
  };

  const emit = (state) => {
    if (typeof win.isDestroyed === 'function' && win.isDestroyed()) return;
    const contents = win.webContents;
    if (!contents) return;
    if (typeof contents.isDestroyed === 'function' && contents.isDestroyed()) return;
    if (typeof contents.send === 'function') contents.send('connect:state', state);
  };

  flow = createFlow({
    parseCode: parsePairingCode,
    makeClient,
    sealEnvelope,
    runSidecar,
    now: () => Date.now(),
    emit,
    version: app.getVersion(),
  });

  const handle = (channel, run) => {
    ipcMain.handle(channel, async (event, ...args) => {
      if (!isOwnSender(event)) throw new Error('refused');
      return run(...args);
    });
  };

  handle('connect:submitCode', (code) => {
    if (typeof code !== 'string' || code.length > 4096) {
      throw new TypeError('submitCode takes a string of at most 4096 characters');
    }
    return flow.submitCode(code);
  });
  handle('connect:consent', () => flow.consent());
  handle('connect:decline', () => flow.decline());
  handle('connect:send', () => flow.send());
  handle('connect:retry', () => flow.retry());
  handle('connect:quit', () => finish());

  ticker = setInterval(() => flow.tick(), 1000);

  await win.loadFile(PAGE_PATH);

  // The renderer subscribes while loading, so a state emitted during
  // createFlow may have arrived before it was listening.
  const initialState = flow.state();
  if (initialState !== undefined && initialState !== null) emit(initialState);

  if (typeof testHook.drive === 'function') {
    try {
      const result = testHook.drive(flow, { app });
      if (result && typeof result.then === 'function') {
        Promise.resolve(result).catch(() => finish(10));
      }
    } catch {
      finish(10);
    }
  }
}

app.whenReady().then(start).catch(() => {
  finish(10);
});
