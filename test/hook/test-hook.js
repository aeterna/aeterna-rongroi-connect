// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Test build only.  The release build replaces this file with the stub in
// src/test-hook.js.  Nothing here may be required from a release.

const DEFAULT_STATE_TIMEOUT_MS = 60 * 1000;
const POLL_MS = 25;

// A real Standard scan can stay in `scanning` past one minute, so run-e2e
// raises this limit through the environment.  Anything that is not a positive
// integer keeps the old guard instead of disabling it.
function parseStateTimeoutMs(value) {
  if (typeof value !== 'string') return DEFAULT_STATE_TIMEOUT_MS;
  const text = value.trim();
  if (!/^[0-9]+$/.test(text)) return DEFAULT_STATE_TIMEOUT_MS;
  const timeout = Number(text);
  if (!Number.isSafeInteger(timeout) || timeout <= 0) return DEFAULT_STATE_TIMEOUT_MS;
  return timeout;
}

function sidecarCommand() {
  const file = process.env.CONNECT_TEST_NODE;
  // Real-sidecar runs leave CONNECT_TEST_NODE unset; CM then launches the
  // bundled resources/rongroi-scan.exe with its hash and image checks active.
  if (typeof file !== 'string' || file.length === 0) return undefined;
  return {
    file,
    args: [process.env.CONNECT_TEST_SIDECAR],
  };
}

function delay(millis) {
  return new Promise((resolve) => setTimeout(resolve, millis));
}

async function invoke(method) {
  const value = method();
  if (value && typeof value.then === 'function') await value;
}

function drive(flow, options) {
  const app = options && options.app;
  const timeoutMs = parseStateTimeoutMs(process.env.CONNECT_TEST_STATE_TIMEOUT_MS);
  let settled = false;
  let timer = null;
  let watcher = null;
  let lastStateName = null;

  // The proof build leaves exactly as a player's Quit does: the flow chooses
  // the code, then Electron runs its before-quit/will-quit cleanup.
  const end = () => {
    try {
      flow.quit();
    } catch {
      // Closing must still ask the app to quit.
    }
    if (app && typeof app.quit === 'function') app.quit();
  };

  const stopWatching = () => {
    if (watcher === null) return;
    clearInterval(watcher);
    watcher = null;
  };

  const stopTimer = () => {
    if (timer === null) return;
    clearTimeout(timer);
    timer = null;
  };

  const stateLine = (state, extra) => {
    let line;
    try {
      line = JSON.stringify({ ...state, ...extra });
    } catch {
      line = JSON.stringify({ name: 'error', ...extra });
    }
    return `${line}\n`;
  };

  const stopWithFailure = (state) => {
    if (settled) return;
    settled = true;
    stopWatching();
    stopTimer();
    process.stdout.write(
      stateLine(state, { observedAt: Date.now(), failed: true }),
      end,
    );
  };

  const armTimer = () => {
    stopTimer();
    timer = setTimeout(() => {
      timer = null;
      stopWithFailure(flow.state());
    }, timeoutMs);
  };

  // run-e2e measures a real scan from these lines, so print each new state
  // with the time it was seen.  Waiting on consent() alone would hide the
  // whole scanning state, which is entered before the sidecar returns.
  const observe = () => {
    const current = flow.state();
    if (current === null || typeof current !== 'object') return;
    if (current.name === lastStateName) return;
    lastStateName = current.name;
    // Only the name goes on the trace: the full hash state holds the record
    // text, which must not be written to the job log on a successful run.
    process.stdout.write(stateLine({ name: current.name }, { observedAt: Date.now() }));
    armTimer();
  };

  const waitFor = async (name) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const current = flow.state();
      if (current && current.name === name) return current;
      if (current && current.name === 'error') {
        throw new Error('the flow reached an error state');
      }
      if (Date.now() >= deadline) {
        throw new Error('the flow did not move in time');
      }
      await delay(POLL_MS);
    }
  };

  armTimer();
  watcher = setInterval(observe, POLL_MS);
  observe();

  return (async () => {
    try {
      await invoke(() => flow.submitCode(process.env.CONNECT_TEST_CODE));
      await waitFor('consent');
      await invoke(() => flow.consent());
      await waitFor('hash');
      await invoke(() => flow.send());
      await waitFor('done');

      if (settled) return;
      settled = true;
      stopWatching();
      stopTimer();
      end();
    } catch {
      stopWithFailure(flow.state());
    }
  })();
}

module.exports = {
  DEFAULT_STATE_TIMEOUT_MS,
  parseStateTimeoutMs,
  sidecarCommand,
  drive,
};
