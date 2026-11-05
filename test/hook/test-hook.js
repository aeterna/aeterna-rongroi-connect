// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// Test build only.  The release build replaces this file with the stub in
// src/test-hook.js.  Nothing here may be required from a release.

const STATE_TIMEOUT_MS = 60 * 1000;
const POLL_MS = 25;

function sidecarCommand() {
  return {
    file: process.env.CONNECT_TEST_NODE,
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
  const deadline = Date.now() + STATE_TIMEOUT_MS;
  let settled = false;

  const stopWithFailure = (state) => {
    if (settled) return;
    settled = true;
    let line;
    try {
      line = JSON.stringify(state);
    } catch {
      line = '{"name":"error"}';
    }
    process.stdout.write(`${line}\n`, () => {
      if (app && typeof app.exit === 'function') app.exit(20);
    });
  };

  const timer = setTimeout(() => {
    stopWithFailure(flow.state());
  }, STATE_TIMEOUT_MS);

  const waitFor = async (name) => {
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
      clearTimeout(timer);
      try {
        await invoke(() => flow.quit());
      } catch {
        // The report was already accepted; closing must still finish.
      }
      if (app && typeof app.quit === 'function') app.quit();
    } catch {
      clearTimeout(timer);
      stopWithFailure(flow.state());
    }
  })();
}

module.exports = { sidecarCommand, drive };
