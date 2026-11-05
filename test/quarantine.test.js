// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  WEB_PREFERENCES,
  decide,
  applySwitches,
  lockSession,
  lockContents,
} = require('../src/main/quarantine');

const ASAR = '/opt/rongroi/resources/app.asar';
const ORIGIN = 'https://server.example:8443';

test('decide allows only the paired origin and files inside the asar', () => {
  assert.equal(decide(`${ORIGIN}/policy`, ORIGIN, ASAR), true);
  assert.equal(decide(`${ORIGIN}/`, ORIGIN, ASAR), true);
  assert.equal(decide('http://127.0.0.1:8080/policy', 'http://127.0.0.1:8080', ASAR), true);

  assert.equal(decide('file:///opt/rongroi/resources/app.asar/index.html', ORIGIN, ASAR), true);
  assert.equal(decide('file:///opt/rongroi/resources/app.asar/nested/renderer.js', ORIGIN, ASAR), true);
  assert.equal(decide('file:///opt/rongroi/resources/app.asar/index.html', null, ASAR), true);

  assert.equal(decide('file:///opt/rongroi/resources/app.asar.evil/index.html', ORIGIN, ASAR), false);
  assert.equal(decide('file:///opt/rongroi/resources/app.asar/../evil.html', ORIGIN, ASAR), false);
  assert.equal(
    decide('file:///opt/rongroi/resources/app.asar/%2e%2e/%2e%2e/evil.html', ORIGIN, ASAR),
    false,
  );
  assert.equal(decide('file:///opt/rongroi/resources/index.html', ORIGIN, ASAR), false);
  assert.equal(decide('file://host/opt/rongroi/resources/app.asar/index.html', ORIGIN, ASAR), false);
});

test('decide normalises Windows separators and drive-letter case', () => {
  const asar = 'C:\\Rongroi\\resources\\app.asar';
  assert.equal(decide('file:///c:/Rongroi/resources/app.asar/index.html', ORIGIN, asar), true);
  assert.equal(decide('file:///C:/Rongroi/resources/app.asar/nested/x.js', ORIGIN, asar), true);
  assert.equal(decide('file:///C:/Rongroi/resources/app.asar.evil/x.js', ORIGIN, asar), false);
});

test('decide denies foreign origins and every non-network scheme', () => {
  assert.equal(decide('https://server.example:8444/policy', ORIGIN, ASAR), false);
  assert.equal(decide('http://server.example:8443/policy', ORIGIN, ASAR), false);
  assert.equal(decide('https://server.example.evil:8443/policy', ORIGIN, ASAR), false);
  assert.equal(decide('https://server.example:8443.evil/policy', ORIGIN, ASAR), false);
  assert.equal(decide('https://evil.example/policy', ORIGIN, ASAR), false);
  assert.equal(decide('https://a@server.example:8443/policy', ORIGIN, ASAR), false);
  assert.equal(decide('https://user:pass@server.example:8443/policy', ORIGIN, ASAR), false);

  assert.equal(decide('http://server.example:8443/policy', null, ASAR), false);
  assert.equal(decide('https://server.example:8443/policy', undefined, ASAR), false);

  assert.equal(decide('data:text/html,hi', ORIGIN, ASAR), false);
  assert.equal(decide(`blob:${ORIGIN}/abc`, ORIGIN, ASAR), false);
  assert.equal(decide('devtools://devtools/bundled/inspector.html', ORIGIN, ASAR), false);
  assert.equal(decide('chrome://settings', ORIGIN, ASAR), false);
  assert.equal(decide('not a url', ORIGIN, ASAR), false);
  assert.equal(decide('', ORIGIN, ASAR), false);
});

test('applySwitches appends the quarantine switches then enables the sandbox', () => {
  const switches = [];
  let sandboxCalls = 0;
  const app = {
    commandLine: {
      appendSwitch(name) {
        switches.push(name);
      },
    },
    enableSandbox() {
      sandboxCalls += 1;
    },
  };

  applySwitches(app);

  assert.deepEqual(switches, [
    'no-proxy-server',
    'disable-background-networking',
    'disable-component-update',
    'disable-domain-reliability',
    'no-pings',
    'dns-prefetch-disable',
    'disable-gpu-shader-disk-cache',
  ]);
  assert.equal(sandboxCalls, 1);
});

function makeSession() {
  const calls = {
    languages: [],
    dictionaryUrl: [],
    enabled: [],
    permissions: [],
    checks: [],
  };
  let beforeRequest = null;
  const ses = {
    setSpellCheckerLanguages(value) {
      calls.languages.push(value);
    },
    setSpellCheckerDictionaryDownloadURL(value) {
      calls.dictionaryUrl.push(value);
    },
    setSpellCheckerEnabled(value) {
      calls.enabled.push(value);
    },
    webRequest: {
      onBeforeRequest(listener) {
        beforeRequest = listener;
      },
    },
    setPermissionRequestHandler(handler) {
      calls.permissions.push(handler);
    },
    setPermissionCheckHandler(handler) {
      calls.checks.push(handler);
    },
  };
  return { ses, calls, beforeRequest: () => beforeRequest };
}

test('lockSession installs the spellcheck calls and the per-request gate', () => {
  const { ses, calls, beforeRequest } = makeSession();
  let origin = ORIGIN;

  lockSession(ses, () => origin, ASAR);

  assert.deepEqual(calls.languages, [[]]);
  assert.deepEqual(calls.dictionaryUrl, ['http://127.0.0.1:9/']);
  assert.deepEqual(calls.enabled, [false]);

  const request = beforeRequest();
  assert.equal(typeof request, 'function');

  let answer = null;
  request({ url: `${ORIGIN}/policy` }, (value) => {
    answer = value;
  });
  assert.deepEqual(answer, { cancel: false });

  request({ url: 'https://evil.example/policy' }, (value) => {
    answer = value;
  });
  assert.deepEqual(answer, { cancel: true });

  request({ url: 'file:///opt/rongroi/resources/app.asar/index.html' }, (value) => {
    answer = value;
  });
  assert.deepEqual(answer, { cancel: false });

  origin = null;
  request({ url: `${ORIGIN}/policy` }, (value) => {
    answer = value;
  });
  assert.deepEqual(answer, { cancel: true });
});

test('lockSession denies permission requests and checks', () => {
  const { ses, calls } = makeSession();
  lockSession(ses, () => null, ASAR);

  assert.equal(calls.permissions.length, 1);
  assert.equal(calls.checks.length, 1);

  let granted = true;
  const result = calls.permissions[0]({}, 'notifications', (value) => {
    granted = value;
  });
  assert.equal(granted, false);
  assert.equal(result, false);
  assert.equal(calls.checks[0]({}, 'notifications', ORIGIN), false);
});

function makeContents() {
  const listeners = {};
  let windowOpen = null;
  const contents = {
    setWindowOpenHandler(handler) {
      windowOpen = handler;
    },
    on(event, listener) {
      listeners[event] = listener;
    },
  };
  return { contents, listeners, windowOpen: () => windowOpen };
}

function makeEvent() {
  return {
    prevented: false,
    preventDefault() {
      this.prevented = true;
    },
  };
}

test('lockContents denies windows and prevents navigation off the app page', () => {
  const created = [];
  const app = {
    on(event, listener) {
      if (event === 'web-contents-created') created.push(listener);
    },
  };
  const seen = [];
  const isOwnPage = (url) => {
    seen.push(url);
    return url === 'app://rongroi/index.html';
  };

  lockContents(app, isOwnPage);
  assert.equal(created.length, 1);

  const { contents, listeners, windowOpen } = makeContents();
  created[0]({}, contents);

  assert.deepEqual(windowOpen()(), { action: 'deny' });

  const own = makeEvent();
  listeners['will-navigate'](own, 'app://rongroi/index.html');
  assert.equal(own.prevented, false);

  const foreign = makeEvent();
  listeners['will-navigate'](foreign, 'https://evil.example/');
  assert.equal(foreign.prevented, true);

  const redirect = makeEvent();
  listeners['will-redirect'](redirect, 'app://rongroi/index.html');
  assert.equal(redirect.prevented, true);

  const webview = makeEvent();
  listeners['will-attach-webview'](webview, {}, {});
  assert.equal(webview.prevented, true);

  assert.deepEqual(seen, ['app://rongroi/index.html', 'https://evil.example/']);
});

test('WEB_PREFERENCES is the frozen section 1 window configuration', () => {
  assert.deepEqual({ ...WEB_PREFERENCES }, {
    sandbox: true,
    contextIsolation: true,
    nodeIntegration: false,
    webSecurity: true,
    spellcheck: false,
    webviewTag: false,
    devTools: false,
  });
  assert.equal(Object.isFrozen(WEB_PREFERENCES), true);
  assert.equal('preload' in WEB_PREFERENCES, false);
});
