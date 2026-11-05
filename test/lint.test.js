// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { ESLint } = require('eslint');

const ROOT = path.resolve(__dirname, '..');
const FILE_PATH = path.join(ROOT, 'src', 'main', 'x.js');
const RULES = new Set(['no-restricted-syntax', 'no-restricted-globals']);

const eslint = new ESLint({
  cwd: ROOT,
  overrideConfigFile: path.join(ROOT, 'eslint.config.js'),
});

async function lint(code) {
  const [result] = await eslint.lintText(code, { filePath: FILE_PATH });
  return result;
}

function restricted(result) {
  return result.messages.filter((message) => RULES.has(message.ruleId));
}

async function assertRestricted(code) {
  const result = await lint(code);
  const messages = restricted(result);
  assert.ok(
    messages.length > 0,
    `expected a restricted-network error for: ${code}\n${JSON.stringify(result.messages)}`,
  );
  assert.ok(result.errorCount > 0);
}

test('require() of a network module fails with and without node:', async () => {
  for (const name of ['http', 'https', 'net', 'tls', 'dgram', 'dns', 'http2']) {
    await assertRestricted(`const moduleValue = require('${name}');`);
    await assertRestricted(`const moduleValue = require('node:${name}');`);
  }
});

test("require('electron').net and destructuring net fail", async () => {
  await assertRestricted("require('electron').net.request({ url: 'http://example.test/' });");
  await assertRestricted("require('electron')['net'].request({ url: 'http://example.test/' });");
  await assertRestricted("const { net } = require('electron');");
  await assertRestricted("const { net: electronNet } = require('electron');");
  await assertRestricted("({ net } = require('electron'));");
});

test('the network globals fail as bare names', async () => {
  await assertRestricted("fetch('http://example.test/');");
  await assertRestricted("new WebSocket('ws://example.test/');");
  await assertRestricted('new XMLHttpRequest();');
  await assertRestricted("new EventSource('http://example.test/');");
});

test('member access of the network globals on globalThis fails', async () => {
  await assertRestricted("globalThis.fetch('http://example.test/');");
  await assertRestricted("globalThis.WebSocket('ws://example.test/');");
  await assertRestricted('globalThis.XMLHttpRequest();');
  await assertRestricted("globalThis.EventSource('http://example.test/');");
  await assertRestricted("globalThis['fetch']('http://example.test/');");
});

test('a plain ses.fetch() call passes', async () => {
  const result = await lint([
    "const ses = { fetch(url) { return url; } };",
    "ses.fetch('http://127.0.0.1:9/nakara_rongroi/policy/abc');",
  ].join('\n'));

  assert.equal(result.errorCount, 0);
  assert.deepEqual(restricted(result), []);
});

test('ordinary electron and node imports are not restricted', async () => {
  const result = await lint([
    "const { app, BrowserWindow } = require('electron');",
    "const path = require('node:path');",
    'app.quit();',
    'void BrowserWindow;',
    'void path;',
  ].join('\n'));

  assert.equal(result.errorCount, 0);
  assert.deepEqual(restricted(result), []);
});
