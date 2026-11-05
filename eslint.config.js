// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// This repository is CommonJS, so no-restricted-imports never sees a
// require() call.  Restrict the syntax instead: the require() expression,
// Electron's net member, and the network globals.
const NETWORK_MODULES = ['http', 'https', 'net', 'tls', 'dgram', 'dns', 'http2'];
const NETWORK_GLOBALS = ['fetch', 'WebSocket', 'XMLHttpRequest', 'EventSource'];

const REQUIRE_MESSAGE =
  'Network requests go through the paired session and its webRequest gate; use Session.fetch().';
const ELECTRON_NET_MESSAGE = 'Use Session.fetch() on the paired session; Electron net is banned.';
const GLOBAL_MESSAGE =
  'Use Session.fetch() on the paired session; the network globals are banned.';

function requireSelectors(modules) {
  const selectors = [];
  for (const name of modules) {
    selectors.push(`CallExpression[callee.name='require'][arguments.length=1][arguments.0.value='${name}']`);
    selectors.push(`CallExpression[callee.name='require'][arguments.length=1][arguments.0.value='node:${name}']`);
  }
  return selectors;
}

function electronSelectors() {
  return [
    // require('electron').net.request and require('electron')['net']
    "MemberExpression[object.type='CallExpression'][object.callee.name='require'][object.arguments.0.value='electron'][property.name='net']",
    "MemberExpression[object.type='CallExpression'][object.callee.name='require'][object.arguments.0.value='electron'][computed=true][property.value='net']",
    // const { net } = require('electron')
    "VariableDeclarator[init.type='CallExpression'][init.callee.name='require'][init.arguments.0.value='electron'] > ObjectPattern > Property[key.name='net']",
    "VariableDeclarator[init.type='CallExpression'][init.callee.name='require'][init.arguments.0.value='electron'] > ObjectPattern > Property[computed=true][key.value='net']",
    // ({ net } = require('electron'))
    "AssignmentExpression[right.type='CallExpression'][right.callee.name='require'][right.arguments.0.value='electron'] > ObjectPattern > Property[key.name='net']",
    "AssignmentExpression[right.type='CallExpression'][right.callee.name='require'][right.arguments.0.value='electron'] > ObjectPattern > Property[computed=true][key.value='net']",
  ];
}

function globalThisSelectors() {
  const selectors = [];
  for (const name of NETWORK_GLOBALS) {
    selectors.push(`MemberExpression[object.name='globalThis'][property.name='${name}']`);
    selectors.push(`MemberExpression[object.name='globalThis'][computed=true][property.value='${name}']`);
  }
  return selectors;
}

function syntaxEntries(modules) {
  return [
    ...requireSelectors(modules).map((selector) => ({ selector, message: REQUIRE_MESSAGE })),
    ...electronSelectors().map((selector) => ({ selector, message: ELECTRON_NET_MESSAGE })),
    ...globalThisSelectors().map((selector) => ({ selector, message: GLOBAL_MESSAGE })),
  ];
}

function restrictedGlobals() {
  return NETWORK_GLOBALS.map((name) => ({ name, message: GLOBAL_MESSAGE }));
}

const ALL_MODULES = NETWORK_MODULES;
const ALL_BUT_NET = NETWORK_MODULES.filter((name) => name !== 'net');

module.exports = [
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
    },
  },
  {
    files: ['src/**/*.js', 'native/pipe/index.js'],
    rules: {
      'no-restricted-syntax': ['error', ...syntaxEntries(ALL_MODULES)],
      'no-restricted-globals': ['error', ...restrictedGlobals()],
    },
  },
  {
    // src/core/pairing.js only calls net.isIP.  This lane may not edit that
    // file, so keep every other network restriction there and leave the
    // node:net ban in force everywhere else.
    files: ['src/core/pairing.js'],
    rules: {
      'no-restricted-syntax': ['error', ...syntaxEntries(ALL_BUT_NET)],
      'no-restricted-globals': ['error', ...restrictedGlobals()],
    },
  },
];
