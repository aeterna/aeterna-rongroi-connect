// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// The pipe module is native (Rust N-API): it does not use node:net, so
// node:net stays banned here alongside every other network module.
const NETWORK_MODULES = ['http', 'https', 'net', 'tls', 'dgram', 'dns'];
const RESTRICTED_IMPORT_MESSAGE =
  'Network requests go through the paired session and its webRequest gate; use Session.fetch().';
const RESTRICTED_PATHS = [];

for (const name of NETWORK_MODULES) {
  RESTRICTED_PATHS.push({ name, message: RESTRICTED_IMPORT_MESSAGE });
  RESTRICTED_PATHS.push({ name: `node:${name}`, message: RESTRICTED_IMPORT_MESSAGE });
}

RESTRICTED_PATHS.push({
  name: 'electron',
  importNames: ['net'],
  message: 'Use Session.fetch() on the paired session; Electron net is banned.',
});

module.exports = [
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
    },
  },
  {
    files: ['src/**/*.js'],
    rules: {
      'no-restricted-imports': ['error', { paths: RESTRICTED_PATHS }],
      'no-restricted-globals': ['error', {
        name: 'fetch',
        message: 'Use Session.fetch() on the paired session; global fetch is banned.',
      }],
      'no-restricted-properties': ['error', {
        object: 'electron',
        property: 'net',
        message: 'Use Session.fetch() on the paired session; Electron net is banned.',
      }],
    },
  },
  {
    // src/core/pairing.js only calls net.isIP. This lane may not edit that
    // file, so keep every other network module banned there and leave the
    // node:net ban in force for the rest of src.
    files: ['src/core/pairing.js'],
    rules: {
      'no-restricted-imports': ['error', {
        paths: RESTRICTED_PATHS.filter(
          (entry) => entry.name !== 'net' && entry.name !== 'node:net',
        ),
      }],
    },
  },
];
