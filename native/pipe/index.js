// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const path = require('node:path');

const primaryPath = path.join(__dirname, 'rongroi_connect_pipe.node');
const candidates = [
  primaryPath,
  path.join(__dirname, 'rongroi-connect-pipe.node'),
  path.join(__dirname, `rongroi-connect-pipe.${process.platform}-${process.arch}.node`),
  path.join(__dirname, 'index.node'),
];

let native = null;
let lastCause = null;

for (const candidate of candidates) {
  try {
    native = require(candidate);
    break;
  } catch (cause) {
    lastCause = cause;
  }
}

if (native === null) {
  const error = new Error(`cannot load native pipe module from ${primaryPath}`);
  error.cause = lastCause;
  throw error;
}

module.exports = {
  pipeName: native.pipeName,
  isValidName: native.isValidName,
  create: native.create,
  accept: native.accept,
  clientImage: native.clientImage,
  writeLine: native.writeLine,
  readUntilClose: native.readUntilClose,
  close: native.close,
};
