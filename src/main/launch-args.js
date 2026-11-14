// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const path = require('node:path');

// ADR 0002 section 1, the launcher handoff contract v1.  The app's own
// arguments are either empty (the player started Connect, the paste field is
// shown) or exactly one `--from-launcher=<pipe>`, where <pipe> is a Windows
// named pipe `\\.\pipe\rongroi-launch-<32 lowercase hex>`.  The launcher
// hosts that pipe; Connect connects to it as a client and reads one pairing
// code.  Anything else — a bare `--from-launcher`, another pipe name, another
// flag, a value, or a Chromium or Node switch such as
// `--remote-debugging-port=9222`, `--inspect` or `--user-data-dir=x` — is
// refused: Connect exits 12 at once, before the temp folder or a window
// exists, because a command line this app does not own is not a command line
// it may act on.
//
// The test build alone may add one `--log-net-log=<absolute path>` so CI can
// record the netlog ADR 0001 section 2 relies on.  The release test hook does
// not expose the switch, so a player's build stays strict.

const LAUNCHER_FLAG = '--from-launcher';
const LAUNCHER_PREFIX = `${LAUNCHER_FLAG}=`;
// The pipe name is matched exactly: the literal prefix `\\.\pipe\`, the
// fixed `rongroi-launch-` stem, then 32 lowercase hex digits and nothing else.
const PIPE_NAME_PATTERN = /^\\\\\.\\pipe\\rongroi-launch-[0-9a-f]{32}$/;
const NET_LOG_PREFIX = '--log-net-log=';
const REFUSED_EXIT_CODE = 12;

const PASTE = Object.freeze({
  ok: true,
  fromLauncher: false,
  reason: null,
  argument: null,
});

function refusal(argument) {
  return {
    ok: false,
    fromLauncher: false,
    reason: 'unexpected_argument',
    argument: argument === undefined || argument === null ? null : String(argument),
  };
}

// In a packaged build argv[0] is the app executable; in development it is the
// Electron binary followed by the app path, so two entries are skipped.
function appArguments(argv, isPackaged) {
  const list = Array.isArray(argv) ? argv : [];
  return list.slice(isPackaged === true ? 1 : 2);
}

function launcherPipe(value) {
  if (typeof value !== 'string' || !value.startsWith(LAUNCHER_PREFIX)) return null;
  const pipe = value.slice(LAUNCHER_PREFIX.length);
  return PIPE_NAME_PATTERN.test(pipe) ? pipe : null;
}

function isNetLogArgument(value, allowNetLog) {
  if (allowNetLog !== true) return false;
  if (typeof value !== 'string' || !value.startsWith(NET_LOG_PREFIX)) return false;
  const target = value.slice(NET_LOG_PREFIX.length);
  return target.length > 0 && path.isAbsolute(target);
}

function interpretLaunchArguments(args, options) {
  if (!Array.isArray(args)) return refusal(args);
  if (args.length === 0) return PASTE;

  const allowNetLog = Boolean(options) && options.allowNetLog === true;
  let pipe = null;
  let netLogSeen = false;
  let offender = null;
  let hasOffender = false;

  for (const value of args) {
    const candidate = launcherPipe(value);
    if (candidate !== null && pipe === null) {
      pipe = candidate;
      continue;
    }
    if (!netLogSeen && isNetLogArgument(value, allowNetLog)) {
      netLogSeen = true;
      continue;
    }
    if (!hasOffender) {
      offender = value;
      hasOffender = true;
    }
  }

  if (hasOffender) return refusal(offender);
  if (pipe === null) return PASTE;
  return Object.freeze({
    ok: true,
    fromLauncher: true,
    reason: null,
    argument: null,
    pipe,
  });
}

module.exports = {
  LAUNCHER_FLAG,
  PIPE_NAME_PATTERN,
  REFUSED_EXIT_CODE,
  appArguments,
  interpretLaunchArguments,
};
