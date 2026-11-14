// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// ADR 0002 section 1, the launcher handoff contract v1.  The app's own
// arguments are either empty (the player started Connect, the paste field is
// shown) or exactly `--from-launcher` (a launcher hands over one pairing code
// on stdin).  Anything else — another flag, a value, or a Chromium or Node
// switch such as `--remote-debugging-port=9222`, `--inspect` or
// `--user-data-dir=x` — is refused: Connect exits 12 at once, before the temp
// folder or a window exists, because a command line this app does not own is
// not a command line it may act on.

const LAUNCHER_FLAG = '--from-launcher';
const REFUSED_EXIT_CODE = 12;

const PASTE = Object.freeze({
  ok: true,
  fromLauncher: false,
  reason: null,
  argument: null,
});
const LAUNCHER = Object.freeze({
  ok: true,
  fromLauncher: true,
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

function interpretLaunchArguments(args) {
  if (!Array.isArray(args)) return refusal(args);
  if (args.length === 0) return PASTE;
  if (args.length === 1 && args[0] === LAUNCHER_FLAG) return LAUNCHER;
  const offender = args.find((value) => value !== LAUNCHER_FLAG);
  return refusal(offender === undefined ? args[0] : offender);
}

module.exports = {
  LAUNCHER_FLAG,
  REFUSED_EXIT_CODE,
  appArguments,
  interpretLaunchArguments,
};
