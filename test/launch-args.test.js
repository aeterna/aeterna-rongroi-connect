// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  LAUNCHER_FLAG,
  REFUSED_EXIT_CODE,
  appArguments,
  interpretLaunchArguments,
} = require('../src/main/launch-args');

test('appArguments skips the Electron binary and, unpackaged, the app path', () => {
  assert.deepEqual(
    appArguments(['electron', '/app', '--from-launcher'], false),
    ['--from-launcher'],
  );
  assert.deepEqual(
    appArguments(['rongroi-connect.exe', '--from-launcher'], true),
    ['--from-launcher'],
  );
  assert.deepEqual(appArguments([], true), []);
  assert.deepEqual(appArguments(['only', 'one'], false), []);
});

test('a refusal exits 12', () => {
  assert.equal(REFUSED_EXIT_CODE, 12);
  assert.equal(LAUNCHER_FLAG, '--from-launcher');
});

test('no argument of its own keeps the paste field', () => {
  assert.deepEqual(interpretLaunchArguments([]), {
    ok: true,
    fromLauncher: false,
    reason: null,
    argument: null,
  });
});

test('exactly --from-launcher starts the launcher handoff', () => {
  assert.deepEqual(interpretLaunchArguments(['--from-launcher']), {
    ok: true,
    fromLauncher: true,
    reason: null,
    argument: null,
  });
});

test('every other argument, including Chromium and Node switches, is refused', () => {
  const refused = [
    ['--remote-debugging-port=9222'],
    ['--inspect'],
    ['--inspect-brk'],
    ['--user-data-dir=x'],
    ['--no-sandbox'],
    ['extra'],
    ['-h'],
    ['--help'],
    ['--from-launcher=x'],
    ['--FROM-LAUNCHER'],
    [''],
    ['--from-launcher', 'extra'],
    ['extra', '--from-launcher'],
    ['--from-launcher', '--from-launcher'],
  ];

  for (const args of refused) {
    const decision = interpretLaunchArguments(args);
    assert.equal(decision.ok, false, args.join(' '));
    assert.equal(decision.fromLauncher, false, args.join(' '));
    assert.equal(decision.reason, 'unexpected_argument', args.join(' '));
    assert.equal(typeof decision.argument, 'string', args.join(' '));
  }
});

test('a refusal names the argument that was not owned by the app', () => {
  assert.equal(interpretLaunchArguments(['--inspect']).argument, '--inspect');
  assert.equal(
    interpretLaunchArguments(['--user-data-dir=x', '--from-launcher']).argument,
    '--user-data-dir=x',
  );
  // Two launcher flags: the second one is the offender.
  assert.equal(
    interpretLaunchArguments(['--from-launcher', '--from-launcher']).argument,
    '--from-launcher',
  );
});

test('a release build refuses the netlog switch', () => {
  for (const options of [undefined, {}, { allowNetLog: false }]) {
    const decision = interpretLaunchArguments(['--log-net-log=/tmp/x.json'], options);
    assert.equal(decision.ok, false);
    assert.equal(decision.fromLauncher, false);
    assert.equal(decision.reason, 'unexpected_argument');
    assert.equal(decision.argument, '--log-net-log=/tmp/x.json');
  }
});

test('the test build accepts one absolute netlog switch alone or with the launcher flag', () => {
  const expectedPaste = {
    ok: true,
    fromLauncher: false,
    reason: null,
    argument: null,
  };
  const expectedLauncher = {
    ok: true,
    fromLauncher: true,
    reason: null,
    argument: null,
  };

  assert.deepEqual(
    interpretLaunchArguments(['--log-net-log=/tmp/x.json'], { allowNetLog: true }),
    expectedPaste,
  );
  assert.deepEqual(
    interpretLaunchArguments(
      ['--log-net-log=/tmp/x.json', '--from-launcher'],
      { allowNetLog: true },
    ),
    expectedLauncher,
  );
  assert.deepEqual(
    interpretLaunchArguments(
      ['--from-launcher', '--log-net-log=/tmp/x.json'],
      { allowNetLog: true },
    ),
    expectedLauncher,
  );
});

test('the test build still refuses a malformed or repeated netlog switch', () => {
  const refused = [
    ['--log-net-log'],
    ['--log-net-log='],
    ['--log-net-log=x.json'],
    ['--log-net-log=./x.json'],
    ['--log-net-log=../x.json'],
    ['--log-net-log=/tmp/x.json', '--log-net-log=/tmp/y.json'],
    ['--from-launcher', '--log-net-log=/tmp/x.json', '--log-net-log=/tmp/y.json'],
    ['--log-net-log=/tmp/x.json', 'extra'],
    ['--log-net-log=/tmp/x.json', '--inspect'],
    ['--from-launcher', '--log-net-log=/tmp/x.json', '--from-launcher'],
  ];

  for (const args of refused) {
    const decision = interpretLaunchArguments(args, { allowNetLog: true });
    assert.equal(decision.ok, false, args.join(' '));
    assert.equal(decision.fromLauncher, false, args.join(' '));
    assert.equal(decision.reason, 'unexpected_argument', args.join(' '));
    assert.equal(typeof decision.argument, 'string', args.join(' '));
  }
});

test('the test build names the first argument it does not own', () => {
  assert.equal(
    interpretLaunchArguments(
      ['--log-net-log=/tmp/x.json', '--log-net-log=/tmp/y.json'],
      { allowNetLog: true },
    ).argument,
    '--log-net-log=/tmp/y.json',
  );
  assert.equal(
    interpretLaunchArguments(
      ['--log-net-log=/tmp/x.json', '--inspect'],
      { allowNetLog: true },
    ).argument,
    '--inspect',
  );
});

test('the decision refuses input that is not an argument list', () => {
  for (const value of [undefined, null, '--from-launcher', 7, {}]) {
    const decision = interpretLaunchArguments(value);
    assert.equal(decision.ok, false, String(value));
    assert.equal(decision.reason, 'unexpected_argument', String(value));
  }
});

test('the accepted decisions are frozen, so a caller cannot turn a refusal into a handoff', () => {
  assert.equal(Object.isFrozen(interpretLaunchArguments([])), true);
  assert.equal(Object.isFrozen(interpretLaunchArguments(['--from-launcher'])), true);
});
