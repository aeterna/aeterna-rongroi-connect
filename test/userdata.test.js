// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  createTempUserData,
  removeTempUserData,
  sweepStale,
} = require('../src/main/userdata');

const NAME = /^rongroi-connect-(\d+)-[0-9a-f]{16}$/;
const TEN_MINUTES = 10 * 60 * 1000;

function withTempRoot(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rongroi-connect-test-'));
  try {
    return run(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function tempName(pid, token) {
  return `rongroi-connect-${pid}-${token}`;
}

test('createTempUserData creates the exact folder and points all three paths at it', () => {
  withTempRoot((root) => {
    const pid = 4242;
    const token = '0123456789abcdef';
    const paths = [];
    const app = {
      setPath(name, value) {
        paths.push([name, value]);
      },
    };

    const directory = createTempUserData(app, {
      os: { tmpdir: () => root },
      fs,
      pid,
      random: () => token,
    });

    const name = path.basename(directory);
    assert.equal(name, tempName(pid, token));
    assert.equal(NAME.test(name), true);
    assert.equal(fs.existsSync(directory), true);
    assert.equal(fs.statSync(directory).isDirectory(), true);
    assert.deepEqual(paths, [
      ['userData', directory],
      ['sessionData', directory],
      ['crashDumps', directory],
    ]);
  });
});

test('createTempUserData derives the token from injected random bytes', () => {
  withTempRoot((root) => {
    const random = (bytes) => Buffer.alloc(bytes, 0xab);
    const directory = createTempUserData({ setPath() {} }, {
      os: { tmpdir: () => root },
      fs,
      pid: 7,
      random,
    });

    assert.equal(path.basename(directory), tempName(7, 'abababababababab'));
    assert.equal(NAME.test(path.basename(directory)), true);
  });
});

test('createTempUserData passes the exact name to mkdtemp when fs is injected', () => {
  const seen = [];
  const paths = [];
  const directory = createTempUserData({ setPath(name, value) { paths.push([name, value]); } }, {
    os: { tmpdir: () => '/fake/tmp' },
    fs: {
      mkdtempSync(prefix) {
        seen.push(prefix);
        return prefix;
      },
    },
    pid: 31,
    random: () => 'abcdef0123456789',
  });

  const expected = path.join('/fake/tmp', tempName(31, 'abcdef0123456789'));
  assert.deepEqual(seen, [expected]);
  assert.equal(directory, expected);
  assert.deepEqual(paths, [
    ['userData', expected],
    ['sessionData', expected],
    ['crashDumps', expected],
  ]);
});

test('removeTempUserData removes a matching folder', () => {
  withTempRoot((root) => {
    const directory = path.join(root, tempName(99, '0123456789abcdef'));
    fs.mkdirSync(directory);

    assert.equal(removeTempUserData(directory, { fs }), true);
    assert.equal(fs.existsSync(directory), false);
  });
});

test('removeTempUserData refuses names that do not match and never throws', () => {
  const cases = [
    '/tmp/rongroi-connect-99-0123456789abcdef0',
    '/tmp/rongroi-connect-99-0123456789ABCDEF',
    '/tmp/rongroi-connect-99-0123456789abcde',
    '/tmp/rongroi-connect-x-0123456789abcdef',
    '/tmp/rongroi-connect-99-0123456789abcdef.evil',
    '/tmp/other-folder',
    '',
  ];
  for (const value of cases) {
    assert.equal(removeTempUserData(value, { fs: { rmSync() {
      throw new Error('must not be called');
    } } }), false);
  }

  assert.doesNotThrow(() => {
    removeTempUserData('/tmp/rongroi-connect-5-0123456789abcdef', {
      fs: {
        rmSync() {
          throw new Error('busy');
        },
      },
    });
  });
});

test('removeTempUserData accepts a Windows-style path by its base name only', () => {
  const seen = [];
  const result = removeTempUserData('C:\\Temp\\rongroi-connect-12-0123456789abcdef', {
    fs: {
      rmSync(value, options) {
        seen.push([value, options]);
      },
    },
  });
  assert.equal(result, true);
  assert.deepEqual(seen, [[
    'C:\\Temp\\rongroi-connect-12-0123456789abcdef',
    { recursive: true, force: true },
  ]]);
});

test('sweepStale removes only stale folders whose pid is not running', () => {
  withTempRoot((root) => {
    const deadPid = 987654;
    const livePid = 424242;
    const stale = tempName(deadPid, '0123456789abcdef');
    const live = tempName(livePid, 'fedcba9876543210');
    const fresh = tempName(deadPid, '1111111111111111');
    const other = 'rongroi-connect-123-nothex';
    const short = 'rongroi-connect-123-0123456789abcde';
    const matchingFile = tempName(deadPid, '2222222222222222');
    const linkName = tempName(deadPid, '3333333333333333');
    const victim = 'victim-target';
    const old = new Date(Date.now() - 60 * 60 * 1000);
    const nowMs = Date.now();

    const stalePath = path.join(root, stale);
    const livePath = path.join(root, live);
    const freshPath = path.join(root, fresh);
    const otherPath = path.join(root, other);
    const shortPath = path.join(root, short);
    const filePath = path.join(root, matchingFile);
    const linkPath = path.join(root, linkName);
    const victimPath = path.join(root, victim);

    fs.mkdirSync(stalePath);
    fs.mkdirSync(livePath);
    fs.mkdirSync(freshPath);
    fs.mkdirSync(otherPath);
    fs.mkdirSync(shortPath);
    fs.writeFileSync(filePath, 'not a folder');
    fs.mkdirSync(victimPath);
    fs.symlinkSync(victimPath, linkPath);

    fs.utimesSync(stalePath, old, old);
    fs.utimesSync(livePath, old, old);
    fs.utimesSync(otherPath, old, old);
    fs.utimesSync(shortPath, old, old);
    fs.utimesSync(filePath, old, old);
    fs.utimesSync(victimPath, old, old);
    if (typeof fs.lutimesSync === 'function') {
      fs.lutimesSync(linkPath, old, old);
    } else {
      fs.utimesSync(linkPath, old, old);
    }

    const removed = sweepStale({
      fs,
      os: { tmpdir: () => root },
      isRunning: (pid) => pid === livePid,
      now: () => nowMs,
    });

    assert.equal(removed, 1);
    assert.equal(fs.existsSync(stalePath), false);
    assert.equal(fs.existsSync(livePath), true);
    assert.equal(fs.existsSync(freshPath), true);
    assert.equal(fs.existsSync(otherPath), true);
    assert.equal(fs.existsSync(shortPath), true);
    assert.equal(fs.existsSync(filePath), true);
    assert.equal(fs.existsSync(linkPath), true);
    assert.equal(fs.lstatSync(linkPath).isSymbolicLink(), true);
    assert.equal(fs.existsSync(victimPath), true);
    assert.ok(nowMs - fs.lstatSync(livePath).mtimeMs > TEN_MINUTES);
  });
});
