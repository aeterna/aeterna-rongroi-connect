// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const defaultFs = require('node:fs');
const defaultOs = require('node:os');

const TEMP_NAME = /^rongroi-connect-(\d+)-[0-9a-f]{16}$/;
const STALE_MS = 10 * 60 * 1000;

function baseName(value) {
  const text = String(value).replace(/\\/g, '/').replace(/\/+$/, '');
  const index = text.lastIndexOf('/');
  return index === -1 ? text : text.slice(index + 1);
}

function drawRandom(random) {
  const attempts = random.length > 0 ? [[16], []] : [[], [16]];
  for (const args of attempts) {
    try {
      const value = random(...args);
      if (value !== undefined && value !== null) return value;
    } catch {
      // Try the other calling convention below.
    }
  }
  throw new TypeError('random did not return a value');
}

function hex16(random) {
  if (typeof random !== 'function') throw new TypeError('random must be a function');
  const value = drawRandom(random);
  let text;
  if (typeof value === 'string') {
    text = value.toLowerCase().replace(/^0x/, '');
  } else if (typeof value.length === 'number') {
    text = Buffer.from(value).toString('hex');
  } else {
    throw new TypeError('random must return a string or bytes');
  }
  if (!/^[0-9a-f]{16,}$/.test(text)) {
    throw new TypeError('random must produce at least 16 hexadecimal characters');
  }
  return text.slice(0, 16);
}

function createTempUserData(app, options = {}) {
  const os = options.os ?? defaultOs;
  const fs = options.fs ?? defaultFs;
  const pid = options.pid ?? process.pid;
  const random = options.random ?? crypto.randomBytes;

  const token = hex16(random);
  const tmpdir = os.tmpdir();
  const target = path.join(tmpdir, `rongroi-connect-${pid}-${token}`);

  let directory = target;
  let created = false;

  if (typeof fs.mkdtempSync === 'function') {
    try {
      const made = fs.mkdtempSync(target);
      if (typeof made === 'string' && made.length > 0) {
        directory = made;
        created = true;
        if (!TEMP_NAME.test(baseName(made)) && typeof fs.renameSync === 'function') {
          // Some Node versions append their own suffix to a template without
          // six X's. The folder must keep its exact name for the stale sweep.
          try {
            fs.renameSync(made, target);
            directory = target;
          } catch {
            directory = made;
          }
        }
      }
    } catch {
      created = false;
    }
  }

  if (!created) {
    if (typeof fs.mkdirSync !== 'function') {
      throw new TypeError('fs must provide mkdtempSync or mkdirSync');
    }
    fs.mkdirSync(target);
    directory = target;
  }

  app.setPath('userData', directory);
  app.setPath('sessionData', directory);
  app.setPath('crashDumps', directory);
  return directory;
}

function removeTempUserData(directory, options = {}) {
  const fs = options.fs ?? defaultFs;
  try {
    if (!TEMP_NAME.test(baseName(directory))) return false;
    if (typeof fs.rmSync === 'function') {
      fs.rmSync(directory, {
        force: true,
        recursive: true,
        maxRetries: 5,
        retryDelay: 100,
      });
      return true;
    }
    if (typeof fs.rmdirSync === 'function') {
      fs.rmdirSync(directory, { recursive: true });
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function defaultIsRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error !== null && error !== undefined && error.code === 'EPERM';
  }
}

function sweepStale(options = {}) {
  const fs = options.fs ?? defaultFs;
  const os = options.os ?? defaultOs;
  const isRunning = options.isRunning ?? defaultIsRunning;
  const now = options.now ?? Date.now;

  const tmpdir = os.tmpdir();
  let entries;
  try {
    entries = fs.readdirSync(tmpdir);
  } catch {
    return 0;
  }

  const current = Number(typeof now === 'function' ? now() : now);
  if (!Number.isFinite(current)) return 0;

  let removed = 0;
  for (const entry of entries) {
    try {
      const name = typeof entry === 'string' ? entry : entry && entry.name;
      if (typeof name !== 'string') continue;
      const match = TEMP_NAME.exec(name);
      if (match === null) continue;

      const pid = Number(match[1]);
      if (!Number.isSafeInteger(pid)) continue;

      let running = true;
      try {
        running = Boolean(isRunning(pid));
      } catch {
        running = true;
      }
      if (running) continue;

      const full = path.join(tmpdir, name);
      let info;
      if (typeof fs.lstatSync === 'function') {
        info = fs.lstatSync(full);
      } else if (typeof fs.statSync === 'function') {
        info = fs.statSync(full);
      } else if (typeof entry !== 'string') {
        info = entry;
      } else {
        continue;
      }

      // A link is left alone, so a matching name cannot point at another
      // folder and make the sweep delete its target.
      if (typeof info.isSymbolicLink === 'function' && info.isSymbolicLink()) continue;
      if (typeof info.isDirectory === 'function' && !info.isDirectory()) continue;

      const changed = typeof info.mtimeMs === 'number'
        ? info.mtimeMs
        : info.mtime instanceof Date ? info.mtime.getTime() : NaN;
      if (!Number.isFinite(changed)) continue;
      if (!(current - changed > STALE_MS)) continue;

      if (removeTempUserData(full, { fs })) removed += 1;
    } catch {
      // One unreadable or vanished entry must not stop the sweep.
    }
  }
  return removed;
}

module.exports = {
  TEMP_NAME,
  STALE_MS,
  createTempUserData,
  removeTempUserData,
  sweepStale,
};
