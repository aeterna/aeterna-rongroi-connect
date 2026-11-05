// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createSidecarRunner,
  verifySidecar,
  SidecarError,
} = require('../src/main/sidecar');

const PIPE_NAME = '\\\\.\\pipe\\rongroi-0123456789abcdef0123456789abcdef';
const TICKET = '9f82c4e1b07a412891d604e38a291bf0';
const NONCE = 'nonce-abc-123';
const POLICY = {
  required_collectors: ['posture'],
  require_elevation: false,
  server_name: 'Example City',
  expires_at: '2099-01-01T00:00:00Z',
};
const PRODUCER = { name: 'rongroi-connect', version: '0.1.0', mode: 'single-shot' };
const MAX_RECORD_BYTES = 2 * 1024 * 1024;

function makeChild() {
  const handlers = {};
  return {
    stdout: {},
    killed: 0,
    on(event, handler) {
      if (handlers[event] === undefined) handlers[event] = [];
      handlers[event].push(handler);
    },
    emit(event, ...args) {
      for (const handler of handlers[event] ?? []) handler(...args);
    },
    kill() {
      this.killed += 1;
    },
  };
}

function makePipe(child, behaves = {}) {
  const calls = [];
  return {
    calls,
    pipeName(bytes) {
      calls.push(['pipeName', bytes]);
      if (behaves.pipeNameError) throw behaves.pipeNameError;
      return behaves.name ?? PIPE_NAME;
    },
    async create(name) {
      calls.push(['create', name]);
      if (behaves.createError) throw behaves.createError;
      return behaves.handle ?? 7;
    },
    async accept(id, timeoutMs) {
      calls.push(['accept', id, timeoutMs]);
      if (behaves.accept) return behaves.accept({ id, timeoutMs, child, calls });
      return undefined;
    },
    async writeLine(id, text, timeoutMs) {
      calls.push(['writeLine', id, text, timeoutMs]);
      if (behaves.writeLine) return behaves.writeLine({ id, text, timeoutMs, child, calls });
      if (behaves.writeError) throw behaves.writeError;
      return undefined;
    },
    async readUntilClose(id, maxBytes, timeoutMs) {
      calls.push(['readUntilClose', id, maxBytes, timeoutMs]);
      if (behaves.readUntilClose) {
        return behaves.readUntilClose({ id, maxBytes, timeoutMs, child, calls });
      }
      if (behaves.readError) throw behaves.readError;
      return Buffer.from(behaves.recordText ?? '{"ok":true}');
    },
    async close(id) {
      calls.push(['close', id]);
      if (behaves.closeError) throw behaves.closeError;
      return undefined;
    },
  };
}

function makeHarness(options = {}) {
  const child = makeChild();
  const pipe = options.pipe ? options.pipe(child) : makePipe(child, options.pipeBehaves);
  const spawnCalls = [];
  const commandCalls = [];
  const events = [];

  const spawn = options.spawn ?? ((file, args, spawnOptions) => {
    spawnCalls.push({ file, args, options: spawnOptions });
    events.push('spawn');
    if (options.onSpawn) options.onSpawn({ file, args, spawnOptions, child });
    return child;
  });

  const randomBytes = options.randomBytes ?? ((size) => {
    assert.equal(size, 16);
    return Buffer.from([...Array(16).keys()]);
  });

  const sidecarCommand = options.sidecarCommand ?? (() => {
    commandCalls.push(true);
    return { file: 'C:\\Program Files\\Rongroi Connect\\rongroi-scan.exe', args: ['--version', 'x'] };
  });

  const runner = createSidecarRunner({
    pipe,
    spawn,
    randomBytes,
    sidecarCommand,
    timeouts: options.timeouts ?? { connect: 60_000, record: 120_000, exit: 20 },
    verifySidecar: options.verifySidecar,
  });

  return {
    runner,
    child,
    pipe,
    spawnCalls,
    commandCalls,
    events,
    randomBytes,
    call(input = {}) {
      return runner({
        binding: { ticket: TICKET, nonce: NONCE },
        policy: POLICY,
        producer: PRODUCER,
        elevate: false,
        ...input,
      });
    },
  };
}

function callNames(pipe) {
  return pipe.calls.map((call) => call[0]);
}

test('the runner builds the pipe, spawns the sidecar and returns the record text', async () => {
  const h = makeHarness({ pipeBehaves: { recordText: '{"schema":2}' } });
  const result = await h.call();

  assert.deepEqual(result, { recordText: '{"schema":2}' });
  assert.equal(h.pipe.calls[0][0], 'pipeName');
  assert.equal(h.pipe.calls[0][1].length, 16);
  assert.deepEqual(h.pipe.calls[1], ['create', PIPE_NAME]);
  assert.deepEqual(h.spawnCalls[0].args, ['--version', 'x', '--pipe', PIPE_NAME]);
  assert.deepEqual(h.spawnCalls[0].options, { windowsHide: true });

  const accept = h.pipe.calls.find((call) => call[0] === 'accept');
  assert.deepEqual(accept, ['accept', 7, 60_000]);

  const write = h.pipe.calls.find((call) => call[0] === 'writeLine');
  assert.equal(write[1], 7);
  assert.equal(write[3], 60_000);
  assert.deepEqual(JSON.parse(write[2]), {
    binding: { ticket: TICKET, nonce: NONCE },
    policy: POLICY,
    producer: PRODUCER,
  });

  const read = h.pipe.calls.find((call) => call[0] === 'readUntilClose');
  assert.deepEqual(read, ['readUntilClose', 7, MAX_RECORD_BYTES, 120_000]);
  assert.deepEqual(h.pipe.calls[h.pipe.calls.length - 1], ['close', 7]);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('the ticket never appears on the sidecar command line', async () => {
  const h = makeHarness();
  await h.call();
  const command = [h.spawnCalls[0].file, ...h.spawnCalls[0].args].join(' ');
  assert.equal(command.includes(TICKET), false);
  assert.equal(command.includes(NONCE), false);
});

test('the verifySidecar hook runs immediately before spawn', async () => {
  const order = [];
  const h = makeHarness({
    verifySidecar() {
      order.push('verify');
    },
    onSpawn() {
      order.push('spawn');
    },
  });

  await h.call();
  assert.deepEqual(order, ['verify', 'spawn']);
  assert.equal(typeof verifySidecar, 'function');
});

test('a verifySidecar failure closes the pipe and never spawns', async () => {
  const h = makeHarness({
    verifySidecar() {
      throw new Error('wrong hash');
    },
  });

  await assert.rejects(h.call(), /wrong hash/);
  assert.equal(h.spawnCalls.length, 0);
  assert.deepEqual(h.pipe.calls[h.pipe.calls.length - 1], ['close', 7]);
});

test('elevation adds --elevate and announces the pending UAC prompt', async () => {
  let pending = 0;
  const h = makeHarness();
  const result = await h.call({
    elevate: true,
    onElevationPending() {
      pending += 1;
    },
  });

  assert.deepEqual(result, { recordText: '{"ok":true}' });
  assert.equal(h.spawnCalls[0].args.includes('--elevate'), true);
  assert.equal(pending, 1);
});

test('exit code 3 before connecting resolves as declined and closes the pipe', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      accept() {
        queueMicrotask(() => child.emit('exit', 3));
        return new Promise(() => {});
      },
    }),
  });

  assert.deepEqual(await h.call(), { declined: true });
  assert.equal(callNames(h.pipe).includes('writeLine'), false);
  assert.equal(callNames(h.pipe).includes('readUntilClose'), false);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('exit code 0 before connecting does not stop the wait for accept', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      accept() {
        child.emit('exit', 0);
        return Promise.resolve();
      },
      recordText: '{"schema":2}',
    }),
  });

  assert.deepEqual(await h.call(), { recordText: '{"schema":2}' });
  assert.equal(callNames(h.pipe).includes('writeLine'), true);
  assert.equal(callNames(h.pipe).includes('readUntilClose'), true);
});

test('any other exit code before connecting rejects and closes the pipe', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      accept() {
        queueMicrotask(() => child.emit('exit', 7));
        return new Promise(() => {});
      },
    }),
  });

  await assert.rejects(h.call(), /code 7/);
  assert.equal(callNames(h.pipe).includes('writeLine'), false);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a non-zero exit after the record is read rejects as a sidecar failure', async () => {
  const h = makeHarness({
    timeouts: { connect: 60_000, record: 120_000, exit: 100 },
    pipe: (child) => makePipe(child, {
      readUntilClose() {
        setTimeout(() => child.emit('exit', 9), 5);
        return Buffer.from('{"ok":true}');
      },
    }),
  });

  await assert.rejects(h.call(), (failure) => {
    assert.equal(failure instanceof SidecarError, true);
    assert.equal(failure.code, 'sidecar_failed');
    assert.match(failure.message, /code 9/);
    return true;
  });
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a non-zero exit already reported when the record read ends is a sidecar failure', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      readUntilClose() {
        child.emit('exit', 4);
        return Buffer.from('{"ok":true}');
      },
    }),
  });

  await assert.rejects(h.call(), (failure) => {
    assert.equal(failure.code, 'sidecar_failed');
    assert.match(failure.message, /code 4/);
    return true;
  });
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a child that has not exited after the grace period still returns its record', async () => {
  const h = makeHarness({
    timeouts: { connect: 60_000, record: 120_000, exit: 20 },
    pipeBehaves: { recordText: '{"schema":2}' },
  });

  assert.deepEqual(await h.call(), { recordText: '{"schema":2}' });
  assert.equal(h.child.killed, 0);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('an empty record is a sidecar failure whatever the exit code', async () => {
  for (const code of [0, 7]) {
    const h = makeHarness({
      pipe: (child) => makePipe(child, {
        readUntilClose() {
          child.emit('exit', code);
          return Buffer.alloc(0);
        },
      }),
    });

    await assert.rejects(h.call(), (failure) => {
      assert.equal(failure instanceof SidecarError, true);
      assert.equal(failure.code, 'sidecar_failed');
      assert.match(failure.message, /empty/i);
      return true;
    });
    assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
  }
});

test('a non-empty invalid record is left for the flow when the sidecar exits 0', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      readUntilClose() {
        child.emit('exit', 0);
        return Buffer.from('not json');
      },
    }),
  });

  assert.deepEqual(await h.call(), { recordText: 'not json' });
});

test('cancel kills the child, closes the pipe and is harmless when repeated', async () => {
  let cancel = null;
  let accepting;
  const accepted = new Promise((resolve) => { accepting = resolve; });
  const h = makeHarness({
    pipe: () => makePipe(null, {
      accept() {
        accepting();
        return new Promise(() => {});
      },
    }),
  });

  const pending = h.call({
    onCancel(value) {
      cancel = value;
    },
  });
  await accepted;

  assert.equal(typeof cancel, 'function');
  cancel();
  cancel();
  assert.equal(h.child.killed, 1);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
  await assert.rejects(pending, (failure) => {
    assert.equal(failure instanceof SidecarError, true);
    assert.equal(failure.code, 'sidecar_cancelled');
    return true;
  });
});

test('onCancel is called exactly once before the first pipe operation', async () => {
  const h = makeHarness();
  const callsAtRegister = [];
  const pending = h.call({
    onCancel() {
      callsAtRegister.push(callNames(h.pipe).length);
    },
  });

  assert.deepEqual(callsAtRegister, [0]);
  await pending;
  assert.deepEqual(callsAtRegister, [0]);
});

test('an accept timeout kills the child, closes the pipe and rejects', async () => {
  const timeout = Object.assign(new Error('timeout'), { code: 'timeout' });
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      accept() {
        return Promise.reject(timeout);
      },
    }),
  });

  await assert.rejects(h.call(), /timeout/);
  assert.equal(h.child.killed, 1);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a write timeout kills the child and closes the pipe', async () => {
  const timeout = Object.assign(new Error('timeout'), { code: 'timeout' });
  const h = makeHarness({
    pipeBehaves: { writeError: timeout },
  });

  await assert.rejects(h.call(), /timeout/);
  assert.equal(h.child.killed, 1);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a read timeout kills the child and closes the pipe', async () => {
  const timeout = Object.assign(new Error('timeout'), { code: 'timeout' });
  const h = makeHarness({
    pipeBehaves: { readError: timeout },
  });

  await assert.rejects(h.call(), /timeout/);
  assert.equal(h.child.killed, 1);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a non-timeout read failure closes the pipe and rejects without killing', async () => {
  const h = makeHarness({
    pipeBehaves: { readError: new Error('connection closed') },
  });

  await assert.rejects(h.call(), /connection closed/);
  assert.equal(h.child.killed, 0);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a too-large read error becomes a typed SidecarError and does not kill', async () => {
  const error = Object.assign(new Error('too_large'), { code: 'too_large' });
  const h = makeHarness({
    pipeBehaves: { readError: error },
  });

  await assert.rejects(h.call(), (failure) => {
    assert.equal(failure instanceof SidecarError, true);
    assert.equal(failure.code, 'too_large');
    assert.match(failure.message, /2 MiB|2097152|exceeds/i);
    return true;
  });
  assert.equal(h.child.killed, 0);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a record returned over 2 MiB rejects as too_large', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      readUntilClose({ maxBytes }) {
        return Buffer.alloc(maxBytes + 1, 0x7b);
      },
    }),
  });

  await assert.rejects(h.call(), (failure) => {
    assert.equal(failure instanceof SidecarError, true);
    assert.equal(failure.code, 'too_large');
    return true;
  });
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a child error event before connecting closes the pipe and rejects', async () => {
  const h = makeHarness({
    pipe: (child) => makePipe(child, {
      accept() {
        queueMicrotask(() => child.emit('error', new Error('spawn ENOENT')));
        return new Promise(() => {});
      },
    }),
  });

  await assert.rejects(h.call(), /spawn ENOENT/);
  assert.equal(callNames(h.pipe).includes('writeLine'), false);
  assert.equal(callNames(h.pipe).includes('readUntilClose'), false);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a spawn failure closes the pipe and rejects', async () => {
  const h = makeHarness({
    spawn() {
      throw new Error('cannot start');
    },
  });

  await assert.rejects(h.call(), /cannot start/);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});

test('a sidecarCommand failure closes the pipe and never spawns', async () => {
  const h = makeHarness({
    sidecarCommand() {
      throw new Error('missing command');
    },
  });

  await assert.rejects(h.call(), /missing command/);
  assert.equal(h.spawnCalls.length, 0);
  assert.equal(callNames(h.pipe).filter((name) => name === 'close').length, 1);
});
