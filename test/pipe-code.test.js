// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { readCodeFromPipe, DEFAULT_TIMEOUT_MS } = require('../src/main/pipe-code');
const { MAX_CODE_BYTES } = require('../src/main/stdin-code');

const CODE = 'rr1.AbCdEf1234567890';
const testConnect = (target) => net.connect(typeof target === 'string' ? { path: target } : target);
let pipeCounter = 0;

function temporaryPipePath() {
  pipeCounter += 1;
  const id = `${process.pid}-${Date.now()}-${pipeCounter}`;
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\rongroi-test-${id}`;
  }
  return path.join(os.tmpdir(), `rr-${id}.sock`);
}

async function withPipeServer(onConnection, run) {
  const pipePath = temporaryPipePath();
  if (process.platform !== 'win32') {
    try {
      fs.unlinkSync(pipePath);
    } catch {
      // not existing yet
    }
  }

  const server = net.createServer();
  let serverSocket = null;
  let clientWroteBytes = 0;

  server.on('connection', (socket) => {
    serverSocket = socket;
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      clientWroteBytes += chunk.length;
    });
    if (onConnection) {
      onConnection(socket, server);
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(pipePath, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  try {
    return await run(pipePath, () => serverSocket, () => clientWroteBytes);
  } finally {
    if (serverSocket) {
      try {
        serverSocket.destroy();
      } catch {
        // cleanup
      }
    }
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    await new Promise((resolve) => server.close(() => resolve()));
    if (process.platform !== 'win32') {
      try {
        fs.unlinkSync(pipePath);
      } catch {
        // cleanup
      }
    }
  }
}

test('DEFAULT_TIMEOUT_MS is 5000', () => {
  assert.equal(DEFAULT_TIMEOUT_MS, 5000);
});

test('a good code terminated with a newline is accepted', async () => {
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE}\n`);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: true, code: CODE, reason: null });
    },
  );
});

test('a good code at EOF without a newline is accepted', async () => {
  await withPipeServer(
    (socket) => {
      socket.end(CODE);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: true, code: CODE, reason: null });
    },
  );
});

test('a code arriving in multiple chunks is accepted whole', async () => {
  await withPipeServer(
    (socket) => {
      socket.write('rr1.');
      socket.write('AbCdEf');
      socket.write('1234567890\n');
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: true, code: CODE, reason: null });
    },
  );
});

test(`exactly ${MAX_CODE_BYTES} bytes are accepted from the pipe`, async () => {
  const code = 'a'.repeat(MAX_CODE_BYTES);
  await withPipeServer(
    (socket) => {
      socket.write(`${code}\n`);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: true, code, reason: null });
    },
  );
});

test('4097 bytes is refused as too_long', async () => {
  const code = 'a'.repeat(MAX_CODE_BYTES + 1);
  await withPipeServer(
    (socket) => {
      socket.write(`${code}\n`);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'too_long' });
    },
  );
});

test('CRLF in the line is refused as carriage_return', async () => {
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE}\r\n`);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'carriage_return' });
    },
  );
});

test('a UTF-8 BOM is refused as byte_order_mark', async () => {
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const code = Buffer.from(`${CODE}\n`);
  await withPipeServer(
    (socket) => {
      socket.write(Buffer.concat([bom, code]));
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'byte_order_mark' });
    },
  );
});

test('server never writes resolves as timeout', async () => {
  await withPipeServer(
    () => {
      // Keep connection open without writing
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { timeoutMs: 50, connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'timeout' });
    },
  );
});

test('nothing listening resolves as connect_failed', async () => {
  const pipePath = temporaryPipePath();
  const result = await readCodeFromPipe(pipePath, { timeoutMs: 500, connect: testConnect });
  assert.deepEqual(result, { ok: false, code: null, reason: 'connect_failed' });
});

test('server writes nothing and closes resolves as empty', async () => {
  await withPipeServer(
    (socket) => {
      socket.end();
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'empty' });
    },
  );
});

test('the client writes zero bytes to the pipe', async () => {
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE}\n`);
    },
    async (pipePath, getServerSocket, getClientWroteBytes) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.equal(result.ok, true);
      assert.equal(getClientWroteBytes(), 0);
    },
  );
});

test('destroys the socket in every case', async () => {
  // 1. On success
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE}\n`);
    },
    async (pipePath) => {
      let clientSocket = null;
      const result = await readCodeFromPipe(pipePath, {
        connect(target) {
          clientSocket = net.connect(target);
          return clientSocket;
        },
      });
      assert.equal(result.ok, true);
      assert.equal(clientSocket.destroyed, true);
    },
  );

  // 2. On refusal
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE}\r\n`);
    },
    async (pipePath) => {
      let clientSocket = null;
      const result = await readCodeFromPipe(pipePath, {
        connect(target) {
          clientSocket = net.connect(target);
          return clientSocket;
        },
      });
      assert.equal(result.ok, false);
      assert.equal(result.reason, 'carriage_return');
      assert.equal(clientSocket.destroyed, true);
    },
  );

  // 3. On timeout
  await withPipeServer(
    () => {},
    async (pipePath) => {
      let clientSocket = null;
      const result = await readCodeFromPipe(pipePath, {
        timeoutMs: 50,
        connect(target) {
          clientSocket = net.connect(target);
          return clientSocket;
        },
      });
      assert.equal(result.ok, false);
      assert.equal(result.reason, 'timeout');
      assert.equal(clientSocket.destroyed, true);
    },
  );

  // 4. On empty
  await withPipeServer(
    (socket) => {
      socket.end();
    },
    async (pipePath) => {
      let clientSocket = null;
      const result = await readCodeFromPipe(pipePath, {
        connect(target) {
          clientSocket = net.connect(target);
          return clientSocket;
        },
      });
      assert.equal(result.ok, false);
      assert.equal(result.reason, 'empty');
      assert.equal(clientSocket.destroyed, true);
    },
  );

  // 5. On connect_failed
  {
    const missingPipe = temporaryPipePath();
    let clientSocket = null;
    const result = await readCodeFromPipe(missingPipe, {
      timeoutMs: 500,
      connect(target) {
        clientSocket = net.connect(target);
        return clientSocket;
      },
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'connect_failed');
    assert.equal(clientSocket.destroyed, true);
  }
});

test('synchronous connect error resolves as connect_failed', async () => {
  const result = await readCodeFromPipe('invalid-path', {
    connect() {
      throw new Error('sync connect error');
    },
  });
  assert.deepEqual(result, { ok: false, code: null, reason: 'connect_failed' });
});

test('a control character in the code is refused as control_character', async () => {
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE.slice(0, 4)}\u0000${CODE.slice(4)}\n`);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'control_character' });
    },
  );
});

test('trailing data after the terminating newline is refused as trailing_data', async () => {
  await withPipeServer(
    (socket) => {
      socket.write(`${CODE}\nextra`);
    },
    async (pipePath) => {
      const result = await readCodeFromPipe(pipePath, { connect: testConnect });
      assert.deepEqual(result, { ok: false, code: null, reason: 'trailing_data' });
    },
  );
});

const HEX_32 = '0123456789abcdef0123456789abcdef';

test('without an injected connect, 127.0.0.1:80 is refused with bad_pipe and nothing connects', async () => {
  let connectCalls = 0;
  const originalConnect = net.connect;
  net.connect = (...args) => {
    connectCalls += 1;
    return originalConnect(...args);
  };
  try {
    const result = await readCodeFromPipe('127.0.0.1:80');
    assert.deepEqual(result, { ok: false, code: null, reason: 'bad_pipe' });
    assert.equal(connectCalls, 0);
  } finally {
    net.connect = originalConnect;
  }
});

test('without an injected connect, //./pipe/rongroi-launch-<32 hex> is refused with bad_pipe and nothing connects', async () => {
  let connectCalls = 0;
  const originalConnect = net.connect;
  net.connect = (...args) => {
    connectCalls += 1;
    return originalConnect(...args);
  };
  try {
    const result = await readCodeFromPipe(`//./pipe/rongroi-launch-${HEX_32}`);
    assert.deepEqual(result, { ok: false, code: null, reason: 'bad_pipe' });
    assert.equal(connectCalls, 0);
  } finally {
    net.connect = originalConnect;
  }
});

test('without an injected connect, an upper-case hex name is refused with bad_pipe and nothing connects', async () => {
  let connectCalls = 0;
  const originalConnect = net.connect;
  net.connect = (...args) => {
    connectCalls += 1;
    return originalConnect(...args);
  };
  try {
    const result = await readCodeFromPipe(`\\\\.\\pipe\\rongroi-launch-${HEX_32.toUpperCase()}`);
    assert.deepEqual(result, { ok: false, code: null, reason: 'bad_pipe' });
    assert.equal(connectCalls, 0);
  } finally {
    net.connect = originalConnect;
  }
});

test('without an injected connect, a 31-hex name is refused with bad_pipe and nothing connects', async () => {
  let connectCalls = 0;
  const originalConnect = net.connect;
  net.connect = (...args) => {
    connectCalls += 1;
    return originalConnect(...args);
  };
  try {
    const result = await readCodeFromPipe(`\\\\.\\pipe\\rongroi-launch-${HEX_32.slice(0, 31)}`);
    assert.deepEqual(result, { ok: false, code: null, reason: 'bad_pipe' });
    assert.equal(connectCalls, 0);
  } finally {
    net.connect = originalConnect;
  }
});

test('without an injected connect, a valid pipe connects with net.connect({ path: pipePath })', async () => {
  let capturedOptions = null;
  const originalConnect = net.connect;
  const validPipe = `\\\\.\\pipe\\rongroi-launch-${HEX_32}`;

  const { EventEmitter } = require('node:events');
  const fakeSocket = new EventEmitter();
  fakeSocket.destroy = () => {};
  fakeSocket.connecting = true;

  net.connect = (options) => {
    capturedOptions = options;
    return fakeSocket;
  };

  try {
    const promise = readCodeFromPipe(validPipe, { timeoutMs: 20 });
    assert.deepEqual(capturedOptions, { path: validPipe });
    await promise;
  } finally {
    net.connect = originalConnect;
  }
});
