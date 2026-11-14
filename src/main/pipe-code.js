// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// eslint-disable-next-line no-restricted-syntax
const net = require('node:net');
const { readCodeFromStream, DEFAULT_TIMEOUT_MS } = require('./stdin-code');

function refusal(reason) {
  return { ok: false, code: null, reason };
}

function readCodeFromPipe(pipePath, options = {}) {
  const requested = typeof options.timeoutMs === 'number' && Number.isFinite(options.timeoutMs)
    ? options.timeoutMs
    : DEFAULT_TIMEOUT_MS;
  const timeoutMs = requested >= 0 ? requested : DEFAULT_TIMEOUT_MS;
  const scheduleTimeout = typeof options.setTimeout === 'function'
    ? options.setTimeout
    : setTimeout;
  const cancelTimeout = typeof options.clearTimeout === 'function'
    ? options.clearTimeout
    : clearTimeout;
  const connectFn = typeof options.connect === 'function'
    ? options.connect
    : (target) => net.connect(target);
  const now = typeof options.now === 'function'
    ? options.now
    : Date.now;

  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    let socket = null;
    const startTime = now();

    function finish(result) {
      if (settled) return;
      settled = true;
      if (timer !== null) {
        cancelTimeout(timer);
        timer = null;
      }
      if (socket !== null) {
        try {
          socket.on('error', () => {});
          socket.destroy();
        } catch {
          // destroying the socket is cleanup on every path
        }
      }
      resolve(result);
    }

    if (timeoutMs === 0) {
      finish(refusal('timeout'));
      return;
    }

    if (timeoutMs > 0) {
      timer = scheduleTimeout(() => {
        timer = null;
        finish(refusal('timeout'));
      }, timeoutMs);
      if (timer !== null && typeof timer.unref === 'function') {
        timer.unref();
      }
    }

    try {
      socket = connectFn(pipePath);
    } catch {
      finish(refusal('connect_failed'));
      return;
    }

    if (!socket || typeof socket.on !== 'function') {
      finish(refusal('connect_failed'));
      return;
    }

    if (socket.destroyed) {
      finish(refusal('connect_failed'));
      return;
    }

    function cleanupConnect() {
      socket.removeListener('connect', onConnect);
      socket.removeListener('error', onConnectError);
      socket.removeListener('close', onConnectClose);
    }

    function onConnectError() {
      cleanupConnect();
      finish(refusal('connect_failed'));
    }

    function onConnectClose() {
      cleanupConnect();
      finish(refusal('connect_failed'));
    }

    function onConnect() {
      cleanupConnect();
      if (settled) return;

      const elapsed = now() - startTime;
      const remaining = timeoutMs - elapsed;
      if (remaining <= 0) {
        finish(refusal('timeout'));
        return;
      }

      try {
        const pending = readCodeFromStream(socket, {
          ...options,
          timeoutMs: remaining,
        });
        pending.then(
          (result) => finish(result),
          () => finish(refusal('read_error')),
        );
      } catch {
        finish(refusal('read_error'));
      }
    }

    if (socket.connecting === false) {
      onConnect();
    } else {
      socket.on('connect', onConnect);
      socket.on('error', onConnectError);
      socket.on('close', onConnectClose);
    }
  });
}

module.exports = {
  readCodeFromPipe,
  DEFAULT_TIMEOUT_MS,
};
