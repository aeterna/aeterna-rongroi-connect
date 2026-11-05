// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('connect', {
  submitCode(code) {
    return ipcRenderer.invoke('connect:submitCode', code);
  },
  consent() {
    return ipcRenderer.invoke('connect:consent');
  },
  decline() {
    return ipcRenderer.invoke('connect:decline');
  },
  send() {
    return ipcRenderer.invoke('connect:send');
  },
  retry() {
    return ipcRenderer.invoke('connect:retry');
  },
  quit() {
    return ipcRenderer.invoke('connect:quit');
  },
  onState(callback) {
    if (typeof callback !== 'function') return () => {};
    const listener = (event, state) => callback(state);
    ipcRenderer.on('connect:state', listener);
    return () => ipcRenderer.removeListener('connect:state', listener);
  },
});
