// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// The window settings of ADR 0001 section 1. The caller adds `preload`.
const WEB_PREFERENCES = Object.freeze({
  sandbox: true,
  contextIsolation: true,
  nodeIntegration: false,
  webSecurity: true,
  spellcheck: false,
  webviewTag: false,
  devTools: false,
});

// ADR 0001 section 2 items 1 and 3, plus the shader cache switch of section 3.
const SWITCHES = Object.freeze([
  'no-proxy-server',
  'disable-background-networking',
  'disable-component-update',
  'disable-domain-reliability',
  'no-pings',
  'dns-prefetch-disable',
  'disable-gpu-shader-disk-cache',
]);

const SPELLCHECK_DICTIONARY_URL = 'http://127.0.0.1:9/';

function decodePath(pathname) {
  try {
    return decodeURIComponent(pathname);
  } catch {
    return null;
  }
}

// Split a path into segments and resolve `.` and `..` so an encoded trailing
// segment cannot climb out of the asar. Both separators compare the same.
function pathSegments(value) {
  const parts = String(value).replace(/\\/g, '/').split('/');
  const result = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      result.pop();
      continue;
    }
    result.push(part);
  }
  if (result.length > 0 && /^[A-Za-z]:$/.test(result[0])) {
    result[0] = result[0].toLowerCase();
  }
  return result;
}

function isInsideAsar(pathname, asarPath) {
  if (typeof asarPath !== 'string' || asarPath.length === 0) return false;
  const target = pathSegments(pathname);
  const base = pathSegments(asarPath);
  if (base.length === 0 || target.length < base.length) return false;
  for (let index = 0; index < base.length; index += 1) {
    if (target[index] !== base[index]) return false;
  }
  return true;
}

// Pure request gate. Network URLs are allowed only on the paired origin; file
// URLs only inside the app's own asar. Everything else, including a network
// request while there is no paired origin yet, is denied.
function decide(url, serverOrigin, asarPath) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  if (parsed.protocol === 'file:') {
    if (parsed.hostname !== '') return false;
    const decoded = decodePath(parsed.pathname);
    if (decoded === null) return false;
    return isInsideAsar(decoded, asarPath);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  if (serverOrigin === null || serverOrigin === undefined) return false;
  if (parsed.origin === 'null') return false;
  if (parsed.username !== '' || parsed.password !== '') return false;
  return parsed.origin === serverOrigin;
}

function applySwitches(app) {
  for (const name of SWITCHES) app.commandLine.appendSwitch(name);
  app.enableSandbox();
}

function lockSession(ses, getOrigin, asarPath) {
  ses.setSpellCheckerLanguages([]);
  ses.setSpellCheckerDictionaryDownloadURL(SPELLCHECK_DICTIONARY_URL);
  ses.setSpellCheckerEnabled(false);

  const onBeforeRequest = (details, callback) => {
    let origin = null;
    try {
      origin = getOrigin();
    } catch {
      origin = null;
    }
    callback({ cancel: !decide(details && details.url, origin, asarPath) });
  };
  if (ses.webRequest.onBeforeRequest.length >= 2) {
    ses.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, onBeforeRequest);
  } else {
    ses.webRequest.onBeforeRequest(onBeforeRequest);
  }

  ses.setPermissionRequestHandler((webContents, permission, callback) => {
    if (typeof callback === 'function') callback(false);
    return false;
  });
  ses.setPermissionCheckHandler(() => false);
}

function lockContents(app, isOwnPage) {
  app.on('web-contents-created', (event, contents) => {
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));

    contents.on('will-navigate', (navigationEvent, url) => {
      let own = false;
      try {
        own = Boolean(isOwnPage(url));
      } catch {
        own = false;
      }
      if (!own) navigationEvent.preventDefault();
    });

    contents.on('will-redirect', (redirectEvent) => {
      redirectEvent.preventDefault();
    });

    contents.on('will-attach-webview', (attachEvent) => {
      attachEvent.preventDefault();
    });
  });
}

module.exports = {
  WEB_PREFERENCES,
  SWITCHES,
  SPELLCHECK_DICTIONARY_URL,
  decide,
  applySwitches,
  lockSession,
  lockContents,
};
