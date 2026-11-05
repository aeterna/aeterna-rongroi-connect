// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
(function (root) {
  'use strict';

  var ERROR_KEYS = [
    'bad_code',
    'bad_origin',
    'policy_mismatch',
    'unknown_ticket',
    'expired',
    'ticket_used',
    'too_large',
    'redirect_refused',
    'network',
    'timeout',
    'server_error',
    'sidecar_failed',
    'record_refused',
    'internal',
  ];

  function element(tag, attrs, children) {
    var list = children || [];
    var onlyText = list.length > 0;
    for (var index = 0; index < list.length; index += 1) {
      if (list[index] && list[index].tag !== null && list[index].tag !== undefined) {
        onlyText = false;
        break;
      }
    }
    if (onlyText) {
      return {
        tag: tag,
        attrs: attrs || {},
        text: list.map(function (child) {
          return child && child.text !== null && child.text !== undefined
            ? String(child.text)
            : '';
        }).join(''),
        children: [],
      };
    }
    return {
      tag: tag,
      attrs: attrs || {},
      text: null,
      children: list,
    };
  }

  function textNode(value) {
    return {
      tag: null,
      attrs: {},
      text: value === null || value === undefined ? '' : String(value),
      children: [],
    };
  }

  function formatCountdown(value) {
    var total = Number(value);
    if (!Number.isFinite(total) || total < 0) total = 0;
    total = Math.floor(total);
    var minutes = Math.floor(total / 60);
    var seconds = total % 60;
    return String(minutes) + ':' + String(seconds).padStart(2, '0');
  }

  function groupHash(value) {
    var hash = value === null || value === undefined ? '' : String(value);
    var groups = [];
    for (var index = 0; index < hash.length; index += 4) {
      groups.push(hash.slice(index, index + 4));
    }
    return groups.join(' ');
  }

  // The server decides which collectors to require, so it may name one that
  // this build has no sentence for. Show the id in that case rather than hide
  // the collector from the consent list.
  function collectorName(t, collector) {
    var id = collector === null || collector === undefined ? '' : String(collector);
    var key = 'collector.' + id;
    var name = null;
    try {
      name = t(key);
    } catch (error) {
      name = null;
    }
    if (name === null || name === undefined || String(name) === ''
        || String(name) === key) {
      return id;
    }
    return String(name);
  }

  function button(t, action, label, variant) {
    var classes = variant === 'primary'
      ? 'button button-primary'
      : variant === 'quiet'
        ? 'button button-quiet'
        : 'button button-secondary';
    return element('button', {
      type: 'button',
      class: classes,
      'data-action': action,
    }, [textNode(label)]);
  }

  function actions(children) {
    return element('div', { class: 'actions' }, children);
  }

  function title(t, key, params) {
    return element('h1', { class: 'title' }, [textNode(t(key, params))]);
  }

  function screen(state, children) {
    var name = state && state.name ? String(state.name) : 'error';
    return element('section', {
      class: 'screen screen-' + name,
      'data-state': name,
    }, children);
  }

  function countdown(t, state) {
    return element('p', { class: 'countdown' }, [
      textNode(t('common.countdown', { time: formatCountdown(state.secondsLeft) })),
    ]);
  }

  function renderPaste(state, t) {
    var input = element('input', {
      id: 'pairing-code',
      name: 'code',
      type: 'text',
      class: 'input',
      autocomplete: 'off',
      autocapitalize: 'none',
      spellcheck: 'false',
      placeholder: t('paste.placeholder'),
      'aria-describedby': 'paste-warning',
    });
    var label = element('label', { class: 'field', for: 'pairing-code' }, [
      element('span', { class: 'field-label' }, [textNode(t('paste.label'))]),
      input,
    ]);
    return screen(state, [
      title(t, 'paste.title'),
      label,
      element('p', { id: 'paste-warning', class: 'hint' }, [
        textNode(t('paste.warning')),
      ]),
      actions([
        button(t, 'submit', t('common.continue'), 'primary'),
        button(t, 'quit', t('common.quit'), 'quiet'),
      ]),
    ]);
  }

  function renderChecking(state, t) {
    return screen(state, [
      title(t, 'checking.contacting', { origin: state.serverOrigin }),
      actions([
        button(t, 'quit', t('common.quit'), 'quiet'),
      ]),
    ]);
  }

  function renderConsent(state, t) {
    var collectors = Array.isArray(state.collectors) ? state.collectors : [];
    var children = [
      element('p', { class: 'eyebrow' }, [textNode(t('consent.origin'))]),
      element('p', { class: 'origin' }, [textNode(state.serverOrigin)]),
      element('p', { class: 'lede' }, [
        textNode(t('consent.serverCallsItself', { name: state.serverName })),
      ]),
      element('h2', { class: 'subsection' }, [textNode(t('consent.collectors'))]),
      element('ul', { class: 'collectors' }, collectors.map(function (collector) {
        return element('li', {}, [textNode(collectorName(t, collector))]);
      })),
      element('p', { class: 'lede' }, [
        textNode(state.elevation ? t('consent.elevationYes') : t('consent.elevationNo')),
      ]),
      countdown(t, state),
    ];

    if (state.localAddress) {
      children.push(element('p', { class: 'warning' }, [
        textNode(t('consent.localAddress')),
      ]));
    }

    children.push(actions([
      button(t, 'consent', t('common.scan'), 'primary'),
      button(t, 'decline', t('consent.decline'), 'quiet'),
      button(t, 'quit', t('common.quit'), 'quiet'),
    ]));
    return screen(state, children);
  }

  function renderScanning(state, t) {
    return screen(state, [
      title(t, state.elevationPending ? 'scanning.elevationPending' : 'scanning.title'),
      countdown(t, state),
      actions([
        button(t, 'quit', t('common.quit'), 'quiet'),
      ]),
    ]);
  }

  function renderHash(state, t) {
    return screen(state, [
      element('p', { class: 'eyebrow hash-label' }, [textNode(t('hash.label'))]),
      element('h1', { class: 'hash' }, [textNode(groupHash(state.visualHash))]),
      element('p', { class: 'hint hash-hint' }, [textNode(t('hash.hint'))]),
      element('details', { class: 'record' }, [
        element('summary', {}, [textNode(t('hash.see'))]),
        element('pre', { class: 'record-text' }, [textNode(state.recordText)]),
      ]),
      countdown(t, state),
      actions([
        button(t, 'send', t('common.send'), 'primary'),
        button(t, 'quit', t('common.quit'), 'quiet'),
      ]),
    ]);
  }

  function renderUploading(state, t) {
    var progress = state.progress;
    var message = progress
      ? t('uploading.progress', { done: progress.done, total: progress.total })
      : t('uploading.sentence');
    return screen(state, [
      element('p', { class: 'status' }, [textNode(message)]),
    ]);
  }

  function renderDone(state, t) {
    return screen(state, [
      element('p', { class: 'lede' }, [
        textNode(t('done.sent', { origin: state.serverOrigin, hash: state.visualHash })),
      ]),
      actions([
        button(t, 'quit', t('common.quit'), 'quiet'),
      ]),
    ]);
  }

  function renderDeclined(state, t) {
    return screen(state, [
      element('p', { class: 'lede' }, [
        textNode(t('declined.message', { origin: state.serverOrigin })),
      ]),
      actions([
        button(t, 'quit', t('common.quit'), 'quiet'),
      ]),
    ]);
  }

  function renderError(state, t) {
    var error = state.error || {};
    var key = ERROR_KEYS.indexOf(error.key) === -1 ? 'internal' : error.key;
    var children = [
      title(t, 'error.title'),
      element('p', { class: 'lede' }, [textNode(t('error.' + key))]),
      element('p', { class: 'hint' }, [
        textNode(error.sent === true ? t('error.sentYes') : t('error.sentNo')),
      ]),
    ];
    var buttons = [];
    if (state.canRetry) {
      buttons.push(button(t, 'send', t('common.tryAgain'), 'primary'));
    }
    buttons.push(button(t, 'quit', t('common.quit'), 'quiet'));
    children.push(actions(buttons));
    return screen(state, children);
  }

  function render(state, t) {
    var safeState = state || { name: 'error' };
    switch (safeState.name) {
      case 'paste':
        return renderPaste(safeState, t);
      case 'checking':
        return renderChecking(safeState, t);
      case 'consent':
        return renderConsent(safeState, t);
      case 'scanning':
        return renderScanning(safeState, t);
      case 'hash':
        return renderHash(safeState, t);
      case 'uploading':
        return renderUploading(safeState, t);
      case 'done':
        return renderDone(safeState, t);
      case 'declined':
        return renderDeclined(safeState, t);
      case 'error':
      default:
        return renderError(safeState, t);
    }
  }

  render.render = render;
  render.formatCountdown = formatCountdown;
  render.groupHash = groupHash;
  render.errorKeys = ERROR_KEYS.slice();

  root.render = render;
  root.formatCountdown = formatCountdown;
  root.groupHash = groupHash;
  root.RongroiView = render;

  if (typeof module === 'object' && module.exports) {
    module.exports = render;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this));
