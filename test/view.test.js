// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const view = require('../src/renderer/view.js');
const en = require('../src/locales/en.json');
const th = require('../src/locales/th.json');

const LOCALES = { en, th };
const ORIGIN = 'http://127.0.0.1:30120';
const HASH = '0123456789abcdef';
const RECORD = '{"binding":"example","policy":"posture"}';
const RESULT_WORDS = /verified|clean|passed|safe|ผ่าน|ปลอดภัย|สะอาด/i;
const COLLECTOR_IDS = [
  'posture',
  'powershell_text',
  'driver_service',
  'antivirus_product',
  'autostart',
  'defender_exclusion',
  'fivem_dir',
  'net_config',
  'os_image',
  'install_marker',
  'process',
  'evtx',
  'prefetch',
  'bam',
  'pca',
  'userassist',
  'pci_device',
  'hid_device',
  'windows_start',
  'event_fields',
  'usn',
  'fivem_servers',
  'recorded_files',
];

function makeT(messages) {
  return function t(key, params) {
    if (typeof key !== 'string' || !Object.prototype.hasOwnProperty.call(messages, key)) {
      throw new Error(`missing locale key: ${key}`);
    }
    return String(messages[key]).replace(/\{([a-z]+)\}/gi, function (match, name) {
      if (!params || !Object.prototype.hasOwnProperty.call(params, name)) {
        throw new Error(`missing locale parameter "${name}" for ${key}`);
      }
      return String(params[name]);
    });
  };
}

function walk(node, visit) {
  visit(node);
  for (const child of node.children || []) walk(child, visit);
}

function texts(node) {
  const found = [];
  walk(node, function (item) {
    if (item.text !== null && item.text !== undefined) found.push(String(item.text));
  });
  return found;
}

function flatText(node) {
  return texts(node).join('\n');
}

function find(node, predicate) {
  let found = null;
  walk(node, function (item) {
    if (found === null && predicate(item)) found = item;
  });
  return found;
}

function findAll(node, predicate) {
  const found = [];
  walk(node, function (item) {
    if (predicate(item)) found.push(item);
  });
  return found;
}

function buttons(node) {
  return findAll(node, function (item) {
    return item.tag === 'button';
  }).map(function (item) {
    return {
      action: item.attrs['data-action'],
      label: texts(item).join(' '),
      classes: item.attrs.class || '',
    };
  });
}

function primaryCount(node) {
  return buttons(node).filter(function (item) {
    return /\bbutton-primary\b/.test(item.classes);
  }).length;
}

const STATES = {
  paste() {
    return { name: 'paste' };
  },
  checking() {
    return { name: 'checking', serverOrigin: ORIGIN };
  },
  consent() {
    return {
      name: 'consent',
      serverOrigin: ORIGIN,
      serverName: 'Example City',
      collectors: ['posture', 'os_image'],
      elevation: true,
      secondsLeft: 125,
      localAddress: true,
    };
  },
  scanning() {
    return { name: 'scanning', elevationPending: false, secondsLeft: 74 };
  },
  'scanning pending'() {
    return { name: 'scanning', elevationPending: true, secondsLeft: 74 };
  },
  hash() {
    return {
      name: 'hash',
      visualHash: HASH,
      recordText: RECORD,
      secondsLeft: 60,
    };
  },
  uploading() {
    return { name: 'uploading', progress: { done: 2, total: 5 } };
  },
  'uploading without progress'() {
    return { name: 'uploading', progress: null };
  },
  done() {
    return { name: 'done', serverOrigin: ORIGIN, visualHash: HASH };
  },
  declined() {
    return { name: 'declined', serverOrigin: ORIGIN };
  },
  error() {
    return {
      name: 'error',
      error: { key: 'network', sent: false },
      canRetry: false,
    };
  },
};

test('English and Thai locale files carry exactly the same keys', function () {
  assert.deepEqual(Object.keys(en).sort(), Object.keys(th).sort());
});

test('no locale string carries a verdict or a result word', function () {
  for (const [name, messages] of Object.entries(LOCALES)) {
    for (const [key, value] of Object.entries(messages)) {
      assert.equal(
        RESULT_WORDS.test(value),
        false,
        `${name}.${key} contains a forbidden result word: ${value}`,
      );
    }
  }
});

test('every state renders in both locales without a missing key', function () {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const t = makeT(messages);
    for (const [label, factory] of Object.entries(STATES)) {
      const state = factory();
      const tree = view.render(state, t);
      assert.equal(tree.attrs['data-state'], state.name, `${locale}: ${label}`);
      assert.equal(tree.tag, 'section', `${locale}: ${label}`);
      assert.equal(RESULT_WORDS.test(flatText(tree)), false, `${locale}: ${label} has a result word`);
    }
  }
});

test('every error key renders in both locales without a missing key', function () {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const t = makeT(messages);
    for (const key of view.errorKeys) {
      const state = {
        name: 'error',
        error: { key, sent: false },
        canRetry: true,
      };
      const tree = view.render(state, t);
      assert.match(flatText(tree), new RegExp(
        String(messages['error.' + key]).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
      ), `${locale}: ${key}`);
    }
  }
});

test('render is exported to module.exports and globalThis', function () {
  assert.equal(typeof view.render, 'function');
  assert.equal(typeof globalThis.render, 'function');
  assert.equal(globalThis.render, view.render);
});

test('paste shows a code field, the paste warning, continue and quit', function () {
  const tree = view.render(STATES.paste(), makeT(en));
  const input = find(tree, function (node) { return node.tag === 'input'; });
  assert.ok(input, 'paste state has a text field');
  assert.equal(input.attrs.type, 'text');
  assert.equal(input.attrs.id, 'pairing-code');
  assert.match(flatText(tree), /Only paste a code shown to you inside the game/);
  assert.deepEqual(buttons(tree).map(function (item) { return item.action; }), ['submit', 'quit']);
  assert.deepEqual(buttons(tree).map(function (item) { return item.label; }), [
    en['common.continue'],
    en['common.quit'],
  ]);
  assert.equal(primaryCount(tree), 1);
});

test('checking names the origin and offers only quit', function () {
  const tree = view.render(STATES.checking(), makeT(en));
  assert.match(flatText(tree), new RegExp(`Contacting ${ORIGIN}`));
  assert.deepEqual(buttons(tree).map(function (item) { return item.action; }), ['quit']);
  assert.equal(primaryCount(tree), 0);
});

test('consent shows the origin large, the server name as text, collectors and countdown', function () {
  const tree = view.render(STATES.consent(), makeT(en));
  const origin = find(tree, function (node) {
    return node.tag === 'p' && /\borigin\b/.test(node.attrs.class || '');
  });
  assert.ok(origin, 'consent has an origin block');
  assert.equal(origin.text, ORIGIN);

  assert.match(flatText(tree), new RegExp(en['consent.serverCallsItself'].replace('{name}', 'Example City')));
  assert.match(flatText(tree), new RegExp(en['consent.collectors']));
  assert.match(flatText(tree), new RegExp('2:05'));

  const list = find(tree, function (node) { return node.tag === 'ul'; });
  assert.ok(list, 'collectors are a list');
  assert.deepEqual(
    list.children.map(function (item) { return texts(item).join(''); }),
    [en['collector.posture'], en['collector.os_image']],
  );

  assert.match(flatText(tree), new RegExp(en['consent.elevationYes']));
  assert.match(flatText(tree), new RegExp(en['consent.localAddress']));

  const all = buttons(tree);
  assert.deepEqual(all.map(function (item) { return item.action; }), ['consent', 'decline', 'quit']);
  assert.equal(all[1].label, en['consent.decline']);
  assert.equal(primaryCount(tree), 1);
  assert.equal(all[0].classes.includes('button-primary'), true);
});

test('consent omits the elevation sentence it does not apply and hides the local warning', function () {
  const state = {
    ...STATES.consent(),
    elevation: false,
    localAddress: false,
  };
  const tree = view.render(state, makeT(en));
  assert.match(flatText(tree), new RegExp(en['consent.elevationNo']));
  assert.equal(flatText(tree).includes(en['consent.localAddress']), false);
  assert.equal(find(tree, function (node) { return node.attrs.class === 'warning'; }), null);
});

test('both locales name every collector the server can ask for', function () {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    for (const id of COLLECTOR_IDS) {
      assert.equal(
        typeof messages['collector.' + id],
        'string',
        `${locale} is missing collector.${id}`,
      );
    }
  }
});

test('consent shows collector names, not ids, in both locales', function () {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const state = {
      ...STATES.consent(),
      collectors: ['antivirus_product'],
    };
    const tree = view.render(state, makeT(messages));
    const list = find(tree, function (node) { return node.tag === 'ul'; });
    assert.deepEqual(
      list.children.map(function (item) { return texts(item).join(''); }),
      [messages['collector.antivirus_product']],
      `${locale}: antivirus_product is shown by name`,
    );
    assert.equal(
      flatText(tree).includes('antivirus_product'),
      false,
      `${locale}: the raw antivirus_product id is not shown`,
    );
  }
});

test('consent shows an unknown collector id instead of hiding it', function () {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const state = {
      ...STATES.consent(),
      collectors: ['not_a_collector'],
    };
    const tree = view.render(state, makeT(messages));
    const list = find(tree, function (node) { return node.tag === 'ul'; });
    assert.deepEqual(
      list.children.map(function (item) { return texts(item).join(''); }),
      ['not_a_collector'],
      `${locale}: an unknown collector is not hidden`,
    );
    assert.equal(flatText(tree).includes('collector.not_a_collector'), false);
  }
});

test('scanning uses the permission sentence while elevation is pending', function () {
  const waiting = view.render(STATES['scanning pending'](), makeT(en));
  assert.match(flatText(waiting), new RegExp(en['scanning.elevationPending']));
  assert.equal(flatText(waiting).includes(en['scanning.title']), false);
  assert.match(flatText(waiting), new RegExp('1:14'));
  assert.deepEqual(buttons(waiting).map(function (item) { return item.action; }), ['quit']);

  const scanning = view.render(STATES.scanning(), makeT(en));
  assert.match(flatText(scanning), new RegExp(en['scanning.title']));
  assert.equal(flatText(scanning).includes(en['scanning.elevationPending']), false);
  assert.match(flatText(scanning), new RegExp('1:14'));
});

test('hash is grouped 4x4 and the details panel holds the record as text', function () {
  const tree = view.render(STATES.hash(), makeT(en));
  const hash = find(tree, function (node) {
    return node.tag === 'h1' && /\bhash\b/.test(node.attrs.class || '');
  });
  assert.ok(hash, 'hash state has a large hash block');
  assert.equal(hash.text, '0123 4567 89ab cdef');

  const details = find(tree, function (node) { return node.tag === 'details'; });
  assert.ok(details, 'hash state has a details panel');
  const summary = find(details, function (node) { return node.tag === 'summary'; });
  assert.equal(texts(summary).join(''), en['hash.see']);
  const record = find(details, function (node) { return node.tag === 'pre'; });
  assert.equal(record.text, RECORD);

  assert.match(flatText(tree), new RegExp('1:00'));
  const all = buttons(tree);
  assert.deepEqual(all.map(function (item) { return item.action; }), ['send', 'quit']);
  assert.equal(primaryCount(tree), 1);
  assert.equal(all[0].classes.includes('button-primary'), true);
});

test('hash names the code above it and explains sending below it, in both locales', function () {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const tree = view.render(STATES.hash(), makeT(messages));
    const label = find(tree, function (node) {
      return node.tag === 'p' && node.text === messages['hash.label'];
    });
    const hint = find(tree, function (node) {
      return node.tag === 'p' && node.text === messages['hash.hint'];
    });
    const hash = find(tree, function (node) {
      return node.tag === 'h1' && /\bhash\b/.test(node.attrs.class || '');
    });
    assert.ok(label, `${locale}: hash has a label`);
    assert.ok(hint, `${locale}: hash has a hint`);
    assert.ok(hash, `${locale}: hash has the code block`);

    const order = [];
    walk(tree, function (node) {
      if (node === label) order.push('label');
      if (node === hash) order.push('hash');
      if (node === hint) order.push('hint');
    });
    assert.deepEqual(order, ['label', 'hash', 'hint'], `${locale}: label is above and hint below`);
  }
});

test('uploading shows progress when it has it and a sentence otherwise', function () {
  const withProgress = view.render(STATES.uploading(), makeT(en));
  assert.match(flatText(withProgress), new RegExp('Uploading 2 of 5'));
  assert.equal(buttons(withProgress).length, 0);

  const withoutProgress = view.render(STATES['uploading without progress'](), makeT(en));
  assert.match(flatText(withoutProgress), new RegExp(en['uploading.sentence']));
});

test('done and declined report the server outcome and offer quit only', function () {
  const done = view.render(STATES.done(), makeT(en));
  assert.match(flatText(done), new RegExp(
    `Sent to ${ORIGIN}\\. Code on this screen: ${HASH}\\.`,
  ));
  assert.deepEqual(buttons(done).map(function (item) { return item.action; }), ['quit']);

  const declined = view.render(STATES.declined(), makeT(en));
  assert.match(flatText(declined), new RegExp(`You declined\\. ${ORIGIN} was told\\.`));
  assert.deepEqual(buttons(declined).map(function (item) { return item.action; }), ['quit']);
});

test('error states say what failed and whether anything was sent', function () {
  const quiet = view.render({
    name: 'error',
    error: { key: 'network', sent: false },
    canRetry: false,
  }, makeT(en));
  assert.match(flatText(quiet), new RegExp(en['error.network']));
  assert.match(flatText(quiet), new RegExp(en['error.sentNo']));
  assert.deepEqual(buttons(quiet).map(function (item) { return item.action; }), ['quit']);
  assert.equal(primaryCount(quiet), 0);

  const retry = view.render({
    name: 'error',
    error: { key: 'network', sent: true },
    canRetry: true,
  }, makeT(en));
  assert.match(flatText(retry), new RegExp(en['error.sentYes']));
  assert.deepEqual(buttons(retry).map(function (item) { return item.action; }), ['send', 'quit']);
  assert.equal(buttons(retry)[0].label, en['common.tryAgain']);
  assert.equal(primaryCount(retry), 1);
});

test('unknown error keys fall back to the internal sentence', function () {
  const tree = view.render({
    name: 'error',
    error: { key: 'not_a_key', sent: false },
    canRetry: false,
  }, makeT(en));
  assert.match(flatText(tree), new RegExp(en['error.internal']));
  assert.equal(flatText(tree).includes('not_a_key'), false);
});

test('countdown formatting is m:ss and never goes below zero', function () {
  assert.equal(view.formatCountdown(125), '2:05');
  assert.equal(view.formatCountdown(74), '1:14');
  assert.equal(view.formatCountdown(9), '0:09');
  assert.equal(view.formatCountdown(0), '0:00');
  assert.equal(view.formatCountdown(-12), '0:00');
  assert.equal(view.formatCountdown(3600), '60:00');
  assert.equal(view.formatCountdown(65.9), '1:05');
  assert.equal(view.formatCountdown(undefined), '0:00');
});

test('hostile server strings stay text and never become markup', function () {
  const hostile = '<img src=x onerror=1>';
  const consent = view.render({
    ...STATES.consent(),
    serverName: hostile,
    collectors: [hostile],
    serverOrigin: hostile,
  }, makeT(en));
  const hash = view.render({
    ...STATES.hash(),
    visualHash: hostile,
    recordText: '<script>alert(1)</script>',
  }, makeT(en));

  assert.equal(flatText(consent).includes(hostile), true, 'the hostile name is shown as text');
  assert.equal(flatText(hash).includes('<script>alert(1)</script>'), true);

  for (const tree of [consent, hash]) {
    walk(tree, function (node) {
      assert.notEqual(node.tag, 'img');
      assert.notEqual(node.tag, 'script');
      assert.notEqual(node.tag, 'svg');
      for (const value of Object.values(node.attrs || {})) {
        assert.equal(String(value).includes('<img'), false, 'an attribute holds markup');
        assert.equal(String(value).includes('onerror'), false, 'an attribute holds an event handler');
        assert.equal(String(value).includes('<script'), false, 'an attribute holds a script');
      }
    });
  }
});

test('the page CSP, scripts and single app element match the renderer contract', function () {
  const html = fs.readFileSync(path.join(__dirname, '../src/renderer/index.html'), 'utf8');
  assert.match(html, /default-src 'none'; script-src 'self'; style-src 'self'/);
  assert.match(html, /<main id="app"><\/main>/);
  assert.equal((html.match(/<main/g) || []).length, 1);
  assert.equal((html.match(/<style/i) || []).length, 0);
  assert.equal((html.match(/\bstyle=/i) || []).length, 0);
  assert.match(html, /<link rel="stylesheet" href="style\.css">/);
  assert.match(html, /<script src="view\.js"><\/script>/);
  assert.match(html, /<script src="app\.js"><\/script>/);
  assert.equal((html.match(/<script(?![^>]*\bsrc=)[^>]*>/i) || []).length, 0);
});

test('app builds nodes without markup and chooses the locale from navigator.language', function () {
  const source = fs.readFileSync(path.join(__dirname, '../src/renderer/app.js'), 'utf8');
  assert.equal(source.includes('innerHTML'), false);
  assert.match(source, /document\.createElement/);
  assert.match(source, /textContent/);
  assert.match(source, /navigator\.language/);
  assert.match(source, /window\.connect\.onState/);
  assert.match(source, /window\.connect\.submitCode/);
  assert.match(source, /window\.connect\.consent/);
  assert.match(source, /window\.connect\.decline/);
  assert.match(source, /window\.connect\.send/);
  assert.match(source, /window\.connect\.quit/);
  assert.equal(/eval\s*\(|new Function/.test(source), false);
});

test('the app locale mirror carries the collector names and hash lines for both languages', function () {
  const source = fs.readFileSync(path.join(__dirname, '../src/renderer/app.js'), 'utf8');
  for (const id of COLLECTOR_IDS) {
    assert.equal(
      (source.match(new RegExp(`"collector.${id}":`, 'g')) || []).length,
      2,
      `app mirror is missing an en or th entry for collector.${id}`,
    );
  }
  for (const key of ['hash.label', 'hash.hint']) {
    const marker = `"${key}":`;
    assert.equal(
      source.split(marker).length - 1,
      2,
      `app mirror is missing an en or th entry for ${key}`,
    );
  }
});

test('the stylesheet keeps the product tokens, the Thai font stack and no motion', function () {
  const css = fs.readFileSync(path.join(__dirname, '../src/renderer/style.css'), 'utf8');
  const tokens = [
    '--sky-top: #b9e0ff;',
    '--sky-mid: #dcefff;',
    '--ground: #f3f9ff;',
    '--surface: #ffffffe6;',
    '--surface-solid: #ffffff;',
    '--raised: #eef5fd;',
    '--line: #d5e3f1;',
    '--line-strong: #b4cbe3;',
    '--text: #1d2a44;',
    '--muted: #4f5d77;',
    '--blue: #0869b0;',
    '--blue-soft: #e3f1fc;',
    '--navy: #1d2a44;',
    '--found: #a64b00;',
    '--found-ground: #fff3e3;',
    '--found-line: #f2c68f;',
    '--found-mark: #e6820e;',
    '--not-found: #636b7a;',
    '--unmeasured: #4655b8;',
    '--unmeasured-ground: #f0f2ff;',
    '--unmeasured-line: #b8c0ef;',
    '--danger-ground: #fdecec;',
    '--danger: #b42318;',
    '--display: "Mali", "Anuphan", "Leelawadee UI", system-ui, sans-serif;',
    '--mono: "Cascadia Mono", Consolas, ui-monospace, "SFMono-Regular", Menlo, monospace;',
    '--radius: 18px;',
    '--shadow: 0 10px 30px -14px #2a5d9a59;',
    '--panel-edge: inset 0 1px 0 #ffffffcc, inset 0 0 0 1px #ffffff66;',
  ];
  for (const token of tokens) assert.ok(css.includes(token), `missing token ${token}`);

  assert.ok(css.includes('font-family: "Segoe UI", "Leelawadee UI", system-ui, sans-serif;'));
  assert.ok(css.includes('font-family: ui-monospace, Consolas, monospace;'));
  assert.equal(/linear-gradient|radial-gradient/i.test(css), false);
  assert.equal(/@keyframes/i.test(css), false);
  assert.match(css, /prefers-reduced-motion: reduce/);
});
