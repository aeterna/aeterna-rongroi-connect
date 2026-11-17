// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const keep = require('../src/renderer/keep-state.js');

function el(tagName, props) {
  const attrs = (props && props.attrs) || {};
  return Object.assign({
    tagName,
    scrollTop: 0,
    getAttribute: (name) => (name in attrs ? attrs[name] : null),
    focus() { this.doc.activeElement = this; },
  }, props);
}

// A fake document: #app holds `children` (flat list, document order).
function fakeDoc(children, top, appTop) {
  const app = { scrollTop: appTop || 0 };
  const doc = {
    app,
    activeElement: null,
    scrollingElement: { scrollTop: top || 0 },
    getElementById: () => app,
  };
  children.forEach((c) => { c.doc = doc; });
  app.contains = (node) => children.includes(node);
  app.querySelectorAll = (sel) => {
    const m = /^\[data-action="(.*)"\]$/.exec(sel);
    if (m) return children.filter((c) => c.getAttribute('data-action') === m[1]);
    if (sel === 'details pre') return children.filter((c) => c.tagName === 'PRE');
    return children.filter((c) => c.tagName.toLowerCase() === sel);
  };
  return doc;
}

const details = (open) => el('DETAILS', { open });

test('same state name (hash) keeps opened details and scroll', () => {
  const before = fakeDoc([details(false), details(true)], 120, 30);
  const snap = keep.capture(before, 'hash');
  const afterKids = [details(false), details(false)];
  const after = fakeDoc(afterKids, 0, 0);
  keep.restore(after, snap, 'hash');
  assert.deepEqual(afterKids.map((d) => d.open), [false, true]);
  assert.equal(after.scrollingElement.scrollTop, 120);
  assert.equal(after.app.scrollTop, 30);
});

test('changed state name leaves details closed and scroll alone', () => {
  const snap = keep.capture(fakeDoc([details(true)], 120, 30), 'consent');
  const kids = [details(false)];
  const after = fakeDoc(kids, 0, 0);
  keep.restore(after, snap, 'scanning');
  assert.equal(kids[0].open, false);
  assert.equal(after.scrollingElement.scrollTop, 0);
  assert.equal(after.app.scrollTop, 0);
});

test('extra details in the new tree stay closed; missing ones are ignored', () => {
  const snap = keep.capture(fakeDoc([details(true), details(true)]), 'consent');
  const kids = [details(false)];
  keep.restore(fakeDoc(kids), snap, 'consent');
  assert.equal(kids[0].open, true);
});

test('no snapshot is a no-op', () => {
  const kids = [details(false)];
  const after = fakeDoc(kids, 5, 0);
  keep.restore(after, null, 'consent');
  assert.equal(kids[0].open, false);
  assert.equal(after.scrollingElement.scrollTop, 5);
});

test('inner pre scroll is kept on the same state, dropped on a change', () => {
  const before = fakeDoc([details(true), el('PRE', { scrollTop: 77 })]);
  const snap = keep.capture(before, 'consent');
  const pre = el('PRE');
  keep.restore(fakeDoc([details(false), pre]), snap, 'consent');
  assert.equal(pre.scrollTop, 77);
  const pre2 = el('PRE');
  keep.restore(fakeDoc([details(false), pre2]), snap, 'hash');
  assert.equal(pre2.scrollTop, 0);
});

test('focus returns to the element with the same data-action', () => {
  const btn = el('BUTTON', { attrs: { 'data-action': 'decline' } });
  const before = fakeDoc([el('BUTTON', { attrs: { 'data-action': 'consent' } }), btn]);
  before.activeElement = btn;
  const snap = keep.capture(before, 'consent');
  const a = el('BUTTON', { attrs: { 'data-action': 'consent' } });
  const b = el('BUTTON', { attrs: { 'data-action': 'decline' } });
  const after = fakeDoc([a, b]);
  keep.restore(after, snap, 'consent');
  assert.equal(after.activeElement, b);
});

test('focus falls back to tag plus index; not restored on a state change or outside #app', () => {
  const second = el('A');
  const before = fakeDoc([el('A'), second]);
  before.activeElement = second;
  const snap = keep.capture(before, 'consent');
  const kids = [el('A'), el('A')];
  const after = fakeDoc(kids);
  keep.restore(after, snap, 'consent');
  assert.equal(after.activeElement, kids[1]);

  const other = fakeDoc([el('A'), el('A')]);
  keep.restore(other, snap, 'hash');
  assert.equal(other.activeElement, null);

  const outside = fakeDoc([el('A')]);
  outside.activeElement = el('INPUT');
  assert.equal(keep.capture(outside, 'consent').focus, null);
});
