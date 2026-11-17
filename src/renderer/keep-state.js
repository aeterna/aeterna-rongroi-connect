// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
(function (root) {
  'use strict';

  // Keeps <details> open state, scroll positions and keyboard focus across a
  // re-render of the same screen (the flow pushes state every second for the
  // countdown). Everything is matched by document order inside #app.

  var SCROLLERS = 'details pre';

  function each(list, fn) {
    for (var i = 0; i < list.length; i += 1) fn(list[i], i);
  }

  function describeFocus(app, active) {
    if (!active || !app.contains(active)) return null;
    var action = active.getAttribute('data-action');
    if (action) return { action: action };
    var tag = String(active.tagName).toLowerCase();
    var same = app.querySelectorAll(tag);
    for (var i = 0; i < same.length; i += 1) {
      if (same[i] === active) return { tag: tag, index: i };
    }
    return null;
  }

  function capture(doc, name) {
    var app = doc.getElementById('app');
    var snap = { name: name, open: [], scrolls: [], top: 0, appTop: 0, focus: null };
    if (doc.scrollingElement) snap.top = doc.scrollingElement.scrollTop;
    if (!app) return snap;
    snap.appTop = app.scrollTop;
    each(app.querySelectorAll('details'), function (d) { snap.open.push(Boolean(d.open)); });
    each(app.querySelectorAll(SCROLLERS), function (p) { snap.scrolls.push(p.scrollTop); });
    snap.focus = describeFocus(app, doc.activeElement);
    return snap;
  }

  function restore(doc, snap, name) {
    var app = doc.getElementById('app');
    if (!snap || snap.name !== name || !app) return;
    each(app.querySelectorAll('details'), function (d, i) {
      if (i < snap.open.length) d.open = snap.open[i];
    });
    if (doc.scrollingElement) doc.scrollingElement.scrollTop = snap.top;
    app.scrollTop = snap.appTop;
    each(app.querySelectorAll(SCROLLERS), function (p, i) {
      if (i < snap.scrolls.length) p.scrollTop = snap.scrolls[i];
    });
    var f = snap.focus;
    if (f) {
      var hit = f.action
        ? app.querySelectorAll('[data-action="' + f.action + '"]')[0]
        : app.querySelectorAll(f.tag)[f.index];
      if (hit && typeof hit.focus === 'function') hit.focus();
    }
  }

  var api = { capture: capture, restore: restore };
  root.RongroiKeep = api;

  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this));
