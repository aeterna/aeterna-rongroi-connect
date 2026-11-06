// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

// The collector ids this client build knows how to name.  They are the
// `collector.*` keys in src/locales/en.json.  A policy that asks for anything
// else is refused before the consent screen, because the player could not be
// told what the scan would collect.
const KNOWN_COLLECTORS = Object.freeze([
  'posture',
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
]);

module.exports = {
  KNOWN_COLLECTORS,
};
