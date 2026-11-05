// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
(function () {
  'use strict';

  // The page CSP allows scripts only from the app itself and denies all
  // network and data URLs, so the locale files are mirrored here.
  var MESSAGES = {
    en: {
      "app.title": "Rongroi Connect",
      "common.quit": "Quit",
      "common.continue": "Continue",
      "common.scan": "Scan",
      "common.send": "Send",
      "common.tryAgain": "Try again",
      "common.countdown": "{time} left",
      "paste.title": "Paste your code",
      "paste.label": "Code",
      "paste.placeholder": "rr1....",
      "paste.warning": "Only paste a code shown to you inside the game",
      "checking.contacting": "Contacting {origin}",
      "consent.origin": "Server address",
      "consent.serverCallsItself": "The server calls itself {name}",
      "consent.collectors": "Collectors this server requires",
      "consent.elevationYes": "Windows will ask for administrator rights",
      "consent.elevationNo": "Windows will not ask for administrator rights",
      "consent.localAddress": "This is a local address. Only continue if you trust this server.",
      "consent.decline": "Decline and tell the server",
      "collector.posture": "Security settings of this PC",
      "collector.powershell_text": "PowerShell's commands, as kinds of words",
      "collector.driver_service": "Drivers registered with Windows",
      "collector.antivirus_product": "Antivirus products Windows lists",
      "collector.autostart": "Programs that start by themselves (services, Run, scheduled tasks)",
      "collector.defender_exclusion": "Microsoft Defender exclusions",
      "collector.fivem_dir": "FiveM files",
      "collector.net_config": "Network settings (hosts, proxy, firewall)",
      "collector.os_image": "What Windows says this installation is",
      "collector.install_marker": "Places a Windows modification installs",
      "collector.process": "Running programs",
      "collector.evtx": "Windows event logs",
      "collector.prefetch": "Windows Prefetch",
      "collector.bam": "Background Activity Moderator (BAM)",
      "collector.pca": "Program Compatibility Assistant",
      "collector.userassist": "Programs opened through the Windows shell (UserAssist)",
      "collector.pci_device": "PCI devices Windows remembers",
      "collector.hid_device": "Mice, keyboards and other input devices Windows remembers",
      "collector.windows_start": "How Windows started",
      "collector.event_fields": "Service installs, clock changes and refused files from the event logs",
      "collector.usn": "NTFS change journal",
      "collector.fivem_servers": "FiveM server cache folders (full scan)",
      "collector.recorded_files": "Files of programs Windows recorded (full scan)",
      "scanning.title": "Scanning",
      "scanning.elevationPending": "Windows will ask for permission",
      "hash.label": "Code on this screen",
      "hash.hint": "Staff may ask you to read this out. Sending happens only when you press Send.",
      "hash.see": "See what will be sent",
      "uploading.sentence": "Sending the report to the server",
      "uploading.progress": "Uploading {done} of {total}",
      "done.sent": "Sent to {origin}. Code on this screen: {hash}.",
      "declined.message": "You declined. {origin} was told.",
      "error.title": "Something went wrong",
      "error.bad_code": "The code is not one this app can read.",
      "error.bad_origin": "The code points at an address this app cannot use.",
      "error.policy_mismatch": "The server policy does not match this code.",
      "error.unknown_ticket": "The server does not know this code.",
      "error.expired": "This code has expired. Ask staff for a new one.",
      "error.ticket_used": "This code was already used. Ask staff for a new one.",
      "error.too_large": "This report is too large for the server to accept.",
      "error.redirect_refused": "The server tried to send the request somewhere else. Nothing was sent.",
      "error.network": "The server could not be reached.",
      "error.timeout": "The server did not answer in time.",
      "error.server_error": "The server could not accept the request.",
      "error.sidecar_failed": "The scan program failed.",
      "error.record_refused": "The scanner report was not in the expected form.",
      "error.internal": "Something went wrong inside the app.",
      "error.sentYes": "The report was sent.",
      "error.sentNo": "Nothing was sent."
    },
    th: {
      "app.title": "Rongroi Connect",
      "common.quit": "ออก",
      "common.continue": "ดำเนินการต่อ",
      "common.scan": "Scan",
      "common.send": "ส่ง",
      "common.tryAgain": "ลองอีกครั้ง",
      "common.countdown": "เหลืออีก {time}",
      "paste.title": "วางโค้ดของคุณ",
      "paste.label": "โค้ด",
      "paste.placeholder": "rr1....",
      "paste.warning": "วางเฉพาะโค้ดที่แสดงให้คุณเห็นในเกม",
      "checking.contacting": "กำลังติดต่อ {origin}",
      "consent.origin": "ที่อยู่เซิร์ฟเวอร์",
      "consent.serverCallsItself": "เซิร์ฟเวอร์นี้เรียกตัวเองว่า {name}",
      "consent.collectors": "Collectors ที่เซิร์ฟเวอร์นี้ต้องการ",
      "consent.elevationYes": "Windows จะขอสิทธิ์ผู้ดูแลระบบ",
      "consent.elevationNo": "Windows จะไม่ขอสิทธิ์ผู้ดูแลระบบ",
      "consent.localAddress": "ที่อยู่นี้อยู่ในเครือข่ายท้องถิ่น ดำเนินการต่อเฉพาะเมื่อคุณไว้วางใจเซิร์ฟเวอร์นี้",
      "consent.decline": "ปฏิเสธและแจ้งเซิร์ฟเวอร์",
      "collector.posture": "การตั้งค่าความมั่นคงของเครื่อง",
      "collector.powershell_text": "คำสั่ง PowerShell เป็นชนิดของคำ",
      "collector.driver_service": "ไดรเวอร์ที่ลงทะเบียนไว้กับ Windows",
      "collector.antivirus_product": "โปรแกรมแอนตี้ไวรัสที่ Windows ระบุ",
      "collector.autostart": "โปรแกรมที่เริ่มทำงานเอง (service, Run, scheduled task)",
      "collector.defender_exclusion": "exclusion ของ Microsoft Defender",
      "collector.fivem_dir": "ไฟล์ของ FiveM",
      "collector.net_config": "การตั้งค่าเครือข่าย (hosts, proxy, firewall)",
      "collector.os_image": "Windows ตัวนี้บอกว่าตัวเองเป็นอะไร",
      "collector.install_marker": "ที่ที่โปรแกรมดัดแปลง Windows ติดตั้งไว้",
      "collector.process": "โปรแกรมที่กำลังรัน",
      "collector.evtx": "Event log ของ Windows",
      "collector.prefetch": "Prefetch ของ Windows",
      "collector.bam": "Background Activity Moderator (BAM)",
      "collector.pca": "Program Compatibility Assistant",
      "collector.userassist": "โปรแกรมที่เปิดด้วย shell ของ Windows (UserAssist)",
      "collector.pci_device": "อุปกรณ์ PCI ที่ Windows จำไว้",
      "collector.hid_device": "เมาส์ คีย์บอร์ด และอุปกรณ์อินพุตอื่นที่ Windows จำไว้",
      "collector.windows_start": "Windows เริ่มทำงานแบบไหน",
      "collector.event_fields": "การติดตั้ง service การเปลี่ยนนาฬิกา และไฟล์ที่ถูกปฏิเสธ จาก event log",
      "collector.usn": "บันทึกการเปลี่ยนแปลงไฟล์ของ NTFS (USN journal)",
      "collector.fivem_servers": "โฟลเดอร์ cache ของเซิร์ฟเวอร์ใน FiveM (สแกนแบบ Full)",
      "collector.recorded_files": "ไฟล์ของโปรแกรมที่ Windows บันทึกไว้ (สแกนแบบ Full)",
      "scanning.title": "กำลัง Scan",
      "scanning.elevationPending": "Windows จะขออนุญาต",
      "hash.label": "รหัสบนหน้าจอนี้",
      "hash.hint": "ทีมงานอาจขอให้อ่านรหัสนี้ให้ฟัง จะส่งก็ต่อเมื่อคุณกด Send เท่านั้น",
      "hash.see": "ดูสิ่งที่ถูกส่ง",
      "uploading.sentence": "กำลังส่งรายงานไปยังเซิร์ฟเวอร์",
      "uploading.progress": "กำลัง Upload {done} จาก {total}",
      "done.sent": "ส่งไปยัง {origin} แล้ว โค้ดบนหน้าจอนี้: {hash}",
      "declined.message": "คุณปฏิเสธแล้ว แจ้ง {origin} แล้ว",
      "error.title": "เกิดข้อผิดพลาด",
      "error.bad_code": "แอปนี้อ่านโค้ดนี้ไม่ได้",
      "error.bad_origin": "โค้ดนี้ชี้ไปยังที่อยู่ที่แอปนี้ใช้ไม่ได้",
      "error.policy_mismatch": "policy ของเซิร์ฟเวอร์ไม่ตรงกับโค้ดนี้",
      "error.unknown_ticket": "เซิร์ฟเวอร์ไม่รู้จักโค้ดนี้",
      "error.expired": "โค้ดนี้หมดอายุแล้ว ขอโค้ดใหม่จากทีมงาน",
      "error.ticket_used": "โค้ดนี้ถูกใช้ไปแล้ว ขอโค้ดใหม่จากทีมงาน",
      "error.too_large": "รายงานนี้ใหญ่เกินกว่าที่เซิร์ฟเวอร์จะรับได้",
      "error.redirect_refused": "เซิร์ฟเวอร์พยายามส่งคำขอไปที่อื่น ไม่มีอะไรถูกส่ง",
      "error.network": "ติดต่อเซิร์ฟเวอร์ไม่ได้",
      "error.timeout": "เซิร์ฟเวอร์ไม่ตอบภายในเวลา",
      "error.server_error": "เซิร์ฟเวอร์รับคำขอไม่ได้",
      "error.sidecar_failed": "โปรแกรม Scan ล้มเหลว",
      "error.record_refused": "รายงานจาก Scan ไม่อยู่ในรูปแบบที่คาดไว้",
      "error.internal": "เกิดข้อผิดพลาดภายในแอป",
      "error.sentYes": "รายงานถูกส่งแล้ว",
      "error.sentNo": "ไม่มีอะไรถูกส่ง"
    }
  };

  function chooseLanguage() {
    var tag = typeof navigator !== 'undefined' && navigator.language
      ? String(navigator.language)
      : 'en';
    return /^th([-_]|$)/i.test(tag) ? 'th' : 'en';
  }

  var language = chooseLanguage();
  var messages = MESSAGES[language];

  function t(key, params) {
    var template = Object.prototype.hasOwnProperty.call(messages, key)
      ? messages[key]
      : (MESSAGES.en[key] || key);
    return String(template).replace(/\{([a-z]+)\}/gi, function (match, name) {
      return params && Object.prototype.hasOwnProperty.call(params, name)
        ? String(params[name])
        : match;
    });
  }

  function build(node) {
    if (!node || typeof node !== 'object') {
      return document.createTextNode('');
    }
    if (node.tag === null || node.tag === undefined) {
      return document.createTextNode(node.text === null || node.text === undefined
        ? ''
        : String(node.text));
    }

    var element = document.createElement(node.tag);
    var attrs = node.attrs || {};
    Object.keys(attrs).forEach(function (name) {
      var value = attrs[name];
      if (value === null || value === undefined || value === false) return;
      element.setAttribute(name, String(value));
    });

    if (node.text !== null && node.text !== undefined && node.text !== '') {
      element.textContent = String(node.text);
    }
    (node.children || []).forEach(function (child) {
      element.appendChild(build(child));
    });
    return element;
  }

  function submitCode() {
    var input = document.getElementById('pairing-code');
    if (!input || typeof input.value !== 'string') return;
    window.connect.submitCode(input.value.trim());
  }

  function runAction(action) {
    if (action === 'submit') {
      submitCode();
    } else if (action === 'consent') {
      window.connect.consent();
    } else if (action === 'decline') {
      window.connect.decline();
    } else if (action === 'send') {
      window.connect.send();
    } else if (action === 'quit') {
      window.connect.quit();
    }
  }

  function draw(state) {
    var app = document.getElementById('app');
    if (!app || !window.RongroiView || typeof window.RongroiView.render !== 'function') {
      return;
    }

    var tree = window.RongroiView.render(state, t);
    app.textContent = '';
    app.appendChild(build(tree));

    if (state && state.name === 'paste') {
      var input = document.getElementById('pairing-code');
      if (input) input.focus();
    }
  }

  if (typeof document !== 'undefined') {
    document.addEventListener('click', function (event) {
      var target = event.target;
      if (!target || typeof target.closest !== 'function') return;
      var trigger = target.closest('[data-action]');
      if (!trigger) return;
      runAction(trigger.getAttribute('data-action'));
    });

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Enter') return;
      var target = event.target;
      if (target && target.id === 'pairing-code') {
        event.preventDefault();
        submitCode();
      }
    });

    document.documentElement.lang = language;
  }

  if (typeof window !== 'undefined' && window.connect
      && typeof window.connect.onState === 'function') {
    window.connect.onState(draw);
  }
}());
