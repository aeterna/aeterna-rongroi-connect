<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->
# ADR 0002 — Starting Connect from a launcher: the handoff contract (v1)

- Status: proposed — owner approved the direction 2026-11-13; becomes accepted when the K4 spike below passes
- Date: 2026-11-13 · Claude Code - Claude Opus 5.5
- Related: ADR 0001 (sections 2 and 4), the AETERNA Game Launcher (nakara-oss `launcher/`, its ADR 0002)

## Context

A game launcher (open source, MIT, and forkable by any server owner) can start Connect for the player instead of the
player opening Connect and pasting the code. Today Connect reads no command-line argument and no stdin
(`grep process.argv\|process.stdin src/` finds nothing), and its process exit code is 0 both when the server accepted a
report and when it accepted a declined answer (ADR 0001 section 4, `src/main/flow.js`).

A launcher is an **untrusted caller**. Anyone can build one, put any code in it, and start Connect with any arguments.
Nothing in this ADR may let a launcher do what a pasted code could not.

## Decision

1. **One way in.** Connect accepts exactly one argument, `--from-launcher`. With it, Connect reads one line from stdin:
   an `rr1.` pairing code, at most 4 KiB, ended by `\n` or EOF within 5 s. Any other argument, including Chromium
   switches such as `--remote-debugging-port`, `--inspect` or `--user-data-dir`, makes Connect exit **12** before a
   window opens. Without `--from-launcher` Connect behaves exactly as today (paste field).
2. **Same checks as a pasted code.** The code from stdin goes through the same validation as the paste field
   (ADR 0001 section 2: origin form, no userinfo or path, punycode, local-address warning, `policy_hash`). A refused
   code exits 12. The consent screen, the destination in large type, the policy and the hash screen are unchanged
   and need the player's own click. The launcher cannot pre-accept anything.
3. **Why stdin, not argv.** Other programs of the same user can read a process's command line. The code holds the
   single-use `ticket`; a ticket read from argv could be raced to the Kit first. stdin is visible only to the parent.
4. **Exit codes for the caller.** ADR 0001's table, plus one new code:

   | Code | Meaning |
   |---|---|
   | 0 | the server accepted a report |
   | **16** | **the server accepted a declined answer** (today this is 0) |
   | 10 | internal error |
   | 11 | the player closed Connect before anything was sent |
   | 12 | refused: an argument other than `--from-launcher`, or the code or policy |
   | 13 | the sidecar failed, its hash did not match, or it timed out |
   | 14 | the record was refused before upload |
   | 15 | the upload failed or the server refused it |

   Scripts that treat 0 as "something was sent" must also accept 16. The mock Kit and the e2e tests change with it.
5. **Nothing else crosses.** Connect writes nothing to stdout or stderr for the launcher, opens no socket to it and
   reads no file it names. The launcher learns only the exit code.
6. **The launcher's side** (recorded here so both repos agree): it starts a Connect exe it downloaded from a pinned
   release tag and checked against a signed manifest; it shows the same warning as the paste field ("only paste a code
   you got in this game") next to its own code field; it never retries a code by itself.

## K4 spike before acceptance (pass or fall back)

On pik-windows, with the fused, packaged release build (not `npm start`), started by a small Rust program through
`std::process::Command` with `stdin(Stdio::piped())`:
- the code arrives intact (and with CRLF, BOM, and 4 KiB + 1 bytes: refused, exit 12);
- the elevated relaunch path (ADR 0001, sidecar `--elevate`) still works, since only the unelevated Connect reads stdin;
- `--remote-debugging-port=9222` exits 12 and no port opens (`Get-NetTCPConnection`);
- the CI netlog job still shows only the paired host.

**Fallback** if a packaged GUI-subsystem Electron exe cannot read piped stdin reliably: a named pipe with a random
name passed as `--from-launcher=\\.\pipe\rongroi-launch-<32 hex>`, created by the launcher with a DACL for the current
user only, read once, the same way the sidecar pipe works (ADR 0001, `native/pipe`). This ADR is then amended.

### Result, 2026-11-14 (pik-windows, Windows 10.0.26320)

What was tested: the release folder CI built from `feat/launcher-handoff` at `3f501bd` (run 43584325889). The process was started from SSH (session 0) by `handoff.exe` (nakara-oss `launcher-connect`, `std::process::Command` with piped stdin) and by Node `child_process.spawn` writing raw bytes.

- **stdin: fails, so the fallback applies.** A fresh, valid code from the mock Kit was refused with exit 12, and the Kit received no request. Every other input was also refused with exit 12 after about 2.3 s:
  - a damaged code, CRLF, a BOM, 4097 bytes, or an empty line;
  - stdin held open with nothing written;
  - a line written 1 s after start.

  In the open-and-silent case Connect exited at 2.5 s, not at the reader's 5 s timeout. So Connect saw stdin as already ended or failed: the packaged GUI-subsystem Electron exe does not read the inherited pipe. Connect also wrote `\r\n` to stdout in every run. This comes from Electron or Chromium, not from Connect's code.
- **Arguments: pass.** Each of the following exits 12 in 324–376 ms, with no listener on 9222 or 9229 at any 50 ms poll and no netlog file:
  - `--remote-debugging-port=9222`, alone and together with `--from-launcher`;
  - `--inspect=9229`;
  - `--log-net-log=<path>` (release build);
  - `extra`.

  `--user-data-dir=<path>` also exits 12, but Chromium creates the (empty) folder before Connect's code runs.
- With no argument, Connect still opens and stays running (paste field).
- The elevated relaunch is the sidecar's (`--elevate`), not Connect's, so Connect's arguments do not reach it. The CI e2e with its elevated round and the netlog check passed on `8e119a1` (run 43579807676) and `3f501bd` (run 43584325889).

Next: decision 1 moves to the named-pipe fallback above, and this ADR is amended before acceptance. The argument rule stays as tested.

## Consequences

- The proof of ADR 0001 section 2 still runs on what ships: the stdin path is in the release build, not in
  `src/test-hook.js`, so the netlog job and the byte-compare of the two builds cover it.
- The exit code change (0 → 16 for a declined answer) is visible to anyone scripting Connect; it ships in 0.1.0, before
  any public release, so no released behaviour changes.
- A malicious launcher can still show its own fake screens before starting Connect. It cannot change what Connect
  shows or sends. Players are told to download a launcher only from their server's own page (the launcher's docs).
