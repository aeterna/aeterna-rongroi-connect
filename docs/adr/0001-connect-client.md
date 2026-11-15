<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->
# ADR 0001 — The Rongroi Connect client: how it is built, hardened and shipped

- Status: accepted — owner, 2026-11-01 (local-address origins and the 14-day patch rule accepted)
- Date: 2026-11-01
- Amended: 2026-11-05, lane 2c as built ("As built: 2c"); 2026-11-07, lane 3c as built ("As built: 3c");
  Claude Code - Claude Opus 5.5
- Related: aeterna-rongroi ADR 0089 (product line and schema 2,
  [aeterna-rongroi#252](https://github.com/aeterna/aeterna-rongroi/pull/252), not merged yet; this ADR follows
  its revision of 2026-11-01), ADR 0002 (evidence, never a verdict), ADR 0007 (official builds), ADR 0012
  (relaunch elevated), ADR 0040 (the player controls the PC), aeterna-rongroi AGENTS.md hard rules 3 and 9

## Context

ADR 0089 fixes what Connect is and what it sends: the privilege split, the named pipe and the temporary
userData (its section 3), the upload paths, retries and the shared status table (section 4), and the pairing
code, the `policy` object with `server_name`, the envelope and the single-use ticket (section 5). This ADR
does not restate or change those. It decides the parts that belong to the client alone: its processes, the
full quarantine list and its proof (ADR 0089 section 3 points here), what it keeps on disk, how it launches
the sidecar, what the player sees, and how a release is built and checked.

What the spike measured (PoC W1a, 2026-10-31, Electron 44.7.1, Windows box `pik-windows`):

- **S7.** A default Electron fetched the spellcheck dictionary from `redirector.gvt1.com` outside the
  `webRequest` gate, even with `spellcheck: false` and `setSpellCheckerEnabled(false)`, and resolved the DNS
  name `wpad` on every run. The five "harden" switches alone did not stop either (`netlog-harden-clean.json`).
  `setSpellCheckerLanguages([])`, a dictionary URL of `http://127.0.0.1:9/` and `no-proxy-server` did: the
  netlog then held only the paired host (`netlog-fix-clean.json`, `netlog-fixharden-clean.json`). The netlog
  covers Chromium's network stack only. What the OS saw (pktmon) was not checked. The spike's requests went
  through Electron's `net.fetch` on `session.defaultSession`, whose `webRequest` gate blocked the two probe
  URLs with `net::ERR_BLOCKED_BY_CLIENT` (`briefs/brief-sb.md`, `results/run-*.json`).
- **S8.** The sidecar relaunched itself elevated through ADR 0012's mechanism and wrote its JSON into
  `\\.\pipe\rongroi-<32hex>`, which the unelevated shell had created. UAC Yes and No were both handled; on No
  the sidecar exited with 3 and the shell posted a declined answer. Two gaps: the pipe had no ACL of its own,
  and the elevated console window showed, because `relaunch_elevated` passes `SW_SHOWNORMAL`
  (`crates/rongroi-host-windows/src/elevate.rs`).
- **S10.** Defender real-time protection raised no detection, but the files came over scp without the
  Mark-of-the-Web. SmartScreen on a browser download is untested.
- **S12.** Exe 245 MB, folder 387 MB in 74 files, zip 158 MB, unzip 6.4 s, window ready 1.3–2.2 s
  (0.74–0.82 s in the S8 and S13 runs). Nothing new in `%TEMP%` from the app. `%APPDATA%\rongroi-connect-spike`
  gained about 10 MB in 67 files: HTTP cache, GPU and Dawn caches, code cache, and the downloaded dictionary.

The client controls nothing about trust. The player, or anything running as the player, can edit memory,
replace the sidecar or the whole app, or write a report by hand (ADR 0040). Connect and Server Kit establish
that the server received this report after it opened the case, and that the server's recomputed
`visual_hash` equals the value in the record, which staff may compare with what the player reports from the
screen; a player who controls Connect can show or choose any value. The uploader is not identified (ADR 0089,
"What Connect can and cannot show"). Every rule below is about not leaking data, not misleading the player
and keeping other local programs out, never about proving a PC.

`mode: "single-shot"` in this ADR means one case per run: the player pastes one code, consents, sees the
hash and presses Send, and Connect then exits. Nothing runs headless.

## Decision

### 1. Processes and where network code lives

| Process | Integrity | Network | Code |
|---|---|---|---|
| Main (`rongroi-connect.exe`) | medium, never elevated | **the only one**: `ses.fetch()` on the app session | this repo |
| Renderer | sandboxed | none: CSP `default-src 'none'; script-src 'self'; style-src 'self'` | this repo |
| Sidecar (`rongroi-scan.exe`) | medium, or high after UAC | none (aeterna-rongroi hard rule 1) | aeterna-rongroi |

- The main process sends HTTP only through `ses.fetch()` (Electron's `Session.fetch`), where `ses` is the
  in-memory app session of section 3, so every request passes that session's `webRequest` gate. The spike's
  evidence covers `net.fetch` on the default session, not `Session.fetch` on a partition; that the gate
  catches it is unverified until the 2c netlog job passes. Node's global `fetch`, `node:http`, `node:https`,
  `node:net`, `node:tls`, `node:dgram` and `node:dns`, and Electron's `net` module, are banned in this repo by
  an ESLint `no-restricted-imports` / `no-restricted-globals` rule that fails CI.
- The window: `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`,
  `spellcheck: false`, no `webviewTag`, `devTools: false`. `app.enableSandbox()` before ready.
- `web-contents-created`: deny `setWindowOpenHandler`, prevent `will-navigate`, `will-redirect` and
  `will-attach-webview`. Permission request and check handlers return false.
- Fuses: `RunAsNode` off, `EnableNodeOptionsEnvironmentVariable` off, `EnableNodeCliInspectArguments` off,
  `OnlyLoadAppFromAsar` on, `EnableEmbeddedAsarIntegrityValidation` on, `EnableCookieEncryption` on. The spike
  left asar integrity off because its hand-made build did not embed the hash resource; whether the 2c build
  can embed it on Windows is unverified.
- The preload exposes one object, `window.connect`, and nothing else:

| Name | Direction | Does |
|---|---|---|
| `submitCode(code)` | renderer → main | parse the `rr1.` code (section 2), fetch the policy, check `policy_hash` |
| `consent()` | renderer → main | start the scan with the policy shown |
| `decline()` | renderer → main | send the declined answer (ADR 0089 section 5) and finish |
| `send()` | renderer → main | encrypt and upload the record whose hash is on screen |
| `quit()` | renderer → main | close without sending anything more |
| `onState(callback)` | main → renderer | push the state of section 5 and the data it shows |

  Each handler checks `event.senderFrame.url` is the app's own page and refuses otherwise. The renderer never
  holds the per-report key or the envelope. It receives the record as text only to display it.

### 2. Network quarantine, the pairing code, and the proof

Required in every build, applied before `app` is ready or as the first statements in `whenReady`, on both
`session.defaultSession` and the app session:

1. `no-proxy-server` (S7: stops the `wpad` lookup).
2. `setSpellCheckerLanguages([])`, `setSpellCheckerDictionaryDownloadURL('http://127.0.0.1:9/')` and
   `setSpellCheckerEnabled(false)` (S7: stops the dictionary fetch).
3. `disable-background-networking`, `disable-component-update`, `disable-domain-reliability`, `no-pings`,
   `dns-prefetch-disable`. S7 showed these do not fix the leak alone; they stay as defence in depth.
4. The `webRequest.onBeforeRequest` gate of ADR 0089 section 3, as a pure function `decide(url, origin)`:
   allow a URL whose `new URL(u).origin` equals `server_origin`, and `file:` URLs inside the app's own
   `app.asar`; deny everything else, including `data:`, `blob:`, `devtools:` and unparsable URLs. Before a
   code is accepted there is no `server_origin`, and every network request is denied.
5. Every `ses.fetch()` passes `redirect: 'error'`. A redirect, even to the same origin, is an error state.
6. No `autoUpdater`, no `crashReporter.start`, no remote module, no telemetry library.

**A pairing code can be hostile.** Anyone can hand a player an `rr1.` code that points at their own host. The
code is pasted, so the paste field says "Only paste a code shown to you inside the game". Connect refuses a
code whose `server_origin` is not exactly `http://` or `https://`, host, optional port: no userinfo
(`user@`), no path, query or fragment, no other scheme. The consent screen shows the origin in large type,
with the host in its ASCII (punycode) form. **Owner decision (2026-11-01):** a loopback (`127.0.0.0/8`, `::1`) or
private-range (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`, `169.254/16`) origin is allowed, because a
server on the same LAN is ordinary, and shown with a warning line naming it as a local address.

**The proof runs on what ships.** The automated flow lives in one module, `src/test-hook.js`, compiled in
only when the build flag `CONNECT_TEST_HOOK=1` is set; the release build gets a stub with the same exports
that does nothing. CI builds both folders from the same commit, then compares them: every file must be
byte-identical except `resources/app.asar` and the exe's embedded asar-integrity resource, and inside the two
asars only `src/test-hook.js` may differ. On a GitHub-hosted Windows runner the test build is started with
Chromium's `--log-net-log=<file>` against a mock Server Kit on `127.0.0.1:<port>` and the mock sidecar, with a
fresh userData, and runs the whole flow. A script then fails the job if any URL request, socket or host
resolution names anything but the paired host and port. A harness outside the app was rejected: driving the
window from outside needs either a debugging port, which the fuses close, or UI Automation, which is slower
to write and to keep working. The job runs on every PR and on every Electron upgrade. It covers Chromium's
stack only. An OS-level capture (pktmon) is run once by hand in lane 3c and after each Electron major
upgrade, and recorded in the release notes; until then OS-level silence is unverified.

### 3. Nothing on disk but a temporary userData

- Before ready, the main process creates `%TEMP%\rongroi-connect-<pid>-<16hex>` with `fs.mkdtempSync` and
  points `userData`, `sessionData` and `crashDumps` at it (ADR 0089 section 3). The window uses an in-memory
  session (a partition name without `persist:`), so the HTTP cache and cookies stay in memory.
  `disable-gpu-shader-disk-cache` is set. Which of the S12 files still appear is unverified; lane 2c lists them.
- On `quit` the main process deletes the folder. Chromium may still hold files open at that point, so the
  delete is best effort. On start, the main process removes any `rongroi-connect-<pid>-*` folder whose pid is
  not running and whose last change is more than 10 minutes old. After a crash the folder stays until the next
  run, or until Windows' own temp cleanup. It holds caches, not the report.
- The pairing code, ticket, policy, record and envelope live in memory only. No log file is written, and no
  option writes one. Windows' own records of a program run (Prefetch, BAM, Amcache) and a Windows Error
  Reporting dump after a crash are outside Connect's control. Whether WER keeps a dump of the main process
  on a default Windows 11 setup is unverified.

### 4. Launching the sidecar and the pipe

- The sidecar path is `path.join(process.resourcesPath, 'rongroi-scan.exe')`, never `PATH` or the working
  folder. The extracted folder is writable by the player, so another process running as the player could
  replace the sidecar before the UAC prompt and borrow Connect's elevation request. Immediately before each
  launch, Connect computes the file's SHA-256 and compares it with the value the release build embedded in
  `app.asar`; a mismatch is an error state and nothing runs. A swap timed between the check and the launch,
  or during the UAC prompt (the elevated relaunch opens the file by path again), is not caught.
- Connect always uses the pipe, elevated or not, so there is one code path. It creates
  `\\.\pipe\rongroi-<32 lowercase hex from crypto.randomBytes(16)>` with `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`, one instance, and the DACL of ADR 0089 section 3 (the current user's SID and
  Administrators). Administrators is needed when a standard user elevates with another account at the UAC
  prompt. `node:net` offers no way to pass a security descriptor (from memory of the libuv API, unverified),
  so the pipe is created by a small Rust N-API module in this repo, with no network crate and `cargo deny` as
  in aeterna-rongroi.
- Connect stays the server and the elevated sidecar stays a client that connects out. The other way round, an
  elevated process would accept connections from medium-integrity processes.
- One connection only. After the first client connects, Connect stops listening. It compares the client's
  image path (`GetNamedPipeClientProcessId`, then `QueryFullProcessImageNameW`) with the bundled sidecar path
  and drops the connection on a mismatch. Whether a medium process can read an elevated client's image path
  this way is unverified.
- The protocol is duplex. Connect writes one JSON line `{binding, policy, producer}`, where `producer` is
  `{name: "rongroi-connect", version: <Connect's version>, mode: "single-shot"}`. The sidecar scans the
  collectors in `policy.required_collectors` and writes back one schema 2 record built by `rongroi-core`,
  `visual_hash` included, then closes. The ticket never goes on a command line, where other processes and
  process-creation logs could read it. Connect checks that the record's `binding`, `policy` and `producer`
  equal what it sent and that `visual_hash` is 16 lowercase hex; it does not recompute the hash, the server
  does (ADR 0089 section 2). Connect stops reading at 2 MiB, and refuses before encrypting any record whose
  envelope would exceed Server Kit's 2 MiB cap (ADR 0089 section 4), with "This report is too large for the
  server to accept".
- Arguments: `--pipe \\.\pipe\rongroi-<32hex>`, plus `--elevate` when `policy.require_elevation` is true. The
  unelevated launch uses `execFile` with `windowsHide: true`.

Requirements on the sidecar (changes in aeterna-rongroi): `--pipe` must match
`^\\\\\.\\pipe\\rongroi-[0-9a-f]{32}$` or exit 1, which also refuses a UNC path to another machine; open the
pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the server cannot impersonate the elevated
token; validate every pipe input (one line of at most 16 KiB, no unknown members, collector IDs only from the
fixed set its `rongroi_version` knows, every string bounded); give up with exit 1 if the pipe cannot be
opened within 10 s of start; exit when a pipe write fails; and pass `SW_HIDE` through a new show-window
argument of ADR 0012's `relaunch_elevated`. The UAC prompt is drawn by Windows and is not affected.

Timeouts. The ticket's 300 s lifetime is the owner's (ADR 0089 section 5); the limits below are chosen so the
waits leave room for the player's own steps inside it, and are not measured:

| Wait | Limit | On expiry |
|---|---|---|
| Policy `GET` | 10 s | error state, "Try again" allowed while the ticket has time left |
| Sidecar connects to the pipe (covers the UAC prompt) | 60 s | close the pipe, error state |
| Record after connect | 120 s | close the pipe, error state |
| Each upload `POST` | 15 s | a failed attempt under the retries below |

From the consent screen on, the window shows the ticket's remaining time as a countdown. The local clock may
differ from the server's, so Connect corrects `expires_at` by the offset between the policy response's
`Date` header and its own clock (1 s resolution). The S9 posture scan took 0.39 s unelevated and 0.45–4.7 s
elevated. A standard scan's duration is unverified, and lane 3c measures it against the 120 s limit. On a
timeout Connect kills an unelevated sidecar through its child handle; an elevated one exits on its own when
the pipe closes. Connect sends nothing on a timeout; ADR 0089 defines only the declined answer.

Upload responses, from ADR 0089 section 4's shared status table. Retries use its 500, 1500, 3000 ms schedule,
for the direct `POST report` as well as for slices, and every request carries `X-Rongroi-Upload-Id`:

| Status | Connect does |
|---|---|
| 200 | done, or next slice. A retry after a lost response is safe: the same accepted envelope gets 200 again |
| 400 | no retry, error state |
| 404 | no retry, error state |
| 409 | no retry: the ticket was used. Error state "This code was already used. Ask staff for a new one" |
| 410 | no retry: the ticket expired. Error state asking for a new code |
| 413 | no retry, error state |
| 422 | restart the whole upload once while the ticket has time left, then error state |
| 429 | wait `Retry-After` (counts as an attempt); if that passes the ticket's expiry, error state |
| no answer, timeout, 5xx | retry on the schedule, then error state |

A failed upload returns the ticket to issued (ADR 0089 section 5), so the error state offers "Try again"
while the countdown runs.

Sidecar exit codes (the S8 contract; changes go through aeterna-rongroi):

| Sidecar code | Stdout | Connect does |
|---|---|---|
| 0 | `{"elevate":"requested"}`, or nothing when it scanned into the pipe | waits for the pipe |
| 3 | `{"elevate":"declined"}` | sends the declined answer, state "Declined" |
| 1 | `{"elevate":"failed",…}` or an error | error state |
| other | — | error state |

Connect's own process exit codes, for scripts and tests, start at 10 so they cannot be read as sidecar codes:

| Connect code | Meaning |
|---|---|
| 0 | the server accepted a report or a declined answer |
| 10 | internal error |
| 11 | the player closed Connect before anything was sent |
| 12 | the code or the policy was refused (bad code, origin form, `policy_hash` mismatch, unknown collector) |
| 13 | the sidecar failed, its hash did not match, or it timed out |
| 14 | the record was refused before upload (binding, policy or producer mismatch, over 2 MiB) |
| 15 | the upload failed or the server refused it |

### 5. What the window says

| State | Shows | Player can |
|---|---|---|
| Paste code | a field for the `rr1.` code; "Only paste a code shown to you inside the game" | paste, quit |
| Checking | "Contacting `<server_origin>`" | quit |
| Consent | `server_origin` large; `policy.server_name` (covered by `policy_hash`); every collector by name; whether Windows will ask for admin rights; the countdown; the local-address warning for a loopback or private-range origin | consent, decline (the button says the server is told), quit |
| Scanning | "Scanning"; while elevation is pending, "Windows will ask for permission"; the countdown | quit |
| Hash shown | `visual_hash` in large type, grouped 4×4; a "See what will be sent" panel with the record as text; the countdown | send, quit (nothing sent) |
| Uploading | progress by slice when chunked | — |
| Done | "Sent to `<server_origin>`. Code on this screen: `<visual_hash>`." | quit |
| Declined | "You declined. `<server_origin>` was told." | quit |
| Error | what failed, in one sentence, and whether anything was sent | try again where section 4 allows, quit |

No state uses "verified", "clean", "passed", "safe" or a colour that reads as a result. Text comes from a
locale file, English and Thai at 0.1.0.

### 6. Electron upgrades

Connect follows Electron's security releases, not rongroi's release rhythm. Electron and its tooling are
pinned to exact versions in `package.json` and the lockfile. Dependabot watches them. A patch release of
Connect ships (owner, 2026-11-01) within 14 days of an Electron release that fixes a Chromium or Electron security bug, on the
same major, after the quarantine job of section 2 passes on it. When the pinned major leaves Electron's
supported range, Connect moves to a supported major in the next release. A major upgrade repeats the pktmon
check, because Chromium may add a background fetch the switches do not cover.

### 7. Build, provenance and the zip

- The release workflow runs on a GitHub-hosted Windows runner (not the shared `wsl-pik-*` runners) on a
  `v*` tag: `npm ci` from the lockfile, Electron from `@electron/get` with its checksum check, the N-API module
  built with `cargo build --locked`, fuses flipped, asar packed with the sidecar's SHA-256 embedded, the test
  build and the comparison of section 2.
- The sidecar is not built here. The workflow downloads `rongroi-scan.exe` from a tagged aeterna-rongroi
  release, checks it against that release's `SHA256SUMS` and attestation, and records its version. That
  aeterna-rongroi publishes `rongroi-scan.exe` at all is a change still to make there.
- The workflow writes `SHA256SUMS` for the zip and attaches a GitHub artifact attestation
  (`actions/attest-build-provenance`) naming the commit, workflow and runner. Players check the hash;
  anyone can run `gh attestation verify`. Attestations on a private repository need a plan the org does not
  have (unverified), so the first attested release is the public 0.1.0. A byte-for-byte reproducible build is
  not claimed for 0.1.0.

```
rongroi-connect-0.1.0-windows-x64.zip
└── rongroi-connect-0.1.0/
    ├── rongroi-connect.exe
    ├── resources/app.asar
    ├── resources/rongroi-scan.exe
    ├── LICENSE                  (GPL-3.0-or-later)
    ├── LICENSES.chromium.html   (from the Electron distribution)
    ├── README.txt               (the player steps below, and the source URL for this tag)
    └── … Electron runtime files
```

One top folder, so "Extract All" does not scatter 74 files. Player steps, as ADR 0089 Consequences fixes:
download the zip from Releases; in Command Prompt run `certutil -hashfile <zip> SHA256` and compare with the
line in `SHA256SUMS`; only on a match, Properties → **Unblock** → OK; "Extract All" with Windows' extractor;
run `rongroi-connect.exe` (no install, no admin); if SmartScreen warns, **More info → Run anyway**; paste the
code from the game. The guide never suggests a third-party extractor. Signing is out of 0.1.0 (ADR 0089).

### 8. Versioning

Connect has its own semver, starting at 0.1.0 (pre-alpha); tags are `v<version>`. `producer.version` is
Connect's version, sent to the sidecar over the pipe; `rongroi_version` is the sidecar's. One Connect release
bundles exactly one sidecar version, named in the release notes. Before 1.0, a change to what is sent, to the
pipe protocol or to the bundled sidecar's minor version bumps Connect's minor version; an Electron security
update alone is a patch.

### Out of scope

A persistent or background mode (its own ADR, owner decision Q17); auto-update of any kind; Hub; an installer;
code signing; macOS and Linux builds.

## As built: 2c

Differences from the sections above, each found while building:

- The preload also exposes `retry()`, for the error state's "Try again". Section 1's table listed five calls and `onState`.
- A 5xx or a lost answer that uses up its retries restarts the whole upload once while the ticket has time left, as 422 does, then is an error. Server Kit answers 500 when saving failed and has dropped its buffer, so repeating one slice cannot work (section 4's table says retry, then error).
- A lost-answer or partial upload error says part of the report may have reached the server, since some slices may have been accepted.
- Electron is 44.10.2, not the spike's 44.7.1: `npm audit` reported a high advisory on the earlier version.
- **One known socket, accepted by the owner (2026-11-05).** Section 2's job fails on any socket naming anything but the paired host. Chromium's host resolver opens one UDP socket and connects it to `[2001:4860:4860::8888]:443`, a Google public DNS address, to learn whether IPv6 is reachable, even for a request to an IP address. So Connect opens a socket toward that address, and sends nothing on it, as measured below. This is weaker than "no socket", and nothing here may say otherwise.

  | Where (Electron 44.10.2) | IPv6 route | Connect result | Packets to that address |
  |---|---|---|---|
  | This repo's hosted Windows runner | none | `net_error -109` | netlog: no byte events. Not captured by the OS |
  | Development PC, Windows, `pktmon` | none (Teredo and Tailscale only) | `net_error -109` | none seen, but the control could not send either, so this shows nothing beyond "no route, nothing leaves" |
  | MacBook, macOS, `tcpdump` | yes | connected, `ipv6_available: true` | **0**, with a control that sent 1 byte and captured 1 packet |
  | pik-windows, Windows build 26320, `pktmon` (2026-11-15, CI run 43683279014 test folder, whole e2e: 3 runs) | yes, a **test route**: `::/0` via a fixed neighbor on the WSL virtual adapter, source `2001:db8:3c::2` (documentation prefix; traffic stays inside the machine, nothing reaches the internet) | connected in all 3 runs (`acceptedIpv6Check` `{"connected":true}`, sources 2, 4, 4); netlog check passed | **0** packet records over the whole run, with the same pktmon filter on the same address catching a control that sent 1 UDP byte to `[2001:4860:4860::8888]:443` (11 records: one packet seen at 11 stack components) |

  `--enable-features` with `EnableIPv6ReachabilityOverride` or `kEnableIPv6ReachabilityOverride` did not stop the check on the Mac. No `disable-ipv6` switch string was found in the binary. Whether another way exists is unknown.

  The netlog shows this socket at two layers, as a `UDP_SOCKET` source and a `UDP_CLIENT_SOCKET` source. The netlog check accepts them only when the type is UDP, the address and port are exactly that, the source holds only open, connect, local-address and alive events (so no bytes and no send or receive attempt, failed or not), and the log holds Chromium's IPv6 reachability check event. Any other case fails the job.

  **Windows with an IPv6 route: measured 2026-11-15 (M3), 0 packets.** The route was a test route, because no network at hand had real IPv6 (the phone's carrier gave none). Chromium's check only needs `connect()` to succeed, which a route of any kind allows, and the control proves pktmon sees a packet on that path. What this does not cover is a route that reaches the internet. Evidence (pktmon text, e2e report and netlog, the scripts, `SHA256SUMS`): `/Volumes/WD1TB/aeterna-backups/connect-m3-2026-11-15/` on the owner's drive. A packet to that address on any later measurement ends this exception. The owner accepted this test-route measurement for 0.1.0 (2026-11-15).
- **Files left in `%TEMP%` after a normal exit (hosted Windows runner, Electron 44.10.2, the mock flow, run 42021779777 on `1991908`).** The delete in `will-quit` does not finish: the folder stays with 20 files, 115,883 bytes. Why is not proven; files Chromium still holds open is the likely cause (section 3). The stale sweep removes the folder on a later run, once its pid is gone and it is more than 10 minutes old, so a player who never runs Connect again keeps it until Windows' own temp cleanup.

  | Under the folder | Files | Bytes |
  |---|---|---:|
  | `Shared Dictionary\db`, `db-journal`, `cache\index`, `cache\index-dir\the-real-index` | 4 | 45,128 |
  | `Network\Trust Tokens`, `Trust Tokens-journal`, `Network Persistent State`, `NetworkDataMigrated` | 4 | 36,975 |
  | `declarative_performance_observer.db`, `-journal` | 2 | 32,768 |
  | `Local Storage\leveldb\` `000003.log`, `CURRENT`, `LOCK`, `LOG`, `MANIFEST-000001` | 5 | 402 |
  | `Local State`, `Preferences` | 2 | 610 |
  | `GPUPersistentCache\DawnGraphiteCache\<id>\` | 3 | 0 |

  The e2e job searches every leftover file up to 1 MiB for the run's ticket, nonce, Kit key and origin, as plain UTF-8 and UTF-16LE: no hits in this run. A ticket, nonce or key hit fails the job; an origin hit is only reported. Larger or unreadable files are listed in the report as not searched, and a value stored compressed or encoded would not be found. That is a search for those four values in a mock flow, not proof about a real scan, and the real sidecar's run is lane 3c's to repeat. S12's HTTP, code and shader caches and the dictionary did not appear.

  This list is what remained after the delete, not everything Chromium wrote during the run. A crash can leave more.

- A scan that a player quits, or whose ticket expires, is stopped: the main process kills the child if it is its own and closes the pipe. An elevated sidecar cannot be killed from the unelevated main process; it finds the pipe closed.
- A sidecar that connects and writes nothing, or exits non-zero within 2 seconds of the pipe closing, is a sidecar failure (exit 13). Non-empty invalid text with no bad exit stays a refused record (exit 14), so a sidecar killed without an exit code after a partial write is reported as 14.
- A refused code or policy, and any other error without "Try again", is final for the run: the player closes Connect and starts it again to enter a new code. This is `single-shot` as defined above.
- **The client image check of section 4 is not in 2c.** The pipe module exposes it and nothing calls it yet. Until lane 3c adds it, a process running as the same user that opens the pipe first gets the binding, policy and producer, and can supply the record. 0.1.0 does not ship without it.
- **What the release smoke shows.** The release folder's exe stayed running for 8 seconds, with embedded asar integrity on. It does not show that the window drew or that the release build completes a flow, since the test hook is not in it. The byte comparison with the test build carries the rest.

## As built: 3c

Lane 3c connected Connect to the real `rongroi-scan` sidecar (#3, #4, #6, #8). Differences from the sections above
and from "As built: 2c", each found while building or measuring:

- **The sidecar is built from source at a pinned commit until 0.1.0** (owner, 2026-11-06). `sidecar.lock.json` names
  aeterna-rongroi `3a08e2d`. CI refuses a lock whose commit is not exactly 40 lowercase hex, checks out that commit,
  builds `rongroi-scan` with `--locked`, and `scripts/build.js` copies it next to the asar and writes its SHA-256 into
  `src/sidecar.json`. A missing `vendor/rongroi-scan.exe` fails the build. This build is not an official one
  (ADR 0007). Replaced by the released asset before 0.1.0: see "Section 7 as built" below.
- **Connect checks the sidecar's SHA-256 before every launch.** This is a time-of-check to time-of-use pair: Connect
  hashes the file and the operating system opens it again when it starts the process, so a process running as the
  player could replace it in between. The pipe check below compares the image path, not its bytes. Both stop a wrong
  or damaged file and other users' processes. Neither stops code that already runs as the player, which the Context
  above already puts outside what the client controls.
- **The policy check is stricter.** The policy has exactly five members. The canonical hash of the policy without its
  `policy_hash` member must equal the hash in the pairing code (`net.js`), and `policy_hash` must be 16 lowercase hex
  characters. Each collector must be one of the 20 ids this build knows, with no duplicates (1 to 64 entries). The
  profile may be `posture`, `standard` or `custom`, and nothing requires the whole Standard set. A request line over
  16 KiB is refused before any process starts.
- **The client image check is in** (C3). The 2c gap above is closed: Connect compares the pipe client's image path
  with the bundled sidecar and drops a mismatch. Section 4's open question is answered for one PC: on Windows, with
  Connect at Medium integrity and the player answering Yes to UAC, Connect read the elevated copy's image path and the
  scan completed (2026-11-07). Other Windows versions and security products are unmeasured.
- **After the launcher prints `{"elevate":"requested"}` and exits 0, the elevated copy has 15 s to connect**, inside
  the 60 s connect limit. A launcher that exits 0 without that line has scanned already, or failed if no connection came.
- **Declining UAC works end to end.** The launcher exits 3, Connect sends the declined answer, and the state is
  "Declined" 2.6 s after scanning began (2026-11-07). The mock Kit had refused that answer with 400 because it took only
  schema 2 records. #8 made it follow the real Kit's rule (binding ticket and nonce for both kinds, `scan: "declined"`
  without a schema).
- **A Standard scan is far inside section 4's limits.** Measured with 20 collectors:

  | Where | Run | Scan | Record |
  |---|---|---:|---:|
  | Hosted Windows runner (High integrity), run 42307666982 | elevated, first and cold | 29.0 s (run) | 112,450 B |
  | same | unelevated, after it | 6.0 s (run) | 112,446 B |
  | Development PC, Connect at Medium integrity, UAC Yes | elevated | 18.8 s | 199,766 B |
  | same | unelevated | 4.2 s | 49,953 B |

  The first scan on a machine is the slow one, about 27 s on the runner with or without elevation. Records are at
  most a tenth of the 2 MiB limit. These are two machines, not a range for players' PCs.
- **CI does not exercise the UAC relaunch.** The hosted runner's job runs at High integrity, so `--elevate` scans in
  place with no prompt. The prompt, Yes and No, was checked by hand on a PC. An elevated run that waited 120 s in
  `scanning` during wave 2 did not happen again once each run's policy reached the mock Kit (two traced runs, debug PR #5).
  Its cause is not proven.
- **Section 7 as built (K5, 2026-11-15).** `sidecar.lock.json` now pins the aeterna-rongroi 0.15.0 asset
  `rongroi-scan-0.15.0-windows-x64.exe` (tag `v2026.11.13-0.15.0`, commit `d8d17f0`) with its SHA-256. The composite
  action `.github/actions/fetch-sidecar` downloads it and refuses it unless it matches the lock, the release's
  `SHA256SUMS` line and aeterna-rongroi's attestation for that tag and commit; `ci.yml` and `release.yml` both use it, so
  CI tests the sidecar that ships. `build.js` refuses a vendor sidecar whose hash differs from a release lock.
  `release.yml` on a `v<version>` tag (the tag must equal `package.json`) builds both folders, compares them, runs the
  release smoke, lays out the folder with `scripts/package.js`, zips it, checks every entry sits under the one top
  folder, writes `SHA256SUMS`, attests the zip and opens a draft pre-release. On a pull request that touches packaging
  it stops after the zip. Differences from section 7: Electron's own `LICENSE` (MIT) ships as `LICENSE.electron.txt`
  so `LICENSE` can be this repository's GPL text, and the zip is named `rongroi-connect-<version>-windows-x64.zip`.
  The attestation step needs a public repository, so the first tag waits for the repository to go public (K7).
- **Still open before 0.1.0:** quitting during an elevated scan, which only unit tests cover because a scan ends
  too fast to quit by hand; the first tagged release run (it needs the public repository). The real-sidecar runs found
  none of the run's ticket, nonce or Kit key in the files left in `%TEMP%` (run 42307666982); the 2c limits of that
  search still apply.

## Consequences

- Network code sits in one process and one function path, and a CI job fails when the release asar's code
  talks to anything but the paired host. A new Chromium background fetch shows up as a failing netlog check,
  as long as the mock flow exercises it.
- The player, or anything running as the player, can still replace the whole app, sidecar and hash included.
  The sidecar hash check only stops a swap of the sidecar alone made before the check; it says nothing about
  the report.
- A hostile code can still point Connect at any host the player agrees to on the consent screen. Connect
  limits the form of the origin and shows it large; it cannot know whose server it is.
- A small native module adds a Rust toolchain to this repo's build. In exchange the pipe gets the ACL and
  flags ADR 0089 requires, which the spike lacked.
- Changes land in aeterna-rongroi, not here: the sidecar's duplex pipe protocol, input validation, `--pipe`
  form and SQOS flags, the hidden elevated window, and a release asset for `rongroi-scan.exe`.
- The temp userData moves about 10 MB of caches from `%APPDATA%` to `%TEMP%` for the life of a run. A crash
  leaves them there until the next run.
- Connect sends nothing on a timeout, so staff see an expired ticket rather than a reason.
- The 14-day patch rule commits a maintainer to releases that carry no feature work.

## Order of work

Product code is written by engineer runs through `aeterna-delegate` (org AGENTS.md section 10.7); this ADR
only decides. Lanes 2c and 3c run in their own worktrees; 3c needs 2c merged and the aeterna-rongroi changes.

- **2c, Connect shell with a mock sidecar.** Sections 1, 2, 3, 5: process model and preload, `decide()` and
  the pairing-code checks with tests written first, the quarantine switches, temp userData and the stale
  sweep, the N-API pipe module, the UI states, countdown and locale file, the test hook and the release-versus-
  test comparison, a mock sidecar that speaks the pipe protocol and returns a fixture record, a mock Server Kit
  that answers every status in section 4, and the netlog CI job. Done when the netlog job passes on a hosted
  Windows runner and the list of files left in `%TEMP%` after a normal exit is recorded.
- **3c, real sidecar, zip, SHA256SUMS and provenance.** Sections 4, 6, 7, 8: the real sidecar from an
  aeterna-rongroi release, the sidecar hash check, the client image-path check, the timeouts, the release
  workflow with the zip layout, `SHA256SUMS` and the attestation, the pktmon check and a standard-scan timing
  on a Windows PC. The owner's browser-download and Unblock test of ADR 0089 (W4) runs on this zip.
