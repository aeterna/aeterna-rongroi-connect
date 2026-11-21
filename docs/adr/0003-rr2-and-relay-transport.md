<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->
# ADR 0003 — `rr2.` codes and the relay transport in Connect

- Status: accepted — the owner decided aeterna-rongroi ADR 0097's questions on 2026-11-21, each as recommended
- Date: 2026-11-21 · Claude Code - Claude Opus 5.5
- Amends: ADR 0001 (pairing parser, network gate, upload plan, consent and done screens) and ADR 0002 (exit code 17 only;
  the code still never travels on argv, and a launcher still hands it over the pipe).
- Related: aeterna-rongroi ADR 0097 (the protocol: `rr2`, the Relay, envelope v2), ADR 0089 §4–5; nakara-oss ADR 0001
  §14 (the Server Kit side)

## Context

Connect accepts only `rr1.` codes with exactly six members (`src/core/pairing.js:157-178`), sends every request under
the fixed path `/nakara_rongroi/` (`src/main/net.js:8`), and plans uploads for Enhanced's 8 KiB body limit
(`src/core/upload-plan.js:7-8`). aeterna-rongroi ADR 0097 adds a code format and a transport so a server that is not
named `nakara_rongroi`, sits behind the Cfx proxy, or is not a FiveM server can use Connect. This ADR records what
changes in Connect. The protocol itself is owned by ADR 0097.

## Decision

1. **Parser.** `rr2.` is accepted next to `rr1.`, throughout 0.x. An `rr2` object has exactly eight members; unknown
   members are refused as in rr1. `base_path` must match `^[a-z0-9_-]{1,64}$` and `transport` must be `direct` or
   `relay`. Both go through the same quarantine as `server_origin`. A `relay` code with an `http:` origin is refused.
2. **URLs.** Every request is built as `server_origin + "/" + base_path + "/…"`. `PATH_PREFIX` stays as the value for
   `rr1` codes only. The network gate still allows only `server_origin`'s exact origin.
3. **Upload plan by transport.** `direct` keeps today's plan (≤ 7,168 bytes in one `POST`, else 4 KiB slices). `relay`
   sends one `POST` of at most 2 MiB with `X-Rongroi-Envelope: 2`. Every `rr2` code (direct or relay) uses envelope v2;
   every `rr1` code uses v1.
4. **Envelope v2.** The body carries `"v": 2`; HKDF `info` prefix `rongroi-connect report v2`; additional data = JCS
   of `{ base_path, policy_hash, server_origin, ticket, transport }` with the exact strings from the code (ADR 0097 §4). `rr1` codes keep envelope v1.
   Test vectors (`test-vectors/envelope-v2.json`) merge before the code that uses them.
5. **Status and the done screen.** For `relay`, a `202` means stored, not accepted. Connect polls
   `GET <base>/status/<ticket>/<sha256>` (backing off from 2 s to 15 s) until it reads a result:
   - `accepted` → the existing "Sent" screen;
   - `404`, `409`, `410`, `422`, `500` → the existing screens for those codes. A relay result is final: Connect does not
     restart or retry the upload, unlike a direct `422` or `5xx`;
   - no result yet → "Delivered to the relay, waiting for the server";
   - no result by `expires_at` + 10 minutes → "The relay has the report but the server has not confirmed it". This
     screen never says "Sent".
   As soon as the relay answers `202`, the screen changes to "Delivered to the relay at <origin>. Waiting for the game
   server to collect it." (amended 2026-11-22 after Q3), and quitting from then on exits 17, not 15.
   Trust: through a relay, "Sent" means the relay reported the server's `accepted`. The player chose that relay's
   origin on the consent screen; a relay that lies can make Connect say "Sent" for a report the server never saw, the
   same way a server can lie about its own `200` today.
   Exit codes for a launcher (ADR 0002): 0 (or 16 for a declined answer) only after `accepted`. The two waiting cases
   exit **17**, a new code added to ADR 0002's table, because 15 already means the upload failed or was refused.
6. **Consent screen.** The large-type origin stays the destination. For `relay` one line is added: "Through a relay the
   server runs; the game server collects it from there." `server_name` is not presented as a fact about where data
   goes. "Only paste a code from the game" stays.
7. **Sidecar pin.** A scheduled workflow opens a PR when aeterna-rongroi publishes a `rongroi-scan` newer than
   `sidecar.lock.json`, with the new hash and attestation check. It never merges by itself.
8. **Not added:** a `rongroi://` protocol handler (the code would arrive on argv, refused by ADR 0002 §3, and from
   outside the game) and an installer (the owner chose a zip on 2026-11-01). Distribution stays the zip, also listed
   through a winget manifest that points at the same release asset.

## Consequences

- Connect works with servers of any resource name, behind the Cfx proxy through a Relay, and with non-FiveM servers
  that implement ADR 0097.
- A relay upload has one more state the player can see ("waiting for the server"), which is the truthful one.
- `rr1` and envelope v1 stay supported, so the Nakara path and Connect 0.1.1 users are not affected.
- Exit code 17 is new: ADR 0002's table and the launcher's `launcher-connect` crate both need it before the relay
  transport ships (checked in the joint test).
