<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->
# aeterna-rongroi-connect

**Status: pre-alpha, not yet released.** Rongroi Connect is a Windows app that, with the player's consent,
sends one [aeterna-rongroi](https://github.com/aeterna/aeterna-rongroi) report to the one FiveM server the
player paired it with. The offline rongroi program stays unchanged and sends nothing.

- The server runs the `nakara_rongroi` Server Kit from [nakara-oss](https://github.com/aeterna/nakara-oss).
  The player pastes a code from the game into Connect, sees what will be sent, and agrees or declines.
- The scan is done by `rongroi-scan`, the sidecar from an aeterna-rongroi release, checked against its
  SHA-256 before every run.
- A server's launcher can start Connect and hand it the code over a named pipe
  ([ADR 0002](docs/adr/0002-launcher-handoff.md)).

How it is built, what it sends and what it never sends: [ADR 0001](docs/adr/0001-connect-client.md).

Rules that apply to every rongroi product: evidence, never a verdict; no "clean" or "verified" label;
no automatic ban. See aeterna-rongroi `AGENTS.md` and its ADRs 0002 and 0040.

## Download and check

Releases are zips on the Releases page, with `SHA256SUMS` and a GitHub build-provenance attestation. The
player steps are in `README.txt` inside the zip and in ADR 0001 section 7. To check a zip:

```
gh attestation verify rongroi-connect-<version>-windows-x64.zip --repo aeterna/aeterna-rongroi-connect
```

## Build

Windows, Node 24 and Rust 1.98.1: `npm ci --ignore-scripts`, `npm run build:native`, put the pinned sidecar
at `vendor/rongroi-scan.exe` (see `sidecar.lock.json` and `.github/actions/fetch-sidecar`), then
`npm run build`. `npm test` and `npm run lint` run anywhere.

## License

GPL-3.0-or-later. Security reports: [SECURITY.md](SECURITY.md).
