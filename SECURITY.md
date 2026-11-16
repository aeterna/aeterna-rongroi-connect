<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: GPL-3.0-or-later
-->
# Security policy

## Reporting

Use GitHub **private vulnerability reporting**: the "Report a vulnerability" button under the repository's
Security tab. Do not open a public issue.

Please report privately:

- data leaving the PC that ADR 0001 does not list, or leaving before the player agrees
- a way for a server, a launcher or another program to make Connect send to a server the player did not pair
- a way to make Connect run a sidecar other than the pinned one
- a way to change what a report says between the scan and the server

Include the version, the zip's SHA-256 and the smallest steps that reproduce the problem. Please do not
publish details until a fixed release is available.

Detection bypasses in the scan itself belong to aeterna-rongroi's own private reporting.

## What happens next

A maintainer acknowledges the report, reproduces it and fixes it in a new release. Credit is given in the
release notes unless you ask otherwise.

## Supported versions

Only the latest release is supported during pre-alpha.
