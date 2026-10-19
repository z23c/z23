<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Security Policy

## Supported status

Z23 is **pre-v1 and in active stabilization** — it is not
production-ready, and there are no supported release lines yet. Only the
current `main` branch receives fixes. Do not rely on this build as a
mainnet node until the v1 acceptance criteria in
[`docs/quality/MVP.md`](../docs/quality/MVP.md) are met.

Known soft spots are stated plainly in the README status section and in
the audit disposition below (for example: off-chain ZMSG P2P messages
are currently plaintext on the wire).

## Safety and integrity model

Z23 is security-sensitive full-node software, not offensive-security
tooling. The repository contains Tor, wallet/key handling, P2P networking,
native operator commands, fuzzers, and crash harnesses because those are required to
run, inspect, and harden an operator-owned node.

The safety boundary, scanner context, local gates, command authorization, release
integrity checks, and reviewer checklist are documented in
[`docs/node/SECURITY_AND_INTEGRITY.md`](../docs/node/SECURITY_AND_INTEGRITY.md).

## Automated review of pull requests

Every outside contribution is security-reviewed before it is merged. The
reviewer runs `tools/scripts/pr_security_scan.sh` locally over the proposed
diff, which checks for: consensus divergence from `zclassicd`
  ([`docs/CONSENSUS_PARITY_DOCTRINE.md`](../docs/CONSENSUS_PARITY_DOCTRINE.md)),
  supply-chain execution (fetch-and-run / decode-and-run / dynamic load / remote
  installs / new submodules + workflows), committed secrets, and dangerous C
  calls. A **HIGH** finding blocks the merge. The scan reads the proposed head as
inert Git data and executes nothing from it.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub security
advisories on
[z23c/z23](https://github.com/z23c/z23/security/advisories/new),
rather than filing a public issue. If you cannot use advisories, contact
the maintainer privately.

There is no bug-bounty program.

## Past audits

A third-party security and cryptographic audit was received and triaged
in June 2026. The point-by-point disposition record — what was fixed,
what was refuted (with citations), and what is deferred and tracked — is
folded into ["Concrete safeguards"](../docs/node/SECURITY_AND_INTEGRITY.md#concrete-safeguards).
