<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Hosting a caller-pinned original share

The split sender accepts an optional original share with an absolute `--share`
path and all three caller-reviewed values: `--share-sha256`,
`--share-publisher`, and `--share-root`. It copies and hashes the regular
file, verifies its release identity, receives and builds it locally, and
hosts an offer for the same bytes. The image hash is the result of that local
build; it is not a previously pinned image. The sender retains public command
responses and publishes `share-ready.json` only after observing host status.
The normal tiny-app sender remains the default when `--share` is absent.
<!-- claim: symbol-present aj_role_sender_share tools/app_journey_live.c # caller-pinned original share sender -->

Split roles accept `--network=main` or `--network=regtest`, defaulting to
regtest. Main mode omits the regtest and validation-disabling flags, binds its
node listener to loopback, and uses a fresh caller-owned home and datadir.
The sender's explicit dead-sink connection suppresses normal outbound peer
selection; the Tor endpoint remains reachable, so this is not an inbound
allowlist. For a mainnet share, include `--network=main` alongside the pinned
share arguments. The sender records the network in `share-ready.json`; a
receiver must select the same network.

The focused fake-child selftest passed through the forced R2 gate on source
`7c5e43bbc010ff6437f3c612f88b6fcc3580bf7d`, including the main-mode
supervised node worker and binding and refusal checks. Its evidence manifest
verified and successful scratch was released. This fixture is not a live
network or GUI test.

A first live sender on source `4ba42f5a65465d1899025cbcf1418cf6bb17dd00`
verified the reviewed share and its receive plan, but receive commit refused
`wrong-chain-id` while the fixture selected regtest. No hosting was established
in that run. The share contains a mainnet chain identifier; native package
acceptance remains enforced.

A main-mode sender on `7c5e43bbc010ff6437f3c612f88b6fcc3580bf7d` then
verified, received and built the original share, pinned the same bytes as a
carrier and observed an enabled host at generation 1. The share SHA-256 was
`6a714436ba1a66b98339cfeddbb68dbdf634fd4dea9d335db6fad663e1cb5cc9`;
the locally rebuilt image SHA3 was
`baf203b90f1f4149d93812ebee99695fec709aaacb5913e775fc52032f4ea0de`.
The isolated fixture reported zero peers. Receive commit took 65.013 seconds
and build commit 12.632 seconds; both reported exceeded budgets. The sender
finished successfully and its gate scratch was released. Remote data transfer,
cross-host retrieval, catalog discovery and graphical operation: NOT RUN.
