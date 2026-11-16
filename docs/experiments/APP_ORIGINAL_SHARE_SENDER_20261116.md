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

The source fixture exercises the native command boundaries with a fake child,
including mismatched identity, plan, carrier, digest and status refusals.
The focused selftest passed on source `b079eee79d0cb6df72ead2aca710ad5cd1c9a2e9` through the forced R2 gate; its archive and manifest verified and the successful scratch was released. A real original-share sender, receiver, graphical
observation, and two-host exchange: NOT RUN. This fixture does not establish
live network or GUI behavior.

A first live sender on source `4ba42f5a65465d1899025cbcf1418cf6bb17dd00`
verified the reviewed share and its receive plan, but receive commit refused
`wrong-chain-id` while the fixture selected regtest. No hosting or live
exchange was established. The share contains a mainnet chain identifier;
acceptance remains enforced by the native package store.

Split roles accept `--network=main` or `--network=regtest`, defaulting to
regtest. Main mode omits the regtest and validation-disabling flags, binds its
node listener to loopback, and uses a fresh caller-owned home and datadir.
The sender's explicit dead-sink connection suppresses normal outbound peer
selection; the Tor endpoint remains reachable, so this is not an inbound
allowlist. Main-mode focused checks and an original-share rerun: NOT RUN.

For an original mainnet share, include `--network=main` alongside the
caller-pinned share arguments. The sender records the selected network in
`share-ready.json`; a receiver must select the same network.
