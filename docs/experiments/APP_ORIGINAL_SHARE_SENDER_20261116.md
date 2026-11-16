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
Focused selftest: NOT RUN. A real original-share sender, receiver, graphical
observation, and two-host exchange: NOT RUN. This fixture does not establish
live network or GUI behavior.
