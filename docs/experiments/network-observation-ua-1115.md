<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

<!-- claim: symbol-present nm_copy_user_agent engine/services/src/network_monitor.c # bounded peer user-agent normalization -->
# Peer observation user-agent persistence

On 2026-11-15, source base `cf951c66924bcf5ed1b7a19ae5b9a11843fad5cc` was tested with GCC 14.2.0 on an AMD Ryzen 9 7950X3D. The sampler copies peer-supplied user agents into observation records. Empty, whitespace-only and non-printable values failed the existing model validation. The model save lifecycle trims surrounding ASCII whitespace.

The sampler now replaces bytes outside printable ASCII with `?` and uses `unknown` when the bounded result is empty or all spaces. Already-canonical printable names are preserved. Model validation remains unchanged. The sampler fixture covers empty, whitespace-only, control and high-byte input, printable punctuation and the 95-byte bound, while retaining its existing peer and fold assertions.

`DEVBUILD_CLASS=normal devbuild --wait make -j28 t-fast ONLY=network_monitor` ran one group. Before the fix, the group failed with seven assertions after four peer observations failed validation. After the fix and final fixture changes, the same group passed with no skips. These are correctness observations, not a performance comparison.

The first serial compilation was interrupted without a test verdict; its unverified development object epoch was quarantined and the subsequent run rebuilt it. Local experiment logs are retained by SHA-256: the red run log has SHA-256 `a7debd5f920f4afa10a06e3906b1161a6fb67ce4c25147132c163926961db083`, its group log `51fd5b4cb03a851b5f5b56889af3040497da3448aa4fc34354ea2c47b1530975`, and the final passing log `2eaf3db4a5de4d7c0c4af5689270a515b42ca2094ebc1a5bff6391e2d084082e`. The failure scratch was retained by the admission rail.
