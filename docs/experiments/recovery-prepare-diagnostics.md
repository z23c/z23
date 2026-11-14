<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Pending replay preparation diagnostics

The preparation failure message previously combined several failure stages. Fixed
messages now identify the failed stage without including wallet data or hashes.
The checks retain their order and cancellation remains silent.

<!-- claim: symbol-present boot_pending_replay_prepare engine/composition/src/boot_wallet_cutover_startup.c # pending replay preparation -->

On 2026-11-14, the initial complexity check found the preparation function at
16 against the cap of 15. Extracting the diagnostic helpers brought the
revised tree under the cap. `DEVBUILD_CLASS=light devbuild --wait
build/bin/z23-lint check-cyclomatic-complexity` passed. A first focused run
passed while the source was being revised and is superseded by the final run.
The final `DEVBUILD_CLASS=normal devbuild --wait make t-fast
ONLY=block_index_loader` run passed one group with zero failures or skips;
external archive and memory fixture environment variables were unset.
