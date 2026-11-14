<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Catchup pause and Sapling witness parity

On 2026-11-14, a focused `node_db_catchup_service` fixture at base
`4343941d97dd1a3e0c2a5f730df27537b8c7f908` compared an interrupted main
catchup walk with an uninterrupted walk over five disk-backed blocks. Both
isolated databases were seeded with the same test note; the blocks contain
Sapling commitments and the walk creates and advances its serialized witness.
This does not test note decryption or importing existing wallet keys.

The fixture observes a committed partial prefix before requesting pause and
bounds each child run to 30 seconds using a monotonic deadline. With every body available, both runs
produce the same block rows, per-height receipts, cursor and witness bytes,
height and independently computed tree root at the tip. With height 4 marked
missing, both runs retain the same witness at height 3 and produce matching
rows and receipts for the readable heights. The witness is stale across the
missing body; this is not evidence of a tip-ready witness.

`devbuild --wait make -j8 t-fast ONLY=node_db_catchup_service` passed one group
with zero skips in 26.2 seconds of test execution. The pause trigger uses the
existing batch counter and a test delay; its exact stopping height depends on
scheduling, and the fixture asserts that the observed stop is partial. The
first fixture run failed before indexing because its predecessor hash was
blank; the corrected fixture uses a nonzero predecessor. A focused cyclomatic
complexity check passed after the test helpers were split.

## Background deferral and wallet recovery

On 2026-11-14, isolated fixtures exercised the background deferral candidate
with a wallet-import scan-state change. A disk-backed Sapling fixture compared
an interrupted GENTLE background walk with an uninterrupted walk for complete
and sparse bodies, including nonempty witness bytes, roots, heights, rows and
receipts. Separate cases exercised BUSY_SNAPSHOT restart and restoration of
owed database settings after a foreign transaction and an injected restore
failure.

A wallet-reconcile fixture deferred background history, then processed a tip
body containing a previously absent encrypted note. It checked note discovery,
the derived nullifier and witness, a confirmed transaction, a spent nullifier
and completion of a queued writer barrier. This exercises wallet reconciliation;
it does not represent a complete reducer or device thermal test.

An isolated default spending-key import scanned a three-body chain and found a
previously absent encrypted historical note. With one historical body missing,
the original implementation returned success after reading two of three bodies,
while its scan height still reached the tip and no retry marker existed. After
the scan-state change, the same incomplete import reported an error, retained
the key across a node database reopen, and exposed a durable pending scan floor
and an incomplete public scan status. Restoring the body and completing a
rescan and wallet flush found the note and cleared the persisted marker. A
forced overlap held an older scan before marker clearing while a second key was
imported with no chain context; the older scan preserved the new obligation,
and a later full scan found the note. A triggered postscan marker-delete failure
returned the scan-save error, retained the key and marker across reopen, and
recovered after removing the trigger and rescanning.

The integrated `node_db_catchup_service`, `tip_finalize_post_step` and
`wallet_rescan_coverage` groups passed together with zero skips. Following
stronger database-reopen and attributed fault assertions, the focused
`node_db_catchup_service` group passed with zero skips. These are isolated
fixture results; they do not establish physical-device behavior, a complete
reducer path, or performance under thermal pressure.

Reproduce the combined focused selection with:

```sh
devbuild --wait make -j8 t-fast-exact ONLY=node_db_catchup_service,tip_finalize_post_step,wallet_rescan_coverage
```
