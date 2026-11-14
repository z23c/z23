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
