<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Projection status write experiment

The projection status replay uses a prepared UPSERT that assigns every
reconstructed non-key column. Header replay retains its existing replacement.
The repository-owned projection schema has a hash primary key and height
index, with no triggers or foreign keys. UPSERT and replacement have different
trigger and conflict behavior in modified schemas; this experiment does not
claim equivalence for those schemas.

<!-- claim: symbol-present catch_up_apply_status engine/modules/storage/src/block_index_projection_status.c # status projection replay -->

On 2026-11-15 UTC, three alternating pairs ran a synthetic fixture on ext4 on
an AMD Ryzen 9 7950X3D with GCC 14.2.0. Each used 500,000 headers with
400-byte solutions and three 171,912-event changing-status phases. The first
and third phases used the same distributed targets in sorted and fixed-seed
shuffled order; the middle phase reset them. Before each phase a synthetic
flat binding cleared the dirty journal and the SQLite connection was reopened.
The projection was 429,932,544 bytes, with a 256 MiB SQLite page cache.
The target count is a synthetic workload choice, not an observation of phone
shutdown replay. Host OS cache was not controlled.

| Pair | Variant | Sorted s | Reset s | Shuffled s |
| --- | --- | ---: | ---: | ---: |
| 1 | baseline | 14.656 | 19.719 | 16.169 |
| 1 | UPSERT | 11.506 | 13.382 | 15.403 |
| 2 | baseline | 21.116 | 20.300 | 13.803 |
| 2 | UPSERT | 14.094 | 12.999 | 6.198 |
| 3 | baseline | 15.962 | 17.038 | 20.304 |
| 3 | UPSERT | 13.374 | 13.622 | 10.722 |

SQLite reported baseline cache writes of 166,962 / 151,637 / 137,233 for
sorted / reset / shuffled, versus 122,833 / 122,758 / 123,501 for UPSERT in
each pair. These are SQLite cache-write counters, not bytes or flash writes.
Every run passed the same isolated registered test, with no retries or skips;
load averages varied from 4.47 to 40.01. These samples support the measured
synthetic write reduction but do not establish phone performance or explain a
phone shutdown.

A separate 99 Hz user-space cycles profile sampled the registered fixture;
SQLite index traversal and cache work appeared among test-process symbols.
Frame-pointer call chains did not reliably distinguish fixture generation,
validation and replay, and sample percentages are not wall-time shares.

The base commit was efc86274e00ec5f38b783b112c4d6f3825776e55. The comparison
fixture was Git blob 07c78da0047d663853b9ff23a475a45ae6ece055; the tested
projection, internal header and status blobs were respectively
211383a9316123dcb3148b5c7cee38da6087f044,
1a214d6612cd0d65a25f78ccf10d812ced8ebe1f and
981ede7bcfa269e910a6b1bcfaed530b7879d4dd. The full regression fixture retains
the UPDATE failure injection; the comparison used the same INSERT failure
injection for both variants. The large fixture is retained in the external
projection-cache-scale-20261115 evidence archive, not in ordinary test runs.
Its PAIRED-SHA256SUMS manifest has SHA-256
8f3f30b4ca308e24e245df5b8bb21e72a779837613cf9191b7a7bab3214c8906.
Run the retained fixture on an isolated worktree through
`ZCL_BIP_SCALE_EXPERIMENT=1 DEVBUILD_CLASS=normal devbuild --wait make -j28
ZCL_TEST_TMPFS=0 t-fast-exact ONLY=test_block_index_projection_shard_07`.
