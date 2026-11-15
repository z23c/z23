<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Block index projection catch-up

On 2026-11-15 UTC, an isolated event log and SQLite projection exercised
1,000 synthetic headers, 10,000 changing status events and 10,000 identical
status events. The host used an AMD Ryzen 9 7950X3D and GCC 14.2.0; the
fixture ran on ext4. This is not a phone datadir or a reproduction of a phone
shutdown.

Before the change, three runs measured identical-status catch-up at 57.794,
57.395 and 61.425 ms; changing-status catch-up took 58.234, 59.115 and
58.622 ms. Post-change standalone runs measured identical status at 53.956,
57.179 and 42.594 ms; changing status took 74.298, 98.087 and 63.665 ms.
Host conditions varied; these unpaired measurements do not establish a
performance improvement or rule out a changing-status regression.

Three alternating baseline/candidate pairs measured identical-status elapsed
milliseconds as follows. The baseline intentionally fails the new no-write
regression and the runner automatically repeats it, adding work before each
candidate; both baseline observations are listed. Host load varied.

| Pair | Baseline first | Baseline rerun | Candidate |
| --- | ---: | ---: | ---: |
| 1 | 59.674 | 57.360 | 40.310 |
| 2 | 105.938 | 122.321 | 60.421 |
| 3 | 79.935 | 73.286 | 75.103 |

The candidate test traces SQL: an identical status does not write its row or
add a dirty entry, while changes to each of the five fields and reversions do.
It verifies event and scan counters, cursor, existing dirty state and reopened
rows. Timing differences between outer elapsed time and `last_catch_up_ms`
include metadata persistence, checkpoint work and clock rounding; they do not
measure checkpoint time alone. The cause and duration of a real phone shutdown
remain unproven.

<!-- claim: symbol-present catch_up_apply_status engine/modules/storage/src/block_index_projection_status.c # status replay -->

For changing-status events, the paired baseline reruns took 57.575, 128.579
and 72.283 ms; candidates took 59.265, 105.346 and 115.562 ms. The runner
retained only excerpts of the first failed baseline attempts, so their
changing-status timings are unavailable. The full projection group passed nine
cold groups before the final test-only assertion was added; the affected
shard and shape checks passed after it.

The source base was commit 2a9b44755018bfcc4db9a18819e778472918abce.
The timed status implementation was Git blob d53bbab2628b401b09af979c4b328d6b6a6f883e;
the final refactored implementation is blob c6ac375fcbf2ff714079c7c8a895af287e3778b6.
The latter retains the same comparisons and was not retimed. Run the isolated
disk fixture with `DEVBUILD_CLASS=normal devbuild --wait make -j28
ZCL_TEST_TMPFS=0 t-fast-exact ONLY=test_block_index_projection_shard_07`;
run the full registered group with `DEVBUILD_CLASS=normal devbuild --wait
make -j28 t-fast ONLY=block_index_projection`. The retained external evidence
archive is named projection-catchup-20261115; its SHA256SUMS manifest has
SHA-256 37dd8f3ded65b4338ef46262eebb96b5fe6f21bcaefd625aec85a1f4771524b3.
