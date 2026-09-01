/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_batch_commit — structured per-batch-commit telemetry for the
 * utxo_apply kernel drain (engine/jobs/src/utxo_apply_stage_drain.c:
 * utxo_apply_stage_drain). A "batch" is the outer BEGIN IMMEDIATE ..
 * COMMIT window stage_batch_begin()/stage_batch_end() (platform/modules/util/src/
 * stage.c) opens once around up to max_steps single-height folds, so the
 * COMMIT + fsync it pays is the one IO cliff a slow disk / degraded WAL
 * shows up on first. utxo_apply_stage_drain() calls
 * utxo_apply_batch_commit_record() exactly once per successful outer
 * COMMIT, with the height range folded, the row (block) count, and the
 * measured commit wall time. That turns a silent slowdown into one
 * greppable LOG_INFO line plus rolling stats any operator or agent can read
 * live via the diagnostics registry (`z23 dumpstate batch_commit`).
 */
#ifndef ZCL_JOBS_UTXO_APPLY_BATCH_COMMIT_H
#define ZCL_JOBS_UTXO_APPLY_BATCH_COMMIT_H

#include <stdbool.h>
#include <stdint.h>

/* Record one successful outer-batch COMMIT. height_before_batch is the
 * cursor (g_ua_last_advance_height) snapshotted BEFORE the drain loop ran;
 * rows is the number of heights advanced in this batch (utxo_apply_
 * stage_drain's `advanced`) — heights folded are the inclusive range
 * (height_before_batch+1 .. height_before_batch+rows) when rows > 0, or
 * just height_before_batch (a zero-row commit: dirty non-advancing work
 * only, e.g. a reorg unwind — see stage_batch_dirty in util/stage.h) when
 * rows == 0. commit_us is the measured wall time of the stage_batch_end()
 * call that issued the COMMIT (includes any pre-commit fsync hook). Emits
 * one LOG_INFO("[batch_commit] heights=%d..%d rows=%d commit_us=%lld ...")
 * line and folds the sample into a rolling ring buffer + EWMA + running
 * max. Cheap: one mutex, no allocation, no I/O beyond the log line itself.
 * Reentrant-safe. */
void utxo_apply_batch_commit_record(int64_t height_before_batch, int rows,
                                     int64_t commit_us);

/* Test-only: reset every rolling-stats field to its zero state. The
 * telemetry is process-global (one drain loop applies at a time, mirroring
 * stage_batch_begin/end's own process-global g_batch_open), so a test that
 * wants to assert exact ring/EWMA values after a known sequence of commits
 * must reset first — otherwise earlier test blocks' commits are still
 * folded in. No-op in production (never called outside lib/test). */
void utxo_apply_batch_commit_reset_for_test(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe; allocates
 * nothing (the caller's json_value owns the buffer). */
struct json_value;
bool utxo_apply_batch_commit_dump_state_json(struct json_value *out,
                                              const char *key);

#endif /* ZCL_JOBS_UTXO_APPLY_BATCH_COMMIT_H */
