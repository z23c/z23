/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * batch_fsync_slow — Condition that watches the reducer drive's batched
 * pre-commit durability flush (reducer_body_fsync.c) EWMA against a budget
 * and names a blocker on a sustained IO regression. See the doc comment in
 * engine/conditions/src/batch_fsync_slow.c for the full SYMPTOM/REMEDY/WITNESSED
 * contract. */

#ifndef ZCL_CONDITIONS_BATCH_FSYNC_SLOW_H
#define ZCL_CONDITIONS_BATCH_FSYNC_SLOW_H

#include <stdint.h>

/* SYMPTOM/REMEDY/WITNESSED: see the doc comment in
 * engine/conditions/src/batch_fsync_slow.c. In short: watches the EWMA of the
 * reducer drive's batched pre-commit durability flush
 * (reducer_batched_durability_precommit in
 * engine/reducer/services/src/reducer_body_fsync.c — fdatasyncs deferred block bodies +
 * flushes the event_log once per stage-batch COMMIT, and can VETO the
 * commit) against a GENEROUS env-tunable budget
 * (ZCL_BATCH_FSYNC_SLOW_EWMA_US, default 4,000,000 = 4s), and names a
 * TRANSIENT "batch_fsync_slow" blocker when a SUSTAINED IO regression is
 * observed. OBSERVATIONAL ONLY — never changes the flush cadence, the veto
 * decision, or any validity predicate; it only times an already-expensive
 * fsync. COND_WARN; a one-time informational page then an unbounded
 * 5-minute cooldown re-arm while the flush stays slow — never latches
 * operator_needed on a transient IO regression (mirrors disk_full_pause.c). */
void register_batch_fsync_slow(void);

#ifdef ZCL_TESTING
void batch_fsync_slow_test_reset(void);
int  batch_fsync_slow_test_remedy_calls(void);
/* Force the budget the detect/witness/remedy predicates compare the EWMA
 * against, instead of the env var / compile-time default, so tests do not
 * depend on process-wide getenv state. Pass a negative value to restore the
 * real env-or-default lookup. */
void batch_fsync_slow_test_set_budget_us(int64_t budget_us);
#endif

#endif /* ZCL_CONDITIONS_BATCH_FSYNC_SLOW_H */
