/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_BODY_FETCH_MISSING_HAVE_DATA_H
#define ZCL_CONDITIONS_BODY_FETCH_MISSING_HAVE_DATA_H

#include <stdbool.h>
#include <stdint.h>

/* SYMPTOM: tip has not advanced for >= 60s and EITHER (a) the active-frontier
 *   candidate from stage_repair has no observed body and its block_index
 *   lacks BLOCK_HAVE_DATA (the next body to extend the chain is missing), OR
 *   (b) utxo_apply's own select-idle record (jobs/utxo_apply_stage.h) names
 *   an ARBITRARY earlier height whose HAVE_DATA flag the sibling
 *   have_data_unreadable Condition just cleared (mid-chain, e.g. during a
 *   stale-script/coin-backfill replay) — that height sits behind
 *   body_fetch's own cursor, so candidate (a) never matches it. The lower of
 *   the two candidates is targeted first.
 * Candidate (a) is bound to the durable validate hash, best-header ancestry,
 * and the exact visible or durable finalized parent identity, then queues through
 * sync_monitor_queue_best_header_body(target, exact_hash). Candidate (b)
 * retains the active-frontier queue path. A failed queue returns
 * COND_REMEDY_FAILED.
 * WITNESSED: an exact-hash body row is observed, OR that exact captured
 *   target's block data is readable on disk.
 * COND_CRITICAL; poll_secs=5 (backoff 30s, max_attempts 5). Continue-with-
 *   cooldown: re-arms every 600s (unbounded) after exhaustion instead of
 *   latching permanently — the remedy depends on an external P2P fetch. */
void register_body_fetch_missing_have_data(void);

#ifdef ZCL_TESTING
void body_fetch_missing_have_data_test_reset(void);
int body_fetch_missing_have_data_test_remedy_calls(void);
/* Stable diagnostic emitted when candidate 1 is intentionally not queued. */
const char *body_fetch_missing_have_data_test_last_skip_reason(void);
/* Overrides the utxo_apply select-idle candidate's source. NULL restores the
 * "no signal" stub (the reset() default) — production always uses the real
 * jobs/utxo_apply_stage.h accessors. */
void body_fetch_missing_have_data_test_set_select_idle_stubs(
    int64_t (*height_fn)(void), bool (*is_read_failure_fn)(void));
#endif

#endif /* ZCL_CONDITIONS_BODY_FETCH_MISSING_HAVE_DATA_H */
