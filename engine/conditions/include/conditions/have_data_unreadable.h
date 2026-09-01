/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_HAVE_DATA_UNREADABLE_H
#define ZCL_CONDITIONS_HAVE_DATA_UNREADABLE_H

#include <stdbool.h>
#include <stdint.h>

/* SYMPTOM: tip has not advanced for >= 60s and EITHER (a) the tip+1 block is
 *   marked BLOCK_HAVE_DATA but block_index_have_data_readable() fails
 *   (file=nFile pos=nDataPos unreadable on disk), OR (b) utxo_apply's own
 *   select-idle record (jobs/utxo_apply_stage.h) names an ARBITRARY earlier
 *   height it is stuck re-reading with reason INDEXED_BODY_READ_FAILED /
 *   STAGE_READ_FAILED (e.g. mid-chain, during a stale-script/coin-backfill
 *   replay that rewinds the stage cursor) — never just tip+1. The lower of
 *   the two candidates is targeted first.
 * REMEDY: clearing h — clear BLOCK_HAVE_DATA, set nFile=-1/nDataPos=0 and
 *   emit EV_BLOCK_REJECTED so the body is re-fetched (the sibling
 *   body_fetch_missing_have_data Condition drives the re-queue).
 * WITNESSED: that block's data is readable again
 *   (block_index_have_data_readable()), OR the blocked stage's own cursor
 *   (utxo_apply_stage_cursor()) has advanced past target — the reducer
 *   re-derived through the repaired height.
 * COND_WARN; poll_secs=5 (backoff 30s, max_attempts 3). Continue-with-
 *   cooldown: re-arms every 600s (unbounded) after exhaustion instead of
 *   latching permanently — the remedy depends on an external P2P re-fetch. */
void register_have_data_unreadable(void);

#ifdef ZCL_TESTING
void have_data_unreadable_test_reset(void);
int have_data_unreadable_test_remedy_calls(void);
/* Overrides the utxo_apply select-idle candidate's source. NULL restores the
 * "no signal" stub (the reset() default) — production always uses the real
 * jobs/utxo_apply_stage.h accessors. */
void have_data_unreadable_test_set_select_idle_stubs(
    int64_t (*height_fn)(void), bool (*is_read_failure_fn)(void));
#endif

#endif /* ZCL_CONDITIONS_HAVE_DATA_UNREADABLE_H */
