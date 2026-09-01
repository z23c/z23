/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * replay_count_only — the D2 coinbase-maturity REPLAY GATE counting harness.
 *
 * THE GATE (docs/CONSENSUS_PARITY_DOCTRINE.md): before TIGHTENING the
 * bounded coinbase-maturity predicate (utxo_apply_delta.c:281) to restore
 * parity with zclassicd, replay the ENTIRE real chain (genesis->tip) with the
 * candidate tightening ON (-enforce-coinbase-maturity) and confirm ZERO
 * false-rejects. 0 == safe to land the parity restore; >=1 == the chain
 * depends on the looser rule (the h=478544 class) and the fix MUST NOT ship.
 *
 * The live fold STOPS at the first D2 fire (delta_fail -> JOB_BLOCKED, the
 * frontier halts), so it can only ever find the FIRST offender. This module
 * provides a NON-STOPPING COUNT-AND-CONTINUE mode (mirroring the model in
 * replay_verify_service.c:55-67 note_first_fail) that LOGS + COUNTS every D2
 * fire and lets the fold continue to tip, accumulating a total.
 *
 * ── SAFETY (the load-bearing invariant) ──────────────────────────────────
 *   Count-only mode is GATED ENTIRELY on the ZCL_REPLAY_COUNT_ONLY env var.
 *   When the env is UNSET, replay_count_only_active() returns false and EVERY
 *   function here is a no-op the live fold never calls into — the live
 *   consensus path is BYTE-IDENTICAL to today. The env is read ONCE (cached),
 *   so the active-state is stable for the whole process.
 *
 *   When counting, the fold AUTHORS NO COINS for an offending block and
 *   ADVANCES NO state for it beyond the read-only cursor walk — strictly
 *   read/log/continue. Authoring past a real reject would corrupt the copy
 *   datadir's coins_kv, which is why this is a copy-only diagnostic.
 *
 * This is consensus-ADJACENT but only behind the env gate; never run against
 * a live datadir (the make target refuses ~/.zclassic-c23 and ~/.zclassic).
 */

#ifndef ZCL_JOBS_REPLAY_COUNT_ONLY_H
#define ZCL_JOBS_REPLAY_COUNT_ONLY_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uint256;

/* True iff ZCL_REPLAY_COUNT_ONLY is set (to a non-empty, non-"0" value).
 * Read ONCE on first call, then cached — the active-state is stable for the
 * whole process. When false, the count-only path is never entered and the
 * live fold runs exactly as it does today. */
bool replay_count_only_active(void);

/* Record one D2 coinbase-maturity fire (a premature coinbase spend the
 * tightening would NEWLY reject). Logs height + spent outpoint, increments
 * total_newly_rejected, and records the FIRST offending height (mirrors
 * note_first_fail). No-op if count-only is inactive. */
void replay_count_only_note_d2_fire(uint32_t height,
                                    const struct uint256 *spent_txid,
                                    uint32_t spent_vout);

/* Record that one block at `height` was replayed (folded, read-only walk).
 * Tracks blocks_replayed and the max height seen (== tip on a contiguous
 * genesis->tip walk). No-op if count-only is inactive. */
void replay_count_only_note_block_replayed(uint32_t height);

/* COVERAGE PRE-FLIGHT (anti-false-0): a sparse / non-genesis walk silently
 * reports a FALSE 0 (the predicate never fires on the blocks it skipped).
 * Record that genesis (h=0) was readable; the gate FAILS unless this is set
 * AND blocks_replayed == tip+1 (contiguous). No-op if count-only inactive. */
void replay_count_only_mark_genesis_readable(void);

/* Emit the single greppable structured summary line (models
 * replay_verify_service.c:264-285):
 *   {first_offending_height, total_newly_rejected, blocks_replayed, tip,
 *    target_tip, genesis_readable, contiguous, reached_target, gate_pass}
 * `target_tip` is the header-chain target the staged pipeline climbs toward
 * (the header_admit cursor); pass <0 if unknown. reached_target is true iff
 * tip+1 == target_tip (the apply walk reached the full header tip, not just a
 * stalled subset). gate_pass is true iff total_newly_rejected==0 &&
 * genesis_readable && contiguous (blocks_replayed==tip+1) && reached_target.
 * The make target greps this line. No-op (no line) if count-only is inactive.
 * Safe to call repeatedly; emits each call. */
void replay_count_only_emit_summary(int64_t target_tip);

/* Test-only reset of the cached active-state + counters (so a unit test can
 * toggle the env between cases). Not called by production code. */
void replay_count_only_reset_for_test(void);

/* Test-only accessors (read the accumulated counters). */
int64_t  replay_count_only_total_rejected(void);
int64_t  replay_count_only_first_offending_height(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_JOBS_REPLAY_COUNT_ONLY_H */
