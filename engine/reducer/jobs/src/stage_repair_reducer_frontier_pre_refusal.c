/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_reducer_frontier_pre_refusal — tear-only reducer-frontier
 * helpers that run before the coin-tear refusal returns control to L2.
 *
 * The retained cursor-refill machinery lives in
 * stage_repair_reducer_frontier_refill.c. This file is the narrow
 * pre-refusal adapter layer: it can clear a pending coin-tear refusal only
 * after proving a local cursor clamp can make forward progress.
 *
 * // repair-rung-ok:test_stage_repair_script_refill
 */

#include "jobs/stage_repair.h"
#include "stage_repair_reducer_frontier_internal.h"

#include "util/log_macros.h"

#include <sqlite3.h>

bool stage_reducer_frontier_reconcile_validate_hash_split_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out)
        LOG_FAIL("stage_repair",
                 "[stage_repair] validate hash-split cursor: NULL argument "
                 "(db=%d out=%d)", db != NULL, out != NULL);
    if (out->validate_headers_cursor_before <= out->hstar + 1)
        return true;

    int end_height = out->validate_headers_cursor_before - 1;
    if (out->sweep_top < end_height)
        end_height = out->sweep_top;
    if (!stage_reducer_frontier_find_lowest_validate_headers_hash_split_unlocked(
            db, out->hstar + 1, end_height,
            &out->lowest_validate_headers_hash_split)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] validate hash-split cursor scan failed "
                 "window=[%d,%d] cursor=%d hstar=%d",
                 out->hstar + 1, end_height,
                 out->validate_headers_cursor_before, out->hstar);
        return false;
    }
    if (out->lowest_validate_headers_hash_split < 0)
        return true;

    if (out->validate_headers_cursor_before <=
        out->lowest_validate_headers_hash_split) {
        out->validate_headers_cursor_after =
            out->validate_headers_cursor_before;
        return true;
    }

    out->clamped_validate_headers = true;
    out->validate_headers_cursor_after =
        out->lowest_validate_headers_hash_split;
    if (!apply)
        return true;

    if (!stage_reducer_frontier_force_stage_cursor_in_tx(
            db, "validate_headers", "validate_headers-hash-split",
            out->lowest_validate_headers_hash_split)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] validate hash-split cursor clamp failed "
                 "target=%d before=%d",
                 out->lowest_validate_headers_hash_split,
                 out->validate_headers_cursor_before);
        return false;
    }
    return true;
}

/* FIX-2a — pre-refusal invocation. Runs while refused_coin_tear is pending,
 * after the replay repairs and BEFORE the coin-tear refusal (call site in
 * stage_repair_reducer_frontier.c). Bounds start at
 * max(hstar+1, coins_applied) so by construction only provably-unapplied
 * heights are eligible. On clamp it clears refused_coin_tear and claims the
 * tick (the exact shape of the pre-refusal hash-split repair), which lets
 * the script stage's next tick rewrite the missing row within seconds. */
bool stage_reducer_frontier_try_unapplied_hole_clamp(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out,
    bool *handled)
{
    if (handled)
        *handled = false;
    if (!db || !out || !handled) {
        LOG_WARN("stage_repair",
                 "[stage_repair] unapplied-hole clamp: NULL argument "
                 "(db=%d out=%d handled=%d)",
                 db != NULL, out != NULL, handled != NULL);
        return false;
    }
    /* No coin-tear refusal pending: the post-refusal FIX-2b invocation in
     * reconcile_refill_cursors owns this tick (and the tip_finalize floor
     * reconcile must still run after it). Silent no-op — this is the
     * healthy per-tick path, not a refusal. */
    if (!out->refused_coin_tear)
        return true;
    if (!out->coins_applied_found || out->coins_applied_height < 0) {
        LOG_WARN("stage_repair",
                 "[stage_repair] unapplied-hole clamp refused: coins "
                 "frontier unknown (coins_applied_found=%d height=%d)",
                 out->coins_applied_found, out->coins_applied_height);
        return true;
    }

    int scan_floor = out->hstar + 1;
    if (out->coins_applied_height > scan_floor)
        scan_floor = out->coins_applied_height;

    if (!stage_reducer_frontier_reconcile_script_proof_refill_cursors(
            db, apply, scan_floor, out))
        return false;

    if (!out->clamped_script_validate && !out->clamped_proof_validate)
        return true; /* no unapplied hole in bounds; the refusal proceeds */

    out->pre_refusal_unapplied_clamp = true;
    out->refused_coin_tear = false;
    out->repaired = true;
    *handled = true;
    if (apply) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier clamped unapplied "
                 "script/proof refill hole before coin-tear refusal "
                 "hstar=%d coins_applied=%d script_validate=%d->%d "
                 "proof_validate=%d->%d script_hole=%d proof_hole=%d",
                 out->hstar, out->coins_applied_height,
                 out->script_validate_cursor_before,
                 out->script_validate_cursor_after,
                 out->proof_validate_cursor_before,
                 out->proof_validate_cursor_after,
                 out->lowest_script_validate_refill_hole,
                 out->lowest_proof_validate_refill_hole);
    }
    return true;
}
