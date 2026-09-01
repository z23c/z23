/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_reducer_frontier_refill — refill forward-only reducer stages
 * after a hole is discovered below their cursor.
 *
 * FIX-2 (script/proof missing-row refill) keeps the shared scan+clamp core
 * here, with TWO invocations —
 *   FIX-2a stage_reducer_frontier_try_unapplied_hole_clamp(): pre-refusal
 *          wrapper in stage_repair_reducer_frontier_pre_refusal.c, bounds
 *          [max(hstar+1, coins_applied), min(cursor-1, sweep_top)], so only
 *          provably-UNAPPLIED heights are eligible. On clamp it clears
 *          refused_coin_tear (the pre-refusal hash-split precedent in
 *          stage_repair_reducer_frontier.c).
 *   FIX-2b stage_reducer_frontier_reconcile_refill_cursors(): post-refusal,
 *          retained here, bounds [hstar+1, min(cursor-1, sweep_top)] with the
 *          same coins floor on the clamp target.
 *
 * Coins floor (hard): a clamp target h must satisfy
 * h >= coins_applied_height. Coins are applied THROUGH coins_applied - 1
 * (utxo_apply_stage.c co-commit), so the height at coins_applied is
 * provably unapplied and a forward re-walk cannot hit spent prevouts. A
 * hole strictly below the coins frontier is the stale-script replay's
 * domain (inverse-delta machinery, stage_repair_reducer_frontier_coin.c).
 *
 * NEVER touch the utxo_apply cursor here: rewinding it would re-apply
 * coin deltas that are already committed (double-applied coins). Refill
 * clamps are limited to the script_validate / proof_validate cursors,
 * whose log stores are INSERT OR REPLACE — the forward re-walk rewrites
 * fresh verdicts and deletes nothing.
 */

#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "stage_repair_reducer_frontier_internal.h"

#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stddef.h>

#define RF_REFILL_REQUIRE(call, context) do {                         \
    if (!(call))                                                       \
        LOG_FAIL("stage_repair",                                      \
                 "[stage_repair] reducer_frontier refill failed "     \
                 "during %s", (context));                             \
} while (0)

static bool reconcile_validate_headers_refill_holes(
    sqlite3 *db,
    struct main_state *ms,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out)
        LOG_FAIL("stage_repair",
                 "[stage_repair] validate_headers refill: invalid args "
                 "(db=%d out=%d)", db != NULL, out != NULL);
    if (out->validate_headers_cursor_before <= out->hstar + 1)
        return true;

    int end_height = out->validate_headers_cursor_before - 1;
    if (out->sweep_top < end_height)
        end_height = out->sweep_top;
    if (!stage_reducer_frontier_find_lowest_validate_headers_refill_hole_unlocked(
            db, out->hstar + 1, end_height,
            &out->lowest_validate_headers_refill_hole)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] validate_headers refill scan failed "
                 "window=[%d,%d] cursor=%d hstar=%d",
                 out->hstar + 1, end_height,
                 out->validate_headers_cursor_before, out->hstar);
        return false;
    }
    if (!stage_reducer_frontier_find_lowest_validate_headers_hash_split_unlocked(
            db, out->hstar + 1, end_height,
            &out->lowest_validate_headers_hash_split)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] validate_headers hash-split scan failed "
                 "window=[%d,%d] cursor=%d hstar=%d",
                 out->hstar + 1, end_height,
                 out->validate_headers_cursor_before, out->hstar);
        return false;
    }

    /* VALIDATE-SIDE-ONLY clamp: the cursor rewind below re-derives the
     * canonical HEADER, which cures a stale validate_headers verdict but is a
     * semantic no-op for a SCRIPT-side split (it leaves the stale script row, so
     * H* cannot climb and the clamp would self-clear without progress). Classify
     * the split by the canonical active header; route a script-side split to the
     * coins-rewinding dual replay (lowest_script_validate_hash_split) and drop it
     * from the validate clamp target. INDETERMINATE (active header unavailable)
     * keeps the existing direction-blind clamp as a fallback. */
    if (out->lowest_validate_headers_hash_split >= 0) {
        bool err = false;
        enum rf_hash_split_side side = stage_repair_classify_hash_split(
            ms, db, out->lowest_validate_headers_hash_split, &err);
        if (err)
            return false;
        if (side == RF_SPLIT_SCRIPT_SIDE) {
            out->lowest_script_validate_hash_split =
                out->lowest_validate_headers_hash_split;
            out->lowest_validate_headers_hash_split = -1;
        }
    }
    return true;
}

static bool reconcile_body_fetch_refill_holes(
    sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out)
        LOG_FAIL("stage_repair",
                 "[stage_repair] body_fetch refill: invalid args "
                 "(db=%d out=%d)", db != NULL, out != NULL);
    if (out->body_fetch_cursor_before <= out->hstar + 1)
        return true;

    int end_height = out->body_fetch_cursor_before - 1;
    if (out->sweep_top < end_height)
        end_height = out->sweep_top;
    if (!stage_reducer_frontier_find_lowest_body_fetch_refill_hole_unlocked(
            db, out->hstar + 1, end_height,
            &out->lowest_body_fetch_refill_hole)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] body_fetch refill scan failed "
                 "window=[%d,%d] cursor=%d hstar=%d",
                 out->hstar + 1, end_height,
                 out->body_fetch_cursor_before, out->hstar);
        return false;
    }
    return true;
}

static bool reconcile_body_persist_refill_holes(
    sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out)
        LOG_FAIL("stage_repair",
                 "[stage_repair] body_persist refill: invalid args "
                 "(db=%d out=%d)", db != NULL, out != NULL);
    if (out->body_persist_cursor_before <= out->hstar + 1)
        return true;

    int end_height = out->body_persist_cursor_before - 1;
    if (out->sweep_top < end_height)
        end_height = out->sweep_top;
    if (!stage_reducer_frontier_find_lowest_body_persist_refill_hole_unlocked(
            db, out->hstar + 1, end_height,
            &out->lowest_body_persist_refill_hole)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] body_persist refill scan failed "
                 "window=[%d,%d] cursor=%d hstar=%d",
                 out->hstar + 1, end_height,
                 out->body_persist_cursor_before, out->hstar);
        return false;
    }
    return true;
}

bool stage_reducer_frontier_force_stage_cursor_in_tx(
    sqlite3 *db,
    const char *stage_name,
    const char *label,
    int target)
{
    progress_store_tx_lock();

    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier %s BEGIN failed: %s",
                 label, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }

    if (!stage_repair_force_stage_cursor(db, stage_name, target)) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reducer_frontier %s COMMIT failed: %s",
                 label, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }

    progress_store_tx_unlock();
    return true;
}

static int lower_refill_target(int target, int candidate)
{
    if (candidate >= 0 && (target < 0 || candidate < target))
        return candidate;
    return target;
}

static bool reconcile_validate_headers_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    int target = out->lowest_validate_headers_refill_hole;
    target = lower_refill_target(target,
                                 out->lowest_validate_headers_hash_split);
    if (target < 0) {
        out->validate_headers_cursor_after =
            out->validate_headers_cursor_before;
        return true;
    }

    if (out->validate_headers_cursor_before <= target) {
        out->validate_headers_cursor_after =
            out->validate_headers_cursor_before;
        return true;
    }

    out->clamped_validate_headers = true;
    out->validate_headers_cursor_after = target;
    if (!apply)
        return true;

    if (!stage_reducer_frontier_force_stage_cursor_in_tx(
            db, "validate_headers", "validate_headers", target)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] validate_headers cursor clamp failed "
                 "target=%d before=%d",
                 target, out->validate_headers_cursor_before);
        return false;
    }
    return true;
}

static bool reconcile_body_fetch_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    int target = out->lowest_have_data_cleared;
    target = lower_refill_target(target,
                                 out->lowest_validate_headers_refill_hole);
    target = lower_refill_target(target, out->lowest_body_fetch_refill_hole);
    if (target < 0) {
        out->body_fetch_cursor_after = out->body_fetch_cursor_before;
        return true;
    }

    if (out->body_fetch_cursor_before <= target) {
        out->body_fetch_cursor_after = out->body_fetch_cursor_before;
        return true;
    }

    out->clamped_body_fetch = true;
    out->body_fetch_cursor_after = target;
    if (!apply)
        return true;

    if (!stage_reducer_frontier_force_stage_cursor_in_tx(
            db, "body_fetch", "body_fetch", target)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] body_fetch cursor clamp failed "
                 "target=%d before=%d",
                 target, out->body_fetch_cursor_before);
        return false;
    }
    return true;
}

static bool reconcile_body_persist_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    int target = out->lowest_body_persist_refill_hole;
    int upstream_targets[] = {
        out->lowest_validate_headers_refill_hole,
        out->lowest_body_fetch_refill_hole,
    };
    for (size_t i = 0;
         i < sizeof(upstream_targets) / sizeof(upstream_targets[0]);
         i++) {
        int candidate = upstream_targets[i];
        if (candidate < 0)
            continue;
        bool present = false;
        if (!stage_reducer_frontier_body_persist_log_present_unlocked(
                db, candidate, &present)) {
            LOG_WARN("stage_repair",
                     "[stage_repair] body_persist upstream presence probe "
                     "failed h=%d",
                     candidate);
            return false;
        }
        if (!present)
            target = lower_refill_target(target, candidate);
    }
    if (target < 0) {
        out->body_persist_cursor_after = out->body_persist_cursor_before;
        return true;
    }

    if (out->body_persist_cursor_before <= target) {
        out->body_persist_cursor_after = out->body_persist_cursor_before;
        return true;
    }

    out->clamped_body_persist = true;
    out->body_persist_cursor_after = target;
    if (!apply)
        return true;

    if (!stage_reducer_frontier_force_stage_cursor_in_tx(
            db, "body_persist", "body_persist", target)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] body_persist cursor clamp failed "
                 "target=%d before=%d",
                 target, out->body_persist_cursor_before);
        return false;
    }
    return true;
}

/* Snapshot the script_validate / proof_validate cursors into the result
 * (before == after until a clamp lands). */
static bool read_script_proof_cursors(
    sqlite3 *db,
    struct stage_reducer_frontier_reconcile_result *out)
{
    progress_store_tx_lock();

    int script_cursor = -1;
    if (!stage_repair_cursor_at_unlocked(db, "script_validate",
                                         &script_cursor)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] script_validate cursor snapshot failed");
        progress_store_tx_unlock();
        return false;
    }

    int proof_cursor = -1;
    if (!stage_repair_cursor_at_unlocked(db, "proof_validate",
                                         &proof_cursor)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] proof_validate cursor snapshot failed");
        progress_store_tx_unlock();
        return false;
    }

    progress_store_tx_unlock();

    out->script_validate_cursor_before = script_cursor;
    out->script_validate_cursor_after = script_cursor;
    out->proof_validate_cursor_before = proof_cursor;
    out->proof_validate_cursor_after = proof_cursor;
    return true;
}

/* FIX-2 coins floor (hard): only clamp to heights whose coins are provably
 * UNAPPLIED — coins are applied THROUGH coins_applied_height - 1
 * (utxo_apply_stage.c co-commit), so h >= coins_applied_height means the
 * forward re-walk re-validates fresh and cannot double-apply deltas or hit
 * spent prevouts. Anything below the frontier is refused here and left to
 * the stale-script replay (inverse-delta machinery). */
static bool refill_target_in_unapplied_domain(
    const struct stage_reducer_frontier_reconcile_result *out,
    const char *stage_name,
    int target)
{
    if (!out->coins_applied_found || out->coins_applied_height < 0) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s refill clamp refused: coins frontier "
                 "unknown (target h=%d)",
                 stage_name, target);
        return false;
    }
    if (target < out->coins_applied_height) {
        LOG_WARN("stage_repair",
                 "[stage_repair] %s refill hole h=%d is strictly below the "
                 "coins frontier coins_applied=%d: replay domain "
                 "(inverse-delta), refusing forward refill clamp",
                 stage_name, target, out->coins_applied_height);
        return false;
    }
    return true;
}

static bool reconcile_script_validate_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    int target = out->lowest_script_validate_refill_hole;
    if (target < 0)
        return true;
    if (!refill_target_in_unapplied_domain(out, "script_validate", target))
        return true;
    if (out->script_validate_cursor_before <= target)
        return true;

    out->clamped_script_validate = true;
    out->script_validate_cursor_after = target;
    if (!apply)
        return true;

    return stage_reducer_frontier_force_stage_cursor_in_tx(
        db, "script_validate", "script_validate-refill", target);
}

static bool reconcile_proof_validate_cursor(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    int target = out->lowest_proof_validate_refill_hole;

    /* Fold in the script hole when NO proof row exists there: the proof
     * scan's upstream join (script ok=1) cannot see a height whose script
     * row is itself the missing one. An existing proof row at that height
     * is a real verdict and is left alone (never deleted). */
    int script_hole = out->lowest_script_validate_refill_hole;
    if (script_hole >= 0) {
        bool present = false;
        if (!stage_reducer_frontier_proof_validate_log_present_unlocked(
                db, script_hole, &present)) {
            LOG_WARN("stage_repair",
                     "[stage_repair] proof_validate presence probe failed "
                     "at script hole h=%d",
                     script_hole);
            return false;
        }
        if (!present)
            target = lower_refill_target(target, script_hole);
    }

    if (target < 0)
        return true;
    if (!refill_target_in_unapplied_domain(out, "proof_validate", target))
        return true;
    if (out->proof_validate_cursor_before <= target)
        return true;

    out->clamped_proof_validate = true;
    out->proof_validate_cursor_after = target;
    if (!apply)
        return true;

    if (!stage_reducer_frontier_force_stage_cursor_in_tx(
            db, "proof_validate", "proof_validate-refill", target)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] proof_validate cursor clamp failed "
                 "target=%d before=%d",
                 target, out->proof_validate_cursor_before);
        return false;
    }
    return true;
}

/* FIX-2 shared core (ONE implementation, TWO call sites): scan for rowless
 * script/proof holes from `scan_floor` up to min(cursor-1, sweep_top) per
 * stage, then clamp each cursor to its hole subject to the coins floor.
 * Touches ONLY the script_validate / proof_validate cursors; both log
 * stores are INSERT OR REPLACE, so the forward re-walk rewrites fresh
 * verdicts and no log row is ever deleted. */
bool stage_reducer_frontier_reconcile_script_proof_refill_cursors(
    sqlite3 *db,
    bool apply,
    int scan_floor,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out) {
        LOG_WARN("stage_repair",
                 "[stage_repair] script/proof refill: invalid args "
                 "(db=%d out=%d)",
                 db != NULL, out != NULL);
        return false;
    }
    if (!read_script_proof_cursors(db, out)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] script/proof refill cursor snapshot failed "
                 "scan_floor=%d",
                 scan_floor);
        return false;
    }

    out->lowest_script_validate_refill_hole = -1;
    out->lowest_proof_validate_refill_hole = -1;

    if (out->script_validate_cursor_before > scan_floor) {
        int end_height = out->script_validate_cursor_before - 1;
        if (out->sweep_top < end_height)
            end_height = out->sweep_top;
        if (!stage_reducer_frontier_find_lowest_script_validate_refill_hole_unlocked(
                db, scan_floor, end_height,
                &out->lowest_script_validate_refill_hole)) {
            LOG_WARN("stage_repair",
                     "[stage_repair] script_validate refill scan failed "
                     "window=[%d,%d] cursor=%d",
                     scan_floor, end_height,
                     out->script_validate_cursor_before);
            return false;
        }
    }

    if (out->proof_validate_cursor_before > scan_floor) {
        int end_height = out->proof_validate_cursor_before - 1;
        if (out->sweep_top < end_height)
            end_height = out->sweep_top;
        if (!stage_reducer_frontier_find_lowest_proof_validate_refill_hole_unlocked(
                db, scan_floor, end_height,
                &out->lowest_proof_validate_refill_hole)) {
            LOG_WARN("stage_repair",
                     "[stage_repair] proof_validate refill scan failed "
                     "window=[%d,%d] cursor=%d",
                     scan_floor, end_height,
                     out->proof_validate_cursor_before);
            return false;
        }
    }

    if (!reconcile_script_validate_cursor(db, apply, out)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] script_validate refill cursor reconcile "
                 "failed hole=%d cursor=%d apply=%d",
                 out->lowest_script_validate_refill_hole,
                 out->script_validate_cursor_before, apply);
        return false;
    }
    if (!reconcile_proof_validate_cursor(db, apply, out)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] proof_validate refill cursor reconcile "
                 "failed hole=%d cursor=%d apply=%d",
                 out->lowest_proof_validate_refill_hole,
                 out->proof_validate_cursor_before, apply);
        return false;
    }
    return true;
}

bool stage_reducer_frontier_reconcile_refill_cursors(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    RF_REFILL_REQUIRE(reconcile_validate_headers_refill_holes(db, ms, out),
                      "validate_headers reconcile");
    RF_REFILL_REQUIRE(reconcile_body_fetch_refill_holes(db, out),
                      "body_fetch scan");
    RF_REFILL_REQUIRE(reconcile_body_persist_refill_holes(db, out),
                      "body_persist scan");
    RF_REFILL_REQUIRE(reconcile_validate_headers_cursor(db, apply, out),
                      "validate_headers cursor clamp");
    RF_REFILL_REQUIRE(reconcile_body_fetch_cursor(db, apply, out),
                      "body_fetch cursor clamp");
    RF_REFILL_REQUIRE(reconcile_body_persist_cursor(db, apply, out),
                      "body_persist cursor clamp");

    /* FIX-2b — post-refusal invocation of the script/proof refill core:
     * bounds [hstar+1, min(cursor-1, sweep_top)], same coins floor. */
    RF_REFILL_REQUIRE(stage_reducer_frontier_reconcile_script_proof_refill_cursors(
                          db, apply, out->hstar + 1, out),
                      "script/proof cursor refill");

    return true;
}
