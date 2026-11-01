/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seal_rewind_executor — the executable REWIND CONSUMER of the state-seal ring.
 * Contract + rationale in jobs/seal_rewind.h.
 *
 * This resets the reducer to the nearest self-verified seal at/below a target
 * height H so a forward drive re-folds only [G, H] — O(delta from the nearest
 * seal) recovery instead of an O(chain) fold from the compiled SHA3 checkpoint.
 *
 * The whole reset is ONE progress.kv BEGIN IMMEDIATE (inverse deltas + coins
 * commitment self-check + row deletes + cursor rewinds + applied-height rewind
 * commit or roll back as one unit — the same atomicity discipline as the reorg
 * unwind it generalizes). The SELF-DERIVED proof is the load-bearing part: the
 * coins set at G is re-DERIVED by replaying real inverse deltas, and the rewind
 * is REFUSED unless the re-derived coins_kv_commitment reproduces the seal's
 * stored coins_sha3 — the stored value is never trusted on its own, so a torn or
 * forged seal cannot install unverified state. */

#include "jobs/seal_rewind.h"

#include "jobs/stage_repair_internal.h"   /* stage_repair_force_stage_cursor */
#include "jobs/stage_helpers.h"           /* stage_cursor_persisted */
#include "jobs/utxo_apply_stage.h"
#include "utxo_apply_delta_internal.h"    /* utxo_apply_emit_inverse_delta,
                                           * utxo_apply_delete_rows_above */
#include "storage/seal_kv.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "event/event.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <string.h>

/* Record a clean (non-error) refusal in *out and return true — the reducer is
 * left exactly as found. The txn (if any) is already resolved by the caller. */
static bool seal_rewind_refuse(struct seal_rewind_result *out,
                               enum seal_rewind_refusal why)
{
    out->refusal = why;
    out->rewound = false;
    return true;
}

/* Inverse-apply the retained deltas for [F, C-1] (F = G + 1, the first height
 * the seal does not include), newest first. On the first failure *failed_h
 * names that height and false is returned; *unwound counts
 * the heights applied so far. The caller logs and rolls back. */
static bool seal_rewind_unwind_inverse_deltas(sqlite3 *db, int32_t F, int32_t C,
                                              int32_t *failed_h, int32_t *unwound)
{
    for (int32_t h = C - 1; h >= F; h--) {
        if (!utxo_apply_emit_inverse_delta(db, h)) {
            *failed_h = h;
            return false; // raw-return-ok:caller_logs_unwind_failure
        }
        (*unwound)++;
    }
    return true;
}

/* Land the reducer rows and cursors at the verified seal G (the set through
 * block G, so the frontier F = G + 1), in the caller's
 * txn: drop the rows from F up, force both stage cursors to F and pull
 * coins_applied_height back to F. Stops at the first failed write. */
static bool seal_rewind_reset_rows_and_cursors(sqlite3 *db, int32_t F, int32_t C)
{
    return utxo_apply_delete_rows_above(db, F, C - 1) &&
           stage_repair_force_stage_cursor(db, "utxo_apply", F) &&
           stage_repair_force_stage_cursor(db, "tip_finalize", F) &&
           utxo_apply_frontier_set_in_tx(db, F);
}

/* Helpers split out of seal_rewind_to_nearest. The WARN lines inside them are
 * LOG_WARN_IN so they still name seal_rewind_to_nearest. Each helper that ends
 * a path returns true (the function's "clean refusal" result); the caller
 * returns it immediately. */

/* A store-level refusal: *out gets SEAL_REWIND_STORE_ERROR. */
static bool seal_rewind_store_error(struct seal_rewind_result *out)
{
    out->refusal = SEAL_REWIND_STORE_ERROR;
    return true;
}

/* Roll the open txn back, release the tx lock. */
static void seal_rewind_abort_txn(sqlite3 *db)
{
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
}

/* The utxo_apply cursor as a height, or -1 (after the WARN) when it is too
 * large to be one. */
static int64_t seal_rewind_read_cursor(sqlite3 *db)
{
    uint64_t cursor = stage_cursor_persisted(db, "utxo_apply", "seal_rewind");
    if (cursor > (uint64_t)INT32_MAX) {
        LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                    "[seal_rewind] utxo_apply cursor too large: %llu",
                    (unsigned long long)cursor);
        return -1; // raw-return-ok:logged_by_LOG_WARN_IN_above
    }
    return (int64_t)cursor;
}

/* BEGIN IMMEDIATE under the tx lock; on failure WARN, unlock, and return false
 * with the store-error refusal set. */
static bool seal_rewind_begin(sqlite3 *db, struct seal_rewind_result *out)
{
    char *err = NULL;
    progress_store_tx_lock();
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK)
        return true;
    LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                "[seal_rewind] BEGIN failed: %s", err ? err : "(no message)");
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    seal_rewind_store_error(out);
    return false;
}

/* Unwind the inverse deltas [F, C-1]; on failure WARN, roll back and set the
 * store-error refusal. out->unwound_heights is set either way. */
static bool seal_rewind_unwind(sqlite3 *db, int32_t F, int32_t C,
                               struct seal_rewind_result *out)
{
    int32_t unwound = 0;
    int32_t h = 0;
    bool ok = seal_rewind_unwind_inverse_deltas(db, F, C, &h, &unwound);
    if (!ok) {
        LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                    "[seal_rewind] inverse delta unwind failed h=%d "
                    "(range [%d,%d])", h, F, C - 1);
        seal_rewind_abort_txn(db);
        seal_rewind_store_error(out);
    }
    out->unwound_heights = unwound;
    return ok;
}

/* Recompute the coins commitment and require it to equal the seal's. On a
 * recompute failure or a mismatch: WARN, roll back, set the refusal (store
 * error / commitment mismatch plus the rejected event) and return false. */
static bool seal_rewind_self_verify(sqlite3 *db, const struct seal_record *base,
                                    int32_t H, struct seal_rewind_result *out)
{
    const int32_t G = base->height;
    uint8_t got[32];
    if (coins_kv_commitment(db, got) != 0) {
        LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                    "[seal_rewind] coins commitment recompute failed at G=%d", G);
        seal_rewind_abort_txn(db);
        seal_rewind_store_error(out);
        return false;
    }
    if (memcmp(got, base->coins_sha3, 32) != 0) {
        LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                    "[seal_rewind] SELF-VERIFY FAILED at G=%d: re-derived coins "
                    "set does not reproduce the seal's coins_sha3 — refusing the "
                    "rewind (torn/forged seal)", G);
        seal_rewind_abort_txn(db);
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "seal_rewind self_verify_failed G=%d H=%d", G, H);
        seal_rewind_refuse(out, SEAL_REWIND_COMMITMENT_MISMATCH);
        return false;
    }
    out->coins_verified = true;
    return true;
}

/* Reset rows and cursors, then COMMIT. On either failure: WARN, roll back,
 * clear coins_verified, set the store-error refusal and return false. */
static bool seal_rewind_reset_and_commit(sqlite3 *db, int32_t G, int32_t F,
                                         int32_t C, struct seal_rewind_result *out)
{
    char *err = NULL;
    bool reset_ok = seal_rewind_reset_rows_and_cursors(db, F, C);
    if (reset_ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK)
        return true;
    if (!reset_ok) {
        LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                    "[seal_rewind] reset writes failed at G=%d — rolling back", G);
    } else {
        LOG_WARN_IN("seal_rewind_to_nearest", "seal_rewind",
                    "[seal_rewind] COMMIT failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
    }
    seal_rewind_abort_txn(db);
    out->coins_verified = false;
    seal_rewind_store_error(out);
    return false;
}

bool seal_rewind_to_nearest(sqlite3 *db, int32_t H, int32_t floor,
                            struct seal_rewind_result *out)
{
    if (!db || !out)
        return false;

    memset(out, 0, sizeof(*out));
    out->target_h = H;
    out->seal_height = -1;
    out->cursor_before = -1;
    out->refusal = SEAL_REWIND_OK;

    /* (1) Nearest self-valid seal at/below H. seal_kv_nearest_rewind_base
     * acquires + releases the recursive tx lock itself. */
    struct seal_record base;
    bool found = false;
    if (!seal_kv_nearest_rewind_base(db, H, &base, &found)) {
        LOG_WARN("seal_rewind",
                 "[seal_rewind] nearest-base scan failed H=%d", H);
        return seal_rewind_store_error(out);
    }
    if (!found)
        return seal_rewind_refuse(out, SEAL_REWIND_NO_BASE);

    const int32_t G = base.height;
    out->base_found = true;
    out->seal_height = G;

    /* Never rewind across the irreversible finality floor. */
    if (G < floor) {
        LOG_WARN("seal_rewind",
                 "[seal_rewind] nearest seal G=%d below finality floor=%d — "
                 "refusing", G, floor);
        return seal_rewind_refuse(out, SEAL_REWIND_BELOW_FLOOR);
    }

    /* (2) The applied frontier: the utxo_apply cursor is the next height to
     * apply, so blocks [0, C) are applied and coins_applied_height == C. To
     * land at coins_applied_height == F we must inverse-apply blocks [F, C-1].
     * If F is at/above C there is nothing above the seal to unwind. */
    int64_t cursor = seal_rewind_read_cursor(db);
    if (cursor < 0)
        return seal_rewind_store_error(out);
    const int32_t C = (int32_t)cursor;
    out->cursor_before = C;
    /* The seal at G commits the set THROUGH block G (a checkpoint-height
     * convention), so its applied frontier is F = G + 1; compared in 64 bits
     * so G == INT32_MAX cannot overflow (it is simply above the frontier). */
    if ((int64_t)G + 1 >= C)
        return seal_rewind_refuse(out, SEAL_REWIND_ABOVE_FRONTIER);
    const int32_t F = G + 1;

    /* (3+4) Atomic reset. Ensure the stage tables exist first (a repair path
     * can reach here before stage init on a fresh datadir). */
    if (!stage_table_ensure(db))
        return seal_rewind_store_error(out);

    if (!seal_rewind_begin(db, out))
        return true;

    /* Replay the retained inverse deltas for [F, C-1] into coins_kv, newest
     * first (disconnect order), so the set unwinds to coins_applied_height==F.
     * Read the delta rows BEFORE deleting them below. */
    if (!seal_rewind_unwind(db, F, C, out))
        return true;

    /* SELF-DERIVED PROOF: recompute the commitment over the re-derived coins set
     * and require it reproduce the seal's stored value. A mismatch means the
     * seal (or a delta) is torn/forged — REFUSE and roll back, leaving the
     * reducer untouched. This is what lets a torn anchor self-heal on any
     * datadir: an unverifiable base can never be installed. */
    if (!seal_rewind_self_verify(db, &base, H, out))
        return true;

    /* Verified. Drop the now-invalid reducer rows above the seal
     * (utxo_apply_log/delta + nullifiers + Sprout/Sapling anchors), force the
     * utxo_apply + tip_finalize cursors down to F so the forward drive re-folds
     * [F, ...], and pull coins_applied_height back to F in this same txn.
     *
     * Upstream header/script/proof logs are DELIBERATELY untouched: their
     * [G, H] verdicts stay valid (the seal domain is the UTXO set), so
     * utxo_apply re-consumes them on the forward re-fold. tip_finalize_log rows
     * are NEVER deleted — only its cursor moves — preserving served-floor
     * evidence, exactly as the header-poison rewind does. */
    if (!seal_rewind_reset_and_commit(db, G, F, C, out))
        return true;
    progress_store_tx_unlock();

    const int32_t unwound = out->unwound_heights;
    out->rewound = true;
    out->refusal = SEAL_REWIND_OK;
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "seal_rewind to G=%d (H=%d) from cursor=%d unwound=%d "
                "coins_verified",
                G, H, C, unwound);
    LOG_INFO("seal_rewind",
             "[seal_rewind] reset reducer to self-verified seal G=%d "
             "(target H=%d, from cursor=%d, unwound=%d heights) — forward "
             "drive re-folds [%d, %d]",
             G, H, C, unwound, F, H);
    return true;
}
