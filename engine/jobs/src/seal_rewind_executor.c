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
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
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
     * land at coins_applied_height == G we must inverse-apply blocks [G, C-1].
     * If the seal is at/above C there is nothing above it to unwind. */
    uint64_t cursor = stage_cursor_persisted(db, "utxo_apply", "seal_rewind");
    if (cursor > (uint64_t)INT32_MAX) {
        LOG_WARN("seal_rewind",
                 "[seal_rewind] utxo_apply cursor too large: %llu",
                 (unsigned long long)cursor);
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
    }
    const int32_t C = (int32_t)cursor;
    out->cursor_before = C;
    if (G >= C)
        return seal_rewind_refuse(out, SEAL_REWIND_ABOVE_FRONTIER);

    /* (3+4) Atomic reset. Ensure the stage tables exist first (a repair path
     * can reach here before stage init on a fresh datadir). */
    if (!stage_table_ensure(db)) {
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
    }

    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("seal_rewind", "[seal_rewind] BEGIN failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
    }

    /* Replay the retained inverse deltas for [G, C-1] into coins_kv, newest
     * first (disconnect order), so the set unwinds to coins_applied_height==G.
     * Read the delta rows BEFORE deleting them below. */
    int32_t unwound = 0;
    for (int32_t h = C - 1; h >= G; h--) {
        if (!utxo_apply_emit_inverse_delta(db, h)) {
            LOG_WARN("seal_rewind",
                     "[seal_rewind] inverse delta unwind failed h=%d "
                     "(range [%d,%d])", h, G, C - 1);
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            progress_store_tx_unlock();
            out->unwound_heights = unwound;
            out->refusal = SEAL_REWIND_STORE_ERROR;
            return true;
        }
        unwound++;
    }
    out->unwound_heights = unwound;

    /* SELF-DERIVED PROOF: recompute the commitment over the re-derived coins set
     * and require it reproduce the seal's stored value. A mismatch means the
     * seal (or a delta) is torn/forged — REFUSE and roll back, leaving the
     * reducer untouched. This is what lets a torn anchor self-heal on any
     * datadir: an unverifiable base can never be installed. */
    uint8_t got[32];
    if (coins_kv_commitment(db, got) != 0) {
        LOG_WARN("seal_rewind",
                 "[seal_rewind] coins commitment recompute failed at G=%d", G);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
    }
    if (memcmp(got, base.coins_sha3, 32) != 0) {
        LOG_WARN("seal_rewind",
                 "[seal_rewind] SELF-VERIFY FAILED at G=%d: re-derived coins "
                 "set does not reproduce the seal's coins_sha3 — refusing the "
                 "rewind (torn/forged seal)", G);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "seal_rewind self_verify_failed G=%d H=%d", G, H);
        return seal_rewind_refuse(out, SEAL_REWIND_COMMITMENT_MISMATCH);
    }
    out->coins_verified = true;

    /* Verified. Drop the now-invalid reducer rows above the seal
     * (utxo_apply_log/delta + nullifiers + Sprout/Sapling anchors), force the
     * utxo_apply + tip_finalize cursors down to G so the forward drive re-folds
     * [G, ...], and pull coins_applied_height back to G in this same txn.
     *
     * Upstream header/script/proof logs are DELIBERATELY untouched: their
     * [G, H] verdicts stay valid (the seal domain is the UTXO set), so
     * utxo_apply re-consumes them on the forward re-fold. tip_finalize_log rows
     * are NEVER deleted — only its cursor moves — preserving served-floor
     * evidence, exactly as the header-poison rewind does. */
    if (!utxo_apply_delete_rows_above(db, G, C - 1) ||
        !stage_repair_force_stage_cursor(db, "utxo_apply", G) ||
        !stage_repair_force_stage_cursor(db, "tip_finalize", G) ||
        !utxo_apply_frontier_set_in_tx(db, G)) {
        LOG_WARN("seal_rewind",
                 "[seal_rewind] reset writes failed at G=%d — rolling back", G);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        out->coins_verified = false;
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
    }

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("seal_rewind", "[seal_rewind] COMMIT failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        out->coins_verified = false;
        out->refusal = SEAL_REWIND_STORE_ERROR;
        return true;
    }
    progress_store_tx_unlock();

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
             G, H, C, unwound, G, H);
    return true;
}
