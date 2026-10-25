/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_delta — reorg unwind path.
 *
 * The stage-side disconnect: when the active chain diverges from what the
 * UTXO stage applied, this rewinds applied state down to the fork point by
 * replaying inverse UTXO events, deletes the invalidated log+delta rows,
 * and rewinds the stage cursor so the winning branch re-applies forward.
 * The forward delta-apply path is utxo_apply_delta.c; the contract shared by
 * both is jobs/utxo_apply_delta.h. */

#include "platform/time_compat.h"
#include "jobs/utxo_apply_delta.h"
#include "utxo_apply_delta_internal.h"
#include "jobs/reducer_commit_invariants.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_log_rows.h"
#include "jobs/utxo_apply_stage.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "event/event.h"
#include "coins/coins.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/anchor_kv.h"
#include "storage/shielded_pool_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STAGE_NAME "utxo_apply"

/* Wall clock + delta deserialization helpers — used only by the reorg
 * replay below (their forward-path siblings live in utxo_apply_delta.c). */
static int64_t wall_now_s(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static bool blob_get_u32(const uint8_t **p, const uint8_t *end, uint32_t *out)
{
    /* Compare remaining length, never form a pointer past end (UB). */
    if (*p > end || end - *p < 4) return false;
    *out = (uint32_t)(*p)[0] | ((uint32_t)(*p)[1] << 8) |
           ((uint32_t)(*p)[2] << 16) | ((uint32_t)(*p)[3] << 24);
    *p += 4;
    return true;
}

static bool blob_get_i64(const uint8_t **p, const uint8_t *end, int64_t *out)
{
    if (*p > end || end - *p < 8) return false;
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) u |= (uint64_t)(*p)[i] << (8 * i);
    *out = (int64_t)u;
    *p += 8;
    return true;
}

/* ── Reorg unwind ──────────────────────────────────────────────────────
 *
 * The stage-side disconnect path. Structurally mirrors tip_finalize's
 * rewind_cursor_if_active_chain_reorged: detect that the active chain
 * has diverged from what we applied, walk DOWN to the fork point, emit
 * inverse UTXO events for the abandoned blocks (the exact inverse of the
 * former disconnect block path: restored spent coin -> ADD, erased created
 * coin -> SPEND), delete the now-invalid log+delta rows, and rewind the
 * stage cursor to the fork boundary so step_apply re-applies the winning
 * branch forward. Bounded by ZCL_FINALITY_DEPTH (legacy's floor). */

/* Load the persisted branch_hash for a delta row via a caller-prepared
 * statement (bind/step/reset — the fork walk below reuses one statement for
 * every height instead of re-preparing per iteration). Returns 1 if found
 * (out filled), 0 if absent, -1 on error. */
static int delta_branch_hash_step(sqlite3_stmt *st, sqlite3 *db, int height,
                                  struct uint256 *out)
{
    sqlite3_bind_int(st, 1, height);
    int found = 0;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (blob && n == 32) {
            memcpy(out->data, blob, 32);
            found = 1;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] delta branch_hash step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        found = -1;  // raw-return-ok:logged-above
    }
    sqlite3_reset(st);
    return found;
}

static const char *const DELTA_BRANCH_HASH_SQL =
    "SELECT branch_hash FROM utxo_apply_delta WHERE height = ?";

/* One-shot delta_branch_hash_step (prepare + step + finalize). Same
 * tri-state contract. */
static int delta_branch_hash_at(sqlite3 *db, int height, struct uint256 *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, DELTA_BRANCH_HASH_SQL, -1, &st, NULL)
            != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] delta branch_hash prepare failed: %s", sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    int found = delta_branch_hash_step(st, db, height, out);
    sqlite3_finalize(st);
    return found;
}

/* Re-ADD every spent coin from spent_blob with its ORIGINAL
 * value/height/is_coinbase/script pre-image (exactly disconnect_block's
 * restore->ADD). The blob must be consumed exactly: a malformed entry or a
 * trailing fragment returns false. */
static bool inverse_readd_spent(sqlite3 *db, const uint8_t *blob, int n)
{
    if (n <= 0)
        return true; /* empty blob: SQLite gives NULL; NULL + 0 is UB */
    const uint8_t *p = blob;
    const uint8_t *end = blob + (n > 0 ? n : 0);
    while (p < end) {
        if (end - p < 32) return false;
        uint8_t txid[32];
        memcpy(txid, p, 32); p += 32;
        uint32_t vout = 0, ch = 0, slen = 0;
        int64_t value = 0;
        if (!blob_get_u32(&p, end, &vout)) return false; // raw-return-ok:short-blob-logged-by-caller
        if (!blob_get_i64(&p, end, &value)) return false; // raw-return-ok:short-blob-logged-by-caller
        if (!blob_get_u32(&p, end, &ch)) return false; // raw-return-ok:short-blob-logged-by-caller
        if (p >= end) return false;
        bool is_cb = (*p++ != 0);
        if (!blob_get_u32(&p, end, &slen)) return false; // raw-return-ok:short-blob-logged-by-caller
        const uint8_t *script = NULL;
        if (slen) {
            /* blob_get_u32 guarantees p <= end, so (end - p) is a
             * non-negative size; `p + slen > end` would be UB on a corrupt
             * blob. */
            if (slen > (size_t)(end - p)) return false;
            script = p;
            p += slen;
        }
        if (!coins_kv_add(db, txid, vout, value, (int32_t)ch, is_cb,
                          script, slen))
            return false;
    }
    return p == end;
}

/* SPEND (delete) every created outpoint from added_blob. Exact 36-byte
 * framing: a trailing fragment returns false. coins_kv_spend of an absent row
 * is a no-op (DELETE of nothing), which is what removes an intra-block
 * create-then-spend coin that inverse_readd_spent just re-added. */
static bool inverse_spend_added(sqlite3 *db, const uint8_t *blob, int n)
{
    if (n <= 0)
        return true; /* empty blob: SQLite gives NULL; NULL + 0 is UB */
    const uint8_t *p = blob;
    const uint8_t *end = blob + (n > 0 ? n : 0);
    while (p < end) {
        if (end - p < 36) return false;
        uint8_t txid[32];
        memcpy(txid, p, 32); p += 32;
        uint32_t vout = 0;
        if (!blob_get_u32(&p, end, &vout)) return false; // raw-return-ok:short-blob-logged-by-caller
        if (!coins_kv_spend(db, txid, vout)) return false;
    }
    return p == end;
}

/* A height with no delta row is invertible as a no-op ONLY when the apply log
 * records it as a failure (ok == 0): failure rows never persist a delta. A
 * missing log row, an ok == 1 row (its delta was lost), or an ok that is not
 * stored as INTEGER exactly 0 means the stored history is incomplete, so the
 * caller must refuse rather than report a partial unwind as success. The table
 * is not STRICT, so ok must be stored as INTEGER exactly 0 to allow the no-op. */
static bool inverse_missing_delta_allowed(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok FROM utxo_apply_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] inverse delta log prepare failed h=%d: %s",
                 height, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    bool allowed = false;
    if (rc == SQLITE_ROW) {
        int type = sqlite3_column_type(st, 0);
        int64_t log_ok = type == SQLITE_INTEGER ? sqlite3_column_int64(st, 0) : -1;
        allowed = (type == SQLITE_INTEGER && log_ok == 0);
        if (!allowed)
            LOG_WARN("utxo_apply", "[utxo_apply] inverse delta missing for applied "
                     "height h=%d (log ok type=%d value=%lld): refusing partial unwind",
                     height, type, (long long)log_ok);
    } else if (rc == SQLITE_DONE) {
        LOG_WARN("utxo_apply", "[utxo_apply] inverse delta missing and no log row "
                 "h=%d: refusing partial unwind", height);
    } else {
        LOG_WARN("utxo_apply", "[utxo_apply] inverse delta log step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);
    return allowed;
}

/* Apply the inverse delta for one persisted delta row to coins_kv.
 *
 * ORDER IS LOAD-BEARING: re-ADD every spent pre-image FIRST, then SPEND
 * (delete) every created outpoint. The forward writer records an output that
 * is created AND spent inside the same block in BOTH arrays. Witness: before
 * block h live={p}; T1 spends p, creates x; T2 spends x, creates y; the
 * coinbase creates b => added={x,y,b}, spent={p,x}. Spends-first would delete
 * x (absent) and then re-add its spent pre-image, leaving {p,x} with x at
 * creator height h above the rewound cursor. Adds-first re-adds p and x, then
 * deletes x,y,b, leaving exactly {p}. As sets: forward F=(U u A)\W, so the
 * exact inverse is (F u W)\A. Under valid no-overwrite inputs W and F are
 * disjoint so the re-add never meets a live row (coins_kv_add is INSERT OR
 * IGNORE plus an exact-field refresh of an existing row, never a failure).
 *
 * Returns true when there is no delta row for the height AND the apply log
 * records that height as a failure (ok == 0; failure rows never persist a
 * delta). A missing delta with a missing or ok != 0 log row returns false.
 * Returns false on an SQL
 * error, a malformed or trailing-fragment blob, or a coins_kv failure. */
bool utxo_apply_emit_inverse_delta(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT spent_blob, added_blob FROM utxo_apply_delta WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] inverse delta prepare failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_DONE) {
        /* No delta row. That is only benign for a failure row (ok == 0),
         * which never persists a delta; anything else is a lost delta and
         * the unwind must refuse instead of skipping the height. */
        sqlite3_finalize(st);
        return inverse_missing_delta_allowed(db, height);
    }
    if (rc != SQLITE_ROW) {
        LOG_WARN("utxo_apply", "[utxo_apply] inverse delta step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    const uint8_t *spent = sqlite3_column_blob(st, 0);
    int spent_n = sqlite3_column_bytes(st, 0);
    const uint8_t *added = sqlite3_column_blob(st, 1);
    int added_n = sqlite3_column_bytes(st, 1);

    bool ok = !(spent_n > 0 && !spent) && !(added_n > 0 && !added);
    ok = ok && inverse_readd_spent(db, spent, spent_n);
    ok = ok && inverse_spend_added(db, added, added_n);

    sqlite3_finalize(st);
    if (!ok)
        LOG_WARN("utxo_apply", "[utxo_apply] inverse delta unwind failed h=%d "
                 "(malformed blob or coins_kv write)", height);
    return ok;
}

/* ZIP-209 pool totals for the unwound range: a row left above the fork
 * would be recomputed on the new branch and (rightly) refuse to agree. */
static bool unwind_pool_totals(sqlite3 *db, int fork_plus1, int last_h)
{
    if (!shielded_pool_kv_ensure_schema(db) ||
        !shielded_pool_kv_delete_range(db, fork_plus1, last_h)) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] unwind pool totals delete failed "
                 "range=[%d,%d]", fork_plus1, last_h);
        return false;
    }
    return true;
}

/* Delete the log + delta + nullifier rows for heights in
 * [fork_plus1 .. last_h]. The nullifier pass enforces the rewind invariant
 * (storage/nullifier_kv.h): every cursor rewind deletes the nullifiers
 * revealed in the rewound range IN THE SAME txn, or the stale rows would
 * false-reject the re-apply as a shielded double-spend. Routing it through
 * this shared primitive automatically covers the reorg unwind below, the
 * value_overflow repair (utxo_apply_delta_repair.c), and the stale-script
 * replay (stage_repair_reducer_frontier_coin.c). */
bool utxo_apply_delete_rows_above(sqlite3 *db, int fork_plus1, int last_h)
{
    /* Idempotent, transactional DDL: repair paths can reach this primitive
     * on a datadir that predates the nullifiers table (stage init not yet
     * run), where the bare DELETE would fail "no such table". */
    if (!nullifier_kv_ensure_schema(db))
        return false;  /* nullifier_kv logged the failure */
    if (!anchor_kv_ensure_schema(db)) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] unwind could not ensure anchor schema "
                 "range=[%d,%d]",
                 fork_plus1, last_h);
        return false;
    }
    static const char *const sqls[] = {
        "DELETE FROM utxo_apply_log WHERE height >= ? AND height <= ?",
        "DELETE FROM utxo_apply_delta WHERE height >= ? AND height <= ?",
        "DELETE FROM nullifiers WHERE height >= ? AND height <= ?",
    };
    sqlite3_stmt *st = NULL;
    for (size_t pass = 0; pass < sizeof(sqls) / sizeof(sqls[0]); pass++) {
        const char *sql = sqls[pass];
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
            LOG_WARN("utxo_apply", "[utxo_apply] unwind delete prepare failed: %s", sqlite3_errmsg(db));
            return false;
        }
        /* Fail CLOSED on bind failure: an unbound param is NULL, the WHERE
         * matches nothing, and the DELETE silently no-ops — leaving stale
         * nullifier rows that false-reject the re-apply as a shielded
         * double-spend. Returning false rolls the txn back so the repair
         * retries. */
        if (sqlite3_bind_int(st, 1, fork_plus1) != SQLITE_OK ||
            sqlite3_bind_int(st, 2, last_h)     != SQLITE_OK) {
            LOG_WARN("utxo_apply", "[utxo_apply] unwind delete bind failed: %s",
                     sqlite3_errmsg(db));
            sqlite3_finalize(st);
            return false;
        }
        int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
        int changed = sqlite3_changes(db);
        sqlite3_finalize(st);
        st = NULL;
        if (rc != SQLITE_DONE) {
            LOG_WARN("utxo_apply", "[utxo_apply] unwind delete rc=%d", rc);
            return false;
        }
        /* Keep the published utxo_apply_log row counter honest across the
         * reorg unwind (see jobs/stage_log_rows.h). Only pass 0 is that table. */
        if (pass == 0)
            stage_log_rows_note_delete("utxo_apply_log", (int64_t)changed);
    }
    if (!anchor_kv_delete_range(db, fork_plus1, last_h)) {
        LOG_WARN("utxo_apply",
                 "[utxo_apply] unwind anchor delete failed range=[%d,%d]",
                 fork_plus1, last_h);
        return false;
    }
    return unwind_pool_totals(db, fork_plus1, last_h);
}

/* UPSERT the stage cursor row inside the caller's transaction (mirrors
 * stage.c's cursor_write_locked, which is static). */
bool utxo_apply_unwind_write_cursor(sqlite3 *db, uint64_t value)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO stage_cursor (name, cursor, updated_at) "
        "VALUES (?1, ?2, ?3) "
        "ON CONFLICT(name) DO UPDATE SET "
        "  cursor = excluded.cursor, updated_at = excluded.updated_at",
        -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] unwind cursor prepare failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text (st, 1, STAGE_NAME, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)wall_now_s());
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        LOG_WARN("utxo_apply", "[utxo_apply] unwind cursor step rc=%d", rc);
        return false;
    }
    return true;
}

/* Name a deep-reorg refusal.
 *
 * Both refusal paths below raise a typed blocker so `dumpstate blocker`
 * shows the node declining to follow the network. With
 * ZCL_FINALITY_DEPTH = 10, a partition longer than 10 blocks on both sides
 * never reconverges, so the refusal must be named, not only logged.
 *
 * height_is_immutable() (validation/checkpoint.h) is the predicate that
 * DEFINES the refusal — the fork point sits at or below tip - FINALITY_DEPTH,
 * so every block above it is already final. It is READ here, never
 * re-implemented and never redefined, and it picks the reason token: a
 * refusal whose fork point is somehow not immutable is a different fault and
 * must not borrow this name. Either way a blocker is raised; there is no path
 * through this helper that stays quiet.
 *
 * BLOCKER_PERMANENT: a consensus refusal is never auto-retried. See the
 * ZCL_BLOCKER_REMEDY / ZCL_BLOCKER_DECISION rows for
 * `chain.reorg_refused_below_finality`. */
void utxo_apply_reorg_name_refusal_blocker(int tip_h, int fork_h)
{
    const bool immutable = height_is_immutable(tip_h, fork_h);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "%s: unwind REFUSED tip=%d fork=%d depth=%d > "
             "ZCL_FINALITY_DEPTH=%d. Heights <= %d are final; this node keeps "
             "its own chain and will not rewind them. A split this deep does "
             "not reconverge on its own.",
             immutable ? "reorg_below_finality" : "reorg_refused_unclassified",
             tip_h, fork_h, tip_h - fork_h, ZCL_FINALITY_DEPTH,
             tip_h - ZCL_FINALITY_DEPTH);

    struct blocker_record b;
    if (blocker_init(&b, "chain.reorg_refused_below_finality", "utxo_apply",
                     BLOCKER_PERMANENT, reason))
        (void)blocker_set(&b);
}

bool utxo_apply_reorg_unwind_if_needed(sqlite3 *db,
                                       struct stage *stage,
                                       struct main_state *ms,
                                       _Atomic uint64_t *unwound_counter,
                                       _Atomic int64_t *last_blocked_unix)
{
    if (!stage || !ms)
        return true;

    uint64_t cursor = stage_cursor_persisted(db, STAGE_NAME, "utxo_apply");
    if (cursor == 0)
        return true;
    if (cursor > (uint64_t)INT32_MAX) {
        LOG_WARN("utxo_apply", "[utxo_apply] reorg cursor too large: %llu", (unsigned long long)cursor);
        return false;
    }
    int C = (int)cursor;  /* next height to apply; [0, C) already applied */

    /* The stage is itself the tip authority (tip_finalize sets the in-mem
     * chain[]), so the active chain at C-1 reflects the stage's OWN tip. The
     * divergence detection + fork walk below run against that tip. */

    /* Compare the OLD branch hash recorded for the highest applied height
     * (C-1) against the block now occupying that height on the active
     * chain. A mismatch is the divergence signal: the winning branch now
     * occupies C-1 (set by the stage itself); our delta rows recorded the
     * losing branch. */
    struct uint256 recorded;
    int have = delta_branch_hash_at(db, C - 1, &recorded);
    if (have < 0)
        return false;
    if (have == 0)
        return true;  /* no delta at C-1 (e.g. all-failure tail) → nothing to do */

    struct block_index *active = active_chain_at(&ms->chain_active, C - 1);
    if (!active || !active->phashBlock) {
        /* A missing slot or shorter raw window alone is NOT a branch verdict:
         * boot/resume deliberately permits the visible window to lag durable
         * reducer rows.  An operator invalidation supplies the missing fact by
         * marking the exact recorded block hash FAILED before retracting the
         * window.  Only that hash-bound verdict converts absence into a known
         * divergence; otherwise preserve the sparse-window HOLD contract. */
        struct block_index *recorded_owner =
            block_map_find(&ms->map_block_index, &recorded);
        if (!recorded_owner || !block_has_any_failure(recorded_owner))
            return true;
        /* Explicitly failed recorded block: continue as a mismatch. */
    } else if (uint256_eq(&recorded, active->phashBlock)) {
        return true;  /* no divergence */
    }

    /* Walk DOWN to the fork point F: the highest height where our recorded
     * branch_hash still matches the active chain. Disconnect (F, C-1].
     *
     * The walk is CLAMPED to the finality floor (C-1) - ZCL_FINALITY_DEPTH:
     * any fork below it would be refused by the reorg_is_allowed gate below,
     * so scanning further (to genesis, per-height, under the progress lock —
     * this whole function runs with it held) buys nothing. Heights below the
     * lowest retained delta row can never match either (no branch_hash to
     * compare), so the clamp subsumes that floor too. Behavior-identical for
     * every input: a fork at/above the floor is found exactly as before; no
     * fork at/above it means the unclamped walk could only have produced the
     * finality refusal, which we emit directly. */
    int floor_h = C - 1 - ZCL_FINALITY_DEPTH;
    if (floor_h < 0)
        floor_h = 0;
    int fork = -1;
    {
        sqlite3_stmt *walk_st = NULL;
        if (sqlite3_prepare_v2(db, DELTA_BRANCH_HASH_SQL, -1, &walk_st, NULL)
                != SQLITE_OK) {
            LOG_WARN("utxo_apply",
                     "[utxo_apply] fork walk prepare failed: %s",
                     sqlite3_errmsg(db));
            return false;
        }
        for (int h = C - 2; h >= floor_h; h--) {
            struct uint256 rec_h;
            int hv = delta_branch_hash_step(walk_st, db, h, &rec_h);
            if (hv < 0) {
                sqlite3_finalize(walk_st);
                return false;
            }
            struct block_index *act_h = active_chain_at(&ms->chain_active, h);
            if (hv == 1 && act_h && act_h->phashBlock &&
                uint256_eq(&rec_h, act_h->phashBlock)) {
                fork = h;
                break;
            }
        }
        sqlite3_finalize(walk_st);
    }
    if (fork < 0 && floor_h > 0) {
        LOG_WARN("utxo_apply",
            "[utxo_apply] reorg unwind refused below finality floor "
            "tip=%d fork<%d depth>%d (ZCL_FINALITY_DEPTH=%d)",
            C - 1, floor_h, ZCL_FINALITY_DEPTH, ZCL_FINALITY_DEPTH);
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "utxo_apply unwind_below_finality tip=%d fork=%d depth=%d",
                    C - 1, floor_h - 1, C - floor_h);
        utxo_apply_reorg_name_refusal_blocker(C - 1, floor_h - 1);
        return false;
    }
    int fork_plus1 = fork + 1;  /* first height to disconnect (== 0 if F<0) */

    /* Finality-depth floor: never unwind below tip - ZCL_FINALITY_DEPTH. The
     * deepest disconnected block is at fork_plus1, whose fork point is `fork`;
     * the reorg depth is (C-1) - fork. This reorg_is_allowed(C-1, fork) check
     * is the sole gate on whether the unwind proceeds.
     *
     * Why (C-1), the stage cursor, is the correct depth reference: the stage
     * drives the tip, so C-1 IS the authoritative tip height and
     * reorg_is_allowed(C-1, fork) is the exact finality check. The unwind is
     * gated purely on this — there is no external engine to wait on. */
    {
        const char *reason = NULL;
        if (!reorg_is_allowed(C - 1, fork, &reason)) {
            LOG_WARN("utxo_apply",
                "[utxo_apply] reorg unwind refused below finality floor "
                "tip=%d fork=%d depth=%d reason=%s (ZCL_FINALITY_DEPTH=%d)",
                C - 1, fork, (C - 1) - fork, reason ? reason : "(null)",
                ZCL_FINALITY_DEPTH);
            event_emitf(EV_BLOCK_REJECTED, 0,
                        "utxo_apply unwind_below_finality tip=%d fork=%d depth=%d",
                        C - 1, fork, (C - 1) - fork);
            utxo_apply_reorg_name_refusal_blocker(C - 1, fork);
            return false;
        }
    }

    /* Atomically, in ONE BEGIN IMMEDIATE on progress.kv: replay the inverse
     * deltas into the authoritative coins_kv set, drop the abandoned log/delta
     * rows, and rewind the cursor to fork_plus1 (the first height step_apply
     * re-applies on the winner). Wrapping the inverse-delta loop in the SAME txn
     * as the cursor rewind is the fix that keeps coins_kv from drifting from the
     * cursor on a crash mid-unwind (docs/node/tip-durability-collapse.md):
     * coins_kv mutation + delete + cursor commit or roll back as one unit.
     * coins_kv is the sole live UTXO store. The in-memory s->cursor is reloaded
     * from this DB row at the top of the next stage_run_once (cursor_read). */
    /* This unwind is ONE atomic unit (inverse deltas + row deletes + cursor
     * rewind + applied-height rewind commit or roll back together). When the
     * drain has an outer batch txn open (stage_batch_begin), a nested
     * BEGIN IMMEDIATE would error, so open a SAVEPOINT instead: the unwind
     * stays atomic relative to that savepoint and its writes enrol in the
     * batch (committed once by stage_batch_end). Pure I/O txn-boundary
     * change — identical writes, identical atomicity, fewer fsyncs. */
    const bool ua_batched = stage_batch_active();
    const char *ua_open   = ua_batched ? "SAVEPOINT utxo_apply_unwind"
                                       : "BEGIN IMMEDIATE";
    const char *ua_undo   = ua_batched
        ? "ROLLBACK TO SAVEPOINT utxo_apply_unwind; "
          "RELEASE SAVEPOINT utxo_apply_unwind"
        : "ROLLBACK";
    const char *ua_done   = ua_batched ? "RELEASE SAVEPOINT utxo_apply_unwind"
                                       : "COMMIT";
    char *err = NULL;
    if (sqlite3_exec(db, ua_open, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] unwind BEGIN failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    for (int h = C - 1; h >= fork_plus1; h--) {
        if (!utxo_apply_emit_inverse_delta(db, h)) {
            sqlite3_exec(db, ua_undo, NULL, NULL, NULL);
            return false;
        }
    }
    if (!utxo_apply_delete_rows_above(db, fork_plus1, C - 1)) {
        sqlite3_exec(db, ua_undo, NULL, NULL, NULL);
        return false;
    }
    if (!utxo_apply_unwind_write_cursor(db, (uint64_t)fork_plus1)) {
        sqlite3_exec(db, ua_undo, NULL, NULL, NULL);
        return false;
    }
    /* Pull the contiguous applied frontier BACK to fork_plus1 in THIS unwind
     * txn — the exact value just written to the cursor — so coins_applied_height
     * == utxo_apply cursor stays true across a reorg. A PLAIN set (allows the
     * decrease): a monotonic-floor helper would BLOCK the legitimate rewind and
     * strand the frontier ABOVE the rewound coins (a phantom-forward frontier
     * the self-heal would wrongly trust). Co-committed with the inverse delta +
     * cursor; ROLLBACK on failure like the surrounding writes. */
    if (!utxo_apply_frontier_set_in_tx(db, fork_plus1)) {
        sqlite3_exec(db, ua_undo, NULL, NULL, NULL);
        return false;
    }
    if (sqlite3_exec(db, ua_done, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("utxo_apply", "[utxo_apply] unwind COMMIT failed: %s", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, ua_undo, NULL, NULL, NULL);
        return false;
    }
    /* The unwind is durable, correct work that did NOT advance the forward
     * cursor (the winning block is re-applied on a later drain, after reconcile
     * purges the displaced verdict). When it enrolled in an outer drain batch
     * (the SAVEPOINT/RELEASE path above), flag the batch dirty so
     * stage_batch_end COMMITs it — a drain that ends with advanced==0 would
     * otherwise ROLLBACK the completed unwind and oscillate. */
    if (ua_batched) stage_batch_mark_dirty();

    /* This unwind mutated coins/anchors/nullifiers (inverse deltas + range
     * deletes) inside the open drain batch. Its inverse-delta arithmetic
     * invalidates the pure-forward conservation baseline, so rebaseline the
     * batch-commit invariants: verify() passes loudly instead of false-refusing
     * (no-op unless a batch is open). */
    reducer_commit_invariants_note_reorg();

    atomic_fetch_add(unwound_counter, 1);
    atomic_store(last_blocked_unix, wall_now_s());
    event_emitf(EV_BLOCK_REJECTED, 0,
                "utxo_apply reorg_unwind from=%d to=%d depth=%d",
                C, fork_plus1, (C - 1) - fork);
    LOG_INFO("utxo_apply", "[utxo_apply] reorg unwind from=%d to=%d depth=%d",
             C, fork_plus1, (C - 1) - fork);
    return true;
}
