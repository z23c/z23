/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * UTXO Recovery Backfill Service
 *
 * Rehydrates per-block Sprout/Sapling value columns from the in-memory block
 * index and, when needed, block files on disk. This service owns shielded-value
 * backfill for UTXO recovery.
 *
 * Bounded-suffix design (see docs/BOOT_INVARIANTS.md, "finality → precompute →
 * cheap verify"): the walk covers only the height suffix `(cursor, tip]` via
 * active-chain height lookups, never the full ~3.18M-entry block map. The
 * persisted `shielded_backfill_height` cursor IS the proof-of-computation: it
 * is advanced only AFTER the covering rows are durably committed, so every
 * height at or below it is known-final and is never re-scanned. This encodes
 * the distinction the old full-map scan defended by brute force — "genuinely
 * all-zero" vs "not yet computed" — durably in the cursor instead of by
 * re-reading every block body on every boot.
 */

#include "services/utxo_recovery_service.h"
#include "config/db_service.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "models/database.h"
#include "storage/disk_block_io.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/result.h"
#include <stdio.h>
#include <sqlite3.h>

/* Commit + advance the durable cursor every this-many heights scanned. Bounds
 * the SQLite transaction size on the (rare) one-time full pass and gives
 * crash-safe incremental progress; the common re-fire suffix is far smaller. */
#define SHIELDED_BACKFILL_SCAN_BATCH 50000

struct shielded_backfill_ctx {
    int updated;
    struct main_state *state;
    const char *datadir;
    int start_height;   /* first height to (re)compute, inclusive (>=1) */
    int tip_height;     /* last height to cover, inclusive */
};

int utxo_recovery_shielded_backfill_start(int64_t done_cursor, int tip_height)
{
    if (tip_height <= 1000)
        return 0;                   /* too shallow to bother (pre-activation) */
    if (done_cursor >= tip_height)
        return 0;                   /* cursor already covers the tip: skip */
    return (done_cursor < 0) ? 1 : (int)(done_cursor + 1);
}

static struct zcl_result backfill_validate_args(
    struct node_db *ndb,
    struct db_service *dbsvc,
    struct main_state *state)
{
    if (!state)
        return ZCL_ERR(-50, "backfill: invalid state=%p", (void *)state);
    if (!dbsvc && (!ndb || !ndb->open))
        return ZCL_ERR(-51, "backfill: invalid ndb=%p open=%d",
                       (void *)ndb, ndb ? ndb->open : 0);
    return ZCL_OK;
}

static bool backfill_shielded_write(struct node_db *ndb, void *ctx_ptr)
{
    struct shielded_backfill_ctx *bctx = ctx_ptr;
    if (!ndb || !ndb->open)
        LOG_FAIL("utxo_recovery",
                 "backfill_shielded called with null or closed db");
    if (!bctx || !bctx->state)
        LOG_FAIL("utxo_recovery",
                 "backfill_shielded called with null ctx/state");

    struct active_chain *chain = &bctx->state->chain_active;
    int start = bctx->start_height < 1 ? 1 : bctx->start_height;
    int tip = bctx->tip_height;

    if (tip < start) {
        /* Nothing above the cursor; monotonically advance to the tip. */
        node_db_state_set_int(ndb, "shielded_backfill_height", tip);
        bctx->updated = 0;
        return true;
    }

    /* This backfill only DERIVES the two shielded-value columns; it must never
     * disturb the consensus columns (solution, chain_work, undo_pos,
     * sapling_root, sprout_root) that normal sync wrote. So the primary path is
     * a keyed UPDATE of exactly those two columns. The old INSERT OR REPLACE
     * clobbered every other column with empty/NULL, wiping the real solution and
     * chain_work of any suffix block already populated by normal sync. Rows are
     * keyed by hash (the blocks PK); height is NOT unique across forks. */
    sqlite3_stmt *upd = NULL;
    if (sqlite3_prepare_v2(
            ndb->db,
            "UPDATE blocks SET sapling_value=?, sprout_value=? WHERE hash=?",
            -1, &upd, NULL) != SQLITE_OK)
        LOG_FAIL("utxo_recovery", "backfill: prepare UPDATE failed: %s",
                 sqlite3_errmsg(ndb->db));

    /* Fallback only for a hash with no existing row (a shielded block above the
     * blocks-table population). An UPDATE that matched 0 rows must NOT silently
     * drop the computed value, so we INSERT a full row using the REAL fields
     * from the in-memory block_index (solution/chain_work/undo_pos/sapling_root),
     * never empty placeholders. On the active chain the row essentially always
     * exists, so this path is a rarely-taken safety net. */
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(
            ndb->db,
            "INSERT INTO blocks"
            "(hash,height,prev_hash,version,merkle_root,"
            "time,bits,nonce,solution,chain_work,status,"
            "file_num,data_pos,undo_pos,num_tx,"
            "sapling_root,sprout_root,sapling_value,sprout_value)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?)",
            -1, &ins, NULL) != SQLITE_OK) {
        sqlite3_finalize(upd);
        LOG_FAIL("utxo_recovery", "backfill: prepare INSERT failed: %s",
                 sqlite3_errmsg(ndb->db));
    }

    int updated = 0, scanned = 0;
    int cursor_committed = start - 1;   /* durable floor already proven */
    node_db_begin(ndb);

    int h = start;
    for (; h <= tip; h++) {
        struct block_index *bi = active_chain_at(chain, h);
        if (!bi)
            break;   /* gap on the active chain: stop; keep the cursor honest */
        if (bi->nFile < 0 || !(bi->nStatus & BLOCK_HAVE_DATA) ||
            (bi->nDataPos == 0 && bi->nHeight > 0))
            break;   /* no committed body → cannot compute; stop advancing */

        int64_t sprout_val = bi->nSproutValue;
        int64_t sapling_val = bi->nSaplingValue;

        if (sprout_val == 0 && sapling_val == 0) {
            /* Cached zero is ambiguous. Read the body to resolve it. A read
             * failure means we cannot PROVE zero, so we must not advance the
             * cursor past this height — stop and retry next boot. */
            struct block blk;
            if (!read_block_from_disk_index(&blk, bi, bctx->datadir))
                break;
            for (size_t i = 0; i < blk.num_vtx; i++) {
                const struct transaction *tx = &blk.vtx[i];
                for (size_t j = 0; j < tx->num_joinsplit; j++) {
                    sprout_val += tx->v_joinsplit[j].vpub_old;
                    sprout_val -= tx->v_joinsplit[j].vpub_new;
                }
                sapling_val += tx->value_balance;
            }
            block_free(&blk);
            if (sprout_val != 0 || sapling_val != 0) {
                bi->nSproutValue = sprout_val;
                bi->nSaplingValue = sapling_val;
            }
        }

        if (sprout_val != 0 || sapling_val != 0) {
            /* Primary path: derive-only UPDATE keyed by hash. Touches ONLY the
             * two shielded-value columns — the consensus columns of an
             * already-populated row are left exactly as normal sync wrote them. */
            sqlite3_reset(upd);
            sqlite3_bind_int64(upd, 1, sapling_val);
            sqlite3_bind_int64(upd, 2, sprout_val);
            sqlite3_bind_blob(upd, 3, bi->phashBlock->data, 32, SQLITE_STATIC);

            bool wrote = false;
            if (AR_STEP_WRITE(upd) != SQLITE_DONE) {
                static int uerrs = 0;
                if (++uerrs <= 3)
                    LOG_INFO("chain", "backfill UPDATE h=%d: %s", bi->nHeight,
                             sqlite3_errmsg(ndb->db));
            } else if (sqlite3_changes(ndb->db) > 0) {
                wrote = true;
            } else {
                /* No row for this hash yet: insert a FULL row from the in-memory
                 * block_index (real solution/chain_work/undo_pos/sapling_root),
                 * so the computed value is preserved instead of silently lost. */
                sqlite3_reset(ins);
                sqlite3_bind_blob(ins, 1, bi->phashBlock->data, 32, SQLITE_STATIC);
                sqlite3_bind_int(ins, 2, bi->nHeight);
                sqlite3_bind_blob(ins, 3,
                    bi->pprev ? bi->pprev->phashBlock->data
                              : (const uint8_t[32]){0},
                    32, SQLITE_STATIC);
                sqlite3_bind_int(ins, 4, bi->nVersion);
                sqlite3_bind_blob(ins, 5, bi->hashMerkleRoot.data, 32,
                                  SQLITE_STATIC);
                sqlite3_bind_int64(ins, 6, bi->nTime);
                sqlite3_bind_int(ins, 7, (int)bi->nBits);
                sqlite3_bind_blob(ins, 8, bi->nNonce.data, 32, SQLITE_STATIC);
                sqlite3_bind_blob(ins, 9,
                    bi->nSolution ? (const void *)bi->nSolution : (const void *)"",
                    bi->nSolution ? (int)bi->nSolutionSize : 0, SQLITE_STATIC);
                sqlite3_bind_blob(ins, 10, bi->nChainWork.pn, 32, SQLITE_STATIC);
                sqlite3_bind_int(ins, 11, bi->nStatus);
                sqlite3_bind_int(ins, 12, bi->nFile);
                sqlite3_bind_int(ins, 13, (int)bi->nDataPos);
                sqlite3_bind_int(ins, 14, (int)bi->nUndoPos);
                sqlite3_bind_int(ins, 15, bi->nTx);
                sqlite3_bind_blob(ins, 16, bi->hashFinalSaplingRoot.data, 32,
                                  SQLITE_STATIC);
                sqlite3_bind_int64(ins, 17, sapling_val);
                sqlite3_bind_int64(ins, 18, sprout_val);
                if (AR_STEP_WRITE(ins) != SQLITE_DONE) {
                    static int ierrs = 0;
                    if (++ierrs <= 3)
                        LOG_INFO("chain", "backfill INSERT h=%d: %s", bi->nHeight,
                                 sqlite3_errmsg(ndb->db));
                } else {
                    wrote = true;
                }
            }
            if (wrote)
                updated++;
        }

        if (++scanned >= SHIELDED_BACKFILL_SCAN_BATCH) {
            /* Cursor advance is part of THIS transaction: the covering rows
             * and the cursor commit atomically together (crash-safe). */
            cursor_committed = h;
            node_db_state_set_int(ndb, "shielded_backfill_height",
                                  cursor_committed);
            node_db_commit(ndb);
            node_db_begin(ndb);
            scanned = 0;
            printf("  backfill: scanned through h=%d (%d shielded rows)...\n",
                   h, updated);
            fflush(stdout);
        }
    }

    /* Highest height actually resolved: tip on a full pass, or (h-1) if we
     * broke early. Never move the cursor backward. */
    int reached = h - 1;
    if (reached < cursor_committed)
        reached = cursor_committed;
    node_db_state_set_int(ndb, "shielded_backfill_height", reached);
    node_db_commit(ndb);
    sqlite3_finalize(upd);
    sqlite3_finalize(ins);

    bctx->updated = updated;
    printf("Shielded backfill: covered (%d,%d] — %d blocks carried "
           "JoinSplit/Sapling values\n", start - 1, reached, updated);
    fflush(stdout);
    return true;
}

struct zcl_result utxo_recovery_backfill_shielded_range(struct node_db *ndb,
                                     struct db_service *dbsvc,
                                     struct main_state *state,
                                     const char *datadir,
                                     int start_height,
                                     int tip_height,
                                     int *out_updated)
{
    struct zcl_result valid = backfill_validate_args(ndb, dbsvc, state);
    if (!valid.ok)
        return valid;  /* zcl_result self-describes; the caller logs the reason */

    struct shielded_backfill_ctx bctx = {
        .updated = 0,
        .state = state,
        .datadir = datadir,
        .start_height = start_height,
        .tip_height = tip_height,
    };
    bool ok = false;

    printf("Backfilling shielded values over (%d,%d]...\n",
           (start_height < 1 ? 1 : start_height) - 1, tip_height);
    fflush(stdout);
    if (dbsvc)
        ok = db_service_run_write(dbsvc, backfill_shielded_write, &bctx);
    else
        ok = backfill_shielded_write(ndb, &bctx);

    if (ok) {
        if (out_updated)
            *out_updated = bctx.updated;
        return ZCL_OK;
    }

    return ZCL_ERR(-52, "backfill: failed to persist shielded values "
                   "to blocks table");
}

struct zcl_result utxo_recovery_backfill_shielded(struct node_db *ndb,
                                     struct db_service *dbsvc,
                                     struct main_state *state,
                                     const char *datadir,
                                     int *out_updated)
{
    /* Full backfill utility: cover the whole active chain from height 1.
     * The boot path uses the cursor-bounded suffix walk (see
     * utxo_recovery_backfill_shielded_if_needed); this force-full variant is
     * kept for explicit rebuilds. */
    int tip = state ? active_chain_height(&state->chain_active) : 0;
    return utxo_recovery_backfill_shielded_range(ndb, dbsvc, state, datadir,
                                                 1, tip, out_updated);
}

void utxo_recovery_backfill_shielded_if_needed(struct node_db *ndb,
                                               struct db_service *dbsvc,
                                               struct main_state *state,
                                               const char *datadir,
                                               int tip_height)
{
    if (!ndb || !ndb->open || tip_height <= 1000)
        return;

    /* Cursor-bounded suffix walk. `shielded_backfill_height` records the tip
     * already covered; below it the per-block Sprout/Sapling values are final
     * (finality doctrine) and are never re-scanned. Only the suffix
     * (cursor, tip] is walked, via active-chain height lookups — NOT the full
     * ~3.18M-entry block map — so a node that synced a few blocks since the
     * last boot pays only for those few, not an O(chain) disk re-read. The
     * --importblockindex and snapshot-import paths pre-stamp this cursor, so a
     * fresh 2-step datadir skips the walk entirely and RPC binds in seconds.
     * Deferring past services was rejected: the reducer mutates
     * state->chain_active as blocks arrive once services are up, so this must
     * stay a single-threaded pre-services pass — bounded is what makes that
     * acceptable. */
    int64_t done = -1;
    node_db_state_get_int(ndb, "shielded_backfill_height", &done);

    int start = utxo_recovery_shielded_backfill_start(done, tip_height);
    if (start <= 0) {
        printf("Shielded backfill: skipped (already covered through h=%lld)\n",
               (long long)done);
        fflush(stdout);
        return;
    }

    struct zcl_result r = utxo_recovery_backfill_shielded_range(
        ndb, dbsvc, state, datadir, start, tip_height, NULL);
    if (!r.ok) {
        LOG_WARN("utxo_recovery", "shielded backfill: %s", r.message);
        return;
    }
    /* The durable cursor is advanced inside the walk (crash-safe), so a
     * partial pass resumes from where it committed rather than restarting. */
}
