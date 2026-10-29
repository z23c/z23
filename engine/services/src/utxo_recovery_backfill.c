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
#include "validation/connect_block.h"
#include "chain/chain.h"
#include "models/database.h"
#include "storage/disk_block_io.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <sqlite3.h>

/* Commit + advance the durable cursor every this-many heights scanned. Bounds
 * the SQLite transaction size on the (rare) one-time full pass and gives
 * crash-safe incremental progress; the common re-fire suffix is far smaller. */
#define SHIELDED_BACKFILL_SCAN_BATCH 50000

/* Outcome codes for backfill_walk_value_range: a non-negative result is the
 * highest height resolved (the caller persists it as the cursor);
 * negatives say why the walk stopped early. */
enum backfill_walk_status {
    BACKFILL_WALK_ABORTED = -1,       /* batch flush failed; *abort_op names it */
    BACKFILL_WALK_BEGIN_FAILED = -2,  /* BEGIN for the next batch failed */
    BACKFILL_WALK_CLEANED = -3,       /* write failed; already rolled back */
};

/* One derived block value pair awaiting its durable commit. The in-memory
 * block_index is refreshed from these ONLY after the covering transaction
 * commits, so a failed write never changes memory (plain 8-byte stores, as
 * connect_block.c and block_index_loader_topup.c do for these fields). Note:
 * the cumulative nChainSaplingValue/nChainSproutValue (getblockchaininfo
 * valuePools) are NOT corrected by this code. */
struct shielded_verify_item {
    struct block_index *bi;
    int64_t sprout;
    int64_t sapling;
};

struct backfill_pending {
    struct shielded_verify_item *items;
    int count;
};

static void backfill_apply_pending(struct backfill_pending *p)
{
    for (int i = 0; i < p->count; i++) {
        p->items[i].bi->nSproutValue = p->items[i].sprout;
        p->items[i].bi->nSaplingValue = p->items[i].sapling;
    }
    p->count = 0;
}

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
    /* Absent cursor: do NOT read ~every body before services start. Cover only
     * the tip; the background verify pass heals everything below it. */
    return (done_cursor < 0) ? tip_height : (int)(done_cursor + 1);
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

/* The cursor is a proof that every covered row is durable.  Once this writer
 * owns a transaction, any persistence failure must discard the whole current
 * batch rather than let a later cursor write certify a missing value. */
static bool backfill_abort_write(struct node_db *ndb, sqlite3_stmt *upd,
                                 sqlite3_stmt *ins, const char *operation)
{
    LOG_WARN("utxo_recovery", "backfill: %s failed: %s", operation,
             sqlite3_errmsg(ndb->db));
    if (!node_db_rollback(ndb))
        LOG_WARN("utxo_recovery", "backfill: rollback after %s failed: %s",
                 operation, sqlite3_errmsg(ndb->db));
    sqlite3_finalize(upd);
    sqlite3_finalize(ins);
    return false;
}

static bool backfill_open_write(struct node_db *ndb, sqlite3_stmt **upd_out,
                                sqlite3_stmt **ins_out)
{
    sqlite3_stmt *upd = NULL;
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(
            ndb->db,
            "UPDATE blocks SET sapling_value=?1, sprout_value=?2 WHERE hash=?3 "
            "AND (sapling_value IS NOT ?1 OR sprout_value IS NOT ?2)",
            -1, &upd, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_recovery", "backfill: prepare UPDATE failed: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    if (sqlite3_prepare_v2(
            ndb->db,
            "INSERT OR IGNORE INTO blocks"
            "(hash,height,prev_hash,version,merkle_root,"
            "time,bits,nonce,solution,chain_work,status,"
            "file_num,data_pos,undo_pos,num_tx,"
            "sapling_root,sprout_root,sapling_value,sprout_value)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?)",
            -1, &ins, NULL) != SQLITE_OK) {
        sqlite3_finalize(upd);
        LOG_WARN("utxo_recovery", "backfill: prepare INSERT failed: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    if (!node_db_begin(ndb)) {
        sqlite3_finalize(upd);
        sqlite3_finalize(ins);
        LOG_WARN("utxo_recovery", "backfill: begin transaction failed: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    *upd_out = upd;
    *ins_out = ins;
    return true;
}

static bool backfill_mark_empty_range(struct node_db *ndb, int tip)
{
    if (!node_db_state_set_int(ndb, "shielded_backfill_height", tip)) {
        LOG_WARN("utxo_recovery", "backfill: persist empty-range cursor failed: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    return true;
}

static bool backfill_finish_write(struct node_db *ndb, sqlite3_stmt *upd,
                                  sqlite3_stmt *ins, int reached, int start,
                                  int updated, struct shielded_backfill_ctx *bctx)
{
    if (!node_db_state_set_int(ndb, "shielded_backfill_height", reached))
        return backfill_abort_write(ndb, upd, ins, "persist final cursor");
    if (!node_db_commit(ndb))
        return backfill_abort_write(ndb, upd, ins, "commit final value batch");
    sqlite3_finalize(upd);
    sqlite3_finalize(ins);
    bctx->updated = updated;
    printf("Shielded backfill: covered (%d,%d] — %d blocks carried "
           "JoinSplit/Sapling values\n", start - 1, reached, updated);
    fflush(stdout);
    return true;
}

/* Derive one block's shielded values from its BODY. A cached non-zero
 * nSaplingValue/nSproutValue is never trusted: blocks connected before the
 * valueDeltaZat sign fix (8d8346b743) can carry the wrong sign in the index.
 * Pure: it stores nothing; each caller refreshes bi only AFTER its write
 * commits. Returns 0 with both values derived, or -1
 * when the body cannot be read, in which case the caller must stop without
 * advancing the cursor (we cannot PROVE the value, zero or otherwise). */
static int backfill_resolve_block_values(struct block_index *bi,
                                         const char *datadir,
                                         int64_t *sprout_val,
                                         int64_t *sapling_val)
{
    struct block blk;
    if (!read_block_from_disk_index(&blk, bi, datadir))
        return -1; /* raw-return-ok:unreadable body; the walk stops and retries next boot */
    connect_block_shielded_values(&blk, sprout_val, sapling_val);
    block_free(&blk);
    return 0;
}


/* Write one block's derived shielded values, compare-first: the UPDATE only
 * touches a row whose stored pair differs, so a correct row is never rewritten
 * (and is not counted). Returns 1 when a value row was repaired or inserted,
 * 0 when nothing changed and -1 when a step failed.  allow_insert=false (the
 * self-verify pass) never creates rows. A
 * failure is rolled back and both statements finalized HERE, while the
 * SQLITE_STATIC bindings of this frame are still alive. */
static int backfill_write_value_row(struct node_db *ndb, sqlite3_stmt *upd,
                                    sqlite3_stmt *ins,
                                    struct block_index *bi,
                                    int64_t sprout_val, int64_t sapling_val,
                                    bool allow_insert)
{
    /* Primary path: derive-only UPDATE keyed by hash. Touches ONLY the
     * two shielded-value columns — the consensus columns of an
     * already-populated row are left exactly as normal sync wrote them. */
    sqlite3_reset(upd);
    sqlite3_bind_int64(upd, 1, sapling_val);
    sqlite3_bind_int64(upd, 2, sprout_val);
    sqlite3_bind_blob(upd, 3, bi->phashBlock->data, 32, SQLITE_STATIC);

    if (AR_STEP_WRITE(upd) != SQLITE_DONE) {
        backfill_abort_write(ndb, upd, ins, "UPDATE value row");
        return -1; /* raw-return-ok:backfill_abort_write logged the failed step */
    }
    if (sqlite3_changes(ndb->db) > 0)
        return 1;
    if (!allow_insert || (sprout_val == 0 && sapling_val == 0))
        return 0;   /* nothing to repair; never invent an all-zero row */
    /* No row for this hash yet: insert a FULL row from the in-memory
     * block_index (real solution/chain_work/undo_pos/sapling_root),
     * so the computed value is preserved instead of silently lost. */
    sqlite3_reset(ins);
    const struct uint256 bi_merkle = block_index_merkle_root(bi);
    const struct uint256 bi_nonce = block_index_nonce(bi);
    size_t bi_sol_len = 0;
    const unsigned char *bi_sol = block_index_solution(bi, &bi_sol_len);
    sqlite3_bind_blob(ins, 1, bi->phashBlock->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(ins, 2, bi->nHeight);
    sqlite3_bind_blob(ins, 3,
                      bi->pprev ? bi->pprev->phashBlock->data
                                : (const uint8_t[32]){0},
                      32, SQLITE_STATIC);
    sqlite3_bind_int(ins, 4, bi->nVersion);
    sqlite3_bind_blob(ins, 5, bi_merkle.data, 32,
                      SQLITE_STATIC);
    sqlite3_bind_int64(ins, 6, bi->nTime);
    sqlite3_bind_int(ins, 7, (int)bi->nBits);
    sqlite3_bind_blob(ins, 8, bi_nonce.data, 32, SQLITE_STATIC);
    sqlite3_bind_blob(ins, 9,
                      bi_sol ? (const void *)bi_sol : (const void *)"",
                      bi_sol ? (int)bi_sol_len : 0, SQLITE_STATIC);
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
        backfill_abort_write(ndb, upd, ins, "INSERT value row");
        return -1; /* raw-return-ok:backfill_abort_write logged the failed step */
    }
    /* INSERT OR IGNORE: 0 changes means a row appeared meanwhile; leave it. */
    return sqlite3_changes(ndb->db) > 0 ? 1 : 0;
}

/* Durably commit one scanned batch and advance the in-transaction cursor.
 * Returns 0 on success, -1 when the cursor persist failed and -2 when the
 * commit failed; on failure *abort_op names the failed operation. */
static int backfill_flush_scan_batch(struct node_db *ndb, int h,
                                     int *cursor_committed,
                                     const char **abort_op)
{
    /* Cursor advance is part of THIS transaction: the covering rows
     * and the cursor commit atomically together (crash-safe). */
    if (!node_db_state_set_int(ndb, "shielded_backfill_height", h)) {
        *abort_op = "persist batch cursor";
        return -1; /* raw-return-ok:the caller aborts and logs *abort_op */
    }
    if (!node_db_commit(ndb)) {
        *abort_op = "commit value batch";
        return -2;
    }
    *cursor_committed = h;
    return 0;
}

/* Highest height actually resolved: tip on a full pass, or (h-1) if we
 * broke early. Never move the cursor backward. */
static int backfill_final_reached_height(int h, int cursor_committed)
{
    int reached = h - 1;
    if (reached < cursor_committed)
        reached = cursor_committed;
    return reached;
}

/* Walk [start, tip] on the active chain, deriving and writing each
 * block's shielded values. Returns the highest height resolved (not yet
 * durable beyond the last committed batch; the caller persists it),
 * BACKFILL_WALK_CLEANED after a failed row write (already rolled back and
 * finalized), BACKFILL_WALK_ABORTED after a failed batch flush (*abort_op
 * names the operation for backfill_abort_write), or BACKFILL_WALK_BEGIN_FAILED when the BEGIN
 * for the next batch failed after a commit (statements are NOT finalized;
 * the caller finalizes and logs). */
static int backfill_walk_value_range(struct node_db *ndb,
                                     struct active_chain *chain,
                                     const char *datadir,
                                     sqlite3_stmt *upd, sqlite3_stmt *ins,
                                     int start, int tip, int *updated,
                                     const char **abort_op,
                                     struct backfill_pending *pend)
{
    int cursor_committed = start - 1;   /* durable floor already proven */
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
        if (backfill_resolve_block_values(bi, datadir, &sprout_val,
                                          &sapling_val) != 0)
            break;

        int wrote = backfill_write_value_row(ndb, upd, ins, bi,
                                             sprout_val, sapling_val, true);
        if (wrote < 0)
            return BACKFILL_WALK_CLEANED;
        if (wrote > 0)
            (*updated)++;

        pend->items[pend->count++] =
            (struct shielded_verify_item){ bi, sprout_val, sapling_val };
        if (pend->count >= SHIELDED_BACKFILL_SCAN_BATCH) {
            if (backfill_flush_scan_batch(ndb, h, &cursor_committed,
                                          abort_op) != 0)
                return BACKFILL_WALK_ABORTED;
            backfill_apply_pending(pend);   /* committed: memory may follow */
            if (!node_db_begin(ndb))
                return BACKFILL_WALK_BEGIN_FAILED;
            printf("  backfill: scanned through h=%d (%d shielded rows)...\n",
                   h, *updated);
            fflush(stdout);
        }
    }
    return backfill_final_reached_height(h, cursor_committed);
}

/* Turn the walk outcome into the write result, finishing (or aborting) the
 * open transaction. */
static bool backfill_walk_conclude(struct node_db *ndb, sqlite3_stmt *upd,
                                   sqlite3_stmt *ins, int reached,
                                   const char *abort_op, int start,
                                   int updated,
                                   struct shielded_backfill_ctx *bctx)
{
    if (reached == BACKFILL_WALK_BEGIN_FAILED) {
        sqlite3_finalize(upd);
        sqlite3_finalize(ins);
        LOG_FAIL("utxo_recovery", "backfill: begin next batch failed: %s",
                 sqlite3_errmsg(ndb->db));
    }
    if (reached == BACKFILL_WALK_CLEANED)
        return false;
    if (abort_op)
        return backfill_abort_write(ndb, upd, ins, abort_op);
    return backfill_finish_write(ndb, upd, ins, reached, start, updated, bctx);
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
        bctx->updated = 0;
        return backfill_mark_empty_range(ndb, tip);
    }

    /* This backfill only DERIVES the two shielded-value columns; it must never
     * disturb the consensus columns (solution, chain_work, undo_pos,
     * sapling_root, sprout_root) that normal sync wrote. So the primary path is
     * a keyed UPDATE of exactly those two columns. The old INSERT OR REPLACE
     * clobbered every other column with empty/NULL, wiping the real solution and
     * chain_work of any suffix block already populated by normal sync. Rows are
     * keyed by hash (the blocks PK); height is NOT unique across forks. */
    /* Fallback only for a hash with no existing row (a shielded block above the
     * blocks-table population). An UPDATE that matched 0 rows must NOT silently
     * drop the computed value, so we INSERT a full row using the REAL fields
     * from the in-memory block_index (solution/chain_work/undo_pos/sapling_root),
     * never empty placeholders. On the active chain the row essentially always
     * exists, so this path is a rarely-taken safety net. */
    sqlite3_stmt *upd = NULL;
    sqlite3_stmt *ins = NULL;
    if (!backfill_open_write(ndb, &upd, &ins))
        return false; // raw-return-ok:backfill_open_write-logs-each-failure

    struct backfill_pending pend = {
        .items = zcl_calloc(SHIELDED_BACKFILL_SCAN_BATCH, sizeof(*pend.items),
                            "backfill_pending"),
    };
    if (!pend.items) {
        sqlite3_finalize(upd);
        sqlite3_finalize(ins);
        LOG_FAIL("utxo_recovery", "backfill: out of memory");
    }
    int updated = 0;
    const char *abort_op = NULL;
    int reached = backfill_walk_value_range(ndb, chain, bctx->datadir,
                                            upd, ins, start, tip,
                                            &updated, &abort_op, &pend);
    bool ok = backfill_walk_conclude(ndb, upd, ins, reached, abort_op, start,
                                     updated, bctx);
    if (ok)
        backfill_apply_pending(&pend);   /* only after the final commit */
    free(pend.items);
    return ok;
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

/* ── Background self-verify of the persisted shielded values ─────────────
 *
 * blocks.sapling_value must equal zclassicd's valueDeltaZat (-sum(valueBalance)).
 * Rows written by self-connection before the sign fix can carry the wrong sign
 * BELOW the boot backfill cursor, where the boot walk never looks again.  This
 * pass re-derives both values from the block bodies, in small paced batches
 * through the node's own write helpers, and compare-and-updates by hash.  It is
 * explorer/projection data only; no consensus predicate reads it.
 *
 * Cursor `shielded_value_verify_height` is the highest height fully verified
 * (advanced in the same transaction as the row repairs).  Marker
 * `shielded_value_verify_done` is set once the pass has covered the tip. */

#define SHIELDED_VERIFY_CURSOR_KEY "shielded_value_verify_height"
#define SHIELDED_VERIFY_DONE_KEY "shielded_value_verify_done"


struct shielded_verify_ctx {
    struct shielded_verify_item *items;
    int count;
    int through;      /* cursor value to persist with this batch */
    bool mark_done;   /* persist the done marker in the same transaction */
    int repaired;
};

int utxo_recovery_shielded_verify_may_run(int chain_tip, int projection_tip,
                                           int64_t header_tip)
{
    if (chain_tip <= 0 || projection_tip < 0 || header_tip < 0)
        return 0;
    /* Both the node.db projection and the header chain must be within the live
     * edge; anything further behind is sync work this pass must not compete
     * with. */
    return projection_tip + 1 >= chain_tip && header_tip <= (int64_t)chain_tip + 1 ? 1 : 0;
}

/* Phase 1 (no db): derive the values of [from, to] from block bodies. Stops at
 * the first height with no body or an unreadable body, so the result is always
 * the contiguous verified prefix (the count of items = heights verified). */
static int verify_collect_range(struct active_chain *chain, const char *datadir,
                                int from, int to,
                                struct shielded_verify_item *items)
{
    int n = 0;
    for (int h = from; h <= to; h++) {
        struct block_index *bi = active_chain_at(chain, h);
        if (!bi || bi->nFile < 0 || !(bi->nStatus & BLOCK_HAVE_DATA) ||
            (bi->nDataPos == 0 && bi->nHeight > 0))
            break;   /* cannot prove this height: stop, retry next tick */
        int64_t sprout = 0, sapling = 0;
        if (backfill_resolve_block_values(bi, datadir, &sprout, &sapling) != 0)
            break;   /* cannot prove this height: stop, retry next tick */
        items[n++] = (struct shielded_verify_item){ bi, sprout, sapling };
    }
    return n;
}

static bool verify_write_batch(struct node_db *ndb, void *ctx_ptr)
{
    struct shielded_verify_ctx *vctx = ctx_ptr;
    if (!ndb || !ndb->open || !vctx)
        LOG_FAIL("utxo_recovery", "shielded verify: null or closed db");
    sqlite3_stmt *upd = NULL;
    sqlite3_stmt *ins = NULL;
    if (!backfill_open_write(ndb, &upd, &ins))
        return false; // raw-return-ok:backfill_open_write-logs-each-failure
    vctx->repaired = 0;
    for (int i = 0; i < vctx->count; i++) {
        const struct shielded_verify_item *it = &vctx->items[i];
        int wrote = backfill_write_value_row(ndb, upd, ins, it->bi,
                                             it->sprout, it->sapling, false);
        if (wrote < 0)
            return false; // raw-return-ok:backfill_write_value_row rolled back
        vctx->repaired += wrote;
    }
    if (!node_db_state_set_int(ndb, SHIELDED_VERIFY_CURSOR_KEY, vctx->through))
        return backfill_abort_write(ndb, upd, ins, "persist verify cursor");
    if (vctx->mark_done &&
        !node_db_state_set_int(ndb, SHIELDED_VERIFY_DONE_KEY, 1))
        return backfill_abort_write(ndb, upd, ins, "persist verify done marker");
    if (!node_db_commit(ndb))
        return backfill_abort_write(ndb, upd, ins, "commit verify batch");
    sqlite3_finalize(upd);
    sqlite3_finalize(ins);
    return true;
}

/* Phase 2: run the collected batch through the node's write path, then refresh
 * the in-memory index from the derived values. Frees vctx->items. */
static bool verify_commit_batch(struct node_db *ndb, struct db_service *dbsvc,
                                struct shielded_verify_ctx *vctx)
{
    bool ok = dbsvc ? db_service_run_write(dbsvc, verify_write_batch, vctx)
                    : verify_write_batch(ndb, vctx);
    if (ok) {
        struct backfill_pending pend = { vctx->items, vctx->count };
        backfill_apply_pending(&pend);
    }
    free(vctx->items);
    vctx->items = NULL;
    return ok;
}

/* First height still to verify: above the persisted cursor, never below Sapling
 * activation. */
static int verify_first_height(struct node_db *ndb, int sapling_activation,
                               int64_t *cursor)
{
    *cursor = -1;
    node_db_state_get_int(ndb, SHIELDED_VERIFY_CURSOR_KEY, cursor);
    int from = (int)*cursor + 1;
    if (from < sapling_activation)
        from = sapling_activation;
    return from < 1 ? 1 : from;
}

static bool verify_args_ok(const struct node_db *ndb, int max_heights)
{
    return ndb && ndb->open && max_heights > 0;
}

static bool verify_marker_set(struct node_db *ndb)
{
    int64_t done = 0;
    return node_db_state_get_int(ndb, SHIELDED_VERIFY_DONE_KEY, &done) && done;
}

static void verify_report(const struct shielded_value_verify_batch *res,
                          bool had_range, int tip_height)
{
    if (had_range)
        LOG_INFO("utxo_recovery",
                 "shielded verify: heights %d..%d scanned=%d repaired=%d",
                 res->from, res->through, res->scanned, res->repaired);
    if (res->at_tip)
        LOG_INFO("utxo_recovery",
                 "shielded verify: complete through tip height %d", tip_height);
}

struct zcl_result utxo_recovery_verify_shielded_values_batch(
    struct node_db *ndb, struct db_service *dbsvc, struct main_state *state,
    const char *datadir, int sapling_activation, int tip_height,
    int max_heights, struct shielded_value_verify_batch *out)
{
    struct shielded_value_verify_batch res = {0};
    struct zcl_result valid = backfill_validate_args(ndb, dbsvc, state);
    if (!valid.ok)
        return valid;
    if (!verify_args_ok(ndb, max_heights))
        return ZCL_ERR(-53, "shielded verify: bad batch arguments");

    if (verify_marker_set(ndb)) {
        res.at_tip = res.already_done = true;
        if (out)
            *out = res;
        return ZCL_OK;
    }
    int64_t cursor;
    int from = verify_first_height(ndb, sapling_activation, &cursor);
    if (cursor < 0)
        cursor = 0;
    int to = from + max_heights - 1;
    if (to > tip_height)
        to = tip_height;
    res.from = from;
    struct shielded_verify_ctx vctx = {0};
    size_t slots = to >= from ? (size_t)(to - from + 1) : 1;
    vctx.items = zcl_calloc(slots, sizeof(*vctx.items), "shielded_verify_items");
    if (!vctx.items)
        return ZCL_ERR(-54, "shielded verify: out of memory");
    if (to >= from)
        vctx.count = verify_collect_range(&state->chain_active, datadir,
                                          from, to, vctx.items);
    /* Only the contiguous verified prefix is certified: a height whose body
     * is missing or unreadable stops the batch, the cursor stays below it and
     * the done marker is withheld until a later batch verifies it. */
    int verified = to >= from ? from + vctx.count - 1 : to;
    vctx.through = (to >= from && vctx.count > 0) ? verified : (int)cursor;
    vctx.mark_done = verified >= tip_height;
    res.through = verified;
    if (!verify_commit_batch(ndb, dbsvc, &vctx))
        return ZCL_ERR(-55, "shielded verify: batch write failed");
    res.scanned = vctx.count;
    res.repaired = vctx.repaired;
    res.at_tip = vctx.mark_done;
    verify_report(&res, res.scanned > 0, tip_height);
    if (out)
        *out = res;
    return ZCL_OK;
}
