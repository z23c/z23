/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Reorg unwind of the explorer projection and its on-chain overlays.
 *
 * Why this exists: the catchup cursor can be rewound below a block that a
 * reorg took off the active chain (node_db_catchup_fork_rewind), but the
 * rows the losing branch wrote stayed behind. Two kinds of damage followed:
 *
 *   1. Height-stamped rows (tx_outputs, tx_inputs, op_returns, zslp_*,
 *      zanc_anchors, view_integrity, ...) of the loser kept describing
 *      transactions that are not on the chain.
 *   2. Overlay state that is MUTATED in place (a ZNAM name's owner, target
 *      and expiry, its text and address records, ZID identity status, the
 *      ZDIR directory) cannot be undone by height: a loser REGISTER kept the
 *      name FCFS-taken so the winner's REGISTER was refused, and a re-walk of
 *      a winner RENEW or TRANSFER ran twice over state it had already
 *      changed.
 *
 * The fix is exact and needs no new table or schema version:
 *
 *   - everything stamped with a height above `fork_height` is deleted;
 *   - when the stale range carried any ZNAM / ZID / ZDIR operation (or a
 *     mutable row was last touched above the fork), the in-place tables are
 *     cleared and re-folded from the on-chain operations at heights at or
 *     below the fork, in block order, by the same apply code the live walk
 *     runs. The common reorg (no overlay operation in the stale range) pays
 *     only the stamped deletes;
 *   - the two cursor-owning derived catalogs (zslp_ledger, op_return_index)
 *     carry a running digest that cannot be rewound, so when their cursor is
 *     above the fork they are truncated and their own services re-derive
 *     them, exactly as a reindex does.
 *
 * All of it runs in one transaction: a failure leaves the projection as it
 * was. node.db ONLY; never consulted by consensus. */

#include "services/explorer_unwind_service.h"
#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/op_return_index.h"
#include "models/zslp_ledger.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "overlay/overlay_projection.h"
#include "script/standard.h"
#include "util/ar_step_readonly.h"
#include "util/result.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "zdir/zdir.h"
#include "znam/znam.h"
#include "zid/zid_anchor.h"

#include <stdlib.h>
#include <string.h>

/* Every table below carries a block height on each row; the derived row is a
 * pure function of the block at that height (and of rows below it), so a
 * delete above the fork is exact. */
static const char *const k_stamped_deletes[] = {
    "DELETE FROM tx_outputs WHERE block_height>?",
    "DELETE FROM tx_inputs WHERE block_height>?",
    "DELETE FROM op_returns WHERE block_height>?",
    "DELETE FROM sapling_spends WHERE block_height>?",
    "DELETE FROM sapling_outputs WHERE block_height>?",
    "DELETE FROM joinsplits WHERE block_height>?",
    "DELETE FROM sprout_nullifiers WHERE block_height>?",
    "DELETE FROM view_integrity WHERE height>?",
    "DELETE FROM op_return_index WHERE height>?",
    "DELETE FROM zslp_transfers WHERE block_height>?",
    "DELETE FROM zslp_validity WHERE block_height>?",
    "DELETE FROM zslp_ledger WHERE created_height>?",
    "DELETE FROM zslp_tokens WHERE genesis_height>?",
    "DELETE FROM zanc_anchors WHERE height>?",
};

/* A spend recorded above the fork un-happens with the block. */
static const char k_ledger_unspend[] =
    "UPDATE zslp_ledger SET spent_by_txid=NULL,spent_height=NULL"
    " WHERE spent_height>?";

/* Tables whose rows are mutated in place by overlay operations. They are
 * rebuilt from the chain, never patched. */
static const char *const k_mutable_clears[] = {
    "DELETE FROM znam_names",
    "DELETE FROM znam_text_records",
    "DELETE FROM znam_addr_records",
    "DELETE FROM zid_identities",
    "DELETE FROM onion_directory",
};

/* Does a mutable overlay row carry a stamp above the fork? Catches state the
 * op_returns probe cannot see (a row whose op_returns row was never written). */
static const char k_mutable_stamped_probe[] =
    "SELECT 1 WHERE EXISTS (SELECT 1 FROM znam_names WHERE reg_height>?)"
    " OR EXISTS (SELECT 1 FROM zid_identities WHERE updated_height>?)"
    " OR EXISTS (SELECT 1 FROM onion_directory WHERE updated_height>?)";

static bool unwind_exec_height(struct node_db *ndb, const char *sql,
                               int64_t h)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s, sql);
    AR_BIND_INT(s, 1, h);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        LOG_ERROR("explorer", "unwind: statement failed: %s", sql);
    return ok;
}

static bool unwind_exec_plain(struct node_db *ndb, const char *sql)
{
    if (!node_db_exec(ndb, sql)) {
        LOG_ERROR("explorer", "unwind: statement failed: %s", sql);
        return false;
    }
    return true;
}

/* The registry the replay dispatches through: only the overlays whose state
 * is mutated in place. Built from the live registry so a descriptor is never
 * duplicated here. */
static bool unwind_replay_registry(struct overlay_registry *out)
{
    static const char *const names[] = { "znam", "zid", "zdir" };
    const struct overlay_registry *all = explorer_index_overlays();
    if (!all)
        return false;
    overlay_registry_init(out);
    bool ok = true;
    for (size_t i = 0; i < all->count; i++) {
        for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
            if (all->entries[i].name &&
                strcmp(all->entries[i].name, names[n]) == 0)
                ok = overlay_registry_add(out, &all->entries[i]) && ok;
        }
    }
    return ok && overlay_registry_count(out) == 3;
}

static bool unwind_script_replayed(const struct overlay_registry *reg,
                                   const uint8_t *script, size_t len)
{
    char tag[OVERLAY_LOKAD_LEN];
    return script && overlay_peek_lokad(script, len, tag) &&
           overlay_registry_find(reg, tag) != NULL;
}

/* True when any op_returns row above the fork is a replayed-overlay op. */
static bool unwind_stale_range_touched(struct node_db *ndb,
                                       const struct overlay_registry *reg,
                                       int fork_height, bool *touched)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT script FROM op_returns WHERE block_height>?");
    AR_BIND_INT(s, 1, fork_height);
    *touched = false;
    enum zcl_step rc = ZCL_STEP_ROW;
    while (!*touched &&
           (rc = ar_step_checked(s, "unwind op_returns probe", NULL)) ==
               ZCL_STEP_ROW) {
        const uint8_t *script = sqlite3_column_blob(s, 0);
        if (unwind_script_replayed(reg, script, (size_t)AR_COL_BYTES(s, 0)))
            *touched = true;
    }
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR)
        LOG_FAIL("explorer", "unwind: op_returns probe step failed");
    if (*touched)
        return true;

    AR_PREPARE_BOOL(ndb, s, k_mutable_stamped_probe);
    AR_BIND_INT(s, 1, fork_height);
    AR_BIND_INT(s, 2, fork_height);
    AR_BIND_INT(s, 3, fork_height);
    rc = ar_step_checked(s, "unwind stamp probe", NULL);
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR)
        LOG_FAIL("explorer", "unwind: stamp probe step failed");
    *touched = rc == ZCL_STEP_ROW;
    return true;
}

/* Ascending, de-duplicated heights at or below the fork that carry a
 * replayed-overlay operation. Caller frees *out. */
static bool unwind_replay_heights(struct node_db *ndb,
                                  const struct overlay_registry *reg,
                                  int fork_height, int **out, size_t *n_out)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT block_height,script FROM op_returns WHERE block_height<=?"
        " ORDER BY block_height ASC");
    AR_BIND_INT(s, 1, fork_height);

    int *heights = NULL;
    size_t n = 0, cap = 0;
    bool ok = true;
    enum zcl_step rc = ZCL_STEP_ROW;
    while (ok && (rc = ar_step_checked(s, "unwind replay heights", NULL)) ==
                       ZCL_STEP_ROW) {
        int h = (int)AR_COL_INT(s, 0);
        const uint8_t *script = sqlite3_column_blob(s, 1);
        if (!unwind_script_replayed(reg, script, (size_t)AR_COL_BYTES(s, 1)))
            continue;
        if (n > 0 && heights[n - 1] == h)
            continue;
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            int *grown = zcl_realloc(heights, ncap * sizeof(*heights),
                                   "unwind replay heights");
            if (!grown) {
                LOG_ERROR("explorer", "unwind: out of memory for %zu heights",
                          ncap);
                ok = false;
                break;
            }
            heights = grown;
            cap = ncap;
        }
        heights[n++] = h;
    }
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR) {
        LOG_ERROR("explorer", "unwind: op_returns replay scan step failed");
        ok = false;
    }
    if (!ok) {
        free(heights);
        return false;
    }
    *out = heights;
    *n_out = n;
    return true;
}

/* The same first-OP_RETURN rule the live indexer applies. */
static const struct tx_out *unwind_first_op_return(const struct transaction *tx)
{
    for (size_t vo = 0; vo < tx->num_vout; vo++) {
        const struct tx_out *o = &tx->vout[vo];
        uint8_t a20[20];
        bool has = false;
        if (utxo_classify_script(o->script_pub_key.data,
                                 o->script_pub_key.size, a20, &has) ==
            SCRIPT_OP_RETURN)
            return o;
    }
    return NULL;
}

static bool unwind_replay_block(struct node_db *ndb,
                                const struct overlay_registry *reg,
                                const struct block *blk, int height)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        const struct tx_out *o = unwind_first_op_return(tx);
        if (!o)
            continue;
        (void)overlay_ingest(reg, ndb, tx, o->script_pub_key.data,
                             o->script_pub_key.size, height);
    }
    return true;
}

static bool unwind_replay(struct node_db *ndb,
                          const struct overlay_registry *reg, int fork_height,
                          explorer_block_reader_fn read, void *rctx)
{
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(k_mutable_clears) /
                                    sizeof(k_mutable_clears[0]); i++)
        ok = unwind_exec_plain(ndb, k_mutable_clears[i]);

    int *heights = NULL;
    size_t n = 0;
    if (ok)
        ok = unwind_replay_heights(ndb, reg, fork_height, &heights, &n);
    if (ok && n > 0 && !read) {
        LOG_ERROR("explorer", "unwind: %zu overlay block(s) to replay but no "
                  "block reader", n);
        ok = false;
    }
    for (size_t i = 0; ok && i < n; i++) {
        struct block blk;
        block_init(&blk);
        if (!read(rctx, heights[i], &blk)) {
            LOG_ERROR("explorer", "unwind: block at height %d unreadable; "
                      "overlay state cannot be rebuilt", heights[i]);
            ok = false;
            continue;
        }
        ok = unwind_replay_block(ndb, reg, &blk, heights[i]);
        block_free(&blk);
    }
    free(heights);
    return ok;
}

/* A derived catalog that owns a cursor and a running digest cannot be rewound
 * to an earlier height; above the fork it is dropped and re-derived. */
static bool unwind_derived_catalogs(struct node_db *ndb, int fork_height)
{
    int32_t ledger_h = -1;
    uint8_t digest[32];
    bool ok = zslp_ledger_get_cursor(ndb, &ledger_h, digest);
    if (ok)
        ok = ledger_h > fork_height
                 ? zslp_ledger_truncate(ndb)
                 : unwind_exec_height(ndb, k_ledger_unspend, fork_height);

    int32_t cursor = -1, base = 0;
    if (ok && op_return_index_get_cursor_heights(ndb, &cursor, &base) &&
        cursor > fork_height)
        ok = op_return_index_truncate(ndb);
    if (!ok)
        LOG_ERROR("explorer", "unwind: derived catalogs could not be reset "
                  "at fork height %d", fork_height);
    return ok;
}

static bool unwind_stamped_deletes(struct node_db *ndb, int fork_height)
{
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(k_stamped_deletes) /
                                    sizeof(k_stamped_deletes[0]); i++)
        ok = unwind_exec_height(ndb, k_stamped_deletes[i], fork_height);
    return ok;
}

static bool unwind_body(struct node_db *ndb, int fork_height,
                        explorer_block_reader_fn read, void *rctx)
{
    struct overlay_registry reg;
    if (!unwind_replay_registry(&reg)) {
        LOG_ERROR("explorer", "unwind: overlay registry is incomplete");
        return false;
    }
    bool touched = false;
    bool ok = unwind_stale_range_touched(ndb, &reg, fork_height, &touched);

    /* A replay can only rebuild what the projection holds: it needs the
     * outputs and op_returns of every height up to the fork. A datadir
     * seeded from a snapshot, or with holes below the fork, lacks them, and
     * clearing the in-place tables there would destroy state that cannot be
     * re-derived. Such a database gets the stamped deletes only. */
    bool complete = fork_height < 0 ||
                    db_view_integrity_contiguous_height(ndb) >= fork_height;

    /* The derived catalogs read the stamped tables, so they settle first. */
    if (ok)
        ok = unwind_derived_catalogs(ndb, fork_height);
    if (ok)
        ok = unwind_stamped_deletes(ndb, fork_height);
    if (ok && touched && !complete) {
        LOG_WARN("explorer", "unwind: overlay operations above height %d but "
                 "the projection is not contiguous up to it; ZNAM/ZID/ZDIR "
                 "state is left as is (reindex-explorer rebuilds it)",
                 fork_height);
    } else if (ok && touched) {
        LOG_WARN("explorer", "unwind: overlay operations above height %d; "
                 "rebuilding ZNAM/ZID/ZDIR state from the chain",
                 fork_height);
        ok = unwind_replay(ndb, &reg, fork_height, read, rctx);
    }
    return ok;
}

struct zcl_result explorer_index_unwind_above(struct node_db *ndb,
                                              int fork_height,
                                              explorer_block_reader_fn read,
                                              void *rctx)
{
    if (!ndb || !ndb->open || fork_height < -1)
        return ZCL_ERR(-1, "explorer_index_unwind_above: invalid args "
                       "(fork_height=%d)", fork_height);
    if (!node_db_begin_immediate(ndb))
        return ZCL_ERR(-2, "unwind above height %d: could not open a "
                       "transaction", fork_height);
    if (!unwind_body(ndb, fork_height, read, rctx)) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("explorer", "unwind: rollback failed");
        return ZCL_ERR(-3, "unwind above height %d failed; projection left "
                       "as it was", fork_height);
    }
    if (!node_db_commit(ndb)) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("explorer", "unwind: rollback after failed commit "
                      "failed");
        return ZCL_ERR(-4, "unwind above height %d: commit failed",
                       fork_height);
    }
    return ZCL_OK;
}
