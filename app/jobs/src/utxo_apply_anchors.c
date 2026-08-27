/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_anchors -- implementation.  See jobs/utxo_apply_anchors.h. */

#include "jobs/utxo_apply_anchors.h"

#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "config/runtime.h"
#include "consensus/upgrades.h"
#include "jobs/reducer_frontier.h"
#include "jobs/reducer_commit_invariants.h"
#include "jobs/utxo_apply_delta.h"
#include "models/block.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ANCHOR_STAGE_SUBSYS "utxo_apply"

struct anchor_lookup_view {
    struct coins_view view;
    sqlite3 *db;
};

static enum coins_anchor_lookup_result anchor_lookup_vtable(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    struct anchor_lookup_view *av = self;
    if (!av || !av->db)
        return COINS_ANCHOR_ERROR;
    enum anchor_kv_lookup_result r = anchor_kv_get(
        av->db, (int)pool, root, tree_out, NULL);
    switch (r) {
    case ANCHOR_KV_FOUND: return COINS_ANCHOR_FOUND;
    case ANCHOR_KV_MISSING: return COINS_ANCHOR_MISSING;
    case ANCHOR_KV_HISTORY_INCOMPLETE:
        return COINS_ANCHOR_HISTORY_INCOMPLETE;
    case ANCHOR_KV_ERROR:
    default: return COINS_ANCHOR_ERROR;
    }
}

static struct coins_view_vtable g_anchor_lookup_vtable = {
    .get_anchor = anchor_lookup_vtable,
};

static void anchor_reject(struct delta_summary *summary,
                          const struct transaction *tx,
                          const char *status, const char *kind)
{
    summary->ok = false;
    summary->status = status;
    summary->failure_kind = kind;
    memset(summary->failure_detail, 0, sizeof(summary->failure_detail));
    if (tx)
        memcpy(summary->failure_detail, tx->hash.data, 32);
}

static bool block_has_sprout_commitments(const struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++)
        if (blk->vtx[i].num_joinsplit > 0)
            return true;
    return false;
}

static bool block_has_sapling_commitments(const struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++)
        if (blk->vtx[i].num_shielded_output > 0)
            return true;
    return false;
}

static const struct transaction *first_anchor_tx(const struct block *blk,
                                                  int pool)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        if ((pool == ANCHOR_POOL_SPROUT && tx->num_joinsplit > 0) ||
            (pool == ANCHOR_POOL_SAPLING &&
             (tx->num_shielded_spend > 0 ||
              tx->num_shielded_output > 0)))
            return tx;
    }
    return NULL;
}

static enum anchor_kv_lookup_result latest_tree_for_fold(
    sqlite3 *db, int pool, int height, bool full_replay,
    struct incremental_merkle_tree *tree)
{
    enum anchor_kv_lookup_result result = anchor_kv_latest_tree(
        db, pool, tree, NULL, NULL);
    if (result != ANCHOR_KV_HISTORY_INCOMPLETE || !full_replay)
        return result;
    /* Only the bounded genesis replay may use an implicit empty frontier while
     * its public marker remains positive. The session proves exact next height,
     * and the per-pool started bit prevents an unexpectedly cleared table from
     * being reinterpreted as "no commitments yet" later in the replay. */
    if (!shielded_history_full_replay_empty_frontier_allowed(
            db, pool, height))
        return result;
    if (pool == ANCHOR_POOL_SPROUT)
        sprout_tree_init(tree);
    else
        sapling_tree_init(tree);
    return ANCHOR_KV_FOUND;
}

static bool fold_sprout(sqlite3 *db, const struct block *blk, int height,
                        struct delta_summary *summary, bool full_replay)
{
    if (!block_has_sprout_commitments(blk))
        return true;
    struct incremental_merkle_tree tree;
    enum anchor_kv_lookup_result lr = latest_tree_for_fold(
        db, ANCHOR_POOL_SPROUT, height, full_replay, &tree);
    if (lr == ANCHOR_KV_ERROR)
        return false;
    if (lr != ANCHOR_KV_FOUND) {
        anchor_reject(summary, first_anchor_tx(blk, ANCHOR_POOL_SPROUT),
                      "shielded_anchor_history_gap",
                      "sprout-anchor-frontier-unavailable");
        return true;
    }
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        for (size_t j = 0; j < tx->num_joinsplit; j++)
            for (size_t k = 0; k < ZC_NUM_JS_OUTPUTS; k++)
                incremental_tree_append(
                    &tree, &tx->v_joinsplit[j].commitments[k]);
    }
    if (!anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &tree, height))
        LOG_RETURN(false, ANCHOR_STAGE_SUBSYS,
                   "[utxo_apply] Sprout frontier persist failed h=%d",
                   height);
    /* Feed the batch-commit append-only invariant (b) (no-op unless batched). */
    reducer_commit_invariants_note_anchor(height, ANCHOR_POOL_SPROUT);
    return !full_replay ||
        shielded_history_full_replay_mark_pool_started_in_tx(
            db, ANCHOR_POOL_SPROUT, height);
}

static bool fold_sapling(sqlite3 *db, const struct block *blk, int height,
                         struct delta_summary *summary, bool full_replay)
{
    if (!block_has_sapling_commitments(blk))
        return true;
    struct incremental_merkle_tree tree;
    enum anchor_kv_lookup_result lr = latest_tree_for_fold(
        db, ANCHOR_POOL_SAPLING, height, full_replay, &tree);
    if (lr == ANCHOR_KV_ERROR)
        return false;
    if (lr != ANCHOR_KV_FOUND) {
        anchor_reject(summary, first_anchor_tx(blk, ANCHOR_POOL_SAPLING),
                      "shielded_anchor_history_gap",
                      "sapling-anchor-frontier-unavailable");
        return true;
    }
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        for (size_t j = 0; j < tx->num_shielded_output; j++)
            incremental_tree_append(&tree, &tx->v_shielded_output[j].cm);
    }

    const struct chain_params *params = chain_params_get();
    bool sapling_active = params && consensus_network_upgrade_active(
        &params->consensus, height, UPGRADE_SAPLING);
    if (sapling_active) {
        struct uint256 root;
        incremental_tree_root(&tree, &root);
        if (!uint256_eq(&root, &blk->header.hashFinalSaplingRoot)) {
            /* This is not labelled a peer-invalid verdict until immutable
             * history replay proves the newly-threaded frontier.  It is still
             * fail closed: no anchor/coin/cursor write survives and H* holds. */
            anchor_reject(summary,
                          first_anchor_tx(blk, ANCHOR_POOL_SAPLING),
                          "sapling_frontier_mismatch",
                          "sapling-anchor-frontier-mismatch");
            return true;
        }
    }
    if (!anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &tree, height))
        LOG_RETURN(false, ANCHOR_STAGE_SUBSYS,
                   "[utxo_apply] Sapling frontier persist failed h=%d",
                   height);
    /* Feed the batch-commit append-only invariant (b) (no-op unless batched). */
    reducer_commit_invariants_note_anchor(height, ANCHOR_POOL_SAPLING);
    return !full_replay ||
        shielded_history_full_replay_mark_pool_started_in_tx(
            db, ANCHOR_POOL_SAPLING, height);
}

static bool check_and_insert_anchors(sqlite3 *db, const struct block *blk,
                                     int height,
                                     struct delta_summary *summary,
                                     bool full_replay)
{
    if (!db || !blk || !summary || height < 0) {
        LOG_WARN(ANCHOR_STAGE_SUBSYS,
                 "[utxo_apply] anchor check invalid args h=%d", height);
        return false;
    }

    struct anchor_lookup_view av = {
        .view = { .vtable = &g_anchor_lookup_vtable, .impl = NULL },
        .db = db,
    };
    av.view.impl = &av;
    struct coins_view_cache cache;
    coins_view_cache_init(&cache, &av.view);

    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        enum coins_shielded_requirements_result rr =
            coins_view_cache_check_shielded_requirements(&cache, tx);
        if (rr == COINS_SHIELDED_REQUIREMENTS_STORE_ERROR) {
            coins_view_cache_free(&cache);
            return false;
        }
        if (rr == COINS_SHIELDED_REQUIREMENTS_HISTORY_INCOMPLETE) {
            anchor_reject(summary, tx, "shielded_anchor_history_gap",
                          "anchor-membership-history-incomplete");
            coins_view_cache_free(&cache);
            return true;
        }
        if (rr == COINS_SHIELDED_REQUIREMENTS_MISSING_ANCHOR) {
            anchor_reject(summary, tx, "shielded_anchor_missing",
                          "anchor-membership-not-found");
            coins_view_cache_free(&cache);
            return true;
        }
    }
    coins_view_cache_free(&cache);

    /* PushAnchor happens only after EVERY transaction was checked, exactly as
     * zclassicd ConnectBlock: roots made by an earlier tx in this block cannot
     * satisfy a later tx (only same-tx Sprout intermediates can). */
    if (!fold_sprout(db, blk, height, summary, full_replay) || !summary->ok)
        return summary->ok ? false : true;
    if (!fold_sapling(db, blk, height, summary, full_replay) || !summary->ok)
        return summary->ok ? false : true;
    return true;
}

bool utxo_apply_check_and_insert_anchors(sqlite3 *db,
                                         const struct block *blk,
                                         int height,
                                         struct delta_summary *summary)
{
    return check_and_insert_anchors(db, blk, height, summary, false);
}

bool utxo_apply_check_and_insert_anchors_full_replay(
    sqlite3 *db, const struct block *blk, int height,
    struct delta_summary *summary)
{
    return check_and_insert_anchors(db, blk, height, summary, true);
}

bool utxo_apply_anchor_bind_mismatch(sqlite3 *db, struct node_db *ndb,
                                     int64_t *frontier_h_out,
                                     int32_t *coins_h_out)
{
    if (frontier_h_out) *frontier_h_out = -1;
    if (coins_h_out) *coins_h_out = -1;
    if (!db || !ndb)
        return false;  /* no evidence channel — pure detection stays off */

    /* Only a COMPLETE-history claim (both cursors present and 0) can be
     * height-mismatched; a positive cursor is the safe wedge the backfill
     * blocker already names. */
    for (int pool = ANCHOR_POOL_SPROUT; pool <= ANCHOR_POOL_SAPLING; pool++) {
        int64_t cur = -1;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, pool, &cur, &found))
            LOG_RETURN(false, ANCHOR_STAGE_SUBSYS,
                       "[utxo_apply] bind guard: cursor read failed pool=%d",
                       pool);
        if (!found || cur != 0)
            return false;
    }

    int32_t coins_h = -1;
    uint8_t cb_hash[32];
    bool cb_hash_found = false, cb_found = false;
    if (!reducer_frontier_derive_coins_best(db, &coins_h, cb_hash,
                                            &cb_hash_found, &cb_found))
        LOG_RETURN(false, ANCHOR_STAGE_SUBSYS,
                   "[utxo_apply] bind guard: coins-best derive failed");
    if (!cb_found || coins_h < 0)
        return false;  /* no coins authority — nothing to mismatch against */

    struct incremental_merkle_tree tree;
    struct uint256 frontier_root;
    int64_t frontier_h = -1;
    enum anchor_kv_lookup_result lr = anchor_kv_latest_tree(
        db, ANCHOR_POOL_SAPLING, &tree, &frontier_root, &frontier_h);
    if (lr == ANCHOR_KV_ERROR)
        LOG_RETURN(false, ANCHOR_STAGE_SUBSYS,
                   "[utxo_apply] bind guard: latest Sapling frontier read "
                   "failed");
    if (lr != ANCHOR_KV_FOUND)
        return false;  /* the incomplete cases are owned by positive cursors */
    if (frontier_h >= (int64_t)coins_h)
        return false;  /* frontier at/past the resume anchor — consistent */

    /* The frontier the fold would append to predates the resume anchor. That
     * is consistent ONLY when no Sapling-output block sits in
     * (frontier_h, coins_h] — i.e. the header-committed root did not move
     * (roots change only on commitment blocks). Compare against the header
     * chain's persisted hashFinalSaplingRoot at the island root. */
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    if (!db_block_find_by_height(ndb, (int)coins_h, &blk))
        return false;  // raw-return-ok:bind-guard detection — no header evidence at the island root; the fold's own fail-closed root check stays the backstop
    static const uint8_t k_zero_root[32] = {0};
    if (memcmp(blk.sapling_root, k_zero_root, 32) == 0)
        return false;  /* pre-Sapling / old header import — no evidence */
    if (memcmp(frontier_root.data, blk.sapling_root, 32) == 0)
        return false;  /* commitment-free tail — the frontier is still valid */

    if (frontier_h_out) *frontier_h_out = frontier_h;
    if (coins_h_out) *coins_h_out = coins_h;
    return true;
}

void utxo_apply_anchor_gap_blocker_refresh_with_ndb(struct sqlite3 *db,
                                                    struct node_db *ndb)
{
    if (!db) {
        LOG_WARN(ANCHOR_STAGE_SUBSYS,
                 "[utxo_apply] anchor gap blocker refresh: NULL db");
        return;
    }
    int64_t max_activation = 0;
    bool incomplete = false;
    for (int pool = ANCHOR_POOL_SPROUT; pool <= ANCHOR_POOL_SAPLING; pool++) {
        int64_t activation = 0;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, pool, &activation, &found)) {
            incomplete = true;
            continue;
        }
        if (!found || activation > 0) {
            incomplete = true;
            if (activation > max_activation)
                max_activation = activation;
        }
    }
    if (!incomplete) {
        /* The cursors claim complete history. Before clearing, run the bind
         * guard: a height-mismatched -import-complete-shielded bind (frontier
         * keyed below the coins island root, cursors flipped to 0) must KEEP
         * the named permanent blocker — folding into it livelocks at the
         * first Sapling-commitment block above the island. Detection only,
         * no auto-repair. */
        int64_t frontier_h = -1;
        int32_t coins_h = -1;
        if (utxo_apply_anchor_bind_mismatch(db, ndb, &frontier_h, &coins_h)) {
            struct blocker_record rec;
            char reason[BLOCKER_REASON_MAX];
            snprintf(reason, sizeof(reason),
                     "shielded anchor height mismatch: frontier=%lld, coins "
                     "island=%d, activation cursors claim complete; rerun "
                     "-import-complete-shielded with a source whose best "
                     "block equals the island root; no auto-repair",
                     (long long)frontier_h, coins_h);
            if (!blocker_init(&rec, UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID,
                              ANCHOR_STAGE_SUBSYS, BLOCKER_PERMANENT, reason))
                return;
            blocker_set(&rec);
            LOG_WARN(ANCHOR_STAGE_SUBSYS,
                     "[utxo_apply] bind guard: %s", reason);
            return;
        }
        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        return;
    }

    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "shielded anchor history incomplete below cursor %lld; unknown "
             "roots hold H*. Condition %.48s seeds an empty frontier or starts "
             "bounded refold; historical gaps require owner backfill",
             (long long)max_activation,
             SAPLING_ANCHOR_FRONTIER_CONDITION_NAME);
    if (!blocker_init(&rec, UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID,
                      ANCHOR_STAGE_SUBSYS, BLOCKER_PERMANENT, reason))
        return;
    blocker_set(&rec);
}

void utxo_apply_anchor_gap_blocker_refresh(sqlite3 *db)
{
    utxo_apply_anchor_gap_blocker_refresh_with_ndb(db, app_runtime_node_db());
}
