/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* purpose: Bind mining templates to their parent's Sapling frontier. */
#include "controllers/mining_controller.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include <sqlite3.h>
#include <string.h>

static bool mining_sapling_has_outputs(const struct block *block)
{
    for (size_t i = 0; i < block->num_vtx; i++)
        if (block->vtx[i].num_shielded_output) return true;
    return false;
}

static bool mining_sapling_load_tree(struct incremental_merkle_tree *tree,
                                      const struct uint256 *parent_root, bool empty_parent)
{
    sapling_tree_init(tree);
    struct uint256 empty_root;
    incremental_tree_root(tree, &empty_root);
    if (empty_parent || uint256_eq(parent_root, &empty_root)) return true;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    bool found = db && anchor_kv_get(db, ANCHOR_POOL_SAPLING, parent_root,
                                     tree, NULL) == ANCHOR_KV_FOUND;
    progress_store_tx_unlock();
    return found;
}

static bool mining_sapling_append(struct incremental_merkle_tree *tree,
                                   const struct block *block)
{
    for (size_t i = 0; i < block->num_vtx; i++)
        for (size_t j = 0; j < block->vtx[i].num_shielded_output; j++) {
            if (!block->vtx[i].v_shielded_output || incremental_tree_is_complete(tree)) return false;
            incremental_tree_append(tree,
                                    &block->vtx[i].v_shielded_output[j].cm);
        }
    return true;
}

/* A legacy zero header root is usable only at the exact applied coins tip. */
static bool mining_sapling_legacy_root(const struct block *block, int height,
                                        struct uint256 *root)
{
    int32_t coins_height = -1;
    int64_t tree_height = -1;
    uint8_t hash[32];
    bool found = false, hash_found = false;
    struct incremental_merkle_tree tree;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    bool ok = db && reducer_frontier_derive_coins_best(db, &coins_height, hash,
        &hash_found, &found) && found && hash_found && coins_height == height - 1 &&
        memcmp(hash, block->header.hashPrevBlock.data, sizeof(hash)) == 0 &&
        tip_finalize_full_evidence_at(db, coins_height, &block->header.hashPrevBlock) == 1 &&
        anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &tree, root, &tree_height) == ANCHOR_KV_FOUND &&
        tree_height <= coins_height;
    progress_store_tx_unlock();
    return ok;
}

/* The parent root is captured under cs_main; tree lookup happens after unlock. */
bool mining_stamp_sapling_final_root(struct block *block, int height,
    const struct chain_params *cp, const struct uint256 *parent_root, bool genesis)
{
    if (!block || !cp || !parent_root || height < 1 || (block->num_vtx && !block->vtx)) return false;
    if (!consensus_network_upgrade_active(&cp->consensus, height, UPGRADE_SAPLING)) return true;
    bool empty_parent = genesis || !consensus_network_upgrade_active(
        &cp->consensus, height - 1, UPGRADE_SAPLING);
    struct uint256 recovered_root;
    if (!empty_parent && uint256_is_null(parent_root)) {
        if (!mining_sapling_legacy_root(block, height, &recovered_root)) return false;
        parent_root = &recovered_root;
    }
    if (!empty_parent && !mining_sapling_has_outputs(block)) {
        block->header.hashFinalSaplingRoot = *parent_root;
        return true;
    }
    struct incremental_merkle_tree tree;
    if (!mining_sapling_load_tree(&tree, parent_root, empty_parent) ||
        !mining_sapling_append(&tree, block)) return false;
    incremental_tree_root(&tree, &block->header.hashFinalSaplingRoot);
    return true;
}
