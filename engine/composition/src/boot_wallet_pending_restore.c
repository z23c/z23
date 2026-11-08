/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Restore an authenticated pending-cutover view without persistent writes. */
#include "config/boot_wallet_pending_restore.h"

#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/chain_state_service.h"
#include "services/island_anchor.h"
#include "services/block_index_loader.h"
#include "storage/anchor_kv.h"
#include "storage/node_db_runtime.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "wallet/wallet_sqlite.h"
#include <string.h>

static bool bpr_bound(const struct main_state *ms, const struct chain_state_repository *csr)
{
    return ms && csr && csr->initialized && csr->block_map == &ms->map_block_index &&
        csr->chain_active == &ms->chain_active && csr->pindex_best_hdr == &ms->pindex_best_header &&
        csr->coins_tip;
}

static bool bpr_header(const struct block_index *p, struct block_header *out)
{
    if (!node_db_runtime_load_header_by_hash_height(p->nHeight, p->phashBlock->data, out))
        return false;
    struct uint256 hash;
    block_header_get_hash(out, &hash);
    return uint256_eq(&hash, p->phashBlock) && out->nVersion == p->nVersion &&
        out->nTime == p->nTime && out->nBits == p->nBits &&
        uint256_eq(&out->hashFinalSaplingRoot, &p->hashFinalSaplingRoot);
}

static bool bpr_entry_valid(struct main_state *ms, struct block_index *p,
    int32_t installed_height, const struct uint256 *installed_hash, bool *target_seen)
{
    if (!p->phashBlock || p->nHeight < 0 ||
        block_map_find(&ms->map_block_index, p->phashBlock) != p) return false;
    if (p->nHeight == installed_height) {
        if (!uint256_eq(p->phashBlock, installed_hash)) return false;
        *target_seen = true;
    }
    return true;
}

static bool bpr_genesis_valid(const struct block_index *p, const struct chain_params *params,
                              bool target_seen)
{
    return target_seen && !p->pprev && uint256_eq(p->phashBlock, &params->consensus.hashGenesisBlock);
}

static enum boot_pending_restore_result bpr_ancestry(struct main_state *ms,
    struct block_index *tip, struct block_header *tip_header,
    int32_t installed_height, const struct uint256 *installed_hash)
{
    const struct chain_params *params = chain_params_get();
    if (!params) return BOOT_PENDING_RESTORE_INVALID_CONTEXT;
    bool target_seen = false;
    for (struct block_index *p = tip; p; p = p->pprev) {
        if (!bpr_entry_valid(ms, p, installed_height, installed_hash, &target_seen))
            return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
        if (p->nHeight == 0)
            return bpr_genesis_valid(p, params, target_seen)
                ? BOOT_PENDING_RESTORE_OK : BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
        struct block_header header;
        if (!bpr_header(p, &header)) return BOOT_PENDING_RESTORE_HEADER_UNAVAILABLE;
        if (p == tip) *tip_header = header;
        if (!p->pprev)
            return target_seen && island_anchor_is_root(p) ? BOOT_PENDING_RESTORE_OK : BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
        if (!p->pprev->phashBlock || p->pprev->nHeight != p->nHeight - 1 ||
            !uint256_eq(&header.hashPrevBlock, p->pprev->phashBlock))
            return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
    }
    return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
}

static bool bpr_tree(int32_t height, struct incremental_merkle_tree *tree)
{
    int64_t anchor_height = -1;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    enum anchor_kv_lookup_result found = db ?
        anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, tree, NULL, &anchor_height) : ANCHOR_KV_ERROR;
    progress_store_tx_unlock();
    return found == ANCHOR_KV_FOUND && anchor_height >= 0 && anchor_height <= height;
}

/* The old chain and the separately verified target window remain distinct. */
static bool bpr_old_ancestry(struct main_state *ms, struct block_index *tip,
                             struct block_header *tip_header)
{
    const struct chain_params *params = chain_params_get();
    if (!params) return false;
    for (struct block_index *p = tip; p; p = p->pprev) {
        if (!p->phashBlock || p->nHeight < 0 ||
            block_map_find(&ms->map_block_index, p->phashBlock) != p) return false;
        if (p->nHeight == 0)
            return !p->pprev && uint256_eq(p->phashBlock, &params->consensus.hashGenesisBlock);
        struct block_header header;
        if (!bpr_header(p, &header) || !p->pprev || !p->pprev->phashBlock ||
            p->pprev->nHeight != p->nHeight - 1 ||
            !uint256_eq(&header.hashPrevBlock, p->pprev->phashBlock)) return false;
        if (p == tip) *tip_header = header;
    }
    return false;
}

static bool bpr_old_tree(int32_t height, const struct block_header *header,
                         struct incremental_merkle_tree *tree)
{
    const struct chain_params *params = chain_params_get();
    if (!params) return false;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    int64_t anchor_height = -1;
    enum anchor_kv_lookup_result found = db ?
        anchor_kv_tree_at_or_below(db, ANCHOR_POOL_SAPLING, height, tree, NULL, &anchor_height) :
        ANCHOR_KV_ERROR;
    progress_store_tx_unlock();
    if (found != ANCHOR_KV_FOUND) return false;
    if (!consensus_network_upgrade_active(&params->consensus, height, UPGRADE_SAPLING))
        return incremental_tree_size(tree) == 0;
    struct uint256 root;
    incremental_tree_root(tree, &root);
    return anchor_height >= 0 && anchor_height <= height &&
        !uint256_is_null(&header->hashFinalSaplingRoot) &&
        uint256_eq(&root, &header->hashFinalSaplingRoot);
}

static bool bpr_old_partial_island(const struct wallet_cutover_binding *binding,
                                   struct island_anchor *island, bool *seeded)
{
    enum island_anchor_state state = island_anchor_state_load(progress_store_db());
    *seeded = state == ISLAND_ANCHOR_STATE_SEEDED;
    if (!*seeded) return state == ISLAND_ANCHOR_STATE_NONE && !island_anchor_registered();
    return island_anchor_get(island) && island->rung_height == binding->target_height &&
        memcmp(island->rung_hash.data, binding->target_hash, 32) == 0;
}

static bool bpr_old_genesis_authority(const struct wallet_cutover_binding *binding,
                                       const struct chain_params *params,
                                       struct island_anchor *island)
{
    return binding && params && binding->old_height == 0 &&
        memcmp(binding->old_hash, params->consensus.hashGenesisBlock.data, 32) == 0 &&
        island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_SEEDED &&
        island_anchor_get(island) && island->rung_height == binding->target_height &&
        memcmp(island->rung_hash.data, binding->target_hash, 32) == 0 &&
        island_anchor_genesis_fold_proven(progress_store_db()).ok;
}

enum boot_pending_restore_result boot_wallet_old_partial_restore(
    struct main_state *ms, struct chain_state_repository *csr,
    const struct wallet_cutover_binding *binding)
{
    if (!bpr_bound(ms, csr) || !binding || binding->old_height <= 0)
        return BOOT_PENDING_RESTORE_INVALID_CONTEXT;
    struct island_anchor island;
    bool seeded;
    if (!bpr_old_partial_island(binding, &island, &seeded))
        return BOOT_PENDING_RESTORE_INVALID_CONTEXT;
    struct uint256 hash;
    memcpy(hash.data, binding->old_hash, 32);
    struct block_index *tip = block_map_find(&ms->map_block_index, &hash);
    struct block_index *rung = seeded ? block_map_find(&ms->map_block_index, &island.rung_hash) : tip;
    struct block_header header;
    if (!tip || tip->nHeight != binding->old_height || !rung ||
        (seeded && rung->nHeight != island.rung_height) || !bpr_old_ancestry(ms, tip, &header))
        return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    if (!bpr_old_tree(binding->old_height, &header, &tree))
        return BOOT_PENDING_RESTORE_TREE_UNAVAILABLE;
    if (!csr_restore_in_memory_view(csr, tip, rung, &hash))
        return BOOT_PENDING_RESTORE_CSR_REFUSED;
    ms->sapling_tree = tree;
    ms->sapling_tree_loaded = true;
    return BOOT_PENDING_RESTORE_OK;
}

enum boot_pending_restore_result boot_wallet_old_genesis_restore(
    struct main_state *ms, struct chain_state_repository *csr,
    const struct wallet_cutover_binding *binding)
{
    const struct chain_params *params = chain_params_get();
    struct island_anchor island;
    if (!bpr_bound(ms, csr) || !bpr_old_genesis_authority(binding, params, &island))
        return BOOT_PENDING_RESTORE_INVALID_CONTEXT;
    struct block_index *genesis = block_map_find(&ms->map_block_index,
        &params->consensus.hashGenesisBlock);
    if (!block_index_initialize_genesis(genesis, params))
        return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
    struct block_index *rung = block_map_find(&ms->map_block_index, &island.rung_hash);
    if (!rung || rung->nHeight != island.rung_height)
        return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
    if (!csr_restore_in_memory_view(csr, genesis, rung, &params->consensus.hashGenesisBlock))
        return BOOT_PENDING_RESTORE_CSR_REFUSED;
    sapling_tree_init(&ms->sapling_tree);
    ms->sapling_tree_loaded = true;
    return BOOT_PENDING_RESTORE_OK;
}

enum boot_pending_restore_result boot_wallet_pending_restore(
    struct main_state *ms, struct chain_state_repository *csr,
    int32_t coins_height, const struct uint256 *coins_hash,
    int32_t installed_height, const struct uint256 *installed_hash)
{
    if (!bpr_bound(ms, csr) || !coins_hash || !installed_hash || coins_height <= 0 ||
        installed_height < 0 || installed_height > coins_height)
        return BOOT_PENDING_RESTORE_INVALID_CONTEXT;
    struct block_index *tip = block_map_find(&ms->map_block_index, coins_hash);
    if (!tip || tip->nHeight != coins_height) return BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
    struct block_header header;
    enum boot_pending_restore_result result = bpr_ancestry(ms, tip, &header, installed_height, installed_hash);
    if (result != BOOT_PENDING_RESTORE_OK) return result;
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    if (!bpr_tree(coins_height, &tree)) return BOOT_PENDING_RESTORE_TREE_UNAVAILABLE;
    struct uint256 root;
    incremental_tree_root(&tree, &root);
    if (uint256_is_null(&header.hashFinalSaplingRoot) ||
        !uint256_eq(&root, &header.hashFinalSaplingRoot)) return BOOT_PENDING_RESTORE_TREE_MISMATCH;
    if (!csr_restore_in_memory_view(csr, tip, tip, coins_hash)) return BOOT_PENDING_RESTORE_CSR_REFUSED;
    ms->sapling_tree = tree;
    ms->sapling_tree_loaded = true;
    return BOOT_PENDING_RESTORE_OK;
}
