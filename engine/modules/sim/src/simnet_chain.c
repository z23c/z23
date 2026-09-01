/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Retained per-node simnet chain store.
 *
 * This layer keeps accepted blocks, their undo data, and stable block_index
 * records so a simulated node can reorg through the same disconnect_block /
 * connect_block paths as the live validator.
 */

#define ZCL_SIMNET_CLUSTER_INTERNAL
#include "sim/simnet_cluster.h"

#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/connect_block.h"
#include "validation/contextual_check_tx.h"
#include "validation/update_coins.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define SIM_CHAIN_BASE_HEIGHT 100
#define SIM_CHAIN_CHECKPOINT_HEIGHT 1000000
#define SIM_CHAIN_COINBASE_VALUE 1000000

struct simnet_block_entry {
    struct block block;
    struct block_undo undo;
    struct block_index index;
    struct uint256 hash;
    struct uint256 parent_hash;
    struct simnet_block_entry *parent;
    uint64_t first_seen;
    bool active;
};

struct simnet_height_bucket {
    struct simnet_block_entry **entries;
    size_t count;
    size_t cap;
};

struct simnet_chain {
    struct coins_view_cache view;
    struct coins_view null_view;
    struct chain_params params;
    struct checkpoint_entry cpentry;
    struct block_index base_index;
    struct simnet_block_entry *active_tip;
    struct simnet_height_bucket *heights;
    size_t height_count;
    uint64_t node_tag;
    uint64_t mint_seq;
};

static void simnet_chain_free_entry(struct simnet_block_entry *entry)
{
    if (!entry)
        return;
    block_free(&entry->block);
    block_undo_free(&entry->undo);
    free(entry);
}

static void simnet_chain_free_buckets(struct simnet_chain *chain)
{
    if (!chain || !chain->heights)
        return;
    for (size_t h = 0; h < chain->height_count; h++) {
        struct simnet_height_bucket *bucket = &chain->heights[h];
        for (size_t i = 0; i < bucket->count; i++)
            simnet_chain_free_entry(bucket->entries[i]);
        free(bucket->entries);
    }
    free(chain->heights);
    chain->heights = NULL;
    chain->height_count = 0;
}

static bool simnet_chain_hash_is_base(const struct simnet_chain *chain,
                                      const struct uint256 *hash)
{
    return chain && hash && uint256_eq(hash, &chain->base_index.hashBlock);
}

static struct simnet_block_entry *simnet_chain_find_entry(
    const struct simnet_chain *chain, const struct uint256 *hash)
{
    if (!chain || !hash)
        return NULL;
    for (size_t h = 0; h < chain->height_count; h++) {
        const struct simnet_height_bucket *bucket = &chain->heights[h];
        for (size_t i = 0; i < bucket->count; i++) {
            if (uint256_eq(&bucket->entries[i]->hash, hash))
                return bucket->entries[i];
        }
    }
    return NULL;
}

static int simnet_chain_entry_height(const struct simnet_block_entry *entry)
{
    return entry ? entry->index.nHeight : SIM_CHAIN_BASE_HEIGHT - 1;
}

static bool simnet_chain_ensure_height(struct simnet_chain *chain, int height)
{
    if (!chain)
        LOG_FAIL("simnet.chain", "NULL chain");
    if (height < SIM_CHAIN_BASE_HEIGHT)
        LOG_FAIL("simnet.chain", "height %d below base", height);

    size_t slot = (size_t)(height - SIM_CHAIN_BASE_HEIGHT);
    if (slot < chain->height_count)
        return true;

    size_t want = slot + 1;
    size_t new_count = chain->height_count ? chain->height_count : 8;
    while (new_count < want)
        new_count *= 2;

    struct simnet_height_bucket *grown =
        zcl_realloc(chain->heights, new_count * sizeof(*grown),
                    "simnet_chain_heights");
    if (!grown)
        LOG_FAIL("simnet.chain", "OOM growing height buckets to %zu",
                 new_count);
    for (size_t i = chain->height_count; i < new_count; i++)
        memset(&grown[i], 0, sizeof(grown[i]));
    chain->heights = grown;
    chain->height_count = new_count;
    return true;
}

static bool simnet_chain_bucket_add(struct simnet_chain *chain,
                                    struct simnet_block_entry *entry)
{
    if (!chain || !entry)
        LOG_FAIL("simnet.chain", "invalid bucket add");
    if (!simnet_chain_ensure_height(chain, entry->index.nHeight))
        return false;

    size_t slot = (size_t)(entry->index.nHeight - SIM_CHAIN_BASE_HEIGHT);
    struct simnet_height_bucket *bucket = &chain->heights[slot];
    if (bucket->count == bucket->cap) {
        size_t new_cap = bucket->cap ? bucket->cap * 2 : 2;
        struct simnet_block_entry **grown =
            zcl_realloc(bucket->entries, new_cap * sizeof(*grown),
                        "simnet_chain_height_entries");
        if (!grown)
            LOG_FAIL("simnet.chain", "OOM growing height %d entries",
                     entry->index.nHeight);
        bucket->entries = grown;
        bucket->cap = new_cap;
    }
    bucket->entries[bucket->count++] = entry;
    return true;
}

static bool simnet_chain_copy_path(struct simnet_block_entry *tip,
                                   struct simnet_block_entry ***out_path,
                                   size_t *out_count)
{
    if (!out_path || !out_count)
        LOG_FAIL("simnet.chain", "invalid path output");
    *out_path = NULL;
    *out_count = 0;

    size_t count = 0;
    for (struct simnet_block_entry *e = tip; e; e = e->parent)
        count++;
    if (count == 0)
        return true;

    struct simnet_block_entry **path =
        zcl_calloc(count, sizeof(*path), "simnet_chain_path");
    if (!path)
        LOG_FAIL("simnet.chain", "OOM allocating path depth=%zu", count);

    size_t i = count;
    for (struct simnet_block_entry *e = tip; e; e = e->parent)
        path[--i] = e;

    *out_path = path;
    *out_count = count;
    return true;
}

static bool simnet_chain_connect_existing(struct simnet_chain *chain,
                                          struct simnet_block_entry *entry,
                                          struct coins_view_cache *view)
{
    if (!chain || !entry || !view)
        LOG_FAIL("simnet.chain", "invalid connect_existing");

    struct validation_state vs;
    validation_state_init(&vs);
    if (!connect_block(&entry->block, &vs, &entry->index, view,
                       &chain->params, false)) {
        LOG_FAIL("simnet.chain", "connect_block rejected retained h=%d: %s",
                 entry->index.nHeight, vs.reject_reason);
    }
    return true;
}

static bool simnet_chain_replay_to(struct simnet_chain *chain,
                                   struct simnet_block_entry *tip,
                                   struct coins_view *null_view,
                                   struct coins_view_cache *view)
{
    if (!chain || !null_view || !view)
        LOG_FAIL("simnet.chain", "invalid replay request");

    memset(null_view, 0, sizeof(*null_view));
    coins_view_cache_init(view, null_view);
    coins_view_cache_set_best_block(view, &chain->base_index.hashBlock);

    struct simnet_block_entry **path = NULL;
    size_t count = 0;
    if (!simnet_chain_copy_path(tip, &path, &count)) {
        coins_view_cache_free(view);
        return false;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++)
        ok = simnet_chain_connect_existing(chain, path[i], view);
    free(path);
    if (!ok) {
        coins_view_cache_free(view);
        return false;
    }
    return true;
}

static bool simnet_chain_capture_undo(const struct block *block,
                                      int height,
                                      struct coins_view_cache *parent_view,
                                      struct block_undo *out_undo)
{
    if (!block || !parent_view || !out_undo || block->num_vtx == 0)
        LOG_FAIL("simnet.chain", "invalid undo capture");

    block_undo_init(out_undo);
    if (block->num_vtx > 1 && !block_undo_alloc(out_undo,
                                                block->num_vtx - 1)) {
        LOG_FAIL("simnet.chain", "OOM allocating undo txs=%zu",
                 block->num_vtx - 1);
    }

    struct coins_view parent_as_view;
    coins_view_cache_as_view(&parent_as_view, parent_view);
    struct coins_view_cache scratch;
    coins_view_cache_init(&scratch, &parent_as_view);

    update_coins(&block->vtx[0], &scratch, height);
    for (size_t i = 1; i < block->num_vtx; i++) {
        if (!update_coins_with_undo(&block->vtx[i], &scratch,
                                    &out_undo->vtxundo[i - 1], height)) {
            coins_view_cache_free(&scratch);
            block_undo_free(out_undo);
            LOG_FAIL("simnet.chain", "undo capture failed h=%d tx=%zu",
                     height, i);
        }
    }

    coins_view_cache_free(&scratch);
    return true;
}

static void simnet_chain_fill_index(struct block_index *idx,
                                    const struct block *block,
                                    const struct uint256 *hash,
                                    struct block_index *parent,
                                    int height,
                                    uint64_t first_seen)
{
    block_index_init(idx);
    idx->hashBlock = *hash;
    idx->phashBlock = &idx->hashBlock;
    idx->pprev = parent;
    idx->hashMerkleRoot = block->header.hashMerkleRoot;
    idx->hashFinalSaplingRoot = block->header.hashFinalSaplingRoot;
    idx->nNonce = block->header.nNonce;
    idx->nHeight = height;
    idx->nVersion = block->header.nVersion;
    idx->nTime = block->header.nTime;
    idx->nBits = block->header.nBits;
    idx->nSequenceId = (uint32_t)first_seen;
    idx->nTx = (unsigned int)block->num_vtx;
    idx->nChainTx = parent ? parent->nChainTx + idx->nTx : idx->nTx;
    idx->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
    idx->has_chain_sprout_value = false;
    idx->has_chain_sapling_value = false;
    if (parent) {
        struct arith_uint256 one;
        arith_uint256_set_u64(&one, 1);
        arith_uint256_add(&idx->nChainWork, &parent->nChainWork, &one);
    } else {
        arith_uint256_set_u64(&idx->nChainWork, (uint64_t)height + 1);
    }
}

static struct simnet_block_entry *simnet_chain_store_entry(
    struct simnet_chain *chain, const struct block *block,
    const struct uint256 *hash, const struct uint256 *parent_hash,
    struct simnet_block_entry *parent, const struct block_index *idx,
    struct block_undo *undo, uint64_t first_seen)
{
    struct simnet_block_entry *entry =
        zcl_calloc(1, sizeof(*entry), "simnet_chain_entry");
    if (!entry) {
        block_undo_free(undo);
        LOG_NULL("simnet.chain", "OOM allocating retained entry");
    }

    block_init(&entry->block);
    if (!block_clone(&entry->block, block)) {
        block_undo_free(undo);
        free(entry);
        LOG_NULL("simnet.chain", "block clone failed h=%d", idx->nHeight);
    }

    entry->undo = *undo;
    block_undo_init(undo);
    entry->index = *idx;
    entry->index.phashBlock = &entry->index.hashBlock;
    entry->hash = *hash;
    entry->parent_hash = *parent_hash;
    entry->parent = parent;
    entry->first_seen = first_seen;
    entry->active = false;

    if (!simnet_chain_bucket_add(chain, entry)) {
        simnet_chain_free_entry(entry);
        return NULL;
    }
    return entry;
}

static bool simnet_chain_entry_better(const struct simnet_chain *chain,
                                      const struct simnet_block_entry *entry,
                                      const struct simnet_block_entry *best)
{
    if (!chain || !entry)
        LOG_FAIL("simnet.chain", "invalid fork-choice comparison");
    if (!best)
        return arith_uint256_compare(&entry->index.nChainWork,
                                     &chain->base_index.nChainWork) > 0;

    int work_cmp = arith_uint256_compare(&entry->index.nChainWork,
                                         &best->index.nChainWork);
    if (work_cmp != 0)
        return work_cmp > 0;
    if (entry->first_seen != best->first_seen)
        return entry->first_seen < best->first_seen;
    return uint256_cmp(&entry->hash, &best->hash) < 0;
}

static struct simnet_block_entry *simnet_chain_find_fork(
    struct simnet_block_entry *a, struct simnet_block_entry *b)
{
    while (simnet_chain_entry_height(a) > simnet_chain_entry_height(b))
        a = a->parent;
    while (simnet_chain_entry_height(b) > simnet_chain_entry_height(a))
        b = b->parent;
    while (a != b) {
        a = a ? a->parent : NULL;
        b = b ? b->parent : NULL;
    }
    return a;
}

static bool simnet_chain_activate(struct simnet_chain *chain,
                                  struct simnet_block_entry *target)
{
    if (!chain || !target)
        LOG_FAIL("simnet.chain", "invalid activation target");
    if (chain->active_tip == target)
        return true;

    struct simnet_block_entry *fork =
        simnet_chain_find_fork(chain->active_tip, target);

    for (struct simnet_block_entry *e = chain->active_tip;
         e && e != fork; e = e->parent) {
        struct validation_state vs;
        validation_state_init(&vs);
        if (!disconnect_block(&e->block, &vs, &e->index, &chain->view,
                              &e->undo)) {
            LOG_FAIL("simnet.chain", "disconnect_block failed h=%d",
                     e->index.nHeight);
        }
        e->active = false;
    }

    size_t count = 0;
    for (struct simnet_block_entry *e = target; e && e != fork; e = e->parent)
        count++;

    struct simnet_block_entry **path = NULL;
    if (count > 0) {
        path = zcl_calloc(count, sizeof(*path), "simnet_chain_activate_path");
        if (!path)
            LOG_FAIL("simnet.chain", "OOM allocating activation path=%zu",
                     count);
        size_t i = count;
        for (struct simnet_block_entry *e = target; e && e != fork;
             e = e->parent)
            path[--i] = e;
    }

    for (size_t i = 0; i < count; i++) {
        if (!simnet_chain_connect_existing(chain, path[i], &chain->view)) {
            free(path);
            return false;
        }
        path[i]->active = true;
    }
    free(path);
    chain->active_tip = target;
    return true;
}

static struct transaction simnet_chain_make_coinbase(int height,
                                                     uint64_t node_tag,
                                                     uint64_t mint_seq)
{
    struct transaction tx;
    transaction_init(&tx);
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "simnet_cluster_cb_vin");
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "simnet_cluster_cb_vout");
    if (!tx.vin || !tx.vout) {
        transaction_free(&tx);
        return tx;
    }

    uint8_t sig[22];
    sig[0] = 4;
    sig[1] = (uint8_t)(height & 0xff);
    sig[2] = (uint8_t)((height >> 8) & 0xff);
    sig[3] = (uint8_t)((height >> 16) & 0xff);
    sig[4] = (uint8_t)((height >> 24) & 0xff);
    for (int i = 0; i < 8; i++)
        sig[5 + i] = (uint8_t)(node_tag >> (8 * i));
    for (int i = 0; i < 8; i++)
        sig[13 + i] = (uint8_t)(mint_seq >> (8 * i));
    sig[21] = 0x23;
    script_set(&tx.vin[0].script_sig, sig, sizeof(sig));
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xffffffffu;
    tx.vin[0].sequence = 0xffffffffu;

    tx.vout[0].value = SIM_CHAIN_COINBASE_VALUE;
    uint8_t pk[4] = {0x76, 0xa9, 0x14, (uint8_t)node_tag};
    script_set(&tx.vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(&tx);
    return tx;
}

static bool simnet_chain_make_block(struct simnet_chain *chain,
                                    struct block *block,
                                    int height)
{
    if (!chain || !block)
        LOG_FAIL("simnet.chain", "invalid block build");

    block_init(block);
    struct transaction cb =
        simnet_chain_make_coinbase(height, chain->node_tag,
                                   ++chain->mint_seq);
    if (!cb.vin || !cb.vout)
        LOG_FAIL("simnet.chain", "coinbase allocation failed");

    block->num_vtx = 1;
    block->vtx = zcl_calloc(1, sizeof(struct transaction),
                            "simnet_cluster_block_vtx");
    if (!block->vtx) {
        transaction_free(&cb);
        LOG_FAIL("simnet.chain", "OOM allocating block tx");
    }
    block->vtx[0] = cb;

    struct uint256 txid = cb.hash;
    block->header.nVersion = 4;
    block->header.hashPrevBlock = chain->active_tip ?
        chain->active_tip->hash : chain->base_index.hashBlock;
    block->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    block->header.nTime = (uint32_t)height;
    return true;
}

struct simnet_chain *simnet_chain_create(uint64_t node_tag)
{
    struct simnet_chain *chain =
        zcl_calloc(1, sizeof(*chain), "simnet_chain");
    if (!chain)
        LOG_NULL("simnet.chain", "OOM allocating chain");

    chain->node_tag = node_tag;
    chain->mint_seq = 0;

    atomic_store(&g_deferred_proof_validation_below_height, -1);

    chain->params = *chain_params_get();
    memset(&chain->cpentry, 0, sizeof(chain->cpentry));
    chain->cpentry.height = SIM_CHAIN_CHECKPOINT_HEIGHT;
    memset(chain->cpentry.hash.data, 0x01, sizeof(chain->cpentry.hash.data));
    chain->params.checkpointData.entries = &chain->cpentry;
    chain->params.checkpointData.nEntries = 1;

    block_index_init(&chain->base_index);
    chain->base_index.nHeight = SIM_CHAIN_BASE_HEIGHT - 1;
    memset(chain->base_index.hashBlock.data, 0x33,
           sizeof(chain->base_index.hashBlock.data));
    chain->base_index.phashBlock = &chain->base_index.hashBlock;
    chain->base_index.has_chain_sprout_value = false;
    chain->base_index.has_chain_sapling_value = false;
    arith_uint256_set_u64(&chain->base_index.nChainWork,
                          (uint64_t)SIM_CHAIN_BASE_HEIGHT);

    memset(&chain->null_view, 0, sizeof(chain->null_view));
    coins_view_cache_init(&chain->view, &chain->null_view);
    coins_view_cache_set_best_block(&chain->view,
                                    &chain->base_index.hashBlock);

    return chain;
}

void simnet_chain_free(struct simnet_chain *chain)
{
    if (!chain)
        return;
    simnet_chain_free_buckets(chain);
    coins_view_cache_free(&chain->view);
    free(chain);
}

bool simnet_chain_mint(struct simnet_chain *chain, uint64_t first_seen,
                       struct uint256 *out_block_hash)
{
    if (!chain)
        LOG_FAIL("simnet.chain", "NULL chain mint");

    int height = simnet_chain_entry_height(chain->active_tip) + 1;
    struct block block;
    if (!simnet_chain_make_block(chain, &block, height))
        return false;

    struct uint256 hash;
    block_header_get_hash(&block.header, &hash);
    bool ok = simnet_chain_accept_block(chain, &block, first_seen);
    block_free(&block);
    if (!ok)
        LOG_FAIL("simnet.chain", "minted block rejected h=%d", height);
    if (out_block_hash)
        *out_block_hash = hash;
    return true;
}

static struct simnet_block_entry *connect_retained(
    struct simnet_chain *chain, const struct block *block,
    struct simnet_block_entry *parent, struct block_index *parent_idx,
    uint64_t first_seen)
{
    if (!chain || !block || !parent_idx || block->num_vtx == 0)
        LOG_NULL("simnet.chain", "invalid connect_retained request");

    struct uint256 hash;
    block_header_get_hash(&block->header, &hash);

    int height = parent_idx->nHeight + 1;
    struct block_index idx;
    simnet_chain_fill_index(&idx, block, &hash, parent_idx, height,
                            first_seen);

    struct coins_view scratch_null;
    struct coins_view_cache scratch;
    if (!simnet_chain_replay_to(chain, parent, &scratch_null, &scratch))
        LOG_NULL("simnet.chain", "parent replay failed h=%d", height);

    struct block_undo undo;
    if (!simnet_chain_capture_undo(block, height, &scratch, &undo)) {
        coins_view_cache_free(&scratch);
        LOG_NULL("simnet.chain", "undo capture failed h=%d", height);
    }

    struct validation_state vs;
    validation_state_init(&vs);
    if (!connect_block(block, &vs, &idx, &scratch, &chain->params, false)) {
        block_undo_free(&undo);
        coins_view_cache_free(&scratch);
        LOG_NULL("simnet.chain", "connect_block rejected h=%d: %s",
                 height, vs.reject_reason);
    }
    coins_view_cache_free(&scratch);

    return simnet_chain_store_entry(chain, block, &hash,
                                    &block->header.hashPrevBlock, parent,
                                    &idx, &undo, first_seen);
}

bool simnet_chain_accept_block(struct simnet_chain *chain,
                               const struct block *block,
                               uint64_t first_seen)
{
    if (!chain || !block || block->num_vtx == 0)
        LOG_FAIL("simnet.chain", "invalid accept request");

    struct uint256 hash;
    block_header_get_hash(&block->header, &hash);
    if (simnet_chain_find_entry(chain, &hash))
        return true;

    struct simnet_block_entry *parent = NULL;
    struct block_index *parent_idx = NULL;
    if (simnet_chain_hash_is_base(chain, &block->header.hashPrevBlock)) {
        parent_idx = &chain->base_index;
    } else {
        parent = simnet_chain_find_entry(chain, &block->header.hashPrevBlock);
        if (!parent)
            LOG_FAIL("simnet.chain", "parent unknown for accepted block");
        parent_idx = &parent->index;
    }

    struct simnet_block_entry *entry =
        connect_retained(chain, block, parent, parent_idx, first_seen);
    if (!entry)
        LOG_FAIL("simnet.chain", "connect_retained failed");

    if (simnet_chain_entry_better(chain, entry, chain->active_tip)) {
        if (!simnet_chain_activate(chain, entry))
            return false;
    }

    return true;
}

bool simnet_chain_has_block(const struct simnet_chain *chain,
                            const struct uint256 *hash)
{
    if (!chain || !hash)
        return false;
    return simnet_chain_hash_is_base(chain, hash) ||
           simnet_chain_find_entry(chain, hash) != NULL;
}

bool simnet_chain_has_parent_for_block(const struct simnet_chain *chain,
                                       const struct block *block)
{
    if (!chain || !block)
        return false;
    return simnet_chain_has_block(chain, &block->header.hashPrevBlock);
}

const struct block *simnet_chain_block_by_hash(
    const struct simnet_chain *chain, const struct uint256 *hash)
{
    struct simnet_block_entry *entry = simnet_chain_find_entry(chain, hash);
    return entry ? &entry->block : NULL;
}

bool simnet_chain_block_first_seen(const struct simnet_chain *chain,
                                   const struct uint256 *hash,
                                   uint64_t *out_first_seen)
{
    if (!chain || !hash || !out_first_seen)
        LOG_FAIL("simnet.chain", "invalid first-seen lookup");
    struct simnet_block_entry *entry = simnet_chain_find_entry(chain, hash);
    if (!entry)
        LOG_FAIL("simnet.chain", "block first-seen missing");
    *out_first_seen = entry->first_seen;
    return true;
}

bool simnet_chain_tip_hash(const struct simnet_chain *chain,
                           struct uint256 *out)
{
    if (!chain || !out)
        LOG_FAIL("simnet.chain", "invalid tip hash request");
    *out = chain->active_tip ? chain->active_tip->hash :
        chain->base_index.hashBlock;
    return true;
}

bool simnet_chain_tip_height(const struct simnet_chain *chain,
                             int32_t *out_height)
{
    if (!chain || !out_height)
        LOG_FAIL("simnet.chain", "invalid tip height request");
    *out_height = (int32_t)simnet_chain_entry_height(chain->active_tip);
    return true;
}

bool simnet_chain_coins_digest(struct simnet_chain *chain,
                               struct utxo_commitment *out)
{
    if (!chain || !out)
        LOG_FAIL("simnet.chain", "invalid coins digest request");
    coins_view_cache_recompute_commitment(&chain->view, out);
    return true;
}
