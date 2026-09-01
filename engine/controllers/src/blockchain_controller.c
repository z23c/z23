/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Blockchain controller — public surface, shared context, MMR/MMB
 * commitment globals, RPC command registration. The route handlers live
 * in the sibling files:
 *
 *   blockchain_controller_blocks.c       — block accessor RPCs
 *   blockchain_controller_chain.c        — chain info + commitments
 *   blockchain_controller_admin.c        — reindex / import
 *
 * See blockchain_controller_internal.h for cross-sibling declarations. */

#include "platform/time_compat.h"
#include "controllers/blockchain_controller.h"
#include "blockchain_controller_internal.h"
#include "chain/chain.h"
#include "chain/mmr.h"
#include "chain/mmb.h"
#include "core/uint256.h"
#include "json/json.h"
#include "models/database.h"
#include "primitives/block.h"
#include "storage/coins_kv.h"           /* boundary utxo_root read */
#include "storage/progress_store.h"     /* progress_store_db() handle */
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* ── Shared controller context ──────────────────────────── */

static struct blockchain_context g_blockchain_ctx = {0};

struct blockchain_context *blockchain_ctx(void)
{
    return &g_blockchain_ctx;
}

void rpc_blockchain_set_state(struct main_state *ms, struct tx_mempool *mp,
                               const char *datadir)
{
    g_blockchain_ctx.main_state = ms;
    g_blockchain_ctx.mempool = mp;
    if (datadir && datadir[0]) {
        (void)snprintf(g_blockchain_ctx.datadir_storage,
                       sizeof(g_blockchain_ctx.datadir_storage), "%s",
                       datadir);
        g_blockchain_ctx.datadir = g_blockchain_ctx.datadir_storage;
    } else {
        g_blockchain_ctx.datadir_storage[0] = '\0';
        g_blockchain_ctx.datadir = NULL;
    }
}

void rpc_blockchain_set_coins_db(struct coins_view_db *cvdb,
                                  struct coins_view_cache *coins_tip)
{
    g_blockchain_ctx.coins_db = cvdb;
    g_blockchain_ctx.coins_tip = coins_tip;
}

void rpc_blockchain_set_node_db(struct node_db *ndb)
{
    g_blockchain_ctx.node_db = ndb;
}

/* ── Global MMR ────────────────────────────────────────── */

static struct mmr g_mmr;
static bool g_mmr_initialized = false;
static pthread_mutex_t g_mmr_lock = PTHREAD_MUTEX_INITIALIZER;

void rpc_blockchain_mmr_append(const uint8_t block_hash[32])
{
    pthread_mutex_lock(&g_mmr_lock);
    if (!g_mmr_initialized) {
        mmr_init(&g_mmr);
        g_mmr_initialized = true;
    }
    mmr_append(&g_mmr, block_hash);
    pthread_mutex_unlock(&g_mmr_lock);
}

bool rpc_blockchain_mmr_snapshot(uint8_t root[32], uint64_t *num_leaves,
                                 uint32_t *num_peaks)
{
    pthread_mutex_lock(&g_mmr_lock);
    bool initialized = g_mmr_initialized;
    if (initialized) {
        if (root)
            mmr_root(&g_mmr, root);
        if (num_leaves)
            *num_leaves = g_mmr.num_leaves;
        if (num_peaks)
            *num_peaks = g_mmr.num_peaks;
    }
    pthread_mutex_unlock(&g_mmr_lock);
    return initialized;
}

void rpc_blockchain_mmr_init_from_state(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;

    uint8_t buf[MMR_SERIALIZED_MAX];
    size_t len = 0;
    struct mmr loaded;
    bool have_loaded = false;
    if (node_db_state_get(ndb, "mmr_state", buf, sizeof(buf), &len) &&
        len >= 12 && mmr_deserialize(&loaded, buf, len)) {
        have_loaded = true;
    }
    pthread_mutex_lock(&g_mmr_lock);
    if (have_loaded) {
        g_mmr = loaded;
        g_mmr_initialized = true;
    }
    if (!g_mmr_initialized) {
        mmr_init(&g_mmr);
        g_mmr_initialized = true;
    }
    pthread_mutex_unlock(&g_mmr_lock);
}

void rpc_blockchain_mmr_catchup(struct main_state *ms)
{
    if (!ms) return;
    pthread_mutex_lock(&g_mmr_lock);
    if (!g_mmr_initialized) {
        pthread_mutex_unlock(&g_mmr_lock);
        return;
    }
    int chain_height = active_chain_height(&ms->chain_active);
    int mmr_height = (int)g_mmr.num_leaves - 1;

    if (mmr_height >= chain_height) {
        pthread_mutex_unlock(&g_mmr_lock);
        return;
    }

    int start = mmr_height + 1;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    for (int h = start; h <= chain_height; h++) {
        const struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (bi && bi->phashBlock)
            mmr_append(&g_mmr, bi->phashBlock->data);
    }
    uint64_t leaves = g_mmr.num_leaves;
    pthread_mutex_unlock(&g_mmr_lock);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    printf("MMR catchup: %d → %d (%d blocks, %llds, %llu leaves)\n",
           start, chain_height, chain_height - start + 1, (long long)elapsed,
           (unsigned long long)leaves);
}

void rpc_blockchain_mmr_save(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;
    uint8_t buf[MMR_SERIALIZED_MAX];
    pthread_mutex_lock(&g_mmr_lock);
    if (!g_mmr_initialized) {
        pthread_mutex_unlock(&g_mmr_lock);
        return;
    }
    size_t len = mmr_serialize(&g_mmr, buf, sizeof(buf));
    pthread_mutex_unlock(&g_mmr_lock);
    if (len == 0) return;
    if (!node_db_state_set(ndb, "mmr_state", buf, len))
        LOG_WARN("blockchain", "MMR state save failed");
}

/* ── Global MMB (Merkle Mountain Belt) ────────────────── */

static struct mmb g_mmb;
static bool g_mmb_initialized = false;
static pthread_mutex_t g_mmb_lock = PTHREAD_MUTEX_INITIALIZER;

void rpc_blockchain_mmb_append(const struct mmb_leaf *leaf)
{
    pthread_mutex_lock(&g_mmb_lock);
    if (!g_mmb_initialized) {
        mmb_init(&g_mmb);
        g_mmb_initialized = true;
    }
    mmb_append(&g_mmb, leaf);
    pthread_mutex_unlock(&g_mmb_lock);
}

bool rpc_blockchain_mmb_snapshot(uint8_t root[32], uint64_t *num_leaves,
                                 uint32_t *num_mountains)
{
    pthread_mutex_lock(&g_mmb_lock);
    bool initialized = g_mmb_initialized;
    if (initialized) {
        if (root)
            mmb_root(&g_mmb, root);
        if (num_leaves)
            *num_leaves = g_mmb.num_leaves;
        if (num_mountains)
            *num_mountains = g_mmb.num_mountains;
    }
    pthread_mutex_unlock(&g_mmb_lock);
    return initialized;
}

void rpc_blockchain_mmb_init_from_state(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;

    uint8_t buf[MMB_SERIALIZED_MAX];
    size_t len = 0;
    struct mmb loaded;
    bool have_loaded = false;
    if (node_db_state_get(ndb, "mmb_state", buf, sizeof(buf), &len) &&
        len >= 13 && mmb_deserialize(&loaded, buf, len)) {
        have_loaded = true;
    }
    pthread_mutex_lock(&g_mmb_lock);
    if (have_loaded) {
        g_mmb = loaded;
        g_mmb_initialized = true;
    }
    if (!g_mmb_initialized) {
        mmb_init(&g_mmb);
        g_mmb_initialized = true;
    }
    printf("MMB: loaded %llu leaves, %u peaks\n",
           (unsigned long long)g_mmb.num_leaves, g_mmb.num_mountains);
    pthread_mutex_unlock(&g_mmb_lock);
}

void rpc_blockchain_mmb_catchup(struct main_state *ms)
{
    if (!ms) return;
    pthread_mutex_lock(&g_mmb_lock);
    if (!g_mmb_initialized) {
        pthread_mutex_unlock(&g_mmb_lock);
        return;
    }
    int chain_height = active_chain_height(&ms->chain_active);
    int mmb_height = (int)g_mmb.num_leaves - 1;

    if (mmb_height >= chain_height) {
        pthread_mutex_unlock(&g_mmb_lock);
        return;
    }

    int start = mmb_height + 1;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    sqlite3 *pdb = progress_store_db();
    for (int h = start; h <= chain_height; h++) {
        const struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (bi && bi->phashBlock) {
            /* At a 100-block boundary, read the utxo_root the live connect path
             * recorded so the catch-up leaf hash is byte-identical to it. The
             * boundary root is NOT recoverable from the leaf store (it keeps
             * only 32-byte hashes), so it MUST come from the persisted table; a
             * missing entry falls back to the zero sentinel — that height's
             * leaf is then the pre-keystone hash until a forward pass stamps it
             * (the keystone binding for that boundary is simply absent, never
             * forged). */
            uint8_t utxo_root[32] = {0};
            if (pdb && bi->nHeight > 0 &&
                bi->nHeight % MMR_COMMITMENT_INTERVAL == 0) {
                bool found = false;
                coins_kv_boundary_root_get(pdb, bi->nHeight, utxo_root, &found);
                if (!found) memset(utxo_root, 0, 32);
            }
            struct mmb_leaf leaf;
            mmb_leaf_from_block(&leaf,
                bi->phashBlock->data,
                bi->nHeight, bi->nTime, bi->nBits,
                bi->hashFinalSaplingRoot.data,
                (const uint8_t *)bi->nChainWork.pn,
                utxo_root);
            mmb_append(&g_mmb, &leaf);
        }
    }
    uint32_t mountains = g_mmb.num_mountains;
    pthread_mutex_unlock(&g_mmb_lock);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    printf("MMB catchup: %d → %d (%d blocks, %llds, %u peaks)\n",
           start, chain_height, chain_height - start + 1,
           (long long)elapsed, mountains);
}

void rpc_blockchain_mmb_save(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;
    uint8_t buf[MMB_SERIALIZED_MAX];
    pthread_mutex_lock(&g_mmb_lock);
    if (!g_mmb_initialized) {
        pthread_mutex_unlock(&g_mmb_lock);
        return;
    }
    size_t len = mmb_serialize(&g_mmb, buf, sizeof(buf));
    pthread_mutex_unlock(&g_mmb_lock);
    if (len == 0) return;
    if (!node_db_state_set(ndb, "mmb_state", buf, len))
        LOG_WARN("blockchain", "MMB state save failed");
}

/* ── Auxiliary commitment MMR (advisory UTXO evidence) ───────── */

static struct mmr g_commitment_mmr;
static bool g_commitment_mmr_initialized = false;
static pthread_mutex_t g_commitment_mmr_lock = PTHREAD_MUTEX_INITIALIZER;

bool rpc_blockchain_commitment_mmr_snapshot(uint8_t root[32],
                                            uint64_t *num_leaves,
                                            uint32_t *num_peaks)
{
    pthread_mutex_lock(&g_commitment_mmr_lock);
    if (!g_commitment_mmr_initialized) {
        mmr_init(&g_commitment_mmr);
        g_commitment_mmr_initialized = true;
    }
    if (root)
        mmr_root(&g_commitment_mmr, root);
    if (num_leaves)
        *num_leaves = g_commitment_mmr.num_leaves;
    if (num_peaks)
        *num_peaks = g_commitment_mmr.num_peaks;
    pthread_mutex_unlock(&g_commitment_mmr_lock);
    return true;
}

void rpc_blockchain_commitment_mmr_init_from_state(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;

    uint8_t buf[MMR_SERIALIZED_MAX];
    size_t len = 0;
    struct mmr loaded;
    bool have_loaded = false;
    if (node_db_state_get(ndb, "commitment_mmr_state", buf, sizeof(buf),
                          &len)) {
        if (len >= 12 && mmr_deserialize(&loaded, buf, len)) {
            have_loaded = true;
        }
    }
    pthread_mutex_lock(&g_commitment_mmr_lock);
    if (have_loaded) {
        g_commitment_mmr = loaded;
        g_commitment_mmr_initialized = true;
        printf("Commitment MMR loaded: %llu leaves\n",
               (unsigned long long)g_commitment_mmr.num_leaves);
    }
    if (!g_commitment_mmr_initialized) {
        mmr_init(&g_commitment_mmr);
        g_commitment_mmr_initialized = true;
    }
    pthread_mutex_unlock(&g_commitment_mmr_lock);
}

void rpc_blockchain_commitment_mmr_save(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return;
    uint8_t buf[MMR_SERIALIZED_MAX];
    pthread_mutex_lock(&g_commitment_mmr_lock);
    if (!g_commitment_mmr_initialized) {
        pthread_mutex_unlock(&g_commitment_mmr_lock);
        return;
    }
    size_t len = mmr_serialize(&g_commitment_mmr, buf, sizeof(buf));
    pthread_mutex_unlock(&g_commitment_mmr_lock);
    if (len == 0) return;
    if (!node_db_state_set(ndb, "commitment_mmr_state", buf, len))
        LOG_WARN("blockchain", "commitment MMR state save failed");
}

void rpc_blockchain_maybe_commit(int32_t height,
                                  const uint8_t block_hash[32],
                                  const uint8_t xor_accumulator[32],
                                  uint64_t utxo_count)
{
    if (height <= 0 || height % MMR_COMMITMENT_INTERVAL != 0)
        return;

    /* Skip commitment during deferred proof validation IBD — the MMR will be built
     * from scratch once we pass deferred proof validation height. */
    extern _Atomic int g_deferred_proof_validation_below_height;
    if (g_deferred_proof_validation_below_height >= 0 && height <= g_deferred_proof_validation_below_height)
        return;

    /* Use the incremental XOR accumulator (O(1)) instead of the O(N)
     * SHA3 full-table scan that was killing sync performance. */
    struct mmr_commitment c = { .height = height };
    memcpy(c.block_hash, block_hash, 32);
    memcpy(c.utxo_root, xor_accumulator, 32);
    memset(c.data_root, 0, 32);

    pthread_mutex_lock(&g_commitment_mmr_lock);
    if (!g_commitment_mmr_initialized) {
        mmr_init(&g_commitment_mmr);
        g_commitment_mmr_initialized = true;
    }
    mmr_append_commitment(&g_commitment_mmr, &c);

    if (height % 10000 == 0) {
        uint8_t root[32];
        mmr_root(&g_commitment_mmr, root);
        printf("MMR commitment: h=%d utxos=%llu root=",
               height, (unsigned long long)utxo_count);
        for (int i = 0; i < 8; i++) printf("%02x", root[i]);
        printf("... (%u leaves)\n",
               (unsigned)g_commitment_mmr.num_leaves);
    }
    pthread_mutex_unlock(&g_commitment_mmr_lock);
}

/* ── SHA3 UTXO commitment RPC ──────────────────────────── */

/* ── RPC command registration ─────────────────────────── */

void register_blockchain_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "blockchain", "getblockcount",     rpc_getblockcount,     true },
        { "blockchain", "getbestblockhash",  rpc_getbestblockhash,  true },
        { "blockchain", "getchaintip",       rpc_getchaintip,       true },
        { "blockchain", "getdifficulty",     rpc_getdifficulty,     true },
        { "blockchain", "getblockhash",      rpc_getblockhash,      true },
        { "blockchain", "getblockheader",    rpc_getblockheader,    true },
        { "blockchain", "getblock",          rpc_getblock,          true },
        { "blockchain", "getblockchaininfo", rpc_getblockchaininfo, true },
        { "blockchain", "getmempoolinfo",    rpc_getmempoolinfo,    true },
        { "blockchain", "getrawmempool",     rpc_getrawmempool,     true },
        { "blockchain", "getmempoolfeestats", rpc_getmempoolfeestats, true },
        { "blockchain", "gettxoutsetinfo",      rpc_gettxoutsetinfo,      true },
        /* HODL wave commands in hodl_controller.c */
        { "blockchain", "reindexchainstate",    rpc_reindexchainstate,     false },
        { "blockchain", "importchainstate",     rpc_importchainstate,       false },
        { "blockchain", "invalidateblock",      rpc_invalidateblock,       false },
        { "blockchain", "reconsiderblock",      rpc_reconsiderblock,       false },
        { "blockchain", "getutxocommitment",   rpc_getutxocommitment,     true },
        { "blockchain", "getutxoaudit",        rpc_getutxoaudit,          true },
        { "blockchain", "getmmrroot",          rpc_getmmrroot,            true },
        { "blockchain", "getcommitmentmmr",   rpc_getcommitmentmmr,     true },
        { "blockchain", "auditchain",          rpc_auditchain,            true },
        { "blockchain", "verifycheckpoint",    rpc_verifycheckpoint,      true },
        { "blockchain", "getdataintegrity",    rpc_getdataintegrity,      true },
        { "blockchain", "rebuildsaplingtree", rpc_rebuildsaplingtree,    false },
        /* Long-poll waitfor* (additive, read-only; ok_safe_mode=true) */
        { "blockchain", "waitforheight",       rpc_waitforheight,         true },
        { "blockchain", "waitforhalt",         rpc_waitforhalt,           true },
        { "blockchain", "waitforblocker",      rpc_waitforblocker,        true },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
