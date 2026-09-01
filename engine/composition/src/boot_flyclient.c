/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_flyclient.h"

#include "config/boot_internal.h"
#include "chain/chain.h"
#include "chain/mmb.h"
#include "coins/utxo_commitment.h"
#include "controllers/blockchain_controller.h"
#include "models/block.h"
#include "models/mmb_leaf_store.h"
#include "models/utxo.h"
#include "net/snapshot_sync_contract.h"
#include "util/log_macros.h"

#include <stdio.h>

struct mmb_leaf_store g_mmb_leaf_store = {0};

bool boot_build_flyclient_proof(struct fc_response *resp,
                                const struct fc_challenge *challenge,
                                const struct active_chain *chain_active,
                                void *ctx)
{
    (void)ctx;

    if (!resp || !challenge || !chain_active)
        LOG_FAIL("boot",
                 "FlyClient proof build missing resp=%p challenge=%p chain=%p",
                 (void *)resp, (const void *)challenge,
                 (const void *)chain_active);

    uint64_t mmb_leaves = 0;
    rpc_blockchain_mmb_snapshot(NULL, &mmb_leaves, NULL);
    const uint8_t (*all_hashes)[32] =
        mmb_leaf_store_all(&g_mmb_leaf_store);
    if (mmb_leaves == 0 || !all_hashes)
        return false;

    return snapsync_build_fc_response(resp, challenge, chain_active,
                                      &g_mmb_leaf_store).ok;
}

int boot_load_block_hashes_range(int32_t start_height,
                                 int32_t end_height,
                                 uint8_t (*hashes_out)[32],
                                 size_t max,
                                 void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!svc || !svc->node_db || !hashes_out || max == 0) {
        LOG_WARN("boot",
                 "block hash range load missing svc=%p ndb=%p out=%p max=%zu",
                 (void *)svc, svc ? (void *)svc->node_db : NULL,
                 (void *)hashes_out, max);
        return 0;
    }

    if (end_height >= start_height && svc->state) {
        int32_t needed_i32 = end_height - start_height + 1;
        if (needed_i32 > 0 && (size_t)needed_i32 <= max) {
            size_t count = 0;
            for (int32_t h = start_height; h <= end_height; h++) {
                const struct block_index *bi =
                    active_chain_at(&svc->state->chain_active, h);
                if (!bi || !bi->phashBlock ||
                    !(bi->nStatus & BLOCK_HAVE_DATA)) {
                    count = 0;
                    break;
                }
                memcpy(hashes_out[count], bi->phashBlock->data, 32);
                count++;
            }
            if (count == (size_t)needed_i32)
                return (int)count;
        }
    }

    return db_block_hashes_in_range(svc->node_db, start_height, end_height,
                                    hashes_out, max);
}

bool boot_compute_utxo_sha3(uint8_t out[32],
                            uint64_t *utxo_count,
                            void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!svc || !svc->node_db || !svc->node_db->db || !out || !utxo_count) {
        LOG_WARN("boot",
                 "UTXO SHA3 compute missing svc=%p ndb=%p out=%p count=%p",
                 (void *)svc, svc ? (void *)svc->node_db : NULL,
                 (void *)out, (void *)utxo_count);
        return false;
    }

    utxo_commitment_sha3_compute(svc->node_db->db, out, utxo_count);
    return true;
}

int64_t boot_serialize_utxo_snapshot(void *ctx,
                                     const char *path,
                                     uint32_t chunk_size,
                                     uint8_t sha3_out[32])
{
    struct node_db *ndb = ctx;

    if (!ndb || !ndb->open || !path || !sha3_out) {
        LOG_WARN("boot",
                 "UTXO snapshot serialize missing ndb=%p path=%p sha3=%p",
                 (void *)ndb, (const void *)path, (void *)sha3_out);
        return -1;
    }

    return db_utxo_serialize_snapshot(ndb, path, chunk_size, sha3_out);
}

static bool boot_mmb_leaf_store_catchup_legacy(
    struct mmb_leaf_store *store,
    int tip_height,
    boot_mmb_leaf_loader_fn load_legacy_leaf)
{
    if (!store || !store->open || tip_height < 0 || !load_legacy_leaf)
        return false;

    uint64_t target = (uint64_t)tip_height + 1;
    if (store->num_leaves >= target)
        return true;

    uint64_t start = store->num_leaves;
    for (uint64_t i = start; i < target; i++) {
        struct mmb_leaf leaf;
        uint8_t hash[32];

        if (!load_legacy_leaf((int)i, &leaf)) {
            printf("[FlyClient] MMB leaf legacy catchup stopped at h=%llu\n",
                   (unsigned long long)i);
            break;
        }
        mmb_hash_leaf(&leaf, hash);
        if (!mmb_leaf_store_append(store, hash)) {
            printf("[FlyClient] MMB leaf append failed at h=%llu\n",
                   (unsigned long long)i);
            break;
        }
    }

    if (!mmb_leaf_store_remap(store)) {
        printf("[FlyClient] MMB leaf remap failed after legacy catchup\n");
        return false;
    }

    printf("[FlyClient] MMB leaf store legacy catchup: %llu -> %llu/%llu\n",
           (unsigned long long)start,
           (unsigned long long)store->num_leaves,
           (unsigned long long)target);
    return store->num_leaves >= target;
}

static bool boot_mmb_leaf_store_repair_prefix_legacy(
    struct mmb_leaf_store *store,
    uint64_t count,
    boot_mmb_leaf_loader_fn load_legacy_leaf)
{
    if (!store || !store->open || store->fd < 0 || count == 0 ||
        !load_legacy_leaf)
        return false;
    if (count > store->num_leaves)
        count = store->num_leaves;

    for (uint64_t i = 0; i < count; i++) {
        struct mmb_leaf leaf;
        uint8_t hash[32];

        if (!load_legacy_leaf((int)i, &leaf)) {
            printf("[FlyClient] MMB leaf prefix repair stopped at h=%llu\n",
                   (unsigned long long)i);
            return false;
        }
        mmb_hash_leaf(&leaf, hash);
        if (!mmb_leaf_store_write_at(store, i, hash)) {
            printf("[FlyClient] MMB leaf prefix repair write failed at h=%llu\n",
                   (unsigned long long)i);
            return false;
        }
    }

    if (!mmb_leaf_store_remap(store)) {
        printf("[FlyClient] MMB leaf remap failed after prefix repair\n");
        return false;
    }

    printf("[FlyClient] MMB leaf store prefix repaired: %llu leaves\n",
           (unsigned long long)count);
    return true;
}

bool boot_prepare_mmb_leaf_store(struct boot_svc_ctx *svc,
                                 const char *datadir,
                                 boot_mmb_leaf_loader_fn legacy_loader)
{
    if (!svc || !svc->state || !datadir || !*datadir)
        LOG_FAIL("boot", "MMB leaf store prepare missing svc=%p datadir=%p",
                 (void *)svc, (const void *)datadir);

    char leaf_path[512];
    int n = snprintf(leaf_path, sizeof(leaf_path), "%s/mmb_leaves.bin",
                     datadir);
    if (n <= 0 || (size_t)n >= sizeof(leaf_path))
        LOG_FAIL("boot", "MMB leaf store path too long for datadir '%s'",
                 datadir);

    mmb_leaf_store_open(&g_mmb_leaf_store, leaf_path);
    uint64_t mmb_leaves = 0;
    rpc_blockchain_mmb_snapshot(NULL, &mmb_leaves, NULL);
    if (g_mmb_leaf_store.num_leaves < mmb_leaves) {
        printf("[FlyClient] Rebuilding MMB leaf store (%llu -> %llu)...\n",
               (unsigned long long)g_mmb_leaf_store.num_leaves,
               (unsigned long long)mmb_leaves);
        mmb_leaf_store_rebuild(&g_mmb_leaf_store,
                               &svc->state->chain_active);
    }

    int tip_h = active_chain_height(&svc->state->chain_active);
    if (tip_h >= 0 && g_mmb_leaf_store.num_leaves < (uint64_t)tip_h + 1) {
        uint64_t repair_count = g_mmb_leaf_store.num_leaves < 2048
                                    ? g_mmb_leaf_store.num_leaves
                                    : 2048;
        boot_mmb_leaf_store_repair_prefix_legacy(&g_mmb_leaf_store,
                                                  repair_count,
                                                  legacy_loader);
        boot_mmb_leaf_store_catchup_legacy(&g_mmb_leaf_store, tip_h,
                                           legacy_loader);
    }
    printf("[FlyClient] MMB leaf store: %llu hashes ready\n",
           (unsigned long long)g_mmb_leaf_store.num_leaves);
    return g_mmb_leaf_store.open;
}
