/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_flyclient.h"

#include "config/boot_internal.h"
#include "chain/chain.h"
#include "chain/mmb.h"
#include "chain/mmr.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "coins/utxo_commitment.h"
#include "controllers/blockchain_controller.h"
#include "models/block.h"
#include "models/mmb_leaf_store.h"
#include "models/utxo.h"
#include "net/snapshot_sync_contract.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

struct mmb_leaf_store g_mmb_leaf_store = {0};
static _Atomic bool g_mmb_leaf_available;
static zcl_once_t g_mmb_binding_once = ZCL_ONCE_INIT;
static zcl_mutex_t g_mmb_binding_lock;
static const struct active_chain *g_mmb_chain;
static int g_mmb_height;
static uint8_t g_mmb_hash[32];
static uint64_t g_mmb_count;

#ifdef ZCL_TESTING
static void (*g_mmb_height_hook)(void);
void boot_mmb_test_height_hook(void (*hook)(void))
{
    g_mmb_height_hook = hook;
}
#endif

static int boot_mmb_authority_height(const struct active_chain *chain)
{
#ifdef ZCL_TESTING
    if (g_mmb_height_hook) g_mmb_height_hook();
#endif
    return active_chain_height(chain);
}

static void boot_mmb_binding_init(void)
{
    zcl_mutex_init(&g_mmb_binding_lock);
}

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
    if (!boot_mmb_leaf_store_available(chain_active) || mmb_leaves == 0)
        return false;
    const uint8_t (*all_hashes)[32] = mmb_leaf_store_all(&g_mmb_leaf_store);
    if (!all_hashes) return false;

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

    if (sha3_out)
        memset(sha3_out, 0, 32);
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

/* A compacted list of sparse heights is not a height-indexed MMB prefix. */
static bool boot_mmb_chain_dense(const struct active_chain *chain)
{
    if (!chain) return false;
    int tip = boot_mmb_authority_height(chain);
    struct active_chain *c = (struct active_chain *)chain;
    zcl_mutex_lock(&c->write_lock);
    const struct block_index *prev = NULL;
    bool ok = tip >= 0;
    for (int64_t h = 0; ok && h <= tip; h++) {
        const struct block_index *p = active_chain_at(chain, (int)h);
        ok = p && p->phashBlock && p->nHeight == h && (h == 0 || p->pprev == prev);
        prev = p;
    }
    zcl_mutex_unlock(&c->write_lock);
    return ok;
}

bool boot_mmb_leaf_store_available(const struct active_chain *chain)
{
    if (!chain || !atomic_load(&g_mmb_leaf_available) ||
        !zcl_once_call(&g_mmb_binding_once, boot_mmb_binding_init)) return false;
    zcl_mutex_lock(&g_mmb_binding_lock);
    const struct active_chain *bound = g_mmb_chain;
    int height = g_mmb_height;
    uint64_t count = g_mmb_count;
    uint8_t hash[32];
    memcpy(hash, g_mmb_hash, sizeof(hash));
    zcl_mutex_unlock(&g_mmb_binding_lock);
    if (bound != chain) return false;
    struct active_chain *c = (struct active_chain *)chain;
    zcl_mutex_lock(&c->write_lock);
    const struct block_index *tip = active_chain_at(chain, height);
    bool ok = atomic_load(&g_mmb_leaf_available) && tip && tip->phashBlock &&
        tip->nHeight == height && !memcmp(tip->phashBlock->data, hash, sizeof(hash)) &&
        g_mmb_leaf_store.open && g_mmb_leaf_store.num_leaves == count;
    zcl_mutex_unlock(&c->write_lock);
    return ok;
}

/* A stored leaf is trusted only if the active chain reproduces it. Checks the
 * last leaf plus older samples (last-1, last-100, last-2048) when present. */
static bool boot_mmb_leaf_store_prefix_matches(
    const struct mmb_leaf_store *store, const struct active_chain *chain)
{
    static const uint64_t back[] = {0, 1, 100, 2048};
    for (size_t i = 0; i < sizeof(back) / sizeof(back[0]); i++) {
        if (store->num_leaves <= back[i]) continue;
        uint64_t idx = store->num_leaves - 1 - back[i];
        uint8_t want[32];
        const uint8_t *have = mmb_leaf_store_get(store, idx);
        if (!have || idx > (uint64_t)INT32_MAX ||
            !mmb_leaf_store_hash_at(chain, (int)idx, want) ||
            memcmp(have, want, 32) != 0)
            return false;
    }
    return true;
}

/* Bring the leaf store to the active chain with the least work: append only the
 * missing tail when the stored prefix still matches the chain, else rebuild. */
bool boot_reconcile_mmb_leaf_store(struct mmb_leaf_store *store,
                                   const struct active_chain *chain,
                                   uint64_t mmb_leaves)
{
    int tip_h = active_chain_height(chain);
    if (!store || !store->open || tip_h < 0 || !boot_mmb_chain_dense(chain)) return false;
    uint64_t chain_leaves = (uint64_t)tip_h + 1;
    uint64_t target = mmb_leaves < chain_leaves ? mmb_leaves : chain_leaves;
    uint64_t have = store->num_leaves;
    if (mmb_leaves > chain_leaves)
        printf("[FlyClient] MMB state %llu leaves ahead of active chain; "
               "store follows the chain (state %llu, chain %llu)\n",
               (unsigned long long)(mmb_leaves - chain_leaves),
               (unsigned long long)mmb_leaves,
               (unsigned long long)chain_leaves);

    const char *reason = NULL;
    if (have > chain_leaves)
        reason = "store longer than chain";
    else if (have >= target)
        return true;
    else if (have == 0)
        reason = "store empty";
    else if (!boot_mmb_leaf_store_prefix_matches(store, chain))
        reason = "stored prefix does not match chain";

    if (!reason) {
        uint64_t added = mmb_leaf_store_extend(store, chain, (int)have);
        if (have + added == chain_leaves) {
            printf("[FlyClient] MMB leaf store: extended %llu leaves from "
                   "h=%llu\n", (unsigned long long)added,
                   (unsigned long long)have);
            return true;
        }
        reason = "extend fell short";
    }
    printf("[FlyClient] MMB leaf store: full rebuild (%s; %llu -> %llu)\n",
           reason, (unsigned long long)have, (unsigned long long)target);
    mmb_leaf_store_rebuild(store, chain);
    return true;
}

/* A prior sparse rebuild may have compacted arbitrary holes; samples cannot
 * prove the height-indexed prefix. Compare every leaf before offering it. */
static bool boot_mmb_copy_leaf(const struct active_chain *chain, int height,
                               const struct block_index **prev, struct mmb_leaf *leaf)
{
    struct active_chain *c = (struct active_chain *)chain;
    zcl_mutex_lock(&c->write_lock);
    const struct block_index *p = active_chain_at(chain, height);
    bool ok = p && p->phashBlock && p->nHeight == height &&
              (height == 0 || p->pprev == *prev);
    if (ok) {
        uint8_t zero[32] = {0};
        mmb_leaf_from_block(leaf, p->phashBlock->data, p->nHeight, p->nTime,
                            p->nBits, p->hashFinalSaplingRoot.data,
                            (const uint8_t *)p->nChainWork.pn, zero);
        *prev = p;
    }
    zcl_mutex_unlock(&c->write_lock);
    return ok;
}

static bool boot_mmb_boundary_root(int64_t height, struct mmb_leaf *leaf)
{
    sqlite3 *db = progress_store_db();
    if (!db || height <= 0 || height % MMR_COMMITMENT_INTERVAL != 0) return true;
    bool found = false;
    if (!coins_kv_boundary_root_get(db, (int32_t)height, leaf->utxo_root, &found)) return false;
    if (!found) memset(leaf->utxo_root, 0, sizeof(leaf->utxo_root));
    return true;
}


static bool boot_mmb_store_matches_chain(const struct mmb_leaf_store *store,
                                         const struct active_chain *chain, int tip,
                                         const uint8_t frontier[32])
{
    if (!store || !store->open || tip < 0 || store->num_leaves != (uint64_t)tip + 1)
        return false;
    const struct block_index *prev = NULL;
    for (int64_t height = 0; height <= tip; height++) {
        struct mmb_leaf leaf;
        uint8_t expected[32];
        const uint8_t *stored = mmb_leaf_store_get(store, (uint64_t)height);
        if (!stored || !boot_mmb_copy_leaf(chain, (int)height, &prev, &leaf)) return false;
        if (!boot_mmb_boundary_root(height, &leaf)) return false;
        mmb_hash_leaf(&leaf, expected);
        if (memcmp(stored, expected, sizeof(expected))) return false;
        if (height == tip && memcmp(leaf.block_hash, frontier, 32)) return false;
    }
    return true;
}

static bool boot_mmb_validate_and_bind(const struct active_chain *chain)
{
    if (!chain || !zcl_once_call(&g_mmb_binding_once, boot_mmb_binding_init)) return false;
    int tip = boot_mmb_authority_height(chain);
    struct active_chain *c = (struct active_chain *)chain;
    zcl_mutex_lock(&c->write_lock);
    const struct block_index *p = tip >= 0 ? active_chain_at(chain, tip) : NULL;
    uint8_t frontier[32];
    bool ok = p && p->phashBlock && p->nHeight == tip;
    if (ok) memcpy(frontier, p->phashBlock->data, sizeof(frontier));
    zcl_mutex_unlock(&c->write_lock);
    if (!ok || !boot_mmb_store_matches_chain(&g_mmb_leaf_store, chain, tip, frontier)) return false;
    zcl_mutex_lock(&c->write_lock);
    p = active_chain_at(chain, tip);
    ok = p && p->phashBlock && p->nHeight == tip &&
         !memcmp(p->phashBlock->data, frontier, sizeof(frontier));
    if (ok) {
        zcl_mutex_lock(&g_mmb_binding_lock);
        g_mmb_chain = chain; g_mmb_height = tip; g_mmb_count = (uint64_t)tip + 1;
        memcpy(g_mmb_hash, frontier, sizeof(g_mmb_hash));
        atomic_store(&g_mmb_leaf_available, true);
        zcl_mutex_unlock(&g_mmb_binding_lock);
    }
    zcl_mutex_unlock(&c->write_lock);
    return ok;
}

#ifdef ZCL_TESTING
bool boot_mmb_leaf_store_test_verify(const struct active_chain *chain)
{
    atomic_store(&g_mmb_leaf_available, false);
    return boot_mmb_validate_and_bind(chain);
}
#endif

static void boot_mmb_legacy_finish(int tip, boot_mmb_leaf_loader_fn loader)
{
    if (tip < 0 || g_mmb_leaf_store.num_leaves >= (uint64_t)tip + 1) return;
    uint64_t count = g_mmb_leaf_store.num_leaves < 2048 ? g_mmb_leaf_store.num_leaves : 2048;
    bool ok = count == 0 || boot_mmb_leaf_store_repair_prefix_legacy(&g_mmb_leaf_store, count, loader);
    if (ok) boot_mmb_leaf_store_catchup_legacy(&g_mmb_leaf_store, tip, loader);
}


bool boot_prepare_mmb_leaf_store(struct boot_svc_ctx *svc,
                                 const char *datadir,
                                 boot_mmb_leaf_loader_fn legacy_loader)
{
    atomic_store(&g_mmb_leaf_available, false);
    if (!svc || !svc->state || !datadir || !*datadir)
        LOG_FAIL("boot", "MMB leaf store prepare missing svc=%p datadir=%p",
                 (void *)svc, (const void *)datadir);

    /* The store keeps its own copy of the path and refuses one that does not
     * fit; check against that limit so a refusal is named here, before the
     * global store is touched. */
    char leaf_path[512];
    int n = snprintf(leaf_path, sizeof(leaf_path), "%s/mmb_leaves.bin",
                     datadir);
    if (n <= 0 || (size_t)n >= sizeof(leaf_path) ||
        (size_t)n >= sizeof(g_mmb_leaf_store.path))
        LOG_FAIL("boot", "MMB leaf store path too long (%d bytes, store "
                 "holds %zu) for datadir '%s'", n,
                 sizeof(g_mmb_leaf_store.path) - 1, datadir);

    if (!boot_mmb_chain_dense(&svc->state->chain_active)) {
        printf("[FlyClient] MMB leaf proof unavailable: sparse active chain\n");
        return true;
    }

    if (!mmb_leaf_store_open(&g_mmb_leaf_store, leaf_path))
        LOG_FAIL("boot", "MMB leaf store open failed at '%s'", leaf_path);
    uint64_t mmb_leaves = 0;
    rpc_blockchain_mmb_snapshot(NULL, &mmb_leaves, NULL);
    (void)boot_reconcile_mmb_leaf_store(&g_mmb_leaf_store,
                                        &svc->state->chain_active,
                                        mmb_leaves);

    boot_mmb_legacy_finish(active_chain_height(&svc->state->chain_active), legacy_loader);
    bool complete = boot_mmb_validate_and_bind(&svc->state->chain_active);
    printf("[FlyClient] MMB leaf store: %llu hashes, proof %s\n",
           (unsigned long long)g_mmb_leaf_store.num_leaves,
           complete ? "available" : "unavailable");
    return g_mmb_leaf_store.open;
}
