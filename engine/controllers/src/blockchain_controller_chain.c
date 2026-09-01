/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Chain-state RPCs: getblockchaininfo, getmempoolinfo, gettxoutsetinfo,
 * UTXO commitments + audit, MMR/MMB roots, data integrity, checkpoint
 * verification, sapling-tree rebuild and chain audit. See
 * blockchain_controller_internal.h for shared declarations. */

#include "platform/time_compat.h"
#include "controllers/blockchain_controller.h"
#include "blockchain_controller_internal.h"
#include "controllers/network_controller.h"
#include "controllers/strong_params.h"
#include "controllers/sync_controller.h"
#include "views/format_helpers.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "consensus/upgrades.h"
#include "consensus/params.h"
#include "chain/mmr.h"
#include "chain/mmb.h"
#include "coins/coins.h"
#include "coins/utxo_commitment.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "net/connman.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/utxo_audit_service.h"
#include "storage/block_index_db.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

bool rpc_getblockchaininfo(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result, "getblockchaininfo\nReturns blockchain state info.");
    if (!ctx->main_state) {
        json_set_str(result, "Not initialized");
        LOG_FAIL("blockchain", "getblockchaininfo: main_state not initialized");
    }

    const struct chain_params *cp = chain_params_get();

    json_set_object(result);
    json_push_kv_str(result, "chain", cp->strNetworkID);

    /* Report the PROVABLE tip (H*), not the sync-window/lookahead active tip:
     * an external getblockchaininfo must never name a height we cannot prove or
     * that rewinds under a reorg. Mirror getblockcount (which already serves
     * reducer_frontier_provable_tip_cached) — and resolve the WHOLE reported
     * best block AT H* so every tip-derived field below (bestblockhash,
     * mediantime, difficulty, chainwork, valuePools, upgrade status) stays
     * internally consistent with the reported "blocks" rather than a higher
     * active tip leaking through mid-fold / post-reorg.
     *
     * `tip` is resolved by-height via active_chain_at(H*): equals the active
     * tip at steady state, LOWER mid-fold / after a reorg. If the H* slot is
     * unresolved, fail closed: the active/lookahead tip is not an acceptable
     * substitute for public chain identity. */
    int32_t hstar = reducer_frontier_provable_tip_cached();
    struct block_index *tip = active_chain_at(&ctx->main_state->chain_active,
                                              (int)hstar);
    if (!tip) {
        /* No provable tip slot resolved yet (fresh / pre-resolve datadir, or
         * mid-fold before the H* block is in the active window). Return a VALID
         * IBD-shaped object instead of overwriting the result with a bare
         * "No provable tip" string — an external getblockchaininfo must always
         * be parseable JSON. blocks = the honest provable height (>=0), headers
         * = the best header height we know, initialblockdownload = true, and
         * bestblockhash when the header tip is available. */
        struct block_index *bh = ctx->main_state->pindex_best_header;
        int hdr_h = bh ? bh->nHeight : 0;
        json_push_kv_int(result, "blocks", hstar > 0 ? hstar : 0);
        json_push_kv_int(result, "headers", hdr_h);
        json_push_kv_int(result, "best_header_height", hdr_h);
        if (bh && bh->phashBlock) {
            char hbhex[65];
            uint256_get_hex(bh->phashBlock, hbhex);
            json_push_kv_str(result, "bestblockhash", hbhex);
        }
        json_push_kv_bool(result, "initialblockdownload", true);
        LOG_WARN("blockchain",
                 "getblockchaininfo: provable tip hstar=%d unresolved — "
                 "returning IBD object (blocks=%d headers=%d)",
                 hstar, hstar > 0 ? hstar : 0, hdr_h);
        return true;
    }
    json_push_kv_int(result, "blocks", tip ? tip->nHeight : 0);
    struct block_index *best_hdr = ctx->main_state->pindex_best_header;
    /* Emit headers=0 when best_header isn't known yet, rather than
     * falling back to tip — that masks the "headers haven't been
     * downloaded yet" condition. Matches zclassicd which emits 0. */
    int header_height = best_hdr ? best_hdr->nHeight : 0;
    json_push_kv_int(result, "headers", header_height);
    json_push_kv_int(result, "best_header_height", header_height);

    if (tip && tip->phashBlock) {
        char hex[65];
        uint256_get_hex(tip->phashBlock, hex);
        json_push_kv_str(result, "bestblockhash", hex);
    }

    /* Median-time-past at tip — zclassicd parity for BIP113 / mempool
     * timestamp checks. */
    if (tip)
        json_push_kv_int(result, "mediantime",
                         block_index_get_median_time_past(tip));

    json_push_kv_real(result, "difficulty", difficulty_from_index(tip));

    /* Cumulative PoW at tip, big-endian hex (zclassicd format). */
    if (tip) {
        char work_hex[65];
        arith_uint256_get_hex(&tip->nChainWork, work_hex);
        json_push_kv_str(result, "chainwork", work_hex);
    }

    /* verificationprogress: fraction of expected validation work done,
     * matching zclassicd semantics (chain_tx history vs checkpoint
     * baseline projection). Falls back to peer-height ratio only when
     * the checkpoint data is unavailable. */
    double progress = 1.0;
    if (tip) {
        progress = checkpoints_guess_verification_progress(
            &cp->checkpointData, tip, true);
        if (progress <= 0.0 || progress > 1.0) {
            /* Fallback: ratio against best peer height. Catches the
             * fresh-IBD window where the checkpoint projection isn't
             * meaningful yet. */
            struct connman *cm = rpc_net_get_connman();
            int max_peer_h = cm ? connman_max_peer_height(cm) : 0;
            int our_h = tip->nHeight;
            progress = (max_peer_h > 0 && our_h < max_peer_h)
                ? (double)our_h / (double)max_peer_h
                : 1.0;
        }
    }
    json_push_kv_real(result, "verificationprogress", progress);

    /* valuePools — sprout + sapling pool balances. Match zclassicd
     * format: each pool is an object with id / monitored / chainValue
     * (ZCL) / chainValueZat.
     *
     * Source: tip->nChainSaplingValue + tip->nChainSproutValue. These
     * are the cumulative ZIP-209 turnstile values maintained by
     * connect_block.c lines 172-209 — boost::optional semantics, only
     * valid when has_chain_*_value is true (i.e., every ancestor's
     * per-block value was known at connect time).
     *
     * Read the pool values from the chain_index field (populated by
     * connect_block whenever the value is known), never from
     * SUM(blocks.sapling_value): the lean catchup path (sync_block_lean
     * in sync_controller_catchup.c) writes sapling_value=0 per block, so
     * a SUM under-reports the pool balance on any datadir whose history
     * came through catchup rather than the consensus connect_block path. */
    if (tip) {
        struct json_value pools = {0};
        json_set_array(&pools);
        const struct {
            const char *id;
            bool        monitored;
            int64_t     zat;
        } pool_defs[] = {
            { "sprout",  tip->has_chain_sprout_value,
              tip->has_chain_sprout_value  ? tip->nChainSproutValue  : 0 },
            { "sapling", tip->has_chain_sapling_value,
              tip->has_chain_sapling_value ? tip->nChainSaplingValue : 0 },
        };
        for (size_t i = 0; i < sizeof(pool_defs)/sizeof(pool_defs[0]); i++) {
            struct json_value pool = {0};
            json_set_object(&pool);
            json_push_kv_str(&pool, "id", pool_defs[i].id);
            json_push_kv_bool(&pool, "monitored", pool_defs[i].monitored);
            if (pool_defs[i].monitored) {
                json_push_kv_real(&pool, "chainValue",
                                  (double)pool_defs[i].zat / 1e8);
                json_push_kv_int(&pool, "chainValueZat", pool_defs[i].zat);
            }
            json_push_back(&pools, &pool);
            json_free(&pool);
        }
        json_push_kv(result, "valuePools", &pools);
        json_free(&pools);
    }

    /* Upgrades — one entry per network-upgrade slot whose activation
     * height is set (skipping BASE_SPROUT, which is always-active and
     * doesn't appear in zclassicd's output, and UPGRADE_TESTDUMMY,
     * which has no real activation height on mainnet). Matches
     * zclassicd format: keyed by branch-id hex string, each value
     * carries name + activationheight + status + info.
     *
     * Two ZClassic upgrades (DIFFADJ/"Bubbly" and BUTTERCUP/"Buttercup")
     * intentionally share branch id 0x930b540d. Keying solely on the
     * branch id would emit "930b540d" twice, which a strict JSON parser
     * dedups (silently dropping one entry). Keep the bare branch-id key
     * for the first occurrence (zclassicd parity for the common case)
     * and disambiguate any colliding key with the upgrade name so every
     * map key is unique. The shared branch id is a consensus value and
     * is unchanged. */
    struct json_value upgrades = {0};
    json_set_object(&upgrades);
    int tip_height = tip ? tip->nHeight : 0;
    for (int idx = UPGRADE_OVERWINTER; idx < MAX_NETWORK_UPGRADES; idx++) {
        int activation = cp->consensus.vUpgrades[idx].nActivationHeight;
        if (activation == NETWORK_UPGRADE_NO_ACTIVATION)
            continue;
        const struct nu_info *info = &NetworkUpgradeInfo[idx];
        char key[48];
        snprintf(key, sizeof(key), "%08x", info->nBranchId);
        if (json_get(&upgrades, key) != NULL) {
            /* Branch id already present — append the upgrade name to keep
             * the JSON map key unique. */
            snprintf(key, sizeof(key), "%08x-%s", info->nBranchId,
                     info->strName ? info->strName : "?");
        }
        const char *status =
            tip_height >= activation ? "active" :
            (activation == NETWORK_UPGRADE_NO_ACTIVATION ? "disabled" :
             "pending");
        struct json_value upg = {0};
        json_set_object(&upg);
        json_push_kv_str(&upg, "name", info->strName ? info->strName : "?");
        json_push_kv_int(&upg, "activationheight", activation);
        json_push_kv_str(&upg, "status", status);
        json_push_kv_str(&upg, "info", info->strInfo ? info->strInfo : "");
        json_push_kv(&upgrades, key, &upg);
        json_free(&upg);
    }
    json_push_kv(result, "upgrades", &upgrades);
    json_free(&upgrades);

    return true;
}

bool rpc_getmempoolinfo(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    struct tx_mempool_stats stats = {0};
    (void)params;
    RPC_HELP(help, result, "getmempoolinfo\nReturns mempool state.");

    json_set_object(result);
    tx_mempool_stats_snapshot(ctx->mempool, &stats);
    json_push_kv_int(result, "size", (int64_t)stats.size);
    json_push_kv_int(result, "bytes", (int64_t)stats.bytes);
    json_push_kv_int(result, "added_total", (int64_t)stats.added_total);
    json_push_kv_int(result, "removed_direct_total",
                     (int64_t)stats.removed_direct_total);
    json_push_kv_int(result, "removed_for_block_total",
                     (int64_t)stats.removed_for_block_total);
    json_push_kv_int(result, "removed_for_branch_total",
                     (int64_t)stats.removed_for_branch_total);
    json_push_kv_int(result, "cleared_total", (int64_t)stats.cleared_total);
    return true;
}

bool rpc_getrawmempool(const struct json_value *params, bool help,
                       struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getrawmempool\nReturns all transaction ids in the mempool.");

    json_set_array(result);
    if (!ctx->mempool)
        return true;

    size_t capacity = tx_mempool_size(ctx->mempool);
    if (capacity == 0)
        return true;
    if (capacity > SIZE_MAX / sizeof(struct uint256))
        LOG_FAIL("blockchain", "getrawmempool: entry count overflow");

    struct uint256 *hashes = zcl_malloc(
        capacity * sizeof(*hashes), "getrawmempool_hashes");
    if (!hashes)
        LOG_FAIL("blockchain", "getrawmempool: hash snapshot allocation failed");

    size_t count = 0;
    tx_mempool_query_hashes(ctx->mempool, hashes, capacity, &count);
    for (size_t i = 0; i < count; i++) {
        char hash_hex[65];
        struct json_value item = {0};
        uint256_get_hex(&hashes[i], hash_hex);
        json_set_str(&item, hash_hex);
        bool pushed = json_push_back(result, &item);
        json_free(&item);
        if (!pushed) {
            free(hashes);
            LOG_FAIL("blockchain", "getrawmempool: result append failed");
        }
    }
    free(hashes);
    return true;
}

/* getmempoolfeestats: fee-rate (zat/byte) + age histogram across mempool
 * entries. Power-user signal for transaction construction (what fee will
 * get my tx confirmed?) and for diagnosing congestion. Single snapshot
 * under the mempool mutex. */
bool rpc_getmempoolfeestats(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getmempoolfeestats\n"
        "\nReturns fee-rate (zat/byte) and age histograms for the current\n"
        "mempool. Buckets are fixed.\n"
        "\nResult:\n"
        "  { size, bytes, fee_buckets:[{rate_zat_per_byte_ge,count,bytes,...}],\n"
        "    age_buckets:[{name,max_age_seconds,count,bytes}] }");

    json_set_object(result);
    if (!ctx->mempool) {
        json_push_kv_int(result, "size",  0);
        json_push_kv_int(result, "bytes", 0);
        return true;
    }

    /* Fee buckets: lower-bound zat/byte. Upper-open at the top. */
    static const int64_t fee_lower[] = { 0, 1, 2, 5, 10, 50, 100, 500 };
    enum { N_FEE = sizeof(fee_lower) / sizeof(fee_lower[0]) };
    int64_t fee_count[N_FEE] = {0};
    int64_t fee_bytes[N_FEE] = {0};

    /* Age buckets: upper-bound seconds. Last bucket is open. */
    static const struct { const char *name; int64_t max_age; }
        age_buckets[] = {
            { "lt_1m",     60 },
            { "lt_5m",    300 },
            { "lt_30m",  1800 },
            { "lt_2h",   7200 },
            { "ge_2h",     -1 },
        };
    enum { N_AGE = sizeof(age_buckets) / sizeof(age_buckets[0]) };
    int64_t age_count[N_AGE] = {0};
    int64_t age_bytes[N_AGE] = {0};

    int64_t now = (int64_t)platform_time_wall_time_t();
    int64_t total_count = 0, total_bytes = 0;

    zcl_mutex_lock(&ctx->mempool->cs);
    for (size_t i = 0; i < ctx->mempool->num_entries; i++) {
        const struct mempool_entry *e = &ctx->mempool->entries[i];
        size_t sz = e->tx_size ? e->tx_size : 1;
        int64_t rate = e->fee / (int64_t)sz;  // zat/byte, integer floor
        int fb = 0;
        for (int j = N_FEE - 1; j >= 0; j--) {
            if (rate >= fee_lower[j]) { fb = j; break; }
        }
        fee_count[fb]++;
        fee_bytes[fb] += (int64_t)sz;

        int64_t age = now - e->time;
        int ab = N_AGE - 1;
        for (int j = 0; j < N_AGE - 1; j++) {
            if (age < age_buckets[j].max_age) { ab = j; break; }
        }
        age_count[ab]++;
        age_bytes[ab] += (int64_t)sz;

        total_count++;
        total_bytes += (int64_t)sz;
    }
    zcl_mutex_unlock(&ctx->mempool->cs);

    json_push_kv_int(result, "size",  total_count);
    json_push_kv_int(result, "bytes", total_bytes);

    struct json_value fees = {0};
    json_set_array(&fees);
    for (int i = 0; i < N_FEE; i++) {
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_int(&row, "rate_zat_per_byte_ge", fee_lower[i]);
        json_push_kv_int(&row, "count", fee_count[i]);
        json_push_kv_int(&row, "bytes", fee_bytes[i]);
        json_push_back(&fees, &row);
        json_free(&row);
    }
    json_push_kv(result, "fee_buckets", &fees);
    json_free(&fees);

    struct json_value ages = {0};
    json_set_array(&ages);
    for (int i = 0; i < N_AGE; i++) {
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_str(&row, "name", age_buckets[i].name);
        json_push_kv_int(&row, "max_age_seconds", age_buckets[i].max_age);
        json_push_kv_int(&row, "count", age_count[i]);
        json_push_kv_int(&row, "bytes", age_bytes[i]);
        json_push_back(&ages, &row);
        json_free(&row);
    }
    json_push_kv(result, "age_buckets", &ages);
    json_free(&ages);

    return true;
}

/* gettxoutsetinfo: UTXO set statistics matching legacy node output. */
bool rpc_gettxoutsetinfo(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "gettxoutsetinfo\n"
        "\nReturns statistics about the UTXO set.\n");

    sqlite3 *cdb = progress_store_db();
    if (!cdb) {
        json_set_str(result, "coins store not available");
        LOG_FAIL("blockchain", "gettxoutsetinfo: coins store not available");
    }
    if (!ctx->main_state || !active_chain_tip(&ctx->main_state->chain_active)) {
        json_set_str(result, "Chain not loaded");
        LOG_FAIL("blockchain", "gettxoutsetinfo: chain not loaded or no tip");
    }

    int tip_height = active_chain_height(&ctx->main_state->chain_active);
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    uint8_t coins_best_hash[32] = {0};
    bool coins_best_hash_found = false;
    int32_t coins_best_height = -1;
    if (reducer_frontier_derive_coins_best_now(&coins_best_height,
                                               coins_best_hash,
                                               &coins_best_hash_found) &&
        coins_best_height >= 0) {
        tip_height = coins_best_height;
        tip = active_chain_at(&ctx->main_state->chain_active,
                              (int)coins_best_height);
    }

    int64_t total_amount = 0;
    int64_t num_txs = 0;
    int64_t num_txouts = 0;

    /* UTXO set statistics from the authoritative atomic coins set. */
    if (!coins_kv_setinfo(cdb, &num_txs, &num_txouts, &total_amount)) {
        json_set_str(result, "coins setinfo failed");
        LOG_FAIL("blockchain", "gettxoutsetinfo: coins setinfo failed");
    }

    json_set_object(result);
    json_push_kv_int(result, "height", tip_height);
    if (coins_best_hash_found) {
        struct uint256 h;
        memcpy(h.data, coins_best_hash, 32);
        char hex[65];
        uint256_get_hex(&h, hex);
        json_push_kv_str(result, "bestblock", hex);
    } else if (tip && tip->phashBlock) {
        char hex[65];
        uint256_get_hex(tip->phashBlock, hex);
        json_push_kv_str(result, "bestblock", hex);
    }
    json_push_kv_int(result, "transactions", num_txs);
    json_push_kv_int(result, "txouts", num_txouts);

    char amt[32];
    snprintf(amt, sizeof(amt), "%lld.%08lld",
             (long long)(total_amount / ZATOSHI_PER_ZCL),
             (long long)(total_amount % ZATOSHI_PER_ZCL));
    json_push_kv_str(result, "total_amount", amt);

    return true;
}

bool rpc_getutxocommitment(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getutxocommitment\n"
        "\nComputes SHA3-256 hash over the entire UTXO set in canonical order.\n"
        "This is a deterministic commitment that two nodes can compare.\n");

    sqlite3 *cdb = progress_store_db();
    if (!cdb) {
        json_set_str(result, "coins store not available");
        LOG_FAIL("blockchain", "getutxocommitment: coins store not available");
    }
    if (!ctx->main_state) {
        json_set_str(result, "Chain not loaded");
        LOG_FAIL("blockchain", "getutxocommitment: chain not loaded");
    }

    uint8_t sha3_hash[32];
    uint64_t count = 0;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    if (coins_kv_commitment(cdb, sha3_hash) != 0) {
        json_set_str(result, "commitment failed");
        LOG_FAIL("blockchain", "getutxocommitment: coins commitment failed");
    }
    count = (uint64_t)coins_kv_count(cdb);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    int tip = active_chain_height(&ctx->main_state->chain_active);
    int32_t coins_best_height = -1;
    if (reducer_frontier_derive_coins_best_now(&coins_best_height, NULL,
                                               NULL) &&
        coins_best_height >= 0)
        tip = coins_best_height;

    /* Save checkpoint (harmless node.db metadata; not load-bearing for reads). */
    if (ctx->node_db && ctx->node_db->open)
        utxo_commitment_sha3_save(ctx->node_db->db, sha3_hash, tip, count);

    char hex[65];
    HexStr(sha3_hash, 32, false, hex, sizeof(hex));

    json_set_object(result);
    json_push_kv_str(result, "sha3_hash", hex);
    json_push_kv_int(result, "height", tip);
    json_push_kv_int(result, "utxo_count", (int64_t)count);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
    return true;
}

static void utxo_audit_result_to_json(const struct utxo_audit_result *audit,
                                      struct json_value *result)
{
    json_set_object(result);
    json_push_kv_str(result, "status", utxo_audit_status_name(audit->status));
    json_push_kv_bool(result, "drift_detected", audit->drift_detected);
    json_push_kv_str(result, "local_sha3", audit->local_sha3);
    json_push_kv_int(result, "local_height", audit->local_height);
    json_push_kv_int(result, "local_utxo_count",
                     (int64_t)audit->local_utxo_count);
    if (audit->remote_sha3[0])
        json_push_kv_str(result, "remote_sha3", audit->remote_sha3);
    if (audit->remote_height > 0)
        json_push_kv_int(result, "remote_height", audit->remote_height);
    if (audit->source[0])
        json_push_kv_str(result, "source", audit->source);
    if (audit->error[0])
        json_push_kv_str(result, "error", audit->error);
}

bool rpc_getutxoaudit(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    RPC_HELP(help, result,
        "getutxoaudit [remote_sha3] [remote_height] [source]\n"
        "\nComputes the local SHA3 UTXO commitment and optionally compares it\n"
        "to a peer-supplied commitment. A mismatch is advisory: it emits an\n"
        "event and sets node_state['utxo_drift_detected']; it never wipes.\n");

    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Database not available");
        LOG_FAIL("blockchain", "getutxoaudit: database not available");
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 3);
    const char *remote_sha3 = rpc_permit_str(&p, 0, "remote_sha3", NULL);
    int64_t remote_height = rpc_permit_int(&p, 1, "remote_height", 0);
    const char *source = rpc_permit_str(&p, 2, "source", "peer-commitment");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("blockchain", "getutxoaudit: invalid params");
    }

    int height = 0;
    if (ctx->main_state)
        height = active_chain_height(&ctx->main_state->chain_active);
    if (remote_height <= 0)
        remote_height = height;

    struct utxo_audit_result audit;
    struct zcl_result audit_res = remote_sha3 && remote_sha3[0]
        ? utxo_audit_compare_remote(ctx->node_db, remote_sha3,
                                    (int32_t)remote_height, source, &audit)
        : utxo_audit_local(ctx->node_db, height, &audit);
    if (!audit_res.ok) {
        json_set_str(result, "UTXO audit failed");
        LOG_FAIL("blockchain", "getutxoaudit: audit failed: %s",
                 audit_res.message);
    }
    utxo_audit_result_to_json(&audit, result);
    return audit.status != UTXO_AUDIT_ERROR;
}

/* ── SHA3 checkpoint verification RPC ──────────────────── */

bool rpc_verifycheckpoint(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "verifycheckpoint\n"
        "\nVerifies the UTXO set against the hardcoded SHA3 checkpoint.\n"
        "Returns pass/fail with details. Flushes coins cache first.\n");

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        json_set_str(result, "No checkpoint available");
        LOG_FAIL("blockchain", "verifycheckpoint: no SHA3 checkpoint available");
    }
    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Database not available");
        LOG_FAIL("blockchain", "verifycheckpoint: database not available");
    }
    if (!ctx->main_state) {
        json_set_str(result, "Chain not loaded");
        LOG_FAIL("blockchain", "verifycheckpoint: chain not loaded");
    }

    int tip = active_chain_height(&ctx->main_state->chain_active);
    if (tip < cp->height) {
        json_set_object(result);
        json_push_kv_str(result, "status", "pending");
        json_push_kv_int(result, "checkpoint_height", cp->height);
        json_push_kv_int(result, "current_height", tip);
        return true;
    }

    sqlite3 *cdb = progress_store_db();
    if (!cdb) {
        json_set_str(result, "coins store not available");
        LOG_FAIL("blockchain", "verifycheckpoint: coins store not available");
    }

    uint8_t sha3_hash[32];
    uint64_t count = 0;
    if (coins_kv_commitment(cdb, sha3_hash) != 0) {
        json_set_str(result, "commitment failed");
        LOG_FAIL("blockchain", "verifycheckpoint: coins commitment failed");
    }
    count = (uint64_t)coins_kv_count(cdb);

    bool match = (memcmp(sha3_hash, cp->sha3_hash, 32) == 0);

    char local_hex[65], expected_hex[65];
    HexStr(sha3_hash, 32, false, local_hex, sizeof(local_hex));
    HexStr(cp->sha3_hash, 32, false, expected_hex, sizeof(expected_hex));

    json_set_object(result);
    json_push_kv_str(result, "status", match ? "PASSED" : "FAILED");
    json_push_kv_int(result, "checkpoint_height", cp->height);
    json_push_kv_str(result, "expected_sha3", expected_hex);
    json_push_kv_str(result, "computed_sha3", local_hex);
    json_push_kv_int(result, "expected_utxos", (int64_t)cp->utxo_count);
    json_push_kv_int(result, "computed_utxos", (int64_t)count);

    if (match)
        printf("SHA3 checkpoint verification: PASSED at height %d\n",
               cp->height);
    else
        printf("SHA3 checkpoint verification: FAILED at height %d!\n"
               "  expected: %s\n  computed: %s\n",
               cp->height, expected_hex, local_hex);

    return true;
}

/* ── Full data integrity hash RPC ──────────────────────── */

bool rpc_getdataintegrity(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "getdataintegrity\n"
        "\nComputes SHA3-256 hashes over ALL consensus data tables:\n"
        "blocks, transactions, tx_inputs, tx_outputs, utxos,\n"
        "sapling_nullifiers, sapling_outputs, sapling_spends,\n"
        "sprout_nullifiers, joinsplits, zslp_tokens, zslp_transfers.\n"
        "Returns per-table hashes and a master hash combining all.\n");

    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Database not available");
        LOG_FAIL("blockchain", "getdataintegrity: database not available");
    }

    int64_t t0 = (int64_t)platform_time_wall_time_t();
    struct data_integrity_detail d;
    data_integrity_compute(ctx->node_db->db, &d);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    json_set_object(result);
    json_push_kv_str(result, "source", "persisted_consensus_tables");

    /* Helper: convert 32-byte hash to hex and push as kv */
    const struct { const char *name; const uint8_t *hash; } tables[] = {
        { "blocks",              d.blocks },
        { "transactions",        d.transactions },
        { "tx_inputs",           d.tx_inputs },
        { "tx_outputs",          d.tx_outputs },
        { "utxos",               d.utxos },
        { "sapling_nullifiers",  d.sapling_nullifiers },
        { "sapling_outputs",     d.sapling_outputs },
        { "sapling_spends",      d.sapling_spends },
        { "sprout_nullifiers",   d.sprout_nullifiers },
        { "joinsplits",          d.joinsplits },
        { "zslp_tokens",         d.zslp_tokens },
        { "zslp_transfers",      d.zslp_transfers },
        { "master",              d.master },
    };

    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char hex[65];
        HexStr(tables[i].hash, 32, false, hex, sizeof(hex));
        json_push_kv_str(result, tables[i].name, hex);
    }

    int tip = ctx->main_state ? active_chain_height(&ctx->main_state->chain_active) : 0;
    json_push_kv_int(result, "height", tip);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
    return true;
}
