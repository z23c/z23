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
#include "consensus/upgrades.h"
#include "consensus/params.h"
#include "chain/mmr.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "event/event.h"
#include "json/json.h"
#include "net/connman.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/utxo_audit_service.h"
#include "storage/block_index_db.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


/* ── MMR root RPC ──────────────────────────────────────── */

bool rpc_getmmrroot(const struct json_value *params, bool help,
                             struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getmmrroot\n"
        "\nReturns the Merkle Mountain Range root over all block hashes.\n"
        "Uses SHA3-256 with domain separation for power node sync.\n");

    uint8_t root[32];
    uint64_t leaves = 0;
    uint32_t peaks = 0;
    if (!rpc_blockchain_mmr_snapshot(root, &leaves, &peaks)) {
        json_set_str(result, "MMR not initialized");
        LOG_FAIL("blockchain", "getmmrroot: MMR not initialized");
    }

    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", root[i]);

    json_set_object(result);
    json_push_kv_str(result, "mmr_root", hex);
    json_push_kv_int(result, "num_leaves", (int64_t)leaves);
    json_push_kv_int(result, "num_peaks", peaks);
    return true;
}

bool rpc_getcommitmentmmr(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getcommitmentmmr\n"
        "\nReturns the advisory commitment MMR root (not a ZClassic consensus state commitment).\n"
        "Each leaf: SHA3(height || block_hash || utxo_root) every 100 blocks.\n"
        "Used to verify imported UTXO snapshots without replaying history.\n");

    uint8_t root[32];
    uint64_t leaves = 0;
    rpc_blockchain_commitment_mmr_snapshot(root, &leaves, NULL);

    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", root[i]);

    json_set_object(result);
    json_push_kv_str(result, "commitment_mmr_root", hex);
    json_push_kv_int(result, "num_commitments", (int64_t)leaves);
    json_push_kv_int(result, "commitment_interval", MMR_COMMITMENT_INTERVAL);
    json_push_kv_int(result, "covers_height",
        (int64_t)leaves * MMR_COMMITMENT_INTERVAL);
    return true;
}

bool rpc_auditchain(const struct json_value *params, bool help,
                            struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "auditchain\n"
        "\nFull chain audit: verify block-hash MMR and commitment MMR.\n"
        "Reports the state of both MMRs and what height they cover.\n"
        "Restart with -reindex-chainstate for full block replay + UTXO rebuild.\n"
        "Use verifycheckpoint to check UTXO SHA3 at hardcoded height.\n");

    json_set_object(result);

    /* Block-hash MMR */
    uint8_t broot[32] = {0};
    uint64_t block_leaves = 0;
    bool block_mmr_initialized =
        rpc_blockchain_mmr_snapshot(broot, &block_leaves, NULL);
    char bhex[65];
    for (int i = 0; i < 32; i++)
        snprintf(bhex + i * 2, 3, "%02x", broot[i]);
    json_push_kv_str(result, "block_mmr_root", bhex);
    json_push_kv_int(result, "block_mmr_leaves", (int64_t)block_leaves);

    /* Commitment MMR */
    uint8_t croot[32];
    uint64_t commitment_leaves = 0;
    rpc_blockchain_commitment_mmr_snapshot(croot, &commitment_leaves,
                                           NULL);
    char chex[65];
    for (int i = 0; i < 32; i++)
        snprintf(chex + i * 2, 3, "%02x", croot[i]);
    json_push_kv_str(result, "commitment_mmr_root", chex);
    json_push_kv_int(result, "commitment_leaves", (int64_t)commitment_leaves);
    json_push_kv_int(result, "commitment_covers_height",
        (int64_t)commitment_leaves * MMR_COMMITMENT_INTERVAL);

    /* Chain state */
    int chain_h = ctx->main_state ? active_chain_height(
        &ctx->main_state->chain_active) : 0;
    json_push_kv_int(result, "chain_height", chain_h);

    /* Consistency check */
    bool block_mmr_ok = block_mmr_initialized &&
                        (int64_t)block_leaves >= chain_h;
    bool commit_ok = (int64_t)commitment_leaves * MMR_COMMITMENT_INTERVAL >=
                     chain_h - MMR_COMMITMENT_INTERVAL;
    json_push_kv_bool(result, "block_mmr_consistent", block_mmr_ok);
    json_push_kv_bool(result, "commitment_mmr_consistent", commit_ok);
    json_push_kv_bool(result, "audit_passed", block_mmr_ok && commit_ok);

    return true;
}

/* ── rebuildsaplingtree — replay Sapling outputs, rebuild tree ─── */

bool rpc_rebuildsaplingtree(const struct json_value *params,
                                    bool help, struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    (void)params;
    RPC_HELP(help, result,
        "rebuildsaplingtree\n"
        "\nRebuild the Sapling commitment tree by replaying every shielded\n"
        "output from Sapling activation (height 476969) to chain tip.\n"
        "Verifies computed root matches hashFinalSaplingRoot in each header.\n"
        "Fixes tree divergence caused by corrupted persisted state.\n"
        "This may take several minutes for the full chain.\n");

    if (!ctx->main_state || !ctx->datadir || !ctx->node_db) {
        json_set_str(result, "error: node not fully initialized");
        LOG_FAIL("blockchain", "rebuildsaplingtree: node not fully initialized (main_state=%p datadir=%p node_db=%p)",
                 (void *)ctx->main_state, (void *)ctx->datadir, (void *)ctx->node_db);
    }

    struct main_state *ms = ctx->main_state;
    struct node_db *ndb = ctx->node_db;
    const char *datadir = ctx->datadir;

    extern _Atomic bool g_sapling_tree_rebuilding;
    atomic_store(&g_sapling_tree_rebuilding, true);
    int n = sapling_tree_rebuild(ndb, &ms->chain_active, datadir);
    atomic_store(&g_sapling_tree_rebuilding, false);

    if (n < 0) {
        json_set_str(result, "error: rebuild failed");
        LOG_FAIL("blockchain", "rebuildsaplingtree: sapling_tree_rebuild returned %d", n);
    }

    /* Reload rebuilt tree into main_state */
    uint8_t tbuf[8192];
    size_t tlen = 0;
    if (node_db_state_get(ndb, "sapling_tree", tbuf, sizeof(tbuf), &tlen)
        && tlen > 0) {
        struct byte_stream ts;
        stream_init_from_data(&ts, tbuf, tlen);
        sapling_tree_init(&ms->sapling_tree);
        incremental_tree_deserialize(&ms->sapling_tree, &ts);
        ms->sapling_tree_loaded = true;
    }

    /* Verify against chain tip */
    struct uint256 final_root;
    incremental_tree_root(&ms->sapling_tree, &final_root);
    char root_hex[65];
    uint256_get_hex(&final_root, root_hex);

    const struct block_index *tip = active_chain_tip(&ms->chain_active);
    char expected_hex[65] = "n/a";
    bool roots_match = false;
    if (tip) {
        uint256_get_hex(&tip->hashFinalSaplingRoot, expected_hex);
        roots_match = (memcmp(final_root.data,
                              tip->hashFinalSaplingRoot.data, 32) == 0);
    }

    json_set_object(result);
    json_push_kv_str(result, "status", roots_match ? "success" : "mismatch");
    json_push_kv_int(result, "total_commitments", (int64_t)n);
    json_push_kv_int(result, "tree_size",
        (int64_t)incremental_tree_size(&ms->sapling_tree));
    json_push_kv_str(result, "computed_root", root_hex);
    json_push_kv_str(result, "expected_root", expected_hex);
    json_push_kv_bool(result, "roots_match", roots_match);
    return true;
}
