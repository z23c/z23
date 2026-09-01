/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Administrative chainstate RPCs: reindexchainstate compatibility error and
 * importchainstate (bulk-import UTXO set from an external LevelDB chainstate).
 * Heavy, operator-invoked operations. See
 * blockchain_controller_internal.h for shared declarations. */

#include "controllers/blockchain_controller.h"
#include "blockchain_controller_internal.h"
#include "controllers/sync_controller.h"
#include "controllers/strong_params.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "json/json.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "services/chain_state_service.h"
#include "storage/coins_db.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── reindexchainstate ──────────────────────────────────────── */

bool rpc_reindexchainstate(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "reindexchainstate\n"
        "\nRuntime chainstate replay is retired. Restart the node with\n"
        "-reindex-chainstate so boot can rebuild the SQLite UTXO set through\n"
        "the single reducer/boot reindex writer before services start.\n");

    json_set_str(result,
                 "Runtime reindexchainstate is retired; restart with "
                 "-reindex-chainstate");
    LOG_FAIL("blockchain",
             "reindexchainstate RPC retired; use -reindex-chainstate at boot");
}

/* ── importchainstate ──────────────────────────────────────── */

bool rpc_importchainstate(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    RPC_HELP(help, result,
        "importchainstate \"chainstate_path\"\n"
        "\nRebuild the UTXO index from an external LevelDB chainstate directory.\n"
        "Use this to import the complete UTXO set from a zclassicd node:\n"
        "  importchainstate /home/user/.zclassic/chainstate\n"
        "\nThis replaces all UTXOs in SQLite with those from the given chainstate.\n"
        "The source node should be stopped to avoid LevelDB lock conflicts.\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *cs_path = rpc_require_str(&p, 0, "chainstate_path");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("blockchain", "importchainstate: invalid params"); }

    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Node database not open");
        LOG_FAIL("blockchain", "importchainstate: node database not open");
    }

    printf("importchainstate: opening %s...\n", cs_path);
    fflush(stdout);

    struct coins_view_db ext_db;
    memset(&ext_db, 0, sizeof(ext_db));
    if (!coins_view_db_open(&ext_db, cs_path, 256, false, false)) {
        json_set_str(result, "Cannot open chainstate LevelDB");
        LOG_FAIL("blockchain", "importchainstate: cannot open LevelDB at %s", cs_path);
    }

    /* Read best block hash from LevelDB before importing.
     * This is the height at which the UTXO set was snapshotted. */
    struct uint256 ldb_best_block;
    memset(&ldb_best_block, 0, sizeof(ldb_best_block));
    coins_view_db_get_best_block(&ext_db, &ldb_best_block);
    if (uint256_is_null(&ldb_best_block)) {
        coins_view_db_close(&ext_db);
        json_set_str(result, "LevelDB chainstate best block is unset");
        LOG_FAIL("blockchain", "importchainstate: best block is unset");
    }
    if (!ctx->main_state) {
        coins_view_db_close(&ext_db);
        json_set_str(result, "Main chain state not available");
        LOG_FAIL("blockchain", "importchainstate: main state not available");
    }
    struct block_index *ldb_tip = block_map_find(
        &ctx->main_state->map_block_index, &ldb_best_block);
    if (!ldb_tip || !ldb_tip->phashBlock) {
        coins_view_db_close(&ext_db);
        json_set_str(result,
                     "LevelDB best block is not verified in the block index");
        LOG_FAIL("blockchain",
                 "importchainstate: best block missing from block index");
    }

    struct node_db import_db;
    struct node_db *import_target = ctx->node_db;
    if (node_db_sync_open_private_db_like(ctx->node_db, &import_db))
        import_target = &import_db;

    int count = node_db_sync_import_utxos(import_target, &ext_db);
    if (import_target == &import_db)
        node_db_close(&import_db);
    coins_view_db_close(&ext_db);

    if (count < 0) {
        json_set_str(result, "Import failed");
        LOG_FAIL("blockchain", "importchainstate: UTXO import failed (count=%d)", count);
    }

    /* Fix height=0 UTXOs from transaction index (LevelDB decoder can
     * fail to read the trailing height varint for some entries). */
    {
        int64_t h0_count = db_utxo_count_missing_heights(ctx->node_db);
        if (h0_count > 0) {
            printf("importchainstate: fixing %lld UTXOs with height=0...\n",
                   (long long)h0_count);
            int fixed = db_utxo_repair_missing_heights_from_tx_index(ctx->node_db);
            printf("importchainstate: fixed %d UTXO heights\n",
                   fixed);
        }
    }

    if (!db_utxo_rebuild_wallet_and_address_caches(ctx->node_db)) {
        json_set_str(result, "Failed to rebuild wallet/address caches");
        LOG_FAIL("blockchain",
                 "importchainstate: failed to rebuild wallet/address caches");
    }

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_UTXO_REPAIR,
        .decision = POLICY_ALLOW,
        .from_height = active_chain_height(&ctx->main_state->chain_active),
        .to_height = ldb_tip->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "leveldb_chainstate_best_block_indexed",
        .reason = "rpc.importchainstate",
    };
    struct chain_state_commit commit = {
        .new_tip = ldb_tip,
        .new_coins_best = *ldb_tip->phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = true,
        .persist_coins_best = true,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = "rpc.importchainstate",
    };
    enum csr_result csr_rc = csr_commit_tip(csr_instance(), &commit);
#ifdef ZCL_TESTING
    if (csr_rc == CSR_REJECTED_NOT_INITIALIZED) {
        coins_view_cache_set_best_block(ctx->coins_tip, ldb_tip->phashBlock);
        csr_rc = CSR_OK;
    }
#endif
    if (csr_rc != CSR_OK) {
        json_set_str(result, "CSR rejected imported chainstate tip");
        LOG_FAIL("blockchain",
                 "importchainstate: csr rejected imported tip (%s)",
                 csr_result_name(csr_rc));
    }

    json_set_object(result);
    json_push_kv_int(result, "utxos_imported", count);

    /* Report balance */
    int64_t total_value = db_utxo_total_value(ctx->node_db);
    if (total_value < 0) {
        json_set_str(result, "Failed to read imported UTXO total");
        LOG_FAIL("blockchain",
                 "importchainstate: failed to read imported UTXO total");
    }
    json_push_kv_int(result, "total_value_zatoshi", total_value);
    json_push_kv_int(result, "wallet_balance_zatoshi",
                     db_wallet_utxo_balance(ctx->node_db));

    printf("importchainstate: done — %d UTXOs imported\n", count);
    fflush(stdout);
    return true;
}
