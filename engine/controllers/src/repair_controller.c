/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * UTXO repair: scan ahead through blocks on zclassicd, find inputs whose
 * UTXOs are missing locally, fetch and insert them so connect_block succeeds.
 */

#include "controllers/repair_controller_internal.h"

struct repair_context g_repair_ctx = {0};

void rpc_repair_set_state(struct main_state *ms,
                           struct coins_view_cache *coins_tip,
                           struct node_db *ndb,
                           const char *datadir,
                           const struct chain_params *params)
{
    struct repair_context *ctx = repair_ctx();
    ctx->main_state = ms;
    ctx->coins_tip = coins_tip;
    ctx->node_db = ndb;
    ctx->datadir = datadir;
    ctx->params = params;
}

static bool rpc_repairheights(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct repair_context *ctx = repair_ctx();
    (void)params;
    RPC_HELP(help, result,
        "repairheights\n"
        "\nFixes UTXOs with height=0 by looking up the creating transaction\n"
        "in the transaction index. This repairs HODL wave calculations that\n"
        "show incorrect age distributions.\n"
        "\nThe LevelDB import pipeline sometimes fails to decode the height\n"
        "varint from coins entries, leaving height=0. This command fixes\n"
        "those entries using the transaction → block_height mapping.\n");

    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Database not available");
        return false;
    }

    int64_t t0 = (int64_t)platform_time_wall_time_t();

    int64_t before = db_utxo_count_missing_heights(ctx->node_db);
    if (before < 0) {
        json_set_str(result, "Failed to count height=0 UTXOs");
        LOG_FAIL("repair", "repairheights: count before failed");
    }

    if (before == 0) {
        json_set_object(result);
        json_push_kv_int(result, "fixed", 0);
        json_push_kv_str(result, "status", "no height=0 UTXOs to fix");
        return true;
    }

    printf("repairheights: fixing %lld UTXOs with height=0...\n",
           (long long)before);
    fflush(stdout);

    int changes = db_utxo_repair_missing_heights_from_tx_index(ctx->node_db);
    if (changes < 0) {
        json_set_str(result, "Failed to repair height=0 UTXOs");
        LOG_FAIL("repair", "repairheights: update failed");
    }

    int64_t after = db_utxo_count_missing_heights(ctx->node_db);
    if (after < 0) {
        json_set_str(result, "Failed to count remaining height=0 UTXOs");
        LOG_FAIL("repair", "repairheights: count after failed");
    }

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    printf("repairheights: fixed %d heights in %llds (%lld remaining)\n",
           changes, (long long)elapsed, (long long)after);
    fflush(stdout);

    json_set_object(result);
    json_push_kv_int(result, "fixed", changes);
    json_push_kv_int(result, "remaining_height_zero", after);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
    return true;
}

/* ── rescanblockfiles — re-scan all blk*.dat files ────────────── */

static bool rpc_rescanblockfiles(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct repair_context *ctx = repair_ctx();
    RPC_HELP(help, result,
        "rescanblockfiles\n"
        "\nRe-scan all blk*.dat block files, matching them against the block\n"
        "index and setting BLOCK_HAVE_DATA for every match. Useful after\n"
        "copying block files from zclassicd.\n"
        "\nResult:\n"
        "  {\n"
        "    \"marked\": n,      (numeric) blocks newly marked with BLOCK_HAVE_DATA\n"
        "    \"total_index\": n, (numeric) total block index entries\n"
        "    \"have_data\": n,   (numeric) entries with BLOCK_HAVE_DATA\n"
        "    \"elapsed_s\": n    (numeric) scan time in seconds\n"
        "  }\n");
    (void)params;

    if (!ctx->main_state || !ctx->datadir || !ctx->params) {
        json_set_str(result, "node not ready");
        return false;
    }

    int64_t t0 = (int64_t)platform_time_wall_time_t();
    printf("RPC rescanblockfiles: starting full block file scan...\n");
    fflush(stdout);

    int marked = scan_block_files_mark_data(ctx->main_state,
                                             ctx->datadir, ctx->params);

    /* Propagate nChainTx + nChainWork so find_most_work_chain can
     * consider newly-marked blocks as chain tip candidates. */
    int propagated = propagate_nchaintx(ctx->main_state);
    if (propagated > 0)
        printf("RPC rescanblockfiles: propagated nChainTx for %d blocks\n",
               propagated);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    /* Count index stats */
    size_t total_entries = 0, have_data_entries = 0;
    {
        size_t si = 0;
        struct block_index *sb;
        while (block_map_next(&ctx->main_state->map_block_index,
                               &si, NULL, &sb)) {
            if (!sb) continue;
            total_entries++;
            if (sb->nStatus & BLOCK_HAVE_DATA)
                have_data_entries++;
        }
    }

    json_set_object(result);
    json_push_kv_int(result, "marked", marked);
    json_push_kv_int(result, "total_index", (int64_t)total_entries);
    json_push_kv_int(result, "have_data", (int64_t)have_data_entries);
    json_push_kv_int(result, "elapsed_s", elapsed);

    printf("RPC rescanblockfiles: %d marked, %zu/%zu have data (%llds)\n",
           marked, have_data_entries, total_entries, (long long)elapsed);
    fflush(stdout);

    /* Diagnostic: verify coins_best_block matches active chain tip */
    {
        struct uint256 coins_best;
        coins_view_cache_get_best_block(ctx->coins_tip, &coins_best);
        struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
        if (tip && tip->phashBlock &&
            uint256_cmp(&coins_best, tip->phashBlock) != 0) {
            char cbhex[65], tiphex[65];
            uint256_get_hex(&coins_best, cbhex);
            uint256_get_hex(tip->phashBlock, tiphex);
            printf("RPC rescanblockfiles: WARNING coins_best_block=%s "
                   "!= tip=%s (h=%d) — connect_block will reconcile\n",
                   cbhex, tiphex, tip->nHeight);
        }
    }

    /* If we have blocks with data above our tip, trigger chain activation
     * to connect them immediately instead of waiting for header sync. */
    {
        int tip_h = active_chain_height(&ctx->main_state->chain_active);
        size_t above_tip = 0;
        size_t si2 = 0;
        struct block_index *sb2;
        while (block_map_next(&ctx->main_state->map_block_index,
                               &si2, NULL, &sb2)) {
            if (sb2 && (sb2->nStatus & BLOCK_HAVE_DATA) &&
                sb2->nHeight > tip_h)
                above_tip++;
        }
        json_push_kv_int(result, "tip_height", (int64_t)tip_h);

        /* Diagnostic: check next block after tip */
        {
            size_t di = 0;
            struct block_index *db;
            struct block_index *next_any = NULL;
            while (block_map_next(&ctx->main_state->map_block_index,
                                   &di, NULL, &db)) {
                if (db && db->nHeight == tip_h + 1) {
                    next_any = db;
                    if (db->nStatus & BLOCK_HAVE_DATA) break;
                }
            }
            if (next_any) {
                json_push_kv_int(result, "next_nChainTx",
                                  (int64_t)next_any->nChainTx);
                json_push_kv_int(result, "next_have_data",
                                  (next_any->nStatus & BLOCK_HAVE_DATA) ? 1 : 0);
                json_push_kv_int(result, "next_has_pprev",
                                  next_any->pprev ? 1 : 0);
                json_push_kv_int(result, "next_status",
                                  (int64_t)next_any->nStatus);
                /* Compare chain work: does next block beat the tip? */
                struct block_index *tip_bi = active_chain_tip(
                    &ctx->main_state->chain_active);
                if (tip_bi) {
                    int cmp = arith_uint256_compare(&next_any->nChainWork,
                                                     &tip_bi->nChainWork);
                    json_push_kv_int(result, "next_vs_tip_chainwork", cmp);
                    json_push_kv_int(result, "tip_nChainWork_zero",
                        arith_uint256_is_zero(&tip_bi->nChainWork) ? 1 : 0);
                    json_push_kv_int(result, "next_nChainWork_zero",
                        arith_uint256_is_zero(&next_any->nChainWork) ? 1 : 0);
                    /* Check block_index_is_valid for tip+1 */
                    json_push_kv_int(result, "next_valid_tree",
                        block_index_is_valid(next_any, BLOCK_VALID_TREE) ? 1 : 0);
                }
            }
        }

        if (above_tip > 0) {
            struct activation_exec_outcome ao;
            activation_request_connect(boot_activation_controller(),
                ACTIVATION_SRC_BLOCK_FILE_SCAN, NULL, &ao);
            json_push_kv_int(result, "activated_above_tip",
                              (int64_t)above_tip);
            json_push_kv_int(result, "activation_result",
                              (int64_t)ao.result);
            json_push_kv_str(result, "activation_reason", ao.reason);

            /* Check new tip after activation */
            int new_tip = active_chain_height(&ctx->main_state->chain_active);
            json_push_kv_int(result, "new_tip", (int64_t)new_tip);
        }
    }

    return true;
}

void register_repair_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "blockchain", "repairutxos", rpc_repairutxos, false },
        { "blockchain", "repairheights", rpc_repairheights, false },
        { "blockchain", "rescanblockfiles", rpc_rescanblockfiles, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
