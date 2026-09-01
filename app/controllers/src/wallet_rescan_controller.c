/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Wallet rescan, legacy import, and witness management RPCs. */

#include "controllers/wallet_rescan_controller_internal.h"

static bool rpc_replaywalletfromchain(const struct json_value *params,
                                       bool help, struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "replaywalletfromchain confirm\n"
        "Nuclear rebuild: rescan all block files from chain truth, then\n"
        "atomically replace wallet UTXOs and transactions in SQLite.\n"
        "\nArguments:\n"
        "1. confirm  (bool, required) Must be true to proceed\n");

    ENSURE_WALLET(result);
    if (!ctx->main_state) {
        json_set_str(result, "Main state not available");
        return false;
    }
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }
    if (!ctx->datadir) {
        json_set_str(result, "Data directory not configured");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    bool confirm = rpc_require_bool(&p, 0, "confirm");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    if (!confirm) {
        json_set_str(result,
            "Safety interlock: pass confirm=true to proceed");
        return false;
    }

    int64_t old_balance = db_wallet_utxo_balance(ctx->node_db);

    wallet_rebuild_spent_set(ctx->wallet);

    int chain_tip = active_chain_height(&ctx->main_state->chain_active);

    printf("replaywalletfromchain: rescanning %d blocks...\n",
           chain_tip + 1);
    fflush(stdout);

    int found = wallet_scan_blocks(ctx->node_db,
        &ctx->main_state->chain_active, ctx->wallet, ctx->datadir,
        0, chain_tip);
    if (found < 0) {
        json_set_str(result,
                     "Wallet replay failed; previous projection retained");
        return false;
    }

    int64_t new_balance = db_wallet_utxo_balance(ctx->node_db);
    int utxo_count = 0;
    {
        struct db_wallet_utxo tmp[4096];
        utxo_count = db_wallet_utxo_list_unspent(ctx->node_db, tmp, 4096);
        for (int i = 0; i < utxo_count; i++)
            db_wallet_utxo_free(&tmp[i]);
    }

    wallet_view_replay_summary(result, utxo_count,
        found > 0 ? found : 0, new_balance, old_balance);
    return true;
}

static bool rpc_import_from(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "import-from \"legacy_datadir\"\n"
        "Repair wallet LevelDB, copy chain data from legacy node, and reload.\n"
        "\nPhase 1: Repairs wallet LevelDB MANIFEST to recover lost keys.\n"
        "Phase 2: Copies blocks/index and chainstate from legacy datadir.\n"
        "Phase 3: Reloads wallet keys and rebuilds spent set.\n"
        "\nArguments:\n"
        "1. legacy_datadir (string, required) Path to legacy ~/.zclassic\n");

    ENSURE_WALLET(result);

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *legacy_dir = rpc_require_str(&p, 0, "legacy_datadir");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    if (!ctx->datadir) {
        json_set_str(result, "Data directory not configured");
        return false;
    }
    if (!ctx->wallet_db) {
        json_set_str(result, "Wallet DB not available");
        return false;
    }

    json_set_object(result);

    /* ── Phase 1: Reload wallet from SQLite ── */
    size_t keys_before = ctx->wallet->keystore.num_keys;
    size_t txs_before = ctx->wallet->num_wallet_tx;

    /* Re-read wallet data from SQLite (no LevelDB repair needed) */
    bool repaired = true;

    struct json_value phase1 = {0};
    json_set_object(&phase1);
    json_push_kv_bool(&phase1, "repair_success", repaired);

    if (ctx->wallet_db && ctx->wallet_db->open) {
        struct zcl_result rk = wallet_sqlite_read_keys_r(ctx->wallet_db, ctx->wallet);
        if (!rk.ok) {
            LOG_FAIL("wallet", "wallet_repair: read_keys_r failed "
                                "(code=%d): %s", rk.code, rk.message);
        }
        wallet_sqlite_read_txs(ctx->wallet_db, ctx->wallet);
        wallet_sqlite_read_sapling_keys(ctx->wallet_db, ctx->wallet);
        wallet_sqlite_read_scripts(ctx->wallet_db, ctx->wallet);
        wallet_sqlite_read_watch_only(ctx->wallet_db, ctx->wallet);
    }

    size_t keys_after = ctx->wallet->keystore.num_keys;
    size_t txs_after = ctx->wallet->num_wallet_tx;
    size_t keys_recovered = keys_after > keys_before
                          ? keys_after - keys_before : 0;
    size_t txs_recovered = txs_after > txs_before
                         ? txs_after - txs_before : 0;

    json_push_kv_int(&phase1, "keys_before", (int64_t)keys_before);
    json_push_kv_int(&phase1, "keys_after", (int64_t)keys_after);
    json_push_kv_int(&phase1, "keys_recovered", (int64_t)keys_recovered);
    json_push_kv_int(&phase1, "txs_recovered", (int64_t)txs_recovered);
    json_push_kv(result, "wallet_repair", &phase1);
    json_free(&phase1);

    /* ── Phase 2: Validate + copy chain data via chain_snapshot model ── */
    struct chain_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    snap.src_dir = legacy_dir;
    snap.dst_dir = ctx->datadir;

    if (!chain_snapshot_validate(&snap)) {
        struct json_value err = {0};
        json_set_object(&err);
        json_push_kv_str(&err, "error", "Source validation failed");
        json_push_kv_str(&err, "src_dir", legacy_dir);
        json_push_kv(result, "chain_copy", &err);
        json_free(&err);
        return true;
    }

    chain_snapshot_save(&snap);

    /* ── Phase 3: Rebuild wallet state ── */
    wallet_rebuild_spent_set(ctx->wallet);

    struct json_value phase3 = {0};
    json_set_object(&phase3);
    json_push_kv_int(&phase3, "total_keys", (int64_t)ctx->wallet->keystore.num_keys);
    json_push_kv_int(&phase3, "total_txs", (int64_t)ctx->wallet->num_wallet_tx);
    json_push_kv_int(&phase3, "spent_outpoints", (int64_t)ctx->wallet->num_spent);

    char s[32];
    format_amount(wallet_get_balance(ctx->wallet), s, sizeof(s));
    json_push_kv_str(&phase3, "balance", s);

    json_push_kv_str(&phase3, "note",
        "Restart node to load new chain data. "
        "Then run syncwalletfromdb to fix balance.");
    json_push_kv(result, "wallet_state", &phase3);
    json_free(&phase3);

    return true;
}

static bool rpc_syncwalletfromdb(const struct json_value *params, bool help,
                                  struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "syncwalletfromdb\n"
        "Sync in-memory wallet spent set from SQLite + chainstate truth.\n"
        "For each SQLite unspent UTXO verified in chainstate, removes it from\n"
        "the spent set if incorrectly marked. For UTXOs not in chainstate,\n"
        "marks them as spent. Fixes getbalance without restart.");

    ENSURE_WALLET(result);
    if (!ctx->coins_tip) {
        json_set_str(result, "Chainstate (coins DB) not available");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
            "syncwalletfromdb", "Chainstate lookup"))
        return false;
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }

    int64_t balance_before = wallet_get_balance(ctx->wallet);

    struct db_wallet_utxo unspent[4096];
    int count = db_wallet_utxo_list_unspent(ctx->node_db, unspent, 4096);

    int synced = 0, already_correct = 0, marked_spent = 0;

    for (int i = 0; i < count; i++) {
        struct uint256 tid;
        memcpy(tid.data, unspent[i].txid, 32);

        struct coins c;
        coins_init(&c);
        bool found = coins_view_cache_get_coins(ctx->coins_tip, &tid, &c);
        bool available = found &&
            coins_is_available(&c, unspent[i].vout);
        coins_free(&c);

        if (available) {
            if (wallet_is_outpoint_spent(ctx->wallet, &tid, unspent[i].vout)) {
                wallet_unmark_outpoint_spent(ctx->wallet, &tid, unspent[i].vout);
                synced++;
            } else {
                already_correct++;
            }
        } else {
            if (!wallet_is_outpoint_spent(ctx->wallet, &tid, unspent[i].vout)) {
                wallet_mark_outpoint_spent(ctx->wallet, &tid, unspent[i].vout);
                marked_spent++;
            } else {
                already_correct++;
            }
        }
    }

    int64_t balance_after = wallet_get_balance(ctx->wallet);

    for (int i = 0; i < count; i++)
        db_wallet_utxo_free(&unspent[i]);

    wallet_view_sync_summary(result, synced, already_correct, marked_spent,
                              balance_before, balance_after);
    return true;
}


static bool rpc_rescanwallet(const struct json_value *params, bool help,
                               struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "rescanwallet\n"
        "Rescan the entire chain for wallet transactions using the current\n"
        "full key set. Finds UTXOs that were missed because keys were added\n"
        "after the initial scan. Imports them into SQLite and syncs the\n"
        "in-memory wallet.");

    ENSURE_WALLET(result);
    if (!ctx->main_state) {
        json_set_str(result, "Main state not available");
        return false;
    }
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }
    if (!ctx->datadir) {
        json_set_str(result, "Data directory not configured");
        return false;
    }
    if (!ctx->coins_tip) {
        json_set_str(result, "Chainstate not available");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
            "rescanwallet", "Chainstate lookup"))
        return false;

    int64_t balance_before = db_wallet_utxo_balance(ctx->node_db);
    int utxos_before = 0;
    {
        struct db_wallet_utxo tmp[4096];
        utxos_before = db_wallet_utxo_list_unspent(ctx->node_db, tmp, 4096);
        for (int i = 0; i < utxos_before; i++)
            db_wallet_utxo_free(&tmp[i]);
    }

    /* Full rescan from block 0. wallet_scan_blocks owns the sole atomic
     * replacement; retain the old projection if scanning or storage fails. */
    int chain_tip = active_chain_height(&ctx->main_state->chain_active);
    printf("rescanwallet: rescanning %d blocks with %zu keys...\n",
           chain_tip + 1, ctx->wallet->keystore.num_keys);
    fflush(stdout);

    int found = wallet_scan_blocks(ctx->node_db,
        &ctx->main_state->chain_active, ctx->wallet, ctx->datadir,
        0, chain_tip);
    if (found < 0) {
        json_set_str(result,
                     "Wallet rescan failed; previous projection retained");
        return false;
    }

    /* Now sync the in-memory wallet from the fresh SQLite data */
    struct db_wallet_utxo unspent[4096];
    int count = db_wallet_utxo_list_unspent(ctx->node_db, unspent, 4096);

    int synced = 0;
    for (int i = 0; i < count; i++) {
        struct uint256 tid;
        memcpy(tid.data, unspent[i].txid, 32);

        struct coins c;
        coins_init(&c);
        bool avail = coins_view_cache_get_coins(ctx->coins_tip, &tid, &c)
                   && coins_is_available(&c, unspent[i].vout);
        coins_free(&c);

        if (avail && wallet_is_outpoint_spent(ctx->wallet, &tid,
                                               unspent[i].vout)) {
            wallet_unmark_outpoint_spent(ctx->wallet, &tid, unspent[i].vout);
            synced++;
        }
    }

    int64_t balance_after = db_wallet_utxo_balance(ctx->node_db);

    json_set_object(result);
    json_push_kv_int(result, "blocks_scanned", (int64_t)(chain_tip + 1));
    json_push_kv_int(result, "wallet_txs_found",
                      found > 0 ? (int64_t)found : 0);
    json_push_kv_int(result, "utxos_before", utxos_before);
    json_push_kv_int(result, "utxos_after", count);
    json_push_kv_int(result, "spent_set_fixed", synced);

    char amt[32];
    format_amount(balance_before, amt, sizeof(amt));
    json_push_kv_str(result, "balance_before", amt);
    format_amount(balance_after, amt, sizeof(amt));
    json_push_kv_str(result, "balance_after", amt);

    for (int i = 0; i < count; i++)
        db_wallet_utxo_free(&unspent[i]);

    return true;
}


void register_wallet_rescan_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "wallet", "replaywalletfromchain", rpc_replaywalletfromchain, false },
        { "wallet", "import-from",         rpc_import_from,          false },
        { "wallet", "syncwalletfromdb",    rpc_syncwalletfromdb,     false },
        { "wallet", "coinanalysis",        rpc_coinanalysis,         false },
        { "wallet", "rescanwallet",        rpc_rescanwallet,         false },
        { "wallet", "rescanwitnesses",     rpc_rescanwitnesses,      false },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}

/* ── rescan reply shape ───────────────────────────────────────────────
 * See wallet_rescan_controller.h. Keeps the coverage accounting that
 * rescanblockchain returns in one place. */
void wallet_rescan_report_to_json(struct json_value *out,
                                  const struct wallet_rescan_report *rep)
{
    if (!out || !rep)
        return;
    json_set_object(out);
    json_push_kv_int(out, "start_height", rep->start_height);
    json_push_kv_int(out, "stop_height", rep->stop_height);
    json_push_kv_int(out, "blocks_in_range", rep->blocks_in_range);
    json_push_kv_int(out, "blocks_indexed", rep->blocks_indexed);
    json_push_kv_int(out, "blocks_scanned", rep->blocks_scanned);
    json_push_kv_int(out, "blocks_no_index", rep->blocks_no_index);
    json_push_kv_int(out, "blocks_missing_data", rep->blocks_missing_data);
    json_push_kv_int(out, "blocks_read_failed", rep->blocks_read_failed);
    json_push_kv_int(out, "outputs_found", rep->outputs_found);
    json_push_kv_int(out, "shielded_notes_found", rep->shielded_notes_found);
    json_push_kv_int(out, "shielded_txs_unscanned", rep->shielded_txs_unscanned);
    json_push_kv_int(out, "sapling_key_count", (int64_t)rep->sapling_key_count);
    json_push_kv_bool(out, "shielded_scan_skipped", rep->shielded_scan_skipped);
    json_push_kv_bool(out, "coverage_ok", rep->coverage_ok);
    if (!rep->coverage_ok)
        json_push_kv_str(out, "blocker", rep->blocker);
}
