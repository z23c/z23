/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/wallet_diagnostic_controller.h"
#include "controllers/rpc_chainstate_guard.h"
#include "controllers/wallet_helpers.h"
#include "controllers/strong_params.h"
#include "wallet_diagnostic_internal.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "chain/chainparams.h"
#include "encoding/utilmoneystr.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "sapling/fast_scan.h"
#include <stdatomic.h>
#include "script/standard.h"
#include "support/cleanse.h"
#include "core/utiltime.h"
#include "core/random.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/txmempool.h"
#include "wallet/wallet_sqlite.h"
#include "net/connman.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include "sapling/incremental_merkle_tree.h"
#include "consensus/upgrades.h"
#include "models/database.h"
#include "models/block.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/mempool_entry.h"
#include "models/peer.h"
#include "controllers/wallet_scan.h"
#include "models/chain_snapshot.h"
#include "controllers/legacy_import.h"
#include "core/serialize.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "views/wallet_view.h"
#include <stdio.h>
#include <stdlib.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <time.h>

/* wallet-diagnostic repair RPCs: destructive wallet/DB mutations. */

bool rpc_scanblockfiles(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "scanblockfiles\n"
        "\nScan all block files on disk for wallet transactions.\n"
        "Faster than rescanblockchain — reads raw block files sequentially.\n"
        "Updates the spent-outpoint index for accurate balances.\n");

    ENSURE_WALLET(result);

    char default_dir[4096];
    const char *dir = ctx->datadir;
    if (!dir || !dir[0]) {
        const char *home = getenv("HOME");
        (void)snprintf(default_dir, sizeof(default_dir), "%s/.zclassic-c23",
                       home && home[0] ? home : ".");
        dir = default_dir;
    }
    int found = wallet_scan_blockfiles(ctx->wallet, dir);

    /* Also persist wallet updates */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_sqlite_flush_r(ctx->wallet_db, ctx->wallet);
        if (!fr.ok) {
            LOG_FAIL("wallet", "scanblocksindex: post-scan flush failed "
                                "(code=%d): %s", fr.code, fr.message);
        }
    }

    json_set_object(result);
    json_push_kv_int(result, "wallet_outputs_found", found);
    json_push_kv_int(result, "spent_outpoints", (int64_t)ctx->wallet->num_spent);

    /* Report corrected balance */
    int64_t balance = wallet_get_balance(ctx->wallet);
    char tbal[32], zbal[32];
    format_amount(balance, tbal, sizeof(tbal));
    json_push_kv_real(result, "transparent_balance", strtod(tbal, NULL));

    int64_t z_balance = wallet_get_sapling_balance(ctx->wallet);
    format_amount(z_balance, zbal, sizeof(zbal));
    json_push_kv_real(result, "shielded_balance", strtod(zbal, NULL));

    return true;
}
bool rpc_reindexdb(const struct json_value *params, bool help,
                          struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "reindexdb\n"
        "Wipes wallet_utxos, wallet_transactions, and wallet_sapling_notes,\n"
        "then re-scans all blocks from disk to rebuild them.\n"
        "Returns the corrected balance.\n");

    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "SQLite database not available");
        return false;
    }
    if (!ctx->wallet) {
        json_set_str(result, "Wallet not loaded");
        return false;
    }
    if (!ctx->main_state) {
        json_set_str(result, "Chain state not available");
        return false;
    }

    int chain_tip = active_chain_height(&ctx->main_state->chain_active);
    printf("reindexdb: fast wallet scan of %d blocks...\n", chain_tip + 1);
    fflush(stdout);

    int found = wallet_scan_blocks(ctx->node_db,
        &ctx->main_state->chain_active, ctx->wallet, ctx->datadir,
        0, chain_tip);

    /* Persist the repaired wallet through the encryption-aware writer —
     * the single writer of the wallet key tables (the old plaintext
     * mirror sync was removed). */
    if (ctx->wallet_db) {
        struct zcl_result fr = wallet_sqlite_flush_r(ctx->wallet_db,
                                                     ctx->wallet);
        if (!fr.ok) {
            LOG_FAIL("wallet", "reindexdb: post-scan flush failed "
                               "(code=%d): %s", fr.code, fr.message);
        }
    }

    json_set_object(result);
    json_push_kv_int(result, "blocks_scanned", chain_tip + 1);
    json_push_kv_int(result, "wallet_transactions", found);

    int64_t t_bal = db_wallet_utxo_balance(ctx->node_db);
    char bal_str[32];
    format_amount(t_bal, bal_str, sizeof(bal_str));
    json_push_kv_str(result, "wallet_t_balance", bal_str);

    int64_t z_bal = db_sapling_note_balance(ctx->node_db);
    char zbal_str[32];
    format_amount(z_bal, zbal_str, sizeof(zbal_str));
    json_push_kv_str(result, "wallet_z_balance", zbal_str);

    int64_t total = t_bal + z_bal;
    char tot_str[32];
    format_amount(total, tot_str, sizeof(tot_str));
    json_push_kv_str(result, "total_balance", tot_str);

    struct db_wallet_utxo utxos[256];
    int utxo_count = db_wallet_utxo_list_unspent(ctx->node_db, utxos, 256);
    json_push_kv_int(result, "unspent_utxos", utxo_count);

    printf("reindexdb: complete — balance %s ZCL (%d UTXOs)\n",
           tot_str, utxo_count);
    fflush(stdout);

    return true;
}
bool rpc_importlegacy(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "importlegacy ( \"datadir\" )\n"
        "Import wallet data from a stopped legacy C++ node's data directory.\n"
        "Reads the LevelDB block index and scans block files directly.\n"
        "The legacy node MUST be stopped first.\n"
        "\nArguments:\n"
        "1. datadir  (string, optional) Legacy data directory "
        "(default: ~/.zclassic)\n"
        "\nResult: { blocks_scanned, wallet_transactions, balance }\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    const char *legacy_dir = rpc_permit_str(&p, 0, "datadir", NULL);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "SQLite database not available");
        return false;
    }
    if (!ctx->wallet) {
        json_set_str(result, "Wallet not loaded");
        return false;
    }

    char default_dir[512];
    if (!legacy_dir || legacy_dir[0] == '\0') {
        const char *home = getenv("HOME");
        snprintf(default_dir, sizeof(default_dir),
                 "%s/.zclassic", home ? home : "/root");
        legacy_dir = default_dir;
    }

    printf("importlegacy: importing from %s...\n", legacy_dir);
    fflush(stdout);

    int found = legacy_import(legacy_dir, ctx->node_db, ctx->wallet, true);
    if (found < 0) {
        json_set_str(result,
            "Import failed — is the legacy node stopped?");
        return false;
    }

    json_set_object(result);
    json_push_kv_int(result, "wallet_transactions", found);

    int64_t t_bal = db_wallet_utxo_balance(ctx->node_db);
    char bal_str[32];
    format_amount(t_bal, bal_str, sizeof(bal_str));
    json_push_kv_str(result, "wallet_t_balance", bal_str);

    int64_t z_bal = db_sapling_note_balance(ctx->node_db);
    char zbal_str[32];
    format_amount(z_bal, zbal_str, sizeof(zbal_str));
    json_push_kv_str(result, "wallet_z_balance", zbal_str);

    int64_t total = t_bal + z_bal;
    char tot_str[32];
    format_amount(total, tot_str, sizeof(tot_str));
    json_push_kv_str(result, "total_balance", tot_str);

    struct db_wallet_utxo utxos[256];
    int utxo_count = db_wallet_utxo_list_unspent(ctx->node_db, utxos, 256);
    json_push_kv_int(result, "unspent_utxos", utxo_count);

    return true;
}
bool rpc_removestalletxs(const struct json_value *params,
                                 bool help, struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "removestalletxs\n"
        "Remove unconfirmed wallet transactions whose inputs are\n"
        "already spent on-chain (dead transactions). Rebuilds the\n"
        "spent set and verifies UTXOs against the chainstate.");

    ENSURE_WALLET(result);
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "removestalletxs",
            "Chainstate lookup"))
        return false;
    json_set_object(result);

    /* Phase 1: Find unconfirmed txs whose inputs are spent on-chain */
    int removed = 0;
    int64_t recovered = 0;
    struct json_value removed_list = {0};
    json_init(&removed_list);
    json_set_array(&removed_list);

    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!ctx->wallet->map_wallet[i].used)
            continue;
        struct wallet_tx *wtx = &ctx->wallet->map_wallet[i];
        if (wtx->confirms > 0)
            continue; /* skip confirmed txs */
        if (!wtx->from_me)
            continue; /* skip received unconfirmed */

        /* Check if any input's prevout is spent on-chain
         * (i.e., NOT in the current UTXO set) */
        bool any_input_spent = false;
        if (ctx->coins_tip) {
            for (size_t j = 0; j < wtx->tx.num_vin; j++) {
                struct coins c;
                coins_init(&c);
                bool found = coins_view_cache_get_coins(ctx->coins_tip,
                    &wtx->tx.vin[j].prevout.hash, &c);
                bool avail = found && coins_is_available(&c,
                    wtx->tx.vin[j].prevout.n);
                coins_free(&c);
                if (!avail) {
                    any_input_spent = true;
                    break;
                }
            }
        }

        if (!any_input_spent)
            continue; /* inputs still unspent, tx might still be valid */

        /* This tx's inputs are spent — it's a dead transaction.
         * Sum the value of outputs that were "locked" by this dead tx */
        int64_t locked_val = 0;
        for (size_t j = 0; j < wtx->tx.num_vout; j++) {
            if (wallet_is_mine(ctx->wallet, &wtx->tx.vout[j]))
                locked_val += wtx->tx.vout[j].value;
        }

        char txid[65];
        uint256_get_hex(&wtx->tx.hash, txid);

        struct json_value entry = {0};
        json_init(&entry);
        json_set_object(&entry);
        json_push_kv_str(&entry, "txid", txid);
        char s[32];
        format_amount(locked_val, s, sizeof(s));
        json_push_kv_real(&entry, "locked_value", strtod(s, NULL));
        json_push_back(&removed_list, &entry);
        json_free(&entry);

        /* Remove the dead tx */
        transaction_free(&wtx->tx);
        memset(wtx, 0, sizeof(*wtx));
        ctx->wallet->num_wallet_tx--;
        removed++;
        recovered += locked_val;
    }

    /* Phase 2: Rebuild spent set from remaining wallet txs.
     * Do NOT call wallet_verify_utxos here — the C23 chainstate may be
     * incomplete and would incorrectly prune valid UTXOs that exist
     * on-chain but are missing from our coins cache. */
    if (removed > 0) {
        wallet_rebuild_spent_set(ctx->wallet);
    }

    /* Compute new balance */
    int64_t new_balance = wallet_get_balance(ctx->wallet);
    char bal_str[32];
    format_amount(new_balance, bal_str, sizeof(bal_str));

    json_push_kv_int(result, "removed", removed);
    char rec_str[32];
    format_amount(recovered, rec_str, sizeof(rec_str));
    json_push_kv_real(result, "recovered_value", strtod(rec_str, NULL));
    json_push_kv_real(result, "new_balance", strtod(bal_str, NULL));
    json_push_kv_int(result, "wallet_tx_count",
                     (int64_t)ctx->wallet->num_wallet_tx);
    json_push_kv(&result[0], "removed_txs", &removed_list);
    json_free(&removed_list);

    return true;
}
bool rpc_reconcilewalletutxos(const struct json_value *params,
                                      bool help, struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "reconcilewalletutxos ( fix )\n"
        "Verify every wallet UTXO against chainstate.\n"
        "Classifies each as: verified, phantom, spent_on_chain, value_mismatch.\n"
        "If fix=true, marks phantoms and spent-on-chain as spent in both\n"
        "in-memory wallet and SQLite.\n"
        "\nArguments:\n"
        "1. fix    (bool, optional, default=false) Fix mismatches\n");

    ENSURE_WALLET(result);
    if (!ctx->coins_tip) {
        json_set_str(result, "Chainstate (coins DB) not available");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
            "reconcilewalletutxos", "Chainstate lookup"))
        return false;
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    bool fix = rpc_permit_bool(&p, 0, "fix", false);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    int64_t balance_before = db_wallet_utxo_balance(ctx->node_db);

    struct db_wallet_utxo unspent[4096];
    int count = db_wallet_utxo_list_unspent(ctx->node_db, unspent, 4096);

    int verified = 0, phantom = 0, spent_on_chain = 0, mismatched = 0;
    int fixed = 0;
    static const uint8_t RECONCILE_SENTINEL[32] = {
        0xff, 0x00, 0xff, 0x00, 'R', 'E', 'C', 'O',
        'N', 'C', 'I', 'L', 'E', 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    struct json_value details = {0};
    json_set_array(&details);

    for (int i = 0; i < count; i++) {
        struct uint256 tid;
        memcpy(tid.data, unspent[i].txid, 32);

        struct coins c;
        coins_init(&c);
        bool found = coins_view_cache_get_coins(ctx->coins_tip, &tid, &c);
        bool available = found && coins_is_available(&c, unspent[i].vout);
        int64_t chain_val = 0;
        if (available && unspent[i].vout < c.num_vout)
            chain_val = c.vout[unspent[i].vout].value;
        coins_free(&c);

        const char *status;
        if (!found) {
            status = "phantom";
            phantom++;
        } else if (!available) {
            status = "spent_on_chain";
            spent_on_chain++;
        } else if (chain_val != unspent[i].value) {
            status = "value_mismatch";
            mismatched++;
        } else {
            status = "verified";
            verified++;
            continue;
        }

        char txid_hex[65];
        for (int b = 31; b >= 0; b--)
            snprintf(txid_hex + (31 - b) * 2, 3, "%02x",
                     unspent[i].txid[b]);

        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_str(&entry, "txid", txid_hex);
        json_push_kv_int(&entry, "vout", unspent[i].vout);
        char amt[32];
        format_amount(unspent[i].value, amt, sizeof(amt));
        json_push_kv_str(&entry, "wallet_value", amt);
        json_push_kv_str(&entry, "status", status);

        if (fix) {
            db_wallet_utxo_mark_spent(ctx->node_db, unspent[i].txid,
                                       unspent[i].vout,
                                       RECONCILE_SENTINEL, 0);
            wallet_mark_outpoint_spent(ctx->wallet, &tid, unspent[i].vout);
            json_push_kv_bool(&entry, "fixed", true);
            fixed++;
        }

        json_push_back(&details, &entry);
        json_free(&entry);
    }

    int64_t balance_after = fix ? db_wallet_utxo_balance(ctx->node_db)
                                : balance_before;

    if (fix) {
        node_db_state_set_int(ctx->node_db, "last_reconcile_height",
            ctx->main_state
                ? active_chain_height(&ctx->main_state->chain_active) : 0);
    }

    wallet_view_reconcile_summary(result, verified, phantom,
        spent_on_chain, mismatched, fixed, balance_before, balance_after);
    json_push_kv(result, "issues", &details);
    json_free(&details);
    return true;
}
bool rpc_purgephantomutxos(const struct json_value *params,
                                   bool help, struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "purgephantomutxos confirm ( dryrun )\n"
        "Delete phantom UTXOs from the wallet SQLite database.\n"
        "Phantoms are wallet UTXOs not present in chainstate.\n"
        "\nArguments:\n"
        "1. confirm  (bool, required) Must be true to proceed\n"
        "2. dryrun   (bool, optional, default=false) Report without deleting\n");

    ENSURE_WALLET(result);
    if (!ctx->coins_tip) {
        json_set_str(result, "Chainstate (coins DB) not available");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
            "purgephantomutxos", "Chainstate lookup"))
        return false;
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }

    struct rpc_params p;
    rpc_params_init(&p, params);
    bool confirm = rpc_require_bool(&p, 0, "confirm");
    bool dryrun = rpc_permit_bool(&p, 1, "dryrun", false);
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        return false;
    }

    if (!confirm) {
        json_set_str(result,
            "Safety interlock: pass confirm=true to proceed");
        return false;
    }

    int64_t balance_before = db_wallet_utxo_balance(ctx->node_db);

    struct db_wallet_utxo unspent[4096];
    int count = db_wallet_utxo_list_unspent(ctx->node_db, unspent, 4096);

    int utxos_deleted = 0;
    int txs_deleted = 0;
    int64_t amount_purged = 0;

    if (!wallet_diag_begin_checked(ctx->node_db, "purge-orphans begin")) {
        json_set_str(result, "Failed to begin orphan purge transaction");
        return false;
    }

    for (int i = 0; i < count; i++) {
        struct uint256 tid;
        memcpy(tid.data, unspent[i].txid, 32);

        struct coins c;
        coins_init(&c);
        bool found = coins_view_cache_get_coins(ctx->coins_tip, &tid, &c);
        bool available = found && coins_is_available(&c, unspent[i].vout);
        coins_free(&c);

        if (available)
            continue;

        amount_purged += unspent[i].value;

        if (!dryrun) {
            if (!db_wallet_utxo_delete(ctx->node_db, unspent[i].txid,
                                       unspent[i].vout)) {
                wallet_diag_rollback_best_effort(ctx->node_db,
                                                 "purge-orphans rollback");
                json_set_str(result, "Failed to delete orphan wallet UTXO");
                return false;
            }
            wallet_mark_outpoint_spent(ctx->wallet, &tid, unspent[i].vout);
        }
        utxos_deleted++;

        if (!dryrun) {
            int remaining = db_wallet_utxo_count_for_tx(ctx->node_db,
                                                         unspent[i].txid);
            if (remaining == 0) {
                if (!db_wallet_tx_delete(ctx->node_db, unspent[i].txid)) {
                    wallet_diag_rollback_best_effort(ctx->node_db,
                                                     "purge-orphans rollback");
                    json_set_str(result,
                                 "Failed to delete orphan wallet transaction");
                    return false;
                }
                txs_deleted++;
            }
        }
    }

    if (!dryrun) {
        if (!wallet_diag_commit_checked(ctx->node_db,
                                        "purge-orphans commit")) {
            json_set_str(result, "Failed to commit orphan purge transaction");
            return false;
        }
        wallet_rebuild_spent_set(ctx->wallet);
    } else {
        wallet_diag_rollback_best_effort(ctx->node_db, "purge-orphans dry-run rollback");
    }

    int64_t balance_after = dryrun ? balance_before
                                   : db_wallet_utxo_balance(ctx->node_db);

    wallet_view_purge_summary(result, utxos_deleted, txs_deleted,
        amount_purged, balance_before, balance_after);
    json_push_kv_bool(result, "dryrun", dryrun);
    return true;
}
