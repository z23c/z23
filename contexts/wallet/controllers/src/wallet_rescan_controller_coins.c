/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * coinanalysis RPC: compare wallet-tracked UTXOs against chainstate and
 * report recoverable transparent balance. */

#include "controllers/wallet_rescan_controller_internal.h"

bool rpc_coinanalysis(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "coinanalysis\n"
        "Full chain analysis: for every wallet key, queries chainstate for\n"
        "unspent outputs. Compares against wallet's tracked UTXOs to find\n"
        "missing (untracked) coins. Reports total recoverable balance.");

    ENSURE_WALLET(result);
    if (!ctx->coins_tip) {
        json_set_str(result, "Chainstate not available");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
            "coinanalysis", "Chainstate lookup"))
        return false;
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }

    json_set_object(result);

    /* Get all wallet-tracked unspent UTXOs */
    struct db_wallet_utxo tracked[4096];
    int tracked_count = db_wallet_utxo_list_unspent(ctx->node_db, tracked, 4096);

    int64_t tracked_balance = 0;
    for (int i = 0; i < tracked_count; i++)
        tracked_balance += tracked[i].value;

    /* Scan all wallet transactions for outputs to our keys
     * that aren't in our tracked UTXO set */
    int untracked_count = 0;
    int64_t untracked_balance = 0;
    struct json_value untracked_arr = {0};
    json_set_array(&untracked_arr);

    /* Iterate all wallet transactions (from in-memory wallet) */
    for (size_t ti = 0; ti < ctx->wallet->num_wallet_tx; ti++) {
        const struct wallet_tx *wtx = &ctx->wallet->map_wallet[ti];
        for (size_t vi = 0; vi < wtx->tx.num_vout; vi++) {
            const struct tx_out *out = &wtx->tx.vout[vi];

            /* Check if output goes to one of our keys */
            struct tx_destination dest;
            if (!script_extract_destination(&out->script_pub_key, &dest))
                continue;
            if (dest.type != DEST_KEY_ID) continue;

            struct privkey test_key;
            if (!keystore_get_key(&ctx->wallet->keystore,
                                   &dest.id.key, &test_key))
                continue;
            memory_cleanse(test_key.vch, 32);

            /* It's ours. Check if tracked in SQLite */
            bool is_tracked = false;
            for (int j = 0; j < tracked_count; j++) {
                if (memcmp(tracked[j].txid, wtx->tx.hash.data, 32) == 0 &&
                    tracked[j].vout == (uint32_t)vi) {
                    is_tracked = true;
                    break;
                }
            }

            /* Check chainstate: is it actually unspent? */
            struct coins c;
            coins_init(&c);
            bool in_chain = coins_view_cache_get_coins(
                ctx->coins_tip, &wtx->tx.hash, &c);
            bool available = in_chain &&
                coins_is_available(&c, (unsigned int)vi);
            coins_free(&c);

            if (available && !is_tracked) {
                untracked_count++;
                untracked_balance += out->value;

                char addr[128];
                wallet_encode_destination(&dest, addr, sizeof(addr));

                char txid_hex[65];
                uint256_get_hex(&wtx->tx.hash, txid_hex);

                struct json_value entry = {0};
                json_set_object(&entry);
                json_push_kv_str(&entry, "txid", txid_hex);
                json_push_kv_int(&entry, "vout", (int64_t)vi);
                json_push_kv_str(&entry, "address", addr);

                char amt[32];
                format_amount(out->value, amt, sizeof(amt));
                json_push_kv_str(&entry, "amount", amt);
                json_push_kv_int(&entry, "confirmations",
                                  (int64_t)wtx->confirms);
                json_push_back(&untracked_arr, &entry);
                json_free(&entry);
            }
        }
    }

    /* Shielded analysis — all notes (spent and unspent) */
    int64_t z_balance = 0;
    int z_unspent = 0;
    int z_spent = 0;
    int64_t z_total_received = 0;
    struct json_value z_arr = {0};
    json_set_array(&z_arr);

    /* Query all sapling notes (both spent and unspent) via the model. */
    static struct db_sapling_note z_notes[8192];
    int z_note_count = db_sapling_note_list_all_analysis(ctx->node_db,
                                                         z_notes, 8192);
    for (int zi = 0; zi < z_note_count; zi++) {
        const struct db_sapling_note *n = &z_notes[zi];
        int64_t nval = n->value;
        bool is_spent = n->is_spent;
        z_total_received += nval;
        if (!is_spent) {
            z_balance += nval;
            z_unspent++;
        } else {
            z_spent++;
        }

        struct json_value ze = {0};
        json_set_object(&ze);

        char txid_hex[65];
        wallet_txid_hex_le(n->txid, txid_hex);
        json_push_kv_str(&ze, "txid", txid_hex);
        json_push_kv_int(&ze, "output_index", (int)n->output_index);

        json_push_kv_str(&ze, "address", n->address);

        char zamt[32];
        format_amount(nval, zamt, sizeof(zamt));
        json_push_kv_str(&ze, "amount", zamt);
        json_push_kv_int(&ze, "block_height", n->block_height);
        json_push_kv_str(&ze, "status", is_spent ? "spent" : "unspent");

        if (is_spent) {
            char spent_hex[65];
            wallet_txid_hex_le(n->spent_txid, spent_hex);
            json_push_kv_str(&ze, "spent_by", spent_hex);
        }

        if (n->witness_height > 0)
            json_push_kv_int(&ze, "witness_height", n->witness_height);

        json_push_back(&z_arr, &ze);
        json_free(&ze);
    }

    /* Fee accounting from wallet transactions */
    int tx_count = 0;
    int64_t total_fees = db_wallet_tx_total_fees(ctx->node_db, &tx_count);

    /* Summary */
    char amt[32];
    json_push_kv_int(result, "tracked_utxos", tracked_count);
    format_amount(tracked_balance, amt, sizeof(amt));
    json_push_kv_str(result, "tracked_balance", amt);
    json_push_kv_int(result, "untracked_utxos", untracked_count);
    format_amount(untracked_balance, amt, sizeof(amt));
    json_push_kv_str(result, "untracked_balance", amt);

    json_push_kv_int(result, "shielded_unspent", z_unspent);
    json_push_kv_int(result, "shielded_spent", z_spent);
    format_amount(z_balance, amt, sizeof(amt));
    json_push_kv_str(result, "shielded_balance", amt);
    format_amount(z_total_received, amt, sizeof(amt));
    json_push_kv_str(result, "shielded_total_received", amt);

    int64_t grand_total = tracked_balance + untracked_balance + z_balance;
    format_amount(grand_total, amt, sizeof(amt));
    json_push_kv_str(result, "total_balance", amt);

    format_amount(total_fees, amt, sizeof(amt));
    json_push_kv_str(result, "total_fees_paid", amt);
    json_push_kv_int(result, "fee_paying_txns", tx_count);

    json_push_kv(result, "untracked", &untracked_arr);
    json_free(&untracked_arr);
    json_push_kv(result, "shielded_notes_detail", &z_arr);
    json_free(&z_arr);

    for (int i = 0; i < tracked_count; i++)
        db_wallet_utxo_free(&tracked[i]);

    return true;
}
