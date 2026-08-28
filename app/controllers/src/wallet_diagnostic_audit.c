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
#include "controllers/sync_controller.h"
#include "controllers/wallet_scan.h"
#include "models/chain_snapshot.h"
#include "controllers/legacy_import.h"
#include "core/serialize.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "views/wallet_view.h"
#include <stdio.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <string.h>

/* wallet-diagnostic audit RPCs: cross-reference UTXO + tx state, no mutations. */

bool rpc_walletaudit(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "walletaudit\n"
        "Definitive wallet balance audit.\n"
        "Verifies every wallet UTXO against the chainstate coins DB.\n"
        "Reports: verified balance, phantom UTXOs, spent-on-chain outputs,\n"
        "and per-address breakdown with chain-verified balances.");

    ENSURE_WALLET(result);

    if (!ctx->coins_tip) {
        json_set_str(result, "Chainstate (coins DB) not available");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
            "walletaudit", "Chainstate lookup"))
        return false;

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    int tip_height = ctx->main_state
        ? active_chain_height(&ctx->main_state->chain_active) : 0;

    json_set_object(result);
    json_push_kv_int(result, "chain_height", tip_height);

    /* Phase 1: Get all wallet UTXOs and verify each against chainstate */
    struct coin_entry wallet_coins[4096];
    size_t num_wallet_coins = 0;
    wallet_available_coins(ctx->wallet, wallet_coins, &num_wallet_coins,
                            4096, false, false);

    int64_t verified_balance = 0;
    int64_t phantom_balance = 0;
    int verified_count = 0;
    int phantom_count = 0;

    struct json_value verified_utxos = {0};
    json_set_array(&verified_utxos);
    struct json_value phantom_utxos = {0};
    json_set_array(&phantom_utxos);

    /* Per-address verified balance tracking */
    struct {
        char address[128];
        int64_t verified;
        int64_t phantom;
        int v_count;
        int p_count;
    } addr_bal[512];
    size_t num_addrs = 0;

    for (size_t i = 0; i < num_wallet_coins; i++) {
        const struct wallet_tx *wtx = wallet_coins[i].wtx;
        uint32_t vout_n = wallet_coins[i].i;
        const struct tx_out *out = &wtx->tx.vout[vout_n];

        /* Resolve address */
        char addr[128];
        addr[0] = '\0';
        struct tx_destination dest;
        if (script_extract_destination(&out->script_pub_key, &dest))
            encode_destination(&dest, pk_pfx, pk_pfx_len,
                               sc_pfx, sc_pfx_len, addr, sizeof(addr));

        /* Check chainstate: does this UTXO actually exist? */
        struct coins chain_coins;
        coins_init(&chain_coins);
        bool in_chain = coins_view_cache_get_coins(ctx->coins_tip,
            &wtx->tx.hash, &chain_coins);
        bool available = in_chain
            && coins_is_available(&chain_coins, vout_n);

        /* If available, also verify the value matches */
        int64_t chain_value = 0;
        if (available && vout_n < chain_coins.num_vout)
            chain_value = chain_coins.vout[vout_n].value;
        coins_free(&chain_coins);

        char txid[65];
        uint256_get_hex(&wtx->tx.hash, txid);

        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_str(&entry, "txid", txid);
        json_push_kv_int(&entry, "vout", vout_n);
        if (addr[0])
            json_push_kv_str(&entry, "address", addr);
        char amt[32];
        format_amount(out->value, amt, sizeof(amt));
        json_push_kv_str(&entry, "amount", amt);
        json_push_kv_int(&entry, "confirmations",
                          (int64_t)wallet_coins[i].depth);

        if (available) {
            if (chain_value != out->value) {
                json_push_kv_str(&entry, "status", "value_mismatch");
                char cv[32];
                format_amount(chain_value, cv, sizeof(cv));
                json_push_kv_str(&entry, "chain_value", cv);
            } else {
                json_push_kv_str(&entry, "status", "verified");
            }
            json_push_back(&verified_utxos, &entry);
            verified_balance += out->value;
            verified_count++;
        } else {
            json_push_kv_str(&entry, "status",
                in_chain ? "spent_on_chain" : "tx_not_in_chainstate");
            json_push_back(&phantom_utxos, &entry);
            phantom_balance += out->value;
            phantom_count++;
        }
        json_free(&entry);

        /* Accumulate per-address */
        size_t ai = num_addrs;
        for (size_t k = 0; k < num_addrs; k++) {
            if (strcmp(addr_bal[k].address, addr) == 0) {
                ai = k;
                break;
            }
        }
        if (ai == num_addrs && num_addrs < 512) {
            snprintf(addr_bal[num_addrs].address,
                     sizeof(addr_bal[0].address), "%s", addr);
            addr_bal[num_addrs].verified = 0;
            addr_bal[num_addrs].phantom = 0;
            addr_bal[num_addrs].v_count = 0;
            addr_bal[num_addrs].p_count = 0;
            num_addrs++;
        }
        if (ai < 512) {
            if (available) {
                addr_bal[ai].verified += out->value;
                addr_bal[ai].v_count++;
            } else {
                addr_bal[ai].phantom += out->value;
                addr_bal[ai].p_count++;
            }
        }
    }

    /* Phase 2: Shielded notes (always from SQLite) */
    int64_t z_balance = 0;
    int z_unspent = 0;
    if (wallet_ctx_db_ready(ctx)) {
        z_balance = db_sapling_note_balance(ctx->node_db);
        struct db_sapling_note db_notes[256];
        z_unspent = db_sapling_note_list_unspent(ctx->node_db, db_notes, 256);
    }

    /* Phase 3: Build summary */
    char s[32];
    struct json_value summary = {0};
    json_set_object(&summary);

    format_amount(verified_balance, s, sizeof(s));
    json_push_kv_str(&summary, "verified_balance", s);
    json_push_kv_int(&summary, "verified_utxos", verified_count);

    format_amount(phantom_balance, s, sizeof(s));
    json_push_kv_str(&summary, "phantom_balance", s);
    json_push_kv_int(&summary, "phantom_utxos", phantom_count);

    format_amount(verified_balance + phantom_balance, s, sizeof(s));
    json_push_kv_str(&summary, "wallet_claims", s);

    format_amount(z_balance, s, sizeof(s));
    json_push_kv_str(&summary, "shielded_balance", s);
    json_push_kv_int(&summary, "shielded_notes", z_unspent);

    format_amount(verified_balance + z_balance, s, sizeof(s));
    json_push_kv_str(&summary, "true_total_balance", s);

    format_amount(phantom_balance, s, sizeof(s));
    json_push_kv_str(&summary, "discrepancy", s);

    int64_t wallet_reports = wallet_get_balance(ctx->wallet);
    format_amount(wallet_reports, s, sizeof(s));
    json_push_kv_str(&summary, "getbalance_reports", s);

    if (wallet_ctx_db_ready(ctx)) {
        int64_t sqlite_balance = db_wallet_utxo_balance(ctx->node_db);
        format_amount(sqlite_balance, s, sizeof(s));
        json_push_kv_str(&summary, "sqlite_verified_balance", s);
    }

    json_push_kv(&result[0], "summary", &summary);
    json_free(&summary);

    /* Per-address breakdown */
    struct json_value addr_list = {0};
    json_set_array(&addr_list);
    for (size_t i = 0; i < num_addrs; i++) {
        struct json_value a = {0};
        json_set_object(&a);
        json_push_kv_str(&a, "address", addr_bal[i].address);
        format_amount(addr_bal[i].verified, s, sizeof(s));
        json_push_kv_str(&a, "verified_balance", s);
        json_push_kv_int(&a, "verified_utxos", addr_bal[i].v_count);
        if (addr_bal[i].phantom > 0) {
            format_amount(addr_bal[i].phantom, s, sizeof(s));
            json_push_kv_str(&a, "phantom_balance", s);
            json_push_kv_int(&a, "phantom_utxos", addr_bal[i].p_count);
        }
        json_push_back(&addr_list, &a);
        json_free(&a);
    }
    json_push_kv(&result[0], "addresses", &addr_list);
    json_free(&addr_list);

    /* Verified UTXOs */
    json_push_kv(&result[0], "verified_utxos", &verified_utxos);
    json_free(&verified_utxos);

    /* Phantom UTXOs (wallet thinks unspent, chain says spent) */
    if (phantom_count > 0) {
        json_push_kv(&result[0], "phantom_utxos", &phantom_utxos);
    }
    json_free(&phantom_utxos);

    return true;
}
bool rpc_diagnoseutxos(const struct json_value *params, bool help,
                               struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "diagnoseutxos\n"
        "Per-UTXO diagnostic: checks script type, destination extraction,\n"
        "key existence (have_key), key retrieval (get_key), and chainstate\n"
        "presence. Identifies exactly why each UTXO can or cannot be spent.");

    ENSURE_WALLET(result);
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "diagnoseutxos",
            "Chainstate lookup"))
        return false;

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    struct coin_entry coins[4096];
    size_t num_coins = 0;
    wallet_available_coins(ctx->wallet, coins, &num_coins, 4096, false, false);

    json_set_object(result);

    int can_spend = 0, cannot_spend = 0;
    int64_t spendable_balance = 0, locked_balance = 0;

    struct json_value utxo_list = {0};
    json_set_array(&utxo_list);

    for (size_t i = 0; i < num_coins; i++) {
        const struct wallet_tx *wtx = coins[i].wtx;
        uint32_t vout_n = coins[i].i;
        const struct tx_out *out = &wtx->tx.vout[vout_n];

        struct json_value entry = {0};
        json_set_object(&entry);

        char txid[65];
        uint256_get_hex(&wtx->tx.hash, txid);
        json_push_kv_str(&entry, "txid", txid);
        json_push_kv_int(&entry, "vout", vout_n);

        char amt[32];
        format_amount(out->value, amt, sizeof(amt));
        json_push_kv_str(&entry, "amount", amt);

        /* Extract destination */
        struct tx_destination dest;
        bool have_dest = script_extract_destination(
            &out->script_pub_key, &dest);

        if (!have_dest) {
            json_push_kv_str(&entry, "script_type", "unknown");
            json_push_kv_str(&entry, "status", "no_destination");
            cannot_spend++;
            locked_balance += out->value;
            json_push_back(&utxo_list, &entry);
            json_free(&entry);
            continue;
        }

        const char *dest_type = dest.type == DEST_KEY_ID ? "p2pkh"
                               : dest.type == DEST_SCRIPT_ID ? "p2sh"
                               : "other";
        json_push_kv_str(&entry, "script_type", dest_type);

        /* Resolve address */
        char addr[128];
        encode_destination(&dest, pk_pfx, pk_pfx_len,
                           sc_pfx, sc_pfx_len, addr, sizeof(addr));
        json_push_kv_str(&entry, "address", addr);

        /* Key hash hex */
        char keyhash[41];
        HexStr(dest.id.key.id.data, 20, false, keyhash, sizeof(keyhash));
        json_push_kv_str(&entry, "key_id", keyhash);

        /* Check key availability */
        bool have = false;
        bool can_get = false;

        if (dest.type == DEST_KEY_ID) {
            have = keystore_have_key(&ctx->wallet->keystore, &dest.id.key);
            struct privkey test_key;
            can_get = keystore_get_key(&ctx->wallet->keystore,
                                        &dest.id.key, &test_key);
            if (can_get)
                memory_cleanse(test_key.vch, 32);
        } else if (dest.type == DEST_SCRIPT_ID) {
            have = keystore_have_cscript(&ctx->wallet->keystore,
                                          &dest.id.script.hash);
            json_push_kv_str(&entry, "note",
                "p2sh — need underlying keys, not just script");
        }

        json_push_kv_bool(&entry, "have_key", have);
        json_push_kv_bool(&entry, "can_retrieve_key", can_get);

        /* Chainstate check */
        if (ctx->coins_tip) {
            struct coins c;
            coins_init(&c);
            bool found = coins_view_cache_get_coins(ctx->coins_tip,
                &wtx->tx.hash, &c);
            bool avail = found &&
                coins_is_available(&c, vout_n);
            coins_free(&c);
            json_push_kv_bool(&entry, "in_chainstate", avail);
        }

        if (can_get) {
            json_push_kv_str(&entry, "status", "spendable");
            can_spend++;
            spendable_balance += out->value;
        } else if (have && !can_get) {
            json_push_kv_str(&entry, "status",
                "have_key_but_cannot_retrieve");
            cannot_spend++;
            locked_balance += out->value;
        } else {
            json_push_kv_str(&entry, "status", "key_missing");
            cannot_spend++;
            locked_balance += out->value;
        }

        json_push_back(&utxo_list, &entry);
        json_free(&entry);
    }

    /* Summary */
    struct json_value summary = {0};
    json_set_object(&summary);
    json_push_kv_int(&summary, "total_utxos", (int64_t)num_coins);
    json_push_kv_int(&summary, "spendable", can_spend);
    json_push_kv_int(&summary, "not_spendable", cannot_spend);

    char s[32];
    format_amount(spendable_balance, s, sizeof(s));
    json_push_kv_str(&summary, "spendable_balance", s);
    format_amount(locked_balance, s, sizeof(s));
    json_push_kv_str(&summary, "locked_balance", s);
    json_push_kv_int(&summary, "keystore_keys",
        (int64_t)ctx->wallet->keystore.num_keys);

    json_push_kv(result, "summary", &summary);
    json_free(&summary);

    json_push_kv(result, "utxos", &utxo_list);
    json_free(&utxo_list);

    return true;
}
