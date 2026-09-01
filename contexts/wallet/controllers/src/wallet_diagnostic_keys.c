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
#include <stdlib.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <string.h>

/* wallet-diagnostic health RPCs: read-only inspection of wallet state. */


/* wallet-diagnostic key/tx-detail/balance-flow inspection RPCs. */

struct key_balance_ctx {
    struct json_value *arr;
    struct node_db *ndb;
    const unsigned char *pk_pfx;
    size_t pk_pfx_len;
    const unsigned char *sc_pfx;
    size_t sc_pfx_len;
    struct coins_view_cache *coins_tip;
    int64_t total_balance;
    int total_keys;
};

static void key_balance_cb(const struct db_wallet_key *key, void *ctx)
{
    struct key_balance_ctx *kc = ctx;

    /* Get UTXOs for this key */
    struct db_wallet_utxo utxos[256];
    int n = db_wallet_key_utxos(kc->ndb, key->pubkey_hash, utxos, 256);

    /* Sum verified balance */
    int64_t balance = 0;
    int unspent = 0;
    for (int i = 0; i < n; i++) {
        if (!utxos[i].is_spent) {
            if (kc->coins_tip) {
                struct uint256 tid;
                memcpy(tid.data, utxos[i].txid, 32);
                struct coins cc;
                coins_init(&cc);
                bool found = coins_view_cache_get_coins(kc->coins_tip,
                    &tid, &cc);
                bool avail = found &&
                    coins_is_available(&cc, utxos[i].vout);
                coins_free(&cc);
                if (avail) {
                    balance += utxos[i].value;
                    unspent++;
                }
            } else {
                balance += utxos[i].value;
                unspent++;
            }
        }
    }

    /* Encode address */
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, key->pubkey_hash, 20);
    char addr[128];
    encode_destination(&dest, kc->pk_pfx, kc->pk_pfx_len,
                       kc->sc_pfx, kc->sc_pfx_len, addr, sizeof(addr));

    struct json_value entry = {0};
    wallet_view_key_entry(&entry, key, addr, unspent, balance);
    json_push_back(kc->arr, &entry);
    json_free(&entry);

    kc->total_balance += balance;
    kc->total_keys++;
}

bool rpc_listwalletkeys(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "listwalletkeys ( include_privkeys )\n"
        "Show every key with per-key verified balance.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    (void)rpc_permit_bool(&p, 0, "include_privkeys", false);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    ENSURE_WALLET(result);
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Wallet database not available");
        return false;
    }
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "listwalletkeys",
            "Chainstate lookup"))
        return false;

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    json_set_object(result);

    /* Transparent keys */
    struct json_value keys_arr = {0};
    json_set_array(&keys_arr);

    struct key_balance_ctx kctx = {
        .arr = &keys_arr,
        .ndb = ctx->node_db,
        .pk_pfx = pk_pfx,
        .pk_pfx_len = pk_pfx_len,
        .sc_pfx = sc_pfx,
        .sc_pfx_len = sc_pfx_len,
        .coins_tip = ctx->coins_tip,
        .total_balance = 0,
        .total_keys = 0,
    };
    db_wallet_key_each(ctx->node_db, key_balance_cb, &kctx);

    json_push_kv(result, "transparent_keys", &keys_arr);
    json_free(&keys_arr);

    /* Sapling keys */
    struct json_value z_keys = {0};
    json_set_array(&z_keys);
    int64_t z_total = 0;

    for (size_t i = 0; i < ctx->wallet->sapling_keys.num_keys; i++) {
        if (!ctx->wallet->sapling_keys.keys[i].used) continue;
        const struct sapling_key_entry *sk = &ctx->wallet->sapling_keys.keys[i];

        int64_t z_bal = 0;
        if (wallet_ctx_db_ready(ctx))
            z_bal = db_sapling_note_balance_for_ivk(ctx->node_db, sk->ivk);

        struct json_value zentry = {0};
        json_set_object(&zentry);

        char zaddr[128];
        if (sapling_encode_payment_address(sk->diversifier, sk->pk_d,
                cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                zaddr, sizeof(zaddr)))
            json_push_kv_str(&zentry, "address", zaddr);

        char amt[32];
        format_amount(z_bal, amt, sizeof(amt));
        json_push_kv_real(&zentry, "balance", strtod(amt, NULL));
        z_total += z_bal;

        json_push_back(&z_keys, &zentry);
        json_free(&zentry);
    }

    json_push_kv(result, "sapling_keys", &z_keys);
    json_free(&z_keys);

    /* Summary */
    struct json_value summary = {0};
    json_set_object(&summary);
    json_push_kv_int(&summary, "transparent_key_count", kctx.total_keys);
    char amt[32];
    format_amount(kctx.total_balance, amt, sizeof(amt));
    json_push_kv_real(&summary, "transparent_balance", strtod(amt, NULL));
    format_amount(z_total, amt, sizeof(amt));
    json_push_kv_real(&summary, "shielded_balance", strtod(amt, NULL));
    format_amount(kctx.total_balance + z_total, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_balance", strtod(amt, NULL));
    json_push_kv(result, "summary", &summary);
    json_free(&summary);

    return true;
}
bool rpc_listwallettxdetail(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "listwallettxdetail ( count offset )\n"
        "Full transaction history with input/output breakdown.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 2);
    int count = (int)rpc_permit_int(&p, 0, "count", 100);
    int offset = (int)rpc_permit_int(&p, 1, "offset", 0);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    ENSURE_WALLET(result);
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Wallet database not available");
        return false;
    }

    if (count > 1000) count = 1000;

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    struct db_wallet_tx *rows = zcl_calloc((size_t)count, sizeof(struct db_wallet_tx), "wallet_tx_rows");
    if (!rows) {
        json_set_str(result, "Out of memory");
        return false;
    }

    int n = db_wallet_tx_list(ctx->node_db, rows, (size_t)count, (size_t)offset);

    json_set_array(result);

    for (int i = 0; i < n; i++) {
        struct transaction tx;
        if (!wallet_db_tx_deserialize(&rows[i], &tx)) {
            db_wallet_tx_free(&rows[i]);
            continue;
        }

        struct json_value entry = {0};
        json_set_object(&entry);

        char txid_hex[65];
        uint256_get_hex(&tx.hash, txid_hex);
        json_push_kv_str(&entry, "txid", txid_hex);
        json_push_kv_int(&entry, "confirmations",
                         (int64_t)wallet_db_tx_confirmations(&rows[i]));
        json_push_kv_int(&entry, "height", rows[i].block_height);
        json_push_kv_int(&entry, "time", rows[i].time_received);
        json_push_kv_bool(&entry, "from_me", rows[i].from_me);

        /* Outputs */
        struct json_value vouts = {0};
        json_set_array(&vouts);
        int64_t credit = 0;
        for (size_t j = 0; j < tx.num_vout; j++) {
            struct json_value vo = {0};
            json_set_object(&vo);
            json_push_kv_int(&vo, "n", (int64_t)j);

            char amt[32];
            format_amount(tx.vout[j].value, amt, sizeof(amt));
            json_push_kv_real(&vo, "value", strtod(amt, NULL));

            bool mine = wallet_is_mine(ctx->wallet, &tx.vout[j]);
            json_push_kv_bool(&vo, "is_mine", mine);
            json_push_kv_bool(&vo, "is_change",
                              wallet_is_change(ctx->wallet, &tx.vout[j]));

            struct tx_destination dest;
            if (script_extract_destination(
                    &tx.vout[j].script_pub_key, &dest)) {
                char addr[128];
                encode_destination(&dest, pk_pfx, pk_pfx_len,
                                   sc_pfx, sc_pfx_len, addr, sizeof(addr));
                json_push_kv_str(&vo, "address", addr);
            }

            if (mine) credit += tx.vout[j].value;

            json_push_back(&vouts, &vo);
            json_free(&vo);
        }
        json_push_kv(&entry, "outputs", &vouts);
        json_free(&vouts);

        /* Inputs */
        struct json_value vins = {0};
        json_set_array(&vins);
        int64_t debit = 0;
        for (size_t j = 0; j < tx.num_vin; j++) {
            struct json_value vi = {0};
            json_set_object(&vi);

            char prev_txid[65];
            uint256_get_hex(&tx.vin[j].prevout.hash, prev_txid);
            json_push_kv_str(&vi, "txid", prev_txid);
            json_push_kv_int(&vi, "vout", tx.vin[j].prevout.n);

            /* Try to resolve the input value from chainstate or wallet */
            int64_t in_val = 0;
            bool in_mine = false;
            if (wallet_ctx_db_ready(ctx)) {
                struct db_wallet_utxo prev_utxo;
                if (db_wallet_utxo_find(ctx->node_db,
                        tx.vin[j].prevout.hash.data,
                        tx.vin[j].prevout.n, &prev_utxo)) {
                    in_val = prev_utxo.value;
                    in_mine = true;
                }
            }

            if (in_val > 0) {
                char amt[32];
                format_amount(in_val, amt, sizeof(amt));
                json_push_kv_real(&vi, "value", strtod(amt, NULL));
                json_push_kv_bool(&vi, "is_mine", in_mine);
                if (in_mine) debit += in_val;
            }

            json_push_back(&vins, &vi);
            json_free(&vi);
        }
        json_push_kv(&entry, "inputs", &vins);
        json_free(&vins);

        /* Shielded components */
        if (tx.num_shielded_spend > 0 || tx.num_shielded_output > 0) {
            struct json_value shielded = {0};
            json_set_object(&shielded);
            json_push_kv_int(&shielded, "spends",
                             (int64_t)tx.num_shielded_spend);
            json_push_kv_int(&shielded, "outputs",
                             (int64_t)tx.num_shielded_output);
            json_push_kv(&entry, "shielded", &shielded);
            json_free(&shielded);
        }

        /* Net effect */
        int64_t net = credit - debit;
        if (rows[i].from_me && rows[i].fee > 0)
            net -= rows[i].fee;
        char net_str[32];
        format_amount(net, net_str, sizeof(net_str));
        json_push_kv_real(&entry, "net_effect", strtod(net_str, NULL));

        if (rows[i].from_me && rows[i].fee > 0) {
            char fee_str[32];
            format_amount(rows[i].fee, fee_str, sizeof(fee_str));
            json_push_kv_real(&entry, "fee", strtod(fee_str, NULL));
        }

        json_push_back(result, &entry);
        json_free(&entry);
        transaction_free(&tx);
        db_wallet_tx_free(&rows[i]);
    }

    free(rows);
    return true;
}
bool rpc_getbalanceflow(const struct json_value *params, bool help,
                                struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "getbalanceflow ( min_height max_height )\n"
        "Chronological balance flow showing where every satoshi went.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 2);
    int min_height = (int)rpc_permit_int(&p, 0, "min_height", 0);
    int max_height = (int)rpc_permit_int(&p, 1, "max_height", 999999999);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    ENSURE_WALLET(result);
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Wallet database not available");
        return false;
    }
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "getbalanceflow",
            "Chainstate lookup"))
        return false;

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);
    (void)pk_pfx; (void)pk_pfx_len;
    (void)sc_pfx; (void)sc_pfx_len;

    /* Get all wallet UTXOs (spent + unspent) sorted by height */
    struct db_wallet_utxo *all_utxos = zcl_calloc(4096, sizeof(struct db_wallet_utxo), "wallet_utxos");
    if (!all_utxos) {
        json_set_str(result, "Out of memory");
        return false;
    }
    int nutxos = db_wallet_utxo_list_all(ctx->node_db, all_utxos, 4096);

    /* Get all wallet txs sorted by time */
    struct db_wallet_tx *txs = zcl_calloc(2000, sizeof(struct db_wallet_tx), "wallet_txs");
    if (!txs) {
        free(all_utxos);
        json_set_str(result, "Out of memory");
        return false;
    }
    int ntxs = db_wallet_tx_list(ctx->node_db, txs, 2000, 0);

    json_set_object(result);

    struct json_value flows = {0};
    json_set_array(&flows);

    int64_t running_balance = 0;
    int64_t total_received = 0;
    int64_t total_sent = 0;
    int64_t total_fees = 0;
    int flow_count = 0;

    /* Process each transaction */
    for (int i = ntxs - 1; i >= 0; i--) {
        if (txs[i].block_height < min_height ||
            txs[i].block_height > max_height) {
            db_wallet_tx_free(&txs[i]);
            continue;
        }

        struct transaction tx;
        if (!wallet_db_tx_deserialize(&txs[i], &tx)) {
            db_wallet_tx_free(&txs[i]);
            continue;
        }

        /* Calculate credit: outputs that are mine */
        int64_t credit = 0;
        for (size_t j = 0; j < tx.num_vout; j++) {
            if (wallet_is_mine(ctx->wallet, &tx.vout[j]))
                credit += tx.vout[j].value;
        }

        /* Calculate debit: inputs from wallet UTXOs */
        int64_t debit = 0;
        if (txs[i].from_me) {
            for (size_t j = 0; j < tx.num_vin; j++) {
                for (int k = 0; k < nutxos; k++) {
                    if (memcmp(all_utxos[k].txid,
                               tx.vin[j].prevout.hash.data, 32) == 0 &&
                        all_utxos[k].vout == tx.vin[j].prevout.n) {
                        debit += all_utxos[k].value;
                        break;
                    }
                }
            }
        }

        int64_t fee = txs[i].from_me ? txs[i].fee : 0;
        int64_t net = credit - debit;

        char txid_hex[65];
        uint256_get_hex(&tx.hash, txid_hex);

        const char *category;
        if (txs[i].from_me && credit < debit)
            category = "send";
        else if (!txs[i].from_me && credit > 0)
            category = "receive";
        else
            category = "internal";

        running_balance += net;
        if (credit > 0 && !txs[i].from_me)
            total_received += credit;
        if (debit > 0)
            total_sent += (debit - credit);
        total_fees += fee;

        struct json_value entry = {0};
        wallet_view_flow_entry(&entry, txid_hex, category,
                               net, fee,
                               txs[i].block_height, running_balance);
        json_push_back(&flows, &entry);
        json_free(&entry);
        flow_count++;

        transaction_free(&tx);
        db_wallet_tx_free(&txs[i]);
    }

    json_push_kv(result, "flows", &flows);
    json_free(&flows);

    /* Summary */
    struct json_value summary = {0};
    json_set_object(&summary);
    json_push_kv_int(&summary, "transaction_count", flow_count);

    char amt[32];
    format_amount(total_received, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_received", strtod(amt, NULL));
    format_amount(total_sent, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_sent", strtod(amt, NULL));
    format_amount(total_fees, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_fees", strtod(amt, NULL));
    format_amount(running_balance, amt, sizeof(amt));
    json_push_kv_real(&summary, "final_balance", strtod(amt, NULL));

    /* Cross-verify with chainstate */
    if (ctx->coins_tip) {
        int64_t chain_balance = 0;
        struct db_wallet_utxo unspent[1024];
        int nu = db_wallet_utxo_list_unspent(ctx->node_db, unspent, 1024);
        for (int i = 0; i < nu; i++) {
            struct uint256 tid;
            memcpy(tid.data, unspent[i].txid, 32);
            struct coins cc;
            coins_init(&cc);
            bool found = coins_view_cache_get_coins(ctx->coins_tip, &tid, &cc);
            if (found && coins_is_available(&cc, unspent[i].vout))
                chain_balance += unspent[i].value;
            coins_free(&cc);
        }
        format_amount(chain_balance, amt, sizeof(amt));
        json_push_kv_real(&summary, "chainstate_verified_balance",
                          strtod(amt, NULL));
    }

    json_push_kv(result, "summary", &summary);
    json_free(&summary);

    free(all_utxos);
    free(txs);
    return true;
}
