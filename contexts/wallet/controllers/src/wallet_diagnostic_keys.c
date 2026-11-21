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
#include "core/amount.h"
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
    bool failed;
};

static bool key_utxo_available(struct key_balance_ctx *kc,
                               const struct db_wallet_utxo *utxo)
{
    if (utxo->is_spent) return false;
    if (!kc->coins_tip) return true;
    struct uint256 tid;
    memcpy(tid.data, utxo->txid, 32);
    struct coins cc;
    coins_init(&cc);
    bool found = coins_view_cache_get_coins(kc->coins_tip, &tid, &cc);
    bool available = found && coins_is_available(&cc, utxo->vout);
    coins_free(&cc);
    return available;
}

static void key_balance_cb(const struct db_wallet_key *key, void *ctx)
{
    struct key_balance_ctx *kc = ctx;
    if (kc->failed) return;

    /* Get UTXOs for this key */
    struct db_wallet_utxo utxos[256];
    int n = db_wallet_key_utxos_checked(kc->ndb, key->pubkey_hash, utxos, 256);
    if (n < 0) { kc->failed = true; return; }

    /* Sum verified balance */
    int64_t balance = 0;
    int unspent = 0;
    for (int i = 0; i < n; i++) {
        if (key_utxo_available(kc, &utxos[i])) {
            if (!MoneyRange(utxos[i].value) ||
                ckd_add(&balance, balance, utxos[i].value))
                kc->failed = true;
            unspent++;
        }
    }
    for (int i = 0; i < n; i++) db_wallet_utxo_free(&utxos[i]);
    if (kc->failed || ckd_add(&kc->total_balance, kc->total_balance, balance)) {
        kc->failed = true;
        return;
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
    if (!json_push_back(kc->arr, &entry)) kc->failed = true;
    json_free(&entry);

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
    if (db_wallet_key_each_checked(ctx->node_db, key_balance_cb, &kctx) < 0 ||
        kctx.failed) {
        json_free(&keys_arr);
        return wallet_balance_unavailable(result);
    }

    json_push_kv(result, "transparent_keys", &keys_arr);
    json_free(&keys_arr);

    /* Sapling keys */
    struct json_value z_keys = {0};
    json_set_array(&z_keys);
    int64_t z_total = 0;

    for (size_t i = 0; i < ctx->wallet->sapling_keys.num_keys; i++) {
        if (!ctx->wallet->sapling_keys.keys[i].used) continue;
        const struct sapling_key_entry *sk = &ctx->wallet->sapling_keys.keys[i];

        int64_t z_bal = db_sapling_note_balance_for_ivk(ctx->node_db, sk->ivk);
        if (!MoneyRange(z_bal)) {
            json_free(&z_keys);
            return wallet_balance_unavailable(result);
        }

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
        if (ckd_add(&z_total, z_total, z_bal)) {
            json_free(&zentry);
            json_free(&z_keys);
            return wallet_balance_unavailable(result);
        }

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
    int64_t total;
    if (ckd_add(&total, kctx.total_balance, z_total)) {
        json_free(&summary);
        return wallet_balance_unavailable(result);
    }
    format_amount(total, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_balance", strtod(amt, NULL));
    json_push_kv(result, "summary", &summary);
    json_free(&summary);

    return true;
}

struct txdetail_ctx {
    struct wallet_rpc_context *wctx;
    const unsigned char *pk_pfx;
    size_t pk_pfx_len;
    const unsigned char *sc_pfx;
    size_t sc_pfx_len;
};

static void txdetail_push_outputs(const struct txdetail_ctx *tc,
                                  struct json_value *entry,
                                  struct transaction *tx,
                                  int64_t *credit)
{
    struct json_value vouts = {0};
    json_set_array(&vouts);
    for (size_t j = 0; j < tx->num_vout; j++) {
        struct json_value vo = {0};
        json_set_object(&vo);
        json_push_kv_int(&vo, "n", (int64_t)j);

        char amt[32];
        format_amount(tx->vout[j].value, amt, sizeof(amt));
        json_push_kv_real(&vo, "value", strtod(amt, NULL));

        bool mine = wallet_is_mine(tc->wctx->wallet, &tx->vout[j]);
        json_push_kv_bool(&vo, "is_mine", mine);
        json_push_kv_bool(&vo, "is_change",
                          wallet_is_change(tc->wctx->wallet, &tx->vout[j]));

        struct tx_destination dest;
        if (script_extract_destination(
                &tx->vout[j].script_pub_key, &dest)) {
            char addr[128];
            encode_destination(&dest, tc->pk_pfx, tc->pk_pfx_len,
                               tc->sc_pfx, tc->sc_pfx_len,
                               addr, sizeof(addr));
            json_push_kv_str(&vo, "address", addr);
        }

        if (mine) *credit += tx->vout[j].value;

        json_push_back(&vouts, &vo);
        json_free(&vo);
    }
    json_push_kv(entry, "outputs", &vouts);
    json_free(&vouts);
}

static void txdetail_push_inputs(struct wallet_rpc_context *ctx,
                                 struct json_value *entry,
                                 struct transaction *tx,
                                 int64_t *debit)
{
    struct json_value vins = {0};
    json_set_array(&vins);
    for (size_t j = 0; j < tx->num_vin; j++) {
        struct json_value vi = {0};
        json_set_object(&vi);

        char prev_txid[65];
        uint256_get_hex(&tx->vin[j].prevout.hash, prev_txid);
        json_push_kv_str(&vi, "txid", prev_txid);
        json_push_kv_int(&vi, "vout", tx->vin[j].prevout.n);

        /* Try to resolve the input value from chainstate or wallet */
        int64_t in_val = 0;
        bool in_mine = false;
        if (wallet_ctx_db_ready(ctx)) {
            struct db_wallet_utxo prev_utxo;
            if (db_wallet_utxo_find(ctx->node_db,
                    tx->vin[j].prevout.hash.data,
                    tx->vin[j].prevout.n, &prev_utxo)) {
                in_val = prev_utxo.value;
                in_mine = true;
            }
        }

        if (in_val > 0) {
            char amt[32];
            format_amount(in_val, amt, sizeof(amt));
            json_push_kv_real(&vi, "value", strtod(amt, NULL));
            json_push_kv_bool(&vi, "is_mine", in_mine);
            if (in_mine) *debit += in_val;
        }

        json_push_back(&vins, &vi);
        json_free(&vi);
    }
    json_push_kv(entry, "inputs", &vins);
    json_free(&vins);
}

static void txdetail_push_shielded(struct json_value *entry,
                                   struct transaction *tx)
{
    if (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0) {
        struct json_value shielded = {0};
        json_set_object(&shielded);
        json_push_kv_int(&shielded, "spends",
                         (int64_t)tx->num_shielded_spend);
        json_push_kv_int(&shielded, "outputs",
                         (int64_t)tx->num_shielded_output);
        json_push_kv(entry, "shielded", &shielded);
        json_free(&shielded);
    }
}

static void txdetail_push_net_effect(struct json_value *entry,
                                     struct db_wallet_tx *row,
                                     int64_t credit, int64_t debit)
{
    int64_t net = credit - debit;
    if (row->from_me && row->fee > 0)
        net -= row->fee;
    char net_str[32];
    format_amount(net, net_str, sizeof(net_str));
    json_push_kv_real(entry, "net_effect", strtod(net_str, NULL));

    if (row->from_me && row->fee > 0) {
        char fee_str[32];
        format_amount(row->fee, fee_str, sizeof(fee_str));
        json_push_kv_real(entry, "fee", strtod(fee_str, NULL));
    }
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

    struct txdetail_ctx tc = {
        .wctx = ctx,
        .pk_pfx = pk_pfx,
        .pk_pfx_len = pk_pfx_len,
        .sc_pfx = sc_pfx,
        .sc_pfx_len = sc_pfx_len,
    };

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
        int64_t credit = 0;
        txdetail_push_outputs(&tc, &entry, &tx, &credit);

        /* Inputs */
        int64_t debit = 0;
        txdetail_push_inputs(ctx, &entry, &tx, &debit);

        /* Shielded components */
        txdetail_push_shielded(&entry, &tx);

        /* Net effect */
        txdetail_push_net_effect(&entry, &rows[i], credit, debit);

        json_push_back(result, &entry);
        json_free(&entry);
        transaction_free(&tx);
        db_wallet_tx_free(&rows[i]);
    }

    free(rows);
    return true;
}

struct balanceflow_ctx {
    struct wallet_rpc_context *wctx;
    struct db_wallet_utxo *utxos;
    int nutxos;
    int min_height;
    int max_height;
    int64_t running_balance;
    int64_t total_received;
    int64_t total_sent;
    int64_t total_fees;
    int flow_count;
};

static bool balanceflow_tx_credit(struct wallet_rpc_context *ctx,
                                  struct transaction *tx, int64_t *out)
{
    int64_t credit = 0;
    for (size_t j = 0; j < tx->num_vout; j++) {
        if (wallet_is_mine(ctx->wallet, &tx->vout[j]) &&
            (!MoneyRange(tx->vout[j].value) ||
             ckd_add(&credit, credit, tx->vout[j].value)))
            return false;
    }
    *out = credit;
    return true;
}

static bool balanceflow_tx_debit(struct db_wallet_utxo *utxos,
                                 int nutxos, struct transaction *tx, int64_t *out)
{
    int64_t debit = 0;
    for (size_t j = 0; j < tx->num_vin; j++) {
        for (int k = 0; k < nutxos; k++) {
            if (memcmp(utxos[k].txid,
                       tx->vin[j].prevout.hash.data, 32) == 0 &&
                utxos[k].vout == tx->vin[j].prevout.n) {
                if (!MoneyRange(utxos[k].value) ||
                    ckd_add(&debit, debit, utxos[k].value))
                    return false;
                break;
            }
        }
    }
    *out = debit;
    return true;
}

static const char *balanceflow_tx_category(bool from_me, int64_t credit,
                                           int64_t debit)
{
    if (from_me && credit < debit)
        return "send";
    else if (!from_me && credit > 0)
        return "receive";
    else
        return "internal";
}

static bool balanceflow_chainstate_balance(struct wallet_rpc_context *ctx,
    const struct db_wallet_utxo *utxos, int count, int64_t *out)
{
    int64_t chain_balance = 0;
    for (int i = 0; i < count; i++) {
        if (utxos[i].is_spent) continue;
        struct uint256 tid;
        memcpy(tid.data, utxos[i].txid, 32);
        struct coins cc;
        coins_init(&cc);
        bool found = coins_view_cache_get_coins(ctx->coins_tip, &tid, &cc);
        bool available = found && coins_is_available(&cc, utxos[i].vout);
        coins_free(&cc);
        if (available && (!MoneyRange(utxos[i].value) ||
            ckd_add(&chain_balance, chain_balance, utxos[i].value))) return false;
    }
    *out = chain_balance;
    return true;
}

static bool balanceflow_update_totals(struct balanceflow_ctx *fc, bool from_me,
                                      int64_t credit, int64_t debit, int64_t fee,
                                      int64_t *net)
{
    int64_t sent = 0;
    if (ckd_sub(net, credit, debit) ||
        ckd_add(&fc->running_balance, fc->running_balance, *net) ||
        (credit > 0 && !from_me &&
         ckd_add(&fc->total_received, fc->total_received, credit)) ||
        (debit > 0 && (ckd_sub(&sent, debit, credit) ||
         ckd_add(&fc->total_sent, fc->total_sent, sent))) ||
        ckd_add(&fc->total_fees, fc->total_fees, fee))
        return false;
    return true;
}

static bool balanceflow_append_tx_flow(struct balanceflow_ctx *fc,
                                       struct json_value *flows,
                                       struct db_wallet_tx *row)
{
    if (row->block_height < fc->min_height ||
        row->block_height > fc->max_height) {
        db_wallet_tx_free(row);
        return true;
    }

    struct transaction tx;
    if (!wallet_db_tx_deserialize(row, &tx)) {
        db_wallet_tx_free(row);
        return false;
    }

    /* Calculate credit: outputs that are mine */
    int64_t credit = 0;

    /* Calculate debit: inputs from wallet UTXOs */
    int64_t debit = 0;
    bool ok = balanceflow_tx_credit(fc->wctx, &tx, &credit);
    if (row->from_me && ok)
        ok = balanceflow_tx_debit(fc->utxos, fc->nutxos, &tx, &debit);

    int64_t fee = row->from_me ? row->fee : 0;
    int64_t net = 0;
    if (!ok || !balanceflow_update_totals(fc, row->from_me, credit, debit, fee, &net)) {
        transaction_free(&tx);
        db_wallet_tx_free(row);
        return false;
    }

    char txid_hex[65];
    uint256_get_hex(&tx.hash, txid_hex);

    const char *category = balanceflow_tx_category(row->from_me,
                                                   credit, debit);

    struct json_value entry = {0};
    wallet_view_flow_entry(&entry, txid_hex, category,
                           net, fee,
                           row->block_height, fc->running_balance);
    ok = json_push_back(flows, &entry);
    json_free(&entry);
    fc->flow_count++;

    transaction_free(&tx);
    db_wallet_tx_free(row);
    return ok;
}

static void balanceflow_free_utxos(struct db_wallet_utxo *utxos, int count)
{
    for (int i = 0; i < count; i++) db_wallet_utxo_free(&utxos[i]);
    free(utxos);
}

static void balanceflow_push_summary(struct json_value *result,
                                     struct wallet_rpc_context *ctx,
                                     const struct balanceflow_ctx *fc,
                                     int64_t chain_balance)
{
    struct json_value summary = {0};
    json_set_object(&summary);
    json_push_kv_int(&summary, "transaction_count", fc->flow_count);

    char amt[32];
    format_amount(fc->total_received, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_received", strtod(amt, NULL));
    format_amount(fc->total_sent, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_sent", strtod(amt, NULL));
    format_amount(fc->total_fees, amt, sizeof(amt));
    json_push_kv_real(&summary, "total_fees", strtod(amt, NULL));
    format_amount(fc->running_balance, amt, sizeof(amt));
    json_push_kv_real(&summary, "final_balance", strtod(amt, NULL));

    /* Cross-verify with chainstate */
    if (ctx->coins_tip) {
        format_amount(chain_balance, amt, sizeof(amt));
        json_push_kv_real(&summary, "chainstate_verified_balance",
                          strtod(amt, NULL));
    }

    json_push_kv(result, "summary", &summary);
    json_free(&summary);
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

    /* Get all wallet UTXOs (spent + unspent) sorted by height */
    struct db_wallet_utxo *all_utxos = zcl_calloc(4096, sizeof(struct db_wallet_utxo), "wallet_utxos");
    if (!all_utxos) {
        json_set_str(result, "Out of memory");
        return false;
    }
    int nutxos = db_wallet_utxo_list_all_checked(ctx->node_db, all_utxos, 4096);
    if (nutxos < 0) {
        free(all_utxos);
        return wallet_balance_unavailable(result);
    }

    /* Get all wallet txs sorted by time */
    struct db_wallet_tx *txs = zcl_calloc(2000, sizeof(struct db_wallet_tx), "wallet_txs");
    if (!txs) {
        balanceflow_free_utxos(all_utxos, nutxos);
        json_set_str(result, "Out of memory");
        return false;
    }
    int ntxs = db_wallet_tx_list_checked(ctx->node_db, txs, 2000);
    if (ntxs < 0) {
        balanceflow_free_utxos(all_utxos, nutxos);
        free(txs);
        return wallet_balance_unavailable(result);
    }

    int64_t chain_balance = 0;
    bool ok = !ctx->coins_tip || balanceflow_chainstate_balance(
        ctx, all_utxos, nutxos, &chain_balance);

    json_set_object(result);

    struct json_value flows = {0};
    json_set_array(&flows);

    struct balanceflow_ctx fc = {
        .wctx = ctx,
        .utxos = all_utxos,
        .nutxos = nutxos,
        .min_height = min_height,
        .max_height = max_height,
        .running_balance = 0,
        .total_received = 0,
        .total_sent = 0,
        .total_fees = 0,
        .flow_count = 0,
    };

    /* Process each transaction */
    for (int i = ntxs - 1; i >= 0; i--) {
        if (ok) ok = balanceflow_append_tx_flow(&fc, &flows, &txs[i]);
        else db_wallet_tx_free(&txs[i]);
    }

    if (ok) ok = json_push_kv(result, "flows", &flows);
    json_free(&flows);

    /* Summary */
    if (ok) balanceflow_push_summary(result, ctx, &fc, chain_balance);

    balanceflow_free_utxos(all_utxos, nutxos);
    free(txs);
    return ok ? true : wallet_balance_unavailable(result);
}
