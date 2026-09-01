/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Transparent wallet transaction-listing RPC handlers: listtransactions and
 * gettransaction. */

#include "controllers/wallet_controller_internal.h"

bool rpc_listtransactions(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "listtransactions ( \"account\" count skip )\n"
        "Returns up to 'count' most recent transactions.\n"
        "Arguments:\n"
        "1. \"account\"  (string, optional) DEPRECATED. Ignored.\n"
        "2. count       (numeric, optional, default=10)\n"
        "3. skip        (numeric, optional, default=0)");

    ENSURE_WALLET(result);

    /* C++ API: listtransactions "account" count skip
     * params[0] is the account name (string, ignored).
     * params[1] is count, params[2] is skip.
     * For backward compat, if params[0] is numeric, treat as count. */
    int count = 10;
    int skip = 0;
    int param_offset = 0;
    if (json_size(params) >= 1) {
        const struct json_value *p0 = json_at(params, 0);
        if (p0 && p0->type == JSON_STR)
            param_offset = 1; /* skip account name */
        else if (p0)
            count = (int)json_get_int(p0);
    }
    if (json_size(params) >= (size_t)(param_offset + 1))
        count = (int)json_get_int(json_at(params, param_offset));
    if (json_size(params) >= (size_t)(param_offset + 2))
        skip = (int)json_get_int(json_at(params, param_offset + 1));
    if (count < 0) count = 0;
    if (skip < 0) skip = 0;

    json_set_array(result);
    if (count == 0)
        return true;

    if (wallet_history_db_ready()) {
        struct db_wallet_tx *rows =
            zcl_calloc((size_t)count, sizeof(struct db_wallet_tx), "listtransactions rows");
        if (!rows) {
            json_set_str(result, "Out of memory");
            LOG_FAIL("wallet", "listtransactions: alloc failed for %d rows", count);
        }

        int n = db_wallet_tx_list(ctx->node_db, rows, (size_t)count, (size_t)skip);
        for (int i = 0; i < n; i++) {
            struct transaction tx;
            if (wallet_db_tx_deserialize(&rows[i], &tx)) {
                wallet_append_tx_entry(&tx, rows[i].from_me, rows[i].fee,
                                       wallet_db_tx_confirmations(&rows[i]),
                                       rows[i].time_received, result);
                transaction_free(&tx);
            }
            db_wallet_tx_free(&rows[i]);
        }
        free(rows);
        return true;
    }

    int seen = 0;
    int added = 0;
    for (size_t i = 0; i < MAX_WALLET_TX && added < count; i++) {
        if (!ctx->wallet->map_wallet[i].used)
            continue;
        if (seen++ < skip)
            continue;
        const struct wallet_tx *wtx = &ctx->wallet->map_wallet[i];
        wallet_append_tx_entry(&wtx->tx, wtx->from_me, 0, wtx->confirms,
                               wtx->time_received, result);
        added++;
    }

    return true;
}

bool rpc_gettransaction(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "gettransaction \"txid\"\n"
        "Get detailed information about wallet transaction.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *txid_str = rpc_require_str(&p, 0, "txid");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); LOG_FAIL("wallet", "gettransaction: invalid params"); }

    ENSURE_WALLET(result);
    struct uint256 txid;
    uint256_set_hex(&txid, txid_str);

    if (wallet_ctx_db_ready(ctx)) {
        struct db_wallet_tx dbtx;
        if (db_wallet_tx_find(ctx->node_db, txid.data, &dbtx)) {
            struct transaction tx;
            if (!wallet_db_tx_deserialize(&dbtx, &tx)) {
                db_wallet_tx_free(&dbtx);
                json_set_str(result, "Failed to decode wallet transaction");
                LOG_FAIL("wallet", "gettransaction: failed to deserialize tx %s", txid_str);
            }

            json_set_object(result);

            int64_t credit = 0;
            for (size_t j = 0; j < tx.num_vout; j++) {
                if (wallet_is_mine(ctx->wallet, &tx.vout[j]))
                    credit += tx.vout[j].value;
            }
            int64_t debit = dbtx.from_me
                ? (transaction_get_value_out(&tx) + dbtx.fee)
                : 0;
            int64_t net = credit - debit;
            char net_str[32];
            format_amount(net, net_str, sizeof(net_str));
            json_push_kv_real(result, "amount", strtod(net_str, NULL));
            json_push_kv_int(result, "confirmations",
                             (int64_t)wallet_db_tx_confirmations(&dbtx));

            char hex_txid[65];
            uint256_get_hex(&tx.hash, hex_txid);
            json_push_kv_str(result, "txid", hex_txid);

            json_push_kv_int(result, "time", dbtx.time_received);
            json_push_kv_int(result, "timereceived", dbtx.time_received);

            if (dbtx.has_block) {
                char bhash[65];
                struct uint256 bh;
                memcpy(bh.data, dbtx.block_hash, 32);
                uint256_get_hex(&bh, bhash);
                json_push_kv_str(result, "blockhash", bhash);
            }

            if (dbtx.from_me && dbtx.fee > 0) {
                char fee_str[32];
                format_amount(-dbtx.fee, fee_str, sizeof(fee_str));
                json_push_kv_real(result, "fee", strtod(fee_str, NULL));
            }

            transaction_free(&tx);
            db_wallet_tx_free(&dbtx);
            return true;
        }
    }

    const struct wallet_tx *wtx = wallet_get_tx(ctx->wallet, &txid);
    if (!wtx) {
        json_set_str(result, "Invalid or non-wallet transaction id");
        LOG_FAIL("wallet", "gettransaction: tx %s not found in wallet", txid_str);
    }

    json_set_object(result);

    int64_t credit = 0;
    int64_t debit = wallet_get_debit(ctx->wallet, &wtx->tx);
    for (size_t j = 0; j < wtx->tx.num_vout; j++) {
        if (wallet_is_mine(ctx->wallet, &wtx->tx.vout[j]))
            credit += wtx->tx.vout[j].value;
    }

    int64_t net = credit - debit;
    char net_str[32];
    format_amount(net, net_str, sizeof(net_str));
    json_push_kv_real(result, "amount", strtod(net_str, NULL));
    json_push_kv_int(result, "confirmations", (int64_t)wtx->confirms);

    char hex_txid[65];
    uint256_get_hex(&wtx->tx.hash, hex_txid);
    json_push_kv_str(result, "txid", hex_txid);

    json_push_kv_int(result, "time", wtx->time_received);
    json_push_kv_int(result, "timereceived", wtx->time_received);

    if (!uint256_is_null(&wtx->hash_block)) {
        char bhash[65];
        uint256_get_hex(&wtx->hash_block, bhash);
        json_push_kv_str(result, "blockhash", bhash);
    }

    return true;
}
