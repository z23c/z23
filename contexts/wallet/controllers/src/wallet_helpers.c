/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/wallet_helpers.h"
#include "controllers/sync_controller.h"
#include "views/format_helpers.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "chain/chainparams.h"
#include "config/runtime.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "validation/main_state.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "jobs/reducer_frontier.h"
#include "core/serialize.h"
#include <stdio.h>
#include <string.h>
#include "util/log_macros.h"

struct wallet_rpc_context g_wallet_ctx = {0};

int64_t wallet_transparent_spendable_balance_diagnose(
    const struct wallet_rpc_context *ctx,
    struct wallet_balance_freshness *freshness)
{
    if (freshness)
        memset(freshness, 0, sizeof(*freshness));
    if (!ctx || !ctx->wallet)
        return 0;

    int wallet_height = 0;
    size_t wallet_txs = 0;
    size_t wallet_confirmed_txs = 0;
    zcl_mutex_lock(&ctx->wallet->cs);
    wallet_height = ctx->wallet->best_block_height;
    wallet_txs = ctx->wallet->num_wallet_tx;
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (ctx->wallet->map_wallet[i].used &&
            ctx->wallet->map_wallet[i].confirms > 0)
            wallet_confirmed_txs++;
    }
    zcl_mutex_unlock(&ctx->wallet->cs);

    int chain_height = -1;
    int external_height = reducer_frontier_external_tip_height();
    if (reducer_frontier_provable_tip_is_published() ||
        external_height > 0) {
        /* Use the same external H* contract as getblockcount.  During the
         * short unpublished-cache window it recovers the durable finalized
         * height; the speculative active window is never money authority. */
        chain_height = external_height;
    } else if (ctx->main_state) {
        /* Hermetic/genesis fixtures can have neither a published nor durable
         * H*. Retain their local active-chain fallback only in that empty
         * authority state. */
        zcl_mutex_lock(&ctx->main_state->cs_main);
        chain_height = active_chain_height(&ctx->main_state->chain_active);
        zcl_mutex_unlock(&ctx->main_state->cs_main);
    }

    int db_confirmed_txs = wallet_ctx_db_ready(ctx)
        ? db_wallet_tx_confirmed_count(ctx->node_db) : 0;
    int64_t memory_balance = wallet_get_balance(ctx->wallet);
    int64_t durable_balance = wallet_ctx_db_ready(ctx)
        ? db_wallet_utxo_spendable_balance(ctx->node_db, NULL)
        : memory_balance;

    /* best_block_height is a scan cursor, not proof that every wallet effect
     * at that height has reached RAM.  In particular, a restarted sender can
     * observe a confirmed outgoing transaction in the durable projection
     * before the live wallet entry is upgraded from confirms=0.  Prefer RAM
     * only when it covers at least every confirmation already durable in the
     * wallet model; otherwise the exact SQLite UTXO projection owns the read. */
    if (wallet_txs > 0 && chain_height >= 0 &&
        wallet_height >= chain_height &&
        wallet_confirmed_txs >= (size_t)db_confirmed_txs) {
        if (freshness)
            freshness->source = "memory";
    } else if (freshness) {
        freshness->source = "durable_projection";
    }
    if (freshness) {
        freshness->sources_agree = memory_balance == durable_balance;
        freshness->wallet_height = wallet_height;
        freshness->chain_height = chain_height;
        freshness->memory_confirmed_txs = wallet_confirmed_txs;
        freshness->durable_confirmed_txs = db_confirmed_txs;
    }
    return freshness && strcmp(freshness->source, "memory") == 0
        ? memory_balance
        : ((wallet_txs > 0 && chain_height >= 0 &&
            wallet_height >= chain_height &&
            wallet_confirmed_txs >= (size_t)db_confirmed_txs)
               ? memory_balance : durable_balance);
}

int64_t wallet_transparent_spendable_balance(
    const struct wallet_rpc_context *ctx)
{
    return wallet_transparent_spendable_balance_diagnose(ctx, NULL);
}

struct wallet_flush_lane_ctx {
    struct wallet_sqlite *wallet_db;
    struct wallet *wallet;
    bool transactions_only;
    struct zcl_result result;
};

static bool wallet_flush_lane_write(struct node_db *ndb, void *opaque)
{
    struct wallet_flush_lane_ctx *flush = opaque;

    if (!flush || !flush->wallet_db || !flush->wallet) {
        if (flush)
            flush->result = ZCL_ERR(-1, "wallet flush lane: invalid context");
        LOG_FAIL("wallet", "wallet flush lane: invalid context");
    }
    if (ndb && ndb->sync_in_batch && !node_db_sync_flush(ndb)) {
        flush->result = ZCL_ERR(-1,
            "wallet flush lane: pending node.db batch commit failed");
        LOG_FAIL("wallet", "%s", flush->result.message);
    }
    flush->result = flush->transactions_only
        ? wallet_sqlite_flush_transactions_r(flush->wallet_db, flush->wallet)
        : wallet_sqlite_flush_r(flush->wallet_db, flush->wallet);
    if (!flush->result.ok)
        LOG_FAIL("wallet", "wallet flush lane failed (code=%d): %s",
                 flush->result.code, flush->result.message);
    return true;
}

struct zcl_result wallet_commit_from_context(
    const struct wallet_rpc_context *ctx, struct wallet_tx *wtx)
{
    if (!ctx || !wtx)
        return ZCL_ERR(-1, "wallet commit context: NULL context or transaction");
    struct wallet_tx_admission admission = {
        .mempool = ctx->mempool,
        .coins_tip = ctx->coins_tip,
        .main_state = ctx->main_state,
        .params = chain_params_get(),
    };
    return wallet_commit_transaction(ctx->wallet, wtx, &admission);
}

struct zcl_result wallet_reaccept_from_context(
    const struct wallet_rpc_context *ctx, struct wallet_tx *wtx)
{
    if (!ctx || !wtx)
        return ZCL_ERR(-1,
            "wallet reaccept context: NULL context or transaction");
    struct wallet_tx_admission admission = {
        .mempool = ctx->mempool,
        .coins_tip = ctx->coins_tip,
        .main_state = ctx->main_state,
        .params = chain_params_get(),
    };
    return wallet_reaccept_transaction(wtx, &admission);
}

static struct zcl_result wallet_flush_scope_from_context(
    const struct wallet_rpc_context *ctx, bool transactions_only)
{
    if (!ctx || !ctx->wallet)
        return ZCL_ERR(-1, "wallet flush: incomplete context");
    if (!ctx->wallet_db)
        return ZCL_OK;

    struct wallet_flush_lane_ctx flush = {
        .wallet_db = ctx->wallet_db,
        .wallet = ctx->wallet,
        .transactions_only = transactions_only,
        .result = ZCL_ERR(-1, "wallet flush lane did not run"),
    };
    struct db_service *dbsvc = app_runtime_db_service();
    if (dbsvc && db_service_is_started(dbsvc) && ctx->node_db &&
        db_service_node_db(dbsvc) == ctx->node_db) {
        bool ran = db_service_run_write(dbsvc, wallet_flush_lane_write, &flush);
        if (!ran && flush.result.ok)
            return ZCL_ERR(-1, "wallet flush lane failed without detail");
        return flush.result;
    }

    (void)wallet_flush_lane_write(ctx->node_db, &flush);
    return flush.result;
}

struct zcl_result wallet_flush_from_context(
    const struct wallet_rpc_context *ctx)
{
    return wallet_flush_scope_from_context(ctx, false);
}

struct zcl_result wallet_persist_commit_before_relay(
    const struct wallet_rpc_context *ctx, const struct wallet_tx *wtx)
{
    if (!ctx || !ctx->wallet || !ctx->mempool || !wtx)
        return ZCL_ERR(-1,
            "wallet durability: incomplete context or transaction");
    if (!ctx->wallet_db)
        return ZCL_OK;

    /* Transaction construction consumes only already-persisted keypool
     * entries.  The pre-relay durability boundary therefore persists the
     * newly admitted wallet transaction without re-encrypting every immutable
     * key, seed, and script on each payment. */
    struct zcl_result flushed = wallet_flush_scope_from_context(ctx, true);
    if (flushed.ok)
        return ZCL_OK;

    struct zcl_result rollback = wallet_rollback_transaction(
        ctx->wallet, wtx, ctx->mempool);
    if (!rollback.ok) {
        return ZCL_ERR(-3,
            "wallet durability failed (%s) and rollback failed (%s)",
            flushed.message, rollback.message);
    }
    return ZCL_ERR(-2,
        "wallet durability failed before relay; commit rolled back: %s",
        flushed.message);
}

struct zcl_result wallet_rollback_persisted_commit(
    const struct wallet_rpc_context *ctx, const struct wallet_tx *wtx)
{
    if (!ctx || !ctx->wallet || !ctx->mempool || !wtx)
        return ZCL_ERR(-1,
            "wallet persisted rollback: incomplete context or transaction");

    struct zcl_result memory = wallet_rollback_transaction(
        ctx->wallet, wtx, ctx->mempool);
    bool disk_ok = true;
    if (ctx->wallet_db) {
        disk_ok = ctx->node_db && ctx->node_db->open &&
            node_db_sync_wallet_tx_delete(ctx->node_db, wtx->tx.hash.data);
    }

    if (!memory.ok && !disk_ok)
        return ZCL_ERR(-4,
            "wallet persisted rollback failed in memory (%s) and on disk",
            memory.message);
    if (!memory.ok)
        return ZCL_ERR(-2, "wallet persisted rollback failed in memory: %s",
                       memory.message);
    if (!disk_ok)
        return ZCL_ERR(-3,
            "wallet persisted rollback removed memory/mempool state but could "
            "not delete wallet_transactions row");
    return ZCL_OK;
}

void wallet_rpc_context_set_base(struct wallet *wallet,
                                 struct main_state *main_state,
                                 const char *datadir,
                                 struct wallet_sqlite *wallet_db,
                                 struct tx_mempool *mempool,
                                 struct connman *connman)
{
    g_wallet_ctx.wallet = wallet;
    g_wallet_ctx.main_state = main_state;
    if (datadir && datadir[0]) {
        (void)snprintf(g_wallet_ctx.datadir_storage,
                       sizeof(g_wallet_ctx.datadir_storage), "%s", datadir);
        g_wallet_ctx.datadir = g_wallet_ctx.datadir_storage;
    } else {
        g_wallet_ctx.datadir_storage[0] = '\0';
        g_wallet_ctx.datadir = NULL;
    }
    g_wallet_ctx.wallet_db = wallet_db;
    g_wallet_ctx.mempool = mempool;
    g_wallet_ctx.connman = connman;
}

void wallet_rpc_context_set_node_db(struct node_db *node_db)
{
    g_wallet_ctx.node_db = node_db;
}

void wallet_rpc_context_set_coins_tip(struct coins_view_cache *coins_tip)
{
    g_wallet_ctx.coins_tip = coins_tip;
}

void format_amount(int64_t satoshis, char *out, size_t out_size)
{
    zcl_format_zcl(out, out_size, satoshis);
}

int64_t parse_amount(const struct json_value *v)
{
    if (!v) LOG_ERR("wallet", "parse_amount called with NULL json value");

    if (v->type == JSON_INT) {
        int64_t val = json_get_int(v);
        return val * ZATOSHI_PER_ZCL;
    }

    const char *str = NULL;
    char tmp[64];
    if (v->type == JSON_STR) {
        str = json_get_str(v);
    } else if (v->type == JSON_REAL) {
        snprintf(tmp, sizeof(tmp), "%.8f", json_get_real(v));
        str = tmp;
    }
    if (!str) LOG_ERR("wallet", "parse_amount: unsupported json type %d", v->type);

    const char *p = str;
    while (*p == ' ') p++;
    bool neg = false;
    if (*p == '-') { neg = true; p++; }

    int64_t whole = 0;
    while (*p >= '0' && *p <= '9') {
        whole = whole * 10 + (*p - '0');
        p++;
    }

    int64_t frac = 0;
    int frac_digits = 0;
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9' && frac_digits < 8) {
            frac = frac * 10 + (*p - '0');
            frac_digits++;
            p++;
        }
    }
    while (frac_digits < 8) {
        frac *= 10;
        frac_digits++;
    }

    int64_t satoshis = whole * ZATOSHI_PER_ZCL + frac;
    return neg ? -satoshis : satoshis;
}

bool wallet_ctx_db_ready(const struct wallet_rpc_context *ctx)
{
    return ctx->node_db && ctx->node_db->open;
}

/* Fetch the active chain's base58 prefixes for P2PKH and P2SH addresses.
 * Both the decode and encode paths need the same pair, so resolve them
 * in one place to keep the two address paths in lockstep. */
static void wallet_get_address_prefixes(
    const unsigned char **pk_pfx, size_t *pk_pfx_len,
    const unsigned char **sc_pfx, size_t *sc_pfx_len)
{
    const struct chain_params *cp = chain_params_get();
    *pk_pfx = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, pk_pfx_len);
    *sc_pfx = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, sc_pfx_len);
}

bool wallet_decode_address(const char *str, struct tx_destination *dest)
{
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx, *sc_pfx;
    wallet_get_address_prefixes(&pk_pfx, &pk_pfx_len, &sc_pfx, &sc_pfx_len);
    return decode_destination(str, pk_pfx, pk_pfx_len,
                              sc_pfx, sc_pfx_len, dest);
}

bool wallet_encode_destination(const struct tx_destination *dest,
                               char *out, size_t out_size)
{
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx, *sc_pfx;
    wallet_get_address_prefixes(&pk_pfx, &pk_pfx_len, &sc_pfx, &sc_pfx_len);
    return encode_destination(dest, pk_pfx, pk_pfx_len,
                              sc_pfx, sc_pfx_len, out, out_size);
}

void wallet_txid_hex_le(const uint8_t txid[32], char *out)
{
    for (int j = 0; j < 32; j++)
        snprintf(out + j * 2, 3, "%02x", txid[31 - j]);
}

int wallet_history_count(void)
{
    struct wallet *wallet = wallet_rpc_wallet();
    struct node_db *node_db = wallet_rpc_node_db();
    int mem_count = wallet ? (int)wallet->num_wallet_tx : 0;
    int db_count = (node_db && node_db->open) ? db_wallet_tx_count(node_db) : 0;
    return db_count > mem_count ? db_count : mem_count;
}

bool wallet_history_db_ready(void)
{
    struct wallet *wallet = wallet_rpc_wallet();
    struct node_db *node_db = wallet_rpc_node_db();

    if (!wallet || !node_db || !node_db->open)
        return false;

    int db_count = db_wallet_tx_count(node_db);
    if (db_count >= (int)wallet->num_wallet_tx)
        return true;

    return wallet->num_wallet_tx >= MAX_WALLET_TX;
}

bool wallet_db_tx_deserialize(const struct db_wallet_tx *dbtx,
                              struct transaction *tx)
{
    if (!dbtx || !dbtx->raw_tx || dbtx->raw_tx_len == 0)
        LOG_FAIL("wallet", "wallet_db_tx_deserialize: invalid dbtx (null=%d, raw_null=%d, len=%zu)",
                 (dbtx == NULL), (dbtx ? (dbtx->raw_tx == NULL) : 1),
                 (dbtx ? dbtx->raw_tx_len : (size_t)0));

    struct byte_stream s;
    stream_init_from_data(&s, dbtx->raw_tx, dbtx->raw_tx_len);
    transaction_init(tx);
    if (!transaction_deserialize(tx, &s)) {
        transaction_free(tx);
        LOG_FAIL("wallet", "wallet_db_tx_deserialize: deserialize failed (raw_tx_len=%zu)", dbtx->raw_tx_len);
    }

    transaction_compute_hash(tx);
    return true;
}

int wallet_db_tx_confirmations(const struct db_wallet_tx *dbtx)
{
    struct main_state *main_state = wallet_rpc_main_state();

    if (!dbtx || !dbtx->has_block || !main_state)
        return 0;

    int tip_height = active_chain_height(&main_state->chain_active);
    if (tip_height < dbtx->block_height)
        return 0;

    return tip_height - dbtx->block_height + 1;
}

void append_one_entry(struct json_value *result,
                      const char *txid, int vout_n,
                      const char *category, const char *address,
                      int64_t amount, int64_t fee,
                      int confirmations, int64_t time_received)
{
    struct json_value entry = {0};
    json_init(&entry);
    json_set_object(&entry);
    json_push_kv_str(&entry, "txid", txid);
    json_push_kv_int(&entry, "vout", vout_n);
    json_push_kv_str(&entry, "category", category);
    if (address)
        json_push_kv_str(&entry, "address", address);
    char a[32];
    format_amount(amount, a, sizeof(a));
    json_push_kv_real(&entry, "amount", strtod(a, NULL));
    if (fee != 0) {
        char f[32];
        format_amount(fee, f, sizeof(f));
        json_push_kv_real(&entry, "fee", strtod(f, NULL));
    }
    json_push_kv_int(&entry, "confirmations", confirmations);
    json_push_kv_int(&entry, "time", time_received);
    json_push_kv_int(&entry, "timereceived", time_received);
    json_push_back(result, &entry);
    json_free(&entry);
}

bool wallet_append_tx_entry(const struct transaction *tx,
                            bool from_me, int64_t fee,
                            int confirmations, int64_t time_received,
                            struct json_value *result)
{
    struct wallet *wallet = wallet_rpc_wallet();

    char txid[65];
    uint256_get_hex(&tx->hash, txid);

    if (from_me) {
        bool fee_emitted = false;
        for (size_t j = 0; j < tx->num_vout; j++) {
            struct tx_destination dest;
            char addr[128];
            addr[0] = '\0';
            if (script_extract_destination(
                    &tx->vout[j].script_pub_key, &dest))
                wallet_encode_destination(&dest, addr, sizeof(addr));

            int64_t per_fee = 0;
            if (!fee_emitted) { per_fee = -fee; fee_emitted = true; }

            append_one_entry(result, txid, (int)j, "send",
                             addr[0] ? addr : NULL,
                             -(int64_t)tx->vout[j].value, per_fee,
                             confirmations, time_received);

            if (wallet_is_mine(wallet, &tx->vout[j])) {
                append_one_entry(result, txid, (int)j, "receive",
                                 addr[0] ? addr : NULL,
                                 (int64_t)tx->vout[j].value, 0,
                                 confirmations, time_received);
            }
        }
    } else {
        for (size_t j = 0; j < tx->num_vout; j++) {
            if (!wallet_is_mine(wallet, &tx->vout[j]))
                continue;
            struct tx_destination dest;
            char addr[128];
            addr[0] = '\0';
            if (script_extract_destination(
                    &tx->vout[j].script_pub_key, &dest))
                wallet_encode_destination(&dest, addr, sizeof(addr));

            append_one_entry(result, txid, (int)j,
                             confirmations > 0 ? "receive" : "immature",
                             addr[0] ? addr : NULL,
                             (int64_t)tx->vout[j].value, 0,
                             confirmations, time_received);
        }
    }

    return true;
}
