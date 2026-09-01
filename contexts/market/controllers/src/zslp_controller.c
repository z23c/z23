/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZSLP token controller — token operations + shielded payments. */

#include "controllers/zslp_controller.h"
#include "zslp_controller_internal.h"
#include "controllers/wallet_helpers.h"
#include "controllers/sync_controller.h"
#include "core/uint256.h"
#include "wallet/wallet.h"
#include "primitives/transaction.h"
#include "config/runtime.h"
#include "models/zslp.h"
#include "models/database.h"
#include "models/zslp_validity.h"
#include "jobs/reducer_frontier.h"
#include "services/zslp_command_service.h"
#include "services/zslp_service.h"
#include "rpc/server.h"
#include "json/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sqlite3.h>
#include "util/log_macros.h"
#include "controllers/sovereignty_controller.h"
#include "net/connman.h"

/* Sovereign guard for the three write verbs (createtoken/send/mint all spend
 * wallet UTXOs and mutate asset state): refuse while the tip is
 * release_assisted (borrowed shielded history, not self-folded) — same
 * doctrine as rpc_z_sendmany / rpc_sendtoaddress. Returns true when the
 * spend capability is granted; on refusal sets the error body and returns
 * false via LOG_FAIL. */
static bool zslp_sovereignty_spend_guard(struct json_value *result,
                                         const char *verb)
{
    char sov_reason[96] = {0};
    if (sovereignty_guard_allow("wallet_spend", sov_reason,
                                sizeof(sov_reason)))
        return true;
    json_set_str(result, "Error: spend refused — tip is release_assisted "
                         "(borrowed shielded history, not self-folded)");
    LOG_FAIL("zslp", "%s: refused — %s", verb, sov_reason);
}

struct zslp_context {
    const char *datadir;
};

static struct zslp_context g_zslp_ctx = {0};

static struct zslp_context *zslp_ctx(void)
{
    return &g_zslp_ctx;
}

struct wallet *zslp_controller_wallet(void)
{
    return app_runtime_wallet();
}

struct tx_mempool *zslp_controller_mempool(void)
{
    return app_runtime_mempool();
}

const char *zslp_controller_datadir(const char *datadir)
{
    return datadir ? datadir : zslp_ctx()->datadir;
}

static bool zslp_open_runtime_db(const char *datadir, sqlite3 **db_out,
                                 bool *owns_db)
{
    struct zcl_result r =
        zslp_service_open_db(zslp_controller_datadir(datadir), db_out, owns_db);
    if (!r.ok)
        LOG_FAIL("zslp", "open_runtime_db: %s", r.message);
    return true;
}

/* Same durability/relay contract as sendtoaddress: persist any freshly
 * generated keys before admission, durably persist the admitted wallet row,
 * mirror it into node.db, then announce it to peers. The old ZSLP path stopped
 * after local mempool admission while printing "broadcast". */
bool zslp_controller_publish(struct wallet_tx *wtx, char txid_out[65],
                             char *error_out, size_t error_size)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!ctx || !ctx->wallet || !ctx->mempool || !ctx->coins_tip ||
        !ctx->main_state || !wtx) {
        snprintf(error_out, error_size,
                 "wallet validation/relay context is incomplete");
        LOG_FAIL("zslp", "publish: %s", error_out);
    }

    if (ctx->wallet_db) {
        struct zcl_result flushed = wallet_flush_from_context(ctx);
        if (!flushed.ok) {
            snprintf(error_out, error_size,
                     "cannot persist token keys before broadcast: %s",
                     flushed.message);
            LOG_FAIL("zslp", "publish: %s", error_out);
        }
    }

    struct zcl_result commit = wallet_commit_from_context(ctx, wtx);
    if (!commit.ok) {
        snprintf(error_out, error_size, "%s", commit.message);
        LOG_FAIL("zslp", "publish: commit failed code=%d: %s", commit.code,
                 commit.message);
    }
    struct zcl_result persisted = wallet_persist_commit_before_relay(ctx, wtx);
    if (!persisted.ok) {
        snprintf(error_out, error_size, "%s", persisted.message);
        LOG_FAIL("zslp", "publish: persistence failed code=%d: %s",
                 persisted.code, persisted.message);
    }
    if (wallet_ctx_db_ready(ctx))
        node_db_sync_wallet_tx(ctx->node_db, &wtx->tx, ctx->wallet, 0);
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &wtx->tx.hash);
    uint256_get_hex(&wtx->tx.hash, txid_out);
    return true;
}

/* ── Token creation (GENESIS) ────────────────────────────── */

const char *zslp_create_token_with_receipt(
    const char *datadir, const char *ticker, const char *name,
    uint8_t decimals, uint64_t initial_supply, struct zslp_tx_receipt *receipt)
{
    if (receipt)
        memset(receipt, 0, sizeof(*receipt));
    const char *effective_datadir = zslp_controller_datadir(datadir);
    struct zslp_token_create_request req = {
        .ticker = ticker,
        .name = name,
        .decimals = decimals,
        .initial_supply = initial_supply
    };
    const char *validation_error = NULL;
    if (!effective_datadir || !ticker || !name)
        LOG_NULL("zslp", "create_token: missing required param (datadir=%p ticker=%p name=%p)",
                 (const void *)effective_datadir, (const void *)ticker, (const void *)name);

    validation_error = zslp_service_validate_create_request(&req);
    if (validation_error)
        LOG_NULL("zslp", "create_token: %s", validation_error);

    /* Build transaction:
     *   vout[0]: OP_RETURN with GENESIS script (value=0)
     *   vout[1]: dust output to our address (receives initial supply)
     *   vout[2]: dust output to our address (mint baton)
     * Sign and broadcast via wallet. */
    char *broadcast_txid = NULL; /* set if we successfully broadcast */
    struct wallet *wallet = zslp_controller_wallet();
    struct tx_mempool *mempool = zslp_controller_mempool();

    if (!wallet || !mempool) {
        /* No wallet available (test mode) — skip on-chain broadcast,
         * just track in SQLite below. */
        goto store_sqlite;
    }

    struct wallet_tx wtx;
    int64_t fee_paid = 0;
    const char *tx_error = NULL;
    struct zcl_result built = zslp_command_build_token_genesis_tx(
        wallet, ticker, name, decimals, initial_supply, &wtx, &fee_paid,
        &tx_error);
    if (!built.ok)
        LOG_NULL("zslp", "create_token: tx build failed: %s",
                 tx_error ? tx_error : built.message);

    static char bc_txid[65];
    char publish_error[256] = {0};
    if (!zslp_controller_publish(&wtx, bc_txid, publish_error,
                                 sizeof(publish_error))) {
        transaction_free(&wtx.tx);
        return NULL;
    }
    broadcast_txid = bc_txid;
    if (receipt) {
        snprintf(receipt->txid, sizeof(receipt->txid), "%s", bc_txid);
        receipt->fee_paid = fee_paid;
        receipt->broadcast = true;
    }
    printf("ZSLP GENESIS broadcast: token_id=%s\n", broadcast_txid);
    transaction_free(&wtx.tx);

store_sqlite:
    ;
    static char result[128];
    if (!zslp_command_finalize_genesis(effective_datadir, broadcast_txid, &req,
                                       result).ok)
        LOG_NULL("zslp", "finalize_genesis failed for ticker=%s", ticker);
    return result;
}

const char *zslp_create_token(const char *datadir, const char *ticker,
                              const char *name, uint8_t decimals,
                              uint64_t initial_supply)
{
    return zslp_create_token_with_receipt(datadir, ticker, name, decimals,
                                          initial_supply, NULL);
}

/* ── Token balance ───────────────────────────────────────── */

uint64_t zslp_balance(const char *datadir,
                       const char *token_id_hex,
                       const char *addr)
{
    sqlite3 *db = NULL;
    bool owns_db = false;
    if (!zslp_controller_datadir(datadir) ||
        !zslp_service_validate_token_key(token_id_hex).ok ||
        !zslp_service_validate_recipient_addr(addr, false).ok) return 0;

    /* Scan the SQLite token_balances table */
    if (!zslp_open_runtime_db(datadir, &db, &owns_db))
        return 0;

    uint64_t bal = zslp_service_get_balance(db, token_id_hex, addr);
    zslp_service_close_db(db, owns_db);
    return bal;
}

/* ── Shielded payment address ────────────────────────────── */

bool zslp_generate_payment_address(const char *datadir,
                                    char *z_addr_out, size_t max)
{
    if (!zslp_controller_datadir(datadir))
        LOG_FAIL("zslp", "generate_payment_address: datadir not initialized");
    struct zcl_result r =
        zslp_payment_generate_address(zslp_controller_wallet(), z_addr_out, max);
    if (!r.ok)
        LOG_FAIL("zslp", "generate_payment_address: %s", r.message);
    return true;
}

/* ── Payment detection ───────────────────────────────────── */

int64_t zslp_check_payment(const char *datadir,
                            const char *z_addr,
                            int64_t min_amount)
{
    if (!zslp_controller_datadir(datadir))
        return 0;
    return zslp_payment_check_received(zslp_controller_datadir(datadir),
                                       z_addr, min_amount);
}

/* ── Token mint ──────────────────────────────────────────── */

bool zslp_mint_with_receipt(const char *datadir, const char *token_id_hex,
                            const char *recipient_addr, uint64_t amount,
                            struct zslp_tx_receipt *receipt)
{
    if (receipt)
        memset(receipt, 0, sizeof(*receipt));
    bool strict_chain_addr = (zslp_controller_wallet() != NULL &&
                              zslp_controller_mempool() != NULL);
    struct zslp_token_transfer_request req = {
        .token_id = token_id_hex,
        .recipient_addr = recipient_addr,
        .amount = amount,
        .strict_chain_addr = strict_chain_addr
    };
    const char *validation_error = NULL;
    if (!zslp_controller_datadir(datadir) ||
        !zslp_service_validate_token_key(token_id_hex).ok ||
        !recipient_addr)
        LOG_FAIL("zslp", "mint: invalid params (datadir=%p token=%p recipient=%p)",
                 (const void *)zslp_controller_datadir(datadir),
                 (const void *)token_id_hex, (const void *)recipient_addr);

    validation_error = zslp_service_validate_transfer_request(&req);
    if (validation_error)
        LOG_FAIL("zslp", "mint: %s", validation_error);

    /* Build and broadcast ZSLP MINT transaction on-chain */
    struct wallet *wallet = zslp_controller_wallet();
    struct tx_mempool *mempool = zslp_controller_mempool();
    if (!wallet || !mempool) {
        /* Credit-only merchant-store fixture mode. Production balances are
         * chain-derived and never change before a transaction confirms. */
        if (!zslp_command_credit_transfer(zslp_controller_datadir(datadir),
                                          &req).ok)
            LOG_FAIL("zslp", "mint: fixture balance update failed token=%s",
                     token_id_hex ? token_id_hex : "?");
        return true;
    }
    if (!zslp_controller_validity_ready(NULL, "zslp_mint"))
        return false; // raw-return-ok:readiness helper logged the refusal

    struct uint256 token_id;
    uint256_set_hex(&token_id, token_id_hex);
    if (uint256_is_null(&token_id))
        LOG_FAIL("zslp", "mint: invalid token_id for broadcast: %s",
                 token_id_hex ? token_id_hex : "(null)");

    struct wallet_tx wtx;
    int64_t fee_paid = 0;
    const char *tx_error = NULL;
    struct zcl_result built = zslp_command_build_token_mint_tx(
        wallet, token_id.data, recipient_addr, amount, &wtx, &fee_paid,
        &tx_error);
    if (!built.ok)
        LOG_FAIL("zslp", "mint: tx build failed: %s",
                 tx_error ? tx_error : built.message);
    char validity_reason[96];
    if (!zslp_validity_inputs_match(app_runtime_node_db(), &wtx.tx,
                                    token_id.data,
                                    ZSLP_LEDGER_MINT_BATON,
                                    validity_reason,
                                    sizeof(validity_reason))) {
        transaction_free(&wtx.tx);
        LOG_FAIL("zslp", "mint: selected baton is not VALID: %s",
                 validity_reason);
    }

    char txid[65];
    char publish_error[256] = {0};
    if (!zslp_controller_publish(&wtx, txid, publish_error,
                                 sizeof(publish_error))) {
        transaction_free(&wtx.tx);
        return false;
    }
    printf("ZSLP MINT broadcast: token=%s amount=%llu to=%s txid=%s\n",
           token_id_hex, (unsigned long long)amount, recipient_addr, txid);
    if (receipt) {
        snprintf(receipt->txid, sizeof(receipt->txid), "%s", txid);
        receipt->fee_paid = fee_paid;
        receipt->broadcast = true;
    }
    transaction_free(&wtx.tx);
    return true;
}

bool zslp_mint(const char *datadir, const char *token_id_hex,
               const char *recipient_addr, uint64_t amount)
{
    return zslp_mint_with_receipt(datadir, token_id_hex, recipient_addr,
                                  amount, NULL);
}

/* ── Token send ──────────────────────────────────────────── */

bool zslp_send_with_receipt(const char *datadir, const char *token_id_hex,
                            const char *to_addr, uint64_t amount,
                            struct zslp_tx_receipt *receipt)
{
    if (receipt)
        memset(receipt, 0, sizeof(*receipt));
    struct wallet *wallet = zslp_controller_wallet();
    struct tx_mempool *mempool = zslp_controller_mempool();
    struct zslp_token_transfer_request req = {
        .token_id = token_id_hex,
        .recipient_addr = to_addr,
        .amount = amount,
        .strict_chain_addr = (wallet != NULL && mempool != NULL)
    };
    const char *validation_error = NULL;
    if (!zslp_controller_datadir(datadir) ||
        !zslp_service_validate_token_key(token_id_hex).ok ||
        !to_addr)
        LOG_FAIL("zslp", "send: invalid params (datadir=%p token=%p to=%p)",
                 (const void *)zslp_controller_datadir(datadir),
                 (const void *)token_id_hex, (const void *)to_addr);
    validation_error = zslp_service_validate_transfer_request(&req);
    if (validation_error)
        LOG_FAIL("zslp", "send: %s", validation_error);

    if (!wallet || !mempool) {
        /* No wallet (test mode) — just update SQLite balances */
        struct zcl_result r =
            zslp_command_credit_transfer(zslp_controller_datadir(datadir), &req);
        if (!r.ok)
            LOG_FAIL("zslp", "send: balance update failed: %s", r.message);
        return true;
    }
    if (!zslp_controller_validity_ready(NULL, "zslp_send"))
        return false; // raw-return-ok:readiness helper logged the refusal

    struct uint256 token_id;
    uint256_set_hex(&token_id, token_id_hex);
    if (uint256_is_null(&token_id))
        LOG_FAIL("zslp", "send: invalid token_id: %s",
                 token_id_hex ? token_id_hex : "(null)");

    struct wallet_tx wtx;
    int64_t fee_paid = 0;
    const char *tx_error = NULL;
    struct zcl_result built = zslp_command_build_token_send_tx(
        wallet, token_id.data, to_addr, amount, &wtx, &fee_paid, &tx_error);
    if (!built.ok)
        LOG_FAIL("zslp", "send: tx build failed: %s",
                 tx_error ? tx_error : built.message);
    char validity_reason[96];
    if (!zslp_validity_inputs_match(app_runtime_node_db(), &wtx.tx,
                                    token_id.data, ZSLP_LEDGER_TOKEN,
                                    validity_reason,
                                    sizeof(validity_reason))) {
        transaction_free(&wtx.tx);
        LOG_FAIL("zslp", "send: selected inputs are not VALID: %s",
                 validity_reason);
    }

    char txid[65];
    char publish_error[256] = {0};
    if (!zslp_controller_publish(&wtx, txid, publish_error,
                                 sizeof(publish_error))) {
        transaction_free(&wtx.tx);
        return false;
    }
    printf("ZSLP SEND broadcast: token=%s amount=%llu to=%s txid=%s\n",
           token_id_hex, (unsigned long long)amount, to_addr, txid);
    if (receipt) {
        snprintf(receipt->txid, sizeof(receipt->txid), "%s", txid);
        receipt->fee_paid = fee_paid;
        receipt->broadcast = true;
    }
    transaction_free(&wtx.tx);
    return true;
}

bool zslp_send(const char *datadir, const char *token_id_hex,
               const char *to_addr, uint64_t amount)
{
    return zslp_send_with_receipt(datadir, token_id_hex, to_addr, amount,
                                  NULL);
}

/* ── RPC handlers ────────────────────────────────────────── */

void zslp_rpc_set_datadir(const char *datadir)
{
    zslp_ctx()->datadir = datadir;
}

static bool zslp_parse_token_param(const struct json_value *params, size_t index,
                                   const char **token_id,
                                   struct json_value *result);
static bool zslp_parse_addr_param(const struct json_value *params, size_t index,
                                  bool strict_chain_addr, const char **addr,
                                  struct json_value *result);

static void zslp_render_token_json(struct json_value *out,
                                   const struct db_zslp_token_info *token)
{
    json_set_object(out);
    json_push_kv_str(out, "token_id", token->token_id);
    json_push_kv_str(out, "ticker", token->ticker);
    json_push_kv_str(out, "name", token->name);
    json_push_kv_int(out, "decimals", token->decimals);
    json_push_kv_int(out, "genesis_height", token->genesis_height);
    json_push_kv_int(out, "total_minted", token->total_minted);
    zslp_controller_render_validity(out, token);
}

static bool zslp_parse_create_request(const struct json_value *params,
                                      struct zslp_token_create_request *req,
                                      struct json_value *result)
{
    const char *validation_error;

    req->ticker = json_get_str(json_at(params, 0));
    req->name = json_get_str(json_at(params, 1));
    req->decimals = (uint8_t)json_get_int(json_at(params, 2));
    req->initial_supply = 0;
    if (!req->ticker || !req->name) {
        json_set_str(result, "invalid parameters");
        return false;
    }
    validation_error = zslp_service_validate_create_request(req);
    if (validation_error && strcmp(validation_error,
            "initial supply exceeds maximum") != 0) {
        json_set_str(result, validation_error);
        return false;
    }
    if (!zslp_controller_parse_amount(json_at(params, 3), &req->initial_supply)) {
        json_set_str(result, "supply must be a positive integer");
        return false;
    }
    validation_error = zslp_service_validate_create_request(req);
    if (validation_error) {
        json_set_str(result, validation_error);
        return false;
    }
    return true;
}

static bool zslp_parse_transfer_request(const struct json_value *params,
                                        bool strict_chain_addr,
                                        struct zslp_token_transfer_request *req,
                                        struct json_value *result)
{
    const char *validation_error;

    if (!zslp_parse_token_param(params, 0, &req->token_id, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_parse_addr_param(params, 1, strict_chain_addr,
                               &req->recipient_addr, result))
        return false;
    if (!zslp_controller_parse_amount(json_at(params, 2), &req->amount)) {
        json_set_str(result, "amount must be a positive integer");
        return false;
    }
    req->strict_chain_addr = strict_chain_addr;
    validation_error = zslp_service_validate_transfer_request(req);
    if (validation_error) {
        json_set_str(result, validation_error);
        return false;
    }
    return true;
}

static bool zslp_parse_token_param(const struct json_value *params, size_t index,
                                   const char **token_id,
                                   struct json_value *result)
{
    *token_id = json_get_str(json_at(params, index));
    return zslp_controller_require_token(*token_id, result);
}

static bool zslp_parse_addr_param(const struct json_value *params, size_t index,
                                  bool strict_chain_addr, const char **addr,
                                  struct json_value *result)
{
    *addr = json_get_str(json_at(params, index));
    return zslp_controller_require_address(*addr, strict_chain_addr, result);
}

static bool zslp_rpc_require_context(struct json_value *result)
{
    if (!zslp_controller_datadir(NULL)) {
        json_set_str(result, "zslp runtime/datadir not initialized");
        return false;
    }
    return true;
}

/* zslp_createtoken "ticker" "name" decimals supply */
static bool rpc_zslp_createtoken(const struct json_value *params,
                                   bool help, struct json_value *result)
{
    struct zslp_token_create_request req;
    if (help || !params || json_size(params) < 4) {
        json_set_str(result,
            "zslp_createtoken \"ticker\" \"name\" decimals supply");
        return !help;
    }
    if (!zslp_sovereignty_spend_guard(result, "zslp_createtoken"))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (zslp_controller_wallet() && zslp_controller_mempool() &&
        !zslp_controller_validity_ready(result, "zslp_createtoken"))
        return false; // raw-return-ok:RPC error body already set
    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_parse_create_request(params, &req, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)

    const char *token_id = zslp_create_token(NULL, req.ticker, req.name,
        req.decimals, req.initial_supply);
    if (token_id)
        json_set_str(result, token_id);
    else {
        json_set_str(result, "token creation failed");
        return false;
    }
    return true;
}

/* zslp_send "token_id" "address" amount */
static bool rpc_zslp_send(const struct json_value *params,
                             bool help, struct json_value *result)
{
    struct zslp_token_transfer_request req;
    bool strict_chain_addr;
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "zslp_send \"token_id\" \"address\" amount");
        return !help;
    }
    if (!zslp_sovereignty_spend_guard(result, "zslp_send"))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (zslp_controller_wallet() && zslp_controller_mempool() &&
        !zslp_controller_validity_ready(result, "zslp_send"))
        return false; // raw-return-ok:RPC error body already set
    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    strict_chain_addr = (zslp_controller_wallet() != NULL &&
                         zslp_controller_mempool() != NULL);
    if (!zslp_parse_transfer_request(params, strict_chain_addr, &req, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)

    bool ok = zslp_send(NULL, req.token_id, req.recipient_addr, req.amount);
    json_set_bool(result, ok);
    return ok;
}

/* zslp_balance "token_id" "address" */
static bool rpc_zslp_balance(const struct json_value *params,
                               bool help, struct json_value *result)
{
    const char *token_id = NULL;
    const char *addr = NULL;
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "zslp_balance \"token_id\" \"address\"");
        return !help;
    }

    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_parse_token_param(params, 0, &token_id, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_parse_addr_param(params, 1, false, &addr, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)

    uint64_t bal = zslp_balance(NULL, token_id, addr);
    json_set_int(result, (int64_t)bal);
    return true;
}

/* zslp_mint "token_id" "address" amount */
static bool rpc_zslp_mint(const struct json_value *params,
                             bool help, struct json_value *result)
{
    struct zslp_token_transfer_request req;
    bool strict_chain_addr;
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "zslp_mint \"token_id\" \"address\" amount");
        return !help;
    }
    if (!zslp_sovereignty_spend_guard(result, "zslp_mint"))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (zslp_controller_wallet() && zslp_controller_mempool() &&
        !zslp_controller_validity_ready(result, "zslp_mint"))
        return false; // raw-return-ok:RPC error body already set
    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    strict_chain_addr = (zslp_controller_wallet() != NULL &&
                         zslp_controller_mempool() != NULL);
    if (!zslp_parse_transfer_request(params, strict_chain_addr, &req, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)

    bool ok = zslp_mint(NULL, req.token_id, req.recipient_addr, req.amount);
    json_set_bool(result, ok);
    return ok;
}

static bool rpc_zslp_gettoken(const struct json_value *params,
                              bool help, struct json_value *result)
{
    sqlite3 *db = NULL;
    bool owns_db = false;
    const char *token_id = NULL;
    struct db_zslp_token_info token;

    if (help || !params || json_size(params) < 1) {
        json_set_str(result, "zslp_gettoken \"token_id\"");
        return !help;
    }
    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_parse_token_param(params, 0, &token_id, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_open_runtime_db(NULL, &db, &owns_db)) {
        json_set_str(result, "zslp database unavailable");
        return false;
    }
    if (!zslp_service_get_token(db, token_id, &token).ok) {
        zslp_service_close_db(db, owns_db);
        json_set_str(result, "token not found");
        return false;
    }
    zslp_service_close_db(db, owns_db);

    zslp_render_token_json(result, &token);
    return true;
}

static bool rpc_zslp_listtokens(const struct json_value *params,
                                bool help, struct json_value *result)
{
    sqlite3 *db = NULL;
    bool owns_db = false;
    struct db_zslp_token_info tokens[64];
    int count = 0;
    int64_t limit = 50;

    if (help) {
        json_set_str(result, "zslp_listtokens ( limit )");
        return false;
    }
    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (params && json_size(params) > 0) {
        limit = json_get_int(json_at(params, 0));
        if (limit <= 0 || limit > 64) {
            json_set_str(result, "limit must be between 1 and 64");
            return false;
        }
    }
    if (!zslp_open_runtime_db(NULL, &db, &owns_db)) {
        json_set_str(result, "zslp database unavailable");
        return false;
    }
    count = zslp_service_list_tokens(db, tokens, (size_t)limit);
    zslp_service_close_db(db, owns_db);

    json_set_array(result);
    for (int i = 0; i < count; i++) {
        struct json_value entry = {0};
        json_init(&entry);
        zslp_render_token_json(&entry, &tokens[i]);
        json_push_back(result, &entry);
    }
    return true;
}

static bool rpc_zslp_listtransfers(const struct json_value *params,
                                   bool help, struct json_value *result)
{
    sqlite3 *db = NULL;
    bool owns_db = false;
    const char *token_id = NULL;
    struct db_zslp_transfer_info transfers[64];
    int count = 0;
    int64_t limit = 50;

    if (help || !params || json_size(params) < 1) {
        json_set_str(result, "zslp_listtransfers \"token_id\" ( limit )");
        return !help;
    }
    if (!zslp_rpc_require_context(result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (!zslp_parse_token_param(params, 0, &token_id, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)
    if (json_size(params) > 1) {
        limit = json_get_int(json_at(params, 1));
        if (limit <= 0 || limit > 64) {
            json_set_str(result, "limit must be between 1 and 64");
            return false;
        }
    }
    if (!zslp_open_runtime_db(NULL, &db, &owns_db)) {
        json_set_str(result, "zslp database unavailable");
        return false;
    }
    count = zslp_service_list_transfers(db, token_id, transfers, (size_t)limit);
    zslp_service_close_db(db, owns_db);

    json_set_array(result);
    for (int i = 0; i < count; i++) {
        struct json_value entry = {0};
        json_init(&entry);
        zslp_controller_render_transfer(&entry, &transfers[i]);
        json_push_back(result, &entry);
    }
    return true;
}

void register_zslp_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "zslp", "zslp_createtoken", rpc_zslp_createtoken, false },
        { "zslp", "zslp_gettoken",    rpc_zslp_gettoken,    true  },
        { "zslp", "zslp_listtokens",  rpc_zslp_listtokens,  true  },
        { "zslp", "zslp_listtransfers", rpc_zslp_listtransfers, true },
        { "zslp", "zslp_send",       rpc_zslp_send,         false },
        { "zslp", "zslp_balance",    rpc_zslp_balance,      true  },
        { "zslp", "zslp_mint",       rpc_zslp_mint,         false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
    register_zslp_transaction_rpc_commands(t);
}
