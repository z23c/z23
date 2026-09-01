/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Receipt-bearing ZSLP RPC port for typed native plan/commit commands. */

#include "controllers/zslp_controller.h"
#include "controllers/sovereignty_controller.h"
#include "services/zslp_service.h"
#include "rpc/server.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "wallet/wallet.h"
#include "zslp/slp.h"

#include <stdint.h>
#include <stdio.h>

/* Implemented by the custody-bound intent controller. */
void register_zslp_intent_rpc_command(struct rpc_table *table);

static bool zslp_tx_rpc_units(const struct json_value *v, uint64_t *out)
{
    const char *s = json_get_str(v);
    if (!s || !s[0]) return false;
    uint64_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (n > (UINT64_MAX - digit) / 10) return false;
        n = n * 10 + digit;
    }
    if (n == 0) return false;
    *out = n;
    return true;
}

static bool zslp_tx_rpc_coin_reserved(const struct transaction *tx,
                                      uint32_t vout, void *ctx)
{
    (void)ctx;
    struct slp_output_metadata meta;
    return slp_classify_tx_output(tx, vout, &meta);
}

static bool zslp_tx_rpc_guard(struct json_value *result, const char *verb)
{
    char reason[96] = {0};
    if (sovereignty_guard_allow("wallet_spend", reason, sizeof(reason)))
        return true;
    json_set_str(result, "Error: spend refused — tip is release_assisted "
                         "(borrowed shielded history, not self-folded)");
    LOG_FAIL("zslp.txrpc", "%s refused: %s", verb, reason);
}

static void zslp_tx_rpc_receipt(struct json_value *out,
                                const struct zslp_tx_receipt *receipt)
{
    json_set_object(out);
    json_push_kv_str(out, "status", "broadcast");
    json_push_kv_str(out, "txid", receipt->txid);
    json_push_kv_int(out, "fee", receipt->fee_paid);
}

static bool zslp_tx_rpc_transfer_request(const struct json_value *params,
                                         struct zslp_token_transfer_request *r,
                                         struct json_value *result)
{
    r->token_id = json_get_str(json_at(params, 0));
    r->recipient_addr = json_get_str(json_at(params, 1));
    r->amount = 0;
    if (!zslp_tx_rpc_units(json_at(params, 2), &r->amount)) {
        json_set_str(result, "units must be an unsigned decimal string");
        LOG_FAIL("zslp.txrpc", "invalid transfer units");
    }
    r->strict_chain_addr = true;
    const char *why = zslp_service_validate_transfer_request(r);
    if (!why)
        return true;
    json_set_str(result, why);
    LOG_FAIL("zslp.txrpc", "invalid transfer request: %s", why);
}

static bool rpc_zslp_createtoken_tx(const struct json_value *params,
                                    bool help, struct json_value *result)
{
    if (help || !params || json_size(params) < 4) {
        json_set_str(result,
            "zslp_createtoken_tx \"ticker\" \"name\" decimals supply");
        return !help;
    }
    uint64_t supply = 0;
    if (!zslp_tx_rpc_units(json_at(params, 3), &supply)) {
        json_set_str(result, "supply must be an unsigned decimal string");
        LOG_FAIL("zslp.txrpc", "invalid genesis supply");
    }
    struct zslp_token_create_request req = {
        .ticker = json_get_str(json_at(params, 0)),
        .name = json_get_str(json_at(params, 1)),
        .decimals = (uint8_t)json_get_int(json_at(params, 2)),
        .initial_supply = supply,
    };
    const char *why = zslp_service_validate_create_request(&req);
    if (!zslp_tx_rpc_guard(result, "zslp_createtoken_tx"))
        return false; // raw-return-ok:RPC error body already set
    if (why) {
        json_set_str(result, why);
        LOG_FAIL("zslp.txrpc", "invalid create request: %s", why);
    }
    struct zslp_tx_receipt receipt;
    const char *token_id = zslp_create_token_with_receipt(
        NULL, req.ticker, req.name, req.decimals, req.initial_supply, &receipt);
    if (!token_id || !receipt.broadcast) {
        json_set_str(result, "token creation was not broadcast");
        LOG_FAIL("zslp.txrpc", "create returned no broadcast receipt");
    }
    zslp_tx_rpc_receipt(result, &receipt);
    json_push_kv_str(result, "token_id", token_id);
    return true;
}

static bool zslp_tx_rpc_move(const struct json_value *params, bool help,
                             struct json_value *result, bool mint)
{
    const char *method = mint ? "zslp_mint_tx" : "zslp_send_tx";
    if (help || !params || json_size(params) < 3) {
        json_set_str(result, mint
            ? "zslp_mint_tx \"token_id\" \"address\" amount"
            : "zslp_send_tx \"token_id\" \"address\" amount");
        return !help;
    }
    struct zslp_token_transfer_request req;
    if (!zslp_tx_rpc_guard(result, method) ||
        !zslp_tx_rpc_transfer_request(params, &req, result))
        return false; // raw-return-ok:RPC error body already set
    struct zslp_tx_receipt receipt;
    bool ok = mint
        ? zslp_mint_with_receipt(NULL, req.token_id, req.recipient_addr,
                                 req.amount, &receipt)
        : zslp_send_with_receipt(NULL, req.token_id, req.recipient_addr,
                                 req.amount, &receipt);
    if (!ok || !receipt.broadcast) {
        json_set_str(result, mint ? "token mint was not broadcast"
                                  : "token send was not broadcast");
        LOG_FAIL("zslp.txrpc", "%s returned no broadcast receipt", method);
    }
    zslp_tx_rpc_receipt(result, &receipt);
    json_push_kv_str(result, "token_id", req.token_id);
    json_push_kv_str(result, "to", req.recipient_addr);
    char units[32];
    snprintf(units, sizeof(units), "%llu",
             (unsigned long long)req.amount);
    json_push_kv_str(result, "units", units);
    return true;
}

static bool rpc_zslp_send_tx(const struct json_value *params, bool help,
                             struct json_value *result)
{
    return zslp_tx_rpc_move(params, help, result, false);
}

static bool rpc_zslp_mint_tx(const struct json_value *params, bool help,
                             struct json_value *result)
{
    return zslp_tx_rpc_move(params, help, result, true);
}

static bool rpc_zslp_burn_tx(const struct json_value *params, bool help,
                             struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result, "zslp_burn_tx \"token_id\" \"units\"");
        return !help;
    }
    const char *token_id = json_get_str(json_at(params, 0));
    uint64_t units = 0;
    if (!token_id || !zslp_tx_rpc_units(json_at(params, 1), &units)) {
        json_set_str(result, "token_id and unsigned decimal units required");
        LOG_FAIL("zslp.txrpc", "invalid burn request");
    }
    if (!zslp_tx_rpc_guard(result, "zslp_burn_tx"))
        return false; // raw-return-ok:RPC error body already set
    struct zslp_tx_receipt receipt;
    if (!zslp_burn_with_receipt(NULL, token_id, units, &receipt) ||
        !receipt.broadcast) {
        json_set_str(result, "token burn was not broadcast");
        LOG_FAIL("zslp.txrpc", "burn returned no broadcast receipt");
    }
    zslp_tx_rpc_receipt(result, &receipt);
    json_push_kv_str(result, "token_id", token_id);
    char amount[32];
    snprintf(amount, sizeof(amount), "%llu", (unsigned long long)units);
    json_push_kv_str(result, "burned_units", amount);
    return true;
}

void register_zslp_transaction_rpc_commands(struct rpc_table *t)
{
    wallet_set_coin_reservation_probe(zslp_tx_rpc_coin_reserved, NULL);
    struct rpc_command commands[] = {
        { "zslp", "zslp_createtoken_tx", rpc_zslp_createtoken_tx, false },
        { "zslp", "zslp_send_tx", rpc_zslp_send_tx, false },
        { "zslp", "zslp_mint_tx", rpc_zslp_mint_tx, false },
        { "zslp", "zslp_burn_tx", rpc_zslp_burn_tx, false },
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
        rpc_table_must_append(t, &commands[i]);
    register_zslp_intent_rpc_command(t);
}
