/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the yardsale wallet-glue RPC methods — wallet-context adapters
 * over services/yardsale_wallet_service.h (which holds every rule). The
 * native yardsale.seller.* / yardsale.buy leaves forward to these from
 * the CLI; the wallet, seller profile, and pending-buy table are all
 * process memory here. Params arrive as one input object:
 *   yardsale_seller_arm {token_txid, token_vout, ad_root, confirm?}
 *   yardsale_buy        {ad_root, confirm?}
 * both with an optional now_unix (operator-pinned clock, same convention
 * as the science plan/commit methods); disarm/status take none. */

#include "controllers/yardsale_wallet_controller.h"

#include "base/hex.h"
#include "controllers/native_handler_body.h"
#include "controllers/strong_params.h"
#include "controllers/wallet_helpers.h"
#include "controllers/yardsale_controller.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/yardsale_wallet_service.h"
#include "util/log_macros.h"

#include <string.h>

/* The service rides a port (shape-direction gate: services never include
 * controllers/); the enum yardsale_error crosses as int. */
static int ywc_buyer_begin(const struct zswap_quote_v1 *ad,
                           const struct zswap_buyer_accept *buyer,
                           const struct privkey *input_keys,
                           size_t num_keys, int64_t now_unix,
                           uint8_t *wire_out, size_t wire_cap,
                           size_t *wire_len)
{
    return (int)yardsale_buyer_begin(ad, buyer, input_keys, num_keys,
                                     now_unix, wire_out, wire_cap, wire_len);
}

static void ywc_error(struct json_value *out, const char *code,
                      const char *msg)
{
    json_set_object(out);
    json_push_kv_bool(out, "ok", false);
    json_push_kv_str(out, "code", code);
    json_push_kv_str(out, "message", msg);
}

static bool ywc_hex32(const char *s, uint8_t out[32])
{
    return s && strlen(s) == 64 && zcl_hex_decode_lower(s, out, 32);
}

/* The wallet + plan ledger must both be reachable; everything else the
 * service names itself. */
static bool ywc_ready(struct wallet_rpc_context *ctx,
                      struct json_value *result)
{
    if (!ctx || !ctx->wallet) {
        ywc_error(result, "WALLET_UNAVAILABLE",
                  "the in-process wallet is not available");
        return false;
    }
    if (!ctx->node_db || !ctx->node_db->open) {
        ywc_error(result, "DATABASE_UNAVAILABLE",
                  "node.db is unavailable — the plan ledger cannot persist");
        return false;
    }
    return true;
}

static int64_t ywc_now(const struct json_value *input)
{
    const struct json_value *pinned =
        input ? json_get(input, "now_unix") : NULL;
    if (pinned && pinned->type == JSON_INT && json_get_int(pinned) > 0)
        return json_get_int(pinned);
    return (int64_t)platform_time_wall_time_t();
}

static bool rpc_yardsale_seller_arm(const struct json_value *params,
                                    bool help, struct json_value *result)
{
    RPC_HELP(help, result,
        "yardsale_seller_arm {token_txid,token_vout,ad_root,confirm?}\n");
    const struct json_value *input = json_at(params, 0);
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!input || input->type != JSON_OBJ) {
        ywc_error(result, "INVALID_INPUT", "one input object is required");
        return true;
    }
    if (!ywc_ready(ctx, result))
        return true;
    uint8_t token_txid[32], ad_root[32];
    const struct json_value *vout = json_get(input, "token_vout");
    if (!ywc_hex32(json_get_str(json_get(input, "token_txid")), token_txid) ||
        !vout || vout->type != JSON_INT || json_get_int(vout) < 0 ||
        json_get_int(vout) > UINT32_MAX ||
        !ywc_hex32(json_get_str(json_get(input, "ad_root")), ad_root)) {
        ywc_error(result, "INVALID_INPUT",
                  "token_txid (64 hex), token_vout (0..2^32-1), and ad_root "
                  "(64 hex) are required");
        return true;
    }
    (void)yardsale_wallet_seller_arm(
        ctx->wallet, ctx->node_db, token_txid, (uint32_t)json_get_int(vout),
        ad_root, json_get_bool_or(input, "confirm", false),
        ywc_now(input), result);
    return true;
}

static bool rpc_yardsale_seller_disarm(const struct json_value *params,
                                       bool help, struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result, "yardsale_seller_disarm\n");
    (void)yardsale_wallet_seller_disarm(result);
    return true;
}

static bool rpc_yardsale_seller_status(const struct json_value *params,
                                       bool help, struct json_value *result)
{
    RPC_HELP(help, result, "yardsale_seller_status\n");
    const struct json_value *input = json_at(params, 0);
    (void)yardsale_wallet_seller_status(ywc_now(input), result);
    return true;
}

static bool rpc_yardsale_buy(const struct json_value *params, bool help,
                             struct json_value *result)
{
    RPC_HELP(help, result, "yardsale_buy {ad_root,confirm?}\n");
    const struct json_value *input = json_at(params, 0);
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!input || input->type != JSON_OBJ) {
        ywc_error(result, "INVALID_INPUT", "one input object is required");
        return true;
    }
    if (!ywc_ready(ctx, result))
        return true;
    uint8_t ad_root[32];
    if (!ywc_hex32(json_get_str(json_get(input, "ad_root")), ad_root)) {
        ywc_error(result, "INVALID_INPUT",
                  "ad_root (64 hex) is required");
        return true;
    }
    (void)yardsale_wallet_buy(ctx->wallet, ctx->node_db, ad_root,
                              json_get_bool_or(input, "confirm", false),
                              ywc_now(input), result);
    return true;
}

void register_yardsale_wallet_rpc_commands(struct rpc_table *t)
{
    static const struct yardsale_wallet_ceremony_port port = {
        .seller_profile_configure = yardsale_seller_profile_configure,
        .seller_profile_clear = yardsale_seller_profile_clear,
        .seller_profile_configured = yardsale_seller_profile_configured,
        .seller_profile_snapshot = yardsale_seller_profile_snapshot,
        .pending_count = yardsale_pending_count,
        .buyer_begin = ywc_buyer_begin,
        .buyer_error_string = yardsale_error_string,
    };
    const struct rpc_command cmds[] = {
        { "wallet", "yardsale_seller_arm",    rpc_yardsale_seller_arm,    false },
        { "wallet", "yardsale_seller_disarm", rpc_yardsale_seller_disarm, false },
        { "wallet", "yardsale_seller_status", rpc_yardsale_seller_status, false },
        { "wallet", "yardsale_buy",           rpc_yardsale_buy,           false },
    };
    yardsale_wallet_set_ceremony_port(&port);
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
