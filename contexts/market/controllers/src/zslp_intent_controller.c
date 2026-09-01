/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Wallet adapter and RPC for durable ZSLP transaction intents. */

#include "zslp_controller_internal.h"

#include "controllers/native_handler_body.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/wallet_helpers.h"
#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zslp.h"
#include "models/zslp_validity.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "services/wallet_money_service.h"
#include "services/zslp_command_service.h"
#include "services/zslp_transaction_intent_service.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct zcl_result ztic_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct wallet_rpc_context *ctx = opaque;
    return wallet_money_snapshot_build(ctx ? ctx->node_db : NULL,
                                       ctx ? ctx->main_state : NULL,
                                       scope, out);
}

static struct zcl_result ztic_prepare(
    void *opaque, const struct zslp_intent_request *request,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat,
    struct vault_intent_input *inputs, size_t input_capacity,
    size_t *input_count)
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !request || !raw_tx || !raw_tx_len ||
        !txid_out || !actual_fee_zat || !inputs || !input_count ||
        maximum_fee_zat <= 0)
        return ZCL_ERR(-1, "ZSLP wallet prepare context is incomplete");
    if (request->operation != ZSLP_INTENT_GENESIS &&
        !zslp_controller_validity_ready(NULL, "zslp_intent_prepare"))
        return ZCL_ERR(-2, "strict ZSLP validity is not current");
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    int64_t fee = 0;
    const char *why = NULL;
    struct zcl_result built;
    struct uint256 token_id; uint256_set_null(&token_id);
    if (request->operation != ZSLP_INTENT_GENESIS)
        uint256_set_hex(&token_id, request->token_id);
    switch (request->operation) {
    case ZSLP_INTENT_GENESIS:
        built = zslp_command_build_token_genesis_tx(
            ctx->wallet, request->ticker, request->name, request->decimals,
            request->supply, &wtx, &fee, &why);
        break;
    case ZSLP_INTENT_MINT:
        built = zslp_command_build_token_mint_tx(
            ctx->wallet, token_id.data, request->recipient, request->units,
            &wtx, &fee, &why);
        break;
    case ZSLP_INTENT_SEND:
        built = zslp_command_build_token_send_tx(
            ctx->wallet, token_id.data, request->recipient, request->units,
            &wtx, &fee, &why);
        break;
    case ZSLP_INTENT_BURN:
        built = zslp_command_build_token_burn_tx(
            ctx->wallet, token_id.data, request->units, &wtx, &fee, &why);
        break;
    default:
        return ZCL_ERR(-3, "unknown ZSLP wallet operation");
    }
    if (!built.ok)
        return ZCL_ERR(-4, "ZSLP exact transaction build failed: %s",
                       why ? why : built.message);
    if (fee < 0 || fee > maximum_fee_zat || wtx.tx.num_vin == 0 ||
        wtx.tx.num_vin > input_capacity) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-5, "ZSLP transaction exceeds fee or input contract");
    }
    if (request->operation == ZSLP_INTENT_MINT ||
        request->operation == ZSLP_INTENT_SEND ||
        request->operation == ZSLP_INTENT_BURN) {
        enum zslp_ledger_role role = request->operation == ZSLP_INTENT_MINT
            ? ZSLP_LEDGER_MINT_BATON : ZSLP_LEDGER_TOKEN;
        char reason[96];
        if (!zslp_validity_inputs_match(ctx->node_db, &wtx.tx,
                                        token_id.data, role, reason,
                                        sizeof(reason))) {
            transaction_free(&wtx.tx);
            return ZCL_ERR(-6, "ZSLP selected inputs are not VALID: %s", reason);
        }
    }
    struct zcl_result flushed = wallet_flush_from_context(ctx);
    if (!flushed.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-7, "ZSLP plan key persistence failed: %s",
                       flushed.message);
    }
    struct byte_stream stream;
    stream_init(&stream, 1024);
    bool serialized = transaction_serialize(&wtx.tx, &stream) &&
                      stream.size <= raw_capacity;
    if (serialized) {
        memcpy(raw_tx, stream.data, stream.size);
        *raw_tx_len = stream.size;
        memcpy(txid_out, wtx.tx.hash.data, 32);
        *actual_fee_zat = fee;
        *input_count = wtx.tx.num_vin;
        for (size_t i = 0; i < wtx.tx.num_vin; i++) {
            memcpy(inputs[i].txid, wtx.tx.vin[i].prevout.hash.data, 32);
            inputs[i].vout = wtx.tx.vin[i].prevout.n;
        }
    }
    stream_free(&stream);
    transaction_free(&wtx.tx);
    return serialized ? ZCL_OK
                      : ZCL_ERR(-8, "prepared ZSLP transaction is too large");
}

static struct zcl_result ztic_publish(
    void *opaque, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32])
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !raw_tx || raw_tx_len == 0 || !expected_txid)
        return ZCL_ERR(-1, "ZSLP publish context is incomplete");
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    struct byte_stream stream;
    stream_init_from_data(&stream, raw_tx, raw_tx_len);
    bool decoded = transaction_deserialize(&wtx.tx, &stream) &&
                   stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (!decoded) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-2, "prepared ZSLP transaction failed to decode");
    }
    transaction_compute_hash(&wtx.tx);
    if (memcmp(wtx.tx.hash.data, expected_txid, 32) != 0) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-3, "prepared ZSLP transaction identity changed");
    }
    if (wallet_get_tx(ctx->wallet, &wtx.tx.hash)) {
        if (ctx->connman) connman_relay_transaction(ctx->connman, &wtx.tx.hash);
        transaction_free(&wtx.tx);
        return ZCL_OK;
    }
    char txid[65], error[256] = {0};
    bool published = zslp_controller_publish(&wtx, txid, error, sizeof(error));
    transaction_free(&wtx.tx);
    return published ? ZCL_OK
                     : ZCL_ERR(-4, "ZSLP publication failed: %s", error);
}

static struct zcl_result ztic_runtime(struct zslp_intent_runtime *out,
                                      struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!out || !vault_intent_context_ready(ctx, result))
        return ZCL_ERR(-1, "ZSLP custody context is not ready");
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    if (!tip) return ZCL_ERR(-2, "ZSLP active tip is unavailable");
    memset(out, 0, sizeof(*out));
    out->node_db = ctx->node_db;
    out->read_money = ztic_money; out->money_ctx = ctx;
    out->prepare = ztic_prepare; out->prepare_ctx = ctx;
    out->publish = ztic_publish; out->publish_ctx = ctx;
    out->tip_height = tip->nHeight;
    memcpy(out->tip_hash, tip->hashBlock.data, 32);
    out->maximum_fee_zat = wallet_default_fee(ctx->wallet);
    out->now_unix = (int64_t)platform_time_wall_time_t();
    return ZCL_OK;
}

static bool ztic_units(const struct json_value *value, uint64_t *out)
{
    if (!value || !out) return false;
    if (value->type == JSON_INT && json_get_int(value) > 0) {
        *out = (uint64_t)json_get_int(value);
        return true;
    }
    const char *text = value->type == JSON_STR ? json_get_str(value) : NULL;
    if (!text || !text[0]) return false;
    uint64_t parsed = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (parsed > (UINT64_MAX - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0) return false;
    *out = parsed;
    return true;
}

static void ztic_render(const struct zslp_intent_result *intent,
                        struct json_value *result)
{
    char plan_id[65], txid[65], root[65], digest[65], units[32];
    HexStr(intent->plan_id, 32, false, plan_id, sizeof(plan_id));
    HexStr(intent->snapshot_root, 32, false, root, sizeof(root));
    HexStr(intent->plan_digest, 32, false, digest, sizeof(digest));
    snprintf(units, sizeof(units), "%llu",
             (unsigned long long)intent->units);
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.app_token_txresult.v1");
    json_push_kv_str(result, "wallet_scope", intent->wallet_scope);
    json_push_kv_str(result, "wallet_instance_id",
                     intent->wallet_instance_id);
    json_push_kv_str(result, "network_genesis", intent->network_genesis);
    json_push_kv_str(result, "operation",
                     zslp_intent_operation_name(intent->operation));
    json_push_kv_str(result, "plan_id", plan_id);
    json_push_kv_str(result, "state", intent->state);
    json_push_kv_str(result, "status",
                     intent->broadcast ? "broadcast" : "planned");
    json_push_kv_str(result, "token_id", intent->token_id);
    json_push_kv_str(result, "units", units);
    json_push_kv_int(result, "actual_fee_zat", intent->actual_fee_zat);
    json_push_kv_int(result, "maximum_fee_zat", intent->maximum_fee_zat);
    json_push_kv_int(result, "reserved_zat", intent->reserved_zat);
    json_push_kv_int(result, "expires_at", intent->expires_at);
    json_push_kv_str(result, "money_snapshot_root", root);
    json_push_kv_str(result, "money_status", "CURRENT");
    json_push_kv_str(result, "plan_digest", digest);
    json_push_kv_bool(result, "idempotent_replay", intent->idempotent_replay);
    json_push_kv_bool(result, "owner_commit_required", !intent->broadcast);
    if (intent->has_txid) {
        struct uint256 hash; memcpy(hash.data, intent->txid, 32);
        uint256_get_hex(&hash, txid);
        json_push_kv_str(result, "txid", txid);
    }
}

static bool rpc_zslp_intent(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zslp_intent plan {wallet_scope,operation,...,idempotency_key}\n"
            "zslp_intent commit {wallet_scope,plan_id,confirm:true}\n");
        return true;
    }
    const struct json_value *input = params && json_size(params)
        ? json_at(params, 0) : NULL;
    if (!input || input->type != JSON_OBJ) {
        json_set_str(result, "zslp_intent requires one object");
        return false;
    }
    const char *scope = json_get_str(json_get(input, "wallet_scope"));
    bool confirm = json_get_bool_or(input, "confirm", false);
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0)) {
        json_set_str(result, "zslp_intent requires wallet_scope=dev|prod");
        return false;
    }
    struct zslp_intent_runtime runtime;
    struct zcl_result ready = ztic_runtime(&runtime, result);
    if (!ready.ok) return false; /* result already carries the custody reason */
    struct zslp_intent_result intent;
    struct zcl_result outcome;
    if (confirm) {
        const char *plan_hex = json_get_str(json_get(input, "plan_id"));
        uint8_t plan_id[32];
        if (!plan_hex || strlen(plan_hex) != 64 || !IsHex(plan_hex) ||
            ParseHex(plan_hex, plan_id, sizeof(plan_id)) != 32) {
            json_set_str(result, "commit requires a 64-hex plan_id");
            return false;
        }
        outcome = zslp_transaction_intent_commit(
            &runtime, scope, plan_id, &intent);
    } else {
        const char *operation = json_get_str(json_get(input, "operation"));
        const char *idempotency =
            json_get_str(json_get(input, "idempotency_key"));
        struct zslp_intent_request request; memset(&request, 0, sizeof(request));
        snprintf(request.wallet_scope, sizeof(request.wallet_scope), "%s", scope);
        if (operation && strcmp(operation, "genesis") == 0)
            request.operation = ZSLP_INTENT_GENESIS;
        else if (operation && strcmp(operation, "mint") == 0)
            request.operation = ZSLP_INTENT_MINT;
        else if (operation && strcmp(operation, "send") == 0)
            request.operation = ZSLP_INTENT_SEND;
        else if (operation && strcmp(operation, "burn") == 0)
            request.operation = ZSLP_INTENT_BURN;
        const char *ticker = json_get_str(json_get(input, "ticker"));
        const char *name = json_get_str(json_get(input, "name"));
        const char *token = json_get_str(json_get(input, "token_id"));
        const char *recipient = json_get_str(json_get(input, "to"));
        if (!idempotency || strlen(idempotency) > VAULT_INTENT_IDEMPOTENCY_MAX ||
            (ticker && strlen(ticker) > ZSLP_INTENT_TICKER_MAX) ||
            (name && strlen(name) > ZSLP_INTENT_NAME_MAX) ||
            (token && strlen(token) > 64) ||
            (recipient && strlen(recipient) > ZSLP_INTENT_ADDRESS_MAX)) {
            json_set_str(result, "ZSLP plan input exceeds bounds");
            return false;
        }
        snprintf(request.idempotency_key, sizeof(request.idempotency_key),
                 "%s", idempotency);
        snprintf(request.ticker, sizeof(request.ticker), "%s",
                 ticker ? ticker : "");
        snprintf(request.name, sizeof(request.name), "%s", name ? name : "");
        snprintf(request.token_id, sizeof(request.token_id), "%s",
                 token ? token : "");
        snprintf(request.recipient, sizeof(request.recipient), "%s",
                 recipient ? recipient : "");
        int64_t decimals = json_get_int_or(input, "decimals", -1);
        if (decimals >= 0 && decimals <= UINT8_MAX)
            request.decimals = (uint8_t)decimals;
        (void)ztic_units(json_get(input, "supply"), &request.supply);
        (void)ztic_units(json_get(input, "units"), &request.units);
        outcome = zslp_transaction_intent_plan(&runtime, &request, &intent);
    }
    if (!outcome.ok) {
        json_set_str(result, outcome.message);
        LOG_FAIL("zslp.intent", "request refused: %s", outcome.message);
    }
    ztic_render(&intent, result);
    return true;
}

void register_zslp_intent_rpc_command(struct rpc_table *table)
{
    struct rpc_command command = {
        "zslp", "zslp_intent", rpc_zslp_intent, false,
    };
    rpc_table_must_append(table, &command);
}
