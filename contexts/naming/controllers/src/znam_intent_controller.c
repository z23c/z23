/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Wallet adapter and RPC for durable ZNAM transaction intents. */

#include "controllers/name_controller.h"
#include "controllers/name_resolver.h"
#include "controllers/native_handler_body.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/wallet_helpers.h"
#include "zslp_controller_internal.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/znam.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "services/wallet_money_service.h"
#include "services/znam_transaction_intent_service.h"
#include "services/zslp_command_service.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct zcl_result znic_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct wallet_rpc_context *ctx = opaque;
    return wallet_money_snapshot_build(ctx ? ctx->node_db : NULL,
                                       ctx ? ctx->main_state : NULL,
                                       scope, out);
}

static struct zcl_result znic_build_script(
    const struct znam_intent_request *request, uint8_t script[512],
    size_t *script_len)
{
    switch (request->operation) {
    case ZNAM_INTENT_REGISTER:
        *script_len = znam_build_register(
            script, 512, request->name, request->target_type, request->value);
        break;
    case ZNAM_INTENT_UPDATE:
        *script_len = znam_build_update(
            script, 512, request->name, request->target_type, request->value);
        break;
    case ZNAM_INTENT_TRANSFER:
        *script_len = znam_build_transfer(
            script, 512, request->name, request->new_owner);
        break;
    case ZNAM_INTENT_RENEW:
        *script_len = znam_build_renew(script, 512, request->name);
        break;
    case ZNAM_INTENT_SET_RECORD:
        *script_len = znam_build_set_record(
            script, 512, request->name, request->target_type, request->value);
        break;
    case ZNAM_INTENT_SET_TEXT:
        *script_len = znam_build_set_text(
            script, 512, request->name, request->key, request->value);
        break;
    default:
        return ZCL_ERR(-1, "unknown ZNAM wallet operation");
    }
    return *script_len > 0
        ? ZCL_OK : ZCL_ERR(-2, "ZNAM OP_RETURN does not satisfy protocol limits");
}

static struct zcl_result znic_prepare(
    void *opaque, const struct znam_intent_request *request,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat,
    struct vault_intent_input *inputs, size_t input_capacity,
    size_t *input_count)
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !ctx->node_db || !request || !raw_tx ||
        !raw_tx_len || !txid_out || !actual_fee_zat || !inputs ||
        !input_count || maximum_fee_zat <= 0)
        return ZCL_ERR(-3, "ZNAM wallet prepare context is incomplete");
    struct znam_entry existing;
    bool found = db_znam_find(ctx->node_db, request->name, &existing);
    if (request->operation == ZNAM_INTENT_REGISTER && found)
        return ZCL_ERR(-4, "ZNAM name is already registered");
    if (request->operation != ZNAM_INTENT_REGISTER && !found)
        return ZCL_ERR(-5, "ZNAM name is not registered");
    uint8_t script[512];
    size_t script_len = 0;
    ZCL_CHECK(znic_build_script(request, script, &script_len));
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    int64_t fee = 0;
    const char *why = NULL;
    struct zcl_result built;
    if (request->operation == ZNAM_INTENT_REGISTER ||
        request->operation == ZNAM_INTENT_RENEW) {
        built = zslp_command_build_genesis_base_tx(
            ctx->wallet, &wtx, &fee, &why);
    } else {
        built = zslp_command_build_owner_base_tx(
            ctx->wallet, existing.owner_address, &wtx, &fee, &why);
    }
    if (!built.ok)
        return ZCL_ERR(-6, "ZNAM funding/owner input build failed: %s",
                       why ? why : built.message);
    struct zcl_result prepared = zslp_command_prepare_with_op_return(
        ctx->wallet, &wtx, script, script_len);
    if (!prepared.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-7, "ZNAM exact transaction signing failed: %s",
                       prepared.message);
    }
    if (fee < 0 || fee > maximum_fee_zat || wtx.tx.num_vin == 0 ||
        wtx.tx.num_vin > input_capacity) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-8, "ZNAM transaction exceeds fee or input contract");
    }
    struct zcl_result flushed = wallet_flush_from_context(ctx);
    if (!flushed.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-9, "ZNAM plan key persistence failed: %s",
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
                      : ZCL_ERR(-10, "prepared ZNAM transaction is too large");
}

static struct zcl_result znic_publish(
    void *opaque, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32])
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !raw_tx || raw_tx_len == 0 || !expected_txid)
        return ZCL_ERR(-1, "ZNAM publish context is incomplete");
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    struct byte_stream stream;
    stream_init_from_data(&stream, raw_tx, raw_tx_len);
    bool decoded = transaction_deserialize(&wtx.tx, &stream) &&
                   stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (!decoded) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-2, "prepared ZNAM transaction failed to decode");
    }
    transaction_compute_hash(&wtx.tx);
    if (memcmp(wtx.tx.hash.data, expected_txid, 32) != 0) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-3, "prepared ZNAM transaction identity changed");
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
                     : ZCL_ERR(-4, "ZNAM publication failed: %s", error);
}

static struct zcl_result znic_runtime(struct znam_intent_runtime *out,
                                      struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!out || !vault_intent_context_ready(ctx, result))
        return ZCL_ERR(-1, "ZNAM custody context is not ready");
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    if (!tip) return ZCL_ERR(-2, "ZNAM active tip is unavailable");
    memset(out, 0, sizeof(*out));
    out->node_db = ctx->node_db;
    out->read_money = znic_money; out->money_ctx = ctx;
    out->prepare = znic_prepare; out->prepare_ctx = ctx;
    out->publish = znic_publish; out->publish_ctx = ctx;
    out->tip_height = tip->nHeight;
    memcpy(out->tip_hash, tip->hashBlock.data, 32);
    out->maximum_fee_zat = wallet_default_fee(ctx->wallet);
    out->now_unix = (int64_t)platform_time_wall_time_t();
    return ZCL_OK;
}

static void znic_render(const struct znam_intent_result *intent,
                        struct json_value *result)
{
    char plan_id[65], txid[65], root[65], digest[65];
    HexStr(intent->plan_id, 32, false, plan_id, sizeof(plan_id));
    HexStr(intent->snapshot_root, 32, false, root, sizeof(root));
    HexStr(intent->plan_digest, 32, false, digest, sizeof(digest));
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.app_name_txresult.v1");
    json_push_kv_str(result, "wallet_scope", intent->wallet_scope);
    json_push_kv_str(result, "wallet_instance_id", intent->wallet_instance_id);
    json_push_kv_str(result, "network_genesis", intent->network_genesis);
    json_push_kv_str(result, "operation",
                     znam_intent_operation_name(intent->operation));
    json_push_kv_str(result, "plan_id", plan_id);
    json_push_kv_str(result, "plan_digest", digest);
    json_push_kv_str(result, "snapshot_root", root);
    json_push_kv_str(result, "snapshot_status", "CURRENT");
    json_push_kv_int(result, "actual_fee_zat", intent->actual_fee_zat);
    json_push_kv_int(result, "maximum_fee_zat", intent->maximum_fee_zat);
    json_push_kv_int(result, "reserved_zat", intent->reserved_zat);
    json_push_kv_int(result, "expires_at", intent->expires_at);
    json_push_kv_str(result, "state", intent->state);
    json_push_kv_bool(result, "idempotent_replay", intent->idempotent_replay);
    if (intent->broadcast && intent->has_txid) {
        HexStr(intent->txid, 32, false, txid, sizeof(txid));
        json_push_kv_str(result, "txid", txid);
        json_push_kv_str(result, "status", "broadcast");
    } else {
        json_push_kv_str(result, "status", "planned");
    }
}

static enum znam_intent_operation znic_operation(const char *operation)
{
    if (operation && strcmp(operation, "register") == 0)
        return ZNAM_INTENT_REGISTER;
    if (operation && strcmp(operation, "update") == 0)
        return ZNAM_INTENT_UPDATE;
    if (operation && strcmp(operation, "transfer") == 0)
        return ZNAM_INTENT_TRANSFER;
    if (operation && strcmp(operation, "renew") == 0)
        return ZNAM_INTENT_RENEW;
    if (operation && strcmp(operation, "set_record") == 0)
        return ZNAM_INTENT_SET_RECORD;
    if (operation && strcmp(operation, "set_text") == 0)
        return ZNAM_INTENT_SET_TEXT;
    return 0;
}

static bool rpc_znam_intent(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "znam_intent plan {wallet_scope,operation,...,idempotency_key}\n"
            "znam_intent commit {wallet_scope,plan_id,confirm:true}\n");
        return true;
    }
    const struct json_value *input = params && json_size(params)
        ? json_at(params, 0) : NULL;
    if (!input || input->type != JSON_OBJ) {
        json_set_str(result, "znam_intent requires one object");
        return false;
    }
    const char *scope = json_get_str(json_get(input, "wallet_scope"));
    bool confirm = json_get_bool_or(input, "confirm", false);
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0)) {
        json_set_str(result, "znam_intent requires wallet_scope=dev|prod");
        return false;
    }
    struct znam_intent_runtime runtime;
    struct zcl_result ready = znic_runtime(&runtime, result);
    if (!ready.ok) return false;
    struct znam_intent_result intent;
    struct zcl_result outcome;
    if (confirm) {
        const char *plan_hex = json_get_str(json_get(input, "plan_id"));
        uint8_t plan_id[32];
        if (!plan_hex || strlen(plan_hex) != 64 || !IsHex(plan_hex) ||
            ParseHex(plan_hex, plan_id, sizeof(plan_id)) != 32) {
            json_set_str(result, "commit requires a 64-hex plan_id");
            return false;
        }
        outcome = znam_transaction_intent_commit(
            &runtime, scope, plan_id, &intent);
    } else {
        struct znam_intent_request request; memset(&request, 0, sizeof(request));
        const char *operation = json_get_str(json_get(input, "operation"));
        const char *name = json_get_str(json_get(input, "name"));
        const char *type = json_get_str(json_get(input, "type"));
        const char *value = json_get_str(json_get(input, "value"));
        const char *owner = json_get_str(json_get(input, "new_owner"));
        const char *key = json_get_str(json_get(input, "key"));
        const char *idempotency =
            json_get_str(json_get(input, "idempotency_key"));
        if (!name || !idempotency || strlen(name) > ZNAM_INTENT_NAME_MAX ||
            strlen(idempotency) > VAULT_INTENT_IDEMPOTENCY_MAX ||
            (value && strlen(value) > ZNAM_INTENT_VALUE_MAX) ||
            (owner && strlen(owner) > ZNAM_INTENT_OWNER_MAX) ||
            (key && strlen(key) > ZNAM_INTENT_KEY_MAX)) {
            json_set_str(result, "ZNAM plan input is missing or exceeds bounds");
            return false;
        }
        snprintf(request.wallet_scope, sizeof(request.wallet_scope), "%s", scope);
        request.operation = znic_operation(operation);
        snprintf(request.name, sizeof(request.name), "%s", name);
        request.target_type = type ? znam_type_from_name(type) : 0;
        snprintf(request.value, sizeof(request.value), "%s", value ? value : "");
        snprintf(request.new_owner, sizeof(request.new_owner), "%s",
                 owner ? owner : "");
        snprintf(request.key, sizeof(request.key), "%s", key ? key : "");
        snprintf(request.idempotency_key, sizeof(request.idempotency_key),
                 "%s", idempotency);
        outcome = znam_transaction_intent_plan(&runtime, &request, &intent);
    }
    if (!outcome.ok) {
        json_set_str(result, outcome.message);
        LOG_FAIL("znam.intent", "request refused: %s", outcome.message);
    }
    znic_render(&intent, result);
    return true;
}

void register_znam_intent_rpc_command(struct rpc_table *table)
{
    struct rpc_command command = {
        "names", "znam_intent", rpc_znam_intent, false,
    };
    rpc_table_must_append(table, &command);
}
