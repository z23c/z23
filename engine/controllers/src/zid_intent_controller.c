/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Wallet adapter and RPC for durable ZID overlay intents. */

#include "controllers/identity_controller.h"
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
#include "models/zid_identity.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "services/overlay_transaction_intent_service.h"
#include "services/wallet_money_service.h"
#include "services/zslp_command_service.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "zid/zid_anchor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZID_INTENT_APPLICATION "zid_intent"

static bool ziic_parse_key(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) != 64 || !IsHex(hex) ||
        ParseHex(hex, out, 32) != 32)
        return false;
    for (size_t i = 0; i < 32; i++)
        if (out[i]) return true;
    return false;
}

static struct zcl_result ziic_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct wallet_rpc_context *ctx = opaque;
    return wallet_money_snapshot_build(ctx ? ctx->node_db : NULL,
                                       ctx ? ctx->main_state : NULL,
                                       scope, out);
}

static struct zcl_result ziic_build_script(
    const struct overlay_intent_request *request, uint8_t *script,
    size_t capacity, size_t *script_len,
    char owner[ZID_IDENTITY_ADDRESS_MAX],
    struct wallet_rpc_context *ctx)
{
    owner[0] = '\0';
    if (strcmp(request->operation, "anchor") == 0 &&
        request->semantics_len == 32) {
        struct zid_identity previous;
        if (db_zid_identity_find(ctx->node_db, request->semantics, &previous) &&
            strcmp(previous.status, ZID_IDENTITY_STATUS_ACTIVE) != 0)
            return ZCL_ERR(-1, "dead or superseded ZID key cannot be re-anchored");
        *script_len = zid_anchor_build_anchor(
            script, capacity, request->semantics);
    } else if (strcmp(request->operation, "rotate") == 0 &&
               request->semantics_len == 64) {
        if (memcmp(request->semantics, request->semantics + 32, 32) == 0)
            return ZCL_ERR(-2, "ZID self-rotation is invalid");
        struct zid_identity previous;
        if (!db_zid_identity_find(ctx->node_db, request->semantics, &previous))
            return ZCL_ERR(-3, "ZID key is not anchored");
        if (strcmp(previous.status, ZID_IDENTITY_STATUS_REVOKED) == 0)
            return ZCL_ERR(-4, "revoked ZID key cannot rotate");
        if (!previous.owner_address[0])
            return ZCL_ERR(-5, "ZID row has no provable owner");
        snprintf(owner, ZID_IDENTITY_ADDRESS_MAX, "%s",
                 previous.owner_address);
        *script_len = zid_anchor_build_rotate(
            script, capacity, request->semantics, request->semantics + 32);
    } else if (strcmp(request->operation, "revoke") == 0 &&
               request->semantics_len == 32) {
        struct zid_identity previous;
        if (!db_zid_identity_find(ctx->node_db, request->semantics, &previous))
            return ZCL_ERR(-6, "ZID key is not anchored");
        if (strcmp(previous.status, ZID_IDENTITY_STATUS_REVOKED) == 0)
            return ZCL_ERR(-7, "ZID key is already revoked");
        if (!previous.owner_address[0])
            return ZCL_ERR(-8, "ZID row has no provable owner");
        snprintf(owner, ZID_IDENTITY_ADDRESS_MAX, "%s",
                 previous.owner_address);
        *script_len = zid_anchor_build_revoke(
            script, capacity, request->semantics);
    } else {
        return ZCL_ERR(-9, "ZID operation or semantic payload is invalid");
    }
    return *script_len > 0
        ? ZCL_OK : ZCL_ERR(-10, "ZID OP_RETURN builder refused the request");
}

static struct zcl_result ziic_prepare(
    void *opaque, const struct overlay_intent_request *request,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat,
    struct vault_intent_input *inputs, size_t input_capacity,
    size_t *input_count)
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !ctx->node_db || !request || !raw_tx ||
        !raw_tx_len || !txid_out || !actual_fee_zat || !inputs ||
        !input_count || maximum_fee_zat <= 0)
        return ZCL_ERR(-11, "ZID prepare context is incomplete");
    uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
    size_t script_len = 0;
    char owner[ZID_IDENTITY_ADDRESS_MAX];
    ZCL_CHECK(ziic_build_script(
        request, script, sizeof(script), &script_len, owner, ctx));
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    int64_t fee = 0;
    const char *why = NULL;
    struct zcl_result built = owner[0]
        ? zslp_command_build_owner_base_tx(ctx->wallet, owner, &wtx, &fee, &why)
        : zslp_command_build_genesis_base_tx(ctx->wallet, &wtx, &fee, &why);
    if (!built.ok)
        return ZCL_ERR(-12, "ZID funding/owner input build failed: %s",
                       why ? why : built.message);
    struct zcl_result prepared = zslp_command_prepare_with_op_return(
        ctx->wallet, &wtx, script, script_len);
    if (!prepared.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-13, "ZID exact signing failed: %s", prepared.message);
    }
    if (fee < 0 || fee > maximum_fee_zat || wtx.tx.num_vin == 0 ||
        wtx.tx.num_vin > input_capacity) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-14, "ZID transaction exceeds fee or input contract");
    }
    struct zcl_result flushed = wallet_flush_from_context(ctx);
    if (!flushed.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-15, "ZID plan key persistence failed: %s",
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
                      : ZCL_ERR(-16, "prepared ZID transaction is too large");
}

static struct zcl_result ziic_publish(
    void *opaque, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32])
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !raw_tx || raw_tx_len == 0 || !expected_txid)
        return ZCL_ERR(-17, "ZID publish context is incomplete");
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    struct byte_stream stream;
    stream_init_from_data(&stream, raw_tx, raw_tx_len);
    bool decoded = transaction_deserialize(&wtx.tx, &stream) &&
                   stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (!decoded) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-18, "prepared ZID transaction failed to decode");
    }
    transaction_compute_hash(&wtx.tx);
    if (memcmp(wtx.tx.hash.data, expected_txid, 32) != 0) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-19, "prepared ZID transaction identity changed");
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
                     : ZCL_ERR(-20, "ZID publication failed: %s", error);
}

static struct zcl_result ziic_runtime(struct overlay_intent_runtime *out,
                                      struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!out || !vault_intent_context_ready(ctx, result))
        return ZCL_ERR(-21, "ZID custody context is not ready");
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    if (!tip) return ZCL_ERR(-22, "ZID active tip is unavailable");
    memset(out, 0, sizeof(*out));
    out->node_db = ctx->node_db;
    out->read_money = ziic_money; out->money_ctx = ctx;
    out->prepare = ziic_prepare; out->prepare_ctx = ctx;
    out->publish = ziic_publish; out->publish_ctx = ctx;
    out->tip_height = tip->nHeight;
    memcpy(out->tip_hash, tip->hashBlock.data, 32);
    out->maximum_fee_zat = wallet_default_fee(ctx->wallet);
    out->now_unix = (int64_t)platform_time_wall_time_t();
    return ZCL_OK;
}

static void ziic_render(const struct overlay_intent_result *intent,
                        struct json_value *result)
{
    char plan[65], txid[65], root[65], digest[65];
    HexStr(intent->plan_id, 32, false, plan, sizeof(plan));
    HexStr(intent->snapshot_root, 32, false, root, sizeof(root));
    HexStr(intent->plan_digest, 32, false, digest, sizeof(digest));
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.core_identity_anchor.v2");
    json_push_kv_str(result, "wallet_scope", intent->wallet_scope);
    json_push_kv_str(result, "wallet_instance_id", intent->wallet_instance_id);
    json_push_kv_str(result, "network_genesis", intent->network_genesis);
    json_push_kv_str(result, "operation", intent->operation);
    json_push_kv_str(result, "plan_id", plan);
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

static bool rpc_zid_intent(const struct json_value *params, bool help,
                           struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zid_intent plan {wallet_scope,operation,keys,idempotency_key}\n"
            "zid_intent commit {wallet_scope,plan_id,confirm:true}\n");
        return true;
    }
    const struct json_value *input = params && json_size(params)
        ? json_at(params, 0) : NULL;
    if (!input || input->type != JSON_OBJ) {
        json_set_str(result, "zid_intent requires one object");
        return false;
    }
    const char *scope = json_get_str(json_get(input, "wallet_scope"));
    bool confirm = json_get_bool_or(input, "confirm", false);
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0)) {
        json_set_str(result, "zid_intent requires wallet_scope=dev|prod");
        return false;
    }
    struct overlay_intent_runtime runtime;
    struct zcl_result ready = ziic_runtime(&runtime, result);
    if (!ready.ok) {
        /* ziic_runtime's own refusals (context incomplete, active tip
         * unavailable) never touch `result` — without this the envelope
         * ships {"result":null,"error":null} and every caller reports an
         * empty, causeless failure. */
        if (json_get_str(result) == NULL && result->type != JSON_OBJ)
            json_set_str(result, ready.message);
        return false;
    }
    struct overlay_intent_result intent;
    struct zcl_result outcome;
    if (confirm) {
        const char *plan_hex = json_get_str(json_get(input, "plan_id"));
        uint8_t plan_id[32];
        if (!plan_hex || strlen(plan_hex) != 64 || !IsHex(plan_hex) ||
            ParseHex(plan_hex, plan_id, sizeof(plan_id)) != 32) {
            json_set_str(result, "ZID commit requires a 64-hex plan_id");
            return false;
        }
        outcome = overlay_transaction_intent_commit(
            &runtime, ZID_INTENT_APPLICATION, scope, plan_id, &intent);
    } else {
        const char *operation = json_get_str(json_get(input, "operation"));
        const char *pubkey = json_get_str(json_get(input, "pubkey"));
        const char *new_pubkey = json_get_str(json_get(input, "new_pubkey"));
        const char *idempotency =
            json_get_str(json_get(input, "idempotency_key"));
        struct overlay_intent_request request; memset(&request, 0, sizeof(request));
        if (!operation || !idempotency ||
            !ziic_parse_key(pubkey, request.semantics)) {
            json_set_str(result, "ZID plan requires a valid operation, pubkey, and idempotency_key");
            return false;
        }
        request.semantics_len = 32;
        if (strcmp(operation, "rotate") == 0) {
            if (!ziic_parse_key(new_pubkey, request.semantics + 32)) {
                json_set_str(result, "ZID rotate requires a valid new_pubkey");
                return false;
            }
            request.semantics_len = 64;
        } else if (strcmp(operation, "anchor") != 0 &&
                   strcmp(operation, "revoke") != 0) {
            json_set_str(result, "ZID operation must be anchor, rotate, or revoke");
            return false;
        }
        snprintf(request.wallet_scope, sizeof(request.wallet_scope), "%s", scope);
        snprintf(request.application_kind, sizeof(request.application_kind),
                 "%s", ZID_INTENT_APPLICATION);
        snprintf(request.operation, sizeof(request.operation), "%s", operation);
        snprintf(request.idempotency_key, sizeof(request.idempotency_key),
                 "%s", idempotency);
        outcome = overlay_transaction_intent_plan(&runtime, &request, &intent);
    }
    if (!outcome.ok) {
        json_set_str(result, outcome.message);
        LOG_FAIL("zid.intent", "request refused: %s", outcome.message);
    }
    ziic_render(&intent, result);
    return true;
}

void register_zid_intent_rpc_command(struct rpc_table *table)
{
    struct rpc_command command = {
        "identity", "zid_intent", rpc_zid_intent, false,
    };
    rpc_table_must_append(table, &command);
}
