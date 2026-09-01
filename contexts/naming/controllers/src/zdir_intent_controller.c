/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Wallet adapter and RPC for durable ZDIR overlay intents. */

#include "controllers/zdir_controller.h"
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
#include "models/onion_directory.h"
#include "net/connman.h"
#include "net/onion_peer_merge.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "services/overlay_transaction_intent_service.h"
#include "services/wallet_money_service.h"
#include "services/zslp_command_service.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "zdir/zdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZDIR_INTENT_APPLICATION "zdir_intent"
#define ZDIR_INTENT_HOST_OFFSET 1
#define ZDIR_INTENT_KEY_OFFSET  (ZDIR_INTENT_HOST_OFFSET + ZDIR_HOSTNAME_LEN)

static bool zdic_parse_key(const char *hex, uint8_t out[ZDIR_PUBKEY_LEN])
{
    if (!hex || strlen(hex) != 64 || !IsHex(hex) ||
        ParseHex(hex, out, ZDIR_PUBKEY_LEN) != ZDIR_PUBKEY_LEN)
        return false;
    for (size_t i = 0; i < ZDIR_PUBKEY_LEN; i++)
        if (out[i]) return true;
    return false;
}

static struct zcl_result zdic_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct wallet_rpc_context *ctx = opaque;
    return wallet_money_snapshot_build(ctx ? ctx->node_db : NULL,
                                       ctx ? ctx->main_state : NULL,
                                       scope, out);
}

static struct zcl_result zdic_build_script(
    const struct overlay_intent_request *request, uint8_t *script,
    size_t capacity, size_t *script_len,
    char owner[ONION_DIRECTORY_ADDRESS_MAX], struct wallet_rpc_context *ctx)
{
    owner[0] = '\0';
    if (!request || request->semantics_len < ZDIR_INTENT_KEY_OFFSET ||
        request->semantics[0] > 1)
        return ZCL_ERR(-1, "ZDIR semantic payload is invalid");
    char hostname[ZDIR_HOSTNAME_LEN + 1];
    memcpy(hostname, request->semantics + ZDIR_INTENT_HOST_OFFSET,
           ZDIR_HOSTNAME_LEN);
    hostname[ZDIR_HOSTNAME_LEN] = '\0';
    if (!onion_hostname_valid(hostname))
        return ZCL_ERR(-2, "ZDIR hostname is invalid");

    struct db_onion_directory previous;
    memset(&previous, 0, sizeof(previous));
    bool known = db_onion_directory_find(ctx->node_db, hostname, &previous);
    if (strcmp(request->operation, "register") == 0) {
        bool has_key = request->semantics[0] == 1;
        size_t expected = ZDIR_INTENT_KEY_OFFSET +
                          (has_key ? ZDIR_PUBKEY_LEN : 0);
        if (request->semantics_len != expected)
            return ZCL_ERR(-3, "ZDIR register semantic length is invalid");
        if (known) {
            if (!previous.owner_address[0])
                return ZCL_ERR(-4, "ZDIR row has no provable owner");
            snprintf(owner, ONION_DIRECTORY_ADDRESS_MAX, "%s",
                     previous.owner_address);
        }
        *script_len = zdir_build_register(
            script, capacity, hostname,
            has_key ? request->semantics + ZDIR_INTENT_KEY_OFFSET : NULL);
    } else if (strcmp(request->operation, "deregister") == 0) {
        if (request->semantics[0] != 0 ||
            request->semantics_len != ZDIR_INTENT_KEY_OFFSET)
            return ZCL_ERR(-5, "ZDIR deregister semantic payload is invalid");
        if (!known)
            return ZCL_ERR(-6, "ZDIR hostname is not registered");
        if (strcmp(previous.status, ONION_DIRECTORY_STATUS_RETIRED) == 0)
            return ZCL_ERR(-7, "ZDIR hostname is already retired");
        if (!previous.owner_address[0])
            return ZCL_ERR(-8, "ZDIR row has no provable owner");
        snprintf(owner, ONION_DIRECTORY_ADDRESS_MAX, "%s",
                 previous.owner_address);
        *script_len = zdir_build_deregister(script, capacity, hostname);
    } else {
        return ZCL_ERR(-9, "ZDIR operation is invalid");
    }
    return *script_len > 0
        ? ZCL_OK : ZCL_ERR(-10, "ZDIR OP_RETURN builder refused the request");
}

static struct zcl_result zdic_prepare(
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
        return ZCL_ERR(-11, "ZDIR prepare context is incomplete");
    uint8_t script[ZDIR_SCRIPT_MAX];
    size_t script_len = 0;
    char owner[ONION_DIRECTORY_ADDRESS_MAX];
    ZCL_CHECK(zdic_build_script(
        request, script, sizeof(script), &script_len, owner, ctx));
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    int64_t fee = 0;
    const char *why = NULL;
    struct zcl_result built = owner[0]
        ? zslp_command_build_owner_base_tx(ctx->wallet, owner, &wtx, &fee, &why)
        : zslp_command_build_genesis_base_tx(ctx->wallet, &wtx, &fee, &why);
    if (!built.ok)
        return ZCL_ERR(-12, "ZDIR funding/owner input build failed: %s",
                       why ? why : built.message);
    struct zcl_result prepared = zslp_command_prepare_with_op_return(
        ctx->wallet, &wtx, script, script_len);
    if (!prepared.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-13, "ZDIR exact signing failed: %s", prepared.message);
    }
    if (fee < 0 || fee > maximum_fee_zat || wtx.tx.num_vin == 0 ||
        wtx.tx.num_vin > input_capacity) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-14, "ZDIR transaction exceeds fee or input contract");
    }
    struct zcl_result flushed = wallet_flush_from_context(ctx);
    if (!flushed.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-15, "ZDIR plan key persistence failed: %s",
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
                      : ZCL_ERR(-16, "prepared ZDIR transaction is too large");
}

static struct zcl_result zdic_publish(
    void *opaque, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32])
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !raw_tx || raw_tx_len == 0 || !expected_txid)
        return ZCL_ERR(-17, "ZDIR publish context is incomplete");
    struct wallet_tx wtx; memset(&wtx, 0, sizeof(wtx));
    struct byte_stream stream;
    stream_init_from_data(&stream, raw_tx, raw_tx_len);
    bool decoded = transaction_deserialize(&wtx.tx, &stream) &&
                   stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (!decoded) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-18, "prepared ZDIR transaction failed to decode");
    }
    transaction_compute_hash(&wtx.tx);
    if (memcmp(wtx.tx.hash.data, expected_txid, 32) != 0) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-19, "prepared ZDIR transaction identity changed");
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
                     : ZCL_ERR(-20, "ZDIR publication failed: %s", error);
}

static struct zcl_result zdic_runtime(struct overlay_intent_runtime *out,
                                      struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!out || !vault_intent_context_ready(ctx, result))
        return ZCL_ERR(-21, "ZDIR custody context is not ready");
    struct block_index *tip = active_chain_tip(&ctx->main_state->chain_active);
    if (!tip) return ZCL_ERR(-22, "ZDIR active tip is unavailable");
    memset(out, 0, sizeof(*out));
    out->node_db = ctx->node_db;
    out->read_money = zdic_money; out->money_ctx = ctx;
    out->prepare = zdic_prepare; out->prepare_ctx = ctx;
    out->publish = zdic_publish; out->publish_ctx = ctx;
    out->tip_height = tip->nHeight;
    memcpy(out->tip_hash, tip->hashBlock.data, 32);
    out->maximum_fee_zat = wallet_default_fee(ctx->wallet);
    out->now_unix = (int64_t)platform_time_wall_time_t();
    return ZCL_OK;
}

static void zdic_render(const struct overlay_intent_result *intent,
                        struct json_value *result)
{
    char plan[65], txid[65], root[65], digest[65];
    HexStr(intent->plan_id, 32, false, plan, sizeof(plan));
    HexStr(intent->snapshot_root, 32, false, root, sizeof(root));
    HexStr(intent->plan_digest, 32, false, digest, sizeof(digest));
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.core_zdir_register.v2");
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

static bool rpc_zdir_intent(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zdir_intent plan {wallet_scope,operation,hostname,pubkey?,idempotency_key}\n"
            "zdir_intent commit {wallet_scope,plan_id,confirm:true}\n");
        return true;
    }
    const struct json_value *input = params && json_size(params)
        ? json_at(params, 0) : NULL;
    if (!input || input->type != JSON_OBJ) {
        json_set_str(result, "zdir_intent requires one object");
        return false;
    }
    const char *scope = json_get_str(json_get(input, "wallet_scope"));
    bool confirm = json_get_bool_or(input, "confirm", false);
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0)) {
        json_set_str(result, "zdir_intent requires wallet_scope=dev|prod");
        return false;
    }
    struct overlay_intent_runtime runtime;
    struct zcl_result ready = zdic_runtime(&runtime, result);
    if (!ready.ok) return false;
    struct overlay_intent_result intent;
    struct zcl_result outcome;
    if (confirm) {
        const char *plan_hex = json_get_str(json_get(input, "plan_id"));
        uint8_t plan_id[32];
        if (!plan_hex || strlen(plan_hex) != 64 || !IsHex(plan_hex) ||
            ParseHex(plan_hex, plan_id, sizeof(plan_id)) != 32) {
            json_set_str(result, "ZDIR commit requires a 64-hex plan_id");
            return false;
        }
        outcome = overlay_transaction_intent_commit(
            &runtime, ZDIR_INTENT_APPLICATION, scope, plan_id, &intent);
    } else {
        const char *operation = json_get_str(json_get(input, "operation"));
        const char *hostname = json_get_str(json_get(input, "hostname"));
        const char *pubkey = json_get_str(json_get(input, "pubkey"));
        const char *idempotency =
            json_get_str(json_get(input, "idempotency_key"));
        if (!operation || !hostname || !onion_hostname_valid(hostname) ||
            !idempotency) {
            json_set_str(result, "ZDIR plan requires a valid operation, hostname, and idempotency_key");
            return false;
        }
        struct overlay_intent_request request; memset(&request, 0, sizeof(request));
        request.semantics[0] = 0;
        memcpy(request.semantics + ZDIR_INTENT_HOST_OFFSET, hostname,
               ZDIR_HOSTNAME_LEN);
        request.semantics_len = ZDIR_INTENT_KEY_OFFSET;
        if (strcmp(operation, "register") == 0) {
            if (pubkey && pubkey[0]) {
                if (!zdic_parse_key(pubkey,
                        request.semantics + ZDIR_INTENT_KEY_OFFSET)) {
                    json_set_str(result, "ZDIR pubkey must be 64 non-zero hex characters");
                    return false;
                }
                request.semantics[0] = 1;
                request.semantics_len += ZDIR_PUBKEY_LEN;
            }
        } else if (strcmp(operation, "deregister") != 0) {
            json_set_str(result, "ZDIR operation must be register or deregister");
            return false;
        }
        snprintf(request.wallet_scope, sizeof(request.wallet_scope), "%s", scope);
        snprintf(request.application_kind, sizeof(request.application_kind),
                 "%s", ZDIR_INTENT_APPLICATION);
        snprintf(request.operation, sizeof(request.operation), "%s", operation);
        snprintf(request.idempotency_key, sizeof(request.idempotency_key),
                 "%s", idempotency);
        outcome = overlay_transaction_intent_plan(&runtime, &request, &intent);
    }
    if (!outcome.ok) {
        json_set_str(result, outcome.message);
        LOG_FAIL("zdir.intent", "request refused: %s", outcome.message);
    }
    zdic_render(&intent, result);
    return true;
}

void register_zdir_intent_rpc_command(struct rpc_table *table)
{
    struct rpc_command command = {
        "zdir", "zdir_intent", rpc_zdir_intent, false,
    };
    rpc_table_must_append(table, &command);
}
