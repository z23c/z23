/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native handlers for the `yardsale` root — the wallet-backed
 * seller arm/disarm/status and the wallet-backed buy.
 *
 * THE INVARIANT OF THIS FILE: there is no wallet or ceremony logic here.
 * The wallet, the seller profile, and the pending-buy table all live in
 * the running node's process memory, so every leaf forwards its input
 * object verbatim to the RPC method registered by
 * contexts/wallet/controllers/src/yardsale_wallet_controller.c, which adapts the
 * wallet RPC context onto engine/services/src/yardsale_wallet_service*.c —
 * the one place the rules live. The plan/commit gate
 * (ZCL_COMMAND_CONFIRM_PLAN_COMMIT) is enforced node-side by the service:
 * without "confirm":true the answer is an exact expiring plan; with it,
 * the plan commits. */

#include "command/native_command.h"

#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/log_macros.h"
#include "wallet/wallet.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define YS_TAG "native.yardsale"

/* Fail the reply with a logged, evidence-carrying error body. Every
 * failure path in this file goes through here, so no leaf can return
 * without saying why. */
static void ys_fail(struct zcl_command_reply *reply,
                    enum zcl_command_status status,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *phase, bool retryable, const char *message,
                    const char *evidence)
{
    LOG_ERROR(YS_TAG, "%s: %s (%s)", code ? code : "ERROR",
              message ? message : "", evidence ? evidence : "");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           false, message, evidence);
}

/* True when the leaf's input is present and usable as an object for the
 * RPC forward. */
static bool ys_input_is_object(const struct json_value *input)
{
    return input && input->type == JSON_OBJ;
}

/* Read the node's raw RPC reply into *body; true only when it parsed and
 * came back as a JSON object. */
static bool ys_read_rpc_body(struct json_value *body, const char *result)
{
    json_init(body);
    return json_read(body, result, strlen(result)) && body->type == JSON_OBJ;
}

/* A refusal's own text when the service sent a non-empty one, else the
 * fixed fallback this leaf reports. */
static const char *ys_refusal_text(const char *field, const char *fallback)
{
    if (field && field[0])
        return field;
    return fallback;
}

/* Forward the leaf's input object to the node's yardsale wallet RPC
 * method and project the node's body into the reply. The service body
 * contract is {ok:bool, ...}: ok:false carries code+message and means
 * nothing was armed, begun, or persisted. */
static void ys_forward(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply,
                       const char *rpc_method, bool input_required)
{
    if (!request || !reply || !rpc_method)
        return;
    const char *leaf = request->spec ? request->spec->path : rpc_method;

    struct json_value empty;
    json_init(&empty);
    json_set_object(&empty);
    const struct json_value *input = request->input;
    if (!ys_input_is_object(input)) {
        if (input_required) {
            ys_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT", "normalize",
                    false, "one input object is required", leaf);
            json_free(&empty);
            return;
        }
        input = &empty;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_value(&p, input);
    char *params = rpc_arg_builder_to_json(&p);
    json_free(&empty);
    if (!params) {
        ys_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED", "normalize",
                false, "could not encode the RPC parameters", leaf);
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *result = node_rpc_call(rpc_method, params);
    free(params);
    if (!result) {
        ys_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                true, "the node returned no body for the yardsale RPC",
                rpc_method);
        (void)zcl_command_reply_add_next(reply, "status", "{}",
                                         "confirm the node is running");
        return;
    }

    struct json_value body;
    if (!ys_read_rpc_body(&body, result)) {
        json_free(&body);
        free(result);
        ys_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                false, "the yardsale RPC returned an unreadable body",
                rpc_method);
        return;
    }
    free(result);

    if (!json_get_bool_or(&body, "ok", false)) {
        const char *code = json_get_str(json_get(&body, "code"));
        const char *message = json_get_str(json_get(&body, "message"));
        ys_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                ys_refusal_text(code, "YARDSALE_REFUSED"), "execute", false,
                ys_refusal_text(
                    message,
                    "the yardsale wallet service refused the request"),
                rpc_method);
        json_free(&body);
        return;
    }

    json_copy(&reply->data, &body);
    reply->error.mutated = json_get_bool_or(&body, "committed", false);
    json_free(&body);
}

void zcl_native_handle_yardsale_seller_arm(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ys_forward(request, reply, "yardsale_seller_arm", true);
}

void zcl_native_handle_yardsale_seller_disarm(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ys_forward(request, reply, "yardsale_seller_disarm", false);
}

void zcl_native_handle_yardsale_seller_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ys_forward(request, reply, "yardsale_seller_status", false);
}

void zcl_native_handle_yardsale_buy(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    ys_forward(request, reply, "yardsale_buy", true);
}

static bool ys_push_layer(struct json_value *layers, const char *id,
                          const char *story, const char *plan,
                          const char *test_group, const char *expected)
{
    struct json_value layer;
    json_init(&layer);
    json_set_object(&layer);
    bool ok = json_push_kv_str(&layer, "id", id) &&
              json_push_kv_str(&layer, "user_story", story) &&
              json_push_kv_str(&layer, "plan_command", plan) &&
              json_push_kv_str(&layer, "test_group", test_group) &&
              json_push_kv_str(&layer, "expected", expected) &&
              json_push_back(layers, &layer);
    json_free(&layer);
    return ok;
}

/* One scalar guide field, in reply order. A NULL value marks the single
 * numeric row, which is pushed as an int instead of a string. */
struct ys_guide_field {
    const char *key;
    const char *value;
};

static const struct ys_guide_field ys_guide_fields[] = {
    {"mission",
     "Pay ZCL and sell a 1/1 collectible without giving anyone "
     "custody of your keys."},
    {"next_action",
     "See whether this node holds confirmed ZCL, then plan. "
     "Nothing broadcasts until confirm:true."},
    {"start_command", "z23 vault list"},
    {"fee_zat", NULL},
    {"fee_zcl", "0.00000100"},
    {"fee_policy",
     "Wallet default_fee is the min-relay floor (100 zat). This "
     "node's mempool and miners accept that amount. Plans render "
     "the exact fee before commit."},
    {"pay_plan",
     "printf '%s' '{\"wallet_scope\":\"dev\",\"route\":\"transparent\","
     "\"idempotency_key\":\"pay-001\",\"effects\":[{\"asset\":\"ZCL\","
     "\"to\":\"<recipient>\",\"amount\":\"0.01\"}]}' | "
     "z23 vault intent plan --input=-"},
    {"pay_commit",
     "z23 vault intent commit --input='{\"wallet_scope\":\"dev\","
     "\"plan_id\":\"<64hex>\",\"confirm\":true}'"},
    {"nft_create",
     "z23 app tokens create --input='{\"wallet_scope\":\"dev\","
     "\"ticker\":\"ART1\",\"name\":\"One of one\",\"decimals\":0,"
     "\"supply\":\"1\",\"idempotency_key\":\"nft-genesis-1\"}'"},
    {"yardsale_sell",
     "z23 yardsale.seller.arm --input='{\"token_txid\":\"<64hex>\","
     "\"token_vout\":1,\"ad_root\":\"<64hex>\"}'"},
    {"yardsale_buy",
     "z23 yardsale.buy --input='{\"ad_root\":\"<64hex>\"}'"},
    {"torrent_announce",
     "z23 app market offer --input='{\"filepath\":\"/data/file\","
     "\"price_per_mb_zat\":100}'"},
    {"torrent_fetch",
     "z23 zcode package fetch --input='{\"root\":\"<64hex>\"}'"},
    {"onion_shop", "z23 app shop init"},
    {"confirm_rule",
     "Every money leaf is plan then confirm:true on that exact plan. "
     "A guide never spends, never prints keys or addresses."},
    {"funding_rule",
     "An empty wallet refuses at plan time and names the shortfall. "
     "Fund this node's wallet first; do not export keys or invent a "
     "balance."},
    {"continue_rule",
     "Follow the plan reply's commit_input. Discover exact keys with "
     "z23 discover schema <leaf>."},
    {"docs", "docs/node/SELL.md"},
};

/* Push one guide field row onto the reply data. */
static bool ys_guide_push_row(struct json_value *data,
                              const struct ys_guide_field *field)
{
    if (field->value)
        return json_push_kv_str(data, field->key, field->value);
    return json_push_kv_int(data, field->key, WALLET_DEFAULT_FEE_ZAT);
}

/* Push every scalar guide field in order; a failed row stops the rows
 * after it, exactly like the original single && chain. */
static bool ys_guide_push_fields(struct json_value *data)
{
    size_t field_count =
        sizeof(ys_guide_fields) / sizeof(ys_guide_fields[0]);
    bool ok = true;
    for (size_t i = 0; i < field_count; i++)
        ok = ok && ys_guide_push_row(data, &ys_guide_fields[i]);
    return ok;
}

/* Build the guide's six progress layers; a failed layer stops the layers
 * after it, exactly like the original chain. */
static bool ys_guide_fill_layers(struct json_value *layers)
{
    return ys_push_layer(layers, "pay_zcl",
            "Pay confirmed ZCL to a transparent address without exporting keys.",
            "vault.intent.plan", "test_simnet_wallet_import_backup",
            "simnet_confirmed") &&
        ys_push_layer(layers, "sapling",
            "Shield or send Sapling value through the same plan-then-confirm vault.",
            "vault.intent.plan", "test_simnet_shielded_wallet_e2e",
            "simnet_confirmed") &&
        ys_push_layer(layers, "zslp_one_of_one",
            "Mint a 1/1 ZSLP collectible (decimals 0, supply 1) as a plan.",
            "app.tokens.create", "test_simnet", "simnet_confirmed") &&
        ys_push_layer(layers, "yardsale",
            "Atomically swap that 1/1 for ZCL between two wallets in one transaction.",
            "yardsale.buy", "test_yardsale_app", "simnet_confirmed") &&
        ys_push_layer(layers, "onion_market",
            "Pay ZCL, then fetch SHA3-verified chunks over the onion file-service.",
            "app.market.purchase.plan", "test_file_market",
            "simnet_confirmed") &&
        ys_push_layer(layers, "zcode_package",
            "Publish or fetch an exact C23 package root; fetch is inert until accept.",
            "zcode.work.start", "test_zcode_release", "simnet_confirmed");
}

void zcl_native_handle_yardsale_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input || request->input->type != JSON_OBJ ||
        request->input->num_children != 0) {
        ys_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_YARDSALE_GUIDE_INPUT", "validate", false,
                "yardsale guide accepts no input keys", "yardsale.guide");
        return;
    }
    bool ok = ys_guide_push_fields(&reply->data);
    struct json_value layers;
    json_init(&layers);
    json_set_array(&layers);
    ok = ok && ys_guide_fill_layers(&layers) &&
        json_push_kv(&reply->data, "layers", &layers);
    json_free(&layers);
    if (!ok)
        ys_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "YARDSALE_GUIDE_OUTPUT", "render", false,
                "the sell guide could not be rendered", "yardsale.guide");
}
