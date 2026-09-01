/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Typed, path-free seller offer command for the P2P file market. */

#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MON_TAG "native.market.offer"

struct mon_code_map {
    const char *code;
    enum zcl_command_status status;
    enum zcl_command_exit exit_code;
};

static const struct mon_code_map k_codes[] = {
    { "CONTENT_UNAVAILABLE", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_INVALID },
    { "CONTENT_INVALID", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_INVALID },
    { "CONTENT_TOO_LARGE", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_INVALID },
    { "CONTENT_UNSTABLE", ZCL_COMMAND_STATUS_BLOCKED,
      ZCL_COMMAND_EXIT_TRANSIENT },
    { "PRICE_INVALID", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_INVALID },
    { "ENDPOINT_UNKNOWN", ZCL_COMMAND_STATUS_BLOCKED,
      ZCL_COMMAND_EXIT_DENIED },
    { "ONION_ENDPOINT_UNAVAILABLE", ZCL_COMMAND_STATUS_BLOCKED,
      ZCL_COMMAND_EXIT_DENIED },
    { "PAYEE_UNAVAILABLE", ZCL_COMMAND_STATUS_BLOCKED,
      ZCL_COMMAND_EXIT_DENIED },
    { "SELLER_KEY_UNAVAILABLE", ZCL_COMMAND_STATUS_BLOCKED,
      ZCL_COMMAND_EXIT_DENIED },
    { "SEAL_FAILED", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_FAILED },
    { "OFFER_SAVE_FAILED", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_FAILED },
    { "CONTENT_BIND_FAILED", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_FAILED },
    { "WIRE_FAILED", ZCL_COMMAND_STATUS_FAILED,
      ZCL_COMMAND_EXIT_INTERNAL },
};

static void mon_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence, bool mutated)
{
    LOG_ERROR(MON_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, status, exit_code, code, phase, mutated,
                           false, message, evidence ? evidence : "");
}

static void mon_merge(struct json_value *dst, const struct json_value *src)
{
    if (!dst || !src || src->type != JSON_OBJ) return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *key = src->keys ? src->keys[i] : NULL;
        if (!key || !key[0] || strcmp(key, "ok") == 0 ||
            strcmp(key, "code") == 0 || strcmp(key, "message") == 0)
            continue;
        (void)json_push_kv(dst, key, &src->children[i]);
    }
}

static bool mon_call(struct zcl_command_reply *reply,
                     const struct json_value *input, struct json_value *body)
{
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, input);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        mon_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode the offer request",
                 "zmarket_offer_publish", false);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("zmarket_offer_publish", params);
    free(params);
    if (!raw) {
        mon_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 "the node did not answer the offer request",
                 "zmarket_offer_publish", false);
        return false;
    }
    bool parsed = json_read(body, raw, strlen(raw));
    free(raw);
    if (!parsed || body->type != JSON_OBJ) {
        json_free(body);
        mon_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "the node returned an invalid offer document",
                 "zmarket_offer_publish", false);
        return false;
    }
    if (json_get_bool_or(body, "ok", false)) return true;

    const char *code = json_get_str(json_get(body, "code"));
    const char *message = json_get_str(json_get(body, "message"));
    enum zcl_command_status status = ZCL_COMMAND_STATUS_FAILED;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_FAILED;
    for (size_t i = 0; i < sizeof(k_codes) / sizeof(k_codes[0]); i++) {
        if (code && strcmp(code, k_codes[i].code) == 0) {
            status = k_codes[i].status;
            exit_code = k_codes[i].exit_code;
            break;
        }
    }
    char code_copy[64], message_copy[320];
    (void)snprintf(code_copy, sizeof(code_copy), "%s",
                   code && code[0] ? code : "OFFER_REFUSED");
    (void)snprintf(message_copy, sizeof(message_copy), "%s",
                   message && message[0] ? message
                                         : "the offer operation was refused");
    json_free(body);
    mon_fail(reply, status, exit_code, code_copy, "execute", message_copy,
             "zmarket_offer_publish", false);
    return false;
}

void zcl_native_handle_market_offer(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply) return;
    const char *filepath = json_get_str(json_get(request->input, "filepath"));
    const struct json_value *price = json_get(request->input,
                                              "price_per_mb_zat");
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    if (!filepath || !filepath[0] || !price || price->type != JSON_INT ||
        json_get_int(price) <= 0) {
        mon_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 "filepath and a positive integer price_per_mb_zat are required",
                 "app.market.offer", false);
        return;
    }

    struct json_value input = {0};
    json_set_object(&input);
    json_push_kv_str(&input, "filepath", filepath);
    json_push_kv_int(&input, "price_per_mb_zat", json_get_int(price));
    json_push_kv_bool(&input, "confirm", confirm);
    struct json_value body;
    json_init(&body);
    if (!mon_call(reply, &input, &body)) {
        json_free(&input);
        return;
    }
    char commit[4608];
    size_t commit_len = confirm ? 0 : json_write(&input, commit,
                                                 sizeof(commit));
    json_free(&input);
    mon_merge(&reply->data, &body);
    if (!confirm) {
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_bool(&reply->data, "spends_funds", false);
        (void)json_push_kv_str(
            &reply->data, "confirm_hint",
            "pass commit_input back to app market offer to sign, bind, and announce");
        (void)json_push_kv_str(&reply->data, "commit_input",
                               commit_len > 0 && commit_len < sizeof(commit)
                                   ? commit : "{\"confirm\":true}");
        reply->error.mutated = false;
        json_free(&body);
        return;
    }
    bool replay = json_get_bool_or(&body, "idempotent_replay", false);
    bool announced = json_get_bool_or(&body, "announced", false);
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_bool(&reply->data, "spends_funds", false);
    reply->error.mutated = !replay || announced;
    json_free(&body);
}
