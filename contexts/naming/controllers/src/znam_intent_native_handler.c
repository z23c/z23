/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Typed native adapter for durable, custody-bound ZNAM intents. */

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

#define ZNIN_TAG "native.znam.intent"

static void znin_fail(struct zcl_command_reply *reply,
                      enum zcl_command_status status,
                      enum zcl_command_exit exit_code, const char *code,
                      const char *phase, const char *message,
                      const char *evidence)
{
    LOG_ERROR(ZNIN_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool znin_rpc_error(const struct json_value *body, const char **message)
{
    if (!body) return true;
    if (body->type == JSON_STR) {
        if (message) *message = json_get_str(body);
        return true;
    }
    if (body->type != JSON_OBJ) return false;
    const struct json_value *error = json_get(body, "error");
    if (error && !json_is_null(error)) {
        if (message)
            *message = error->type == JSON_OBJ
                ? json_get_str(json_get(error, "message"))
                : json_get_str(error);
        return true;
    }
    return false;
}

static void znin_merge(struct json_value *dst, const struct json_value *src)
{
    if (!src || src->type != JSON_OBJ) return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *key = src->keys ? src->keys[i] : NULL;
        if (key && key[0]) (void)json_push_kv(dst, key, &src->children[i]);
    }
}

static void znin_run(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply, const char *operation,
                     bool operation_inputs_present)
{
    if (!request || !request->spec || !reply || !operation) return;
    const char *path = request->spec->path;
    const char *scope = json_get_str(json_get(request->input, "wallet_scope"));
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    const char *plan_id = json_get_str(json_get(request->input, "plan_id"));
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0)) {
        znin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "WALLET_SCOPE_REQUIRED", "normalize",
                  "wallet_scope must explicitly be dev or prod", path);
        return;
    }
    bool has_idempotency =
        json_get_str(json_get(request->input, "idempotency_key")) != NULL;
    if ((confirm && (!plan_id || strlen(plan_id) != 64)) ||
        (!confirm && (!has_idempotency || !operation_inputs_present))) {
        znin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "MISSING_INPUT", "normalize",
                  confirm
                    ? "commit requires wallet_scope, 64-hex plan_id, and confirm:true"
                    : "plan requires wallet_scope, operation fields, and idempotency_key",
                  path);
        return;
    }
    struct json_value forwarded;
    json_init(&forwarded); json_set_object(&forwarded);
    for (size_t i = 0; i < request->input->num_children; i++) {
        const char *key = request->input->keys ? request->input->keys[i] : NULL;
        if (key && key[0])
            (void)json_push_kv(&forwarded, key, &request->input->children[i]);
    }
    if (!confirm) (void)json_push_kv_str(&forwarded, "operation", operation);
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, &forwarded);
    json_free(&forwarded);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        znin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "ARG_BUILD_FAILED", "normalize",
                  "could not encode ZNAM intent parameters", path);
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("znam_intent", params);
    free(params);
    if (!raw) {
        znin_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                  ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                  "the node did not answer znam_intent", "znam_intent");
        return;
    }
    struct json_value body;
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&body);
        znin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "BAD_RPC_BODY", "serialize",
                  "znam_intent returned an unparseable body", "znam_intent");
        return;
    }
    const char *error = NULL;
    if (znin_rpc_error(&body, &error) || body.type != JSON_OBJ) {
        char message[256];
        snprintf(message, sizeof(message), "%s",
                 error && error[0] ? error : "znam_intent reported an error");
        json_free(&body);
        znin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                  "ZNAM_INTENT_REFUSED", "execute", message, "znam_intent");
        return;
    }
    const char *status = json_get_str(json_get(&body, "status"));
    const char *expected = confirm ? "broadcast" : "planned";
    if (!status || strcmp(status, expected) != 0) {
        char message[192];
        snprintf(message, sizeof(message),
                 "ZNAM intent expected %s, got %s", expected,
                 status && status[0] ? status : "absent");
        json_free(&body);
        znin_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                  "ZNAM_INTENT_INCOMPLETE", "execute", message,
                  "znam_intent");
        return;
    }
    znin_merge(&reply->data, &body);
    if (!confirm) {
        const char *durable = json_get_str(json_get(&body, "plan_id"));
        struct json_value commit;
        json_init(&commit); json_set_object(&commit);
        (void)json_push_kv_str(&commit, "wallet_scope", scope);
        (void)json_push_kv_str(&commit, "plan_id", durable ? durable : "");
        (void)json_push_kv_bool(&commit, "confirm", true);
        char encoded[256];
        size_t wrote = json_write(&commit, encoded, sizeof(encoded));
        json_free(&commit);
        if (wrote == 0 || wrote >= sizeof(encoded))
            snprintf(encoded, sizeof(encoded), "{\"confirm\":true}");
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_str(&reply->data, "commit_input", encoded);
    } else {
        (void)json_push_kv_str(&reply->data, "stage", "committed");
        (void)json_push_kv_bool(&reply->data, "committed", true);
    }
    json_free(&body);
    reply->error.mutated = true; /* plan atomically reserves custody */
}

void zcl_native_handle_name_register(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && json_get_str(json_get(input, "name")) &&
        json_get_str(json_get(input, "type")) &&
        json_get_str(json_get(input, "value"));
    znin_run(request, reply, "register", present);
}

void zcl_native_handle_name_update(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && json_get_str(json_get(input, "name")) &&
        json_get_str(json_get(input, "type")) &&
        json_get_str(json_get(input, "value"));
    znin_run(request, reply, "update", present);
}

void zcl_native_handle_name_transfer(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && json_get_str(json_get(input, "name")) &&
        json_get_str(json_get(input, "new_owner"));
    znin_run(request, reply, "transfer", present);
}

void zcl_native_handle_name_renew(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && json_get_str(json_get(input, "name"));
    znin_run(request, reply, "renew", present);
}

void zcl_native_handle_name_set_record(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && json_get_str(json_get(input, "name")) &&
        json_get_str(json_get(input, "type")) &&
        json_get_str(json_get(input, "value"));
    znin_run(request, reply, "set_record", present);
}

void zcl_native_handle_name_set_text(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && json_get_str(json_get(input, "name")) &&
        json_get_str(json_get(input, "key"));
    znin_run(request, reply, "set_text", present);
}
