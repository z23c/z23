/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared typed adapter for custody-bound opaque overlay intents. */

#include "command/native_command.h"

#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOIC_TAG "native.overlay.intent"

static void noic_fail(struct zcl_command_reply *reply,
                      enum zcl_command_status status,
                      enum zcl_command_exit exit_code, const char *code,
                      const char *phase, const char *message,
                      const char *evidence)
{
    LOG_ERROR(NOIC_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool noic_rpc_error(const struct json_value *body, const char **message)
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
    /* node_rpc_call returns the envelope's error VALUE bare on failure
     * ({ok:false,code,message,...}) — no "error" key. Without this rung
     * every node-side refusal falls through to the status check and is
     * misreported as "expected planned, got absent". */
    const struct json_value *ok = json_get(body, "ok");
    const struct json_value *msg = json_get(body, "message");
    if (ok && ok->type == JSON_BOOL && !json_get_bool(ok) &&
        msg && msg->type == JSON_STR) {
        if (message) *message = json_get_str(msg);
        return true;
    }
    return false;
}

static void noic_merge(struct json_value *dst, const struct json_value *src)
{
    if (!src || src->type != JSON_OBJ) return;
    static const char *const public_fields[] = {
        "schema", "wallet_scope", "wallet_instance_id", "network_genesis",
        "operation", "plan_id", "plan_digest", "snapshot_root",
        "snapshot_status", "actual_fee_zat", "maximum_fee_zat",
        "reserved_zat", "expires_at", "state", "idempotent_replay",
        "status", "txid"
    };
    for (size_t i = 0; i < src->num_children; i++) {
        const char *key = src->keys ? src->keys[i] : NULL;
        bool allowed = false;
        for (size_t j = 0; key && j < sizeof(public_fields) /
                                      sizeof(public_fields[0]); j++)
            if (strcmp(key, public_fields[j]) == 0) {
                allowed = true;
                break;
            }
        if (allowed) (void)json_push_kv(dst, key, &src->children[i]);
    }
}

static bool noic_request_usable(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply,
                                const char *rpc_method, const char *operation)
{
    return request && request->spec && reply && rpc_method && operation;
}

static bool noic_scope_valid(const char *scope)
{
    static const char *const noic_allowed_scopes[] = { "dev", "prod" };
    if (!scope) return false;
    for (size_t i = 0; i < sizeof(noic_allowed_scopes) /
                              sizeof(noic_allowed_scopes[0]); i++)
        if (strcmp(scope, noic_allowed_scopes[i]) == 0) return true;
    return false;
}

static bool noic_intent_inputs_missing(bool confirm, const char *plan_id,
                                       bool has_idempotency,
                                       bool operation_inputs_present)
{
    if (confirm) return !plan_id || strlen(plan_id) != 64;
    return !has_idempotency || !operation_inputs_present;
}

static void noic_build_forwarded(const struct zcl_command_request *request,
                                 const char *operation, bool confirm,
                                 struct json_value *forwarded)
{
    for (size_t i = 0; i < request->input->num_children; i++) {
        const char *key = request->input->keys ? request->input->keys[i] : NULL;
        if (key && key[0])
            (void)json_push_kv(forwarded, key, &request->input->children[i]);
    }
    if (!confirm) (void)json_push_kv_str(forwarded, "operation", operation);
}

static bool noic_body_refused(const struct json_value *body,
                              const char **message)
{
    return noic_rpc_error(body, message) || body->type != JSON_OBJ;
}

static void noic_format_refusal_message(char *message, size_t size,
                                        const char *error)
{
    snprintf(message, size, "%s",
             error && error[0] ? error : "overlay intent reported an error");
}

static const char *noic_expected_status(bool confirm)
{
    return confirm ? "broadcast" : "planned";
}

static bool noic_status_matches(const char *status, const char *expected)
{
    return status && strcmp(status, expected) == 0;
}

static void noic_format_status_message(char *message, size_t size,
                                       const char *expected,
                                       const char *status)
{
    snprintf(message, size, "overlay intent expected %s, got %s", expected,
             status && status[0] ? status : "absent");
}

static void noic_stage_reply(struct zcl_command_reply *reply,
                             const struct json_value *body, const char *scope,
                             bool confirm)
{
    if (!confirm) {
        const char *durable = json_get_str(json_get(body, "plan_id"));
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
}

void zcl_native_overlay_intent_run(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *rpc_method,
    const char *operation, bool operation_inputs_present)
{
    if (!noic_request_usable(request, reply, rpc_method, operation))
        return;
    const char *path = request->spec->path;
    const char *scope = json_get_str(json_get(request->input, "wallet_scope"));
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    const char *plan_id = json_get_str(json_get(request->input, "plan_id"));
    if (!noic_scope_valid(scope)) {
        noic_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "WALLET_SCOPE_REQUIRED", "normalize",
                  "wallet_scope must explicitly be dev or prod", path);
        return;
    }
    bool has_idempotency =
        json_get_str(json_get(request->input, "idempotency_key")) != NULL;
    if (noic_intent_inputs_missing(confirm, plan_id, has_idempotency,
                                   operation_inputs_present)) {
        noic_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "MISSING_INPUT", "normalize",
                  confirm
                    ? "commit requires wallet_scope, 64-hex plan_id, and confirm:true"
                    : "plan requires wallet_scope, operation fields, and idempotency_key",
                  path);
        return;
    }
    struct json_value forwarded;
    json_init(&forwarded); json_set_object(&forwarded);
    noic_build_forwarded(request, operation, confirm, &forwarded);
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, &forwarded);
    json_free(&forwarded);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        noic_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "ARG_BUILD_FAILED", "normalize",
                  "could not encode overlay intent parameters", path);
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(rpc_method, params);
    free(params);
    if (!raw) {
        noic_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                  ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                  "the node did not answer the overlay intent request",
                  rpc_method);
        return;
    }
    struct json_value body;
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&body);
        noic_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "BAD_RPC_BODY", "serialize",
                  "overlay intent returned an unparseable body", rpc_method);
        return;
    }
    const char *error = NULL;
    if (noic_body_refused(&body, &error)) {
        char message[256];
        noic_format_refusal_message(message, sizeof(message), error);
        json_free(&body);
        noic_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                  "OVERLAY_INTENT_REFUSED", "execute", message, rpc_method);
        return;
    }
    const char *status = json_get_str(json_get(&body, "status"));
    const char *expected = noic_expected_status(confirm);
    if (!noic_status_matches(status, expected)) {
        char message[192];
        noic_format_status_message(message, sizeof(message), expected, status);
        json_free(&body);
        noic_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                  "OVERLAY_INTENT_INCOMPLETE", "execute", message, rpc_method);
        return;
    }
    noic_merge(&reply->data, &body);
    noic_stage_reply(reply, &body, scope, confirm);
    json_free(&body);
    reply->error.mutated = true; /* plan atomically reserves custody */
}
