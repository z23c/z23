/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Typed native plan/commit adapter for custody-bound ZBLG anchors. */

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

#define BAN_TAG "native.blog.anchor"

static void ban_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(BAN_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool ban_body_is_error(const struct json_value *body,
                              const char **message)
{
    if (!body)
        return true;
    if (body->type == JSON_STR) {
        if (message) *message = json_get_str(body);
        return true;
    }
    if (body->type != JSON_OBJ)
        return false;
    const struct json_value *error = json_get(body, "error");
    if (error && !json_is_null(error)) {
        if (message) {
            *message = error->type == JSON_OBJ
                ? json_get_str(json_get(error, "message"))
                : json_get_str(error);
        }
        return true;
    }
    const struct json_value *code = json_get(body, "code");
    const struct json_value *text = json_get(body, "message");
    if (code && code->type == JSON_INT && text && text->type == JSON_STR) {
        if (message) *message = json_get_str(text);
        return true;
    }
    return false;
}

static void ban_merge_object(struct json_value *dst,
                             const struct json_value *src)
{
    if (!src || src->type != JSON_OBJ)
        return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *key = src->keys ? src->keys[i] : NULL;
        if (key && key[0])
            (void)json_push_kv(dst, key, &src->children[i]);
    }
}

static bool ban_request_is_malformed(const struct zcl_command_request *request,
                                     const struct zcl_command_reply *reply)
{
    return !request || !request->spec || !reply;
}

static bool ban_scope_is_invalid(const char *scope)
{
    return !scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0);
}

static bool ban_required_inputs_missing(bool confirm, const char *name,
                                        const char *event_id,
                                        const char *idempotency,
                                        const char *plan_id)
{
    return (!confirm && (!name || !event_id || !idempotency))
        || (confirm && !plan_id);
}

static char *ban_encode_rpc_params(const char *scope, bool confirm,
                                   const char *name, const char *event_id,
                                   const char *idempotency,
                                   const char *plan_id)
{
    struct rpc_arg_builder params;
    rpc_arg_builder_init(&params);
    rpc_arg_builder_push_str(&params, scope);
    rpc_arg_builder_push_str(&params, confirm ? "" : name);
    rpc_arg_builder_push_str(&params, confirm ? "" : event_id);
    rpc_arg_builder_push_str(&params, confirm ? "" : idempotency);
    rpc_arg_builder_push_str(&params, confirm ? plan_id : "");
    struct json_value confirm_value;
    json_init(&confirm_value);
    json_set_bool(&confirm_value, confirm);
    rpc_arg_builder_push_value(&params, &confirm_value);
    json_free(&confirm_value);
    return rpc_arg_builder_to_json(&params);
}

static const char *ban_text_or_fallback(const char *text,
                                        const char *fallback)
{
    return text && text[0] ? text : fallback;
}

static const char *ban_expected_status(bool confirm)
{
    return confirm ? "broadcast" : "planned";
}

static void ban_set_reply_stage(struct json_value *data,
                                const struct json_value *body,
                                const char *scope, bool confirm)
{
    if (!confirm) {
        const char *durable_plan = json_get_str(json_get(body, "plan_id"));
        struct json_value commit;
        json_init(&commit);
        json_set_object(&commit);
        json_push_kv_str(&commit, "wallet_scope", scope);
        json_push_kv_str(&commit, "plan_id", durable_plan ? durable_plan : "");
        json_push_kv_bool(&commit, "confirm", true);
        char encoded[256];
        size_t wrote = json_write(&commit, encoded, sizeof(encoded));
        json_free(&commit);
        if (wrote == 0 || wrote >= sizeof(encoded))
            (void)snprintf(encoded, sizeof(encoded), "{\"confirm\":true}");
        json_push_kv_str(data, "stage", "plan");
        json_push_kv_bool(data, "committed", false);
        json_push_kv_str(data, "commit_input", encoded);
    } else {
        json_push_kv_str(data, "stage", "committed");
        json_push_kv_bool(data, "committed", true);
    }
}

/* ── Blog (ZBLG) ────────────────────────────────────────────────────── */

void zcl_native_handle_blog_anchor(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (ban_request_is_malformed(request, reply))
        return;
    const char *path = request->spec->path;
    const char *scope = json_get_str(json_get(request->input, "wallet_scope"));
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    const char *name = json_get_str(json_get(request->input, "name"));
    const char *event_id = json_get_str(json_get(request->input, "event_id"));
    const char *idempotency =
        json_get_str(json_get(request->input, "idempotency_key"));
    const char *plan_id = json_get_str(json_get(request->input, "plan_id"));
    if (ban_scope_is_invalid(scope)) {
        ban_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "WALLET_SCOPE_REQUIRED", "normalize",
                 "wallet_scope must explicitly be dev or prod", path);
        return;
    }
    if (ban_required_inputs_missing(confirm, name, event_id, idempotency,
                                    plan_id)) {
        ban_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_INPUT", "normalize",
                 confirm
                    ? "commit requires wallet_scope, plan_id, and confirm:true"
                    : "plan requires wallet_scope, name, event_id, and idempotency_key",
                 path);
        return;
    }
    char *params_json = ban_encode_rpc_params(scope, confirm, name, event_id,
                                              idempotency, plan_id);
    if (!params_json) {
        ban_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "ARG_BUILD_FAILED", "normalize",
                 "could not encode Blog anchor RPC parameters", path);
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("blog_anchor", params_json);
    free(params_json);
    if (!raw) {
        ban_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 "the node did not answer blog_anchor", "blog_anchor");
        return;
    }
    struct json_value body;
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&body);
        ban_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                 "BAD_RPC_BODY", "serialize",
                 "blog_anchor returned an unparseable body", "blog_anchor");
        return;
    }
    const char *error = NULL;
    if (ban_body_is_error(&body, &error) || body.type != JSON_OBJ) {
        char message[256];
        (void)snprintf(message, sizeof(message), "%s",
                       ban_text_or_fallback(error,
                                            "blog_anchor reported an error"));
        json_free(&body);
        ban_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "BLOG_ANCHOR_REFUSED", "execute", message, "blog_anchor");
        return;
    }
    const char *status = json_get_str(json_get(&body, "status"));
    const char *expected = ban_expected_status(confirm);
    if (!status || strcmp(status, expected) != 0) {
        char message[256];
        (void)snprintf(message, sizeof(message),
                       "Blog anchor expected status %s, got %s", expected,
                       ban_text_or_fallback(status, "absent"));
        json_free(&body);
        ban_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_BLOCKED, "BLOG_ANCHOR_INCOMPLETE",
                 "execute", message, "blog_anchor");
        return;
    }
    ban_merge_object(&reply->data, &body);
    ban_set_reply_stage(&reply->data, &body, scope, confirm);
    json_free(&body);
    /* The plan leg atomically reserves the maximum fee and is therefore a
     * deliberate local money-state mutation even though nothing is relayed. */
    reply->error.mutated = true;
}
