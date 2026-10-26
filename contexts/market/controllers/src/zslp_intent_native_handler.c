/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Typed native adapter for durable, custody-bound ZSLP intents. */

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

#define ZTIN_TAG "native.zslp.intent"

static void ztin_fail(struct zcl_command_reply *reply,
                      enum zcl_command_status status,
                      enum zcl_command_exit exit_code, const char *code,
                      const char *phase, bool retryable, const char *message,
                      const char *evidence)
{
    LOG_ERROR(ZTIN_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           false, message, evidence ? evidence : "");
}

/* json_get_str() answers "" for a key that is ABSENT, and "" for a key that is
 * present but empty — it never answers NULL (platform/modules/json/src/json.c).
 * A required text field therefore has to be tested for CONTENT: a bare
 * `json_get_str(...) != NULL` is true for a request that carried nothing at
 * all, which is how this file's own MISSING_INPUT refusal became unreachable
 * and let a plan with no idempotency key through to a custody reservation with
 * only the node behind it. */
static const char *ztin_text(const struct json_value *parent, const char *key)
{
    const char *value = json_get_str(json_get(parent, key));
    return value && value[0] ? value : NULL;
}

/* Out params are always non-NULL: this is a private helper called from one
 * site below with real locals, never with an optional pointer. */
static bool ztin_rpc_error(const struct json_value *body, const char **message,
                           const char **code, bool *retryable)
{
    *message = NULL;
    *code = NULL;
    *retryable = false;
    if (!body) return true;
    if (body->type == JSON_STR) {
        *message = json_get_str(body);
        return true;
    }
    if (body->type != JSON_OBJ) return false;
    const struct json_value *error = json_get(body, "error");
    if (error && !json_is_null(error)) {
        *message = error->type == JSON_OBJ
            ? json_get_str(json_get(error, "message"))
            : json_get_str(error);
        return true;
    }
    /* node_rpc_call returns the envelope's error VALUE bare on failure
     * ({ok:false,code,message,...}) — no "error" key. Without this rung
     * every node-side refusal (e.g. WALLET_NOT_ENCRYPTED) falls through to
     * the status check below and is misreported as "expected planned, got
     * absent" instead of the node's own code and message. Mirrors
     * tools/command/native_overlay_intent_command.c's noic_rpc_error(). */
    const struct json_value *ok = json_get(body, "ok");
    const struct json_value *msg = json_get(body, "message");
    bool bare_refusal = ok && ok->type == JSON_BOOL && !json_get_bool(ok) &&
        msg && msg->type == JSON_STR;
    if (!bare_refusal) return false;
    *message = json_get_str(msg);
    *code = json_get_str(json_get(body, "code"));
    *retryable = json_get_bool_or(body, "retryable", false);
    return true;
}

/* Copies val into dst, falling back to a default when val is absent — kept
 * out of ztin_run() so its call site is a single statement, not a new
 * branch, and does not grow ztin_run's pinned cyclomatic baseline. */
static void ztin_copy_or(char *dst, size_t n, const char *val,
                         const char *fallback)
{
    bool present = val && val[0];
    snprintf(dst, n, "%s", present ? val : fallback);
}

static void ztin_merge(struct json_value *dst, const struct json_value *src)
{
    if (!src || src->type != JSON_OBJ) return;
    for (size_t i = 0; i < src->num_children; i++) {
        const char *key = src->keys ? src->keys[i] : NULL;
        if (key && key[0]) (void)json_push_kv(dst, key, &src->children[i]);
    }
}

/* True when the adapter itself was invoked without a request, spec, reply or
 * operation name — one call so ztin_run's guard adds no operators of its
 * own and keeps its short-circuit order (request before request->spec). */
static bool ztin_call_arguments_missing(
    const struct zcl_command_request *request,
    const struct zcl_command_reply *reply, const char *operation)
{
    return !request || !request->spec || !reply || !operation;
}

/* wallet_scope only means anything as an explicit "dev" or "prod"; an absent
 * or unknown value must fail closed before anything is built or forwarded. */
static bool ztin_scope_unusable(const char *scope)
{
    return !scope ||
        (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0);
}

/* A commit needs a 64-hex plan_id; a plan needs the operation's own fields
 * plus the shared idempotency_key. Kept as one predicate per phase so
 * ztin_run keeps a single failing branch per refusal. */
static bool ztin_required_inputs_missing(bool confirm, const char *plan_id,
                                         bool common_plan_inputs,
                                         bool operation_inputs_present)
{
    return (confirm && (!plan_id || strlen(plan_id) != 64)) ||
        (!confirm &&
         (!common_plan_inputs || !operation_inputs_present));
}

/* The MISSING_INPUT refusal names exactly the fields the failed phase
 * required — kept beside the predicate that decides it. */
static const char *ztin_missing_inputs_message(bool confirm)
{
    return confirm
        ? "commit requires wallet_scope, 64-hex plan_id, and confirm:true"
        : "plan requires wallet_scope, operation fields, and idempotency_key";
}

/* Forwards the caller's input verbatim — plus the operation name on a plan —
 * and encodes it as the zslp_intent RPC parameters. Returns the encoder's
 * own result; ztin_run() answers ARG_BUILD_FAILED when it is NULL. */
static char *ztin_encode_params(const struct json_value *input,
                                const char *operation, bool confirm)
{
    struct json_value forwarded;
    json_init(&forwarded); json_set_object(&forwarded);
    for (size_t i = 0; i < input->num_children; i++) {
        const char *key = input->keys ? input->keys[i] : NULL;
        if (key && key[0])
            (void)json_push_kv(&forwarded, key, &input->children[i]);
    }
    if (!confirm) (void)json_push_kv_str(&forwarded, "operation", operation);
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, &forwarded);
    json_free(&forwarded);
    return rpc_arg_builder_to_json(&args);
}

/* A plan must answer "planned" and a commit "broadcast"; anything else,
 * including an absent status, leaves the intent unconfirmed. */
static bool ztin_status_unexpected(const char *status, bool confirm)
{
    const char *expected = confirm ? "broadcast" : "planned";
    return !status || strcmp(status, expected) != 0;
}

/* Renders the INCOMPLETE evidence line: the phase's expected status and
 * what the node actually answered ("absent" when it carried none). */
static void ztin_format_status_mismatch(char *out, size_t n, bool confirm,
                                        const char *status)
{
    snprintf(out, n, "ZSLP intent expected %s, got %s",
             confirm ? "broadcast" : "planned",
             status && status[0] ? status : "absent");
}

/* Stages the node's answer on the reply: both phases merge the body, and a
 * plan additionally carries a pre-encoded commit envelope so the follow-up
 * call can be issued verbatim. */
static void ztin_stage_reply(struct zcl_command_reply *reply,
                             const struct json_value *body, const char *scope,
                             bool confirm)
{
    ztin_merge(&reply->data, body);
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

static void ztin_run(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply, const char *operation,
                     bool operation_inputs_present)
{
    if (ztin_call_arguments_missing(request, reply, operation)) return;
    const char *path = request->spec->path;
    const char *scope = ztin_text(request->input, "wallet_scope");
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    const char *plan_id = ztin_text(request->input, "plan_id");
    if (ztin_scope_unusable(scope)) {
        ztin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "WALLET_SCOPE_REQUIRED", "normalize", false,
                  "wallet_scope must explicitly be dev or prod", path);
        return;
    }
    bool common_plan_inputs =
        ztin_text(request->input, "idempotency_key") != NULL;
    if (ztin_required_inputs_missing(confirm, plan_id, common_plan_inputs,
                                     operation_inputs_present)) {
        ztin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "MISSING_INPUT", "normalize", false,
                  ztin_missing_inputs_message(confirm), path);
        return;
    }
    char *params = ztin_encode_params(request->input, operation, confirm);
    if (!params) {
        ztin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "ARG_BUILD_FAILED", "normalize", false,
                  "could not encode ZSLP intent parameters", path);
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("zslp_intent", params);
    free(params);
    if (!raw) {
        ztin_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                  ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                  false, "the node did not answer zslp_intent", "zslp_intent");
        return;
    }
    struct json_value body;
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&body);
        ztin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "BAD_RPC_BODY", "serialize", false,
                  "zslp_intent returned an unparseable body", "zslp_intent");
        return;
    }
    const char *error = NULL;
    const char *node_code = NULL;
    bool retryable = false;
    if (ztin_rpc_error(&body, &error, &node_code, &retryable) ||
        body.type != JSON_OBJ) {
        char message[256];
        char code[64];
        ztin_copy_or(message, sizeof(message), error,
                     "zslp_intent reported an error");
        ztin_copy_or(code, sizeof(code), node_code, "ZSLP_INTENT_REFUSED");
        json_free(&body);
        ztin_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                  code, "execute", retryable, message, "zslp_intent");
        return;
    }
    const char *status = json_get_str(json_get(&body, "status"));
    if (ztin_status_unexpected(status, confirm)) {
        char message[192];
        ztin_format_status_mismatch(message, sizeof(message), confirm, status);
        json_free(&body);
        ztin_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                  "ZSLP_INTENT_INCOMPLETE", "execute", false, message,
                  "zslp_intent");
        return;
    }
    ztin_stage_reply(reply, &body, scope, confirm);
    json_free(&body);
    reply->error.mutated = true; /* plan atomically reserves custody */
}

void zcl_native_handle_token_create(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && ztin_text(input, "ticker") &&
        ztin_text(input, "name") &&
        json_get(input, "decimals") && json_get(input, "supply");
    ztin_run(request, reply, "genesis", present);
}

void zcl_native_handle_token_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && ztin_text(input, "token_id") &&
        ztin_text(input, "to") && json_get(input, "units");
    ztin_run(request, reply, "send", present);
}

void zcl_native_handle_token_mint(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && ztin_text(input, "token_id") &&
        ztin_text(input, "to") && json_get(input, "units");
    ztin_run(request, reply, "mint", present);
}

void zcl_native_handle_token_burn(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    bool present = input && ztin_text(input, "token_id") &&
        json_get(input, "units");
    ztin_run(request, reply, "burn", present);
}
