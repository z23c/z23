/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: typed CLI adapters for durable vault intent RPCs. */

#include "command/native_command.h"
#include "controllers/rpc_params.h"
#include "controllers/agent_session_client.h"
#include "controllers/vault_intent_controller.h"
#include "controllers/wallet_native_handlers.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "rpc/rpc_timeout.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VNI_TAG "native.vault.intent"

static void vni_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, const char *evidence)
{
    LOG_ERROR(VNI_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "intent", false, false, message,
        evidence ? evidence : "");
}

static void vni_apply_agent_session_bearer(
    const struct zcl_command_request *request, struct json_value *rpc_input,
    const char *method)
{
    const char *session = request->context
        ? request->context->agent_session : NULL;
    /* Planning must apply a lowered owner-reviewed reserve floor inside the
     * node's atomic reservation, not in the CLI after the fact. This bearer
     * field exists only in the authenticated local RPC packet and is never
     * copied into output or logs. */
    if (session && session[0] &&
        strcmp(method, "vault_intent_plan") == 0)
        (void)json_push_kv_str(rpc_input, "_agent_session", session);
}

static bool vni_method_needs_proof_build(const char *method)
{
    return strcmp(method, "vault_intent_plan") == 0 ||
           strcmp(method, "vault_intent_fanout_plan") == 0 ||
           strcmp(method, "vault_intent_commit") == 0;
}

static void vni_copy_error_state(struct zcl_command_reply *reply,
                                 const struct json_value *body)
{
    const char *current_state =
        json_get_str(json_get(body, "current_state"));
    const char *next_action =
        json_get_str(json_get(body, "next_action"));
    bool retryable = json_get_bool_or(body, "retryable", false);
    bool human_action_required = json_get_bool_or(
        body, "human_action_required", false);
    reply->error.retryable = retryable;
    reply->error.human_action_required = human_action_required;
    (void)snprintf(reply->error.current_state,
                   sizeof(reply->error.current_state), "%s",
                   current_state && current_state[0]
                       ? current_state : "REQUEST_FAILED");
    (void)snprintf(reply->error.next_action,
                   sizeof(reply->error.next_action), "%s",
                   next_action && next_action[0]
                       ? next_action : "inspect the intent request and retry safely");
    if (retryable) {
        reply->status = ZCL_COMMAND_STATUS_BLOCKED;
        reply->exit_code = ZCL_COMMAND_EXIT_TRANSIENT;
    }
}

static bool vni_rpc(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply, const char *method)
{
    struct json_value rpc_input;
    json_init(&rpc_input);
    json_copy(&rpc_input, request->input);
    vni_apply_agent_session_bearer(request, &rpc_input, method);
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, &rpc_input);
    char *params = rpc_arg_builder_to_json(&args);
    json_free(&rpc_input);
    if (!params) {
        vni_fail(reply, "ARG_BUILD_FAILED", "could not encode intent input",
                 method);
        return false;
    }
    struct json_value body;
    /* Private commit rebuilds and persists the exact signed Sapling
     * transaction before relay, so it needs the same bounded proof budget as
     * the non-broadcasting preflight.  Treating commit as an ordinary 10 s
     * RPC makes a timeout ambiguous precisely at the broadcast boundary. */
    bool proof_build = vni_method_needs_proof_build(method);
    bool called = proof_build
        ? wnh_call_rpc_deadline(reply, method, params,
                                RPC_PROOF_BUILD_TIMEOUT_MS, &body)
        : wnh_call_rpc(reply, method, params, &body);
    free(params);
    if (!called) return false;
    bool ok = json_get_bool(json_get(&body, "ok"));
    if (!ok) {
        const char *code = json_get_str(json_get(&body, "code"));
        const char *message = json_get_str(json_get(&body, "message"));
        vni_fail(reply, code ? code : "INTENT_FAILED",
                 message ? message : "intent operation failed", method);
        vni_copy_error_state(reply, &body);
        json_free(&body);
        return false;
    }
    json_copy(&reply->data, &body);
    json_free(&body);
    return true;
}

void zcl_native_handle_vault_intent_issue(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *asset = json_get_str(json_get(request->input, "asset"));
    const char *amount = json_get_str(json_get(request->input, "amount"));
    int64_t amount_zat = 0;
    if (!asset) asset = "ZCL";
    if (strcmp(asset, "ZCL") != 0 ||
        !vault_intent_parse_zcl_amount(amount, &amount_zat)) {
        vni_fail(reply, "INVALID_REQUEST",
                 "issue currently requires asset=ZCL and decimal-string amount",
                 "vault.intent.issue");
        return;
    }
    struct json_value body;
    if (!wnh_call_rpc(reply, "getnewaddress", NULL, &body)) return;
    const char *address = body.type == JSON_STR ? json_get_str(&body) : NULL;
    if (!address || !address[0]) {
        json_free(&body);
        vni_fail(reply, "NO_ADDRESS", "wallet did not return a fresh address",
                 "getnewaddress");
        return;
    }
    char uri[256];
    snprintf(uri, sizeof(uri), "zclassic:%s?amount=%s", address, amount);
    json_push_kv_str(&reply->data, "uri", uri);
    json_push_kv_str(&reply->data, "address", address);
    json_push_kv_str(&reply->data, "asset", "ZCL");
    json_push_kv_str(&reply->data, "amount", amount);
    json_push_kv_str(&reply->data, "sender_authentication", "anonymous");
    json_push_kv_str(&reply->data, "request_format", "zclassic-uri");
    reply->error.mutated = true;
    json_free(&body);
}

void zcl_native_handle_vault_intent_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!zcl_native_input_was_stdin()) {
        vni_fail(reply, "STDIN_REQUIRED",
                 "intent effects are accepted only through --input=-",
                 "vault.intent.plan");
        return;
    }
    if (!vni_rpc(request, reply, "vault_intent_plan"))
        return;
    const char *session = request->context
        ? request->context->agent_session : NULL;
    if (!session || !session[0])
        return;
    const char *plan_id = json_get_str(json_get(&reply->data, "plan_id"));
    const struct json_value *effects = json_get(request->input, "effects");
    const struct json_value *first = effects && effects->type == JSON_ARR
        ? json_at(effects, 0) : NULL;
    const char *recipient = first && first->type == JSON_OBJ
        ? json_get_str(json_get(first, "to")) : NULL;
    char why[64] = { 0 };
    if (!plan_id || !recipient ||
        !agent_session_client_bind_intent(
            session, plan_id, recipient, why, sizeof(why))) {
        vni_fail(reply, why[0] ? why : "INTENT_BIND_FAILED",
                 "the durable plan could not be bound to this bounded session; "
                 "retry the same idempotency key", "vault.intent.plan");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s",
                       "retry vault intent plan with the same input and "
                       "idempotency_key");
    }
}

void zcl_native_handle_vault_intent_fanout_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (vni_rpc(request, reply, "vault_intent_fanout_plan"))
        reply->error.mutated = !json_get_bool_or(&reply->data,
                                                  "idempotent_plan", false);
}

void zcl_native_handle_vault_intent_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (vni_rpc(request, reply, "vault_intent_commit"))
        reply->error.mutated = !json_get_bool_or(&reply->data,
                                                 "idempotent_replay", false);
}

void zcl_native_handle_vault_intent_submit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (vni_rpc(request, reply, "vault_intent_submit"))
        reply->error.mutated = !json_get_bool_or(&reply->data,
                                                 "idempotent_submit", false);
}

void zcl_native_handle_vault_intent_cancel(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (vni_rpc(request, reply, "vault_intent_cancel"))
        reply->error.mutated = !json_get_bool_or(&reply->data,
                                                 "idempotent_cancel", false);
}

void zcl_native_handle_vault_intent_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)vni_rpc(request, reply, "vault_intent_status");
}

void zcl_native_handle_vault_intent_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)vni_rpc(request, reply, "vault_intent_list");
}
