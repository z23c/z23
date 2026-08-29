/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native machine-mesh commands: status receipts and the local pairing
 * ceremony (plan/commit/list/revoke). */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define MESH_STATUS_TAG "native.mesh"
#define MESH_STATUS_CLIENT_BUDGET_MS 15000
#define MESH_STATUS_CLIENT_POLL_MS 50

static bool mesh_status_body_ok(const struct json_value *body)
{
    const struct json_value *value = json_get(body, "ok");
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static void mesh_status_fail(struct zcl_command_reply *reply,
                             enum zcl_command_status status,
                             enum zcl_command_exit exit_code,
                             const char *code, const char *phase,
                             bool retryable, const char *message,
                             const char *evidence)
{
    LOG_ERROR(MESH_STATUS_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           false, message, evidence);
}

/* One bounded bridge call; the parsed body moves to `body`. */
static bool mesh_status_rpc(struct json_value *input, const char *method,
                            struct json_value *body,
                            struct zcl_command_reply *reply)
{
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, input);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                         "normalize", false,
                         "could not encode the mesh status request", method);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(method, params);
    free(params);
    if (!raw) {
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                         ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                         "dispatch", true,
                         "the running node returned no mesh status response",
                         method);
        return false;
    }
    json_init(body);
    bool parsed = json_read(body, raw, strlen(raw));
    free(raw);
    if (!parsed || body->type != JSON_OBJ) {
        json_free(body);
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY",
                         "serialize", false,
                         "the mesh status RPC returned an unreadable body",
                         method);
        return false;
    }
    return true;
}

/* Apply an RPC-level refusal body to the reply, preserving its evidence. */
static void mesh_status_apply_refusal(struct zcl_command_reply *reply,
                                      struct json_value *body,
                                      const char *method)
{
    const char *code = json_get_str(json_get(body, "code"));
    const char *message = json_get_str(json_get(body, "message"));
    bool transient = code && (strcmp(code, "peer_not_connected") == 0 ||
                              strcmp(code, "busy") == 0 ||
                              strcmp(code, "send_failed") == 0);
    zcl_command_reply_fail(
        reply,
        transient ? ZCL_COMMAND_STATUS_BLOCKED : ZCL_COMMAND_STATUS_FAILED,
        transient ? ZCL_COMMAND_EXIT_TRANSIENT : ZCL_COMMAND_EXIT_FAILED,
        code && code[0] ? code : "MESH_STATUS_REFUSED", "execute", transient,
        false,
        message && message[0] ? message : "the node refused the status request",
        method);
    json_copy(&reply->data, body);
}

void zcl_native_handle_ops_mesh_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(MESH_STATUS_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const struct json_value *input =
        request->input && request->input->type == JSON_OBJ ? request->input
                                                           : NULL;
    const char *pairing_id =
        input ? json_get_str(json_get(input, "pairing_id")) : NULL;
    if (!pairing_id || strlen(pairing_id) != 64) {
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, "MISSING_PAIRING_ID",
                         "normalize", false,
                         "pairing_id (64 lowercase hex) is required",
                         "pairing_id");
        return;
    }
    struct json_value begin_input;
    json_init(&begin_input);
    json_set_object(&begin_input);
    json_push_kv_str(&begin_input, "pairing_id", pairing_id);
    struct json_value body;
    if (!mesh_status_rpc(&begin_input, "mesh_status_request", &body, reply)) {
        json_free(&begin_input);
        return;
    }
    json_free(&begin_input);
    if (!mesh_status_body_ok(&body)) {
        mesh_status_apply_refusal(reply, &body, "mesh_status_request");
        json_free(&body);
        return;
    }
    const char *request_id = json_get_str(json_get(&body, "request_id"));
    char request_id_copy[65];
    if (!request_id || strlen(request_id) != 64) {
        json_free(&body);
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY",
                         "serialize", false,
                         "request admission omitted its request id",
                         "mesh_status_request");
        return;
    }
    memcpy(request_id_copy, request_id, sizeof(request_id_copy));
    json_free(&body);

    /* Bounded client-side poll: the responder answers on the established
     * Noise session or the request expires; both are honest outcomes. */
    int64_t deadline = platform_time_monotonic_ms() +
                       MESH_STATUS_CLIENT_BUDGET_MS;
    for (;;) {
        struct json_value poll_input;
        json_init(&poll_input);
        json_set_object(&poll_input);
        json_push_kv_str(&poll_input, "request_id", request_id_copy);
        bool called = mesh_status_rpc(&poll_input, "mesh_status_poll", &body,
                                      reply);
        json_free(&poll_input);
        if (!called)
            return;
        const char *state = json_get_str(json_get(&body, "state"));
        bool ok = mesh_status_body_ok(&body);
        if (!ok || !state) {
            mesh_status_apply_refusal(reply, &body, "mesh_status_poll");
            json_free(&body);
            return;
        }
        if (strcmp(state, "pending") != 0) {
            if (strcmp(state, "expired") == 0) {
                json_free(&body);
                mesh_status_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                                 ZCL_COMMAND_EXIT_TRANSIENT, "STATUS_TIMEOUT",
                                 "execute", true,
                                 "no receipt arrived before the request "
                                 "expired (peer offline, unpaired, or the "
                                 "session dropped)",
                                 "mesh_status_poll");
                return;
            }
            /* Terminal receipt view: "ok" or a named "refused" status — both
             * are successful observations of the peer's answer. */
            zcl_native_bridge_project(request, &body, reply);
            json_free(&body);
            return;
        }
        json_free(&body);
        if (platform_time_monotonic_ms() >= deadline) {
            mesh_status_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                             ZCL_COMMAND_EXIT_TRANSIENT, "STATUS_TIMEOUT",
                             "execute", true,
                             "the status request stayed pending for the full "
                             "client budget",
                             "mesh_status_poll");
            return;
        }
        platform_sleep_ms(MESH_STATUS_CLIENT_POLL_MS);
    }
}


void zcl_native_handle_ops_mesh_identity(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR("native.mesh", "INVALID_REQUEST: null request or reply");
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("dumpstate", "[\"machine_identity\"]");
    if (!raw) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return its machine identity",
                               "machine_identity");
        return;
    }
    struct json_value body = {0};
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    const struct json_value *state = parsed && body.type == JSON_OBJ
                                         ? json_get(&body, "state")
                                         : NULL;
    if (!state || state->type != JSON_OBJ) {
        json_free(&body);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_STATE_BODY",
                               "serialize", false, false,
                               "machine identity response carried no state object",
                               "machine_identity");
        return;
    }
    zcl_native_bridge_project(request, state, reply);
    json_free(&body);
}

/* ── Local pairing ceremony ──────────────────────────────────────────── */

/* days arrives as JSON_INT or a decimal string depending on the transport;
 * both normalize to the integer the RPC adapter requires. */
static bool mesh_pair_input_days(const struct json_value *input,
                                 int64_t *days_out, bool *given_out)
{
    *given_out = false;
    const struct json_value *value = input ? json_get(input, "days") : NULL;
    if (!value)
        return true;
    if (value->type == JSON_INT) {
        *days_out = json_get_int(value);
        *given_out = true;
        return true;
    }
    if (value->type == JSON_STR) {
        const char *s = json_get_str(value);
        char *end = NULL;
        long parsed = s ? strtol(s, &end, 10) : 0;
        if (s && end && *end == '\0' && end != s) {
            *days_out = (int64_t)parsed;
            *given_out = true;
            return true;
        }
    }
    return false;
}

/* Apply a pairing RPC refusal body, preserving its code and evidence. */
static void mesh_pair_apply_refusal(struct zcl_command_reply *reply,
                                    struct json_value *body,
                                    const char *method)
{
    const char *code = json_get_str(json_get(body, "code"));
    const char *message = json_get_str(json_get(body, "message"));
    bool transient = code && (strcmp(code, "PEER_NOT_CONNECTED") == 0 ||
                              strcmp(code, "UNAVAILABLE") == 0);
    zcl_command_reply_fail(
        reply,
        transient ? ZCL_COMMAND_STATUS_BLOCKED : ZCL_COMMAND_STATUS_FAILED,
        transient ? ZCL_COMMAND_EXIT_TRANSIENT : ZCL_COMMAND_EXIT_FAILED,
        code && code[0] ? code : "MESH_PAIRING_REFUSED", "execute", transient,
        false,
        message && message[0] ? message : "the node refused the pairing command",
        method);
    json_copy(&reply->data, body);
}

/* Bridge one pairing RPC body; on success projects it, optionally marking
 * the reply mutated (commit/revoke write durable authority). */
static void mesh_pair_bridge(const struct zcl_command_request *request,
                             struct json_value *input, const char *method,
                             bool mutates, struct zcl_command_reply *reply)
{
    struct json_value body;
    if (!mesh_status_rpc(input, method, &body, reply))
        return;
    if (!mesh_status_body_ok(&body)) {
        mesh_pair_apply_refusal(reply, &body, method);
        json_free(&body);
        return;
    }
    if (mutates)
        reply->error.mutated = true;
    zcl_native_bridge_project(request, &body, reply);
    json_free(&body);
}

void zcl_native_handle_ops_mesh_pair_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(MESH_STATUS_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const struct json_value *input =
        request->input && request->input->type == JSON_OBJ ? request->input
                                                           : NULL;
    const char *peer = input ? json_get_str(json_get(input, "peer")) : NULL;
    struct json_value plan_input;
    json_init(&plan_input);
    json_set_object(&plan_input);
    if (peer && peer[0])
        json_push_kv_str(&plan_input, "peer", peer);
    mesh_pair_bridge(request, &plan_input, "mesh_pairing_plan", false, reply);
    json_free(&plan_input);
}

void zcl_native_handle_ops_mesh_pair_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(MESH_STATUS_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const struct json_value *input =
        request->input && request->input->type == JSON_OBJ ? request->input
                                                           : NULL;
    const char *fingerprint =
        input ? json_get_str(json_get(input, "fingerprint")) : NULL;
    if (!fingerprint || !fingerprint[0]) {
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, "MISSING_FINGERPRINT",
                         "normalize", false,
                         "fingerprint (64 lowercase hex) is required: compare "
                         "the peer's Noise fingerprint out of band (ops mesh "
                         "pair plan here, ops mesh identity on the other "
                         "machine)",
                         "fingerprint");
        return;
    }
    int64_t days = 0;
    bool days_given = false;
    if (!mesh_pair_input_days(input, &days, &days_given)) {
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, "INVALID_DAYS",
                         "normalize", false, "days must be an integer",
                         "days");
        return;
    }
    const char *peer = input ? json_get_str(json_get(input, "peer")) : NULL;
    struct json_value commit_input;
    json_init(&commit_input);
    json_set_object(&commit_input);
    if (peer && peer[0])
        json_push_kv_str(&commit_input, "peer", peer);
    json_push_kv_str(&commit_input, "fingerprint", fingerprint);
    if (days_given)
        json_push_kv_int(&commit_input, "days", days);
    mesh_pair_bridge(request, &commit_input, "mesh_pairing_commit", true,
                     reply);
    json_free(&commit_input);
}

void zcl_native_handle_ops_mesh_pair_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(MESH_STATUS_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    struct json_value list_input;
    json_init(&list_input);
    json_set_object(&list_input);
    mesh_pair_bridge(request, &list_input, "mesh_pairing_list", false, reply);
    json_free(&list_input);
}

void zcl_native_handle_ops_mesh_pair_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(MESH_STATUS_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const struct json_value *input =
        request->input && request->input->type == JSON_OBJ ? request->input
                                                           : NULL;
    const char *pairing_id =
        input ? json_get_str(json_get(input, "pairing_id")) : NULL;
    if (!pairing_id || strlen(pairing_id) != 64) {
        mesh_status_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, "MISSING_PAIRING_ID",
                         "normalize", false,
                         "pairing_id (64 lowercase hex) is required",
                         "pairing_id");
        return;
    }
    struct json_value revoke_input;
    json_init(&revoke_input);
    json_set_object(&revoke_input);
    json_push_kv_str(&revoke_input, "pairing_id", pairing_id);
    mesh_pair_bridge(request, &revoke_input, "mesh_pairing_revoke", true,
                     reply);
    json_free(&revoke_input);
}
