/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native read-only machine-mesh status commands. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NATIVE_MESH_TAG "native.mesh"

static void mesh_fail(struct zcl_command_reply *reply,
                      enum zcl_command_status status,
                      enum zcl_command_exit exit_code, const char *code,
                      const char *phase, const char *detail,
                      const char *evidence)
{
    bool mutated = reply && reply->error.mutated;
    LOG_ERROR(NATIVE_MESH_TAG, "%s: %s", code, detail);
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           mutated, detail, evidence ? evidence : "");
}

static bool mesh_rpc_object(const char *method, const char *params,
                            struct json_value *out,
                            struct zcl_command_reply *reply)
{
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(method, params);
    if (!raw) {
        mesh_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                  ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                  "the node did not answer the pairing request", method);
        return false;
    }
    bool parsed = json_read(out, raw, strlen(raw));
    free(raw);
    const struct json_value *ok = parsed && out->type == JSON_OBJ
                                      ? json_get(out, "ok") : NULL;
    if (!parsed || out->type != JSON_OBJ ||
        (ok && ok->type == JSON_BOOL && !json_get_bool(ok))) {
        const char *message = parsed && out->type == JSON_OBJ
                                  ? json_get_str(json_get(out, "message"))
                                  : NULL;
        char detail[224];
        snprintf(detail, sizeof(detail), "%s",
                 message && message[0] ? message
                                       : "pairing request returned an invalid body");
        json_free(out);
        mesh_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                  parsed ? ZCL_COMMAND_EXIT_INVALID : ZCL_COMMAND_EXIT_INTERNAL,
                  parsed ? "PAIRING_REFUSED" : "BAD_RPC_BODY", "execute",
                  detail, method);
        return false;
    }
    return true;
}

static void mesh_copy_fields(struct json_value *out,
                             const struct json_value *body,
                             const char *const *fields, size_t count)
{
    json_set_object(out);
    for (size_t i = 0; i < count; i++) {
        const struct json_value *value = json_get(body, fields[i]);
        if (value)
            (void)json_push_kv(out, fields[i], value);
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

void zcl_native_handle_ops_mesh_pair_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(NATIVE_MESH_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    struct json_value body = {0};
    if (!mesh_rpc_object("mesh_pairing_list", "[]", &body, reply))
        return;
    static const char *const fields[] = {
        "schema", "observed_at", "total", "active", "expired", "revoked",
        "truncated", "pairings",
    };
    mesh_copy_fields(&reply->data, &body, fields,
                     sizeof(fields) / sizeof(fields[0]));
    json_free(&body);
}

void zcl_native_handle_ops_mesh_pair_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(NATIVE_MESH_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const char *pairing_id = request->input
        ? json_get_str(json_get(request->input, "pairing_id")) : NULL;
    const char *confirm = request->input
        ? json_get_str(json_get(request->input, "confirm")) : NULL;
    if (!pairing_id || strlen(pairing_id) != 64) {
        mesh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                  "PAIRING_ID_REQUIRED", "normalize",
                  "pairing_id must be exactly 64 lowercase hexadecimal characters",
                  "pairing_id");
        return;
    }

    struct json_value input = {0};
    json_set_object(&input);
    (void)json_push_kv_str(&input, "pairing_id", pairing_id);
    if (confirm && confirm[0])
        (void)json_push_kv_str(&input, "confirm", confirm);
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, &input);
    json_free(&input);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        mesh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                  "ARG_BUILD_FAILED", "normalize",
                  "could not encode the pairing revocation request",
                  "pairing_id");
        return;
    }

    bool committing = confirm && confirm[0];
    struct json_value body = {0};
    bool called = mesh_rpc_object(committing ? "mesh_pairing_revoke_commit"
                                              : "mesh_pairing_revoke_plan",
                                  params, &body, reply);
    free(params);
    if (!called)
        return;
    static const char *const fields[] = {
        "schema", "status", "pairing_id", "state", "expires_at",
        "revoked_at", "revocation_generation", "confirmation",
        "idempotent_replay",
    };
    mesh_copy_fields(&reply->data, &body, fields,
                     sizeof(fields) / sizeof(fields[0]));
    if (!committing) {
        const char *token = json_get_str(json_get(&body, "confirmation"));
        struct json_value commit = {0};
        json_set_object(&commit);
        (void)json_push_kv_str(&commit, "pairing_id", pairing_id);
        (void)json_push_kv_str(&commit, "confirm", token ? token : "");
        char encoded[384];
        size_t wrote = json_write(&commit, encoded, sizeof(encoded));
        json_free(&commit);
        if (wrote >= sizeof(encoded))
            encoded[0] = '\0';
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        (void)json_push_kv_bool(&reply->data, "committed", false);
        (void)json_push_kv_str(&reply->data, "commit_input", encoded);
    } else {
        const struct json_value *replayed =
            json_get(&body, "idempotent_replay");
        reply->error.mutated = !(replayed && replayed->type == JSON_BOOL &&
                                 json_get_bool(replayed));
        (void)json_push_kv_str(&reply->data, "stage", "commit");
        (void)json_push_kv_bool(&reply->data, "committed", true);
    }
    json_free(&body);
}
