/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: typed operator binding for an explicit outbound P2P edge. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NNP_TAG "native.network.peer"

static void nnp_fail(struct zcl_command_reply *reply,
                     enum zcl_command_status status,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *phase, bool retryable, bool mutated,
                     const char *message, const char *evidence)
{
    LOG_ERROR(NNP_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           mutated, message, evidence ? evidence : "");
}

static const char *nnp_rpc_error(const struct json_value *body)
{
    if (!body)
        return "missing response body";
    if (body->type == JSON_STR)
        return json_get_str(body);
    if (body->type != JSON_OBJ)
        return NULL;
    const struct json_value *error = json_get(body, "error");
    if (error && !json_is_null(error)) {
        if (error->type == JSON_STR)
            return json_get_str(error);
        if (error->type == JSON_OBJ)
            return json_get_str(json_get(error, "message"));
        return "node returned an unstructured RPC error";
    }
    const struct json_value *code = json_get(body, "code");
    const struct json_value *message = json_get(body, "message");
    if (code && code->type == JSON_INT && message && message->type == JSON_STR)
        return json_get_str(message);
    return NULL;
}

/* addnode success is JSON null: either the unwrapped result, or a JSON-RPC
 * envelope whose result is null and whose error is absent/null. A non-null
 * result is not a success for this method. */
static bool nnp_addnode_success(const struct json_value *body)
{
    if (!body)
        return false;
    if (body->type == JSON_NULL)
        return true;
    if (body->type != JSON_OBJ)
        return false;
    const struct json_value *result = json_get(body, "result");
    return result && json_is_null(result);
}

static bool nnp_is_onion_endpoint(const char *address)
{
    if (!address)
        return false;
    const char *suffix = strstr(address, ".onion");
    return suffix && (suffix[6] == '\0' || suffix[6] == ':');
}

void zcl_native_handle_network_peer_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(NNP_TAG, "INVALID_REQUEST: request or reply is null");
        return;
    }
    const char *address = request->input
        ? json_get_str(json_get(request->input, "address")) : NULL;
    if (!address || !address[0]) {
        nnp_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                 "MISSING_ADDRESS", "normalize", false, false,
                 "address is required as a numeric ip:port or v3 onion endpoint",
                 "address");
        return;
    }
    bool onion_endpoint = nnp_is_onion_endpoint(address);

    struct rpc_arg_builder params;
    rpc_arg_builder_init(&params);
    rpc_arg_builder_push_str(&params, address);
    rpc_arg_builder_push_str(&params, "add");
    char *params_json = rpc_arg_builder_to_json(&params);
    if (!params_json) {
        nnp_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED", "normalize",
                 false, false, "could not encode addnode parameters", address);
        return;
    }

    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("addnode", params_json);
    free(params_json);
    if (!raw) {
        nnp_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                 ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE", "dispatch",
                 true, false, "the node did not answer addnode", address);
        return;
    }

    struct json_value body;
    json_init(&body);
    bool parsed = json_read(&body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&body);
        nnp_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                 false, true,
                 "addnode returned an unparseable body after dispatch",
                 address);
        return;
    }
    const char *rpc_error = nnp_rpc_error(&body);
    if (rpc_error) {
        char message[256];
        (void)snprintf(message, sizeof(message), "%s",
                       rpc_error[0] ? rpc_error : "addnode refused the peer");
        json_free(&body);
        nnp_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                 "PEER_ADD_REFUSED", "execute", false, false, message,
                 address);
        return;
    }
    if (!nnp_addnode_success(&body)) {
        json_free(&body);
        nnp_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                 ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                 false, true,
                 "addnode returned a non-null success body after dispatch",
                 address);
        return;
    }
    json_free(&body);

    (void)json_push_kv_str(&reply->data, "schema", "zcl.peer_add.v1");
    (void)json_push_kv_str(&reply->data, "address", address);
    (void)json_push_kv_str(&reply->data, "status", "dial_requested");
    (void)json_push_kv_str(&reply->data, "transport",
                           onion_endpoint ? "tor+p2p_tcp" : "p2p_tcp");
    (void)json_push_kv_str(&reply->data, "rendezvous",
                           onion_endpoint ? "direct_onion_p2p"
                                          : "operator_numeric_endpoint");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
}
