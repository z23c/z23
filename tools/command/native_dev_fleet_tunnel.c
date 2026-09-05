/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The operator's five `z23 dev fleet tunnel` leaves. Each is a
 * bounded envelope over one node RPC: the listeners, the loopback dial and
 * the allow table all live in the node (engine/composition/src/
 * mesh_tunnel.c), and nothing here decides anything the node has not
 * already decided. A refusal arrives as the tunnel's own named token and
 * is surfaced unchanged, so the operator reads the same word the code
 * used. */

#include "command/native_dev_fleet.h"
#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TUN_LEAF_TAG "native.dev_fleet_tunnel"

/* Every refusal the node can name, and the one sentence each means to the
 * operator. An unknown token is still surfaced, never swallowed. */
static const char *tunnel_refusal_help(const char *refusal)
{
    if (!refusal)
        return "the node refused the tunnel request";
    if (strcmp(refusal, "tunnel_target_not_allowed") == 0)
        return "the far machine has no allow row for this port and this "
               "peer; run `dev fleet tunnel allow` there";
    if (strcmp(refusal, "tunnel_peer_unpaired") == 0)
        return "no live pairing row names that peer; pair the machines first";
    if (strcmp(refusal, "tunnel_local_bind_failed") == 0)
        return "the local port could not be bound on 127.0.0.1";
    if (strcmp(refusal, "tunnel_cap") == 0)
        return "this node already holds all the tunnels it will hold at once";
    if (strcmp(refusal, "tunnel_dial_failed") == 0)
        return "the far machine allowed the port and nothing was listening "
               "on its loopback there";
    if (strcmp(refusal, "tunnel_no_such_tunnel") == 0)
        return "no tunnel with that id is open on this node";
    if (strcmp(refusal, "tunnel_malformed") == 0)
        return "the request named no peer, or a port outside 1..65535";
    return "the node refused the tunnel request";
}

static void tunnel_fail(struct zcl_command_reply *reply, const char *code,
                        const char *phase, const char *message,
                        const char *evidence)
{
    LOG_ERROR(TUN_LEAF_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false, false,
                           message, evidence);
}

/* One bounded node call. `arguments` is moved into the params array; `body`
 * receives the parsed reply and belongs to the caller. */
static bool tunnel_rpc(struct json_value *arguments, const char *method,
                       struct json_value *body,
                       struct zcl_command_reply *reply)
{
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, arguments);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        tunnel_fail(reply, "ARG_BUILD_FAILED", "normalize",
                    "could not encode the tunnel request", method);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(method, params);
    free(params);
    if (!raw) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the running node answered no tunnel request",
                               method);
        return false;
    }
    json_init(body);
    bool parsed = json_read(body, raw, strlen(raw));
    free(raw);
    if (!parsed || body->type != JSON_OBJ) {
        json_free(body);
        tunnel_fail(reply, "BAD_RPC_BODY", "serialize",
                    "the tunnel RPC returned an unreadable body", method);
        return false;
    }
    return true;
}

/* The node answered. `ok` true means the body IS the answer; otherwise the
 * body names the refusal and the leaf fails with that exact token. */
static void tunnel_finish(struct json_value *body,
                          struct zcl_command_reply *reply, const char *method)
{
    const struct json_value *ok = json_get(body, "ok");
    if (ok && ok->type == JSON_BOOL && json_get_bool(ok)) {
        json_copy(&reply->data, body);
        json_free(body);
        return;
    }
    const char *refusal = json_get_str(json_get(body, "refusal"));
    char code[64];
    snprintf(code, sizeof(code), "%s",
             refusal && refusal[0] ? refusal : "TUNNEL_REFUSED");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           false, tunnel_refusal_help(refusal), method);
    json_copy(&reply->data, body);
    json_free(body);
}

static const struct json_value *tunnel_leaf_input(
    const struct zcl_command_request *request)
{
    return request && request->input && request->input->type == JSON_OBJ
               ? request->input
               : NULL;
}

/* A 64-hex peer id, or nothing. The node re-checks it; the leaf checks it
 * too so a typo never costs a round trip. */
static const char *tunnel_hex64(const char *peer)
{
    return peer && strlen(peer) == 64 ? peer : NULL;
}

static int64_t tunnel_int(const struct json_value *object, const char *key,
                          int64_t missing)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : missing;
}

static void tunnel_invalid(struct zcl_command_reply *reply, const char *code,
                           const char *message, const char *evidence)
{
    LOG_ERROR(TUN_LEAF_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, message, evidence);
}

void zcl_native_handle_dev_fleet_tunnel_open(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *input = tunnel_leaf_input(request);
    const char *peer = tunnel_hex64(json_get_str(json_get(input, "peer")));
    int64_t remote = tunnel_int(input, "remote_port", -1);
    int64_t local = tunnel_int(input, "local_port", 0);
    if (!peer) {
        tunnel_invalid(reply, "MISSING_PEER",
                       "peer (64 lowercase hex) is required", "peer");
        return;
    }
    if (remote < 1 || remote > 65535 || local < 0 || local > 65535) {
        tunnel_invalid(reply, "INVALID_PORT",
                       "remote_port is 1..65535 and local_port is 0..65535",
                       "remote_port");
        return;
    }
    struct json_value args, body;
    json_init(&args);
    json_set_object(&args);
    json_push_kv_str(&args, "peer", peer);
    json_push_kv_int(&args, "remote_port", remote);
    json_push_kv_int(&args, "local_port", local);
    if (tunnel_rpc(&args, "mesh_tunnel_open", &body, reply))
        tunnel_finish(&body, reply, "mesh_tunnel_open");
    json_free(&args);
}

void zcl_native_handle_dev_fleet_tunnel_close(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *input = tunnel_leaf_input(request);
    int64_t id = tunnel_int(input, "tunnel_id", -1);
    if (id < 1) {
        tunnel_invalid(reply, "MISSING_TUNNEL_ID",
                       "tunnel_id is required and is a positive integer",
                       "tunnel_id");
        return;
    }
    struct json_value args, body;
    json_init(&args);
    json_set_object(&args);
    json_push_kv_int(&args, "tunnel_id", id);
    if (tunnel_rpc(&args, "mesh_tunnel_close", &body, reply))
        tunnel_finish(&body, reply, "mesh_tunnel_close");
    json_free(&args);
}

void zcl_native_handle_dev_fleet_tunnel_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value args, body;
    json_init(&args);
    json_set_object(&args);
    if (tunnel_rpc(&args, "mesh_tunnel_list", &body, reply))
        tunnel_finish(&body, reply, "mesh_tunnel_list");
    json_free(&args);
}

void zcl_native_handle_dev_fleet_tunnel_allow(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *input = tunnel_leaf_input(request);
    const char *peer = tunnel_hex64(json_get_str(json_get(input, "peer")));
    const char *why = json_get_str(json_get(input, "why"));
    int64_t port = tunnel_int(input, "port", -1);
    if (!peer) {
        tunnel_invalid(reply, "MISSING_PEER",
                       "peer (64 lowercase hex) is required", "peer");
        return;
    }
    if (port < 1 || port > 65535) {
        tunnel_invalid(reply, "INVALID_PORT", "port is 1..65535", "port");
        return;
    }
    struct json_value args, body;
    json_init(&args);
    json_set_object(&args);
    json_push_kv_str(&args, "peer", peer);
    json_push_kv_int(&args, "port", port);
    json_push_kv_str(&args, "why", why ? why : "");
    if (tunnel_rpc(&args, "mesh_tunnel_allow", &body, reply))
        tunnel_finish(&body, reply, "mesh_tunnel_allow");
    json_free(&args);
}

void zcl_native_handle_dev_fleet_tunnel_deny(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const struct json_value *input = tunnel_leaf_input(request);
    const char *peer = tunnel_hex64(json_get_str(json_get(input, "peer")));
    int64_t port = tunnel_int(input, "port", -1);
    if (!peer) {
        tunnel_invalid(reply, "MISSING_PEER",
                       "peer (64 lowercase hex) is required", "peer");
        return;
    }
    if (port < 1 || port > 65535) {
        tunnel_invalid(reply, "INVALID_PORT", "port is 1..65535", "port");
        return;
    }
    struct json_value args, body;
    json_init(&args);
    json_set_object(&args);
    json_push_kv_str(&args, "peer", peer);
    json_push_kv_int(&args, "port", port);
    if (tunnel_rpc(&args, "mesh_tunnel_deny", &body, reply))
        tunnel_finish(&body, reply, "mesh_tunnel_deny");
    json_free(&args);
}
