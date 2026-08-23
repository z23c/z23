/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native zses:v1 invite create/accept and ops.mesh.join. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "keys/key.h"
#include "session/zses.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ZSES_TAG "native.zses"

static void zses_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail, const char *field)
{
    bool mutated = reply && reply->error.mutated;
    LOG_ERROR(ZSES_TAG, "%s: %s", code, detail);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           mutated, detail, field ? field : "");
}

static const char *zses_input_str(const struct json_value *input,
                                  const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool zses_read_onion(const char *datadir, char *out, size_t cap)
{
    if (!datadir || !datadir[0] || !out || cap < 8)
        return false;
    char path[512];
    int n = snprintf(path, sizeof(path),
                     "%s/tor_data/onion_service/hostname", datadir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    if (!fgets(out, (int)cap, f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r')) {
        out[--len] = '\0';
    }
    return zses_looks_onion(out);
}

void zcl_native_handle_zses_invite_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(ZSES_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const char *endpoint_in = zses_input_str(request->input, "endpoint");
    const char *posture = zses_input_str(request->input, "posture");
    const char *tag = zses_input_str(request->input, "capability_tag");
    if (!tag)
        tag = zses_input_str(request->input, "capability-tag");
    const char *port_s = zses_input_str(request->input, "port");
    const struct json_value *exp_v =
        request->input ? json_get(request->input, "expires") : NULL;
    int64_t expires = exp_v ? json_get_int(exp_v) : 0;
    if (expires <= 0)
        expires = (int64_t)time(NULL) + 3600;

    char picked[ZSES_ENDPOINT_MAX + 1];
    enum zses_refuse refuse = ZSES_OK;
    if (endpoint_in && endpoint_in[0]) {
        const char *p = (posture && posture[0]) ? posture : "onion";
        if (zses_looks_clearnet(endpoint_in) && strcmp(p, "clearnet") != 0) {
            zses_fail(reply, "CLEARNET_FORBIDDEN",
                      "numeric endpoint refused unless posture=clearnet",
                      "endpoint");
            return;
        }
        if (strlen(endpoint_in) > ZSES_ENDPOINT_MAX) {
            zses_fail(reply, "BAD_ENDPOINT", "endpoint too long", "endpoint");
            return;
        }
        memcpy(picked, endpoint_in, strlen(endpoint_in) + 1);
    } else {
        zcl_native_bridge_ensure_rpc();
        char onion[ZSES_ENDPOINT_MAX + 1];
        onion[0] = '\0';
        const char *dd = node_rpc_client_datadir();
        if (zses_read_onion(dd, onion, sizeof(onion))) {
            const char *port = (port_s && port_s[0]) ? port_s : "8055";
            char onion_ep[ZSES_ENDPOINT_MAX + 1];
            (void)snprintf(onion_ep, sizeof(onion_ep), "%s:%s", onion, port);
            if (!zses_pick_endpoint(posture, onion_ep, NULL, picked,
                                    sizeof(picked), &refuse)) {
                zses_fail(reply, "NO_ONION_ENDPOINT",
                          zses_refuse_name(refuse), "endpoint");
                return;
            }
        } else {
            zses_fail(reply, "NO_ONION_ENDPOINT",
                      "no onion hostname and no endpoint supplied",
                      "endpoint");
            return;
        }
    }

    struct zses_invite inv;
    memset(&inv, 0, sizeof(inv));
    memcpy(inv.endpoint, picked, strlen(picked) + 1);
    inv.expires = expires;
    if (tag && tag[0] && strlen(tag) <= ZSES_TAG_MAX)
        memcpy(inv.capability_tag, tag, strlen(tag) + 1);
    else
        memcpy(inv.capability_tag, "session", 8);

    struct privkey k;
    privkey_make_new(&k, true);
    if (!zses_invite_sign(&inv, &k)) {
        zses_fail(reply, "SIGN_FAILED", "secp256k1 compact sign failed",
                  "signature");
        return;
    }
    char invite_json[ZSES_JSON_MAX];
    if (!zses_invite_encode_json(&inv, invite_json, sizeof(invite_json))) {
        zses_fail(reply, "ENCODE_FAILED", "could not encode invite JSON",
                  "invite");
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.zses_invite.v1");
    (void)json_push_kv_str(&reply->data, "invite", invite_json);
    (void)json_push_kv_str(&reply->data, "endpoint", inv.endpoint);
    (void)json_push_kv_int(&reply->data, "expires", inv.expires);
    (void)json_push_kv_str(&reply->data, "capability_tag", inv.capability_tag);
    (void)json_push_kv_str(&reply->data, "posture",
                           (posture && posture[0]) ? posture : "onion");
}

void zcl_native_handle_zses_invite_accept(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(ZSES_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    char invite_buf[ZSES_JSON_MAX];
    const char *invite = zses_input_str(request->input, "invite");
    if ((!invite || !invite[0]) && request->input) {
        const struct json_value *inv_v = json_get(request->input, "invite");
        if (inv_v && inv_v->type == JSON_OBJ) {
            size_t n = json_write(inv_v, invite_buf, sizeof(invite_buf));
            if (n > 0 && n < sizeof(invite_buf))
                invite = invite_buf;
        }
    }
    if (!invite || !invite[0]) {
        zses_fail(reply, "MISSING_INVITE", "invite JSON is required", "invite");
        return;
    }
    const struct json_value *now_v =
        request->input ? json_get(request->input, "now") : NULL;
    int64_t now = now_v ? json_get_int(now_v) : (int64_t)time(NULL);
    struct zses_invite inv;
    if (!zses_invite_decode_json(invite, &inv)) {
        zses_fail(reply, "malformed", "invite is not valid zses:v1 JSON",
                  "invite");
        return;
    }
    enum zses_refuse r = zses_invite_verify(&inv, now);
    if (r != ZSES_OK) {
        zses_fail(reply, zses_refuse_name(r),
                  "invite verify refused", "invite");
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.zses_invite_accept.v1");
    (void)json_push_kv_str(&reply->data, "endpoint", inv.endpoint);
    (void)json_push_kv_int(&reply->data, "expires", inv.expires);
    (void)json_push_kv_str(&reply->data, "capability_tag", inv.capability_tag);
    (void)json_push_kv_bool(&reply->data, "accepted", true);
}

static const char *mesh_join_endpoint(const struct json_value *input)
{
    const char *ep = zses_input_str(input, "endpoint");
    if (ep && ep[0])
        return ep;
    return zses_input_str(input, "address");
}

static bool mesh_peer_is_peered(const struct json_value *peer)
{
    if (!peer || peer->type != JSON_OBJ)
        return false;
    const char *state = json_get_str(json_get(peer, "state"));
    const char *subver = json_get_str(json_get(peer, "subver"));
    int64_t version = json_get_int(json_get(peer, "version"));
    if (version > 0 && subver && subver[0])
        return true;
    if (state && (strcmp(state, "active") == 0 ||
                  strcmp(state, "handshake_complete") == 0 ||
                  strcmp(state, "syncing_headers") == 0 ||
                  strcmp(state, "syncing_blocks") == 0))
        return true;
    return false;
}

static bool mesh_fill_join_status(const char *endpoint,
                                  struct json_value *out)
{
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("getpeerinfo", "[]");
    if (!raw) {
        LOG_ERROR(ZSES_TAG, "join_status: getpeerinfo returned no body");
        return false;
    }
    struct json_value peers;
    json_init(&peers);
    if (!json_read(&peers, raw, strlen(raw))) {
        LOG_ERROR(ZSES_TAG, "join_status: getpeerinfo body is not JSON");
        free(raw);
        json_free(&peers);
        return false;
    }
    free(raw);
    const struct json_value *arr = &peers;
    if (peers.type == JSON_OBJ) {
        const struct json_value *result = json_get(&peers, "result");
        if (result)
            arr = result;
    }
    bool peered = false;
    const char *state = "";
    if (arr->type == JSON_ARR) {
        size_t n = json_size(arr);
        for (size_t i = 0; i < n; i++) {
            const struct json_value *p = json_at(arr, i);
            const char *addr = json_get_str(json_get(p, "addr"));
            if (!addr)
                continue;
            if (endpoint && endpoint[0] && strstr(addr, endpoint) == NULL &&
                strstr(endpoint, addr) == NULL)
                continue;
            state = json_get_str(json_get(p, "state"));
            if (!state)
                state = "";
            if (mesh_peer_is_peered(p)) {
                peered = true;
                break;
            }
        }
    }
    (void)json_push_kv_str(out, "schema", "zcl.ops_mesh_join_status.v1");
    (void)json_push_kv_bool(out, "peered", peered);
    (void)json_push_kv_str(out, "endpoint", endpoint ? endpoint : "");
    (void)json_push_kv_str(out, "state", state);
    json_free(&peers);
    return true;
}

void zcl_native_handle_ops_mesh_join(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(ZSES_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const char *endpoint = mesh_join_endpoint(request->input);
    if (!endpoint || !endpoint[0]) {
        zses_fail(reply, "MISSING_ENDPOINT", "endpoint is required",
                  "endpoint");
        return;
    }
    struct rpc_arg_builder params;
    rpc_arg_builder_init(&params);
    rpc_arg_builder_push_str(&params, endpoint);
    rpc_arg_builder_push_str(&params, "add");
    char *params_json = rpc_arg_builder_to_json(&params);
    if (!params_json) {
        zses_fail(reply, "ARG_BUILD_FAILED", "could not encode addnode",
                  "endpoint");
        return;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("addnode", params_json);
    free(params_json);
    if (!raw) {
        zses_fail(reply, "NODE_UNAVAILABLE", "the node did not answer addnode",
                  "endpoint");
        return;
    }
    free(raw);

    json_set_object(&reply->data);
    reply->error.mutated = true;
    int tries;
    for (tries = 0; tries < 80; tries++) {
        struct json_value tmp;
        json_init(&tmp);
        json_set_object(&tmp);
        if (mesh_fill_join_status(endpoint, &tmp) &&
            json_get_bool(json_get(&tmp, "peered"))) {
            json_free(&reply->data);
            reply->data = tmp;
            return;
        }
        json_free(&tmp);
        struct timespec wait = { .tv_sec = 0, .tv_nsec = 250000000L };
        (void)nanosleep(&wait, NULL);
    }
    (void)mesh_fill_join_status(endpoint, &reply->data);
}

void zcl_native_handle_ops_mesh_join_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(ZSES_TAG, "INVALID_REQUEST: null request or reply");
        return;
    }
    const char *endpoint = mesh_join_endpoint(request->input);
    json_set_object(&reply->data);
    if (!mesh_fill_join_status(endpoint ? endpoint : "", &reply->data)) {
        zses_fail(reply, "PEERINFO_FAILED", "getpeerinfo failed", "endpoint");
    }
}
