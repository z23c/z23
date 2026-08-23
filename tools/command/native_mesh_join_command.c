/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ops.mesh.join / ops.mesh.join_status — the one-command mesh join.
 *
 * `join` takes an operator-provided rendezvous endpoint (a v3 onion
 * host:port), refuses by name on every unmet prerequisite, and delegates
 * the dial itself to core.network.peers.add so there is exactly one
 * addnode path in the tree. Success means "dial requested", never
 * "handshake complete" — the same honest contract as peers.add.
 *
 * `join_status` answers the only question an operator has after a join:
 * did the peer land? It reads getconnectioncount/getpeerinfo through the
 * same RPC client, counts onion peers (optionally filtered by endpoint
 * host), and reports a boolean verdict with no invented fields.
 *
 * Nothing here opens sockets or touches consensus; every failure names
 * its phase and remedy. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NJ_TAG "native.ops.mesh"
#define NJ_ONION_HOST_LEN 56

/* Same link-time fact shop_native_probes.c reads: resolves NULL against
 * libtor_stub.a, non-NULL against the real vendored Tor. */
extern int dynhost_client_fetch(const char *, uint16_t, const char *,
    void (*)(int, const uint8_t *, size_t, void *), void *, int)
    __attribute__((weak));

static bool nj_tor_real_build_linked(void)
{
    return dynhost_client_fetch != NULL;
}

#define NJ_REMEDY_TOR \
    "rebuild with the real vendored Tor: make tor-full && make -j\"$(nproc)\""
#define NJ_REMEDY_NODE \
    "boot the node with -listen -tor -onion-persist before joining"

static void nj_fail(struct zcl_command_reply *reply,
                    enum zcl_command_status status,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *phase, bool retryable,
                    const char *message, const char *evidence)
{
    LOG_ERROR(NJ_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           false, message, evidence ? evidence : "");
}

/* A v3 onion endpoint: 56-char base32 label + ".onion", numeric port
 * 1..65535. The hostname check is structural — decode lives in net/. */
static bool nj_endpoint_valid(const char *endpoint,
                              char host[NJ_ONION_HOST_LEN + 1], int *port)
{
    if (!endpoint || !endpoint[0] || !port)
        return false;
    const size_t len = strlen(endpoint);
    if (len < NJ_ONION_HOST_LEN + 7 || len > 128)
        return false;
    char buf[129];
    memcpy(buf, endpoint, len + 1);
    char *colon = strrchr(buf, ':');
    if (!colon || colon == buf || !colon[1])
        return false;
    char *end = NULL;
    const long p = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || p < 1 || p > 65535)
        return false;
    *colon = '\0';
    if (strlen(buf) != NJ_ONION_HOST_LEN + 6
        || strcmp(buf + NJ_ONION_HOST_LEN, ".onion") != 0)
        return false;
    for (size_t i = 0; i < NJ_ONION_HOST_LEN; i++) {
        const char c = buf[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok)
            return false;
    }
    buf[NJ_ONION_HOST_LEN] = '\0';
    memcpy(host, buf, NJ_ONION_HOST_LEN + 1);
    *port = (int)p;
    return true;
}

/* The running node answers a cheap read. */
static bool nj_node_reachable(void)
{
    char *raw = node_rpc_call("getblockcount", NULL);
    if (!raw)
        return false;
    free(raw);
    return true;
}

void zcl_native_handle_mesh_join(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(NJ_TAG, "INVALID_REQUEST: request or reply is null");
        return;
    }

    const char *endpoint = request->input
        ? json_get_str(json_get(request->input, "endpoint")) : NULL;
    char host[NJ_ONION_HOST_LEN + 1];
    int port = 0;
    const bool endpoint_ok = nj_endpoint_valid(endpoint, host, &port);

    if (!json_get_bool_or(request->input, "confirm", false)) {
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        struct json_value checks;
        json_init(&checks);
        json_set_array(&checks);
        static const struct {
            const char *name;
            const char *remedy;
        } checks_table[] = {
            { "tor_real_build", NJ_REMEDY_TOR },
            { "endpoint_valid",
              "pass --input='{\"endpoint\":\"<56-char v3 onion>:<port>\"}' "
              "of the peer to join" },
            { "node_running", NJ_REMEDY_NODE },
        };
        const bool ready[sizeof(checks_table) / sizeof(checks_table[0])] = {
            nj_tor_real_build_linked(),
            endpoint_ok,
            nj_node_reachable(),
        };
        for (size_t i = 0; i < sizeof(checks_table) / sizeof(checks_table[0]);
             i++) {
            struct json_value item;
            json_init(&item);
            json_set_object(&item);
            (void)json_push_kv_str(&item, "check", checks_table[i].name);
            (void)json_push_kv_bool(&item, "ready", ready[i]);
            if (!ready[i])
                (void)json_push_kv_str(&item, "remedy",
                                       checks_table[i].remedy);
            (void)json_push_back(&checks, &item);
            json_free(&item);
        }
        (void)json_push_kv(&reply->data, "checks", &checks);
        json_free(&checks);
        (void)json_push_kv_str(
            &reply->data, "commit_input",
            "{\"confirm\":true,\"endpoint\":\"<host>.onion:<port>\"}");
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
        return;
    }

    /* Cheapest, most specific refusals first: a malformed endpoint is
     * named as itself no matter which Tor build or node state follows. */
    if (!endpoint_ok) {
        nj_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_TORV3_ENDPOINT", "normalize", false,
                "endpoint must be a 56-char v3 .onion host plus port "
                "(<host>.onion:<port>)",
                endpoint ? endpoint : "(missing)");
        return;
    }
    if (!nj_tor_real_build_linked()) {
        nj_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "TOR_STUB_BUILD", "prereq", false,
                "this binary links the Tor stub; outbound onion dials cannot "
                "leave localhost",
                NJ_REMEDY_TOR);
        return;
    }
    if (!nj_node_reachable()) {
        nj_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "NODE_UNREACHABLE", "dispatch", true,
                "no running node answered getblockcount on this datadir",
                NJ_REMEDY_NODE);
        return;
    }

    /* One addnode path: delegate to the typed peers.add binding instead of
     * building a second RPC caller. Its named failures are forwarded as-is;
     * its success already carries schema/address/status/transport keys. */
    struct zcl_command_request sub;
    memset(&sub, 0, sizeof(sub));
    struct json_value sub_in;
    json_init(&sub_in);
    json_set_object(&sub_in);
    (void)json_push_kv_str(&sub_in, "address", endpoint);
    sub.input = &sub_in;
    zcl_native_handle_network_peer_add(&sub, reply);
    json_free(&sub_in);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED)
        return;

    (void)json_push_kv_str(&reply->data, "join",
                           "dial_requested — poll with ops.mesh.join_status");
    reply->error.mutated = true;
}

void zcl_native_handle_mesh_join_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) {
        LOG_ERROR(NJ_TAG, "INVALID_REQUEST: request or reply is null");
        return;
    }
    const char *filter = request->input
        ? json_get_str(json_get(request->input, "endpoint")) : NULL;
    char host[NJ_ONION_HOST_LEN + 1];
    int port = 0;
    const bool filtered = filter && filter[0];
    if (filtered && !nj_endpoint_valid(filter, host, &port)) {
        nj_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_TORV3_ENDPOINT", "normalize", false,
                "filter must be a 56-char v3 .onion host plus port",
                filter);
        return;
    }

    char *cc_raw = node_rpc_call("getconnectioncount", NULL);
    if (!cc_raw) {
        nj_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNREACHABLE", "dispatch",
                true, "no running node answered getconnectioncount",
                NJ_REMEDY_NODE);
        return;
    }
    struct json_value cc;
    json_init(&cc);
    int64_t connections = -1;
    if (!json_read(&cc, cc_raw, strlen(cc_raw))) {
        json_free(&cc);
        free(cc_raw);
        nj_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                false, "getconnectioncount returned an unparseable body",
                "-");
        return;
    }
    /* The RPC client may return the bare result or the JSON-RPC envelope;
     * accept either shape, like the addnode success decoder does. */
    if (cc.type == JSON_INT) {
        connections = cc.val.i;
    } else {
        const struct json_value *r = json_get(&cc, "result");
        if (r && r->type == JSON_INT)
            connections = r->val.i;
    }
    json_free(&cc);
    free(cc_raw);

    char *pi_raw = node_rpc_call("getpeerinfo", NULL);
    if (!pi_raw) {
        nj_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNREACHABLE", "dispatch",
                true, "no running node answered getpeerinfo",
                NJ_REMEDY_NODE);
        return;
    }
    struct json_value pi;
    json_init(&pi);
    if (!json_read(&pi, pi_raw, strlen(pi_raw))) {
        free(pi_raw);
        json_free(&pi);
        nj_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY", "serialize",
                false, "getpeerinfo returned an unparseable body", "-");
        return;
    }
    free(pi_raw);

    long onion_peers = 0;
    bool peered_host = false;
    struct json_value peers_out;
    json_init(&peers_out);
    json_set_array(&peers_out);
    const struct json_value *result = json_get(&pi, "result");
    if (result && result->type == JSON_ARR) {
        for (size_t i = 0; i < json_size(result); i++) {
            const struct json_value *p = json_at(result, i);
            const char *addr = json_get_str(json_get(p, "addr"));
            if (!addr || !strstr(addr, ".onion"))
                continue;
            onion_peers++;
            const bool match = filtered && strstr(addr, host) != NULL;
            if (match)
                peered_host = true;
            if (!filtered || match) {
                struct json_value row;
                json_init(&row);
                json_set_object(&row);
                (void)json_push_kv_str(&row, "addr", addr);
                (void)json_push_kv_bool(
                    &row, "inbound",
                    json_get_bool_or(p, "inbound", false));
                (void)json_push_back(&peers_out, &row);
                json_free(&row);
            }
        }
    }
    json_free(&pi);

    /* The verdict derives only from observed rows: unfiltered, any onion
     * peer counts; filtered, only the requested host. */
    const bool peered = filtered ? peered_host : onion_peers > 0;

    (void)json_push_kv_str(&reply->data, "schema", "zcl.mesh_join_status.v1");
    if (filtered)
        (void)json_push_kv_str(&reply->data, "endpoint", filter);
    (void)json_push_kv_int(&reply->data, "connections", connections);
    (void)json_push_kv_int(&reply->data, "onion_peers", onion_peers);
    (void)json_push_kv_bool(&reply->data, "peered", peered);
    (void)json_push_kv(&reply->data, "onion_peer_rows", &peers_out);
    json_free(&peers_out);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
