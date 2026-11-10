/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet bundle` leaves — hand one bounded file (a git bundle,
 *          1 B to 5 MiB) to another Z23 node over the package swarm instead
 *          of scp+ssh, so a contributor with no ssh can land a commit.
 *
 *   fleet bundle offer   put the file in this node's package store (pinned,
 *                        never evicting), announce it, and report the root,
 *                        the sha256 of the file bytes, the size and (when
 *                        known) this node's own onion name.
 *   fleet bundle fetch   ask the swarm for a root, wait a bounded time,
 *                        recompute the sha256, and only on a match create
 *                        --out (0600, never overwriting).
 *
 * WHERE IT RUNS. The store and the swarm engine are in the node, so the
 * one-shot CLI forwards each step over the node RPC (fleet_bundle_offer,
 * fleet_bundle_fetch) and the node runs the same handler against its
 * resident store. The fetch step is non-blocking in the node; the CLI polls
 * it until the file is written or the bounded wait ends. The bytes are never
 * executed here: `dev land receive --bundle=<out>` is the next, separate
 * step. The core is native_fleet_bundle.c. */

#include "command/native_command.h"
#include "command/native_fleet_bundle.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "config/boot_zcode_swarm.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "json/json.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "rpc/protocol.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FBC_TIMEOUT_DEFAULT_S 300
#define FBC_TIMEOUT_MAX_S 1800
#define FBC_POLL_MS 2000
#define FBC_BOUND_PEERS_MAX 4u
#define FBC_OFFER_CMD "fleet.bundle.offer"
#define FBC_FETCH_CMD "fleet.bundle.fetch"

static const char *fbc_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static void fbc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, bool retryable, bool mutated,
                     const char *command)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           retryable ? ZCL_COMMAND_EXIT_TRANSIENT
                                     : ZCL_COMMAND_EXIT_INVALID,
                           code, "execute", retryable, mutated, message,
                           command);
}

static void fbc_fail_outcome(struct zcl_command_reply *reply,
                             const struct zcl_fleet_bundle_outcome *o,
                             const char *command)
{
    fbc_fail(reply, o->code, o->message, o->retryable, o->mutated, command);
}

static void fbc_push_hex(struct json_value *obj, const char *key,
                         const uint8_t bytes[32])
{
    char hex[65];
    zcl_hex_encode(bytes, 32, hex);
    (void)json_push_kv_str(obj, key, hex);
}

/* ── forwarding to the node ──────────────────────────────────────── */

/* Call `method` on the node with `fwd` as its one input object. True when
 * the node answered ok; `data` then holds its data object (caller frees).
 * Every other outcome fills `reply` with the refusal. */
static bool fbc_forward(const char *method, const struct json_value *fwd,
                        struct zcl_command_reply *reply, struct json_value *data,
                        const char *command)
{
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, fwd);
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        fbc_fail(reply, "ARG_BUILD_FAILED", "could not encode the request",
                 false, false, command);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(method, params);
    free(params);
    struct json_value body;
    json_init(&body);
    bool parsed = raw && json_read(&body, raw, strlen(raw)) &&
                  body.type == JSON_OBJ && json_get(&body, "ok");
    free(raw);
    if (!parsed) {
        json_free(&body);
        fbc_fail(reply, "NODE_UNAVAILABLE",
                 "the node did not answer (is it running with "
                 "-packagehost=1?)", true, false, command);
        return false;
    }
    const struct json_value *d = json_get(&body, "data");
    if (json_get_bool_or(&body, "ok", false) && d && d->type == JSON_OBJ) {
        json_init(data);
        json_copy(data, d);
        json_free(&body);
        return true;
    }
    const char *code = json_get_str(json_get(&body, "code"));
    const char *message = json_get_str(json_get(&body, "message"));
    fbc_fail(reply, code && code[0] ? code : "NODE_REFUSED",
             message && message[0] ? message : "the node refused the step",
             json_get_bool_or(&body, "retryable", false),
             json_get_bool_or(&body, "mutated", false), command);
    json_free(&body);
    return false;
}

/* ── offer ───────────────────────────────────────────────────────── */

void zcl_native_handle_fleet_bundle_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *file = fbc_str(request->input, "file");
    if (!file || file[0] != '/') {
        fbc_fail(reply, "MISSING_FILE",
                 "file is required and must be an absolute path", false,
                 false, FBC_OFFER_CMD);
        return;
    }
    struct vcs_package_store *store = vcs_package_store_global();
    if (!store) {
        struct json_value fwd, data;
        json_init(&fwd);
        json_set_object(&fwd);
        (void)json_push_kv_str(&fwd, "file", file);
        bool ok = fbc_forward("fleet_bundle_offer", &fwd, reply, &data,
                              FBC_OFFER_CMD);
        json_free(&fwd);
        if (!ok)
            return;
        json_copy(&reply->data, &data);
        json_free(&data);
        return;
    }
    struct zcl_fleet_bundle_outcome o;
    if (zcl_fleet_bundle_offer(store, vcs_swarm_engine_global(), file, &o) !=
        ZCL_FLEET_BUNDLE_DONE) {
        fbc_fail_outcome(reply, &o, FBC_OFFER_CMD);
        return;
    }
    fbc_push_hex(&reply->data, "root", o.root);
    fbc_push_hex(&reply->data, "sha256", o.sha256);
    (void)json_push_kv_int(&reply->data, "size", (int64_t)o.size);
    (void)json_push_kv_int(&reply->data, "announced", (int64_t)o.announced);
    (void)json_push_kv_bool(&reply->data, "pinned", true);
}

/* ── fetch ───────────────────────────────────────────────────────── */

struct fbc_fetch_in {
    struct zcl_fleet_bundle_fetch_args args;
    const char *peer;
    int64_t timeout_s;
};

static bool fbc_parse_hex32(const struct json_value *input, const char *key,
                            uint8_t out[32])
{
    const char *hex = fbc_str(input, key);
    return hex && strlen(hex) == 64u && zcl_hex_decode_lower(hex, out, 32);
}

static bool fbc_parse_timeout(const struct json_value *input,
                              struct fbc_fetch_in *in)
{
    const struct json_value *t = json_get(input, "timeout_s");
    in->timeout_s = FBC_TIMEOUT_DEFAULT_S;
    if (!t)
        return true;
    if (t->type != JSON_INT || json_get_int(t) < 1 ||
        json_get_int(t) > FBC_TIMEOUT_MAX_S)
        return false;
    in->timeout_s = json_get_int(t);
    return true;
}

/* Validate every field before anything is contacted. */
static bool fbc_parse_fetch(const struct json_value *input,
                            struct zcl_command_reply *reply,
                            struct fbc_fetch_in *in)
{
    memset(in, 0, sizeof(*in));
    if (!fbc_parse_hex32(input, "root", in->args.root)) {
        fbc_fail(reply, "BAD_ROOT", "root must be 64 lowercase hex chars",
                 false, false, FBC_FETCH_CMD);
        return false;
    }
    if (!fbc_parse_hex32(input, "sha256", in->args.sha256)) {
        fbc_fail(reply, "BAD_SHA256",
                 "sha256 must be 64 lowercase hex chars", false, false,
                 FBC_FETCH_CMD);
        return false;
    }
    const struct json_value *size = json_get(input, "size");
    if (!size || size->type != JSON_INT || json_get_int(size) < 1 ||
        json_get_int(size) > (int64_t)VCS_BUNDLE_MAX_BYTES) {
        fbc_fail(reply, "BAD_SIZE", "size must be 1 to 5242880 bytes", false,
                 false, FBC_FETCH_CMD);
        return false;
    }
    in->args.size = (uint64_t)json_get_int(size);
    in->args.out_path = fbc_str(input, "out");
    if (!in->args.out_path || in->args.out_path[0] != '/') {
        fbc_fail(reply, "MISSING_OUT",
                 "out is required and must be an absolute path", false,
                 false, FBC_FETCH_CMD);
        return false;
    }
    in->peer = fbc_str(input, "peer");
    if (in->peer && !zcl_fleet_bundle_peer_is_onion(in->peer)) {
        fbc_fail(reply, "BAD_PEER",
                 "peer must be a v3 <56 chars>.onion name (an IP address or "
                 "clearnet host is refused)", false, false, FBC_FETCH_CMD);
        return false;
    }
    if (!fbc_parse_timeout(input, in)) {
        fbc_fail(reply, "BAD_TIMEOUT", "timeout_s must be 1 to 1800", false,
                 false, FBC_FETCH_CMD);
        return false;
    }
    return true;
}

static void fbc_render_step(struct zcl_command_reply *reply,
                            const struct zcl_fleet_bundle_fetch_args *a,
                            const struct zcl_fleet_bundle_outcome *o)
{
    bool done = o->status == ZCL_FLEET_BUNDLE_DONE;
    (void)json_push_kv_str(&reply->data, "state",
                           done ? "complete" : "pending");
    fbc_push_hex(&reply->data, "root", a->root);
    if (done) {
        (void)json_push_kv_str(&reply->data, "path", a->out_path);
        fbc_push_hex(&reply->data, "sha256", o->sha256);
        (void)json_push_kv_int(&reply->data, "size", (int64_t)o->size);
        return;
    }
    (void)json_push_kv_int(&reply->data, "present_chunks",
                           (int64_t)o->present_chunks);
    (void)json_push_kv_int(&reply->data, "total_chunks",
                           (int64_t)o->total_chunks);
}

/* Add the onion peer through the node's addnode RPC (the same call
 * `network peer add` makes). */
static bool fbc_add_peer(const char *peer, struct zcl_command_reply *reply)
{
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_str(&args, peer);
    rpc_arg_builder_push_str(&args, "add");
    char *params = rpc_arg_builder_to_json(&args);
    if (!params) {
        fbc_fail(reply, "ARG_BUILD_FAILED", "could not encode addnode",
                 false, false, FBC_FETCH_CMD);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("addnode", params);
    free(params);
    struct json_value body;
    json_init(&body);
    bool parsed = raw && json_read(&body, raw, strlen(raw));
    free(raw);
    bool refused = !parsed;
    if (parsed && body.type == JSON_STR)
        refused = true;
    if (parsed && body.type == JSON_OBJ) {
        const struct json_value *err = json_get(&body, "error");
        refused = (err && !json_is_null(err)) ||
                  (json_get(&body, "code") && json_get(&body, "message"));
    }
    json_free(&body);
    if (refused)
        fbc_fail(reply, "PEER_ADD_REFUSED",
                 "the node did not accept the onion peer", true, false,
                 FBC_FETCH_CMD);
    return !refused;
}

static void fbc_fetch_resident(struct vcs_package_store *store,
                               struct fbc_fetch_in *in,
                               struct zcl_command_reply *reply)
{
    in->args.now = (uint64_t)platform_time_wall_unix();
    in->args.day = (int64_t)(in->args.now / 86400u);
    /* A named peer binds the download to it: the peer's ANNOUNCE inventory
     * may be full, in which case a new offer is never announced to us. Not
     * connected yet: fall back to discovery; the CLI poll retries. */
    uint64_t bound[FBC_BOUND_PEERS_MAX];
    if (in->peer && !in->args.local_only) {
        in->args.provider_count = boot_zcode_swarm_peers_for_onion(
            in->peer, bound, FBC_BOUND_PEERS_MAX);
        in->args.providers = bound;
    }
    struct zcl_fleet_bundle_outcome o;
    if (zcl_fleet_bundle_fetch_step(store, vcs_swarm_engine_global(),
                                    &in->args, &o) ==
        ZCL_FLEET_BUNDLE_REFUSED) {
        fbc_fail_outcome(reply, &o, FBC_FETCH_CMD);
        return;
    }
    fbc_render_step(reply, &in->args, &o);
}

static bool fbc_fwd_object(const struct fbc_fetch_in *in,
                           struct json_value *fwd)
{
    json_init(fwd);
    json_set_object(fwd);
    char hex[65];
    zcl_hex_encode(in->args.root, 32, hex);
    bool ok = json_push_kv_str(fwd, "root", hex);
    zcl_hex_encode(in->args.sha256, 32, hex);
    ok = ok && json_push_kv_str(fwd, "sha256", hex);
    ok = ok && json_push_kv_int(fwd, "size", (int64_t)in->args.size);
    ok = ok && json_push_kv_str(fwd, "out", in->args.out_path);
    if (in->peer)
        ok = ok && json_push_kv_str(fwd, "peer", in->peer);
    return ok;
}

enum fbc_local_result { FBC_LOCAL_ERROR, FBC_LOCAL_MISS, FBC_LOCAL_DONE };

static bool fbc_local_complete(const struct json_value *data, const struct fbc_fetch_in *in)
{
    char root[65], sha[65];
    zcl_hex_encode(in->args.root, 32, root); zcl_hex_encode(in->args.sha256, 32, sha);
    const char *state = fbc_str(data, "state"), *r = fbc_str(data, "root");
    const char *s = fbc_str(data, "sha256"), *path = fbc_str(data, "path");
    const struct json_value *size = json_get(data, "size");
    return data && data->type == JSON_OBJ && state && !strcmp(state, "complete") &&
        r && !strcmp(r, root) && s && !strcmp(s, sha) && path && !strcmp(path, in->args.out_path) &&
        size && size->type == JSON_INT && json_get_int(size) == (int64_t)in->args.size;
}

static bool fbc_local_old_node(const struct json_value *body)
{
    const struct json_value *legacy_code = json_get(body, "code");
    const char *method = fbc_str(body, "method");
    const char *legacy_message = fbc_str(body, "message");
    return legacy_code && legacy_code->type == JSON_INT &&
        json_get_int(legacy_code) == RPC_METHOD_NOT_FOUND && method &&
        !strcmp(method, "fleet_bundle_fetch_local") && legacy_message &&
        !strcmp(legacy_message, "Method not found");
}

static enum fbc_local_result fbc_local_invalid(struct zcl_command_reply *reply)
{
    fbc_fail(reply, "NODE_UNAVAILABLE", "the local bundle check returned an invalid response", true, true, FBC_FETCH_CMD);
    return FBC_LOCAL_ERROR;
}

static enum fbc_local_result fbc_local_refusal(const struct json_value *body,
                                                struct zcl_command_reply *reply)
{
    const char *code = fbc_str(body, "code"), *message = fbc_str(body, "message");
    const struct json_value *retryable = json_get(body, "retryable"), *mutated = json_get(body, "mutated");
    if (!code || !message || (retryable && retryable->type != JSON_BOOL) ||
        (mutated && mutated->type != JSON_BOOL)) return fbc_local_invalid(reply);
    if (!strcmp(code, "LOCAL_MISS") && retryable && mutated &&
        !json_get_bool(retryable) && !json_get_bool(mutated))
        return FBC_LOCAL_MISS;
    fbc_fail(reply, code, message, retryable && json_get_bool(retryable),
             mutated && json_get_bool(mutated), FBC_FETCH_CMD);
    return FBC_LOCAL_ERROR;
}

static enum fbc_local_result fbc_local_response(const struct json_value *body,
    const struct fbc_fetch_in *in, struct zcl_command_reply *reply)
{
    if (!body || body->type != JSON_OBJ) return fbc_local_invalid(reply);
    const struct json_value *ok = json_get(body, "ok");
    if (!ok && fbc_local_old_node(body)) return FBC_LOCAL_MISS;
    if (!ok || ok->type != JSON_BOOL) return fbc_local_invalid(reply);
    if (!json_get_bool(ok)) return fbc_local_refusal(body, reply);
    const struct json_value *data = json_get(body, "data");
    if (!fbc_local_complete(data, in) || !json_copy_checked(&reply->data, data))
        return fbc_local_invalid(reply);
    return FBC_LOCAL_DONE;
}

static enum fbc_local_result fbc_check_local(const struct fbc_fetch_in *in,
                                              struct zcl_command_reply *reply)
{
    struct json_value fwd, body, args; bool built = fbc_fwd_object(in, &fwd);
    json_init(&body); json_init(&args); json_set_array(&args);
    built = built && json_push_kv_bool(&fwd, "local_only", true) && json_push_back(&args, &fwd);
    size_t need = built ? json_write(&args, NULL, 0) : 0;
    char *params = need && need <= 32768u ? zcl_malloc(need + 1u, "bundle-local-rpc") : NULL;
    if (params && json_write(&args, params, need + 1u) != need) { free(params); params = NULL; }
    char *raw = NULL;
    if (params) { zcl_native_bridge_ensure_rpc(); raw = node_rpc_call("fleet_bundle_fetch_local", params); }
    enum fbc_local_result result = FBC_LOCAL_ERROR;
    if (raw && json_read(&body, raw, strlen(raw))) result = fbc_local_response(&body, in, reply);
    else if (params) fbc_fail(reply, "NODE_UNAVAILABLE", "the local bundle check did not answer", true, true, FBC_FETCH_CMD);
    else fbc_fail(reply, "ARG_BUILD_FAILED", "could not encode the local bundle check", false, false, FBC_FETCH_CMD);
    free(raw); free(params); json_free(&args); json_free(&body); json_free(&fwd); return result;
}

/* Read the node's peer list once and say whether the named onion is in it.
 * `count` gets the number of connected peers when the list was read. */
static enum zcl_fleet_bundle_peer_state fbc_probe_peer(const char *peer,
                                                       size_t *count)
{
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("getpeerinfo", "[]");
    if (!raw)
        return ZCL_FLEET_PEER_UNKNOWN;
    struct json_value peers;
    json_init(&peers);
    bool parsed = json_read(&peers, raw, strlen(raw));
    free(raw);
    const struct json_value *arr = &peers;
    if (parsed && peers.type == JSON_OBJ && json_get(&peers, "result"))
        arr = json_get(&peers, "result");
    enum zcl_fleet_bundle_peer_state state = ZCL_FLEET_PEER_UNKNOWN;
    if (parsed && arr->type == JSON_ARR) {
        state = ZCL_FLEET_PEER_ABSENT;
        *count = json_size(arr);
        for (size_t i = 0; i < *count; i++) {
            const char *addr =
                json_get_str(json_get(json_at(arr, i), "addr"));
            if (zcl_fleet_bundle_addr_is_peer(peer, addr)) {
                state = ZCL_FLEET_PEER_CONNECTED;
                break;
            }
        }
    }
    json_free(&peers);
    return state;
}

/* The FETCH_TIMEOUT reply. With --peer the peer's state goes in
 * data.failure_facts (the only data a failed envelope exports); the full
 * detail lives there because error.message is capped at 192 bytes. */
void zcl_native_fleet_bundle_timeout_reply(
    struct zcl_command_reply *reply, const char *peer,
    enum zcl_fleet_bundle_peer_state state, size_t count, const char *root)
{
    char summary[192];
    char detail[512];
    if (!zcl_fleet_bundle_timeout_summary(summary, sizeof(summary), peer,
                                          state))
        (void)snprintf(summary, sizeof(summary),
                       "the bundle did not arrive within timeout_s");
    if (peer && zcl_fleet_bundle_timeout_message(detail, sizeof(detail), peer,
                                                 state, root)) {
        struct json_value facts;
        json_init(&facts);
        json_set_object(&facts);
        (void)json_push_kv_str(&facts, "peer", peer);
        (void)json_push_kv_str(&facts, "detail", detail);
        if (state != ZCL_FLEET_PEER_UNKNOWN) {
            (void)json_push_kv_bool(&facts, "peer_connected",
                                    state == ZCL_FLEET_PEER_CONNECTED);
            (void)json_push_kv_int(&facts, "peers_connected",
                                   (int64_t)count);
        }
        (void)json_push_kv(&reply->data, "failure_facts", &facts);
        json_free(&facts);
    }
    fbc_fail(reply, "FETCH_TIMEOUT", summary, true, false, FBC_FETCH_CMD);
}

static void fbc_fail_timeout(const struct fbc_fetch_in *in,
                             struct zcl_command_reply *reply)
{
    enum zcl_fleet_bundle_peer_state state = ZCL_FLEET_PEER_UNKNOWN;
    size_t count = 0;
    if (in->peer)
        state = fbc_probe_peer(in->peer, &count);
    char root[65];
    zcl_hex_encode(in->args.root, 32, root);
    zcl_native_fleet_bundle_timeout_reply(reply, in->peer, state, count, root);
}

/* One-shot CLI: poll the node's non-blocking step until complete or the
 * bounded wait ends. */
static void fbc_fetch_poll(struct fbc_fetch_in *in,
                           struct zcl_command_reply *reply)
{
    struct json_value fwd;
    if (!fbc_fwd_object(in, &fwd)) {
        json_free(&fwd);
        fbc_fail(reply, "ARG_BUILD_FAILED", "could not encode the request", false, false, FBC_FETCH_CMD);
        return;
    }
    uint64_t deadline =
        (uint64_t)platform_time_wall_unix() + (uint64_t)in->timeout_s;
    bool continuing = false;
    for (;;) {
        struct json_value data;
        if (!fbc_forward("fleet_bundle_fetch", &fwd, reply, &data,
                         FBC_FETCH_CMD))
            break;
        const char *state = json_get_str(json_get(&data, "state"));
        bool complete = state && strcmp(state, "complete") == 0;
        if (complete)
            json_copy(&reply->data, &data);
        json_free(&data);
        if (complete)
            break;
        if (!continuing) {
            if (!json_push_kv_bool(&fwd, "continuation", true)) {
                fbc_fail(reply, "ARG_BUILD_FAILED", "could not encode continuation", false, false, FBC_FETCH_CMD);
                break;
            }
            continuing = true;
        }
        if ((uint64_t)platform_time_wall_unix() >= deadline) {
            fbc_fail_timeout(in, reply);
            break;
        }
        platform_sleep_ms(FBC_POLL_MS);
    }
    json_free(&fwd);
}

static void fbc_fetch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, bool continuation, bool local_only)
{
    if (!request || !reply)
        return;
    struct fbc_fetch_in in;
    if (!fbc_parse_fetch(request->input, reply, &in))
        return;
    in.args.continuation = continuation;
    in.args.local_only = local_only;
    struct vcs_package_store *store = vcs_package_store_global();
    if (store) {
        fbc_fetch_resident(store, &in, reply);
        return;
    }
    if (local_only) {
        fbc_fail(reply, "HOSTING_DISABLED", "package hosting is disabled on this node", false, false, FBC_FETCH_CMD);
        return;
    }
    if (!platform_private_path_absent(in.args.out_path)) {
        fbc_fail(reply, "OUT_EXISTS",
                 "out already exists; pick a path that does not exist",
                 false, false, FBC_FETCH_CMD);
        return;
    }
    if (in.peer) {
        enum fbc_local_result local = fbc_check_local(&in, reply);
        if (local != FBC_LOCAL_MISS) return;
        if (!fbc_add_peer(in.peer, reply)) return;
    }
    fbc_fetch_poll(&in, reply);
}

void zcl_native_handle_fleet_bundle_fetch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fbc_fetch(request, reply, false, false);
}

void zcl_native_fleet_bundle_fetch_continue(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fbc_fetch(request, reply, true, false);
}

void zcl_native_fleet_bundle_fetch_local(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fbc_fetch(request, reply, false, true);
}
