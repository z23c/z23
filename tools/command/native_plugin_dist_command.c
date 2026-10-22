/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.publish and plugin.fetch - peer-to-peer distribution of a
 *          signed plugin generation over the existing package store and swarm.
 *          publish files an installed or packed generation as a package root
 *          with a signed release so a hosting node can serve it. fetch takes a
 *          root that the swarm delivered to this datadir, re-derives every
 *          claim (root, completeness, shape, publisher pin, image hash,
 *          downgrade) and hands the generation to the ordinary install path
 *          as a NEW generation. Neither command switches or runs a plugin.
 *          Every refusal carries a stable PLUGIN_DIST_* code and a next
 *          action. The daemon is not contacted. */

#include "command/native_command.h"
#include "native_plugin_common.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "json/json.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_store.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_service.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void pdc_refuse(struct zcl_command_reply *reply, enum plugin_dist_status st,
                       const char *what, const char *detail, bool retryable,
                       bool mutated)
{
    char message[320];
    (void)snprintf(message, sizeof(message), "plugin %s refused: %s: %s", what,
                   plugin_dist_status_code(st), detail && detail[0] ? detail : "no detail");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           retryable ? ZCL_COMMAND_EXIT_TRANSIENT : ZCL_COMMAND_EXIT_INVALID,
                           plugin_dist_status_code(st), what, retryable, mutated, message,
                           detail ? detail : "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                   plugin_dist_status_next_action(st));
    reply->error.human_action_required = true;
}

static bool pdc_flag(const struct zcl_command_request *request, const char *key)
{
    const struct json_value *v = request->input ? json_get(request->input, key) : NULL;
    if (!v)
        return false;
    if (v->type == JSON_BOOL)
        return json_get_bool(v);
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0 || s[0] == '\0');
}

static bool pdc_u64(const struct zcl_command_request *request, const char *key,
                    uint64_t *out)
{
    const struct json_value *v = request->input ? json_get(request->input, key) : NULL;
    if (!v) {
        *out = 0;
        return true;
    }
    if (v->type == JSON_INT) {
        int64_t n = json_get_int(v);
        *out = n > 0 ? (uint64_t)n : 0;
        return n > 0;
    }
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    char *end = NULL;
    unsigned long long n = s && *s ? strtoull(s, &end, 10) : 0;
    *out = n;
    return s && *s && end && *end == '\0' && n > 0;
}

static struct vcs_package_store *pdc_open_store(struct zcl_command_reply *reply,
                                                const char *what, const char *datadir)
{
    struct vcs_package_store *store =
        datadir ? vcs_package_store_open(datadir, vcs_package_store_quota_bytes()) : NULL;
    if (!store)
        pdc_refuse(reply, PLUGIN_DIST_ERR_STORE, what,
                   datadir ? "the package store could not be opened; stop any node using this datadir"
                           : "no datadir; pass --datadir", false, false);
    return store;
}

void zcl_native_handle_plugin_publish(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char plugins[PATH_MAX];
    uint64_t sequence = 0;
    const char *name = plg_str(request, "name");
    if (!pdc_u64(request, "sequence", &sequence) ||
        (!zcl_native_plugin_root(plugins, sizeof(plugins)) && !plg_str(request, "dir"))) {
        pdc_refuse(reply, PLUGIN_DIST_ERR_ARGUMENT, "publish",
                   "sequence must be a positive integer and HOME must be absolute",
                   false, false);
        return;
    }
    if (!name) {
        pdc_refuse(reply, PLUGIN_DIST_ERR_ARGUMENT, "publish", "name is required", false, false);
        return;
    }
    const char *datadir = plg_str(request, "datadir");
    if (!datadir)
        datadir = zcl_native_command_datadir();
    struct vcs_package_store *store = pdc_open_store(reply, "publish", datadir);
    if (!store)
        return;
    struct plugin_dist_publish_request rq = {
        .plugins_dir = plugins, .name = name, .generation = plg_str(request, "generation"),
        .src_dir = plg_str(request, "dir"), .license_file = plg_str(request, "license-file"),
        .spdx = plg_str(request, "spdx"), .release_key = plg_str(request, "release-key"),
        .sequence = sequence
    };
    struct plugin_dist_published out;
    enum plugin_dist_status st = plugin_dist_publish(store, &rq, &out);
    vcs_package_store_close(store);
    if (st != PLUGIN_DIST_OK) {
        pdc_refuse(reply, st, "publish", out.detail, false, false);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_publish.v1");
    (void)json_push_kv_str(&reply->data, "root", out.root_hex);
    (void)json_push_kv_str(&reply->data, "manifest_sha3", out.generation);
    (void)json_push_kv_str(&reply->data, "name", out.name);
    (void)json_push_kv_str(&reply->data, "version", out.version);
    (void)json_push_kv_str(&reply->data, "exe_sha3", out.exe_sha3);
    (void)json_push_kv_int(&reply->data, "files", out.files);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)out.bytes);
    (void)json_push_kv_str(&reply->data, "serve",
        "start a hosting node on this datadir (z23 join, or -packagehost=1) and "
        "give receivers this root; the signed release is filed in the store");
    reply->error.mutated = true;
}

/* One-shot: persist the resumable download record the hosting node replays. */
static bool pdc_register_download(const char *datadir, const uint8_t root[32],
                                  struct vcs_package_store *store)
{
    char zcode_dir[PATH_MAX];
    if (snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir) >= (int)sizeof(zcode_dir))
        return false;
    struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
    struct vcs_swarm_engine *engine = vcs_swarm_engine_create(store, book, zcode_dir, NULL, NULL);
    bool ok = false;
    if (engine) {
        uint64_t now = (uint64_t)platform_time_wall_unix();
        enum vcs_swarm_fetch_result r =
            vcs_swarm_engine_fetch(engine, root, (int64_t)(now / 86400), now);
        ok = r == VCS_SWARM_FETCH_OK || r == VCS_SWARM_FETCH_ALREADY_COMPLETE;
        vcs_swarm_engine_free(engine);
    }
    vcs_service_book_free(book);
    return ok;
}

void zcl_native_handle_plugin_fetch(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char plugins[PATH_MAX], scratch[PATH_MAX], err[160];
    uint8_t root[32];
    const char *name = plg_str(request, "name");
    if (!zcl_native_require_hex64("root", plg_str(request, "root"), root, err, sizeof(err))) {
        pdc_refuse(reply, PLUGIN_DIST_ERR_ARGUMENT, "fetch", err, false, false);
        return;
    }
    if (!name || !zcl_native_plugin_root(plugins, sizeof(plugins))) {
        pdc_refuse(reply, PLUGIN_DIST_ERR_ARGUMENT, "fetch",
                   "name is required and HOME must be absolute", false, false);
        return;
    }
    const char *datadir = plg_str(request, "datadir");
    if (!datadir)
        datadir = zcl_native_command_datadir();
    struct vcs_package_store *store = pdc_open_store(reply, "fetch", datadir);
    if (!store)
        return;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, root, &status)) {
        /* Nothing received yet: record the download for the hosting node
         * and say so. The peers are the hosting node's own connections. */
        bool recorded = pdc_register_download(datadir, root, store);
        vcs_package_store_close(store);
        pdc_refuse(reply, PLUGIN_DIST_ERR_NOT_FETCHED, "fetch",
                   recorded ? "the root is not in this datadir; a resumable download was recorded for the hosting node"
                            : "the root is not in this datadir and the download could not be recorded",
                   true, recorded);
        return;
    }
    if (snprintf(scratch, sizeof(scratch), "%s/zcode/plugin-dist", datadir) >= (int)sizeof(scratch) ||
        !platform_private_directory_ensure(scratch)) {
        vcs_package_store_close(store);
        pdc_refuse(reply, PLUGIN_DIST_ERR_IO, "fetch", "cannot create the checkout scratch directory",
                   false, false);
        return;
    }
    struct plugin_dist_receive_request rq = {
        .store = store, .name = name, .plugins_dir = plugins, .scratch_dir = scratch,
        .allow_downgrade = pdc_flag(request, "allow-downgrade")
    };
    memcpy(rq.requested_root, root, 32);
    struct plugin_dist_received out;
    enum plugin_dist_status st = plugin_dist_receive(&rq, &out);
    vcs_package_store_close(store);
    if (st != PLUGIN_DIST_OK) {
        char detail[256];
        if (st == PLUGIN_DIST_ERR_PLUGIN)
            (void)snprintf(detail, sizeof(detail), "%s (%s)", out.detail, plugin_status_code(out.plugin));
        else
            (void)snprintf(detail, sizeof(detail), "%s", out.detail);
        pdc_refuse(reply, st, "fetch", detail, st == PLUGIN_DIST_ERR_TRUNCATED, false);
        return;
    }
    json_set_object(&reply->data);
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.plugin_fetch.v1");
    (void)json_push_kv_str(&reply->data, "root", root_hex);
    (void)json_push_kv_str(&reply->data, "name", out.name);
    (void)json_push_kv_str(&reply->data, "version", out.version);
    (void)json_push_kv_str(&reply->data, "generation", out.generation);
    (void)json_push_kv_bool(&reply->data, "already_present", out.already_present);
    (void)json_push_kv_bool(&reply->data, "downgrade_allowed", out.downgrade_allowed);
    (void)json_push_kv_bool(&reply->data, "switched", false);
    reply->error.mutated = !out.already_present;
    char input[256];
    (void)snprintf(input, sizeof(input), "{\"name\":\"%s\",\"generation\":\"%s\"}", out.name,
                   out.generation);
    (void)zcl_command_reply_add_next(reply, "plugin.switch", input, "make this generation current");
}

/* ---- plugin.fetch_remote: the running node fetches and installs ------------ */

#define PDC_REMOTE_POLL_MS 250

static char *pdc_remote_params(const struct zcl_command_request *request, bool *bad)
{
    struct json_value arg, one, peers, peer_value;
    uint64_t max_bytes = 0, timeout = 0, peer = 0, job = 0;
    json_init(&arg);
    json_init(&one);
    json_init(&peers);
    json_init(&peer_value);
    json_set_array(&arg);
    json_set_object(&one);
    json_set_array(&peers);
    *bad = !pdc_u64(request, "max-bytes", &max_bytes) || !pdc_u64(request, "timeout", &timeout) ||
           !pdc_u64(request, "peer_id", &peer) || !pdc_u64(request, "job", &job);
    if (job) {
        json_push_kv_int(&one, "job", (int64_t)job);
    } else {
        json_push_kv_str(&one, "root", plg_str(request, "root"));
        json_push_kv_str(&one, "name", plg_str(request, "name"));
        json_push_kv_bool(&one, "allow_downgrade", pdc_flag(request, "allow-downgrade"));
        if (peer) {
            json_set_int(&peer_value, (int64_t)peer);
            json_push_back(&peers, &peer_value);
            json_push_kv(&one, "peers", &peers);
        }
        if (max_bytes)
            json_push_kv_int(&one, "max_bytes", (int64_t)max_bytes);
        if (timeout)
            json_push_kv_int(&one, "timeout_s", (int64_t)timeout);
    }
    json_push_back(&arg, &one);
    size_t needed = json_write(&arg, NULL, 0);
    char *wire = needed ? zcl_malloc(needed + 1, "plugin.fetch_remote.params") : NULL;
    if (wire && json_write(&arg, wire, needed + 1) != needed) {
        free(wire);
        wire = NULL;
    }
    json_free(&arg);
    json_free(&one);
    json_free(&peers);
    json_free(&peer_value);
    return wire;
}

/* json_get_str never returns NULL (a missing or non-string value reads as ""),
 * so "x ? x : fallback" never reaches its fallback. This does. */
static const char *pdc_str_or(const struct json_value *body, const char *key, const char *fallback)
{
    const char *value = json_get_str(json_get(body, key));
    return value[0] ? value : fallback;
}

enum pdc_call {
    PDC_CALL_OK,        /* the node answered ok:true */
    PDC_CALL_REFUSED,   /* the node answered ok:false with its own envelope: final */
    PDC_CALL_TRANSPORT, /* no node answer: refused connect, deadline, bare JSON-RPC error */
};

/* A node answer carries a boolean "ok". Anything else (no reply, unparseable
 * text, the client's bare {"code":-32603,"message":..} error value, or a
 * {"error":..} wrapper) is the transport failing, not the node deciding. */
static bool pdc_body_is_node_answer(const struct json_value *body)
{
    const struct json_value *ok = json_get(body, "ok");
    return body->type == JSON_OBJ && ok && ok->type == JSON_BOOL;
}

/* The transport's own explanation, or a stock one. */
static const char *pdc_transport_text(const struct json_value *body)
{
    const struct json_value *err = json_get(body, "error");
    const struct json_value *src = err && err->type == JSON_OBJ ? err : body;
    return pdc_str_or(src, "message", "no running node answered on this datadir's RPC");
}

/* One resident call. On a refusal or transport failure the reply is filled. */
static enum pdc_call pdc_remote_call(struct zcl_command_reply *reply, const char *method, const char *params,
                                     struct json_value *body)
{
    char *raw = node_rpc_call(method, params);
    bool parsed = raw && json_read(body, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(body);
        json_init(body);
    }
    if (!pdc_body_is_node_answer(body)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_TRANSIENT,
                               "PLUGIN_FETCH_NO_NODE", "fetch_remote", true, false,
                               pdc_transport_text(body),
                               "start the node with -packagehost=1, or use the two-phase plugin fetch");
        return PDC_CALL_TRANSPORT;
    }
    if (!json_get_bool_or(body, "ok", false)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                               pdc_str_or(body, "code", "PLUGIN_FETCH_REFUSED"), "fetch_remote", false, false,
                               pdc_str_or(body, "message", "the node refused the request"), "");
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                       json_get_str(json_get(body, "next_action")));
        reply->error.human_action_required = true;
        return PDC_CALL_REFUSED;
    }
    return PDC_CALL_OK;
}

static void pdc_remote_finish(struct zcl_command_reply *reply, struct json_value *body)
{
    const char *state = json_get_str(json_get(body, "state"));
    if (state && strcmp(state, "failed") == 0) {
        const char *detail = pdc_str_or(body, "detail", "the fetch job failed");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                               pdc_str_or(body, "code", "PLUGIN_FETCH_FAILED"), "fetch_remote", false, false,
                               detail, detail);
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s",
                       json_get_str(json_get(body, "next_action")));
        reply->error.human_action_required = true;
        return;
    }
    json_free(&reply->data);
    json_init(&reply->data);
    json_copy(&reply->data, body);
    if (state && strcmp(state, "installed") == 0) {
        reply->error.mutated = !json_get_bool_or(body, "already_present", false);
        char input[256];
        (void)snprintf(input, sizeof(input), "{\"name\":\"%s\",\"generation\":\"%s\"}",
                       json_get_str(json_get(body, "name")), json_get_str(json_get(body, "generation")));
        (void)zcl_command_reply_add_next(reply, "plugin.switch", input, "make this generation current");
    }
}

/* Consecutive poll transport failures tolerated before the wait gives up. Each
 * failure is followed by the poll sleep, so this is also a floor on how long a
 * node that is busy (or just booted) gets to answer again. */
#define PDC_REMOTE_POLL_RETRIES 8

static bool pdc_remote_job_running(const struct json_value *body)
{
    const char *state = json_get_str(json_get(body, "state"));
    return strcmp(state, "fetching") == 0 || strcmp(state, "installing") == 0;
}

/* The poll kept failing: say so, naming the job, which is still running. */
static void pdc_remote_poll_lost(struct zcl_command_reply *reply, int64_t job, const char *why)
{
    char message[320];
    (void)snprintf(message, sizeof(message),
                   "lost contact with the node while waiting on fetch job %lld, which may still be running: %s",
                   (long long)job, why);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_TRANSIENT,
                           "PLUGIN_FETCH_POLL_FAILED", "fetch_remote", true, false, message, "");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "poll again: z23 plugin fetch_remote --job=%lld", (long long)job);
    reply->error.human_action_required = true;
}

/* Polls the job until it leaves fetching/installing or wait_s of wall time runs
 * out. A poll that gets no node answer is retried (bounded); only a final
 * failure is reported, and never while a good answer is the latest one. */
static bool pdc_remote_wait(struct zcl_command_reply *reply, struct json_value *body, uint64_t wait_s)
{
    int64_t job = json_get_int(json_get(body, "job"));
    const int64_t deadline = platform_time_monotonic_ms() + (int64_t)(wait_s * 1000u);
    const enum zcl_command_status status = reply->status;
    const enum zcl_command_exit exit_code = reply->exit_code;
    const struct zcl_command_error clean = reply->error;
    int failures = 0;
    bool last_ok = true;
    while ((last_ok ? pdc_remote_job_running(body) : true) && platform_time_monotonic_ms() < deadline) {
        platform_sleep_ms(PDC_REMOTE_POLL_MS);
        char poll[64];
        (void)snprintf(poll, sizeof(poll), "[{\"job\":%lld}]", (long long)job);
        struct json_value next;
        json_init(&next);
        enum pdc_call rc = pdc_remote_call(reply, "plugin_fetch_poll", poll, &next);
        if (rc == PDC_CALL_REFUSED) {
            json_free(&next);
            return false;
        }
        last_ok = rc == PDC_CALL_OK;
        if (last_ok) {
            json_free(body);
            *body = next;
            failures = 0;
            reply->status = status;
            reply->exit_code = exit_code;
            reply->error = clean;
        } else {
            const char *why = pdc_transport_text(&next);
            char kept[256];
            (void)snprintf(kept, sizeof(kept), "%s", why);
            json_free(&next);
            pdc_remote_poll_lost(reply, job, kept);
            if (++failures > PDC_REMOTE_POLL_RETRIES)
                return false;
        }
    }
    return last_ok || (pdc_remote_poll_lost(reply, job, "the wait ran out before the node answered again"), false);
}

static bool pdc_remote_args_ok(const struct zcl_command_request *request, bool polling, bool bad,
                               const char *params, uint64_t *wait_s)
{
    return !bad && params && pdc_u64(request, "wait", wait_s) &&
           (polling || (plg_str(request, "root") && plg_str(request, "name")));
}

void zcl_native_handle_plugin_fetch_remote(const struct zcl_command_request *request,
                                           struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    bool bad = false, polling = json_get(request->input, "job") != NULL;
    uint64_t wait_s = 0;
    char *params = pdc_remote_params(request, &bad);
    if (!pdc_remote_args_ok(request, polling, bad, params, &wait_s)) {
        free(params);
        pdc_refuse(reply, PLUGIN_DIST_ERR_ARGUMENT, "fetch_remote",
                   "root and name (or job), and positive integers for peer_id, max-bytes, timeout, wait are required",
                   false, false);
        return;
    }
    zcl_native_bridge_ensure_rpc();
    struct json_value body;
    json_init(&body);
    bool ok = pdc_remote_call(reply, polling ? "plugin_fetch_poll" : "plugin_fetch_begin", params, &body) == PDC_CALL_OK;
    free(params);
    ok = ok && pdc_remote_wait(reply, &body, wait_s);
    if (ok)
        pdc_remote_finish(reply, &body);
    json_free(&body);
}
