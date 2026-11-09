/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: plugin.fetch_remote — ask the node already running on this
 *          datadir to fetch one package root from its peers and install it
 *          as a new generation. plugin.publish and the inert plugin.fetch
 *          live in native_plugin_swarm_command.c. Every refusal carries a
 *          stable PLUGIN_DIST_* code and a next action. */

#include "command/native_command.h"
#include "native_plugin_common.h"

#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "platform/time_compat.h"
#include "json/json.h"
#include "plugin/plugin_dist.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        const char *why = pdc_transport_text(body);
        bool cookie = strstr(why, "RPC auth cookie") != NULL;
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_TRANSIENT,
                               "PLUGIN_FETCH_NO_NODE", "fetch_remote", true, false, why,
                               cookie ? "pass -datadir=<the running node's data directory> and, when it is not the default, "
                                        "-rpcport=<its RPC port>, so the cookie and the node are found; the node must run with -packagehost=1"
                                      : "start the node with -packagehost=1, or use the two-phase plugin fetch");
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

/* Largest accepted fetch_remote wait, in seconds. Bounding it keeps
 * wait_s * 1000 well inside int64 milliseconds for the poll deadline. */
#define PDC_REMOTE_WAIT_MAX_S 86400u

static bool pdc_remote_args_ok(const struct zcl_command_request *request, bool polling, bool bad,
                               const char *params, uint64_t *wait_s)
{
    return !bad && params && pdc_u64(request, "wait", wait_s) && *wait_s <= PDC_REMOTE_WAIT_MAX_S &&
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
                   "root and name (or job), and positive integers for peer_id, max-bytes, timeout, wait are required; wait is at most 86400 seconds",
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
