/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.network.onion.remote-status. See controllers/onion_remote_status.h.
 *
 * One fetch of the constant path /status through the embedded Tor, at most
 * one in flight per node, a 4096-byte body cap, strict parsing, and an output
 * copied only from an allowlist of fields. */

#include "controllers/onion_remote_status.h"

#include "controllers/rpc_client.h"
#include "controllers/status_native_helpers.h"
#include "json/json.h"
#include "net/onion_peer_merge.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REMOTE_STATUS_PATH "/status"

static atomic_flag g_in_flight = ATOMIC_FLAG_INIT;

#ifdef ZCL_TESTING
static tor_fetch_dispatch_fn g_test_dispatch;
static bool g_test_tor_ready;

void onion_remote_status_set_test_hooks(tor_fetch_dispatch_fn dispatch,
                                        bool tor_ready)
{
    g_test_dispatch = dispatch;
    g_test_tor_ready = tor_ready;
}

void onion_remote_status_clear_test_hooks(void)
{
    g_test_dispatch = NULL;
    g_test_tor_ready = false;
}
#endif

/* Typed refusal: "CODE: detail". The detail ends with the next action. */
static char *rs_fail(struct zcl_native_body_err *err,
                     enum zcl_native_body_status status, const char *code,
                     const char *detail)
{
    err->status = status;
    snprintf(err->message, sizeof(err->message), "%s: %s", code, detail);
    LOG_WARN("native.net", "onion remote-status: %s", err->message);
    return NULL;
}

static bool rs_tor_ready(void)
{
#ifdef ZCL_TESTING
    if (g_test_dispatch)
        return g_test_tor_ready;
#endif
    return tor_integration_is_ready();
}

static int rs_fetch(const char *onion, int timeout_secs,
                    struct onion_fetch_result *res)
{
#ifdef ZCL_TESTING
    if (g_test_dispatch)
        return tor_integration_fetch_onion_blocking_for_test(
            onion, REMOTE_STATUS_PATH, res, timeout_secs, g_test_dispatch);
#endif
    return tor_integration_fetch_onion_blocking(onion, REMOTE_STATUS_PATH,
                                                res, timeout_secs);
}

/* Map a fetch outcome that is not a usable 200 body to a typed refusal.
 * Returns true when the response is a 200 with a body inside the cap. */
static bool rs_check_response(int rc, const struct onion_fetch_result *res,
                              int timeout_secs,
                              struct zcl_native_body_err *err)
{
    if (rc < 0) {
        char detail[128];
        if (res->status >= 200)
            rs_fail(err, ZCL_NATIVE_BODY_PROTOCOL, "BODY_TOO_LARGE",
                    "remote body exceeds the fetch ceiling; this is not a "
                    "node status endpoint");
        else if (res->status > 0)
            rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "HTTP_STATUS",
                    "remote answered with an interim status; retry later");
        else {
            /* Tor readiness was checked before the fetch, so no HTTP status
             * means one honest outcome: nothing answered. */
            (void)snprintf(detail, sizeof(detail),
                           "no answer from the onion within %d s (down, "
                           "unreachable or slow); retry", timeout_secs);
            rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "UNREACHABLE", detail);
        }
        return false;
    }
    if (res->status == 429)
        rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "RATE_LIMITED",
                "remote rate limit hit; wait a minute and retry");
    else if (res->status == 402)
        rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "PUZZLE_REQUIRED",
                "remote demands a puzzle before answering; retry later");
    else if (res->status != 200)
        rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "HTTP_STATUS",
                "remote answered with a non-200 status; check the onion");
    else if (res->body_len > ONION_REMOTE_STATUS_BODY_MAX)
        rs_fail(err, ZCL_NATIVE_BODY_PROTOCOL, "BODY_TOO_LARGE",
                "remote /status body exceeds 4096 bytes; refused");
    else if (!res->body || res->body_len == 0)
        rs_fail(err, ZCL_NATIVE_BODY_PROTOCOL, "BAD_JSON",
                "remote /status body is empty; refused");
    else
        return true;
    return false;
}

/* Push remote[dst] from root[src] when it has the allowed type, else null. */
static void rs_push_field(struct json_value *remote,
                          const struct json_value *root, const char *src,
                          const char *dst, enum json_type want)
{
    const struct json_value *v = json_get(root, src);
    struct json_value none;
    json_init(&none);
    json_push_kv(remote, dst, (v && v->type == want) ? v : &none);
}

static void rs_build_remote(struct json_value *remote,
                            const struct json_value *root)
{
    json_set_object(remote);
    json_push_kv_int(remote, "height", json_get_int(json_get(root, "height")));
    rs_push_field(remote, root, "syncing", "syncing", JSON_BOOL);
    rs_push_field(remote, root, "peers", "peers_seen_1h", JSON_INT);
    rs_push_field(remote, root, "tor_ready", "tor_ready", JSON_BOOL);
    rs_push_field(remote, root, "onion_service_ready", "onion_service_ready",
                  JSON_BOOL);
    rs_push_field(remote, root, "uptime", "uptime", JSON_INT);
    rs_push_field(remote, root, "last_block_age", "last_block_age", JSON_INT);
}

static char *rs_render(const char *onion, int64_t elapsed_ms,
                       int64_t local_height, const struct json_value *root,
                       struct zcl_native_body_err *err)
{
    struct json_value out, remote;
    json_init(&out);
    json_init(&remote);
    json_set_object(&out);
    json_push_kv_str(&out, "schema", "zcl.onion_remote_status.v1");
    json_push_kv_str(&out, "onion", onion);
    json_push_kv_int(&out, "http_status", 200);
    json_push_kv_int(&out, "elapsed_ms", elapsed_ms);
    rs_build_remote(&remote, root);
    json_push_kv(&out, "remote", &remote);
    json_free(&remote);

    struct json_value none;
    json_init(&none);
    int64_t remote_height = json_get_int(json_get(root, "height"));
    if (local_height >= 0) {
        json_push_kv_int(&out, "local_height", local_height);
        json_push_kv_int(&out, "height_delta", local_height - remote_height);
    } else {
        json_push_kv(&out, "local_height", &none);
        json_push_kv(&out, "height_delta", &none);
    }
    char *body = zcl_json_value_to_body(&out, "onion_remote_status_body");
    json_free(&out);
    if (!body)
        rs_fail(err, ZCL_NATIVE_BODY_INTERNAL, "INTERNAL",
                "could not allocate the response; retry");
    return body;
}

static char *rs_fetch_and_render(const char *onion, int timeout_secs,
                                 int64_t local_height,
                                 struct zcl_native_body_err *err)
{
    struct onion_fetch_result res;
    memset(&res, 0, sizeof(res));
    int64_t t0 = platform_time_monotonic_ms();
    int rc = rs_fetch(onion, timeout_secs, &res);
    int64_t elapsed_ms = platform_time_monotonic_ms() - t0;

    char *out = NULL;
    if (rs_check_response(rc, &res, timeout_secs, err)) {
        struct json_value root;
        json_init(&root);
        const struct json_value *h = NULL;
        if (!json_read(&root, (const char *)res.body, res.body_len) ||
            root.type != JSON_OBJ)
            rs_fail(err, ZCL_NATIVE_BODY_PROTOCOL, "BAD_JSON",
                    "remote /status is not a JSON object; refused");
        else if (!(h = json_get(&root, "height")) || h->type != JSON_INT ||
                 json_get_int(h) < 0)
            rs_fail(err, ZCL_NATIVE_BODY_PROTOCOL, "BAD_HEIGHT",
                    "remote /status has no integer height; refused");
        else
            out = rs_render(onion, elapsed_ms, local_height, &root, err);
        json_free(&root);
    }
    free(res.body);
    return out;
}

char *onion_remote_status_run(const char *onion, int timeout_secs,
                              int64_t local_height,
                              struct zcl_native_body_err *err)
{
    if (!onion || !onion_hostname_valid(onion))
        return rs_fail(err, ZCL_NATIVE_BODY_INVALID, "BAD_ONION",
                       "onion must be 56 base32 chars plus .onion, nothing "
                       "else");
    if (!rs_tor_ready())
        return rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "TOR_UNAVAILABLE",
                       "embedded Tor is not bootstrapped; see core network "
                       "onion status");
    if (atomic_flag_test_and_set(&g_in_flight))
        return rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "BUSY",
                       "another remote-status fetch is in flight; retry "
                       "after it ends");
    char *out = rs_fetch_and_render(onion, timeout_secs, local_height, err);
    atomic_flag_clear(&g_in_flight);
    return out;
}

bool onion_remote_status_check_args(const struct json_value *onion,
                                    const struct json_value *timeout,
                                    int *timeout_out,
                                    struct zcl_native_body_err *err)
{
    if (!onion || onion->type != JSON_STR ||
        !onion_hostname_valid(json_get_str(onion))) {
        rs_fail(err, ZCL_NATIVE_BODY_INVALID, "BAD_ONION",
                "onion must be 56 base32 chars plus .onion, nothing else");
        return false;
    }
    *timeout_out = ONION_REMOTE_STATUS_TIMEOUT_DEFAULT;
    if (!timeout || timeout->type == JSON_NULL)
        return true;
    int64_t v = json_get_int(timeout);
    if (timeout->type != JSON_INT || v < ONION_REMOTE_STATUS_TIMEOUT_MIN ||
        v > ONION_REMOTE_STATUS_TIMEOUT_MAX) {
        rs_fail(err, ZCL_NATIVE_BODY_INVALID, "BAD_TIMEOUT",
                "timeout_secs must be an integer 5..60");
        return false;
    }
    *timeout_out = (int)v;
    return true;
}

/* The refusal class a typed "CODE: detail" message belongs to. */
static enum zcl_native_body_status rs_status_for_message(const char *msg)
{
    static const struct {
        const char *code;
        enum zcl_native_body_status status;
    } rows[] = {
        { "BAD_ONION:", ZCL_NATIVE_BODY_INVALID },
        { "BAD_TIMEOUT:", ZCL_NATIVE_BODY_INVALID },
        { "BODY_TOO_LARGE:", ZCL_NATIVE_BODY_PROTOCOL },
        { "BAD_JSON:", ZCL_NATIVE_BODY_PROTOCOL },
        { "BAD_HEIGHT:", ZCL_NATIVE_BODY_PROTOCOL },
        { "INTERNAL:", ZCL_NATIVE_BODY_INTERNAL },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        if (strncmp(msg, rows[i].code, strlen(rows[i].code)) == 0)
            return rows[i].status;
    return ZCL_NATIVE_BODY_UNAVAILABLE;
}

/* The node's refusal object ({"code","message"} or {"error":{...}}), or NULL
 * when `root` is an ordinary result. */
static const struct json_value *rs_rpc_error(const struct json_value *root)
{
    const struct json_value *e = json_get(root, "error");
    if (e && e->type == JSON_OBJ)
        return e;
    const struct json_value *code = json_get(root, "code");
    const struct json_value *msg = json_get(root, "message");
    return (code && code->type == JSON_INT && msg && msg->type == JSON_STR)
               ? root : NULL;
}

/* Hand back the node's document, or turn its refusal into a typed one. */
static char *rs_unwrap_reply(char *raw, struct zcl_native_body_err *err)
{
    if (!raw)
        return rs_fail(err, ZCL_NATIVE_BODY_UNAVAILABLE, "NODE_UNAVAILABLE",
                       "no answer from the node; check core status");
    struct json_value root;
    json_init(&root);
    if (!json_read(&root, raw, strlen(raw)) || root.type != JSON_OBJ) {
        json_free(&root);
        free(raw);
        return rs_fail(err, ZCL_NATIVE_BODY_INTERNAL, "INTERNAL",
                       "the node returned an unreadable reply; retry");
    }
    const struct json_value *e = rs_rpc_error(&root);
    if (e) {
        const char *m = json_get_str(json_get(e, "message"));
        char msg[sizeof(err->message)];
        snprintf(msg, sizeof(msg), "%s", m ? m : "node refused the call");
        err->status = rs_status_for_message(msg);
        snprintf(err->message, sizeof(err->message), "%s", msg);
        json_free(&root);
        free(raw);
        return NULL;
    }
    json_free(&root);
    return raw;
}

char *zcl_native_onion_remote_status_body(const struct json_value *args,
                                          struct zcl_native_body_err *err)
{
    const struct json_value *o = json_get(args, "onion");
    int timeout_secs;
    if (!onion_remote_status_check_args(o, json_get(args, "timeout_secs"),
                                        &timeout_secs, err))
        return NULL;
    /* The embedded Tor and the chain live in the node, not in this CLI
     * process: ask the node to run the fetch. The onion was validated above,
     * so it carries nothing that needs JSON escaping. */
    char params[128];
    snprintf(params, sizeof(params), "[\"%s\",%d]", json_get_str(o),
             timeout_secs);
    char *raw = node_rpc_call_deadline("onionremotestatus", params, 2000,
                                       ((long)timeout_secs + 10) * 1000L);
    return rs_unwrap_reply(raw, err);
}
