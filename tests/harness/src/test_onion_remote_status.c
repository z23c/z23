/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_onion_remote_status: core.network.onion.remote-status through the
 * tor_integration_fetch_onion_blocking_for_test seam. No Tor, no network: an
 * injected dispatcher answers (or refuses, or stays silent) and the typed
 * result or refusal is read back. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "controllers/network_controller.h"
#include "controllers/onion_remote_status.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "rpc/server.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 54 'a' then "ad": 56 base32 chars, the shape of a v3 host. */
#define HOST "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"

static int g_status;
static const char *g_body;
static int g_dispatch_rc;
static bool g_silent;
static int g_calls;
static char g_last_path[32];
static bool g_reenter;
static char g_inner_msg[192];
static tor_fetch_callback_fn g_pending_cb;
static void *g_pending_ctx;

static int fake_dispatch(const char *onion, const char *path, bool use_post,
                         const uint8_t *body, size_t body_len,
                         tor_fetch_callback_fn cb, void *ctx, int timeout_secs)
{
    (void)onion; (void)use_post; (void)body; (void)body_len;
    (void)timeout_secs;
    g_calls++;
    snprintf(g_last_path, sizeof(g_last_path), "%s", path);
    if (g_dispatch_rc < 0)
        return g_dispatch_rc;
    if (g_reenter) {
        struct zcl_native_body_err inner = {0};
        char *r = onion_remote_status_run(HOST, 1, 0, &inner);
        if (r)
            free(r);
        snprintf(g_inner_msg, sizeof(g_inner_msg), "%s", inner.message);
    }
    if (g_silent) {
        /* Silence: hold the completion back, as a real in-flight fetch does.
         * The callback keeps its reference until settle_silent_fetch(). */
        g_pending_cb = cb;
        g_pending_ctx = ctx;
        return 0;
    }
    cb(g_status, (const uint8_t *)g_body, g_body ? strlen(g_body) : 0, ctx);
    return 0;
}

/* Deliver a held-back completion after the waiter has timed out. The real
 * dispatcher always calls back eventually (here: a dead fetch, status 0, no
 * body), and that call drops the callback's reference on the fetch context. */
static void settle_silent_fetch(void)
{
    if (!g_pending_cb)
        return;
    tor_fetch_callback_fn cb = g_pending_cb;
    void *ctx = g_pending_ctx;
    g_pending_cb = NULL;
    g_pending_ctx = NULL;
    cb(0, NULL, 0, ctx);
}

static void arm(int status, const char *body)
{
    settle_silent_fetch();
    g_status = status;
    g_body = body;
    g_dispatch_rc = 0;
    g_silent = false;
    g_calls = 0;
    g_reenter = false;
    g_inner_msg[0] = '\0';
    onion_remote_status_set_test_hooks(fake_dispatch, true);
}

/* Run once and report whether the typed refusal `code` came back. */
static bool refused_with(const char *onion, int timeout, const char *code)
{
    struct zcl_native_body_err err = {0};
    char *r = onion_remote_status_run(onion, timeout, 100, &err);
    if (r) {
        free(r);
        return false;
    }
    return strncmp(err.message, code, strlen(code)) == 0 &&
           err.message[strlen(code)] == ':';
}

#define OK_BODY "{\"height\":90,\"peers\":4,\"version\":\"0.1.0\"," \
    "\"uptime\":77,\"syncing\":true,\"tor_ready\":true," \
    "\"onion_service_ready\":false,\"last_block_age\":12," \
    "\"transactions\":5,\"secret_extra\":\"nope\"}"

static int test_success(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: success copies allowlist, computes delta") {
        arm(200, OK_BODY);
        struct zcl_native_body_err err = {0};
        char *r = onion_remote_status_run(HOST, 1, 100, &err);
        ASSERT(r != NULL);
        ASSERT(strcmp(g_last_path, "/status") == 0);
        ASSERT(strstr(r, "secret_extra") == NULL);
        ASSERT(strstr(r, "transactions") == NULL);
        struct json_value root;
        json_init(&root);
        ASSERT(json_read(&root, r, strlen(r)));
        free(r);
        const struct json_value *rem = json_get(&root, "remote");
        ASSERT(rem != NULL);
        ASSERT_EQ(json_get_int(json_get(rem, "height")), 90);
        ASSERT_EQ(json_get_int(json_get(rem, "peers_seen_1h")), 4);
        ASSERT(json_get_bool(json_get(rem, "syncing")));
        ASSERT(!json_get_bool(json_get(rem, "onion_service_ready")));
        ASSERT_EQ(json_get_int(json_get(rem, "uptime")), 77);
        ASSERT_EQ(json_get_int(json_get(rem, "last_block_age")), 12);
        ASSERT_EQ(json_get_int(json_get(&root, "local_height")), 100);
        ASSERT_EQ(json_get_int(json_get(&root, "height_delta")), 10);
        ASSERT_EQ(json_get_int(json_get(&root, "http_status")), 200);
        ASSERT_STR_EQ(json_get_str(json_get(&root, "schema")),
                      "zcl.onion_remote_status.v1");
        json_free(&root);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_body_refusals(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: bad bodies and statuses refuse typed") {
        char *big = zcl_malloc(5000, "orsbig");
        ASSERT(big != NULL);
        memset(big, 'x', 4999);
        big[4999] = '\0';
        arm(200, big);
        ASSERT(refused_with(HOST, 1, "BODY_TOO_LARGE"));
        free(big);
        arm(200, "{not json");
        ASSERT(refused_with(HOST, 1, "BAD_JSON"));
        arm(200, "{\"peers\":1}");
        ASSERT(refused_with(HOST, 1, "BAD_HEIGHT"));
        arm(200, "{\"height\":\"90\"}");
        ASSERT(refused_with(HOST, 1, "BAD_HEIGHT"));
        arm(429, "slow down");
        ASSERT(refused_with(HOST, 1, "RATE_LIMITED"));
        arm(402, "puzzle");
        ASSERT(refused_with(HOST, 1, "PUZZLE_REQUIRED"));
        arm(503, "down");
        ASSERT(refused_with(HOST, 1, "HTTP_STATUS"));
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_transport_refusals(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: silence and dial refusal are UNREACHABLE, Tor down is TOR_UNAVAILABLE") {
        arm(200, OK_BODY);
        g_silent = true;
        ASSERT(refused_with(HOST, 1, "UNREACHABLE"));
        ASSERT_EQ(g_calls, 1);
        arm(200, OK_BODY);
        g_dispatch_rc = -1;
        ASSERT(refused_with(HOST, 1, "UNREACHABLE"));
        arm(200, OK_BODY);
        onion_remote_status_set_test_hooks(fake_dispatch, false);
        ASSERT(refused_with(HOST, 1, "TOR_UNAVAILABLE"));
        ASSERT_EQ(g_calls, 0);
    } TEST_END
    settle_silent_fetch();
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_bad_onions(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: bad onion strings refuse before any fetch") {
        static const char *const bad[] = {
            "http://" HOST,
            HOST "/status",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD.onion",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1.onion",
            "192.168.1.10",
            HOST ":80",
            "",
        };
        arm(200, OK_BODY);
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
            ASSERT(refused_with(bad[i], 1, "BAD_ONION"));
        ASSERT_EQ(g_calls, 0);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_busy(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: an overlapping call refuses BUSY") {
        arm(200, OK_BODY);
        g_reenter = true;
        struct zcl_native_body_err err = {0};
        char *r = onion_remote_status_run(HOST, 1, 100, &err);
        ASSERT(r != NULL);
        free(r);
        ASSERT(strncmp(g_inner_msg, "BUSY:", 5) == 0);
        ASSERT_EQ(g_calls, 1);
        /* The flag is released: the next call goes through. */
        g_reenter = false;
        r = onion_remote_status_run(HOST, 1, 100, &err);
        ASSERT(r != NULL);
        free(r);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

/* Run onionremotestatus in-process through the real RPC table. */
static bool rpc_run(const char *params_json, struct json_value *result)
{
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_net_rpc_commands(&tbl);
    /* rpc_table_execute refuses every method while the process is in
     * warmup, which is the default in a bare test process. */
    set_rpc_warmup_finished();
    struct json_value params;
    json_init(&params);
    json_init(result);
    bool ok = json_read(&params, params_json, strlen(params_json)) &&
              rpc_table_execute(&tbl, "onionremotestatus", &params, result);
    json_free(&params);
    return ok;
}

/* True when the RPC refused with `code` as the message prefix. */
static bool rpc_refused_with(const char *params_json, const char *code)
{
    struct json_value result;
    bool ok = rpc_run(params_json, &result);
    const char *msg = json_get_str(json_get(&result, "message"));
    bool match = !ok && msg && strncmp(msg, code, strlen(code)) == 0 &&
                 msg[strlen(code)] == ':';
    json_free(&result);
    return match;
}

static int test_rpc_registered(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: onionremotestatus RPC is registered") {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_net_rpc_commands(&tbl);
        ASSERT(rpc_table_find(&tbl, "onionremotestatus") != NULL);
        ASSERT(rpc_table_find(&tbl, "onionstatus") != NULL);
    } TEST_END
    return failures;
}

static int test_rpc_success(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: RPC success runs in the node") {
        arm(200, OK_BODY);
        struct json_value result;
        ASSERT(rpc_run("[\"" HOST "\",5]", &result));
        ASSERT(strcmp(g_last_path, "/status") == 0);
        ASSERT_STR_EQ(json_get_str(json_get(&result, "schema")),
                      "zcl.onion_remote_status.v1");
        ASSERT_EQ(json_get_int(json_get(json_get(&result, "remote"),
                                        "height")), 90);
        json_free(&result);
        /* The timeout is optional. */
        ASSERT(rpc_run("[\"" HOST "\"]", &result));
        json_free(&result);
        ASSERT_EQ(g_calls, 2);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_rpc_refusals(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: RPC revalidates and refuses typed") {
        arm(200, OK_BODY);
        ASSERT(rpc_refused_with("[]", "BAD_ONION"));
        ASSERT(rpc_refused_with("{}", "BAD_ONION"));
        ASSERT(rpc_refused_with("[\"http://" HOST "\"]", "BAD_ONION"));
        ASSERT(rpc_refused_with("[7]", "BAD_ONION"));
        ASSERT(rpc_refused_with("[\"" HOST "\",4]", "BAD_TIMEOUT"));
        ASSERT(rpc_refused_with("[\"" HOST "\",61]", "BAD_TIMEOUT"));
        ASSERT(rpc_refused_with("[\"" HOST "\",\"9\"]", "BAD_TIMEOUT"));
        ASSERT_EQ(g_calls, 0);
        g_silent = true;
        ASSERT(rpc_refused_with("[\"" HOST "\",5]", "UNREACHABLE"));
        arm(429, "slow");
        ASSERT(rpc_refused_with("[\"" HOST "\",5]", "RATE_LIMITED"));
        arm(200, OK_BODY);
        onion_remote_status_set_test_hooks(fake_dispatch, false);
        ASSERT(rpc_refused_with("[\"" HOST "\",5]", "TOR_UNAVAILABLE"));
        ASSERT_EQ(g_calls, 0);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_rpc_busy(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: RPC refuses BUSY while one is in flight") {
        arm(200, OK_BODY);
        g_reenter = true;
        struct json_value result;
        ASSERT(rpc_run("[\"" HOST "\",5]", &result));
        json_free(&result);
        ASSERT(strncmp(g_inner_msg, "BUSY:", 5) == 0);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static bool has_permit_row(const char *leaf)
{
    bool found = false;
#define REMOTE_COMMAND_CLASS(l, cls, reason) \
    if (strcmp((l), leaf) == 0) found = true;
#include "../../../engine/composition/remote_command_classes.def"
#undef REMOTE_COMMAND_CLASS
    return found;
}

static int test_registry(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: operator-only, no remote permit, budget") {
        const char *leaf = "core.network.onion.remote-status";
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *spec = NULL;
        for (size_t i = 0; i < reg->count; i++)
            if (strcmp(reg->commands[i].path, leaf) == 0)
                spec = &reg->commands[i];
        ASSERT(spec != NULL);
        ASSERT(spec->authority == ZCL_COMMAND_AUTH_OPERATOR);
        ASSERT(!has_permit_row(leaf));
        char doc[2816 + 1];
        size_t n = zcl_command_registry_describe_json(reg, leaf, doc,
                                                      sizeof(doc));
        ASSERT(n > 0 && n <= 2816);
    } TEST_END
    return failures;
}

/* Mutation-gap coverage: fetch outcome classes, size and height boundaries,
 * output shape, the argument check and the node-reply mapping. */

/* Run once; true when the refusal carries `status`, the typed `code`, and
 * `detail` somewhere in the message. */
static bool refused_as(const char *onion, int timeout, int64_t local,
                       const char *code, enum zcl_native_body_status status,
                       const char *detail)
{
    struct zcl_native_body_err err = {0};
    char *r = onion_remote_status_run(onion, timeout, local, &err);
    if (r) {
        free(r);
        return false;
    }
    return err.status == status && strncmp(err.message, code, strlen(code)) == 0 &&
           err.message[strlen(code)] == ':' && strstr(err.message, detail);
}

static char *sized_body(size_t total, const char *prefix, const char *suffix)
{
    char *b = zcl_malloc(total + 1, "orsbody");
    if (!b)
        return NULL;
    size_t pre = strlen(prefix), suf = strlen(suffix);
    memcpy(b, prefix, pre);
    memset(b + pre, 'x', total - pre - suf);
    memcpy(b + total - suf, suffix, suf);
    b[total] = '\0';
    return b;
}

static int test_fetch_classes(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: each fetch outcome maps to its own refusal") {
        const enum zcl_native_body_status un = ZCL_NATIVE_BODY_UNAVAILABLE;
        arm(100, "x");
        ASSERT(refused_as(HOST, 1, 0, "HTTP_STATUS", un, "interim"));
        arm(199, "x");
        ASSERT(refused_as(HOST, 1, 0, "HTTP_STATUS", un, "interim"));
        arm(1, "x");
        ASSERT(refused_as(HOST, 1, 0, "HTTP_STATUS", un, "interim"));
        arm(0, "");
        ASSERT(refused_as(HOST, 7, 0, "UNREACHABLE", un, "within 7 s"));
        arm(503, "down");
        ASSERT(refused_as(HOST, 1, 0, "HTTP_STATUS", un, "non-200"));
        arm(429, "x");
        ASSERT(refused_as(HOST, 1, 0, "RATE_LIMITED", un, "wait a minute"));
        arm(402, "x");
        ASSERT(refused_as(HOST, 1, 0, "PUZZLE_REQUIRED", un, "puzzle"));
        char *huge = sized_body(1048577, "{\"height\":5,\"p\":\"", "\"}");
        ASSERT(huge != NULL);
        arm(200, huge);
        ASSERT(refused_as(HOST, 1, 0, "BODY_TOO_LARGE",
                          ZCL_NATIVE_BODY_PROTOCOL, "fetch ceiling"));
        free(huge);
        onion_remote_status_clear_test_hooks();
        ASSERT(refused_as(HOST, 1, 0, "TOR_UNAVAILABLE", un, "bootstrapped"));
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static bool refuses_bad_body(const char *body, const char *code,
                             const char *detail)
{
    arm(200, body);
    return refused_as(HOST, 1, 0, code, ZCL_NATIVE_BODY_PROTOCOL, detail);
}

static bool accepts_body(const char *body)
{
    arm(200, body);
    struct zcl_native_body_err err = {0};
    char *r = onion_remote_status_run(HOST, 1, 0, &err);
    bool got = r != NULL;
    free(r);
    return got && err.status == ZCL_NATIVE_BODY_OK && err.message[0] == '\0';
}

static int test_body_limits(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: the 4096-byte cap and the height floor are exact") {
        char *edge = sized_body(4096, "{\"height\":5,\"p\":\"", "\"}");
        char *over = sized_body(4097, "{\"height\":5,\"p\":\"", "\"}");
        ASSERT(edge && over);
        ASSERT(accepts_body(edge));
        ASSERT(refuses_bad_body(over, "BODY_TOO_LARGE", "4096 bytes"));
        free(edge);
        free(over);
        ASSERT(refuses_bad_body("", "BAD_JSON", "is empty"));
        ASSERT(refuses_bad_body(NULL, "BAD_JSON", "is empty"));
        ASSERT(refuses_bad_body("x", "BAD_JSON", "not a JSON object"));
        ASSERT(refuses_bad_body("[1]", "BAD_JSON", "not a JSON object"));
        ASSERT(refuses_bad_body("5", "BAD_JSON", "not a JSON object"));
        ASSERT(refuses_bad_body("{\"height\":-1}", "BAD_HEIGHT", "integer"));
        ASSERT(accepts_body("{\"height\":0}"));
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static struct json_value *render(const char *body, int64_t local,
                                 struct json_value *root)
{
    arm(200, body);
    struct zcl_native_body_err err = {0};
    char *r = onion_remote_status_run(HOST, 1, local, &err);
    json_init(root);
    bool ok = r && json_read(root, r, strlen(r));
    free(r);
    return ok ? root : NULL;
}

static bool remote_is_null(const struct json_value *rem, const char *key)
{
    const struct json_value *v = json_get(rem, key);
    return v && v->type == JSON_NULL;
}

static int test_output_shape(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: output fields, nulls and local-height edges") {
        struct json_value root;
        ASSERT(render(OK_BODY, 0, &root));
        const struct json_value *rem = json_get(&root, "remote");
        const struct json_value *tor = json_get(rem, "tor_ready");
        ASSERT(tor && tor->type == JSON_BOOL && json_get_bool(tor));
        const struct json_value *onion = json_get(rem, "onion_service_ready");
        ASSERT(onion && onion->type == JSON_BOOL && !json_get_bool(onion));
        const struct json_value *lh = json_get(&root, "local_height");
        ASSERT(lh && lh->type == JSON_INT && json_get_int(lh) == 0);
        ASSERT_EQ(json_get_int(json_get(&root, "height_delta")), -90);
        ASSERT_STR_EQ(json_get_str(json_get(&root, "onion")), HOST);
        const struct json_value *ms = json_get(&root, "elapsed_ms");
        ASSERT(ms && ms->type == JSON_INT && json_get_int(ms) >= 0);
        json_free(&root);
        ASSERT(render(OK_BODY, -1, &root));
        ASSERT(remote_is_null(&root, "local_height"));
        ASSERT(remote_is_null(&root, "height_delta"));
        json_free(&root);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

static int test_output_types(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: a wrong-typed or missing field becomes null") {
        struct json_value root;
        ASSERT(render("{\"height\":7,\"syncing\":\"yes\",\"peers\":\"4\","
                      "\"tor_ready\":1,\"onion_service_ready\":null,"
                      "\"uptime\":true,\"last_block_age\":\"x\"}", 3, &root));
        const struct json_value *rem = json_get(&root, "remote");
        ASSERT(remote_is_null(rem, "syncing"));
        ASSERT(remote_is_null(rem, "peers_seen_1h"));
        ASSERT(remote_is_null(rem, "tor_ready"));
        ASSERT(remote_is_null(rem, "onion_service_ready"));
        ASSERT(remote_is_null(rem, "uptime"));
        ASSERT(remote_is_null(rem, "last_block_age"));
        ASSERT_EQ(json_get_int(json_get(rem, "height")), 7);
        json_free(&root);
        ASSERT(render("{\"height\":7}", 3, &root));
        rem = json_get(&root, "remote");
        ASSERT(remote_is_null(rem, "syncing"));
        ASSERT(remote_is_null(rem, "uptime"));
        json_free(&root);
    } TEST_END
    onion_remote_status_clear_test_hooks();
    return failures;
}

/* Run check_args on JSON text; true when it answers `want`, writes the
 * expected seconds and carries the expected refusal code. */
static bool args_check(const char *onion_json, const char *timeout_json,
                       bool want, int seconds, const char *code)
{
    struct json_value on, to;
    json_init(&on);
    json_init(&to);
    bool have_to = timeout_json != NULL;
    bool parsed = json_read(&on, onion_json, strlen(onion_json)) &&
                  (!have_to || json_read(&to, timeout_json, strlen(timeout_json)));
    struct zcl_native_body_err err = {0};
    int out = -1;
    bool got = parsed && onion_remote_status_check_args(
                             &on, have_to ? &to : NULL, &out, &err);
    bool good = parsed && got == want;
    good = good && (want ? out == seconds && err.message[0] == '\0'
                         : strncmp(err.message, code, strlen(code)) == 0 &&
                               err.status == ZCL_NATIVE_BODY_INVALID);
    json_free(&on);
    json_free(&to);
    return good;
}

static int test_check_args(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: check_args bounds the timeout and the host") {
        const char *h = "\"" HOST "\"";
        ASSERT(args_check(h, NULL, true, 30, ""));
        ASSERT(args_check(h, "null", true, 30, ""));
        ASSERT(args_check(h, "5", true, 5, ""));
        ASSERT(args_check(h, "60", true, 60, ""));
        ASSERT(args_check(h, "4", false, 0, "BAD_TIMEOUT"));
        ASSERT(args_check(h, "61", false, 0, "BAD_TIMEOUT"));
        ASSERT(args_check(h, "\"9\"", false, 0, "BAD_TIMEOUT"));
        ASSERT(args_check("\"nope.onion\"", NULL, false, 0, "BAD_ONION"));
        ASSERT(args_check("7", NULL, false, 0, "BAD_ONION"));
        struct zcl_native_body_err err = {0};
        int out = 0;
        ASSERT(!onion_remote_status_check_args(NULL, NULL, &out, &err));
        ASSERT(strncmp(err.message, "BAD_ONION:", 10) == 0);
    } TEST_END
    return failures;
}

static const char *g_node_reply;
static int g_node_calls;
static char g_node_method[48];
static char g_node_params[160];

static char *node_hook(const char *method, const char *params_json)
{
    g_node_calls++;
    snprintf(g_node_method, sizeof(g_node_method), "%s", method);
    snprintf(g_node_params, sizeof(g_node_params), "%s", params_json);
    if (!g_node_reply)
        return NULL;
    size_t n = strlen(g_node_reply) + 1;
    char *copy = zcl_malloc(n, "orsreply");
    if (copy)
        memcpy(copy, g_node_reply, n);
    return copy;
}

/* Drive the CLI bridge against a stubbed node answer. Returns the body (or
 * NULL) and fills err. */
static char *bridge(const char *args_json, const char *reply,
                    struct zcl_native_body_err *err)
{
    struct json_value args;
    json_init(&args);
    if (!json_read(&args, args_json, strlen(args_json)))
        return NULL;
    g_node_reply = reply;
    g_node_calls = 0;
    memset(err, 0, sizeof(*err));
    node_rpc_client_set_test_hook(node_hook);
    char *r = zcl_native_onion_remote_status_body(&args, err);
    node_rpc_client_set_test_hook(NULL);
    json_free(&args);
    return r;
}

#define BRIDGE_ARGS "{\"onion\":\"" HOST "\"}"

/* The node refused with `reply`: no body, `status`, and the message verbatim. */
static bool bridge_refused(const char *reply, enum zcl_native_body_status status,
                           const char *message)
{
    struct zcl_native_body_err err;
    char *r = bridge(BRIDGE_ARGS, reply, &err);
    bool none = r == NULL;
    free(r);
    return none && err.status == status && strcmp(err.message, message) == 0;
}

/* The node answered with a document that is not a refusal: passed through. */
static bool bridge_passes(const char *reply)
{
    struct zcl_native_body_err err;
    char *r = bridge(BRIDGE_ARGS, reply, &err);
    bool same = r && strcmp(r, reply) == 0 && err.message[0] == '\0';
    free(r);
    return same;
}

static int test_bridge_calls(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: the bridge sends the exact node call") {
        struct zcl_native_body_err err;
        char *r = bridge("{\"onion\":\"" HOST "\",\"timeout_secs\":9}",
                         "{\"ok\":1}", &err);
        ASSERT(r != NULL);
        free(r);
        ASSERT_EQ(g_node_calls, 1);
        ASSERT_STR_EQ(g_node_method, "onionremotestatus");
        ASSERT_STR_EQ(g_node_params, "[\"" HOST "\",9]");
        r = bridge(BRIDGE_ARGS, "{\"ok\":1}", &err);
        ASSERT(r != NULL);
        free(r);
        ASSERT_STR_EQ(g_node_params, "[\"" HOST "\",30]");
        r = bridge("{\"onion\":\"bad.onion\"}", "{\"ok\":1}", &err);
        ASSERT(r == NULL && g_node_calls == 0);
        ASSERT_EQ(err.status, ZCL_NATIVE_BODY_INVALID);
        ASSERT(strncmp(err.message, "BAD_ONION:", 10) == 0);
        r = bridge("{\"onion\":\"" HOST "\",\"timeout_secs\":3}",
                   "{\"ok\":1}", &err);
        ASSERT(r == NULL && g_node_calls == 0);
        ASSERT(strncmp(err.message, "BAD_TIMEOUT:", 12) == 0);
    } TEST_END
    return failures;
}

static int test_bridge_unwrap(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: the bridge maps node refusals to typed classes") {
        const enum zcl_native_body_status un = ZCL_NATIVE_BODY_UNAVAILABLE;
        const enum zcl_native_body_status pr = ZCL_NATIVE_BODY_PROTOCOL;
        const enum zcl_native_body_status in = ZCL_NATIVE_BODY_INVALID;
        const enum zcl_native_body_status it = ZCL_NATIVE_BODY_INTERNAL;
        ASSERT(bridge_refused(NULL, un, "NODE_UNAVAILABLE: no answer from the "
                                        "node; check core status"));
        ASSERT(bridge_refused("not json", it, "INTERNAL: the node returned an "
                                              "unreadable reply; retry"));
        ASSERT(bridge_refused("[1,2]", it, "INTERNAL: the node returned an "
                                           "unreadable reply; retry"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"BAD_ONION: a\"}",
                              in, "BAD_ONION: a"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"BAD_TIMEOUT: b\"}",
                              in, "BAD_TIMEOUT: b"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"BODY_TOO_LARGE: c\"}",
                              pr, "BODY_TOO_LARGE: c"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"BAD_JSON: d\"}",
                              pr, "BAD_JSON: d"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"BAD_HEIGHT: e\"}",
                              pr, "BAD_HEIGHT: e"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"INTERNAL: f\"}",
                              it, "INTERNAL: f"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"BUSY: g\"}",
                              un, "BUSY: g"));
        ASSERT(bridge_refused("{\"code\":-1,\"message\":\"xBAD_ONION: h\"}",
                              un, "xBAD_ONION: h"));
        ASSERT(bridge_refused("{\"error\":{\"message\":\"BAD_HEIGHT: z\"}}",
                              pr, "BAD_HEIGHT: z"));
    } TEST_END
    return failures;
}

static int test_bridge_passthrough(void)
{
    int failures = 0;
    TEST_CASE("onion_remote_status: only a real refusal shape is a refusal") {
        ASSERT(bridge_passes("{\"schema\":\"zcl.onion_remote_status.v1\"}"));
        ASSERT(bridge_passes("{\"error\":\"str\",\"height\":1}"));
        ASSERT(bridge_passes("{\"code\":5}"));
        ASSERT(bridge_passes("{\"message\":\"m\"}"));
        ASSERT(bridge_passes("{\"code\":\"5\",\"message\":\"m\"}"));
        ASSERT(bridge_passes("{\"code\":5,\"message\":7}"));
    } TEST_END
    return failures;
}

static int test_mutation_gaps(void)
{
    int failures = 0;
    failures += test_fetch_classes();
    failures += test_body_limits();
    failures += test_output_shape();
    failures += test_output_types();
    failures += test_check_args();
    failures += test_bridge_calls();
    failures += test_bridge_unwrap();
    failures += test_bridge_passthrough();
    return failures;
}

int test_onion_remote_status(void)
{
    int failures = 0;
    printf("onion_remote_status...\n");
    failures += test_success();
    failures += test_body_refusals();
    failures += test_transport_refusals();
    failures += test_bad_onions();
    failures += test_busy();
    failures += test_rpc_registered();
    failures += test_rpc_success();
    failures += test_rpc_refusals();
    failures += test_rpc_busy();
    failures += test_registry();
    failures += test_mutation_gaps();
    return failures;
}
