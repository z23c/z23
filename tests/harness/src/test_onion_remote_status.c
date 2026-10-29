/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_onion_remote_status: core.network.onion.remote-status through the
 * tor_integration_fetch_onion_blocking_for_test seam. No Tor, no network: an
 * injected dispatcher answers (or refuses, or stays silent) and the typed
 * result or refusal is read back. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "controllers/onion_remote_status.h"
#include "json/json.h"
#include "kernel/command_registry.h"
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
    if (!g_silent)
        cb(g_status, (const uint8_t *)g_body, g_body ? strlen(g_body) : 0, ctx);
    return 0;
}

static void arm(int status, const char *body)
{
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
    TEST_CASE("onion_remote_status: timeout, dial refusal, Tor down") {
        arm(200, OK_BODY);
        g_silent = true;
        ASSERT(refused_with(HOST, 1, "TIMEOUT"));
        ASSERT_EQ(g_calls, 1);
        arm(200, OK_BODY);
        g_dispatch_rc = -1;
        ASSERT(refused_with(HOST, 1, "TOR_UNAVAILABLE"));
        arm(200, OK_BODY);
        onion_remote_status_set_test_hooks(fake_dispatch, false);
        ASSERT(refused_with(HOST, 1, "TOR_UNAVAILABLE"));
        ASSERT_EQ(g_calls, 0);
    } TEST_END
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

int test_onion_remote_status(void)
{
    int failures = 0;
    printf("onion_remote_status...\n");
    failures += test_success();
    failures += test_body_refusals();
    failures += test_transport_refusals();
    failures += test_bad_onions();
    failures += test_busy();
    failures += test_registry();
    return failures;
}
