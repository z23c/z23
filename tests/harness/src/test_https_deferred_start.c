/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_https_deferred_start: the engine-owned deferred HTTPS start keeps the
 * configured ports. The start call is injected, so no socket is bound.
 * Precondition: no HTTPS server is running in this test process. */

#include "test/test_core.h"
#include "services/https_deferred_start.h"

#include <stdio.h>
#include <string.h>

static int g_starts;
static char g_cert[1024];
static char g_key[1024];
static char g_host[256];
static int g_https_port;
static int g_http_port;

static bool record_start(const char *cert, const char *key, const char *host,
                         int https_port, int http_port)
{
    g_starts++;
    snprintf(g_cert, sizeof(g_cert), "%s", cert);
    snprintf(g_key, sizeof(g_key), "%s", key);
    snprintf(g_host, sizeof(g_host), "%s", host ? host : "");
    g_https_port = https_port;
    g_http_port = http_port;
    return true;
}

/* The query always reports through its result; a failed query reads as not
 * pending, the safe default. */
static bool pending_now(void)
{
    bool pending = false;
    struct zcl_result q = https_deferred_start_pending(&pending);
    return q.ok && pending;
}

/* Each case is its own function: TEST_CASE labels are function-scoped. */
static int case_set_keeps_ports_pending(void)
{
    int failures = 0;

    TEST_CASE("https_deferred_start: set keeps custom ports pending")
    {
        ASSERT(https_deferred_start_set("/d/fullchain.pem", "/d/privkey.pem",
                                        "node.example", 18443, 18080).ok);
        ASSERT(pending_now());
        ASSERT_EQ(g_starts, 0);
    }
    TEST_END
    return failures;
}

static int case_bad_ports_refused(void)
{
    int failures = 0;

    TEST_CASE("https_deferred_start: bad ports are refused and not queued")
    {
        /* Drain the start case 1 queued, so refusals begin from "not pending". */
        https_deferred_start_check();
        ASSERT_EQ(g_starts, 1);
        struct zcl_result refused_zero =
            https_deferred_start_set("/d/fullchain.pem", "/d/privkey.pem",
                                     "node.example", 0, 18080);
        ASSERT(!refused_zero.ok);
        ASSERT(refused_zero.message[0] != '\0');
        ASSERT(!pending_now());
        ASSERT(!https_deferred_start_set("/d/fullchain.pem", "/d/privkey.pem",
                                         "node.example", 18443, 70000).ok);
        ASSERT(!pending_now());
        /* A missing path, or one too long to keep whole, is refused too:
         * a truncated certificate path would start on the wrong file. */
        ASSERT(!https_deferred_start_set(NULL, "/d/privkey.pem",
                                         "node.example", 18443, 18080).ok);
        ASSERT(!pending_now());
        static char long_path[1100];
        memset(long_path, 'p', sizeof(long_path) - 1u);
        long_path[0] = '/';
        ASSERT(!https_deferred_start_set(long_path, "/d/privkey.pem",
                                         "node.example", 18443, 18080).ok);
        ASSERT(!pending_now());
        https_deferred_start_check();
        ASSERT_EQ(g_starts, 1);
    }
    TEST_END
    return failures;
}

static int case_check_uses_stored_ports(void)
{
    int failures = 0;

    TEST_CASE("https_deferred_start: check starts with the stored ports")
    {
        ASSERT(https_deferred_start_set("/d/fullchain.pem", "/d/privkey.pem",
                                        "node.example", 18443, 18080).ok);
        https_deferred_start_check();
        ASSERT_EQ(g_starts, 2);
        ASSERT(strcmp(g_cert, "/d/fullchain.pem") == 0);
        ASSERT(strcmp(g_key, "/d/privkey.pem") == 0);
        ASSERT(strcmp(g_host, "node.example") == 0);
        ASSERT_EQ(g_https_port, 18443);
        ASSERT_EQ(g_http_port, 18080);
        ASSERT(!pending_now());
    }
    TEST_END
    return failures;
}

static int case_check_when_not_pending(void)
{
    int failures = 0;

    TEST_CASE("https_deferred_start: check when not pending does nothing")
    {
        https_deferred_start_check();
        ASSERT_EQ(g_starts, 2);
    }
    TEST_END
    return failures;
}

static int case_second_check_no_double_start(void)
{
    int failures = 0;

    TEST_CASE("https_deferred_start: a second check does not start twice")
    {
        ASSERT(https_deferred_start_set("/d/fullchain.pem", "/d/privkey.pem",
                                        "node.example", 19443, 19080).ok);
        https_deferred_start_check();
        https_deferred_start_check();
        ASSERT_EQ(g_starts, 3);
        ASSERT_EQ(g_https_port, 19443);
    }
    TEST_END
    return failures;
}

int test_https_deferred_start(void)
{
    int failures = 0;

    https_deferred_start_set_starter_for_testing(record_start);
    g_starts = 0;

    /* Drain any queued state so the cases start from "not pending". */
    https_deferred_start_check();

    failures += case_set_keeps_ports_pending();
    failures += case_bad_ports_refused();
    failures += case_check_uses_stored_ports();
    failures += case_check_when_not_pending();
    failures += case_second_check_no_double_start();

    https_deferred_start_set_starter_for_testing(NULL);
    return failures;
}
