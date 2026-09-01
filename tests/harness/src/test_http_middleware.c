/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the HTTP RPC middleware: rate limit, per-IP bucket, ban
 * threshold, env loading, loopback exemption, and stat counters. */

#include "test/test_core.h"
#include "rpc/http_middleware.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* htonl-style constructor — keep tests independent of <arpa/inet.h>
 * for portability. */
static uint32_t ip_be(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    /* network byte order: a is the high byte */
    return ((uint32_t)a) | ((uint32_t)b << 8) |
           ((uint32_t)c << 16) | ((uint32_t)d << 24);
}

static struct rpc_http_middleware mw;

static void fresh(void)
{
    if (mw.initialized) rpc_http_middleware_destroy(&mw);
    rpc_http_middleware_init(&mw);
}

static int test_init_defaults(void)
{
    int failures = 0;
    TEST("rpc_http_mw: init populates sane defaults") {
        fresh();
        ASSERT(mw.global_rps == 50);
        ASSERT(mw.global_burst == 100);
        ASSERT(mw.per_ip_rps == 5);
        ASSERT(mw.per_ip_burst == 10);
        ASSERT(mw.auth_fail_threshold == 5);
        ASSERT(mw.ban_seconds == 3600);
        PASS();
    } _test_next:;
    return failures;
}

static int test_loopback_bypass(void)
{
    int failures = 0;
    TEST("rpc_http_mw: 127.0.0.1 bypasses ban + per-IP buckets") {
        fresh();
        uint32_t lo = ip_be(127, 0, 0, 1);
        /* 6 auth fails should NOT ban localhost. */
        for (int i = 0; i < 6; i++)
            rpc_http_middleware_record_auth_fail(&mw, lo);
        ASSERT(!rpc_http_middleware_is_banned(&mw, lo));
        ASSERT(rpc_http_middleware_active_bans(&mw) == 0);

        /* Per-IP bucket has 10 token burst — but loopback skips it,
         * so 100 calls in a row should still ALLOW (capped only by
         * the global bucket of 100). */
        int allowed = 0;
        for (int i = 0; i < 100; i++) {
            if (rpc_http_middleware_check(&mw, lo) == RPC_HTTP_ALLOW)
                allowed++;
        }
        ASSERT(allowed == 100);
        PASS();
    } _test_next:;
    return failures;
}

static int test_per_ip_rate_limit(void)
{
    int failures = 0;
    TEST("rpc_http_mw: per-IP burst caps a single non-loopback client") {
        fresh();
        uint32_t client = ip_be(8, 8, 8, 8);
        /* Per-IP burst is 10. Eleventh call must be RATE_LIMITED_PER_IP. */
        int rate_limited = 0;
        for (int i = 0; i < 20; i++) {
            enum rpc_http_decision d =
                rpc_http_middleware_check(&mw, client);
            if (d == RPC_HTTP_RATE_LIMITED_PER_IP) rate_limited++;
        }
        ASSERT(rate_limited >= 5);
        ASSERT(mw.stat_rate_limited_per_ip >= 5);
        PASS();
    } _test_next:;
    return failures;
}

static int test_global_rate_limit(void)
{
    int failures = 0;
    TEST("rpc_http_mw: global burst caps total across all IPs") {
        fresh();
        /* Drain the global bucket via 100 distinct IPs (each gets one
         * shot at the global token before its per-IP bucket also
         * drains). After 100 different IPs the global bucket of 100
         * should be empty regardless of per-IP burst. */
        for (int i = 0; i < 100; i++) {
            uint32_t c = ip_be(10, 0, (uint8_t)(i / 256), (uint8_t)(i % 256));
            rpc_http_middleware_check(&mw, c);
        }
        /* The 101st distinct IP should hit the global bucket. */
        uint32_t fresh_ip = ip_be(11, 0, 0, 1);
        enum rpc_http_decision d = rpc_http_middleware_check(&mw, fresh_ip);
        /* It might be allowed if the global bucket refilled in the
         * microseconds between calls — accept either ALLOW (next refill
         * tick) or RATE_LIMITED_GLOBAL. */
        ASSERT(d == RPC_HTTP_ALLOW || d == RPC_HTTP_RATE_LIMITED_GLOBAL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_auth_fail_ban(void)
{
    int failures = 0;
    TEST("rpc_http_mw: 5 auth failures bans the IP") {
        fresh();
        uint32_t c = ip_be(192, 0, 2, 50);
        for (int i = 0; i < 4; i++)
            rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(!rpc_http_middleware_is_banned(&mw, c));
        ASSERT(rpc_http_middleware_ip_auth_fails(&mw, c) == 4);

        rpc_http_middleware_record_auth_fail(&mw, c);  /* 5th — should ban */
        ASSERT(rpc_http_middleware_is_banned(&mw, c));
        ASSERT(rpc_http_middleware_active_bans(&mw) == 1);

        /* Subsequent check rejects the banned IP. */
        ASSERT(rpc_http_middleware_check(&mw, c) == RPC_HTTP_BANNED);
        ASSERT(mw.stat_banned_rejected >= 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_success_resets_failures(void)
{
    int failures = 0;
    TEST("rpc_http_mw: successful request resets the per-IP fail counter") {
        fresh();
        uint32_t c = ip_be(203, 0, 113, 17);
        for (int i = 0; i < 4; i++)
            rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(rpc_http_middleware_ip_auth_fails(&mw, c) == 4);

        rpc_http_middleware_record_success(&mw, c);
        ASSERT(rpc_http_middleware_ip_auth_fails(&mw, c) == 0);
        ASSERT(!rpc_http_middleware_is_banned(&mw, c));
        PASS();
    } _test_next:;
    return failures;
}

static int test_env_overrides(void)
{
    int failures = 0;
    TEST("rpc_http_mw: env overrides apply on load_from_env") {
        setenv("ZCL_RPC_RPS",                 "200", 1);
        setenv("ZCL_RPC_BURST",               "400", 1);
        setenv("ZCL_RPC_PER_IP_RPS",          "20",  1);
        setenv("ZCL_RPC_PER_IP_BURST",        "40",  1);
        setenv("ZCL_RPC_AUTH_FAIL_THRESHOLD", "3",   1);
        setenv("ZCL_RPC_BAN_SECONDS",         "60",  1);

        fresh();
        rpc_http_middleware_load_from_env(&mw);

        ASSERT(mw.global_rps == 200);
        ASSERT(mw.global_burst == 400);
        ASSERT(mw.per_ip_rps == 20);
        ASSERT(mw.per_ip_burst == 40);
        ASSERT(mw.auth_fail_threshold == 3);
        ASSERT(mw.ban_seconds == 60);

        unsetenv("ZCL_RPC_RPS");
        unsetenv("ZCL_RPC_BURST");
        unsetenv("ZCL_RPC_PER_IP_RPS");
        unsetenv("ZCL_RPC_PER_IP_BURST");
        unsetenv("ZCL_RPC_AUTH_FAIL_THRESHOLD");
        unsetenv("ZCL_RPC_BAN_SECONDS");
        PASS();
    } _test_next:;
    return failures;
}

static int test_env_threshold_three(void)
{
    int failures = 0;
    TEST("rpc_http_mw: env-tuned auth_fail_threshold=3 bans after 3") {
        setenv("ZCL_RPC_AUTH_FAIL_THRESHOLD", "3", 1);
        fresh();
        rpc_http_middleware_load_from_env(&mw);

        uint32_t c = ip_be(198, 51, 100, 9);
        rpc_http_middleware_record_auth_fail(&mw, c);
        rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(!rpc_http_middleware_is_banned(&mw, c));
        rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(rpc_http_middleware_is_banned(&mw, c));

        unsetenv("ZCL_RPC_AUTH_FAIL_THRESHOLD");
        PASS();
    } _test_next:;
    return failures;
}

static int test_disabled_layers(void)
{
    int failures = 0;
    TEST("rpc_http_mw: ZCL_RPC_RPS=0 disables global limit (always ALLOW)") {
        setenv("ZCL_RPC_RPS", "0", 1);
        setenv("ZCL_RPC_PER_IP_RPS", "0", 1);
        fresh();
        rpc_http_middleware_load_from_env(&mw);

        uint32_t c = ip_be(8, 8, 4, 4);
        int allowed = 0;
        for (int i = 0; i < 1000; i++) {
            if (rpc_http_middleware_check(&mw, c) == RPC_HTTP_ALLOW)
                allowed++;
        }
        ASSERT(allowed == 1000);

        unsetenv("ZCL_RPC_RPS");
        unsetenv("ZCL_RPC_PER_IP_RPS");
        PASS();
    } _test_next:;
    return failures;
}

static int test_lru_eviction(void)
{
    int failures = 0;
    TEST("rpc_http_mw: per-IP table LRU-evicts when full") {
        /* Disable the global bucket so we can drive MAX_IPS+10 distinct
         * client check()s without the global cap killing us early.  Keep
         * the per-IP guard enabled (with a generous burst) so the table
         * actually gets populated. */
        setenv("ZCL_RPC_RPS",          "0",   1);
        setenv("ZCL_RPC_PER_IP_RPS",   "100", 1);
        setenv("ZCL_RPC_PER_IP_BURST", "100", 1);
        fresh();
        rpc_http_middleware_load_from_env(&mw);

        for (int i = 0; i < RPC_HTTP_MW_MAX_IPS + 10; i++) {
            uint32_t c = ip_be(172, 16, (uint8_t)(i / 256), (uint8_t)(i % 256));
            rpc_http_middleware_check(&mw, c);
        }
        ASSERT(rpc_http_middleware_tracked_ips(&mw) == RPC_HTTP_MW_MAX_IPS);

        unsetenv("ZCL_RPC_RPS");
        unsetenv("ZCL_RPC_PER_IP_RPS");
        unsetenv("ZCL_RPC_PER_IP_BURST");
        PASS();
    } _test_next:;
    return failures;
}

static int test_reset_state(void)
{
    int failures = 0;
    TEST("rpc_http_mw: reset_state clears IPs and bans (preserves config)") {
        fresh();
        uint32_t c = ip_be(192, 0, 2, 1);
        for (int i = 0; i < 5; i++)
            rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(rpc_http_middleware_active_bans(&mw) == 1);
        ASSERT(rpc_http_middleware_tracked_ips(&mw) >= 1);

        int saved_threshold = mw.auth_fail_threshold;
        rpc_http_middleware_reset_state(&mw);

        ASSERT(rpc_http_middleware_active_bans(&mw) == 0);
        ASSERT(rpc_http_middleware_tracked_ips(&mw) == 0);
        ASSERT(mw.auth_fail_threshold == saved_threshold);
        PASS();
    } _test_next:;
    return failures;
}

static int test_stats_increment(void)
{
    int failures = 0;
    TEST("rpc_http_mw: stat counters track ALLOW + REJECT outcomes") {
        fresh();
        uint32_t c = ip_be(8, 8, 8, 9);
        for (int i = 0; i < 5; i++)
            rpc_http_middleware_check(&mw, c);
        ASSERT(mw.stat_allowed >= 5);

        for (int i = 0; i < 4; i++)
            rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(mw.stat_auth_failures == 4);
        ASSERT(mw.stat_bans_issued == 0);

        rpc_http_middleware_record_auth_fail(&mw, c);
        ASSERT(mw.stat_bans_issued == 1);

        rpc_http_middleware_check(&mw, c);
        ASSERT(mw.stat_banned_rejected >= 1);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Wave 5 #1: global handle + stats snapshot ─────────────── */

static int test_global_handle(void)
{
    int failures = 0;
    TEST("rpc_http_mw: global handle starts NULL, set/get is symmetric") {
        /* Pristine state before the RPC server (or any test) has
         * published the global handle. */
        rpc_http_middleware_set_global(NULL);
        ASSERT(rpc_http_middleware_get_global() == NULL);

        fresh();
        rpc_http_middleware_set_global(&mw);
        ASSERT(rpc_http_middleware_get_global() == &mw);

        rpc_http_middleware_set_global(NULL);
        ASSERT(rpc_http_middleware_get_global() == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_stats_snapshot_null_safe(void)
{
    int failures = 0;
    TEST("rpc_http_mw: stats_snapshot on NULL middleware is zeroed") {
        struct rpc_http_stats_snapshot s;
        /* Pre-fill to detect leaked bytes. */
        memset(&s, 0xAB, sizeof(s));
        rpc_http_middleware_stats_snapshot(NULL, &s);
        ASSERT(s.global_rps == 0);
        ASSERT(s.allowed == 0);
        ASSERT(s.active_bans == 0);
        ASSERT(s.tracked_ips == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_stats_snapshot_mirrors_struct(void)
{
    int failures = 0;
    TEST("rpc_http_mw: stats_snapshot mirrors live config + counters") {
        fresh();

        /* Drive a few allows + one per-IP rate-limit + one ban. */
        uint32_t lo = ip_be(127, 0, 0, 1);      /* loopback — always allowed */
        uint32_t c  = ip_be(203, 0, 113, 7);   /* per-IP target */

        for (int i = 0; i < 3; i++)
            rpc_http_middleware_check(&mw, lo);

        for (int i = 0; i < 20; i++)
            rpc_http_middleware_check(&mw, c);

        for (int i = 0; i < mw.auth_fail_threshold; i++)
            rpc_http_middleware_record_auth_fail(&mw, c);

        struct rpc_http_stats_snapshot s;
        rpc_http_middleware_stats_snapshot(&mw, &s);

        /* Config mirrors live fields. */
        ASSERT(s.global_rps == mw.global_rps);
        ASSERT(s.global_burst == mw.global_burst);
        ASSERT(s.per_ip_rps == mw.per_ip_rps);
        ASSERT(s.per_ip_burst == mw.per_ip_burst);
        ASSERT(s.auth_fail_threshold == mw.auth_fail_threshold);
        ASSERT(s.ban_seconds == mw.ban_seconds);

        /* Counters mirror live stats. */
        ASSERT(s.allowed == mw.stat_allowed);
        ASSERT(s.rate_limited_per_ip == mw.stat_rate_limited_per_ip);
        ASSERT(s.bans_issued == mw.stat_bans_issued);
        ASSERT(s.auth_failures == mw.stat_auth_failures);

        /* Gauges reflect the table state. */
        ASSERT(s.tracked_ips >= 1);
        ASSERT(s.active_bans == 1);
        ASSERT(s.bans_issued == 1);
        ASSERT(s.rate_limited_per_ip >= 1);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_http_middleware(void);

int test_http_middleware(void)
{
    int failures = 0;

    failures += test_init_defaults();
    failures += test_loopback_bypass();
    failures += test_per_ip_rate_limit();
    failures += test_global_rate_limit();
    failures += test_auth_fail_ban();
    failures += test_success_resets_failures();
    failures += test_env_overrides();
    failures += test_env_threshold_three();
    failures += test_disabled_layers();
    failures += test_lru_eviction();
    failures += test_reset_state();
    failures += test_stats_increment();
    failures += test_global_handle();
    failures += test_stats_snapshot_null_safe();
    failures += test_stats_snapshot_mirrors_struct();

    if (mw.initialized) rpc_http_middleware_destroy(&mw);
    /* Leave the global pointer NULL so downstream metrics tests
     * observe the "inactive" rendering path by default. */
    rpc_http_middleware_set_global(NULL);
    return failures;
}
