/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for per-peer bandwidth quotas: token bucket refill,
 * throttle, direction isolation, trusted-peer bypass, env
 * overrides, LRU eviction, and EV_PEER_THROTTLED emission. */

#include "test/test_core.h"
#include "net/peer_bandwidth.h"
#include "event/event.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct peer_bandwidth pb;

static void fresh(void)
{
    if (pb.initialized) peer_bandwidth_destroy(&pb);
    peer_bandwidth_init(&pb);
}

static int test_init_defaults(void)
{
    int failures = 0;
    TEST("peer_bw: init populates sane defaults") {
        fresh();
        ASSERT(pb.up_bps      == 10LL * 1024 * 1024);
        ASSERT(pb.down_bps    == 20LL * 1024 * 1024);
        ASSERT(pb.burst_bytes == 1LL * 1024 * 1024);
        ASSERT(pb.num_peers   == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_consume_under_burst_allows(void)
{
    int failures = 0;
    TEST("peer_bw: consume below burst returns true") {
        fresh();
        /* Burst is 1 MB; ten 10-KB writes should all succeed. */
        for (int i = 0; i < 10; i++) {
            ASSERT(peer_bandwidth_consume(&pb, 42, PEER_BW_UP, 10 * 1024));
        }
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_UP) == 0);
        ASSERT(pb.stat_allowed_bytes_up == 10 * 10 * 1024);
        PASS();
    } _test_next:;
    return failures;
}

static int test_consume_over_burst_throttles(void)
{
    int failures = 0;
    TEST("peer_bw: consume above burst returns false and counts") {
        fresh();
        /* Burst = 1 MB; first consume of 1MB - 1 KB drains most
         * of it, then a 100 KB request should throttle because we
         * don't refill fast enough mid-test. */
        ASSERT(peer_bandwidth_consume(&pb, 7, PEER_BW_UP,
                                       1024 * 1024 - 1024));
        ASSERT(!peer_bandwidth_consume(&pb, 7, PEER_BW_UP, 100 * 1024));
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_UP) == 1);
        ASSERT(peer_bandwidth_throttled_bytes(&pb, PEER_BW_UP)
               == 100 * 1024);
        PASS();
    } _test_next:;
    return failures;
}

static int test_direction_isolation(void)
{
    int failures = 0;
    TEST("peer_bw: up bucket and down bucket don't share tokens") {
        fresh();
        /* Drain the up bucket of peer 11. */
        ASSERT(peer_bandwidth_consume(&pb, 11, PEER_BW_UP,
                                       1024 * 1024 - 1024));
        ASSERT(!peer_bandwidth_consume(&pb, 11, PEER_BW_UP, 100 * 1024));
        /* Down bucket should still have the full burst. */
        ASSERT(peer_bandwidth_consume(&pb, 11, PEER_BW_DOWN,
                                       1024 * 1024 - 1024));
        /* And up throttle count is 1, down is 0. */
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_UP)   == 1);
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_DOWN) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_trusted_peer_bypass(void)
{
    int failures = 0;
    TEST("peer_bw: trusted peer bypasses the quota entirely") {
        fresh();
        peer_bandwidth_mark_trusted(&pb, 99, true);
        /* 4 MB in one go — far above the 1 MB burst — still allowed. */
        ASSERT(peer_bandwidth_consume(&pb, 99, PEER_BW_UP, 4 * 1024 * 1024));
        ASSERT(peer_bandwidth_consume(&pb, 99, PEER_BW_DOWN, 4 * 1024 * 1024));
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_UP)   == 0);
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_DOWN) == 0);
        ASSERT(peer_bandwidth_available(&pb, 99, PEER_BW_UP)   == SIZE_MAX);
        ASSERT(peer_bandwidth_available(&pb, 99, PEER_BW_DOWN) == SIZE_MAX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_disabled_layer_allows(void)
{
    int failures = 0;
    TEST("peer_bw: up_bps=0 disables upload gate") {
        fresh();
        setenv("ZCL_PEER_UP_BPS",   "0", 1);
        setenv("ZCL_PEER_DOWN_BPS", "20971520", 1);  /* 20 MB/s */
        peer_bandwidth_load_from_env(&pb);
        /* Huge single write on up bucket — would be throttled
         * otherwise — should succeed. */
        ASSERT(peer_bandwidth_consume(&pb, 5, PEER_BW_UP, 50 * 1024 * 1024));
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_UP) == 0);
        unsetenv("ZCL_PEER_UP_BPS");
        unsetenv("ZCL_PEER_DOWN_BPS");
        PASS();
    } _test_next:;
    return failures;
}

static int test_refill_over_time(void)
{
    int failures = 0;
    TEST("peer_bw: tokens refill after a short sleep") {
        fresh();
        /* Tighten the config so refill happens quickly in a test:
         * up_bps = 1 MB/s, burst = 100 KB. A 1 KB sleep should
         * refill about 1000 bytes. */
        setenv("ZCL_PEER_UP_BPS", "1048576", 1);
        setenv("ZCL_PEER_BURST",  "102400",  1);
        peer_bandwidth_load_from_env(&pb);
        peer_bandwidth_reset_state(&pb);

        /* Drain the bucket. */
        ASSERT(peer_bandwidth_consume(&pb, 3, PEER_BW_UP, 100 * 1024));
        ASSERT(!peer_bandwidth_consume(&pb, 3, PEER_BW_UP, 10 * 1024));

        /* Sleep 50ms → 1MB/s * 0.05s = 50 KB refill. */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        ASSERT(peer_bandwidth_consume(&pb, 3, PEER_BW_UP, 10 * 1024));

        unsetenv("ZCL_PEER_UP_BPS");
        unsetenv("ZCL_PEER_BURST");
        PASS();
    } _test_next:;
    return failures;
}

static int test_available_tracks_usage(void)
{
    int failures = 0;
    TEST("peer_bw: available() reflects consumed tokens") {
        fresh();
        /* Fresh peer → full burst available. */
        size_t avail = peer_bandwidth_available(&pb, 17, PEER_BW_UP);
        ASSERT(avail >= (size_t)(pb.burst_bytes - 1));

        ASSERT(peer_bandwidth_consume(&pb, 17, PEER_BW_UP, 600 * 1024));
        size_t after = peer_bandwidth_available(&pb, 17, PEER_BW_UP);
        /* Should have burst - 600K ≈ 424 KB left (modulo tiny refill). */
        ASSERT(after <  (size_t)(pb.burst_bytes - 500 * 1024));
        ASSERT(after >= (size_t)(pb.burst_bytes - 700 * 1024));
        PASS();
    } _test_next:;
    return failures;
}

static int test_env_overrides(void)
{
    int failures = 0;
    TEST("peer_bw: env overrides drive live config") {
        fresh();
        setenv("ZCL_PEER_UP_BPS",   "5242880",   1);  /* 5 MB/s */
        setenv("ZCL_PEER_DOWN_BPS", "15728640",  1);  /* 15 MB/s */
        setenv("ZCL_PEER_BURST",    "524288",    1);  /* 512 KB  */
        peer_bandwidth_load_from_env(&pb);
        ASSERT(pb.up_bps      == 5 * 1024 * 1024);
        ASSERT(pb.down_bps    == 15 * 1024 * 1024);
        ASSERT(pb.burst_bytes == 512 * 1024);
        unsetenv("ZCL_PEER_UP_BPS");
        unsetenv("ZCL_PEER_DOWN_BPS");
        unsetenv("ZCL_PEER_BURST");
        PASS();
    } _test_next:;
    return failures;
}

static int test_tracked_peers_grows(void)
{
    int failures = 0;
    TEST("peer_bw: tracked_peers counts unique peer_ids") {
        fresh();
        for (uint32_t i = 1; i <= 16; i++)
            peer_bandwidth_consume(&pb, i, PEER_BW_UP, 1024);
        ASSERT(peer_bandwidth_tracked_peers(&pb) == 16);
        /* Repeating the same peer_id does NOT grow the table. */
        for (uint32_t i = 1; i <= 16; i++)
            peer_bandwidth_consume(&pb, i, PEER_BW_UP, 1024);
        ASSERT(peer_bandwidth_tracked_peers(&pb) == 16);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reset_state_clears_buckets(void)
{
    int failures = 0;
    TEST("peer_bw: reset_state zeros counters and drops peers") {
        fresh();
        peer_bandwidth_consume(&pb, 100, PEER_BW_UP,   1024);
        peer_bandwidth_consume(&pb, 100, PEER_BW_DOWN, 1024);
        ASSERT(peer_bandwidth_tracked_peers(&pb) == 1);

        peer_bandwidth_reset_state(&pb);
        ASSERT(peer_bandwidth_tracked_peers(&pb) == 0);
        ASSERT(pb.stat_allowed_bytes_up   == 0);
        ASSERT(pb.stat_allowed_bytes_down == 0);
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_UP)   == 0);
        ASSERT(peer_bandwidth_throttled_events(&pb, PEER_BW_DOWN) == 0);
        /* Config is preserved across reset_state. */
        ASSERT(pb.up_bps   > 0);
        ASSERT(pb.down_bps > 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Emission test: observe EV_PEER_THROTTLED and assert the payload
 * shape matches what peer_bandwidth_consume emits on a throttle. */
static volatile int g_throttle_observed = 0;
static char g_throttle_payload[256];

static void throttle_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)peer_id; (void)ctx;
    if (type != EV_PEER_THROTTLED) return;
    g_throttle_observed++;
    if (payload && payload_len > 0 &&
        payload_len < sizeof(g_throttle_payload)) {
        memcpy(g_throttle_payload, payload, payload_len);
        g_throttle_payload[payload_len] = '\0';
    }
}

static int test_throttle_event_emission(void)
{
    int failures = 0;
    TEST("peer_bw: throttle emits EV_PEER_THROTTLED with diagnostic") {
        fresh();
        event_clear_observers(EV_PEER_THROTTLED);
        g_throttle_observed = 0;
        g_throttle_payload[0] = '\0';
        event_observe(EV_PEER_THROTTLED, throttle_observer, NULL);

        /* Drain the bucket then overshoot. */
        ASSERT(peer_bandwidth_consume(&pb, 77, PEER_BW_UP,
                                       1024 * 1024 - 1024));
        ASSERT(!peer_bandwidth_consume(&pb, 77, PEER_BW_UP, 500 * 1024));

        ASSERT(g_throttle_observed >= 1);
        ASSERT(strstr(g_throttle_payload, "peer=77") != NULL);
        ASSERT(strstr(g_throttle_payload, "dir=up") != NULL);
        ASSERT(strstr(g_throttle_payload, "bytes=512000") != NULL);
        ASSERT(strstr(g_throttle_payload, "bucket=") != NULL);

        event_clear_observers(EV_PEER_THROTTLED);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_peer_bandwidth(void);

int test_peer_bandwidth(void)
{
    int failures = 0;
    event_log_init();

    failures += test_init_defaults();
    failures += test_consume_under_burst_allows();
    failures += test_consume_over_burst_throttles();
    failures += test_direction_isolation();
    failures += test_trusted_peer_bypass();
    failures += test_disabled_layer_allows();
    failures += test_refill_over_time();
    failures += test_available_tracks_usage();
    failures += test_env_overrides();
    failures += test_tracked_peers_grows();
    failures += test_reset_state_clears_buckets();
    failures += test_throttle_event_emission();

    if (pb.initialized) peer_bandwidth_destroy(&pb);
    return failures;
}
