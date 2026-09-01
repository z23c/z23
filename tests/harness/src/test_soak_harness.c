/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: 7-day soak harness (MVP criterion #6).
 *
 * Exercises soak_compute_verdict() against synthetic sample
 * streams. The runner in tools/soak/ is the I/O shell that
 * captures real samples from a running node over 7 days; this
 * test pins the analyzer logic so any regression to the verdict
 * rules surfaces in CI rather than after a week of wall-clock
 * runtime.
 *
 * Six cases, each asserting a specific verdict:
 *
 *   1. empty state                                    → FAIL_NO_SAMPLES
 *   2. one-hour sample run, healthy otherwise         → FAIL_TOO_SHORT
 *   3. seven-day run, chain advances, RSS flat        → OK
 *   4. any sample where the node PID was down         → FAIL_CRASH
 *   5. ≥ 30 min without a new tip high-water mark     → FAIL_TIP_STALL
 *   6. RSS grows past baseline + 512 MiB post-warmup  → FAIL_RSS_WALK
 *
 * Pre-GREEN: stub returns SOAK_OK for every input, so cases 1,
 * 2, 4, 5, 6 all FAIL. Post-GREEN: all six pass.
 */

#include "test/test_core.h"
#include "test/soak_harness.h"

int test_soak_harness(void);

static soak_thresholds_t mk_default_cfg(void)
{
    soak_thresholds_t cfg;
    soak_thresholds_default_7d(&cfg);
    return cfg;
}

static int t_empty_state_is_no_samples(void)
{
    soak_state_t s;
    soak_thresholds_t cfg = mk_default_cfg();
    soak_state_init(&s, &cfg);
    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_FAIL_NO_SAMPLES) {
        printf("FAIL (empty → expected FAIL_NO_SAMPLES, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

static int t_one_hour_run_is_too_short(void)
{
    soak_state_t s;
    soak_thresholds_t cfg = mk_default_cfg();
    soak_state_init(&s, &cfg);
    /* 60 samples over 1 h; chain advances every 5 min, RSS pinned
     * at 1 GiB — so the only outstanding failure mode is duration. */
    int64_t h = 1000;
    for (uint64_t ts = 0; ts <= 3600; ts += 60) {
        if (ts > 0 && ts % 300 == 0) h++;
        soak_record_sample(&s, ts, true, h, 1ULL << 30);
    }
    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_FAIL_TOO_SHORT) {
        printf("FAIL (1 h → expected FAIL_TOO_SHORT, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

/* Shared healthy generator — used by the OK case and by the
 * walk/stall cases that need a 7-day baseline before injecting
 * a defect. tip_step_sec: how often the chain advances. */
static void feed_healthy_window(soak_state_t *s,
                                uint64_t start_ts,
                                uint64_t end_ts,
                                int64_t *height_io,
                                uint64_t rss_bytes,
                                uint64_t tip_step_sec)
{
    for (uint64_t ts = start_ts; ts <= end_ts; ts += 60) {
        if (ts > start_ts && (ts % tip_step_sec) == 0) (*height_io)++;
        soak_record_sample(s, ts, true, *height_io, rss_bytes);
    }
}

static int t_seven_day_healthy_is_ok(void)
{
    soak_state_t s;
    soak_thresholds_t cfg = mk_default_cfg();
    soak_state_init(&s, &cfg);

    int64_t h = 1000;
    uint64_t end = 7ULL * 24 * 3600 + 60;
    feed_healthy_window(&s, 0, end, &h, 1ULL << 30, 300);

    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_OK) {
        printf("FAIL (7 d healthy → expected OK, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

static int t_crash_sample_is_fail_crash(void)
{
    soak_state_t s;
    soak_thresholds_t cfg = mk_default_cfg();
    soak_state_init(&s, &cfg);

    int64_t h = 1000;
    feed_healthy_window(&s, 0, 300, &h, 1ULL << 30, 300);
    /* Sample #6 catches the process down. */
    soak_record_sample(&s, 360, false, 0, 0);
    /* Even if we resumed healthy afterwards, the crash is sticky. */
    feed_healthy_window(&s, 420, 7ULL * 24 * 3600 + 60, &h, 1ULL << 30, 300);

    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_FAIL_CRASH) {
        printf("FAIL (crash → expected FAIL_CRASH, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

static int t_tip_stall_is_fail_stall(void)
{
    soak_state_t s;
    soak_thresholds_t cfg = mk_default_cfg();
    soak_state_init(&s, &cfg);

    int64_t h = 1000;
    /* First 3 h advance normally. */
    feed_healthy_window(&s, 0, 3ULL * 3600, &h, 1ULL << 30, 300);
    /* Next 60 min: same height, no advance — exceeds 30 min threshold. */
    for (uint64_t ts = 3ULL * 3600 + 60; ts <= 4ULL * 3600; ts += 60) {
        soak_record_sample(&s, ts, true, h, 1ULL << 30);
    }
    /* Resume advancing through the rest of the 7-day window. */
    feed_healthy_window(&s, 4ULL * 3600 + 60, 7ULL * 24 * 3600 + 60,
                        &h, 1ULL << 30, 300);

    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_FAIL_TIP_STALL) {
        printf("FAIL (stall → expected FAIL_TIP_STALL, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

static int t_rss_walk_is_fail_walk(void)
{
    soak_state_t s;
    soak_thresholds_t cfg = mk_default_cfg();
    soak_state_init(&s, &cfg);

    int64_t h = 1000;
    /* Warmup 30 min @ 1.0 GiB — baseline locks right at the cutoff. */
    for (uint64_t ts = 0; ts <= 30ULL * 60; ts += 60) {
        if (ts > 0 && ts % 300 == 0) h++;
        soak_record_sample(&s, ts, true, h, 1ULL << 30);
    }
    /* Post-warmup: RSS walks up by 1 MiB per minute. Crosses
     * baseline + 512 MiB (the default threshold) at roughly
     * warmup + 512 min; 7 d is 10 080 min, so the walk is
     * unambiguous by the end. */
    uint64_t rss = 1ULL << 30;
    for (uint64_t ts = 30ULL * 60 + 60; ts <= 7ULL * 24 * 3600 + 60; ts += 60) {
        if (ts % 300 == 0) h++;
        rss += 1ULL << 20;
        soak_record_sample(&s, ts, true, h, rss);
    }

    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_FAIL_RSS_WALK) {
        printf("FAIL (rss walk → expected FAIL_RSS_WALK, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

/* The CI-proxy thresholds drive `make soak-ci`. Verify they run through
 * the SAME verdict math: a healthy 180 s compressed run with the tip
 * advancing under load and flat RSS → SOAK_OK, while a sub-floor run
 * still trips FAIL_TOO_SHORT (the un-fakeable duration gate). */
static int t_ci_proxy_healthy_is_ok(void)
{
    soak_thresholds_t cfg;
    soak_thresholds_ci_proxy(&cfg);
    if (cfg.min_duration_sec != 180 || cfg.max_tip_stall_sec != 30 ||
        cfg.rss_walk_warmup_sec != 30 ||
        cfg.max_rss_growth_bytes != 96ULL * 1024 * 1024) {
        printf("FAIL (ci_proxy thresholds drifted from the documented set)\n");
        return 1;
    }
    soak_state_t s;
    soak_state_init(&s, &cfg);
    /* 5 s cadence for 180 s; tip advances every 10 s (generate-load),
     * RSS pinned at 256 MiB so the only question is the verdict path. */
    int64_t h = 100;
    for (uint64_t ts = 0; ts <= 180; ts += 5) {
        if (ts > 0 && ts % 10 == 0) h++;
        soak_record_sample(&s, ts, true, h, 256ULL << 20);
    }
    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_OK) {
        printf("FAIL (ci_proxy healthy → expected OK, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

static int t_ci_proxy_short_is_too_short(void)
{
    soak_thresholds_t cfg;
    soak_thresholds_ci_proxy(&cfg);
    soak_state_t s;
    soak_state_init(&s, &cfg);
    /* Only 60 s of samples — below the 180 s floor. */
    int64_t h = 100;
    for (uint64_t ts = 0; ts <= 60; ts += 5) {
        if (ts > 0 && ts % 10 == 0) h++;
        soak_record_sample(&s, ts, true, h, 256ULL << 20);
    }
    soak_verdict_t v = soak_compute_verdict(&s);
    if (v != SOAK_FAIL_TOO_SHORT) {
        printf("FAIL (ci_proxy 60s → expected FAIL_TOO_SHORT, got %s)\n",
               soak_verdict_str(v));
        return 1;
    }
    return 0;
}

int test_soak_harness(void)
{
    int failures = 0;
    printf("\n=== soak harness (MVP #6) ===\n");

    printf("soak_harness empty → FAIL_NO_SAMPLES... ");
    if (t_empty_state_is_no_samples()) failures++;
    else printf("OK\n");

    printf("soak_harness 1 h run → FAIL_TOO_SHORT... ");
    if (t_one_hour_run_is_too_short()) failures++;
    else printf("OK\n");

    printf("soak_harness 7 d healthy → OK... ");
    if (t_seven_day_healthy_is_ok()) failures++;
    else printf("OK\n");

    printf("soak_harness crash sample → FAIL_CRASH... ");
    if (t_crash_sample_is_fail_crash()) failures++;
    else printf("OK\n");

    printf("soak_harness tip stall → FAIL_TIP_STALL... ");
    if (t_tip_stall_is_fail_stall()) failures++;
    else printf("OK\n");

    printf("soak_harness rss walk → FAIL_RSS_WALK... ");
    if (t_rss_walk_is_fail_walk()) failures++;
    else printf("OK\n");

    printf("soak_harness ci-proxy healthy → OK... ");
    if (t_ci_proxy_healthy_is_ok()) failures++;
    else printf("OK\n");

    printf("soak_harness ci-proxy 60s → FAIL_TOO_SHORT... ");
    if (t_ci_proxy_short_is_too_short()) failures++;
    else printf("OK\n");

    return failures;
}
