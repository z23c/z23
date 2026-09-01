/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fix: see test/soak_harness.h.
 *
 * Offline verdict analyzer for the 7-day MVP soak run. The runner
 * in tools/soak/ polls the live node every 60 s and feeds each
 * sample through soak_record_sample(); after the planned window
 * (default 7 days) it calls soak_compute_verdict() once and exits
 * with the verdict as status. Nothing here touches the network
 * or the filesystem — this keeps the rules testable from test_zcl
 * against synthetic streams.
 *
 * Design notes:
 *
 *  - Tip tracking uses a high-water mark rather than "last seen
 *    height" so a chain reorg doesn't reset the stall timer. Only
 *    a new peak advances it; the stall trip reflects "the network
 *    stopped building on us", not "we saw a tip change".
 *
 *  - RSS tracking uses a latched baseline — the min RSS observed
 *    after the warmup window (default 30 min, matches how long the
 *    UTXO cache takes to warm on a cold boot). Anything that grows
 *    past baseline + threshold is a leak; bouncing above and below
 *    baseline by less than the threshold isn't. Tracking "max RSS
 *    over window" would flag a single spike; tracking "last RSS"
 *    misses a slow creep that regressed once. A latched baseline
 *    is simple and robust against both.
 *
 *  - crash_count accumulates across the whole run (one strike and
 *    you're out) because the MVP criterion is "no operator
 *    intervention" — if the harness ever had to observe a down
 *    node, that's a failure regardless of whether systemd
 *    restarted it cleanly.
 *
 *  - The verdict is priority-ordered: NO_SAMPLES > CRASH >
 *    TOO_SHORT > TIP_STALL > RSS_WALK. This keeps the output
 *    deterministic for CI and makes the soonest-actionable signal
 *    land first (a crash is louder than an RSS walk).
 */

#include "test/soak_harness.h"

#include <string.h>

void soak_thresholds_default_7d(soak_thresholds_t *out)
{
    out->min_duration_sec     = 7ULL * 24 * 3600;    /* 7 days */
    out->max_tip_stall_sec    = 30ULL * 60;          /* 30 minutes */
    out->rss_walk_warmup_sec  = 30ULL * 60;          /* 30 minutes */
    out->max_rss_growth_bytes = 512ULL * 1024 * 1024;/* 512 MiB */
}

void soak_thresholds_ci_proxy(soak_thresholds_t *out)
{
    /* ~3 min bounded run. min_duration is the un-fakeable floor (a
     * runner that exits early trips FAIL_TOO_SHORT). Stall window 30 s
     * is meaningful because synthetic generate-load advances the tip
     * every few seconds; warmup 30 s lets the UTXO cache settle before
     * the RSS baseline latches; 96 MiB tolerates CI RSS noise while
     * still catching a real leak. */
    out->min_duration_sec     = 180;                /* 3 minutes */
    out->max_tip_stall_sec    = 30;                 /* 30 seconds */
    out->rss_walk_warmup_sec  = 30;                 /* 30 seconds */
    out->max_rss_growth_bytes = 96ULL * 1024 * 1024;/* 96 MiB */
}

void soak_state_init(soak_state_t *s, const soak_thresholds_t *cfg)
{
    memset(s, 0, sizeof(*s));
    s->cfg = *cfg;
}

void soak_record_sample(soak_state_t *s,
                        uint64_t unix_ts,
                        bool alive,
                        int64_t height,
                        uint64_t rss_bytes)
{
    if (s->n_samples == 0) {
        s->first_ts = unix_ts;
        s->last_advance_ts = unix_ts;
    }
    s->last_ts = unix_ts;
    s->n_samples++;

    if (!alive) {
        /* Stop the stall clock too — we can't measure tip progress
         * when the node isn't answering. Crash is the dominant
         * failure signal here; the verdict returns FAIL_CRASH
         * regardless of whatever else would have tripped. */
        s->crash_count++;
        return;
    }

    /* Tip tracking — high-water mark advance. */
    if (!s->tip_hwm_set || height > s->tip_hwm) {
        s->tip_hwm = height;
        s->tip_hwm_set = true;
        s->last_advance_ts = unix_ts;
    } else if (unix_ts - s->last_advance_ts > s->cfg.max_tip_stall_sec) {
        s->stall_observed = true;
    }

    /* RSS tracking — update max, latch baseline after warmup. */
    if (rss_bytes > s->rss_max_seen) s->rss_max_seen = rss_bytes;
    uint64_t elapsed = unix_ts - s->first_ts;
    if (elapsed >= s->cfg.rss_walk_warmup_sec) {
        if (!s->rss_baseline_set || rss_bytes < s->rss_baseline) {
            s->rss_baseline = rss_bytes;
            s->rss_baseline_set = true;
        }
        if (s->rss_baseline_set &&
            rss_bytes > s->rss_baseline + s->cfg.max_rss_growth_bytes) {
            s->walk_observed = true;
        }
    }
}

soak_verdict_t soak_compute_verdict(const soak_state_t *s)
{
    if (s->n_samples == 0) return SOAK_FAIL_NO_SAMPLES;
    if (s->crash_count > 0) return SOAK_FAIL_CRASH;
    if (s->last_ts - s->first_ts < s->cfg.min_duration_sec)
        return SOAK_FAIL_TOO_SHORT;
    if (s->stall_observed) return SOAK_FAIL_TIP_STALL;
    if (s->walk_observed)  return SOAK_FAIL_RSS_WALK;
    return SOAK_OK;
}

const char *soak_verdict_str(soak_verdict_t v)
{
    switch (v) {
    case SOAK_OK:               return "OK";
    case SOAK_FAIL_NO_SAMPLES:  return "FAIL_NO_SAMPLES";
    case SOAK_FAIL_CRASH:       return "FAIL_CRASH";
    case SOAK_FAIL_TOO_SHORT:   return "FAIL_TOO_SHORT";
    case SOAK_FAIL_TIP_STALL:   return "FAIL_TIP_STALL";
    case SOAK_FAIL_RSS_WALK:    return "FAIL_RSS_WALK";
    }
    return "?";
}
