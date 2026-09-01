/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 7-day soak harness (MVP criterion #6).
 *
 * Offline analyzer for the sample stream emitted by `tools/soak/`
 * while it polls a running node every 60 s for 7 days. Split from
 * the runner so the verdict logic is testable from `test_zcl` —
 * the runner is just the I/O shell (pidof, /proc/<pid>/status,
 * build/bin/zcl-rpc getblockcount).
 *
 * Failure modes we gate on (in this priority order — soak_compute_verdict
 * returns the first one that matches, so the verdict is deterministic):
 *
 *   1. FAIL_NO_SAMPLES — analyzer never saw a sample
 *   2. FAIL_CRASH     — node was down on ≥1 poll
 *   3. FAIL_TOO_SHORT — observed window < cfg.min_duration_sec
 *   4. FAIL_TIP_STALL — block height didn't advance beyond its
 *                        previous high-water mark for
 *                        > cfg.max_tip_stall_sec
 *   5. FAIL_RSS_WALK  — RSS rose by > cfg.max_rss_growth_bytes
 *                        above the post-warmup baseline
 *
 * "Post-warmup" = after the first cfg.rss_walk_warmup_sec seconds
 * of the run, at which point the min RSS observed so far is
 * latched as the baseline. Growing past this baseline by more
 * than the threshold is a leak; bouncing above and below the
 * baseline by less than the threshold is not.
 */

#ifndef ZCL_TEST_SOAK_HARNESS_H
#define ZCL_TEST_SOAK_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SOAK_OK = 0,
    SOAK_FAIL_NO_SAMPLES,
    SOAK_FAIL_CRASH,
    SOAK_FAIL_TOO_SHORT,
    SOAK_FAIL_TIP_STALL,
    SOAK_FAIL_RSS_WALK,
} soak_verdict_t;

typedef struct {
    uint64_t min_duration_sec;       /* default: 7 × 24 × 3600 */
    uint64_t max_tip_stall_sec;      /* default: 30 × 60 */
    uint64_t rss_walk_warmup_sec;    /* default: 30 × 60 */
    uint64_t max_rss_growth_bytes;   /* default: 512 MiB */
} soak_thresholds_t;

typedef struct {
    soak_thresholds_t cfg;

    /* Counters */
    size_t   n_samples;
    uint32_t crash_count;

    /* Time window */
    uint64_t first_ts;
    uint64_t last_ts;

    /* Tip tracking — high-water mark, not last height, so a
     * reorg alone doesn't reset the stall timer. Only a new
     * tip advance beyond the previous peak does. */
    int64_t  tip_hwm;
    bool     tip_hwm_set;
    uint64_t last_advance_ts;
    bool     stall_observed;

    /* RSS tracking — baseline locks to the min RSS observed
     * after the warmup window; anything exceeding it by more
     * than max_rss_growth_bytes trips the walk flag. */
    uint64_t rss_baseline;
    bool     rss_baseline_set;
    uint64_t rss_max_seen;
    bool     walk_observed;
} soak_state_t;

/* Default 7-day soak thresholds. Separate function rather than
 * a const global so the test suite and the runner can each grab
 * a local copy and tune one field without mutating a shared one. */
void soak_thresholds_default_7d(soak_thresholds_t *out);

/* Accelerated thresholds for the hermetic CI compressed-soak PROXY
 * (`make soak-ci`): a ~180 s bounded run on an isolated /tmp regtest
 * node under synthetic generate-load. Named so the proxy uses an
 * intentional, reviewable threshold set rather than magic flags. The
 * verdict MATH is identical to the 7-day path — only the numbers
 * differ. This is a CI green/red SIGNAL, never a substitute for the
 * real operational #6 soak (168 h live + real tx load). */
void soak_thresholds_ci_proxy(soak_thresholds_t *out);

void soak_state_init(soak_state_t *s, const soak_thresholds_t *cfg);

/* Record one sample.
 *
 *   unix_ts    — absolute wall-clock time (seconds).
 *   alive      — true if the node PID was up at poll time.
 *   height     — block height reported by the node. Ignored
 *                when alive == false.
 *   rss_bytes  — resident set size of the node process in bytes.
 *                Ignored when alive == false.
 */
void soak_record_sample(soak_state_t *s,
                        uint64_t unix_ts,
                        bool alive,
                        int64_t height,
                        uint64_t rss_bytes);

soak_verdict_t soak_compute_verdict(const soak_state_t *s);
const char    *soak_verdict_str(soak_verdict_t v);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TEST_SOAK_HARNESS_H */
