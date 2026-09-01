/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the time-discipline organ (platform/modules/util/src/time_authority.c).
 *
 * Coverage:
 *   - time_auth_mono_us(): monotonic (never decreases) across consecutive
 *     calls, and advances (real time actually elapses)
 *   - time_auth_wall_us(): sane (roughly "now", within a generous bound)
 *   - offset tracking: first sample seeds the baseline (no step, no drift
 *     update, observation_count=1); a second close sample updates offset
 *     without registering a step
 *   - step detection: an injected sample with |Δoffset| > 500ms increments
 *     step_count and records the correct signed magnitude + a fresh
 *     last_step_age_us, all via the ZCL_TESTING injection seam
 *     (time_auth_observe_for_testing) — no system-clock manipulation
 *   - EWMA convergence: repeated identical-rate synthetic samples converge
 *     the reported drift_ppm_milli toward the true injected rate
 *   - dumpstate: time_authority_dump_state_json exposes all report fields */

#include "test/test_core.h"
#include "util/time_authority.h"

#include <stdint.h>
#include <stdio.h>

#include "json/json.h"

#define TA_CHECK(name, expr) do { \
    printf("time_authority: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_time_authority(void);
int test_time_authority(void)
{
    printf("\n=== time_authority tests ===\n");
    int failures = 0;

    /* ── mono/wall clock sanity ──────────────────────────────────── */
    {
        int64_t m1 = time_auth_mono_us();
        int64_t m2 = time_auth_mono_us();
        TA_CHECK("mono_us non-negative", m1 > 0 && m2 > 0);
        TA_CHECK("mono_us monotonic (never decreases)", m2 >= m1);

        int64_t w1 = time_auth_wall_us();
        /* Sanity bound: wall time is after 2020-01-01 and before
         * 2100-01-01, in microseconds since the epoch. Catches a units bug
         * (ms vs us) without pinning to "now". */
        int64_t epoch_2020_us = 1577836800LL * 1000000LL;
        int64_t epoch_2100_us = 4102444800LL * 1000000LL;
        TA_CHECK("wall_us in sane range", w1 > epoch_2020_us && w1 < epoch_2100_us);
    }

    /* ── first sample seeds the baseline ─────────────────────────── */
    {
        time_auth_reset_for_testing();

        struct time_auth_skew_report r;
        time_auth_skew_report(&r);
        TA_CHECK("fresh module: observation_count=0", r.observation_count == 0);
        TA_CHECK("fresh module: step_count=0", r.step_count == 0);
        TA_CHECK("fresh module: last_step_age_us=-1 (never)",
                 r.last_step_age_us == -1);

        time_auth_observe_for_testing(1000000, 1000000 + 5); /* offset=5us */
        time_auth_skew_report(&r);
        TA_CHECK("first sample: observation_count=1", r.observation_count == 1);
        TA_CHECK("first sample: no step recorded", r.step_count == 0);
        TA_CHECK("first sample: offset_us seeded", r.offset_us == 5);
        TA_CHECK("first sample: drift EWMA untouched", r.drift_ppm_milli == 0);
    }

    /* ── ordinary (non-step) second sample: offset updates, no step ─ */
    {
        time_auth_reset_for_testing();

        time_auth_observe_for_testing(1000000, 1000000 + 100); /* offset=100us */
        /* 1s later (mono += 1_000_000us), offset drifts by 50us (a slow,
         * ordinary slew rate — well under the 500ms step threshold). */
        time_auth_observe_for_testing(2000000, 2000000 + 150); /* offset=150us */

        struct time_auth_skew_report r;
        time_auth_skew_report(&r);
        TA_CHECK("second sample: observation_count=2", r.observation_count == 2);
        TA_CHECK("second sample: no step (delta well under 500ms)",
                 r.step_count == 0);
        TA_CHECK("second sample: offset_us advanced to 150", r.offset_us == 150);
        TA_CHECK("second sample: last_step_age_us still -1 (no step yet)",
                 r.last_step_age_us == -1);
    }

    /* ── step detection: injected jump > 500ms ───────────────────── */
    {
        time_auth_reset_for_testing();

        time_auth_observe_for_testing(1000000, 1000000); /* offset=0, baseline */
        /* 1s later, wall jumps forward by 2s beyond the elapsed monotonic
         * time: Δoffset = +2,000,000us, far past the 500,000us threshold. */
        time_auth_observe_for_testing(2000000, 2000000 + 2000000);

        struct time_auth_skew_report r;
        time_auth_skew_report(&r);
        TA_CHECK("step: step_count incremented", r.step_count == 1);
        TA_CHECK("step: magnitude recorded (+2,000,000us)",
                 r.last_step_magnitude_us == 2000000);
        TA_CHECK("step: last_step_age_us >= 0 (a step has happened)",
                 r.last_step_age_us >= 0);
        TA_CHECK("step: offset_us reflects the post-step value",
                 r.offset_us == 2000000);
        TA_CHECK("step: time_auth_step_count() accessor agrees",
                 time_auth_step_count() == 1);

        /* A BACKWARD step also counts, with a negative magnitude. */
        time_auth_observe_for_testing(3000000, 3000000 + 2000000 - 3000000);
        time_auth_skew_report(&r);
        TA_CHECK("backward step: step_count now 2", r.step_count == 2);
        TA_CHECK("backward step: negative magnitude",
                 r.last_step_magnitude_us < 0);
    }

    /* ── multiple steps accumulate; a stable run in between does not
     * reset the counter ─────────────────────────────────────────── */
    {
        time_auth_reset_for_testing();

        time_auth_observe_for_testing(1000000, 1000000);
        time_auth_observe_for_testing(2000000, 2000000 + 900000); /* step 1 */
        time_auth_observe_for_testing(3000000, 3000000 + 900000); /* stable */
        time_auth_observe_for_testing(4000000, 4000000 + 900000); /* stable */
        time_auth_observe_for_testing(5000000, 5000000 + 1900000); /* step 2 */

        TA_CHECK("multiple steps: count=2 across stable gaps",
                 time_auth_step_count() == 2);
    }

    /* ── EWMA convergence toward a steady synthetic drift rate ──────
     * Inject a constant +100 ppm rate (100us of offset growth per second
     * of monotonic time — well under the 500ms step threshold) for many
     * samples; the EWMA should converge close to 100,000 milli-ppm
     * (100 ppm * 1000). */
    {
        time_auth_reset_for_testing();

        int64_t mono = 1000000;
        int64_t offset = 0;
        time_auth_observe_for_testing(mono, mono + offset); /* seed */

        const int64_t rate_us_per_sec = 100; /* 100 ppm */
        for (int i = 0; i < 200; i++) {
            mono += 1000000;      /* +1s */
            offset += rate_us_per_sec;
            time_auth_observe_for_testing(mono, mono + offset);
        }

        struct time_auth_skew_report r;
        time_auth_skew_report(&r);
        int64_t expected_milli_ppm = rate_us_per_sec * 1000; /* 100,000 */
        int64_t diff = r.drift_ppm_milli - expected_milli_ppm;
        if (diff < 0) diff = -diff;
        TA_CHECK("EWMA converges near the injected 100ppm rate",
                 diff < (expected_milli_ppm / 20)); /* within 5% */
        TA_CHECK("EWMA convergence: zero steps fired at this slow rate",
                 r.step_count == 0);
        TA_CHECK("EWMA convergence: observation_count = 201",
                 r.observation_count == 201);
    }

    /* ── dumpstate JSON surface ──────────────────────────────────── */
    {
        time_auth_reset_for_testing();
        time_auth_observe_for_testing(1000000, 1000000 + 42);
        time_auth_observe_for_testing(2000000, 2000000 + 2000042); /* a step */

        struct json_value v;
        json_init(&v);
        json_set_object(&v);
        bool ok = time_authority_dump_state_json(&v, NULL);
        TA_CHECK("dumpstate returns true", ok);
        TA_CHECK("dumpstate: offset_us present",
                 json_get(&v, "offset_us") != NULL);
        TA_CHECK("dumpstate: offset_us value",
                 json_get_int(json_get(&v, "offset_us")) == 2000042);
        TA_CHECK("dumpstate: step_count=1",
                 json_get_int(json_get(&v, "step_count")) == 1);
        TA_CHECK("dumpstate: last_step_magnitude_us present",
                 json_get(&v, "last_step_magnitude_us") != NULL);
        TA_CHECK("dumpstate: observation_count=2",
                 json_get_int(json_get(&v, "observation_count")) == 2);
        TA_CHECK("dumpstate: drift_ppm_milli present",
                 json_get(&v, "drift_ppm_milli") != NULL);
        TA_CHECK("dumpstate: drift_ppm_approx present",
                 json_get(&v, "drift_ppm_approx") != NULL);
        TA_CHECK("dumpstate: NULL out -> false",
                 !time_authority_dump_state_json(NULL, NULL));
        json_free(&v);
    }

    time_auth_reset_for_testing();

    if (failures == 0) {
        printf("=== time_authority tests: ALL PASS ===\n\n");
    } else {
        printf("=== time_authority tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
