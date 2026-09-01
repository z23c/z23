/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * time_authority — implementation. See util/time_authority.h for the design
 * rationale (the ONE operational deadline/interval clock + wall-vs-monotonic
 * skew/step telemetry). Operational time only — consensus time semantics
 * (block nTime, median-time-past, platform/modules/util/timedata.h's network-adjusted
 * clock) are untouched. */

#include "util/time_authority.h"

#include "json/json.h"
#include "platform/clock.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdint.h>

/* A |Δoffset| larger than this between two consecutive observe() samples is
 * a STEP (NTP step correction, VM resume, manual `date -s`), not ordinary
 * slewing. Ordinary NTP slewing is bounded to roughly 500 ppm, i.e. well
 * under 1 ms of drift per second of elapsed time — a genuine half-second
 * jump between ~1 Hz samples cannot be slew. */
#define TIME_AUTH_STEP_THRESHOLD_US   500000LL

/* EWMA smoothing: new = old + (sample - old) / EWMA_SHIFT_DIVISOR. Divisor 8
 * (the classic TCP RTT smoothing constant, alpha = 1/8) — responsive enough
 * to track a real slew-rate change within a handful of samples, stable
 * enough that one noisy sample cannot swing the reported drift wildly. */
#define TIME_AUTH_EWMA_SHIFT_DIVISOR  8

/* ── State (all cross-thread; observe() writes from the health-sweep
 * thread, dumpstate/report reads from the RPC thread) ──────────────────── */

static _Atomic bool    g_have_baseline;
static _Atomic int64_t g_prev_mono_us;
static _Atomic int64_t g_prev_offset_us;

static _Atomic int64_t g_offset_us;
static _Atomic int64_t g_drift_ppm_milli_ewma;

static _Atomic int64_t g_step_count;
static _Atomic int64_t g_last_step_mono_us;        /* 0 = no step yet */
static _Atomic int64_t g_last_step_magnitude_us;

static _Atomic int64_t g_observation_count;

int64_t time_auth_mono_us(void)
{
    return clock_now_monotonic_raw_us();
}

int64_t time_auth_wall_us(void)
{
    return platform_time_realtime_us();
}

/* Shared fold logic for both the real sampler and the test-injection seam. */
static void fold_observation(int64_t mono_us, int64_t wall_us)
{
    int64_t offset_us = wall_us - mono_us;

    if (!atomic_load(&g_have_baseline)) {
        /* First sample: seed the baseline only — nothing to compare yet. */
        atomic_store(&g_prev_mono_us, mono_us);
        atomic_store(&g_prev_offset_us, offset_us);
        atomic_store(&g_offset_us, offset_us);
        atomic_store(&g_have_baseline, true);
        atomic_fetch_add(&g_observation_count, 1);
        return;
    }

    int64_t prev_mono_us   = atomic_load(&g_prev_mono_us);
    int64_t prev_offset_us = atomic_load(&g_prev_offset_us);
    int64_t delta_offset_us = offset_us - prev_offset_us;
    int64_t abs_delta_us = delta_offset_us < 0 ? -delta_offset_us : delta_offset_us;
    int64_t dt_mono_us = mono_us - prev_mono_us;

    if (abs_delta_us > TIME_AUTH_STEP_THRESHOLD_US) {
        /* A discrete jump — record it, but do NOT fold it into the drift
         * EWMA (it is not the slow slew the EWMA is meant to track). */
        atomic_fetch_add(&g_step_count, 1);
        atomic_store(&g_last_step_mono_us, mono_us);
        atomic_store(&g_last_step_magnitude_us, delta_offset_us);
    } else if (dt_mono_us > 0) {
        /* Ordinary sample: fold the instantaneous rate into the EWMA.
         * rate (milli-ppm) = delta_offset_us / dt_mono_us * 1e6 (ppm) * 1e3.
         * delta_offset_us is bounded by the step threshold (<=500000) here,
         * so delta_offset_us * 1e9 fits comfortably in int64_t regardless of
         * dt_mono_us's magnitude. */
        int64_t rate_milli_ppm =
            (delta_offset_us * 1000000000LL) / dt_mono_us;
        int64_t ewma_old = atomic_load(&g_drift_ppm_milli_ewma);
        int64_t ewma_new = ewma_old +
            (rate_milli_ppm - ewma_old) / TIME_AUTH_EWMA_SHIFT_DIVISOR;
        atomic_store(&g_drift_ppm_milli_ewma, ewma_new);
    }
    /* dt_mono_us <= 0 (clock read out of order / two samples same
     * microsecond) is silently skipped for the EWMA update but still
     * advances the baseline below — never divide by a non-positive dt. */

    atomic_store(&g_prev_mono_us, mono_us);
    atomic_store(&g_prev_offset_us, offset_us);
    atomic_store(&g_offset_us, offset_us);
    atomic_fetch_add(&g_observation_count, 1);
}

void time_auth_observe(void)
{
    fold_observation(time_auth_mono_us(), time_auth_wall_us());
}

void time_auth_skew_report(struct time_auth_skew_report *out)
{
    if (!out) return;

    out->offset_us       = atomic_load(&g_offset_us);
    out->drift_ppm_milli  = atomic_load(&g_drift_ppm_milli_ewma);
    out->step_count       = atomic_load(&g_step_count);
    out->last_step_magnitude_us = atomic_load(&g_last_step_magnitude_us);
    out->observation_count = atomic_load(&g_observation_count);

    int64_t last_step_mono_us = atomic_load(&g_last_step_mono_us);
    out->last_step_age_us = (last_step_mono_us == 0)
        ? -1
        : (time_auth_mono_us() - last_step_mono_us);
}

int64_t time_auth_step_count(void)
{
    return atomic_load(&g_step_count);
}

bool time_authority_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;

    struct time_auth_skew_report r;
    time_auth_skew_report(&r);

    json_push_kv_int(out, "offset_us", r.offset_us);
    json_push_kv_int(out, "drift_ppm_milli", r.drift_ppm_milli);
    json_push_kv_int(out, "drift_ppm_approx", r.drift_ppm_milli / 1000);
    json_push_kv_int(out, "step_count", r.step_count);
    json_push_kv_int(out, "last_step_age_us", r.last_step_age_us);
    json_push_kv_int(out, "last_step_magnitude_us", r.last_step_magnitude_us);
    json_push_kv_int(out, "observation_count", r.observation_count);
    return true;
}

#ifdef ZCL_TESTING
void time_auth_observe_for_testing(int64_t mono_us, int64_t wall_us)
{
    fold_observation(mono_us, wall_us);
}

void time_auth_reset_for_testing(void)
{
    atomic_store(&g_have_baseline, false);
    atomic_store(&g_prev_mono_us, 0);
    atomic_store(&g_prev_offset_us, 0);
    atomic_store(&g_offset_us, 0);
    atomic_store(&g_drift_ppm_milli_ewma, 0);
    atomic_store(&g_step_count, 0);
    atomic_store(&g_last_step_mono_us, 0);
    atomic_store(&g_last_step_magnitude_us, 0);
    atomic_store(&g_observation_count, 0);
}
#endif
