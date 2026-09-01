/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// repair-rung-ok:test_sticky_conditions
/* The marker above: this is NOT a chain-state repair rung (TENACITY I3 targets
 * rungs that paper over bad state a WRITER emitted). There is no writer that
 * produces wall-clock skew — the host clock stepping is an ENVIRONMENTAL event
 * (NTP step / VM resume), not a state this node wrote. The "reconcile" here
 * only re-anchors the condition engine's own wall-keyed cadence timers so a
 * backward jump can't freeze backoff and a forward jump can't stampede every
 * condition. test_sticky_conditions proves the full detect->remedy->witness->
 * clear cycle and that it never latches operator_needed. */

#include "conditions/clock_skew_reconcile.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "event/event.h"
#include "platform/time_compat.h"
#include "util/time_authority.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* A clock STEP larger than this (in seconds) between two consecutive polls,
 * over and above the elapsed monotonic time, is treated as a wall-clock jump
 * that the engine's wall-keyed cadence math must reconcile. 120 s comfortably
 * exceeds normal NTP slewing (which is gradual) while catching real steps. */
#define CLOCK_SKEW_TOLERANCE_SECS  120
#define CLOCK_SKEW_POLL_SECS       30

/* Baselines captured at the previous detect() poll. */
static _Atomic int64_t g_last_wall_unix;       /* 0 = no baseline yet */
static _Atomic int64_t g_last_mono_ms;
static _Atomic int64_t g_last_skew_secs;

/* time_authority feed: the last step_count value we've already accounted
 * for. time_auth (util/time_authority.h) runs its own independent ~1 Hz
 * wall-vs-CLOCK_MONOTONIC_RAW sampler (fed from the health-sweep tick) and
 * flags a step whenever |Δoffset| exceeds its own 500 ms threshold. That is
 * an ADDITIONAL detection signal on top of this condition's own Δwall/
 * Δmonotonic poll below — a step time_authority sees but this condition's
 * coarser CLOCK_SKEW_POLL_SECS-spaced poll might straddle (a step followed
 * by a compensating step within one 30 s window) still trips detect() here. */
static _Atomic int64_t g_last_step_count_seen;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static int64_t skew_tolerance(void)
{
    const char *v = getenv("ZCL_CLOCK_SKEW_TOLERANCE_SECS");
    if (v && v[0]) {
        long t = strtol(v, NULL, 10);
        if (t > 0) return (int64_t)t;
    }
    return CLOCK_SKEW_TOLERANCE_SECS;
}

/* time_authority feed: has ITS independent sampler recorded a step since
 * the last time WE checked? Always advances g_last_step_count_seen (even on
 * this condition's first poll) so a step that happened before this
 * condition started watching is not re-attributed to a later poll. */
static bool time_authority_step_signal(void)
{
    int64_t steps_now = time_auth_step_count();
    int64_t last_seen = atomic_load(&g_last_step_count_seen);
    atomic_store(&g_last_step_count_seen, steps_now);
    return steps_now > last_seen;
}

static bool detect_clock_skew(void)
{
    int64_t wall = platform_time_wall_unix();
    int64_t mono = platform_time_monotonic_ms();

    int64_t prev_wall = atomic_load(&g_last_wall_unix);
    int64_t prev_mono = atomic_load(&g_last_mono_ms);

    /* First poll: just seed both baselines; nothing to compare against yet. */
    if (prev_wall == 0) {
        atomic_store(&g_last_wall_unix, wall);
        atomic_store(&g_last_mono_ms, mono);
        (void)time_authority_step_signal(); /* seed only — ignore on first poll */
        return false;
    }

    int64_t d_wall = wall - prev_wall;                 /* seconds */
    int64_t d_mono = (mono - prev_mono) / 1000;        /* seconds */
    int64_t skew = d_wall - d_mono;                    /* +fwd jump / -back jump */
    int64_t abs_skew = skew < 0 ? -skew : skew;

    atomic_store(&g_last_skew_secs, skew);

    /* Additional signal: time_authority's own independent ~1 Hz sampler
     * (util/time_authority.h) recorded a step since our last poll. Its
     * 500 ms step threshold is finer-grained than this condition's
     * CLOCK_SKEW_POLL_SECS-spaced Δwall/Δmonotonic comparison, so it can
     * catch a step this poll's coarser math would otherwise straddle. */
    bool step_signal = time_authority_step_signal();

    if (abs_skew > skew_tolerance() || step_signal) {
        /* Do NOT advance the baseline here — the remedy re-baselines after it
         * reconciles, so the witness measures the post-remedy stability. */
        return true;
    }

    /* Stable: advance the baseline normally. */
    atomic_store(&g_last_wall_unix, wall);
    atomic_store(&g_last_mono_ms, mono);
    return false;
}

static enum condition_remedy_result remedy_clock_skew(void)
{
    int64_t skew = atomic_load(&g_last_skew_secs);
    LOG_INFO("condition",
             "[condition:clock_skew_reconcile] wall jumped %lld s vs monotonic "
             "— re-baselining engine cadence anchors",
             (long long)skew);

    /* Re-baseline every wall-keyed cadence anchor in the engine so a backward
     * jump cannot freeze backoff math and a forward jump cannot stampede every
     * condition at once. (Per-condition module-static wall anchors are a
     * documented follow-up — a broadcast "clock re-based" each module honors.) */
    condition_engine_rebaseline_clocks();

    /* Adopt the current pair as the new baseline so the witness sees a stable
     * Δwall≈Δmonotonic on the next poll. */
    atomic_store(&g_last_wall_unix, platform_time_wall_unix());
    atomic_store(&g_last_mono_ms, platform_time_monotonic_ms());

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_clock_skew(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: this condition is ENVIRONMENTAL (the host wall clock),
    // not chain-progress — there is no tip/cursor/H* that "moves" when a clock
    // jump reconciles. The observable here is the real (wall,monotonic) delta:
    // detect() re-reads both clocks each poll and records g_last_skew_secs, so
    // the witness passes only when the most recent REAL re-measure is back
    // within tolerance (the clock actually stabilized), not on FSM state.
    int64_t skew = atomic_load(&g_last_skew_secs);
    int64_t abs_skew = skew < 0 ? -skew : skew;
    return abs_skew <= skew_tolerance();
}

static bool detail_clock_skew(struct json_value *out)
{
    return out &&
        json_push_kv_int(out, "last_wall_unix", atomic_load(&g_last_wall_unix)) &&
        json_push_kv_int(out, "last_mono_ms", atomic_load(&g_last_mono_ms)) &&
        json_push_kv_int(out, "last_skew_secs", atomic_load(&g_last_skew_secs));
}

static struct condition c_clock_skew_reconcile = {
    .name = "clock_skew_reconcile",
    .severity = COND_WARN,
    .poll_secs = CLOCK_SKEW_POLL_SECS,
    .backoff_secs = 0,
    .max_attempts = 1000000,   /* effectively unbounded: a recoverable, one-
                                * shot event class — never give up / page. */
    .detect = detect_clock_skew,
    .remedy = remedy_clock_skew,
    .witness = witness_clock_skew,
    .detail = detail_clock_skew,
    .witness_window_secs = CLOCK_SKEW_POLL_SECS * 2,
};

void register_clock_skew_reconcile(void)
{
    (void)condition_register(&c_clock_skew_reconcile);
}

#ifdef ZCL_TESTING
void clock_skew_reconcile_test_reset(void)
{
    atomic_store(&g_last_wall_unix, 0);
    atomic_store(&g_last_mono_ms, 0);
    atomic_store(&g_last_skew_secs, 0);
    atomic_store(&g_last_step_count_seen, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

int clock_skew_reconcile_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
