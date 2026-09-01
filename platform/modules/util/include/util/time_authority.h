/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * time_authority — the ONE operational time subsystem.
 *
 * Why this exists
 * ----------------
 * Timeouts, deadlines, retry backoffs, and rate/EWMA math scattered across
 * the node all read "the clock" and implicitly assume it behaves well: never
 * jumps backward, never leaps forward, advances at a steady rate. Real
 * hosts violate that assumption routinely — NTP step corrections, VM
 * pause/resume, a hypervisor migrating a live guest, an operator running
 * `date -s`. None of that is consensus time (block nTime / median-time-past
 * validity predicates are FROZEN — see docs/CONSENSUS_PARITY_DOCTRINE.md and
 * platform/modules/util/timedata.h's network-adjusted clock, which this module does not
 * touch or duplicate). This is purely OPERATIONAL time: how long has this
 * deadline been outstanding, is this rate window still meaningful, has the
 * wall clock the operator sees just discontinuously stepped.
 *
 * time_auth_mono_us() is the ONE clock new deadline/interval code should
 * read: CLOCK_MONOTONIC_RAW, immune to NTP frequency slewing (unlike plain
 * CLOCK_MONOTONIC), so an interval measured against it does not silently
 * drift when ntpd/chronyd is correcting the system clock in the background.
 * time_auth_wall_us() is CLOCK_REALTIME for when the actual wall-clock
 * value is needed (logging, display, human-facing timestamps).
 *
 * The sampler (time_auth_observe) runs at ~1 Hz, call-site driven from an
 * EXISTING supervised tick (engine/modules/health/src/heartbeat.c's sweeper thread —
 * already on the supervisor tree, already firing once per
 * g_check_interval_ms) rather than spinning up a dedicated thread. Each
 * sample folds one (mono_us, wall_us) pair into:
 *   - offset_us:        wall_us - mono_us, the current clock disagreement
 *   - drift_ppm_milli:  an EWMA of the RATE the offset is changing between
 *                       consecutive non-step samples, in milli-ppm (value /
 *                       1000 = parts-per-million) — the slow, expected NTP
 *                       slew rate
 *   - step_count / last_step_*: a STEP is |Δoffset| > 500 ms between two
 *     consecutive samples — too large to be slewing, so it is recorded as a
 *     discrete jump (count, mono timestamp, signed magnitude) rather than
 *     folded into the drift EWMA.
 *
 * This module FEEDS engine/conditions/src/clock_skew_reconcile.c (which
 * re-baselines the condition engine's wall-keyed cadence anchors on a
 * skew) via time_auth_step_count() — an additional detection signal
 * alongside that condition's own independent Δwall/Δmonotonic poll. It does
 * not replace that condition's logic.
 *
 * Style: all cross-thread state is _Atomic (dumpstate reads from the RPC
 * thread while the sampler writes from the health-sweep thread); no
 * allocation; no locks on the observe/read paths; no external deps. */

#ifndef ZCL_UTIL_TIME_AUTHORITY_H
#define ZCL_UTIL_TIME_AUTHORITY_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct json_value; /* fwd; see json/json.h */

/* The ONE deadline/interval clock: CLOCK_MONOTONIC_RAW microseconds (falls
 * back to CLOCK_MONOTONIC if RAW is unavailable — see
 * platform/clock.h:clock_now_monotonic_raw_us). Never steps backward. Use
 * this for new timeout/deadline/interval math instead of reading
 * clock_gettime or platform_time_monotonic_*() directly. */
int64_t time_auth_mono_us(void);

/* CLOCK_REALTIME microseconds — the wall-clock value itself, for logging /
 * display / human-facing timestamps. Routes through the existing injectable
 * platform.clock path (platform_time_realtime_us), so tests/the simulator
 * can still fast-forward it. */
int64_t time_auth_wall_us(void);

/* Fold one real-clock sample into the skew tracker. Call this from an
 * EXISTING ~1 Hz supervised tick — do not spin up a dedicated thread for it.
 * Wired into engine/modules/health/src/heartbeat.c's sweeper loop (zcl_health_sweep,
 * already a supervisor-tree child, already firing every
 * g_check_interval_ms ≈ 1000 ms). O(1), no allocation, no locks. */
void time_auth_observe(void);

/* Snapshot of the current skew-tracking state. All fields are point-in-time
 * reads of independent atomics (not a single consistent transaction — fine
 * for an operational telemetry surface, not a correctness-critical one). */
struct time_auth_skew_report {
    int64_t offset_us;              /* most recent wall_us - mono_us */
    int64_t drift_ppm_milli;        /* EWMA drift rate; value/1000 = ppm */
    int64_t step_count;             /* total |Δoffset| > 500ms events seen */
    int64_t last_step_age_us;       /* mono_us since the last step; -1 = none yet */
    int64_t last_step_magnitude_us; /* signed Δoffset of the last step; 0 = none yet */
    int64_t observation_count;      /* total time_auth_observe() samples folded */
};

/* Fill `out` with the current skew report. `out` must be non-NULL; a NULL
 * argument is a no-op (nothing to write into). */
void time_auth_skew_report(struct time_auth_skew_report *out);

/* Total step-event count. A thin accessor so
 * engine/conditions/src/clock_skew_reconcile.c can consume step events as an
 * additional detection signal without pulling in the full report struct. */
int64_t time_auth_step_count(void);

/* dumpstate `time_authority` — see CLAUDE.md "Adding state introspection".
 * `out` is caller-initialized (json_set_object already called); `key` is
 * unused (one dump returns the full report). */
bool time_authority_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Test seam: fold a SYNTHETIC (mono_us, wall_us) pair directly, bypassing
 * the real clock reads entirely. This is how a test injects a simulated
 * clock step deterministically without touching the system clock (which
 * would be both slow and flaky under a test harness). Same fold logic as
 * time_auth_observe(); production never calls this. */
void time_auth_observe_for_testing(int64_t mono_us, int64_t wall_us);

/* Reset all tracked state (offset, EWMA, step history, counters) to the
 * fresh-module baseline. Each fork-based test process is already isolated,
 * but call this between sub-cases within one test function for a clean
 * baseline. */
void time_auth_reset_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_TIME_AUTHORITY_H */
