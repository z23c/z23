/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_CLOCK_SKEW_RECONCILE_H
#define ZCL_CONDITIONS_CLOCK_SKEW_RECONCILE_H

/* SYMPTOM: the WALL clock jumped relative to the MONOTONIC clock (NTP step,
 *   VM resume, manual set). Between two polls monotonic advances by ~poll
 *   secs; if |Δwall − Δmonotonic| exceeds the tolerance (default 120 s) the
 *   wall clock stepped. This matters because condition.c's now_unix() reads
 *   platform_time_wall_unix() (wall-only): a BACKWARD wall jump freezes every
 *   wall-keyed condition's backoff math; a FORWARD jump can fire them all at
 *   once.
 * REMEDY: re-baseline the engine's wall-keyed cadence anchors off the new
 *   wall reading (condition_engine_rebaseline_clocks()), so the skew can't
 *   freeze or stampede the engine. AUTO-TERMINATING: a clock jump is a
 *   one-shot event; COND_WARN, never operator-terminal.
 * WITNESSED: the next poll shows Δwall ≈ Δmonotonic again (clock stable).
 * COND_WARN; poll_secs=30. */
void register_clock_skew_reconcile(void);

#ifdef ZCL_TESTING
void clock_skew_reconcile_test_reset(void);
int  clock_skew_reconcile_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_CLOCK_SKEW_RECONCILE_H */
