/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocker_stall_meta_detector -- the GENERIC backstop for the "typed blocker
 * with an EMPTY escape_action holding H*" defect CLASS.
 *
 * Doctrine (docs/work/tenacity-roadmap.md "Hold-class doctrine" + the stickiness
 * invariant): a stall must ALWAYS be a named blocker WITH an auto-terminating
 * remedy. A typed blocker (platform/modules/util/blocker.h) that is active with an EMPTY
 * escape_action while H* (the reducer_frontier provable tip) does not advance
 * is, by construction, a stall with no remedy -- e.g. a sapling-anchor P0
 * with no escape action on utxo_apply.anchor_backfill_gap sits silent
 * for hours otherwise.
 *
 * Instance cures (e.g. sapling_anchor_frontier_unavailable) fix the specific
 * blocker. This condition fixes the CLASS: it knows NOTHING about any specific
 * blocker id. It detects ANY active blocker with an empty escape_action while
 * H* is frozen for longer than a configurable threshold (default 15 min,
 * uptime-clocked with movement-reset hysteresis), then arms the sticky
 * escalator (whose deepest rung is the real refold-from-anchor) and lets the
 * condition engine page the operator naming the offending blocker id.
 *
 * Config: ZCL_BLOCKER_META_STALL_SECS overrides the default frozen-H* window.
 *
 * This is a BACKSTOP, never a cure: arming the escalator + paging is honest
 * "attention needed, self-heal underway", never a fake resolve. The witness is
 * the sole clear-edge: H* climbed past the height captured at detect. */

#ifndef ZCL_CONDITIONS_BLOCKER_STALL_META_DETECTOR_H
#define ZCL_CONDITIONS_BLOCKER_STALL_META_DETECTOR_H

#include <stdbool.h>
#include <stdint.h>

#define BLOCKER_STALL_META_CONDITION_NAME "blocker_stall_meta_detector"

/* Default frozen-H* window before an empty-escape blocker is treated as a
 * class defect. Overridable via ZCL_BLOCKER_META_STALL_SECS. */
#define BLOCKER_STALL_META_DEFAULT_SECS 900

void register_blocker_stall_meta_detector(void);

#ifdef ZCL_TESTING
/* Reset all module + condition state between tests. */
void blocker_stall_meta_detector_test_reset(void);

/* Inject the uptime clock (>= 0 overrides platform_time_monotonic_us; -1
 * restores the real clock). Lets the frozen-H* window + hysteresis be driven
 * deterministically. */
void blocker_stall_meta_detector_test_set_clock_us(int64_t now_us);

/* Run the REAL detect logic (no engine), returning what detect() would.
 * out_blocker_id (nullable, >= 64 bytes) receives the offending blocker id on
 * a true return. */
bool blocker_stall_meta_detector_test_detect(void);

/* Number of remedy dispatches (armings) since the last reset. */
int blocker_stall_meta_detector_test_remedy_calls(void);

/* Zero the engine's wall-clock cadence anchors (last_poll_unix +
 * last_remedy_unix) so a fast test can drive detect+remedy every
 * condition_engine_tick() without waiting real poll/backoff seconds. */
void blocker_stall_meta_detector_test_clear_cadence(void);
#endif

#endif /* ZCL_CONDITIONS_BLOCKER_STALL_META_DETECTOR_H */
