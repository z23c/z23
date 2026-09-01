/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_rate_below_floor — ACTING liveness signal for real fold throughput
 * (blocks/sec), net of ibd_throttle's DELIBERATE injected sleep. See the
 * SYMPTOM/REMEDY/WITNESSED contract below. Never touches a validity predicate
 * and never gates or slows the fold (CLAUDE.md "Consensus parity is
 * inviolable") — it names a slowdown AND invokes the recovery ladder. */

#ifndef ZCL_CONDITIONS_SYNC_RATE_BELOW_FLOOR_H
#define ZCL_CONDITIONS_SYNC_RATE_BELOW_FLOOR_H

#include <stdbool.h>
#include <stdint.h>

/* SYMPTOM: sampled once per poll tick, the utxo_apply cursor's advance rate
 *   (blocks/sec) over the window since the previous sample — with the
 *   window's wall time reduced by ibd_throttle's OWN injected sleep in that
 *   same window (engine/services/src/ibd_throttle.c:ibd_throttle_status_snapshot
 *   total_wait_us delta), so a deliberately-throttled IBD lane is never
 *   confused with a genuine slowdown — stays below env
 *   ZCL_SYNC_RATE_FLOOR_BPS (default SYNC_RATE_DEFAULT_FLOOR_BPS, chosen well
 *   below the measured worst-case legitimate fold rate (~50 blk/s
 *   pprev-walk ceiling) for SYNC_RATE_CONSECUTIVE_TICKS consecutive samples, WHILE at
 *   least one peer is connected AND there is pending work (network_tip —
 *   connman_max_peer_height — is strictly above log_head —
 *   tip_finalize_stage_cursor()). A window too short to measure meaningfully
 *   (post-throttle-subtraction, below SYNC_RATE_MIN_WINDOW_US), or a tick
 *   with no peers / no pending work, is simply skipped (streak untouched).
 * REMEDY: names the slow window with a typed BLOCKER_TRANSIENT blocker
 *   ("sync_rate_below_floor") carrying observed_bps, floor_bps, network_tip,
 *   log_head, and the id of the current dominant active blocker
 *   (blocker_select_dominant over the full registry, if any — the likely root
 *   cause), THEN invokes the top-level always-terminating recovery ladder via
 *   sticky_escalator_note_stall() (whose rungs re-derive on their own
 *   supervised ticks and self-clear on tip progress) and returns
 *   COND_REMEDY_OK — a corrective action was taken. The remedy never gates or
 *   slows the fold; if the slow-fold symptom has not cleared by the witness
 *   window the engine downgrades the OK to COND_REMEDY_UNWITNESSED and re-arms
 *   on cooldown, re-noting the stall. The operator page stays the LAST resort
 *   on the ladder, not the first response to this recoverable class.
 * WITNESSED: clears once the live window rate recovers to/above the floor,
 *   OR the gate itself resolves (peers vanish, or pending work drains —
 *   network_tip <= log_head, i.e. the node caught up) — an honest clear,
 *   since the symptom this condition names ("behind and not catching up")
 *   no longer applies either way.
 * COND_WARN; poll_secs=30 while inactive (backoff 120s, max_attempts=1);
 *   cooldown re-arms every 600s, unbounded, re-noting the stall to the ladder
 *   while the rate stays below floor. */
void register_sync_rate_below_floor(void);

struct json_value;

/* See CLAUDE.md "Adding state introspection". Reentrant-safe (atomic loads
 * only, no allocation — `out` is caller-initialized via json_set_object()).
 * `key` is unused (NULL or ""). Emits: current/floor bps (x1000 fixed
 * point), the below-floor streak (consecutive sub-floor windows seen so
 * far), whether the peers+pending-work gate is currently open, the
 * episode-start snapshot (observed/floor bps, network_tip, log_head,
 * dominant blocker at the moment the blocker was raised, if any), and the
 * last-fire unix timestamp. */
bool sync_rate_below_floor_dump_state_json(struct json_value *out,
                                           const char *key);

#ifdef ZCL_TESTING
void sync_rate_below_floor_test_reset(void);
int  sync_rate_below_floor_test_remedy_calls(void);

/* Force the utxo_apply cursor reader to return `v` instead of calling the
 * real utxo_apply_stage_cursor(). -1 = use the real reader. */
void sync_rate_below_floor_test_set_cursor_override(int64_t v);

/* Force the log_head (tip_finalize) cursor reader to return `v` instead of
 * calling the real tip_finalize_stage_cursor(). -1 = use the real reader. */
void sync_rate_below_floor_test_set_log_head_override(int64_t v);

/* Force the ibd_throttle cumulative total_wait_us reader to return `v`
 * instead of calling the real ibd_throttle_status_snapshot(). -1 = use the
 * real reader (so a test does not need ibd_throttle_start()'d). */
void sync_rate_below_floor_test_set_throttle_wait_us_override(int64_t v);

/* Force the monotonic clock this condition samples against, in
 * microseconds. -1 = use the real platform_time_monotonic_us(). */
void sync_rate_below_floor_test_set_now_us_override(int64_t v);
#endif

#endif /* ZCL_CONDITIONS_SYNC_RATE_BELOW_FLOOR_H */
