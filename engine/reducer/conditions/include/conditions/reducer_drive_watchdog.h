/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_drive_watchdog — condition + "reducer_drive" dumpstate subsystem
 * for the synchronous reducer/mint drive; see the SYMPTOM/REMEDY/WITNESSED
 * contract below. */

#ifndef ZCL_CONDITIONS_REDUCER_DRIVE_WATCHDOG_H
#define ZCL_CONDITIONS_REDUCER_DRIVE_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>

/* SYMPTOM: a SYNCHRONOUS reducer drive (reducer_ingest_block, entered via
 *   util/reducer_drive_guard.h) has been continuously active for more than
 *   ZCL_DRIVE_WATCHDOG_SEC (env override, default 60s) AND the durable
 *   utxo_apply stage cursor did not move between two consecutive detect
 *   ticks. The drive legitimately runs synchronously for a long time (a
 *   mint/refold fold can take hours) and the staged_sync_supervisor's own
 *   8-stage children heartbeat WITHOUT draining while it is active
 *   (staged_sync_supervisor.c), so a genuinely wedged drive was previously
 *   invisible: no supervisor child watches it. This Condition is that watch.
 * REMEDY: the remedy cannot safely touch a wedged synchronous drive on
 *   another thread (killing it mid-write risks a torn commit), so it returns
 *   COND_REMEDY_FAILED and pages the operator on the normal ladder. It is no
 *   longer a dead end, though: it names the fault with a typed
 *   BLOCKER_TRANSIENT blocker ("reducer_drive_stuck") carrying the driver
 *   label, age, and the frozen utxo_apply cursor height, AND arms a
 *   deadline-gated escape ("reducer_drive_ladder_kick",
 *   REDUCER_DRIVE_ESCAPE_DEADLINE_SEC) that blocker_supervisor_sweep()
 *   actuates into the top-level recovery ladder (sticky_escalator_note_stall)
 *   if the drive is still frozen past the grace window — a safe corrective
 *   action that never touches the drive's write path.
 * WITNESSED: the blocker clears (witness calls blocker_clear) the instant
 *   the drive exits OR the utxo_apply cursor advances past the height
 *   frozen at detect time — whichever comes first.
 * COND_CRITICAL; poll_secs=15 (backoff 60s, max_attempts 1 -> operator_needed
 * fast; cooldown re-arms every 600s, unbounded, while the drive stays
 * wedged, so a long-lived stall re-notifies without permanently latching). */
void register_reducer_drive_watchdog(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe, allocates
 * nothing. Registered in engine/controllers/src/diagnostics_registry.c
 * g_dumpers as "reducer_drive". Fields: active, label, age_us,
 * watchdog_threshold_secs, last_watchdog_fire_unix (0 = never fired),
 * utxo_apply_cursor (lock-free in-memory stage cursor), stage_spin (present
 * only when nonzero — see reducer_drain.c), drain_exit_converged_total,
 * drain_exit_budget_total, drain_last_round_advances, drain_last_elapsed_us
 * (drive+fsync telemetry gap 1 — see reducer_drain.c's exit-stats doc
 * comment), fsync_last_flush_us, fsync_flush_us_ewma (drive+fsync telemetry
 * gap 2 — see reducer_body_fsync.c / conditions/batch_fsync_slow.c),
 * coins_applied_height + coins_applied_read_ok (the lagging coins_kv
 * frontier, read under progress_store_tx_trylock — skipped, not blocked,
 * while the drive holds the lock; see LOCK-ORDER LAW in
 * DEFENSIVE_CODING.md). */
struct json_value;
bool reducer_drive_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
void reducer_drive_watchdog_test_reset(void);
int reducer_drive_watchdog_test_remedy_calls(void);
/* Force the next threshold read to use this value instead of the env var /
 * default, so tests do not depend on process-wide getenv state. -1 = use
 * the real env-or-default lookup. */
void reducer_drive_watchdog_test_set_threshold_secs(int secs);
/* Force the durable utxo_apply cursor reader to return this value instead of
 * calling utxo_apply_stage_cursor(), so tests do not need to spin up the
 * real utxo_apply stage module. -1 = use the real reader. */
void reducer_drive_watchdog_test_set_cursor_override(int64_t cursor);
#endif

#endif /* ZCL_CONDITIONS_REDUCER_DRIVE_WATCHDOG_H */
