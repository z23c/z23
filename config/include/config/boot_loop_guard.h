/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: boot-loop detector — counts recent boots via the durable
 * boot_flight_recorder history and raises the boot.restart_loop blocker
 * when the count crosses a threshold within a bounded window. */

#ifndef ZCL_CONFIG_BOOT_LOOP_GUARD_H
#define ZCL_CONFIG_BOOT_LOOP_GUARD_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct node_db;
struct json_value;

/* LIVE INCIDENT this closes: the supervisor backstop's (or chain-tip-
 * watchdog's) "orderly shutdown + self-respawn" can exit the process without
 * ever completing the in-process re-exec (a shutdown-stage deadline can
 * force an early _exit() first — see util/shutdown_stagewatch.h), and under
 * systemd Restart=always the resulting restart carries no signal that this
 * was anything other than an operator restart. The node restart-looped with
 * zero named blocker. This module makes that impossible to hide: it counts
 * how many DISTINCT boots landed in the last BOOT_LOOP_GUARD_WINDOW_MINUTES
 * minutes (reusing boot_flight_recorder's own durable boot_stage_timings
 * table — no second history store) and, at BOOT_LOOP_GUARD_THRESHOLD or
 * more, raises the named, non-fatal blocker "boot.restart_loop" (BLOCKER_
 * TRANSIENT, OWNER remedy — app/conditions/include/conditions/
 * blocker_remedy_bindings.def) naming the count, window, and the last exit-
 * reason breadcrumb (util/shutdown_stagewatch.h). This is a NAMED SIGNAL,
 * never a wedge: boot always proceeds regardless of what this module
 * finds. */
#define BOOT_LOOP_GUARD_WINDOW_MINUTES 15
#define BOOT_LOOP_GUARD_THRESHOLD      3
#define BOOT_LOOP_GUARD_BLOCKER_ID     "boot.restart_loop"
#define BOOT_LOOP_GUARD_BLOCKER_OWNER  "boot_loop_guard"

/* Run the detector for the boot in progress. Call exactly once per boot,
 * AFTER boot_flight_recorder_finish() has persisted this boot's own row (so
 * the window count includes it) — boot_flight_recorder_finish() does this
 * automatically as its last step; a caller that needs to run the check
 * independently may call it directly too, idempotently (blocker_set
 * rate-limits repeats). Derives the datadir from `ndb`'s own path
 * ("<datadir>/node.db", the convention every node_db_open() call site
 * uses); a `ndb` opened against ":memory:" or with no '/' in its path skips
 * the exit-reason breadcrumb step (no datadir to read it from) but still
 * runs the boot-count check. A NULL/closed `ndb` is a logged no-op, never
 * fatal. When the exit-reason breadcrumb says the PREVIOUS boot's exit was
 * a self-respawn, also counts that exit toward the binary A/B launcher's
 * boot-failure streak (services/binary_ab_fallback.h) — a self-respawn
 * re-execs the SAME binary in-process, bypassing deploy/
 * the external native launcher entirely, so without this the streak would never see
 * it. */
void boot_loop_guard_check(struct node_db *ndb);

/* Write half of the exit-reason breadcrumb (util/shutdown_stagewatch.h):
 * call once per shutdown, in config/src/boot_services.c's app_shutdown_svc(),
 * right after shutdown_stagewatch_begin() returns and BEFORE any teardown
 * stage runs — so the breadcrumb is durable even if a later stage's deadline
 * force-_exit()s from shutdown_stagewatch_on_alarm() before main.c's post-
 * app_shutdown() self-respawn check ever runs. Reads the SAME two latched
 * flags main.c checks for that self-respawn re-exec (chain_tip_watchdog_
 * respawn_requested(), supervisor_backstop_respawn_requested()) — both are
 * set (if at all) before the caller requested this shutdown, never after,
 * so this is a faithful snapshot of intent — and resolves them to one of
 * the SHUTDOWN_EXIT_REASON_* constants before writing. */
void boot_loop_guard_note_shutdown_intent(void);

/* Diagnostics: merges a "restart_loop" sub-object (count, window_minutes,
 * threshold, armed, fired, last_exit_reason, last_exit_forced) into `out`,
 * which the caller (boot_flight_recorder_dump_state_json, the "boot_timings"
 * dumper — see CLAUDE.md "Adding state introspection") has already
 * json_set_object'd. `armed` is true once this process has run the check at
 * least once this boot; `fired` reflects that check's own verdict. Reentrant
 * -safe (mutex-protected snapshot). Always returns true — a zeroed
 * sub-object before the first check ever runs is a valid answer, not a
 * failure. */
bool boot_loop_guard_dump_state_json(struct json_value *out);

#ifdef ZCL_TESTING
/* Test-only: reset the in-process snapshot (count/fired/last-exit-reason)
 * that boot_loop_guard_dump_state_json reports, so a test can start from a
 * known-empty state instead of accumulating across unrelated test groups
 * linked into the same test_zcl binary. Does not touch node.db or clear the
 * boot.restart_loop blocker (use blocker_clear for that). */
void boot_loop_guard_reset_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_LOOP_GUARD_H */
