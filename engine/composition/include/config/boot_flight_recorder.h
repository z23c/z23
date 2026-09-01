/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: boot flight recorder — collects per-stage boot timings, persists
 * the last ~30 boots in node.db, and raises the boot.stage_regression
 * blocker when a stage exceeds max(5s, 4x its recorded median). */

#ifndef ZCL_CONFIG_BOOT_FLIGHT_RECORDER_H
#define ZCL_CONFIG_BOOT_FLIGHT_RECORDER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct node_db;
struct json_value;

/* Boot-phase flight recorder: durable per-stage boot timings + a
 * regression check against each stage's own recorded history.
 *
 * boot.c already prints "[boot] <stage> <ms>ms" lines (boot_topmark /
 * boot_submark). This module gives those lines a memory: every call to
 * boot_flight_recorder_mark() during the CURRENT boot is buffered
 * in-process (cheap, mutex-protected), then boot_flight_recorder_finish()
 * — called once, after node.db is open, near the end of boot — persists
 * them into a small durable node.db table (keeping the last
 * BOOT_FLIGHT_RECORDER_MAX_BOOTS boots) and compares each stage's ms
 * this boot against its recorded median from PRIOR boots. A stage that
 * blows past max(5s, 4x its median) raises the named blocker
 * "boot.stage_regression" (BLOCKER_TRANSIENT, OWNER remedy —
 * engine/conditions/include/conditions/blocker_remedy_bindings.def) naming
 * the stage + ms + median. This is a NAMED SIGNAL, never a wedge: boot
 * always proceeds regardless of what this module finds. */

/* Cap on distinct stage marks buffered per boot; a stage beyond this many
 * distinct names is dropped (a single WARN, not a crash) — generous
 * headroom over boot.c's current ~20 named phases/sub-phases. */
#define BOOT_FLIGHT_RECORDER_MAX_STAGES 64

/* How many most-recent boots' timings the durable table retains
 * (pruned by boot_epoch on every boot_flight_recorder_finish()). */
#define BOOT_FLIGHT_RECORDER_MAX_BOOTS 30

/* Record one stage's timing for the boot in progress. Safe to call before
 * node.db opens (buffered in memory only until finish()). Thread-safe
 * (mutex-protected); boot.c calls it from the single boot thread, but the
 * lock also makes a concurrent diagnostics read of the buffer safe should
 * one ever be added. A NULL/empty `stage` or a full buffer is a logged
 * no-op, never fatal. */
void boot_flight_recorder_mark(const char *stage, int64_t ms);

/* Persist this boot's buffered marks (see boot_flight_recorder_mark) into
 * node.db and run the regression check described above. Call exactly once
 * per boot, after `ndb` is open. A NULL/closed `ndb`, or a boot with no
 * marks recorded, is a logged no-op — this is diagnostic telemetry, never
 * a boot-blocking dependency. */
void boot_flight_recorder_finish(struct node_db *ndb);

/* Diagnostics dumper (CLAUDE.md "Adding state introspection") registered
 * under subsystem "boot_timings": the most recently persisted boot's
 * per-stage ms next to each stage's recorded median (computed over all
 * durably retained boots, including that most recent one), plus a
 * "restart_loop" sub-object (count/window_minutes/threshold/armed/fired/
 * last_exit_reason/last_exit_forced) folded in from the boot-loop detector
 * (config/boot_loop_guard.h). `key` is unused (NULL-safe); `out` must
 * already be json_set_object'd by the caller. Returns true even when the
 * table is empty (first-ever boot) — an empty "stages" array is a valid
 * answer, not a failure. */
bool boot_flight_recorder_dump_state_json(struct json_value *out, const char *key);

/* Close out one named boot sub-stage and open the next, in one move.
 *
 * Prints the `[boot]   <done> <ms>` marker for the step that just
 * finished — which, by construction, can only describe a step that
 * RETURNED — and then hands the name of the step starting now to the
 * boot-step reporter (util/boot_phase.h), which reports it from the
 * heartbeat sweeper every budget window until it ends. That is the half
 * that survives a step which never returns. Pass NULL for `next` to end
 * the sequence. Returns the sub-stage clock for the new step. */
int64_t boot_mark_step(int64_t t0, const char *done, const char *next);

#ifdef ZCL_TESTING
/* Test-only: drop every buffered-but-not-yet-persisted mark, so a test
 * process that shares translation units with unrelated code can start each
 * assertion from a known-empty buffer instead of accumulating marks across
 * unrelated test groups linked into the same test_zcl binary. Does not
 * touch node.db. */
void boot_flight_recorder_reset_buffer_for_testing(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_FLIGHT_RECORDER_H */
