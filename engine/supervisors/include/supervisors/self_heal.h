/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SELF_HEAL_SUPERVISOR_H
#define ZCL_SELF_HEAL_SUPERVISOR_H

#include <stdbool.h>

struct main_state;

/* Register the self-heal engine's liveness contract as a child of the
 * operations supervisor domain (`g_op_sup`) and wire it to `ms`.
 *
 * The engine (condition detect/remedy passes, the blocker escape sweep, the
 * remedy ladder) does NOT run on the supervisor sweep thread: its detect()
 * probes and remedies can each run for seconds (SQL over a 3.1M-header
 * progress store, a reducer-frontier reconcile, a point-in-time chainstate
 * copy), and a heavy pass on the root sweep thread freezes
 * supervisor_sweep_heartbeat() past the 30 s backstop otherwise. The
 * contract therefore carries NO on_tick — the sweep only SUPERVISES the
 * runner's heartbeat, naming a `self_heal.worker_wedged` blocker (never a
 * frozen liveness root) if a remedy hangs past the stall deadline. Call
 * self_heal_start() to spawn the dedicated runner thread that actually drives
 * the engine.
 *
 * Idempotent: a no-op if `ms` is NULL or the engine is already registered. On
 * registration failure (registry full), logs a warning AND sets a PERMANENT
 * "self_heal.unsupervised" blocker + emits EV_OPERATOR_NEEDED. */
void self_heal_register(struct main_state *ms);

/* Spawn the dedicated `zcl_self_heal` condition-runner thread. Must be called
 * after self_heal_register(). Idempotent. Returns true if the runner is
 * running (already-started counts as success); false if registration never
 * succeeded or the thread could not be spawned (a loud blocker is set on
 * spawn failure). The thread exits on the global shutdown flag. */
bool self_heal_start(void);

/* Request the runner thread stop and join it. Idempotent; safe if never
 * started. Used by tests and orderly shutdown. */
void self_heal_stop(void);

#ifdef ZCL_TESTING
/* Reset module state (stops the runner, clears g_ms/g_id/g_registered). */
void self_heal_test_reset(void);
#endif

#endif /* ZCL_SELF_HEAL_SUPERVISOR_H */
