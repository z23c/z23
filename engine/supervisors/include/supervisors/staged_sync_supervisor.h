/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Staged-sync supervisor children — declarative liveness registration.
 *
 * Owns the eight staged-sync reducer children, each a
 * supervised on_tick that drains a bounded batch and publishes its cursor:
 *   staged.header_admit
 *   staged.validate_headers
 *   staged.body_fetch
 *   staged.body_persist
 *   staged.script_validate
 *   staged.proof_validate
 *   staged.utxo_apply
 *   staged.tip_finalize
 * All registered in the `chain` domain (g_chain_sup), in this order. A
 * stage whose _init fails (e.g. progress_store didn't open) is still
 * registered as a disabled child with stall_reason=child_reported, so
 * `z23 dumpstate supervisor` and tests can see the missing core child
 * without running it. */

#ifndef ZCL_STAGED_SYNC_SUPERVISOR_H
#define ZCL_STAGED_SYNC_SUPERVISOR_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;

/* Register all staged-sync supervisor children, in pipeline order.
 * Idempotent per-stage. `ms` is the live chainstate each stage binds to. */
void staged_sync_supervisor_register(struct main_state *ms);

/* Initialize the eight reducer stages without registering supervisor children.
 * This is for one-shot offline drivers such as -mint-anchor that need the same
 * stage tables and cursors but must not start runtime services, P2P, RPC, or
 * liveness callbacks. Returns false if any stage init fails. */
bool staged_sync_supervisor_init_stages_offline(struct main_state *ms);

/* Tear down stages initialized by staged_sync_supervisor_init_stages_offline().
 * Call only on the offline path, or after any supervisor users are already
 * stopped. */
void staged_sync_supervisor_shutdown_stages(void);

#ifdef ZCL_TESTING
/* Test-only reset for this module's file-static child IDs. Call after
 * supervisor_reset_for_testing() so no registry entry still points at the
 * contracts being cleared. */
void staged_sync_supervisor_test_reset_runtime(void);

/* The consecutive-quiet-window size (STAGED_STAGE_QUIET_US) used by the
 * stall-escalation policy below, in microseconds. Exposed so tests compute
 * escalation-boundary quiet durations without hardcoding the constant. */
int64_t staged_sync_supervisor_test_quiet_window_us(void);

/* Direct entry point to the pure stall-escalation decision (no clock, no
 * live contract): given a stage's identity/cursor/upstream-cursor and an
 * explicit quiet duration, sets or clears the "stage_stalled_<name>"
 * blocker exactly as staged_stage_tick would. `escalated` is caller-owned
 * (mirrors reducer_drain.c's g_spin_blocker_active pattern) so a test can
 * drive a synthetic streak across calls without touching module state. */
void staged_sync_supervisor_test_apply_stall_escalation(
    const char *dotted_name, const char *upstream_dotted_name,
    uint64_t cursor, uint64_t upstream_cursor, bool have_upstream,
    int64_t quiet_us, bool *escalated);

/* Run one real staged_stage_tick() cycle against a synthetic stage built
 * from caller-supplied name/drain/cursor/upstream_cursor and an already
 * main_state_init()-inited `ms` (staged_stage_tick's durability-mode check
 * needs a real cs_main). Returns the resulting progress_marker, so a test
 * can assert what gets published to the supervisor child both with and
 * without an active reducer drive, without full stage registration.
 * `period_us_out`, if non-NULL, receives the contract's effective
 * `period_us` AFTER the tick (0 when neither refold_cadence nor
 * catchup_cadence is active — the shared 2s period_secs applies then). */
int64_t staged_sync_supervisor_test_run_stage_tick(
    const char *name, const char *upstream_name,
    int (*drain)(int max_steps), uint64_t (*cursor)(void),
    uint64_t (*upstream_cursor)(void),
    struct main_state *ms, bool *stall_escalated_inout,
    int64_t *period_us_out);

/* Direct entry to the pure per-tick effective-batch decision (A12): given a
 * stage's normal batch and its per-step fan-out, returns the batch the tick
 * would actually drain, applying the refold/catch-up cadence overrides and the
 * fan-out cap. No clock, no contract. Exposed so a test can assert that an
 * active catch-up scales a fan-out stage's per-tick work only by the catch-up
 * pool width in force (never to the raw catch-up batch), and that an inactive
 * cadence returns the normal batch untouched. */
int staged_sync_supervisor_test_effective_batch(int normal_batch,
                                                 int per_step_fanout);
#endif

#endif /* ZCL_STAGED_SYNC_SUPERVISOR_H */
