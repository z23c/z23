/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_liveness — a tiny adapter that puts a long-running background
 * thread onto the supervisor liveness tree with an honest contract, in
 * three lines at the call site:
 *
 *   static struct thread_liveness_child g_child = { .id = SUPERVISOR_INVALID_ID };
 *   ...start()... thread_liveness_register(&g_child, "zcl_foo", 120, 0);
 *   ...loop body... thread_liveness_beat(&g_child, work_counter);
 *   ...stop()...   thread_liveness_retire(&g_child);
 *
 * Why this exists
 * ----------------
 * The supervisor tree gave app-side services (disk_monitor, gap_fill, …) a
 * liveness contract, but the cross-cutting infrastructure threads that live
 * in lib/ and config/ (the health sweeper, the metrics printer, the async
 * event dispatcher, the RPC-timeout watchdog, the DB worker + WAL
 * checkpointer) were spawned through thread_registry_spawn and then never
 * appeared on the supervisor tree — a wedged loop there was silent, exactly
 * the failure mode the supervisor was built to make impossible. Those TUs cannot
 * include the app-side domain header (`supervisors/domains.h`) without a
 * lib-layering violation (Gate #15), so they register a ROOT child through
 * this platform/modules/util adapter instead of a domain.
 *
 * Contract shape (see util/supervisor.h for the field semantics)
 * --------------------------------------------------------------
 *   - The child heartbeats itself (period_secs=0); the supervisor never
 *     drives on_tick. thread_liveness_beat() is the single heartbeat call
 *     the loop body makes — an atomic tick + optional atomic progress
 *     marker, zero behavior change on the thread's real work path.
 *   - deadline_secs > 0 arms the TIME_DEADLINE stall (the heartbeat
 *     lapsed). Use it for threads that tick on a bounded cadence.
 *   - progress_quiet_us > 0 arms the NO_PROGRESS stall (the marker froze).
 *     Use it when the thread does real, marker-advancing work on every
 *     healthy cadence.
 *   - Pass 0 for either gate to leave it disabled. A dormant-until-event
 *     thread (a condvar waiter that can idle indefinitely) registers with
 *     deadline_secs=0, progress_quiet_us=0 — it is present in the tree and
 *     heartbeats when it does work, but is never falsely flagged for
 *     legitimately sitting idle. Do NOT fake a progress marker for such a
 *     thread.
 *   - on_stall names a typed TRANSIENT blocker "thread_stalled_<name>";
 *     the next thread_liveness_beat() clears it.
 */

#ifndef ZCL_THREAD_LIVENESS_H
#define ZCL_THREAD_LIVENESS_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "util/blocker.h"
#include "util/supervisor.h"

/* Caller owns a *static* instance. Initialize `.id = SUPERVISOR_INVALID_ID`
 * at the declaration (a zero-initialized static would look like the valid
 * child id 0 and defeat the idempotent-register guard). All other fields
 * are set by thread_liveness_register{,_restartable}(). */
struct thread_liveness_child {
    struct liveness_contract contract;   /* ctx points back to this struct */
    /* _Atomic: restartable callers spawn the worker BEFORE registering, so
     * the worker reads id concurrently (thread_liveness_worker_alive). The
     * register path publishes it with memory_order_release and every reader
     * loads with memory_order_acquire, so a worker that observes a valid id
     * also sees the completed supervisor_register() that produced it. A
     * worker that still reads SUPERVISOR_INVALID_ID skips one beat and
     * self-heals on the next. */
    _Atomic supervisor_child_id id;
    _Atomic bool             blocker_standing;
    char                     blocker_id[BLOCKER_ID_MAX];

    /* Restart wiring (populated only by thread_liveness_register_restartable;
     * a plain thread_liveness_register child leaves these zeroed and is never
     * auto-restarted). The child owns the worker tid so respawn and graceful
     * stop agree on a single, current handle. */
    pthread_t                worker_tid;
    _Atomic bool             worker_tid_set;
    const char              *thread_name;      /* static; re-used on respawn */
    void                    *(*worker_entry)(void *);
    void                    *worker_arg;
    pthread_mutex_t          restart_lock;     /* serializes respawn vs stop */
    _Atomic bool             restart_lock_init;
    char                     storm_blocker_id[BLOCKER_ID_MAX];
};

/* Register `c` as a supervised ROOT child named `name` (heartbeat-driven).
 * deadline_secs>0 arms the heartbeat-lapse stall; progress_quiet_us>0 arms
 * the frozen-marker stall; 0 disables that gate. Idempotent: a second call
 * on an already-registered child returns its existing id without
 * re-registering. Returns the child id, or SUPERVISOR_INVALID_ID on
 * registry-full. */
supervisor_child_id thread_liveness_register(struct thread_liveness_child *c,
                                             const char *name,
                                             int64_t deadline_secs,
                                             int64_t progress_quiet_us);

/* Heartbeat from the loop body. `progress` >= 0 publishes a monotonic
 * progress marker; pass -1 to record a heartbeat only. Clears a standing
 * "thread_stalled_<name>" blocker when the thread resumes ticking. O(1)
 * atomics only — no allocation, no locks on the hot path. Safe to call on
 * an unregistered child (no-op). */
void thread_liveness_beat(struct thread_liveness_child *c, int64_t progress);

/* Unregister on shutdown. Clears any standing blocker and removes the child
 * from the tree. Idempotent. */
void thread_liveness_retire(struct thread_liveness_child *c);

/* ── Bounded auto-restart (Erlang/OTP), for SAFE stateless workers ONLY ──
 *
 * Register `c` as a PERMANENT restartable ROOT child: if the worker thread
 * EXITS abnormally (returns while the node is still running and the child is
 * not marked complete), the supervisor respawns it — up to `intensity_max`
 * (N) restarts within `period_secs` (M), after which it stops respawning and
 * names a PERMANENT blocker "thread_restart_storm_<name>" (the node stays
 * alive and named; it never infinite-spawns or crashes the process).
 *
 * ONLY use this for pure periodic-loop workers with NO consensus/shared
 * mutable state — re-entering the loop from scratch must be a no-op on
 * correctness (metrics printer, health sweeper, RPC-timeout watchdog). NEVER
 * use it for a consensus reducer stage, the reducer drive, or the DB
 * worker/checkpointer — respawning those mid-fold is a correctness hazard;
 * they keep the plain thread_liveness_register (named-blocker) model.
 *
 * Preconditions: the caller has ALREADY spawned the initial worker into
 * `c->worker_tid` via thread_registry_spawn(name, entry, arg, &c->worker_tid).
 * `name`, `entry`, `arg` are re-used verbatim on every respawn; `name` and
 * `arg` must have process lifetime. The worker loop must publish liveness with
 * thread_liveness_worker_alive()/_exited() (below). Returns the child id or
 * SUPERVISOR_INVALID_ID. Idempotent like thread_liveness_register. */
supervisor_child_id thread_liveness_register_restartable(
    struct thread_liveness_child *c, const char *name,
    int64_t deadline_secs, int64_t progress_quiet_us,
    void *(*entry)(void *), void *arg,
    int64_t intensity_max, int64_t period_secs);

/* Worker liveness for a restartable child. Call _alive() at the top of the
 * worker loop (redundant with beat(), which also marks ALIVE) and _exited()
 * on EVERY return path from the worker. O(1) atomics; no-op on a NULL/
 * unregistered child. */
void thread_liveness_worker_alive(struct thread_liveness_child *c);
void thread_liveness_worker_exited(struct thread_liveness_child *c);

/* Graceful stop for a restartable child, race-free against an in-flight
 * respawn. Call sequence in the module's stop():
 *   thread_liveness_stop_begin(c);   // mark complete (no more restarts) +
 *                                    // drain any respawn in progress
 *   <signal the worker loop to exit: set the module's own stop flag / wake>
 *   thread_liveness_stop_finish(c);  // join the (current) worker tid + retire
 * begin()/finish() must be paired. Safe on a child that was never restartable
 * (falls back to a plain join+retire). */
void thread_liveness_stop_begin(struct thread_liveness_child *c);
void thread_liveness_stop_finish(struct thread_liveness_child *c);

#endif /* ZCL_THREAD_LIVENESS_H */
