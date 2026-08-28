/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_liveness — see util/thread_liveness.h for the contract. This is the
 * single lib/util seam that registers cross-cutting infrastructure threads
 * (health sweep, metrics, event dispatch, RPC-timeout, DB worker/checkpoint)
 * as ROOT supervisor children, so a wedged loop in lib/ or config/ is a
 * named blocker instead of a silent stop. SAFE stateless workers may also opt
 * into bounded auto-restart (Erlang/OTP) via the _restartable variant. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* pthread_tryjoin_np */
#endif

#include "util/thread_liveness.h"

#include "util/log_macros.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Supervisor stall callback (runs on the supervisor thread, edge-triggered).
 * Name a typed TRANSIENT blocker so the wedge is visible via
 * `dumpstate blocker` / node.log; thread_liveness_beat() clears it the moment
 * the thread resumes ticking. */
static void tl_on_stall(struct liveness_contract *self)
{
    if (!self) return;
    struct thread_liveness_child *c =
        (struct thread_liveness_child *)self->ctx;
    if (!c) return;

    int r = atomic_load(&self->stall_reason);

    /* Restart-storm escalation: the bounded restart engine gave up (N restarts
     * inside the window). This is NOT a transient wedge — a repeatedly-dying
     * worker needs operator attention — so name a PERMANENT blocker that a
     * resumed heartbeat does NOT clear. */
    if (r == SUPERVISOR_STALL_REPEATED_RESTART) {
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof reason,
                 "supervised thread '%s' died and was auto-restarted too many "
                 "times within the intensity window (restart storm) — giving "
                 "up to avoid infinite respawn; operator must diagnose and "
                 "restart the node",
                 self->name);
        struct blocker_record rec;
        if (blocker_init(&rec, c->storm_blocker_id, "thread_liveness",
                         BLOCKER_PERMANENT, reason)) {
            (void)blocker_set(&rec);
        }
        LOG_WARN("thread_liveness",
                 "%s RESTART STORM — permanent blocker %s (restarts=%u)",
                 self->name, c->storm_blocker_id,
                 (unsigned)atomic_load(&self->restart_count));
        return;
    }

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof reason,
             "supervised thread '%s' stopped heartbeating (%s) — its loop is "
             "wedged or exited without retiring; clears when it ticks again",
             self->name, supervisor_stall_reason_name(r));

    struct blocker_record rec;
    if (blocker_init(&rec, c->blocker_id, "thread_liveness",
                     BLOCKER_TRANSIENT, reason)) {
        (void)blocker_set(&rec);
        atomic_store(&c->blocker_standing, true);
    }

    LOG_WARN("thread_liveness",
             "[thread_liveness] %s stalled (%s) — named blocker %s",
             self->name, supervisor_stall_reason_name(r), c->blocker_id);
}

/* Respawn callback invoked by the supervisor when a restartable child's worker
 * has EXITED. Reaps the dead worker (pthread_tryjoin_np, which also GUARDS
 * against a false EXITED: EBUSY ⇒ the worker is actually still alive, so we
 * abort without spawning — never double-spawn a live thread) and starts a
 * fresh worker with the same entry/arg. Returns true when it handled the death
 * (spawned, or definitively failed to and wants the attempt counted toward the
 * storm cap); false only when the worker was still alive. Runs on the
 * supervisor thread; serialized against thread_liveness_stop_* by
 * restart_lock. */
static bool tl_on_respawn(struct liveness_contract *self)
{
    if (!self) return false;
    struct thread_liveness_child *c =
        (struct thread_liveness_child *)self->ctx;
    if (!c) return false;

    if (atomic_load(&c->restart_lock_init))
        pthread_mutex_lock(&c->restart_lock);

    bool handled = false;

    /* Don't fight a graceful stop that already marked the child complete. */
    if (atomic_load(&self->completed))
        goto out;

    if (atomic_load(&c->worker_tid_set)) {
#if defined(__linux__)
        int jr = pthread_tryjoin_np(c->worker_tid, NULL);
#elif defined(_WIN32)
        int jr = _pthread_tryjoin(c->worker_tid, NULL);
#endif
#if defined(__linux__) || defined(_WIN32)
        if (jr == EBUSY) {
            /* False EXITED — the worker is still terminating. Abort: do NOT
             * spawn, do NOT count. Restore EXITED (the supervisor claimed it as
             * RESTARTING) so the next sweep retries once the worker is truly
             * gone. Never double-spawn a live thread. */
            atomic_store(&self->worker_state, SUPERVISOR_WORKER_EXITED);
            goto out;
        }
        /* jr == 0 (reaped) or ESRCH/EINVAL (already gone): worker is dead. */
        atomic_store(&c->worker_tid_set, false);
#else
        /* This restart contract requires a non-blocking join to prove the old
         * worker is gone before creating its successor. Darwin has no such
         * primitive, so preserve single-worker ownership and leave the child
         * EXITED for the operator-visible blocker. */
        atomic_store(&self->worker_state, SUPERVISOR_WORKER_EXITED);
        goto out;
#endif
    }

    pthread_t tid;
    int rc = thread_registry_spawn(c->thread_name, c->worker_entry,
                                   c->worker_arg, &tid);  // supervised:restartable-worker-respawn
    if (rc != 0) {
        /* Spawn failed: no live worker. Mark EXITED so the next sweep retries
         * and the storm cap eventually trips → permanent blocker (bounded). */
        atomic_store(&self->worker_state, SUPERVISOR_WORKER_EXITED);
        LOG_WARN("thread_liveness",
                 "[thread_liveness] respawn of '%s' failed rc=%d — will retry "
                 "under the restart cap", c->thread_name, rc);
        handled = true;   /* count the attempt toward the storm cap */
        goto out;
    }

    /* Success. Leave worker_state as RESTARTING — the fresh worker publishes
     * ALIVE on entry (or EXITED if it dies immediately); the supervisor must
     * NOT write ALIVE here or it could clobber that EXITED. */
    c->worker_tid = tid;
    atomic_store(&c->worker_tid_set, true);
    LOG_WARN("thread_liveness",
             "[thread_liveness] respawned dead worker '%s' (restart #%u)",
             c->thread_name,
             (unsigned)atomic_load(&self->restart_count) + 1u);
    handled = true;

out:
    if (atomic_load(&c->restart_lock_init))
        pthread_mutex_unlock(&c->restart_lock);
    return handled;
}

supervisor_child_id thread_liveness_register(struct thread_liveness_child *c,
                                             const char *name,
                                             int64_t deadline_secs,
                                             int64_t progress_quiet_us)
{
    if (!c || !name || !name[0]) return SUPERVISOR_INVALID_ID;
    supervisor_child_id existing =
        atomic_load_explicit(&c->id, memory_order_acquire);
    if (existing != SUPERVISOR_INVALID_ID) return existing;  /* idempotent */

    liveness_contract_init(&c->contract, name);
    /* Child-driven heartbeat: the supervisor never calls on_tick. */
    atomic_store(&c->contract.period_secs, (int64_t)0);
    atomic_store(&c->contract.deadline_secs, deadline_secs);
    atomic_store(&c->contract.progress_max_quiet_us, progress_quiet_us);
    c->contract.ctx      = c;
    c->contract.on_tick  = NULL;
    c->contract.on_stall = tl_on_stall;

    atomic_store(&c->blocker_standing, false);
    /* blocker-id: thread_stalled_* */
    snprintf(c->blocker_id, sizeof c->blocker_id, "thread_stalled_%s", name);

    supervisor_child_id id = supervisor_register(&c->contract);  // supervisor-root-ok:cross-cutting-infra-thread
    /* Release-publish the id: restartable callers spawn the worker BEFORE
     * this registration runs, so the worker reads c->id concurrently (see
     * thread_liveness_worker_alive). Pairing this release store with the
     * readers' acquire load means a worker that observes a valid id also
     * observes the completed registry insertion above. */
    atomic_store_explicit(&c->id, id, memory_order_release);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("thread_liveness",
                 "[thread_liveness] register failed for '%s' — thread runs "
                 "UNsupervised this boot (registry full?)", name);
    }
    return id;
}

void thread_liveness_beat(struct thread_liveness_child *c, int64_t progress)
{
    if (!c) return;
    supervisor_child_id id = atomic_load_explicit(&c->id, memory_order_acquire);
    if (id == SUPERVISOR_INVALID_ID) return;
    if (progress >= 0)
        supervisor_progress(id, progress);
    supervisor_tick(id);
    if (atomic_load(&c->blocker_standing)) {
        blocker_clear(c->blocker_id);
        atomic_store(&c->blocker_standing, false);
    }
}

void thread_liveness_retire(struct thread_liveness_child *c)
{
    if (!c) return;
    supervisor_child_id id = atomic_load_explicit(&c->id, memory_order_acquire);
    if (id == SUPERVISOR_INVALID_ID) return;
    if (atomic_load(&c->blocker_standing)) {
        blocker_clear(c->blocker_id);
        atomic_store(&c->blocker_standing, false);
    }
    supervisor_unregister(id);
    atomic_store_explicit(&c->id, SUPERVISOR_INVALID_ID, memory_order_release);
}

/* ── Bounded auto-restart ──────────────────────────────────────────── */

supervisor_child_id thread_liveness_register_restartable(
    struct thread_liveness_child *c, const char *name,
    int64_t deadline_secs, int64_t progress_quiet_us,
    void *(*entry)(void *), void *arg,
    int64_t intensity_max, int64_t period_secs)
{
    if (!c || !name || !name[0] || !entry) return SUPERVISOR_INVALID_ID;
    supervisor_child_id existing =
        atomic_load_explicit(&c->id, memory_order_acquire);
    if (existing != SUPERVISOR_INVALID_ID) return existing;  /* idempotent */

    /* Base registration (heartbeat-driven ROOT child, same as the plain path)
     * plus the restart wiring. Note the contract's on_stall is tl_on_stall,
     * which branches on REPEATED_RESTART to name the permanent storm blocker. */
    supervisor_child_id id = thread_liveness_register(c, name, deadline_secs,
                                                      progress_quiet_us);
    if (id == SUPERVISOR_INVALID_ID) return id;

    c->thread_name  = name;   /* process lifetime per the contract */
    c->worker_entry = entry;
    c->worker_arg   = arg;
    /* blocker-id: thread_restart_storm_* */
    snprintf(c->storm_blocker_id, sizeof c->storm_blocker_id,
             "thread_restart_storm_%s", name);
    if (!atomic_load(&c->restart_lock_init)) {
        pthread_mutex_init(&c->restart_lock, NULL);
        atomic_store(&c->restart_lock_init, true);
    }
    /* The caller already spawned the initial worker into c->worker_tid. */
    atomic_store(&c->worker_tid_set, true);

    c->contract.on_respawn = tl_on_respawn;
    supervisor_worker_alive(id);
    supervisor_set_restart_policy(id, SUPERVISOR_RESTART_PERMANENT,
                                  intensity_max, period_secs);
    return id;
}

void thread_liveness_worker_alive(struct thread_liveness_child *c)
{
    if (!c) return;
    supervisor_child_id id = atomic_load_explicit(&c->id, memory_order_acquire);
    if (id == SUPERVISOR_INVALID_ID) return;
    supervisor_worker_alive(id);
}

void thread_liveness_worker_exited(struct thread_liveness_child *c)
{
    if (!c) return;
    supervisor_child_id id = atomic_load_explicit(&c->id, memory_order_acquire);
    if (id == SUPERVISOR_INVALID_ID) return;
    supervisor_worker_exited(id);
}

void thread_liveness_stop_begin(struct thread_liveness_child *c)
{
    if (!c) return;
    supervisor_child_id id = atomic_load_explicit(&c->id, memory_order_acquire);
    if (id == SUPERVISOR_INVALID_ID) return;
    /* Mark complete FIRST so no future sweep restarts the worker, then take
     * restart_lock to drain any respawn already in flight on the supervisor
     * thread. After this returns, c->worker_tid is stable for the join. */
    supervisor_child_complete(id);
    if (atomic_load(&c->restart_lock_init))
        pthread_mutex_lock(&c->restart_lock);
}

void thread_liveness_stop_finish(struct thread_liveness_child *c)
{
    if (!c) return;
    supervisor_child_id id = atomic_load_explicit(&c->id, memory_order_acquire);
    if (id == SUPERVISOR_INVALID_ID) return;
    if (atomic_load(&c->worker_tid_set)) {
        pthread_join(c->worker_tid, NULL);
        atomic_store(&c->worker_tid_set, false);
    }
    if (atomic_load(&c->restart_lock_init))
        pthread_mutex_unlock(&c->restart_lock);
    thread_liveness_retire(c);
}
