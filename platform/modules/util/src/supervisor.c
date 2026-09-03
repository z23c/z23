/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Supervisor — implementation. See util/supervisor.h for design notes. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* pthread_timedjoin_np */
#endif
/*
 *
 * Architecture:
 *   - Fixed-cap pointer registry (caller owns contracts).
 *   - One dedicated thread "zcl_supervisor", loop period configurable
 *     (default 1000 ms). Loop body: snapshot now; for each registered
 *     contract: maybe-tick (period_secs), maybe-stall (deadline_secs
 *     OR progress_max_quiet_us). All edge-triggered: stall_reason set
 *     to non-zero means "we already fired"; child clearing it by
 *     ticking re-arms the edge.
 *   - Registry mutex protects the array of pointers; supervisor
 *     snapshots pointers under lock, then releases the lock BEFORE
 *     invoking any callback — callbacks may freely call back into the
 *     supervisor API. */

#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "util/supervisor.h"

#include "json/json.h"
#include "util/blocker.h"
#include "util/thread_registry.h"
#include "util/thread_work_probe.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ── Internal state ────────────────────────────────────────────────── */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static struct liveness_contract *g_contracts[SUPERVISOR_CAP];
static supervisor_domain_t      *g_contract_domains[SUPERVISOR_CAP];
static int                       g_contract_count = 0;

struct supervisor_domain {
    char label[SUPERVISOR_NAME_MAX];
};

static supervisor_domain_t       g_domains[SUPERVISOR_DOMAIN_CAP];
static int                       g_domain_count = 0;

static _Atomic bool   g_running       = false;
static _Atomic bool   g_thread_alive  = false;
static _Atomic int    g_tick_ms       = 1000;
static pthread_t      g_thread_id;
static _Atomic bool   g_thread_handle_set = false;

/* Pillar 7 heartbeat: bumps once per sweep_once() call, before any child
 * callback runs, so a dead/wedged sweep freezes it. See
 * util/supervisor_backstop.h for the external watcher. */
static _Atomic uint64_t g_sweep_heartbeat = 0;
static _Atomic int64_t  g_sweep_last_us   = 0;

/* Process-wide stall observer (ops.debug.bundle auto-capture registers it
 * at boot). NULL by default; release-store / acquire-load publication. */
static supervisor_stall_observer_fn _Atomic g_stall_observer = NULL;

void supervisor_set_stall_observer(supervisor_stall_observer_fn fn)
{
    atomic_store_explicit(&g_stall_observer, fn, memory_order_release);
}

/* Single stall-fire path for every trigger site: bump the fire counter,
 * run the per-contract callback, then the process-wide observer. Runs on
 * the DETECTING thread (the supervisor sweep thread for deadline/progress
 * stalls, the child itself for supervisor_report_stall) — the observer
 * contract (cheap, non-blocking) is documented in util/supervisor.h. */
static void note_stall_fire(struct liveness_contract *c,
                            enum supervisor_stall_reason r)
{
    atomic_fetch_add(&c->stall_fires, 1u);
    if (c->on_stall) c->on_stall(c);
    supervisor_stall_observer_fn obs =
        atomic_load_explicit(&g_stall_observer, memory_order_acquire);
    if (obs) obs(c->name, r);
}

/* ── Tick-runner thread ────────────────────────────────────────────────
 * A dedicated thread that executes every child's on_tick callback OFF the
 * sweep thread. The sweep only marks due children (atomic flag) + reads
 * atomics + heartbeats; it never enters a child callback, so a child whose
 * tick commits a SQLite transaction (fsync → jbd2_log_wait_commit under IO
 * saturation) can no longer freeze the sweep heartbeat and get a healthy,
 * progressing node killed by supervisor_backstop.
 *
 * The runner is itself a supervised liveness contract: g_runner_contract has
 * a deadline, and the sweep monitors it INLINE (not via g_contracts, so the
 * countable child registry + every child-count assertion is unchanged). If a
 * single child's on_tick wedges the runner past the deadline, the sweep raises
 * the edge-triggered "supervisor.tick_runner_wedged" blocker — a NAMED blocker,
 * never a dead node — and clears it when the runner heartbeats again.
 *
 * g_runner_enabled doubles as the drain-ownership flag: true ⇒ the runner
 * thread drains due ticks and the sweep monitors it; false ⇒ no runner (spawn
 * failed, or the ZCL_TESTING synchronous seam) and the sweep drains due ticks
 * INLINE so children are never silently un-driven. */
#define SUPERVISOR_TICK_RUNNER_DEADLINE_SECS 30
static _Atomic bool   g_runner_running    = false;
/* Published by the runner thread from its own entry point (0 until it runs).
 * Lets a liveness gate ask the kernel whether the runner is working while it
 * sits inside one child's on_tick, rather than reading a stale heartbeat as
 * death. */
static _Atomic long   g_runner_tid       = 0;
static _Atomic bool   g_runner_enabled    = false;
static pthread_t      g_runner_thread_id;
static _Atomic bool   g_runner_handle_set = false;
static struct liveness_contract g_runner_contract;
static pthread_mutex_t g_runner_wake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_runner_wake_cond = PTHREAD_COND_INITIALIZER;
static _Atomic uint64_t g_runner_wake_seq = 0;
/* A contract is caller-owned and may be unregistered as part of service
 * teardown.  Publish a stable name snapshot instead of retaining that pointer
 * in diagnostics.  g_lock also makes concurrent JSON reads race-free. */
static char g_runner_active_name[SUPERVISOR_NAME_MAX];

const char *supervisor_stall_reason_name(enum supervisor_stall_reason r)
{
    switch (r) {
    case SUPERVISOR_STALL_NONE:             return "none";
    case SUPERVISOR_STALL_TIME_DEADLINE:    return "time_deadline";
    case SUPERVISOR_STALL_NO_PROGRESS:      return "no_progress";
    case SUPERVISOR_STALL_CHILD_REPORTED:   return "child_reported";
    case SUPERVISOR_STALL_REPEATED_RESTART: return "repeated_restart";
    }
    return "(invalid)";
}

/* The policy an operator should be TOLD, which is not always the one a child
 * declared. Three children (chain.coord_escalation, net.outbound_floor, and
 * the staged-sync stages) arm detection by storing progress_max_quiet_us
 * directly rather than through the setter. Reporting those as "undeclared"
 * because they skipped the API would be a lie — the detector is genuinely
 * live on them — and gating the sweep on the declared field would silently
 * DISARM them, which is the exact class of regression this whole change
 * exists to remove. So: an explicit EXEMPT wins, otherwise a positive window
 * IS armed however it was set, otherwise nobody has chosen. */
static enum supervisor_progress_policy
effective_progress_policy(const struct liveness_contract *c)
{
    if (atomic_load(&c->progress_policy) == (int)SUPERVISOR_PROGRESS_EXEMPT)
        return SUPERVISOR_PROGRESS_EXEMPT;
    if (atomic_load(&c->progress_max_quiet_us) > 0)
        return SUPERVISOR_PROGRESS_ARMED;
    return SUPERVISOR_PROGRESS_UNDECLARED;
}

const char *supervisor_progress_policy_name(enum supervisor_progress_policy p)
{
    switch (p) {
    case SUPERVISOR_PROGRESS_UNDECLARED: return "undeclared";
    case SUPERVISOR_PROGRESS_ARMED:      return "armed";
    case SUPERVISOR_PROGRESS_EXEMPT:     return "exempt";
    }
    return "(invalid)";
}

const char *supervisor_restart_policy_name(enum supervisor_restart_policy p)
{
    switch (p) {
    case SUPERVISOR_RESTART_TEMPORARY: return "temporary";
    case SUPERVISOR_RESTART_TRANSIENT: return "transient";
    case SUPERVISOR_RESTART_PERMANENT: return "permanent";
    }
    return "(invalid)";
}

/* ── Init / registry ───────────────────────────────────────────────── */

void liveness_contract_init(struct liveness_contract *c, const char *name)
{
    if (!c) return;
    memset(c, 0, sizeof(*c));
    if (name) {
        size_t n = strnlen(name, SUPERVISOR_NAME_MAX - 1);
        memcpy(c->name, name, n);
        c->name[n] = '\0';
    }
    c->parent = -1;
    /* All atomic fields zero-initialize to their value-equivalent of
     * the underlying type (0 for ints), which is correct for first use. */
    atomic_store(&c->last_tick_us, platform_time_monotonic_us());
    atomic_store(&c->progress_changed_at_us, platform_time_monotonic_us());
}

static supervisor_child_id supervisor_register_locked(
    supervisor_domain_t *domain, struct liveness_contract *c)
{
    if (!c) return SUPERVISOR_INVALID_ID;
    /* Single pass: reject a live duplicate name (helps tests + catches
     * double-registers) while remembering the first retired slot.
     * Retired (NULL) slots are skipped, never matched. */
    int free_slot = -1;
    for (int i = 0; i < g_contract_count; i++) {
        if (g_contracts[i] == NULL) {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (strncmp(g_contracts[i]->name, c->name, SUPERVISOR_NAME_MAX) == 0) {
            fprintf(stderr,  // obs-ok:pre-existing-diagnostic
                "[supervisor] FAIL register '%s': duplicate name\n", c->name);
            return SUPERVISOR_INVALID_ID;
        }
    }
    /* Reuse the first retired slot so restart cycles never grow the
     * table. Ids of live children never move: the old swap-remove
     * relocated the last child into the freed slot, invalidating the
     * id cached in that child's owner (thread_liveness_child.id) — the
     * moved entry could never be retired again (orphaned registration
     * printing duplicate-name FAILs on every restart) and a stale id
     * could retire the wrong slot. */
    int id;
    if (free_slot >= 0) {
        id = free_slot;
    } else {
        if (g_contract_count >= SUPERVISOR_CAP) {
            fprintf(stderr,  // obs-ok:pre-existing-diagnostic
                "[supervisor] FAIL register '%s': registry full (cap=%d)\n",
                c->name, SUPERVISOR_CAP);
            return SUPERVISOR_INVALID_ID;
        }
        id = g_contract_count++;
    }
    g_contracts[id] = c;
    g_contract_domains[id] = domain;
    return id;
}

supervisor_child_id supervisor_register(struct liveness_contract *c)
{
    pthread_mutex_lock(&g_lock);
    supervisor_child_id id = supervisor_register_locked(NULL, c);
    pthread_mutex_unlock(&g_lock);
    return id;
}

supervisor_domain_t *supervisor_create_domain(const char *label)
{
    if (!label || !label[0]) return NULL;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_domain_count; i++) {
        if (strncmp(g_domains[i].label, label, SUPERVISOR_NAME_MAX) == 0) {
            pthread_mutex_unlock(&g_lock);
            return &g_domains[i];
        }
    }
    if (g_domain_count >= SUPERVISOR_DOMAIN_CAP) {
        pthread_mutex_unlock(&g_lock);
        fprintf(stderr,  // obs-ok:supervisor-domain-full
            "[supervisor] FAIL create domain '%s': domain registry full (cap=%d)\n",
            label, SUPERVISOR_DOMAIN_CAP);
        return NULL;
    }
    supervisor_domain_t *domain = &g_domains[g_domain_count++];
    memset(domain, 0, sizeof(*domain));
    size_t n = strnlen(label, SUPERVISOR_NAME_MAX - 1);
    memcpy(domain->label, label, n);
    domain->label[n] = '\0';
    pthread_mutex_unlock(&g_lock);
    return domain;
}

supervisor_child_id supervisor_register_in_domain(
    supervisor_domain_t *domain, struct liveness_contract *c)
{
    if (!domain) return SUPERVISOR_INVALID_ID;
    pthread_mutex_lock(&g_lock);
    supervisor_child_id id = supervisor_register_locked(domain, c);
    pthread_mutex_unlock(&g_lock);
    return id;
}

void supervisor_unregister(supervisor_child_id id)
{
    pthread_mutex_lock(&g_lock);
    if (id < 0 || id >= g_contract_count) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    /* Tombstone: clear this slot in place and leave every other id
     * untouched. Ids are cached in child owners
     * (thread_liveness_child.id) and MUST never move — see register
     * above for what swap-remove broke. Retired slots are reused by
     * register, so restart cycles are allocation-stable; the count is
     * a high-water mark, and live-entry queries count non-NULL slots. */
    g_contracts[id] = NULL;
    g_contract_domains[id] = NULL;
    pthread_mutex_unlock(&g_lock);
}

/* ── Child-side O(1) helpers ───────────────────────────────────────── */

static struct liveness_contract *contract_for(supervisor_child_id id)
{
    /* Reads under lock; the returned pointer is to caller-owned static
     * storage, so dereferencing without the lock is safe. */
    pthread_mutex_lock(&g_lock);
    struct liveness_contract *c = NULL;
    if (id >= 0 && id < g_contract_count) c = g_contracts[id];
    pthread_mutex_unlock(&g_lock);
    return c;
}

void supervisor_child_complete(supervisor_child_id id)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;

    atomic_store(&c->period_secs, 0);
    atomic_store(&c->deadline_secs, 0);
    atomic_store(&c->progress_max_quiet_us, 0);
    atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
    atomic_store(&c->last_tick_us, platform_time_monotonic_us());
    atomic_store(&c->completed, true);
}

void supervisor_tick(supervisor_child_id id)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;
    if (atomic_load(&c->completed)) return;
    atomic_store(&c->last_tick_us, platform_time_monotonic_us());
    atomic_fetch_add(&c->ticks_run, 1u);
    /* Edge-rearm: ticking clears a TIME_DEADLINE stall. NO_PROGRESS
     * is cleared by progress changes, not by ticks. */
    int prev = atomic_load(&c->stall_reason);
    if (prev == SUPERVISOR_STALL_TIME_DEADLINE ||
        prev == SUPERVISOR_STALL_CHILD_REPORTED) {
        atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
    }
}

void supervisor_progress(supervisor_child_id id, int64_t marker)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;
    if (atomic_load(&c->completed)) return;
    int64_t prev = atomic_load(&c->progress_marker);
    if (marker != prev) {
        atomic_store(&c->progress_marker, marker);
        atomic_store(&c->progress_changed_at_us, platform_time_monotonic_us());
        /* Progress rearm: clears NO_PROGRESS. */
        int sr = atomic_load(&c->stall_reason);
        if (sr == SUPERVISOR_STALL_NO_PROGRESS)
            atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
    }
}

void supervisor_progress_idle(supervisor_child_id id)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;
    if (atomic_load(&c->completed)) return;
    atomic_fetch_add(&c->idle_ticks, 1u);
    /* Refresh the quiet clock WITHOUT touching progress_marker: an idle run
     * must not be able to masquerade as work, and must not be called stuck.
     * Same rearm as real progress — a child that has caught up is healthy. */
    atomic_store(&c->progress_changed_at_us, platform_time_monotonic_us());
    int sr = atomic_load(&c->stall_reason);
    if (sr == SUPERVISOR_STALL_NO_PROGRESS)
        atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
}

void supervisor_report_stall(supervisor_child_id id,
                             enum supervisor_stall_reason r)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;
    if (atomic_load(&c->completed)) return;
    /* Only fire on the rising edge. */
    int expected = SUPERVISOR_STALL_NONE;
    if (atomic_compare_exchange_strong(&c->stall_reason, &expected, (int)r)) {
        note_stall_fire(c, r);
    }
}

void supervisor_set_period(supervisor_child_id id, int64_t secs)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) {
        fprintf(stderr,  // obs-ok:supervisor-invalid-child
            "[supervisor] set_period: invalid/unregistered child_id=%d — "
            "ignored (liveness contract keeps its default)\n", (int)id);
        return;
    }
    atomic_store(&c->period_secs, secs);
}

void supervisor_set_deadline(supervisor_child_id id, int64_t secs)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) {
        fprintf(stderr,  // obs-ok:supervisor-invalid-child
            "[supervisor] set_deadline: invalid/unregistered child_id=%d — "
            "ignored (a stale deadline is a liveness hazard)\n", (int)id);
        return;
    }
    atomic_store(&c->deadline_secs, secs);
}

void supervisor_request_tick(supervisor_child_id id)
{
    struct liveness_contract *c = contract_for(id);
    if (!c || atomic_load(&c->completed)) return;
    atomic_store(&c->tick_pending, true);
    atomic_fetch_add(&g_runner_wake_seq, UINT64_C(1));
    pthread_mutex_lock(&g_runner_wake_lock);
    pthread_cond_signal(&g_runner_wake_cond);
    pthread_mutex_unlock(&g_runner_wake_lock);
}

void supervisor_set_progress_max_quiet(supervisor_child_id id,
                                       int64_t microseconds)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) {
        fprintf(stderr,  // obs-ok:supervisor-invalid-child
            "[supervisor] set_progress_max_quiet: invalid/unregistered "
            "child_id=%d — ignored\n", (int)id);
        return;
    }
    atomic_store(&c->progress_max_quiet_us, microseconds);
    /* A positive window is the ARMED declaration. Disarming returns the child
     * to UNDECLARED rather than to a silent off — an operator reading the dump
     * then sees debt, which is the truth, and the lint floor keeps counting it.
     * Reset the quiet clock on arming so a child that arms late is measured
     * from the arm, never retroactively stalled by the pre-arm quiet period. */
    if (microseconds > 0) {
        atomic_store(&c->progress_changed_at_us, platform_time_monotonic_us());
        atomic_store(&c->progress_policy, (int)SUPERVISOR_PROGRESS_ARMED);
    } else if (atomic_load(&c->progress_policy) ==
               (int)SUPERVISOR_PROGRESS_ARMED) {
        atomic_store(&c->progress_policy, (int)SUPERVISOR_PROGRESS_UNDECLARED);
    }
}

void supervisor_set_progress_exempt(supervisor_child_id id,
                                    const char *reason)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) {
        fprintf(stderr,  // obs-ok:supervisor-invalid-child
            "[supervisor] set_progress_exempt: invalid/unregistered "
            "child_id=%d — ignored\n", (int)id);
        return;
    }
    if (!reason || !reason[0]) {
        /* Refuse rather than record a blank justification. The child stays
         * UNDECLARED, which is counted debt — strictly more honest than an
         * exemption with nothing behind it. */
        fprintf(stderr,  // obs-ok:supervisor-invalid-child
            "[supervisor] set_progress_exempt('%s'): empty reason refused — "
            "child stays undeclared\n", c->name);
        return;
    }
    size_t n = strnlen(reason, SUPERVISOR_EXEMPT_REASON_MAX - 1);
    memcpy(c->progress_exempt_reason, reason, n);
    c->progress_exempt_reason[n] = '\0';
    atomic_store(&c->progress_max_quiet_us, (int64_t)0);
    atomic_store(&c->progress_policy, (int)SUPERVISOR_PROGRESS_EXEMPT);
}

int supervisor_progress_undeclared_count(void)
{
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_contract_count; i++) {
        struct liveness_contract *c = g_contracts[i];
        if (!c) continue;
        if (effective_progress_policy(c) == SUPERVISOR_PROGRESS_UNDECLARED)
            n++;
    }
    pthread_mutex_unlock(&g_lock);
    return n;
}

/* Live-entry count under the registry lock. g_contract_count is a
 * high-water mark (retired slots tombstone to NULL and are reused),
 * so every "how many children" query counts non-NULL slots. */
static int supervisor_live_count_locked(void)
{
    int n = 0;
    for (int i = 0; i < g_contract_count; i++)
        if (g_contracts[i] != NULL)
            n++;
    return n;
}

int supervisor_child_headroom(void)
{
    pthread_mutex_lock(&g_lock);
    int used = supervisor_live_count_locked();
    pthread_mutex_unlock(&g_lock);
    int left = SUPERVISOR_CAP - used;
    return left > 0 ? left : 0;
}

void supervisor_set_restart_policy(supervisor_child_id id,
                                   enum supervisor_restart_policy policy,
                                   int64_t intensity_max, int64_t period_secs)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) {
        fprintf(stderr,  // obs-ok:supervisor-invalid-child
            "[supervisor] set_restart_policy: invalid/unregistered child_id=%d "
            "— ignored (child keeps the default TEMPORARY policy)\n", (int)id);
        return;
    }
    if (intensity_max < 1) intensity_max = 1;
    atomic_store(&c->restart_intensity_max, intensity_max);
    atomic_store(&c->restart_period_us,
                 period_secs > 0 ? period_secs * 1000000 : 0);
    atomic_store(&c->restart_window_start_us, platform_time_monotonic_us());
    atomic_store(&c->restarts_in_window, 0u);
    atomic_store(&c->restart_policy, (int)policy);
}

void supervisor_worker_alive(supervisor_child_id id)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;
    atomic_store(&c->worker_state, SUPERVISOR_WORKER_ALIVE);
}

void supervisor_worker_exited(supervisor_child_id id)
{
    struct liveness_contract *c = contract_for(id);
    if (!c) return;
    atomic_store(&c->worker_state, SUPERVISOR_WORKER_EXITED);
}

/* ── Supervisor loop ───────────────────────────────────────────────── */

/* Bounded restart engine (OTP intensity/period). Runs on the supervisor
 * thread, single-writer for every field it touches here. Called once per child
 * per sweep, BEFORE the stall block so a storm escalation sets stall_reason and
 * the stall block then skips the child. Pure contract math + the on_respawn
 * callback — no pthread/thread_registry knowledge (that lives in the caller's
 * on_respawn, e.g. util/thread_liveness.c), which keeps this unit-testable. */
static void maybe_restart(struct liveness_contract *c, int64_t now)
{
    int policy = atomic_load(&c->restart_policy);
    if (policy == SUPERVISOR_RESTART_TEMPORARY) return;   /* opt-in only */
    if (!c->on_respawn) return;
    if (atomic_load(&c->completed)) return;
    if (atomic_load(&c->worker_state) != SUPERVISOR_WORKER_EXITED) return;
    /* Already gave up (sticky): never respawn again this boot. */
    if (atomic_load(&c->stall_reason) == SUPERVISOR_STALL_REPEATED_RESTART)
        return;

    /* Roll the intensity window forward if it has elapsed. */
    int64_t win_us = atomic_load(&c->restart_period_us);
    if (win_us > 0) {
        int64_t start = atomic_load(&c->restart_window_start_us);
        if ((now - start) > win_us) {
            atomic_store(&c->restart_window_start_us, now);
            atomic_store(&c->restarts_in_window, 0u);
        }
    }

    /* Storm cap: the (N+1)th restart inside the window escalates instead of
     * respawning. Sticky REPEATED_RESTART ⇒ node stays alive + named, never
     * infinite-spawns. */
    int64_t cap = atomic_load(&c->restart_intensity_max);
    if (cap < 1) cap = 1;
    if ((int64_t)atomic_load(&c->restarts_in_window) >= cap) {
        int expected = SUPERVISOR_STALL_NONE;
        if (atomic_compare_exchange_strong(&c->stall_reason,
                &expected, SUPERVISOR_STALL_REPEATED_RESTART)) {
            note_stall_fire(c, SUPERVISOR_STALL_REPEATED_RESTART);
        }
        return;
    }

    /* Claim the death by CAS EXITED → RESTARTING. RESTARTING is a state only
     * the supervisor writes, so it cannot clobber a fast new worker's EXITED
     * (the lost-signal race): on_respawn never writes ALIVE — the fresh worker
     * does, on entry. On a false EXITED (worker still terminating) on_respawn
     * restores EXITED and returns false, so we count nothing and retry next
     * sweep. The single supervisor thread is the only claimer, so the CAS never
     * contends with itself. */
    int expected = SUPERVISOR_WORKER_EXITED;
    if (!atomic_compare_exchange_strong(&c->worker_state, &expected,
                                        SUPERVISOR_WORKER_RESTARTING))
        return;   /* state moved under us; re-check next sweep */
    if (c->on_respawn(c)) {
        atomic_fetch_add(&c->restarts_in_window, 1u);
        atomic_fetch_add(&c->restart_count, 1u);
        atomic_store(&c->last_restart_us, now);
    }
}

/* Runner on_stall: name the blocker (edge-triggered by the sweep). Pure
 * platform/modules/util — blocker_set lives in the same layer (util/blocker.h). No event/
 * app-side header (Gate #14). */
static void runner_on_stall(struct liveness_contract *self)
{
    (void)self;
    struct blocker_record rec;
    if (blocker_init(&rec, "supervisor.tick_runner_wedged", "supervisor",
                     BLOCKER_TRANSIENT,
                     "a supervised child's on_tick has run on the tick-runner "
                     "thread past its deadline; the sweep heartbeat is "
                     "unaffected (node stays alive) but one child's periodic "
                     "work is wedged — inspect `dumpstate supervisor` for the "
                     "child whose last_tick_age exceeds its period"))
        (void)blocker_set(&rec);
}

/* Execute every child whose tick_pending flag is set. Runs on the tick-runner
 * thread in production; runs inline on the sweep thread only as the
 * runner-absent fallback. Snapshots pointers under the registry lock, releases
 * it, then invokes callbacks outside the lock (callbacks re-enter the API). */
static void run_due_ticks(void)
{
    struct liveness_contract *snap[SUPERVISOR_CAP];
    int n;
    pthread_mutex_lock(&g_lock);
    n = g_contract_count;
    memcpy(snap, g_contracts, (size_t)n * sizeof(snap[0]));
    pthread_mutex_unlock(&g_lock);

    for (int i = 0; i < n; i++) {
        /* Same shutdown gate as the sweep: dispatch no further callbacks once
         * process shutdown is requested (a staged-sync tick can read the
         * chainstate app_shutdown frees). */
        if (thread_registry_shutdown_requested()) return;
        struct liveness_contract *c = snap[i];
        if (!c) continue;
        if (atomic_load(&c->completed)) continue;

        bool expected_running = false;
        if (!atomic_compare_exchange_strong(&c->tick_running,
                                             &expected_running, true))
            continue;   /* this contract already has an owned callback */
        bool expected = true;
        if (!atomic_compare_exchange_strong(&c->tick_pending, &expected, false)) {
            atomic_store(&c->tick_running, false);
            continue;   /* not marked due */
        }

        int64_t before = atomic_load(&c->last_tick_us);
        pthread_mutex_lock(&g_lock);
        snprintf(g_runner_active_name, sizeof(g_runner_active_name), "%s",
                 c->name);
        pthread_mutex_unlock(&g_lock);
        if (c->on_tick) c->on_tick(c);
        pthread_mutex_lock(&g_lock);
        g_runner_active_name[0] = '\0';
        pthread_mutex_unlock(&g_lock);
        /* If on_tick didn't call supervisor_tick itself, stamp it now so we
         * don't busy-fire — byte-identical to the old inline sweep semantics
         * (works for on_tick==NULL period-driven children too). */
        int64_t after = atomic_load(&c->last_tick_us);
        if (after == before) {
            atomic_store(&c->last_tick_us, platform_time_monotonic_us());
            atomic_fetch_add(&c->ticks_run, 1u);
        }
        atomic_store(&c->tick_running, false);
        /* Heartbeat the runner BETWEEN children so a long batch of children
         * never trips the runner deadline — only a single wedged tick does. */
        atomic_store(&g_runner_contract.last_tick_us,
                     platform_time_monotonic_us());
    }
}

/* Inline runner-liveness monitor, called by the sweep once per pass when a
 * runner thread is active. Edge-triggered: fires the named blocker once when
 * the runner's heartbeat lapses past its deadline, and clears it (+ re-arms)
 * when the runner heartbeats again. The sweep itself does no I/O here — this is
 * pure atomic math + one blocker_set/blocker_clear on the transition edge. */
static void supervisor_monitor_runner(int64_t now)
{
    int64_t rlt = atomic_load(&g_runner_contract.last_tick_us);
    int64_t rdl = atomic_load(&g_runner_contract.deadline_secs);
    int     rsr = atomic_load(&g_runner_contract.stall_reason);

    if (rdl > 0 && (now - rlt) >= rdl * 1000000) {
        int expected = SUPERVISOR_STALL_NONE;
        if (atomic_compare_exchange_strong(&g_runner_contract.stall_reason,
                &expected, SUPERVISOR_STALL_TIME_DEADLINE)) {
            atomic_fetch_add(&g_runner_contract.stall_fires, 1u);
            if (g_runner_contract.on_stall)
                g_runner_contract.on_stall(&g_runner_contract);
        }
    } else if (rsr != SUPERVISOR_STALL_NONE) {
        /* Runner heartbeat resumed within the deadline: clear the latched
         * stall + the named blocker so a transient wedge self-heals. */
        atomic_store(&g_runner_contract.stall_reason, SUPERVISOR_STALL_NONE);
        blocker_clear("supervisor.tick_runner_wedged");
    }
}

static void sweep_once(void)
{
    int64_t now = platform_time_monotonic_us();

    /* Pillar 7: bump FIRST — a hang anywhere below (even inside a
     * child's on_tick) freezes this at its last recorded value. */
    atomic_fetch_add(&g_sweep_heartbeat, 1u);
    atomic_store(&g_sweep_last_us, now);

    /* Snapshot the list of pointers under lock; release before
     * invoking any callback so callbacks can re-enter the API safely. */
    struct liveness_contract *snap[SUPERVISOR_CAP];
    int n;
    pthread_mutex_lock(&g_lock);
    n = g_contract_count;
    memcpy(snap, g_contracts, (size_t)n * sizeof(snap[0]));
    pthread_mutex_unlock(&g_lock);

    for (int i = 0; i < n; i++) {
        /* Shutdown gate: once process shutdown is requested, dispatch no
         * further callbacks. A staged-sync on_tick drains validation work
         * that can run for seconds and must not outlive the chainstate
         * app_shutdown frees; the loop predicate alone cannot stop a
         * sweep already in flight. */
        if (thread_registry_shutdown_requested()) return;
        struct liveness_contract *c = snap[i];
        if (!c) continue;
        if (atomic_load(&c->completed)) continue;

        int64_t last_tick = atomic_load(&c->last_tick_us);
        int64_t period_s  = atomic_load(&c->period_secs);
        int64_t period_u  = atomic_load(&c->period_us);
        int64_t deadl_s   = atomic_load(&c->deadline_secs);
        int64_t quiet_us  = atomic_load(&c->progress_max_quiet_us);

        /* Effective tick window: period_us (sub-second override) wins when set,
         * else period_secs. Default period_us=0 ⇒ byte-identical to before for
         * every child that does not opt into the sub-second cadence. */
        int64_t period_window_us = period_u > 0 ? period_u
                                                : period_s * 1000000;

        /* Periodic on_tick driving. When the configured period has elapsed we
         * only MARK the child due (an atomic flag); the tick-runner thread
         * executes on_tick + stamps last_tick/ticks_run. The sweep never runs
         * a child callback itself, so no child's I/O can freeze this thread.
         * (Idempotent: re-marking an already-pending child is a no-op.) */
        if (period_window_us > 0 &&
            !atomic_load(&c->tick_running) &&
            (now - last_tick) >= period_window_us) {
            atomic_store(&c->tick_pending, true);
        }

        /* Bounded restart policy (OTP): a restartable child whose worker has
         * EXITED is respawned here, or escalated to REPEATED_RESTART on storm.
         * Runs before the stall block: a storm sets stall_reason, which the
         * block below then honors (skips). TEMPORARY children are a no-op. */
        maybe_restart(c, now);

        /* Edge-triggered stall fires. Only on the rising edge:
         * stall_reason transitions NONE → something. */
        int sr = atomic_load(&c->stall_reason);
        if (sr != SUPERVISOR_STALL_NONE) continue;

        /* Reload last_tick_us in case the tick-runner just bumped it. */
        int64_t lt = atomic_load(&c->last_tick_us);

        if (deadl_s > 0 && (now - lt) >= deadl_s * 1000000) {
            int expected = SUPERVISOR_STALL_NONE;
            if (atomic_compare_exchange_strong(&c->stall_reason,
                    &expected, SUPERVISOR_STALL_TIME_DEADLINE)) {
                note_stall_fire(c, SUPERVISOR_STALL_TIME_DEADLINE);
            }
            continue;
        }

        /* ARMED (see effective_progress_policy). `progress_changed_at_us` is
         * refreshed by real progress AND by an explicit idle report, so what
         * this actually detects is "ran repeatedly, produced nothing, and did
         * not claim to be idle" — stuck, as opposed to caught up. */
        if (quiet_us > 0) {
            int64_t changed = atomic_load(&c->progress_changed_at_us);
            if ((now - changed) >= quiet_us) {
                int expected = SUPERVISOR_STALL_NONE;
                if (atomic_compare_exchange_strong(&c->stall_reason,
                        &expected, SUPERVISOR_STALL_NO_PROGRESS)) {
                    note_stall_fire(c, SUPERVISOR_STALL_NO_PROGRESS);
                }
            }
        }
    }

    /* Drain / monitor the tick-runner. When a runner thread is active it owns
     * draining; the sweep just monitors its liveness (no I/O). When there is no
     * runner (spawn failed, or the ZCL_TESTING synchronous seam) the sweep
     * drains due ticks INLINE so children are never silently un-driven. */
    if (atomic_load(&g_runner_enabled))
        supervisor_monitor_runner(now);
    else
        run_due_ticks();
}

/* Tick-runner thread: the ONLY place a child's on_tick runs in production. It
 * heartbeats its own liveness contract at the top of every loop and between
 * children (inside run_due_ticks); a wedge inside a single child tick freezes
 * this heartbeat, which the sweep detects and names as a blocker. */
static void *supervisor_tick_runner_main(void *arg)
{
    (void)arg;
    atomic_store(&g_runner_tid, thread_work_probe_self_tid());
    atomic_store(&g_runner_contract.last_tick_us,
                 platform_time_monotonic_us());
    while (atomic_load(&g_runner_running) &&
           !thread_registry_shutdown_requested())
    {
        uint64_t wake_seq = atomic_load(&g_runner_wake_seq);
        atomic_store(&g_runner_contract.last_tick_us,
                     platform_time_monotonic_us());
        run_due_ticks();
        int ms = atomic_load(&g_tick_ms);
        if (ms < 1) ms = 1;
        if (ms > 60000) ms = 60000;
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += ms / 1000;
        deadline.tv_nsec += (long)(ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&g_runner_wake_lock);
        if (wake_seq == atomic_load(&g_runner_wake_seq) &&
            atomic_load(&g_runner_running) &&
            !thread_registry_shutdown_requested())
            (void)pthread_cond_timedwait(&g_runner_wake_cond,
                                         &g_runner_wake_lock, &deadline);
        pthread_mutex_unlock(&g_runner_wake_lock);
    }
    atomic_store(&g_runner_running, false);
    thread_registry_unregister_self();
    return NULL;
}

static void *supervisor_thread_main(void *arg)
{
    (void)arg;
    atomic_store(&g_thread_alive, true);
    while (atomic_load(&g_running) &&
           !thread_registry_shutdown_requested())
    {
        /* Deliberately NOT joining the Landlock retrofit here (see
         * os_sandbox_landlock_apply_to_self() in platform/os_sandbox.h):
         * this is the single dispatch thread for EVERY registered supervisor
         * child (sweep_once() below runs every g_contracts[] on_tick handler
         * synchronously, across every subsystem). Confining this thread would
         * confine every dispatched on_tick, not just an audited loop — any
         * child callback that does filesystem I/O outside the datadir grant
         * would EPERM-fail with no per-child opt-out. This thread stays the
         * documented Landlock-unconfined-but-seccomp-confined residual
         * alongside file_service/wallet_backup_service/disk_monitor/
         * event_async (see os_sandbox_landlock_apply_to_self's doc comment). */

        sweep_once();
        int ms = atomic_load(&g_tick_ms);
        if (ms < 1) ms = 1;
        if (ms > 60000) ms = 60000;
        struct timespec req = { ms / 1000, (long)(ms % 1000) * 1000000L };
        nanosleep(&req, NULL);
    }
    atomic_store(&g_thread_alive, false);
    thread_registry_unregister_self();
    return NULL;
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */

bool supervisor_start(void)
{
    bool was = atomic_exchange(&g_running, true);
    if (was) return true;        /* idempotent */
    atomic_store(&g_thread_alive, false);

    pthread_t tid;
    int rc = thread_registry_spawn("zcl_supervisor",
                                       supervisor_thread_main, NULL, &tid);
    if (rc != 0) {
        atomic_store(&g_running, false);
        fprintf(stderr,
            "[supervisor] FAIL thread_registry_spawn rc=%d\n", rc);
        return false;
    }
    g_thread_id = tid;
    atomic_store(&g_thread_handle_set, true);

    /* Spawn the dedicated tick-runner. It, not the sweep, executes every
     * child's on_tick. Arm its liveness contract (deadline-monitored inline by
     * the sweep — see supervisor_monitor_runner). If the spawn fails we leave
     * g_runner_enabled=false so the sweep drains ticks inline (degraded but
     * never un-driven); the sweep itself is already up, so the node lives. */
    liveness_contract_init(&g_runner_contract, "supervisor.tick_runner");
    atomic_store(&g_runner_contract.deadline_secs,
                 (int64_t)SUPERVISOR_TICK_RUNNER_DEADLINE_SECS);
    g_runner_contract.on_stall = runner_on_stall;
    atomic_store(&g_runner_contract.last_tick_us,
                 platform_time_monotonic_us());
    atomic_store(&g_runner_running, true);
    pthread_t rtid;
    // thread-supervision-ok:monitored-inline-by-the-sweep-not-via-g_contracts
    int rrc = thread_registry_spawn("zcl_supervisor_tick_runner",
                                    supervisor_tick_runner_main, NULL, &rtid);
    if (rrc != 0) {
        atomic_store(&g_runner_running, false);
        atomic_store(&g_runner_enabled, false);
        fprintf(stderr,  // obs-ok:supervisor-tick-runner-spawn-fail
            "[supervisor] WARN tick-runner spawn rc=%d — sweep drains ticks "
            "inline (degraded: a slow child tick can freeze the sweep)\n", rrc);
    } else {
        g_runner_thread_id = rtid;
        atomic_store(&g_runner_handle_set, true);
        atomic_store(&g_runner_enabled, true);
    }
    return true;
}

void supervisor_stop(void)
{
    if (!atomic_load(&g_running)) return;
    atomic_store(&g_running, false);

    /* Stop the tick-runner first (it may be mid-on_tick). Disable monitoring
     * so a slow drain during teardown doesn't spuriously name the blocker. */
    atomic_store(&g_runner_enabled, false);
    atomic_store(&g_runner_running, false);
    atomic_fetch_add(&g_runner_wake_seq, UINT64_C(1));
    pthread_mutex_lock(&g_runner_wake_lock);
    pthread_cond_signal(&g_runner_wake_cond);
    pthread_mutex_unlock(&g_runner_wake_lock);
    if (atomic_load(&g_runner_handle_set)) {
        for (;;) {
            struct timespec rdeadline;
            platform_time_realtime_timespec(&rdeadline);
            rdeadline.tv_sec += 2;
            int rjc = platform_thread_join_until(g_runner_thread_id, NULL,
                                                 &rdeadline);
            if (rjc == 0) {
                atomic_store(&g_runner_handle_set, false);
                break;
            }
            if (rjc != ETIMEDOUT || !thread_registry_shutdown_requested()) {
                fprintf(stderr,  // obs-ok:supervisor-tick-runner-join
                    "[supervisor] WARN tick-runner join rc=%d (thread still alive)\n",
                    rjc);
                break;
            }
            fprintf(stderr,  // obs-ok:shutdown-join-progress
                "[supervisor] shutdown join: tick-runner still draining; waiting\n");
        }
    }

    /* Join the loop. It polls g_running and the global shutdown flag
     * between sweeps, and sweep_once dispatches no callbacks once
     * shutdown is requested, so the wait is bounded by the one in-flight
     * on_tick. On the shutdown path that tick can be a multi-second
     * staged-sync drain reading the chainstate app_shutdown frees next —
     * abandoning the thread there is a use-after-free, so keep re-arming
     * the 2 s join with progress logs (the alarm() watchdog in
     * app_shutdown_svc is the hard backstop for a truly hung tick).
     * Non-shutdown callers (test teardown) keep the single ≤2 s attempt. */
    if (atomic_load(&g_thread_handle_set)) {
        for (;;) {
            struct timespec deadline;
            platform_time_realtime_timespec(&deadline);
            deadline.tv_sec += 2;
            int rc = platform_thread_join_until(g_thread_id, NULL, &deadline);
            if (rc == 0) {
                atomic_store(&g_thread_handle_set, false);
                break;
            }
            if (rc != ETIMEDOUT || !thread_registry_shutdown_requested()) {
                fprintf(stderr,  // obs-ok:pre-existing-diagnostic
                    "[supervisor] WARN supervisor_stop join rc=%d (thread still alive)\n",
                    rc);
                break;
            }
            fprintf(stderr,  // obs-ok:shutdown-join-progress
                "[supervisor] shutdown join: in-flight tick still draining; waiting\n");
        }
    }
}

void supervisor_set_tick_ms_for_testing(int ms)
{
    if (ms < 1) ms = 1;
    atomic_store(&g_tick_ms, ms);
}

void supervisor_request_min_tick_ms(int ms)
{
    if (ms < 1) return;              /* no-op on a nonsense request */
    if (ms > 60000) ms = 60000;      /* mirror the loop's own clamp */
    /* Monotonic min via a CAS loop: never RAISE the interval (another
     * accelerated child may have already lowered it), only lower it. */
    int cur = atomic_load(&g_tick_ms);
    while (ms < cur) {
        if (atomic_compare_exchange_weak(&g_tick_ms, &cur, ms))
            break;
        /* cur reloaded by the CAS; loop re-checks ms < cur. */
    }
}

#ifdef ZCL_TESTING
void supervisor_reset_for_testing(void)
{
    /* Stop first so the sweeper isn't iterating while we clear. */
    supervisor_stop();
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < SUPERVISOR_CAP; i++) g_contracts[i] = NULL;
    for (int i = 0; i < SUPERVISOR_CAP; i++) g_contract_domains[i] = NULL;
    g_contract_count = 0;
    memset(g_domains, 0, sizeof(g_domains));
    g_domain_count = 0;
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_tick_ms, 1000);
    atomic_store_explicit(&g_stall_observer, NULL, memory_order_release);

    /* supervisor_stop() already cleared g_runner_enabled/running; clear the
     * monitored contract's latched state so the next test starts clean. */
    atomic_store(&g_runner_enabled, false);
    atomic_store(&g_runner_contract.stall_reason, SUPERVISOR_STALL_NONE);
    atomic_store(&g_runner_contract.stall_fires, 0u);
    blocker_clear("supervisor.tick_runner_wedged");
}

void supervisor_sweep_once_for_testing(void)
{
    sweep_once();
}

void supervisor_tick_runner_setup_for_testing(int64_t deadline_secs)
{
    liveness_contract_init(&g_runner_contract, "supervisor.tick_runner");
    atomic_store(&g_runner_contract.deadline_secs, deadline_secs);
    g_runner_contract.on_stall = runner_on_stall;
    atomic_store(&g_runner_contract.last_tick_us,
                 platform_time_monotonic_us());
    atomic_store(&g_runner_enabled, true);
}

void supervisor_tick_runner_backdate_hb_for_testing(int64_t age_us)
{
    atomic_store(&g_runner_contract.last_tick_us,
                 platform_time_monotonic_us() - age_us);
}

void supervisor_tick_runner_monitor_for_testing(void)
{
    supervisor_monitor_runner(platform_time_monotonic_us());
}
#endif

int64_t supervisor_tick_runner_last_hb_age_us(void)
{
    return platform_time_monotonic_us() -
           atomic_load(&g_runner_contract.last_tick_us);
}

uint32_t supervisor_tick_runner_stall_fires(void)
{
    return atomic_load(&g_runner_contract.stall_fires);
}

bool supervisor_tick_runner_running(void)
{
    return atomic_load(&g_runner_running);
}

long supervisor_tick_runner_tid(void)
{
    return atomic_load(&g_runner_tid);
}

const char *supervisor_active_callback_name(void)
{
    static _Thread_local char name[SUPERVISOR_NAME_MAX];
    pthread_mutex_lock(&g_lock);
    snprintf(name, sizeof(name), "%s",
             g_runner_active_name[0] ? g_runner_active_name : "none");
    pthread_mutex_unlock(&g_lock);
    return name;
}

/* ── Introspection ─────────────────────────────────────────────────── */

int supervisor_child_count_total(void)
{
    pthread_mutex_lock(&g_lock);
    int n = supervisor_live_count_locked();
    pthread_mutex_unlock(&g_lock);
    return n;
}

uint64_t supervisor_sweep_heartbeat(void)
{
    return atomic_load(&g_sweep_heartbeat);
}

int64_t supervisor_sweep_last_us(void)
{
    return atomic_load(&g_sweep_last_us);
}

int supervisor_snapshot_all(struct supervisor_snapshot *out, int max)
{
    if (!out || max <= 0) return 0;
    int64_t now = platform_time_monotonic_us();
    pthread_mutex_lock(&g_lock);
    /* Dense live-only snapshot: retired (NULL) slots are skipped, so a
     * recently restarted subsystem never appears twice and never faults
     * the dereference below. */
    int n = 0;
    for (int i = 0; i < g_contract_count && n < max; i++) {
        const struct liveness_contract *c = g_contracts[i];
        if (!c)
            continue;
        memset(&out[n], 0, sizeof(out[n]));
        memcpy(out[n].name, c->name, sizeof(out[n].name));
        out[n].parent           = c->parent;
        int64_t lt              = atomic_load(&c->last_tick_us);
        out[n].last_tick_age_us = now - lt;
        out[n].progress_marker  = atomic_load(&c->progress_marker);
        out[n].period_secs      = atomic_load(&c->period_secs);
        out[n].period_us        = atomic_load(&c->period_us);
        out[n].deadline_secs    = atomic_load(&c->deadline_secs);
        out[n].completed        = atomic_load(&c->completed);
        out[n].stall_reason     = atomic_load(&c->stall_reason);
        out[n].progress_policy  = (int)effective_progress_policy(c);
        out[n].progress_max_quiet_us =
                                  atomic_load(&c->progress_max_quiet_us);
        memcpy(out[n].progress_exempt_reason, c->progress_exempt_reason,
               sizeof(out[n].progress_exempt_reason));
        out[n].ticks_run        = atomic_load(&c->ticks_run);
        out[n].idle_ticks       = atomic_load(&c->idle_ticks);
        out[n].stall_fires      = atomic_load(&c->stall_fires);
        out[n].restart_count    = atomic_load(&c->restart_count);
        out[n].restart_policy   = atomic_load(&c->restart_policy);
        out[n].worker_state     = atomic_load(&c->worker_state);
        out[n].restarts_in_window = atomic_load(&c->restarts_in_window);
        n++;
    }
    pthread_mutex_unlock(&g_lock);
    return n;
}

bool supervisor_dump_state_json(struct json_value *out, const char *key)
{
    if (!out) return false;
    json_set_object(out);
    json_push_kv_bool(out, "running",      atomic_load(&g_running));
    json_push_kv_bool(out, "thread_alive", atomic_load(&g_thread_alive));
    json_push_kv_int (out, "tick_ms",      atomic_load(&g_tick_ms));
    /* Pillar 7: is the root sweep thread itself alive. */
    json_push_kv_int (out, "sweep_heartbeat",
                      (int64_t)atomic_load(&g_sweep_heartbeat));
    json_push_kv_int (out, "sweep_last_age_us",
                      platform_time_monotonic_us() - atomic_load(&g_sweep_last_us));
    /* Tick-runner: the thread that actually executes child on_tick callbacks.
     * A last_hb_age_us past the runner deadline means one child's tick is
     * wedged (named via the supervisor.tick_runner_wedged blocker); the sweep
     * above is unaffected, so the node stays alive. */
    json_push_kv_bool(out, "tick_runner_running",
                      atomic_load(&g_runner_running));
    json_push_kv_int (out, "tick_runner_last_hb_age_us",
                      supervisor_tick_runner_last_hb_age_us());
    json_push_kv_int (out, "tick_runner_stall_fires",
                      (int64_t)atomic_load(&g_runner_contract.stall_fires));
    json_push_kv_str(out, "active_callback",
                     supervisor_active_callback_name());
    /* Progress-policy debt, at the root where an operator reads it first:
     * how many supervised children have no answer to "how would anyone know
     * if this stopped achieving anything?". Floored (shrink-only) by
     * tools/lint/check_supervisor_progress_declared.sh. */
    json_push_kv_int (out, "progress_undeclared_count",
                      (int64_t)supervisor_progress_undeclared_count());
    /* Registry margin. 0 means the next subsystem to register runs
     * UNSUPERVISED — see SUPERVISOR_CAP in util/supervisor.h. */
    json_push_kv_int (out, "child_headroom",
                      (int64_t)supervisor_child_headroom());

    if (key && key[0]) {
        pthread_mutex_lock(&g_lock);
        supervisor_domain_t *domain = NULL;
        for (int i = 0; i < g_domain_count; i++) {
            if (strncmp(g_domains[i].label, key, SUPERVISOR_NAME_MAX) == 0) {
                domain = &g_domains[i];
                break;
            }
        }
        pthread_mutex_unlock(&g_lock);
        return supervisor_domain_dump_state_json(domain, out);
    }

    json_push_kv_int(out, "child_count", supervisor_child_count_total());

    struct json_value domains;
    json_init(&domains);
    json_set_array(&domains);

    pthread_mutex_lock(&g_lock);
    supervisor_domain_t *domain_snap[SUPERVISOR_DOMAIN_CAP];
    int dn = g_domain_count;
    for (int i = 0; i < dn; i++) domain_snap[i] = &g_domains[i];
    pthread_mutex_unlock(&g_lock);

    for (int i = 0; i < dn; i++) {
        struct json_value domain_json;
        json_init(&domain_json);
        if (supervisor_domain_dump_state_json(domain_snap[i], &domain_json)) {
            json_push_back(&domains, &domain_json);
        }
        json_free(&domain_json);
    }
    json_push_kv(out, "domains", &domains);
    json_free(&domains);

    struct json_value orphans;
    json_init(&orphans);
    json_set_array(&orphans);
    struct supervisor_domain root_domain;
    memset(&root_domain, 0, sizeof(root_domain));
    if (supervisor_domain_dump_state_json(&root_domain, &orphans)) {
        const struct json_value *kids = json_get(&orphans, "children");
        if (kids) json_push_kv(out, "root_orphans", kids);
    } else {
        json_push_kv(out, "root_orphans", &orphans);
    }
    json_free(&orphans);
    return true;
}

static void push_contract_json(struct json_value *arr,
                               const struct liveness_contract *c,
                               int64_t now)
{
    struct json_value child;
    json_init(&child);
    json_set_object(&child);
    json_push_kv_str (&child, "name",   c->name);
    json_push_kv_int (&child, "parent", c->parent);
    int64_t lt = atomic_load(&c->last_tick_us);
    json_push_kv_int (&child, "last_tick_age_us", now - lt);
    json_push_kv_int (&child, "progress_marker",
                      atomic_load(&c->progress_marker));
    json_push_kv_int (&child, "period_secs",
                      atomic_load(&c->period_secs));
    json_push_kv_int (&child, "period_us",
                      atomic_load(&c->period_us));
    json_push_kv_int (&child, "deadline_secs",
                      atomic_load(&c->deadline_secs));
    json_push_kv_bool(&child, "completed",
                      atomic_load(&c->completed));
    json_push_kv_str (&child, "stall_reason",
                      supervisor_stall_reason_name(
                          (enum supervisor_stall_reason)
                          atomic_load(&c->stall_reason)));
    json_push_kv_int (&child, "ticks_run",
                      atomic_load(&c->ticks_run));
    /* Results, not activity. `ticks_run` says it ran; these say whether it
     * achieved anything, was legitimately idle, or is being watched at all.
     * ticks_run - idle_ticks is the count of runs that were supposed to
     * produce something. */
    json_push_kv_int (&child, "idle_ticks",
                      atomic_load(&c->idle_ticks));
    json_push_kv_str (&child, "progress_policy",
                      supervisor_progress_policy_name(
                          effective_progress_policy(c)));
    json_push_kv_int (&child, "progress_max_quiet_us",
                      atomic_load(&c->progress_max_quiet_us));
    json_push_kv_str (&child, "progress_exempt_reason",
                      c->progress_exempt_reason);
    json_push_kv_int (&child, "stall_fires",
                      atomic_load(&c->stall_fires));
    json_push_kv_int (&child, "restart_count",
                      atomic_load(&c->restart_count));
    json_push_kv_str (&child, "restart_policy",
                      supervisor_restart_policy_name(
                          (enum supervisor_restart_policy)
                          atomic_load(&c->restart_policy)));
    json_push_kv_int (&child, "restarts_in_window",
                      atomic_load(&c->restarts_in_window));
    json_push_back(arr, &child);
    json_free(&child);
}

bool supervisor_domain_dump_state_json(supervisor_domain_t *domain,
                                       struct json_value *out)
{
    if (!domain || !out) return false;
    bool root = (domain->label[0] == '\0');
    json_set_object(out);
    json_push_kv_str(out, "name", root ? "root" : domain->label);

    struct liveness_contract *snap[SUPERVISOR_CAP];
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_contract_count && n < SUPERVISOR_CAP; i++) {
        if (g_contracts[i] == NULL)
            continue; /* retired slot: never counted, never dumped */
        bool match = root ? (g_contract_domains[i] == NULL)
                          : (g_contract_domains[i] == domain);
        if (match) snap[n++] = g_contracts[i];
    }
    pthread_mutex_unlock(&g_lock);

    json_push_kv_int(out, "child_count", n);
    struct json_value children;
    json_init(&children);
    json_set_array(&children);
    int64_t now = platform_time_monotonic_us();
    for (int i = 0; i < n; i++) {
        if (snap[i]) push_contract_json(&children, snap[i], now);
    }
    json_push_kv(out, "children", &children);
    json_free(&children);
    return true;
}
