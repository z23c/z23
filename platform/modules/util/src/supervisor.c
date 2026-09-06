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
 *   - Registry mutex protects the array of pointers. Dedicated bounded
 *     workers invoke child tick and stall callbacks without holding it. */

#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "util/supervisor.h"
#include "supervisor_internal.h"

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

pthread_mutex_t g_supervisor_lock = PTHREAD_MUTEX_INITIALIZER;

struct liveness_contract *g_supervisor_contracts[SUPERVISOR_CAP];
supervisor_domain_t      *g_supervisor_contract_domains[SUPERVISOR_CAP];
int                       g_supervisor_contract_count = 0;

supervisor_domain_t g_supervisor_domains[SUPERVISOR_DOMAIN_CAP];
int                 g_supervisor_domain_count = 0;

_Atomic bool g_supervisor_running      = false;
_Atomic bool g_supervisor_thread_alive = false;
_Atomic int  g_supervisor_tick_ms      = 1000;
static pthread_t      g_thread_id;
static _Atomic bool   g_thread_handle_set = false;

/* Pillar 7 heartbeat: bumps once per sweep_once() call, before sweep work.
 * Child tick and stall callbacks are isolated; inline on_respawn remains an
 * explicit residual callback that can freeze the sweep. See
 * util/supervisor_backstop.h for the external watcher. */
_Atomic uint64_t g_supervisor_sweep_heartbeat = 0;
_Atomic int64_t  g_supervisor_sweep_last_us   = 0;

/* Process-wide stall observer (ops.debug.bundle auto-capture registers it
 * at boot). NULL by default; release-store / acquire-load publication. */
static supervisor_stall_observer_fn _Atomic g_stall_observer = NULL;

/* One fixed worker drains the one-slot handoff embedded in each contract.
 * A blocked recovery action can delay other recovery actions, but cannot
 * delay the root sweep heartbeat or allocate more work. */
_Atomic bool g_supervisor_stall_runner_running = false;
static pthread_t g_stall_runner_thread_id;
static _Atomic bool g_stall_runner_handle_set = false;
static pthread_mutex_t g_stall_wake_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_stall_wake_cond = PTHREAD_COND_INITIALIZER;
static _Atomic uint64_t g_stall_wake_seq = 0;
_Atomic int64_t g_supervisor_stall_runner_last_us = 0;
static char g_stall_runner_active_name[SUPERVISOR_NAME_MAX];
enum runner_blocker_action {
    RUNNER_BLOCKER_NONE = 0,
    RUNNER_BLOCKER_SET,
    RUNNER_BLOCKER_CLEAR,
};
_Atomic int g_supervisor_runner_blocker_action = RUNNER_BLOCKER_NONE;
_Atomic uint32_t g_supervisor_runner_blocker_coalesced = 0;
_Atomic uint32_t g_supervisor_runner_blocker_discarded = 0;
#ifdef ZCL_TESTING
static supervisor_stale_cancel_hook_fn g_stale_cancel_hook;
static void *g_stale_cancel_hook_ctx;
static supervisor_rearm_cancel_hook_fn g_rearm_cancel_hook;
static void *g_rearm_cancel_hook_ctx;
#endif

void supervisor_set_stall_observer(supervisor_stall_observer_fn fn)
{
    atomic_store_explicit(&g_stall_observer, fn, memory_order_release);
}

static void stall_wake(void)
{
    atomic_fetch_add(&g_stall_wake_seq, UINT64_C(1));
    pthread_mutex_lock(&g_stall_wake_lock);
    pthread_cond_signal(&g_stall_wake_cond);
    pthread_mutex_unlock(&g_stall_wake_lock);
}

static void stall_deliver(struct liveness_contract *c,
                          enum supervisor_stall_reason r)
{
    if (c->on_stall)
        c->on_stall(c);
    supervisor_stall_observer_fn obs =
        atomic_load_explicit(&g_stall_observer, memory_order_acquire);
    if (obs)
        obs(c->name, r);
}

static void stall_cancel_pending(struct liveness_contract *c)
{
    uint64_t observed = atomic_load(&c->stall_delivery_pending);
    while (supervisor_stall_token_reason(observed) != SUPERVISOR_STALL_NONE) {
        uint64_t cleared = supervisor_stall_token_cleared(observed);
        if (atomic_compare_exchange_weak(&c->stall_delivery_pending,
                                         &observed, cleared)) {
            atomic_fetch_add(&c->stall_delivery_discarded, 1u);
            return;
        }
    }
}

static void stall_cancel_observed(struct liveness_contract *c,
                                  uint64_t observed)
{
    if (supervisor_stall_token_reason(observed) == SUPERVISOR_STALL_NONE)
        return;
    uint64_t expected = observed;
    if (atomic_compare_exchange_strong(&c->stall_delivery_pending,
                                       &expected,
                                       supervisor_stall_token_cleared(observed)))
        atomic_fetch_add(&c->stall_delivery_discarded, 1u);
}

/* Cancel only the exact report the caller looked at. The delivery worker
 * reads the pending reason and the live stall reason in two separate loads;
 * between them a child can rearm and report a NEWER stall into the same slot.
 * Clearing the slot unconditionally there would throw that fresh report away,
 * and because stall_reason stays latched the sweep would never fire it again —
 * the stall would be lost for the life of the process. */
static void stall_cancel_stale(struct liveness_contract *c, uint64_t observed)
{
#ifdef ZCL_TESTING
    if (g_stale_cancel_hook) {
        supervisor_stale_cancel_hook_fn hook = g_stale_cancel_hook;
        void *ctx = g_stale_cancel_hook_ctx;
        pthread_mutex_unlock(&g_lock);
        hook(c, supervisor_stall_token_reason(observed), ctx);
        pthread_mutex_lock(&g_lock);
    }
#endif
    stall_cancel_observed(c, observed);
}

/* Rearm owns only the report incarnation it observed before making the live
 * reason NONE. A new report published in that window advances the token and
 * must remain pending. Completion/unregister deliberately use the separate
 * cancel-current helper above. */
static void stall_cancel_rearmed(struct liveness_contract *c,
                                 uint64_t observed)
{
#ifdef ZCL_TESTING
    supervisor_rearm_cancel_hook_fn hook = NULL;
    void *ctx = NULL;
    pthread_mutex_lock(&g_lock);
    hook = g_rearm_cancel_hook;
    ctx = g_rearm_cancel_hook_ctx;
    pthread_mutex_unlock(&g_lock);
    if (hook)
        hook(c, ctx);
#endif
    stall_cancel_observed(c, observed);
}

/* Publish reason and incarnation together. Cancellation preserves the upper
 * incarnation bits; every later report advances them, so an old claim cannot
 * match a replacement with the same reason. At 2^56-1 publications the slot
 * saturates and refuses further delivery instead of wrapping into an ABA. */
static bool stall_publish(struct liveness_contract *c,
                          enum supervisor_stall_reason r)
{
    uint64_t observed = atomic_load(&c->stall_delivery_pending);
    for (;;) {
        uint64_t generation =
            observed >> SUPERVISOR_STALL_TOKEN_REASON_BITS;
        if (generation ==
                (UINT64_MAX >> SUPERVISOR_STALL_TOKEN_REASON_BITS)) {
            fprintf(stderr,  // obs-ok:supervisor-stall-generation-exhausted
                "[supervisor] FAIL stall delivery incarnation exhausted "
                "for child='%s'\n", c->name);
            atomic_fetch_add(&c->stall_delivery_discarded, 1u);
            return false;
        }
        uint64_t replacement =
            ((generation + UINT64_C(1)) <<
                 SUPERVISOR_STALL_TOKEN_REASON_BITS) |
            (uint64_t)r;
        if (atomic_compare_exchange_weak(&c->stall_delivery_pending,
                                         &observed, replacement)) {
            if (supervisor_stall_token_reason(observed) !=
                    SUPERVISOR_STALL_NONE)
                atomic_fetch_add(&c->stall_delivery_coalesced, 1u);
            return true;
        }
    }
}

/* Single stall-fire path for every trigger site. Production delivery uses a
 * fixed per-contract slot; no caller callback or observer runs on the root
 * sweep. Tests that drive sweep_once without starting threads remain
 * synchronous. */
static void note_stall_fire(struct liveness_contract *c,
                            enum supervisor_stall_reason r)
{
    atomic_fetch_add(&c->stall_fires, 1u);
    if (!atomic_load(&g_running)) {
        /* Preserve the historical before-start/testing seam only when no
         * production worker can still be draining. stop() clears g_running
         * before joining the sweep, so a handle here means drop, never an
         * inline callback on that in-flight sweep. */
        if (!atomic_load(&g_thread_handle_set) &&
            !atomic_load(&g_stall_runner_handle_set))
            stall_deliver(c, r);
        else
            atomic_fetch_add(&c->stall_delivery_discarded, 1u);
        return;
    }
    if (stall_publish(c, r))
        stall_wake();
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
 * g_runner_enabled is the drain-ownership flag. Production startup requires
 * the runner; the false/inline case exists only for the ZCL_TESTING
 * synchronous seam. */
#define SUPERVISOR_TICK_RUNNER_DEADLINE_SECS 30
_Atomic bool g_supervisor_runner_running = false;
/* Published by the runner thread from its own entry point (0 until it runs).
 * Lets a liveness gate ask the kernel whether the runner is working while it
 * sits inside one child's on_tick, rather than reading a stale heartbeat as
 * death. */
static _Atomic long   g_runner_tid       = 0;
static _Atomic bool   g_runner_enabled    = false;
static pthread_t      g_runner_thread_id;
static _Atomic bool   g_runner_handle_set = false;
struct liveness_contract g_supervisor_runner_contract;
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
enum supervisor_progress_policy
supervisor_effective_progress_policy(const struct liveness_contract *c)
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
    if (g_contracts[id])
        stall_cancel_pending(g_contracts[id]);
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
    stall_cancel_pending(c);
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
        uint64_t pending = atomic_load(&c->stall_delivery_pending);
        atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
        stall_cancel_rearmed(c, pending);
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
        if (sr == SUPERVISOR_STALL_NO_PROGRESS) {
            uint64_t pending = atomic_load(&c->stall_delivery_pending);
            atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
            stall_cancel_rearmed(c, pending);
        }
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
    if (sr == SUPERVISOR_STALL_NO_PROGRESS) {
        uint64_t pending = atomic_load(&c->stall_delivery_pending);
        atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
        stall_cancel_rearmed(c, pending);
    }
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
int supervisor_live_count_locked(void)
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

static void runner_blocker_apply(enum runner_blocker_action action)
{
    if (action == RUNNER_BLOCKER_SET)
        runner_on_stall(&g_runner_contract);
    else if (action == RUNNER_BLOCKER_CLEAR)
        blocker_clear("supervisor.tick_runner_wedged");
}

static void runner_blocker_schedule(enum runner_blocker_action action)
{
    if (!atomic_load(&g_running)) {
        if (!atomic_load(&g_thread_handle_set) &&
            !atomic_load(&g_stall_runner_handle_set))
            runner_blocker_apply(action);
        else
            atomic_fetch_add(&g_runner_blocker_discarded, 1u);
        return;
    }
    int previous = atomic_exchange(&g_runner_blocker_action, (int)action);
    if (previous != RUNNER_BLOCKER_NONE)
        atomic_fetch_add(&g_runner_blocker_coalesced, 1u);
    stall_wake();
}

static bool stall_deliver_one(void)
{
    struct liveness_contract *claimed = NULL;
    enum supervisor_stall_reason reason = SUPERVISOR_STALL_NONE;

    /* Claim only the next live slot. Do not snapshot pending pointers across
     * an earlier blocking callback: completion/unregister can still cancel
     * every later slot before this worker reaches it. */
    pthread_mutex_lock(&g_lock);
    if (!atomic_load(&g_stall_runner_running)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }
    for (int i = 0; i < g_contract_count; i++) {
        struct liveness_contract *c = g_contracts[i];
        if (!c)
            continue;
        uint64_t pending = atomic_load(&c->stall_delivery_pending);
        enum supervisor_stall_reason reason_pending =
            supervisor_stall_token_reason(pending);
        if (reason_pending == SUPERVISOR_STALL_NONE)
            continue;
        if (atomic_load(&c->completed) ||
            atomic_load(&c->stall_reason) != (int)reason_pending) {
            stall_cancel_stale(c, pending);
            continue;
        }
        uint64_t expected = pending;
        if (atomic_compare_exchange_strong(&c->stall_delivery_pending,
                                            &expected,
                                            supervisor_stall_token_cleared(
                                                pending))) {
            claimed = c;
            reason = reason_pending;
            snprintf(g_stall_runner_active_name,
                     sizeof(g_stall_runner_active_name), "%s", c->name);
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (!claimed)
        return false;
    /* Membership was valid when claimed. Unregister cancels work not yet
     * claimed; it is deliberately not a quiescence barrier for this callback. */
    atomic_store(&g_stall_runner_last_us, platform_time_monotonic_us());
    stall_deliver(claimed, reason);
    pthread_mutex_lock(&g_lock);
    g_stall_runner_active_name[0] = '\0';
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_stall_runner_last_us, platform_time_monotonic_us());
    return true;
}

static void stall_discard_all(void)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_contract_count; i++) {
        if (g_contracts[i])
            stall_cancel_pending(g_contracts[i]);
    }
    pthread_mutex_unlock(&g_lock);
    if (atomic_exchange(&g_runner_blocker_action,
                        RUNNER_BLOCKER_NONE) != RUNNER_BLOCKER_NONE)
        atomic_fetch_add(&g_runner_blocker_discarded, 1u);
}

static void *supervisor_stall_runner_main(void *arg)
{
    (void)arg;
    while (atomic_load(&g_stall_runner_running) &&
           !thread_registry_shutdown_requested()) {
        atomic_store(&g_stall_runner_last_us, platform_time_monotonic_us());
        uint64_t wake_seq = atomic_load(&g_stall_wake_seq);
        int action = atomic_load(&g_stall_runner_running)
            ? atomic_exchange(&g_runner_blocker_action, RUNNER_BLOCKER_NONE)
            : RUNNER_BLOCKER_NONE;
        if (action != RUNNER_BLOCKER_NONE) {
            pthread_mutex_lock(&g_lock);
            snprintf(g_stall_runner_active_name,
                     sizeof(g_stall_runner_active_name), "%s",
                     "supervisor.tick_runner");
            pthread_mutex_unlock(&g_lock);
            runner_blocker_apply((enum runner_blocker_action)action);
            pthread_mutex_lock(&g_lock);
            g_stall_runner_active_name[0] = '\0';
            pthread_mutex_unlock(&g_lock);
            atomic_store(&g_stall_runner_last_us, platform_time_monotonic_us());
        }
        if (stall_deliver_one())
            continue;

        pthread_mutex_lock(&g_stall_wake_lock);
        if (wake_seq == atomic_load(&g_stall_wake_seq) &&
            atomic_load(&g_stall_runner_running) &&
            !thread_registry_shutdown_requested()) {
            struct timespec deadline;
            platform_time_realtime_timespec(&deadline);
            deadline.tv_sec += 1;
            (void)pthread_cond_timedwait(&g_stall_wake_cond,
                                         &g_stall_wake_lock, &deadline);
        }
        pthread_mutex_unlock(&g_stall_wake_lock);
    }
    stall_discard_all();
    atomic_store(&g_stall_runner_running, false);
    thread_registry_unregister_self();
    return NULL;
}

/* Execute every child whose tick_pending flag is set. Runs on the tick-runner
 * thread in production and inline only in the threadless test seam. Snapshots
 * pointers under the registry lock, then invokes callbacks outside it. */
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
            runner_blocker_schedule(RUNNER_BLOCKER_SET);
        }
    } else if (rsr != SUPERVISOR_STALL_NONE) {
        /* Runner heartbeat resumed within the deadline: clear the latched
         * stall + the named blocker so a transient wedge self-heals. */
        atomic_store(&g_runner_contract.stall_reason, SUPERVISOR_STALL_NONE);
        runner_blocker_schedule(RUNNER_BLOCKER_CLEAR);
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

    /* Drain / monitor the tick-runner. Production startup requires it. Inline
     * draining exists only for the threadless synchronous test seam; stop()
     * cannot turn an in-flight root sweep into a callback runner. */
    if (atomic_load(&g_runner_enabled))
        supervisor_monitor_runner(now);
    else if (!atomic_load(&g_thread_handle_set))
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

static bool stall_runner_stop_and_join(void)
{
    atomic_store(&g_stall_runner_running, false);
    stall_wake();
    if (!atomic_load(&g_stall_runner_handle_set))
        return true;
    for (;;) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 2;
        int rc = platform_thread_join_until(g_stall_runner_thread_id, NULL,
                                             &deadline);
        if (rc == 0) {
            atomic_store(&g_stall_runner_handle_set, false);
            return true;
        }
        if (rc != ETIMEDOUT || !thread_registry_shutdown_requested()) {
            fprintf(stderr,  // obs-ok:supervisor-stall-runner-join
                "[supervisor] WARN stall-delivery join rc=%d "
                "(thread still alive)\n", rc);
            return false;
        }
        fprintf(stderr,  // obs-ok:shutdown-join-progress
            "[supervisor] shutdown join: stall delivery still draining; "
            "waiting\n");
    }
}

bool supervisor_start(void)
{
    bool was = atomic_exchange(&g_running, true);
    if (was) return true;        /* idempotent */
    if (atomic_load(&g_thread_handle_set) ||
        atomic_load(&g_runner_handle_set) ||
        atomic_load(&g_stall_runner_handle_set)) {
        atomic_store(&g_running, false);
        fprintf(stderr,  // obs-ok:supervisor-unjoined-worker
            "[supervisor] FAIL start: a prior worker handle is not joined\n");
        return false;
    }
    atomic_store(&g_thread_alive, false);

    /* Recovery delivery is required: starting the sweep without it would
     * either lose stalls or force callbacks back onto the keepalive thread. */
    atomic_store(&g_stall_runner_running, true);
    pthread_t stid;
    // thread-supervision-ok:fixed-bounded-delivery-worker-joined-by-supervisor
    int src = thread_registry_spawn("zcl_supervisor_stall",
                                    supervisor_stall_runner_main, NULL,
                                    &stid);
    if (src != 0) {
        atomic_store(&g_stall_runner_running, false);
        atomic_store(&g_running, false);
        stall_discard_all();
        fprintf(stderr,  // obs-ok:supervisor-stall-runner-spawn-fail
            "[supervisor] FAIL stall-delivery spawn rc=%d\n", src);
        return false;
    }
    g_stall_runner_thread_id = stid;
    atomic_store(&g_stall_runner_handle_set, true);

    /* Spawn the dedicated tick-runner. It, not the sweep, executes every
     * child's on_tick. Arm its liveness contract (deadline-monitored inline by
     * the sweep — see supervisor_monitor_runner). Both callback workers must
     * exist before the root sweep starts; otherwise startup refuses. */
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
        atomic_store(&g_running, false);
        (void)stall_runner_stop_and_join();
        fprintf(stderr,  // obs-ok:supervisor-tick-runner-spawn-fail
            "[supervisor] FAIL tick-runner spawn rc=%d\n", rrc);
        return false;
    }
    g_runner_thread_id = rtid;
    atomic_store(&g_runner_handle_set, true);
    atomic_store(&g_runner_enabled, true);

    pthread_t tid;
    int rc = thread_registry_spawn("zcl_supervisor",
                                   supervisor_thread_main, NULL, &tid);
    if (rc != 0) {
        supervisor_stop();
        fprintf(stderr,  // obs-ok:supervisor-root-spawn-fail
            "[supervisor] FAIL root sweep spawn rc=%d\n", rc);
        return false;
    }
    g_thread_id = tid;
    atomic_store(&g_thread_handle_set, true);
    return true;
}

void supervisor_stop(void)
{
    atomic_store(&g_running, false);
    /* Start no new recovery callbacks during teardown. An already-claimed
     * callback remains owned by the delivery worker and is joined below. */
    atomic_store(&g_stall_runner_running, false);
    stall_wake();

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
    (void)stall_runner_stop_and_join();
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
void supervisor_set_stale_cancel_hook_for_testing(
    supervisor_stale_cancel_hook_fn fn, void *ctx)
{
    pthread_mutex_lock(&g_lock);
    g_stale_cancel_hook = fn;
    g_stale_cancel_hook_ctx = ctx;
    pthread_mutex_unlock(&g_lock);
}

void supervisor_set_rearm_cancel_hook_for_testing(
    supervisor_rearm_cancel_hook_fn fn, void *ctx)
{
    pthread_mutex_lock(&g_lock);
    g_rearm_cancel_hook = fn;
    g_rearm_cancel_hook_ctx = ctx;
    pthread_mutex_unlock(&g_lock);
}

void supervisor_reset_for_testing(void)
{
    /* Stop first so the sweeper isn't iterating while we clear. */
    supervisor_stop();
    if (atomic_load(&g_thread_handle_set) ||
        atomic_load(&g_runner_handle_set) ||
        atomic_load(&g_stall_runner_handle_set)) {
        fprintf(stderr,  // obs-ok:supervisor-unjoined-worker
            "[supervisor] FAIL reset: a worker remains unjoined\n");
        return;
    }
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < SUPERVISOR_CAP; i++) g_contracts[i] = NULL;
    for (int i = 0; i < SUPERVISOR_CAP; i++) g_contract_domains[i] = NULL;
    g_contract_count = 0;
    memset(g_domains, 0, sizeof(g_domains));
    g_domain_count = 0;
    g_stall_runner_active_name[0] = '\0';
    g_stale_cancel_hook = NULL;
    g_stale_cancel_hook_ctx = NULL;
    g_rearm_cancel_hook = NULL;
    g_rearm_cancel_hook_ctx = NULL;
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_tick_ms, 1000);
    atomic_store_explicit(&g_stall_observer, NULL, memory_order_release);

    /* supervisor_stop() already cleared g_runner_enabled/running; clear the
     * monitored contract's latched state so the next test starts clean. */
    atomic_store(&g_runner_enabled, false);
    atomic_store(&g_runner_contract.stall_reason, SUPERVISOR_STALL_NONE);
    atomic_store(&g_runner_contract.stall_fires, 0u);
    atomic_store(&g_runner_blocker_action, RUNNER_BLOCKER_NONE);
    atomic_store(&g_runner_blocker_coalesced, 0u);
    atomic_store(&g_runner_blocker_discarded, 0u);
    atomic_store(&g_stall_runner_last_us, 0);
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

const char *supervisor_stall_active_callback_name_internal(void)
{
    static _Thread_local char name[SUPERVISOR_NAME_MAX];
    pthread_mutex_lock(&g_lock);
    snprintf(name, sizeof(name), "%s",
             g_stall_runner_active_name[0]
                 ? g_stall_runner_active_name : "none");
    pthread_mutex_unlock(&g_lock);
    return name;
}
