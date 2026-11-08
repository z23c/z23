/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Serialized registered-child stall and tick bookkeeping. */
#include "supervisor_internal.h"
#include "platform/time_compat.h"

/* Registry lock precedes this lock when both are needed. */
pthread_mutex_t g_supervisor_stall_transition_lock = PTHREAD_MUTEX_INITIALIZER;

static bool rearm_locked(struct liveness_contract *c, int first, int second,
                         uint64_t *pending)
{
    int reason = atomic_load(&c->stall_reason);
    if ((reason != first && reason != second) || c->stall_incarnation == UINT64_MAX)
        return false;
    *pending = atomic_load(&c->stall_delivery_pending);
    ++c->stall_incarnation;
    atomic_store(&c->stall_reason, SUPERVISOR_STALL_NONE);
    return true;
}

bool supervisor_stall_rearm(struct liveness_contract *c, int first, int second,
                            uint64_t *pending)
{
    pthread_mutex_lock(&g_stall_transition_lock);
    bool cleared = rearm_locked(c, first, second, pending);
    pthread_mutex_unlock(&g_stall_transition_lock);
    return cleared;
}

bool supervisor_stall_explicit_tick(struct liveness_contract *c, uint64_t *pending)
{
    pthread_mutex_lock(&g_stall_transition_lock);
    atomic_store(&c->last_tick_us, platform_time_monotonic_us());
    atomic_fetch_add(&c->ticks_run, 1u);
    bool cleared = rearm_locked(c, SUPERVISOR_STALL_TIME_DEADLINE,
                                SUPERVISOR_STALL_CHILD_REPORTED, pending);
    pthread_mutex_unlock(&g_stall_transition_lock);
    return cleared;
}

struct supervisor_tick_snapshot supervisor_stall_tick_snapshot(struct liveness_contract *c)
{
    pthread_mutex_lock(&g_stall_transition_lock);
    struct supervisor_tick_snapshot before = {
        atomic_load(&c->ticks_run), atomic_load(&c->stall_reason), c->stall_incarnation
    };
    pthread_mutex_unlock(&g_stall_transition_lock);
    return before;
}

bool supervisor_stall_implicit_tick(struct liveness_contract *c,
    struct supervisor_tick_snapshot before, uint64_t *pending)
{
    bool cleared = false;
    pthread_mutex_lock(&g_stall_transition_lock);
    if (atomic_load(&c->ticks_run) == before.ticks) {
        atomic_store(&c->last_tick_us, platform_time_monotonic_us());
        atomic_fetch_add(&c->ticks_run, 1u);
        if (before.reason == SUPERVISOR_STALL_TIME_DEADLINE &&
            c->stall_incarnation == before.incarnation)
            cleared = rearm_locked(c, before.reason, before.reason, pending);
    }
    pthread_mutex_unlock(&g_stall_transition_lock);
    return cleared;
}
