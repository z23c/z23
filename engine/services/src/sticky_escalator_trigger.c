/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prevent generic conditions from rewinding a caught-up chain. */
// one-result-type-ok:pure-recovery-trigger-predicates-have-no-failure-surface

#include "services/sticky_escalator_trigger.h"

#include "chain/chain.h"
#include "net/connman.h"
#include "services/sync_monitor.h"
#include "validation/main_state.h"

#include <stdatomic.h>

static _Atomic bool g_suppressed;
static _Atomic uint64_t g_suppressions;
#ifdef ZCL_TESTING
static _Atomic int g_pending_override = -1;
#endif

/* H* is the served/folded authority. active_chain and best_header name local
 * work already known to the node; max peer height names announced work. The
 * generic auto-arm is deliberately fail-open when runtime context is absent:
 * explicit tests and early boot retain the old conservative recovery posture. */
static bool chain_work_pending(struct main_state *ms, int64_t hstar)
{
#ifdef ZCL_TESTING
    int override = atomic_load(&g_pending_override);
    if (override >= 0)
        return override != 0;
#endif
    if (!ms || hstar < 0)
        return true;

    int target = -1;
    zcl_mutex_lock(&ms->cs_main);
    target = active_chain_height(&ms->chain_active);
    if (ms->pindex_best_header && ms->pindex_best_header->nHeight > target)
        target = ms->pindex_best_header->nHeight;
    zcl_mutex_unlock(&ms->cs_main);

    struct connman *cm = sync_monitor_connman();
    int peer_height = cm ? connman_max_peer_height(cm) : -1;
    if (peer_height > target)
        target = peer_height;
    return (int64_t)target > hstar;
}

bool sticky_trigger_auto_arm_allowed(struct main_state *ms, int64_t hstar,
                                     int unresolved_critical)
{
    if (unresolved_critical <= 0) {
        atomic_store(&g_suppressed, false);
        return false;
    }
    if (chain_work_pending(ms, hstar)) {
        atomic_store(&g_suppressed, false);
        return true;
    }
    atomic_store(&g_suppressed, true);
    atomic_fetch_add(&g_suppressions, 1u);
    return false;
}

bool sticky_trigger_auto_arm_suppressed(void)
{
    return atomic_load(&g_suppressed);
}

uint64_t sticky_trigger_auto_arm_suppressions(void)
{
    return atomic_load(&g_suppressions);
}

#ifdef ZCL_TESTING
void sticky_trigger_test_reset(void)
{
    atomic_store(&g_suppressed, false);
    atomic_store(&g_suppressions, 0u);
    atomic_store(&g_pending_override, -1);
}

void sticky_trigger_test_set_pending_work(int override_value)
{
    atomic_store(&g_pending_override, override_value);
}
#endif
