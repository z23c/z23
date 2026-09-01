/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/sync_state_stuck.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "event/event.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "util/long_op.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int g_state_at_detect = SYNC_IDLE;
static _Atomic int g_height_at_detect = -1;
static _Atomic int64_t g_age_at_detect = 0;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_sync_state_stuck(void)
{
    enum sync_state state = sync_get_state();
    if (state == SYNC_AT_TIP || state == SYNC_HEADERS_DOWNLOAD ||
        state == SYNC_BLOCKS_DOWNLOAD)
        return false;

    int64_t age = sync_get_state_duration();
    if (age < 600)
        return false;

    int64_t lo_age = 0;
    if (long_op_is_active(&lo_age) && lo_age < 60)
        return false;

    struct main_state *ms = sync_monitor_main_state();
    int h = ms ? active_chain_height(&ms->chain_active) : -1;
    atomic_store(&g_state_at_detect, state);
    atomic_store(&g_height_at_detect, h);
    atomic_store(&g_age_at_detect, age);
    return true;
}

static enum condition_remedy_result remedy_sync_state_stuck(void)
{
    enum sync_state state = (enum sync_state)atomic_load(&g_state_at_detect);
    struct connman *cm = sync_monitor_connman();
    int peer_max = cm ? connman_max_peer_height(cm) : -1;
    LOG_WARN("condition", "[condition:sync_state_stuck] state=%s age=%llds height=%d " "peer_max=%d action=kick_fsm", sync_state_name(state), (long long)atomic_load(&g_age_at_detect), atomic_load(&g_height_at_detect), peer_max);
    event_emitf(EV_TIP_STALE, 0, "state=%s since=%lld our_h=%d peer_max=%d",
                sync_state_name(state), (long long)atomic_load(&g_age_at_detect),
                atomic_load(&g_height_at_detect), peer_max);

    if (!sync_set_state(SYNC_HEADERS_DOWNLOAD,
                        "condition sync_state_stuck")) {
        sync_set_state(SYNC_IDLE, "condition sync_state_stuck via idle");
        sync_set_state(SYNC_HEADERS_DOWNLOAD,
                       "condition sync_state_stuck");
    }
    sync_monitor_kick_local_sync("condition:sync_state_stuck");
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_sync_state_stuck(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Law 7: the witness must observe the SYMPTOM moving, not merely that the
     * remedy mutated the FSM. The remedy force-sets SYNC_HEADERS_DOWNLOAD, so a
     * bare "FSM changed" check is always true and would be a LIE — a stuck FSM
     * can just become stuck in a different state. Require BOTH: we are now in a
     * healthy state (at tip or actively downloading), AND the tip height has
     * advanced since detect (real forward progress). */
    enum sync_state state = sync_get_state();
    bool healthy = (state == SYNC_AT_TIP ||
                    state == SYNC_HEADERS_DOWNLOAD ||
                    state == SYNC_BLOCKS_DOWNLOAD);
    if (!healthy)
        return false;

    struct main_state *ms = sync_monitor_main_state();
    int h = ms ? active_chain_height(&ms->chain_active) : -1;
    return h > atomic_load(&g_height_at_detect);
}

static struct condition c_sync_state_stuck = {
    .name = "sync_state_stuck",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 600,
    .max_attempts = 3,
    .detect = detect_sync_state_stuck,
    .remedy = remedy_sync_state_stuck,
    .witness = witness_sync_state_stuck,
    .witness_window_secs = 60,
    /* External-resource fault (FSM stalled waiting on peer progress): re-arm on
     * a cooldown so the FSM kick keeps retrying until sync advances, instead of
     * latching operator_needed forever. Pages once at the cap; never gives up.
     * Mirrors peer_floor_violated. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
};

void register_sync_state_stuck(void)
{
    (void)condition_register(&c_sync_state_stuck);
}

#ifdef ZCL_TESTING
void sync_state_stuck_test_reset(void)
{
    atomic_store(&g_state_at_detect, SYNC_IDLE);
    atomic_store(&g_height_at_detect, -1);
    atomic_store(&g_age_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

int sync_state_stuck_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
