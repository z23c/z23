/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/snapshot_offer_ready.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "config/runtime.h"
#include "event/event.h"
#include "net/snapshot_sync_contract.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

#define SNAPSHOT_OFFER_READY_MIN_GAP 1000

static _Atomic int g_local_height_at_detect = -1;
static _Atomic int g_snapshot_height_at_detect = -1;
static _Atomic int g_peer_id_at_detect = 0;
static _Atomic int64_t g_staged_at_detect = -1;

#ifdef ZCL_TESTING
static struct snapshot_sync_service *g_test_svc;
static _Atomic int g_test_remedy_calls;
#endif

static struct snapshot_sync_service *runtime_snapsync(void)
{
#ifdef ZCL_TESTING
    if (g_test_svc)
        return g_test_svc;
#endif
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (svc)
        return svc;
    return snapsync_global_initialized() ? snapsync_global() : NULL;
}

static int local_chain_height(void)
{
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        ms = condition_engine_main_state();
    if (!ms)
        return -1; // raw-return-ok:engine-not-ready
    return active_chain_height(&ms->chain_active);
}

static bool snapshot_offer_is_active(enum snapshot_sync_state state)
{
    return state == SNAPSYNC_NEGOTIATING ||
           state == SNAPSYNC_RECEIVING ||
           state == SNAPSYNC_VERIFYING;
}

static bool sync_state_can_receive_snapshot(enum sync_state state)
{
    return state == SYNC_IDLE ||
           state == SYNC_FINDING_PEERS ||
           state == SYNC_HEADERS_DOWNLOAD ||
           state == SYNC_BLOCKS_DOWNLOAD ||
           state == SYNC_CONNECTING_BLOCKS;
}

static bool detect_snapshot_offer_ready(void)
{
    struct snapshot_sync_service *svc = runtime_snapsync();
    struct snapsync_status status = {0};
    if (!svc)
        return false;

#ifdef ZCL_TESTING
    if (svc == g_test_svc) {
        status.state = svc->state;
        status.offered_height = svc->offered_height;
        status.offered_count = svc->offered_count;
        status.serving_peer_id = svc->serving_peer_id;
    } else
#endif
    {
        snapsync_get_status_snapshot(svc, &status);
    }
    if (!snapshot_offer_is_active(status.state) ||
        status.offered_height <= 0 ||
        status.offered_count == 0)
        return false;

    int local_h = local_chain_height();
    if (local_h < 0 ||
        local_h >= status.offered_height - SNAPSHOT_OFFER_READY_MIN_GAP)
        return false;

    if (!sync_state_can_receive_snapshot(sync_get_state()))
        return false; // raw-return-ok:sync-state-already-past-receive-window

    atomic_store(&g_local_height_at_detect, local_h);
    atomic_store(&g_snapshot_height_at_detect, status.offered_height);
    atomic_store(&g_peer_id_at_detect, (int)status.serving_peer_id);
    atomic_store(&g_staged_at_detect, status.staged_row_count);
    return true;
}

/* Read the CURRENT offer state (same test-service branch as detect). The
 * remedy and witness must never act on the at-detect snapshot alone: the
 * condition engine keeps remedying an ACTIVE episode even when detect()
 * reads false, so a dead offer would otherwise re-force
 * SYNC_SNAPSHOT_RECEIVE from stale state forever. */
static bool snapshot_offer_currently_active(void)
{
    struct snapshot_sync_service *svc = runtime_snapsync();
    struct snapsync_status status = {0};
    if (!svc)
        return false;
#ifdef ZCL_TESTING
    if (svc == g_test_svc) {
        status.state = svc->state;
    } else
#endif
    {
        snapsync_get_status_snapshot(svc, &status);
    }
    return snapshot_offer_is_active(status.state);
}

static enum condition_remedy_result remedy_snapshot_offer_ready(void)
{
    int local_h = atomic_load(&g_local_height_at_detect);
    int snap_h = atomic_load(&g_snapshot_height_at_detect);
    int peer_id = atomic_load(&g_peer_id_at_detect);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    if (!snapshot_offer_currently_active()) {
        LOG_INFO("condition",
                 "[condition:snapshot_offer_ready] offer no longer active "
                 "(local=%d snapshot=%d peer=%d) — skip, not forcing "
                 "SYNC_SNAPSHOT_RECEIVE from stale detect state",
                 local_h, snap_h, peer_id);
        return COND_REMEDY_SKIP;
    }

    LOG_INFO("condition", "[condition:snapshot_offer_ready] local=%d snapshot=%d " "peer=%d sync_state=%s action=set_snapshot_receive", local_h, snap_h, peer_id, sync_state_name(sync_get_state()));

    if (!sync_set_state(SYNC_SNAPSHOT_RECEIVE,
                        "condition snapshot_offer_ready")) {
        event_emitf(EV_SYNC_STATE_CHANGE, 0,
                    "condition snapshot_offer_ready failed local=%d "
                    "snapshot=%d peer=%d",
                    local_h, snap_h, peer_id);
        return COND_REMEDY_FAILED;
    }

    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "condition snapshot_offer_ready local=%d snapshot=%d "
                "peer=%d",
                local_h, snap_h, peer_id);
    return COND_REMEDY_OK;
}

static bool witness_snapshot_offer_ready(int64_t target_at_detect)
{
    (void)target_at_detect;

    /* Episode-moot clear: if the offer this condition fired on is no longer
     * active (SNAPSYNC_COMPLETE, FAILED, or back to IDLE), the symptom
     * "offer ready but not receiving" no longer exists — clear the episode.
     * Those terminal states have their own condition owners
     * (snapshot_complete_resume, snapshot_failed_reset,
     * snapshot_negotiation_stalled); without this, an active episode whose
     * offer died could never witness-clear and would latch forever, arming
     * the sticky escalator on a healthy node. */
    if (!snapshot_offer_currently_active())
        return true;

    /* The remedy unconditionally drives the SYNC FSM to SYNC_SNAPSHOT_RECEIVE,
     * so observing that state alone proves nothing — it is a remedy echo. The
     * honest, remedy-INDEPENDENT signal is the snapsync service's OWN state:
     * snapshot_offer_is_active(status.state) is true only when the offer the
     * remedy acted on is genuinely NEGOTIATING/RECEIVING/VERIFYING in the
     * snapsync FSM, which this condition's remedy never sets. We require BOTH
     * the SYNC FSM moved AND the snapsync offer is genuinely active; if the
     * receive has progressed (staged rows climbed past the detect baseline)
     * that is even stronger, but an active offer is the post-condition this
     * (offer-ready -> enter-receive) condition owns — the data-arrival symptom
     * is witnessed by snapshot_receive_stalled. "A remedy that returns ok
     * without moving the symptom is a LIE." */
    if (sync_get_state() != SYNC_SNAPSHOT_RECEIVE)
        return false;

    struct snapshot_sync_service *svc = runtime_snapsync();
    if (!svc)
        return false;

    struct snapsync_status status = {0};
#ifdef ZCL_TESTING
    if (svc == g_test_svc) {
        /* The test service has no ndb; read its fields directly (matching
         * detect_snapshot_offer_ready) instead of snapsync_get_status_snapshot,
         * which would deref a NULL staging store. */
        status.state = svc->state;
        status.offered_height = svc->offered_height;
        status.offered_count = svc->offered_count;
        status.serving_peer_id = svc->serving_peer_id;
    } else
#endif
    {
        snapsync_get_status_snapshot(svc, &status);
    }

    if (!snapshot_offer_is_active(status.state)) {
        LOG_WARN("condition",
                 "[condition:snapshot_offer_ready] witness: snapsync offer "
                 "no longer active (state=%d) — remedy's FSM move to "
                 "SYNC_SNAPSHOT_RECEIVE was a remedy echo, not proof",
                 (int)status.state);
        return false;
    }

    int64_t staged_at_detect = atomic_load(&g_staged_at_detect);
    return status.staged_row_count >= staged_at_detect;
}

static struct condition c_snapshot_offer_ready = {
    .name = "snapshot_offer_ready",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 2,
    .detect = detect_snapshot_offer_ready,
    .remedy = remedy_snapshot_offer_ready,
    .witness = witness_snapshot_offer_ready,
    .witness_window_secs = 30,
};

void register_snapshot_offer_ready(void)
{
    (void)condition_register(&c_snapshot_offer_ready);
}

#ifdef ZCL_TESTING
void snapshot_offer_ready_test_reset(void)
{
    g_test_svc = NULL;
    atomic_store(&g_local_height_at_detect, -1);
    atomic_store(&g_snapshot_height_at_detect, -1);
    atomic_store(&g_peer_id_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

void snapshot_offer_ready_test_set_service(struct snapshot_sync_service *svc)
{
    g_test_svc = svc;
}

int snapshot_offer_ready_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
