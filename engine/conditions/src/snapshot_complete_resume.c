/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include "config/runtime.h"
#include "event/event.h"
#include "net/snapshot_sync_contract.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int g_height_at_detect;
static _Atomic uint64_t g_utxos_at_detect;
static _Atomic uint32_t g_peer_at_detect;

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

static bool snapshot_complete_status(struct snapshot_sync_service *svc,
                                     struct snapsync_status *st)
{
    if (!svc || !st)
        return false;
    *st = (struct snapsync_status){0};
#ifdef ZCL_TESTING
    if (svc == g_test_svc) {
        st->state = svc->state;
        st->offered_height = svc->offered_height;
        st->offered_count = svc->offered_count;
        st->serving_peer_id = svc->serving_peer_id;
        return true;
    }
#endif
    snapsync_get_status_snapshot(svc, st);
    return true;
}

static struct main_state *runtime_main_state(void)
{
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        ms = condition_engine_main_state();
    return ms;
}

static bool detect_snapshot_complete_resume(void)
{
    struct snapshot_sync_service *svc = runtime_snapsync();
    struct snapsync_status st;
    if (!snapshot_complete_status(svc, &st))
        return false; // raw-return-ok:snapsync-service-not-active-is-normal-steady-state
    if (st.state != SNAPSYNC_COMPLETE ||
        sync_get_state() != SYNC_SNAPSHOT_RECEIVE ||
        st.offered_height <= 0)
        return false;

    atomic_store(&g_height_at_detect, st.offered_height);
    atomic_store(&g_utxos_at_detect, st.offered_count);
    atomic_store(&g_peer_at_detect, st.serving_peer_id);
    return true;
}

static enum condition_remedy_result remedy_snapshot_complete_resume(void)
{
    struct snapshot_sync_service *svc = runtime_snapsync();
    struct main_state *ms = runtime_main_state();
    int height = atomic_load(&g_height_at_detect);
    uint32_t peer = atomic_load(&g_peer_at_detect);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    if (!svc || !ms) {
        LOG_WARN("condition", "[condition:snapshot_complete_resume] missing runtime " "svc=%p ms=%p height=%d action=resume_headers", (void *)svc, (void *)ms, height);
        return COND_REMEDY_FAILED;
    }

    int activated_height = snapsync_activate_verified_tip(svc, ms);
    LOG_INFO("condition", "[condition:snapshot_complete_resume] peer=%u height=%d " "utxos=%llu activated=%d action=resume_headers", (unsigned)peer, height, (unsigned long long)atomic_load(&g_utxos_at_detect), activated_height);

    event_emitf(EV_SYNC_STATE_CHANGE, peer,
                "condition snapshot_complete_resume h=%d activated=%d",
                height, activated_height);
    if (!sync_set_state(SYNC_HEADERS_DOWNLOAD,
                        "condition snapshot_complete_resume")) {
        sync_set_state(SYNC_IDLE, "condition snapshot complete via idle");
        if (!sync_set_state(SYNC_HEADERS_DOWNLOAD,
                            "condition snapshot_complete_resume"))
            return COND_REMEDY_FAILED;
    }
    /* COMPLETE is a legacy/stale state until peer snapshots use the unified
     * transactional installer.  Resuming ordinary header/body sync is safe,
     * but containment is not a successful snapshot activation and must not
     * satisfy the condition witness. */
    return activated_height >= 0 ? COND_REMEDY_OK : COND_REMEDY_FAILED;
}

static bool witness_snapshot_complete_resume(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Law 7: a witness must observe the symptom MOVED, not just that the
     * FSM left SYNC_SNAPSHOT_RECEIVE. The remedy activates the verified
     * snapshot tip at g_height_at_detect; the honest post-condition is that
     * the active chain tip actually reached that activated height. */
    struct main_state *ms = runtime_main_state();
    int height_at_detect = atomic_load(&g_height_at_detect);
    if (!ms || height_at_detect <= 0)
        return false;
    return sync_get_state() != SYNC_SNAPSHOT_RECEIVE &&
           active_chain_height(&ms->chain_active) >= height_at_detect;
}

static struct condition c_snapshot_complete_resume = {
    .name = "snapshot_complete_resume",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 2,
    .detect = detect_snapshot_complete_resume,
    .remedy = remedy_snapshot_complete_resume,
    .witness = witness_snapshot_complete_resume,
    .witness_window_secs = 30,
};

void register_snapshot_complete_resume(void)
{
    (void)condition_register(&c_snapshot_complete_resume);
}

#ifdef ZCL_TESTING
void snapshot_complete_resume_test_reset(void)
{
    g_test_svc = NULL;
    atomic_store(&g_height_at_detect, 0);
    atomic_store(&g_utxos_at_detect, 0);
    atomic_store(&g_peer_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_snapshot_complete_resume);
}

void snapshot_complete_resume_test_set_service(struct snapshot_sync_service *svc)
{
    g_test_svc = svc;
}

int snapshot_complete_resume_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
