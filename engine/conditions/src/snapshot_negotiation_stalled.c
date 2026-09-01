/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include "config/runtime.h"
#include "net/snapshot_sync_contract.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int64_t g_elapsed_at_detect;
static _Atomic int g_height_at_detect;
static _Atomic uint64_t g_utxos_at_detect;
static _Atomic uint32_t g_peer_at_detect;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_snapshot_negotiation_stalled(void)
{
    struct snapshot_sync_service *svc = snapsync_condition_service();
    struct snapsync_negotiation_status st;
    if (!svc)
        return false;

    snapsync_get_negotiation_status(svc, &st);
    if (!st.stalled)
        return false;

    atomic_store(&g_elapsed_at_detect, st.elapsed_secs);
    atomic_store(&g_height_at_detect, st.offered_height);
    atomic_store(&g_utxos_at_detect, st.offered_utxos);
    atomic_store(&g_peer_at_detect, st.serving_peer_id);
    return true;
}

static enum condition_remedy_result remedy_snapshot_negotiation_stalled(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    LOG_WARN("condition", "[condition:snapshot_negotiation_stalled] peer=%u " "elapsed=%llds height=%d utxos=%llu action=reset", (unsigned)atomic_load(&g_peer_at_detect), (long long)atomic_load(&g_elapsed_at_detect), atomic_load(&g_height_at_detect), (unsigned long long)atomic_load(&g_utxos_at_detect));
    return snapsync_check_negotiation_stall() ? COND_REMEDY_OK
                                             : COND_REMEDY_SKIP;
}

static bool witness_snapshot_negotiation_stalled(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct snapshot_sync_service *svc = snapsync_condition_service();
    struct snapsync_negotiation_status st;
    if (!svc)
        return true;
    snapsync_get_negotiation_status(svc, &st);

    /* Law 7: a remedy that returns ok without moving the symptom is a LIE.
     * The remedy blacklists the stalled peer and resets to IDLE, so the bare
     * !st.stalled flag flips on its own and would always pass — that is the
     * pure inverse of detect, not independent verification. Witness instead
     * that the negotiation actually MOVED relative to what we captured at
     * detect: either the offer advanced (height/utxos grew) or a fresh peer
     * is now serving (the reset reopened the path to a different peer). */
    bool offer_advanced =
        st.offered_height > atomic_load(&g_height_at_detect) ||
        st.offered_utxos > atomic_load(&g_utxos_at_detect);
    bool new_peer =
        st.negotiating && st.serving_peer_id != atomic_load(&g_peer_at_detect);

    return offer_advanced || new_peer;
}

static struct condition c_snapshot_negotiation_stalled = {
    .name = "snapshot_negotiation_stalled",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 2,
    .detect = detect_snapshot_negotiation_stalled,
    .remedy = remedy_snapshot_negotiation_stalled,
    .witness = witness_snapshot_negotiation_stalled,
    .witness_window_secs = 60,
    /* External-resource fault (snapshot peer stalled mid-negotiation): re-arm on
     * a cooldown so the stall-check/re-offer keeps retrying until a peer's offer
     * completes, instead of latching operator_needed forever. Pages once at the
     * cap; never gives up. Mirrors snapshot_receive_stalled / peer_floor_violated. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
};

void register_snapshot_negotiation_stalled(void)
{
    (void)condition_register(&c_snapshot_negotiation_stalled);
}

#ifdef ZCL_TESTING
void snapshot_negotiation_stalled_test_reset(void)
{
    atomic_store(&g_elapsed_at_detect, 0);
    atomic_store(&g_height_at_detect, 0);
    atomic_store(&g_utxos_at_detect, 0);
    atomic_store(&g_peer_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_snapshot_negotiation_stalled);
}

int snapshot_negotiation_stalled_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
