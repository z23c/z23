/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include "config/runtime.h"
#include "net/snapshot_sync_contract.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int64_t g_elapsed_at_detect;
static _Atomic uint64_t g_received_at_detect;
static _Atomic uint64_t g_offered_at_detect;
static _Atomic uint32_t g_peer_at_detect;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_snapshot_receive_stalled(void)
{
    struct snapshot_sync_service *svc = snapsync_condition_service();
    struct snapsync_stall_status st;
    if (!svc)
        return false;

    snapsync_get_stall_status(svc, &st);
    if (!st.stalled)
        return false;

    atomic_store(&g_elapsed_at_detect, st.elapsed_secs);
    atomic_store(&g_received_at_detect, st.received_utxos);
    atomic_store(&g_offered_at_detect, st.offered_utxos);
    atomic_store(&g_peer_at_detect, st.serving_peer_id);
    return true;
}

static enum condition_remedy_result remedy_snapshot_receive_stalled(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    LOG_WARN("condition", "[condition:snapshot_receive_stalled] peer=%u " "elapsed=%llds received=%llu offered=%llu action=reset", (unsigned)atomic_load(&g_peer_at_detect), (long long)atomic_load(&g_elapsed_at_detect), (unsigned long long)atomic_load(&g_received_at_detect), (unsigned long long)atomic_load(&g_offered_at_detect));
    return snapsync_check_stall() ? COND_REMEDY_OK : COND_REMEDY_SKIP;
}

static bool witness_snapshot_receive_stalled(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct snapshot_sync_service *svc = snapsync_condition_service();
    struct snapsync_stall_status st;
    if (!svc)
        return true;
    snapsync_get_stall_status(svc, &st);

    /* Law 7: witness that the symptom MOVED, not merely that the stall
     * flag cleared. A pure inverse of detect (!receiving || !stalled)
     * would accept a still-RECEIVING stream whose timer was refreshed
     * without a single new UTXO. Honest post-conditions:
     *   (a) the snapshot advanced — received_utxos climbed past what
     *       we captured at detect; OR
     *   (b) the stalled receive was actually torn down — no longer
     *       RECEIVING, so a fresh offer or header-sync fallback runs. */
    if (!st.receiving)
        return true;
    return st.received_utxos > atomic_load(&g_received_at_detect);
}

static struct condition c_snapshot_receive_stalled = {
    .name = "snapshot_receive_stalled",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 2,
    .detect = detect_snapshot_receive_stalled,
    .remedy = remedy_snapshot_receive_stalled,
    .witness = witness_snapshot_receive_stalled,
    .witness_window_secs = 60,
    /* External-resource fault (snapshot peer stalled mid-transfer): re-arm on a
     * cooldown so the stall-check/re-offer keeps retrying until a peer serves
     * the snapshot, instead of latching operator_needed forever. Pages once at
     * the cap; never gives up. Mirrors peer_floor_violated. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
};

void register_snapshot_receive_stalled(void)
{
    (void)condition_register(&c_snapshot_receive_stalled);
}

#ifdef ZCL_TESTING
void snapshot_receive_stalled_test_reset(void)
{
    atomic_store(&g_elapsed_at_detect, 0);
    atomic_store(&g_received_at_detect, 0);
    atomic_store(&g_offered_at_detect, 0);
    atomic_store(&g_peer_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_snapshot_receive_stalled);
}

int snapshot_receive_stalled_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
