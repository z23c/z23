/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include "config/runtime.h"
#include "net/snapshot_sync_contract.h"
#include "sync/sync_state.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int64_t g_elapsed_at_detect;
static _Atomic int g_height_at_detect;
static _Atomic uint64_t g_utxos_at_detect;
static _Atomic uint32_t g_peer_at_detect;
static _Atomic int64_t g_staged_at_detect;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_snapshot_failed_reset(void)
{
    struct snapshot_sync_service *svc = snapsync_condition_service();
    struct snapsync_failed_status st;
    if (!svc)
        return false;

    snapsync_get_failed_status(svc, &st);
    if (!st.failed)
        return false;

    atomic_store(&g_elapsed_at_detect, st.elapsed_secs);
    atomic_store(&g_height_at_detect, st.offered_height);
    atomic_store(&g_utxos_at_detect, st.offered_utxos);
    atomic_store(&g_peer_at_detect, st.serving_peer_id);
    atomic_store(&g_staged_at_detect, st.staged_row_count);
    return true;
}

static enum condition_remedy_result remedy_snapshot_failed_reset(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    LOG_WARN("condition", "[condition:snapshot_failed_reset] peer=%u elapsed=%llds " "height=%d utxos=%llu staged=%lld action=blacklist_reset", (unsigned)atomic_load(&g_peer_at_detect), (long long)atomic_load(&g_elapsed_at_detect), atomic_load(&g_height_at_detect), (unsigned long long)atomic_load(&g_utxos_at_detect), (long long)atomic_load(&g_staged_at_detect));
    return snapsync_check_failed_reset() ? COND_REMEDY_OK : COND_REMEDY_SKIP;
}

static bool witness_snapshot_failed_reset(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: the remedy's job is a HANDOFF — abandon the dead
    // snapshot peer and fall back to the header-sync path. The forward
    // progress of that path is witnessed downstream (sync_state_stuck /
    // local_header_refill_needed read active_chain_height / peer height).
    // This witness only confirms the handoff took effect (left FAILED and
    // left SNAPSHOT_RECEIVE); it deliberately does not re-witness the header
    // path's tip advance, which is a different condition's responsibility.
    /* Honest post-condition: clearing the FAILED poison flag is not progress
     * (the remedy sets it false, so !failed alone is a tautology). The remedy's
     * actual job is to abandon the dead snapshot peer and FALL BACK to header
     * sync so the node keeps moving toward tip. Witness that fallback took
     * effect: the service left FAILED AND sync is no longer wedged in
     * SNAPSHOT_RECEIVE — it has handed off to the forward header path. */
    struct snapshot_sync_service *svc = snapsync_condition_service();
    struct snapsync_failed_status st;
    if (!svc)
        return true;
    snapsync_get_failed_status(svc, &st);
    if (st.failed)
        return false;
    return sync_get_state() != SYNC_SNAPSHOT_RECEIVE;
}

static struct condition c_snapshot_failed_reset = {
    .name = "snapshot_failed_reset",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 2,
    .detect = detect_snapshot_failed_reset,
    .remedy = remedy_snapshot_failed_reset,
    .witness = witness_snapshot_failed_reset,
    .witness_window_secs = 60,
};

void register_snapshot_failed_reset(void)
{
    (void)condition_register(&c_snapshot_failed_reset);
}

#ifdef ZCL_TESTING
void snapshot_failed_reset_test_reset(void)
{
    atomic_store(&g_elapsed_at_detect, 0);
    atomic_store(&g_height_at_detect, 0);
    atomic_store(&g_utxos_at_detect, 0);
    atomic_store(&g_peer_at_detect, 0);
    atomic_store(&g_staged_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_snapshot_failed_reset);
}

int snapshot_failed_reset_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
