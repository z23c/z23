/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/runtime.h"
#include "framework/condition.h"
#include "net/snapshot_sync_contract.h"

#include <string.h>

#define SRS_CHECK(name, expr) do { \
    printf("snapshot_receive_stalled_condition: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_snapshot_receive_stalled(void);
void snapshot_receive_stalled_test_reset(void);
int snapshot_receive_stalled_test_remedy_calls(void);
int64_t snapsync_now_us_internal(void);

static void reset_srs(struct snapshot_sync_service *svc,
                      struct app_runtime_context *runtime)
{
    condition_engine_reset_for_testing();
    snapshot_receive_stalled_test_reset();
    memset(svc, 0, sizeof(*svc));
    memset(runtime, 0, sizeof(*runtime));
    snapsync_init(svc, NULL);
    runtime->snapshot_sync = svc;
    app_runtime_set_current(runtime);
}

static void cleanup_srs(void)
{
    app_runtime_set_current(NULL);
    condition_engine_reset_for_testing();
}

int test_snapshot_receive_stalled_condition(void)
{
    printf("\n=== snapshot_receive_stalled condition tests ===\n");
    int failures = 0;

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_srs(&svc, &runtime);
        bool ok = true;
        register_snapshot_receive_stalled();

        svc.state = SNAPSYNC_RECEIVING;
        svc.received_utxos = 10;
        svc.last_progress_utxos = 10;
        svc.offered_count = 100;
        svc.serving_peer_id = 7;
        svc.last_progress_time_us =
            snapsync_now_us_internal() -
            ((int64_t)SNAPSYNC_STALL_TIMEOUT_SECS + 1) * 1000000LL;

        condition_engine_tick();
        ok = ok && snapshot_receive_stalled_test_remedy_calls() == 1;
        ok = ok && svc.state == SNAPSYNC_IDLE;
        ok = ok && snapsync_is_peer_blacklisted(&svc, 7);
        ok = ok && condition_engine_get_active_count() == 0;
        SRS_CHECK("stalled receive resets and blacklists peer", ok);
        cleanup_srs();
    }

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_srs(&svc, &runtime);
        bool ok = true;
        register_snapshot_receive_stalled();

        svc.state = SNAPSYNC_RECEIVING;
        svc.received_utxos = 10;
        svc.last_progress_utxos = 10;
        svc.offered_count = 100;
        svc.serving_peer_id = 8;
        svc.last_progress_time_us = snapsync_now_us_internal();

        condition_engine_tick();
        ok = ok && snapshot_receive_stalled_test_remedy_calls() == 0;
        ok = ok && svc.state == SNAPSYNC_RECEIVING;
        SRS_CHECK("fresh receive is not reset", ok);
        cleanup_srs();
    }

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_srs(&svc, &runtime);
        bool ok = true;

        svc.state = SNAPSYNC_RECEIVING;
        svc.received_utxos = 20;
        svc.last_progress_utxos = 10;
        svc.last_progress_time_us =
            snapsync_now_us_internal() -
            ((int64_t)SNAPSYNC_STALL_TIMEOUT_SECS + 1) * 1000000LL;

        struct snapsync_stall_status st;
        int64_t before = snapsync_now_us_internal();
        snapsync_get_stall_status(&svc, &st);
        int64_t after = snapsync_now_us_internal();
        ok = ok && !st.stalled;
        ok = ok && svc.last_progress_utxos == 20;
        ok = ok && svc.last_progress_time_us >= before;
        ok = ok && svc.last_progress_time_us <= after;
        SRS_CHECK("progress refreshes stall timer", ok);
        cleanup_srs();
    }

    cleanup_srs();
    return failures;
}
