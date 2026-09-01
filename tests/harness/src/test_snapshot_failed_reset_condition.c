/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/runtime.h"
#include "framework/condition.h"
#include "net/snapshot_sync_contract.h"

#include <string.h>

#define SFR_CHECK(name, expr) do { \
    printf("snapshot_failed_reset_condition: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_snapshot_failed_reset(void);
void snapshot_failed_reset_test_reset(void);
int snapshot_failed_reset_test_remedy_calls(void);
int64_t snapsync_now_us_internal(void);

static void reset_sfr(struct snapshot_sync_service *svc,
                      struct app_runtime_context *runtime)
{
    condition_engine_reset_for_testing();
    snapshot_failed_reset_test_reset();
    memset(svc, 0, sizeof(*svc));
    memset(runtime, 0, sizeof(*runtime));
    snapsync_init(svc, NULL);
    runtime->snapshot_sync = svc;
    app_runtime_set_current(runtime);
}

static void cleanup_sfr(void)
{
    app_runtime_set_current(NULL);
    condition_engine_reset_for_testing();
}

static void fill_hash(uint8_t h[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        h[i] = (uint8_t)(seed + i);
}

int test_snapshot_failed_reset_condition(void)
{
    printf("\n=== snapshot_failed_reset condition tests ===\n");
    int failures = 0;

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_sfr(&svc, &runtime);
        bool ok = true;
        register_snapshot_failed_reset();

        svc.state = SNAPSYNC_FAILED;
        svc.offered_height = 3000000;
        svc.offered_count = 1350000;
        svc.serving_peer_id = 21;
        svc.start_time_us =
            snapsync_now_us_internal() - 17 * 1000000LL;

        condition_engine_tick();
        ok = ok && snapshot_failed_reset_test_remedy_calls() == 1;
        ok = ok && svc.state == SNAPSYNC_IDLE;
        ok = ok && svc.serving_peer_id == 0;
        ok = ok && snapsync_is_peer_blacklisted(&svc, 21);
        ok = ok && condition_engine_get_active_count() == 0;
        SFR_CHECK("failed snapshot resets and blacklists peer", ok);
        cleanup_sfr();
    }

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        reset_sfr(&svc, &runtime);
        bool ok = true;
        register_snapshot_failed_reset();

        svc.state = SNAPSYNC_RECEIVING;
        svc.offered_height = 3000000;
        svc.offered_count = 1350000;
        svc.serving_peer_id = 22;

        condition_engine_tick();
        ok = ok && snapshot_failed_reset_test_remedy_calls() == 0;
        ok = ok && svc.state == SNAPSYNC_RECEIVING;
        ok = ok && !snapsync_is_peer_blacklisted(&svc, 22);
        SFR_CHECK("active receive is not reset", ok);
        cleanup_sfr();
    }

    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        uint8_t root[32];
        uint8_t mmb[32];
        uint8_t block[32];
        reset_sfr(&svc, &runtime);
        bool ok = true;

        fill_hash(root, 1);
        fill_hash(mmb, 33);
        fill_hash(block, 65);

        svc.state = SNAPSYNC_FAILED;
        svc.serving_peer_id = 23;
        ok = ok && !snapsync_accept_offer(&svc, 3000000, 1350000,
                                          root, mmb, block, 24).ok;
        ok = ok && snapsync_check_failed_reset();
        ok = ok && svc.state == SNAPSYNC_IDLE;
        ok = ok && snapsync_accept_offer(&svc, 3000000, 1350000,
                                         root, mmb, block, 24).ok;
        ok = ok && svc.state == SNAPSYNC_NEGOTIATING;
        ok = ok && svc.serving_peer_id == 24;
        SFR_CHECK("reset reopens snapshot offer path", ok);
        cleanup_sfr();
    }

    cleanup_sfr();
    return failures;
}
