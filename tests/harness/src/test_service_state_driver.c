/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for service_state_driver — the app-layer glue that drives the
 * canonical service_state from real progress and persists it to progress.kv.
 *
 * Covers: REPAIRING flip + prior-state restore (A); the sync-gap state machine
 * via test overrides (B); the boot-state ordinal guard (C); the persistence
 * round-trip incl. invalid-record rejection (D); reason_copy buffer safety (E).
 *
 * No chain, cursor, tip, or consensus gate is touched here — the driver is
 * pure observability/state, and these tests pin that contract. */

#include "test/test_core.h"

#include "util/service_state.h"
#include "services/service_state_driver.h"
#include "framework/condition.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define SSD(desc, expr) do { \
    printf("ssd: %s... ", (desc)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static _Atomic bool g_ssd_detect;
static _Atomic bool g_ssd_witness;

static bool ssd_detect(void) { return atomic_load(&g_ssd_detect); }
static enum condition_remedy_result ssd_remedy(void) { return COND_REMEDY_OK; }
static bool ssd_witness(int64_t t) { (void)t; return atomic_load(&g_ssd_witness); }

/* Make a condition with `name` active (detect true + one tick). */
static struct condition g_cond;
static void ssd_register_active(const char *name)
{
    condition_engine_reset_for_testing();
    atomic_store(&g_ssd_detect, true);
    atomic_store(&g_ssd_witness, false);
    g_cond = (struct condition){
        .name = name,
        .severity = COND_CRITICAL,
        .poll_secs = 1,
        .backoff_secs = 0,
        .max_attempts = 5,
        .detect = ssd_detect,
        .remedy = ssd_remedy,
        .witness = ssd_witness,
        .witness_window_secs = 60,
    };
    condition_register(&g_cond);
    condition_engine_tick();   /* detect=true -> currently_active */
}

static void ssd_clear_active(void)
{
    atomic_store(&g_ssd_detect, false);
    atomic_store(&g_ssd_witness, true);
    condition_engine_tick();   /* witness=true -> cleared */
}

int test_service_state_driver(void);
int test_service_state_driver(void)
{
    printf("\n=== service_state driver tests ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ssdriver", "main");
    if (!progress_store_open(dir)) {
        printf("ssd: progress_store_open FAILED\n");
        return 1;
    }
    progress_meta_table_ensure(progress_store_db());

    /* ── Test A: REPAIRING flip + prior-state restore ── */
    {
        ssd_register_active("body_fetch_missing_have_data");
        service_state_advance(SERVICE_STATE_SYNCING, "baseline");
        service_state_driver_test_clear_overrides();
        service_state_driver_tick();
        SSD("repair active -> REPAIRING",
            service_state_current() == SERVICE_STATE_REPAIRING);
        ssd_clear_active();
        service_state_driver_tick();
        SSD("repair cleared -> restored to prior (SYNCING)",
            service_state_current() == SERVICE_STATE_SYNCING);

        /* variant: prior == DEGRADED_SERVING must restore to DEGRADED_SERVING */
        ssd_register_active("stale_validate_headers_repair");
        service_state_advance(SERVICE_STATE_DEGRADED_SERVING, "baseline2");
        service_state_driver_tick();
        SSD("repair active from DEGRADED -> REPAIRING",
            service_state_current() == SERVICE_STATE_REPAIRING);
        ssd_clear_active();
        service_state_driver_tick();
        SSD("repair cleared -> restored to DEGRADED_SERVING",
            service_state_current() == SERVICE_STATE_DEGRADED_SERVING);
    }

    /* ── Test B: sync-gap machine via overrides (no live ms/connman) ── */
    {
        condition_engine_reset_for_testing();   /* no active conditions */
        service_state_advance(SERVICE_STATE_SYNCING, "baseline");

        service_state_driver_test_set_overrides(/*local*/100, /*peer*/100,
                                                /*age*/10);
        service_state_driver_tick();
        SSD("gap<=1, no conditions -> HEALTHY",
            service_state_current() == SERVICE_STATE_HEALTHY);

        service_state_driver_test_set_overrides(100, 500, 10);
        service_state_driver_tick();
        SSD("gap>1 -> SYNCING",
            service_state_current() == SERVICE_STATE_SYNCING);

        /* active condition (non-repair name) forces DEGRADED even at tip */
        ssd_register_active("ssd_generic_non_repair");
        service_state_advance(SERVICE_STATE_SYNCING, "baseline");
        service_state_driver_test_set_overrides(100, 100, 10);
        service_state_driver_tick();
        SSD("active condition + at tip -> DEGRADED_SERVING",
            service_state_current() == SERVICE_STATE_DEGRADED_SERVING);

        /* no peers (peer_max<0) must NOT flip to HEALTHY */
        condition_engine_reset_for_testing();
        service_state_advance(SERVICE_STATE_SYNCING, "baseline");
        service_state_driver_test_set_overrides(100, -1, 10);
        service_state_driver_tick();
        SSD("no peers (peer_max<0) -> state UNCHANGED (SYNCING)",
            service_state_current() == SERVICE_STATE_SYNCING);

        /* negative gap (stale peer height) treated as on-tip -> HEALTHY */
        service_state_driver_test_set_overrides(200, 150, 10);
        service_state_driver_tick();
        SSD("peer below us (negative gap) -> HEALTHY (clamped on-tip)",
            service_state_current() == SERVICE_STATE_HEALTHY);

        service_state_driver_test_clear_overrides();
    }

    /* ── Test C: boot-state ordinal guard (driver must not leave RECONCILE) ── */
    {
        condition_engine_reset_for_testing();
        service_state_advance(SERVICE_STATE_RECONCILE, "boot");
        service_state_driver_test_set_overrides(100, 100, 10);
        service_state_driver_tick();
        SSD("driver does not advance out of RECONCILE",
            service_state_current() == SERVICE_STATE_RECONCILE);
        service_state_driver_test_clear_overrides();
    }

    /* ── Test D: persistence round-trip + invalid-record rejection ── */
    {
        service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                              "reconcilable divergence");
        SSD("persist succeeds", service_state_persist_to_progress_store().ok);

        service_state_advance(SERVICE_STATE_BOOT, "boot");
        SSD("restore returns true", service_state_restore_from_progress_store().ok);
        SSD("restored state == DEGRADED_SERVING",
            service_state_current() == SERVICE_STATE_DEGRADED_SERVING);
        SSD("restored reason preserved",
            strcmp(service_state_reason(), "reconcilable divergence") == 0);

        /* invalid state id (999) must be rejected, leaving state unchanged */
        int32_t bogus = 999;
        progress_store_tx_lock();
        progress_meta_set(progress_store_db(), "service_state",
                          &bogus, sizeof(bogus));
        progress_store_tx_unlock();
        service_state_advance(SERVICE_STATE_SYNCING, "pre-bogus");
        SSD("restore of invalid id returns false",
            service_state_restore_from_progress_store().ok == false);
        SSD("invalid id leaves state unchanged (SYNCING)",
            service_state_current() == SERVICE_STATE_SYNCING);
    }

    /* ── Test E: reason_copy buffer safety ── */
    {
        char big[300];
        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        service_state_advance(SERVICE_STATE_HEALTHY, big);
        char buf[128];
        service_state_reason_copy(buf, sizeof(buf));
        SSD("reason_copy truncates + NUL-terminates",
            strlen(buf) < sizeof(buf));
        /* no-op forms must not crash */
        service_state_reason_copy(NULL, 0);
        service_state_reason_copy(buf, 0);
        SSD("reason_copy no-op forms safe", true);
    }

    /* restore benign global state for any subsequent test in this group */
    condition_engine_reset_for_testing();
    service_state_driver_test_clear_overrides();
    service_state_advance(SERVICE_STATE_BOOT, "boot");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    printf("ssd: %d failures\n", failures);
    return failures;
}
