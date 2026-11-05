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

/* ── Mutation-gap tests (survivor sweep 1105) ───────────────────────── */

/* Overrides + one tick from `from`, with no condition active. */
static enum service_state ssd_tick_from(enum service_state from, int local_h,
                                        int peer_max)
{
    condition_engine_reset_for_testing();
    service_state_advance(from, "ssd baseline");
    service_state_driver_test_set_overrides(local_h, peer_max, 10);
    service_state_driver_tick();
    service_state_driver_test_clear_overrides();
    return service_state_current();
}

/* The on-tip boundary is exactly gap 1; peer height 0 is a valid reading;
 * DEGRADED_SERVING is a serving mode the driver may leave. */
static int ssd_gap_boundary_tests(void)
{
    int failures = 0;
    SSD("gap 1 (SYNCING) -> HEALTHY",
        ssd_tick_from(SERVICE_STATE_SYNCING, 100, 101) == SERVICE_STATE_HEALTHY);
    SSD("gap 2 (HEALTHY) -> SYNCING",
        ssd_tick_from(SERVICE_STATE_HEALTHY, 100, 102) == SERVICE_STATE_SYNCING);
    SSD("peer height 0 is a reading, not 'no peers' -> HEALTHY",
        ssd_tick_from(SERVICE_STATE_SYNCING, 0, 0) == SERVICE_STATE_HEALTHY);
    SSD("DEGRADED_SERVING with no active condition at tip -> HEALTHY",
        ssd_tick_from(SERVICE_STATE_DEGRADED_SERVING, 100, 100) ==
            SERVICE_STATE_HEALTHY);
    SSD("RECONCILE is still left alone at tip",
        ssd_tick_from(SERVICE_STATE_RECONCILE, 100, 100) ==
            SERVICE_STATE_RECONCILE);

    /* A stale peer below us is clamped to gap 0 in the recorded reason. */
    (void)ssd_tick_from(SERVICE_STATE_SYNCING, 200, 150);
    SSD("negative gap recorded as gap=0 in the reason",
        strcmp(service_state_reason(),
               "local=200 peer=150 gap=0 active=0 age=10s") == 0);
    return failures;
}

/* No override and no main state: a tick must hold, and clearing the
 * overrides must really turn them off. */
static int ssd_no_main_state_tests(void)
{
    int failures = 0;
    condition_engine_reset_for_testing();
    service_state_advance(SERVICE_STATE_SYNCING, "ssd baseline");
    service_state_driver_test_set_overrides(100, 100, 10);
    service_state_driver_test_clear_overrides();
    service_state_driver_tick();
    SSD("overrides cleared + no main state -> state held (SYNCING)",
        service_state_current() == SERVICE_STATE_SYNCING);
    return failures;
}

/* Put g_prior_state at SYNCING through the real REPAIRING detour. */
static void ssd_seed_prior_syncing(void)
{
    ssd_register_active("body_fetch_missing_have_data");
    service_state_advance(SERVICE_STATE_SYNCING, "seed");
    service_state_driver_tick();
    ssd_clear_active();
    service_state_driver_tick();
    condition_engine_reset_for_testing();
}

/* Seed prior=SYNCING, persist `id`, restore it, force REPAIRING and clear:
 * the state the driver returns to is the prior the restore left behind. */
static enum service_state ssd_prior_after_restore(enum service_state id)
{
    ssd_seed_prior_syncing();
    service_state_advance(id, "ssd persisted");
    (void)service_state_persist_to_progress_store();
    service_state_advance(SERVICE_STATE_BOOT, "boot");
    (void)service_state_restore_from_progress_store();
    service_state_advance(SERVICE_STATE_REPAIRING, "forced");
    service_state_driver_tick();
    return service_state_current();
}

static int ssd_prior_tests(void)
{
    int failures = 0;

    /* A tick that moves the node records the new mode as the prior. */
    ssd_seed_prior_syncing();
    (void)ssd_tick_from(SERVICE_STATE_SYNCING, 100, 100);   /* -> HEALTHY */
    service_state_advance(SERVICE_STATE_REPAIRING, "forced");
    service_state_driver_tick();
    SSD("tick transition records prior (HEALTHY)",
        service_state_current() == SERVICE_STATE_HEALTHY);

    SSD("restore DEGRADED_SERVING seeds the prior",
        ssd_prior_after_restore(SERVICE_STATE_DEGRADED_SERVING) ==
            SERVICE_STATE_DEGRADED_SERVING);
    SSD("restore HEALTHY seeds the prior",
        ssd_prior_after_restore(SERVICE_STATE_HEALTHY) == SERVICE_STATE_HEALTHY);
    SSD("restore BOOT leaves the prior alone",
        ssd_prior_after_restore(SERVICE_STATE_BOOT) == SERVICE_STATE_SYNCING);
    SSD("restore REPAIRING leaves the prior alone",
        ssd_prior_after_restore(SERVICE_STATE_REPAIRING) ==
            SERVICE_STATE_SYNCING);
    return failures;
}

static void ssd_set_meta(const char *key, const void *p, size_t n)
{
    progress_store_tx_lock();
    progress_meta_set(progress_store_db(), key, p, n);
    progress_store_tx_unlock();
}

static void ssd_del_meta(const char *key)
{
    progress_store_tx_lock();
    progress_meta_delete(progress_store_db(), key);
    progress_store_tx_unlock();
}

/* Restore: id range, the missing-record result, and the reason fallbacks. */
static int ssd_restore_edge_tests(void)
{
    int failures = 0;
    int32_t id = SERVICE_STATE_BOOT;
    ssd_set_meta("service_state", &id, sizeof(id));
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    SSD("restore of id 0 (BOOT) is valid",
        service_state_restore_from_progress_store().ok &&
        service_state_current() == SERVICE_STATE_BOOT);

    id = SERVICE_STATE__COUNT;
    ssd_set_meta("service_state", &id, sizeof(id));
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    struct zcl_result r = service_state_restore_from_progress_store();
    SSD("restore of id == COUNT rejected with code -5",
        !r.ok && r.code == -5 &&
        service_state_current() == SERVICE_STATE_SYNCING);

    id = SERVICE_STATE_HEALTHY;
    ssd_set_meta("service_state", &id, sizeof(id));
    ssd_del_meta("service_state_reason");
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    SSD("missing reason row -> reason 'restored'",
        service_state_restore_from_progress_store().ok &&
        strcmp(service_state_reason(), "restored") == 0);

    ssd_set_meta("service_state_reason", "", 0);
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    SSD("empty reason row -> reason 'restored'",
        service_state_restore_from_progress_store().ok &&
        strcmp(service_state_reason(), "restored") == 0);

    ssd_set_meta("service_state_reason", "x", 1);
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    SSD("one-byte reason row kept as-is",
        service_state_restore_from_progress_store().ok &&
        strcmp(service_state_reason(), "x") == 0);

    ssd_del_meta("service_state");
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    r = service_state_restore_from_progress_store();
    SSD("no persisted record -> code -7, state unchanged",
        !r.ok && r.code == -7 &&
        service_state_current() == SERVICE_STATE_SYNCING);
    return failures;
}

static bool ssd_exec(const char *sql)
{
    return sqlite3_exec(progress_store_db(), sql, NULL, NULL, NULL) == SQLITE_OK;
}

/* After a failed persist the stored (state, reason) pair is still the old one. */
static bool ssd_stored_pair_is_old(void)
{
    service_state_advance(SERVICE_STATE_BOOT, "boot");
    return service_state_restore_from_progress_store().ok &&
           service_state_current() == SERVICE_STATE_DEGRADED_SERVING &&
           strcmp(service_state_reason(), "old pair") == 0;
}

static void ssd_store_old_pair_then_move_ram(void)
{
    service_state_advance(SERVICE_STATE_DEGRADED_SERVING, "old pair");
    (void)service_state_persist_to_progress_store();
    service_state_advance(SERVICE_STATE_HEALTHY, "new pair");
}

static int ssd_persist_failure_tests(void)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();

    /* BEGIN refused: the caller already holds a transaction. */
    ssd_store_old_pair_then_move_ram();
    ssd_exec("BEGIN IMMEDIATE");
    struct zcl_result r = service_state_persist_to_progress_store();
    SSD("BEGIN failure -> code -6, caller's tx untouched",
        !r.ok && r.code == -6 && sqlite3_get_autocommit(db) == 0);
    ssd_exec("ROLLBACK");
    SSD("BEGIN failure leaves the stored pair old", ssd_stored_pair_is_old());

    /* Second row write refused: both rows roll back together. */
    ssd_store_old_pair_then_move_ram();
    ssd_exec("CREATE TRIGGER ssd_t1 BEFORE INSERT ON progress_meta "
             "WHEN NEW.key = 'service_state_reason' "
             "BEGIN SELECT RAISE(ABORT, 'ssd'); END");
    ssd_exec("CREATE TRIGGER ssd_t2 BEFORE UPDATE ON progress_meta "
             "WHEN NEW.key = 'service_state_reason' "
             "BEGIN SELECT RAISE(ABORT, 'ssd'); END");
    r = service_state_persist_to_progress_store();
    SSD("meta write failure -> code -6, no transaction left open",
        !r.ok && r.code == -6 && sqlite3_get_autocommit(db) != 0);
    ssd_exec("DROP TRIGGER ssd_t1");
    ssd_exec("DROP TRIGGER ssd_t2");
    SSD("meta write failure does not tear the pair", ssd_stored_pair_is_old());
    return failures;
}

/* COMMIT refused through a deferred foreign key: the driver must roll back. */
static int ssd_commit_failure_tests(void)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    ssd_store_old_pair_then_move_ram();
    bool armed =
        ssd_exec("PRAGMA foreign_keys = ON") &&
        ssd_exec("CREATE TABLE ssd_p(id INTEGER PRIMARY KEY)") &&
        ssd_exec("CREATE TABLE ssd_c(pid INTEGER REFERENCES ssd_p(id) "
                 "DEFERRABLE INITIALLY DEFERRED)") &&
        ssd_exec("CREATE TRIGGER ssd_t3 AFTER INSERT ON progress_meta "
                 "BEGIN INSERT INTO ssd_c VALUES (99); END") &&
        ssd_exec("CREATE TRIGGER ssd_t4 AFTER UPDATE ON progress_meta "
                 "BEGIN INSERT INTO ssd_c VALUES (99); END");
    SSD("commit-failure fixture armed", armed);
    struct zcl_result r = service_state_persist_to_progress_store();
    SSD("COMMIT failure -> code -6", !r.ok && r.code == -6);
    SSD("COMMIT failure is rolled back, no transaction left open",
        sqlite3_get_autocommit(db) != 0);
    ssd_exec("DROP TRIGGER IF EXISTS ssd_t3");
    ssd_exec("DROP TRIGGER IF EXISTS ssd_t4");
    ssd_exec("DROP TABLE IF EXISTS ssd_c");
    ssd_exec("DROP TABLE IF EXISTS ssd_p");
    ssd_exec("PRAGMA foreign_keys = OFF");
    SSD("COMMIT failure leaves the stored pair old", ssd_stored_pair_is_old());
    return failures;
}

/* transition_and_persist advances RAM and writes the same state through. */
static int ssd_transition_persist_tests(void)
{
    int failures = 0;
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    service_state_transition_and_persist(SERVICE_STATE_HEALTHY, "tp reason");
    SSD("transition_and_persist advances RAM",
        service_state_current() == SERVICE_STATE_HEALTHY);
    service_state_advance(SERVICE_STATE_BOOT, "boot");
    SSD("transition_and_persist wrote the new pair",
        service_state_restore_from_progress_store().ok &&
        service_state_current() == SERVICE_STATE_HEALTHY &&
        strcmp(service_state_reason(), "tp reason") == 0);
    return failures;
}

/* progress.kv closed: persist and restore refuse with code -5; a transition
 * still lands in RAM because the persist failure is swallowed. */
static int ssd_closed_store_tests(void)
{
    int failures = 0;
    progress_store_close();
    service_state_advance(SERVICE_STATE_SYNCING, "pre");
    struct zcl_result r = service_state_persist_to_progress_store();
    SSD("persist with no store -> code -5", !r.ok && r.code == -5);
    r = service_state_restore_from_progress_store();
    SSD("restore with no store -> code -5, state unchanged",
        !r.ok && r.code == -5 &&
        service_state_current() == SERVICE_STATE_SYNCING);
    service_state_transition_and_persist(SERVICE_STATE_HEALTHY, "ram only");
    SSD("transition with no store still advances RAM",
        service_state_current() == SERVICE_STATE_HEALTHY);
    return failures;
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

    failures += ssd_gap_boundary_tests();
    failures += ssd_no_main_state_tests();
    failures += ssd_prior_tests();
    failures += ssd_restore_edge_tests();
    failures += ssd_persist_failure_tests();
    failures += ssd_commit_failure_tests();
    failures += ssd_transition_persist_tests();
    failures += ssd_closed_store_tests();   /* closes the store: keep last */

    /* restore benign global state for any subsequent test in this group */
    condition_engine_reset_for_testing();
    service_state_driver_test_clear_overrides();
    service_state_advance(SERVICE_STATE_BOOT, "boot");

    progress_store_close();
    test_cleanup_tmpdir(dir);
    printf("ssd: %d failures\n", failures);
    return failures;
}
