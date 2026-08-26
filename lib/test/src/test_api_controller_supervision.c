/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused regression tests for supervision-coverage item #13: the REST
 * /api cache-refresh thread and the block/tx/address lookup-worker thread
 * are registered with the util/supervisor.h liveness tree (op domain) and
 * name a typed blocker when their on_stall fires. Exercises the
 * registration + stall wiring hermetically via ZCL_TESTING seams, without
 * spawning the real detached worker threads (which sleep and drive
 * compute_* against whatever main_state is/isn't set). */

#include "test/test_core.h"

#include "controllers/api_controller.h"
#include "models/hodl_wave.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "../../../app/controllers/src/api_controller_internal.h"

#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

#define ACS_CHECK(name, expr) do { \
    printf("api_controller_supervision: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool find_snapshot(const char *name, struct supervisor_snapshot *out)
{
    struct supervisor_snapshot snaps[SUPERVISOR_CAP];
    int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].name, name) == 0) {
            *out = snaps[i];
            return true;
        }
    }
    return false;
}

int api_controller_supervision_focused_tests(void)
{
    printf("\n=== api_controller supervision-coverage tests (#13) ===\n");
    int failures = 0;

    /* A cache stop must interrupt a long read without allowing the rows read
     * before SQLITE_INTERRUPT to become a seemingly valid partial snapshot. */
    {
        bool ok = true;
        sqlite3 *db = NULL;
        ok = ok && sqlite3_open(":memory:", &db) == SQLITE_OK;
        ok = ok && sqlite3_exec(db,
            "CREATE TABLE utxos(height INTEGER, value INTEGER);"
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL "
            "SELECT x+1 FROM n WHERE x<5000) "
            "INSERT INTO utxos SELECT x, x FROM n;",
            NULL, NULL, NULL) == SQLITE_OK;

        _Atomic int running = 1;
        ok = ok && api_cache_test_sqlite_progress(&running) == 0;
        atomic_store(&running, 0);
        ok = ok && api_cache_test_sqlite_progress(&running) == 1;
        sqlite3_progress_handler(db, 1000, api_cache_test_sqlite_progress,
                                 &running);
        struct hodl_wave_snapshot hodl;
        bool scanned = hodl_wave_scan_current_utxos(db, 5000, &hodl);
        sqlite3_progress_handler(db, 0, NULL, NULL);
        ok = ok && !scanned &&
             strcmp(hodl.status, "UTXO index scan interrupted") == 0;
        if (db)
            sqlite3_close(db);
        ACS_CHECK("cache stop interrupts UTXO scan without partial success", ok);
    }

    /* ── Cache-refresh thread ─────────────────────────────────────── */
    {
        bool ok = true;
        blocker_clear("api_cache_refresh_stalled");

        api_cache_test_register_supervisor();
        ok = ok && api_cache_test_supervisor_id() != SUPERVISOR_INVALID_ID;

        struct supervisor_snapshot snap;
        bool found = find_snapshot("op.api_cache_refresh", &snap);
        ok = ok && found;
        ok = ok && found && snap.deadline_secs == 120;
        ok = ok && found && snap.period_secs == 0;

        ok = ok && !blocker_exists("api_cache_refresh_stalled");
        api_cache_test_force_stall();
        ok = ok && blocker_exists("api_cache_refresh_stalled");
        ok = ok && blocker_class_for("api_cache_refresh_stalled") ==
                         BLOCKER_TRANSIENT;

        blocker_clear("api_cache_refresh_stalled");
        ACS_CHECK("api cache-refresh thread registered + names blocker on stall",
                  ok);
    }

    /* ── Lookup-worker thread ─────────────────────────────────────── */
    {
        bool ok = true;
        blocker_clear("api_lookup_stalled");

        api_lookup_test_register_supervisor();
        ok = ok && api_lookup_test_supervisor_id() != SUPERVISOR_INVALID_ID;

        struct supervisor_snapshot snap;
        bool found = find_snapshot("op.api_lookup", &snap);
        ok = ok && found;
        ok = ok && found && snap.deadline_secs == 60;
        ok = ok && found && snap.period_secs == 0;

        ok = ok && !blocker_exists("api_lookup_stalled");
        api_lookup_test_force_stall();
        ok = ok && blocker_exists("api_lookup_stalled");
        ok = ok && blocker_class_for("api_lookup_stalled") ==
                         BLOCKER_TRANSIENT;

        blocker_clear("api_lookup_stalled");
        ACS_CHECK("api lookup-worker thread registered + names blocker on stall",
                  ok);
    }

    /* ── Both children distinct, both in the op domain (dumpstate
     * supervisor visibility — acceptance bar for #13). ─────────────── */
    {
        bool ok = true;
        ok = ok && api_cache_test_supervisor_id() !=
                         api_lookup_test_supervisor_id();

        struct supervisor_snapshot cache_snap, lookup_snap;
        ok = ok && find_snapshot("op.api_cache_refresh", &cache_snap);
        ok = ok && find_snapshot("op.api_lookup", &lookup_snap);
        ACS_CHECK("cache + lookup are distinct, both-visible supervisor children",
                  ok);
    }

    /* Stop/restart reuses the registered children. Prove that quiesce's
     * deadline=0 is temporary and each next generation re-arms supervision. */
    {
        bool ok = true;
        api_cache_supervisor_quiesce();
        api_lookup_supervisor_quiesce();
        struct supervisor_snapshot cache_snap, lookup_snap;
        ok = ok && find_snapshot("op.api_cache_refresh", &cache_snap) &&
             cache_snap.deadline_secs == 0;
        ok = ok && find_snapshot("op.api_lookup", &lookup_snap) &&
             lookup_snap.deadline_secs == 0;

        api_cache_test_register_supervisor();
        api_lookup_test_register_supervisor();
        ok = ok && find_snapshot("op.api_cache_refresh", &cache_snap) &&
             cache_snap.deadline_secs == 120;
        ok = ok && find_snapshot("op.api_lookup", &lookup_snap) &&
             lookup_snap.deadline_secs == 60;
        ACS_CHECK("stop/restart re-arms both existing supervisor children", ok);
    }

    return failures;
}
