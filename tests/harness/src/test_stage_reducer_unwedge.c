/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for stage_reconcile_clamp_tip_finalize_to_floor — the SAFE reducer
 * cursor/coins/finality reconcile that un-wedges the chain.
 *
 * The wedge: after an unclean restart the durable tip_finalize cursor sits
 * AHEAD of the applied coins tip, so tip_finalize idles and the connect gate
 * rejects every block as "block-not-finalized-by-reducer".
 *
 * A PRIOR fix (reverted) deleted *_log rows above the floor and clamped every
 * cursor; on restart the Tier-2 public-tip authority
 * (SELECT MAX(height) FROM tip_finalize_log WHERE ok=1) lost its evidence base
 * and the public tip COLLAPSED to an ancient surviving row (~47279) — a chain
 * reset. A later variant used MAX(ok=1) as executable cursor authority and
 * recreated the live uv_cursor_gap wedge when stale served-floor rows sat above
 * coins_best. This test pins the corrected, reset-safe behavior:
 *   - reconciles ONLY the tip_finalize cursor (upstream cursors untouched),
 *   - deletes NO log rows (so MAX(ok=1) can never drop below coins_best),
 *   - never writes the executable cursor above coins_best just because stale
 *     served-floor evidence exists,
 *   - uses the served tip's OWN height convention (cursor C == served tip at C,
 *     NOT C+1), and no-ops when coins_best < 0. */

#include "test/test_core.h"
#include "jobs/stage_repair.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define UW(desc, expr) do { \
    printf("unwedge: %s... ", (desc)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Tier-2 public-tip authority query — single source of truth (Law 8).
 * The highest finalized (ok=1) height in tip_finalize_log, or -1 if none. */
static const char SQL_TIP_FINALIZE_MAX_OK[] =
    "SELECT COALESCE(MAX(height),-1) FROM tip_finalize_log WHERE ok=1";

static void uw_exec(sqlite3 *db, const char *sql)
{
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}

static int uw_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int v = -999;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

static int uw_query_int(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

int test_stage_reducer_unwedge(void);
int test_stage_reducer_unwedge(void)
{
    printf("\n=== stage reducer un-wedge (tip_finalize clamp) tests ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "unwedge", "main");
    if (!progress_store_open(dir)) {
        printf("unwedge: progress_store_open FAILED\n");
        return 1;
    }
    sqlite3 *db = progress_store_db();

    const int APPLIED = 3;   /* coins_best — stale durably applied tip scan */
    const int STALE   = 6;   /* durable served floor in tip_finalize_log */
    const int CURSOR  = 8;   /* cursor drifted above both floors */

    uw_exec(db,
        "CREATE TABLE IF NOT EXISTS stage_cursor("
        "name TEXT PRIMARY KEY, cursor INTEGER, updated_at INTEGER)");
    uw_exec(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER,"
        "work_delta_high INTEGER, work_delta_low INTEGER,"
        "utxo_size_after INTEGER, reorg_depth INTEGER, finalized_at INTEGER,"
        "tip_hash BLOB)");

    /* WEDGE: tip_finalize is above the served floor, while the upstream cursors
     * remain at the header high. */
    uw_exec(db, "INSERT OR REPLACE INTO stage_cursor VALUES('tip_finalize',8,1)");
    uw_exec(db, "INSERT OR REPLACE INTO stage_cursor VALUES('utxo_apply',8,1)");
    uw_exec(db, "INSERT OR REPLACE INTO stage_cursor VALUES('body_fetch',8,1)");

    /* Contiguous finalized rows 0..STALE (ok=1): rows 0..APPLIED are the
     * surviving authority; rows APPLIED+1..STALE model the pre-crash
     * finalization above the rewound coins tip. PLUS an ancient anchor row to
     * prove the Tier-2 MAX never selects it. */
    uw_exec(db, "INSERT OR REPLACE INTO tip_finalize_log"
        "(height,status,ok,work_delta_high,work_delta_low,utxo_size_after,"
        "reorg_depth,finalized_at) VALUES(0,'anchor',1,0,1,0,0,1)");
    for (int h = 0; h <= STALE; h++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,utxo_size_after,"
            "reorg_depth,finalized_at) VALUES(%d,'finalized',1,0,1,0,0,1)", h);
        uw_exec(db, sql);
    }

    int rows_before = uw_query_int(db, "SELECT COUNT(*) FROM tip_finalize_log");
    int max_before  = uw_query_int(db, SQL_TIP_FINALIZE_MAX_OK);

    /* ── the reconcile ── */
    struct stage_reconcile_result rr;
    memset(&rr, 0, sizeof(rr));
    UW("reconcile runs",
       stage_reconcile_clamp_tip_finalize_to_floor(db, APPLIED, &rr));
    UW("reconciled (cursor was off target)", rr.clamped == true);
    /* TASK #31: the served-tip cursor floor is the served tip's OWN height,
     * NEVER +1. The live regression pinned here is distinct: stale
     * served-floor evidence at STALE must not raise the executable cursor above
     * APPLIED, because utxo_apply has not applied APPLIED+1..STALE. */
    UW("floor stays at applied coins frontier", rr.floor == APPLIED);

    /* reconciles ONLY tip_finalize, to the applied-frontier target */
    UW("tip_finalize cursor reconciled to coins frontier",
       uw_cursor(db, "tip_finalize") == APPLIED);
    /* upstream cursors UNCHANGED (this is what lets re-finalize replay forward) */
    UW("utxo_apply cursor UNCHANGED", uw_cursor(db, "utxo_apply") == CURSOR);
    UW("body_fetch cursor UNCHANGED", uw_cursor(db, "body_fetch") == CURSOR);

    /* NO log rows deleted — the reset-safety property */
    UW("no tip_finalize_log rows deleted",
       uw_query_int(db, "SELECT COUNT(*) FROM tip_finalize_log") == rows_before);
    /* the ~47279-style regression guard: Tier-2 floor never drops below coins */
    UW("Tier-2 MAX(ok=1) >= coins_best (no tip collapse)",
       uw_query_int(db, SQL_TIP_FINALIZE_MAX_OK) >= APPLIED);
    UW("Tier-2 MAX(ok=1) unchanged by reconcile",
       uw_query_int(db, SQL_TIP_FINALIZE_MAX_OK) == max_before);

    /* ── no-op: cursor already at the applied-frontier floor. ── */
    uw_exec(db, "INSERT OR REPLACE INTO stage_cursor VALUES('tip_finalize',3,1)");
    struct stage_reconcile_result rr2;
    memset(&rr2, 0, sizeof(rr2));
    UW("no-op when cursor at floor (not ahead)",
       stage_reconcile_clamp_tip_finalize_to_floor(db, APPLIED, &rr2) &&
       rr2.clamped == false);
    UW("cursor unchanged on no-op", uw_cursor(db, "tip_finalize") == APPLIED);

    /* ── behind the applied frontier: raise to coins_best. ── */
    uw_exec(db, "INSERT OR REPLACE INTO stage_cursor VALUES('tip_finalize',2,1)");
    struct stage_reconcile_result rr3;
    memset(&rr3, 0, sizeof(rr3));
    UW("raises when cursor is behind coins frontier",
       stage_reconcile_clamp_tip_finalize_to_floor(db, APPLIED, &rr3) &&
       rr3.clamped == true);
    UW("cursor raised to coins frontier", uw_cursor(db, "tip_finalize") == APPLIED);

    /* ── refuse when no durable anchor (coins_best < 0) ── */
    struct stage_reconcile_result rr4;
    memset(&rr4, 0, sizeof(rr4));
    UW("no-op when coins_best < 0",
       stage_reconcile_clamp_tip_finalize_to_floor(db, -1, &rr4) &&
       rr4.clamped == false);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    printf("unwedge: %d failures\n", failures);
    return failures;
}
