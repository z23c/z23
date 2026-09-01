/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the hodl_history storage seam.
 *
 * Two layers are exercised against an ISOLATED in-memory fixture DB
 * (built with the real blocks / tx_outputs / tx_inputs / hodl_history
 * schema) — never the live node DB:
 *
 *   1. The sqlite adapter through its port surface directly:
 *      block_time, compute_snapshot, upsert_snapshot, max_filled_height,
 *      load_all. We assert the alive-at-H aggregate matches a hand-
 *      computed expectation.
 *
 *   2. The service (hodl_history_fill_one / _fill_pending / _load_all)
 *      driving the SAME fixture and producing identical persisted rows —
 *      proving the rewire preserved external behaviour bit-for-bit.
 *
 * NOTE on coupling: test_explorer.c / test_wallet_view.c query the LIVE
 * node DB and are unrelated to this fixture-based test; this file does
 * not touch them and uses its own throwaway DB so it is hermetic.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/hodl_history_sqlite.h"
#include "ports/hodl_history_port.h"
#include "services/hodl_history_service.h"
#include "util/ar_step_readonly.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HH_CHECK(name, expr) do {                           \
    printf("hodl_history_port: %s... ", (name));            \
    if ((expr)) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* Build the minimal subset of the real schema the queries touch. */
static bool make_fixture_db(sqlite3 **out_db)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK || !db)
        return false;

    static const char *ddl =
        "CREATE TABLE blocks ("
        " hash BLOB PRIMARY KEY, height INTEGER NOT NULL,"
        " time INTEGER NOT NULL);"
        "CREATE TABLE tx_outputs ("
        " txid BLOB NOT NULL, vout INTEGER NOT NULL,"
        " value INTEGER NOT NULL, block_height INTEGER NOT NULL,"
        " PRIMARY KEY (txid, vout));"
        "CREATE TABLE tx_inputs ("
        " txid BLOB NOT NULL, vin_index INTEGER NOT NULL,"
        " prev_txid BLOB NOT NULL, prev_vout INTEGER NOT NULL,"
        " block_height INTEGER NOT NULL,"
        " PRIMARY KEY (txid, vin_index));"
        "CREATE TABLE hodl_history ("
        " height INTEGER PRIMARY KEY,"
        " time INTEGER NOT NULL,"
        " total_zat INTEGER NOT NULL DEFAULT 0 CHECK(total_zat >= 0),"
        " older_6m_zat INTEGER NOT NULL DEFAULT 0"
        "   CHECK(older_6m_zat >= 0 AND older_6m_zat <= total_zat),"
        " older_1y_zat INTEGER NOT NULL DEFAULT 0"
        "   CHECK(older_1y_zat >= 0 AND older_1y_zat <= total_zat),"
        " older_2y_zat INTEGER NOT NULL DEFAULT 0"
        "   CHECK(older_2y_zat >= 0 AND older_2y_zat <= total_zat),"
        " older_5y_zat INTEGER NOT NULL DEFAULT 0"
        "   CHECK(older_5y_zat >= 0 AND older_5y_zat <= total_zat),"
        " older_6m_pct REAL NOT NULL DEFAULT 0,"
        " older_1y_pct REAL NOT NULL DEFAULT 0,"
        " older_2y_pct REAL NOT NULL DEFAULT 0,"
        " older_5y_pct REAL NOT NULL DEFAULT 0,"
        " calc_version INTEGER NOT NULL DEFAULT 0,"
        " source_tip_height INTEGER NOT NULL DEFAULT -1);";
    if (sqlite3_exec(db, ddl, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    *out_db = db;
    return true;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool set_projection_tip(sqlite3 *db, int64_t height)
{
    sqlite3_stmt *s = NULL;
    if (!db ||
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS node_state ("
            "key TEXT PRIMARY KEY,value BLOB)",
            NULL, NULL, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO node_state(key,value) VALUES(?1,?2)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_text(s, 1, "sync_projection_tip_height", -1,
                      SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, &height, (int)sizeof(height),
                      SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static int64_t query_total_at_height(sqlite3 *db, int64_t height, int64_t fallback)
{
    sqlite3_stmt *s = NULL;
    int64_t v = fallback;
    if (!db ||
        sqlite3_prepare_v2(db,
            "SELECT total_zat FROM hodl_history WHERE height=?1",
            -1, &s, NULL) != SQLITE_OK || !s)
        return fallback;
    sqlite3_bind_int64(s, 1, height);
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

/* Seed a scenario:
 *   block 1 @ t=0           : creates output (txA,0)=100, (txA,1)=50
 *   block 2 @ t=1y+10       : creates output (txB,0)=200
 *   block 3 @ t=2y          : spends (txA,1)  [so 50 becomes dead at >=3]
 *
 * "Alive at height H" + "older than 1y" arithmetic, with the 1-Julian-
 * year cutoff = 31557600 s, evaluated at H=3 (block_time = 2y):
 *   alive at 3 = (txA,0)=100, (txB,0)=200  -> total = 300
 *               ((txA,1)=50 is spent at block 3 <= 3, so excluded)
 *   cutoff = 2y - 1y = 1y. created-block time <= 1y:
 *     (txA,0): block 1 time 0      <= 1y  -> older
 *     (txB,0): block 2 time 1y+10  >  1y  -> not older
 *   so older = 100, pct = 100/300*100 = 33.333... */
static bool seed_scenario(sqlite3 *db)
{
    const int64_t YEAR = 31557600;
    char sql[1024];
    snprintf(sql, sizeof sql,
        "INSERT INTO blocks(hash,height,time) VALUES"
        " (x'01',1,0),(x'02',2,%lld),(x'03',3,%lld);",
        (long long)(YEAR + 10), (long long)(2 * YEAR));
    if (!exec_sql(db, sql)) return false;

    if (!exec_sql(db,
        "INSERT INTO tx_outputs(txid,vout,value,block_height) VALUES"
        " (x'AA',0,100,1),(x'AA',1,50,1),(x'BB',0,200,2);"))
        return false;

    /* block 3 spends (txA=0xAA, vout=1). */
    if (!exec_sql(db,
        "INSERT INTO tx_inputs(txid,vin_index,prev_txid,prev_vout,block_height)"
        " VALUES (x'CC',0,x'AA',1,3);"))
        return false;
    return true;
}

int test_hodl_history_port(void)
{
    int failures = 0;
    const int64_t YEAR = 31557600;

    /* ---- Layer 1: adapter through the port directly ---- */
    {
        sqlite3 *db = NULL;
        HH_CHECK("fixture db builds", make_fixture_db(&db));
        HH_CHECK("scenario seeds", db && seed_scenario(db));

        struct hodl_history_port port = {0};
        HH_CHECK("bind sqlite port", hodl_history_sqlite_bind(db, &port));

        int64_t bt = -1;
        HH_CHECK("block_time(3) hit", port.block_time(port.self, 3, &bt));
        HH_CHECK("block_time(3) == 2y", bt == 2 * YEAR);

        int64_t bt_miss = -1;
        HH_CHECK("block_time(99) miss",
                 !port.block_time(port.self, 99, &bt_miss));

        int64_t total = -1;
        int64_t older[HODL_HISTORY_THRESHOLDS] = {-1, -1, -1, -1};
        int64_t cutoffs[HODL_HISTORY_THRESHOLDS] = {
            (2 * YEAR) - HODL_HISTORY_HALF_YEAR_SECONDS,
            (2 * YEAR) - HODL_HISTORY_ONE_YEAR_SECONDS,
            (2 * YEAR) - HODL_HISTORY_TWO_YEAR_SECONDS,
            (2 * YEAR) - HODL_HISTORY_FIVE_YEAR_SECONDS,
        };
        HH_CHECK("compute_snapshot ok",
                 port.compute_snapshot(port.self, 3, cutoffs, &total, older));
        HH_CHECK("total alive at 3 == 300", total == 300);
        HH_CHECK("older-than-6m == 300",
                 older[HODL_HISTORY_THRESHOLD_6M] == 300);
        HH_CHECK("older-than-1y == 100",
                 older[HODL_HISTORY_THRESHOLD_1Y] == 100);
        HH_CHECK("older-than-2y includes exact boundary",
                 older[HODL_HISTORY_THRESHOLD_2Y] == 100);
        HH_CHECK("older-than-5y == 0",
                 older[HODL_HISTORY_THRESHOLD_5Y] == 0);

        HH_CHECK("max_filled empty == 0",
                 port.max_filled_height(port.self) == 0);

        struct hodl_history_snapshot row = {
            .height = 3, .time = 2 * YEAR,
            .total_zat = total,
            .older_6m_zat = older[HODL_HISTORY_THRESHOLD_6M],
            .older_1y_zat = older[HODL_HISTORY_THRESHOLD_1Y],
            .older_2y_zat = older[HODL_HISTORY_THRESHOLD_2Y],
            .older_5y_zat = older[HODL_HISTORY_THRESHOLD_5Y],
            .older_6m_pct = 100.0,
            .older_1y_pct = (double)older[HODL_HISTORY_THRESHOLD_1Y] /
                             (double)total * 100.0,
            .older_2y_pct = (double)older[HODL_HISTORY_THRESHOLD_2Y] /
                             (double)total * 100.0,
            .older_5y_pct = 0.0,
        };
        HH_CHECK("upsert ok", port.upsert_snapshot(port.self, &row));
        HH_CHECK("max_filled == 3", port.max_filled_height(port.self) == 3);

        /* Idempotent INSERT OR REPLACE: re-upsert same key, still 1 row. */
        HH_CHECK("upsert idempotent", port.upsert_snapshot(port.self, &row));

        struct hodl_history_snapshot loaded[8];
        int n = port.load_all(port.self, loaded, 8);
        HH_CHECK("load_all returns 1 row", n == 1);
        HH_CHECK("loaded height", n == 1 && loaded[0].height == 3);
        HH_CHECK("loaded total", n == 1 && loaded[0].total_zat == 300);
        HH_CHECK("loaded older 6m", n == 1 && loaded[0].older_6m_zat == 300);
        HH_CHECK("loaded older", n == 1 && loaded[0].older_1y_zat == 100);
        HH_CHECK("loaded older 2y", n == 1 && loaded[0].older_2y_zat == 100);
        HH_CHECK("loaded older 5y", n == 1 && loaded[0].older_5y_zat == 0);
        HH_CHECK("loaded pct 6m", n == 1 && loaded[0].older_6m_pct == 100.0);
        HH_CHECK("loaded pct ~33.33",
                 n == 1 && loaded[0].older_1y_pct > 33.0 &&
                 loaded[0].older_1y_pct < 33.5);

        sqlite3_close(db);
    }

    /* ---- Layer 2: the service produces identical rows via the port ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db) || !seed_scenario(db)) {
            HH_CHECK("service fixture builds", false);
            if (db) sqlite3_close(db);
            return failures;
        }

        /* fill_one drives the same aggregate + clamp + pct + upsert. */
        HH_CHECK("service fill_one(3)", hodl_history_fill_one(db, 3).ok);

        struct hodl_history_row rows[8];
        int n = hodl_history_load_all(db, rows, 8);
        HH_CHECK("service load_all 1 row", n == 1);
        HH_CHECK("service height 3", n == 1 && rows[0].height == 3);
        HH_CHECK("service time 2y", n == 1 && rows[0].time == 2 * YEAR);
        HH_CHECK("service total 300", n == 1 && rows[0].total_zat == 300);
        HH_CHECK("service older 6m 300",
                 n == 1 && rows[0].older_6m_zat == 300);
        HH_CHECK("service older 100", n == 1 && rows[0].older_1y_zat == 100);
        HH_CHECK("service older 2y 100",
                 n == 1 && rows[0].older_2y_zat == 100);
        HH_CHECK("service older 5y 0",
                 n == 1 && rows[0].older_5y_zat == 0);
        HH_CHECK("service pct 6m",
                 n == 1 && rows[0].older_6m_pct == 100.0);
        HH_CHECK("service pct ~33.33",
                 n == 1 && rows[0].older_1y_pct > 33.0 &&
                 rows[0].older_1y_pct < 33.5);

        /* fill_one on a missing height is a clean no-op false (block
         * not indexed) and must NOT persist a row. */
        HH_CHECK("service fill_one(99) false",
                 !hodl_history_fill_one(db, 99).ok);
        n = hodl_history_load_all(db, rows, 8);
        HH_CHECK("still 1 row after miss", n == 1);

        sqlite3_close(db);
    }

    /* ---- fill_pending repairs stale/missing rows below the max height ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db)) {
            HH_CHECK("repair fixture builds", false);
            return failures;
        }

        const int64_t S = HODL_HISTORY_SAMPLE_STRIDE;
        char sql[2048];
        snprintf(sql, sizeof sql,
            "INSERT INTO blocks(hash,height,time) VALUES"
            " (x'10',%lld,%lld),(x'11',%lld,%lld),"
            " (x'12',%lld,%lld),(x'13',%lld,%lld);"
            "INSERT INTO tx_outputs(txid,vout,value,block_height) VALUES"
            " (x'DD',0,100,%lld);"
            "INSERT INTO hodl_history(height,time,total_zat,older_1y_zat,"
            "older_1y_pct,calc_version,source_tip_height) VALUES"
            " (%lld,%lld,0,0,0.0,%d,%lld),"
            " (%lld,%lld,50,0,0.0,%d,%lld),"
            " (%lld,%lld,100,0,0.0,%d,%lld);",
            (long long)S,       (long long)YEAR,
            (long long)(2 * S), (long long)(YEAR + 100),
            (long long)(3 * S), (long long)(YEAR + 200),
            (long long)(4 * S), (long long)(YEAR + 300),
            (long long)S,
            (long long)S,       (long long)YEAR,
            HODL_HISTORY_SNAPSHOT_CALC_VERSION, (long long)(S - 1),
            (long long)(3 * S), (long long)(YEAR + 200),
            HODL_HISTORY_SNAPSHOT_CALC_VERSION, (long long)(3 * S - 1),
            (long long)(4 * S), (long long)(YEAR + 300),
            HODL_HISTORY_SNAPSHOT_CALC_VERSION, (long long)(4 * S));
        HH_CHECK("repair scenario seeds", exec_sql(db, sql));

        HH_CHECK("repair stale zero below max",
                 hodl_history_fill_pending(db, 4 * S, 1) == 1);
        HH_CHECK("stale zero recomputed",
                 query_total_at_height(db, S, -1) == 100);

        HH_CHECK("repair missing middle sample",
                 hodl_history_fill_pending(db, 4 * S, 1) == 1);
        HH_CHECK("middle sample inserted",
                 query_total_at_height(db, 2 * S, -1) == 100);

        HH_CHECK("repair stale nonzero with insufficient source coverage",
                 hodl_history_fill_pending(db, 4 * S, 1) == 1);
        HH_CHECK("stale nonzero recomputed",
                 query_total_at_height(db, 3 * S, -1) == 100);

        HH_CHECK("repair complete no-op",
                 hodl_history_fill_pending(db, 4 * S, 1) == 0);

        sqlite3_close(db);
    }

    /* ---- fill_pending waits for source projection coverage ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db)) {
            HH_CHECK("source-gate fixture builds", false);
            return failures;
        }

        const int64_t S = HODL_HISTORY_SAMPLE_STRIDE;
        char sql[1536];
        snprintf(sql, sizeof sql,
            "INSERT INTO blocks(hash,height,time) VALUES"
            " (x'20',%lld,%lld),(x'21',%lld,%lld);"
            "INSERT INTO tx_outputs(txid,vout,value,block_height) VALUES"
            " (x'EE',0,100,%lld);"
            "INSERT INTO hodl_history(height,time,total_zat,older_1y_zat,"
            "older_1y_pct,calc_version,source_tip_height) VALUES"
            " (%lld,%lld,100,0,0.0,%d,%lld);",
            (long long)S,       (long long)YEAR,
            (long long)(2 * S), (long long)(YEAR + 100),
            (long long)S,
            (long long)S,       (long long)YEAR,
            HODL_HISTORY_SNAPSHOT_CALC_VERSION, (long long)S);
        HH_CHECK("source-gate scenario seeds", exec_sql(db, sql));
        HH_CHECK("source tip set to first sample",
                 set_projection_tip(db, S));

        HH_CHECK("missing sample waits for source coverage",
                 hodl_history_fill_pending(db, 2 * S, 1) == 0);
        HH_CHECK("source tip advances to missing sample",
                 set_projection_tip(db, 2 * S));
        HH_CHECK("missing sample fills after source coverage",
                 hodl_history_fill_pending(db, 2 * S, 1) == 1);
        HH_CHECK("source-gated sample inserted",
                 query_total_at_height(db, 2 * S, -1) == 100);

        sqlite3_close(db);
    }

    /* ---- fill_pending starts at the first indexed sample after an anchor ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db)) {
            HH_CHECK("anchor fixture builds", false);
            return failures;
        }

        const int64_t S = HODL_HISTORY_SAMPLE_STRIDE;
        char sql[1024];
        snprintf(sql, sizeof sql,
            "INSERT INTO blocks(hash,height,time) VALUES"
            " (x'30',%lld,%lld),(x'31',%lld,%lld);"
            "INSERT INTO tx_outputs(txid,vout,value,block_height) VALUES"
            " (x'FA',0,100,%lld);",
            (long long)(10 * S), (long long)YEAR,
            (long long)(11 * S), (long long)(YEAR + 100),
            (long long)(10 * S));
        HH_CHECK("anchor scenario seeds", exec_sql(db, sql));
        HH_CHECK("anchor source tip covers samples",
                 set_projection_tip(db, 11 * S));

        HH_CHECK("anchor skips unavailable early samples",
                 hodl_history_fill_pending(db, 11 * S, 1) == 1);
        HH_CHECK("anchor first indexed sample inserted",
                 query_total_at_height(db, 10 * S, -1) == 100);
        HH_CHECK("anchor did not insert pre-anchor sample",
                 query_total_at_height(db, S, -1) == -1);

        sqlite3_close(db);
    }

    /* ---- Chart loader keeps the most recent capped samples, displayed ASC ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db)) {
            HH_CHECK("recency fixture builds", false);
            return failures;
        }

        HH_CHECK("recency rows seed",
                 exec_sql(db,
                     "INSERT INTO hodl_history(height,time,total_zat,"
                     "older_6m_zat,older_1y_zat,older_2y_zat,older_5y_zat,"
                     "older_6m_pct,older_1y_pct,older_2y_pct,older_5y_pct,"
                     "calc_version,source_tip_height) VALUES"
                     "(1,10,100,20,10,0,0,20.0,10.0,0.0,0.0,2,1),"
                     "(2,20,200,40,20,0,0,20.0,10.0,0.0,0.0,2,2),"
                     "(3,30,300,60,30,0,0,20.0,10.0,0.0,0.0,2,3);"));

        struct hodl_history_row rows[2];
        int n = hodl_history_load_all(db, rows, 2);
        HH_CHECK("load_all cap keeps newest two",
                 n == 2 && rows[0].height == 2 && rows[1].height == 3);
        HH_CHECK("load_all newest two stay ascending",
                 n == 2 && rows[0].time == 20 && rows[1].time == 30);

        sqlite3_close(db);
    }

    /* ---- Guard rails: NULL / bad args ---- */
    {
        struct hodl_history_port port = {0};
        HH_CHECK("bind rejects NULL db",
                 !hodl_history_sqlite_bind(NULL, &port));
        HH_CHECK("fill_one rejects NULL db",
                 !hodl_history_fill_one(NULL, 1).ok);
        HH_CHECK("fill_one rejects height<1",
                 !hodl_history_fill_one((sqlite3 *)0x1, 0).ok);
        HH_CHECK("load_all rejects NULL db",
                 hodl_history_load_all(NULL, NULL, 8) == 0);
        HH_CHECK("fill_pending rejects small tip",
                 hodl_history_fill_pending((sqlite3 *)0x1, 1, 4) == 0);
    }

    return failures;
}
