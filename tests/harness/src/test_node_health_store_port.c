/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the node_health storage seam.
 *
 * node_health_collect() performs exactly three persistent reads against
 * the node DB; this file exercises the sqlite adapter that now backs them
 * through node_health_store_port — against ISOLATED in-memory / temp-file
 * fixture DBs, never the live node DB:
 *
 *   tip_height_from_blocks  "SELECT COALESCE(MAX(height), -1) FROM blocks"
 *   utxo_count              "SELECT count(*) FROM utxos"
 *   wal_size_bytes          sqlite3_db_filename(...,"main") + stat("-wal")
 *
 * We assert the COALESCE(-1) empty-table behaviour, the MAX over multiple
 * rows, the exact UTXO count, and that wal_size_bytes returns false for an
 * in-memory DB (no on-disk filename) yet succeeds against a file-backed DB
 * once a WAL exists. NULL-arg guards round it out.
 *
 * NOTE on coupling: test_node_health_service.c drives the full
 * node_health_collect() over its own in-memory node_db; that group is
 * unrelated to this fixture-based adapter test and is left untouched. This
 * file is hermetic (its own throwaway DBs).
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/node_health_store_sqlite.h"
#include "ports/node_health_store_port.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NHS_CHECK(name, expr) do {                          \
    printf("node_health_store_port: %s... ", (name));       \
    if ((expr)) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

static bool exec_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

/* Minimal subset of the real schema the two SELECTs touch: blocks(height)
 * and utxos (count only). */
static bool make_fixture_db(sqlite3 **out_db)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK || !db)
        return false;
    static const char *ddl =
        "CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash BLOB);"
        "CREATE TABLE utxos (txid BLOB, vout INTEGER,"
        " PRIMARY KEY (txid, vout));";
    if (sqlite3_exec(db, ddl, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    *out_db = db;
    return true;
}

int test_node_health_store_port(void)
{
    int failures = 0;

    /* ---- empty tables: COALESCE(-1) and count 0 ---- */
    {
        sqlite3 *db = NULL;
        NHS_CHECK("fixture db builds", make_fixture_db(&db));

        struct node_health_store_sqlite_ctx ctx;
        struct node_health_store_port port = {0};
        NHS_CHECK("bind ok",
                  node_health_store_sqlite_bind(&ctx, db, db, &port));

        int tip = 12345;   /* sentinel — should be overwritten to -1 */
        NHS_CHECK("tip_height empty ok",
                  port.tip_height_from_blocks(port.self, &tip));
        NHS_CHECK("tip_height empty == -1", tip == -1);

        int64_t n = 99;
        NHS_CHECK("utxo_count empty ok", port.utxo_count(port.self, &n));
        NHS_CHECK("utxo_count empty == 0", n == 0);

        sqlite3_close(db);
    }

    /* ---- populated tables: MAX(height) and exact count ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db)) {
            NHS_CHECK("populated fixture builds", false);
            if (db) sqlite3_close(db);
            return failures;
        }
        NHS_CHECK("seed blocks",
                  exec_sql(db,
                      "INSERT INTO blocks(height) VALUES (1),(2),(7),(5);"));
        NHS_CHECK("seed utxos",
                  exec_sql(db,
                      "INSERT INTO utxos(txid,vout) VALUES"
                      " (x'AA',0),(x'AA',1),(x'BB',0);"));

        struct node_health_store_sqlite_ctx ctx;
        struct node_health_store_port port = {0};
        NHS_CHECK("bind ok",
                  node_health_store_sqlite_bind(&ctx, db, db, &port));

        int tip = -99;
        NHS_CHECK("tip_height ok",
                  port.tip_height_from_blocks(port.self, &tip));
        NHS_CHECK("tip_height == MAX 7", tip == 7);

        int64_t n = -1;
        NHS_CHECK("utxo_count ok", port.utxo_count(port.self, &n));
        NHS_CHECK("utxo_count == 3", n == 3);

        sqlite3_close(db);
    }

    /* ---- wal_size_bytes: in-memory has no on-disk path -> false ---- */
    {
        sqlite3 *db = NULL;
        NHS_CHECK("memdb builds", make_fixture_db(&db));
        struct node_health_store_sqlite_ctx ctx;
        struct node_health_store_port port = {0};
        NHS_CHECK("bind ok",
                  node_health_store_sqlite_bind(&ctx, db, db, &port));
        int64_t wal = 12345;
        NHS_CHECK("wal_size in-memory false",
                  !port.wal_size_bytes(port.self, &wal));
        NHS_CHECK("wal_size left untouched on false", wal == 12345);
        sqlite3_close(db);
    }

    /* ---- wal_size_bytes: file-backed DB in WAL mode -> true ---- */
    {
        char tmpl[] = "/tmp/zcl_nhs_test_XXXXXX";
        int fd = mkstemp(tmpl);
        if (fd >= 0) close(fd);
        unlink(tmpl);   /* let sqlite create it fresh */

        sqlite3 *db = NULL;
        bool opened = (sqlite3_open(tmpl, &db) == SQLITE_OK && db);
        NHS_CHECK("file db opens", opened);
        if (opened) {
            (void)exec_sql(db, "PRAGMA journal_mode=WAL;");
            NHS_CHECK("file schema",
                      exec_sql(db,
                          "CREATE TABLE blocks(height INTEGER PRIMARY KEY,"
                          " hash BLOB);"));
            /* A committed write in WAL mode materialises the -wal file. */
            NHS_CHECK("file write",
                      exec_sql(db, "INSERT INTO blocks(height) VALUES (1);"));

            struct node_health_store_sqlite_ctx ctx;
            struct node_health_store_port port = {0};
            NHS_CHECK("bind ok",
                      node_health_store_sqlite_bind(&ctx, NULL, db, &port));
            int64_t wal = -1;
            bool got = port.wal_size_bytes(port.self, &wal);
            NHS_CHECK("wal_size file-backed ok", got);
            NHS_CHECK("wal_size >= 0", !got || wal >= 0);

            sqlite3_close(db);
        }
        /* Clean up DB + sidecar files. */
        char side[1100];
        unlink(tmpl);
        snprintf(side, sizeof side, "%s-wal", tmpl); unlink(side);
        snprintf(side, sizeof side, "%s-shm", tmpl); unlink(side);
    }

    /* ---- NULL / bad-arg guards ---- */
    {
        struct node_health_store_sqlite_ctx ctx;
        struct node_health_store_port port = {0};

        NHS_CHECK("bind rejects NULL ctx",
                  !node_health_store_sqlite_bind(NULL, (sqlite3 *)0x1,
                                                 (sqlite3 *)0x1, &port));
        NHS_CHECK("bind rejects NULL out_port",
                  !node_health_store_sqlite_bind(&ctx, (sqlite3 *)0x1,
                                                 (sqlite3 *)0x1, NULL));

        /* NULL connections are legal at bind; methods then return false. */
        NHS_CHECK("bind NULL conns ok",
                  node_health_store_sqlite_bind(&ctx, NULL, NULL, &port));
        int tip = 7;
        int64_t n = 7, wal = 7;
        NHS_CHECK("tip_height NULL db false",
                  !port.tip_height_from_blocks(port.self, &tip));
        NHS_CHECK("utxo_count NULL db false",
                  !port.utxo_count(port.self, &n));
        NHS_CHECK("wal_size NULL db false",
                  !port.wal_size_bytes(port.self, &wal));
        NHS_CHECK("out untouched on NULL db",
                  tip == 7 && n == 7 && wal == 7);

        /* NULL out-parameter guards. */
        struct node_health_store_port port2 = {0};
        node_health_store_sqlite_bind(&ctx, (sqlite3 *)0x1, (sqlite3 *)0x1,
                                      &port2);
        NHS_CHECK("tip_height NULL out false",
                  !port2.tip_height_from_blocks(port2.self, NULL));
        NHS_CHECK("utxo_count NULL out false",
                  !port2.utxo_count(port2.self, NULL));
        NHS_CHECK("wal_size NULL out false",
                  !port2.wal_size_bytes(port2.self, NULL));

        /* NULL self. */
        NHS_CHECK("tip_height NULL self false",
                  !port.tip_height_from_blocks(NULL, &tip));
    }

    return failures;
}
