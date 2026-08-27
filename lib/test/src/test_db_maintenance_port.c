/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the db_maintenance storage seam.
 *
 * db_maintenance runs exactly three SQLite maintenance ops
 * (PRAGMA wal_checkpoint(TRUNCATE) / ANALYZE / VACUUM) plus one WAL-size
 * probe; this file exercises the sqlite adapter that now backs them
 * through db_maintenance_port — against ISOLATED temp-file / in-memory
 * fixture DBs, never the live node DB.
 *
 * We assert each op reports success on a real WAL-mode DB, that
 * wal_checkpoint(TRUNCATE) actually shrinks the on-disk WAL to zero, that
 * a successful op clears the error buffer while NULL-conn ops fill it and
 * return false, and that wal_size_bytes mirrors node_health's behaviour
 * (false for :memory:, true once a file-backed WAL exists). NULL-arg
 * guards round it out.
 *
 * NOTE on coupling: test_db_maintenance.c drives the full
 * db_maintenance_run_now() service (events, status snapshot, scheduler
 * lifecycle) over its own scratch node_db; that group is unrelated to
 * this fixture-based adapter test and is left untouched. This file is
 * hermetic (its own throwaway DBs).
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/db_maintenance_sqlite.h"
#include "ports/db_maintenance_port.h"
#include "util/wal_checkpoint_stats.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBMP_CHECK(name, expr) do {                       \
    printf("db_maintenance_port: %s... ", (name));        \
    if ((expr)) { printf("OK\n"); }                       \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

static bool exec_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

/* Open a fresh file-backed WAL-mode DB with a little churn so ANALYZE /
 * VACUUM / checkpoint have real work to do. Returns the path so the
 * caller can clean up the sidecar files. */
static bool make_file_db(sqlite3 **out_db, char *path, size_t pathsz)
{
    snprintf(path, pathsz, "/tmp/zcl_dbmp_test_%d_XXXXXX", (int)getpid());
    int fd = mkstemp(path);
    if (fd >= 0) close(fd);
    unlink(path);   /* let sqlite create it fresh */

    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK || !db)
        return false;
    if (!exec_sql(db, "PRAGMA journal_mode=WAL;")) { sqlite3_close(db); return false; }
    if (!exec_sql(db,
            "CREATE TABLE kv(k INTEGER PRIMARY KEY, v BLOB);"
            "INSERT INTO kv VALUES(1, randomblob(64));"
            "INSERT INTO kv VALUES(2, randomblob(128));"
            "INSERT INTO kv VALUES(3, randomblob(256));"
            "DELETE FROM kv WHERE k=2;")) {
        sqlite3_close(db);
        return false;
    }
    *out_db = db;
    return true;
}

static void clean_file_db(sqlite3 *db, const char *path)
{
    if (db) sqlite3_close(db);
    char side[1100];
    unlink(path);
    snprintf(side, sizeof side, "%s-wal", path); unlink(side);
    snprintf(side, sizeof side, "%s-shm", path); unlink(side);
}

static int64_t wal_file_size(const char *db_path)
{
    char wal[1100];
    struct stat st;
    snprintf(wal, sizeof wal, "%s-wal", db_path);
    if (stat(wal, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

int test_db_maintenance_port(void)
{
    int failures = 0;

    /* ---- each op succeeds on a real WAL-mode file DB ---- */
    {
        char path[256];
        sqlite3 *db = NULL;
        DBMP_CHECK("file db builds", make_file_db(&db, path, sizeof path));

        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        DBMP_CHECK("bind ok",
                   db_maintenance_sqlite_bind(&ctx, db, &port));

        char err[256] = "sentinel";
        struct db_maintenance_wal_outcome wal = {0};
        DBMP_CHECK("wal_checkpoint ok",
                   port.wal_checkpoint(port.self, &wal, err, sizeof err));
        DBMP_CHECK("wal_checkpoint clears err on success", err[0] == 0);

        /* The TRUNCATE checkpoint flushes WAL frames into the main file
         * and truncates the WAL back to zero bytes. */
        DBMP_CHECK("wal_checkpoint truncated WAL to 0",
                   wal_file_size(path) == 0);

        /* The counts are the point: a checkpoint that drained a non-empty WAL
         * must be DISTINGUISHABLE from one that moved nothing. Both report
         * success, so only these numbers separate them. */
        DBMP_CHECK("wal_checkpoint reports frames moved",
                   wal.ckpt_frames > 0);
        DBMP_CHECK("wal_checkpoint drained the whole log",
                   wal.ckpt_frames >= wal.log_frames);
        DBMP_CHECK("wal_checkpoint was not busy", !wal.busy);
        DBMP_CHECK("wal_checkpoint records SQLITE_OK", wal.rc == SQLITE_OK);
        DBMP_CHECK("wal_checkpoint records file reset",
                   wal.truncate_rc == SQLITE_OK && wal.truncated);
        DBMP_CHECK("a drain classifies as drained",
                   wal_ckpt_classify(true, wal.busy, wal.log_frames,
                                     wal.ckpt_frames) == WAL_CKPT_DRAINED);

        /* Immediately re-checkpointing an already-drained WAL moves zero
         * frames. That is a NO-OP, and it must not read as a drain of a WAL
         * that had something in it. */
        struct db_maintenance_wal_outcome again = {0};
        DBMP_CHECK("second checkpoint also succeeds",
                   port.wal_checkpoint(port.self, &again, err, sizeof err));
        DBMP_CHECK("second checkpoint moved nothing",
                   again.ckpt_frames == 0 && again.log_frames == 0);

        strcpy(err, "sentinel");
        DBMP_CHECK("analyze ok", port.analyze(port.self, err, sizeof err));
        DBMP_CHECK("analyze clears err", err[0] == '\0');

        strcpy(err, "sentinel");
        DBMP_CHECK("vacuum ok", port.vacuum(port.self, err, sizeof err));
        DBMP_CHECK("vacuum clears err", err[0] == '\0');

        clean_file_db(db, path);
    }

    /* ---- wal_size_bytes: file-backed DB -> true and >= 0 ---- */
    {
        char path[256];
        sqlite3 *db = NULL;
        DBMP_CHECK("file db builds (walsize)",
                   make_file_db(&db, path, sizeof path));

        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        db_maintenance_sqlite_bind(&ctx, db, &port);

        int64_t bytes = -1;
        bool got = port.wal_size_bytes(port.self, &bytes);
        DBMP_CHECK("wal_size file-backed ok", got);
        DBMP_CHECK("wal_size >= 0", !got || bytes >= 0);

        clean_file_db(db, path);
    }

    /* ---- wal_size_bytes: in-memory has no on-disk path -> false ---- */
    {
        sqlite3 *db = NULL;
        DBMP_CHECK("memdb opens",
                   sqlite3_open(":memory:", &db) == SQLITE_OK && db);
        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        db_maintenance_sqlite_bind(&ctx, db, &port);
        int64_t bytes = 12345;
        DBMP_CHECK("wal_size in-memory false",
                   !port.wal_size_bytes(port.self, &bytes));
        DBMP_CHECK("wal_size untouched on false", bytes == 12345);
        sqlite3_close(db);
    }

    /* ---- ops on an in-memory DB still succeed (no WAL file) ---- */
    {
        sqlite3 *db = NULL;
        DBMP_CHECK("memdb opens (ops)",
                   sqlite3_open(":memory:", &db) == SQLITE_OK && db);
        (void)exec_sql(db,
            "CREATE TABLE kv(k INTEGER PRIMARY KEY, v BLOB);"
            "INSERT INTO kv VALUES(1, randomblob(64));");
        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        db_maintenance_sqlite_bind(&ctx, db, &port);
        char err[256];
        /* A non-WAL connection has no log to reclaim; the engine reports the
         * frame counts as unknown rather than as zero, and the outcome is
         * UNKNOWN — never a claimed drain. */
        struct db_maintenance_wal_outcome wal = {0};
        DBMP_CHECK("memdb wal_checkpoint ok",
                   port.wal_checkpoint(port.self, &wal, err, sizeof err));
        DBMP_CHECK("memdb wal_checkpoint reports unknown counts",
                   wal.log_frames < 0 && wal.ckpt_frames < 0 && !wal.busy);
        DBMP_CHECK("unknown counts never classify as a drain",
                   wal_ckpt_classify(true, false, wal.log_frames,
                                     wal.ckpt_frames) == WAL_CKPT_UNKNOWN);
        DBMP_CHECK("memdb analyze ok",
                   port.analyze(port.self, err, sizeof err));
        DBMP_CHECK("memdb vacuum ok",
                   port.vacuum(port.self, err, sizeof err));
        sqlite3_close(db);
    }

    /* ---- NULL / bad-arg guards ---- */
    {
        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};

        DBMP_CHECK("bind rejects NULL ctx",
                   !db_maintenance_sqlite_bind(NULL, (sqlite3 *)0x1, &port));
        DBMP_CHECK("bind rejects NULL out_port",
                   !db_maintenance_sqlite_bind(&ctx, (sqlite3 *)0x1, NULL));

        /* NULL connection is legal at bind; ops then return false with a
         * filled error buffer and wal_size returns false untouched. */
        DBMP_CHECK("bind NULL conn ok",
                   db_maintenance_sqlite_bind(&ctx, NULL, &port));
        char err[256] = "";
        struct db_maintenance_wal_outcome wal = {0};
        DBMP_CHECK("wal_checkpoint NULL db false",
                   !port.wal_checkpoint(port.self, &wal, err, sizeof err));
        DBMP_CHECK("wal_checkpoint NULL db fills err", err[0] != 0);
        DBMP_CHECK("wal_checkpoint NULL db reports unknown counts",
                   wal.log_frames == -1 && wal.ckpt_frames == -1);
        DBMP_CHECK("wal_checkpoint NULL db records misuse",
                   wal.rc == SQLITE_MISUSE && wal.truncate_rc == -1 &&
                   !wal.truncated);
        DBMP_CHECK("analyze NULL db false",
                   !port.analyze(port.self, err, sizeof err));
        DBMP_CHECK("vacuum NULL db false",
                   !port.vacuum(port.self, err, sizeof err));
        int64_t bytes = 7;
        DBMP_CHECK("wal_size NULL db false",
                   !port.wal_size_bytes(port.self, &bytes));
        DBMP_CHECK("wal_size untouched on NULL db", bytes == 7);

        /* NULL self. */
        DBMP_CHECK("wal_checkpoint NULL self false",
                   !port.wal_checkpoint(NULL, &wal, err, sizeof err));
        DBMP_CHECK("wal_size NULL self false",
                   !port.wal_size_bytes(NULL, &bytes));

        /* NULL err buffer is tolerated (op runs; error path just can't
         * report text). NULL out for wal_size returns false. */
        struct db_maintenance_sqlite_ctx ctx2;
        struct db_maintenance_port port2 = {0};
        db_maintenance_sqlite_bind(&ctx2, NULL, &port2);
        DBMP_CHECK("wal_checkpoint NULL err tolerated (still false)",
                   !port2.wal_checkpoint(port2.self, NULL, NULL, 0));
        DBMP_CHECK("wal_size NULL out false",
                   !port2.wal_size_bytes(port2.self, NULL));
    }

    return failures;
}
