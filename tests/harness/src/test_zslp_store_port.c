/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the zslp storage seam.
 *
 * zslp_service_open_db()'s "open from datadir" branch is the only place the
 * ZSLP service named sqlite; it now runs through zslp_store_port, backed by
 * the sqlite adapter exercised here against an ISOLATED temp datadir, never
 * the live node DB.
 *
 * We assert that open():
 *   - creates "<datadir>/node.db" with the zslp_balances table present,
 *   - hands back a usable, owned connection,
 *   - rejects NULL datadir / NULL db_out (leaving *db_out NULL),
 *   - returns false for an unopenable path,
 * and that close() releases the handle and tolerates NULL. NULL-arg guards
 * on bind round it out.
 *
 * Hermetic: every connection here is over a throwaway temp directory the
 * test creates and removes; no coupling to the live node DB.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/zslp_store_sqlite.h"
#include "ports/zslp_store_port.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZSS_CHECK(name, expr) do {                          \
    printf("zslp_store_port: %s... ", (name));              \
    if ((expr)) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* Does the open connection have a zslp_balances table? */
static bool has_zslp_balances(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    bool present = false;
    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='zslp_balances'",
            -1, &stmt, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        present = true;
    sqlite3_finalize(stmt);
    return present;
}

int test_zslp_store_port(void)
{
    int failures = 0;

    /* ---- happy path: open creates node.db + zslp_balances ---- */
    {
        char dir[] = "/tmp/zcl_zss_test_XXXXXX";
        bool made = (mkdtemp(dir) != NULL);
        ZSS_CHECK("temp datadir made", made);

        struct zslp_store_port port = {0};
        ZSS_CHECK("bind ok", zslp_store_sqlite_bind(&port));

        void *db = NULL;
        ZSS_CHECK("open ok", port.open(port.self, dir, &db));
        ZSS_CHECK("open set handle", db != NULL);
        ZSS_CHECK("zslp_balances table present",
                  db && has_zslp_balances((sqlite3 *)db));

        /* node.db materialised on disk under the datadir. */
        char path[1100];
        struct stat st;
        snprintf(path, sizeof path, "%s/node.db", dir);
        ZSS_CHECK("node.db on disk", stat(path, &st) == 0);

        port.close(port.self, db);

        /* Clean up DB + sidecar files + dir. */
        unlink(path);
        char side[1200];
        snprintf(side, sizeof side, "%s-wal", path); unlink(side);
        snprintf(side, sizeof side, "%s-shm", path); unlink(side);
        rmdir(dir);
    }

    /* ---- NULL datadir / NULL db_out guards ---- */
    {
        struct zslp_store_port port = {0};
        ZSS_CHECK("bind ok", zslp_store_sqlite_bind(&port));

        void *db = (void *)0x1;   /* sentinel — must be set NULL on reject */
        ZSS_CHECK("open NULL datadir false",
                  !port.open(port.self, NULL, &db));
        ZSS_CHECK("open NULL datadir left db NULL", db == NULL);

        ZSS_CHECK("open NULL db_out false",
                  !port.open(port.self, "/tmp", NULL));
    }

    /* ---- unopenable path -> false, db_out NULL ---- */
    {
        struct zslp_store_port port = {0};
        ZSS_CHECK("bind ok", zslp_store_sqlite_bind(&port));

        /* A datadir that is actually a regular file makes "<dir>/node.db"
         * unopenable. */
        char f[] = "/tmp/zcl_zss_file_XXXXXX";
        int fd = mkstemp(f);
        if (fd >= 0) close(fd);

        void *db = (void *)0x1;
        ZSS_CHECK("open under file-path false",
                  !port.open(port.self, f, &db));
        ZSS_CHECK("open failure left db NULL", db == NULL);

        unlink(f);
    }

    /* ---- close tolerates NULL ---- */
    {
        struct zslp_store_port port = {0};
        ZSS_CHECK("bind ok", zslp_store_sqlite_bind(&port));
        port.close(port.self, NULL);   /* must not crash */
        ZSS_CHECK("close NULL no-op", true);
    }

    /* ---- bind rejects NULL out_port ---- */
    {
        ZSS_CHECK("bind rejects NULL out_port",
                  !zslp_store_sqlite_bind(NULL));
    }

    return failures;
}
