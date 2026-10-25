/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sqlq — read-only SQL query CLI over any sqlite database file.
 *
 * The operator/diagnosis story: python is banned in this repo and the
 * sqlite3 CLI is not installed on the host, so ad-hoc inspection of the
 * node's sqlite stores (the `consensus.db` kernel store's stage cursors —
 * `progress.kv` on a pre-flip datadir — node.db tables, or a copied fixture
 * datadir) from a shell needs a vendored-sqlite C tool (same precedent as
 * tools/p2_invariant_check.c). `core storage query` covers node.db but
 * cannot reach the kernel store or a copied fixture datadir.
 *
 *   build/bin/sqlq <db-path> <SELECT ...>
 *
 * Opens SQLITE_OPEN_READONLY (never creates, never writes, WAL-reader
 * safe against a live node). Prints rows tab-separated, NULL as "NULL",
 * BLOBs as lowercase hex. Exit 0 on success, 1 on usage/open/SQL error.
 */

#include "multicall.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

int sqlq_main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: sqlq <db-path> <SELECT ...>\n");
        return 1;
    }
    const char *sql = argv[2];
    if (strncasecmp(sql, "SELECT", 6) != 0 &&
        strncasecmp(sql, "PRAGMA", 6) != 0) {
        fprintf(stderr, "sqlq: read-only — SELECT/PRAGMA only\n");
        return 1;
    }

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READONLY, NULL) !=
        SQLITE_OK) {
        fprintf(stderr, "sqlq: open failed: %s\n",
                db ? sqlite3_errmsg(db) : "out of memory");
        sqlite3_close(db);
        return 1;
    }
    sqlite3_busy_timeout(db, 2000);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "sqlq: prepare failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-diagnostic-cli
        int n = sqlite3_column_count(st);
        for (int i = 0; i < n; i++) {
            if (i) fputc('\t', stdout);
            switch (sqlite3_column_type(st, i)) {
            case SQLITE_NULL:
                fputs("NULL", stdout);
                break;
            case SQLITE_BLOB: {
                const unsigned char *b = sqlite3_column_blob(st, i);
                int len = sqlite3_column_bytes(st, i);
                for (int j = 0; j < len; j++) printf("%02x", b[j]);
                break;
            }
            default:
                fputs((const char *)sqlite3_column_text(st, i), stdout);
            }
        }
        fputc('\n', stdout);
    }
    int ok = (rc == SQLITE_DONE);
    if (!ok)
        fprintf(stderr, "sqlq: step failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok ? 0 : 1;
}
