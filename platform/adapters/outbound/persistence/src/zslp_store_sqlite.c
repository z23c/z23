/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * zslp_store_sqlite — sqlite implementation of zslp_store_port.
 *
 * The open() body below is the exact connection-open path that used to
 * live inline in contexts/market/services/src/zslp_service.c (zslp_service_open_db's
 * "open from datadir" branch): sqlite3_open of "<datadir>/node.db", a 5 s
 * busy timeout, and the zslp_balances CREATE TABLE IF NOT EXISTS DDL. The
 * SQL text, the path construction, and the close-on-failure cleanup are
 * preserved verbatim so the resulting on-disk store is bit-for-bit
 * identical.
 */

#include "adapters/outbound/persistence/zslp_store_sqlite.h"

#include <sqlite3.h>

#include <stddef.h>
#include <stdio.h>

/* Open "<datadir>/node.db" as a fresh caller-owned connection. Mirrors the
 * original inline open path exactly. */
static bool zss_open(void *self, const char *datadir, void **db_out)
{
    (void)self;
    sqlite3 *db = NULL;
    char db_path[1024];

    if (!db_out)
        return false;
    *db_out = NULL;
    if (!datadir)
        return false;

    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    sqlite3_busy_timeout(db, 5000);
    char *exec_err = NULL;
    if (sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS zslp_balances ("
        "token_id TEXT NOT NULL,"
        "address TEXT NOT NULL,"
        "balance INTEGER NOT NULL DEFAULT 0,"
        "PRIMARY KEY (token_id, address))",
        NULL, NULL, &exec_err) != SQLITE_OK) {
        sqlite3_free(exec_err);
        sqlite3_close(db);
        *db_out = NULL;
        return false;
    }
    *db_out = db;
    return true;
}

/* Close a connection returned by zss_open(). NULL is a no-op. */
static void zss_close(void *self, void *db)
{
    (void)self;
    if (db)
        sqlite3_close((sqlite3 *)db);
}

bool zslp_store_sqlite_bind(struct zslp_store_port *out_port)
{
    if (!out_port)
        return false;
    *out_port = (struct zslp_store_port){
        .self  = NULL,
        .open  = zss_open,
        .close = zss_close,
    };
    return true;
}
