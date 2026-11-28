/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_pool_kv -- implementation. See storage/shielded_pool_kv.h.
 * Raw sqlite3_step calls carry // raw-sql-ok:progress-kv-kernel-store, the
 * sanctioned hatch for the kernel store (same as nullifier_kv.c). */

#include "storage/shielded_pool_kv.h"

#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

#define SP_SUBSYS "shielded_pool_kv"

static bool pool_ironwood_column_exists(sqlite3 *db, bool *exists)
{
    *exists = false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(shielded_pool_totals)",
                           -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "table_info prepare failed: %s", sqlite3_errmsg(db));
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const unsigned char *name = sqlite3_column_text(s, 1);
        if (name && strcmp((const char *)name, "ironwood") == 0)
            *exists = true;
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "table_info step rc=%d", rc);
    return true;
}

bool shielded_pool_kv_ensure_schema(sqlite3 *db)
{
    if (!db)
        LOG_FAIL(SP_SUBSYS, "ensure_schema: NULL db");
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS shielded_pool_totals ("
        "  height INTEGER PRIMARY KEY,"
        "  sprout INTEGER NOT NULL,"
        "  sapling INTEGER NOT NULL,"
        "  ironwood INTEGER"
        ")", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN(SP_SUBSYS, "ensure_schema failed: %s",
                 err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        return false;
    }
    bool exists = false;
    if (!pool_ironwood_column_exists(db, &exists)) return false;
    if (!exists && sqlite3_exec(db,
            "ALTER TABLE shielded_pool_totals ADD COLUMN ironwood INTEGER",
            NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN(SP_SUBSYS, "ensure_schema Ironwood migration failed: %s",
                 err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool shielded_pool_kv_get(sqlite3 *db, int64_t height, int64_t *sprout_out,
                          int64_t *sapling_out, bool *found_out)
{
    if (found_out) *found_out = false;
    if (sprout_out) *sprout_out = 0;
    if (sapling_out) *sapling_out = 0;
    if (!db || height < 0 || !sprout_out || !sapling_out || !found_out)
        LOG_FAIL(SP_SUBSYS, "get: invalid args height=%lld",
                 (long long)height);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT sprout, sapling FROM shielded_pool_totals WHERE height=?",
            -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "get prepare failed: %s", sqlite3_errmsg(db));
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *sprout_out = sqlite3_column_int64(s, 0);
        *sapling_out = sqlite3_column_int64(s, 1);
        *found_out = true;
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "get step rc=%d height=%lld", rc,
                 (long long)height);
    return true;
}

static bool pool_insert(sqlite3 *db, int64_t height, int64_t sprout,
                        int64_t sapling)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO shielded_pool_totals(height, sprout, sapling) "
            "VALUES(?,?,?)", -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "put prepare failed: %s", sqlite3_errmsg(db));
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)sprout);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)sapling);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "put step rc=%d height=%lld: %s", rc,
                 (long long)height, sqlite3_errmsg(db));
    return true;
}

bool shielded_pool_kv_put(sqlite3 *db, int64_t height, int64_t sprout,
                          int64_t sapling)
{
    int64_t old_sprout = 0, old_sapling = 0;
    bool found = false;
    if (!shielded_pool_kv_get(db, height, &old_sprout, &old_sapling, &found))
        return false;
    if (!found)
        return pool_insert(db, height, sprout, sapling);
    if (old_sprout != sprout || old_sapling != sapling)
        LOG_FAIL(SP_SUBSYS,
                 "put conflict height=%lld stored sprout=%lld sapling=%lld "
                 "new sprout=%lld sapling=%lld",
                 (long long)height, (long long)old_sprout,
                 (long long)old_sapling, (long long)sprout,
                 (long long)sapling);
    return true;
}

bool shielded_pool_kv_get_ironwood(sqlite3 *db, int64_t height,
                                   int64_t *total_out, bool *known_out,
                                   bool *found_out)
{
    if (total_out) *total_out = 0;
    if (known_out) *known_out = false;
    if (found_out) *found_out = false;
    if (!db || height < 0 || !total_out || !known_out || !found_out)
        LOG_FAIL(SP_SUBSYS, "get_ironwood: invalid args height=%lld",
                 (long long)height);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ironwood FROM shielded_pool_totals WHERE height=?",
            -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "get_ironwood prepare failed: %s", sqlite3_errmsg(db));
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int type = sqlite3_column_type(s, 0);
        if (type == SQLITE_NULL) {
            *found_out = true;
        } else if (type == SQLITE_INTEGER) {
            *total_out = sqlite3_column_int64(s, 0);
            *known_out = true;
            *found_out = true;
        }
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "get_ironwood step rc=%d height=%lld", rc,
                 (long long)height);
    return true;
}

bool shielded_pool_kv_put_ironwood(sqlite3 *db, int64_t height, int64_t total)
{
    int64_t old_total = 0;
    bool known = false, found = false;
    if (!shielded_pool_kv_get_ironwood(db, height, &old_total, &known, &found))
        return false;
    if (!found)
        LOG_FAIL(SP_SUBSYS, "put_ironwood: missing parent row height=%lld",
                 (long long)height);
    if (known && old_total != total)
        LOG_FAIL(SP_SUBSYS,
                 "put_ironwood conflict height=%lld stored=%lld new=%lld",
                 (long long)height, (long long)old_total, (long long)total);
    if (known) return true;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE shielded_pool_totals SET ironwood=? WHERE height=?",
            -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "put_ironwood prepare failed: %s", sqlite3_errmsg(db));
    sqlite3_bind_int64(s, 1, (sqlite3_int64)total);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)height);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "put_ironwood step rc=%d height=%lld: %s", rc,
                 (long long)height, sqlite3_errmsg(db));
    if (sqlite3_changes(db) != 1)
        LOG_FAIL(SP_SUBSYS, "put_ironwood affected row count is not one: height=%lld",
                 (long long)height);
    return true;
}

bool shielded_pool_kv_max_height(sqlite3 *db, int64_t *height_out,
                                 bool *found_out)
{
    if (height_out) *height_out = -1;
    if (found_out) *found_out = false;
    if (!db || !height_out || !found_out)
        LOG_FAIL(SP_SUBSYS, "max_height: invalid args");
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MAX(height) FROM shielded_pool_totals",
                           -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "max_height prepare failed: %s",
                 sqlite3_errmsg(db));
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW && sqlite3_column_type(s, 0) != SQLITE_NULL) {
        *height_out = sqlite3_column_int64(s, 0);
        *found_out = true;
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "max_height step rc=%d", rc);
    return true;
}

bool shielded_pool_kv_delete_range(sqlite3 *db, int64_t from, int64_t to)
{
    if (!db || from < 0 || to < from)
        LOG_FAIL(SP_SUBSYS, "delete_range: invalid args from=%lld to=%lld",
                 (long long)from, (long long)to);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM shielded_pool_totals WHERE height>=? AND height<=?",
            -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(SP_SUBSYS, "delete_range prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_int64(s, 1, (sqlite3_int64)from);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)to);
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL(SP_SUBSYS, "delete_range step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
    return true;
}

bool shielded_pool_kv_reset_in_tx(sqlite3 *db)
{
    if (!db)
        LOG_FAIL(SP_SUBSYS, "reset: NULL db");
    if (sqlite3_get_autocommit(db) != 0)
        LOG_FAIL(SP_SUBSYS, "reset requires caller transaction");
    if (!shielded_pool_kv_ensure_schema(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "DELETE FROM shielded_pool_totals", NULL, NULL, &err)
        != SQLITE_OK) {
        LOG_WARN(SP_SUBSYS, "reset delete failed: %s",
                 err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        return false;
    }
    return true;
}
