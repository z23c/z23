/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Content-addressed per-file scan shards for incremental codeindex generations. */

#include "codeindex_priv.h"

#include "base/serialize_le.h"
#include "util/log_macros.h"

#include <sqlite3.h>

#include <string.h>

static void shard_text(struct sha3_256_ctx *sha, const unsigned char *text)
{
    const unsigned char empty = 0;
    if (!text) {
        sha3_256_write(sha, &empty, 1);
        return;
    }
    sha3_256_write(sha, text, strlen((const char *)text) + 1);
}

static bool scan_shard_digest(struct ci_store *store, const char *path,
                              uint8_t out[32])
{
    sqlite3 *db = ci_store_db(store);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.codeindex.scan_shard.v1";
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    shard_text(&sha, (const unsigned char *)path);

    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT \"group\",purpose,content_sha3 FROM files WHERE path=?",
            -1, &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) == SQLITE_OK;
    int rc = ok ? sqlite3_step(statement) : SQLITE_ERROR; // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW && sqlite3_column_type(statement, 0) == SQLITE_TEXT &&
        sqlite3_column_type(statement, 1) == SQLITE_TEXT &&
        sqlite3_column_type(statement, 2) == SQLITE_BLOB &&
        sqlite3_column_bytes(statement, 2) == 32) {
        shard_text(&sha, sqlite3_column_text(statement, 0));
        shard_text(&sha, sqlite3_column_text(statement, 1));
        sha3_256_write(&sha, sqlite3_column_blob(statement, 2), 32);
    } else {
        ok = false;
    }
    sqlite3_finalize(statement);

    static const char symbol_sql[] =
        "SELECT " CI_SYM_COLS " FROM symbols WHERE def_path=?1 OR decl_path=?1 ORDER BY "
        "name COLLATE BINARY,kind COLLATE BINARY,def_path COLLATE BINARY,def_line,"
        "decl_path COLLATE BINARY,decl_line,signature COLLATE BINARY,"
        "doc COLLATE BINARY,guard COLLATE BINARY,\"group\" COLLATE BINARY,"
        "partial,row_sha3";
    if (ok && sqlite3_prepare_v2(db, symbol_sql, -1, &statement, NULL) == SQLITE_OK) {
        ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) == SQLITE_OK;
        while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
            struct ci_symbol symbol;
            if (!ci_store_fill_symbol(statement, &symbol) ||
                sqlite3_column_type(statement, 11) != SQLITE_BLOB ||
                sqlite3_column_bytes(statement, 11) != 32) {
                ok = false;
                break;
            }
            sha3_256_write(&sha, sqlite3_column_blob(statement, 11), 32);
        }
        if (ok && rc != SQLITE_DONE) ok = false;
        sqlite3_finalize(statement);
    } else if (ok) {
        ok = false;
    }

    static const char ref_sql[] =
        "SELECT callee_name,ref_line,enclosing FROM refs WHERE ref_file=? ORDER BY "
        "callee_name COLLATE BINARY,ref_line,enclosing COLLATE BINARY";
    if (ok && sqlite3_prepare_v2(db, ref_sql, -1, &statement, NULL) == SQLITE_OK) {
        ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) == SQLITE_OK;
        while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
            sqlite3_int64 ref_line = sqlite3_column_int64(statement, 1);
            if (sqlite3_column_type(statement, 0) != SQLITE_TEXT ||
                sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
                ref_line < 0 || ref_line > INT32_MAX ||
                sqlite3_column_type(statement, 2) != SQLITE_TEXT) {
                ok = false;
                break;
            }
            shard_text(&sha, sqlite3_column_text(statement, 0));
            uint8_t line[4];
            zcl_write_i32_le(line, (int32_t)ref_line);
            sha3_256_write(&sha, line, sizeof(line));
            shard_text(&sha, sqlite3_column_text(statement, 2));
        }
        if (ok && rc != SQLITE_DONE) ok = false;
        sqlite3_finalize(statement);
    } else if (ok) {
        ok = false;
    }
    if (ok) sha3_256_finalize(&sha, out);
    return ok;
}

bool ci_store_scan_shard_refresh(struct ci_store *store, const char *path)
{
    uint8_t digest[32];
    if (!store || !path || !scan_shard_digest(store, path, digest))
        LOG_FAIL("codeindex", "derive scan shard for %s", path ? path : "(null)");
    sqlite3_stmt *statement = NULL;
    sqlite3 *db = ci_store_db(store);
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO scan_shards(path,digest) VALUES(?,?)",
            -1, &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_blob(statement, 2, digest, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE; // raw-sql-ok:codeindex-derived
    sqlite3_finalize(statement);
    return ok;
}

bool ci_store_scan_shards_are_valid(struct ci_store *store, bool *valid)
{
    if (valid) *valid = false;
    if (!store || !valid) LOG_FAIL("codeindex", "invalid scan shard verifier");
    ci_store_lock(store);
    sqlite3 *db = ci_store_db(store);
    sqlite3_stmt *statement = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT path,digest FROM scan_shards ORDER BY path", -1,
        &statement, NULL) == SQLITE_OK;
    int rows = 0, rc = SQLITE_DONE;
    while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        const char *path = (const char *)sqlite3_column_text(statement, 0);
        const void *stored = sqlite3_column_blob(statement, 1);
        uint8_t actual[32];
        if (!path || !stored || sqlite3_column_bytes(statement, 1) != 32 ||
            !scan_shard_digest(store, path, actual) ||
            memcmp(stored, actual, 32) != 0) {
            ok = false;
            break;
        }
        rows++;
    }
    if (ok && rc != SQLITE_DONE) ok = false;
    sqlite3_finalize(statement);
    if (ok && sqlite3_prepare_v2(db,
            "SELECT count(*) FROM files", -1, &statement, NULL) == SQLITE_OK) {
        rc = sqlite3_step(statement); // raw-sql-ok:codeindex-derived
        ok = rc == SQLITE_ROW && sqlite3_column_int(statement, 0) == rows;
        sqlite3_finalize(statement);
    } else if (ok) {
        ok = false;
    }
    *valid = ok;
    ci_store_unlock(store);
    return true;
}
