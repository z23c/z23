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

static void shard_i32(struct sha3_256_ctx *sha, int value)
{
    unsigned char encoded[4];
    zcl_write_i32_le(encoded, value);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

bool ci_scan_shard_writer_close(struct ci_scan_shard_writer *writer)
{
    if (!writer) return false;
    int file_rc = writer->file ? sqlite3_finalize(writer->file) : SQLITE_OK;
    int symbol_rc = writer->symbols ? sqlite3_finalize(writer->symbols) : SQLITE_OK;
    int ref_rc = writer->refs ? sqlite3_finalize(writer->refs) : SQLITE_OK;
    int insert_rc = writer->insert ? sqlite3_finalize(writer->insert) : SQLITE_OK;
    memset(writer, 0, sizeof(*writer));
    return file_rc == SQLITE_OK && symbol_rc == SQLITE_OK &&
           ref_rc == SQLITE_OK && insert_rc == SQLITE_OK;
}

bool ci_scan_shard_writer_open(struct ci_scan_shard_writer *writer,
                               struct ci_store *store, bool writing)
{
    if (!writer || !store) return false;
    memset(writer, 0, sizeof(*writer));
    sqlite3 *db = ci_store_db(store);
    static const char symbol_sql[] =
        "SELECT " CI_SYM_COLS " FROM symbols WHERE def_path=?1 OR decl_path=?1 ORDER BY "
        "name COLLATE BINARY,kind COLLATE BINARY,def_path COLLATE BINARY,def_line,"
        "decl_path COLLATE BINARY,decl_line,signature COLLATE BINARY,"
        "doc COLLATE BINARY,guard COLLATE BINARY,\"group\" COLLATE BINARY,"
        "partial,row_sha3";
    static const char ref_sql[] =
        "SELECT callee_name,ref_line,enclosing FROM refs WHERE ref_file=? ORDER BY "
        "callee_name COLLATE BINARY,ref_line,enclosing COLLATE BINARY";
    bool ok = sqlite3_prepare_v2(db,
        "SELECT \"group\",purpose,content_sha3,line_count FROM files WHERE path=?",
        -1, &writer->file, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db, symbol_sql, -1, &writer->symbols, NULL) ==
            SQLITE_OK &&
        sqlite3_prepare_v2(db, ref_sql, -1, &writer->refs, NULL) ==
            SQLITE_OK &&
        (!writing || sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO scan_shards(path,digest) VALUES(?,?)",
            -1, &writer->insert, NULL) == SQLITE_OK);
    if (!ok) (void)ci_scan_shard_writer_close(writer);
    return ok;
}

static bool shard_statement_reset(sqlite3_stmt *statement)
{
    int reset_rc = sqlite3_reset(statement);
    int clear_rc = sqlite3_clear_bindings(statement);
    return reset_rc == SQLITE_OK && clear_rc == SQLITE_OK;
}

static bool shard_digest_file(struct ci_scan_shard_writer *writer,
                              const char *path, struct sha3_256_ctx *sha)
{
    sqlite3_stmt *statement = writer->file;
    bool ok = sqlite3_bind_text(statement, 1, path, -1,
                                SQLITE_TRANSIENT) == SQLITE_OK;
    int rc = ok ? sqlite3_step(statement) : SQLITE_ERROR; // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW && sqlite3_column_type(statement, 0) == SQLITE_TEXT &&
        sqlite3_column_type(statement, 1) == SQLITE_TEXT &&
        sqlite3_column_type(statement, 2) == SQLITE_BLOB &&
        sqlite3_column_bytes(statement, 2) == 32 &&
        sqlite3_column_type(statement, 3) == SQLITE_INTEGER) {
        shard_text(sha, sqlite3_column_text(statement, 0));
        shard_text(sha, sqlite3_column_text(statement, 1));
        sha3_256_write(sha, sqlite3_column_blob(statement, 2), 32);
        shard_i32(sha, sqlite3_column_int(statement, 3));
    } else {
        ok = false;
    }
    return shard_statement_reset(statement) && ok;
}

static bool shard_digest_symbols(struct ci_scan_shard_writer *writer,
                                 const char *path, struct sha3_256_ctx *sha)
{
    sqlite3_stmt *statement = writer->symbols;
    bool ok = sqlite3_bind_text(statement, 1, path, -1,
                                SQLITE_TRANSIENT) == SQLITE_OK;
    int rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        struct ci_symbol symbol;
        if (!ci_store_fill_symbol(statement, &symbol) ||
            sqlite3_column_type(statement, 12) != SQLITE_BLOB ||
            sqlite3_column_bytes(statement, 12) != 32) {
            ok = false;
            break;
        }
        sha3_256_write(sha, sqlite3_column_blob(statement, 12), 32);
    }
    if (rc != SQLITE_DONE) ok = false;
    return shard_statement_reset(statement) && ok;
}

static bool shard_digest_refs(struct ci_scan_shard_writer *writer,
                              const char *path, struct sha3_256_ctx *sha)
{
    sqlite3_stmt *statement = writer->refs;
    bool ok = sqlite3_bind_text(statement, 1, path, -1,
                                SQLITE_TRANSIENT) == SQLITE_OK;
    int rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        sqlite3_int64 ref_line = sqlite3_column_int64(statement, 1);
        if (sqlite3_column_type(statement, 0) != SQLITE_TEXT ||
            sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            ref_line < 0 || ref_line > INT32_MAX ||
            sqlite3_column_type(statement, 2) != SQLITE_TEXT) {
            ok = false;
            break;
        }
        shard_text(sha, sqlite3_column_text(statement, 0));
        uint8_t line[4];
        zcl_write_i32_le(line, (int32_t)ref_line);
        sha3_256_write(sha, line, sizeof(line));
        shard_text(sha, sqlite3_column_text(statement, 2));
    }
    if (rc != SQLITE_DONE) ok = false;
    return shard_statement_reset(statement) && ok;
}

static bool scan_shard_digest(struct ci_scan_shard_writer *writer,
                              const char *path, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.codeindex.scan_shard.v1";
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    shard_text(&sha, (const unsigned char *)path);
    if (!shard_digest_file(writer, path, &sha) ||
        !shard_digest_symbols(writer, path, &sha) ||
        !shard_digest_refs(writer, path, &sha)) return false;
    sha3_256_finalize(&sha, out);
    return true;
}

bool ci_scan_shard_writer_refresh(struct ci_scan_shard_writer *writer,
                                  const char *path)
{
    uint8_t digest[32];
    if (!writer || !writer->insert || !path ||
        !scan_shard_digest(writer, path, digest)) return false;
    sqlite3_stmt *statement = writer->insert;
    bool ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_blob(statement, 2, digest, 32, SQLITE_TRANSIENT) == SQLITE_OK;
    int rc = ok ? sqlite3_step(statement) : SQLITE_ERROR; // raw-sql-ok:codeindex-derived
    return shard_statement_reset(statement) && rc == SQLITE_DONE;
}

bool ci_store_scan_shard_refresh(struct ci_store *store, const char *path)
{
    struct ci_scan_shard_writer writer;
    if (!ci_scan_shard_writer_open(&writer, store, true))
        LOG_FAIL("codeindex", "prepare scan shard for %s", path ? path : "(null)");
    bool ok = ci_scan_shard_writer_refresh(&writer, path);
    if (!ci_scan_shard_writer_close(&writer)) ok = false;
    if (!ok) LOG_FAIL("codeindex", "derive scan shard for %s", path ? path : "(null)");
    return true;
}

static bool scan_shard_rows_match(sqlite3 *db,
                                  struct ci_scan_shard_writer *writer,
                                  int *rows)
{
    sqlite3_stmt *statement = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT path,digest FROM scan_shards ORDER BY path", -1,
        &statement, NULL) == SQLITE_OK;
    int rc = SQLITE_DONE;
    while (ok && (rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        const char *path = (const char *)sqlite3_column_text(statement, 0);
        const void *stored = sqlite3_column_blob(statement, 1);
        uint8_t actual[32];
        if (!path || !stored || sqlite3_column_bytes(statement, 1) != 32 ||
            !scan_shard_digest(writer, path, actual) ||
            memcmp(stored, actual, 32) != 0) {
            ok = false;
            break;
        }
        (*rows)++;
    }
    if (ok && rc != SQLITE_DONE) ok = false;
    sqlite3_finalize(statement);
    return ok;
}

bool ci_store_scan_shards_are_valid(struct ci_store *store, bool *valid)
{
    if (valid) *valid = false;
    if (!store || !valid) LOG_FAIL("codeindex", "invalid scan shard verifier");
    ci_store_lock(store);
    sqlite3 *db = ci_store_db(store);
    struct ci_scan_shard_writer writer;
    if (!ci_scan_shard_writer_open(&writer, store, false)) {
        ci_store_unlock(store);
        return true;
    }
    int rows = 0;
    bool ok = scan_shard_rows_match(db, &writer, &rows);
    sqlite3_stmt *statement = NULL;
    if (ok && sqlite3_prepare_v2(db,
            "SELECT count(*) FROM files", -1, &statement, NULL) == SQLITE_OK) {
        int rc = sqlite3_step(statement); // raw-sql-ok:codeindex-derived
        ok = rc == SQLITE_ROW && sqlite3_column_int(statement, 0) == rows;
        sqlite3_finalize(statement);
    } else if (ok) {
        ok = false;
    }
    if (!ci_scan_shard_writer_close(&writer)) ok = false;
    *valid = ok;
    ci_store_unlock(store);
    return true;
}
