/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Initialize the deterministic codeindex SQLite schema. */

#include "codeindex_priv.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

bool ci_store_apply_pragmas(sqlite3 *db)
{
    static const char *const pragmas[] = {
        "PRAGMA journal_mode=DELETE",
        "PRAGMA synchronous=FULL",
        "PRAGMA busy_timeout=5000",
        NULL,
    };
    for (size_t i = 0; pragmas[i]; i++) {
        char *err = NULL;
        if (sqlite3_exec(db, pragmas[i], NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "[codeindex] pragma failed (%s): %s\n",
                    pragmas[i], err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
    }
    return true;
}

static bool ci_index_list(sqlite3 *db, const char *table, const char *wanted)
{
    sqlite3_stmt *st = NULL; char sql[128];
    int n = snprintf(sql, sizeof(sql), "PRAGMA index_list('%s')", table);
    if (n < 0 || (size_t)n >= sizeof(sql) || sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return false;
    bool found = false, ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (!name) { ok = false; break; }
        if (strcmp((const char *)name, wanted) == 0) {
            if (found || sqlite3_column_int(st, 2) != 0 ||
                sqlite3_column_int(st, 4) != 0) { ok = false; break; }
            found = true;
        }
    }
    if (rc != SQLITE_DONE) ok = false;
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok && found;
}

static bool ci_index_columns(sqlite3 *db, const char *wanted,
                                 const char *const *names, size_t expected)
{
    sqlite3_stmt *st = NULL; char sql[128];
    int n = snprintf(sql, sizeof(sql), "PRAGMA index_xinfo('%s')", wanted);
    if (n < 0 || (size_t)n >= sizeof(sql) || sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return false;
    size_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        if (!sqlite3_column_int(st, 5)) continue;
        const unsigned char *name = sqlite3_column_text(st, 2);
        const unsigned char *collation = sqlite3_column_text(st, 4);
        if (count >= expected || !name || !collation ||
            strcmp((const char *)name, names[count]) != 0 ||
            strcmp((const char *)collation, "BINARY") != 0 ||
            sqlite3_column_int(st, 3) != 0) { ok = false; break; }
        count++;
    }
    if (rc != SQLITE_DONE || count != expected) ok = false;
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok;
}

static bool ci_ensure_index(sqlite3 *db, const char *table, const char *name,
    const char *const *columns, size_t count, const char *create, const char *drop)
{
    if (!db || sqlite3_exec(db, create, NULL, NULL, NULL) != SQLITE_OK ||
        !ci_index_list(db, table, name) || !ci_index_columns(db, name, columns, count)) {
        fprintf(stderr, "[codeindex] index %s creation or verification failed\n", name);
        return false;
    }
    if (sqlite3_exec(db, drop, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "[codeindex] legacy index removal failed for %s\n", name);
        return false;
    }
    return true;
}

bool ci_store_ensure_ordered_indexes(sqlite3 *db)
{
    static const char *const file[] = {"ref_file", "callee_name", "ref_line", "enclosing"};
    static const char *const enclosing[] = {"enclosing", "ref_file", "ref_line"};
    static const char *const symbol[] = {"name", "def_path", "def_line"};
    return ci_ensure_index(db, "refs", "idx_refs_file_ordered", file, 4,
        "CREATE INDEX IF NOT EXISTS idx_refs_file_ordered ON refs(ref_file,callee_name COLLATE BINARY,ref_line,enclosing COLLATE BINARY)",
        "DROP INDEX IF EXISTS idx_refs_file") &&
        ci_ensure_index(db, "refs", "idx_refs_enclosing_ordered", enclosing, 3,
        "CREATE INDEX IF NOT EXISTS idx_refs_enclosing_ordered ON refs(enclosing COLLATE BINARY,ref_file COLLATE BINARY,ref_line)",
        "DROP INDEX IF EXISTS idx_refs_enclosing") &&
        ci_ensure_index(db, "symbols", "idx_symbols_name_ordered", symbol, 3,
        "CREATE INDEX IF NOT EXISTS idx_symbols_name_ordered ON symbols(name COLLATE BINARY,def_path COLLATE BINARY,def_line)",
        "DROP INDEX IF EXISTS idx_symbols_name");
}

bool ci_store_ensure_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS files ("
        "id INTEGER PRIMARY KEY,path TEXT UNIQUE NOT NULL,"
        "\"group\" TEXT NOT NULL,purpose TEXT NOT NULL,"
        "content_sha3 BLOB NOT NULL,mtime INTEGER NOT NULL,"
        "line_count INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS symbols ("
        "id INTEGER PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,"
        "def_path TEXT NOT NULL,def_line INTEGER NOT NULL,"
        "decl_path TEXT NOT NULL,decl_line INTEGER NOT NULL,"
        "signature TEXT NOT NULL,doc TEXT NOT NULL,guard TEXT NOT NULL,"
        "\"group\" TEXT NOT NULL,partial INTEGER NOT NULL,"
        "end_line INTEGER NOT NULL DEFAULT 0,"
        "row_sha3 BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS includes ("
        "file_id INTEGER NOT NULL,dep_path TEXT NOT NULL,"
        "UNIQUE(file_id,dep_path));"
        "CREATE TABLE IF NOT EXISTS refs ("
        "callee_name TEXT NOT NULL,ref_file TEXT NOT NULL,"
        "ref_line INTEGER NOT NULL,enclosing TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS groups ("
        "path TEXT PRIMARY KEY,kind TEXT NOT NULL,parent TEXT NOT NULL,"
        "purpose TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS scan_shards ("
        "path TEXT PRIMARY KEY,digest BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS docs ("
        "path TEXT PRIMARY KEY,title TEXT NOT NULL,summary TEXT NOT NULL,"
        "headings TEXT NOT NULL,line_count INTEGER NOT NULL,"
        "content_sha3 BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS pages ("
        "directory TEXT NOT NULL,tree_oid TEXT NOT NULL,source_commit TEXT NOT NULL,"
        "body TEXT NOT NULL,artifact_root BLOB NOT NULL,"
        "PRIMARY KEY(directory,tree_oid,source_commit,artifact_root));"
        "CREATE TABLE IF NOT EXISTS pages_state (id INTEGER PRIMARY KEY CHECK(id=1),"
        "state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2));"
        "INSERT OR IGNORE INTO pages_state(id,state) VALUES(1,0);"
        "CREATE TABLE IF NOT EXISTS meta ("
        "k TEXT PRIMARY KEY,v BLOB NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_refs_callee ON refs(callee_name);"
        "CREATE INDEX IF NOT EXISTS idx_files_group ON files(\"group\");"
        /* The capability query asks "which symbols does this FILE own" once
         * per ranked candidate. Without these two it is a full 69k-row scan
         * each time, which turns a reflexive lookup into something an agent
         * learns not to run. */
        "CREATE INDEX IF NOT EXISTS idx_symbols_def_path ON symbols(def_path);"
        "CREATE INDEX IF NOT EXISTS idx_symbols_decl_path ON symbols(decl_path);"
        "CREATE INDEX IF NOT EXISTS idx_includes_dep ON includes(dep_path);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[codeindex] schema failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return ci_store_ensure_ordered_indexes(db);
}
