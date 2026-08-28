/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Initialize the deterministic codeindex SQLite schema. */

#include "codeindex_priv.h"

#include <sqlite3.h>
#include <stdio.h>

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

bool ci_store_ensure_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS files ("
        "id INTEGER PRIMARY KEY,path TEXT UNIQUE NOT NULL,"
        "\"group\" TEXT NOT NULL,purpose TEXT NOT NULL,"
        "content_sha3 BLOB NOT NULL,mtime INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS symbols ("
        "id INTEGER PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,"
        "def_path TEXT NOT NULL,def_line INTEGER NOT NULL,"
        "decl_path TEXT NOT NULL,decl_line INTEGER NOT NULL,"
        "signature TEXT NOT NULL,doc TEXT NOT NULL,guard TEXT NOT NULL,"
        "\"group\" TEXT NOT NULL,partial INTEGER NOT NULL,"
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
        "CREATE TABLE IF NOT EXISTS meta ("
        "k TEXT PRIMARY KEY,v BLOB NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);"
        "CREATE INDEX IF NOT EXISTS idx_refs_callee ON refs(callee_name);"
        "CREATE INDEX IF NOT EXISTS idx_refs_enclosing ON refs(enclosing);"
        "CREATE INDEX IF NOT EXISTS idx_files_group ON files(\"group\");"
        "CREATE INDEX IF NOT EXISTS idx_includes_dep ON includes(dep_path);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[codeindex] schema failed: %s\n",
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}
