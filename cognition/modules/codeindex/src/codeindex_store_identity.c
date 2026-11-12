/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact stable-identity reads from the derived code index. */
#include "codeindex_store_internal.h"
#include "util/log_macros.h"
#include <sqlite3.h>

static bool ci_symbol_identity_prepare(struct ci_store *s, sqlite3_stmt **slot, bool scoped)
{
    const char *sql = scoped
        ? "SELECT " CI_SYM_COLS " FROM symbols WHERE name=? AND def_path=? ORDER BY def_line ASC LIMIT 1"
        : "SELECT " CI_SYM_COLS " FROM symbols WHERE name=? ORDER BY (def_path='') ASC, def_line ASC, def_path ASC LIMIT 1";
    return *slot || sqlite3_prepare_v2(s->db, sql, -1, slot, NULL) == SQLITE_OK;
}

static bool ci_symbol_identity_bind(sqlite3_stmt *stmt, const char *name, const char *path, bool scoped)
{
    if (sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK) return false;
    return !scoped || sqlite3_bind_text(stmt, 2, path, -1, SQLITE_TRANSIENT) == SQLITE_OK;
}

static bool ci_symbol_identity_read(struct ci_store *s, const char *name, const char *path,
                                    bool scoped, struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!s || !name || (scoped && !path) || !out)
        LOG_FAIL("codeindex", "null arg to symbol identity read");
    ci_store_lock(s);
    sqlite3_stmt **slot = scoped ? &s->symbol_by_name_path_stmt : &s->symbol_by_name_stmt;
    if (!ci_symbol_identity_prepare(s, slot, scoped)) {
        ci_store_unlock(s);
        LOG_FAIL("codeindex", "prepare symbol identity read");
    }
    sqlite3_stmt *stmt = *slot;
    if (!ci_symbol_identity_bind(stmt, name, path, scoped)) {
        (void)ci_store_read_finish(slot, false);
        ci_store_unlock(s);
        LOG_FAIL("codeindex", "bind symbol identity read");
    }
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    bool row_ok = rc == SQLITE_ROW && ci_store_fill_symbol(stmt, out);
    bool complete = rc == SQLITE_ROW || rc == SQLITE_DONE;
    int finish_rc = ci_store_read_finish(slot, complete);
    ci_store_unlock(s);
    if (!complete || finish_rc != SQLITE_OK)
        LOG_FAIL("codeindex", "read symbol identity failed rc=%d finish=%d", rc, finish_rc);
    if (found) *found = row_ok;
    return true;
}

bool ci_store_symbol_by_name(struct ci_store *s, const char *name,
                             struct ci_symbol *out, bool *found)
{ return ci_symbol_identity_read(s, name, NULL, false, out, found); }

bool ci_store_symbol_by_name_path(struct ci_store *s, const char *name, const char *def_path,
                                  struct ci_symbol *out, bool *found)
{ return ci_symbol_identity_read(s, name, def_path, true, out, found); }
