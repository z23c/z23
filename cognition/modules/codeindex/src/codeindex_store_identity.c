/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_store_identity — exact stable-identity reads from the derived
 * code index. Kept separate so identity joins do not regrow the legacy store
 * translation unit beyond its shrinking file-size ceiling. */

#include "codeindex_priv.h"

#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

bool ci_store_symbol_by_name_path(struct ci_store *s, const char *name,
                                  const char *def_path,
                                  struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!s || !name || !def_path || !out)
        LOG_FAIL("codeindex", "null arg to symbol_by_name_path");
    ci_store_lock(s);
    sqlite3 *db = ci_store_db(s);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT " CI_SYM_COLS " FROM symbols"
        " WHERE name=? AND def_path=? ORDER BY def_line ASC LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK) {
        ci_store_unlock(s);
        LOG_FAIL("codeindex", "prepare symbol_by_name_path");
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, def_path, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        if (ci_store_fill_symbol(stmt, out) && found)
            *found = true;
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    ci_store_unlock(s);
    if (!ok) LOG_FAIL("codeindex", "step symbol_by_name_path");
    return true;
}

static int refs_by_name_file(struct ci_store *s, bool by_callee,
                             const char *name, const char *ref_file,
                             struct ci_ref *out, int cap)
{
    if (!s || !name || !ref_file || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to refs_by_name_file");
    const char *sql = by_callee
        ? "SELECT callee_name,ref_file,ref_line,enclosing FROM refs"
          " WHERE callee_name=? AND ref_file=?"
          " ORDER BY ref_file ASC,ref_line ASC"
        : "SELECT callee_name,ref_file,ref_line,enclosing FROM refs"
          " WHERE enclosing=? AND ref_file=?"
          " ORDER BY ref_file ASC,ref_line ASC";
    ci_store_lock(s);
    sqlite3 *db = ci_store_db(s);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        ci_store_unlock(s);
        LOG_ERR("codeindex", "prepare refs_by_name_file");
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ref_file, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].callee, sizeof(out[n].callee),
               (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].ref_file, sizeof(out[n].ref_file),
               (const char *)sqlite3_column_text(stmt, 1));
        out[n].ref_line = sqlite3_column_int(stmt, 2);
        ci_cpy(out[n].enclosing, sizeof(out[n].enclosing),
               (const char *)sqlite3_column_text(stmt, 3));
        n++;
    }
    sqlite3_finalize(stmt);
    ci_store_unlock(s);
    return n;
}

int ci_store_refs_by_callee_file(struct ci_store *s, const char *callee,
                                 const char *ref_file,
                                 struct ci_ref *out, int cap)
{
    return refs_by_name_file(s, true, callee, ref_file, out, cap);
}

int ci_store_refs_by_enclosing_file(struct ci_store *s,
                                    const char *enclosing,
                                    const char *ref_file,
                                    struct ci_ref *out, int cap)
{
    return refs_by_name_file(s, false, enclosing, ref_file, out, cap);
}
