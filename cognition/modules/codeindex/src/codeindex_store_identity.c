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
