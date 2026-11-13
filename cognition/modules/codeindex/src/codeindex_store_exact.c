/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact-name symbol enumeration for the derived code index. */
#include "codeindex_store_internal.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>

static enum codeindex_exact_status ci_exact_checked_rows(
    sqlite3_stmt *stmt, struct ci_symbol *out, int cap, int *count)
{
    int n = 0;
    for (;;) {
        int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
        if (rc == SQLITE_DONE) {
            *count = n;
            return CODEINDEX_EXACT_COMPLETE;
        }
        if (rc != SQLITE_ROW) return CODEINDEX_EXACT_ERROR;
        struct ci_symbol extra;
        if (!ci_store_fill_symbol(stmt, n < cap ? &out[n] : &extra))
            return CODEINDEX_EXACT_CORRUPT;
        if (n == cap) return CODEINDEX_EXACT_TRUNCATED;
        n++;
    }
}

enum codeindex_exact_status ci_store_find_symbols_exact_checked(
    struct ci_store *s, const char *name, struct ci_symbol *out, int cap,
    int *count)
{
    if (count) *count = 0;
    if (!s || !name || !out || cap <= 0 || !count)
        return CODEINDEX_EXACT_ERROR;
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    enum codeindex_exact_status status = CODEINDEX_EXACT_ERROR;
    int n = 0;
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS " FROM symbols WHERE name=?"
        " ORDER BY (def_path='') ASC, def_path ASC, def_line ASC",
        -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT) == SQLITE_OK)
        status = ci_exact_checked_rows(stmt, out, cap, &n);
    if (sqlite3_finalize(stmt) != SQLITE_OK) status = CODEINDEX_EXACT_ERROR;
    pthread_mutex_unlock(&s->lock);
    if (status == CODEINDEX_EXACT_COMPLETE) *count = n;
    return status;
}
