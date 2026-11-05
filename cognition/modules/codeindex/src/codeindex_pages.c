/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Read unsigned page hints from the sealed codeindex generation. */
#include "codeindex/codeindex_pages.h"
#include "codeindex_priv.h"
#include "base/safe_alloc.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

static bool page_text(sqlite3_stmt *s, int col, char *out, size_t cap)
{
    if (sqlite3_column_type(s, col) != SQLITE_TEXT) return false;
    int n = sqlite3_column_bytes(s, col);
    const unsigned char *text = sqlite3_column_text(s, col);
    if (!text || n <= 0 || (size_t)n >= cap || memchr(text, 0, (size_t)n)) return false;
    memcpy(out, text, (size_t)n);
    out[n] = '\0';
    return true;
}

static bool page_row(sqlite3_stmt *s, struct ci_page *row)
{
    if (!page_text(s, 0, row->directory, sizeof(row->directory)) ||
        !page_text(s, 1, row->tree_oid, sizeof(row->tree_oid)) ||
        !page_text(s, 2, row->source_commit, sizeof(row->source_commit)) ||
        !page_text(s, 3, row->body, sizeof(row->body)) ||
        sqlite3_column_type(s, 4) != SQLITE_BLOB || sqlite3_column_bytes(s, 4) != 32)
        return false;
    const void *root = sqlite3_column_blob(s, 4);
    if (!root) return false;
    memcpy(row->artifact_root, root, 32);
    return true;
}

int codeindex_pages_list(struct codeindex *ci, const char *directory,
                         struct ci_page *out, int cap)
{
    if (!ci || !ci->store || !directory || !directory[0] || !out || cap < 1 || cap > 256)
        return -1;
    bool valid = false;
    if (!ci_store_retrieval_projection_is_valid(ci->store, &valid) || !valid) return -1;
    struct ci_page *rows = zcl_calloc((size_t)cap, sizeof(*rows), "codeindex page results");
    if (!rows) return -1;
    ci_store_lock(ci->store);
    sqlite3_stmt *s = NULL;
    sqlite3 *db = ci_store_db(ci->store);
    bool ok = sqlite3_prepare_v2(db, "SELECT directory,tree_oid,source_commit,body,artifact_root "
        "FROM pages WHERE directory=?1 ORDER BY tree_oid COLLATE BINARY,"
        "source_commit COLLATE BINARY,artifact_root", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_bind_text(s, 1, directory, -1, SQLITE_TRANSIENT) == SQLITE_OK;
    int count = 0, rc = SQLITE_ERROR;
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        if (count == cap || !page_row(s, &rows[count])) { ok = false; break; }
        count++;
    }
    if (ok && rc != SQLITE_DONE) ok = false;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    ci_store_unlock(ci->store);
    if (ok) memcpy(out, rows, (size_t)count * sizeof(*out));
    free(rows);
    return ok ? count : -1;
}
