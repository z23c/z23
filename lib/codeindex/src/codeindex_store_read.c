/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the READ half of codeindex_store — every query that steps derived
 * rows back out of <root>/.codeindex/index.kv.
 *
 * Split out of codeindex_store.c along the file-size ceiling seam at the
 * boundary that file already declared with its `── reads ──` banner.
 * codeindex_store.c keeps the WRITE half (row hash, pragmas + schema,
 * open/close, transaction control, every `ci_store_put_*`); this file holds
 * meta_get, the symbol/ref/file/group lookups, and the include-edge count.
 * Both halves are the same single-writer derived store described in
 * codeindex_store.c's header, so raw sqlite3_step here carries the same
 * `// raw-sql-ok:codeindex-derived` marker, and every symbol read still runs
 * through ci_store_fill_symbol()'s verify-on-read row checksum. The one thing
 * that crosses the seam is the handle layout, in
 * codeindex_store_internal.h. */

#include "codeindex_store_internal.h"

#include "util/log_macros.h"

#include <sqlite3.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* ── reads ──────────────────────────────────────────────────────────── */

bool ci_store_meta_get(struct ci_store *s, const char *k, void *buf,
                       size_t cap, size_t *outlen, bool *found)
{
    if (found) *found = false;
    if (outlen) *outlen = 0;
    if (!s || !k || !k[0])
        LOG_FAIL("codeindex", "null arg to meta_get");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT v FROM meta WHERE k=?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "prepare meta_get");
    }
    sqlite3_bind_text(stmt, 1, k, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        if (found) *found = true;
        int n = sqlite3_column_bytes(stmt, 0);
        const void *b = sqlite3_column_blob(stmt, 0);
        if (outlen) *outlen = (size_t)n;
        if (buf && cap > 0 && b) {
            size_t copy = (size_t)n < cap ? (size_t)n : cap;
            if (copy > 0) memcpy(buf, b, copy);
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "step meta_get");
    return true;
}

/* Fill a ci_symbol from a stepped row and verify its integrity checksum.
 * Returns false (row rejected) if the recomputed hash mismatches the stored
 * row_sha3 — verify-on-read. */
bool ci_store_fill_symbol(sqlite3_stmt *stmt, struct ci_symbol *out)
{
    memset(out, 0, sizeof(*out));
    const unsigned char *t;
    t = sqlite3_column_text(stmt, 0);  ci_cpy(out->name, sizeof(out->name), (const char *)t);
    t = sqlite3_column_text(stmt, 1);  out->kind = (t && t[0]) ? (char)t[0] : 'D';
    t = sqlite3_column_text(stmt, 2);  ci_cpy(out->def_path, sizeof(out->def_path), (const char *)t);
    out->def_line = sqlite3_column_int(stmt, 3);
    t = sqlite3_column_text(stmt, 4);  ci_cpy(out->decl_path, sizeof(out->decl_path), (const char *)t);
    out->decl_line = sqlite3_column_int(stmt, 5);
    t = sqlite3_column_text(stmt, 6);  ci_cpy(out->signature, sizeof(out->signature), (const char *)t);
    t = sqlite3_column_text(stmt, 7);  ci_cpy(out->doc, sizeof(out->doc), (const char *)t);
    t = sqlite3_column_text(stmt, 8);  ci_cpy(out->guard, sizeof(out->guard), (const char *)t);
    t = sqlite3_column_text(stmt, 9);  ci_cpy(out->group, sizeof(out->group), (const char *)t);
    out->partial = sqlite3_column_int(stmt, 10) != 0;

    const void *rb = sqlite3_column_blob(stmt, 11);
    int rn = sqlite3_column_bytes(stmt, 11);
    uint8_t want[32];
    ci_symbol_row_hash(out, want);
    if (!rb || rn != 32 || memcmp(rb, want, 32) != 0)
        return false;  /* corrupted row */
    return true;
}

bool ci_store_symbol_by_name(struct ci_store *s, const char *name,
                             struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!s || !name || !out)
        LOG_FAIL("codeindex", "null arg to symbol_by_name");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* Prefer a definition over a bare declaration, then lowest def_line. */
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS " FROM symbols WHERE name=?"
        " ORDER BY (def_path='') ASC, def_line ASC, def_path ASC LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "prepare symbol_by_name");
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        if (ci_store_fill_symbol(stmt, out)) {
            if (found) *found = true;
        }  /* corrupted → leave found=false */
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "step symbol_by_name");
    return true;
}

int ci_store_find_symbols(struct ci_store *s, const char *q,
                          struct ci_symbol *out, int cap)
{
    if (!s || !q || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to find_symbols");
    /* Rank: exact(0) < prefix(1) < substring(2); then name, def_path. */
    char like[300];
    snprintf(like, sizeof(like), "%%%s%%", q);
    char pfx[300];
    snprintf(pfx, sizeof(pfx), "%s%%", q);
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS ", "
        "  CASE WHEN name=?1 THEN 0 WHEN name LIKE ?2 THEN 1 ELSE 2 END AS rank"
        " FROM symbols WHERE name LIKE ?3"
        " ORDER BY rank ASC, name ASC, (def_path='') ASC, def_path ASC, def_line ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare find_symbols");
    }
    sqlite3_bind_text(stmt, 1, q, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pfx, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, like, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        if (ci_store_fill_symbol(stmt, &out[n]))
            n++;  /* skip corrupted rows */
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_refs_by_callee(struct ci_store *s, const char *callee,
                            struct ci_ref *out, int cap)
{
    if (!s || !callee || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to refs_by_callee");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT callee_name,ref_file,ref_line,enclosing FROM refs"
        " WHERE callee_name=? ORDER BY ref_file ASC, ref_line ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare refs_by_callee");
    }
    sqlite3_bind_text(stmt, 1, callee, -1, SQLITE_TRANSIENT);
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
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_refs_by_enclosing(struct ci_store *s, const char *enclosing,
                               struct ci_ref *out, int cap)
{
    if (!s || !enclosing || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to refs_by_enclosing");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT callee_name,ref_file,ref_line,enclosing FROM refs"
        " WHERE enclosing=? ORDER BY ref_file ASC, ref_line ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare refs_by_enclosing");
    }
    sqlite3_bind_text(stmt, 1, enclosing, -1, SQLITE_TRANSIENT);
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
    pthread_mutex_unlock(&s->lock);
    return n;
}

bool ci_store_file_by_path(struct ci_store *s, const char *path,
                           struct ci_file *out, bool *found)
{
    if (found) *found = false;
    if (!s || !path || !out)
        LOG_FAIL("codeindex", "null arg to file_by_path");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,\"group\",purpose FROM files WHERE path=?",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "prepare file_by_path");
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        ci_cpy(out->path, sizeof(out->path), (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out->group, sizeof(out->group), (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out->purpose, sizeof(out->purpose), (const char *)sqlite3_column_text(stmt, 2));
        if (found) *found = true;
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "step file_by_path");
    return true;
}

int ci_store_list_groups(struct ci_store *s, struct ci_group *out, int cap)
{
    if (!s || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to list_groups");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,kind,parent,purpose FROM groups ORDER BY path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare list_groups");
    }
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].path, sizeof(out[n].path), (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].kind, sizeof(out[n].kind), (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out[n].parent, sizeof(out[n].parent), (const char *)sqlite3_column_text(stmt, 2));
        ci_cpy(out[n].purpose, sizeof(out[n].purpose), (const char *)sqlite3_column_text(stmt, 3));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_files_in_group(struct ci_store *s, const char *group,
                            struct ci_file *out, int cap)
{
    if (!s || !group || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to files_in_group");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,\"group\",purpose FROM files WHERE \"group\"=?"
        " ORDER BY path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare files_in_group");
    }
    sqlite3_bind_text(stmt, 1, group, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].path, sizeof(out[n].path), (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].group, sizeof(out[n].group), (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out[n].purpose, sizeof(out[n].purpose), (const char *)sqlite3_column_text(stmt, 2));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_file_count(struct ci_store *s)
{
    if (!s) LOG_ERR("codeindex", "bad arg to file_count");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT COUNT(*) FROM files", -1, &stmt,
                           NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare file_count");
    }
    int n = 0;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    bool ok = rc == SQLITE_ROW;
    if (ok) n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_ERR("codeindex", "step file_count");
    return n;
}

int ci_store_files_page(struct ci_store *s, int offset,
                        struct ci_file *out, int cap)
{
    if (!s || offset < 0 || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to files_page");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,\"group\",purpose FROM files ORDER BY path ASC "
        "LIMIT ?1 OFFSET ?2",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare files_page");
    }
    sqlite3_bind_int(stmt, 1, cap);  // raw-sql-ok:codeindex-derived
    sqlite3_bind_int(stmt, 2, offset);  // raw-sql-ok:codeindex-derived
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].path, sizeof(out[n].path),
               (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].group, sizeof(out[n].group),
               (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out[n].purpose, sizeof(out[n].purpose),
               (const char *)sqlite3_column_text(stmt, 2));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_count_files_in_group(struct ci_store *s, const char *group,
                                  bool recursive)
{
    if (!s || !group)
        LOG_ERR("codeindex", "bad arg to count_files_in_group");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* Direct: only files stamped with EXACTLY this group. Recursive: also
     * every descendant group ("lib/net" under "lib") via the "<group>/%"
     * prefix, so a parent aggregates its children's file totals. */
    const char *sql = recursive
        ? "SELECT COUNT(*) FROM files WHERE \"group\"=? OR \"group\" LIKE ?||'/%'"
        : "SELECT COUNT(*) FROM files WHERE \"group\"=?";
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare count_files_in_group");
    }
    sqlite3_bind_text(stmt, 1, group, -1, SQLITE_TRANSIENT);
    if (recursive)
        sqlite3_bind_text(stmt, 2, group, -1, SQLITE_TRANSIENT);
    int n = 0;
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    else if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_ERR("codeindex", "step count_files_in_group");
    return n;
}

int ci_store_symbols_in_file(struct ci_store *s, const char *path,
                             struct ci_symbol *out, int cap)
{
    if (!s || !path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to symbols_in_file");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* A .c file owns its definitions (def_path); a header owns declarations
     * (decl_path). Match either, definitions first, then source order. */
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS " FROM symbols"
        " WHERE def_path=?1 OR decl_path=?1"
        " ORDER BY (def_path=?1) DESC, def_line ASC, decl_line ASC, name ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare symbols_in_file");
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        if (ci_store_fill_symbol(stmt, &out[n]))
            n++;  /* skip corrupted rows */
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_includes_of_file(struct ci_store *s, const char *path,
                              char (*out)[256], int cap)
{
    if (!s || !path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to includes_of_file");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT i.dep_path FROM includes i JOIN files f ON f.id=i.file_id"
        " WHERE f.path=? ORDER BY i.dep_path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare includes_of_file");
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        ci_cpy(out[n], 256, (const char *)sqlite3_column_text(stmt, 0));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_dependents_of_file(struct ci_store *s, const char *dep_path,
                                char (*out)[256], int cap)
{
    if (!s || !dep_path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to dependents_of_file");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* The mirror of ci_store_includes_of_file. Each row of `includes` is a
     * (translation unit -> prerequisite) pair the COMPILER recorded, and a
     * depfile's prerequisite list is already transitively flattened, so one
     * equality probe answers the whole reverse question: every TU whose bytes
     * the compiler read `dep_path` for, however many headers deep. */
    if (sqlite3_prepare_v2(s->db,
        "SELECT DISTINCT f.path FROM includes i JOIN files f ON f.id=i.file_id"
        " WHERE i.dep_path=? ORDER BY f.path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare dependents_of_file");
    }
    sqlite3_bind_text(stmt, 1, dep_path, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        ci_cpy(out[n], 256, (const char *)sqlite3_column_text(stmt, 0));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int64_t ci_store_include_edge_count(struct ci_store *s)
{
    if (!s)
        LOG_ERR("codeindex", "null store to include_edge_count");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT COUNT(*) FROM includes", -1, &stmt,
                           NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare include_edge_count");
    }
    int64_t count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:codeindex-derived
        count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (count < 0)
        LOG_ERR("codeindex", "read include_edge_count");
    return count;
}
