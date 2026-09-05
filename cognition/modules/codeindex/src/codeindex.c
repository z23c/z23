/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex — public lifecycle: open (verify-on-read, lazily rebuild if the
 * source tree changed) and close. Queries live in codeindex_query.c; the
 * rebuild/staleness machinery in codeindex_build.c.
 *
 * A stale open normally rebuilds here. When a resident mind owns the checkout
 * (codeindex_owner.c) it does not: the open is refused with a typed
 * `index_stale` record instead of a second writer racing the owner. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"
#include "codeindex/codeindex_build.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct codeindex *codeindex_alloc(const char *root)
{
    if (!root || !root[0])
        LOG_NULL("codeindex", "null root");

    struct codeindex *ci = zcl_calloc(1, sizeof(*ci), "codeindex");
    if (!ci)
        LOG_NULL("codeindex", "calloc codeindex");

    int n = snprintf(ci->root, sizeof(ci->root), "%s", root);
    if (n <= 0 || (size_t)n >= sizeof(ci->root)) {
        free(ci);
        LOG_NULL("codeindex", "root too long");
    }

    return ci;
}

struct codeindex *codeindex_open_existing(const char *root)
{
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    ci->store = ci_store_open(root);
    if (!ci->store) {
        codeindex_close(ci);
        return NULL;
    }
    return ci;
}

/* The one place a reader decides between rebuilding and refusing.
 *
 * `ci` is stale. If a resident mind is heart-beating for this checkout, the
 * rebuild is that resident's job and doing it here would be a second writer
 * on the store — the exact race codeindex_build_store.c already refuses,
 * paid for at query latency. Record the typed refusal and return false so
 * the caller closes and returns NULL; every existing leaf keeps its existing
 * NULL handling and `mind ask` renders the refusal in full. */
static bool ci_refresh_or_refuse(struct codeindex *ci, const char *root)
{
    if (codeindex_owner_is_live(root, (long long)platform_time_wall_time_t())) {
        ci_owner_record_refusal(ci, root);
        return false;
    }
    ci_owner_clear_refusal();
    return ci_codeindex_refresh(ci);
}

struct codeindex *codeindex_open(const char *root)
{
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    bool stale = true;
    ci->store = ci_store_open(root);
    if (ci->store && !codeindex_is_stale(ci, &stale)) {
        /* A derived store with a damaged/unreadable freshness record is not
         * authority. Drop that reader and recompute under the single-flight
         * publication lock instead of failing or repairing in place. */
        ci_store_close(ci->store);
        ci->store = NULL;
        stale = true;
    }
    if (!ci->store || stale) {
        if (!ci_refresh_or_refuse(ci, root)) {
            codeindex_close(ci);
            LOG_NULL("codeindex", "rebuild failed or refused: index_stale");
        }
    } else {
        ci_owner_clear_refusal();
    }
    return ci;
}

struct codeindex *codeindex_open_source_view(const char *root)
{
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    bool stale = true;
    ci->store = ci_store_open(root);
    if (ci->store && !ci_codeindex_source_view_is_stale(ci, &stale)) {
        ci_store_close(ci->store);
        ci->store = NULL;
        stale = true;
    }
    if (!ci->store || stale) {
        if (!ci_refresh_or_refuse(ci, root)) {
            codeindex_close(ci);
            LOG_NULL("codeindex",
                     "source-view rebuild failed or refused: index_stale");
        }
    } else {
        ci_owner_clear_refusal();
    }
    return ci;
}

/* Never rebuilds, never refuses: it reports. The mind uses this to decide
 * whether a checkout needs work; a query leaf uses it to answer from the
 * generation it has while saying how old that generation is. */
struct codeindex *codeindex_open_readonly(const char *root, bool *stale_out)
{
    if (stale_out) *stale_out = true;
    struct codeindex *ci = codeindex_alloc(root);
    if (!ci) return NULL;
    ci->store = ci_store_open(root);
    if (!ci->store) {
        codeindex_close(ci);
        return NULL;
    }
    bool stale = true;
    if (!ci_codeindex_source_view_is_stale(ci, &stale))
        stale = true;
    if (stale_out) *stale_out = stale;
    return ci;
}

struct codeindex *codeindex_open_retrieval_view(const char *root)
{
    struct codeindex *ci = codeindex_open_source_view(root);
    if (!ci) return NULL;
    bool valid = false;
    if (!ci_store_retrieval_projection_is_valid(ci->store, &valid)) {
        codeindex_close(ci);
        return NULL;
    }
    if (!valid) {
        /* Same rule as a stale source open: an invalid projection is the
         * owner's work to redo, not this query's. */
        if (codeindex_owner_is_live(root,
                                    (long long)platform_time_wall_time_t())) {
            ci_owner_record_refusal(ci, root);
            codeindex_close(ci);
            LOG_NULL("codeindex",
                     "retrieval projection refused: index_stale");
        }
        if (!codeindex_rebuild(ci) ||
            !ci_store_retrieval_projection_is_valid(ci->store, &valid) ||
            !valid) {
            codeindex_close(ci);
            LOG_NULL("codeindex", "retrieval projection rebuild failed");
        }
    }
    return ci;
}

void codeindex_close(struct codeindex *ci)
{
    if (!ci) return;
    if (ci->store) ci_store_close(ci->store);
    ci_merkle_free(ci->pending_merkle);
    free(ci);
}

bool codeindex_source_root_sha3(struct codeindex *ci, uint8_t out[32])
{
    if (!ci || !ci->store || !out)
        LOG_FAIL("codeindex", "null arg to source_root_sha3");
    size_t len = 0;
    bool found = false;
    if (!ci_store_meta_get(ci->store, "source_root_sha3", out, 32, &len,
                           &found))
        LOG_FAIL("codeindex", "read source_root_sha3");
    if (!found || len != 32)
        LOG_FAIL("codeindex", "invalid source_root_sha3 metadata");
    return true;
}

bool codeindex_build_cold_ms(struct codeindex *ci, long long *ms_out,
                             long long *files_out)
{
    if (ms_out) *ms_out = 0;
    if (files_out) *files_out = 0;
    if (!ci || !ci->store || !ms_out || !files_out)
        LOG_FAIL("codeindex", "null arg to build_cold_ms");
    char ms_text[24], files_text[24];
    size_t ms_len = 0, files_len = 0;
    bool ms_found = false, files_found = false;
    if (!ci_store_meta_get(ci->store, "build_cold_ms", ms_text,
                           sizeof(ms_text) - 1, &ms_len, &ms_found) ||
        !ci_store_meta_get(ci->store, "build_cold_files", files_text,
                           sizeof(files_text) - 1, &files_len, &files_found))
        LOG_FAIL("codeindex", "read cold-build receipt failed");
    /* Stores built before the self-receipt existed simply lack the keys;
     * that absence is a valid observation of an older generation, not a
     * hard failure. */
    if (!ms_found || !files_found || ms_len == 0 || files_len == 0)
        return false;
    ms_text[ms_len] = '\0';
    files_text[files_len] = '\0';
    char *ms_end = NULL, *files_end = NULL;
    long long ms = strtoll(ms_text, &ms_end, 10);
    long long files = strtoll(files_text, &files_end, 10);
    if (!ms_end || *ms_end != '\0' || !files_end || *files_end != '\0' ||
        ms < 0 || files < 0)
        return false;
    *ms_out = ms;
    *files_out = files;
    return true;
}

static bool ci_count_sql(struct ci_store *s, const char *sql, int64_t *out)
{
    if (out) *out = 0;
    if (!s || !sql || !out) return false;
    ci_store_lock(s);
    sqlite3_stmt *stmt = NULL;
    sqlite3 *db = ci_store_db(s);
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        ci_store_unlock(s);
        return false;
    }
    bool ok = sqlite3_step(stmt) == SQLITE_ROW;  // raw-sql-ok:codeindex-derived
    if (ok) *out = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    ci_store_unlock(s);
    return ok;
}

bool codeindex_table_counts(struct codeindex *ci, int64_t *files,
                            int64_t *symbols, int64_t *refs, int64_t *groups)
{
    if (files) *files = 0;
    if (symbols) *symbols = 0;
    if (refs) *refs = 0;
    if (groups) *groups = 0;
    if (!ci || !ci->store || !files || !symbols || !refs || !groups)
        LOG_FAIL("codeindex", "null arg to table_counts");
    if (!ci_count_sql(ci->store, "SELECT COUNT(*) FROM files", files) ||
        !ci_count_sql(ci->store, "SELECT COUNT(*) FROM symbols", symbols) ||
        !ci_count_sql(ci->store, "SELECT COUNT(*) FROM refs", refs) ||
        !ci_count_sql(ci->store, "SELECT COUNT(*) FROM groups", groups))
        LOG_FAIL("codeindex", "count index tables");
    return true;
}

int codeindex_group_metrics(struct codeindex *ci, struct ci_group_metric *out,
                            int cap)
{
    if (!ci || !ci->store || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to group_metrics");
    ci_store_lock(ci->store);
    sqlite3_stmt *stmt = NULL;
    sqlite3 *db = ci_store_db(ci->store);
    static const char sql[] =
        "SELECT g.path,"
        "(SELECT COUNT(*) FROM files f WHERE f.\"group\"=g.path),"
        "(SELECT COUNT(*) FROM symbols s WHERE s.\"group\"=g.path) "
        "FROM groups g ORDER BY g.path";
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        ci_store_unlock(ci->store);
        LOG_ERR("codeindex", "prepare group_metrics");
    }
    int n = 0, rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].name, sizeof(out[n].name),
               (const char *)sqlite3_column_text(stmt, 0));
        out[n].files = sqlite3_column_int64(stmt, 1);
        out[n].lines = sqlite3_column_int64(stmt, 2);
        n++;
    }
    sqlite3_finalize(stmt);
    ci_store_unlock(ci->store);
    return n;
}

bool codeindex_retrieval_projection_root_sha3(struct codeindex *ci,
                                              uint8_t out[32])
{
    if (!ci || !ci->store || !out)
        LOG_FAIL("codeindex", "null arg to retrieval_projection_root_sha3");
    uint8_t root[32];
    size_t len = 0;
    bool found = false;
    if (!ci_store_meta_get(ci->store, CI_RETRIEVAL_PROJECTION_META, root,
                           sizeof(root), &len, &found))
        LOG_FAIL("codeindex", "read retrieval projection root");
    if (!found || len != sizeof(root))
        LOG_FAIL("codeindex", "invalid retrieval projection root metadata");
    memcpy(out, root, sizeof(root));
    return true;
}

bool codeindex_retrieval_projection_is_current(struct codeindex *ci,
                                               bool *current)
{
    if (current) *current = false;
    if (!ci || !ci->store || !current)
        LOG_FAIL("codeindex", "null arg to retrieval_projection_is_current");
    return ci_store_retrieval_projection_is_valid(ci->store, current);
}
