/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replace only changed-file scan and impact rows in a cloned codeindex generation.
 * Unchanged scan shards remain byte-identical across generations. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"

#include "platform/file_metadata.h"
#include "util/log_macros.h"

#include <sqlite3.h>

#include <stdio.h>
#include <string.h>

struct incremental_scan {
    struct ci_store *store;
    bool failed;
};

static void incremental_symbol(const struct ci_symbol *symbol, void *user)
{
    struct incremental_scan *scan = user;
    if (!scan->failed && !ci_store_put_symbol(scan->store, symbol))
        scan->failed = true;
}

static void incremental_ref(const char *callee, const char *file, int line,
                            const char *enclosing, void *user)
{
    struct incremental_scan *scan = user;
    if (!scan->failed &&
        !ci_store_put_ref(scan->store, callee, file, line, enclosing))
        scan->failed = true;
}

static void incremental_ignore_symbol(const struct ci_symbol *symbol, void *user)
{
    (void)symbol;
    (void)user;
}

static void incremental_ignore_ref(const char *callee, const char *file,
                                   int line, const char *enclosing, void *user)
{
    (void)callee;
    (void)file;
    (void)line;
    (void)enclosing;
    (void)user;
}

static bool incremental_delete_path(sqlite3 *db, const char *sql,
                                    const char *path)
{
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE; // raw-sql-ok:codeindex-derived
    sqlite3_finalize(statement);
    return ok;
}

static bool incremental_regular_mtime_ns(const char *path, int64_t *out)
{
    if (!path || !out) return false;
#if defined(_WIN32)
    struct platform_file_metadata metadata;
    if (platform_file_metadata_read(path, &metadata) !=
        PLATFORM_FILE_METADATA_OK)
        return false;
    *out = metadata.modified_seconds * INT64_C(1000000000);
#else
    struct stat metadata;
    if (lstat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode))
        return false;
    *out = (int64_t)metadata.st_mtim.tv_sec * INT64_C(1000000000) +
           (int64_t)metadata.st_mtim.tv_nsec;
#endif
    return true;
}

static bool incremental_delete_file_rows(sqlite3 *db, const char *path)
{
    return incremental_delete_path(db,
                                   "DELETE FROM symbols WHERE def_path=?1 OR decl_path=?1",
                                   path) &&
           incremental_delete_path(db, "DELETE FROM refs WHERE ref_file=?1", path);
}

static bool incremental_scan_file_into_store(const char *root,
                                             struct ci_store *store,
                                             const char *path,
                                             uint8_t content_sha3[32],
                                             char purpose[CI_FILE_PURPOSE_MAX])
{
    struct incremental_scan scan = {.store = store, .failed = false};
    bool registry = ci_path_is_registry(path);
    return ci_scan_file(root, path,
                        registry ? incremental_ignore_symbol : incremental_symbol,
                        registry ? incremental_ignore_ref : incremental_ref,
                        &scan, content_sha3, purpose) &&
           !scan.failed;
}

static bool incremental_file_mtime_ns(const char *root, const char *path,
                                      int64_t *out)
{
    char absolute[CI_PATH_MAX];
    int length = snprintf(absolute, sizeof(absolute), "%s/%s", root, path);
    if (length <= 0 || (size_t)length >= sizeof(absolute) ||
        !incremental_regular_mtime_ns(absolute, out))
        return false;
    return true;
}

static bool incremental_update_file_row(sqlite3 *db, const char *path,
                                        const struct ci_file *file,
                                        const uint8_t content_sha3[32],
                                        int64_t mtime_ns)
{
    sqlite3_stmt *statement = NULL;
    static const char update_sql[] =
        "UPDATE files SET \"group\"=?,purpose=?,content_sha3=?,mtime=? WHERE path=?";
    if (sqlite3_prepare_v2(db, update_sql, -1, &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, file->group, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_text(statement, 2, file->purpose, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_blob(statement, 3, content_sha3, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_int64(statement, 4, mtime_ns) == SQLITE_OK &&
              sqlite3_bind_text(statement, 5, path, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE && // raw-sql-ok:codeindex-derived
              sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    return ok;
}

static bool incremental_replace_file(const char *root, struct ci_store *store,
                                     const char *path)
{
    sqlite3 *db = ci_store_db(store);
    if (!incremental_delete_file_rows(db, path))
        return false;

    uint8_t content_sha3[32];
    char purpose[CI_FILE_PURPOSE_MAX] = "";
    if (!incremental_scan_file_into_store(root, store, path, content_sha3,
                                          purpose))
        return false;

    int64_t mtime_ns = 0;
    if (!incremental_file_mtime_ns(root, path, &mtime_ns))
        return false;

    struct ci_file file;
    memset(&file, 0, sizeof(file));
    ci_cpy(file.path, sizeof(file.path), path);
    ci_group_for_path(path, file.group);
    ci_cpy(file.purpose, sizeof(file.purpose), purpose);
    if (!incremental_update_file_row(db, path, &file, content_sha3, mtime_ns))
        return false;
    return ci_store_scan_shard_refresh(store, path);
}

static bool incremental_source_root(struct ci_store *store, uint8_t out[32])
{
    sqlite3 *db = ci_store_db(store);
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT path,content_sha3 FROM files ORDER BY path", -1,
            &statement, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx sha;
    ci_source_root_init(&sha);
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) { // raw-sql-ok:codeindex-derived
        const char *path = (const char *)sqlite3_column_text(statement, 0);
        const void *digest = sqlite3_column_blob(statement, 1);
        if (!path || !digest || sqlite3_column_bytes(statement, 1) != 32) {
            ok = false;
            break;
        }
        ci_source_root_add(&sha, path, digest);
    }
    if (rc != SQLITE_DONE) ok = false;
    sqlite3_finalize(statement);
    if (ok) sha3_256_finalize(&sha, out);
    return ok;
}

bool ci_deps_include_edge_root(uint8_t out[32]);

/* The include rows are reused, not rebuilt. They answer completely only
 * while the current scan produces exactly the edges they were built from.
 * The rebuild path patches only a generation whose edge root matches, and a
 * seeded one is stamped after its rows are verified, so a mismatch here means
 * the sources moved during this update: the answer refuses and the next
 * update rebuilds. The stored edge root is left as is, so it keeps describing
 * the rows. */
static bool incremental_refresh_include_narrow(const char *root,
                                               struct ci_store *store,
                                               bool rescan_deps)
{
    uint8_t exact[32];
    uint8_t stat_root[32];
    uint8_t edges[32];
    uint8_t stored[32];
    size_t stored_len = 0;
    bool found = false;
    if ((rescan_deps &&
         !ci_deps_scan_roots(root, NULL, NULL, exact, stat_root)) ||
        !ci_deps_include_edge_root(edges) ||
        !ci_store_meta_get(store, "include_edge_root_sha3", stored,
                           sizeof stored, &stored_len, &found))
        return false;
    bool rows_current = found && stored_len == sizeof stored &&
                        memcmp(stored, edges, sizeof edges) == 0;
    const char *bit =
        (!rows_current || ci_deps_include_narrow_unsafe()) ? "1" : "0";
    /* The depfile rule is the more specific evidence when both hold. */
    const char *cause = ci_deps_include_narrow_unsafe()
        ? ci_deps_include_narrow_cause()
        : (!rows_current ? "include_rows_stale" : "");
    return ci_store_meta_set(store, "include_narrow_unsafe", bit, 1) &&
           ci_store_meta_set(store, "include_narrow_cause", cause,
                             strlen(cause));
}

static bool incremental_stamp_projection_and_counts(const char *root,
                                                    struct ci_store *store,
                                                    bool rescan_deps)
{
    uint8_t projection_root[32];
    return incremental_refresh_include_narrow(root, store, rescan_deps) &&
           ci_store_retrieval_projection_root(store, projection_root) &&
           ci_store_meta_set(store, CI_RETRIEVAL_PROJECTION_META,
                             projection_root, sizeof(projection_root)) &&
           ci_store_write_table_count_meta(store);
}

static bool incremental_seal_roots(struct ci_store *store, const uint8_t dep_stat[32],
                                   const uint8_t merkle_root[32])
{
    uint8_t source_root[32];
    return incremental_source_root(store, source_root) &&
           ci_store_meta_set(store, "source_root_sha3", source_root, 32) &&
           ci_store_meta_set(store, "dep_stat_root_sha3", dep_stat, 32) &&
           ci_store_meta_set(store, "source_merkle_root_sha3", merkle_root, 32);
}

static bool incremental_build(const char *root, struct ci_store *store,
                              const struct ci_merkle_leaf *changed,
                              int changed_count, const uint8_t dep_stat[32],
                              const uint8_t merkle_root[32], bool rescan_deps)
{
    if (!root || !store || (changed_count > 0 && !changed) || changed_count < 0 ||
        !dep_stat || !merkle_root)
        LOG_FAIL("codeindex", "invalid incremental store build");
    bool tx_open = ci_store_begin(store);
    bool ok = tx_open;
    for (int i = 0; ok && i < changed_count; i++)
        ok = incremental_replace_file(root, store, changed[i].path);
    if (ok) ok = incremental_seal_roots(store, dep_stat, merkle_root);
    if (ok)
        ok = incremental_stamp_projection_and_counts(root, store, rescan_deps);
    if (!ok) {
        if (tx_open) (void)ci_store_rollback(store);
        LOG_FAIL("codeindex", "incremental changed-row replacement failed");
    }
    if (!ci_store_commit(store))
        LOG_FAIL("codeindex", "incremental store commit failed");
    return true;
}

bool ci_build_store_incremental(const char *root, struct ci_store *store,
                                const struct ci_merkle_leaf *changed,
                                int changed_count,
                                const uint8_t dep_stat[32],
                                const uint8_t merkle_root[32])
{
    return incremental_build(root, store, changed, changed_count, dep_stat,
                             merkle_root, true);
}

bool ci_build_store_incremental_scanned(const char *root, struct ci_store *store,
                                        const struct ci_merkle_leaf *changed,
                                        int changed_count,
                                        const uint8_t dep_stat[32],
                                        const uint8_t merkle_root[32])
{
    return incremental_build(root, store, changed, changed_count, dep_stat,
                             merkle_root, false);
}

static bool diff_merkle_inputs_valid(const struct ci_store *store,
                                     const struct ci_merkle_leaf *current,
                                     int current_count,
                                     const struct ci_merkle_leaf *changed,
                                     int cap, const bool *inventory_same)
{
    return store && current && current_count >= 0 && changed &&
           cap >= current_count && inventory_same;
}

static bool diff_merkle_scan_rows(sqlite3_stmt *statement,
                                  const struct ci_merkle_leaf *current,
                                  int current_count,
                                  struct ci_merkle_leaf *changed, int *nchanged)
{
    for (int i = 0; i < current_count; i++) {
        int rc = sqlite3_step(statement); // raw-sql-ok:codeindex-derived
        const char *path = rc == SQLITE_ROW
            ? (const char *)sqlite3_column_text(statement, 0) : NULL;
        const void *digest = rc == SQLITE_ROW
            ? sqlite3_column_blob(statement, 1) : NULL;
        if (rc != SQLITE_ROW || !path || strcmp(path, current[i].path) != 0 ||
            !digest || sqlite3_column_bytes(statement, 1) != 32)
            return false;
        if (memcmp(digest, current[i].content_digest.bytes, 32) != 0)
            changed[(*nchanged)++] = current[i];
    }
    return true;
}

int ci_store_diff_merkle_leaves(struct ci_store *store,
                                const struct ci_merkle_leaf *current,
                                int current_count,
                                struct ci_merkle_leaf *changed, int cap,
                                bool *inventory_same)
{
    if (inventory_same) *inventory_same = false;
    if (!diff_merkle_inputs_valid(store, current, current_count, changed, cap,
                                  inventory_same))
        LOG_ERR("codeindex", "invalid Merkle/store diff");
    ci_store_lock(store);
    sqlite3_stmt *statement = NULL;
    sqlite3 *db = ci_store_db(store);
    bool ok = sqlite3_prepare_v2(db,
        "SELECT path,content_sha3 FROM files ORDER BY path", -1,
        &statement, NULL) == SQLITE_OK;
    int nchanged = 0;
    if (ok)
        ok = diff_merkle_scan_rows(statement, current, current_count, changed,
                                   &nchanged);
    if (ok && sqlite3_step(statement) != SQLITE_DONE) ok = false; // raw-sql-ok:codeindex-derived
    sqlite3_finalize(statement);
    ci_store_unlock(store);
    *inventory_same = ok;
    return ok ? nchanged : 0;
}
