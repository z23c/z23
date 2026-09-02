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

static bool incremental_replace_file(const char *root, struct ci_store *store,
                                     const char *path)
{
    sqlite3 *db = ci_store_db(store);
    if (!incremental_delete_path(
            db, "DELETE FROM symbols WHERE def_path=?1 OR decl_path=?1", path) ||
        !incremental_delete_path(db, "DELETE FROM refs WHERE ref_file=?1", path))
        return false;

    struct incremental_scan scan = {.store = store, .failed = false};
    uint8_t content_sha3[32];
    char purpose[CI_FILE_PURPOSE_MAX] = "";
    bool registry = ci_path_is_registry(path);
    if (!ci_scan_file(root, path,
                      registry ? incremental_ignore_symbol : incremental_symbol,
                      registry ? incremental_ignore_ref : incremental_ref,
                      &scan, content_sha3, purpose) || scan.failed)
        return false;

    char absolute[CI_PATH_MAX];
    int length = snprintf(absolute, sizeof(absolute), "%s/%s", root, path);
    int64_t mtime_ns = 0;
    if (length <= 0 || (size_t)length >= sizeof(absolute) ||
        !incremental_regular_mtime_ns(absolute, &mtime_ns))
        return false;

    struct ci_file file;
    memset(&file, 0, sizeof(file));
    ci_cpy(file.path, sizeof(file.path), path);
    ci_group_for_path(path, file.group);
    ci_cpy(file.purpose, sizeof(file.purpose), purpose);
    sqlite3_stmt *statement = NULL;
    static const char update_sql[] =
        "UPDATE files SET \"group\"=?,purpose=?,content_sha3=?,mtime=? WHERE path=?";
    if (sqlite3_prepare_v2(db, update_sql, -1, &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, file.group, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_text(statement, 2, file.purpose, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_blob(statement, 3, content_sha3, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_int64(statement, 4, mtime_ns) == SQLITE_OK &&
              sqlite3_bind_text(statement, 5, path, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE && // raw-sql-ok:codeindex-derived
              sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    return ok && ci_store_scan_shard_refresh(store, path);
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

bool ci_build_store_incremental(const char *root, struct ci_store *store,
                                const struct ci_merkle_leaf *changed,
                                int changed_count,
                                const uint8_t dep_stat[32],
                                const uint8_t merkle_root[32])
{
    if (!root || !store || (changed_count > 0 && !changed) || changed_count < 0 ||
        !dep_stat || !merkle_root)
        LOG_FAIL("codeindex", "invalid incremental store build");
    bool tx_open = ci_store_begin(store);
    bool ok = tx_open;
    for (int i = 0; ok && i < changed_count; i++)
        ok = incremental_replace_file(root, store, changed[i].path);
    uint8_t source_root[32], projection_root[32];
    if (ok) ok = incremental_source_root(store, source_root);
    if (ok)
        ok = ci_store_meta_set(store, "source_root_sha3", source_root, 32) &&
             ci_store_meta_set(store, "dep_stat_root_sha3", dep_stat, 32) &&
             ci_store_meta_set(store, "source_merkle_root_sha3", merkle_root, 32);
    if (ok)
        ok = ci_store_retrieval_projection_root(store, projection_root) &&
             ci_store_meta_set(store, CI_RETRIEVAL_PROJECTION_META,
                               projection_root, sizeof(projection_root));
    if (!ok) {
        if (tx_open) (void)ci_store_rollback(store);
        LOG_FAIL("codeindex", "incremental changed-row replacement failed");
    }
    if (!ci_store_commit(store))
        LOG_FAIL("codeindex", "incremental store commit failed");
    return true;
}

int ci_store_diff_merkle_leaves(struct ci_store *store,
                                const struct ci_merkle_leaf *current,
                                int current_count,
                                struct ci_merkle_leaf *changed, int cap,
                                bool *inventory_same)
{
    if (inventory_same) *inventory_same = false;
    if (!store || !current || current_count < 0 || !changed || cap < current_count ||
        !inventory_same)
        LOG_ERR("codeindex", "invalid Merkle/store diff");
    ci_store_lock(store);
    sqlite3_stmt *statement = NULL;
    sqlite3 *db = ci_store_db(store);
    bool ok = sqlite3_prepare_v2(db,
        "SELECT path,content_sha3 FROM files ORDER BY path", -1,
        &statement, NULL) == SQLITE_OK;
    int nchanged = 0;
    for (int i = 0; ok && i < current_count; i++) {
        int rc = sqlite3_step(statement); // raw-sql-ok:codeindex-derived
        const char *path = rc == SQLITE_ROW
            ? (const char *)sqlite3_column_text(statement, 0) : NULL;
        const void *digest = rc == SQLITE_ROW
            ? sqlite3_column_blob(statement, 1) : NULL;
        if (rc != SQLITE_ROW || !path || strcmp(path, current[i].path) != 0 ||
            !digest || sqlite3_column_bytes(statement, 1) != 32) {
            ok = false;
            break;
        }
        if (memcmp(digest, current[i].content_digest.bytes, 32) != 0)
            changed[nchanged++] = current[i];
    }
    if (ok && sqlite3_step(statement) != SQLITE_DONE) ok = false; // raw-sql-ok:codeindex-derived
    sqlite3_finalize(statement);
    ci_store_unlock(store);
    *inventory_same = ok;
    return ok ? nchanged : 0;
}
