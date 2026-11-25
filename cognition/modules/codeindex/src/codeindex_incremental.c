/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replace only changed-file scan and impact rows in a cloned codeindex generation.
 * Unchanged scan shards remain byte-identical across generations. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"

#include "platform/file_metadata.h"
#include "util/log_macros.h"

#include <sqlite3.h>

#include <errno.h>
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

static int incremental_regular_mtime_ns(const char *path, int64_t *out)
{
    if (!path || !out) return -1;
#if defined(_WIN32)
    struct platform_file_metadata metadata;
    enum platform_file_metadata_result result =
        platform_file_metadata_read(path, &metadata);
    if (result == PLATFORM_FILE_METADATA_MISSING) return 0;
    if (result != PLATFORM_FILE_METADATA_OK) return -1;
    *out = metadata.modified_seconds * INT64_C(1000000000);
#else
    struct stat metadata;
    if (lstat(path, &metadata) != 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    if (!S_ISREG(metadata.st_mode)) return -1;
    *out = (int64_t)metadata.st_mtim.tv_sec * INT64_C(1000000000) +
           (int64_t)metadata.st_mtim.tv_nsec;
#endif
    return 1;
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
                                             char purpose[CI_FILE_PURPOSE_MAX],
                                             int *lines)
{
    struct incremental_scan scan = {.store = store, .failed = false};
    bool registry = ci_path_is_registry(path);
    return ci_scan_file(root, path,
                        registry ? incremental_ignore_symbol : incremental_symbol,
                        registry ? incremental_ignore_ref : incremental_ref,
                        &scan, content_sha3, purpose, lines) &&
           !scan.failed;
}

static int incremental_file_mtime_ns(const char *root, const char *path,
                                     int64_t *out)
{
    char absolute[CI_PATH_MAX];
    int length = snprintf(absolute, sizeof(absolute), "%s/%s", root, path);
    if (length <= 0 || (size_t)length >= sizeof(absolute))
        return -1;
    return incremental_regular_mtime_ns(absolute, out);
}

static bool incremental_update_file_row(sqlite3 *db, const char *path,
                                        const struct ci_file *file,
                                        const uint8_t content_sha3[32],
                                        int64_t mtime_ns)
{
    sqlite3_stmt *statement = NULL;
    static const char update_sql[] =
        "INSERT INTO files(path,\"group\",purpose,content_sha3,mtime,line_count)"
        " VALUES(?1,?2,?3,?4,?5,?6)"
        " ON CONFLICT(path) DO UPDATE SET \"group\"=excluded.\"group\","
        " purpose=excluded.purpose,content_sha3=excluded.content_sha3,"
        " mtime=excluded.mtime,line_count=excluded.line_count";
    if (sqlite3_prepare_v2(db, update_sql, -1, &statement, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(statement, 1, path, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_text(statement, 2, file->group, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_text(statement, 3, file->purpose, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_blob(statement, 4, content_sha3, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_int64(statement, 5, mtime_ns) == SQLITE_OK &&
              sqlite3_bind_int(statement, 6, file->line_count) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE && // raw-sql-ok:codeindex-derived
              sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    return ok;
}

static bool incremental_delete_file(sqlite3 *db, const char *path)
{
    return incremental_delete_path(db,
                                   "DELETE FROM includes WHERE file_id IN "
                                   "(SELECT id FROM files WHERE path=?1)",
                                   path) &&
           incremental_delete_path(db,
                                   "DELETE FROM scan_shards WHERE path=?1",
                                   path) &&
           incremental_delete_path(db, "DELETE FROM files WHERE path=?1",
                                   path);
}

static bool incremental_replace_file(const char *root, struct ci_store *store,
                                     const char *path)
{
    sqlite3 *db = ci_store_db(store);
    int64_t mtime_ns = 0;
    int present = incremental_file_mtime_ns(root, path, &mtime_ns);
    if (present < 0 || !incremental_delete_file_rows(db, path))
        LOG_FAIL("codeindex", "incremental stage=delete_rows path=%s", path);
    if (present == 0)
        return incremental_delete_file(db, path);

    uint8_t content_sha3[32];
    char purpose[CI_FILE_PURPOSE_MAX] = "";
    int lines = 0;
    if (!incremental_scan_file_into_store(root, store, path, content_sha3,
                                          purpose, &lines))
        LOG_FAIL("codeindex", "incremental stage=scan path=%s", path);

    struct ci_file file;
    memset(&file, 0, sizeof(file));
    ci_cpy(file.path, sizeof(file.path), path);
    ci_group_for_path(path, file.group);
    ci_cpy(file.purpose, sizeof(file.purpose), purpose);
    file.line_count = lines;
    if (!incremental_update_file_row(db, path, &file, content_sha3, mtime_ns))
        LOG_FAIL("codeindex", "incremental stage=update_file path=%s", path);
    if (!ci_store_scan_shard_refresh(store, path))
        LOG_FAIL("codeindex", "incremental stage=scan_shard path=%s", path);
    return true;
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

struct include_expected_edges {
    sqlite3_stmt *insert;
    bool ok;
};

static void include_expected_edge(const char *source, const char *dependency,
                               void *user)
{
    struct include_expected_edges *expected = user;
    if (!expected->ok) return;
    expected->ok = sqlite3_reset(expected->insert) == SQLITE_OK &&
                   sqlite3_clear_bindings(expected->insert) == SQLITE_OK &&
                   sqlite3_bind_text(expected->insert, 1, source, -1,
                                     SQLITE_TRANSIENT) == SQLITE_OK &&
                   sqlite3_bind_text(expected->insert, 2, dependency, -1,
                                     SQLITE_TRANSIENT) == SQLITE_OK &&
                   sqlite3_step(expected->insert) == SQLITE_DONE; // raw-sql-ok:codeindex-derived
}

/* Replace the staged include rows with a fresh parse of THIS checkout, then
 * prove the table equals that parse. Prior rows may describe different depfiles or a different checkout,
 * so they are never trusted. The
 * join to files mirrors the cold builder's rule that only indexed sources get
 * edges. */
static bool include_rows_match(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(statement); // raw-sql-ok:codeindex-derived
    bool equal = rc == SQLITE_ROW && sqlite3_column_int(statement, 0) == 1;
    return sqlite3_finalize(statement) == SQLITE_OK && equal;
}

static bool reconcile_include_rows(const char *root, struct ci_store *staged,
                                   uint8_t parsed_root[32], uint8_t parsed_stat[32])
{
    static const char create_sql[] =
        "CREATE TEMP TABLE include_expected ("
        "source TEXT NOT NULL, dep_path TEXT NOT NULL,"
        "PRIMARY KEY(source,dep_path)) WITHOUT ROWID";
    static const char rewrite_sql[] =
        "DELETE FROM includes;"
        " INSERT OR IGNORE INTO includes(file_id,dep_path)"
        " SELECT f.id,e.dep_path FROM include_expected e"
        " JOIN files f ON f.path=e.source";
    static const char compare_sql[] =
        "WITH actual AS ("
        " SELECT f.path AS source,i.dep_path FROM includes i"
        " LEFT JOIN files f ON f.id=i.file_id),"
        " expected AS ("
        " SELECT e.source,e.dep_path FROM include_expected e"
        " JOIN files f ON f.path=e.source)"
        " SELECT NOT EXISTS(SELECT * FROM actual EXCEPT SELECT * FROM expected)"
        " AND NOT EXISTS(SELECT * FROM expected EXCEPT SELECT * FROM actual)";
    sqlite3 *db = ci_store_db(staged);
    sqlite3_stmt *insert = NULL;
    bool ok = sqlite3_exec(db, create_sql, NULL, NULL, NULL) == SQLITE_OK &&
              sqlite3_prepare_v2(db,
                  "INSERT OR IGNORE INTO include_expected(source,dep_path)"
                  " VALUES(?1,?2)", -1, &insert, NULL) == SQLITE_OK;
    if (!ok) LOG_ERROR("codeindex", "includes_reconcile stage=sql_setup sqlite=%d",
                       sqlite3_errcode(db));
    struct include_expected_edges expected = {.insert = insert, .ok = ok};
    if (ok) {
        bool scanned = ci_deps_scan_roots(root, include_expected_edge, &expected, parsed_root, parsed_stat);
        if (!scanned) LOG_ERROR("codeindex", "includes_reconcile stage=depfile_scan");
        else if (!expected.ok) LOG_ERROR("codeindex", "includes_reconcile stage=sql_insert sqlite=%d",
                                         sqlite3_errcode(db));
        ok = scanned && expected.ok;
    }
    if (insert) sqlite3_finalize(insert);
    if (ok) {
        ok = sqlite3_exec(db, rewrite_sql, NULL, NULL, NULL) == SQLITE_OK;
        if (!ok) LOG_ERROR("codeindex", "includes_reconcile stage=sql_rewrite sqlite=%d",
                           sqlite3_errcode(db));
    }
    if (ok) {
        ok = include_rows_match(db, compare_sql);
        if (!ok) LOG_ERROR("codeindex", "includes_reconcile stage=compare");
    }
    if (sqlite3_exec(db, "DROP TABLE IF EXISTS temp.include_expected", NULL,
                     NULL, NULL) != SQLITE_OK) {
        LOG_ERROR("codeindex", "includes_reconcile stage=sql_cleanup sqlite=%d",
                  sqlite3_errcode(db));
        ok = false;
    }
    return ok;
}

/* The reconciled rows match the fresh parse; seal its edge root. */
static bool include_stamp_edge_root(struct ci_store *staged)
{
    uint8_t edges[32];
    return ci_deps_include_edge_root(edges) &&
           ci_store_meta_set(staged, "include_edge_root_sha3", edges,
                             sizeof(edges));
}

/* Reconcile and seal from one scan; reject if its observed inventory does not
 * match the depfile metadata captured at the beginning of this build. */
bool ci_reconcile_includes(const char *root, struct ci_store *staged,
                           const uint8_t expected_stat[32])
{
    uint8_t dep_root[32], dep_stat[32];
    if (!reconcile_include_rows(root, staged, dep_root, dep_stat)) return false;
    if (memcmp(dep_stat, expected_stat, 32) != 0)
        LOG_FAIL("codeindex", "includes_reconcile stage=depfile_metadata_mismatch");
    if (!ci_store_meta_set(staged, "dep_root_sha3", dep_root, 32))
        LOG_FAIL("codeindex", "includes_reconcile stage=depfile_root_stamp");
    if (!include_stamp_edge_root(staged))
        LOG_FAIL("codeindex", "includes_reconcile stage=include_root_stamp");
    return true;
}


/* The latest reconciliation scan describes the include rows we just sealed.
 * Preserve its unsafe flag and reason so incomplete input cannot look exact. */
static bool incremental_refresh_include_narrow(struct ci_store *store)
{
    uint8_t edges[32], stored[32];
    size_t stored_len = 0;
    bool found = false;
    if (!ci_deps_include_edge_root(edges) ||
        !ci_store_meta_get(store, "include_edge_root_sha3", stored,
                           sizeof stored, &stored_len, &found))
        return false;
    bool rows_current = found && stored_len == sizeof stored &&
                        memcmp(stored, edges, sizeof edges) == 0;
    const char *bit =
        (!rows_current || ci_deps_include_narrow_unsafe()) ? "1" : "0";
    const char *cause = ci_deps_include_narrow_unsafe()
        ? ci_deps_include_narrow_cause()
        : (!rows_current ? "include_rows_stale" : "");
    return ci_store_meta_set(store, "include_narrow_unsafe", bit, 1) &&
           ci_store_meta_set(store, "include_narrow_cause", cause,
                             strlen(cause));
}

static bool incremental_stamp_projection_and_counts(struct ci_store *store)
{
    uint8_t projection_root[32];
    return incremental_refresh_include_narrow(store) &&
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

/* Replace every changed file's rows, in leaf order. */
static bool incremental_replace_changed(const char *root, struct ci_store *store,
                                        const struct ci_merkle_leaf *changed,
                                        int changed_count)
{
    for (int i = 0; i < changed_count; i++)
        if (!incremental_replace_file(root, store, changed[i].path))
            return false;
    return true;
}

/* Populate the private transaction, then seal the roots and projection that
 * describe its updated source rows and freshly reconciled dependencies. */
static bool incremental_refresh_contents(const char *root, struct ci_store *store,
                                         const struct ci_merkle_leaf *changed,
                                         int changed_count, const uint8_t dep_stat[32],
                                         const uint8_t merkle_root[32], bool rescan_deps)
{
    if (!incremental_replace_changed(root, store, changed, changed_count))
        LOG_FAIL("codeindex", "incremental stage=changed_file");
    if (!ci_docs_refresh(store, root))
        LOG_FAIL("codeindex", "incremental stage=docs_refresh");
    if (rescan_deps && !ci_reconcile_includes(root, store, dep_stat))
        LOG_FAIL("codeindex", "incremental stage=includes_reconcile");
    if (!incremental_seal_roots(store, dep_stat, merkle_root))
        LOG_FAIL("codeindex", "incremental stage=seal_roots");
    if (!incremental_stamp_projection_and_counts(store))
        LOG_FAIL("codeindex", "incremental stage=projection_counts");
    return true;
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
    if (!tx_open)
        LOG_FAIL("codeindex", "incremental stage=begin");
    bool ok = tx_open && incremental_refresh_contents(root, store, changed,
                   changed_count, dep_stat, merkle_root, rescan_deps);
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

static bool diff_merkle_append(struct ci_merkle_leaf *changed, int cap,
                               int *nchanged, const struct ci_merkle_leaf *leaf)
{
    if (*nchanged >= cap) return false;
    changed[(*nchanged)++] = *leaf;
    return true;
}

static bool diff_merkle_donor_row(sqlite3_stmt *statement, bool *donor_row,
                                  const char **path, const void **digest)
{
    if (!*donor_row) {
        int rc = sqlite3_step(statement); // raw-sql-ok:codeindex-derived
        if (rc != SQLITE_ROW) return false;
        *donor_row = true;
    }
    *path = (const char *)sqlite3_column_text(statement, 0);
    *digest = sqlite3_column_blob(statement, 1);
    return *path && *digest && sqlite3_column_bytes(statement, 1) == 32;
}

static bool diff_merkle_scan_rows(sqlite3_stmt *statement, int donor_count,
                                  const struct ci_merkle_leaf *current,
                                  int current_count,
                                  struct ci_merkle_leaf *changed, int cap,
                                  int *nchanged, int *overlap)
{
    int di = 0, ci = 0;
    bool donor_row = false;
    while (di < donor_count || ci < current_count) {
        const char *path = NULL;
        const void *digest = NULL;
        if (di < donor_count &&
            !diff_merkle_donor_row(statement, &donor_row, &path, &digest))
            return false;
        int cmp = di >= donor_count ? 1 : ci >= current_count ? -1 :
            strcmp(path, current[ci].path);
        if (cmp == 0) {
            (*overlap)++;
            if (memcmp(digest, current[ci].content_digest.bytes, 32) != 0 &&
                !diff_merkle_append(changed, cap, nchanged, &current[ci]))
                return false;
            di++;
            ci++;
            donor_row = false;
        } else if (cmp < 0) {
            struct ci_merkle_leaf removed;
            memset(&removed, 0, sizeof(removed));
            ci_cpy(removed.path, sizeof(removed.path), path);
            memcpy(removed.content_digest.bytes, digest, 32);
            if (!diff_merkle_append(changed, cap, nchanged, &removed))
                return false;
            di++;
            donor_row = false;
        } else {
            if (!diff_merkle_append(changed, cap, nchanged, &current[ci]))
                return false;
            ci++;
        }
    }
    return true;
}

int ci_store_diff_merkle_leaves(struct ci_store *store,
                                const struct ci_merkle_leaf *current,
                                int current_count,
                                struct ci_merkle_leaf *changed, int cap,
                                bool *inventory_same, int *inventory_overlap)
{
    if (inventory_same) *inventory_same = false;
    if (inventory_overlap) *inventory_overlap = 0;
    if (!diff_merkle_inputs_valid(store, current, current_count, changed, cap,
                                  inventory_same) || !inventory_overlap)
        LOG_ERR("codeindex", "invalid Merkle/store diff");
    int donor_count = ci_store_file_count(store);
    ci_store_lock(store);
    sqlite3_stmt *statement = NULL;
    sqlite3 *db = ci_store_db(store);
    bool ok = donor_count >= 0 && sqlite3_prepare_v2(db,
        "SELECT path,content_sha3 FROM files ORDER BY path", -1,
        &statement, NULL) == SQLITE_OK;
    int nchanged = 0;
    if (ok)
        ok = diff_merkle_scan_rows(statement, donor_count, current,
                                   current_count, changed, cap, &nchanged,
                                   inventory_overlap);
    sqlite3_finalize(statement);
    ci_store_unlock(store);
    if (!ok) return -1;
    *inventory_same = donor_count == current_count &&
                      *inventory_overlap == current_count;
    return nchanged;
}
