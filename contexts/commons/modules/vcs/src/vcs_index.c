/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_index — implementation. See vcs/vcs_index.h.
 *
 * ── OUTSIDE the node.db ActiveRecord lifecycle by design ──
 * index.kv is a dedicated single-writer SQLite WAL file below the AR layer,
 * exactly like progress.kv (storage/progress_store.c) and seal_kv. Its rows
 * are not models; routing them through AR would be a category error. Raw
 * sqlite3_step here therefore carries the `// raw-sql-ok:vcs-index-kernel-store`
 * marker, and the store is fully DERIVED (rebuildable from the worktree +
 * commits.log by vcs_index_rebuild — "recompute, never repair"). */

#include "vcs/vcs_index.h"
#include "vcs/vcs_commit.h"
#include "vcs/vcs_manifest.h"

#include "vcs_priv.h"
#include "vcs_walk.h"

#include "platform/time_compat.h"
#include "storage/event_log.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VCS_INDEX_PATH_MAX 4096

struct vcs_index {
    sqlite3        *db;
    pthread_mutex_t lock;   /* recursive: held begin..commit; reads take briefly */
    char            repo_root[VCS_INDEX_PATH_MAX];
};

static int64_t wall_now_s(void)
{
    return platform_time_wall_unix();
}

static bool apply_pragmas(sqlite3 *db)
{
    static const char *const pragmas[] = {
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA busy_timeout=5000",
        NULL,
    };
    for (size_t i = 0; pragmas[i]; i++) {
        char *err = NULL;
        if (sqlite3_exec(db, pragmas[i], NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "[vcs] pragma failed (%s): %s\n",  // obs-ok:vcs-index-open-failure
                    pragmas[i], err ? err : "(no message)");
            if (err) sqlite3_free(err);
            return false;
        }
    }
    return true;
}

static bool ensure_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stat_cache ("
        "  path TEXT PRIMARY KEY,"
        "  mtime_ns INTEGER NOT NULL,"
        "  size INTEGER NOT NULL,"
        "  ctime_ns INTEGER NOT NULL,"
        "  blob_hash BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS refs ("
        "  name TEXT PRIMARY KEY,"
        "  commit_id BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS seal_pin ("
        "  id INTEGER PRIMARY KEY CHECK(id=0),"
        "  sealset_hash BLOB NOT NULL,"
        "  updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS anchor ("
        "  commit_id BLOB PRIMARY KEY,"
        "  generation_sha256 BLOB NOT NULL,"
        "  verdict_status INTEGER NOT NULL,"
        "  bound_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS meta ("
        "  key TEXT PRIMARY KEY,"
        "  value BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS package_blob_map ("
        "  blob_hash BLOB PRIMARY KEY,"
        "  mapping_root BLOB NOT NULL);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[vcs] schema failed: %s\n",  // obs-ok:vcs-index-open-failure
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

struct vcs_index *vcs_index_open(const char *repo_root)
{
    if (!repo_root || !repo_root[0])
        LOG_NULL("vcs", "null repo_root");

    struct vcs_index *idx = zcl_calloc(1, sizeof(*idx), "vcs_index");
    if (!idx)
        LOG_NULL("vcs", "calloc vcs_index");

    int n = snprintf(idx->repo_root, sizeof(idx->repo_root), "%s", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(idx->repo_root)) {
        free(idx);
        LOG_NULL("vcs", "repo_root too long");
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&idx->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    char path[VCS_INDEX_PATH_MAX];
    int pn = snprintf(path, sizeof(path), "%s/.zvcs/index.kv", repo_root);
    if (pn <= 0 || (size_t)pn >= sizeof(path)) {
        pthread_mutex_destroy(&idx->lock);
        free(idx);
        LOG_NULL("vcs", "index path too long");
    }

    if (sqlite3_open(path, &idx->db) != SQLITE_OK) {
        fprintf(stderr, "[vcs] sqlite3_open %s: %s\n",  // obs-ok:vcs-index-open-failure
                path, idx->db ? sqlite3_errmsg(idx->db) : "(no handle)");
        if (idx->db) sqlite3_close(idx->db);
        pthread_mutex_destroy(&idx->lock);
        free(idx);
        return NULL;
    }
    if (!apply_pragmas(idx->db) || !ensure_schema(idx->db)) {
        sqlite3_close(idx->db);
        pthread_mutex_destroy(&idx->lock);
        free(idx);
        LOG_NULL("vcs", "index open: pragmas/schema failed");
    }
    return idx;
}

void vcs_index_close(struct vcs_index *idx)
{
    if (!idx) return;
    if (idx->db) {
        sqlite3_exec(idx->db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL);
        sqlite3_close(idx->db);
    }
    pthread_mutex_destroy(&idx->lock);
    free(idx);
}

/* ── transaction control ─────────────────────────────────────────── */

bool vcs_index_begin(struct vcs_index *idx)
{
    if (!idx) LOG_FAIL("vcs", "null idx");
    pthread_mutex_lock(&idx->lock);
    char *err = NULL;
    if (sqlite3_exec(idx->db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        pthread_mutex_unlock(&idx->lock);
        LOG_FAIL("vcs", "BEGIN IMMEDIATE failed");
    }
    return true;
}

bool vcs_index_commit(struct vcs_index *idx)
{
    if (!idx) LOG_FAIL("vcs", "null idx");
    char *err = NULL;
    bool ok = sqlite3_exec(idx->db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    pthread_mutex_unlock(&idx->lock);
    if (!ok) LOG_FAIL("vcs", "COMMIT failed");
    return true;
}

bool vcs_index_rollback(struct vcs_index *idx)
{
    if (!idx) LOG_FAIL("vcs", "null idx");
    char *err = NULL;
    sqlite3_exec(idx->db, "ROLLBACK", NULL, NULL, &err);
    if (err) sqlite3_free(err);
    pthread_mutex_unlock(&idx->lock);
    return true;
}

/* ── writes (in an open txn) ─────────────────────────────────────── */

bool vcs_index_stat_put_in_tx(struct vcs_index *idx, const char *path,
                              int64_t mtime_ns, int64_t size, int64_t ctime_ns,
                              const uint8_t blob[32])
{
    if (!idx || !path || !path[0] || !blob)
        LOG_FAIL("vcs", "null arg to stat_put");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO stat_cache(path,mtime_ns,size,ctime_ns,blob_hash)"
        " VALUES(?,?,?,?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare stat_put: %s", sqlite3_errmsg(idx->db));
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, mtime_ns);
    sqlite3_bind_int64(stmt, 3, size);
    sqlite3_bind_int64(stmt, 4, ctime_ns);
    sqlite3_bind_blob(stmt, 5, blob, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step stat_put rc=%d", rc);
    return true;
}

bool vcs_index_stat_prune_in_tx(struct vcs_index *idx,
                                const struct vcs_manifest *manifest)
{
    if (!idx || !manifest)
        LOG_FAIL("vcs", "null arg to stat_prune");

    /* A TEMP table keeps the one generic DELETE bounded to the manifest and
     * avoids preparing one DELETE per stale row. TEMP writes never enter the
     * durable WAL; only rows actually removed from stat_cache do. */
    char *err = NULL;
    if (sqlite3_exec(idx->db,
        "CREATE TEMP TABLE IF NOT EXISTS current_stat_paths("
        "path TEXT PRIMARY KEY) WITHOUT ROWID;"
        "DELETE FROM current_stat_paths;", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        LOG_FAIL("vcs", "prepare stat prune set");
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT INTO current_stat_paths(path) VALUES(?)", -1, &stmt, NULL) !=
        SQLITE_OK)
        LOG_FAIL("vcs", "prepare stat prune insert: %s",
                 sqlite3_errmsg(idx->db));
    for (size_t i = 0; i < manifest->count; i++) {
        sqlite3_bind_text(stmt, 1, manifest->entries[i].path, -1,
                          SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            LOG_FAIL("vcs", "step stat prune insert rc=%d", rc);
        }
    }
    sqlite3_finalize(stmt);

    err = NULL;
    if (sqlite3_exec(idx->db,
        "DELETE FROM stat_cache WHERE NOT EXISTS ("
        "SELECT 1 FROM current_stat_paths p WHERE p.path=stat_cache.path)",
        NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        LOG_FAIL("vcs", "delete stale stat rows");
    }
    return true;
}

bool vcs_index_package_map_put_in_tx(
    struct vcs_index *idx, const uint8_t blob_root[32],
    const uint8_t mapping_root[32])
{
    if (!idx || !blob_root || !mapping_root)
        LOG_FAIL("vcs", "null arg to package_map_put");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO package_blob_map(blob_hash,mapping_root)"
        " VALUES(?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare package_map_put: %s",
                 sqlite3_errmsg(idx->db));
    sqlite3_bind_blob(stmt, 1, blob_root, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, mapping_root, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step package_map_put rc=%d", rc);
    return true;
}

bool vcs_index_ref_set_in_tx(struct vcs_index *idx, const char *name,
                             const uint8_t commit_id[32])
{
    if (!idx || !name || !name[0] || !commit_id)
        LOG_FAIL("vcs", "null arg to ref_set");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO refs(name,commit_id) VALUES(?,?)",
        -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare ref_set: %s", sqlite3_errmsg(idx->db));
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, commit_id, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step ref_set rc=%d", rc);
    return true;
}

bool vcs_index_seal_pin_set_in_tx(struct vcs_index *idx,
                                  const uint8_t sealset_hash[32])
{
    if (!idx || !sealset_hash)
        LOG_FAIL("vcs", "null arg to seal_pin_set");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO seal_pin(id,sealset_hash,updated_at)"
        " VALUES(0,?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare seal_pin_set: %s", sqlite3_errmsg(idx->db));
    sqlite3_bind_blob(stmt, 1, sealset_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, wall_now_s());
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step seal_pin_set rc=%d", rc);
    return true;
}

bool vcs_index_anchor_put_in_tx(struct vcs_index *idx, const uint8_t commit_id[32],
                                const uint8_t generation_sha256[32],
                                uint32_t verdict_status)
{
    if (!idx || !commit_id || !generation_sha256)
        LOG_FAIL("vcs", "null arg to anchor_put");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO anchor(commit_id,generation_sha256,verdict_status,bound_at)"
        " VALUES(?,?,?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare anchor_put: %s", sqlite3_errmsg(idx->db));
    sqlite3_bind_blob(stmt, 1, commit_id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, generation_sha256, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (int64_t)verdict_status);
    sqlite3_bind_int64(stmt, 4, wall_now_s());
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step anchor_put rc=%d", rc);
    return true;
}

bool vcs_index_meta_set_in_tx(struct vcs_index *idx, const char *key,
                              const void *value, size_t value_len)
{
    if (!idx || !key || !key[0] || (value_len > 0 && !value))
        LOG_FAIL("vcs", "null arg to meta_set");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
        -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare meta_set: %s", sqlite3_errmsg(idx->db));
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, value ? value : "", (int)value_len, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step meta_set rc=%d", rc);
    return true;
}

bool vcs_index_meta_delete_in_tx(struct vcs_index *idx, const char *key)
{
    if (!idx || !key || !key[0])
        LOG_FAIL("vcs", "null arg to meta_delete");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "DELETE FROM meta WHERE key=?", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("vcs", "prepare meta_delete: %s", sqlite3_errmsg(idx->db));
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("vcs", "step meta_delete rc=%d", rc);
    return true;
}

/* ── reads ───────────────────────────────────────────────────────── */

bool vcs_index_ref_get(struct vcs_index *idx, const char *name,
                       uint8_t commit_id[32], bool *found)
{
    if (found) *found = false;
    if (!idx || !name || !name[0] || !commit_id)
        LOG_FAIL("vcs", "null arg to ref_get");
    pthread_mutex_lock(&idx->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db, "SELECT commit_id FROM refs WHERE name=?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&idx->lock);
        LOG_FAIL("vcs", "prepare ref_get");
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    if (rc == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(stmt, 0);
        int n = sqlite3_column_bytes(stmt, 0);
        if (b && n == 32) {
            memcpy(commit_id, b, 32);
            if (found) *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&idx->lock);
    if (!ok) LOG_FAIL("vcs", "step ref_get");
    return true;
}

bool vcs_index_seal_pin_get(struct vcs_index *idx, uint8_t sealset_hash[32],
                            bool *found)
{
    if (found) *found = false;
    if (!idx || !sealset_hash)
        LOG_FAIL("vcs", "null arg to seal_pin_get");
    pthread_mutex_lock(&idx->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db, "SELECT sealset_hash FROM seal_pin WHERE id=0",
                           -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&idx->lock);
        LOG_FAIL("vcs", "prepare seal_pin_get");
    }
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    if (rc == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(stmt, 0);
        int n = sqlite3_column_bytes(stmt, 0);
        if (b && n == 32) {
            memcpy(sealset_hash, b, 32);
            if (found) *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&idx->lock);
    if (!ok) LOG_FAIL("vcs", "step seal_pin_get");
    return true;
}

bool vcs_index_meta_get(struct vcs_index *idx, const char *key, void *out_buf,
                        size_t out_cap, size_t *out_len, bool *found)
{
    if (found) *found = false;
    if (out_len) *out_len = 0;
    if (!idx || !key || !key[0])
        LOG_FAIL("vcs", "null arg to meta_get");
    pthread_mutex_lock(&idx->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db, "SELECT value FROM meta WHERE key=?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&idx->lock);
        LOG_FAIL("vcs", "prepare meta_get");
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    if (rc == SQLITE_ROW) {
        if (found) *found = true;
        int n = sqlite3_column_bytes(stmt, 0);
        const void *b = sqlite3_column_blob(stmt, 0);
        if (out_len) *out_len = (size_t)n;
        if (out_buf && out_cap > 0 && b) {
            size_t copy = (size_t)n < out_cap ? (size_t)n : out_cap;
            if (copy > 0) memcpy(out_buf, b, copy);
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&idx->lock);
    if (!ok) LOG_FAIL("vcs", "step meta_get");
    return true;
}

bool vcs_index_package_map_get(
    struct vcs_index *idx, const uint8_t blob_root[32],
    uint8_t mapping_root[32], bool *found)
{
    if (found) *found = false;
    if (!idx || !blob_root || !mapping_root)
        LOG_FAIL("vcs", "null arg to package_map_get");
    memset(mapping_root, 0, 32);
    pthread_mutex_lock(&idx->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            idx->db,
            "SELECT mapping_root FROM package_blob_map WHERE blob_hash=?",
            -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&idx->lock);
        LOG_FAIL("vcs", "prepare package_map_get");
    }
    sqlite3_bind_blob(stmt, 1, blob_root, 32, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:vcs-index-kernel-store
    if (rc == SQLITE_ROW) {
        const void *bytes = sqlite3_column_blob(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (!bytes || len != 32)
            ok = false;
        else {
            memcpy(mapping_root, bytes, 32);
            if (found) *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&idx->lock);
    if (!ok) LOG_FAIL("vcs", "step package_map_get");
    return true;
}

/* ── in-memory stat-cache snapshot ───────────────────────────────── */

bool vcs_stat_cache_load(struct vcs_index *idx, struct vcs_stat_cache *out)
{
    if (!idx || !out)
        LOG_FAIL("vcs", "null arg to stat_cache_load");
    out->rows = NULL;
    out->count = 0;
    out->cap = 0;

    pthread_mutex_lock(&idx->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(idx->db,
        "SELECT path,mtime_ns,size,ctime_ns,blob_hash FROM stat_cache ORDER BY path",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&idx->lock);
        LOG_FAIL("vcs", "prepare stat_cache_load");
    }
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:vcs-index-kernel-store
        if (out->count == out->cap) {
            size_t ncap = out->cap ? out->cap * 2 : 256;
            struct vcs_stat_row *nr =
                zcl_realloc(out->rows, ncap * sizeof(*nr), "vcs_stat_rows");
            if (!nr) { ok = false; break; }
            out->rows = nr;
            out->cap = ncap;
        }
        struct vcs_stat_row *r = &out->rows[out->count];
        const unsigned char *p = sqlite3_column_text(stmt, 0);
        r->path = zcl_strdup(p ? (const char *)p : "", "vcs_stat_path");
        if (!r->path) { ok = false; break; }
        r->mtime_ns = sqlite3_column_int64(stmt, 1);
        r->size = sqlite3_column_int64(stmt, 2);
        r->ctime_ns = sqlite3_column_int64(stmt, 3);
        const void *b = sqlite3_column_blob(stmt, 4);
        int n = sqlite3_column_bytes(stmt, 4);
        memset(r->blob, 0, 32);
        if (b && n == 32) memcpy(r->blob, b, 32);
        out->count++;
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        ok = false;
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&idx->lock);
    if (!ok) {
        vcs_stat_cache_free(out);
        LOG_FAIL("vcs", "stat_cache_load failed");
    }
    return true;
}

void vcs_stat_cache_free(struct vcs_stat_cache *sc)
{
    if (!sc) return;
    for (size_t i = 0; i < sc->count; i++)
        free(sc->rows[i].path);
    free(sc->rows);
    sc->rows = NULL;
    sc->count = 0;
    sc->cap = 0;
}

const struct vcs_stat_row *vcs_stat_cache_find(const struct vcs_stat_cache *sc,
                                               const char *path)
{
    if (!sc || !path || sc->count == 0)
        return NULL;
    size_t lo = 0, hi = sc->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(sc->rows[mid].path, path);
        if (c == 0) return &sc->rows[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

/* ── rebuild (recompute, never repair) ───────────────────────────── */

struct rebuild_replay_ctx {
    struct vcs_index *idx;
    bool err;
};

static bool rebuild_replay_cb(uint64_t offset, enum event_log_type type,
                              const void *payload, size_t len, void *user)
{
    (void)offset;
    struct rebuild_replay_ctx *c = user;
    if (type != EV_VCS_COMMIT || len != VCS_COMMIT_RECORD_BYTES)
        return true;  /* not a commit / wrong size — ignore, keep replaying */
    struct vcs_commit cm;
    bool self_ok = false;
    if (!vcs_commit_deserialize((const uint8_t *)payload, len, &cm, &self_ok) ||
        !self_ok)
        return true;  /* skip a corrupt record; recompute-never-repair */
    uint8_t cid[32];
    vcs_commit_id(&cm, cid);
    if (!vcs_index_ref_set_in_tx(c->idx, "HEAD", cid) ||
        !vcs_index_seal_pin_set_in_tx(c->idx, cm.sealset_hash) ||
        !vcs_index_anchor_put_in_tx(c->idx, cid, cm.generation_sha256,
                                    cm.verdict_status)) {
        c->err = true;
        return false;
    }
    return true;
}

struct rebuild_stat_ctx {
    struct vcs_index *idx;
    bool err;
};

static bool rebuild_stat_cb(const char *relpath, uint32_t mode, uint64_t size,
                            int64_t mtime_ns, int64_t ctime_ns, void *user)
{
    (void)mode;
    struct rebuild_stat_ctx *c = user;
    uint8_t blob[32];
    if (!vcs_blob_hash_file(c->idx->repo_root, relpath, blob)) {
        c->err = true;
        return false;
    }
    if (!vcs_index_stat_put_in_tx(c->idx, relpath, mtime_ns, (int64_t)size,
                                  ctime_ns, blob)) {
        c->err = true;
        return false;
    }
    return true;
}

bool vcs_index_rebuild(struct vcs_index *idx, const char *repo_root)
{
    if (!idx || !repo_root)
        LOG_FAIL("vcs", "null arg to rebuild");

    /* Phase 1: clear + replay commits.log to rebuild HEAD/anchor/seal_pin. */
    if (!vcs_index_begin(idx))
        LOG_FAIL("vcs", "rebuild: begin (phase 1)");
    char *err = NULL;
    if (sqlite3_exec(idx->db,
        "DELETE FROM stat_cache; DELETE FROM refs; DELETE FROM seal_pin;"
        " DELETE FROM anchor; DELETE FROM package_blob_map;",
        NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        vcs_index_rollback(idx);
        LOG_FAIL("vcs", "rebuild: clear tables");
    }

    char logpath[VCS_INDEX_PATH_MAX];
    int ln = snprintf(logpath, sizeof(logpath), "%s/.zvcs/commits.log", repo_root);
    if (ln <= 0 || (size_t)ln >= sizeof(logpath)) {
        vcs_index_rollback(idx);
        LOG_FAIL("vcs", "rebuild: log path too long");
    }

    event_log_t *log = event_log_open(logpath);
    if (log) {
        struct rebuild_replay_ctx rctx = { idx, false };
        event_log_stream(log, 0, rebuild_replay_cb, &rctx);
        event_log_close(log);
        if (rctx.err) {
            vcs_index_rollback(idx);
            LOG_FAIL("vcs", "rebuild: replay write failed");
        }
    }
    if (!vcs_index_commit(idx))
        LOG_FAIL("vcs", "rebuild: commit (phase 1)");

    /* Phase 2: rehash the worktree into stat_cache. */
    if (!vcs_index_begin(idx))
        LOG_FAIL("vcs", "rebuild: begin (phase 2)");
    struct rebuild_stat_ctx rc = { idx, false };
    bool walked = vcs_walk_tracked(repo_root, rebuild_stat_cb, &rc);
    if (!walked || rc.err) {
        vcs_index_rollback(idx);
        LOG_FAIL("vcs", "rebuild: worktree rehash failed");
    }
    if (!vcs_index_commit(idx))
        LOG_FAIL("vcs", "rebuild: commit (phase 2)");
    return true;
}
