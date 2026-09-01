/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * anchor_kv -- implementation.  See storage/anchor_kv.h.
 *
 * This is a progress.kv kernel primitive.  Raw sqlite steps use the canonical
 * progress-kv marker from DEFENSIVE_CODING.md; callers own transaction scope. */

#include "storage/anchor_kv.h"

#include "core/serialize.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ANCHOR_SUBSYS "anchor_kv"

/* ── Verified-blob memo ─────────────────────────────────
 * Re-deriving a Sapling tree root costs ~10ms of Pedersen combines, and
 * fold/spend validation re-verifies a small working set of recent anchor
 * blobs over and over (anchor_kv_latest_tree per shielded block,
 * anchor_kv_get per Sapling spend). The memo binds
 * sha3_256(pool || blob) → "root integrity check passed":
 *  - the deserialize into `out` still runs on EVERY call (only the root
 *    recompute is skipped), so callers always get a fully-populated tree;
 *  - deserialization + root fold are pure functions of (pool, blob bytes),
 *    so a memo hit is byte-identical to a recompute;
 *  - tampering that flips any blob bit hash-misses, so the fail-closed
 *    check still fires on first sight of any distinct byte string.
 * Round-robin eviction, one mutex; 1024 entries cover a catch-up fold's
 * anchor working set (every add_tree notes its blob → same-boot hits). */
#define ANCHOR_VERIFY_MEMO_SIZE 1024
static struct {
    bool valid;
    uint8_t blob_hash[32];
} s_verify_memo[ANCHOR_VERIFY_MEMO_SIZE];
static size_t s_verify_memo_next;
static pthread_mutex_t s_verify_memo_mtx = PTHREAD_MUTEX_INITIALIZER;

static void anchor_blob_hash(int pool, const void *blob, size_t blob_len,
                             uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    uint8_t p = (uint8_t)pool;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &p, 1);
    sha3_256_write(&ctx, (const unsigned char *)blob, blob_len);
    sha3_256_finalize(&ctx, out);
}

static bool anchor_verify_memo_lookup(const uint8_t blob_hash[32])
{
    bool hit = false;
    pthread_mutex_lock(&s_verify_memo_mtx);
    for (size_t i = 0; i < ANCHOR_VERIFY_MEMO_SIZE; i++) {
        if (s_verify_memo[i].valid &&
            memcmp(s_verify_memo[i].blob_hash, blob_hash, 32) == 0) {
            hit = true;
            break;
        }
    }
    pthread_mutex_unlock(&s_verify_memo_mtx);
    return hit;
}

static void anchor_verify_memo_note(const uint8_t blob_hash[32])
{
    pthread_mutex_lock(&s_verify_memo_mtx);
    memcpy(s_verify_memo[s_verify_memo_next].blob_hash, blob_hash, 32);
    s_verify_memo[s_verify_memo_next].valid = true;
    s_verify_memo_next = (s_verify_memo_next + 1) % ANCHOR_VERIFY_MEMO_SIZE;
    pthread_mutex_unlock(&s_verify_memo_mtx);
}

static bool anchor_pool_valid(int pool)
{
    return pool == ANCHOR_POOL_SPROUT || pool == ANCHOR_POOL_SAPLING;
}

static const char *anchor_table(int pool)
{
    return pool == ANCHOR_POOL_SPROUT ? "sprout_anchors"
                                      : "sapling_anchors";
}

static void anchor_tree_init(int pool, struct incremental_merkle_tree *tree)
{
    if (pool == ANCHOR_POOL_SPROUT)
        sprout_tree_init(tree);
    else
        sapling_tree_init(tree);
}

static bool anchor_empty_tree(int pool, const struct uint256 *root,
                              struct incremental_merkle_tree *tree_out)
{
    struct incremental_merkle_tree empty;
    struct uint256 empty_root;
    anchor_tree_init(pool, &empty);
    incremental_tree_empty_root(&empty, &empty_root); /* cached constant */
    if (!uint256_eq(root, &empty_root))
        return false;
    if (tree_out)
        *tree_out = empty;
    return true;
}

bool anchor_kv_ensure_schema(sqlite3 *db)
{
    if (!db) {
        LOG_WARN(ANCHOR_SUBSYS, "ensure_schema: NULL db");
        return false;
    }
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS sprout_anchors ("
        "  anchor BLOB PRIMARY KEY NOT NULL,"
        "  height INTEGER NOT NULL,"
        "  tree BLOB NOT NULL"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS idx_sprout_anchors_height "
        "ON sprout_anchors(height);"
        "CREATE TABLE IF NOT EXISTS sapling_anchors ("
        "  anchor BLOB PRIMARY KEY NOT NULL,"
        "  height INTEGER NOT NULL,"
        "  tree BLOB NOT NULL"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS idx_sapling_anchors_height "
        "ON sapling_anchors(height);"
        "CREATE TABLE IF NOT EXISTS anchor_state ("
        "  pool INTEGER PRIMARY KEY NOT NULL,"
        "  activation_cursor INTEGER NOT NULL,"
        "  CHECK(typeof(pool)='integer' AND pool IN (0,1)),"
        "  CHECK(typeof(activation_cursor)='integer' AND "
        "        activation_cursor >= 0)"
        ") WITHOUT ROWID",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "ensure_schema failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) sqlite3_free(err);
    return true;
}

bool anchor_kv_initialize_history(sqlite3 *db, int64_t activation_cursor)
{
    if (!db || activation_cursor < 0) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "initialize_history: invalid args db=%p cursor=%lld",
                 (void *)db, (long long)activation_cursor);
        return false;
    }
    /* First adoption must not leave CREATEd tables without state rows after a
     * crash: absent state means unknown coverage.  Own a transaction when the
     * caller did not already provide one; refold/reset callers participate in
     * their existing progress.kv transaction. */
    bool own_tx = sqlite3_get_autocommit(db) != 0;
    char *err = NULL;
    if (own_tx && sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err)
                      != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "initialize BEGIN failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        return false;
    }
    if (!anchor_kv_ensure_schema(db)) {
        if (own_tx) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return false;
    }

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO anchor_state(pool,activation_cursor) "
            "VALUES(?,?)", -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "initialize prepare failed: %s",
                 sqlite3_errmsg(db));
        if (own_tx) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return false;
    }
    bool ok = true;
    for (int pool = ANCHOR_POOL_SPROUT; pool <= ANCHOR_POOL_SAPLING; pool++) {
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
        if (sqlite3_bind_int(s, 1, pool) != SQLITE_OK ||
            sqlite3_bind_int64(s, 2, (sqlite3_int64)activation_cursor)
                != SQLITE_OK) {
            LOG_WARN(ANCHOR_SUBSYS, "initialize bind failed: %s",
                     sqlite3_errmsg(db));
            ok = false;
            break;
        }
        int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
        if (rc != SQLITE_DONE) {
            LOG_WARN(ANCHOR_SUBSYS, "initialize step rc=%d: %s", rc,
                     sqlite3_errmsg(db));
            ok = false;
            break;
        }
    }
    sqlite3_finalize(s);
    /* INSERT OR IGNORE preserves legacy rows. Validate their durable storage
     * class before accepting initialization so a preexisting TEXT/BLOB/REAL
     * cursor cannot survive as a false complete zero via SQLite coercion. */
    for (int pool = ANCHOR_POOL_SPROUT;
         ok && pool <= ANCHOR_POOL_SAPLING; pool++) {
        int64_t persisted = 0;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, pool, &persisted, &found) ||
            !found)
            ok = false;
    }
    if (own_tx) {
        const char *finish = ok ? "COMMIT" : "ROLLBACK";
        err = NULL;
        if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
            LOG_WARN(ANCHOR_SUBSYS, "initialize %s failed: %s", finish,
                     err ? err : sqlite3_errmsg(db));
            if (err) sqlite3_free(err);
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return false;
        }
        if (err) sqlite3_free(err);
    }
    return ok;
}

bool anchor_kv_activation_cursor(sqlite3 *db, int pool,
                                 int64_t *cursor_out, bool *found_out)
{
    if (cursor_out) *cursor_out = 0;
    if (found_out) *found_out = false;
    if (!db || !anchor_pool_valid(pool) || !cursor_out || !found_out) {
        LOG_WARN(ANCHOR_SUBSYS, "activation_cursor: invalid args");
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT activation_cursor FROM anchor_state WHERE pool=?",
            -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "activation_cursor prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    if (sqlite3_bind_int(s, 1, pool) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "activation_cursor bind failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(s);
        return false;
    }
    bool ok = true;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int storage_type = sqlite3_column_type(s, 0);
        if (storage_type != SQLITE_INTEGER) {
            LOG_WARN(ANCHOR_SUBSYS,
                     "activation_cursor corrupt storage type=%d pool=%d",
                     storage_type, pool);
            ok = false;
        } else {
            *cursor_out = sqlite3_column_int64(s, 0);
            if (*cursor_out < 0) {
                LOG_WARN(ANCHOR_SUBSYS,
                         "activation_cursor corrupt negative value=%lld pool=%d",
                         (long long)*cursor_out, pool);
                ok = false;
            } else {
                *found_out = true;
            }
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN(ANCHOR_SUBSYS, "activation_cursor step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(s);
    return ok;
}

static bool anchor_deserialize_checked(int pool, const struct uint256 *want,
                                       const void *blob, int blob_len,
                                       struct incremental_merkle_tree *out)
{
    if (!blob || blob_len <= 0 || !out)
        return false;
    anchor_tree_init(pool, out);
    struct byte_stream bs;
    stream_init_from_data(&bs, blob, (size_t)blob_len);
    if (!incremental_tree_deserialize(out, &bs) ||
        stream_remaining(&bs) != 0) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "anchor tree decode failed pool=%d blob_len=%d remaining=%zu",
                 pool, blob_len, stream_remaining(&bs));
        return false;
    }
    uint8_t blob_hash[32];
    anchor_blob_hash(pool, blob, (size_t)blob_len, blob_hash);
    if (anchor_verify_memo_lookup(blob_hash))
        return true; /* this exact blob already passed the root check below */
    struct uint256 got;
    incremental_tree_root(out, &got);
    if (!uint256_eq(&got, want)) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "anchor tree/root mismatch pool=%d (durable row corrupt)",
                 pool);
        return false;
    }
    anchor_verify_memo_note(blob_hash);
    return true;
}

enum anchor_kv_lookup_result anchor_kv_get(
    sqlite3 *db, int pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out, int64_t *height_out)
{
    if (height_out) *height_out = -1;
    if (!db || !anchor_pool_valid(pool) || !root) {
        LOG_WARN(ANCHOR_SUBSYS, "get: invalid args");
        return ANCHOR_KV_ERROR;
    }
    if (anchor_empty_tree(pool, root, tree_out)) {
        if (height_out) *height_out = -1;
        return ANCHOR_KV_FOUND;
    }

    char sql[128];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT height,tree FROM %s WHERE anchor=?",
                     anchor_table(pool));
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return ANCHOR_KV_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "get prepare failed pool=%d: %s", pool,
                 sqlite3_errmsg(db));
        return ANCHOR_KV_ERROR;
    }
    if (sqlite3_bind_blob(s, 1, root->data, 32, SQLITE_TRANSIENT)
            != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "get bind failed: %s", sqlite3_errmsg(db));
        sqlite3_finalize(s);
        return ANCHOR_KV_ERROR;
    }
    enum anchor_kv_lookup_result result = ANCHOR_KV_MISSING;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(s, 1);
        int blob_len = sqlite3_column_bytes(s, 1);
        struct incremental_merkle_tree scratch;
        struct incremental_merkle_tree *dst = tree_out ? tree_out : &scratch;
        if (!anchor_deserialize_checked(pool, root, blob, blob_len, dst))
            result = ANCHOR_KV_ERROR;
        else {
            if (height_out) *height_out = sqlite3_column_int64(s, 0);
            result = ANCHOR_KV_FOUND;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN(ANCHOR_SUBSYS, "get step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        result = ANCHOR_KV_ERROR;
    }
    sqlite3_finalize(s);
    if (result != ANCHOR_KV_MISSING)
        return result;

    int64_t activation = 0;
    bool state_found = false;
    if (!anchor_kv_activation_cursor(db, pool, &activation, &state_found))
        return ANCHOR_KV_ERROR;
    /* Missing state is not proof of completeness.  Fail closed just like an
     * explicitly nonzero adoption cursor. */
    if (!state_found || activation > 0)
        return ANCHOR_KV_HISTORY_INCOMPLETE;
    return ANCHOR_KV_MISSING;
}

enum anchor_kv_lookup_result anchor_kv_latest_tree(
    sqlite3 *db, int pool, struct incremental_merkle_tree *tree_out,
    struct uint256 *root_out, int64_t *height_out)
{
    if (height_out) *height_out = -1;
    if (!db || !anchor_pool_valid(pool) || !tree_out) {
        LOG_WARN(ANCHOR_SUBSYS, "latest_tree: invalid args");
        return ANCHOR_KV_ERROR;
    }
    char sql[160];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT anchor,height,tree FROM %s "
                     "ORDER BY height DESC LIMIT 1", anchor_table(pool));
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return ANCHOR_KV_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "latest_tree prepare failed: %s",
                 sqlite3_errmsg(db));
        return ANCHOR_KV_ERROR;
    }
    enum anchor_kv_lookup_result result = ANCHOR_KV_HISTORY_INCOMPLETE;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const void *rblob = sqlite3_column_blob(s, 0);
        int rlen = sqlite3_column_bytes(s, 0);
        const void *tblob = sqlite3_column_blob(s, 2);
        int tlen = sqlite3_column_bytes(s, 2);
        struct uint256 root;
        if (!rblob || rlen != 32) {
            LOG_WARN(ANCHOR_SUBSYS, "latest_tree invalid root length=%d", rlen);
            result = ANCHOR_KV_ERROR;
        } else {
            memcpy(root.data, rblob, 32);
            if (!anchor_deserialize_checked(pool, &root, tblob, tlen,
                                            tree_out))
                result = ANCHOR_KV_ERROR;
            else {
                if (root_out) *root_out = root;
                if (height_out) *height_out = sqlite3_column_int64(s, 1);
                result = ANCHOR_KV_FOUND;
            }
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN(ANCHOR_SUBSYS, "latest_tree step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        result = ANCHOR_KV_ERROR;
    }
    sqlite3_finalize(s);
    if (result == ANCHOR_KV_FOUND || result == ANCHOR_KV_ERROR)
        return result;

    int64_t activation = 0;
    bool state_found = false;
    if (!anchor_kv_activation_cursor(db, pool, &activation, &state_found))
        return ANCHOR_KV_ERROR;
    if (!state_found || activation > 0)
        return ANCHOR_KV_HISTORY_INCOMPLETE;
    anchor_tree_init(pool, tree_out);
    if (root_out) incremental_tree_root(tree_out, root_out);
    return ANCHOR_KV_FOUND;
}

bool anchor_kv_add_tree(sqlite3 *db, int pool,
                        const struct incremental_merkle_tree *tree,
                        int64_t height)
{
    if (!db || !anchor_pool_valid(pool) || !tree || height < 0) {
        LOG_WARN(ANCHOR_SUBSYS, "add_tree: invalid args pool=%d height=%lld",
                 pool, (long long)height);
        return false;
    }
    struct uint256 root;
    incremental_tree_root(tree, &root);
    struct incremental_merkle_tree empty;
    struct uint256 empty_root;
    anchor_tree_init(pool, &empty);
    incremental_tree_empty_root(&empty, &empty_root); /* cached constant */
    if (uint256_eq(&root, &empty_root))
        return true;  /* implicit in zclassicd too */

    struct byte_stream bs;
    stream_init(&bs, 2048);
    if (!incremental_tree_serialize(tree, &bs)) {
        stream_free(&bs);
        LOG_WARN(ANCHOR_SUBSYS, "add_tree serialize failed pool=%d h=%lld",
                 pool, (long long)height);
        return false;
    }
    char sql[192];
    int n = snprintf(sql, sizeof(sql),
        "INSERT OR IGNORE INTO %s(anchor,height,tree) VALUES(?,?,?)",
        anchor_table(pool));
    if (n <= 0 || (size_t)n >= sizeof(sql)) {
        stream_free(&bs);
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "add_tree prepare failed: %s",
                 sqlite3_errmsg(db));
        stream_free(&bs);
        return false;
    }
    bool bound =
        sqlite3_bind_blob(s, 1, root.data, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(s, 2, (sqlite3_int64)height) == SQLITE_OK &&
        sqlite3_bind_blob(s, 3, bs.data, (int)bs.size, SQLITE_TRANSIENT)
            == SQLITE_OK;
    if (!bound) {
        LOG_WARN(ANCHOR_SUBSYS, "add_tree bind failed: %s", sqlite3_errmsg(db));
        sqlite3_finalize(s);
        stream_free(&bs);
        return false;
    }
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    if (rc == SQLITE_DONE) {
        /* This blob's root IS the row key by construction, so it is verified
         * without a re-fold: note it for same-boot latest_tree/spend gets. */
        uint8_t blob_hash[32];
        anchor_blob_hash(pool, bs.data, bs.size, blob_hash);
        anchor_verify_memo_note(blob_hash);
    }
    stream_free(&bs);
    if (rc != SQLITE_DONE) {
        LOG_WARN(ANCHOR_SUBSYS, "add_tree step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        return false;
    }
    return true;
}

bool anchor_kv_max_height(sqlite3 *db, int pool, int64_t *out_height)
{
    if (out_height) *out_height = -1;
    if (!db || !anchor_pool_valid(pool) || !out_height) {
        LOG_WARN(ANCHOR_SUBSYS, "max_height: invalid args pool=%d", pool);
        return false;
    }
    char sql[96];
    int n = snprintf(sql, sizeof(sql), "SELECT MAX(height) FROM %s",
                     anchor_table(pool));
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "max_height prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        /* MAX() over an empty table yields SQL NULL — column_type == NULL,
         * which we map to -1 (no rows). A real max is a non-negative height. */
        if (sqlite3_column_type(s, 0) == SQLITE_NULL)
            *out_height = -1;
        else
            *out_height = sqlite3_column_int64(s, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN(ANCHOR_SUBSYS, "max_height step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(s);
    return ok;
}

bool anchor_kv_delete_range(sqlite3 *db, int64_t first_height,
                            int64_t last_height)
{
    if (!db || first_height < 0 || last_height < first_height) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "delete_range: invalid args first=%lld last=%lld",
                 (long long)first_height, (long long)last_height);
        return false;
    }
    sqlite3_stmt *s = NULL;
    for (int pool = ANCHOR_POOL_SPROUT; pool <= ANCHOR_POOL_SAPLING; pool++) {
        char sql[128];
        int n = snprintf(sql, sizeof(sql),
                         "DELETE FROM %s WHERE height>=? AND height<=?",
                         anchor_table(pool));
        if (n <= 0 || (size_t)n >= sizeof(sql) ||
            sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
            LOG_WARN(ANCHOR_SUBSYS, "delete_range prepare failed: %s",
                     sqlite3_errmsg(db));
            return false;
        }
        if (sqlite3_bind_int64(s, 1, (sqlite3_int64)first_height)
                != SQLITE_OK ||
            sqlite3_bind_int64(s, 2, (sqlite3_int64)last_height)
                != SQLITE_OK) {
            LOG_WARN(ANCHOR_SUBSYS, "delete_range bind failed: %s",
                     sqlite3_errmsg(db));
            sqlite3_finalize(s);
            return false;
        }
        int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
        sqlite3_finalize(s);
        s = NULL;
        if (rc != SQLITE_DONE) {
            LOG_WARN(ANCHOR_SUBSYS, "delete_range step rc=%d: %s", rc,
                     sqlite3_errmsg(db));
            return false;
        }
    }
    return true;
}

/* Shared reset body for both typed entry points below.  They differ ONLY in
 * the adoption cursor they stamp — 0 for a from-genesis COMPLETE history, a
 * positive height for an EMPTY-BELOW-N gap — so the SQL, transaction scope, and
 * markers are identical regardless of which caller invoked it. */
static bool anchor_kv_reset_impl_in_tx(sqlite3 *db, int64_t activation_cursor)
{
    if (!db || activation_cursor < 0) {
        LOG_WARN(ANCHOR_SUBSYS, "reset: invalid args cursor=%lld",
                 (long long)activation_cursor);
        return false;
    }
    if (!anchor_kv_ensure_schema(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db,
            "DELETE FROM sprout_anchors; DELETE FROM sapling_anchors; "
            "DELETE FROM anchor_state", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "reset delete failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) sqlite3_free(err);
    return anchor_kv_initialize_history(db, activation_cursor);
}

bool anchor_kv_reset_mark_complete_in_tx(sqlite3 *db)
{
    return anchor_kv_reset_impl_in_tx(db, 0);
}

bool anchor_kv_reset_mark_empty_below_in_tx(sqlite3 *db, int64_t below_height)
{
    return anchor_kv_reset_impl_in_tx(db, below_height);
}

bool anchor_kv_publish_full_replay_complete_in_tx(
    sqlite3 *db, int64_t expected_boundary)
{
    if (!db || expected_boundary <= 0) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "publish complete: invalid boundary=%lld",
                 (long long)expected_boundary);
        return false;
    }
    if (sqlite3_get_autocommit(db) != 0) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "publish complete requires caller transaction");
        return false;
    }
    if (!anchor_kv_ensure_schema(db))
        return false;

    /* Refuse before the UPDATE if either component is absent, malformed, or
     * no longer names this exact replay generation. */
    for (int pool = ANCHOR_POOL_SPROUT;
         pool <= ANCHOR_POOL_SAPLING; pool++) {
        int64_t cursor = -1;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, pool, &cursor, &found) ||
            !found || cursor != expected_boundary) {
            LOG_WARN(ANCHOR_SUBSYS,
                     "publish complete boundary mismatch pool=%d got=%lld "
                     "found=%d expected=%lld",
                     pool, (long long)cursor, found ? 1 : 0,
                     (long long)expected_boundary);
            return false;
        }
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "UPDATE anchor_state SET activation_cursor=0 "
            "WHERE activation_cursor=? AND pool IN(0,1)",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "publish complete prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool ok = sqlite3_bind_int64(
                  st, 1, (sqlite3_int64)expected_boundary) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (!ok || rc != SQLITE_DONE || sqlite3_changes(db) != 2) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "publish complete update failed rc=%d changed=%d: %s",
                 rc, sqlite3_changes(db), sqlite3_errmsg(db));
        return false;
    }

    for (int pool = ANCHOR_POOL_SPROUT;
         pool <= ANCHOR_POOL_SAPLING; pool++) {
        int64_t cursor = -1;
        bool found = false;
        if (!anchor_kv_activation_cursor(db, pool, &cursor, &found) ||
            !found || cursor != 0) {
            LOG_WARN(ANCHOR_SUBSYS,
                     "publish complete zero verification failed pool=%d",
                     pool);
            return false;
        }
    }
    return true;
}

bool anchor_kv_table_is_empty(sqlite3 *db, int pool, bool *empty_out)
{
    if (empty_out) *empty_out = false;
    if (!db || !anchor_pool_valid(pool) || !empty_out) {
        LOG_WARN(ANCHOR_SUBSYS, "table_is_empty: invalid args");
        return false;
    }
    char sql[96];
    int n = snprintf(sql, sizeof(sql), "SELECT 1 FROM %s LIMIT 1",
                     anchor_table(pool));
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "table_is_empty prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_DONE) {
        *empty_out = true;
    } else if (rc == SQLITE_ROW) {
        *empty_out = false;
    } else {
        LOG_WARN(ANCHOR_SUBSYS, "table_is_empty step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(s);
    return ok;
}

bool anchor_kv_row_count(sqlite3 *db, int pool, int64_t *count_out)
{
    if (count_out) *count_out = 0;
    if (!db || !anchor_pool_valid(pool) || !count_out) {
        LOG_WARN(ANCHOR_SUBSYS, "row_count: invalid args");
        return false;
    }
    char sql[96];
    int n = snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s",
                     anchor_table(pool));
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(ANCHOR_SUBSYS, "row_count prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *count_out = sqlite3_column_int64(s, 0);
    } else {
        LOG_WARN(ANCHOR_SUBSYS, "row_count step rc=%d: %s", rc,
                 sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(s);
    return ok;
}

bool anchor_kv_seed_frontier_row(sqlite3 *db, int pool,
                                 const struct incremental_merkle_tree *tree,
                                 int64_t height,
                                 const struct uint256 *expected_root)
{
    if (!db || !anchor_pool_valid(pool) || !tree || height < 0 ||
        !expected_root) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "seed_frontier_row: invalid args pool=%d height=%lld",
                 pool, (long long)height);
        return false;
    }
    /* Recompute the frontier's own root and REFUSE unless it equals the
     * header-bound expected root.  This is the sole guard that keeps an
     * unverified frontier out of the store: a mismatch writes nothing, so the
     * fold keeps failing closed (consensus accept/reject unchanged) rather than
     * threading against a forged/wrong frontier. */
    struct uint256 got;
    incremental_tree_root(tree, &got);
    if (!uint256_eq(&got, expected_root)) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "seed_frontier_row REFUSED pool=%d height=%lld: computed root "
                 "!= expected header root — writing nothing (fail-closed)",
                 pool, (long long)height);
        return false;
    }
    /* anchor_kv_add_tree is idempotent and treats the empty tree as an
     * implicit no-op success (matching zclassicd's implicit empty root). */
    if (!anchor_kv_add_tree(db, pool, tree, height)) {
        LOG_WARN(ANCHOR_SUBSYS,
                 "seed_frontier_row: add_tree failed pool=%d height=%lld",
                 pool, (long long)height);
        return false;
    }
    return true;
}
