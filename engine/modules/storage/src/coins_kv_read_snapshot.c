/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: pin and validate one canonical coins_kv WAL generation for export. */
#include "storage/coins_kv_read_snapshot.h"

#include "core/amount.h"
#include "script/script.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct coins_kv_read_snapshot {
    sqlite3 *db;
    sqlite3_stmt *rows;
    uint8_t *script;
    size_t script_cap;
    uint8_t last_txid[32];
    uint32_t last_vout;
    int32_t applied_height;
    bool have_last;
    bool transaction_open;
    bool exhausted;
    bool failed;
};

static bool snapshot_exec(sqlite3 *db, const char *sql, const char *operation)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        LOG_WARN("coins_kv_read_snapshot", "%s failed rc=%d: %s",
                 operation, rc, error ? error : sqlite3_errmsg(db));
        sqlite3_free(error);
        return false;
    }
    return true;
}

static bool snapshot_release(struct coins_kv_read_snapshot *snapshot,
                             bool commit)
{
    if (!snapshot)
        return false;
    bool ok = true;
    if (snapshot->rows) {
        int rc = sqlite3_finalize(snapshot->rows);
        if (rc != SQLITE_OK) {
            LOG_WARN("coins_kv_read_snapshot", "row finalize failed rc=%d", rc);
            ok = false;
        }
        snapshot->rows = NULL;
    }
    if (snapshot->transaction_open) {
        bool ended = snapshot_exec(snapshot->db, commit ? "COMMIT" : "ROLLBACK",
                                   commit ? "COMMIT" : "ROLLBACK");
        if (!ended && commit)
            (void)snapshot_exec(snapshot->db, "ROLLBACK", "rollback after COMMIT failure");
        ok = ok && ended;
        snapshot->transaction_open = false;
    }
    if (snapshot->db) {
        int rc = sqlite3_close(snapshot->db);
        if (rc != SQLITE_OK) {
            LOG_WARN("coins_kv_read_snapshot", "reader close failed rc=%d", rc);
            ok = false;
        }
    }
    free(snapshot->script);
    free(snapshot);
    return ok;
}

struct coins_kv_read_snapshot *coins_kv_read_snapshot_open(
    struct coins_kv_read_snapshot_info *out_info)
{
    if (out_info)
        memset(out_info, 0, sizeof(*out_info));
    if (!out_info) {
        LOG_WARN("coins_kv_read_snapshot", "open: out_info is NULL");
        return NULL;
    }
    if (coins_ram_active()) {
        LOG_WARN("coins_kv_read_snapshot", "open: in-RAM coins overlay active");
        return NULL;
    }

    struct coins_kv_read_snapshot *snapshot = zcl_calloc(
        1, sizeof(*snapshot), "coins_kv_read_snapshot");
    if (!snapshot)
        return NULL;
    snapshot->db = progress_store_open_reader();
    if (!snapshot->db) {
        LOG_WARN("coins_kv_read_snapshot", "open: independent reader unavailable");
        snapshot_release(snapshot, false);
        return NULL;
    }
    if (!snapshot_exec(snapshot->db, "PRAGMA query_only=ON", "set query_only") ||
        !snapshot_exec(snapshot->db, "BEGIN", "BEGIN read transaction")) {
        snapshot_release(snapshot, false);
        return NULL;
    }
    snapshot->transaction_open = true;

    /* BEGIN is deferred. This authority/frontier query is intentionally the
     * first read: it pins every later metadata and row query to one WAL frame. */
    int32_t applied = -1;
    uint64_t generation = 0;
    if (!coins_kv_is_proven_authority(snapshot->db, &applied) || applied <= 0 ||
        !coins_kv_get_authority_generation(snapshot->db, &generation) ||
        coins_ram_active()) {
        LOG_WARN("coins_kv_read_snapshot",
                 "open: canonical authority unavailable (applied=%d overlay=%d)",
                 applied, coins_ram_active() ? 1 : 0);
        snapshot_release(snapshot, false);
        return NULL;
    }

    static const char sql[] =
        "SELECT txid,vout,value,script,height,is_coinbase "
        "FROM coins ORDER BY txid,vout";
    int rc = sqlite3_prepare_v2(snapshot->db, sql, -1, &snapshot->rows, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("coins_kv_read_snapshot", "open: row prepare failed rc=%d: %s",
                 rc, sqlite3_errmsg(snapshot->db));
        snapshot_release(snapshot, false);
        return NULL;
    }
    out_info->applied_height = applied;
    out_info->authority_generation = generation;
    snapshot->applied_height = applied;
    return snapshot;
}

static bool snapshot_row_key_valid(int txid_type, const void *txid,
                                   int txid_len, bool scalar_types,
                                   int64_t vout, int64_t value)
{
    return txid_type == SQLITE_BLOB && txid && txid_len == 32 && scalar_types &&
           vout >= 0 && vout <= UINT32_MAX && MoneyRange(value);
}

static bool snapshot_row_script_valid(int script_type, const void *script,
                                      int script_len)
{
    return script_type == SQLITE_BLOB && script_len >= 0 &&
           (script_len == 0 || script != NULL) &&
           script_len <= MAX_SCRIPT_SIZE;
}

static bool snapshot_row_meta_in_range(
    const struct coins_kv_read_snapshot *snapshot, int64_t height,
    int64_t coinbase)
{
    return height >= 0 && height < snapshot->applied_height &&
           coinbase >= 0 && coinbase <= 1;
}

static bool snapshot_row_valid(struct coins_kv_read_snapshot *snapshot,
                               sqlite3_stmt *stmt, int64_t vout, int64_t value, int script_len,
                               int64_t height, int64_t coinbase)
{
    const void *txid = sqlite3_column_blob(stmt, 0);
    const void *script = sqlite3_column_blob(stmt, 3);
    int txid_len = sqlite3_column_bytes(stmt, 0);
    int txid_type = sqlite3_column_type(stmt, 0);
    int script_type = sqlite3_column_type(stmt, 3);
    bool scalar_types = sqlite3_column_type(stmt, 1) == SQLITE_INTEGER &&
                        sqlite3_column_type(stmt, 2) == SQLITE_INTEGER &&
                        sqlite3_column_type(stmt, 4) == SQLITE_INTEGER &&
                        sqlite3_column_type(stmt, 5) == SQLITE_INTEGER;
    return snapshot_row_key_valid(txid_type, txid, txid_len, scalar_types,
                                  vout, value) &&
           snapshot_row_script_valid(script_type, script, script_len) &&
           snapshot_row_meta_in_range(snapshot, height, coinbase);
}

static bool snapshot_next_state_invalid(
    const struct coins_kv_read_snapshot *snapshot,
    const struct coins_kv_read_snapshot_row *out_row)
{
    return !snapshot || !out_row || snapshot->failed || snapshot->exhausted;
}

static bool snapshot_row_key_not_increasing(
    const struct coins_kv_read_snapshot *snapshot, const uint8_t *txid,
    int64_t vout)
{
    int order = snapshot->have_last ? memcmp(txid, snapshot->last_txid, 32) : 1;
    return snapshot->have_last &&
           (order < 0 ||
            (order == 0 && (uint32_t)vout <= snapshot->last_vout));
}

static void snapshot_row_publish(
    struct coins_kv_read_snapshot *snapshot,
    struct coins_kv_read_snapshot_row *out_row,
    const uint8_t *txid, const void *script, int64_t vout, int64_t value,
    int script_len, int64_t height, int64_t coinbase)
{
    if (script_len > 0)
        memcpy(snapshot->script, script, (size_t)script_len);

    memcpy(out_row->txid, txid, 32);
    out_row->vout = (uint32_t)vout;
    out_row->value = value;
    out_row->script = script_len > 0 ? snapshot->script : NULL;
    out_row->script_len = (size_t)script_len;
    out_row->height = (int32_t)height;
    out_row->is_coinbase = coinbase != 0;
}

static bool snapshot_reserve_script(struct coins_kv_read_snapshot *snapshot, size_t len)
{
    if (len <= snapshot->script_cap) return true;
    uint8_t *grown = zcl_realloc(snapshot->script, len, "coins_kv_read_snapshot_script");
    if (!grown) return false;
    snapshot->script = grown;
    snapshot->script_cap = len;
    return true;
}

enum coins_kv_read_snapshot_step coins_kv_read_snapshot_next(
    struct coins_kv_read_snapshot *snapshot,
    struct coins_kv_read_snapshot_row *out_row)
{
    if (snapshot_next_state_invalid(snapshot, out_row)) {
        LOG_WARN("coins_kv_read_snapshot", "next: invalid state");
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    memset(out_row, 0, sizeof(*out_row));
    int rc = sqlite3_step(snapshot->rows); // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_DONE) {
        snapshot->exhausted = true;
        return COINS_KV_READ_SNAPSHOT_DONE;
    }
    if (rc != SQLITE_ROW) {
        LOG_WARN("coins_kv_read_snapshot", "next: step failed rc=%d: %s",
                 rc, sqlite3_errmsg(snapshot->db));
        snapshot->failed = true;
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }

    int64_t vout = sqlite3_column_int64(snapshot->rows, 1);
    int64_t value = sqlite3_column_int64(snapshot->rows, 2);
    int script_len = sqlite3_column_bytes(snapshot->rows, 3);
    int64_t height = sqlite3_column_int64(snapshot->rows, 4);
    int64_t coinbase = sqlite3_column_int64(snapshot->rows, 5);
    if (!snapshot_row_valid(snapshot, snapshot->rows, vout, value, script_len, height, coinbase)) {
        LOG_WARN("coins_kv_read_snapshot", "next: malformed canonical coins row");
        snapshot->failed = true;
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }

    const uint8_t *txid = sqlite3_column_blob(snapshot->rows, 0);
    if (snapshot_row_key_not_increasing(snapshot, txid, vout)) {
        LOG_WARN("coins_kv_read_snapshot", "next: non-increasing coins key");
        snapshot->failed = true;
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    if (!snapshot_reserve_script(snapshot, (size_t)script_len)) {
        snapshot->failed = true;
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    const void *script = sqlite3_column_blob(snapshot->rows, 3);
    snapshot_row_publish(snapshot, out_row, txid, script, vout, value,
                         script_len, height, coinbase);
    memcpy(snapshot->last_txid, txid, 32);
    snapshot->last_vout = (uint32_t)vout;
    snapshot->have_last = true;
    return COINS_KV_READ_SNAPSHOT_ROW;
}

bool coins_kv_read_snapshot_finish(struct coins_kv_read_snapshot *snapshot)
{
    if (!snapshot) {
        LOG_WARN("coins_kv_read_snapshot", "finish: snapshot is NULL");
        return false;
    }
    bool ok = snapshot->exhausted && !snapshot->failed;
    if (!ok)
        LOG_WARN("coins_kv_read_snapshot", "finish: traversal incomplete");
    return snapshot_release(snapshot, ok) && ok;
}

void coins_kv_read_snapshot_abort(struct coins_kv_read_snapshot *snapshot)
{
    snapshot_release(snapshot, false);
}

static bool snapshot_point_row(struct coins_kv_read_snapshot *snapshot, sqlite3_stmt *stmt,
    const uint8_t key[32], uint32_t index, struct coins_kv_read_snapshot_row *row)
{
    int64_t vout = sqlite3_column_int64(stmt, 1);
    int64_t value = sqlite3_column_int64(stmt, 2);
    int script_len = sqlite3_column_bytes(stmt, 3);
    int64_t height = sqlite3_column_int64(stmt, 4);
    int64_t coinbase = sqlite3_column_int64(stmt, 5);
    if (!snapshot_row_valid(snapshot, stmt, vout, value, script_len, height, coinbase) ||
        vout != index || memcmp(sqlite3_column_blob(stmt, 0), key, 32) ||
        !snapshot_reserve_script(snapshot, (size_t)script_len)) return false;
    snapshot_row_publish(snapshot, row, sqlite3_column_blob(stmt, 0),
        sqlite3_column_blob(stmt, 3), vout, value, script_len, height, coinbase);
    return true;
}

static enum coins_kv_read_snapshot_lookup_result snapshot_point_query(
    struct coins_kv_read_snapshot *snapshot, const uint8_t key[32], uint32_t vout,
    struct coins_kv_read_snapshot_row *out_row, int *rc_out)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(snapshot->db,
        "SELECT txid,vout,value,script,height,is_coinbase FROM coins WHERE txid=?1 AND vout=?2",
        -1, &stmt, NULL);
    bool ok = rc == SQLITE_OK && sqlite3_bind_blob(stmt, 1, key, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)vout) == SQLITE_OK;
    enum coins_kv_read_snapshot_lookup_result result = COINS_KV_LOOKUP_ERROR;
    if (ok) {
        rc = sqlite3_step(stmt); // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_DONE) result = COINS_KV_LOOKUP_ABSENT;
        else if (rc == SQLITE_ROW && snapshot_point_row(snapshot, stmt, key, vout, out_row) &&
                 sqlite3_step(stmt) == SQLITE_DONE) // raw-sql-ok:progress-kv-kernel-store
            result = COINS_KV_LOOKUP_FOUND;
    }
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) result = COINS_KV_LOOKUP_ERROR;
    *rc_out = rc;
    return result;
}

static bool snapshot_pool_row(sqlite3_stmt *s, int64_t *sprout, int64_t *sapling)
{
    if (sqlite3_column_type(s, 0) != SQLITE_INTEGER ||
        sqlite3_column_type(s, 1) != SQLITE_INTEGER) return false;
    int64_t a = sqlite3_column_int64(s, 0), b = sqlite3_column_int64(s, 1);
    if (a < 0 || b < 0) return false;
    *sprout = a;
    *sapling = b;
    return true;
}

static bool snapshot_pool_query(sqlite3 *db, int32_t height,
    int64_t *sprout, int64_t *sapling, bool *found)
{
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT sprout,sapling FROM shielded_pool_totals WHERE height=?",
        -1, &s, NULL) == SQLITE_OK && s &&
        sqlite3_bind_int(s, 1, height) == SQLITE_OK;
    int64_t a = 0, b = 0;
    bool present = false;
    if (ok) {
        int rc = sqlite3_step(s); // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_ROW) {
            present = true;
            ok = snapshot_pool_row(s, &a, &b) &&
                sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
        } else ok = rc == SQLITE_DONE;
    }
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (!ok) return false;
    *sprout = a; *sapling = b; *found = present;
    return true;
}

bool coins_kv_read_transaction_shielded_pool(sqlite3 *db, int32_t height,
    int64_t *sprout, int64_t *sapling, bool *found)
{
    if (sprout) *sprout = 0;
    if (sapling) *sapling = 0;
    if (found) *found = false;
    int32_t applied = -1;
    bool applied_found = false;
    if (!db || !sprout || !sapling || !found || height < 0 ||
        height == INT32_MAX || sqlite3_get_autocommit(db) ||
        !coins_kv_get_applied_height(db, &applied, &applied_found) ||
        !applied_found || applied != height + 1) return false;
    return snapshot_pool_query(db, height, sprout, sapling, found);
}

bool coins_kv_read_snapshot_shielded_pool(struct coins_kv_read_snapshot *snapshot,
    int32_t height, int64_t *sprout, int64_t *sapling, bool *found)
{
    if (sprout) *sprout = 0;
    if (sapling) *sapling = 0;
    if (found) *found = false;
    if (!snapshot || !sprout || !sapling || !found || snapshot->failed ||
        !snapshot->transaction_open || height < 0 || height != snapshot->applied_height - 1) {
        if (snapshot) snapshot->failed = true;
        return false;
    }
    if (!snapshot_pool_query(snapshot->db, height, sprout, sapling, found)) {
        snapshot->failed = true;
        return false;
    }
    return true;
}

enum coins_kv_read_snapshot_lookup_result coins_kv_read_snapshot_lookup(
    struct coins_kv_read_snapshot *snapshot, const uint8_t txid[32],
    uint32_t vout, struct coins_kv_read_snapshot_row *out_row)
{
    uint8_t key[32];
    if (txid) memcpy(key, txid, sizeof(key));
    if (out_row) memset(out_row, 0, sizeof(*out_row));
    if (!snapshot || !txid || !out_row || snapshot->failed || !snapshot->transaction_open) {
        if (snapshot) snapshot->failed = true;
        return COINS_KV_LOOKUP_ERROR;
    }
    int rc = SQLITE_OK;
    enum coins_kv_read_snapshot_lookup_result result =
        snapshot_point_query(snapshot, key, vout, out_row, &rc);
    if (result == COINS_KV_LOOKUP_ERROR) {
        LOG_WARN("coins_kv_read_snapshot", "lookup failed rc=%d: %s", rc, sqlite3_errmsg(snapshot->db));
        snapshot->failed = true;
        memset(out_row, 0, sizeof(*out_row));
    }
    return result;
}

#ifdef ZCL_TESTING
void coins_kv_read_snapshot_test_authorizer(struct coins_kv_read_snapshot *snapshot,
    int (*authorizer)(void *, int, const char *, const char *, const char *, const char *))
{
    if (snapshot) (void)sqlite3_set_authorizer(snapshot->db, authorizer, NULL);
}
#endif
