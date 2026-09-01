/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * nullifier_kv — implementation. See storage/nullifier_kv.h for the contract
 * (pool namespaces, the rewind invariant, permanence).
 *
 * Raw sqlite3_step calls carry // raw-sql-ok:progress-kv-kernel-store, the
 * sanctioned hatch for the kernel store (same convention as coins_kv.c /
 * progress_store.c). The nullifier set sits BELOW the AR lifecycle — it is
 * reducer consensus state, not an AR model. */
#include "storage/nullifier_kv.h"

#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>

#define NF_ACTIVATION_KEY "nullifier_kv.activation_cursor"
static bool marker_set_i64_in_tx(sqlite3 *db, const char *key, int64_t value)
{
    if (!db || !key || !key[0] || value < 0 ||
        sqlite3_get_autocommit(db) != 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] marker set requires transaction key=%s "
                 "value=%lld",
                 key ? key : "(null)", (long long)value);
        return false;
    }
    char encoded[24];
    int n = snprintf(encoded, sizeof(encoded), "%lld", (long long)value);
    return n > 0 && (size_t)n < sizeof(encoded) &&
           progress_meta_set_in_tx(db, key, encoded, (size_t)n);
}

static bool marker_read_i64(sqlite3 *db, const char *key,
                            int64_t *value_out, bool *found_out)
{
    uint8_t buf[24] = {0};
    size_t len = 0;
    bool found = false;
    if (value_out) *value_out = 0;
    if (found_out) *found_out = false;
    if (!db || !key || !key[0] || !value_out || !found_out) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] marker read invalid args");
        return false;
    }
    if (!progress_meta_get(db, key, buf, sizeof(buf), &len, &found)) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] marker read failed key=%s",
                 key);
        return false;
    }
    if (!found)
        return true;
    if (len == 0 || len >= sizeof(buf) || (len > 1 && buf[0] == '0')) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] marker malformed key=%s length=%zu",
                 key, len);
        return false;
    }
    int64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < (uint8_t)'0' || buf[i] > (uint8_t)'9') {
            LOG_WARN("nullifier_kv",
                     "[nullifier_kv] marker malformed key=%s offset=%zu",
                     key, i);
            return false;
        }
        int digit = (int)(buf[i] - (uint8_t)'0');
        if (value > (INT64_MAX - digit) / 10) {
            LOG_WARN("nullifier_kv",
                     "[nullifier_kv] marker overflow key=%s", key);
            return false;
        }
        value = value * 10 + digit;
    }
    *value_out = value;
    *found_out = true;
    return true;
}

static bool nf_activation_set_in_tx(sqlite3 *db, int64_t cursor)
{
    return marker_set_i64_in_tx(db, NF_ACTIVATION_KEY, cursor);
}

bool nullifier_kv_ensure_schema(sqlite3 *db)
{
    if (!db) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] ensure_schema: NULL db");
        return false;
    }
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS nullifiers ("
        "  nf     BLOB    NOT NULL,"
        "  pool   INTEGER NOT NULL,"
        "  height INTEGER NOT NULL,"
        "  PRIMARY KEY (nf, pool)"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS idx_nullifiers_height "
        "ON nullifiers(height)",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] schema ensure failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

bool nullifier_kv_initialize_history(sqlite3 *db, int64_t activation_cursor)
{
    if (!db || activation_cursor < 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] initialize_history: invalid cursor=%lld",
                 (long long)activation_cursor);
        return false;
    }

    bool own_tx = sqlite3_get_autocommit(db) != 0;
    char *err = NULL;
    if (own_tx)
        progress_store_tx_lock();
    if (own_tx && sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err)
                      != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] initialize BEGIN: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }

    bool ok = progress_meta_table_ensure(db) &&
              nullifier_kv_ensure_schema(db);
    bool found = false;
    size_t marker_len = 0;
    uint8_t marker_probe[1];
    if (ok)
        ok = progress_meta_get(db, NF_ACTIVATION_KEY, marker_probe,
                               sizeof(marker_probe), &marker_len, &found);
    if (ok && !found)
        ok = nf_activation_set_in_tx(db, activation_cursor);

    if (own_tx) {
        const char *finish = ok ? "COMMIT" : "ROLLBACK";
        err = NULL;
        if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
            LOG_WARN("nullifier_kv", "[nullifier_kv] initialize %s: %s",
                     finish, err ? err : sqlite3_errmsg(db));
            if (err) sqlite3_free(err);
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            progress_store_tx_unlock();
            return false;
        }
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
    }
    if (!ok)
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] initialize_history rolled back cursor=%lld",
                 (long long)activation_cursor);
    return ok;
}

bool nullifier_kv_activation_cursor(sqlite3 *db, int64_t *cursor_out,
                                    bool *found_out)
{
    return marker_read_i64(db, NF_ACTIVATION_KEY, cursor_out, found_out);
}

/* Shared reset body for both typed entry points below. They differ ONLY in the
 * adoption cursor they stamp — 0 for a from-genesis COMPLETE history, a positive
 * height for an EMPTY-BELOW-N gap — so the DELETE, transaction scope, and marker
 * write are identical regardless of which caller invoked it. */
static bool nullifier_kv_reset_impl_in_tx(sqlite3 *db, int64_t activation_cursor)
{
    if (!db || activation_cursor < 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] reset: invalid cursor=%lld",
                 (long long)activation_cursor);
        return false;
    }
    if (sqlite3_get_autocommit(db) != 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] reset requires caller transaction");
        return false;
    }
    if (!progress_meta_table_ensure(db) || !nullifier_kv_ensure_schema(db))
        return false;

    char *err = NULL;
    if (sqlite3_exec(db, "DELETE FROM nullifiers", NULL, NULL, &err)
        != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] reset delete failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) sqlite3_free(err);

    if (!nf_activation_set_in_tx(db, activation_cursor)) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] reset marker write failed cursor=%lld",
                 (long long)activation_cursor);
        return false;
    }
    return true;
}

bool nullifier_kv_reset_mark_complete_in_tx(sqlite3 *db)
{
    return nullifier_kv_reset_impl_in_tx(db, 0);
}

bool nullifier_kv_reset_mark_empty_below_in_tx(sqlite3 *db, int64_t below_height)
{
    return nullifier_kv_reset_impl_in_tx(db, below_height);
}

bool nullifier_kv_publish_full_replay_complete_in_tx(sqlite3 *db,
                                                     int64_t expected_boundary)
{
    if (!db || expected_boundary <= 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] publish complete: invalid boundary=%lld",
                 (long long)expected_boundary);
        return false;
    }
    if (sqlite3_get_autocommit(db) != 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] publish complete requires caller transaction");
        return false;
    }
    if (!progress_meta_table_ensure(db) || !nullifier_kv_ensure_schema(db))
        return false;

    /* Refuse before the write unless the marker is present and still names this
     * exact positive replay generation. */
    int64_t cursor = -1;
    bool found = false;
    if (!nullifier_kv_activation_cursor(db, &cursor, &found) || !found ||
        cursor != expected_boundary) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] publish complete boundary mismatch got=%lld "
                 "found=%d expected=%lld",
                 (long long)cursor, found ? 1 : 0,
                 (long long)expected_boundary);
        return false;
    }
    if (!nf_activation_set_in_tx(db, 0)) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] publish complete marker write failed");
        return false;
    }
    /* Re-read and verify the durable zero before accepting. */
    cursor = -1;
    found = false;
    if (!nullifier_kv_activation_cursor(db, &cursor, &found) || !found ||
        cursor != 0) {
        LOG_WARN("nullifier_kv",
                 "[nullifier_kv] publish complete zero verification failed "
                 "got=%lld found=%d",
                 (long long)cursor, found ? 1 : 0);
        return false;
    }
    return true;
}

bool shielded_history_cancel_full_replay_in_tx(sqlite3 *db)
{
    if (!db || sqlite3_get_autocommit(db) != 0) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] replay cancel requires transaction");
        return false;
    }
    return progress_meta_delete_in_tx(db, SHIELDED_REPLAY_TARGET_KEY) &&
           progress_meta_delete_in_tx(db, SHIELDED_REPLAY_NEXT_KEY) &&
           progress_meta_delete_in_tx(
               db, SHIELDED_REPLAY_SPROUT_STARTED_KEY) &&
           progress_meta_delete_in_tx(
               db, SHIELDED_REPLAY_SAPLING_STARTED_KEY);
}

static const char *replay_started_key(int pool)
{
    if (pool == NULLIFIER_POOL_SPROUT)
        return SHIELDED_REPLAY_SPROUT_STARTED_KEY;
    if (pool == NULLIFIER_POOL_SAPLING)
        return SHIELDED_REPLAY_SAPLING_STARTED_KEY;
    return NULL;
}

static bool replay_marker_required(sqlite3 *db, const char *key,
                                   int64_t *value_out)
{
    bool found = false;
    if (!marker_read_i64(db, key, value_out, &found) || !found) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] replay marker unavailable key=%s",
                 key ? key : "(null)");
        return false;
    }
    return true;
}

bool shielded_history_begin_full_replay(sqlite3 *db, int64_t target_height)
{
    if (!db || target_height < 0 || target_height == INT64_MAX ||
        sqlite3_get_autocommit(db) == 0) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] full replay begin invalid target=%lld",
                 (long long)target_height);
        return false;
    }

    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[shielded_history] replay BEGIN failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    int64_t boundary = target_height + 1;
    bool ok = progress_meta_table_ensure(db) &&
              anchor_kv_reset_mark_empty_below_in_tx(db, boundary) &&
              nullifier_kv_reset_mark_empty_below_in_tx(db, boundary) &&
              marker_set_i64_in_tx(db, SHIELDED_REPLAY_TARGET_KEY,
                                   target_height) &&
              marker_set_i64_in_tx(db, SHIELDED_REPLAY_NEXT_KEY, 0) &&
              marker_set_i64_in_tx(
                  db, SHIELDED_REPLAY_SPROUT_STARTED_KEY, 0) &&
              marker_set_i64_in_tx(
                  db, SHIELDED_REPLAY_SAPLING_STARTED_KEY, 0);
    if (!ok)
        LOG_WARN("nullifier_kv", "[shielded_history] replay reset failed");
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[shielded_history] replay %s failed: %s",
                 finish, err ? err : sqlite3_errmsg(db));
        if (ok)
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        ok = false;
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    return ok;
}

bool shielded_history_full_replay_expect_next(sqlite3 *db, int64_t height)
{
    if (!db || height < 0)
        return false;
    int64_t next = -1;
    if (!replay_marker_required(db, SHIELDED_REPLAY_NEXT_KEY, &next))
        return false;
    if (next != height) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] replay order mismatch next=%lld got=%lld",
                 (long long)next, (long long)height);
        return false;
    }
    return true;
}

bool shielded_history_full_replay_empty_frontier_allowed(
    sqlite3 *db, int pool, int64_t height)
{
    const char *started_key = replay_started_key(pool);
    if (!db || !started_key || height < 0 ||
        !shielded_history_full_replay_expect_next(db, height))
        return false;
    int64_t started = -1;
    if (!replay_marker_required(db, started_key, &started) || started != 0)
        return false;
    bool empty = false;
    return anchor_kv_table_is_empty(db, pool, &empty) && empty;
}

bool shielded_history_full_replay_mark_pool_started_in_tx(
    sqlite3 *db, int pool, int64_t height)
{
    const char *started_key = replay_started_key(pool);
    if (!db || !started_key || height < 0 ||
        sqlite3_get_autocommit(db) != 0 ||
        !shielded_history_full_replay_expect_next(db, height)) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] replay pool-start invalid pool=%d h=%lld",
                 pool, (long long)height);
        return false;
    }
    int64_t started = -1;
    if (!replay_marker_required(db, started_key, &started) ||
        (started != 0 && started != 1))
        return false;
    return started == 1 || marker_set_i64_in_tx(db, started_key, 1);
}

bool shielded_history_full_replay_advance_in_tx(
    sqlite3 *db, int64_t height, int64_t target_height)
{
    if (!db || height < 0 || target_height < height ||
        height == INT64_MAX || sqlite3_get_autocommit(db) != 0 ||
        !shielded_history_full_replay_expect_next(db, height)) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] replay advance invalid h=%lld target=%lld",
                 (long long)height, (long long)target_height);
        return false;
    }
    int64_t stored_target = -1;
    if (!replay_marker_required(db, SHIELDED_REPLAY_TARGET_KEY,
                                &stored_target) ||
        stored_target != target_height) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] replay target mismatch stored=%lld "
                 "expected=%lld",
                 (long long)stored_target, (long long)target_height);
        return false;
    }
    return marker_set_i64_in_tx(db, SHIELDED_REPLAY_NEXT_KEY, height + 1);
}

bool shielded_history_publish_full_replay_complete(
    sqlite3 *db, int64_t target_height)
{
    if (!db || target_height < 0 || target_height == INT64_MAX ||
        sqlite3_get_autocommit(db) == 0) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] publish complete invalid target=%lld",
                 (long long)target_height);
        return false;
    }

    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[shielded_history] publish BEGIN failed: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    int64_t stored_target = -1;
    int64_t next = -1;
    int64_t nf_cursor = -1;
    bool nf_found = false;
    int64_t boundary = target_height + 1;
    bool ok = replay_marker_required(db, SHIELDED_REPLAY_TARGET_KEY,
                                     &stored_target) &&
              replay_marker_required(db, SHIELDED_REPLAY_NEXT_KEY, &next) &&
              stored_target == target_height && next == boundary &&
              nullifier_kv_activation_cursor(db, &nf_cursor, &nf_found) &&
              nf_found && nf_cursor == boundary &&
              anchor_kv_publish_full_replay_complete_in_tx(db, boundary) &&
              nf_activation_set_in_tx(db, 0) &&
              progress_meta_delete_in_tx(db, SHIELDED_REPLAY_TARGET_KEY) &&
              progress_meta_delete_in_tx(db, SHIELDED_REPLAY_NEXT_KEY) &&
              progress_meta_delete_in_tx(
                  db, SHIELDED_REPLAY_SPROUT_STARTED_KEY) &&
              progress_meta_delete_in_tx(
                  db, SHIELDED_REPLAY_SAPLING_STARTED_KEY);
    if (!ok) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] publish refused target=%lld stored=%lld "
                 "next=%lld nf=%lld found=%d",
                 (long long)target_height, (long long)stored_target,
                 (long long)next, (long long)nf_cursor, nf_found ? 1 : 0);
    }
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[shielded_history] publish %s failed: %s",
                 finish, err ? err : sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        ok = false;
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    return ok;
}

bool shielded_history_reset_to_boundary(sqlite3 *db,
                                        int64_t activation_cursor)
{
    if (!db || activation_cursor <= 0 || sqlite3_get_autocommit(db) == 0) {
        LOG_WARN("nullifier_kv",
                 "[shielded_history] reset boundary invalid cursor=%lld",
                 (long long)activation_cursor);
        return false;
    }

    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[shielded_history] reset BEGIN: %s",
                 err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    bool ok = anchor_kv_reset_mark_empty_below_in_tx(db, activation_cursor);
    if (ok && !nullifier_kv_reset_mark_empty_below_in_tx(db, activation_cursor))
        ok = false;
    /* Any assisted/general reset cancels a prior full-replay session in the
     * same transaction. The positive component markers remain the authority;
     * orphan session cursors must never authorize a later completion. */
    if (ok && !shielded_history_cancel_full_replay_in_tx(db))
        ok = false;

    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[shielded_history] reset %s: %s",
                 finish, err ? err : sqlite3_errmsg(db));
        if (ok)
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        ok = false;
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    return ok;
}

bool nullifier_kv_table_exists(sqlite3 *db)
{
    if (!db) return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nullifiers'",
        -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] table_exists prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool found = sqlite3_step(s) == SQLITE_ROW;  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    return found;
}

bool nullifier_kv_row_count(sqlite3 *db, int pool, int64_t *count_out)
{
    if (count_out) *count_out = 0;
    if (!db ||
        (pool != NULLIFIER_POOL_SPROUT && pool != NULLIFIER_POOL_SAPLING) ||
        !count_out) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] row_count: invalid args");
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM nullifiers WHERE pool=?",
        -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] row_count prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    if (sqlite3_bind_int(s, 1, pool) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] row_count bind: %s",
                 sqlite3_errmsg(db));
        ok = false;
    } else {
        int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_ROW) {
            *count_out = sqlite3_column_int64(s, 0);
        } else {
            LOG_WARN("nullifier_kv", "[nullifier_kv] row_count step rc=%d: %s",
                     rc, sqlite3_errmsg(db));
            ok = false;
        }
    }
    sqlite3_finalize(s);
    return ok;
}

bool nullifier_kv_get(sqlite3 *db, const uint8_t nf[32], int pool,
                      bool *found, int64_t *height_out)
{
    if (found) *found = false;
    if (!db || !nf || !found) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] get: NULL arg");
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT height FROM nullifiers WHERE nf=? AND pool=?",
        -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] get prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    /* Fail CLOSED on bind failure: an unbound param is NULL, the WHERE
     * matches nothing, *found stays false — returning true here would let
     * a double-spend through on a mere allocation failure. */
    if (sqlite3_bind_blob(s, 1, nf, 32, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int (s, 2, pool)                     != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] get bind failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(s);
        return false;
    }
    bool ok = true;
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *found = true;
        if (height_out) *height_out = sqlite3_column_int64(s, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] get step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(s);
    return ok;
}

bool nullifier_kv_add(sqlite3 *db, const uint8_t nf[32], int pool,
                      int64_t height)
{
    if (!db || !nf) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] add: NULL arg");
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO nullifiers(nf,pool,height) VALUES(?,?,?)",
        -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] add prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    if (sqlite3_bind_blob (s, 1, nf, 32, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int  (s, 2, pool)                     != SQLITE_OK ||
        sqlite3_bind_int64(s, 3, (sqlite3_int64)height)    != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] add bind failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(s);
        return false;
    }
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] add step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}

bool nullifier_kv_delete_range(sqlite3 *db, int64_t first_h, int64_t last_h)
{
    if (!db) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] delete_range: NULL db");
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM nullifiers WHERE height >= ? AND height <= ?",
        -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] delete_range prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    if (sqlite3_bind_int64(s, 1, (sqlite3_int64)first_h) != SQLITE_OK ||
        sqlite3_bind_int64(s, 2, (sqlite3_int64)last_h)  != SQLITE_OK) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] delete_range bind failed: %s",
                 sqlite3_errmsg(db));
        sqlite3_finalize(s);
        return false;
    }
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) {
        LOG_WARN("nullifier_kv", "[nullifier_kv] delete_range step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}
