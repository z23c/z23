/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * hodl_history_sqlite — sqlite implementation of hodl_history_port.
 *
 * The five methods below carry the EXACT SQL text and binding order of the
 * hodl-history queries, so persisted snapshots and the explorer and native
 * command surfaces stay bit-for-bit identical.
 */

#include "adapters/outbound/persistence/hodl_history_sqlite.h"

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <errno.h>
#include <string.h>
#include <time.h>

/* `self` aliases the sqlite3* directly — there is no wrapper struct. */
static inline sqlite3 *db_of(void *self) { return (sqlite3 *)self; }

#define HODL_HISTORY_SOURCE_TIP_KEY "sync_projection_tip_height"
#define HODL_HISTORY_UPSERT_LOCK_RETRIES 3
#define HODL_HISTORY_UPSERT_LOCK_SLEEP_MS 100

static bool hh_lock_rc(int rc)
{
    return rc == SQLITE_BUSY || rc == SQLITE_LOCKED;
}

static void hh_sleep_ms(long ms)
{
    if (ms <= 0)
        return;
    struct timespec ts = {
        .tv_sec = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000L,
    };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

static sqlite3 *hh_open_file_handle(sqlite3 *db,
                                    int flags,
                                    const char *label,
                                    bool *owned)
{
    if (owned)
        *owned = false;
    if (!db)
        return NULL;

    const char *path = sqlite3_db_filename(db, "main");
    if (!path || !path[0] || strcmp(path, ":memory:") == 0)
        return db;

    sqlite3 *handle = NULL;
    int rc = sqlite3_open_v2(path, &handle,
                             flags | SQLITE_OPEN_FULLMUTEX,
                             NULL);
    if (rc != SQLITE_OK || !handle) {
        LOG_WARN("hodl_history",
                 "open private %s failed: %s",
                 label ? label : "handle",
                 handle ? sqlite3_errmsg(handle) : "(null)");
        if (handle)
            sqlite3_close(handle);
        return db;
    }

    sqlite3_busy_timeout(handle, 5000);
    sqlite3_exec(handle,
                 "PRAGMA mmap_size=0;"
                 "PRAGMA foreign_keys=ON",
                 NULL, NULL, NULL);
    if (owned)
        *owned = true;
    return handle;
}

static sqlite3 *hh_open_reader(sqlite3 *db, bool *owned)
{
    return hh_open_file_handle(db, SQLITE_OPEN_READONLY, "reader", owned);
}

static sqlite3 *hh_open_writer(sqlite3 *db, bool *owned)
{
    return hh_open_file_handle(db, SQLITE_OPEN_READWRITE, "writer", owned);
}

static int64_t hh_projection_tip_height(sqlite3 *db, int64_t tableless_fallback)
{
    if (!db)
        return 0;

    sqlite3_stmt *s = NULL;
    const char *sql =
        "SELECT value FROM node_state WHERE key='" HODL_HISTORY_SOURCE_TIP_KEY "'";
    int rc = sqlite3_prepare_v2(db, sql, -1, &s, NULL);
    if (rc != SQLITE_OK || !s) {
        const char *err = sqlite3_errmsg(db);
        if (err && strstr(err, "no such table") != NULL)
            return tableless_fallback;
        LOG_WARN("hodl_history",
                 "prepare source-tip SQL failed: %s", err ? err : "(null)");
        return 0;
    }

    int64_t h = 0;
    rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(s, 0);
        int len = sqlite3_column_bytes(s, 0);
        if (blob && len == (int)sizeof(int64_t)) {
            memcpy(&h, blob, sizeof(h));
        } else if (blob && len == (int)sizeof(int32_t)) {
            int32_t h32 = 0;
            memcpy(&h32, blob, sizeof(h32));
            h = h32;
        } else {
            LOG_WARN("hodl_history",
                     "source-tip value has unexpected length %d", len);
        }
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        LOG_WARN("hodl_history",
                 "source-tip step rc=%d: %s", rc, sqlite3_errmsg(db));
        return 0;
    }
    return h > 0 ? h : 0;
}

static bool hh_block_time(void *self, int64_t height, int64_t *out_time)
{
    sqlite3 *db = db_of(self);
    if (!db || !out_time)
        return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT time FROM blocks WHERE height = ?",
                           -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_int64(s, 1, height);
    bool got = false;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        *out_time = sqlite3_column_int64(s, 0);
        got = true;
    }
    sqlite3_finalize(s);
    return got;
}

static bool hh_compute_snapshot(void *self,
                                int64_t height,
                                const int64_t cutoff_times[HODL_HISTORY_THRESHOLDS],
                                int64_t *out_total,
                                int64_t out_older[HODL_HISTORY_THRESHOLDS])
{
    sqlite3 *db = db_of(self);
    if (!db || !cutoff_times || !out_total || !out_older)
        return false;

    /* Compute total + all age thresholds in a single pass.
     *   o "alive at H": LEFT JOIN tx_inputs filtered to spends <= H,
     *                   keep only rows where no such spend exists.
     *   "older than X": creation-block time <= block_time - X. */
    const char *sql =
        "SELECT "
        "  COALESCE(SUM(o.value), 0) AS total_zat,"
        "  COALESCE(SUM(CASE WHEN b.time <= ?1 THEN o.value ELSE 0 END), 0),"
        "  COALESCE(SUM(CASE WHEN b.time <= ?2 THEN o.value ELSE 0 END), 0),"
        "  COALESCE(SUM(CASE WHEN b.time <= ?3 THEN o.value ELSE 0 END), 0),"
        "  COALESCE(SUM(CASE WHEN b.time <= ?4 THEN o.value ELSE 0 END), 0) "
        "FROM tx_outputs o "
        "JOIN blocks b ON b.height = o.block_height "
        "LEFT JOIN tx_inputs i "
        "  ON i.prev_txid = o.txid AND i.prev_vout = o.vout "
        "     AND i.block_height <= ?5 "
        "WHERE o.block_height <= ?5 AND i.txid IS NULL";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_FAIL("hodl_history",
                 "prepare snapshot SQL failed: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(s, 1, cutoff_times[HODL_HISTORY_THRESHOLD_6M]);
    sqlite3_bind_int64(s, 2, cutoff_times[HODL_HISTORY_THRESHOLD_1Y]);
    sqlite3_bind_int64(s, 3, cutoff_times[HODL_HISTORY_THRESHOLD_2Y]);
    sqlite3_bind_int64(s, 4, cutoff_times[HODL_HISTORY_THRESHOLD_5Y]);
    sqlite3_bind_int64(s, 5, height);
    int64_t total = 0;
    int64_t older[HODL_HISTORY_THRESHOLDS] = {0};
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        total = sqlite3_column_int64(s, 0);
        for (int i = 0; i < HODL_HISTORY_THRESHOLDS; i++)
            older[i] = sqlite3_column_int64(s, i + 1);
    }
    sqlite3_finalize(s);
    *out_total = total;
    for (int i = 0; i < HODL_HISTORY_THRESHOLDS; i++)
        out_older[i] = older[i];
    return true;
}

static bool hh_upsert_snapshot(void *self,
                               const struct hodl_history_snapshot *row)
{
    sqlite3 *db = db_of(self);
    if (!db || !row)
        return false;
    sqlite3_stmt *ins = NULL;
    int64_t source_tip = hh_projection_tip_height(db, row->height);
    bool owned_writer = false;
    sqlite3 *writer = hh_open_writer(db, &owned_writer);
    if (!writer)
        return false;
    const char *ins_sql =
        "INSERT OR REPLACE INTO hodl_history "
        "(height, time, total_zat, "
        " older_6m_zat, older_1y_zat, older_2y_zat, older_5y_zat, "
        " older_6m_pct, older_1y_pct, older_2y_pct, older_5y_pct, "
        " calc_version, source_tip_height) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
    if (sqlite3_prepare_v2(writer, ins_sql, -1, &ins, NULL) != SQLITE_OK ||
        !ins) {
        LOG_FAIL("hodl_history",
                 "prepare INSERT failed: %s", sqlite3_errmsg(writer));
        if (owned_writer)
            sqlite3_close(writer);
        return false;
    }
    sqlite3_bind_int64(ins, 1, row->height);
    sqlite3_bind_int64(ins, 2, row->time);
    sqlite3_bind_int64(ins, 3, row->total_zat);
    sqlite3_bind_int64(ins, 4, row->older_6m_zat);
    sqlite3_bind_int64(ins, 5, row->older_1y_zat);
    sqlite3_bind_int64(ins, 6, row->older_2y_zat);
    sqlite3_bind_int64(ins, 7, row->older_5y_zat);
    sqlite3_bind_double(ins, 8, row->older_6m_pct);
    sqlite3_bind_double(ins, 9, row->older_1y_pct);
    sqlite3_bind_double(ins, 10, row->older_2y_pct);
    sqlite3_bind_double(ins, 11, row->older_5y_pct);
    sqlite3_bind_int(ins, 12, HODL_HISTORY_SNAPSHOT_CALC_VERSION);
    sqlite3_bind_int64(ins, 13, source_tip);
    int rc = SQLITE_OK;
    for (int attempt = 0;
         attempt <= HODL_HISTORY_UPSERT_LOCK_RETRIES;
         attempt++) {
        rc = AR_STEP_WRITE(ins);
        if (!hh_lock_rc(rc))
            break;
        hh_sleep_ms(HODL_HISTORY_UPSERT_LOCK_SLEEP_MS);
    }
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_FAIL("hodl_history",
                 "INSERT step rc=%d: %s", rc, sqlite3_errmsg(writer));
        if (owned_writer)
            sqlite3_close(writer);
        return false;
    }
    if (owned_writer)
        sqlite3_close(writer);
    return true;
}

static int64_t hh_max_filled_height(void *self)
{
    sqlite3 *db = db_of(self);
    if (!db)
        return 0;
    bool owned_reader = false;
    sqlite3 *reader = hh_open_reader(db, &owned_reader);
    if (!reader)
        return 0;
    sqlite3_stmt *s = NULL;
    int64_t v = 0;
    if (sqlite3_prepare_v2(reader,
            "SELECT COALESCE(MAX(height), 0) FROM hodl_history",
            -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            v = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    if (owned_reader)
        sqlite3_close(reader);
    return v;
}

static int64_t hh_first_indexed_sample_height(sqlite3 *db,
                                              int64_t stride,
                                              int64_t source_tip)
{
    if (!db || stride <= 0 || source_tip <= 0)
        return stride;

    sqlite3_stmt *s = NULL;
    int64_t min_height = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MIN(height), 0) FROM blocks "
            "WHERE height > 0 AND height <= ?1",
            -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_WARN("hodl_history",
                 "prepare first indexed sample SQL failed: %s",
                 sqlite3_errmsg(db));
        return stride;
    }
    sqlite3_bind_int64(s, 1, source_tip);
    int rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_ROW)
        min_height = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        LOG_WARN("hodl_history",
                 "first indexed sample step rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        return stride;
    }
    if (min_height <= stride)
        return stride;
    return ((min_height + stride - 1) / stride) * stride;
}

static bool hh_next_fill_height(void *self,
                                int64_t stride,
                                int64_t target,
                                int64_t *out_height)
{
    sqlite3 *db = db_of(self);
    if (!db || !out_height || stride <= 0 || target < stride)
        return false;

    *out_height = 0;
    bool owned_reader = false;
    sqlite3 *reader = hh_open_reader(db, &owned_reader);
    if (!reader)
        return false;
    int64_t source_tip = hh_projection_tip_height(reader, target);
    if (source_tip > target)
        source_tip = target;
    if (source_tip < stride) {
        if (owned_reader)
            sqlite3_close(reader);
        return true;
    }

    int64_t start = hh_first_indexed_sample_height(reader, stride, source_tip);
    if (start > source_tip) {
        if (owned_reader)
            sqlite3_close(reader);
        return true;
    }

    sqlite3_stmt *s = NULL;
    const char *sql =
        "WITH RECURSIVE expected(h) AS ("
        "  SELECT ?1"
        "  UNION ALL SELECT h + ?2 FROM expected WHERE h + ?2 <= ?3"
        ") "
        "SELECT e.h "
        "FROM expected e "
        "LEFT JOIN hodl_history hh ON hh.height = e.h "
        "WHERE e.h <= ?3 AND ("
        "   hh.height IS NULL "
        "   OR hh.calc_version < ?4 "
        "   OR hh.source_tip_height < e.h"
        ") "
        "ORDER BY e.h LIMIT 1";
    if (sqlite3_prepare_v2(reader, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        LOG_FAIL("hodl_history",
                 "prepare next-fill SQL failed: %s", sqlite3_errmsg(reader));
        if (owned_reader)
            sqlite3_close(reader);
        return false;
    }
    sqlite3_bind_int64(s, 1, start);
    sqlite3_bind_int64(s, 2, stride);
    sqlite3_bind_int64(s, 3, source_tip);
    sqlite3_bind_int(s, 4, HODL_HISTORY_SNAPSHOT_CALC_VERSION);
    int rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_ROW)
        *out_height = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        LOG_FAIL("hodl_history",
                 "next-fill step rc=%d: %s", rc, sqlite3_errmsg(reader));
        if (owned_reader)
            sqlite3_close(reader);
        return false;
    }
    if (owned_reader)
        sqlite3_close(reader);
    return true;
}

static int hh_load_all(void *self,
                       struct hodl_history_snapshot *out,
                       int max_rows)
{
    sqlite3 *db = db_of(self);
    if (!db || !out || max_rows <= 0)
        return 0;
    bool owned_reader = false;
    sqlite3 *reader = hh_open_reader(db, &owned_reader);
    if (!reader)
        return 0;
    const char *sql =
        "SELECT height, time, total_zat, "
        "older_6m_zat, older_1y_zat, older_2y_zat, older_5y_zat, "
        "older_6m_pct, older_1y_pct, older_2y_pct, older_5y_pct "
        "FROM ("
        "  SELECT height, time, total_zat, "
        "  older_6m_zat, older_1y_zat, older_2y_zat, older_5y_zat, "
        "  older_6m_pct, older_1y_pct, older_2y_pct, older_5y_pct "
        "  FROM hodl_history "
        "  WHERE calc_version >= ?2 AND source_tip_height >= height "
        "  ORDER BY height DESC LIMIT ?1"
        ") ORDER BY height ASC";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(reader, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        if (owned_reader)
            sqlite3_close(reader);
        return 0;
    }
    sqlite3_bind_int(s, 1, max_rows);
    sqlite3_bind_int(s, 2, HODL_HISTORY_SNAPSHOT_CALC_VERSION);
    int n = 0;
    while (n < max_rows && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        out[n].height       = sqlite3_column_int64(s, 0);
        out[n].time         = sqlite3_column_int64(s, 1);
        out[n].total_zat    = sqlite3_column_int64(s, 2);
        out[n].older_6m_zat = sqlite3_column_int64(s, 3);
        out[n].older_1y_zat = sqlite3_column_int64(s, 4);
        out[n].older_2y_zat = sqlite3_column_int64(s, 5);
        out[n].older_5y_zat = sqlite3_column_int64(s, 6);
        out[n].older_6m_pct = sqlite3_column_double(s, 7);
        out[n].older_1y_pct = sqlite3_column_double(s, 8);
        out[n].older_2y_pct = sqlite3_column_double(s, 9);
        out[n].older_5y_pct = sqlite3_column_double(s, 10);
        n++;
    }
    sqlite3_finalize(s);
    if (owned_reader)
        sqlite3_close(reader);
    return n;
}

bool hodl_history_sqlite_bind(sqlite3 *db, struct hodl_history_port *out_port)
{
    if (!db || !out_port)
        return false;
    *out_port = (struct hodl_history_port){
        .self              = db,
        .block_time        = hh_block_time,
        .compute_snapshot  = hh_compute_snapshot,
        .upsert_snapshot   = hh_upsert_snapshot,
        .max_filled_height = hh_max_filled_height,
        .next_fill_height  = hh_next_fill_height,
        .load_all          = hh_load_all,
    };
    return true;
}
