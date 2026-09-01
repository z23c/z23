/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_itag — implementation. See reducer_frontier_itag.h. */

#include "reducer_frontier_itag.h"

#include "jobs/stage_row_itag.h"
#include "event/event.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct itag_watermark_state {
    uint64_t epoch;
    int32_t height;
};

static _Atomic uint_least64_t g_itag_watermark_epoch = 1;

/* Count of ABSENT (NULL-itag) rows the fold trusted-but-flagged this verify
 * epoch. Reset with the watermark so it reflects the current full re-verify, not
 * a process-lifetime accumulation. Surfaced via reducer_frontier_itag_null_count. */
static _Atomic uint_least64_t g_itag_null_rows = 0;

static bool itag_log_table(const char *table)
{
    static const char *const logs[] = {
        "validate_headers_log", "script_validate_log", "body_persist_log",
        "proof_validate_log", "utxo_apply_log", "tip_finalize_log",
    };
    for (size_t i = 0; i < sizeof(logs) / sizeof(logs[0]); i++)
        if (table && strcmp(table, logs[i]) == 0)
            return true;
    return false;
}

/* A watermark is a promise about exact rows, not merely this connection.
 * Preserve append-only O(delta), but revoke the promise if a trusted-prefix
 * row is inserted/deleted or any existing verdict row is rewritten. SQLite
 * calls this synchronously on the mutating connection before the next fold. */
static void itag_watermark_update(void *ctx, int op, const char *db_name,
                                  const char *table, sqlite3_int64 rowid)
{
    (void)db_name;
    struct itag_watermark_state *state = ctx;
    if (!state || !itag_log_table(table) || state->height < 0)
        return;
    if (op == SQLITE_UPDATE || rowid <= (sqlite3_int64)state->height)
        state->height = -1;
}

static struct itag_watermark_state *itag_watermark_state(sqlite3 *db,
                                                         bool create)
{
    static const char key[] = "zcl.reducer_frontier.itag_watermark.v1";
    if (!db) return NULL;
    struct itag_watermark_state *state = sqlite3_get_clientdata(db, key);
    if (state || !create) return state;
    state = zcl_malloc(sizeof(*state), "reducer frontier itag watermark");
    if (!state) return NULL;
    state->epoch = 0;
    state->height = -1;
    if (sqlite3_set_clientdata(db, key, state, free) != SQLITE_OK)
        return NULL; /* SQLite invokes the destructor on registration failure. */
    sqlite3_update_hook(db, itag_watermark_update, state);
    return state;
}

int32_t reducer_frontier_itag_watermark(sqlite3 *db)
{
    struct itag_watermark_state *state = itag_watermark_state(db, false);
    uint64_t epoch = (uint64_t)atomic_load(&g_itag_watermark_epoch);
    return state && state->epoch == epoch ? state->height : -1;
}

void reducer_frontier_itag_watermark_publish(sqlite3 *db, int32_t hstar)
{
    struct itag_watermark_state *state = itag_watermark_state(db, true);
    if (!state) return;
    state->height = hstar;
    state->epoch = (uint64_t)atomic_load(&g_itag_watermark_epoch);
}

void reducer_frontier_itag_watermark_reset(void)
{
    atomic_fetch_add(&g_itag_watermark_epoch, 1);
    atomic_store(&g_itag_null_rows, 0);
}

int64_t reducer_frontier_itag_scan_floor(int32_t anchor, int64_t cursor,
                                         int32_t verify_above)
{
    int64_t floor = anchor;
    if (cursor <= floor) return floor;
    int64_t last = cursor - 1;
    if ((int64_t)verify_above > floor)
        floor = (int64_t)verify_above < last ? verify_above : last;
    return floor;
}

uint64_t reducer_frontier_itag_null_count(void)
{
    return (uint64_t)atomic_load(&g_itag_null_rows);
}

/* FNV-1a/16 of the (short, fixed) table name — only used to key the throttle so
 * a persistent per-(table,height) mismatch de-storms instead of spamming every
 * fold. Collisions merely merge two throttles, which is harmless. */
static uint32_t itag_table_key16(const char *t)
{
    uint32_t h = 2166136261u;
    for (; t && *t; t++)
        h = (h ^ (uint8_t)*t) * 16777619u;
    return h & 0xffffu;
}

void reducer_frontier_itag_mismatch_warn(const char *table, int64_t height)
{
    static struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t key = ((uint64_t)itag_table_key16(table) << 32) |
                   (uint32_t)(int32_t)height;
    int64_t now = platform_time_wall_unix();
    uint64_t reps = 0;
    if (log_throttle_should_emit(&t, key, now, 300, &reps)) {
        LOG_WARN("reducer",
                 "stage-row integrity tag MISMATCH: table=%s height=%lld — row "
                 "verdict bytes changed under its tag; treating as NOT ok and "
                 "capping H* below this height (corruption LOWERS the frontier) "
                 "repeated=%llu",
                 table, (long long)height, (unsigned long long)reps);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=stage_row_itag_mismatch table=%s height=%lld",
                    table, (long long)height);
    }
}

void reducer_frontier_itag_null_warn(const char *table, int64_t height)
{
    atomic_fetch_add(&g_itag_null_rows, 1);
    /* Per-TABLE throttle (key = table only): an untagged writer leaves a whole
     * contiguous run of NULL rows, so keying on (table,height) would still storm
     * the log one line per height. One line per table per keep-alive window names
     * the offender; the counter above carries the exact row count for dumpstate. */
    static struct log_throttle t = LOG_THROTTLE_INIT;
    uint64_t key = itag_table_key16(table);
    int64_t now = platform_time_wall_unix();
    uint64_t reps = 0;
    if (log_throttle_should_emit(&t, key, now, 300, &reps)) {
        LOG_WARN("reducer",
                 "stage-row integrity tag ABSENT: table=%s height=%lld — row has "
                 "no itag (untagged writer or pre-backfill migration window); "
                 "trusting ok/status without capping H*, but flagging it "
                 "(see dumpstate reducer_frontier.itag_null_rows_seen) "
                 "repeated=%llu",
                 table, (long long)height, (unsigned long long)reps);
    }
}

bool reducer_frontier_itag_row_fails(const char *log_table, int64_t height,
                                     int ok_raw, const void *status,
                                     size_t status_len, const void *tag,
                                     size_t tag_len)
{
    enum stage_row_itag_verdict v = stage_row_itag_verify(
        log_table, height, ok_raw, status, status_len, tag, tag_len);
    if (v == STAGE_ROW_ITAG_MISMATCH) {
        reducer_frontier_itag_mismatch_warn(log_table, height);
        return true;  /* corruption: force NOT ok so H* caps below here */
    }
    if (v == STAGE_ROW_ITAG_ABSENT)
        reducer_frontier_itag_null_warn(log_table, height);
    return false;
}

bool reducer_frontier_itag_column_present(sqlite3 *db, const char *table)
{
    char sql[96];
    int n = snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (n <= 0 || n >= (int)sizeof(sql))
        return false;  // raw-return-ok:bounded-name-cannot-overflow
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-return-ok:absent-column-means-skip-verify
    bool present = false;
    while (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        const unsigned char *name = sqlite3_column_text(st, 1);  /* col 1 = name */
        if (name && strcmp((const char *)name, "itag") == 0) {
            present = true;
            break;
        }
    }
    sqlite3_finalize(st);
    return present;
}
