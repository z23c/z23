/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "storage/small_projections.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/event_log_payloads.h"
#include "storage/projection_consumer.h"
#include "storage/projection_meta.h"
#include "storage/projection_util.h"
#include "util/safe_alloc.h"

#include <inttypes.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct hodl_history_projection {
    sqlite3 *db;
    event_log_t *log;
    uint64_t last_consumed_offset;
    uint64_t events_consumed_total;
    uint64_t snapshot_total;
    uint64_t last_catch_up_ms;
    char path[1024];
};

static _Atomic(event_log_t *) g_event_log = NULL;
static _Atomic(hodl_history_projection_t *) g_projection = NULL;
static _Atomic uint64_t g_emit_snapshot_total = 0;
static _Atomic uint64_t g_emit_fail_total = 0;

static bool append_hodl_event(const void *payload, size_t len)
{
    event_log_t *log = atomic_load_explicit(&g_event_log,
                                            memory_order_acquire);
    if (!log)
        return true;
    if (!payload) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    if (event_log_append(log, EV_HODL_SNAPSHOT,
                         payload, len) == UINT64_MAX) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(&g_emit_snapshot_total, 1,
                              memory_order_relaxed);
    return true;
}

/* Shared exec-and-log body; also satisfies projection_util.h's exec_sql decl. */
static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    return projection_consumer_exec_sql(db, "hodl_history_projection",
                                        sql, ctx);
}

static bool ensure_schema(sqlite3 *db)
{
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS hodl_history ("
        " height INTEGER PRIMARY KEY,"
        " time INTEGER NOT NULL,"
        " total_zat INTEGER NOT NULL,"
        " older_1y_zat INTEGER NOT NULL,"
        " older_1y_pct REAL NOT NULL"
        ")",
        "create hodl_history") &&
        exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_hodl_history_time "
        "ON hodl_history(time)",
        "create idx_hodl_history_time") &&
        projection_meta_ensure(db);
}

hodl_history_projection_t *hodl_history_projection_open(
    const char *path, event_log_t *log)
{
    if (!path || !path[0] || !log) {
        fprintf(stderr,  // obs-ok:hodl-history-projection-open
                "[hodl_history_projection] open: invalid args path=%p log=%p\n",
                (const void *)path, (void *)log);
        return NULL;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:hodl-history-projection-open
                "[hodl_history_projection] sqlite open failed: %s\n",
                db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
        return NULL;
    }
    if (!apply_pragmas(db) || !ensure_schema(db)) {
        sqlite3_close(db);
        return NULL;
    }

    hodl_history_projection_t *p =
        zcl_malloc(sizeof(*p), "hodl_history_projection");
    if (!p) {
        sqlite3_close(db);
        return NULL;
    }
    memset(p, 0, sizeof(*p));
    p->db = db;
    p->log = log;
    p->last_consumed_offset = meta_get_u64(db, "last_consumed_offset");
    snprintf(p->path, sizeof(p->path), "%s", path);
    atomic_store_explicit(&g_projection, p, memory_order_release);
    return p;
}

void hodl_history_projection_close(hodl_history_projection_t *p)
{
    if (!p) return;
    hodl_history_projection_t *cur =
        atomic_load_explicit(&g_projection, memory_order_acquire);
    if (cur == p)
        atomic_store_explicit(&g_projection, NULL, memory_order_release);
    if (p->db) {
        sqlite3_exec(p->db, "PRAGMA wal_checkpoint(TRUNCATE)",
                     NULL, NULL, NULL);
        sqlite3_close(p->db);
    }
    free(p);
}

static bool apply_hodl_snapshot(hodl_history_projection_t *p,
                                const struct ev_hodl_snapshot *ev)
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "INSERT OR REPLACE INTO hodl_history"
        "(height,time,total_zat,older_1y_zat,older_1y_pct)"
        " VALUES(?,?,?,?,?)",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_int(s, 1, ev->height);
    sqlite3_bind_int64(s, 2, ev->time_unix);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)ev->total_zat);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)ev->older_1y_zat);
    sqlite3_bind_double(s, 5, ev->older_1y_pct);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

struct catchup_ctx {
    hodl_history_projection_t *p;
    bool ok;
    uint64_t next_offset;
    uint64_t since_commit;
};

static bool catchup_cb(uint64_t offset, enum event_log_type type,
                       const void *payload, size_t len, void *user)
{
    struct catchup_ctx *ctx = user;
    hodl_history_projection_t *p = ctx->p;
    uint64_t next = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;

    if (type == EV_HODL_SNAPSHOT) {
        struct ev_hodl_snapshot ev;
        if (!ev_hodl_snapshot_parse(payload, len, &ev) ||
            !apply_hodl_snapshot(p, &ev)) {
            ctx->ok = false;
            return false;
        }
        p->snapshot_total++;
        p->events_consumed_total++;
    }

    ctx->next_offset = next;
    p->last_consumed_offset = next;
    ctx->since_commit++;
    if (ctx->since_commit >= 100) {
        if (!meta_set_u64(p->db, "last_consumed_offset", next)) {
            ctx->ok = false;
            return false;
        }
        ctx->since_commit = 0;
    }
    return true;
}

uint64_t hodl_history_projection_catch_up(hodl_history_projection_t *p)
{
    if (!p || !p->db || !p->log) return UINT64_MAX;
    int64_t start_ms = now_ms();
    struct catchup_ctx ctx = {
        .p = p,
        .ok = true,
        .next_offset = p->last_consumed_offset,
    };
    if (!exec_sql(p->db, "BEGIN IMMEDIATE", "begin catch_up"))
        return UINT64_MAX;
    if (event_log_stream(p->log, p->last_consumed_offset,
                         catchup_cb, &ctx) != 0)
        ctx.ok = false;
    if (ctx.ok && !meta_set_u64(p->db, "last_consumed_offset",
                                ctx.next_offset))
        ctx.ok = false;
    bool finish_ok = exec_sql(p->db, ctx.ok ? "COMMIT" : "ROLLBACK",
                              ctx.ok ? "commit catch_up" :
                                       "rollback catch_up");
    if (!ctx.ok || !finish_ok) {
        p->last_consumed_offset = meta_get_u64(p->db, "last_consumed_offset");
        return UINT64_MAX;
    }
    int64_t elapsed = now_ms() - start_ms;
    p->last_catch_up_ms = elapsed > 0 ? (uint64_t)elapsed : 0;
    return p->last_consumed_offset;
}

uint64_t hodl_history_projection_count(hodl_history_projection_t *p)
{
    if (!p || !p->db) return UINT64_MAX;
    sqlite3_stmt *s = NULL;
    uint64_t count = UINT64_MAX;
    if (sqlite3_prepare_v2(p->db, "SELECT COUNT(*) FROM hodl_history",
                           -1, &s, NULL) != SQLITE_OK)
        return UINT64_MAX;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:projection-primitive
        count = (uint64_t)sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return count;
}

void hodl_history_projection_set_event_log(event_log_t *log)
{
    atomic_store_explicit(&g_event_log, log, memory_order_release);
}

hodl_history_projection_t *hodl_history_projection_current(void)
{
    return atomic_load_explicit(&g_projection, memory_order_acquire);
}

bool hodl_history_projection_emit_snapshot(int32_t height,
                                           uint32_t time_unix,
                                           int64_t total_zat,
                                           int64_t older_1y_zat,
                                           double older_1y_pct)
{
    event_log_t *log = atomic_load_explicit(&g_event_log,
                                            memory_order_acquire);
    if (!log)
        return true;
    struct ev_hodl_snapshot ev = {
        .height = height,
        .time_unix = time_unix,
        .total_zat = total_zat,
        .older_1y_zat = older_1y_zat,
        .older_1y_pct = older_1y_pct,
    };
    uint8_t payload[EV_HODL_SNAPSHOT_LEN];
    if (!ev_hodl_snapshot_serialize(&ev, payload)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    return append_hodl_event(payload, sizeof(payload));
}

bool hodl_history_projection_dump_state_json(struct json_value *out,
                                             const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    hodl_history_projection_t *p =
        atomic_load_explicit(&g_projection, memory_order_acquire);
    json_push_kv_bool(out, "open", p != NULL);
    json_push_kv_int(out, "emit_snapshot_total",
        (int64_t)atomic_load_explicit(&g_emit_snapshot_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_fail_total",
        (int64_t)atomic_load_explicit(&g_emit_fail_total,
                                      memory_order_relaxed));

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * engine/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed open + emit_fail_total fields above — no
     * new health logic. */
    {
        uint64_t fails = atomic_load_explicit(&g_emit_fail_total,
                                              memory_order_relaxed);
        projection_push_health(out, "hodl_history_projection", p, fails);
    }
    if (!p) return true;
    json_push_kv_str(out, "path", p->path);
    json_push_kv_int(out, "last_consumed_offset",
                     (int64_t)p->last_consumed_offset);
    json_push_kv_int(out, "events_consumed_total",
                     (int64_t)p->events_consumed_total);
    json_push_kv_int(out, "snapshot_total",
                     (int64_t)p->snapshot_total);
    json_push_kv_int(out, "hodl_history_count",
                     (int64_t)hodl_history_projection_count(p));
    json_push_kv_int(out, "count", (int64_t)hodl_history_projection_count(p));
    json_push_kv_int(out, "last_catch_up_ms",
                     (int64_t)p->last_catch_up_ms);
    return true;
}
