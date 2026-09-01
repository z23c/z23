/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * projection_consumer — generic event-log projection consumer skeleton.
 * See storage/projection_consumer.h for the contract.
 */

#include "storage/projection_consumer.h"

#include "json/json.h"
#include "storage/event_log.h"
#include "storage/projection_util.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct projection_consumer {
    sqlite3 *db;
    event_log_t *log;
    struct projection_consumer_spec spec;
    uint64_t last_consumed_offset;
    uint64_t events_consumed_total;
    uint64_t last_catch_up_ms;
    char path[1024];
};

/* now_ms / apply_pragmas / meta_get_u64 / meta_set_u64 come from
 * storage/projection_util.h; apply_pragmas needs a per-TU 3-arg exec_sql
 * (the thin static wrapper below). */
bool projection_consumer_exec_sql(sqlite3 *db, const char *log_tag,
                                  const char *sql, const char *ctx)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:projection-consumer-sql
                "[%s] %s failed: %s\n",
                log_tag ? log_tag : "projection_consumer", ctx,
                err ? err : sqlite3_errmsg(db));
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    return projection_consumer_exec_sql(db, "projection_consumer", sql, ctx);
}

static bool ensure_meta_schema(projection_consumer_t *pc)
{
    if (!exec_sql(pc->db,
        "CREATE TABLE IF NOT EXISTS projection_meta ("
        " k TEXT PRIMARY KEY,"
        " v TEXT NOT NULL"
        ")",
        "create projection_meta"))
        return false;

    char sql[192];
    snprintf(sql, sizeof(sql),
             "INSERT OR IGNORE INTO projection_meta(k,v) "
             "VALUES('schema_version','%u')",
             pc->spec.schema_version);
    if (!exec_sql(pc->db, sql, "insert schema_version"))
        return false;

    return exec_sql(pc->db,
        "INSERT OR IGNORE INTO projection_meta(k,v) "
        "VALUES('last_consumed_offset','0')",
        "insert last_consumed_offset");
}

projection_consumer_t *projection_consumer_open(
    const char *projection_path, event_log_t *log,
    const struct projection_consumer_spec *spec)
{
    if (!projection_path || !projection_path[0] || !log ||
        !spec || !spec->apply_event)
        LOG_NULL("projection_consumer", "open: invalid args path=%p log=%p spec=%p",
                 (const void *)projection_path, (void *)log, (const void *)spec);

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(projection_path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        const char *msg = db ? sqlite3_errmsg(db) : sqlite3_errstr(rc);
        if (db) sqlite3_close(db);
        LOG_NULL("projection_consumer", "sqlite open failed: %s", msg);
    }

    projection_consumer_t *pc = zcl_malloc(sizeof(*pc), "projection_consumer");
    if (!pc) {
        sqlite3_close(db);
        return NULL;
    }
    memset(pc, 0, sizeof(*pc));
    pc->db = db;
    pc->log = log;
    pc->spec = *spec;
    if (!pc->spec.commit_batch) pc->spec.commit_batch = 100;

    if (!apply_pragmas(db) || !ensure_meta_schema(pc) ||
        (pc->spec.ensure_schema &&
         !pc->spec.ensure_schema(db, pc->spec.ctx))) {
        sqlite3_close(db);
        free(pc);
        return NULL;
    }

    pc->last_consumed_offset = meta_get_u64(db, "last_consumed_offset");
    snprintf(pc->path, sizeof(pc->path), "%s", projection_path);
    return pc;
}

void projection_consumer_close(projection_consumer_t *pc)
{
    if (!pc) return;
    if (pc->db) {
        sqlite3_exec(pc->db, "PRAGMA wal_checkpoint(TRUNCATE)",
                     NULL, NULL, NULL);
        sqlite3_close(pc->db);
    }
    free(pc);
}

struct catchup_ctx {
    projection_consumer_t *pc;
    bool ok;
    uint64_t next_offset;
    uint64_t since_commit;
    uint64_t handled_count;
};

static bool catchup_cb(uint64_t offset, enum event_log_type type,
                       const void *payload, size_t len, void *user)
{
    struct catchup_ctx *ctx = user;
    projection_consumer_t *pc = ctx->pc;
    uint64_t next = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;

    bool handled = false;
    if (!pc->spec.apply_event(pc->db, type, payload, len, pc->spec.ctx,
                              &handled)) {
        ctx->ok = false;
        return false;
    }
    if (handled) ctx->handled_count++;

    ctx->next_offset = next;
    pc->last_consumed_offset = next;
    ctx->since_commit++;
    if (ctx->since_commit >= pc->spec.commit_batch) {
        if (!meta_set_u64(pc->db, "last_consumed_offset", next)) {
            ctx->ok = false;
            return false;
        }
        ctx->since_commit = 0;
    }
    return true;
}

uint64_t projection_consumer_catch_up(projection_consumer_t *pc)
{
    if (!pc || !pc->db || !pc->log) return UINT64_MAX;
    int64_t start_ms = now_ms();
    struct catchup_ctx ctx = {
        .pc = pc,
        .ok = true,
        .next_offset = pc->last_consumed_offset,
        .since_commit = 0,
        .handled_count = 0,
    };

    if (!exec_sql(pc->db, "BEGIN IMMEDIATE", "catch_up begin"))
        return UINT64_MAX;
    if (event_log_stream(pc->log, pc->last_consumed_offset,
                         catchup_cb, &ctx) < 0)
        ctx.ok = false;
    if (ctx.ok)
        ctx.ok = meta_set_u64(pc->db, "last_consumed_offset",
                              ctx.next_offset);

    bool finish_ok = exec_sql(pc->db, ctx.ok ? "COMMIT" : "ROLLBACK",
                              ctx.ok ? "catch_up commit" :
                                       "catch_up rollback");
    if (!ctx.ok || !finish_ok) {
        /* ROLLBACK discarded the in-flight writes AND advance — restore the
           cached offset from persisted meta or the next catch_up skips events. */
        pc->last_consumed_offset = meta_get_u64(pc->db,
                                                "last_consumed_offset");
        return UINT64_MAX;
    }
    pc->last_consumed_offset = ctx.next_offset;
    pc->events_consumed_total += ctx.handled_count;
    int64_t elapsed = now_ms() - start_ms;
    pc->last_catch_up_ms = elapsed > 0 ? (uint64_t)elapsed : 0;
    return pc->last_consumed_offset;
}

uint64_t projection_consumer_rebuild(projection_consumer_t *pc)
{
    if (!pc || !pc->db) return UINT64_MAX;
    if (!meta_set_u64(pc->db, "last_consumed_offset", 0))
        return UINT64_MAX;
    pc->last_consumed_offset = 0;
    pc->events_consumed_total = 0;
    return projection_consumer_catch_up(pc);
}

sqlite3 *projection_consumer_db(projection_consumer_t *pc)
{
    return pc ? pc->db : NULL;
}

void projection_consumer_dump_common(struct json_value *out,
                                     projection_consumer_t *pc)
{
    if (!pc) return;
    json_push_kv_str(out, "path", pc->path);
    json_push_kv_int(out, "last_consumed_offset",
                     (int64_t)pc->last_consumed_offset);
    json_push_kv_int(out, "events_consumed_total",
                     (int64_t)pc->events_consumed_total);
    json_push_kv_int(out, "last_catch_up_ms",
                     (int64_t)pc->last_catch_up_ms);
}
