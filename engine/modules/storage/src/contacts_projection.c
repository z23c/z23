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

struct contacts_projection {
    sqlite3 *db;
    event_log_t *log;
    uint64_t last_consumed_offset;
    uint64_t events_consumed_total;
    uint64_t contact_set_total;
    uint64_t contact_touched_total;
    uint64_t contact_delete_total;
    uint64_t last_catch_up_ms;
    char path[1024];
};

static _Atomic(event_log_t *) g_event_log = NULL;
static _Atomic(contacts_projection_t *) g_projection = NULL;
static _Atomic uint64_t g_emit_set_total = 0;
static _Atomic uint64_t g_emit_touched_total = 0;
static _Atomic uint64_t g_emit_delete_total = 0;
static _Atomic uint64_t g_emit_fail_total = 0;

static bool append_contact_event(enum event_log_type type,
                                 const void *payload, size_t len,
                                 _Atomic uint64_t *counter)
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
    if (event_log_append(log, type, payload, len) == UINT64_MAX) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
    return true;
}

/* Shared exec-and-log body; also satisfies projection_util.h's exec_sql decl. */
static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    return projection_consumer_exec_sql(db, "contacts_projection", sql, ctx);
}

static bool ensure_schema(sqlite3 *db)
{
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS contacts ("
        " address TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " last_used INTEGER NOT NULL DEFAULT 0"
        ") WITHOUT ROWID",
        "create contacts") &&
        projection_meta_ensure(db);
}

contacts_projection_t *contacts_projection_open(const char *path,
                                                event_log_t *log)
{
    if (!path || !path[0] || !log) {
        fprintf(stderr,  // obs-ok:contacts-projection-open
                "[contacts_projection] open: invalid args path=%p log=%p\n",
                (const void *)path, (void *)log);
        return NULL;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:contacts-projection-open
                "[contacts_projection] sqlite open failed: %s\n",
                db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
        return NULL;
    }
    if (!apply_pragmas(db) || !ensure_schema(db)) {
        sqlite3_close(db);
        return NULL;
    }

    contacts_projection_t *p = zcl_malloc(sizeof(*p), "contacts_projection");
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

void contacts_projection_close(contacts_projection_t *p)
{
    if (!p) return;
    contacts_projection_t *cur = atomic_load_explicit(&g_projection,
                                                      memory_order_acquire);
    if (cur == p)
        atomic_store_explicit(&g_projection, NULL, memory_order_release);
    if (p->db) {
        sqlite3_exec(p->db, "PRAGMA wal_checkpoint(TRUNCATE)",
                     NULL, NULL, NULL);
        sqlite3_close(p->db);
    }
    free(p);
}

static bool apply_contact_set(contacts_projection_t *p,
                              const struct ev_contact_set *ev)
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "INSERT OR REPLACE INTO contacts(address,name,last_used) "
        "VALUES(?,?,COALESCE((SELECT last_used FROM contacts WHERE address=?),0))",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, ev->address, ev->address_len, SQLITE_TRANSIENT);
    if (ev->name_len)
        sqlite3_bind_text(s, 2, ev->name, ev->name_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_text(s, 2, "", 0, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, ev->address, ev->address_len, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_contact_touched(contacts_projection_t *p,
                                  const struct ev_contact_touched *ev)
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "UPDATE contacts SET last_used=? WHERE address=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_int64(s, 1, ev->last_used_unix);
    sqlite3_bind_text(s, 2, ev->address, ev->address_len, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_contact_delete(contacts_projection_t *p,
                                 const struct ev_contact_delete *ev)
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "DELETE FROM contacts WHERE address=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, ev->address, ev->address_len, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

struct catchup_ctx {
    contacts_projection_t *p;
    bool ok;
    uint64_t next_offset;
    uint64_t since_commit;
};

static bool catchup_cb(uint64_t offset, enum event_log_type type,
                       const void *payload, size_t len, void *user)
{
    struct catchup_ctx *ctx = user;
    contacts_projection_t *p = ctx->p;
    uint64_t next = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;

    if (type == EV_CONTACT_SET) {
        struct ev_contact_set ev;
        if (!ev_contact_set_parse(payload, len, &ev) ||
            !apply_contact_set(p, &ev)) {
            ctx->ok = false;
            return false;
        }
        p->contact_set_total++;
        p->events_consumed_total++;
    } else if (type == EV_CONTACT_TOUCHED) {
        struct ev_contact_touched ev;
        if (!ev_contact_touched_parse(payload, len, &ev) ||
            !apply_contact_touched(p, &ev)) {
            ctx->ok = false;
            return false;
        }
        p->contact_touched_total++;
        p->events_consumed_total++;
    } else if (type == EV_CONTACT_DELETE) {
        struct ev_contact_delete ev;
        if (!ev_contact_delete_parse(payload, len, &ev) ||
            !apply_contact_delete(p, &ev)) {
            ctx->ok = false;
            return false;
        }
        p->contact_delete_total++;
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

uint64_t contacts_projection_catch_up(contacts_projection_t *p)
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
    if (!exec_sql(p->db, ctx.ok ? "COMMIT" : "ROLLBACK",
                  ctx.ok ? "commit catch_up" : "rollback catch_up")) {
        /* Rolled back — restore the cached offset from persisted meta;
           SQLite discarded the in-flight writes on ROLLBACK. Without this,
           the catchup_cb's in-flight advance leaks and the next catch_up
           skips events. */
        p->last_consumed_offset = meta_get_u64(p->db, "last_consumed_offset");
        return UINT64_MAX;
    }
    if (!ctx.ok) {
        /* Rolled back — restore the cached offset from persisted meta;
           SQLite discarded the in-flight writes on ROLLBACK. */
        p->last_consumed_offset = meta_get_u64(p->db, "last_consumed_offset");
        return UINT64_MAX;
    }
    int64_t elapsed = now_ms() - start_ms;
    p->last_catch_up_ms = elapsed > 0 ? (uint64_t)elapsed : 0;
    return p->last_consumed_offset;
}

uint64_t contacts_projection_count(contacts_projection_t *p)
{
    if (!p || !p->db) return UINT64_MAX;
    sqlite3_stmt *s = NULL;
    uint64_t count = UINT64_MAX;
    if (sqlite3_prepare_v2(p->db, "SELECT COUNT(*) FROM contacts",
                           -1, &s, NULL) != SQLITE_OK)
        return UINT64_MAX;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:projection-primitive
        count = (uint64_t)sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return count;
}

void contacts_projection_set_event_log(event_log_t *log)
{
    atomic_store_explicit(&g_event_log, log, memory_order_release);
}

contacts_projection_t *contacts_projection_current(void)
{
    return atomic_load_explicit(&g_projection, memory_order_acquire);
}

bool contacts_projection_emit_set(const char *address, const char *name)
{
    event_log_t *log = atomic_load_explicit(&g_event_log,
                                            memory_order_acquire);
    if (!log)
        return true;
    size_t address_len = bounded_strlen(address, EV_CONTACT_ADDRESS_MAX);
    size_t name_len = bounded_strlen(name, EV_CONTACT_NAME_MAX);
    struct ev_contact_set ev = {
        .address_len = (uint8_t)address_len,
        .name_len = (uint8_t)name_len,
        .address = address,
        .name = name ? name : "",
    };
    uint8_t payload[EV_CONTACT_SET_FIXED_LEN +
                    EV_CONTACT_ADDRESS_MAX + EV_CONTACT_NAME_MAX];
    size_t len = 0;
    if (address_len == 0 || address_len > EV_CONTACT_ADDRESS_MAX ||
        name_len > EV_CONTACT_NAME_MAX ||
        !ev_contact_set_serialize(&ev, payload, sizeof(payload), &len)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    return append_contact_event(EV_CONTACT_SET, payload, len,
                                &g_emit_set_total);
}

bool contacts_projection_emit_touched(const char *address,
                                      uint32_t last_used)
{
    event_log_t *log = atomic_load_explicit(&g_event_log,
                                            memory_order_acquire);
    if (!log)
        return true;
    size_t address_len = bounded_strlen(address, EV_CONTACT_ADDRESS_MAX);
    struct ev_contact_touched ev = {
        .address_len = (uint8_t)address_len,
        .last_used_unix = last_used,
        .address = address,
    };
    uint8_t payload[EV_CONTACT_TOUCHED_LEN + EV_CONTACT_ADDRESS_MAX];
    size_t len = 0;
    if (address_len == 0 || address_len > EV_CONTACT_ADDRESS_MAX ||
        !ev_contact_touched_serialize(&ev, payload, sizeof(payload), &len)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    return append_contact_event(EV_CONTACT_TOUCHED, payload, len,
                                &g_emit_touched_total);
}

bool contacts_projection_dump_state_json(struct json_value *out,
                                         const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    contacts_projection_t *p = atomic_load_explicit(&g_projection,
                                                    memory_order_acquire);
    json_push_kv_bool(out, "open", p != NULL);
    json_push_kv_int(out, "emit_set_total",
        (int64_t)atomic_load_explicit(&g_emit_set_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_touched_total",
        (int64_t)atomic_load_explicit(&g_emit_touched_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_delete_total",
        (int64_t)atomic_load_explicit(&g_emit_delete_total,
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
        projection_push_health(out, "contacts_projection", p, fails);
    }
    if (!p) return true;
    json_push_kv_str(out, "path", p->path);
    json_push_kv_int(out, "last_consumed_offset",
                     (int64_t)p->last_consumed_offset);
    json_push_kv_int(out, "events_consumed_total",
                     (int64_t)p->events_consumed_total);
    json_push_kv_int(out, "contact_set_total",
                     (int64_t)p->contact_set_total);
    json_push_kv_int(out, "contact_touched_total",
                     (int64_t)p->contact_touched_total);
    json_push_kv_int(out, "contact_delete_total",
                     (int64_t)p->contact_delete_total);
    json_push_kv_int(out, "contacts_count",
                     (int64_t)contacts_projection_count(p));
    json_push_kv_int(out, "count", (int64_t)contacts_projection_count(p));
    json_push_kv_int(out, "last_catch_up_ms",
                     (int64_t)p->last_catch_up_ms);
    return true;
}
