/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * znam_projection — event-log consumer for rebuildable ZNAM state.
 *
 * Folds EV_ZNAM_REGISTER / _UPDATE / _TRANSFER / _RENEW / _EXPIRE into a
 * rebuildable SQLite projection. The cursor/transaction/projection_meta
 * plumbing lives in storage/projection_consumer.c — this file owns only
 * the ZNAM domain schema and per-event apply logic.
 */

#include "storage/znam_projection.h"

#include "json/json.h"
#include "storage/event_log_payloads.h"
#include "storage/projection_consumer.h"
#include "storage/projection_util.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZNAM_PROJECTION_SCHEMA_VERSION 1

struct znam_projection {
    projection_consumer_t *pc;
    sqlite3 *db;  /* == projection_consumer_db(pc); cached for read accessors */
    uint64_t register_total;
    uint64_t update_addr_total;
    uint64_t update_text_total;
    uint64_t update_primary_total;
    uint64_t transfer_total;
    uint64_t renew_total;
    uint64_t expire_total;
};

static _Atomic(event_log_t *) g_event_log = NULL;
static _Atomic(znam_projection_t *) g_projection = NULL;
static _Atomic uint64_t g_emit_register_total = 0;
static _Atomic uint64_t g_emit_update_addr_total = 0;
static _Atomic uint64_t g_emit_update_text_total = 0;
static _Atomic uint64_t g_emit_update_primary_total = 0;
static _Atomic uint64_t g_emit_transfer_total = 0;
static _Atomic uint64_t g_emit_renew_total = 0;
static _Atomic uint64_t g_emit_expire_total = 0;
static _Atomic uint64_t g_emit_fail_total = 0;

static bool apply_event(sqlite3 *db, enum event_log_type type,
                        const void *payload, size_t len, void *ctx,
                        bool *out_handled);

/* Shared exec-and-log body; also satisfies projection_util.h's exec_sql decl. */
static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    return projection_consumer_exec_sql(db, "znam_projection", sql, ctx);
}

static bool ensure_schema(sqlite3 *db, void *ctx)
{
    (void)ctx;
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS znam_names ("
        " name TEXT PRIMARY KEY,"
        " owner_address TEXT NOT NULL,"
        " target_type INTEGER NOT NULL,"
        " target_value TEXT NOT NULL,"
        " reg_txid BLOB NOT NULL,"
        " reg_height INTEGER NOT NULL,"
        " registered_unix INTEGER NOT NULL DEFAULT 0,"
        " expiry_height INTEGER NOT NULL DEFAULT 0,"
        " last_update_txid BLOB NOT NULL"
        ") WITHOUT ROWID",
        "create znam_names") &&
        exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_znam_owner "
        "ON znam_names(owner_address)",
        "create idx_znam_owner") &&
        exec_sql(db,
        "CREATE TABLE IF NOT EXISTS znam_addr_records ("
        " name TEXT NOT NULL,"
        " coin_type INTEGER NOT NULL,"
        " address TEXT NOT NULL,"
        " PRIMARY KEY(name, coin_type)"
        ") WITHOUT ROWID",
        "create znam_addr_records") &&
        exec_sql(db,
        "CREATE TABLE IF NOT EXISTS znam_text_records ("
        " name TEXT NOT NULL,"
        " key TEXT NOT NULL,"
        " value TEXT,"
        " PRIMARY KEY(name, key)"
        ") WITHOUT ROWID",
        "create znam_text_records");
}

znam_projection_t *znam_projection_open(const char *projection_path,
                                        event_log_t *log)
{
    if (!projection_path || !projection_path[0] || !log)
        return NULL;  /* projection_consumer_open() logs the details */

    znam_projection_t *p = zcl_malloc(sizeof(*p), "znam_projection");
    if (!p) return NULL;
    memset(p, 0, sizeof(*p));

    struct projection_consumer_spec spec = {
        .schema_version = ZNAM_PROJECTION_SCHEMA_VERSION,
        .ensure_schema = ensure_schema,
        .apply_event = apply_event,
        .ctx = p,
        .commit_batch = 0,
    };
    p->pc = projection_consumer_open(projection_path, log, &spec);
    if (!p->pc) {
        free(p);
        return NULL;
    }
    p->db = projection_consumer_db(p->pc);
    atomic_store_explicit(&g_projection, p, memory_order_release);
    return p;
}

void znam_projection_close(znam_projection_t *p)
{
    if (!p) return;
    znam_projection_t *cur = atomic_load_explicit(&g_projection,
                                                  memory_order_acquire);
    if (cur == p)
        atomic_store_explicit(&g_projection, NULL, memory_order_release);
    projection_consumer_close(p->pc);
    free(p);
}

/* Best-effort: the addr/text record write is authoritative, so a failure to
   prepare this secondary parent-row UPDATE is non-fatal and ignored. */
static void bump_last_update_txid(sqlite3 *db, const char *name,
                                  const uint8_t update_txid[32])
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE znam_names SET last_update_txid=? WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return;
    sqlite3_bind_blob(s, 1, update_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
}

static bool apply_register(sqlite3 *db, const struct ev_znam_register *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    char owner[EV_ZNAM_OWNER_MAX + 1];
    char target_value[EV_ZNAM_VALUE_MAX + 1];
    memset(name, 0, sizeof(name));
    memset(owner, 0, sizeof(owner));
    memset(target_value, 0, sizeof(target_value));
    memcpy(name, ev->name, ev->name_len);
    memcpy(owner, ev->owner_address, ev->owner_len);
    if (ev->target_value_len)
        memcpy(target_value, ev->target_value, ev->target_value_len);

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO znam_names"
        "(name,owner_address,target_type,target_value,"
        " reg_txid,reg_height,registered_unix,expiry_height,"
        " last_update_txid)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 3, ev->target_type);
    sqlite3_bind_text(s, 4, target_value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 5, ev->reg_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 6, ev->reg_height);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)ev->registered_unix);
    sqlite3_bind_int(s, 8, ev->expiry_height);
    sqlite3_bind_blob(s, 9, ev->reg_txid, 32, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_update_addr(sqlite3 *db, const struct ev_znam_update *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    char value[EV_ZNAM_VALUE_MAX + 1];
    memset(name, 0, sizeof(name));
    memset(value, 0, sizeof(value));
    memcpy(name, ev->name, ev->name_len);
    if (ev->value_len)
        memcpy(value, ev->value, ev->value_len);

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO znam_addr_records(name,coin_type,address)"
        " VALUES(?,?,?)",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, ev->key_or_coin_type);
    sqlite3_bind_text(s, 3, value, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return false;

    bump_last_update_txid(db, name, ev->update_txid);
    return true;
}

static bool apply_update_text(sqlite3 *db, const struct ev_znam_update *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    char key[EV_ZNAM_KEY_MAX + 1];
    char value[EV_ZNAM_VALUE_MAX + 1];
    memset(name, 0, sizeof(name));
    memset(key, 0, sizeof(key));
    memset(value, 0, sizeof(value));
    memcpy(name, ev->name, ev->name_len);
    if (ev->key_len)
        memcpy(key, ev->key, ev->key_len);
    if (ev->value_len)
        memcpy(value, ev->value, ev->value_len);

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO znam_text_records(name,key,value)"
        " VALUES(?,?,?)",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, value, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return false;

    bump_last_update_txid(db, name, ev->update_txid);
    return true;
}

static bool apply_update_primary(sqlite3 *db, const struct ev_znam_update *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    char value[EV_ZNAM_VALUE_MAX + 1];
    memset(name, 0, sizeof(name));
    memset(value, 0, sizeof(value));
    memcpy(name, ev->name, ev->name_len);
    if (ev->value_len)
        memcpy(value, ev->value, ev->value_len);

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE znam_names SET target_type=?,target_value=?,last_update_txid=?"
        " WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_int(s, 1, ev->key_or_coin_type);
    sqlite3_bind_text(s, 2, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 3, ev->update_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_transfer(sqlite3 *db, const struct ev_znam_transfer *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    char new_owner[EV_ZNAM_OWNER_MAX + 1];
    memset(name, 0, sizeof(name));
    memset(new_owner, 0, sizeof(new_owner));
    memcpy(name, ev->name, ev->name_len);
    memcpy(new_owner, ev->new_owner, ev->new_owner_len);

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE znam_names SET owner_address=?,last_update_txid=?"
        " WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, new_owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 2, ev->update_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_renew(sqlite3 *db, const struct ev_znam_renew *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    memset(name, 0, sizeof(name));
    memcpy(name, ev->name, ev->name_len);

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE znam_names SET expiry_height=?,last_update_txid=?"
        " WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_int(s, 1, ev->new_expiry_height);
    sqlite3_bind_blob(s, 2, ev->update_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_expire(sqlite3 *db, const struct ev_znam_expire *ev)
{
    char name[EV_ZNAM_NAME_MAX + 1];
    memset(name, 0, sizeof(name));
    memcpy(name, ev->name, ev->name_len);

    sqlite3_stmt *s = NULL;
    int rc;
    /* Name lease has lapsed — remove all related records. */
    rc = sqlite3_prepare_v2(db,
        "DELETE FROM znam_addr_records WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);

    rc = sqlite3_prepare_v2(db,
        "DELETE FROM znam_text_records WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);

    rc = sqlite3_prepare_v2(db,
        "DELETE FROM znam_names WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_event(sqlite3 *db, enum event_log_type type,
                        const void *payload, size_t len, void *ctx,
                        bool *out_handled)
{
    znam_projection_t *p = ctx;
    *out_handled = false;

    if (type == EV_ZNAM_REGISTER) {
        struct ev_znam_register ev;
        if (!ev_znam_register_parse(payload, len, &ev) ||
            !apply_register(db, &ev))
            return false;
        p->register_total++;
        *out_handled = true;
        return true;
    }
    if (type == EV_ZNAM_UPDATE) {
        struct ev_znam_update ev;
        if (!ev_znam_update_parse(payload, len, &ev))
            return false;
        bool applied = false;
        if (ev.action_type == EV_ZNAM_UPDATE_ACTION_ADDR) {
            applied = apply_update_addr(db, &ev);
            if (applied) p->update_addr_total++;
        } else if (ev.action_type == EV_ZNAM_UPDATE_ACTION_TEXT) {
            applied = apply_update_text(db, &ev);
            if (applied) p->update_text_total++;
        } else if (ev.action_type == EV_ZNAM_UPDATE_ACTION_PRIMARY) {
            applied = apply_update_primary(db, &ev);
            if (applied) p->update_primary_total++;
        } else {
            applied = true;  /* unknown action — skip without failing */
        }
        if (!applied) return false;
        *out_handled = true;
        return true;
    }
    if (type == EV_ZNAM_TRANSFER) {
        struct ev_znam_transfer ev;
        if (!ev_znam_transfer_parse(payload, len, &ev) ||
            !apply_transfer(db, &ev))
            return false;
        p->transfer_total++;
        *out_handled = true;
        return true;
    }
    if (type == EV_ZNAM_RENEW) {
        struct ev_znam_renew ev;
        if (!ev_znam_renew_parse(payload, len, &ev) ||
            !apply_renew(db, &ev))
            return false;
        p->renew_total++;
        *out_handled = true;
        return true;
    }
    if (type == EV_ZNAM_EXPIRE) {
        struct ev_znam_expire ev;
        if (!ev_znam_expire_parse(payload, len, &ev) ||
            !apply_expire(db, &ev))
            return false;
        p->expire_total++;
        *out_handled = true;
        return true;
    }
    return true;  /* unrecognized event type: skip past it */
}

uint64_t znam_projection_catch_up(znam_projection_t *p)
{
    if (!p) return UINT64_MAX;
    return projection_consumer_catch_up(p->pc);
}

bool znam_projection_find(znam_projection_t *p, const char *name,
                          char *owner_out, size_t owner_cap,
                          uint8_t *target_type_out,
                          char *target_value_out, size_t target_cap,
                          int32_t *reg_height_out,
                          int32_t *expiry_height_out)
{
    if (!p || !p->db || !name) return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "SELECT owner_address,target_type,target_value,reg_height,expiry_height"
        " FROM znam_names WHERE name=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    bool found = false;
    if (rc == SQLITE_ROW) {
        const unsigned char *owner = sqlite3_column_text(s, 0);
        if (owner_out && owner_cap)
            snprintf(owner_out, owner_cap, "%s", owner ? (const char *)owner : "");
        if (target_type_out)
            *target_type_out = (uint8_t)sqlite3_column_int(s, 1);
        const unsigned char *tv = sqlite3_column_text(s, 2);
        if (target_value_out && target_cap)
            snprintf(target_value_out, target_cap, "%s",
                     tv ? (const char *)tv : "");
        if (reg_height_out)
            *reg_height_out = sqlite3_column_int(s, 3);
        if (expiry_height_out)
            *expiry_height_out = sqlite3_column_int(s, 4);
        found = true;
    }
    sqlite3_finalize(s);
    return found;
}

bool znam_projection_addr_get(znam_projection_t *p, const char *name,
                              uint8_t coin_type,
                              char *addr_out, size_t addr_cap)
{
    if (!p || !p->db || !name) return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "SELECT address FROM znam_addr_records WHERE name=? AND coin_type=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, coin_type);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    bool found = false;
    if (rc == SQLITE_ROW) {
        const unsigned char *a = sqlite3_column_text(s, 0);
        if (addr_out && addr_cap)
            snprintf(addr_out, addr_cap, "%s", a ? (const char *)a : "");
        found = true;
    }
    sqlite3_finalize(s);
    return found;
}

bool znam_projection_text_get(znam_projection_t *p, const char *name,
                              const char *key,
                              char *value_out, size_t value_cap)
{
    if (!p || !p->db || !name || !key) return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "SELECT value FROM znam_text_records WHERE name=? AND key=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, key, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    bool found = false;
    if (rc == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(s, 0);
        if (value_out && value_cap)
            snprintf(value_out, value_cap, "%s", v ? (const char *)v : "");
        found = true;
    }
    sqlite3_finalize(s);
    return found;
}

static uint64_t count_table(znam_projection_t *p, const char *sql)
{
    if (!p || !p->db) return 0;
    sqlite3_stmt *s = NULL;
    uint64_t n = 0;
    if (sqlite3_prepare_v2(p->db, sql, -1, &s, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:projection-primitive
        n = (uint64_t)sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

uint64_t znam_projection_name_count(znam_projection_t *p)
{
    return count_table(p, "SELECT COUNT(*) FROM znam_names");
}

uint64_t znam_projection_addr_count(znam_projection_t *p)
{
    return count_table(p, "SELECT COUNT(*) FROM znam_addr_records");
}

uint64_t znam_projection_text_count(znam_projection_t *p)
{
    return count_table(p, "SELECT COUNT(*) FROM znam_text_records");
}

void znam_projection_set_event_log(event_log_t *log)
{
    atomic_store_explicit(&g_event_log, log, memory_order_release);
}

event_log_t *znam_projection_event_log(void)
{
    return atomic_load_explicit(&g_event_log, memory_order_acquire);
}

/* Max serialized ZNAM event payload (REGISTER=303, UPDATE=260); 512
 * rounds up generously, fits the stack, no heap allocation needed. */
#define ZNAM_PROJECTION_PAYLOAD_MAX 512

static bool emit_register_internal(event_log_t *log,
                                   const char *name, const char *owner,
                                   uint8_t target_type,
                                   const char *target_value,
                                   const uint8_t reg_txid[32],
                                   int32_t reg_height,
                                   uint32_t registered_unix,
                                   int32_t expiry_height)
{
    struct ev_znam_register ev;
    uint8_t buf[ZNAM_PROJECTION_PAYLOAD_MAX];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    if (!name || !owner) return false;
    size_t nlen = strnlen(name, EV_ZNAM_NAME_MAX + 1);
    size_t olen = strnlen(owner, EV_ZNAM_OWNER_MAX + 1);
    if (nlen == 0 || nlen > EV_ZNAM_NAME_MAX) return false;
    if (olen == 0 || olen > EV_ZNAM_OWNER_MAX) return false;
    ev.name_len = (uint8_t)nlen;
    memcpy(ev.name, name, nlen);
    ev.owner_len = (uint8_t)olen;
    memcpy(ev.owner_address, owner, olen);
    ev.target_type = target_type;
    if (target_value) {
        size_t tlen = strnlen(target_value, EV_ZNAM_VALUE_MAX + 1);
        if (tlen > EV_ZNAM_VALUE_MAX) return false;
        ev.target_value_len = (uint8_t)tlen;
        if (tlen) memcpy(ev.target_value, target_value, tlen);
    }
    if (reg_txid) memcpy(ev.reg_txid, reg_txid, 32);
    ev.reg_height = reg_height;
    ev.registered_unix = registered_unix;
    ev.expiry_height = expiry_height;

    if (!ev_znam_register_serialize(&ev, buf, sizeof(buf), &len))
        return false;
    uint64_t off = event_log_append(log, EV_ZNAM_REGISTER, buf, len);
    return off != UINT64_MAX;
}

bool znam_projection_emit_register(const char *name, const char *owner,
                                   uint8_t target_type,
                                   const char *target_value,
                                   const uint8_t reg_txid[32],
                                   int32_t reg_height,
                                   uint32_t registered_unix,
                                   int32_t expiry_height)
{
    event_log_t *log = znam_projection_event_log();
    if (!log) return false;
    if (!emit_register_internal(log, name, owner, target_type, target_value,
                                reg_txid, reg_height, registered_unix,
                                expiry_height)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(&g_emit_register_total, 1,
                              memory_order_relaxed);
    return true;
}

static bool emit_update_internal(event_log_t *log,
                                 const char *name, uint8_t action_type,
                                 uint8_t key_or_coin_type, const char *key,
                                 const char *value,
                                 const uint8_t update_txid[32])
{
    struct ev_znam_update ev;
    uint8_t buf[ZNAM_PROJECTION_PAYLOAD_MAX];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    if (!name) return false;
    size_t nlen = strnlen(name, EV_ZNAM_NAME_MAX + 1);
    if (nlen == 0 || nlen > EV_ZNAM_NAME_MAX) return false;
    ev.name_len = (uint8_t)nlen;
    memcpy(ev.name, name, nlen);
    ev.action_type = action_type;
    ev.key_or_coin_type = key_or_coin_type;
    if (key && action_type == EV_ZNAM_UPDATE_ACTION_TEXT) {
        size_t klen = strnlen(key, EV_ZNAM_KEY_MAX + 1);
        if (klen > EV_ZNAM_KEY_MAX) return false;
        ev.key_len = (uint8_t)klen;
        if (klen) memcpy(ev.key, key, klen);
    }
    if (value) {
        size_t vlen = strnlen(value, EV_ZNAM_VALUE_MAX + 1);
        if (vlen > EV_ZNAM_VALUE_MAX) return false;
        ev.value_len = (uint8_t)vlen;
        if (vlen) memcpy(ev.value, value, vlen);
    }
    if (update_txid) memcpy(ev.update_txid, update_txid, 32);

    if (!ev_znam_update_serialize(&ev, buf, sizeof(buf), &len))
        return false;
    uint64_t off = event_log_append(log, EV_ZNAM_UPDATE, buf, len);
    return off != UINT64_MAX;
}

bool znam_projection_emit_update_addr(const char *name, uint8_t coin_type,
                                      const char *address,
                                      const uint8_t update_txid[32])
{
    event_log_t *log = znam_projection_event_log();
    if (!log) return false;
    if (!emit_update_internal(log, name, EV_ZNAM_UPDATE_ACTION_ADDR,
                              coin_type, NULL, address, update_txid)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(&g_emit_update_addr_total, 1,
                              memory_order_relaxed);
    return true;
}

bool znam_projection_emit_update_text(const char *name, const char *key,
                                      const char *value,
                                      const uint8_t update_txid[32])
{
    event_log_t *log = znam_projection_event_log();
    if (!log) return false;
    if (!emit_update_internal(log, name, EV_ZNAM_UPDATE_ACTION_TEXT,
                              0, key, value, update_txid)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(&g_emit_update_text_total, 1,
                              memory_order_relaxed);
    return true;
}

bool znam_projection_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    json_set_object(out);
    znam_projection_t *p = atomic_load_explicit(&g_projection,
                                                memory_order_acquire);
    json_push_kv_bool(out, "open", p != NULL);
    json_push_kv_int(out, "emit_register_total",
        (int64_t)atomic_load_explicit(&g_emit_register_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_update_addr_total",
        (int64_t)atomic_load_explicit(&g_emit_update_addr_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_update_text_total",
        (int64_t)atomic_load_explicit(&g_emit_update_text_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_update_primary_total",
        (int64_t)atomic_load_explicit(&g_emit_update_primary_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_transfer_total",
        (int64_t)atomic_load_explicit(&g_emit_transfer_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_renew_total",
        (int64_t)atomic_load_explicit(&g_emit_renew_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_expire_total",
        (int64_t)atomic_load_explicit(&g_emit_expire_total,
                                      memory_order_relaxed));
    json_push_kv_int(out, "emit_fail_total",
        (int64_t)atomic_load_explicit(&g_emit_fail_total,
                                      memory_order_relaxed));

    /* Reserved `_health` key: { ok, reason } from open + emit_fail_total. */
    {
        uint64_t fails = atomic_load_explicit(&g_emit_fail_total,
                                              memory_order_relaxed);
        projection_push_health(out, "znam_projection", p, fails);
    }
    if (!p) return true;
    projection_consumer_dump_common(out, p->pc);
    json_push_kv_int(out, "name_count",
                 (int64_t)znam_projection_name_count(p));
    json_push_kv_int(out, "addr_record_count",
                 (int64_t)znam_projection_addr_count(p));
    json_push_kv_int(out, "text_record_count",
                 (int64_t)znam_projection_text_count(p));
    json_push_kv_int(out, "ev_register_total",
                 (int64_t)p->register_total);
    json_push_kv_int(out, "ev_update_addr_total",
                 (int64_t)p->update_addr_total);
    json_push_kv_int(out, "ev_update_text_total",
                 (int64_t)p->update_text_total);
    json_push_kv_int(out, "ev_update_primary_total",
                 (int64_t)p->update_primary_total);
    json_push_kv_int(out, "ev_transfer_total",
                 (int64_t)p->transfer_total);
    json_push_kv_int(out, "ev_renew_total",
                 (int64_t)p->renew_total);
    json_push_kv_int(out, "ev_expire_total",
                 (int64_t)p->expire_total);
    return true;
}
