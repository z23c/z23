/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mempool_projection — event-log consumer for rebuildable mempool state.
 *
 * Consumes EV_TX_ADMIT_MEMPOOL / EV_TX_REMOVE_MEMPOOL into a rebuildable
 * SQLite projection used by diagnostics and replay checks.
 */

#include "storage/mempool_projection.h"

#include "core/serialize.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
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

struct mempool_projection {
    sqlite3 *db;
    event_log_t *log;
    /* Counters mutated by the catch-up thread and read lock-free by
     * mempool_projection_dump_state_json on other threads. _Atomic so the
     * diagnostic reads are race-free (single writer; plain ++/=/read on an
     * _Atomic compile to atomic RMW/store/load). */
    _Atomic uint64_t last_consumed_offset;
    _Atomic uint64_t events_consumed_total;
    _Atomic uint64_t tx_admit_total;
    _Atomic uint64_t tx_remove_total;
    _Atomic uint64_t replace_collisions_total;
    _Atomic uint64_t last_catch_up_ms;
    char path[1024];
};

static _Atomic(event_log_t *) g_event_log = NULL;
static _Atomic(mempool_projection_t *) g_projection = NULL;
static _Atomic uint64_t g_emit_admit_total = 0;
static _Atomic uint64_t g_emit_remove_total = 0;
static _Atomic uint64_t g_emit_fail_total = 0;

/* Shared exec-and-log body; also satisfies projection_util.h's exec_sql decl. */
static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    return projection_consumer_exec_sql(db, "mempool_projection", sql, ctx);
}

static bool ensure_schema(sqlite3 *db)
{
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS mempool ("
        " txid BLOB PRIMARY KEY,"
        " raw_tx BLOB NOT NULL,"
        " fee INTEGER NOT NULL,"
        " size INTEGER NOT NULL,"
        " weight INTEGER NOT NULL,"
        " admitted_unix INTEGER NOT NULL,"
        " priority_class INTEGER NOT NULL DEFAULT 0"
        ")",
        "create mempool") &&
        exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_mempool_projection_fee"
        " ON mempool(fee DESC)",
        "create mempool fee index") &&
        exec_sql(db,
        "CREATE TABLE IF NOT EXISTS mempool_spends ("
        " prevout_txid BLOB NOT NULL,"
        " prevout_vout INTEGER NOT NULL,"
        " by_txid BLOB NOT NULL,"
        " PRIMARY KEY(prevout_txid, prevout_vout)"
        ") WITHOUT ROWID",
        "create mempool_spends") &&
        exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_mempool_projection_spender"
        " ON mempool_spends(by_txid)",
        "create mempool spender index") &&
        projection_meta_ensure(db);
}

mempool_projection_t *mempool_projection_open(const char *projection_path,
                                              event_log_t *log)
{
    if (!projection_path || !projection_path[0] || !log) {
        fprintf(stderr,  // obs-ok:mempool-projection-open
                "[mempool_projection] open: invalid args path=%p log=%p\n",
                (const void *)projection_path, (void *)log);
        return NULL;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(projection_path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:mempool-projection-open
                "[mempool_projection] sqlite open failed: %s\n",
                db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
        return NULL;
    }
    if (!apply_pragmas(db) || !ensure_schema(db)) {
        sqlite3_close(db);
        return NULL;
    }

    mempool_projection_t *p = zcl_malloc(sizeof(*p), "mempool_projection");
    if (!p) {
        sqlite3_close(db);
        return NULL;
    }
    memset(p, 0, sizeof(*p));
    p->db = db;
    p->log = log;
    p->last_consumed_offset = meta_get_u64(db, "last_consumed_offset");
    snprintf(p->path, sizeof(p->path), "%s", projection_path);
    atomic_store_explicit(&g_projection, p, memory_order_release);
    return p;
}

void mempool_projection_close(mempool_projection_t *p)
{
    if (!p) return;
    mempool_projection_t *cur = atomic_load_explicit(&g_projection,
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

static bool tx_exists(sqlite3 *db, const uint8_t txid[32])
{
    sqlite3_stmt *s = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM mempool WHERE txid=?",
                           -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
    found = sqlite3_step(s) == SQLITE_ROW;  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return found;
}

static bool apply_spends_from_raw(sqlite3 *db, const uint8_t by_txid[32],
                                  const uint8_t *raw, size_t raw_len)
{
    if (!raw || raw_len == 0) return true;
    struct transaction tx;
    transaction_init(&tx);
    struct byte_stream bs;
    stream_init_from_data(&bs, raw, raw_len);
    if (!transaction_deserialize(&tx, &bs)) {
        transaction_free(&tx);
        return true;
    }

    bool ok = true;
    for (size_t i = 0; i < tx.num_vin && ok; i++) {
        sqlite3_stmt *s = NULL;
        int rc = sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO mempool_spends"
            "(prevout_txid,prevout_vout,by_txid) VALUES(?,?,?)",
            -1, &s, NULL);
        if (rc != SQLITE_OK) {
            ok = false;
            break;
        }
        sqlite3_bind_blob(s, 1, tx.vin[i].prevout.hash.data, 32,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, (int)tx.vin[i].prevout.n);
        sqlite3_bind_blob(s, 3, by_txid, 32, SQLITE_TRANSIENT);
        rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
        sqlite3_finalize(s);
        ok = rc == SQLITE_DONE;
    }
    transaction_free(&tx);
    return ok;
}

static bool remove_spends(sqlite3 *db, const uint8_t txid[32])
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM mempool_spends WHERE by_txid=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool apply_tx_admit(mempool_projection_t *p,
                           const struct ev_tx_admit_mempool *ev)
{
    if (tx_exists(p->db, ev->txid))
        p->replace_collisions_total++;
    if (!remove_spends(p->db, ev->txid))
        return false;

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "INSERT OR REPLACE INTO mempool"
        "(txid,raw_tx,fee,size,weight,admitted_unix,priority_class)"
        " VALUES(?,?,?,?,?,?,?)",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_blob(s, 1, ev->txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 2, ev->raw_tx, (int)ev->raw_tx_len,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, ev->fee);
    sqlite3_bind_int(s, 4, (int)ev->size_bytes);
    sqlite3_bind_int(s, 5, (int)ev->weight);
    sqlite3_bind_int64(s, 6, ev->admitted_unix);
    sqlite3_bind_int(s, 7, ev->priority_class);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) return false;
    return apply_spends_from_raw(p->db, ev->txid, ev->raw_tx,
                                 ev->raw_tx_len);
}

static bool apply_tx_remove(mempool_projection_t *p,
                            const struct ev_tx_remove_mempool *ev)
{
    if (!remove_spends(p->db, ev->txid))
        return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "DELETE FROM mempool WHERE txid=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_blob(s, 1, ev->txid, 32, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

struct catchup_ctx {
    mempool_projection_t *p;
    bool ok;
    uint64_t next_offset;
    uint64_t since_commit;
};

static bool catchup_cb(uint64_t offset, enum event_log_type type,
                       const void *payload, size_t len, void *user)
{
    struct catchup_ctx *ctx = user;
    mempool_projection_t *p = ctx->p;
    uint64_t next = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;

    if (type == EV_TX_ADMIT_MEMPOOL) {
        struct ev_tx_admit_mempool ev;
        if (!ev_tx_admit_mempool_parse(payload, len, &ev) ||
            !apply_tx_admit(p, &ev)) {
            ctx->ok = false;
            return false;
        }
        p->tx_admit_total++;
        p->events_consumed_total++;
    } else if (type == EV_TX_REMOVE_MEMPOOL) {
        struct ev_tx_remove_mempool ev;
        if (!ev_tx_remove_mempool_parse(payload, len, &ev) ||
            !apply_tx_remove(p, &ev)) {
            ctx->ok = false;
            return false;
        }
        p->tx_remove_total++;
        p->events_consumed_total++;
    }

    ctx->next_offset = next;
    atomic_store_explicit(&p->last_consumed_offset, next, memory_order_release);
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

uint64_t mempool_projection_catch_up(mempool_projection_t *p)
{
    if (!p || !p->db || !p->log) return UINT64_MAX;
    int64_t start_ms = now_ms();
    struct catchup_ctx ctx = {
        .p = p,
        .ok = true,
        .next_offset = p->last_consumed_offset,
        .since_commit = 0,
    };

    if (!exec_sql(p->db, "BEGIN IMMEDIATE", "catch_up begin"))
        return UINT64_MAX;
    if (event_log_stream(p->log, p->last_consumed_offset,
                         catchup_cb, &ctx) < 0)
        ctx.ok = false;
    if (ctx.ok)
        ctx.ok = meta_set_u64(p->db, "last_consumed_offset",
                              ctx.next_offset);

    bool finish_ok = exec_sql(p->db, ctx.ok ? "COMMIT" : "ROLLBACK",
                              ctx.ok ? "catch_up commit" :
                                       "catch_up rollback");
    if (!ctx.ok || !finish_ok) {
        /* Rolled back — restore the cached offset from persisted meta;
           SQLite discarded the in-flight writes on ROLLBACK. Without this,
           the catchup_cb's in-flight advance leaks and the next catch_up
           skips events. */
        atomic_store_explicit(&p->last_consumed_offset,
                              meta_get_u64(p->db, "last_consumed_offset"),
                              memory_order_release);
        return UINT64_MAX;
    }
    p->last_consumed_offset = ctx.next_offset;
    int64_t elapsed = now_ms() - start_ms;
    p->last_catch_up_ms = elapsed > 0 ? (uint64_t)elapsed : 0;
    return p->last_consumed_offset;
}

bool mempool_projection_get(mempool_projection_t *p,
                            const uint8_t txid[32],
                            int64_t *fee_out,
                            uint32_t *size_out,
                            uint32_t *weight_out)
{
    if (!p || !p->db || !txid) return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "SELECT fee,size,weight FROM mempool WHERE txid=?",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
    rc = sqlite3_step(s);  // raw-sql-ok:projection-primitive
    if (rc == SQLITE_ROW) {
        if (fee_out) *fee_out = sqlite3_column_int64(s, 0);
        if (size_out) *size_out = (uint32_t)sqlite3_column_int(s, 1);
        if (weight_out) *weight_out = (uint32_t)sqlite3_column_int(s, 2);
        sqlite3_finalize(s);
        return true;
    }
    sqlite3_finalize(s);
    return false;
}

int mempool_projection_each(mempool_projection_t *p,
                            mempool_projection_cb cb,
                            void *user)
{
    if (!p || !p->db || !cb) return -1;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(p->db,
        "SELECT txid,fee,size,weight FROM mempool ORDER BY txid",
        -1, &s, NULL);
    if (rc != SQLITE_OK) return -1;

    int count = 0;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {  // raw-sql-ok:projection-primitive
        const void *txid_blob = sqlite3_column_blob(s, 0);
        int txid_len = sqlite3_column_bytes(s, 0);
        if (!txid_blob || txid_len != 32)
            continue;
        uint8_t txid[32];
        memcpy(txid, txid_blob, 32);
        bool keep_going = cb(txid,
                             sqlite3_column_int64(s, 1),
                             (uint32_t)sqlite3_column_int(s, 2),
                             (uint32_t)sqlite3_column_int(s, 3),
                             user);
        count++;
        if (!keep_going)
            break;
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        return -1;
    return count;
}

static int64_t query_i64(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int64_t n = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:projection-primitive
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

uint64_t mempool_projection_count(mempool_projection_t *p)
{
    if (!p || !p->db) return 0;
    return (uint64_t)query_i64(p->db, "SELECT COUNT(*) FROM mempool");
}

int64_t mempool_projection_total_fee(mempool_projection_t *p)
{
    if (!p || !p->db) return 0;
    return query_i64(p->db, "SELECT COALESCE(SUM(fee),0) FROM mempool");
}

uint64_t mempool_projection_total_weight(mempool_projection_t *p)
{
    if (!p || !p->db) return 0;
    return (uint64_t)query_i64(p->db,
        "SELECT COALESCE(SUM(weight),0) FROM mempool");
}

void mempool_projection_set_event_log(event_log_t *log)
{
    atomic_store_explicit(&g_event_log, log, memory_order_release);
}

event_log_t *mempool_projection_event_log(void)
{
    return atomic_load_explicit(&g_event_log, memory_order_acquire);
}

bool mempool_projection_emit_admit(const uint8_t txid[32], int64_t fee,
                                   uint32_t size_bytes, uint32_t weight,
                                   int64_t admitted_unix,
                                   const uint8_t *raw_tx,
                                   size_t raw_tx_len)
{
    event_log_t *log = mempool_projection_event_log();
    if (!log || !txid || !raw_tx || raw_tx_len == 0) return false;
    struct ev_tx_admit_mempool ev;
    uint8_t *buf = NULL;
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.txid, txid, 32);
    ev.fee = fee;
    ev.size_bytes = size_bytes;
    ev.weight = weight;
    ev.admitted_unix = admitted_unix > 0 ? (uint32_t)admitted_unix : 0;
    ev.raw_tx = raw_tx;
    ev.raw_tx_len = raw_tx_len;
    buf = zcl_malloc(EV_TX_ADMIT_MEMPOOL_FIXED_LEN + raw_tx_len,
                     "mempool_projection_emit");
    if (!buf ||
        !ev_tx_admit_mempool_serialize(&ev, buf,
            EV_TX_ADMIT_MEMPOOL_FIXED_LEN + raw_tx_len, &len)) {
        free(buf);
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    uint64_t off = event_log_append(log, EV_TX_ADMIT_MEMPOOL, buf, len);
    free(buf);
    if (off == UINT64_MAX) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(&g_emit_admit_total, 1,
                              memory_order_relaxed);
    return true;
}

bool mempool_projection_emit_remove(const uint8_t txid[32], uint8_t reason)
{
    event_log_t *log = mempool_projection_event_log();
    if (!log || !txid) return false;
    struct ev_tx_remove_mempool ev;
    uint8_t buf[EV_TX_REMOVE_MEMPOOL_LEN];
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.txid, txid, 32);
    ev.reason = reason;
    if (!ev_tx_remove_mempool_serialize(&ev, buf)) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    uint64_t off = event_log_append(log, EV_TX_REMOVE_MEMPOOL, buf,
                                    sizeof(buf));
    if (off == UINT64_MAX) {
        atomic_fetch_add_explicit(&g_emit_fail_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    atomic_fetch_add_explicit(&g_emit_remove_total, 1,
                              memory_order_relaxed);
    return true;
}

bool mempool_projection_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    json_set_object(out);
    mempool_projection_t *p = atomic_load_explicit(&g_projection,
                                                   memory_order_acquire);
    json_push_kv_bool(out, "open", p != NULL);
    json_push_kv_int(out, "emit_admit_total",
                 (int64_t)atomic_load_explicit(&g_emit_admit_total,
                                               memory_order_relaxed));
    json_push_kv_int(out, "emit_remove_total",
                 (int64_t)atomic_load_explicit(&g_emit_remove_total,
                                               memory_order_relaxed));
    json_push_kv_int(out, "emit_fail_total",
                 (int64_t)atomic_load_explicit(&g_emit_fail_total,
                                               memory_order_relaxed));

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * app/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed open + emit_fail_total fields above — no
     * new health logic. */
    {
        uint64_t fails = atomic_load_explicit(&g_emit_fail_total,
                                              memory_order_relaxed);
        projection_push_health(out, "mempool_projection", p, fails);
    }
    if (!p) return true;
    json_push_kv_str(out, "path", p->path);
    json_push_kv_int(out, "last_consumed_offset",
                 (int64_t)p->last_consumed_offset);
    json_push_kv_int(out, "tx_count",
                 (int64_t)mempool_projection_count(p));
    json_push_kv_int(out, "total_fee", mempool_projection_total_fee(p));
    json_push_kv_int(out, "total_weight",
                 (int64_t)mempool_projection_total_weight(p));
    json_push_kv_int(out, "events_consumed_total",
                 (int64_t)p->events_consumed_total);
    json_push_kv_int(out, "ev_tx_admit_total",
                 (int64_t)p->tx_admit_total);
    json_push_kv_int(out, "ev_tx_remove_total",
                 (int64_t)p->tx_remove_total);
    json_push_kv_int(out, "replace_collisions_total",
                 (int64_t)p->replace_collisions_total);
    json_push_kv_int(out, "last_catch_up_ms", (int64_t)p->last_catch_up_ms);
    return true;
}
