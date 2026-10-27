/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Opt-in node.db transaction diagnostics — see util/db_txn_trace.h.
 *
 * This is a debugging instrument, not a consensus or hot path. It is inert
 * unless ZCL_DB_TXN_TRACE=1 is set in the environment at process start. It
 * exists to pin down the "one connection holds an open, idle write
 * transaction and never commits, starving every other node.db writer"
 * failure class by naming the exact owning connection over time. */

#include "util/db_txn_trace.h"
#include "util/subsystem_snapshot.h"

#include "json/json.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define ZCL_DB_TXN_TRACE_MAX_CONNS 32
#define ZCL_DB_TXN_TRACE_DUMP_SECS 3

struct txn_trace_entry {
    sqlite3 *db;             /* connection handle (NULL slot = free) */
    char label[48];          /* owner label */
};

static struct txn_trace_entry g_entries[ZCL_DB_TXN_TRACE_MAX_CONNS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Seqlock-published snapshot of every registered connection's transaction
 * state (Program O4d). The background collector holds the registry lock to
 * pin each handle and tries its connection mutex before reading live state.
 * It publishes under g_lock; db_txn_trace_dump_state_json (on the RPC thread)
 * reads it lock-free and NEVER touches a live sqlite handle. */
struct txn_snap_entry {
    _Atomic int txn_state;    /* -1 unknown, or SQLITE_TXN_NONE / READ / WRITE */
    _Atomic int busy_stmts;   /* -1 unknown, otherwise un-reset cursors */
    _Atomic char label[48];   /* seqlock payload must also be race-free */
};
static struct zcl_snapshot_env g_snap_env = ZCL_SNAPSHOT_ENV_INIT;
static _Atomic int g_snap_count;
static struct txn_snap_entry g_snap[ZCL_DB_TXN_TRACE_MAX_CONNS];
static atomic_bool g_dumper_started = false;
static atomic_bool g_dumper_stop = false;
static pthread_t g_dumper_thread;

/* -1 unknown, 0 disabled, 1 enabled — resolved once, then cached. */
static atomic_int g_enabled_cache = -1;

bool zcl_db_txn_trace_enabled(void)
{
    int cached = atomic_load(&g_enabled_cache);
    if (cached >= 0)
        return cached == 1;
    const char *v = getenv("ZCL_DB_TXN_TRACE");
    int enabled = (v && v[0] == '1' && v[1] == '\0') ? 1 : 0;
    /* Racy first-resolution is fine: every racer computes the same value. */
    atomic_store(&g_enabled_cache, enabled);
    return enabled == 1;
}

static const char *txn_state_name(int st)
{
    switch (st) {
    case SQLITE_TXN_NONE:  return "NONE";
    case SQLITE_TXN_READ:  return "READ";
    case SQLITE_TXN_WRITE: return "WRITE";
    default:               return "UNKNOWN";
    }
}

/* Returns non-zero for statements that open/close a transaction scope. */
static bool is_txn_control_sql(const char *sql)
{
    if (!sql)
        return false;
    while (*sql == ' ' || *sql == '\t' || *sql == '\n' || *sql == '\r')
        sql++;
    /* Case-insensitive leading-keyword check. */
    static const char *kw[] = {
        "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "END", NULL
    };
    for (int i = 0; kw[i]; i++) {
        size_t n = strlen(kw[i]);
        if (strncasecmp(sql, kw[i], n) == 0) {
            char after = sql[n];
            if (after == '\0' || after == ' ' || after == '\t' ||
                after == ';' || after == '\n' || after == '\r')
                return true;
        }
    }
    return false;
}

static int trace_cb(unsigned type, void *ctx, void *p, void *x)
{
    (void)p;
    if (type != SQLITE_TRACE_STMT)
        return 0;
    const char *sql = (const char *)x;
    if (!is_txn_control_sql(sql))
        return 0;
    const struct txn_trace_entry *e = (const struct txn_trace_entry *)ctx;
    fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
            "[db-txn-trace] STMT owner=%s db=%p tid=%lu sql=\"%s\"\n",
            e ? e->label : "?", (void *)e->db,
            (unsigned long)pthread_self(), sql ? sql : "(null)");
    fflush(stderr);
    return 0;
}

/* g_lock pins the handle until unregister. A trylock, never a blocking
 * registry -> SQLite acquisition, protects the ENTIRE statement lifetime.
 * Register/unregister take SQLite -> registry to protect callback context. */
static void observe_connection(struct txn_trace_entry *entry, int *state,
                                int *busy)
{
    sqlite3 *db = entry->db;
    sqlite3_mutex *mutex = sqlite3_db_mutex(db);
    *state = -1;
    *busy = -1;
    if (!mutex || sqlite3_mutex_try(mutex) != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                "[db-txn-trace] STATE owner=%s db=%p unavailable=%s\n",
                entry->label, (void *)db,
                mutex ? "connection_busy" : "no_connection_mutex");
        return;
    }
    *state = sqlite3_txn_state(db, NULL);
    *busy = *state < SQLITE_TXN_NONE ? -1 : 0;
    fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
            "[db-txn-trace] STATE owner=%s db=%p txn=%s autocommit=%d%s\n",
            entry->label, (void *)db, txn_state_name(*state),
            sqlite3_get_autocommit(db), *state == SQLITE_TXN_WRITE
                ? "  <-- HOLDS WRITE LOCK (candidate holder)" : "");
    if (*state > SQLITE_TXN_NONE) {
        sqlite3_stmt *stmt = NULL;
        while ((stmt = sqlite3_next_stmt(db, stmt)) != NULL) {
            if (!sqlite3_stmt_busy(stmt))
                continue;
            ++*busy;
            const char *sql = sqlite3_sql(stmt);
            fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                    "[db-txn-trace]   BUSY-STMT owner=%s db=%p "
                    "stmt=%p sql=\"%s\"\n", entry->label, (void *)db,
                    (void *)stmt, sql ? sql : "(null)");
        }
    }
    sqlite3_mutex_leave(mutex);
}

static void publish_snapshot(void)
{
    pthread_mutex_lock(&g_lock);
    zcl_snapshot_publish_begin(&g_snap_env);
    int count = 0;
    for (int i = 0; i < ZCL_DB_TXN_TRACE_MAX_CONNS; i++) {
        if (!g_entries[i].db)
            continue;
        int state, busy;
        observe_connection(&g_entries[i], &state, &busy);
        atomic_store_explicit(&g_snap[count].txn_state, state, memory_order_relaxed);
        atomic_store_explicit(&g_snap[count].busy_stmts, busy, memory_order_relaxed);
        for (size_t j = 0; j < sizeof(g_snap[count].label); j++)
            atomic_store_explicit(&g_snap[count].label[j], g_entries[i].label[j],
                                  memory_order_relaxed);
        count++;
    }
    atomic_store_explicit(&g_snap_count, count, memory_order_relaxed);
    zcl_snapshot_publish_end(&g_snap_env, count);
    pthread_mutex_unlock(&g_lock);
    fflush(stderr);
}

static void *dumper_main(void *arg)
{
    (void)arg;
    while (!atomic_load(&g_dumper_stop)) {
        for (int slept = 0; slept < ZCL_DB_TXN_TRACE_DUMP_SECS &&
                            !atomic_load(&g_dumper_stop); slept++) {
            struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
        }
        if (!atomic_load(&g_dumper_stop))
            publish_snapshot();
    }
    return NULL;
}

static void ensure_dumper_started_locked(void)
{
    bool expected = false;
    if (atomic_compare_exchange_strong(&g_dumper_started, &expected, true)) {
        /* Opt-in (ZCL_DB_TXN_TRACE=1) diagnostic-only dumper; deliberately kept
         * off thread_registry/supervisor so a debug probe never appears in the
         * liveness tree or gates production shutdown. */
        /* raw-pthread-ok: opt-in diagnostic dumper, off the supervisor tree */
        if (pthread_create(&g_dumper_thread, NULL, dumper_main, NULL) != 0) {
            atomic_store(&g_dumper_started, false);
            fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                    "[db-txn-trace] failed to start dumper thread\n");
        } else {
            fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                    "[db-txn-trace] enabled (dump every %ds)\n",
                    ZCL_DB_TXN_TRACE_DUMP_SECS);
        }
        fflush(stderr);
    }
}

void zcl_db_txn_trace_register(sqlite3 *db, const char *label)
{
    if (!db || !zcl_db_txn_trace_enabled())
        return;

    sqlite3_mutex *mutex = sqlite3_db_mutex(db);
    sqlite3_mutex_enter(mutex);
    pthread_mutex_lock(&g_lock);

    /* Re-label an existing registration or claim a free slot. */
    int slot = -1;
    for (int i = 0; i < ZCL_DB_TXN_TRACE_MAX_CONNS; i++) {
        if (g_entries[i].db == db) { slot = i; break; }
        if (slot < 0 && g_entries[i].db == NULL) slot = i;
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_lock);
        sqlite3_mutex_leave(mutex);
        fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                "[db-txn-trace] registry full; %s not tracked\n",
                label ? label : "?");
        fflush(stderr);
        return;
    }

    g_entries[slot].db = db;
    snprintf(g_entries[slot].label, sizeof(g_entries[slot].label), "%s",
             label ? label : "unnamed");

    /* ctx is the stable registry-entry address (fixed array). */
    if (mutex)
        sqlite3_trace_v2(db, SQLITE_TRACE_STMT, trace_cb, &g_entries[slot]);
    else
        fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                "[db-txn-trace] owner=%s: no connection mutex; "
                "callback disabled, observations unknown\n", g_entries[slot].label);

    ensure_dumper_started_locked();

    fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
            "[db-txn-trace] registered owner=%s db=%p\n",
            g_entries[slot].label, (void *)db);
    fflush(stderr);

    pthread_mutex_unlock(&g_lock);
    sqlite3_mutex_leave(mutex);
}

void zcl_db_txn_trace_unregister(sqlite3 *db)
{
    if (!db || !zcl_db_txn_trace_enabled())
        return;

    sqlite3_mutex *mutex = sqlite3_db_mutex(db);
    sqlite3_mutex_enter(mutex);
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < ZCL_DB_TXN_TRACE_MAX_CONNS; i++) {
        if (g_entries[i].db == db) {
            fprintf(stderr,  // obs-ok:opt-in-debug-tracer (ZCL_DB_TXN_TRACE=1 only)
                    "[db-txn-trace] unregistered owner=%s db=%p\n",
                    g_entries[i].label, (void *)db);
            fflush(stderr);
            g_entries[i].db = NULL;
            g_entries[i].label[0] = '\0';
            /* Detach the trace so a soon-to-be-closed handle stops calling
             * back into a stale ctx pointer. */
            if (mutex)
                sqlite3_trace_v2(db, 0, NULL, NULL);
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    sqlite3_mutex_leave(mutex);
}

struct txn_snap_local {
    int txn_state;
    int busy;
    char label[48];
};

static void emit_connections(struct json_value *out,
                              const struct txn_snap_local *local,
                              int count, bool torn, bool initialized)
{
    int holders = 0, unavailable = 0;
    struct json_value conns;
    json_init(&conns);
    json_set_array(&conns);
    for (int i = 0; i < count; i++) {
        bool available = local[i].txn_state >= SQLITE_TXN_NONE;
        bool holds = available && local[i].txn_state != SQLITE_TXN_NONE;
        if (!available) unavailable++;
        if (holds)
            holders++;
        struct json_value e;
        json_init(&e);
        json_set_object(&e);
        json_push_kv_str(&e, "owner", local[i].label);
        json_push_kv_str(&e, "txn_state", txn_state_name(local[i].txn_state));
        json_push_kv_bool(&e, "observation_available", available);
        json_push_kv_int(&e, "busy_stmts", (int64_t)local[i].busy);
        if (available)
            json_push_kv_bool(&e, "holds_open_txn", holds);
        json_push_back(&conns, &e);
        json_free(&e);
    }
    json_push_kv_int(out, "connection_count", (int64_t)count);
    bool complete = unavailable == 0 && !torn && initialized;
    json_push_kv_bool(out, "observation_complete", complete);
    json_push_kv_int(out, "unavailable_connections", unavailable);
    if (complete)
        json_push_kv_int(out, "open_txn_holders", (int64_t)holders);
    json_push_kv(out, "connections", &conns);
    json_free(&conns);
}

bool db_txn_trace_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    bool enabled = zcl_db_txn_trace_enabled();
    json_push_kv_bool(out, "enabled", enabled);
    if (!enabled) {
        json_push_kv_str(out, "note",
                         "set ZCL_DB_TXN_TRACE=1 at process start to enable");
        return true;
    }

    /* Lock-free seqlock read of the background thread's published snapshot.
     * This NEVER calls sqlite3_txn_state / sqlite3_next_stmt on a live handle
     * from the RPC thread — only the background dumper does that, under g_lock,
     * and publishes the result here. */
    struct txn_snap_local local[ZCL_DB_TXN_TRACE_MAX_CONNS];
    int count = 0;
    bool initialized = false;
    bool torn = true;
    for (int attempt = 0; attempt < ZCL_SNAPSHOT_READ_MAX_RETRIES; attempt++) {
        uint64_t seq;
        if (!zcl_snapshot_read_try(&g_snap_env, &seq))
            continue;
        initialized = atomic_load_explicit(&g_snap_env.generation, memory_order_relaxed) != 0;
        int n = atomic_load_explicit(&g_snap_count, memory_order_relaxed);
        if (n < 0)
            n = 0;
        if (n > ZCL_DB_TXN_TRACE_MAX_CONNS)
            n = ZCL_DB_TXN_TRACE_MAX_CONNS;
        for (int i = 0; i < n; i++) {
            local[i].txn_state = atomic_load_explicit(&g_snap[i].txn_state,
                                                      memory_order_relaxed);
            local[i].busy = atomic_load_explicit(&g_snap[i].busy_stmts,
                                                 memory_order_relaxed);
            for (size_t j = 0; j < sizeof(local[i].label); j++)
                local[i].label[j] = atomic_load_explicit(&g_snap[i].label[j],
                                                        memory_order_relaxed);
            local[i].label[sizeof(local[i].label) - 1] = '\0';
        }
        count = n;
        if (zcl_snapshot_read_ok(&g_snap_env, seq)) {
            torn = false;
            break;
        }
    }
    if (torn) {
        zcl_snapshot_note_torn(&g_snap_env);
        count = 0; /* Do not expose payload bytes from a failed read. */
    }

    emit_connections(out, local, count, torn, initialized);

    struct json_value snap;
    json_init(&snap);
    json_set_object(&snap);
    zcl_snapshot_emit_label(&snap, &g_snap_env, torn,
                            platform_time_monotonic_us());
    json_push_kv(out, "snapshot", &snap);
    json_free(&snap);
    return true;
}
