/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "test/test_core.h"
#include "util/db_txn_trace.h"
#include "json/json.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

static sqlite3_stmt *dtt_next(sqlite3 *, sqlite3_stmt *);
static int dtt_busy(sqlite3_stmt *);
static const char *dtt_sql(sqlite3_stmt *);
static int dtt_sleep(const struct timespec *, struct timespec *);

/* Compile the actual tracer with private names and test-only API boundaries. */
#define zcl_db_txn_trace_enabled dtt_enabled
#define zcl_db_txn_trace_register dtt_register
#define zcl_db_txn_trace_unregister dtt_unregister
#define db_txn_trace_dump_state_json dtt_dump
#define sqlite3_next_stmt dtt_next
#define sqlite3_stmt_busy dtt_busy
#define sqlite3_sql dtt_sql
#define nanosleep dtt_sleep
#ifndef DB_TXN_TRACE_SOURCE
#define DB_TXN_TRACE_SOURCE "../../../platform/modules/util/src/db_txn_trace.c"
#endif
#include DB_TXN_TRACE_SOURCE
#undef nanosleep
#undef sqlite3_sql
#undef sqlite3_stmt_busy
#undef sqlite3_next_stmt
#undef db_txn_trace_dump_state_json
#undef zcl_db_txn_trace_unregister
#undef zcl_db_txn_trace_register
#undef zcl_db_txn_trace_enabled

static void dtt_check(const char *label, bool ok, int *failures)
{
    printf("db_txn_trace: %s... %s\n", label, ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

static pthread_mutex_t dtt_control = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dtt_changed = PTHREAD_COND_INITIALIZER;
static struct {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int request, response, status[3], sleeps;
    bool seen[3], stop_probe, scan_done, start_finalizer, finalizer_probed;
    int finalizer_try, finalize_rc;
} dtt;

static void *dtt_probe_worker(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&dtt_control);
    while (!dtt.stop_probe) {
        while (!dtt.stop_probe && dtt.request == dtt.response)
            pthread_cond_wait(&dtt_changed, &dtt_control);
        if (dtt.stop_probe) break;
        int stage = dtt.request;
        pthread_mutex_unlock(&dtt_control);
        sqlite3_mutex *mutex = sqlite3_db_mutex(dtt.db);
        int rc = sqlite3_mutex_try(mutex);
        if (rc == SQLITE_OK) sqlite3_mutex_leave(mutex);
        pthread_mutex_lock(&dtt_control);
        dtt.status[stage - 1] = rc;
        dtt.response = stage;
        pthread_cond_broadcast(&dtt_changed);
    }
    pthread_mutex_unlock(&dtt_control);
    return NULL;
}

static int dtt_probe(int stage)
{
    pthread_mutex_lock(&dtt_control);
    if (!dtt.seen[stage]) {
        dtt.seen[stage] = true;
        dtt.request = stage + 1;
        pthread_cond_broadcast(&dtt_changed);
        while (dtt.response != dtt.request)
            pthread_cond_wait(&dtt_changed, &dtt_control);
    }
    int rc = dtt.status[stage];
    pthread_mutex_unlock(&dtt_control);
    return rc;
}

static void *dtt_finalizer(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&dtt_control);
    while (!dtt.start_finalizer && !dtt.scan_done)
        pthread_cond_wait(&dtt_changed, &dtt_control);
    pthread_mutex_unlock(&dtt_control);
    sqlite3_mutex *mutex = sqlite3_db_mutex(dtt.db);
    int rc = sqlite3_mutex_try(mutex);
    if (rc == SQLITE_OK) sqlite3_mutex_leave(mutex);
    pthread_mutex_lock(&dtt_control);
    dtt.finalizer_try = rc;
    dtt.finalizer_probed = true;
    pthread_cond_broadcast(&dtt_changed);
    pthread_mutex_unlock(&dtt_control);
    dtt.finalize_rc = sqlite3_finalize(dtt.stmt);
    return NULL;
}

static sqlite3_stmt *dtt_next(sqlite3 *db, sqlite3_stmt *previous)
{
    sqlite3_stmt *stmt = sqlite3_next_stmt(db, previous);
    if (db == dtt.db && stmt && !dtt.seen[0]) {
        int rc = dtt_probe(0);
        if (rc == SQLITE_BUSY) {
            pthread_mutex_lock(&dtt_control);
            dtt.start_finalizer = true;
            pthread_cond_broadcast(&dtt_changed);
            while (!dtt.finalizer_probed)
                pthread_cond_wait(&dtt_changed, &dtt_control);
            pthread_mutex_unlock(&dtt_control);
        }
    }
    return stmt;
}

static int dtt_busy(sqlite3_stmt *stmt)
{
    if (stmt == dtt.stmt) (void)dtt_probe(1);
    return sqlite3_stmt_busy(stmt);
}

static const char *dtt_sql(sqlite3_stmt *stmt)
{
    if (stmt == dtt.stmt) (void)dtt_probe(2);
    return sqlite3_sql(stmt);
}

static int dtt_sleep(const struct timespec *requested, struct timespec *remaining)
{
    (void)requested;
    (void)remaining;
    pthread_mutex_lock(&dtt_control);
    if (++dtt.sleeps > ZCL_DB_TXN_TRACE_DUMP_SECS) {
        atomic_store(&g_dumper_stop, true);
        dtt.scan_done = true;
        pthread_cond_broadcast(&dtt_changed);
    }
    pthread_mutex_unlock(&dtt_control);
    return 0;
}

static int dtt_join_dumper(void)
{
    if (!atomic_load(&g_dumper_started)) return 0;
    int rc = pthread_join(g_dumper_thread, NULL);
    atomic_store(&g_dumper_started, false);
    atomic_store(&g_dumper_stop, false);
    return rc;
}

static int dtt_nomutex_unknown(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(":memory:", &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL);
    dtt_check("NOMUTEX fixture opens", rc == SQLITE_OK && db != NULL, &failures);
    if (!db) return failures;
    dtt_check("NOMUTEX has no connection mutex", sqlite3_db_mutex(db) == NULL, &failures);
    dtt_register(db, "unsupported");
    bool present = false;
    for (int i = 0; i < ZCL_DB_TXN_TRACE_MAX_CONNS; i++)
        if (g_entries[i].db == db) present = true;
    dtt_check("NOMUTEX retains owner", present, &failures);
    dtt_check("NOMUTEX dumper cleanup", dtt_join_dumper() == 0, &failures);
    publish_snapshot();
    struct json_value snap;
    json_init(&snap);
    dtt_dump(&snap, NULL);
    const struct json_value *entry = json_at(json_get(&snap, "connections"), 0);
    dtt_check("NOMUTEX observation unavailable",
        !json_get_bool(json_get(entry, "observation_available")) &&
        json_get_int(json_get(entry, "busy_stmts")) == -1 &&
        json_get(&snap, "open_txn_holders") == NULL, &failures);
    json_free(&snap);
    dtt_unregister(db);
    dtt_check("NOMUTEX fixture closes", sqlite3_close(db) == SQLITE_OK, &failures);
    return failures;
}

static int dtt_snapshot_check(void)
{
    int failures = 0;
    struct json_value snapshot;
    json_init(&snapshot);
    bool dumped = dtt_dump(&snapshot, NULL);
    dtt_check("actual dumper snapshot publishes", dumped, &failures);
    dtt_check("snapshot has one connection",
        json_get_int(json_get(&snapshot, "connection_count")) == 1, &failures);
    const struct json_value *connections = json_get(&snapshot, "connections");
    const struct json_value *entry = json_at(connections, 0);
    dtt_check("snapshot observes actual busy statement",
        json_get_int(json_get(entry, "busy_stmts")) == 1, &failures);
    json_free(&snapshot);
    return failures;
}

static int dtt_fullmutex_inspection(void)
{
    int failures = 0;
    memset(&dtt, 0, sizeof(dtt));
    int rc = sqlite3_open_v2(":memory:", &dtt.db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    dtt_check("FULLMUTEX fixture opens", rc == SQLITE_OK && dtt.db != NULL, &failures);
    if (!dtt.db) return failures;
    dtt_check("FULLMUTEX has a connection mutex", sqlite3_db_mutex(dtt.db) != NULL, &failures);
    rc = sqlite3_exec(dtt.db, "CREATE TABLE rows(value); INSERT INTO rows VALUES(1),(2)",
                      NULL, NULL, NULL);
    dtt_check("fixture rows created", rc == SQLITE_OK, &failures);
    rc = sqlite3_prepare_v2(dtt.db, "SELECT value FROM rows", -1, &dtt.stmt, NULL);
    dtt_check("fixture SELECT prepared", rc == SQLITE_OK && dtt.stmt != NULL, &failures);
    if (!dtt.stmt) { sqlite3_close(dtt.db); return failures; }
    dtt_check("fixture SELECT remains busy", sqlite3_step(dtt.stmt) == SQLITE_ROW, &failures);
    pthread_t probe, finalizer;
    bool probe_started = pthread_create(&probe, NULL, dtt_probe_worker, NULL) == 0;
    bool finalizer_started = probe_started &&
        pthread_create(&finalizer, NULL, dtt_finalizer, NULL) == 0;
    dtt_check("fixture workers start", probe_started && finalizer_started, &failures);
    if (finalizer_started) {
        dtt_register(dtt.db, "lifetime");
        dtt_check("actual dumper terminates", dtt_join_dumper() == 0, &failures);
        pthread_mutex_lock(&dtt_control);
        dtt.scan_done = true;
        pthread_cond_broadcast(&dtt_changed);
        pthread_mutex_unlock(&dtt_control);
        pthread_join(finalizer, NULL);
        dtt_check("finalizer attempted while scan owned mutex",
            dtt.finalizer_try == SQLITE_BUSY, &failures);
        dtt_check("finalizer succeeds after scan", dtt.finalize_rc == SQLITE_OK, &failures);
        for (int i = 0; i < 3; i++)
            dtt_check("actual statement access retains connection mutex",
                dtt.seen[i] && dtt.status[i] == SQLITE_BUSY, &failures);
        failures += dtt_snapshot_check();
        dtt_unregister(dtt.db);
    } else {
        sqlite3_finalize(dtt.stmt);
    }
    if (probe_started) {
        pthread_mutex_lock(&dtt_control);
        dtt.stop_probe = true;
        pthread_cond_broadcast(&dtt_changed);
        pthread_mutex_unlock(&dtt_control);
        pthread_join(probe, NULL);
    }
    dtt_check("FULLMUTEX fixture closes", sqlite3_close(dtt.db) == SQLITE_OK, &failures);
    return failures;
}

/* Exercise the actual private collector, retaining upstream's three statement
 * boundaries and concurrent finalizer test above. */
static int dtt_unseeded(void)
{
    int failures = 0;
    struct json_value snapshot;
    json_init(&snapshot);
    dtt_dump(&snapshot, NULL);
    dtt_check("unseeded snapshot is unavailable",
        !json_get_bool(json_get(&snapshot, "observation_complete")) &&
        json_get(&snapshot, "open_txn_holders") == NULL, &failures);
    json_free(&snapshot);
    return failures;
}

struct dtt_contention {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    sqlite3 *db;
    bool held, release, scanned;
};

static void *dtt_hold_connection(void *arg)
{
    struct dtt_contention *race = arg;
    sqlite3_mutex *mutex = sqlite3_db_mutex(race->db);
    sqlite3_mutex_enter(mutex);
    pthread_mutex_lock(&race->mutex);
    race->held = true;
    pthread_cond_broadcast(&race->changed);
    while (!race->release)
        pthread_cond_wait(&race->changed, &race->mutex);
    pthread_mutex_unlock(&race->mutex);
    sqlite3_mutex_leave(mutex);
    return NULL;
}

static void *dtt_collect_held(void *arg)
{
    struct dtt_contention *race = arg;
    publish_snapshot();
    pthread_mutex_lock(&race->mutex);
    race->scanned = true;
    pthread_cond_broadcast(&race->changed);
    pthread_mutex_unlock(&race->mutex);
    return NULL;
}

static void dtt_busy_snapshot(int *failures)
{
    struct json_value snapshot;
    json_init(&snapshot);
    dtt_dump(&snapshot, NULL);
    const struct json_value *entry = json_at(json_get(&snapshot, "connections"), 0);
    const char *owner = json_get_str(json_get(entry, "owner"));
    const char *state = json_get_str(json_get(entry, "txn_state"));
    dtt_check("busy owner is explicitly unknown",
        owner && state && strcmp(owner, "busy-owner") == 0 &&
        strcmp(state, "UNKNOWN") == 0 &&
        !json_get_bool(json_get(entry, "observation_available")) &&
        json_get_int(json_get(entry, "busy_stmts")) == -1 &&
        json_get(entry, "holds_open_txn") == NULL &&
        json_get(&snapshot, "open_txn_holders") == NULL, failures);
    json_free(&snapshot);
}

static int dtt_nonblocking_unknown(void)
{
    int failures = 0;
    struct dtt_contention race = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .changed = PTHREAD_COND_INITIALIZER
    };
    int rc = sqlite3_open_v2(":memory:", &race.db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    dtt_check("contention fixture opens", rc == SQLITE_OK && race.db, &failures);
    if (rc != SQLITE_OK || !race.db) {
        sqlite3_close(race.db);
        return failures;
    }
    /* Stop the real dumper before manual scans; retain actual registration. */
    pthread_mutex_lock(&dtt_control);
    dtt.sleeps = ZCL_DB_TXN_TRACE_DUMP_SECS + 1;
    pthread_mutex_unlock(&dtt_control);
    dtt_register(race.db, "busy-owner");
    dtt_check("contention dumper joined", dtt_join_dumper() == 0, &failures);
    pthread_t holder, collector;
    bool held = pthread_create(&holder, NULL, dtt_hold_connection, &race) == 0;
    dtt_check("connection holder starts", held, &failures);
    if (held) {
        pthread_mutex_lock(&race.mutex);
        while (!race.held) pthread_cond_wait(&race.changed, &race.mutex);
        pthread_mutex_unlock(&race.mutex);
        bool collecting = pthread_create(&collector, NULL, dtt_collect_held, &race) == 0;
        dtt_check("collector starts", collecting, &failures);
        pthread_mutex_lock(&race.mutex);
        struct timespec deadline;
        timespec_get(&deadline, TIME_UTC);
        deadline.tv_sec += 2;
        while (collecting && !race.scanned) {
            if (pthread_cond_timedwait(&race.changed, &race.mutex, &deadline) != 0)
                break;
        }
        bool nonblocking = race.scanned;
        pthread_mutex_unlock(&race.mutex);
        dtt_check("collector finishes while connection remains held", nonblocking, &failures);
        if (nonblocking)
            dtt_busy_snapshot(&failures);
        pthread_mutex_lock(&race.mutex);
        race.release = true;
        pthread_cond_broadcast(&race.changed);
        pthread_mutex_unlock(&race.mutex);
        pthread_join(holder, NULL);
        if (collecting) pthread_join(collector, NULL);
    }
    publish_snapshot();
    struct json_value recovered;
    json_init(&recovered);
    dtt_dump(&recovered, NULL);
    dtt_check("observation recovers after release",
        json_get_bool(json_get(&recovered, "observation_complete")) &&
        json_get(&recovered, "open_txn_holders") != NULL, &failures);
    json_free(&recovered);
    dtt_unregister(race.db);
    dtt_check("contention fixture closes", sqlite3_close(race.db) == SQLITE_OK, &failures);
    pthread_cond_destroy(&race.changed);
    pthread_mutex_destroy(&race.mutex);
    return failures;
}

static int dtt_torn_unknown(void)
{
    int failures = 0;
    zcl_snapshot_publish_begin(&g_snap_env);
    struct json_value snapshot;
    json_init(&snapshot);
    dtt_dump(&snapshot, NULL);
    dtt_check("torn snapshot withholds payload and aggregate",
        !json_get_bool(json_get(&snapshot, "observation_complete")) &&
        json_get_int(json_get(&snapshot, "connection_count")) == 0 &&
        json_get(&snapshot, "open_txn_holders") == NULL, &failures);
    json_free(&snapshot);
    zcl_snapshot_publish_end(&g_snap_env, 0);
    return failures;
}
int test_db_txn_trace(void);
int test_db_txn_trace(void)
{
    atomic_store(&g_enabled_cache, 1);
    int failures = dtt_unseeded();
    failures += dtt_nomutex_unknown();
    failures += dtt_fullmutex_inspection();
    dtt.db = NULL;
    failures += dtt_nonblocking_unknown();
    failures += dtt_torn_unknown();
    return failures;
}
