/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * topology_store — implementation. See storage/topology_store.h.
 *
 * One handle, one dedicated file (topology.db), opened once at boot —
 * same shape as progress_store: a plain sqlite3 * behind an atomic pointer,
 * guarded by g_lock for write serialization (the handle is reached from at
 * least two threads: the P2P message-processing thread via
 * topology_store_record_edge() and the crawler worker thread via
 * topology_store_record_self_edge()/topology_store_record_sweep()).
 *
 * Row-count bookkeeping is kept in an in-memory atomic counter
 * (initialized once via COUNT(*) at open) so bounded-upsert eviction never
 * needs an O(n) COUNT(*) on the hot path — only a cheap indexed
 * exists-check per new edge. */

#include "storage/topology_store.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/log_rotate.h"
#include "util/sync.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define TOPOLOGY_SUBSYS "topology_store"

/* Pages between passive autocheckpoint attempts. 1000 pages (~4 MB) is
 * SQLite's own default; it is restated here so the number is a decision
 * this file owns and a reader can see it without knowing the library. */
#define TOPOLOGY_WAL_AUTOCHECKPOINT_PAGES 1000
#define TOPOLOGY_SELF_OBSERVER "self"

static zcl_mutex_t g_lock;
static zcl_once_t g_lock_once = ZCL_ONCE_INIT;
static _Atomic(sqlite3 *) g_db = NULL;
/* The path SQLite opened, retained so the WAL bound below can measure
 * "<path>-wal" without the caller having to carry the datadir back in. */
static char g_path[768];
static _Atomic int64_t g_row_count = 0;
static _Atomic int64_t g_cap = TOPOLOGY_EDGES_CAP_DEFAULT;

static _Atomic uint64_t g_edges_recorded_total = 0;
static _Atomic uint64_t g_edges_rejected_total = 0;
static _Atomic uint64_t g_evicted_total = 0;
static _Atomic uint64_t g_sweeps_recorded_total = 0;

static void topology_lock_init(void)
{
    zcl_mutex_init(&g_lock);
}

static zcl_mutex_t *topology_lock_handle(void)
{
    (void)zcl_once_call(&g_lock_once, topology_lock_init);
    return &g_lock;
}

/* ── small sql helpers ───────────────────────────────────────────────── */

static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK)
        return true;
    LOG_WARN(TOPOLOGY_SUBSYS, "%s failed: %s", ctx, err ? err : "?");
    if (err)
        sqlite3_free(err);
    return false;
}

static bool ensure_schema(sqlite3 *db)
{
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS topology_edges ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " observer_ip TEXT NOT NULL,"
        " observer_port INTEGER NOT NULL,"
        " advertised_ip TEXT NOT NULL,"
        " advertised_port INTEGER NOT NULL,"
        " first_advertised INTEGER NOT NULL,"
        " last_advertised INTEGER NOT NULL,"
        " times_seen INTEGER NOT NULL DEFAULT 1,"
        " UNIQUE(observer_ip,observer_port,advertised_ip,advertised_port))",
        "create topology_edges") &&
      exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_topology_edges_last_advertised "
        "ON topology_edges(last_advertised)",
        "create idx_topology_edges_last_advertised") &&
      exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_topology_edges_advertised "
        "ON topology_edges(advertised_ip,advertised_port)",
        "create idx_topology_edges_advertised") &&
      exec_sql(db,
        "CREATE TABLE IF NOT EXISTS topology_sweeps ("
        " sweep_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " started_unix INTEGER NOT NULL,"
        " finished_unix INTEGER NOT NULL DEFAULT 0,"
        " nodes_contacted INTEGER NOT NULL DEFAULT 0,"
        " nodes_reachable INTEGER NOT NULL DEFAULT 0,"
        " edges_seen INTEGER NOT NULL DEFAULT 0,"
        " new_nodes INTEGER NOT NULL DEFAULT 0)",
        "create topology_sweeps") &&
      exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_topology_sweeps_started "
        "ON topology_sweeps(started_unix DESC)",
        "create idx_topology_sweeps_started");
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

bool topology_store_open(const char *datadir)
{
    if (!datadir || !datadir[0]) {
        LOG_WARN(TOPOLOGY_SUBSYS, "open: empty datadir");
        return false;
    }
    zcl_mutex_lock(topology_lock_handle());
    if (atomic_load_explicit(&g_db, memory_order_acquire)) {
        zcl_mutex_unlock(topology_lock_handle());
        return true; /* idempotent */
    }

    char path[768];
    int n = snprintf(path, sizeof(path), "%s/topology.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_WARN(TOPOLOGY_SUBSYS, "open: datadir path too long");
        zcl_mutex_unlock(topology_lock_handle());
        return false;
    }

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(
        path, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (rc != SQLITE_OK || !db) {
        LOG_WARN(TOPOLOGY_SUBSYS, "open(%s) failed: %s", path,
                 db ? sqlite3_errmsg(db) : "?");
        if (db)
            sqlite3_close(db);
        zcl_mutex_unlock(topology_lock_handle());
        return false;
    }
    /* WAL, with a real autocheckpoint AND a size bound above it.
     *
     * A field box carried a 383 MB topology.db-wal against a 49 MB
     * topology.db. SQLite's default autocheckpoint (1000 pages, ~4 MB) is
     * supposed to prevent exactly that, and it does — right up until a
     * checkpoint cannot complete, which is the normal state of this store:
     * every checkpoint attempt runs on the writer's own connection at the
     * end of a transaction, and any concurrent reader holding an older
     * snapshot makes it a no-op. The WAL then grows without limit, and
     * nothing here ever looked at its size, so nobody found out.
     *
     * Two things fix that. wal_autocheckpoint is set EXPLICITLY, so the
     * value is a decision in this file rather than whatever the library
     * default happens to be. And topology_store_wal_checkpoint_if_over()
     * below runs a TRUNCATE checkpoint from the housekeeping tick once the
     * WAL exceeds its bound, which is the thing the passive per-commit
     * attempt cannot do on its own. */
    (void)sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    (void)sqlite3_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    char autockpt[64];
    snprintf(autockpt, sizeof(autockpt), "PRAGMA wal_autocheckpoint=%d",
             TOPOLOGY_WAL_AUTOCHECKPOINT_PAGES);
    (void)sqlite3_exec(db, autockpt, NULL, NULL, NULL);

    if (!ensure_schema(db)) {
        sqlite3_close(db);
        zcl_mutex_unlock(topology_lock_handle());
        return false;
    }

    int64_t count = 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM topology_edges", -1, &s,
                           NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:topology-store-kernel
            count = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    snprintf(g_path, sizeof(g_path), "%s", path);
    atomic_store_explicit(&g_row_count, count, memory_order_relaxed);
    atomic_store_explicit(&g_db, db, memory_order_release);
    zcl_mutex_unlock(topology_lock_handle());
    return true;
}


/* ── WAL bound ────────────────────────────────────────────────────────
 *
 * The passive checkpoint SQLite attempts at each commit is a no-op whenever
 * a reader holds an older snapshot, and nothing else ever measured the
 * result. This is the measurement plus the checkpoint that is allowed to
 * block briefly for it: SQLITE_CHECKPOINT_TRUNCATE both drains every frame
 * into the database and resets the WAL file to zero length, so the bound is
 * on the file an operator can see with ls, not on an internal frame count.
 *
 * `max_bytes` <= 0 disables the bound. Returns true only when a checkpoint
 * actually ran and reported success. */
bool topology_store_wal_checkpoint_if_over(int64_t max_bytes,
                                           int64_t *out_wal_bytes_before)
{
    if (out_wal_bytes_before)
        *out_wal_bytes_before = -1;
    sqlite3 *db = atomic_load_explicit(&g_db, memory_order_acquire);
    if (!db || max_bytes <= 0)
        return false;

    char wal_path[832];
    zcl_mutex_lock(topology_lock_handle());
    int n = snprintf(wal_path, sizeof(wal_path), "%s-wal", g_path);
    zcl_mutex_unlock(topology_lock_handle());
    if (n <= 0 || (size_t)n >= sizeof(wal_path))
        return false;

    int64_t wal_bytes = log_rotate_file_size(wal_path);
    if (out_wal_bytes_before)
        *out_wal_bytes_before = wal_bytes;
    if (wal_bytes < 0 || wal_bytes <= max_bytes)
        return false;

    int log_frames = 0, checkpointed = 0;
    int rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
                                       &log_frames, &checkpointed);
    if (rc != SQLITE_OK) {
        /* SQLITE_BUSY here is the ordinary "a reader is still holding an old
         * snapshot" answer, not a fault: the next tick tries again. It is
         * still named, because a WAL that never drains across many ticks is
         * a reader leak and an operator must be able to see it. */
        LOG_WARN(TOPOLOGY_SUBSYS,
                 "wal checkpoint at %lld bytes (bound %lld) rc=%d (%s) "
                 "log_frames=%d checkpointed=%d",
                 (long long)wal_bytes, (long long)max_bytes, rc,
                 sqlite3_errstr(rc), log_frames, checkpointed);
        return false;
    }
    LOG_INFO(TOPOLOGY_SUBSYS,
             "wal truncated: was %lld bytes (bound %lld), %d frames "
             "checkpointed",
             (long long)wal_bytes, (long long)max_bytes, checkpointed);
    return true;
}

int64_t topology_store_wal_bytes(void)
{
    if (!atomic_load_explicit(&g_db, memory_order_acquire))
        return -1;
    char wal_path[832];
    zcl_mutex_lock(topology_lock_handle());
    int n = snprintf(wal_path, sizeof(wal_path), "%s-wal", g_path);
    zcl_mutex_unlock(topology_lock_handle());
    if (n <= 0 || (size_t)n >= sizeof(wal_path))
        return -1;
    return log_rotate_file_size(wal_path);
}

void topology_store_close(void)

{
    zcl_mutex_lock(topology_lock_handle());
    sqlite3 *db = atomic_exchange_explicit(&g_db, NULL, memory_order_acq_rel);
    zcl_mutex_unlock(topology_lock_handle());
    if (db)
        sqlite3_close(db);
}

/* ── address rendering + validation ──────────────────────────────────── */

/* Render a distinct identity string for `a`. IPv4/IPv6 use the standard
 * dotted/colon form. Onion (torv3) addresses render the FULL 32-byte
 * public-key as hex (not a resolvable .onion string — identity/display
 * only) so distinct onion peers never collapse into one topology node. */
static void topology_render_addr(const struct net_addr *a, char *out,
                                 size_t out_sz)
{
    if (!a || !out_sz)
        return;
    if (a->has_torv3) {
        char hex[2 * TORV3_ADDR_SIZE + 1];
        zcl_hex_encode(a->torv3, TORV3_ADDR_SIZE, hex);
        snprintf(out, out_sz, "onion:%s", hex);
        return;
    }
    net_addr_to_string(a, out, out_sz);
}

/* PEDANTIC: reuse the same IsRoutable-class helper addrman_add() gates
 * ingestion on — reject anything non-routable (unspecified, loopback,
 * documentation ranges, private RFC1918/RFC4193-non-tor, ...) before it
 * ever reaches storage. */
static bool topology_addr_valid(const struct net_addr *a)
{
    return a && net_addr_is_routable(a);
}

/* ── bounded eviction ─────────────────────────────────────────────────── */

/* Caller holds g_lock and a live db. Delete the `excess` globally-oldest
 * (by last_advertised) rows; decrement the in-memory row-count cache by
 * however many were actually removed. */
static void topology_evict_locked(sqlite3 *db, int64_t excess)
{
    if (excess <= 0)
        return;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM topology_edges WHERE id IN "
        "(SELECT id FROM topology_edges "
        " ORDER BY last_advertised ASC, id ASC LIMIT ?)",
        -1, &s, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(s, 1, excess);
    if (sqlite3_step(s) == SQLITE_DONE) { // raw-sql-ok:topology-store-kernel
        int changed = sqlite3_changes(db);
        if (changed > 0) {
            atomic_fetch_sub_explicit(&g_row_count, changed,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&g_evicted_total, (uint64_t)changed,
                                      memory_order_relaxed);
        }
    }
    sqlite3_finalize(s);
}

/* ── edge ingestion ───────────────────────────────────────────────────── */

/* Caller has already rendered+validated observer_str/advertised_addr.
 * Performs the exists-check(s), the bounded upsert, row-count bookkeeping,
 * and cap eviction. */
static bool record_edge_core(const char *observer_str, uint16_t observer_port,
                             const char *advertised_str,
                             uint16_t advertised_port, int64_t now_unix,
                             bool *out_new_advertised_node)
{
    if (out_new_advertised_node)
        *out_new_advertised_node = false;
    if (now_unix <= 0)
        now_unix = platform_time_wall_unix();

    zcl_mutex_lock(topology_lock_handle());
    sqlite3 *db = atomic_load_explicit(&g_db, memory_order_acquire);
    if (!db) {
        zcl_mutex_unlock(topology_lock_handle());
        return false;
    }

    bool edge_exists = false;
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM topology_edges WHERE observer_ip=? AND "
            "observer_port=? AND advertised_ip=? AND advertised_port=? "
            "LIMIT 1", -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_text(s, 1, observer_str, -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 2, observer_port);
            sqlite3_bind_text(s, 3, advertised_str, -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 4, advertised_port);
            edge_exists =
                sqlite3_step(s) == SQLITE_ROW; // raw-sql-ok:topology-store-kernel
            sqlite3_finalize(s);
        }
    }

    if (!edge_exists && out_new_advertised_node) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM topology_edges WHERE advertised_ip=? AND "
            "advertised_port=? LIMIT 1", -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_text(s, 1, advertised_str, -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 2, advertised_port);
            *out_new_advertised_node =
                sqlite3_step(s) != SQLITE_ROW; // raw-sql-ok:topology-store-kernel
            sqlite3_finalize(s);
        }
    }

    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO topology_edges"
        " (observer_ip,observer_port,advertised_ip,advertised_port,"
        "  first_advertised,last_advertised,times_seen)"
        " VALUES(?,?,?,?,?,?,1)"
        " ON CONFLICT(observer_ip,observer_port,advertised_ip,advertised_port)"
        " DO UPDATE SET"
        "  last_advertised=MAX(last_advertised,excluded.last_advertised),"
        "  times_seen=times_seen+1",
        -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_text(s, 1, observer_str, -1, SQLITE_STATIC);
        sqlite3_bind_int(s, 2, observer_port);
        sqlite3_bind_text(s, 3, advertised_str, -1, SQLITE_STATIC);
        sqlite3_bind_int(s, 4, advertised_port);
        sqlite3_bind_int64(s, 5, now_unix);
        sqlite3_bind_int64(s, 6, now_unix);
        ok = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:topology-store-kernel
        sqlite3_finalize(s);
    }

    if (ok) {
        atomic_fetch_add_explicit(&g_edges_recorded_total, 1,
                                  memory_order_relaxed);
        if (!edge_exists) {
            int64_t rc = atomic_fetch_add_explicit(&g_row_count, 1,
                                                    memory_order_relaxed) +
                        1;
            int64_t cap = atomic_load_explicit(&g_cap, memory_order_relaxed);
            if (rc > cap)
                topology_evict_locked(db, rc - cap);
        }
    }
    zcl_mutex_unlock(topology_lock_handle());
    return ok;
}

bool topology_store_record_edge(const struct net_addr *observer_addr,
                                uint16_t observer_port,
                                const struct net_addr *advertised_addr,
                                uint16_t advertised_port, int64_t now_unix,
                                bool *out_new_advertised_node)
{
    if (out_new_advertised_node)
        *out_new_advertised_node = false;
    if (!topology_addr_valid(observer_addr) ||
        !topology_addr_valid(advertised_addr)) {
        atomic_fetch_add_explicit(&g_edges_rejected_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    char obs_s[TOPOLOGY_ADDR_STR_MAX];
    char adv_s[TOPOLOGY_ADDR_STR_MAX];
    topology_render_addr(observer_addr, obs_s, sizeof(obs_s));
    topology_render_addr(advertised_addr, adv_s, sizeof(adv_s));
    if (!obs_s[0] || !adv_s[0]) {
        atomic_fetch_add_explicit(&g_edges_rejected_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    return record_edge_core(obs_s, observer_port, adv_s, advertised_port,
                            now_unix, out_new_advertised_node);
}

bool topology_store_record_self_edge(const struct net_addr *advertised_addr,
                                     uint16_t advertised_port,
                                     int64_t now_unix,
                                     bool *out_new_advertised_node)
{
    if (out_new_advertised_node)
        *out_new_advertised_node = false;
    if (!topology_addr_valid(advertised_addr)) {
        atomic_fetch_add_explicit(&g_edges_rejected_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    char adv_s[TOPOLOGY_ADDR_STR_MAX];
    topology_render_addr(advertised_addr, adv_s, sizeof(adv_s));
    if (!adv_s[0]) {
        atomic_fetch_add_explicit(&g_edges_rejected_total, 1,
                                  memory_order_relaxed);
        return false;
    }
    return record_edge_core(TOPOLOGY_SELF_OBSERVER, 0, adv_s, advertised_port,
                            now_unix, out_new_advertised_node);
}

/* ── sweep summaries ──────────────────────────────────────────────────── */

bool topology_store_record_sweep(int64_t started_unix, int64_t finished_unix,
                                 int32_t nodes_contacted,
                                 int32_t nodes_reachable, int32_t edges_seen,
                                 int32_t new_nodes)
{
    zcl_mutex_lock(topology_lock_handle());
    sqlite3 *db = atomic_load_explicit(&g_db, memory_order_acquire);
    if (!db) {
        zcl_mutex_unlock(topology_lock_handle());
        return false;
    }
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO topology_sweeps"
        " (started_unix,finished_unix,nodes_contacted,nodes_reachable,"
        "  edges_seen,new_nodes) VALUES(?,?,?,?,?,?)",
        -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(s, 1, started_unix);
        sqlite3_bind_int64(s, 2, finished_unix);
        sqlite3_bind_int(s, 3, nodes_contacted);
        sqlite3_bind_int(s, 4, nodes_reachable);
        sqlite3_bind_int(s, 5, edges_seen);
        sqlite3_bind_int(s, 6, new_nodes);
        ok = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:topology-store-kernel
        sqlite3_finalize(s);
    }
    if (ok) {
        atomic_fetch_add_explicit(&g_sweeps_recorded_total, 1,
                                  memory_order_relaxed);
        /* Bounded retention: delete-oldest-past-cap, same idiom as
         * peers_projection's peer_sessions/fork_events ledgers. On an empty
         * table MAX(sweep_id) is NULL so `sweep_id <= NULL` matches
         * nothing — safe. */
        char prune[160];
        snprintf(prune, sizeof(prune),
                "DELETE FROM topology_sweeps WHERE sweep_id <= "
                "(SELECT MAX(sweep_id) FROM topology_sweeps) - %d",
                (int)TOPOLOGY_SWEEPS_CAP);
        (void)exec_sql(db, prune, "prune topology_sweeps");
    }
    zcl_mutex_unlock(topology_lock_handle());
    return ok;
}

/* ── introspection ────────────────────────────────────────────────────── */

static int64_t query_count_distinct(sqlite3 *db, const char *cols)
{
    char sql[192];
    snprintf(sql, sizeof(sql),
            "SELECT COUNT(*) FROM (SELECT DISTINCT %s FROM topology_edges)",
            cols);
    sqlite3_stmt *s = NULL;
    int64_t n = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:topology-store-kernel
            n = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    return n;
}

bool topology_store_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    zcl_mutex_lock(topology_lock_handle());
    sqlite3 *db = atomic_load_explicit(&g_db, memory_order_acquire);
    bool open = db != NULL;

    json_push_kv_bool(out, "open", open);
    json_push_kv_int(out, "edge_count",
                     atomic_load_explicit(&g_row_count, memory_order_relaxed));
    json_push_kv_int(out, "cap",
                     atomic_load_explicit(&g_cap, memory_order_relaxed));
    json_push_kv_int(out, "edges_recorded_total",
                 (int64_t)atomic_load_explicit(&g_edges_recorded_total,
                                               memory_order_relaxed));
    json_push_kv_int(out, "edges_rejected_total",
                 (int64_t)atomic_load_explicit(&g_edges_rejected_total,
                                               memory_order_relaxed));
    json_push_kv_int(out, "evicted_total",
                 (int64_t)atomic_load_explicit(&g_evicted_total,
                                               memory_order_relaxed));
    json_push_kv_int(out, "sweeps_recorded_total",
                 (int64_t)atomic_load_explicit(&g_sweeps_recorded_total,
                                               memory_order_relaxed));

    if (!open) {
        diag_push_health(out, true, "topology store not open");
        zcl_mutex_unlock(topology_lock_handle());
        return true;
    }

    int64_t distinct_observers =
        query_count_distinct(db, "observer_ip,observer_port");
    int64_t distinct_advertised =
        query_count_distinct(db, "advertised_ip,advertised_port");
    json_push_kv_int(out, "distinct_observers", distinct_observers);
    json_push_kv_int(out, "distinct_advertised_nodes", distinct_advertised);

    struct json_value top;
    json_init(&top);
    json_set_array(&top);
    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT advertised_ip,advertised_port,COUNT(*) AS in_degree,"
            " SUM(times_seen) AS total_seen FROM topology_edges "
            "GROUP BY advertised_ip,advertised_port "
            "ORDER BY in_degree DESC, total_seen DESC LIMIT 10",
            -1, &s, NULL) == SQLITE_OK) {
            while (sqlite3_step(s) == SQLITE_ROW) { // raw-sql-ok:topology-store-kernel
                struct json_value row;
                json_init(&row);
                json_set_object(&row);
                const char *ip = (const char *)sqlite3_column_text(s, 0);
                json_push_kv_str(&row, "advertised_ip", ip ? ip : "");
                json_push_kv_int(&row, "advertised_port",
                                 sqlite3_column_int(s, 1));
                json_push_kv_int(&row, "in_degree",
                                 sqlite3_column_int64(s, 2));
                json_push_kv_int(&row, "total_times_seen",
                                 sqlite3_column_int64(s, 3));
                (void)json_push_back(&top, &row);
                json_free(&row);
            }
            sqlite3_finalize(s);
        }
    }
    (void)json_push_kv(out, "top_advertised", &top);
    json_free(&top);

    {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT sweep_id,started_unix,finished_unix,nodes_contacted,"
            " nodes_reachable,edges_seen,new_nodes FROM topology_sweeps "
            "ORDER BY sweep_id DESC LIMIT 1", -1, &s, NULL) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) { // raw-sql-ok:topology-store-kernel
                struct json_value sw;
                json_init(&sw);
                json_set_object(&sw);
                json_push_kv_int(&sw, "sweep_id", sqlite3_column_int64(s, 0));
                json_push_kv_int(&sw, "started_unix",
                                 sqlite3_column_int64(s, 1));
                json_push_kv_int(&sw, "finished_unix",
                                 sqlite3_column_int64(s, 2));
                json_push_kv_int(&sw, "nodes_contacted",
                                 sqlite3_column_int64(s, 3));
                json_push_kv_int(&sw, "nodes_reachable",
                                 sqlite3_column_int64(s, 4));
                json_push_kv_int(&sw, "edges_seen",
                                 sqlite3_column_int64(s, 5));
                json_push_kv_int(&sw, "new_nodes",
                                 sqlite3_column_int64(s, 6));
                (void)json_push_kv(out, "last_sweep", &sw);
                json_free(&sw);
            }
            sqlite3_finalize(s);
        }
    }

    diag_push_health(out, true, "ok");
    zcl_mutex_unlock(topology_lock_handle());
    return true;
}

#ifdef ZCL_TESTING
void topology_store_test_reset(void)
{
    zcl_mutex_lock(topology_lock_handle());
    sqlite3 *db = atomic_load_explicit(&g_db, memory_order_acquire);
    if (db) {
        (void)exec_sql(db, "DELETE FROM topology_edges", "test_reset edges");
        (void)exec_sql(db, "DELETE FROM topology_sweeps", "test_reset sweeps");
        atomic_store_explicit(&g_row_count, 0, memory_order_relaxed);
    }
    atomic_store_explicit(&g_edges_recorded_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_edges_rejected_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_evicted_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_sweeps_recorded_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_cap, TOPOLOGY_EDGES_CAP_DEFAULT,
                          memory_order_relaxed);
    zcl_mutex_unlock(topology_lock_handle());
}

int64_t topology_store_test_edge_count(void)
{
    return atomic_load_explicit(&g_row_count, memory_order_relaxed);
}

int64_t topology_store_test_sweep_count(void)
{
    zcl_mutex_lock(topology_lock_handle());
    sqlite3 *db = atomic_load_explicit(&g_db, memory_order_acquire);
    int64_t n = 0;
    if (db) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM topology_sweeps", -1,
                               &s, NULL) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:topology-store-kernel
                n = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
        }
    }
    zcl_mutex_unlock(topology_lock_handle());
    return n;
}

void topology_store_test_set_cap(int64_t cap)
{
    atomic_store_explicit(&g_cap,
                          cap > 0 ? cap : (int64_t)TOPOLOGY_EDGES_CAP_DEFAULT,
                          memory_order_relaxed);
}
#endif
