/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_seed_ledger — see net/rom_seed_ledger.h for the contract. A lib/
 * module talking raw SQLite (not the AR_* model macros, which live under
 * app/models and would invert the lib/->app/ dependency direction the
 * check-lib-layering gate enforces — see DEFENSIVE_CODING.md Gate #15).
 * Every raw SQLite step call below (tagged `raw-sql-ok`) is a documented,
 * principled exception, matching the existing
 * engine/modules/storage/src/peers_projection.c pattern for its own peer_sessions
 * retention-capped ledger. */

#include "net/rom_seed_ledger.h"

#include "json/json.h"
#include "platform/file_metadata.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/util.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

struct rom_seed_ledger {
    sqlite3 *db;
};

static _Atomic uint64_t g_retention_cap = ROM_SEED_LEDGER_RETENTION_CAP;

static bool exec_sql(sqlite3 *db, const char *sql, const char *ctx)
{
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        LOG_FAIL("rom_seed_ledger", "%s failed: %s", ctx,
                err ? err : "unknown");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static bool ensure_schema(sqlite3 *db)
{
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS artifact_serve_log ("
        " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        " peer_ip BLOB NOT NULL,"
        " peer_port INTEGER NOT NULL,"
        " artifact_id BLOB NOT NULL,"
        " chunks_served INTEGER NOT NULL,"
        " bytes_served INTEGER NOT NULL,"
        " started_unix INTEGER NOT NULL,"
        " finished_unix INTEGER NOT NULL"
        ")",
        "create artifact_serve_log") &&
        exec_sql(db,
        "CREATE INDEX IF NOT EXISTS idx_artifact_serve_log_artifact "
        "ON artifact_serve_log(artifact_id, finished_unix)",
        "create artifact_serve_log index");
}

rom_seed_ledger_t *rom_seed_ledger_open(const char *datadir)
{
    if (!datadir || !datadir[0])
        LOG_NULL("rom_seed_ledger", "open: datadir required");
    char path[600];
    int n = snprintf(path, sizeof(path), "%s/%s", datadir,
                     ROM_SEED_LEDGER_FILENAME);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_NULL("rom_seed_ledger", "open: datadir path too long");

    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "%s",
                db ? sqlite3_errmsg(db) : "unknown");
        if (db) sqlite3_close(db);
        LOG_NULL("rom_seed_ledger", "sqlite3_open(%s) failed: %s", path,
                errbuf);
    }
    (void)exec_sql(db, "PRAGMA journal_mode=WAL", "set WAL mode");
    (void)exec_sql(db, "PRAGMA synchronous=NORMAL", "set synchronous");
    if (!ensure_schema(db)) {
        sqlite3_close(db);
        return NULL;
    }

    rom_seed_ledger_t *l = zcl_malloc(sizeof(*l), "rom_seed_ledger");
    if (!l) {
        sqlite3_close(db);
        return NULL;
    }
    l->db = db;
    return l;
}

void rom_seed_ledger_close(rom_seed_ledger_t *l)
{
    if (!l) return;
    if (l->db) sqlite3_close(l->db);
    free(l);
}

bool rom_seed_ledger_append(rom_seed_ledger_t *l, const uint8_t peer_ip[16],
                            uint16_t peer_port,
                            const uint8_t artifact_id[ROM_SEED_LEDGER_ARTIFACT_ID_LEN],
                            uint32_t chunks_served, uint64_t bytes_served,
                            int64_t started_unix, int64_t finished_unix)
{
    if (!l || !l->db || !peer_ip || !artifact_id)
        LOG_FAIL("rom_seed_ledger", "append: required arg missing");

    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(l->db,
        "INSERT INTO artifact_serve_log"
        "(peer_ip,peer_port,artifact_id,chunks_served,bytes_served,"
        " started_unix,finished_unix) VALUES(?,?,?,?,?,?,?)",
        -1, &s, NULL);
    if (rc != SQLITE_OK) {
        LOG_FAIL("rom_seed_ledger", "prepare insert failed: %s",
                sqlite3_errmsg(l->db));
        return false;
    }
    sqlite3_bind_blob(s, 1, peer_ip, 16, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, peer_port);
    sqlite3_bind_blob(s, 3, artifact_id, ROM_SEED_LEDGER_ARTIFACT_ID_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)chunks_served);
    sqlite3_bind_int64(s, 5, (sqlite3_int64)bytes_served);
    sqlite3_bind_int64(s, 6, started_unix);
    sqlite3_bind_int64(s, 7, finished_unix);
    rc = sqlite3_step(s);  // raw-sql-ok:rom-seed-ledger
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) {
        LOG_FAIL("rom_seed_ledger", "insert step failed: %s",
                sqlite3_errmsg(l->db));
        return false;
    }

    /* Retention: keep the newest N rows (delete-oldest past the cap),
     * mirroring peers_projection's peer_sessions prune. On an empty table
     * MAX(seq) is NULL, so `seq <= NULL` matches nothing — safe. */
    char prune[160];
    snprintf(prune, sizeof(prune),
            "DELETE FROM artifact_serve_log WHERE seq <= "
            "(SELECT MAX(seq) FROM artifact_serve_log) - %llu",
            (unsigned long long)atomic_load_explicit(&g_retention_cap,
                                                     memory_order_relaxed));
    return exec_sql(l->db, prune, "prune artifact_serve_log");
}

int64_t rom_seed_ledger_row_count(rom_seed_ledger_t *l)
{
    if (!l || !l->db) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(l->db, "SELECT COUNT(*) FROM artifact_serve_log",
                           -1, &s, NULL) != SQLITE_OK)
        return 0;
    int64_t n = 0;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:rom-seed-ledger
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

bool rom_seed_ledger_artifact_stats(
    rom_seed_ledger_t *l,
    const uint8_t artifact_id[ROM_SEED_LEDGER_ARTIFACT_ID_LEN],
    struct rom_seed_ledger_artifact_stats *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!l || !l->db || !artifact_id) return false;

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(l->db,
        "SELECT COALESCE(SUM(bytes_served),0),"
        "       COALESCE(SUM(chunks_served),0),"
        "       COUNT(*),"
        "       COALESCE(MAX(finished_unix),0),"
        "       COUNT(DISTINCT peer_ip || ':' || peer_port)"
        " FROM artifact_serve_log WHERE artifact_id=?",
        -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, artifact_id, ROM_SEED_LEDGER_ARTIFACT_ID_LEN,
                      SQLITE_TRANSIENT);
    bool found = false;
    if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:rom-seed-ledger
        out->total_bytes_served = (uint64_t)sqlite3_column_int64(s, 0);
        out->total_chunks_served = (uint64_t)sqlite3_column_int64(s, 1);
        out->sessions = (uint32_t)sqlite3_column_int64(s, 2);
        out->last_served_unix = sqlite3_column_int64(s, 3);
        out->distinct_peers = (uint32_t)sqlite3_column_int64(s, 4);
        found = out->sessions > 0;
    }
    sqlite3_finalize(s);
    return found;
}

size_t rom_seed_ledger_distinct_artifacts(
    rom_seed_ledger_t *l,
    uint8_t (*out_ids)[ROM_SEED_LEDGER_ARTIFACT_ID_LEN], size_t max)
{
    if (!l || !l->db || !out_ids || max == 0) return 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(l->db,
        "SELECT artifact_id, MAX(finished_unix) AS last_seen"
        " FROM artifact_serve_log"
        " GROUP BY artifact_id ORDER BY last_seen DESC LIMIT ?",
        -1, &s, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(s, 1, (sqlite3_int64)(max > INT64_MAX ? INT64_MAX
                                                             : (int64_t)max));
    size_t n = 0;
    while (n < max &&
          sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:rom-seed-ledger
        const void *blob = sqlite3_column_blob(s, 0);
        int len = sqlite3_column_bytes(s, 0);
        if (blob && len == ROM_SEED_LEDGER_ARTIFACT_ID_LEN) {
            memcpy(out_ids[n], blob, ROM_SEED_LEDGER_ARTIFACT_ID_LEN);
            n++;
        }
    }
    sqlite3_finalize(s);
    return n;
}

/* ── process-wide lazily-opened singleton ─────────────────────────────── */

static rom_seed_ledger_t *g_global_ledger = NULL;
static bool g_global_open_attempted = false;

rom_seed_ledger_t *rom_seed_ledger_global(void)
{
    if (g_global_ledger)
        return g_global_ledger;
    if (g_global_open_attempted)
        return NULL;
    char datadir[512];
    GetDataDir(false, datadir, sizeof(datadir));
    g_global_ledger = rom_seed_ledger_open(datadir);
    g_global_open_attempted = (g_global_ledger != NULL);
    return g_global_ledger;
}

bool rom_seed_ledger_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    /* Deliberately does NOT call rom_seed_ledger_global() — that would
     * sqlite3_open() (and WAL-journal-create) the ledger file as a side
     * effect of a bare introspection read. This dumper is reachable from
     * any passive whole-registry sweep (e.g. the `unhealthy` health
     * rollup, engine/controllers/src/diagnostics_health_rollup.c) running in
     * a process that never set up a test-isolated datadir, so a
     * creating-open here would plant a file (plus -wal/-shm sidecars) in
     * whatever datadir that caller happens to be pointed at. Peek the
     * already-open singleton (set only by an explicit prior open/append —
     * i.e. real seed-engine activity) for an accurate row count; when
     * nothing has opened it yet this process, report existence via a
     * non-creating stat() instead. */
    bool open = g_global_ledger != NULL;
    int64_t rows = open ? rom_seed_ledger_row_count(g_global_ledger) : 0;
    if (!open) {
        char datadir[512];
        GetDataDir(false, datadir, sizeof(datadir));
        char path[600];
        int n = snprintf(path, sizeof(path), "%s/%s", datadir,
                         ROM_SEED_LEDGER_FILENAME);
        struct platform_file_metadata metadata;
        if (n > 0 && (size_t)n < sizeof(path) &&
            platform_file_metadata_read(path, &metadata) ==
                PLATFORM_FILE_METADATA_OK)
            open = true;
    }
    (void)json_push_kv_bool(out, "open", open);
    (void)json_push_kv_int(out, "rows", rows);
    (void)json_push_kv_int(out, "retention_cap",
                           (int64_t)atomic_load_explicit(
                               &g_retention_cap, memory_order_relaxed));
    diag_push_health(out, true, "");
    return true;
}

#ifdef ZCL_TESTING
void rom_seed_ledger_test_set_retention_cap(uint64_t cap)
{
    atomic_store_explicit(&g_retention_cap, cap, memory_order_relaxed);
}

void rom_seed_ledger_test_reset_retention_cap(void)
{
    atomic_store_explicit(&g_retention_cap, ROM_SEED_LEDGER_RETENTION_CAP,
                          memory_order_relaxed);
}

void rom_seed_ledger_test_reset_global(void)
{
    if (g_global_ledger)
        rom_seed_ledger_close(g_global_ledger);
    g_global_ledger = NULL;
    g_global_open_attempted = false;
}
#endif
