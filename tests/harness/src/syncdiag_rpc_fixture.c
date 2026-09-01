/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixture bodies for the sync-diagnostic RPC test group — progress-store
 * seeding, JSON lookup shorthands, and synthetic connman peers shared by
 * every test_syncdiag_*.c case file.
 */

#include "test/syncdiag_rpc_fixture.h"

/* No-shell dev-status collector for tests. os-substrate Rung 0 (site 11) made
 * agent_collect_optional_status run ZCL_AGENT_DEV_STATUS_CMD as an argv via
 * execvp (no shell), so the old `printf '...'` shell command no longer works.
 * Write the fixed JSON to a temp file and point the collector at a bare
 * `cat <path>` command — pure argv, no shell quoting or redirection. */
bool set_dev_status_cmd_json(const char *json)
{
    char path[128];
    snprintf(path, sizeof(path), "/tmp/zcl_devstatus_%d.json", (int)getpid());
    FILE *f = fopen(path, "w");
    if (!f) return false;
    fputs(json, f);
    fclose(f);
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "cat %s", path);
    return setenv("ZCL_AGENT_DEV_STATUS_CMD", cmd, 1) == 0;
}

/* Push a 64 KiB frame filled with 0xCC onto the stack, then return.
 * The frame is freed on return but the bytes persist in memory — any
 * subsequent callee with a smaller combined frame size reuses that
 * region, observing 0xCC where `= {0}` would have given zeros. */
__attribute__((noinline)) void dirty_stack_region(void)
{
    volatile unsigned char junk[65536];
    for (size_t i = 0; i < sizeof(junk); i++)
        junk[i] = 0xCC;
    /* Force the compiler to materialize the writes. */
    __asm__ volatile("" : : "r"(junk) : "memory");
}

void *syncdiag_hold_peer_lock(void *arg)
{
    struct syncdiag_peer_lock_hold *hold = arg;
    zcl_mutex_lock(&hold->connman->manager.cs_nodes);
    atomic_store(&hold->ready, true);
    while (!atomic_load(&hold->release))
        platform_sleep_ms(1);
    zcl_mutex_unlock(&hold->connman->manager.cs_nodes);
    return NULL;
}

const struct json_value *find_service(const struct json_value *arr,
                                      const char *name)
{
    if (!arr || arr->type != JSON_ARR || !name)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *svc = json_at(arr, i);
        const struct json_value *n = json_get(svc, "name");
        if (n && strcmp(json_get_str(n), name) == 0)
            return svc;
    }
    return NULL;
}

const struct json_value *find_source_json(const struct json_value *arr,
                                          const char *source)
{
    if (!arr || arr->type != JSON_ARR || !source)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *child = json_at(arr, i);
        const struct json_value *name = json_get(child, "source");
        if (name && strcmp(json_get_str(name), source) == 0)
            return child;
    }
    return NULL;
}

bool syncdiag_touch_file(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    fclose(f);
    return true;
}

bool syncdiag_set_progress_mtime_seconds_ago(const char *dir,
                                             int64_t seconds_ago)
{
    char path[512];
    if (!dir || seconds_ago < 0 ||
        snprintf(path, sizeof(path), "%s/progress.kv", dir) >=
            (int)sizeof(path))
        return false;

    int64_t now = platform_time_wall_unix();
    if (now <= seconds_ago)
        return false;
    struct utimbuf tb;
    tb.actime = (time_t)(now - seconds_ago);
    tb.modtime = (time_t)(now - seconds_ago);
    return utime(path, &tb) == 0;
}

bool syncdiag_exec_sql(sqlite3 *db, const char *sql);

bool syncdiag_open_fresh_progress_wal(const char *dir,
                                      sqlite3 **db_out)
{
    char path[512];
    sqlite3 *db = NULL;
    if (db_out)
        *db_out = NULL;
    if (!dir || !db_out ||
        snprintf(path, sizeof(path), "%s/progress.kv", dir) >=
            (int)sizeof(path) || sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    bool ok = syncdiag_exec_sql(db, "PRAGMA journal_mode=WAL") &&
        syncdiag_exec_sql(db,
            "UPDATE stage_cursor SET updated_at=COALESCE(updated_at,0)+1 "
            "WHERE name='tip_finalize'");
    if (!ok) {
        sqlite3_close(db);
        return false;
    }
    *db_out = db;
    return true;
}

bool syncdiag_set_utxo_sample_ages(const char *dir,
                                   int64_t older_age,
                                   int64_t newer_age)
{
    char path[512];
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int64_t now = platform_time_wall_unix();
    if (!dir || older_age <= newer_age || newer_age < 0 || now <= older_age ||
        snprintf(path, sizeof(path), "%s/progress.kv", dir) >=
            (int)sizeof(path) || sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    const char *sql =
        "UPDATE utxo_apply_log SET applied_at=CASE height "
        "WHEN 0 THEN ?1 WHEN 163999 THEN ?2 ELSE applied_at END";
    bool ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int64(st, 1, now - older_age);
        sqlite3_bind_int64(st, 2, now - newer_age);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

bool syncdiag_set_coins_applied(sqlite3 *db, int32_t height)
{
    char *err = NULL;

    if (!db)
        return false;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, height);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (err) sqlite3_free(err);
    return ok;
}

const struct json_value *find_object_with_str(const struct json_value *arr,
                                              const char *key,
                                              const char *value)
{
    if (!arr || arr->type != JSON_ARR || !key || !value)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *child = json_at(arr, i);
        const struct json_value *field = json_get(child, key);
        if (field && strcmp(json_get_str(field), value) == 0)
            return child;
    }
    return NULL;
}

bool json_array_has_str(const struct json_value *arr, const char *value)
{
    if (!arr || arr->type != JSON_ARR || !value)
        return false;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *child = json_at(arr, i);
        if (child && strcmp(json_get_str(child), value) == 0)
            return true;
    }
    return false;
}

bool json_array_has_substr(const struct json_value *arr,
                           const char *needle)
{
    if (!arr || arr->type != JSON_ARR || !needle)
        return false;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *child = json_at(arr, i);
        const char *s = json_get_str(child);
        if (s && strstr(s, needle))
            return true;
    }
    return false;
}

void syncdiag_set_ipv4(struct net_address *addr,
                       uint8_t a, uint8_t b,
                       uint8_t c, uint8_t d,
                       uint16_t port)
{
    net_address_init(addr);
    addr->svc.addr.ip[10] = 0xff;
    addr->svc.addr.ip[11] = 0xff;
    addr->svc.addr.ip[12] = a;
    addr->svc.addr.ip[13] = b;
    addr->svc.addr.ip[14] = c;
    addr->svc.addr.ip[15] = d;
    addr->svc.port = port;
}

void syncdiag_set_hash(struct uint256 *hash, uint8_t tag)
{
    if (!hash)
        return;
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = tag;
    hash->data[31] = (uint8_t)(0xffu ^ tag);
}

bool syncdiag_exec_sql(sqlite3 *db, const char *sql)
{
    if (!db || !sql)
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK)
        return true;
    if (err)
        sqlite3_free(err);
    return false;
}

bool syncdiag_seed_durable_tip_authority(
    int height, const uint8_t hash[32])
{
    sqlite3 *db = progress_store_db();
    sqlite3_stmt *stmt = NULL;
    if (!db || height < 0 || !hash)
        return false;
    progress_store_tx_lock();
    bool ok = syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
        "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL, "
        "work_delta_low INTEGER NOT NULL, utxo_size_after INTEGER NOT NULL, "
        "reorg_depth INTEGER NOT NULL, finalized_at INTEGER NOT NULL, "
        "tip_hash BLOB)");
    if (ok) {
        ok = sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(?,'anchor',1,0,0,0,0,1,?)",
            -1, &stmt, NULL) == SQLITE_OK;
    }
    if (ok) {
        sqlite3_bind_int(stmt, 1, height);
        sqlite3_bind_blob(stmt, 2, hash, 32, SQLITE_TRANSIENT);
        ok = sqlite3_step(stmt) == SQLITE_DONE; /* raw-sql-ok:test-fixture */
    }
    sqlite3_finalize(stmt);
    progress_store_tx_unlock();
    return ok;
}

bool syncdiag_seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (!db || !name)
        return false;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
            "VALUES(?, ?, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool syncdiag_seed_reducer_frontier_at_anchor(sqlite3 *db,
                                              int32_t anchor)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";

    return db &&
        syncdiag_exec_sql(db, ddl) &&
        syncdiag_seed_cursor(db, "validate_headers", anchor + 1) &&
        syncdiag_seed_cursor(db, "script_validate", anchor + 1) &&
        syncdiag_seed_cursor(db, "body_persist", anchor + 1) &&
        syncdiag_seed_cursor(db, "proof_validate", anchor + 1) &&
        syncdiag_seed_cursor(db, "utxo_apply", anchor + 1) &&
        syncdiag_seed_cursor(db, "tip_finalize", anchor);
}

void syncdiag_write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

void syncdiag_write_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

bool syncdiag_write_empty_anchor_snapshot(const char *dir)
{
    char path[512];
    if (!dir || snprintf(path, sizeof(path), "%s/utxo-anchor.snapshot", dir) >=
                    (int)sizeof(path))
        return false;
    uint8_t header[104] = {0};
    memcpy(header, "ZCLUTXO\0", 8);
    syncdiag_write_le32(header + 8, 1);
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    sha3_256_init(&ctx);
    sha3_256_finalize(&ctx, digest);
    memcpy(header + 72, digest, sizeof(digest));
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(header, 1, sizeof(header), f) == sizeof(header);
    return fclose(f) == 0 && ok;
}

bool syncdiag_seed_meta_blob(sqlite3 *db, const char *key,
                             const void *blob, int len)
{
    sqlite3_stmt *st = NULL;
    if (!db || !key || (!blob && len > 0) || len < 0)
        return false;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?1,?2)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, len, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool syncdiag_create_height_log(sqlite3 *db, const char *table)
{
    char sql[160];
    if (!db || !table)
        return false;
    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s("
             "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)",
             table);
    return syncdiag_exec_sql(db, sql);
}

bool syncdiag_seed_log_point(sqlite3 *db, const char *table,
                             int64_t height)
{
    char sql[160];
    sqlite3_stmt *st = NULL;
    if (!db || !table)
        return false;
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO %s(height) VALUES(?1)", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool syncdiag_seed_log_verdict(sqlite3 *db, const char *table,
                               int64_t height, const char *status,
                               int ok_value)
{
    char sql[200];
    sqlite3_stmt *st = NULL;
    if (!db || !table || !status)
        return false;
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO %s(height,status,ok) "
             "VALUES(?1,?2,?3)", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_value);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool syncdiag_seed_anchorstatus_progress(const char *dir)
{
    char path[512];
    sqlite3 *db = NULL;
    if (!dir ||
        snprintf(path, sizeof(path), "%s/progress.kv", dir) >=
            (int)sizeof(path))
        return false;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    bool ok = true;
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS stage_cursor("
        "name TEXT PRIMARY KEY, cursor INTEGER, updated_at INTEGER)");
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS progress_meta("
        "key TEXT PRIMARY KEY, value BLOB)");

    const char *logs[] = {
        "header_admit_log", "validate_headers_log", "body_fetch_log",
        "body_persist_log", "script_validate_log", "proof_validate_log",
        "utxo_apply_log", "tip_finalize_log",
    };
    for (size_t i = 0; ok && i < sizeof(logs) / sizeof(logs[0]); i++)
        ok = syncdiag_create_height_log(db, logs[i]);
    ok = ok && syncdiag_exec_sql(
        db, "ALTER TABLE utxo_apply_log ADD COLUMN applied_at INTEGER");

    ok = ok && syncdiag_seed_cursor(db, "header_admit", 2791000);
    ok = ok && syncdiag_seed_cursor(db, "validate_headers", 2791000);
    ok = ok && syncdiag_seed_cursor(db, "body_fetch", 2791000);
    ok = ok && syncdiag_seed_cursor(db, "body_persist", 2791000);
    ok = ok && syncdiag_seed_cursor(db, "script_validate", 2791000);
    ok = ok && syncdiag_seed_cursor(db, "proof_validate", 2791000);
    ok = ok && syncdiag_seed_cursor(db, "utxo_apply", 164000);
    ok = ok && syncdiag_seed_cursor(db, "tip_finalize", 164000);

    ok = ok && syncdiag_seed_log_point(db, "header_admit_log", 0);
    ok = ok && syncdiag_seed_log_point(db, "header_admit_log", 3166384);
    ok = ok && syncdiag_seed_log_point(db, "proof_validate_log", 0);
    ok = ok && syncdiag_seed_log_verdict(db, "proof_validate_log", 164000,
                                         "verified", 1);
    ok = ok && syncdiag_seed_log_verdict(db, "script_validate_log", 164000,
                                         "verified", 1);
    ok = ok && syncdiag_seed_log_verdict(db, "proof_validate_log", 2790999,
                                         "verified", 1);
    ok = ok && syncdiag_seed_log_verdict(db, "utxo_apply_log", 0,
                                         "verified", 1);
    ok = ok && syncdiag_seed_log_verdict(db, "utxo_apply_log", 163999,
                                         "verified", 1);
    ok = ok && syncdiag_exec_sql(
        db, "UPDATE utxo_apply_log SET applied_at="
            "CASE height WHEN 0 THEN 1000 WHEN 163999 THEN 1060 END");

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    uint8_t marker[48] = {0};
    memcpy(marker, "ZAM1", 4);
    if (cp) {
        syncdiag_write_le32(marker + 4, (uint32_t)cp->height);
        syncdiag_write_le64(marker + 8, cp->utxo_count);
        memcpy(marker + 16, cp->sha3_hash, 32);
    }
    ok = ok && cp &&
        syncdiag_seed_meta_blob(db, "mint_anchor_in_progress_v1",
                                marker, sizeof(marker));

    uint8_t height_blob[8] = {0};
    syncdiag_write_le64(height_blob, 164000);
    ok = ok && syncdiag_seed_meta_blob(db, "coins_applied_height",
                                       height_blob, sizeof(height_blob));
    const uint8_t one = 1;
    ok = ok && syncdiag_seed_meta_blob(db, "refold_in_progress", &one, 1);

    sqlite3_close(db);
    return ok;
}

bool syncdiag_seed_body_position_hazard(const char *dir)
{
    char path[512];
    sqlite3 *db = NULL;
    if (!dir || snprintf(path, sizeof(path), "%s/progress.kv", dir) >=
                    (int)sizeof(path) || sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    bool ok = syncdiag_seed_cursor(db, "body_persist", 1) &&
        syncdiag_seed_cursor(db, "body_fetch", 2791000);
    sqlite3_close(db);
    return ok;
}

bool syncdiag_seed_log_rows(sqlite3 *db, const char *insert_sql,
                            int max_height)
{
    sqlite3_stmt *st = NULL;
    if (!db || !insert_sql || max_height < 0)
        return false;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h <= max_height; h++) {
        sqlite3_bind_int(st, 1, h);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
    return true;
}

bool syncdiag_seed_lookahead_reducer_progress(int served_height)
{
    sqlite3 *db = progress_store_db();
    if (!db || served_height < 0)
        return false;

    int next_height = served_height + 1;
    bool ok = true;
    progress_store_tx_lock();
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "height INTEGER PRIMARY KEY, hash BLOB, ok INTEGER NOT NULL)");
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
        "ok INTEGER NOT NULL, tx_count INTEGER NOT NULL, "
        "input_count INTEGER NOT NULL, validated_at INTEGER NOT NULL, "
        "block_hash BLOB)");
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL)");
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL)");
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL, "
        "spent_count INTEGER, added_count INTEGER)");
    ok = ok && syncdiag_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
        "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL, "
        "work_delta_low INTEGER NOT NULL, utxo_size_after INTEGER NOT NULL, "
        "reorg_depth INTEGER NOT NULL, finalized_at INTEGER NOT NULL, "
        "tip_hash BLOB)");

    ok = ok && syncdiag_seed_log_rows(db,
        "INSERT OR REPLACE INTO validate_headers_log(height, hash, ok) "
        "VALUES(?, zeroblob(32), 1)",
        served_height);
    ok = ok && syncdiag_seed_log_rows(db,
        "INSERT OR REPLACE INTO script_validate_log"
        "(height, status, ok, tx_count, input_count, validated_at, "
        "block_hash) VALUES(?, 'verified', 1, 1, 0, 1, zeroblob(32))",
        served_height);
    ok = ok && syncdiag_seed_log_rows(db,
        "INSERT OR REPLACE INTO body_persist_log(height, source, ok) "
        "VALUES(?, 'fixture', 1)",
        served_height);
    ok = ok && syncdiag_seed_log_rows(db,
        "INSERT OR REPLACE INTO proof_validate_log(height, status, ok) "
        "VALUES(?, 'verified', 1)",
        served_height);
    ok = ok && syncdiag_seed_log_rows(db,
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height, status, ok, spent_count, added_count) "
        "VALUES(?, 'verified', 1, 0, 0)",
        served_height);
    ok = ok && syncdiag_seed_log_rows(db,
        "INSERT OR REPLACE INTO tip_finalize_log"
        "(height, status, ok, work_delta_high, work_delta_low, "
        "utxo_size_after, reorg_depth, finalized_at, tip_hash) "
        "VALUES(?, 'finalized', 1, 0, 0, 0, 0, 1, zeroblob(32))",
        served_height);

    ok = ok && syncdiag_seed_cursor(db, "validate_headers", next_height);
    ok = ok && syncdiag_seed_cursor(db, "script_validate", next_height);
    ok = ok && syncdiag_seed_cursor(db, "body_persist", next_height);
    ok = ok && syncdiag_seed_cursor(db, "proof_validate", next_height);
    ok = ok && syncdiag_seed_cursor(db, "utxo_apply", next_height);
    ok = ok && syncdiag_seed_cursor(db, "tip_finalize", served_height);
    progress_store_tx_unlock();
    return ok;
}

struct p2p_node *syncdiag_add_peer(struct connman *cm,
                                   uint8_t last_octet,
                                   bool inbound,
                                   enum peer_state state)
{
    struct net_address addr;
    if (!cm)
        return NULL;
    if (!cm->manager.nodes) {
        cm->manager.nodes = zcl_calloc(8, sizeof(*cm->manager.nodes),
                                       "syncdiag_net_nodes");
        cm->manager.nodes_cap = 8;
        if (!cm->manager.nodes)
            return NULL;
    }
    if (cm->manager.num_nodes >= cm->manager.nodes_cap)
        return NULL;
    syncdiag_set_ipv4(&addr, 198, 51, 100, last_octet, 8033);
    struct p2p_node *node = p2p_node_create(
        &cm->manager, ZCL_INVALID_SOCKET, &addr, "syncdiag-net", inbound);
    if (!node)
        return NULL;
    node->state = state;
    node->services = NODE_NETWORK | NODE_ZCL23;
    snprintf(node->sub_ver, sizeof(node->sub_ver),
             "%s", "/ZClassic23:0.1.0/");
    snprintf(node->clean_sub_ver, sizeof(node->clean_sub_ver),
             "%s", node->sub_ver);
    node->starting_height = 3117074;
    cm->manager.nodes[cm->manager.num_nodes++] = node;
    return node;
}

void syncdiag_note_peer_lifecycle_active(
    const struct p2p_node *node, enum peer_lifecycle_source source)
{
    if (!node)
        return;
    peer_lifecycle_note_connected(node, source);
    peer_lifecycle_note_version_received(node, node->services,
                                         node->starting_height,
                                         node->sub_ver);
    if (node->state == PEER_HANDSHAKE_COMPLETE) {
        peer_lifecycle_note_handshake_complete(node);
        peer_lifecycle_note_active(node);
    }
}

void syncdiag_reset_rpc_globals_for_test(void)
{
    rpc_net_set_connman(NULL);
    rpc_net_set_boot_context(NULL, NULL);
    msg_version_clear_external_ip_for_test();
    peer_lifecycle_reset_for_test();
}

/* Fetch a criterion object by its "id" from an mvp criteria array (or NULL). */
const struct json_value *mvp_find_criterion(const struct json_value *arr,
                                            const char *id)
{
    if (!arr || arr->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *c = json_at(arr, i);
        if (c && strcmp(json_get_str(json_get(c, "id")), id) == 0)
            return c;
    }
    return NULL;
}
