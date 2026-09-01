/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for the ZCL_COMMAND_SCOPE_OFFLINE_COPY native leaves
 * (tools/command/native_offline_query.c):
 *
 *   core.storage.query.offline    (zcl_native_handle_core_storage_query_offline)
 *   core.sync.frontier.offline    (zcl_native_handle_core_sync_frontier_offline)
 *
 * Both read a datadir directly off disk with NO node contact and NO RPC —
 * the point being a STOPPED or COPIED datadir is inspectable without
 * booting a full node against it. Each test builds a real on-disk fixture
 * datadir (not :memory:, since the handlers under test open real files at
 * a caller-supplied path) then calls the handler function directly.
 *
 * The reducer-frontier fixture mirrors test_reducer_frontier.c's
 * case_consistent (proven-authority anchor + a contiguous ok=1 run above
 * it) — same shape, written through progress_store_open() at a real
 * directory instead of an in-memory handle. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "controllers/diagnostics_controller.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define ODQ_CHECK(name, expr) do {                                    \
    printf("offline_datadir_query: %s... ", (name));                  \
    if (expr) { printf("OK\n"); }                                     \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

#define A REDUCER_FRONTIER_TRUSTED_ANCHOR

/* ── reducer_frontier fixture builder (trimmed copy of the helpers in
 * test_reducer_frontier.c's "consistent" case — see that file for the full
 * matrix; this file only needs the one straightforward scenario). ── */

static bool odq_build_kernel_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor ("
        "  name TEXT PRIMARY KEY,"
        "  cursor INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_offline_datadir_query] schema: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Stamp coins_kv proven-authority so compute_hstar treats the baked
 * TRUSTED_ANCHOR as a real finality floor (mirrors coins_kv_is_proven_
 * authority: an 8-byte LE coins_applied_height, the migration-complete
 * stamp, and a non-empty coins table). */
static bool odq_stamp_proven_authority(sqlite3 *db, int64_t applied_height)
{
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
    uint8_t one = 1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, ah, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool odq_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET "
            "cursor=excluded.cursor, updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool odq_set_all_cursors(sqlite3 *db, int64_t c)
{
    return odq_set_cursor(db, "validate_headers", c)
        && odq_set_cursor(db, "body_fetch", c)
        && odq_set_cursor(db, "body_persist", c)
        && odq_set_cursor(db, "proof_validate", c)
        && odq_set_cursor(db, "script_validate", c)
        && odq_set_cursor(db, "utxo_apply", c)
        && odq_set_cursor(db, "tip_finalize", c);
}

static void odq_synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
}

/* Insert one fully-consistent, ok=1 row into every log compute_hstar folds
 * over, at height `h` (same shape as test_reducer_frontier.c's
 * put_consistent_height). */
static bool odq_put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    odq_synth_hash(hh, h);
    char sql[256];
    sqlite3_stmt *st;

#define ODQ_EXEC(fmt, bindfn) do {                                     \
        st = NULL;                                                    \
        snprintf(sql, sizeof(sql), fmt);                               \
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)   \
            return false;                                             \
        bindfn                                                        \
        bool ok_ = sqlite3_step(st) == SQLITE_DONE;                    \
        sqlite3_finalize(st);                                         \
        if (!ok_) return false;                                       \
    } while (0)

    ODQ_EXEC("INSERT INTO header_admit_log(height,hash,admitted_at) "
             "VALUES(?,?,0)",
             { sqlite3_bind_int(st, 1, h);
               sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC); });
    ODQ_EXEC("INSERT INTO validate_headers_log(height,hash,ok) "
             "VALUES(?,?,1)",
             { sqlite3_bind_int(st, 1, h);
               sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC); });
    ODQ_EXEC("INSERT INTO script_validate_log(height,status,ok,block_hash) "
             "VALUES(?,'verified',1,?)",
             { sqlite3_bind_int(st, 1, h);
               sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC); });
    ODQ_EXEC("INSERT INTO body_persist_log(height,ok) VALUES(?,1)",
             { sqlite3_bind_int(st, 1, h); });
    ODQ_EXEC("INSERT INTO proof_validate_log(height,status,ok,block_hash) "
             "VALUES(?,'verified',1,?)",
             { sqlite3_bind_int(st, 1, h);
               sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC); });
    ODQ_EXEC("INSERT INTO utxo_apply_log(height,status,ok) "
             "VALUES(?,'verified',1)",
             { sqlite3_bind_int(st, 1, h); });
    ODQ_EXEC("INSERT INTO utxo_apply_delta"
             "(height,branch_hash,spent_blob,added_blob) "
             "VALUES(?,?,x'',x'')",
             { sqlite3_bind_int(st, 1, h);
               sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC); });
    ODQ_EXEC("INSERT INTO tip_finalize_log(height,status,ok) "
             "VALUES(?,'ok',1)",
             { sqlite3_bind_int(st, 1, h); });
#undef ODQ_EXEC
    return true;
}

/* ── core.sync.frontier.offline ──────────────────────────────────────── */

static int t_frontier_offline_reads_hstar(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "offline_frontier", "fixture");
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);

    ODQ_CHECK("frontier fixture: open", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    ODQ_CHECK("frontier fixture: db handle", db != NULL);
    ODQ_CHECK("frontier fixture: schema", odq_build_kernel_schema(db));
    ODQ_CHECK("frontier fixture: proven authority",
             odq_stamp_proven_authority(db, A));

    const int32_t tip = A + 5;
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && odq_put_consistent_height(db, h);
    ODQ_CHECK("frontier fixture: rows", built);
    ODQ_CHECK("frontier fixture: cursors", odq_set_all_cursors(db, tip + 1));
    ODQ_CHECK("frontier fixture: applied height at hstar+1",
             odq_stamp_proven_authority(db, tip + 1));
    progress_store_close();

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)(json_push_kv_str(&input, "datadir", dir));
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.core_sync_frontier_offline.v1");

    zcl_native_handle_core_sync_frontier_offline(&request, &reply);

    ODQ_CHECK("frontier offline: exit OK",
             reply.exit_code == ZCL_COMMAND_EXIT_OK);
    ODQ_CHECK("frontier offline: hstar == tip",
             json_get_int(json_get(&reply.data, "hstar")) == tip);
    ODQ_CHECK("frontier offline: served_floor == tip",
             json_get_int(json_get(&reply.data, "served_floor")) == tip);
    ODQ_CHECK("frontier offline: compiled_anchor == A",
             json_get_int(json_get(&reply.data, "compiled_anchor")) == A);
    ODQ_CHECK("frontier offline: refold_in_progress == false",
             !json_get_bool(json_get(&reply.data, "refold_in_progress")));
    ODQ_CHECK("frontier offline: applied height known",
             json_get_bool(json_get(&reply.data,
                                    "coins_applied_height_known")));
    ODQ_CHECK("frontier offline: applied height == tip+1",
             json_get_int(json_get(&reply.data,
                                   "coins_applied_height")) == tip + 1);
    ODQ_CHECK("frontier offline: borrowed authority is explicit",
             json_get_bool(json_get(&reply.data, "proven_authority")) &&
             !json_get_bool(json_get(&reply.data,
                                     "self_folded_marker")));
    ODQ_CHECK("frontier offline: borrowed copy cannot spend",
             !json_get_bool(json_get(&reply.data,
                                     "wallet_spend_static_allowed")) &&
             strcmp(json_get_str(json_get(&reply.data,
                                          "static_trust_state")),
                    "release_assisted_ready") == 0 &&
             strcmp(json_get_str(json_get(&reply.data,
                                          "wallet_spend_static_reason")),
                    "borrowed_seed_no_refold_marker") == 0);
    ODQ_CHECK("frontier offline: datadir echoed",
             strcmp(json_get_str(json_get(&reply.data, "datadir")), dir) == 0);

    zcl_command_reply_free(&reply);

    /* The exact same copied store becomes statically spend-capable only after
     * the producer-owned self-fold marker exists.  Runtime H* climb remains a
     * separate requirement and is named by the response. */
    ODQ_CHECK("frontier fixture: reopen for self-fold marker",
             progress_store_open(dir));
    db = progress_store_db();
    ODQ_CHECK("frontier fixture: mark self-folded",
             db && coins_kv_mark_self_folded(db));
    progress_store_close();

    zcl_command_reply_init(&reply, "zcl.core_sync_frontier_offline.v1");
    zcl_native_handle_core_sync_frontier_offline(&request, &reply);
    ODQ_CHECK("frontier offline: self-folded copy is sovereign",
             reply.exit_code == ZCL_COMMAND_EXIT_OK &&
             json_get_bool(json_get(&reply.data, "static_self_derived")) &&
             json_get_bool(json_get(&reply.data,
                                    "wallet_spend_static_allowed")) &&
             strcmp(json_get_str(json_get(&reply.data,
                                          "static_trust_state")),
                    "sovereign") == 0 &&
             strcmp(json_get_str(json_get(&reply.data,
                                          "runtime_proof_required")),
                    "two_sample_hstar_climb_and_current_money_snapshot") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

static int t_frontier_offline_missing_datadir(void)
{
    int failures = 0;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.core_sync_frontier_offline.v1");

    zcl_native_handle_core_sync_frontier_offline(&request, &reply);
    ODQ_CHECK("frontier offline: missing datadir -> FAILED",
             reply.status == ZCL_COMMAND_STATUS_FAILED);
    ODQ_CHECK("frontier offline: missing datadir -> MISSING_DATADIR",
             strcmp(reply.error.code, "MISSING_DATADIR") == 0);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

static int t_frontier_offline_no_kernel_store(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "offline_frontier", "empty");
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)(json_push_kv_str(&input, "datadir", dir));
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.core_sync_frontier_offline.v1");

    zcl_native_handle_core_sync_frontier_offline(&request, &reply);
    ODQ_CHECK("frontier offline: empty datadir -> BLOCKED",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED);
    ODQ_CHECK("frontier offline: empty datadir -> KERNEL_STORE_NOT_FOUND",
             strcmp(reply.error.code, "KERNEL_STORE_NOT_FOUND") == 0);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

/* ── core.storage.query.offline ──────────────────────────────────────── */

static bool odq_seed_node_db(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);

    struct node_db ndb;
    if (!node_db_open(&ndb, path))
        return false;
    char *err = NULL;
    bool ok = sqlite3_exec(ndb.db,
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,"
        "time,bits,nonce,solution,chain_work) VALUES("
        "x'aa', 424242, x'bb', 4, x'cc', 0, 0, x'', x'', x'')",
        NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_free(err);
    node_db_close(&ndb);
    return ok;
}

static int t_storage_query_offline_reads_row(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "offline_storage", "fixture");
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);

    ODQ_CHECK("storage fixture: seed node.db", odq_seed_node_db(dir));

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)(json_push_kv_str(&input, "datadir", dir));
    (void)(json_push_kv_str(&input, "sql",
                                   "SELECT height FROM blocks"));
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.storage_query.v1");

    zcl_native_handle_core_storage_query_offline(&request, &reply);

    ODQ_CHECK("storage offline: exit OK",
             reply.exit_code == ZCL_COMMAND_EXIT_OK);
    const struct json_value *rows = json_get(&reply.data, "rows");
    ODQ_CHECK("storage offline: one row back",
             rows && rows->type == JSON_ARR && rows->num_children == 1);
    ODQ_CHECK("storage offline: row height == 424242",
             rows && rows->num_children == 1 &&
             json_get_int(json_at(json_at(rows, 0), 0)) == 424242);
    ODQ_CHECK("storage offline: datadir echoed",
             strcmp(json_get_str(json_get(&reply.data, "datadir")), dir) == 0);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

static int t_storage_query_offline_secret_denied(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "offline_storage", "secret");
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);
    ODQ_CHECK("secret fixture: seed node.db", odq_seed_node_db(dir));

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)(json_push_kv_str(&input, "datadir", dir));
    (void)(json_push_kv_str(&input, "sql",
                                   "SELECT privkey FROM wallet_keys"));
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.storage_query.v1");

    zcl_native_handle_core_storage_query_offline(&request, &reply);
    ODQ_CHECK("storage offline: secret query -> FAILED",
             reply.status == ZCL_COMMAND_STATUS_FAILED);
    ODQ_CHECK("storage offline: secret query -> QUERY_REJECTED",
             strcmp(reply.error.code, "QUERY_REJECTED") == 0);
    ODQ_CHECK("storage offline: secret query message names the secret",
             strstr(reply.error.message, "secret") != NULL);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

static int t_storage_query_offline_missing_node_db(void)
{
    int failures = 0;
    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "offline_storage", "nodb");
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)(json_push_kv_str(&input, "datadir", dir));
    (void)(json_push_kv_str(&input, "sql", "SELECT 1"));
    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.storage_query.v1");

    zcl_native_handle_core_storage_query_offline(&request, &reply);
    ODQ_CHECK("storage offline: no node.db -> BLOCKED",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED);
    ODQ_CHECK("storage offline: no node.db -> NODE_DB_UNAVAILABLE",
             strcmp(reply.error.code, "NODE_DB_UNAVAILABLE") == 0);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

int test_offline_datadir_query(void)
{
    printf("\n=== offline datadir query tests ===\n");
    int failures = 0;

    failures += t_frontier_offline_reads_hstar();
    failures += t_frontier_offline_missing_datadir();
    failures += t_frontier_offline_no_kernel_store();
    failures += t_storage_query_offline_reads_row();
    failures += t_storage_query_offline_secret_denied();
    failures += t_storage_query_offline_missing_node_db();

    return failures;
}
