/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * SQLite ActiveRecord model tests for ZClassic C23. */

#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "test/test_core.h"
#include "chain/chainparams.h"
#include "storage/coins_db.h"
#include "models/wallet_key.h"
#include "models/database_internal.h"
#include "models/database_lifetime.h"
#include "models/database_owner_lease.h"
#include "controllers/snapshot_controller.h"
#include "controllers/sync_controller.h"
#include "config/db_service.h"
#include "config/boot_projection_hole_scan.h"
#include "config/runtime.h"
#include "services/chain_evidence_persistence_service.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "support/cleanse.h"
#include "script/standard.h"
#include "coins/coins_view.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/safe_alloc.h"
#include "util/hw_profile.h"
#include "util/wal_checkpoint_stats.h"
#include <pthread.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <time.h>
#include <unistd.h>

/* Read a single-value PRAGMA off an open connection. Returns -1 when the
 * statement does not produce a row, so a missing setting can never be
 * mistaken for a setting of zero — which for wal_autocheckpoint is exactly
 * the value that means "unbounded". */
static int64_t sqlite_test_pragma_i64(sqlite3 *db, const char *pragma)
{
    sqlite3_stmt *stmt = NULL;
    int64_t value = -1;
    if (sqlite3_prepare_v2(db, pragma, -1, &stmt, NULL) == SQLITE_OK && stmt &&
        sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:read-only-introspection
        value = sqlite3_column_int64(stmt, 0);
    if (stmt)
        sqlite3_finalize(stmt);
    return value;
}

/* Write one wallet_keys row through the encryption-aware single writer
 * (the model save functions are gone — wallet_sqlite owns the secret
 * columns). Returns the row's derived pubkey_hash in kid_out. */
static bool sqlite_test_write_wallet_key(struct node_db *ndb, uint8_t seed,
                                         uint8_t kid_out[20])
{
    struct wallet_sqlite ws;
    if (!wallet_sqlite_open(&ws, ndb->db))
        return false;
    struct privkey key;
    struct pubkey pk;
    privkey_init(&key);
    memset(key.vch, seed, 32);
    key.vch[1] = (uint8_t)(seed ^ 0xAA);
    key.fValid = true;
    key.fCompressed = true;
    bool ok = privkey_get_pubkey(&key, &pk) &&
              wallet_sqlite_write_key(&ws, &pk, &key);
    if (ok) {
        struct key_id kid = pubkey_get_id(&pk);
        memcpy(kid_out, kid.id.data, 20);
    }
    wallet_sqlite_close(&ws);
    memory_cleanse(key.vch, 32);
    return ok;
}

static struct transaction make_sync_test_tx(void)
{
    struct transaction tx;
    uint8_t sig[] = {0x00, 0x00};
    uint8_t pk[] = {0x76, 0xa9, 0x14};

    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.overwintered = false;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_tx_vin");
    memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
    tx.vin[0].prevout.n = 0;
    script_set(&tx.vin[0].script_sig, sig, sizeof(sig));
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_tx_vout");
    tx.vout[0].value = 50 * 100000000LL;
    script_set(&tx.vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(&tx);
    return tx;
}

static void free_sync_test_tx(struct transaction *tx)
{
    if (!tx)
        return;
    free(tx->vin);
    free(tx->vout);
    memset(tx, 0, sizeof(*tx));
}

static void runtime_set_db_service(struct app_runtime_context *runtime,
                                   struct db_service *svc)
{
    memset(runtime, 0, sizeof(*runtime));
    runtime->db_service = svc;
    app_runtime_set_current(runtime);
}

static void cleanup_temp_db_dir(const char *dir_path)
{
    char path[1024];

    if (!dir_path || !dir_path[0])
        return;
    snprintf(path, sizeof(path), "%s/node.db-wal", dir_path);
    unlink(path);
    snprintf(path, sizeof(path), "%s/node.db-shm", dir_path);
    unlink(path);
    snprintf(path, sizeof(path), "%s/node.db", dir_path);
    unlink(path);
    snprintf(path, sizeof(path), "%s/node.db.owner-lock", dir_path);
    unlink(path);
    rmdir(dir_path);
}

struct sqlite_lock_release_ctx {
    struct node_db *ndb;
    unsigned int sleep_us;
};

static void *release_sqlite_write_lock_after_delay(void *arg)
{
    struct sqlite_lock_release_ctx *ctx = arg;

    if (!ctx || !ctx->ndb)
        return NULL;
    struct timespec ts = {
        .tv_sec = ctx->sleep_us / 1000000U,
        .tv_nsec = (long)(ctx->sleep_us % 1000000U) * 1000L,
    };
    nanosleep(&ts, NULL);
    (void)node_db_exec(ctx->ndb, "COMMIT");
    return NULL;
}

static bool test_db_service_write_callback(struct node_db *ndb, void *ctx)
{
    bool *ran = ctx;

    if (ran)
        *ran = true;
    return node_db_exec(ndb,
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('db_service_callback', X'02')");
}

static bool test_db_service_nested_write_callback(struct node_db *ndb, void *ctx)
{
    struct db_service *svc = ctx;

    if (!ndb || !svc)
        return false;
    if (!db_service_is_worker_thread(svc))
        return false;
    if (!db_service_begin_write(svc))
        return false;
    if (!db_service_exec_write(svc,
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('db_service_nested', X'03')")) {
        db_service_rollback_write(svc);
        return false;
    }
    if (!db_service_commit_write(svc)) {
        db_service_rollback_write(svc);
        return false;
    }
    return true;
}

struct test_db_service_async_ctx {
    bool *ran;
    bool *freed;
};

static bool test_db_service_async_write_callback(struct node_db *ndb, void *ctx)
{
    struct test_db_service_async_ctx *async = ctx;

    if (!ndb || !async)
        return false;
    if (async->ran)
        *async->ran = true;
    return node_db_exec(ndb,
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('db_service_async', X'04')");
}

/* Counts frees instead of latching a flag, so the ownership contract can be
 * asserted as EXACTLY once rather than at-least-once. */
static int g_db_service_free_calls;

static void test_db_service_counting_free(void *ctx)
{
    g_db_service_free_calls++;
    free(ctx);
}

static void test_db_service_async_free(void *ctx)
{
    struct test_db_service_async_ctx *async = ctx;

    if (!async)
        return;
    if (async->freed)
        *async->freed = true;
    free(async);
}


static void check_sqlite_1_sqlite_db_open_close(int *failures)
{
    printf("SQLite DB open/close... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    if (ok) {
        int ver = node_db_schema_version(&ndb);
        ok = ok && (ver == NODE_DB_SCHEMA_LATEST);
        node_db_close(&ndb);
    }
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_2_sqlite_state_set_get(int *failures)
{
    printf("SQLite state set/get... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    int64_t val = 0;
    ok = ok && node_db_state_set_int(&ndb, "tip_height", 3034538);
    ok = ok && node_db_state_get_int(&ndb, "tip_height", &val);
    ok = ok && (val == 3034538);

    uint8_t blob[32] = {0xde, 0xad, 0xbe, 0xef};
    ok = ok && node_db_state_set(&ndb, "best_hash", blob, 32);
    uint8_t got[32];
    size_t got_len = 0;
    ok = ok && node_db_state_get(&ndb, "best_hash", got, 32, &got_len);
    ok = ok && (got_len == 32) && (got[0] == 0xde);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_3_open_state(struct node_db *ndb, struct node_db_status *st)
{
    bool ok = node_db_open(ndb, ":memory:");
    ok = ok && ndb->open;
    node_db_get_status(ndb, st);
    ok = ok && st->open;
    ok = ok && !st->tx_open;
    ok = ok && !st->turbo_mode;
    ok = ok && strcmp(st->last_op, "open") == 0;
    return ok;
}

static bool check_sqlite_3_tx_state(struct node_db *ndb, struct node_db_status *st, bool ok)
{
    ok = ok && node_db_begin(ndb);
    node_db_get_status(ndb, st);
    ok = ok && st->tx_open;
    ok = ok && strcmp(st->last_op, "BEGIN TRANSACTION") == 0;

    ok = ok && node_db_commit(ndb);
    node_db_get_status(ndb, st);
    ok = ok && !st->tx_open;
    ok = ok && strcmp(st->last_op, "COMMIT") == 0;
    return ok;
}

static bool check_sqlite_3_turbo_checkpoint_state(struct node_db *ndb,
                                                  struct node_db_status *st,
                                                  bool ok)
{
    ok = ok && node_db_ibd_turbo_mode(ndb);
    node_db_get_status(ndb, st);
    ok = ok && st->turbo_mode;
    ok = ok && strcmp(st->last_op, "ibd_turbo_mode") == 0;

    ok = ok && node_db_wal_checkpoint(ndb);
    node_db_get_status(ndb, st);
    ok = ok && strcmp(st->last_op, "wal_checkpoint") == 0;
    ok = ok && st->last_sqlite_rc == SQLITE_OK;

    ok = ok && node_db_normal_mode(ndb);
    node_db_get_status(ndb, st);
    ok = ok && !st->turbo_mode;
    ok = ok && strcmp(st->last_op, "normal_mode") == 0;
    return ok;
}

static void check_sqlite_3_sqlite_runtime_status_tracks_tx_turbo_ch(int *failures)
{
    printf("SQLite runtime status tracks tx/turbo/checkpoint state... ");
    struct node_db ndb;
    struct node_db_status st = {0};
    bool ok = check_sqlite_3_open_state(&ndb, &st);
    ok = check_sqlite_3_tx_state(&ndb, &st, ok);
    ok = check_sqlite_3_turbo_checkpoint_state(&ndb, &st, ok);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_4_start_and_status(struct db_service *svc,
                                            struct node_db *ndb, bool ok)
{
    ok = ok && !db_service_is_started(svc);
    ok = ok && db_service_node_db(svc) == NULL;
    ok = ok && db_service_attach(svc, ndb);
    ok = ok && db_service_start(svc);
    ok = ok && db_service_is_started(svc);
    ok = ok && db_service_node_db(svc) == ndb;
    ok = ok && db_service_query_db(svc) != NULL;
    ok = ok && db_service_query_db(svc) == ndb->db;
    struct db_service_status svc_status = {0};
    db_service_get_status(svc, &svc_status);
    ok = ok && svc_status.started;
    ok = ok && svc_status.worker_started;
    ok = ok && !svc_status.stop_requested;
    ok = ok && svc_status.queue_depth == 0;
    return ok;
}

static void check_sqlite_4_sqlite_db_service_attaches_and_gates_nod(int *failures)
{
    printf("SQLite DB service attaches and gates node_db access... ");
    struct node_db ndb;
    struct db_service svc;
    bool ok = node_db_open(&ndb, ":memory:");
    db_service_init(&svc);
    ok = check_sqlite_4_start_and_status(&svc, &ndb, ok);
    db_service_stop(&svc);
    ok = ok && !db_service_is_started(&svc);
    ok = ok && db_service_node_db(&svc) == NULL;
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_5_sqlite_db_service_write_wrappers_forward(int *failures)
{
    printf("SQLite DB service write wrappers forward safely... ");
    struct node_db ndb;
    struct db_service svc;
    struct node_db_status st = {0};
    bool ok = node_db_open(&ndb, ":memory:");
    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    ok = ok && db_service_begin_write(&svc);
    node_db_get_status(&ndb, &st);
    ok = ok && st.tx_open;
    ok = ok && db_service_exec_write(&svc,
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('db_service_test', X'01')");
    ok = ok && db_service_commit_write(&svc);
    node_db_get_status(&ndb, &st);
    ok = ok && !st.tx_open;
    ok = ok && db_service_flush_write(&svc);
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_6_sqlite_db_service_runtime_mode_helpers_u(int *failures)
{
    printf("SQLite DB service runtime mode helpers update DB state... ");
    struct node_db ndb;
    struct db_service svc;
    struct node_db_status st = {0};
    bool ok = node_db_open(&ndb, ":memory:");
    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    ok = ok && db_service_ibd_turbo_mode(&svc);
    ok = ok && db_service_set_sync_batch_size(&svc, 250);
    node_db_get_status(&ndb, &st);
    ok = ok && st.turbo_mode;
    ok = ok && strcmp(st.last_op, "set_sync_batch_size") == 0;
    ok = ok && db_service_wal_checkpoint(&svc);
    ok = ok && db_service_normal_mode(&svc);
    node_db_get_status(&ndb, &st);
    ok = ok && !st.turbo_mode;
    ok = ok && strcmp(st.last_op, "normal_mode") == 0;
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_7_sqlite_runtime_state_set_flushes_batch_t(int *failures)
{
    printf("SQLite runtime state_set flushes batch through DB service... ");
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context runtime;
    uint8_t value = 0x5a;
    uint8_t got[8] = {0};
    size_t got_len = 0;
    bool ok = node_db_open(&ndb, ":memory:");
    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    runtime_set_db_service(&runtime, &svc);
    ok = ok && node_db_begin(&ndb);
    ndb.sync_in_batch = true;
    ok = ok && app_runtime_node_db_state_set(
        &ndb, "runtime_state_set", &value, sizeof(value));
    ok = ok && !ndb.sync_in_batch && !ndb.tx_open;
    ok = ok && node_db_state_get(&ndb, "runtime_state_set",
                                 got, sizeof(got), &got_len);
    ok = ok && got_len == 1 && got[0] == value;
    app_runtime_set_current(NULL);
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_8_sqlite_db_service_callback_runs_whole_wr(int *failures)
{
    printf("SQLite DB service callback runs whole write on worker... ");
    struct node_db ndb;
    struct db_service svc;
    bool ran = false;
    uint8_t got[8] = {0};
    size_t got_len = 0;
    bool ok = node_db_open(&ndb, ":memory:");
    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    ok = ok && db_service_run_write(&svc,
        test_db_service_write_callback, &ran);
    ok = ok && ran;
    ok = ok && node_db_state_get(&ndb, "db_service_callback",
                                 got, sizeof(got), &got_len);
    ok = ok && got_len == 1 && got[0] == 0x02;
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_9_sqlite_db_service_nested_worker_writes_s(int *failures)
{
    printf("SQLite DB service nested worker writes stay reentrant... ");
    struct node_db ndb;
    struct db_service svc;
    uint8_t got[8] = {0};
    size_t got_len = 0;
    bool ok = node_db_open(&ndb, ":memory:");
    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    ok = ok && db_service_run_write(&svc,
        test_db_service_nested_write_callback, &svc);
    ok = ok && node_db_state_get(&ndb, "db_service_nested",
                                 got, sizeof(got), &got_len);
    ok = ok && got_len == 1 && got[0] == 0x03;
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_10_sqlite_db_service_async_write_drains_bef(int *failures)
{
    printf("SQLite DB service async write drains before flush... ");
    struct node_db ndb;
    struct db_service svc;
    struct test_db_service_async_ctx *ctx = NULL;
    uint8_t got[8] = {0};
    size_t got_len = 0;
    bool ran = false;
    bool freed = false;
    bool ok = node_db_open(&ndb, ":memory:");

    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    if (ok) {
        ctx = zcl_calloc(1, sizeof(*ctx), "test async db ctx");
        ok = ctx != NULL;
    }
    if (ok) {
        ctx->ran = &ran;
        ctx->freed = &freed;
        ok = db_service_enqueue_write(&svc,
            test_db_service_async_write_callback, ctx,
            test_db_service_async_free);
        ctx = NULL;
    }
    ok = ok && db_service_flush_write(&svc);
    ok = ok && ran && freed;
    ok = ok && node_db_state_get(&ndb, "db_service_async",
                                 got, sizeof(got), &got_len);
    ok = ok && got_len == 1 && got[0] == 0x04;
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ctx)
        free(ctx);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_11_sqlite_db_service_frees_the_context_of_a(int *failures)
{
    printf("SQLite DB service frees the context of a refused async write "
           "exactly once... ");
    struct node_db ndb;
    struct db_service svc;
    bool ok = node_db_open(&ndb, ":memory:");

    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &ndb);
    /* Deliberately NOT started, so the submit is refused deterministically
     * rather than by racing the worker to fill the queue. */
    g_db_service_free_calls = 0;
    if (ok) {
        void *ctx = zcl_calloc(1, 16, "test refused enqueue ctx");
        ok = ctx != NULL;
        if (ok) {
            bool queued = db_service_enqueue_write(&svc,
                test_db_service_async_write_callback, ctx,
                test_db_service_counting_free);
            /* Refused, and the callee owns the disposal. Freeing ctx here
             * would be the double free this test exists to prevent. */
            ok = !queued;
        }
    }
    ok = ok && g_db_service_free_calls == 1;
    db_service_stop(&svc);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else {
        printf("FAIL (free calls=%d, want 1)\n", g_db_service_free_calls);
        (*failures)++;
    }
}

static void check_sqlite_12_sqlite_sync_controller_opens_private_fil(int *failures)
{
    printf("SQLite sync_controller opens private file-backed DB handles... ");
    char dir_template[] = "/tmp/zclassic23-private-db-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    struct node_db ndb;
    struct node_db private_db;
    int64_t value = 0;
    bool ok = dir_path != NULL;

    memset(&ndb, 0, sizeof(ndb));
    memset(&private_db, 0, sizeof(private_db));
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        ok = node_db_open(&ndb, db_path);
    }
    if (ok)
        ok = node_db_sync_open_private_db_like(&ndb, &private_db);
    if (ok) {
        ok = private_db.open;
        ok = ok && private_db.db != ndb.db;
        ok = ok && node_db_state_set_int(&private_db,
                                         "private_handle_test", 77);
        ok = ok && node_db_state_get_int(&ndb,
                                         "private_handle_test", &value);
        ok = ok && value == 77;
    }

    if (private_db.open)
        node_db_close(&private_db);
    if (ndb.open)
        node_db_close(&ndb);
    cleanup_temp_db_dir(dir_path);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_13_stage_marker(const char *db_path)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, db_path);          /* boot open */
    /* Stage a marker in the crash-recovery namespace the boot open wipes. */
    ok = ok && node_db_state_set(&ndb, "snapshot_staging_testmark", "x", 1);
    if (ndb.open) node_db_close(&ndb);
    return ok;
}

static bool check_sqlite_13_runtime_reopen_preserves(const char *db_path)
{
    struct node_db ndb;
    char buf[8];
    size_t glen = 0;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open_runtime(&ndb, db_path, "test.reopen");
    ok = ok && node_db_state_get(&ndb, "snapshot_staging_testmark",
                                 buf, sizeof(buf), &glen);  /* preserved */
    if (ndb.open) node_db_close(&ndb);
    return ok;
}

static bool check_sqlite_13_boot_reopen_wipes(const char *db_path)
{
    struct node_db ndb;
    char buf[8];
    size_t glen = 0;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, db_path);
    ok = ok && !node_db_state_get(&ndb, "snapshot_staging_testmark",
                                  buf, sizeof(buf), &glen);  /* wiped */
    if (ndb.open) node_db_close(&ndb);
    return ok;
}

static bool check_sqlite_13_mandatory_reason(const char *db_path)
{
    struct node_db bad;
    memset(&bad, 0, sizeof(bad));
    bool ok = !node_db_open_runtime(&bad, db_path, NULL);
    memset(&bad, 0, sizeof(bad));
    ok = ok && !node_db_open_runtime(&bad, db_path, "");
    return ok;
}

static void check_sqlite_13_node_db_open_runtime_named_skips_boot_on(int *failures)
{
    /* Regression: a background RUNTIME reopen must not re-run the boot
     * ceremony. If it did (quick_check + version banner + snapshot-staging
     * crash-recovery DELETE every cycle), a merely-stalled node's periodic
     * reopen looks like a silent boot loop — the live P0 this lane fixed.
     * We assert the two structural guarantees behaviorally: (1) a runtime
     * reopen PRESERVES the snapshot_staging namespace that a boot open
     * would wipe, and (2) the reason argument is mandatory. */
    printf("node_db_open_runtime: named + skips boot-only staging wipe... ");
    char dir_template[] = "/tmp/zclassic23-runtime-reopen-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    bool ok = dir_path != NULL;

    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        ok = check_sqlite_13_stage_marker(db_path);
    }
    ok = ok && check_sqlite_13_runtime_reopen_preserves(db_path);
    ok = ok && check_sqlite_13_boot_reopen_wipes(db_path);
    ok = ok && check_sqlite_13_mandatory_reason(db_path);

    cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_14_seed_value(const char *db_path)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, db_path);
    ok = ok && node_db_state_set_int(&ndb, "existing_open_test", 23);
    if (ndb.open) node_db_close(&ndb);
    return ok;
}

static bool check_sqlite_14_light_reopen_preserves_access(const char *db_path)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    int64_t value = 0;
    bool ok = node_db_open_existing_runtime(
        &ndb, db_path, "test.existing_reopen");
    ok = ok && node_db_state_get_int(&ndb, "existing_open_test", &value);
    ok = ok && value == 23;
    sqlite3_stmt *mmap_stmt = NULL;
    int64_t mmap_bytes = -1;
    if (ok && sqlite3_prepare_v2(ndb.db, "PRAGMA mmap_size", -1,
                                 &mmap_stmt, NULL) == SQLITE_OK &&
        sqlite3_step(mmap_stmt) == SQLITE_ROW)
        mmap_bytes = sqlite3_column_int64(mmap_stmt, 0);
    else
        ok = false;
    sqlite3_finalize(mmap_stmt);
    ok = ok && mmap_bytes == 0;
    if (ndb.open) node_db_close(&ndb);
    return ok;
}

static bool check_sqlite_14_missing_file_not_created(const char *missing_path)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = !node_db_open_existing_runtime(
        &ndb, missing_path, "test.must_not_create");
    ok = ok && access(missing_path, F_OK) != 0;
    return ok;
}

static bool check_sqlite_14_schema_mismatch_refused(const char *db_path)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open_runtime(&ndb, db_path,
                                   "test.schema_mismatch_setup");
    int32_t future_schema = NODE_DB_MAX_SCHEMA + 1;
    ok = ok && node_db_state_set(&ndb, "schema_version", &future_schema,
                                 sizeof(future_schema));
    if (ndb.open) node_db_close(&ndb);
    memset(&ndb, 0, sizeof(ndb));
    ok = ok && !node_db_open_existing_runtime(
        &ndb, db_path, "test.schema_mismatch");
    return ok;
}

static void check_sqlite_14_node_db_open_existing_runtime_exact_sche(int *failures)
{
    /* Periodic workers need an exact-schema connection without repeating
     * CREATE/migrate/full-statement preparation every poll. The light open
     * must preserve ordinary model access, never create a missing file,
     * and fail closed on a schema written by another binary version. */
    printf("node_db_open_existing_runtime: exact schema, no create... ");
    char dir_template[] = "/tmp/zclassic23-existing-reopen-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024], missing_path[1024];
    bool ok = dir_path != NULL;

    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        snprintf(missing_path, sizeof(missing_path), "%s/missing.db",
                 dir_path);
        ok = check_sqlite_14_seed_value(db_path);
    }
    ok = ok && check_sqlite_14_light_reopen_preserves_access(db_path);
    ok = ok && check_sqlite_14_missing_file_not_created(missing_path);
    ok = ok && check_sqlite_14_schema_mismatch_refused(db_path);

    cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_15_seed_canonical(const char *dir_path, char *db_path,
                                           size_t db_path_sz, char *wal_path,
                                           size_t wal_path_sz, char *shm_path,
                                           size_t shm_path_sz,
                                           struct node_db *canonical,
                                           struct stat *wal_before,
                                           struct stat *shm_before)
{
    snprintf(db_path, db_path_sz, "%s/node.db", dir_path);
    snprintf(wal_path, wal_path_sz, "%s-wal", db_path);
    snprintf(shm_path, shm_path_sz, "%s-shm", db_path);
    return node_db_open(canonical, db_path) &&
        node_db_state_set_int(canonical, "process_owner_test", 23) &&
        node_db_owner_lease_probe(db_path) ==
            NODE_DB_OWNER_LEASE_OWNED_SELF &&
        stat(wal_path, wal_before) == 0 &&
        stat(shm_path, shm_before) == 0;
}

static bool check_sqlite_15_borrower_process_refused(const char *dir_path,
                                                      const char *db_path)
{
#if defined(_WIN32)
    char log_path[1064];
    snprintf(log_path, sizeof(log_path), "%s/borrower.log", dir_path);
    if (_putenv_s("ZCL_SQLITE_CHILD_DB", db_path) != 0)
        return false;
    void *hp = test_spawn_self_with_role("test_sqlite", "borrower", log_path);
    bool ok = hp && test_self_child_wait(hp) == 0;
    _putenv_s("ZCL_SQLITE_CHILD_DB", "");
    return ok;
#else
    (void)dir_path;
    pid_t child = fork();
    if (child == 0) {
        struct node_db borrowed = {0};
        bool opened = node_db_open_existing_runtime(
            &borrowed, db_path, "test.cross_process_borrower");
        if (opened) node_db_close(&borrowed);
        _exit(opened ? 1 : 0);
    }
    int status = 0;
    return child >= 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

static bool check_sqlite_15_verify_unmoved(const char *wal_path,
                                           const char *shm_path,
                                           struct stat *wal_before,
                                           struct stat *shm_before,
                                           struct node_db *canonical)
{
    struct stat wal_after = {0}, shm_after = {0};
    int64_t value = 0;
    return stat(wal_path, &wal_after) == 0 &&
        stat(shm_path, &shm_after) == 0 &&
        wal_before->st_dev == wal_after.st_dev &&
        wal_before->st_ino == wal_after.st_ino &&
        shm_before->st_dev == shm_after.st_dev &&
        shm_before->st_ino == shm_after.st_ino &&
        node_db_state_get_int(
            canonical, "process_owner_test", &value) && value == 23 &&
        node_db_state_set_int(canonical, "process_owner_after", 24);
}

static void check_sqlite_15_sqlite_live_owner_blocks_cross_process_r(int *failures)
{
    /* Cross-process born-red case from async proof acceptance: a resident
     * canonical owner has no <datadir>/.cookie when credential-directory
     * RPC authentication is used. A one-shot mutable helper must still
     * discover the lease and fail before SQLite can touch its WAL. */
    printf("SQLite live owner blocks cross-process runtime reopen... ");
    char dir_template[] = "/tmp/zclassic23-live-owner-process-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024], wal_path[1032], shm_path[1032];
    struct node_db canonical = {0};
    struct stat wal_before = {0}, shm_before = {0};
    bool ok = dir_path != NULL;
    if (ok)
        ok = check_sqlite_15_seed_canonical(
            dir_path, db_path, sizeof(db_path), wal_path, sizeof(wal_path),
            shm_path, sizeof(shm_path), &canonical, &wal_before, &shm_before);
    ok = ok && check_sqlite_15_borrower_process_refused(dir_path, db_path);
    ok = ok && check_sqlite_15_verify_unmoved(
        wal_path, shm_path, &wal_before, &shm_before, &canonical);
    if (canonical.open) node_db_close(&canonical);
    if (dir_path) cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_16_helper_reopen_loop(const char *db_path)
{
    struct node_db helper = {0};
    int64_t helper_value = 0;
    bool ok = true;
    for (int i = 0; ok && i < 64; i++) {
        ok = node_db_open_existing_runtime(
            &helper, db_path, "test.live_wal_helper") &&
            node_db_state_get_int(
                &helper, "wal_owner_test", &helper_value) &&
            helper_value == 23;
        if (helper.open) node_db_close(&helper);
    }
    return ok;
}

static bool check_sqlite_16_wal_unlink_refused(const char *wal_path,
                                               struct stat *before,
                                               uint64_t unauthorized_before)
{
    /* Exercise the central filesystem boundary directly: a handle owner
     * cannot unlink the backing owner's live WAL even if a caller asks. */
    struct stat after = {0};
    bool ok = db_lifetime_unlink(
        wal_path, "test.borrowed_wal_cleanup",
        DB_LIFETIME_HANDLE_OWNER, 0) != 0;
    ok = ok && stat(wal_path, &after) == 0 &&
        before->st_dev == after.st_dev && before->st_ino == after.st_ino;
    ok = ok && db_lifetime_unauthorized_count() == unauthorized_before + 1;
    return ok;
}

static void check_sqlite_16_sqlite_runtime_helper_preserves_live_wal(int *failures)
{
    /* A live WAL has one filesystem identity. A helper that closes its own
     * mutable handle must not unlink/recreate the canonical owner's WAL,
     * which splits same-process readers across different WAL inodes and
     * surfaces later as schema=0 / SQLITE_IOERR. */
    printf("SQLite runtime helper preserves live WAL identity... ");
    char dir_template[] = "/tmp/zclassic23-live-wal-owner-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024], wal_path[1032];
    struct node_db canonical = {0};
    struct stat before = {0};
    uint64_t unauthorized_before = db_lifetime_unauthorized_count();
    bool ok = dir_path != NULL;
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
        ok = node_db_open(&canonical, db_path) &&
            node_db_state_set_int(&canonical, "wal_owner_test", 23) &&
            stat(wal_path, &before) == 0;
    }
    ok = ok && check_sqlite_16_helper_reopen_loop(db_path);
    ok = ok && check_sqlite_16_wal_unlink_refused(
        wal_path, &before, unauthorized_before);
    if (canonical.open) node_db_close(&canonical);
    if (dir_path) cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_17_raw_reader_reads_and_closes(const char *db_path)
{
    sqlite3 *reader = NULL;
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_open_v2(db_path, &reader,
            SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(reader,
            "SELECT value FROM node_state WHERE key='wal_reader_test'",
            -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    if (reader)
        ok = sqlite3_close(reader) == SQLITE_OK && ok;
    return ok;
}

static bool check_sqlite_17_wal_unmoved_and_writable(const char *wal_path,
                                                     struct stat *before,
                                                     struct node_db *canonical)
{
    struct stat after = {0};
    int64_t read_back = 0;
    return stat(wal_path, &after) == 0 &&
        before->st_dev == after.st_dev && before->st_ino == after.st_ino &&
        node_db_state_set_int(canonical, "wal_reader_test", 2) &&
        node_db_state_get_int(canonical, "wal_reader_test", &read_back) &&
        read_back == 2;
}

static void check_sqlite_17_sqlite_raw_reader_cannot_retire_canonica(int *failures)
{
    /* Born-red reproduction for the live API/projection shape: a raw
     * read-only SQLite connection is opened beside the canonical mutable
     * owner, reads through the WAL, and closes while the owner continues
     * transacting.  Its close must not remove or replace the owner's WAL
     * pathname. */
    printf("SQLite raw reader cannot retire canonical live WAL... ");
    char dir_template[] = "/tmp/zclassic23-live-wal-reader-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024], wal_path[1032];
    struct node_db canonical = {0};
    struct stat before = {0};
    bool ok = dir_path != NULL;
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
        ok = node_db_open(&canonical, db_path) &&
            node_db_state_set_int(&canonical, "wal_reader_test", 1) &&
            stat(wal_path, &before) == 0;
    }
    ok = ok && check_sqlite_17_raw_reader_reads_and_closes(db_path);
    ok = ok && check_sqlite_17_wal_unmoved_and_writable(
        wal_path, &before, &canonical);
    if (canonical.open) node_db_close(&canonical);
    if (dir_path) cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_18_intruder_refused_while_writing(
    const char *dir_path, const char *db_path, struct node_db *canonical)
{
#if defined(_WIN32)
    char log_path[1064];
    snprintf(log_path, sizeof(log_path), "%s/intruder.log", dir_path);
    void *hp = NULL;
    if (_putenv_s("ZCL_SQLITE_CHILD_DB", db_path) == 0)
        hp = test_spawn_self_with_role("test_sqlite", "intruder", log_path);
    bool ok = hp != NULL;
    for (int64_t i = 1; ok && i <= 64; i++)
        ok = node_db_state_set_int(canonical, "process_owner_test", i);
    int child_exit = hp ? test_self_child_wait(hp) : -1;
    _putenv_s("ZCL_SQLITE_CHILD_DB", "");
    return ok && child_exit == 0;
#else
    (void)dir_path;
    pid_t child = fork();
    if (child == 0) {
        struct node_db intruder = {0};
        bool opened = node_db_open(&intruder, db_path);
        if (opened) node_db_close(&intruder);
        _exit(opened ? 1 : 0);
    }
    bool ok = child > 0;
    for (int64_t i = 1; ok && i <= 64; i++)
        ok = node_db_state_set_int(canonical, "process_owner_test", i);
    int status = -1;
    if (child > 0)
        ok = waitpid(child, &status, 0) == child && ok;
    return ok && WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

static bool check_sqlite_18_verify_after(const char *wal_path,
                                         struct stat *before,
                                         struct node_db *canonical)
{
    struct stat after = {0};
    int64_t read_back = 0;
    return stat(wal_path, &after) == 0 &&
        before->st_dev == after.st_dev && before->st_ino == after.st_ino &&
        node_db_state_get_int(canonical, "process_owner_test",
                              &read_back) &&
        read_back == 64 &&
        node_db_state_set_int(canonical, "process_owner_after", 23) &&
        node_db_state_get_int(canonical, "process_owner_after",
                              &read_back) &&
        read_back == 23;
}

static void check_sqlite_18_sqlite_second_process_cannot_boot_open_a(int *failures)
{
    /* Exact ownership defect: a one-shot command used node_db_open() on
     * the resident daemon's live path, then its shutdown retired the
     * daemon's WAL/SHM.  The canonical lease must reject that second
     * process before SQLite is opened, while the resident connection
     * continues transacting throughout. */
    printf("SQLite second process cannot boot-open a live node.db... ");
    char dir_template[] = "/tmp/zclassic23-live-db-process-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024], wal_path[1032];
    struct node_db canonical = {0};
    struct stat before = {0};
    bool ok = dir_path != NULL;
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
        ok = node_db_open(&canonical, db_path) &&
            node_db_state_set_int(&canonical, "process_owner_test", 0) &&
            stat(wal_path, &before) == 0;
    }
    ok = ok && check_sqlite_18_intruder_refused_while_writing(
        dir_path, db_path, &canonical);
    ok = ok && check_sqlite_18_verify_after(wal_path, &before, &canonical);
    if (canonical.open) node_db_close(&canonical);
    if (dir_path) cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_19_sqlite_snapshot_tx_index_job_starts_and_(int *failures)
{
    printf("SQLite snapshot tx-index job starts and joins cleanly... ");
    char dir_template[] = "/tmp/zclassic23-tx-index-job-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    struct node_db ndb;
    struct snapshot_tx_index_job job;
    int result = -1;
    bool ok = dir_path != NULL;

    memset(&ndb, 0, sizeof(ndb));
    snapshot_tx_index_job_init(&job);
    ok = ok && !snapshot_tx_index_job_is_started(&job);
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        ok = node_db_open(&ndb, db_path);
    }
    if (ok) {
        node_db_close(&ndb);
        ok = snapshot_tx_index_job_start(&job, dir_path);
    }
    if (ok)
        ok = snapshot_tx_index_job_is_started(&job);
    if (ok)
        ok = snapshot_tx_index_job_join(&job, &result);
    ok = ok && !snapshot_tx_index_job_is_started(&job);
    ok = ok && result == 0;

    if (ndb.open)
        node_db_close(&ndb);
    cleanup_temp_db_dir(dir_path);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_20_sqlite_sync_job_wrappers_fail_closed_and(int *failures)
{
    printf("SQLite sync job wrappers fail closed and fallback cleanly... ");
    struct node_db ndb;
    struct active_chain ac;
    struct node_db_sync_catchup_job catch_job;
    struct node_db_sync_import_job import_job;
    struct coins_view_db cvdb = {0};
    int result = -1;
    bool ok = node_db_open(&ndb, ":memory:");

    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&catch_job);
    node_db_sync_import_job_init(&import_job);

    ok = ok && !node_db_sync_catchup_job_start(NULL, &ndb, &ac, NULL, NULL);
    ok = ok && !node_db_sync_catchup_job_start(&catch_job, NULL, &ac, NULL, NULL);
    ok = ok && !node_db_sync_catchup_job_start(&catch_job, &ndb, NULL, NULL, NULL);
    ok = ok && !node_db_sync_import_job_start(NULL, &ndb, &cvdb);
    ok = ok && !node_db_sync_import_job_start(&import_job, &ndb, NULL);
    ok = ok && !node_db_sync_catchup_job_join(&catch_job, NULL);
    ok = ok && !node_db_sync_import_job_join(&import_job, NULL);

    if (node_db_sync_catchup_job_start(&catch_job, &ndb, &ac, NULL, NULL))
        ok = ok && node_db_sync_catchup_job_join(&catch_job, &result) && result == 0;

    ok = ok && !node_db_sync_catchup_job_is_started(&catch_job);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }

    active_chain_free(&ac);
    node_db_close(&ndb);
}

static void check_sqlite_21_sqlite_catchup_job_uses_runtime_db_servi(int *failures)
{
    printf("SQLite catchup job uses runtime DB-service lane... ");
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context runtime;
    struct active_chain ac;
    struct node_db_sync_catchup_job catch_job;
    int result = -1;
    bool ok = node_db_open(&ndb, ":memory:");

    db_service_init(&svc);
    active_chain_init(&ac);
    node_db_sync_catchup_job_init(&catch_job);
    ok = ok && db_service_attach(&svc, &ndb);
    ok = ok && db_service_start(&svc);
    runtime_set_db_service(&runtime, &svc);
    node_db_sync_catchup_test_reset_lane_stats();

    ok = ok && node_db_sync_catchup_job_start(&catch_job, &ndb, &ac,
                                              NULL, NULL);
    ok = ok && node_db_sync_catchup_job_join(&catch_job, &result);
    ok = ok && result == 0;
    ok = ok && node_db_sync_catchup_test_lane_calls() == 1;
    ok = ok && node_db_sync_catchup_test_worker_lane_calls() == 1;
    ok = ok && !node_db_sync_catchup_job_is_started(&catch_job);

    app_runtime_set_current(NULL);
    db_service_stop(&svc);
    active_chain_free(&ac);
    node_db_close(&ndb);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

struct check_sqlite_22_fixture {
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context runtime;
    struct transaction tx;
    struct transaction wallet_tx;
    struct wallet *wallet;
    struct db_sapling_note note;
    uint8_t nullifier[32];
    uint8_t spending_txid[32];
};

static bool check_sqlite_22_setup(struct check_sqlite_22_fixture *f)
{
    bool ok = node_db_open(&f->ndb, ":memory:");
    db_service_init(&f->svc);
    ok = ok && db_service_attach(&f->svc, &f->ndb);
    ok = ok && db_service_start(&f->svc);
    runtime_set_db_service(&f->runtime, &f->svc);
    f->wallet = zcl_calloc(1, sizeof(*f->wallet), "test_wallet");
    ok = ok && f->wallet != NULL;
    f->tx = make_sync_test_tx();
    f->wallet_tx = make_sync_test_tx();
    return ok;
}

static bool check_sqlite_22_mempool(struct node_db *ndb, struct transaction *tx, bool ok)
{
    ok = ok && node_db_sync_mempool_add(ndb, tx, 1234, 777);
    ok = ok && (db_mempool_count(ndb) == 1);
    ok = ok && node_db_sync_mempool_remove(ndb, tx->hash.data);
    ok = ok && (db_mempool_count(ndb) == 0);
    return ok;
}

static bool check_sqlite_22_tip_sync(struct node_db *ndb, bool ok)
{
    uint8_t tip_hash[32];
    uint8_t got_tip_hash[32];
    size_t got_tip_len = 0;
    int64_t tip_height = -1;
    memset(tip_hash, 0xAB, sizeof(tip_hash));
    ok = ok && node_db_state_set_int(ndb, "tip_height", 99999);
    ok = ok && node_db_state_set(ndb, "tip_hash",
                                 (const uint8_t[32]){0}, 32);
    ok = ok && node_db_sync_set_tip(ndb, tip_hash, 12345);
    ok = ok && node_db_state_get_int(ndb,
            "sync_projection_tip_height", &tip_height);
    ok = ok && (tip_height == 12345);
    ok = ok && node_db_state_get(ndb, "sync_projection_tip_hash",
            got_tip_hash, sizeof(got_tip_hash), &got_tip_len);
    ok = ok && got_tip_len == sizeof(got_tip_hash);
    ok = ok && memcmp(got_tip_hash, tip_hash, sizeof(tip_hash)) == 0;
    memset(got_tip_hash, 0, sizeof(got_tip_hash));
    got_tip_len = 0;
    ok = ok && node_db_sync_get_tip_height(ndb) == 12345;
    ok = ok && node_db_sync_get_tip_hash(ndb, got_tip_hash);
    ok = ok && memcmp(got_tip_hash, tip_hash, sizeof(tip_hash)) == 0;
    return ok;
}

static bool check_sqlite_22_peer_sync(struct node_db *ndb, bool ok)
{
    struct db_peer peer = {0};
    memset(peer.ip, 0, sizeof(peer.ip));
    peer.ip[10] = 0xFF;
    peer.ip[11] = 0xFF;
    peer.ip[12] = 127;
    peer.ip[15] = 1;
    ok = ok && node_db_sync_peer(ndb, peer.ip, 8033, 9, 1700000000);
    ok = ok && db_peer_find_by_addr(ndb, peer.ip, 8033, &peer);
    ok = ok && peer.services == 9;
    ok = ok && node_db_sync_peer_score(ndb, peer.ip, 8033, 44, true);
    ok = ok && db_peer_find_by_addr(ndb, peer.ip, 8033, &peer);
    ok = ok && peer.bandwidth_score == 44;
    ok = ok && peer.is_zcl23;
    return ok;
}

static bool check_sqlite_22_wallet_tx(struct check_sqlite_22_fixture *f, bool ok)
{
    struct privkey key;
    struct pubkey pubkey;
    struct key_id kid;
    struct tx_destination dest;
    struct db_wallet_utxo wallet_utxo = {0};
    struct db_wallet_tx saved_wallet_tx = {0};
    if (f->wallet)
        wallet_init(f->wallet);
    privkey_make_new(&key, true);
    ok = ok && privkey_get_pubkey(&key, &pubkey);
    ok = ok && f->wallet && keystore_add_key(&f->wallet->keystore, &key);
    kid = pubkey_get_id(&pubkey);
    dest.type = DEST_KEY_ID;
    dest.id.key = kid;
    script_for_destination(&f->wallet_tx.vout[0].script_pub_key, &dest);
    transaction_compute_hash(&f->wallet_tx);
    ok = ok && f->wallet &&
         node_db_sync_wallet_tx(&f->ndb, &f->wallet_tx, f->wallet, 0);
    ok = ok && db_wallet_utxo_find(&f->ndb, f->wallet_tx.hash.data, 0, &wallet_utxo);
    ok = ok && wallet_utxo.value == f->wallet_tx.vout[0].value;
    ok = ok && db_wallet_tx_find(&f->ndb, f->wallet_tx.hash.data, &saved_wallet_tx);
    ok = ok && !saved_wallet_tx.has_block;
    ok = ok && saved_wallet_tx.block_height == 0;
    free(wallet_utxo.script);
    free(saved_wallet_tx.raw_tx);
    return ok;
}

static bool check_sqlite_22_wallet_tx_confirmed(struct check_sqlite_22_fixture *f, bool ok)
{
    struct db_wallet_tx saved_wallet_tx = {0};
    uint8_t confirmed_hash[32];
    memset(confirmed_hash, 0x5c, sizeof(confirmed_hash));
    ok = ok && node_db_sync_wallet_tx_confirmed_async(
        &f->ndb, &f->wallet_tx, f->wallet, 321, confirmed_hash, 1700000321);
    ok = ok && db_service_flush_write(&f->svc);
    ok = ok && db_wallet_tx_find(
        &f->ndb, f->wallet_tx.hash.data, &saved_wallet_tx);
    ok = ok && saved_wallet_tx.has_block;
    ok = ok && saved_wallet_tx.block_height == 321;
    ok = ok && memcmp(saved_wallet_tx.block_hash,
                      confirmed_hash, sizeof(confirmed_hash)) == 0;
    ok = ok && saved_wallet_tx.time_received == 1700000321;
    free(saved_wallet_tx.raw_tx);
    if (f->wallet) {
        wallet_free(f->wallet);
        free(f->wallet);
        f->wallet = NULL;
    }
    return ok;
}

static bool check_sqlite_22_sapling_note(struct check_sqlite_22_fixture *f, bool ok)
{
    memset(&f->note, 0, sizeof(f->note));
    memset(f->note.txid, 0x01, sizeof(f->note.txid));
    f->note.output_index = 2;
    f->note.value = 4200;
    memset(f->note.rcm, 0x02, sizeof(f->note.rcm));
    memset(f->note.ivk, 0x03, sizeof(f->note.ivk));
    memset(f->note.diversifier, 0x04, sizeof(f->note.diversifier));
    memset(f->note.pk_d, 0x05, sizeof(f->note.pk_d));
    memset(f->note.cm, 0x06, sizeof(f->note.cm));
    memset(f->note.nullifier, 0x07, sizeof(f->note.nullifier));
    f->note.block_height = 88;
    ok = ok && node_db_sync_sapling_note(&f->ndb,
                                         f->note.txid,
                                         f->note.output_index,
                                         f->note.value,
                                         f->note.rcm,
                                         NULL,
                                         0,
                                         f->note.ivk,
                                         f->note.diversifier,
                                         f->note.pk_d,
                                         f->note.cm,
                                         f->note.nullifier,
                                         f->note.block_height);
    ok = ok && db_sapling_note_balance_for_ivk(&f->ndb, f->note.ivk) == f->note.value;
    memcpy(f->nullifier, f->note.nullifier, sizeof(f->nullifier));
    memset(f->spending_txid, 0x08, sizeof(f->spending_txid));
    ok = ok && node_db_sync_sapling_spend_bool_compat(&f->ndb, f->nullifier, f->spending_txid);
    ok = ok && db_sapling_note_balance_for_ivk(&f->ndb, f->note.ivk) == 0;
    return ok;
}

static bool check_sqlite_22_sapling_tristate(struct check_sqlite_22_fixture *f, bool ok)
{
    /* Tri-state contract: an indexed note that just got spent must
     * report OK (already spent above, so re-marking changes no row →
     * NOT_FOUND is also acceptable; what matters is it is never ERROR). */
    enum db_mark_spent_result re =
        node_db_sync_sapling_spend(&f->ndb, f->nullifier, f->spending_txid);
    ok = ok && re != DB_MARK_SPENT_ERROR;

    /* Benign not-in-our-index spend: a nullifier we never indexed must
     * report NOT_FOUND (NOT ERROR) so the projection catchup skips it
     * and keeps advancing instead of aborting the whole backfill.
     * Regression guard for the catchup wedge at height 3125020. */
    uint8_t unknown_nf[32];
    uint8_t unknown_txid[32];
    memset(unknown_nf, 0xEE, sizeof(unknown_nf));
    memset(unknown_txid, 0x09, sizeof(unknown_txid));
    enum db_mark_spent_result rmiss =
        node_db_sync_sapling_spend(&f->ndb, unknown_nf, unknown_txid);
    ok = ok && rmiss == DB_MARK_SPENT_NOT_FOUND;
    /* Legacy bool wrapper reports false for the benign miss but must
     * not be treated as fatal by the tri-state catchup path. */
    ok = ok && !node_db_sync_sapling_spend_bool_compat(&f->ndb, unknown_nf, unknown_txid);
    /* Model-level tri-state is consistent with the controller. */
    ok = ok && db_sapling_note_mark_spent(&f->ndb, unknown_nf, unknown_txid)
               == DB_MARK_SPENT_NOT_FOUND;
    return ok;
}

static void check_sqlite_22_sqlite_sync_controller_wrappers_use_runt(int *failures)
{
    printf("SQLite sync_controller wrappers use runtime DB service... ");
    struct check_sqlite_22_fixture f = {0};
    bool ok = check_sqlite_22_setup(&f);
    ok = check_sqlite_22_mempool(&f.ndb, &f.tx, ok);
    ok = check_sqlite_22_tip_sync(&f.ndb, ok);
    ok = check_sqlite_22_peer_sync(&f.ndb, ok);
    ok = check_sqlite_22_wallet_tx(&f, ok);
    ok = check_sqlite_22_wallet_tx_confirmed(&f, ok);
    ok = check_sqlite_22_sapling_note(&f, ok);
    ok = check_sqlite_22_sapling_tristate(&f, ok);

    app_runtime_set_current(NULL);
    db_service_stop(&f.svc);
    free_sync_test_tx(&f.tx);
    free_sync_test_tx(&f.wallet_tx);
    node_db_close(&f.ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_23_sqlite_sapling_spend_reports_nullifier_i(int *failures)
{
    printf("SQLite sapling spend reports nullifier insert failure... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    uint8_t nullifier[32];
    uint8_t spending_txid[32];

    memset(nullifier, 0x0A, sizeof(nullifier));
    memset(spending_txid, 0x0B, sizeof(spending_txid));
    ok = ok && node_db_exec(&ndb, "DROP TABLE sapling_nullifiers");
    if (ok) {
        enum db_mark_spent_result r =
            node_db_sync_sapling_spend(&ndb, nullifier, spending_txid);
        ok = ok && r == DB_MARK_SPENT_ERROR;
    }

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_24_sqlite_block_save_find(int *failures)
{
    printf("SQLite block save/find... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, 0xAA, 32);
    blk.height = 100;
    memset(blk.prev_hash, 0xBB, 32);
    blk.version = 4;
    memset(blk.merkle_root, 0xCC, 32);
    blk.time = 1700000000;
    blk.bits = 0x1d00ffff;
    memset(blk.nonce, 0xDD, 32);
    uint8_t sol[] = {0x01, 0x02, 0x03};
    blk.solution = sol;
    blk.solution_len = 3;
    memset(blk.chain_work, 0xEE, 32);
    blk.status = 5;
    blk.file_num = 1;
    blk.data_pos = 8192;
    blk.num_tx = 42;

    ok = ok && db_block_save(&ndb, &blk);
    ok = ok && (db_block_count(&ndb) == 1);
    ok = ok && (db_block_max_height(&ndb) == 100);

    struct db_block found;
    ok = ok && db_block_find_by_hash(&ndb, blk.hash, &found);
    ok = ok && (found.height == 100);
    ok = ok && (found.num_tx == 42);
    ok = ok && (found.file_num == 1);

    ok = ok && db_block_find_by_height(&ndb, 100, &found);
    ok = ok && (memcmp(found.hash, blk.hash, 32) == 0);

    ok = ok && db_block_delete(&ndb, blk.hash);
    ok = ok && (db_block_count(&ndb) == 0);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_25_sqlite_block_delete_by_height(int *failures)
{
    printf("SQLite block delete_by_height... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, 0x5A, 32);
    blk.height = 777;
    memset(blk.prev_hash, 0x5B, 32);
    blk.version = 4;
    memset(blk.merkle_root, 0x5C, 32);
    blk.time = 1700000777;
    blk.bits = 0x1d00ffff;
    memset(blk.nonce, 0x5D, 32);
    uint8_t sol[] = {0x09, 0x08, 0x07};
    blk.solution = sol;
    blk.solution_len = 3;
    memset(blk.chain_work, 0x5E, 32);
    blk.status = 5;
    blk.num_tx = 1;

    ok = ok && db_block_save(&ndb, &blk);
    ok = ok && (db_block_count(&ndb) == 1);
    /* Purge by height (the row's hash is irrelevant to this path). */
    ok = ok && db_block_delete_by_height(&ndb, 777);
    ok = ok && (db_block_count(&ndb) == 0);
    /* Idempotent: deleting an absent height still succeeds (no such row). */
    ok = ok && db_block_delete_by_height(&ndb, 777);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_26_sqlite_canonical_block_save_demotes_stal(int *failures)
{
    printf("SQLite canonical block save demotes stale height... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    uint8_t sol[] = {0x01, 0x02, 0x03};

    struct db_block stale;
    memset(&stale, 0, sizeof(stale));
    memset(stale.hash, 0xA1, 32);
    stale.height = 200;
    memset(stale.prev_hash, 0xB1, 32);
    stale.version = 4;
    memset(stale.merkle_root, 0xC1, 32);
    stale.time = 1700000200;
    stale.bits = 0x1d00ffff;
    memset(stale.nonce, 0xD1, 32);
    stale.solution = sol;
    stale.solution_len = sizeof(sol);
    memset(stale.chain_work, 0xE1, 32);
    stale.status = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    stale.file_num = 1;
    stale.data_pos = 8192;
    stale.num_tx = 2;
    ok = ok && db_block_save(&ndb, &stale);

    struct db_block canonical = stale;
    memset(canonical.hash, 0xA2, 32);
    memset(canonical.merkle_root, 0xC2, 32);
    canonical.file_num = 2;
    canonical.data_pos = 16384;

    struct db_block open_cursor;
    ok = ok && db_block_find_by_height(&ndb, 200, &open_cursor);
    ok = ok && db_block_save_canonical(&ndb, &canonical);
    ok = ok && (db_block_count(&ndb) == 2);

    struct db_block found;
    ok = ok && db_block_find_by_hash(&ndb, stale.hash, &found);
    ok = ok && (found.height == 200);
    ok = ok && (found.status == BLOCK_VALID_TREE);
    ok = ok && (found.file_num == 1);

    ok = ok && db_block_find_by_height(&ndb, 200, &found);
    ok = ok && (memcmp(found.hash, canonical.hash, 32) == 0);
    ok = ok && (found.status == canonical.status);
    ok = ok && (found.file_num == 2);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_27_sqlite_block_first_missing_connected_hei(int *failures)
{
    printf("SQLite block first missing connected height... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    uint8_t sol[] = {0x01, 0x02, 0x03};

    for (int h = 0; ok && h <= 5; h++) {
        if (h == 3)
            continue;
        struct db_block blk;
        memset(&blk, 0, sizeof(blk));
        memset(blk.hash, 0x10 + h, 32);
        blk.hash[0] = (uint8_t)(0x10 + h);
        blk.height = h;
        if (h > 0)
            memset(blk.prev_hash, 0x20 + h, 32);
        memset(blk.merkle_root, 0x30 + h, 32);
        blk.version = 4;
        blk.time = 1700000000 + (uint32_t)h;
        blk.bits = 0x1d00ffff;
        memset(blk.nonce, 0x40 + h, 32);
        blk.solution = sol;
        blk.solution_len = sizeof(sol);
        memset(blk.chain_work, 0x50 + h, 32);
        blk.status = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        blk.file_num = 1;
        blk.data_pos = h * 100;
        blk.undo_pos = 0;
        blk.num_tx = 1;
        ok = db_block_save(&ndb, &blk);
    }

    int missing = -2;
    ok = ok && db_block_first_missing_connected_height(&ndb, 5, &missing);
    ok = ok && missing == 3;
    ok = ok && db_block_first_missing_connected_height(&ndb, 2, &missing);
    ok = ok && missing == -1;

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_28_seed_blocks(struct node_db *ndb, bool ok)
{
    uint8_t sol[] = {0x01, 0x02, 0x03};
    for (int h = 0; ok && h <= 2; h++) {
        struct db_block blk;
        memset(&blk, 0, sizeof(blk));
        memset(blk.hash, 0x60 + h, 32);
        blk.hash[0] = (uint8_t)(0x60 + h);
        blk.height = h;
        if (h > 0)
            memset(blk.prev_hash, 0x70 + h, 32);
        memset(blk.merkle_root, 0x80 + h, 32);
        blk.version = 4;
        blk.time = 1700000100 + (uint32_t)h;
        blk.bits = 0x1d00ffff;
        memset(blk.nonce, 0x90 + h, 32);
        blk.solution = sol;
        blk.solution_len = sizeof(sol);
        memset(blk.chain_work, 0xA0 + h, 32);
        blk.status = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        blk.file_num = 1;
        blk.data_pos = h * 100;
        blk.num_tx = 1;
        ok = db_block_save(ndb, &blk);
    }
    return ok;
}

static bool check_sqlite_28_first_scan_then_cooldown(
    struct node_db *ndb, struct boot_projection_hole_scan *scan, bool ok)
{
    bool ran = false;
    int missing = -2;
    ok = ok && boot_projection_hole_scan_if_due(
        scan, ndb, 2, false, false, false, 2, 100, &ran, &missing);
    ok = ok && ran && missing == -1 && scan->next_scan_unix == 3700;

    ran = true;
    ok = ok && boot_projection_hole_scan_if_due(
        scan, ndb, 2, false, false, false, 2, 101, &ran, &missing);
    ok = ok && !ran;
    return ok;
}

static bool check_sqlite_28_forced_scan_then_cooldown(
    struct node_db *ndb, struct boot_projection_hole_scan *scan, bool ok)
{
    bool ran = true;
    int missing = -2;
    ok = ok && boot_projection_hole_scan_if_due(
        scan, ndb, 2, false, true, true, 2, 101, &ran, &missing);
    ok = ok && ran && missing == -1 && scan->next_scan_unix == 3701;

    ran = true;
    ok = ok && boot_projection_hole_scan_if_due(
        scan, ndb, 2, false, true, true, 2, 102, &ran, &missing);
    ok = ok && !ran;
    return ok;
}

static bool check_sqlite_28_delete_triggers_scan(
    struct node_db *ndb, struct boot_projection_hole_scan *scan, bool ok)
{
    bool ran = true;
    int missing = -2;
    ok = ok && db_block_delete_by_height(ndb, 1);
    ok = ok && boot_projection_hole_scan_if_due(
        scan, ndb, 2, false, false, false, 2, 3701, &ran, &missing);
    ok = ok && ran && missing == 1 && scan->next_scan_unix == 0;
    return ok;
}

static bool check_sqlite_28_scan_sequence(struct node_db *ndb,
                                          struct boot_projection_hole_scan *scan,
                                          bool ok)
{
    ok = check_sqlite_28_first_scan_then_cooldown(ndb, scan, ok);
    ok = check_sqlite_28_forced_scan_then_cooldown(ndb, scan, ok);
    ok = check_sqlite_28_delete_triggers_scan(ndb, scan, ok);
    return ok;
}

static void check_sqlite_28_sqlite_projection_hole_scan_uses_canonic(int *failures)
{
    printf("SQLite projection hole scan uses canonical owner and is bounded... ");
    char dir_template[] = "/tmp/zclassic23-projection-hole-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    struct node_db ndb;
    bool opened = false;
    bool ok = dir_path != NULL;
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        opened = node_db_open(&ndb, db_path);
        ok = opened;
    }

    ok = check_sqlite_28_seed_blocks(&ndb, ok);

    struct boot_projection_hole_scan scan;
    boot_projection_hole_scan_init(&scan);
    ok = check_sqlite_28_scan_sequence(&ndb, &scan, ok);

    if (opened)
        node_db_close(&ndb);
    cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_29_sqlite_block_save_retries_transient_writ(int *failures)
{
    printf("SQLite block save retries transient writer lock... ");
    char dir_template[] = "/tmp/zclassic23-block-save-lock-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    struct node_db locker;
    struct node_db writer;
    pthread_t thread;
    bool thread_started = false;
    bool ok = dir_path != NULL;
    uint8_t sol[] = {0x01, 0x02, 0x03};

    memset(&locker, 0, sizeof(locker));
    memset(&writer, 0, sizeof(writer));
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        ok = node_db_open(&locker, db_path);
    }
    if (ok)
        ok = node_db_open(&writer, db_path);
    if (ok)
        sqlite3_busy_timeout(writer.db, 0);
    if (ok)
        ok = node_db_exec(&locker, "BEGIN IMMEDIATE");
    if (ok)
        ok = node_db_exec(&locker,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('block_save_lock_test', X'01')");

    struct sqlite_lock_release_ctx ctx = {
        .ndb = &locker,
        .sleep_us = 1200000,
    };
    if (ok) {
        ok = pthread_create(&thread, NULL,
                            release_sqlite_write_lock_after_delay,
                            &ctx) == 0;
        thread_started = ok;
    }

    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, 0xA3, 32);
    blk.height = 201;
    memset(blk.prev_hash, 0xB3, 32);
    blk.version = 4;
    memset(blk.merkle_root, 0xC3, 32);
    blk.time = 1700000201;
    blk.bits = 0x1d00ffff;
    memset(blk.nonce, 0xD3, 32);
    blk.solution = sol;
    blk.solution_len = sizeof(sol);
    memset(blk.chain_work, 0xE3, 32);
    blk.status = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    blk.file_num = 3;
    blk.data_pos = 24576;
    blk.num_tx = 1;

    if (ok)
        ok = db_block_save(&writer, &blk);
    if (thread_started)
        ok = pthread_join(thread, NULL) == 0 && ok;
    if (ok)
        ok = db_block_count(&writer) == 1;

    node_db_close(&writer);
    node_db_close(&locker);
    if (dir_path)
        cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_30_sqlite_tx_index_save_find(int *failures)
{
    printf("SQLite tx index save/find... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    struct db_tx_index tx;
    memset(&tx, 0, sizeof(tx));
    memset(tx.txid, 0x11, 32);
    memset(tx.block_hash, 0x22, 32);
    tx.block_height = 500;
    tx.tx_index = 3;
    tx.file_num = 2;
    tx.file_pos = 16384;
    tx.is_coinbase = true;

    ok = ok && db_tx_save(&ndb, &tx);

    struct db_tx_index found;
    ok = ok && db_tx_find(&ndb, tx.txid, &found);
    ok = ok && (found.block_height == 500);
    ok = ok && (found.tx_index == 3);
    ok = ok && found.is_coinbase;

    ok = ok && db_tx_delete(&ndb, tx.txid);
    ok = ok && !db_tx_find(&ndb, tx.txid, &found);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_31_sqlite_utxo_save_find_balance(int *failures)
{
    printf("SQLite UTXO save/find/balance... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    uint8_t script[] = {0x76, 0xa9, 0x14};
    uint8_t addr[20];
    memset(addr, 0x42, 20);

    struct db_utxo u1 = {
        .vout = 0, .value = 50000000,
        .script = script, .script_len = 3,
        .script_type = SCRIPT_P2PKH,
        .has_address = true, .height = 100,
        .is_coinbase = false
    };
    memset(u1.txid, 0xAA, 32);
    memcpy(u1.address_hash, addr, 20);

    struct db_utxo u2 = {
        .vout = 1, .value = 30000000,
        .script = script, .script_len = 3,
        .script_type = SCRIPT_P2PKH,
        .has_address = true, .height = 101,
        .is_coinbase = false
    };
    memset(u2.txid, 0xBB, 32);
    memcpy(u2.address_hash, addr, 20);

    ok = ok && db_utxo_save(&ndb, &u1);
    ok = ok && db_utxo_save(&ndb, &u2);
    ok = ok && (db_utxo_count(&ndb) == 2);
    ok = ok && db_utxo_exists(&ndb, u1.txid, 0);
    ok = ok && !db_utxo_exists(&ndb, u1.txid, 1);

    int64_t bal = db_utxo_balance_for_address(&ndb, addr);
    ok = ok && (bal == 80000000);

    ok = ok && db_utxo_delete(&ndb, u1.txid, 0);
    ok = ok && (db_utxo_count(&ndb) == 1);
    bal = db_utxo_balance_for_address(&ndb, addr);
    ok = ok && (bal == 30000000);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_32_sqlite_wallet_key_write_find(int *failures)
{
    printf("SQLite wallet key write/find... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    /* Insert via the single writer (model save is gone) */
    uint8_t key_pkh[20];
    ok = ok && sqlite_test_write_wallet_key(&ndb, 0x11, key_pkh);
    ok = ok && db_wallet_key_exists(&ndb, key_pkh);
    ok = ok && (db_wallet_key_count(&ndb) == 1);

    struct db_wallet_key found;
    ok = ok && db_wallet_key_find(&ndb, key_pkh, &found);
    ok = ok && found.compressed;
    ok = ok && (found.pubkey_len == 33);
    ok = ok && (memcmp(found.pubkey_hash, key_pkh, 20) == 0);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_33_seed_txs(struct node_db *ndb, struct db_wallet_tx *t2)
{
    uint8_t raw1[] = {0x01};
    uint8_t raw2[] = {0x02, 0x03};
    uint8_t raw3[] = {0x04, 0x05, 0x06};

    struct db_wallet_tx t1;
    memset(&t1, 0, sizeof(t1));
    memset(t1.txid, 0xA1, 32);
    t1.raw_tx = raw1;
    t1.raw_tx_len = sizeof(raw1);
    t1.time_received = 100;

    memset(t2, 0, sizeof(*t2));
    memset(t2->txid, 0xB2, 32);
    t2->raw_tx = raw2;
    t2->raw_tx_len = sizeof(raw2);
    memset(t2->block_hash, 0x22, 32);
    t2->has_block = true;
    t2->block_height = 10;
    t2->time_received = 300;
    t2->from_me = true;
    t2->fee = 1234;

    struct db_wallet_tx t3;
    memset(&t3, 0, sizeof(t3));
    memset(t3.txid, 0xC3, 32);
    t3.raw_tx = raw3;
    t3.raw_tx_len = sizeof(raw3);
    t3.time_received = 200;

    bool ok = db_wallet_tx_save(ndb, &t1);
    ok = ok && db_wallet_tx_save(ndb, t2);
    ok = ok && db_wallet_tx_save(ndb, &t3);
    ok = ok && (db_wallet_tx_count(ndb) == 3);
    return ok;
}

static bool check_sqlite_33_list_pages(struct node_db *ndb, bool ok)
{
    struct db_wallet_tx rows[2];
    memset(rows, 0, sizeof(rows));
    int n = db_wallet_tx_list(ndb, rows, 2, 0);
    ok = ok && (n == 2);
    ok = ok && (rows[0].time_received == 300);
    ok = ok && (rows[1].time_received == 200);
    ok = ok && rows[0].from_me;
    ok = ok && (rows[0].fee == 1234);
    ok = ok && rows[0].has_block;
    ok = ok && (rows[0].block_height == 10);
    db_wallet_tx_free(&rows[0]);
    db_wallet_tx_free(&rows[1]);

    memset(rows, 0, sizeof(rows));
    n = db_wallet_tx_list(ndb, rows, 1, 2);
    ok = ok && (n == 1);
    ok = ok && (rows[0].time_received == 100);
    db_wallet_tx_free(&rows[0]);
    return ok;
}

static bool check_sqlite_33_find_by_txid(struct node_db *ndb,
                                         struct db_wallet_tx *t2, bool ok)
{
    struct db_wallet_tx found;
    ok = ok && db_wallet_tx_find(ndb, t2->txid, &found);
    ok = ok && found.from_me;
    ok = ok && (found.fee == 1234);
    ok = ok && found.has_block;
    ok = ok && (memcmp(found.block_hash, t2->block_hash, 32) == 0);
    db_wallet_tx_free(&found);
    return ok;
}

static void check_sqlite_33_sqlite_wallet_tx_list_find(int *failures)
{
    printf("SQLite wallet tx list/find... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    struct db_wallet_tx t2;

    ok = ok && check_sqlite_33_seed_txs(&ndb, &t2);
    ok = check_sqlite_33_list_pages(&ndb, ok);
    ok = check_sqlite_33_find_by_txid(&ndb, &t2, ok);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_34_sqlite_wallet_utxo_balance_spend(int *failures)
{
    printf("SQLite wallet UTXO balance/spend... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    uint8_t script[] = {0x76, 0xa9};
    struct db_wallet_utxo u1;
    memset(&u1, 0, sizeof(u1));
    memset(u1.txid, 0xAA, 32);
    u1.vout = 0;
    u1.value = 100000000;
    memset(u1.address_hash, 0x42, 20);
    u1.script = script;
    u1.script_len = 2;
    u1.height = 500;

    struct db_wallet_utxo u2;
    memset(&u2, 0, sizeof(u2));
    memset(u2.txid, 0xBB, 32);
    u2.vout = 0;
    u2.value = 50000000;
    memcpy(u2.address_hash, u1.address_hash, 20);
    u2.script = script;
    u2.script_len = 2;
    u2.height = 501;

    ok = ok && db_wallet_utxo_save(&ndb, &u1);
    ok = ok && db_wallet_utxo_save(&ndb, &u2);

    int64_t bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (bal == 150000000);

    /* Spend one UTXO */
    uint8_t spending_tx[32];
    memset(spending_tx, 0xCC, 32);
    ok = ok && db_wallet_utxo_mark_spent(&ndb, u1.txid, 0,
                                          spending_tx, 0);

    bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (bal == 50000000);

    /* List unspent */
    struct db_wallet_utxo unspent[10];
    int n = db_wallet_utxo_list_unspent(&ndb, unspent, 10);
    ok = ok && (n == 1);
    ok = ok && (unspent[0].value == 50000000);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_35_sqlite_sapling_note_save_balance(int *failures)
{
    printf("SQLite Sapling note save/balance... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    struct db_sapling_note n1;
    memset(&n1, 0, sizeof(n1));
    memset(n1.txid, 0xAA, 32);
    n1.output_index = 0;
    n1.value = 200000000;
    memset(n1.rcm, 0x11, 32);
    memset(n1.ivk, 0x22, 32);
    memset(n1.diversifier, 0x33, 11);
    memset(n1.pk_d, 0x44, 32);
    memset(n1.cm, 0x55, 32);
    memset(n1.nullifier, 0x66, 32);
    n1.block_height = 1000;

    ok = ok && db_sapling_note_save(&ndb, &n1);

    int64_t bal = db_sapling_note_balance(&ndb);
    ok = ok && (bal == 200000000);

    bal = db_sapling_note_balance_for_ivk(&ndb, n1.ivk);
    ok = ok && (bal == 200000000);

    /* Mark spent via nullifier */
    uint8_t spent_by[32];
    memset(spent_by, 0x77, 32);
    ok = ok && db_sapling_note_mark_spent_bool_compat(&ndb, n1.nullifier, spent_by);

    bal = db_sapling_note_balance(&ndb);
    ok = ok && (bal == 0);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_36_save_spend_clear(struct node_db *ndb, bool ok)
{
    uint8_t raw[] = {0x01, 0x00, 0x00, 0x00};
    struct db_mempool_entry e;
    memset(&e, 0, sizeof(e));
    memset(e.txid, 0xAA, 32);
    e.raw_tx = raw;
    e.raw_tx_len = 4;
    e.fee = 10000;
    e.size = 250;
    e.time_added = 1700000000;
    e.height_added = 500;

    ok = ok && db_mempool_save(ndb, &e);
    ok = ok && (db_mempool_count(ndb) == 1);

    /* Add a spend record */
    uint8_t spent_txid[32];
    memset(spent_txid, 0xBB, 32);
    ok = ok && db_mempool_add_spend(ndb, e.txid, spent_txid, 0);
    ok = ok && db_mempool_is_spent(ndb, spent_txid, 0);
    ok = ok && !db_mempool_is_spent(ndb, spent_txid, 1);

    ok = ok && db_mempool_clear(ndb);
    ok = ok && (db_mempool_count(ndb) == 0);
    return ok;
}

static bool check_sqlite_36_stale_entry_revalidated(struct node_db *ndb, bool ok)
{
    /* Startup persistence is untrusted input too. A structurally valid
     * row with a missing prevout must be revalidated and dropped instead
     * of re-entering through tx_mempool_add_unchecked(). */
    struct transaction stale = make_sync_test_tx();
    struct byte_stream raw_stream;
    stream_init(&raw_stream, 256);
    ok = ok && transaction_serialize(&stale, &raw_stream);
    struct db_mempool_entry e;
    memset(&e, 0, sizeof(e));
    memcpy(e.txid, stale.hash.data, 32);
    e.raw_tx = raw_stream.data;
    e.raw_tx_len = raw_stream.size;
    e.fee = 10000;
    e.size = (int)raw_stream.size;
    e.time_added = 1700000000;
    e.height_added = 500;
    ok = ok && db_mempool_save(ndb, &e);

    struct tx_mempool restored;
    tx_mempool_init(&restored, 0);
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);
    struct main_state main_state;
    main_state_init(&main_state);

    int loaded = node_db_sync_mempool_load(
        ndb, &restored, &coins, &main_state, chain_params_get());
    ok = ok && loaded == 0;
    ok = ok && tx_mempool_size(&restored) == 0;
    ok = ok && db_mempool_count(ndb) == 0;

    main_state_free(&main_state);
    coins_view_cache_free(&coins);
    tx_mempool_free(&restored);
    stream_free(&raw_stream);
    free_sync_test_tx(&stale);
    return ok;
}

static void check_sqlite_36_sqlite_mempool_save_find_clear(int *failures)
{
    printf("SQLite mempool save/find/clear... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    ok = check_sqlite_36_save_spend_clear(&ndb, ok);
    ok = check_sqlite_36_stale_entry_revalidated(&ndb, ok);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_37_sqlite_peer_save_find_recent(int *failures)
{
    printf("SQLite peer save/find/recent... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    struct db_peer p;
    memset(&p, 0, sizeof(p));
    p.ip[10] = 0xFF; p.ip[11] = 0xFF;
    p.ip[12] = 127; p.ip[13] = 0; p.ip[14] = 0; p.ip[15] = 1;
    p.port = 8033;
    p.services = 1;
    p.last_seen = 1700000000;

    ok = ok && db_peer_save(&ndb, &p);
    ok = ok && (db_peer_count(&ndb) == 1);

    struct db_peer found;
    ok = ok && db_peer_find_by_addr(&ndb, p.ip, p.port, &found);
    ok = ok && (found.port == 8033);
    ok = ok && (found.services == 1);

    ok = ok && db_peer_mark_tried(&ndb, p.ip, p.port);
    ok = ok && db_peer_find_by_addr(&ndb, p.ip, p.port, &found);
    ok = ok && (found.attempts == 1);

    ok = ok && db_peer_mark_seen(&ndb, p.ip, p.port, 1700000100);
    ok = ok && db_peer_find_by_addr(&ndb, p.ip, p.port, &found);
    ok = ok && (found.attempts == 0);
    ok = ok && (found.last_seen == 1700000100);

    struct db_peer recent[10];
    int n = db_peer_recent(&ndb, recent, 10);
    ok = ok && (n == 1);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_38_sqlite_peer_save_retries_transient_write(int *failures)
{
    printf("SQLite peer save retries transient writer lock... ");
    char dir_template[] = "/tmp/zclassic23-peer-save-lock-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    struct node_db locker;
    struct node_db writer;
    pthread_t thread;
    bool thread_started = false;
    bool ok = dir_path != NULL;

    memset(&locker, 0, sizeof(locker));
    memset(&writer, 0, sizeof(writer));
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        ok = node_db_open(&locker, db_path);
    }
    if (ok)
        ok = node_db_open(&writer, db_path);
    if (ok)
        sqlite3_busy_timeout(writer.db, 0);
    if (ok)
        ok = node_db_exec(&locker, "BEGIN IMMEDIATE");
    if (ok)
        ok = node_db_exec(&locker,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('peer_save_lock_test', X'01')");

    struct sqlite_lock_release_ctx ctx = {
        .ndb = &locker,
        .sleep_us = 3000000,
    };
    if (ok) {
        ok = pthread_create(&thread, NULL,
                            release_sqlite_write_lock_after_delay,
                            &ctx) == 0;
        thread_started = ok;
    }

    struct db_peer p;
    memset(&p, 0, sizeof(p));
    p.ip[10] = 0xFF; p.ip[11] = 0xFF;
    p.ip[12] = 10; p.ip[13] = 9; p.ip[14] = 8; p.ip[15] = 7;
    p.port = 8033;
    p.services = 1;
    p.last_seen = 1700000200;

    if (ok)
        ok = db_peer_save(&writer, &p);
    if (thread_started)
        ok = pthread_join(thread, NULL) == 0 && ok;
    if (ok)
        ok = db_peer_count(&writer) == 1;

    node_db_close(&writer);
    node_db_close(&locker);
    if (dir_path)
        cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_39_sqlite_advisory_peer_save_fails_fast_und(int *failures)
{
    printf("SQLite advisory peer save fails fast under writer lock... ");
    char dir_template[] = "/tmp/zclassic23-peer-save-advisory-XXXXXX";
    char *dir_path = mkdtemp(dir_template);
    char db_path[1024];
    struct node_db locker;
    struct node_db writer;
    bool ok = dir_path != NULL;

    memset(&locker, 0, sizeof(locker));
    memset(&writer, 0, sizeof(writer));
    if (ok) {
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
        ok = node_db_open(&locker, db_path);
    }
    if (ok)
        ok = node_db_open(&writer, db_path);
    if (ok)
        sqlite3_busy_timeout(writer.db, 0);
    if (ok)
        ok = node_db_exec(&locker, "BEGIN IMMEDIATE");
    if (ok)
        ok = node_db_exec(&locker,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('peer_save_advisory_lock_test', X'01')");

    struct db_peer p;
    memset(&p, 0, sizeof(p));
    p.ip[10] = 0xFF; p.ip[11] = 0xFF;
    p.ip[12] = 10; p.ip[13] = 9; p.ip[14] = 8; p.ip[15] = 6;
    p.port = 8033;
    p.services = 1;
    p.last_seen = 1700000300;

    struct timespec start;
    struct timespec end;
    platform_time_monotonic_timespec(&start);
    bool saved = ok && db_peer_save_advisory(&writer, &p);
    platform_time_monotonic_timespec(&end);
    int64_t elapsed_ms =
        (int64_t)(end.tv_sec - start.tv_sec) * 1000 +
        (int64_t)(end.tv_nsec - start.tv_nsec) / 1000000;
    ok = ok && !saved;
    ok = ok && elapsed_ms < 1000;

    node_db_rollback(&locker);
    node_db_close(&writer);
    node_db_close(&locker);
    if (dir_path)
        cleanup_temp_db_dir(dir_path);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_40_sqlite_batch_insert_with_begin_commit(int *failures)
{
    printf("SQLite batch insert with begin/commit... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    ok = ok && node_db_begin(&ndb);
    for (int i = 0; i < 100; i++) {
        struct db_tx_index tx;
        memset(&tx, 0, sizeof(tx));
        memset(tx.txid, 0x11, 32);
        tx.txid[0] = (uint8_t)((i >> 8) + 1);
        tx.txid[1] = (uint8_t)((i & 0xFF) + 1);
        memset(tx.block_hash, 0x22, 32);
        tx.block_height = i;
        tx.tx_index = 0;
        tx.file_num = 0;
        tx.file_pos = i * 1000;
        ok = ok && db_tx_save(&ndb, &tx);
    }
    ok = ok && node_db_commit(&ndb);

    /* Verify all 100 were inserted */
    struct db_tx_index found;
    uint8_t lookup[32];
    memset(lookup, 0x11, 32);
    lookup[0] = 1;
    lookup[1] = 51; /* i=50: (50>>8)+1=1, (50&0xFF)+1=51 */
    ok = ok && db_tx_find(&ndb, lookup, &found);
    ok = ok && (found.block_height == 50);

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_41_sqlite_sapling_key_write_find(int *failures)
{
    printf("SQLite Sapling key write/find... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    /* Insert via the single writer (model save is gone) */
    struct wallet_sqlite ws;
    ok = ok && wallet_sqlite_open(&ws, ndb.db);
    struct sapling_key_entry e;
    memset(&e, 0, sizeof(e));
    memset(e.ivk, 0x11, 32);
    memset(&e.xsk, 0x22, sizeof(e.xsk));
    memset(&e.xfvk, 0x33, sizeof(e.xfvk));
    memset(e.diversifier, 0x44, 11);
    memset(e.pk_d, 0x55, 32);
    e.child_index = 0;
    e.used = true;
    ok = ok && wallet_sqlite_write_sapling_key(&ws, 0, &e);
    ok = ok && (db_sapling_key_count(&ndb) == 1);

    struct db_sapling_key found;
    ok = ok && db_sapling_key_find_by_ivk(&ndb, e.ivk, &found);
    ok = ok && (found.child_index == 0);

    wallet_sqlite_close(&ws);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_42_sqlite_wallet_seed_write_load(int *failures)
{
    printf("SQLite wallet seed write/load... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    struct wallet_sqlite ws;
    ok = ok && wallet_sqlite_open(&ws, ndb.db);

    uint8_t seed[32];
    memset(seed, 0xAB, 32);
    ok = ok && wallet_sqlite_write_sapling_seed(&ws, seed);

    /* Decrypting reader round-trips the seed bytes. */
    uint8_t loaded[32];
    ok = ok && wallet_sqlite_read_sapling_seed(&ws, loaded);
    ok = ok && (memcmp(loaded, seed, 32) == 0);

    /* next_child starts at 0 and advances as keys are written. */
    uint32_t next = 99;
    uint8_t raw[32];
    ok = ok && db_wallet_seed_load(&ndb, raw, &next);
    ok = ok && (next == 0);

    struct sapling_key_entry e;
    memset(&e, 0, sizeof(e));
    memset(e.ivk, 0x77, 32);
    e.child_index = 4;
    e.used = true;
    ok = ok && wallet_sqlite_write_sapling_key(&ws, 4, &e);
    ok = ok && db_wallet_seed_load(&ndb, raw, &next);
    ok = ok && (next == 5);

    memset(e.ivk, 0x88, 32);
    e.child_index = 9;
    ok = ok && wallet_sqlite_write_sapling_key(&ws, 9, &e);
    ok = ok && db_wallet_seed_load(&ndb, raw, &next);
    ok = ok && (next == 10);

    wallet_sqlite_close(&ws);
    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_43_sqlite_wallet_utxo_lifecycle(int *failures)
{
    printf("SQLite wallet UTXO lifecycle... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    uint8_t script[] = {0x76, 0xa9, 0x14};
    uint8_t addr[20];
    memset(addr, 0x42, 20);

    /* Create two wallet UTXOs */
    struct db_wallet_utxo wu1;
    memset(&wu1, 0, sizeof(wu1));
    memset(wu1.txid, 0xAA, 32);
    wu1.vout = 0;
    wu1.value = 50000000; /* 0.5 ZCL */
    memcpy(wu1.address_hash, addr, 20);
    wu1.script = script;
    wu1.script_len = 3;
    wu1.height = 100;
    wu1.is_coinbase = false;

    struct db_wallet_utxo wu2;
    memset(&wu2, 0, sizeof(wu2));
    memset(wu2.txid, 0xBB, 32);
    wu2.vout = 0;
    wu2.value = 48000000; /* 0.48 ZCL */
    memcpy(wu2.address_hash, addr, 20);
    wu2.script = script;
    wu2.script_len = 3;
    wu2.height = 101;
    wu2.is_coinbase = false;

    ok = ok && db_wallet_utxo_save(&ndb, &wu1);
    ok = ok && db_wallet_utxo_save(&ndb, &wu2);

    /* Balance = 0.98 ZCL unspent */
    int64_t bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (bal == 98000000);

    /* Mark one as spent */
    uint8_t spent_by[32];
    memset(spent_by, 0xCC, 32);
    ok = ok && db_wallet_utxo_mark_spent(&ndb, wu1.txid, 0,
                                          spent_by, 0);

    /* Balance = 0.48 ZCL */
    bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (bal == 48000000);

    /* INSERT OR REPLACE: re-save wu1 should reset spent state */
    ok = ok && db_wallet_utxo_save(&ndb, &wu1);
    bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (bal == 98000000); /* back to 0.98 */

    /* Delete one */
    ok = ok && db_wallet_utxo_delete(&ndb, wu2.txid, 0);
    bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (bal == 50000000); /* only wu1 */

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_44_sqlite_utxo_check_constraint_negative_va(int *failures)
{
    printf("SQLite UTXO CHECK constraint (negative value rejected)... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    uint8_t script[] = {0x76, 0xa9, 0x14};
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memset(u.txid, 0xDD, 32);
    u.vout = 0;
    u.value = -1; /* negative — must be rejected */
    u.script = script;
    u.script_len = 3;
    u.script_type = SCRIPT_P2PKH;
    u.height = 1;

    /* Should fail: validation rejects negative value */
    bool saved = db_utxo_save(&ndb, &u);
    ok = ok && !saved;

    /* MAX_MONEY + 1 should also fail */
    u.value = 2100000000000001LL;
    saved = db_utxo_save(&ndb, &u);
    ok = ok && !saved;

    /* Exactly MAX_MONEY should succeed */
    u.value = 2100000000000000LL;
    saved = db_utxo_save(&ndb, &u);
    ok = ok && saved;

    /* Normal value should succeed */
    u.value = 100000000; /* 1 ZCL */
    memset(u.txid, 0xEE, 32);
    saved = db_utxo_save(&ndb, &u);
    ok = ok && saved;

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_45_sqlite_cross_validate_global_vs_wallet_b(int *failures)
{
    printf("SQLite cross-validate global vs wallet balance... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    uint8_t addr[20], script[] = {0x76, 0xa9, 0x14};
    memset(addr, 0x42, 20);

    /* Add UTXO to global table */
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memset(u.txid, 0xAA, 32);
    u.vout = 0;
    u.value = 98000000; /* 0.98 ZCL */
    u.script = script;
    u.script_len = 3;
    u.script_type = SCRIPT_P2PKH;
    u.has_address = true;
    memcpy(u.address_hash, addr, 20);
    u.height = 100;
    ok = ok && db_utxo_save(&ndb, &u);

    /* Add same UTXO to wallet table */
    struct db_wallet_utxo wu;
    memset(&wu, 0, sizeof(wu));
    memcpy(wu.txid, u.txid, 32);
    wu.vout = 0;
    wu.value = 98000000;
    memcpy(wu.address_hash, addr, 20);
    wu.script = script;
    wu.script_len = 3;
    wu.height = 100;
    ok = ok && db_wallet_utxo_save(&ndb, &wu);

    /* Both should report same balance */
    int64_t global_bal = db_utxo_balance_for_address(&ndb, addr);
    int64_t wallet_bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (global_bal == 98000000);
    ok = ok && (wallet_bal == 98000000);
    ok = ok && (global_bal == wallet_bal);

    /* Mark wallet UTXO spent — wallet should be 0, global unchanged */
    uint8_t spent_by[32];
    memset(spent_by, 0xCC, 32);
    ok = ok && db_wallet_utxo_mark_spent(&ndb, wu.txid, 0,
                                          spent_by, 0);
    wallet_bal = db_wallet_utxo_balance(&ndb);
    ok = ok && (wallet_bal == 0);
    global_bal = db_utxo_balance_for_address(&ndb, addr);
    ok = ok && (global_bal == 98000000); /* global unchanged */

    node_db_close(&ndb);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_46_sqlite_pragma_tuning_cache_size_and_mmap(int *failures)
{
    printf("SQLite PRAGMA tuning: cache_size and mmap_size locked... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    sqlite3_stmt *s = NULL;
    int64_t cache_pages = 0;
    int64_t mmap_bytes = 0;
    if (ok && sqlite3_prepare_v2(ndb.db, "PRAGMA cache_size",
                                 -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW)
            cache_pages = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    } else {
        ok = false;
    }
    if (ok && sqlite3_prepare_v2(ndb.db, "PRAGMA mmap_size",
                                 -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW)
            mmap_bytes = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    } else {
        ok = false;
    }

    /* Negative cache_size in SQLite = "abs(N) KiB". */
    int64_t expected_cache_kib = hw_profile_sqlite_cache_kib(
        hw_profile_ram_bytes(), 16 * 1024, 64 * 1024);
    ok = ok && (cache_pages == -expected_cache_kib);
    /* mmap may be silently clamped to 0 on a :memory: database
     * depending on the SQLite build, so accept either the derived
     * value (on a real file) or any value ≥ 0 (on :memory:). */
    ok = ok && (mmap_bytes >= 0);

    node_db_close(&ndb);
    if (ok) printf("OK (cache=%lld mmap=%lld)\n",
                   (long long)cache_pages, (long long)mmap_bytes);
    else { printf("FAIL (cache=%lld mmap=%lld)\n",
                  (long long)cache_pages, (long long)mmap_bytes);
           (*failures)++; }
}

static void check_sqlite_47_sqlite_pragma_tuning_honors_constrained_(int *failures)
{
    /* A large host does not make a 4 GiB cgroup a large lane. Reproduce
     * the live dev envelope and prove both the persistent node handle and
     * read-only explorer helper receive a zero mmap window rather than a
     * 256 MiB working set that repeatedly crosses memory.high. */
    printf("SQLite PRAGMA tuning honors constrained cgroup budget... ");
    struct os_proc_mem constrained = {
        .rss_bytes = 1024 * 1024,
        .vsize_bytes = 2 * 1024 * 1024,
        .cgroup_current = 2LL * 1024 * 1024 * 1024,
        .cgroup_high = 4LL * 1024 * 1024 * 1024,
        .cgroup_max = 8LL * 1024 * 1024 * 1024,
        .sys_total_bytes = 64LL * 1024 * 1024 * 1024,
        .sys_avail_bytes = 32LL * 1024 * 1024 * 1024,
    };
    os_proc_mem_set_override(&constrained);
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");
    sqlite3_stmt *s = NULL;
    int64_t cache_pages = 0;
    if (ok && sqlite3_prepare_v2(ndb.db, "PRAGMA cache_size",
                                 -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)
        cache_pages = sqlite3_column_int64(s, 0);
    else
        ok = false;
    sqlite3_finalize(s);
    ok = ok && cache_pages == -(16 * 1024);
    ok = ok && node_db_recommended_mmap_bytes() == 0;
    if (ndb.open) node_db_close(&ndb);
    os_proc_mem_set_override(NULL);
    if (ok) printf("OK (cache=%lld mmap=0)\n",
                   (long long)cache_pages);
    else { printf("FAIL (cache=%lld)\n", (long long)cache_pages);
           (*failures)++; }
}

static void check_sqlite_48_sqlite_node_state_detached_fallback_wait(int *failures)
{
    printf("SQLite node_state detached fallback waits out writer lock... ");
    char dir[256];
    char dbpath[512];
    test_make_tmpdir(dir, sizeof(dir), "sqlite", "detached_state");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db locker;
    struct node_db writer;
    pthread_t thread;
    bool thread_started = false;
    memset(&locker, 0, sizeof(locker));
    memset(&writer, 0, sizeof(writer));
    app_runtime_set_current(NULL);
    bool ok = node_db_open(&locker, dbpath);
    ok = ok && node_db_open(&writer, dbpath);

    if (ok)
        sqlite3_busy_timeout(writer.db, 0);
    if (ok)
        ok = node_db_exec(&locker, "BEGIN IMMEDIATE");
    if (ok)
        ok = node_db_exec(&locker,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('cec_detached_lock_holder', X'01')");

    struct sqlite_lock_release_ctx ctx = {
        .ndb = &locker,
        .sleep_us = 250000,
    };
    if (ok) {
        ok = pthread_create(&thread, NULL,
                            release_sqlite_write_lock_after_delay,
                            &ctx) == 0;
        thread_started = ok;
    }

    const char fallback[] = "fallback";
    bool fallback_ok = false;
    if (ok) {
        fallback_ok = chain_evidence_state_set_retry(
            &writer, "cec.detached.locked",
            fallback, sizeof(fallback), "unit.detached_state").ok;
    }
    if (thread_started)
        pthread_join(thread, NULL);

    struct node_db_status final_status;
    node_db_get_status(&writer, &final_status);
    char got[32];
    size_t got_len = 0;
    memset(got, 0, sizeof(got));
    ok = ok && fallback_ok &&
         node_db_state_get(&writer, "cec.detached.locked",
                           got, sizeof(got), &got_len) &&
         got_len == sizeof(fallback) &&
         memcmp(got, fallback, sizeof(fallback)) == 0;

    node_db_close(&writer);
    node_db_close(&locker);
    test_cleanup_tmpdir(dir);
    if (ok) printf("OK\n");
    else { printf("FAIL (fallback_ok=%d got_len=%zu "
                   "last_rc=%d last_op=%s)\n",
                  fallback_ok, got_len,
                  final_status.last_sqlite_rc,
                  final_status.last_op[0] ? final_status.last_op : "");
           (*failures)++; }
}

static void check_sqlite_49_sqlite_100k_utxo_random_read_smoke_test(int *failures)
{
    printf("SQLite 100k UTXO random-read smoke test... ");
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:");

    const int N = 100000;  /* 100k rows per brief */
    const int READS = 100;

    /* Seed N rows: txid = i in little-endian, value = i+1 (CHECK >= 0
     * is satisfied by i+1 ≥ 1), height = i.  script and
     * address_hash are NOT NULL in the schema, so bind a minimal
     * P2PKH-shaped blob for both. */
    const uint8_t script[] = {0x76, 0xa9, 0x14, 0x00, 0x00, 0x00};
    const uint8_t addr[20] = {0};
    if (ok) {
        sqlite3_exec(ndb.db, "BEGIN", NULL, NULL, NULL);
        sqlite3_stmt *ins = NULL;
        ok = sqlite3_prepare_v2(ndb.db,
            "INSERT INTO utxos(txid,vout,value,script,script_type,"
            "address_hash,height,is_coinbase) "
            "VALUES(?,0,?,?,0,?,?,0)", -1, &ins, NULL) == SQLITE_OK;
        for (int i = 0; ok && i < N; i++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            txid[0] = (uint8_t)(i & 0xFF);
            txid[1] = (uint8_t)((i >> 8) & 0xFF);
            txid[2] = (uint8_t)((i >> 16) & 0xFF);
            sqlite3_reset(ins);
            sqlite3_bind_blob(ins, 1, txid, 32, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins, 2, i + 1);  /* value = i+1 */
            sqlite3_bind_blob(ins, 3, script, sizeof(script), SQLITE_STATIC);
            sqlite3_bind_blob(ins, 4, addr, sizeof(addr), SQLITE_STATIC);
            sqlite3_bind_int(ins, 5, i);
            ok = sqlite3_step(ins) == SQLITE_DONE;  // raw-sql-ok:test-fixture-setup
        }
        sqlite3_finalize(ins);
        sqlite3_exec(ndb.db, "COMMIT", NULL, NULL, NULL);
    }

    /* 100 random reads — deterministic sequence so failures are
     * reproducible.  LCG: 1664525*x + 1013904223 mod 2^32. */
    uint32_t state = 0xC0FFEE;
    int hits = 0;
    if (ok) {
        sqlite3_stmt *q = NULL;
        ok = sqlite3_prepare_v2(ndb.db,
            "SELECT value,height FROM utxos WHERE txid=? LIMIT 1",
            -1, &q, NULL) == SQLITE_OK;
        for (int k = 0; ok && k < READS; k++) {
            state = state * 1664525u + 1013904223u;
            int idx = (int)(state % (uint32_t)N);
            uint8_t txid[32];
            memset(txid, 0, 32);
            txid[0] = (uint8_t)(idx & 0xFF);
            txid[1] = (uint8_t)((idx >> 8) & 0xFF);
            txid[2] = (uint8_t)((idx >> 16) & 0xFF);
            sqlite3_reset(q);
            sqlite3_bind_blob(q, 1, txid, 32, SQLITE_TRANSIENT);
            int rc = sqlite3_step(q);  // raw-sql-ok:test-fixture-verify
            if (rc == SQLITE_ROW) {
                int64_t val = sqlite3_column_int64(q, 0);
                int64_t h   = sqlite3_column_int64(q, 1);
                if (val == idx + 1 && h == idx) hits++;
                else ok = false;
            } else {
                ok = false;
            }
        }
        sqlite3_finalize(q);
    }

    ok = ok && (hits == READS);
    node_db_close(&ndb);
    if (ok) printf("OK (%d/%d reads consistent)\n", hits, READS);
    else { printf("FAIL (hits=%d)\n", hits); (*failures)++; }
}

static void check_sqlite_50_sqlite_wal_checkpoint_classification_is_(int *failures)
{
    printf("SQLite WAL checkpoint classification is unambiguous... ");
    bool ok = true;

    /* The one case the old code could not express: completed, and
     * reclaimed NOTHING. It must not share an answer with a drain. */
    ok = ok && wal_ckpt_classify(true, false, 400, 0) == WAL_CKPT_NOOP;
    ok = ok && wal_ckpt_classify(true, false, 400, 400) == WAL_CKPT_DRAINED;
    ok = ok && wal_ckpt_classify(true, false, 400, 120) == WAL_CKPT_PARTIAL;
    /* An empty log is drained, not a no-op: there was nothing to move. */
    ok = ok && wal_ckpt_classify(true, false, 0, 0) == WAL_CKPT_DRAINED;
    /* Busy outranks completed, because the engine reports internal
     * contention as a SUCCESSFUL call with busy set in its result row. */
    ok = ok && wal_ckpt_classify(true, true, 400, 400) == WAL_CKPT_BUSY;
    ok = ok && wal_ckpt_classify(false, false, -1, -1) == WAL_CKPT_ERROR;
    /* Unknown counts cannot be talked up into a success. */
    ok = ok && wal_ckpt_classify(true, false, -1, -1) == WAL_CKPT_UNKNOWN;

    ok = ok && wal_ckpt_outcome_reclaimed_nothing(WAL_CKPT_NOOP);
    ok = ok && wal_ckpt_outcome_reclaimed_nothing(WAL_CKPT_BUSY);
    ok = ok && wal_ckpt_outcome_reclaimed_nothing(WAL_CKPT_ERROR);
    ok = ok && !wal_ckpt_outcome_reclaimed_nothing(WAL_CKPT_DRAINED);
    ok = ok && !wal_ckpt_outcome_reclaimed_nothing(WAL_CKPT_PARTIAL);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_51_open_bound_by_open(struct node_db *ndb, bool ok)
{
    /* 1. The bound is established BY THE OPEN, not by an end-of-phase
     *    restore. Both settings are per-connection, so a process killed
     *    mid-sync never reaches a restore and the next process inherits
     *    only what the open path set. Without journal_size_limit an
     *    autocheckpointed WAL keeps its high-water mark for the life of
     *    the connection — the file never shrinks, however clean the
     *    checkpoints look. */
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA wal_autocheckpoint")
                   == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES;
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA journal_size_limit")
                   == ZCL_NODE_DB_JOURNAL_SIZE_LIMIT;
    return ok;
}

static bool check_sqlite_51_bulk_mode_loosens_never_removes(struct node_db *ndb, bool ok)
{
    /* 2. Bulk-sync mode loosens those bounds; it must never remove them.
     *    An unbounded write-ahead log is not a faster setting. */
    ok = ok && node_db_ibd_turbo_mode(ndb);
    int64_t bulk_ckpt =
        sqlite_test_pragma_i64(ndb->db, "PRAGMA wal_autocheckpoint");
    ok = ok && bulk_ckpt != 0;
    ok = ok && bulk_ckpt == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES_BULK;
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA journal_size_limit")
                   == ZCL_NODE_DB_JOURNAL_SIZE_LIMIT_BULK;
    ok = ok && node_db_normal_mode(ndb);
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA wal_autocheckpoint")
                   == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES;
    return ok;
}

static bool check_sqlite_51_drained_vs_noop(struct node_db *ndb,
                                            struct wal_ckpt_record *drain,
                                            bool ok)
{
    /* 3. A checkpoint that DRAINS a non-empty log and one that moves
     *    nothing must be tellable apart. Both return true. */
    wal_ckpt_stats_reset();
    for (int i = 0; ok && i < 64; i++) {
        char key[32];
        uint8_t val[64];
        snprintf(key, sizeof(key), "wal_bounds_%d", i);
        memset(val, (uint8_t)i, sizeof(val));
        ok = node_db_state_set(ndb, key, val, sizeof(val));
    }

    ok = ok && node_db_wal_checkpoint_result(ndb, drain);
    ok = ok && drain->outcome == WAL_CKPT_DRAINED;
    ok = ok && drain->ckpt_frames > 0;      /* it really moved frames */
    ok = ok && drain->log_frames >= 0;

    struct wal_ckpt_record again = {0};
    ok = ok && node_db_wal_checkpoint_result(ndb, &again);
    /* Same true, same outcome name — and a different, honest number.
     * The frame count is the only thing that separates them. */
    ok = ok && again.ckpt_frames == 0;
    ok = ok && again.ckpt_frames != drain->ckpt_frames;
    return ok;
}

static bool check_sqlite_51_ledger_and_periodic_state(struct wal_ckpt_record *drain, bool ok)
{
    /* 4. Every attempt lands in the one ledger the operator reads, from
     *    whichever checkpointer ran it. */
    struct wal_ckpt_stats st;
    memset(&st, 0, sizeof(st));
    wal_ckpt_stats_snapshot(&st);
    ok = ok && st.attempts_total == 2;
    ok = ok && st.frames_moved_total == drain->ckpt_frames;
    ok = ok && st.noop_total == 0 && st.error_total == 0;
    ok = ok && st.last_source && strcmp(st.last_source, "node_db") == 0;

    /* 5. The periodic checkpointer's state is DECLARED, never inferred.
     *    "Not started" and "ran and found nothing to do" are different
     *    facts and must not render as the same silence. */
    wal_ckpt_stats_set_periodic_armed(false, "not_started");
    wal_ckpt_stats_snapshot(&st);
    ok = ok && !st.periodic_armed;
    ok = ok && st.periodic_state &&
               strcmp(st.periodic_state, "not_started") == 0;
    wal_ckpt_stats_set_periodic_armed(true, "armed");
    wal_ckpt_stats_snapshot(&st);
    ok = ok && st.periodic_armed;
    return ok;
}

/* Answer the one question the live node asks every five minutes: can this
 * connection still checkpoint? SQLITE_LOCKED here means the connection is
 * inside a transaction it did not declare — a cached reader parked on a row. */
static int sqlite_53_checkpoint_rc(struct node_db *ndb)
{
    int log_frames = -1, ckpt_frames = -1;
    return sqlite3_wal_checkpoint_v2(ndb->db, NULL, SQLITE_CHECKPOINT_PASSIVE,
                                     &log_frames, &ckpt_frames);
}

static bool check_sqlite_53_seed(struct node_db *ndb, struct db_peer *p,
                                 struct db_utxo *u, bool ok)
{
    static uint8_t script[] = {0x76, 0xa9, 0x14};

    memset(p, 0, sizeof(*p));
    p->ip[10] = 0xFF; p->ip[11] = 0xFF;
    p->ip[12] = 127; p->ip[13] = 0; p->ip[14] = 0; p->ip[15] = 1;
    p->port = 8033;
    p->services = 1;
    p->last_seen = 1700000000;

    memset(u, 0, sizeof(*u));
    memset(u->txid, 0xAA, 32);
    u->vout = 0;
    u->value = 50000000;
    u->script = script;
    u->script_len = sizeof(script);
    u->script_type = SCRIPT_P2PKH;
    u->has_address = true;
    memset(u->address_hash, 0x42, 20);
    u->height = 100;

    ok = ok && db_peer_save(ndb, p);
    ok = ok && db_utxo_save(ndb, u);
    /* A clean connection checkpoints. Anything else and the rest of this
     * check would be measuring the fixture, not the readers. */
    ok = ok && sqlite_53_checkpoint_rc(ndb) != SQLITE_LOCKED;
    return ok;
}

static void check_sqlite_53_cached_readers_release_the_snap(int *failures)
{
    printf("SQLite cached readers release the WAL snapshot they read... ");
    char dir[256];
    char dbpath[512];
    test_make_tmpdir(dir, sizeof(dir), "sqlite", "cached_reader_snapshot");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct db_peer p;
    struct db_utxo u;
    ok = check_sqlite_53_seed(&ndb, &p, &u, ok);

    /* Each of these three reads runs on a statement node_db caches for the
     * life of the connection. A hit used to leave that statement standing on
     * its row, which is how a live node reached "database is locked" on every
     * writer while its reads kept working and its WAL kept growing. */
    struct db_peer found_peer;
    ok = ok && db_peer_find_by_addr(&ndb, p.ip, p.port, &found_peer);
    ok = ok && sqlite_53_checkpoint_rc(&ndb) != SQLITE_LOCKED;

    ok = ok && db_peer_count(&ndb) == 1;
    ok = ok && sqlite_53_checkpoint_rc(&ndb) != SQLITE_LOCKED;

    struct db_utxo found_utxo;
    memset(&found_utxo, 0, sizeof(found_utxo));
    ok = ok && db_utxo_find(&ndb, u.txid, u.vout, &found_utxo);
    ok = ok && found_utxo.value == u.value;
    free(found_utxo.script);
    ok = ok && sqlite_53_checkpoint_rc(&ndb) != SQLITE_LOCKED;

    /* A miss must release the statement too — the same connection is the one
     * every other subsystem writes through. */
    struct db_peer absent_peer;
    uint8_t absent_ip[16];
    memset(absent_ip, 0, sizeof(absent_ip));
    absent_ip[15] = 9;
    ok = ok && !db_peer_find_by_addr(&ndb, absent_ip, 9999, &absent_peer);
    ok = ok && sqlite_53_checkpoint_rc(&ndb) != SQLITE_LOCKED;

    /* And the connection can still write after all of that. */
    p.last_seen = 1700000200;
    ok = ok && db_peer_save(&ndb, &p);

    node_db_close(&ndb);
    test_rm_rf_recursive(dir);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static void check_sqlite_51_sqlite_node_db_opens_with_a_bounded_wal_(int *failures)
{
    printf("SQLite node.db opens with a bounded WAL and reports what "
           "each checkpoint moved... ");
    char dir[256];
    char dbpath[512];
    test_make_tmpdir(dir, sizeof(dir), "sqlite", "wal_bounds");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    app_runtime_set_current(NULL);
    wal_ckpt_stats_reset();
    bool ok = node_db_open(&ndb, dbpath);

    ok = check_sqlite_51_open_bound_by_open(&ndb, ok);
    ok = check_sqlite_51_bulk_mode_loosens_never_removes(&ndb, ok);
    struct wal_ckpt_record drain = {0};
    ok = check_sqlite_51_drained_vs_noop(&ndb, &drain, ok);
    ok = check_sqlite_51_ledger_and_periodic_state(&drain, ok);

    node_db_close(&ndb);
    wal_ckpt_stats_reset();
    test_rm_rf_recursive(dir);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

static bool check_sqlite_52_fill_wal_past_ceiling(struct node_db *ndb,
                                                  const char *walpath,
                                                  int64_t ceiling, bool ok)
{
    /* Simulated catchup writes: push the WAL past a small ceiling. */
    bool past_ceiling = false;
    for (int i = 0; ok && i < 2000; i++) {
        char key[32];
        uint8_t val[4096];
        snprintf(key, sizeof(key), "turbo_midrun_%d", i);
        memset(val, (uint8_t)(i & 0xff), sizeof(val));
        ok = node_db_state_set(ndb, key, val, sizeof(val));
        struct stat fst;
        if (ok && stat(walpath, &fst) == 0 &&
            (int64_t)fst.st_size > ceiling) {
            past_ceiling = true;
            break;
        }
    }
    return ok && past_ceiling;
}

static bool check_sqlite_52_mid_run_checkpoint_behavior(struct node_db *ndb,
                                                        const char *walpath,
                                                        int64_t ceiling,
                                                        bool ok)
{
    /* Over the ceiling the helper must checkpoint mid-run: the
     * ledger advances and the file is back under the ceiling
     * (a missing -wal after TRUNCATE is bounded trivially). */
    struct wal_ckpt_stats before;
    struct wal_ckpt_stats after;
    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    wal_ckpt_stats_snapshot(&before);
    ok = ok && node_db_turbo_maybe_checkpoint(ndb, ceiling);
    wal_ckpt_stats_snapshot(&after);
    ok = ok && after.attempts_total > before.attempts_total;
    struct stat fst;
    ok = ok && (stat(walpath, &fst) != 0 ||
                (int64_t)fst.st_size <= ceiling);

    /* Under the ceiling it must leave turbo alone: no checkpoint. */
    wal_ckpt_stats_snapshot(&before);
    ok = ok && !node_db_turbo_maybe_checkpoint(ndb, ceiling);
    wal_ckpt_stats_snapshot(&after);
    ok = ok && after.attempts_total == before.attempts_total;

    /* No bound configured means no checkpoint, however large. */
    wal_ckpt_stats_snapshot(&before);
    ok = ok && !node_db_turbo_maybe_checkpoint(ndb, 0);
    wal_ckpt_stats_snapshot(&after);
    ok = ok && after.attempts_total == before.attempts_total;
    return ok;
}

static bool check_sqlite_52_error_path_restores_bounds(struct node_db *ndb,
                                                        int64_t ceiling,
                                                        bool ok)
{
    /* Error-path exit: the restore every catchup failure path ends
     * in must return ALL the bounds — synchronous, autocheckpoint,
     * and file-size cap — and clear the turbo flag. */
    ok = ok && node_db_normal_mode(ndb);
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA wal_autocheckpoint")
                   == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES;
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA journal_size_limit")
                   == ZCL_NODE_DB_JOURNAL_SIZE_LIMIT;
    ok = ok && sqlite_test_pragma_i64(ndb->db, "PRAGMA synchronous") == 1;
    ok = ok && !ndb->turbo_mode;

    /* Null handles refuse instead of crashing. */
    ok = ok && !node_db_turbo_maybe_checkpoint(NULL, ceiling);
    return ok;
}

static void check_sqlite_52_sqlite_turbo_run_checkpoints_mid_run_pas(int *failures)
{
    printf("SQLite turbo run checkpoints mid-run past the byte ceiling"
           "... ");
    char dir[256];
    char dbpath[512];
    test_make_tmpdir(dir, sizeof(dir), "sqlite", "turbo_midrun");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    app_runtime_set_current(NULL);
    wal_ckpt_stats_reset();
    bool ok = node_db_open(&ndb, dbpath);

    /* Simulated catchup entry: bulk mode loosens the bound but keeps
     * one (autocheckpoint is never zero in turbo). */
    ok = ok && node_db_ibd_turbo_mode(&ndb);
    ok = ok && ndb.turbo_mode;

    const int64_t ceiling = 256 * 1024;
    char walpath[576];
    snprintf(walpath, sizeof(walpath), "%s-wal", dbpath);
    ok = check_sqlite_52_fill_wal_past_ceiling(&ndb, walpath, ceiling, ok);
    ok = check_sqlite_52_mid_run_checkpoint_behavior(&ndb, walpath, ceiling, ok);
    ok = check_sqlite_52_error_path_restores_bounds(&ndb, ceiling, ok);

    node_db_close(&ndb);
    wal_ckpt_stats_reset();
    test_rm_rf_recursive(dir);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); (*failures)++; }
}

struct sqlite_busy_worker_fixture {
    _Atomic bool entered;
    _Atomic bool release;
    _Atomic bool expired;
};

static bool sqlite_hold_worker(struct node_db *ndb, void *ctx)
{
    (void)ndb;
    struct sqlite_busy_worker_fixture *gate = ctx;
    int64_t deadline = platform_time_monotonic_ms() + 5000;
    atomic_store(&gate->entered, true);
    while (!atomic_load(&gate->release)) {
        if (platform_time_monotonic_ms() >= deadline) {
            atomic_store(&gate->expired, true);
            break;
        }
        platform_sleep_ms(1);
    }
    return true;
}

static bool sqlite_count_worker_call(struct node_db *ndb, void *ctx)
{
    (void)ndb;
    (*(int *)ctx)++;
    return true;
}

struct sqlite_busy_state_fixture {
    char dir[256], path[320];
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context runtime;
    struct sqlite_busy_worker_fixture gate;
    int refused_calls, queued_calls;
};

static bool sqlite_busy_state_open(struct sqlite_busy_state_fixture *f)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dir, sizeof(f->dir), "sqlite", "busy-worker");
    snprintf(f->path, sizeof(f->path), "%s/node.db", f->dir);
    db_service_init(&f->svc);
    bool ok = node_db_open(&f->ndb, f->path);
    ok = ok && db_service_attach(&f->svc, &f->ndb);
    ok = ok && db_service_start_test_worker(&f->svc);
    runtime_set_db_service(&f->runtime, &f->svc);
    ok = ok && db_service_enqueue_write(&f->svc, sqlite_hold_worker, &f->gate, NULL);
    int64_t deadline = platform_time_monotonic_ms() + 5000;
    while (ok && !atomic_load(&f->gate.entered) &&
           platform_time_monotonic_ms() < deadline)
        platform_sleep_ms(1);
    return ok && atomic_load(&f->gate.entered);
}

static bool sqlite_busy_state_admission(struct sqlite_busy_state_fixture *f)
{
    uint8_t value = 0x6b;
    bool ok = !db_service_try_run_write(&f->svc, sqlite_count_worker_call,
                                        &f->refused_calls);
    ok = ok && db_service_enqueue_write(&f->svc, sqlite_count_worker_call,
                                         &f->queued_calls, NULL);
    ok = ok && !app_runtime_node_db_state_try_set(
        &f->ndb, "busy-refused", &value, sizeof(value));
    return ok;
}

static bool sqlite_busy_state_persist(struct sqlite_busy_state_fixture *f)
{
    uint8_t value = 0x6b, got = 0;
    size_t len = 0;
    /* The DB worker stays occupied throughout. The existing detached
     * fallback must persist evidence without waiting for that worker. */
    struct zcl_result result = chain_evidence_state_set_retry(
        &f->ndb, "busy-evidence", &value, sizeof(value), "test.busy-worker");
    return result.ok && !atomic_load(&f->gate.expired) &&
           node_db_state_get(&f->ndb, "busy-evidence", &got, sizeof(got), &len) &&
           len == 1 && got == value;
}

static bool sqlite_busy_state_lock_timeout(struct sqlite_busy_state_fixture *f)
{
    uint8_t value = 0x6b;
    struct node_db locker = {0};
    bool locked = node_db_open(&locker, f->path) &&
                  node_db_begin_immediate(&locker);
    bool ok = locked;
    if (locked) {
        int64_t started = platform_time_monotonic_ms();
        bool persisted = node_db_state_set_detached(
            &f->ndb, "busy-lock-refused", &value, sizeof(value));
        int64_t elapsed = platform_time_monotonic_ms() - started;
        ok = ok && !persisted && elapsed < 2000;
        bool rolled_back = node_db_rollback(&locker);
        ok = ok && rolled_back;
    }
    node_db_close(&locker);
    return ok;
}

static bool sqlite_busy_state_resume(struct sqlite_busy_state_fixture *f)
{
    uint8_t value = 0x6b;
    return f->refused_calls == 0 && f->queued_calls == 1 &&
           app_runtime_node_db_state_try_set(
               &f->ndb, "idle-evidence", &value, sizeof(value)) &&
           db_service_try_run_write(
               &f->svc, test_db_service_nested_write_callback, &f->svc);
}

static void check_state_write_does_not_wait_behind_catchup(int *failures)
{
    struct sqlite_busy_state_fixture f;
    bool ok = sqlite_busy_state_open(&f);
    if (ok) {
        ok &= sqlite_busy_state_admission(&f);
        ok &= sqlite_busy_state_persist(&f);
        ok &= sqlite_busy_state_lock_timeout(&f);
    }
    atomic_store(&f.gate.release, true);
    bool drained = db_service_flush_write(&f.svc);
    ok &= drained;
    if (drained)
        ok &= sqlite_busy_state_resume(&f);
    app_runtime_set_current(NULL);
    db_service_stop(&f.svc);
    node_db_close(&f.ndb);
    test_rm_rf_recursive(f.dir);
    printf("SQLite evidence write bypasses occupied worker: %s\n",
           ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

int test_sqlite(void) {
    int failures = 0;

#if defined(_WIN32)
    /* Cross-process lease tests re-exec this binary with a role instead of
     * fork() (Windows has no fork). The child body returns 0 when the
     * refusal under test happened and 1 when it did not — the process exit
     * code is the assertion the parent waits on. */
    const char *fork_role = getenv("ZCL_TEST_FORK_ROLE");
    if (fork_role && fork_role[0]) {
        const char *child_db = getenv("ZCL_SQLITE_CHILD_DB");
        if (!child_db || !child_db[0]) {
            fprintf(stderr, "test_sqlite role '%s': ZCL_SQLITE_CHILD_DB "
                    "unset\n", fork_role);
            return 1;
        }
        if (strcmp(fork_role, "borrower") == 0) {
            struct node_db borrowed = {0};
            bool opened = node_db_open_existing_runtime(
                &borrowed, child_db, "test.cross_process_borrower");
            if (opened) node_db_close(&borrowed);
            return opened ? 1 : 0;
        }
        if (strcmp(fork_role, "intruder") == 0) {
            struct node_db intruder = {0};
            bool opened = node_db_open(&intruder, child_db);
            if (opened) node_db_close(&intruder);
            return opened ? 1 : 0;
        }
        fprintf(stderr, "test_sqlite: unknown fork role '%s'\n", fork_role);
        return 1;
    }
#endif

    /* DB open/close and schema creation */
    check_sqlite_1_sqlite_db_open_close(&failures);

    /* DB state key-value store */
    check_sqlite_2_sqlite_state_set_get(&failures);

    /* DB runtime status reporting */
    check_sqlite_3_sqlite_runtime_status_tracks_tx_turbo_ch(&failures);

    /* DB service wrapper */
    check_sqlite_4_sqlite_db_service_attaches_and_gates_nod(&failures);

    /* DB service write wrappers */
    check_sqlite_5_sqlite_db_service_write_wrappers_forward(&failures);

    /* DB service runtime mode helpers */
    check_sqlite_6_sqlite_db_service_runtime_mode_helpers_u(&failures);

    /* Runtime state writes use DB service + flush open batches */
    check_sqlite_7_sqlite_runtime_state_set_flushes_batch_t(&failures);

    /* DB service callback writes */
    check_sqlite_8_sqlite_db_service_callback_runs_whole_wr(&failures);

    /* DB service nested worker writes */
    check_sqlite_9_sqlite_db_service_nested_worker_writes_s(&failures);

    /* DB service asynchronous writes */
    check_sqlite_10_sqlite_db_service_async_write_drains_bef(&failures);

    /* A refused async enqueue still disposes of the caller's context.
     *
     * This pins an ownership contract that a live node already violated: the
     * queue is bounded and an async submit fails immediately when it is full,
     * which is routine during sync. A caller that read the false return as
     * "you still own ctx" freed it a second time and aborted the process. */
    check_sqlite_11_sqlite_db_service_frees_the_context_of_a(&failures);

    check_sqlite_12_sqlite_sync_controller_opens_private_fil(&failures);

    check_sqlite_13_node_db_open_runtime_named_skips_boot_on(&failures);

    check_sqlite_14_node_db_open_existing_runtime_exact_sche(&failures);

    check_sqlite_15_sqlite_live_owner_blocks_cross_process_r(&failures);

    check_sqlite_16_sqlite_runtime_helper_preserves_live_wal(&failures);

    check_sqlite_17_sqlite_raw_reader_cannot_retire_canonica(&failures);

    check_sqlite_18_sqlite_second_process_cannot_boot_open_a(&failures);

    check_sqlite_19_sqlite_snapshot_tx_index_job_starts_and_(&failures);

    check_sqlite_20_sqlite_sync_job_wrappers_fail_closed_and(&failures);

    check_sqlite_21_sqlite_catchup_job_uses_runtime_db_servi(&failures);

    /* sync_controller DB-service wrappers */
    check_sqlite_22_sqlite_sync_controller_wrappers_use_runt(&failures);

    /* Sapling spend sync fails loudly when nullifier projection insert fails */
    check_sqlite_23_sqlite_sapling_spend_reports_nullifier_i(&failures);

    /* DB block CRUD */
    check_sqlite_24_sqlite_block_save_find(&failures);

    /* DB block delete-by-height (blocks-hydrate quarantine of a hashless row) */
    check_sqlite_25_sqlite_block_delete_by_height(&failures);

    /* DB canonical block projection demotes stale same-height rows */
    check_sqlite_26_sqlite_canonical_block_save_demotes_stal(&failures);

    /* DB block projection first missing connected height */
    check_sqlite_27_sqlite_block_first_missing_connected_hei(&failures);

    /* Projection hole audit cadence + isolated connection. */
    check_sqlite_28_sqlite_projection_hole_scan_uses_canonic(&failures);

    /* Block projection waits through transient writer locks. */
    check_sqlite_29_sqlite_block_save_retries_transient_writ(&failures);

    /* DB transaction index CRUD */
    check_sqlite_30_sqlite_tx_index_save_find(&failures);

    /* DB UTXO CRUD and balance */
    check_sqlite_31_sqlite_utxo_save_find_balance(&failures);

    /* DB wallet key CRUD */
    check_sqlite_32_sqlite_wallet_key_write_find(&failures);

    /* DB wallet transaction paging */
    check_sqlite_33_sqlite_wallet_tx_list_find(&failures);

    /* DB wallet UTXO and balance */
    check_sqlite_34_sqlite_wallet_utxo_balance_spend(&failures);

    /* DB Sapling note balance */
    check_sqlite_35_sqlite_sapling_note_save_balance(&failures);

    /* DB mempool persistence */
    check_sqlite_36_sqlite_mempool_save_find_clear(&failures);

    /* DB peer storage */
    check_sqlite_37_sqlite_peer_save_find_recent(&failures);

    /* Peer persistence waits through transient writer locks. */
    check_sqlite_38_sqlite_peer_save_retries_transient_write(&failures);

    /* Advisory peer persistence is used by the P2P handshake path and
     * must fail fast instead of pinning the DB worker behind peer churn. */
    check_sqlite_39_sqlite_advisory_peer_save_fails_fast_und(&failures);

    /* DB transaction batching */
    check_sqlite_40_sqlite_batch_insert_with_begin_commit(&failures);

    /* DB sapling key CRUD */
    check_sqlite_41_sqlite_sapling_key_write_find(&failures);

    /* DB wallet seed singleton */
    check_sqlite_42_sqlite_wallet_seed_write_load(&failures);

    /* ── Wallet UTXO lifecycle: save, balance, mark spent, balance ── */
    check_sqlite_43_sqlite_wallet_utxo_lifecycle(&failures);

    /* ── UTXO value CHECK constraint ── */
    check_sqlite_44_sqlite_utxo_check_constraint_negative_va(&failures);

    /* ── Cross-validation: global UTXO vs wallet UTXO balance ── */
    check_sqlite_45_sqlite_cross_validate_global_vs_wallet_b(&failures);

    /* PRAGMA tuning values are effective at node_db_open time.
     * Locking the chainstate cache_size and mmap_size with a test so
     * that future edits to db_set_pragmas that accidentally revert to
     * SQLite defaults (~2 MB cache, no mmap) get caught at CI time.
     * database.c derives both from hw_profile_sqlite_cache_kib/
     * hw_profile_sqlite_mmap_bytes (measured RAM), clamped to the same
     * 64 MiB / 256 MiB ceilings this test has always locked — compute the
     * expected value via the SAME hw_profile call the production code
     * makes (matching this test HOST's measured RAM) rather than a bare
     * literal, so the test stays a real regression guard (catches a
     * revert to SQLite defaults OR a broken derivation) without pinning a
     * value that silently goes stale on a low-RAM CI box. See the
     * boot_index.c:306 mmap landmine comment for why 256 MiB is a hard
     * ceiling, not just a starting point. */
    check_sqlite_46_sqlite_pragma_tuning_cache_size_and_mmap(&failures);

    check_sqlite_47_sqlite_pragma_tuning_honors_constrained_(&failures);

    /* Chain-evidence state writes have to survive transient node.db writer
     * locks during live health/deploy checks. The normal handle has a zero
     * busy timeout here so it fails immediately with SQLITE_BUSY; the CEC retry
     * path must fall back to a short-lived detached writer, wait out the
     * transient lock, and persist the value anyway. */
    check_sqlite_48_sqlite_node_state_detached_fallback_wait(&failures);
    check_state_write_does_not_wait_behind_catchup(&failures);

    /* 100k-row UTXO open + random-read smoke test. Guards the
     * class of bug the brief worries about: a cache-size tweak that
     * interacts badly with SQLite's page cache or shared-connection
     * statement handling and either SIGSEGVs or silently returns
     * stale rows (the "flusher resets shared-conn statements →
     * reader rewound" shape).  100k rows seeded into a fresh
     * :memory: DB, then 100 random reads validated against an
     * in-memory reference.  Any mismatch fails the test; any SIGSEGV
     * kills the process and fails the suite. */
    check_sqlite_49_sqlite_100k_utxo_random_read_smoke_test(&failures);


    /* ── WAL checkpoint accounting ─────────────────────────────────────
     *
     * A checkpoint reports success whether it drained the whole write-ahead
     * log or moved not one frame of it, and for a long time this codebase
     * kept only that bool: sqlite3_wal_checkpoint_v2 was called with NULL for
     * both frame-count out-parameters, and the maintenance adapter ran the
     * PRAGMA through sqlite3_exec with a NULL callback, discarding the result
     * row that carries the counts AND the busy flag. A node whose WAL had
     * grown to many times the size of its database therefore looked, from
     * every log line and every telemetry leaf, exactly like a node whose WAL
     * was being kept at zero.
     *
     * These checks pin the distinction and the bounds that keep it from
     * mattering, against a throwaway database under ./test-tmp. */
    check_sqlite_50_sqlite_wal_checkpoint_classification_is_(&failures);

    check_sqlite_51_sqlite_node_db_opens_with_a_bounded_wal_(&failures);

    /* ── Turbo mid-run WAL bound ────────────────────────────────────
     *
     * A 50k+ block catchup enters turbo and only leaves it at the end of
     * the run. The bulk autocheckpoint folds frames rarely and the bulk
     * journal_size_limit only caps the file after a checkpoint — without
     * a size trigger inside the run, the WAL grows until the end-of-run
     * checkpoint, which is how single runs reached tens of GB. This block
     * simulates that run: bulk writes past a small ceiling must trigger a
     * checkpoint mid-run, and the error-path restore must return every
     * bound (not just the autocheckpoint). */
    check_sqlite_52_sqlite_turbo_run_checkpoints_mid_run_pas(&failures);

    /* ── Cached readers must not pin the snapshot ──────────────────────
     *
     * node.db caches a handful of prepared SELECTs for the life of the
     * connection. Two of them returned their row to the caller without
     * resetting the statement, which leaves the connection inside an
     * implicit read transaction for as long as nobody calls that reader
     * again. On node1 that turned into a permanent wedge: every checkpoint
     * answered SQLITE_LOCKED, the WAL grew for over an hour without the
     * database file changing once, and every writer in the process — chain
     * evidence, the UTXO mirror, the fleet board, peer persistence — was
     * refused with "database is locked" while reads carried on normally. */
    check_sqlite_53_cached_readers_release_the_snap(&failures);

    return failures;
}
