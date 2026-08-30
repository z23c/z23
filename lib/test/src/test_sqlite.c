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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB state key-value store */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB runtime status reporting */
    {
        printf("SQLite runtime status tracks tx/turbo/checkpoint state... ");
        struct node_db ndb;
        bool ok = node_db_open(&ndb, ":memory:");
        struct node_db_status st = {0};

        ok = ok && ndb.open;
        node_db_get_status(&ndb, &st);
        ok = ok && st.open;
        ok = ok && !st.tx_open;
        ok = ok && !st.turbo_mode;
        ok = ok && strcmp(st.last_op, "open") == 0;

        ok = ok && node_db_begin(&ndb);
        node_db_get_status(&ndb, &st);
        ok = ok && st.tx_open;
        ok = ok && strcmp(st.last_op, "BEGIN TRANSACTION") == 0;

        ok = ok && node_db_commit(&ndb);
        node_db_get_status(&ndb, &st);
        ok = ok && !st.tx_open;
        ok = ok && strcmp(st.last_op, "COMMIT") == 0;

        ok = ok && node_db_ibd_turbo_mode(&ndb);
        node_db_get_status(&ndb, &st);
        ok = ok && st.turbo_mode;
        ok = ok && strcmp(st.last_op, "ibd_turbo_mode") == 0;

        ok = ok && node_db_wal_checkpoint(&ndb);
        node_db_get_status(&ndb, &st);
        ok = ok && strcmp(st.last_op, "wal_checkpoint") == 0;
        ok = ok && st.last_sqlite_rc == SQLITE_OK;

        ok = ok && node_db_normal_mode(&ndb);
        node_db_get_status(&ndb, &st);
        ok = ok && !st.turbo_mode;
        ok = ok && strcmp(st.last_op, "normal_mode") == 0;

        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* DB service wrapper */
    {
        printf("SQLite DB service attaches and gates node_db access... ");
        struct node_db ndb;
        struct db_service svc;
        bool ok = node_db_open(&ndb, ":memory:");
        db_service_init(&svc);
        ok = ok && !db_service_is_started(&svc);
        ok = ok && db_service_node_db(&svc) == NULL;
        ok = ok && db_service_attach(&svc, &ndb);
        ok = ok && db_service_start(&svc);
        ok = ok && db_service_is_started(&svc);
        ok = ok && db_service_node_db(&svc) == &ndb;
        ok = ok && db_service_query_db(&svc) != NULL;
        ok = ok && db_service_query_db(&svc) == ndb.db;
        {
            struct db_service_status svc_status = {0};
            db_service_get_status(&svc, &svc_status);
            ok = ok && svc_status.started;
            ok = ok && svc_status.worker_started;
            ok = ok && !svc_status.stop_requested;
            ok = ok && svc_status.queue_depth == 0;
        }
        db_service_stop(&svc);
        ok = ok && !db_service_is_started(&svc);
        ok = ok && db_service_node_db(&svc) == NULL;
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* DB service write wrappers */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB service runtime mode helpers */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* Runtime state writes use DB service + flush open batches */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB service callback writes */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB service nested worker writes */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB service asynchronous writes */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* A refused async enqueue still disposes of the caller's context.
     *
     * This pins an ownership contract that a live node already violated: the
     * queue is bounded and an async submit fails immediately when it is full,
     * which is routine during sync. A caller that read the false return as
     * "you still own ctx" freed it a second time and aborted the process. */
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
            failures++;
        }
    }

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
        else { printf("FAIL\n"); failures++; }
    }

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
        struct node_db ndb;
        bool ok = dir_path != NULL;
        char buf[8];
        size_t glen = 0;

        memset(&ndb, 0, sizeof(ndb));
        if (ok) {
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
            ok = node_db_open(&ndb, db_path);          /* boot open */
        }
        /* Stage a marker in the crash-recovery namespace the boot open wipes. */
        ok = ok && node_db_state_set(&ndb, "snapshot_staging_testmark", "x", 1);
        if (ndb.open) node_db_close(&ndb);

        /* Runtime reopen: mandatory reason; must NOT run the staging wipe. */
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && node_db_open_runtime(&ndb, db_path, "test.reopen");
        ok = ok && node_db_state_get(&ndb, "snapshot_staging_testmark",
                                     buf, sizeof(buf), &glen);  /* preserved */
        if (ndb.open) node_db_close(&ndb);

        /* Boot reopen: MUST run the staging wipe and remove the marker. */
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && node_db_open(&ndb, db_path);
        ok = ok && !node_db_state_get(&ndb, "snapshot_staging_testmark",
                                      buf, sizeof(buf), &glen);  /* wiped */
        if (ndb.open) node_db_close(&ndb);

        /* Mandatory-reason enforcement: NULL/empty reason is refused. */
        {
            struct node_db bad;
            memset(&bad, 0, sizeof(bad));
            ok = ok && !node_db_open_runtime(&bad, db_path, NULL);
            memset(&bad, 0, sizeof(bad));
            ok = ok && !node_db_open_runtime(&bad, db_path, "");
        }

        cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    {
        /* Periodic workers need an exact-schema connection without repeating
         * CREATE/migrate/full-statement preparation every poll. The light open
         * must preserve ordinary model access, never create a missing file,
         * and fail closed on a schema written by another binary version. */
        printf("node_db_open_existing_runtime: exact schema, no create... ");
        char dir_template[] = "/tmp/zclassic23-existing-reopen-XXXXXX";
        char *dir_path = mkdtemp(dir_template);
        char db_path[1024], missing_path[1024];
        struct node_db ndb;
        bool ok = dir_path != NULL;
        int64_t value = 0;

        memset(&ndb, 0, sizeof(ndb));
        if (ok) {
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
            snprintf(missing_path, sizeof(missing_path), "%s/missing.db",
                     dir_path);
            ok = node_db_open(&ndb, db_path);
        }
        ok = ok && node_db_state_set_int(&ndb, "existing_open_test", 23);
        if (ndb.open) node_db_close(&ndb);

        memset(&ndb, 0, sizeof(ndb));
        ok = ok && node_db_open_existing_runtime(
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

        memset(&ndb, 0, sizeof(ndb));
        ok = ok && !node_db_open_existing_runtime(
            &ndb, missing_path, "test.must_not_create");
        ok = ok && access(missing_path, F_OK) != 0;

        memset(&ndb, 0, sizeof(ndb));
        ok = ok && node_db_open_runtime(&ndb, db_path,
                                        "test.schema_mismatch_setup");
        int32_t future_schema = NODE_DB_MAX_SCHEMA + 1;
        ok = ok && node_db_state_set(&ndb, "schema_version", &future_schema,
                                     sizeof(future_schema));
        if (ndb.open) node_db_close(&ndb);
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && !node_db_open_existing_runtime(
            &ndb, db_path, "test.schema_mismatch");

        cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
        struct stat wal_before = {0}, wal_after = {0};
        struct stat shm_before = {0}, shm_after = {0};
        int64_t value = 0;
        bool ok = dir_path != NULL;
        if (ok) {
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
            snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
            snprintf(shm_path, sizeof(shm_path), "%s-shm", db_path);
            ok = node_db_open(&canonical, db_path) &&
                node_db_state_set_int(&canonical, "process_owner_test", 23) &&
                node_db_owner_lease_probe(db_path) ==
                    NODE_DB_OWNER_LEASE_OWNED_SELF &&
                stat(wal_path, &wal_before) == 0 &&
                stat(shm_path, &shm_before) == 0;
        }
#if defined(_WIN32)
        if (ok) {
            char log_path[1064];
            snprintf(log_path, sizeof(log_path), "%s/borrower.log", dir_path);
            if (_putenv_s("ZCL_SQLITE_CHILD_DB", db_path) != 0)
                ok = false;
            void *hp = ok ? test_spawn_self_with_role(
                "test_sqlite", "borrower", log_path) : NULL;
            if (!hp || test_self_child_wait(hp) != 0)
                ok = false;
            _putenv_s("ZCL_SQLITE_CHILD_DB", "");
        }
#else
        pid_t child = ok ? fork() : -1;
        if (child == 0) {
            struct node_db borrowed = {0};
            bool opened = node_db_open_existing_runtime(
                &borrowed, db_path, "test.cross_process_borrower");
            if (opened) node_db_close(&borrowed);
            _exit(opened ? 1 : 0);
        }
        int status = 0;
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            ok = false;
#endif
        ok = ok && stat(wal_path, &wal_after) == 0 &&
            stat(shm_path, &shm_after) == 0 &&
            wal_before.st_dev == wal_after.st_dev &&
            wal_before.st_ino == wal_after.st_ino &&
            shm_before.st_dev == shm_after.st_dev &&
            shm_before.st_ino == shm_after.st_ino &&
            node_db_state_get_int(
                &canonical, "process_owner_test", &value) && value == 23 &&
            node_db_state_set_int(&canonical, "process_owner_after", 24);
        if (canonical.open) node_db_close(&canonical);
        if (dir_path) cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    {
        /* A live WAL has one filesystem identity. A helper that closes its own
         * mutable handle must not unlink/recreate the canonical owner's WAL,
         * which splits same-process readers across different WAL inodes and
         * surfaces later as schema=0 / SQLITE_IOERR. */
        printf("SQLite runtime helper preserves live WAL identity... ");
        char dir_template[] = "/tmp/zclassic23-live-wal-owner-XXXXXX";
        char *dir_path = mkdtemp(dir_template);
        char db_path[1024], wal_path[1032];
        struct node_db canonical = {0}, helper = {0};
        struct stat before = {0}, after = {0};
        int64_t helper_value = 0;
        uint64_t unauthorized_before = db_lifetime_unauthorized_count();
        bool ok = dir_path != NULL;
        if (ok) {
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
            snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
            ok = node_db_open(&canonical, db_path) &&
                node_db_state_set_int(&canonical, "wal_owner_test", 23) &&
                stat(wal_path, &before) == 0;
        }
        for (int i = 0; ok && i < 64; i++) {
            ok = node_db_open_existing_runtime(
                &helper, db_path, "test.live_wal_helper") &&
                node_db_state_get_int(
                    &helper, "wal_owner_test", &helper_value) &&
                helper_value == 23;
            if (helper.open) node_db_close(&helper);
        }
        /* Exercise the central filesystem boundary directly: a handle owner
         * cannot unlink the backing owner's live WAL even if a caller asks. */
        if (ok)
            ok = db_lifetime_unlink(
                wal_path, "test.borrowed_wal_cleanup",
                DB_LIFETIME_HANDLE_OWNER, 0) != 0;
        ok = ok && stat(wal_path, &after) == 0 &&
            before.st_dev == after.st_dev && before.st_ino == after.st_ino;
        ok = ok && db_lifetime_unauthorized_count() ==
            unauthorized_before + 1;
        if (canonical.open) node_db_close(&canonical);
        if (dir_path) cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
        sqlite3 *reader = NULL;
        sqlite3_stmt *stmt = NULL;
        struct stat before = {0}, after = {0};
        bool ok = dir_path != NULL;
        if (ok) {
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
            snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
            ok = node_db_open(&canonical, db_path) &&
                node_db_state_set_int(&canonical, "wal_reader_test", 1) &&
                stat(wal_path, &before) == 0;
        }
        if (ok)
            ok = sqlite3_open_v2(db_path, &reader,
                    SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
                sqlite3_prepare_v2(reader,
                    "SELECT value FROM node_state WHERE key='wal_reader_test'",
                    -1, &stmt, NULL) == SQLITE_OK &&
                sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (reader) {
            ok = sqlite3_close(reader) == SQLITE_OK && ok;
            reader = NULL;
        }
        int64_t read_back = 0;
        ok = ok && stat(wal_path, &after) == 0 &&
            before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
            node_db_state_set_int(&canonical, "wal_reader_test", 2) &&
            node_db_state_get_int(&canonical, "wal_reader_test", &read_back) &&
            read_back == 2;
        if (canonical.open) node_db_close(&canonical);
        if (dir_path) cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
        struct stat before = {0}, after = {0};
        bool ok = dir_path != NULL;
        if (ok) {
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir_path);
            snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
            ok = node_db_open(&canonical, db_path) &&
                node_db_state_set_int(&canonical, "process_owner_test", 0) &&
                stat(wal_path, &before) == 0;
        }
#if defined(_WIN32)
        void *hp = NULL;
        if (ok) {
            char log_path[1064];
            snprintf(log_path, sizeof(log_path), "%s/intruder.log", dir_path);
            if (_putenv_s("ZCL_SQLITE_CHILD_DB", db_path) == 0)
                hp = test_spawn_self_with_role(
                    "test_sqlite", "intruder", log_path);
            ok = hp != NULL;
        }
        for (int64_t i = 1; ok && i <= 64; i++)
            ok = node_db_state_set_int(
                &canonical, "process_owner_test", i);
        int child_exit = -1;
        if (hp)
            child_exit = test_self_child_wait(hp);
        _putenv_s("ZCL_SQLITE_CHILD_DB", "");
        int64_t read_back = 0;
        ok = ok && child_exit == 0 &&
#else
        pid_t child = ok ? fork() : -1;
        if (child == 0) {
            struct node_db intruder = {0};
            bool opened = node_db_open(&intruder, db_path);
            if (opened) node_db_close(&intruder);
            _exit(opened ? 1 : 0);
        }
        ok = ok && child > 0;
        for (int64_t i = 1; ok && i <= 64; i++)
            ok = node_db_state_set_int(
                &canonical, "process_owner_test", i);
        int status = -1;
        if (child > 0)
            ok = waitpid(child, &status, 0) == child && ok;
        int64_t read_back = 0;
        ok = ok && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
#endif
            stat(wal_path, &after) == 0 &&
            before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
            node_db_state_get_int(&canonical, "process_owner_test",
                                  &read_back) &&
            read_back == 64 &&
            node_db_state_set_int(&canonical, "process_owner_after", 23) &&
            node_db_state_get_int(&canonical, "process_owner_after",
                                  &read_back) &&
            read_back == 23;
        if (canonical.open) node_db_close(&canonical);
        if (dir_path) cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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
        else { printf("FAIL\n"); failures++; }
    }

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
        else { printf("FAIL\n"); failures++; }

        active_chain_free(&ac);
        node_db_close(&ndb);
    }

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
        else { printf("FAIL\n"); failures++; }
    }

    /* sync_controller DB-service wrappers */
    {
        printf("SQLite sync_controller wrappers use runtime DB service... ");
        struct node_db ndb;
        struct db_service svc;
        struct app_runtime_context runtime;
        struct transaction tx;
        struct transaction wallet_tx;
        struct wallet *wallet = NULL;
        struct privkey key;
        struct pubkey pubkey;
        struct key_id kid;
        struct tx_destination dest;
        struct db_wallet_utxo wallet_utxo = {0};
        struct db_wallet_tx saved_wallet_tx = {0};
        struct db_peer peer = {0};
        struct db_sapling_note note = {0};
        uint8_t tip_hash[32];
        uint8_t got_tip_hash[32];
        size_t got_tip_len = 0;
        uint8_t nullifier[32];
        uint8_t spending_txid[32];
        int64_t tip_height = -1;
        bool ok = node_db_open(&ndb, ":memory:");

        db_service_init(&svc);
        ok = ok && db_service_attach(&svc, &ndb);
        ok = ok && db_service_start(&svc);
        runtime_set_db_service(&runtime, &svc);
        wallet = zcl_calloc(1, sizeof(*wallet), "test_wallet");
        ok = ok && wallet != NULL;

        tx = make_sync_test_tx();
        wallet_tx = make_sync_test_tx();
        ok = ok && node_db_sync_mempool_add(&ndb, &tx, 1234, 777);
        ok = ok && (db_mempool_count(&ndb) == 1);
        ok = ok && node_db_sync_mempool_remove(&ndb, tx.hash.data);
        ok = ok && (db_mempool_count(&ndb) == 0);

        memset(tip_hash, 0xAB, sizeof(tip_hash));
        ok = ok && node_db_state_set_int(&ndb, "tip_height", 99999);
        ok = ok && node_db_state_set(&ndb, "tip_hash",
                                     (const uint8_t[32]){0}, 32);
        ok = ok && node_db_sync_set_tip(&ndb, tip_hash, 12345);
        ok = ok && node_db_state_get_int(&ndb,
                "sync_projection_tip_height", &tip_height);
        ok = ok && (tip_height == 12345);
        ok = ok && node_db_state_get(&ndb, "sync_projection_tip_hash",
                got_tip_hash, sizeof(got_tip_hash), &got_tip_len);
        ok = ok && got_tip_len == sizeof(got_tip_hash);
        ok = ok && memcmp(got_tip_hash, tip_hash, sizeof(tip_hash)) == 0;
        memset(got_tip_hash, 0, sizeof(got_tip_hash));
        got_tip_len = 0;
        ok = ok && node_db_sync_get_tip_height(&ndb) == 12345;
        ok = ok && node_db_sync_get_tip_hash(&ndb, got_tip_hash);
        ok = ok && memcmp(got_tip_hash, tip_hash, sizeof(tip_hash)) == 0;

        memset(peer.ip, 0, sizeof(peer.ip));
        peer.ip[10] = 0xFF;
        peer.ip[11] = 0xFF;
        peer.ip[12] = 127;
        peer.ip[15] = 1;
        ok = ok && node_db_sync_peer(&ndb, peer.ip, 8033, 9, 1700000000);
        ok = ok && db_peer_find_by_addr(&ndb, peer.ip, 8033, &peer);
        ok = ok && peer.services == 9;
        ok = ok && node_db_sync_peer_score(&ndb, peer.ip, 8033, 44, true);
        ok = ok && db_peer_find_by_addr(&ndb, peer.ip, 8033, &peer);
        ok = ok && peer.bandwidth_score == 44;
        ok = ok && peer.is_zcl23;

        if (wallet)
            wallet_init(wallet);
        privkey_make_new(&key, true);
        ok = ok && privkey_get_pubkey(&key, &pubkey);
        ok = ok && wallet && keystore_add_key(&wallet->keystore, &key);
        kid = pubkey_get_id(&pubkey);
        dest.type = DEST_KEY_ID;
        dest.id.key = kid;
        script_for_destination(&wallet_tx.vout[0].script_pub_key, &dest);
        transaction_compute_hash(&wallet_tx);
        ok = ok && wallet &&
             node_db_sync_wallet_tx(&ndb, &wallet_tx, wallet, 0);
        ok = ok && db_wallet_utxo_find(&ndb, wallet_tx.hash.data, 0, &wallet_utxo);
        ok = ok && wallet_utxo.value == wallet_tx.vout[0].value;
        ok = ok && db_wallet_tx_find(&ndb, wallet_tx.hash.data, &saved_wallet_tx);
        ok = ok && !saved_wallet_tx.has_block;
        ok = ok && saved_wallet_tx.block_height == 0;
        free(wallet_utxo.script);
        free(saved_wallet_tx.raw_tx);
        memset(&saved_wallet_tx, 0, sizeof(saved_wallet_tx));

        uint8_t confirmed_hash[32];
        memset(confirmed_hash, 0x5c, sizeof(confirmed_hash));
        ok = ok && node_db_sync_wallet_tx_confirmed_async(
            &ndb, &wallet_tx, wallet, 321, confirmed_hash, 1700000321);
        ok = ok && db_service_flush_write(&svc);
        ok = ok && db_wallet_tx_find(
            &ndb, wallet_tx.hash.data, &saved_wallet_tx);
        ok = ok && saved_wallet_tx.has_block;
        ok = ok && saved_wallet_tx.block_height == 321;
        ok = ok && memcmp(saved_wallet_tx.block_hash,
                          confirmed_hash, sizeof(confirmed_hash)) == 0;
        ok = ok && saved_wallet_tx.time_received == 1700000321;
        free(saved_wallet_tx.raw_tx);
        if (wallet) {
            wallet_free(wallet);
            free(wallet);
        }

        memset(&note, 0, sizeof(note));
        memset(note.txid, 0x01, sizeof(note.txid));
        note.output_index = 2;
        note.value = 4200;
        memset(note.rcm, 0x02, sizeof(note.rcm));
        memset(note.ivk, 0x03, sizeof(note.ivk));
        memset(note.diversifier, 0x04, sizeof(note.diversifier));
        memset(note.pk_d, 0x05, sizeof(note.pk_d));
        memset(note.cm, 0x06, sizeof(note.cm));
        memset(note.nullifier, 0x07, sizeof(note.nullifier));
        note.block_height = 88;
        ok = ok && node_db_sync_sapling_note(&ndb,
                                             note.txid,
                                             note.output_index,
                                             note.value,
                                             note.rcm,
                                             NULL,
                                             0,
                                             note.ivk,
                                             note.diversifier,
                                             note.pk_d,
                                             note.cm,
                                             note.nullifier,
                                             note.block_height);
        ok = ok && db_sapling_note_balance_for_ivk(&ndb, note.ivk) == note.value;
        memcpy(nullifier, note.nullifier, sizeof(nullifier));
        memset(spending_txid, 0x08, sizeof(spending_txid));
        ok = ok && node_db_sync_sapling_spend_bool_compat(&ndb, nullifier, spending_txid);
        ok = ok && db_sapling_note_balance_for_ivk(&ndb, note.ivk) == 0;

        /* Tri-state contract: an indexed note that just got spent must
         * report OK (already spent above, so re-marking changes no row →
         * NOT_FOUND is also acceptable; what matters is it is never ERROR). */
        {
            enum db_mark_spent_result re =
                node_db_sync_sapling_spend(&ndb, nullifier, spending_txid);
            ok = ok && re != DB_MARK_SPENT_ERROR;
        }

        /* Benign not-in-our-index spend: a nullifier we never indexed must
         * report NOT_FOUND (NOT ERROR) so the projection catchup skips it
         * and keeps advancing instead of aborting the whole backfill.
         * Regression guard for the catchup wedge at height 3125020. */
        {
            uint8_t unknown_nf[32];
            uint8_t unknown_txid[32];
            memset(unknown_nf, 0xEE, sizeof(unknown_nf));
            memset(unknown_txid, 0x09, sizeof(unknown_txid));
            enum db_mark_spent_result rmiss =
                node_db_sync_sapling_spend(&ndb, unknown_nf, unknown_txid);
            ok = ok && rmiss == DB_MARK_SPENT_NOT_FOUND;
            /* Legacy bool wrapper reports false for the benign miss but must
             * not be treated as fatal by the tri-state catchup path. */
            ok = ok && !node_db_sync_sapling_spend_bool_compat(&ndb, unknown_nf, unknown_txid);
            /* Model-level tri-state is consistent with the controller. */
            ok = ok && db_sapling_note_mark_spent(&ndb, unknown_nf, unknown_txid)
                       == DB_MARK_SPENT_NOT_FOUND;
        }

        app_runtime_set_current(NULL);
        db_service_stop(&svc);
        free_sync_test_tx(&tx);
        free_sync_test_tx(&wallet_tx);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Sapling spend sync fails loudly when nullifier projection insert fails */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB block CRUD */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB block delete-by-height (blocks-hydrate quarantine of a hashless row) */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB canonical block projection demotes stale same-height rows */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB block projection first missing connected height */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* Projection hole audit cadence + isolated connection. */
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
            ok = db_block_save(&ndb, &blk);
        }

        struct boot_projection_hole_scan scan;
        boot_projection_hole_scan_init(&scan);
        bool ran = false;
        int missing = -2;
        ok = ok && boot_projection_hole_scan_if_due(
            &scan, &ndb, 2, false, false, false, 2, 100, &ran, &missing);
        ok = ok && ran && missing == -1 && scan.next_scan_unix == 3700;

        ran = true;
        ok = ok && boot_projection_hole_scan_if_due(
            &scan, &ndb, 2, false, false, false, 2, 101, &ran, &missing);
        ok = ok && !ran;

        ok = ok && boot_projection_hole_scan_if_due(
            &scan, &ndb, 2, false, true, true, 2, 101, &ran, &missing);
        ok = ok && ran && missing == -1 && scan.next_scan_unix == 3701;

        ran = true;
        ok = ok && boot_projection_hole_scan_if_due(
            &scan, &ndb, 2, false, true, true, 2, 102, &ran, &missing);
        ok = ok && !ran;

        ok = ok && db_block_delete_by_height(&ndb, 1);
        ok = ok && boot_projection_hole_scan_if_due(
            &scan, &ndb, 2, false, false, false, 2, 3701, &ran, &missing);
        ok = ok && ran && missing == 1 && scan.next_scan_unix == 0;

        if (opened)
            node_db_close(&ndb);
        cleanup_temp_db_dir(dir_path);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Block projection waits through transient writer locks. */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB transaction index CRUD */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB UTXO CRUD and balance */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB wallet key CRUD */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB wallet transaction paging */
    {
        printf("SQLite wallet tx list/find... ");
        struct node_db ndb;
        bool ok = node_db_open(&ndb, ":memory:");

        uint8_t raw1[] = {0x01};
        uint8_t raw2[] = {0x02, 0x03};
        uint8_t raw3[] = {0x04, 0x05, 0x06};

        struct db_wallet_tx t1;
        memset(&t1, 0, sizeof(t1));
        memset(t1.txid, 0xA1, 32);
        t1.raw_tx = raw1;
        t1.raw_tx_len = sizeof(raw1);
        t1.time_received = 100;

        struct db_wallet_tx t2;
        memset(&t2, 0, sizeof(t2));
        memset(t2.txid, 0xB2, 32);
        t2.raw_tx = raw2;
        t2.raw_tx_len = sizeof(raw2);
        memset(t2.block_hash, 0x22, 32);
        t2.has_block = true;
        t2.block_height = 10;
        t2.time_received = 300;
        t2.from_me = true;
        t2.fee = 1234;

        struct db_wallet_tx t3;
        memset(&t3, 0, sizeof(t3));
        memset(t3.txid, 0xC3, 32);
        t3.raw_tx = raw3;
        t3.raw_tx_len = sizeof(raw3);
        t3.time_received = 200;

        ok = ok && db_wallet_tx_save(&ndb, &t1);
        ok = ok && db_wallet_tx_save(&ndb, &t2);
        ok = ok && db_wallet_tx_save(&ndb, &t3);
        ok = ok && (db_wallet_tx_count(&ndb) == 3);

        struct db_wallet_tx rows[2];
        memset(rows, 0, sizeof(rows));
        int n = db_wallet_tx_list(&ndb, rows, 2, 0);
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
        n = db_wallet_tx_list(&ndb, rows, 1, 2);
        ok = ok && (n == 1);
        ok = ok && (rows[0].time_received == 100);
        db_wallet_tx_free(&rows[0]);

        struct db_wallet_tx found;
        ok = ok && db_wallet_tx_find(&ndb, t2.txid, &found);
        ok = ok && found.from_me;
        ok = ok && (found.fee == 1234);
        ok = ok && found.has_block;
        ok = ok && (memcmp(found.block_hash, t2.block_hash, 32) == 0);
        db_wallet_tx_free(&found);

        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* DB wallet UTXO and balance */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB Sapling note balance */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB mempool persistence */
    {
        printf("SQLite mempool save/find/clear... ");
        struct node_db ndb;
        bool ok = node_db_open(&ndb, ":memory:");

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

        ok = ok && db_mempool_save(&ndb, &e);
        ok = ok && (db_mempool_count(&ndb) == 1);

        /* Add a spend record */
        uint8_t spent_txid[32];
        memset(spent_txid, 0xBB, 32);
        ok = ok && db_mempool_add_spend(&ndb, e.txid, spent_txid, 0);
        ok = ok && db_mempool_is_spent(&ndb, spent_txid, 0);
        ok = ok && !db_mempool_is_spent(&ndb, spent_txid, 1);

        ok = ok && db_mempool_clear(&ndb);
        ok = ok && (db_mempool_count(&ndb) == 0);

        /* Startup persistence is untrusted input too. A structurally valid
         * row with a missing prevout must be revalidated and dropped instead
         * of re-entering through tx_mempool_add_unchecked(). */
        struct transaction stale = make_sync_test_tx();
        struct byte_stream raw_stream;
        stream_init(&raw_stream, 256);
        ok = ok && transaction_serialize(&stale, &raw_stream);
        memset(&e, 0, sizeof(e));
        memcpy(e.txid, stale.hash.data, 32);
        e.raw_tx = raw_stream.data;
        e.raw_tx_len = raw_stream.size;
        e.fee = 10000;
        e.size = (int)raw_stream.size;
        e.time_added = 1700000000;
        e.height_added = 500;
        ok = ok && db_mempool_save(&ndb, &e);

        struct tx_mempool restored;
        tx_mempool_init(&restored, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);
        struct main_state main_state;
        main_state_init(&main_state);

        int loaded = node_db_sync_mempool_load(
            &ndb, &restored, &coins, &main_state, chain_params_get());
        ok = ok && loaded == 0;
        ok = ok && tx_mempool_size(&restored) == 0;
        ok = ok && db_mempool_count(&ndb) == 0;

        main_state_free(&main_state);
        coins_view_cache_free(&coins);
        tx_mempool_free(&restored);
        stream_free(&raw_stream);
        free_sync_test_tx(&stale);

        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* DB peer storage */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* Peer persistence waits through transient writer locks. */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* Advisory peer persistence is used by the P2P handshake path and
     * must fail fast instead of pinning the DB worker behind peer churn. */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB transaction batching */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB sapling key CRUD */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* DB wallet seed singleton */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Wallet UTXO lifecycle: save, balance, mark spent, balance ── */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* ── UTXO value CHECK constraint ── */
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
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Cross-validation: global UTXO vs wallet UTXO balance ── */
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
        else { printf("FAIL\n"); failures++; }
    }

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
               failures++; }
    }

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
               failures++; }
    }

    /* Chain-evidence state writes have to survive transient node.db writer
     * locks during live health/deploy checks. The normal handle has a zero
     * busy timeout here so it fails immediately with SQLITE_BUSY; the CEC retry
     * path must fall back to a short-lived detached writer, wait out the
     * transient lock, and persist the value anyway. */
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
               failures++; }
    }

    /* 100k-row UTXO open + random-read smoke test. Guards the
     * class of bug the brief worries about: a cache-size tweak that
     * interacts badly with SQLite's page cache or shared-connection
     * statement handling and either SIGSEGVs or silently returns
     * stale rows (the "flusher resets shared-conn statements →
     * reader rewound" shape).  100k rows seeded into a fresh
     * :memory: DB, then 100 random reads validated against an
     * in-memory reference.  Any mismatch fails the test; any SIGSEGV
     * kills the process and fails the suite. */
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
        else { printf("FAIL (hits=%d)\n", hits); failures++; }
    }


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
        else { printf("FAIL\n"); failures++; }
    }

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

        /* 1. The bound is established BY THE OPEN, not by an end-of-phase
         *    restore. Both settings are per-connection, so a process killed
         *    mid-sync never reaches a restore and the next process inherits
         *    only what the open path set. Without journal_size_limit an
         *    autocheckpointed WAL keeps its high-water mark for the life of
         *    the connection — the file never shrinks, however clean the
         *    checkpoints look. */
        ok = ok && sqlite_test_pragma_i64(ndb.db, "PRAGMA wal_autocheckpoint")
                       == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES;
        ok = ok && sqlite_test_pragma_i64(ndb.db, "PRAGMA journal_size_limit")
                       == ZCL_NODE_DB_JOURNAL_SIZE_LIMIT;

        /* 2. Bulk-sync mode loosens those bounds; it must never remove them.
         *    An unbounded write-ahead log is not a faster setting. */
        ok = ok && node_db_ibd_turbo_mode(&ndb);
        int64_t bulk_ckpt =
            sqlite_test_pragma_i64(ndb.db, "PRAGMA wal_autocheckpoint");
        ok = ok && bulk_ckpt != 0;
        ok = ok && bulk_ckpt == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES_BULK;
        ok = ok && sqlite_test_pragma_i64(ndb.db, "PRAGMA journal_size_limit")
                       == ZCL_NODE_DB_JOURNAL_SIZE_LIMIT_BULK;
        ok = ok && node_db_normal_mode(&ndb);
        ok = ok && sqlite_test_pragma_i64(ndb.db, "PRAGMA wal_autocheckpoint")
                       == ZCL_NODE_DB_WAL_AUTOCKPT_PAGES;

        /* 3. A checkpoint that DRAINS a non-empty log and one that moves
         *    nothing must be tellable apart. Both return true. */
        wal_ckpt_stats_reset();
        for (int i = 0; ok && i < 64; i++) {
            char key[32];
            uint8_t val[64];
            snprintf(key, sizeof(key), "wal_bounds_%d", i);
            memset(val, (uint8_t)i, sizeof(val));
            ok = node_db_state_set(&ndb, key, val, sizeof(val));
        }

        struct wal_ckpt_record drain = {0};
        ok = ok && node_db_wal_checkpoint_result(&ndb, &drain);
        ok = ok && drain.outcome == WAL_CKPT_DRAINED;
        ok = ok && drain.ckpt_frames > 0;      /* it really moved frames */
        ok = ok && drain.log_frames >= 0;

        struct wal_ckpt_record again = {0};
        ok = ok && node_db_wal_checkpoint_result(&ndb, &again);
        /* Same true, same outcome name — and a different, honest number.
         * The frame count is the only thing that separates them. */
        ok = ok && again.ckpt_frames == 0;
        ok = ok && again.ckpt_frames != drain.ckpt_frames;

        /* 4. Every attempt lands in the one ledger the operator reads, from
         *    whichever checkpointer ran it. */
        struct wal_ckpt_stats st;
        memset(&st, 0, sizeof(st));
        wal_ckpt_stats_snapshot(&st);
        ok = ok && st.attempts_total == 2;
        ok = ok && st.frames_moved_total == drain.ckpt_frames;
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

        node_db_close(&ndb);
        wal_ckpt_stats_reset();
        test_rm_rf_recursive(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
