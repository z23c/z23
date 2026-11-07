/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Once-only keyed shielded send. Every case drives the registered
 * core.wallet.shielded.send handler (plan, then commit) over the node RPC
 * test transport. The z_sendmany answer comes from the real
 * wallet_send_once_dispatch and the real node.db record; only the
 * transaction build behind it is replaced by a counter, so no funds, proving
 * parameters or private key are involved. A crash is a forked child that
 * exits without cleanup after its record was committed. Everything runs in
 * isolated temporary datadirs. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_native_handlers.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "controllers/wallet_send_once.h"
#include "controllers/wallet_shielded_controller.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/wallet_send_once.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/txmempool.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"

#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WSO_CHECK(name, expr) do {                                         \
    if (expr) { printf("  wallet_send_once: %s... OK\n", (name)); }         \
    else { printf("  wallet_send_once: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define WSO_KEY "pay-2026-0001"
#define WSO_FROM "zs1WsoSourceAddress"
#define WSO_TO "zs1WsoRecipientAddress"
#define WSO_MEMO "wso-private-memo-text"

enum crash_point { CRASH_NONE, CRASH_BEFORE_RECORD, CRASH_AFTER_RECORD,
                   CRASH_AFTER_BUILT, CRASH_IN_POOL, CRASH_PERSISTED,
                   CRASH_RELAYED };
enum fail_point { FAIL_NONE, FAIL_BEFORE_BUILD, FAIL_AFTER_BUILT,
                  FAIL_AFTER_BUILT_KEPT };

static struct wallet *g_wallet;
static atomic_int g_builds;
static atomic_int g_zsend_calls;
static int g_crash;
static int g_fail;
static bool g_double;
static bool g_old_node;
static atomic_int g_double_admitted;
static int g_delay_ms;
static uint8_t g_txid_fill = 0xA1;
static int64_t g_stale_fee = -1;
static wallet_send_once_fn g_plain;
static bool g_real_rpc;
static bool g_foreign_tx;
/* Open a transaction on the connection right after the synchronous level is
 * raised and before the record write begins its own. */
static bool g_race_tx;
static bool g_race_opened;
static struct node_db *g_ndb;
static atomic_int g_wal_syncs;
static int g_sync_delta;

struct fixture {
    struct node_db ndb;
    char dir[256];
    char path[320];
};

/* ── Stand-in for the build behind z_sendmany ─────────────────────────── */

static void test_txid(struct uint256 *id)
{
    memset(id->data, g_txid_fill, 32);
}

/* Same observable steps as z_sendmany_run: build, hand the finished txid to
 * wallet_commit_from_context's pre-admission hook, then answer the txid. */
static int race_profile(unsigned kind, void *ctx, void *stmt, void *ns)
{
    (void)kind;
    (void)ctx;
    (void)ns;
    if (!g_race_tx)
        return 0;
    char *sql = sqlite3_expanded_sql((sqlite3_stmt *)stmt);
    bool hit = sql && strcmp(sql, "PRAGMA synchronous=FULL") == 0;
    sqlite3_free(sql);
    if (hit) {
        g_race_tx = false;
        g_race_opened = node_db_begin_immediate(g_ndb);
    }
    return 0;
}

static bool test_plain_send(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_builds, 1);
    if (g_crash == CRASH_AFTER_RECORD)
        _exit(77);
    if (g_fail == FAIL_BEFORE_BUILD) {
        json_set_str(result, "Insufficient funds");
        return false;
    }
    if (g_delay_ms > 0) {
        struct timespec ts = { g_delay_ms / 1000,
                               (long)(g_delay_ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    struct uint256 id;
    test_txid(&id);
    if (g_foreign_tx)
        (void)node_db_begin_immediate(g_ndb);
    int syncs_before = atomic_load(&g_wal_syncs);
    struct zcl_result r = wallet_send_once_before_commit(&id);
    g_sync_delta = atomic_load(&g_wal_syncs) - syncs_before;
    if (g_foreign_tx || g_race_opened)
        (void)node_db_rollback(g_ndb);
    if (!r.ok) {
        json_set_str(result, r.message);
        return false;
    }
    if (g_crash == CRASH_AFTER_BUILT)
        _exit(77);
    if (g_double) {
        struct uint256 second;
        memset(second.data, g_txid_fill + 1, 32);
        if (wallet_send_once_before_commit(&second).ok)
            atomic_fetch_add(&g_double_admitted, 1);
    }
    if (g_fail == FAIL_AFTER_BUILT_KEPT) {
        /* Admitted, then a later step failed: the transaction may be relayed. */
        wallet_send_once_after_commit(true);
        json_set_str(result, "Wallet flush failed after admission");
        return false;
    }
    if (g_fail == FAIL_AFTER_BUILT) {
        wallet_send_once_after_commit(false);
        json_set_str(result, "Admission refused; nothing entered the pool");
        return false;
    }
    /* Admission: the wallet now holds the transaction. */
    struct wallet_tx held;
    memset(&held, 0, sizeof(held));
    memcpy(held.tx.hash.data, id.data, 32);
    (void)wallet_add_to_wallet(g_wallet, &held);
    wallet_send_once_after_commit(true);
    char hex[65];
    uint256_get_hex(&id, hex);
    json_set_str(result, hex);
    return true;
}

static char *test_error_body(const char *msg)
{
    char buf[512];
    (void)snprintf(buf, sizeof(buf),
                   "{\"error\":{\"code\":-1,\"message\":\"%s\"}}", msg);
    return strdup(buf);
}

static char *wso_rpc(const char *method, const char *params_json)
{
    if (strcmp(method, "getwalletinfo") == 0) {
        char fee[32];
        format_amount(g_stale_fee >= 0 ? g_stale_fee
                                       : g_wallet->default_fee,
                      fee, sizeof(fee));
        char buf[96];
        (void)snprintf(buf, sizeof(buf), "{\"paytxfee\":\"%s\"}", fee);
        return strdup(buf);
    }
    if (strcmp(method, "z_sendmany") != 0)
        return strdup("null");
    atomic_fetch_add(&g_zsend_calls, 1);
    if (g_crash == CRASH_BEFORE_RECORD)
        _exit(77);
    struct json_value params, result;
    json_init(&params);
    json_init(&result);
    if (!json_read(&params, params_json, strlen(params_json)))
        return test_error_body("bad params");
    bool ok = g_real_rpc
        ? rpc_z_sendmany(&params, false, &result)
        : wallet_send_once_dispatch(&params, false,
                                    g_plain ? g_plain : test_plain_send,
                                    &result);
    if (ok && g_old_node) {
        char hex[65];
        struct uint256 id;
        test_txid(&id);
        uint256_get_hex(&id, hex);
        json_set_str(&result, hex);
    }
    char out[1024];
    char *body = NULL;
    if (ok && json_write(&result, out, sizeof(out)) > 0)
        body = strdup(out);
    else
        body = test_error_body(json_get_str(&result)
                               ? json_get_str(&result) : "failed");
    json_free(&params);
    json_free(&result);
    return body;
}

/* ── Fixture ──────────────────────────────────────────────────────────── */

static bool fx_open(struct fixture *fx, const char *tag, bool fresh)
{
    if (fresh) {
        test_make_tmpdir(fx->dir, sizeof(fx->dir), "wallet_send_once", tag);
        (void)snprintf(fx->path, sizeof(fx->path), "%s/node.db", fx->dir);
    }
    memset(&fx->ndb, 0, sizeof(fx->ndb));
    if (!node_db_open(&fx->ndb, fx->path))
        return false;
    g_ndb = &fx->ndb;
    g_wallet = zcl_calloc(1, sizeof(*g_wallet), "wso_wallet");
    if (!g_wallet)
        return false;
    wallet_init(g_wallet);
    if (!wallet_readiness_initialize(g_wallet, WALLET_READINESS_READY, false, 0)) {
        wallet_free(g_wallet);
        free(g_wallet);
        g_wallet = NULL;
        node_db_close(&fx->ndb);
        g_ndb = NULL;
        return false;
    }
    g_wallet->default_fee = 250;
    wallet_rpc_context_set_base(g_wallet, NULL, fx->dir, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(&fx->ndb);
    node_rpc_client_set_test_hook(wso_rpc);
    return true;
}

static void fx_close(struct fixture *fx, bool remove_dir)
{
    node_rpc_client_set_test_hook(NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    node_db_close(&fx->ndb);
    g_ndb = NULL;
    if (g_wallet) {
        wallet_free(g_wallet);
        free(g_wallet);
        g_wallet = NULL;
    }
    if (remove_dir)
        (void)test_rm_rf_recursive(fx->dir);
}

static void reset_counters(void)
{
    atomic_store(&g_builds, 0);
    atomic_store(&g_zsend_calls, 0);
    g_crash = CRASH_NONE;
    g_fail = FAIL_NONE;
    g_double = false;
    g_old_node = false;
    atomic_store(&g_double_admitted, 0);
    g_delay_ms = 0;
    g_txid_fill = 0xA1;
    g_stale_fee = -1;
    g_plain = NULL;
    g_real_rpc = false;
    g_foreign_tx = false;
    g_race_tx = false;
    g_race_opened = false;
    g_sync_delta = -1;
}

/* ── Command helpers ──────────────────────────────────────────────────── */

static const struct zcl_command_spec *send_spec(void)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, "core.wallet.shielded.send") == 0)
            return &reg->commands[i];
    return NULL;
}

static void build_input(struct json_value *in, const char *amount,
                        const char *memo, const char *key)
{
    json_init(in);
    json_set_object(in);
    (void)json_push_kv_str(in, "wallet_scope", "dev");
    (void)json_push_kv_str(in, "from", WSO_FROM);
    (void)json_push_kv_str(in, "to", WSO_TO);
    (void)json_push_kv_str(in, "amount", amount);
    if (memo)
        (void)json_push_kv_str(in, "memo", memo);
    if (key)
        (void)json_push_kv_str(in, "idempotency_key", key);
}

static void run_leaf(const struct json_value *in,
                     struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = send_spec();
    struct zcl_command_request req = {
        .spec = spec, .input = in, .view = "normal",
    };
    zcl_command_reply_init(reply, spec->output_schema);
    spec->handler(&req, reply);
}

/* Plan, then commit the plan's exact commit_input. */
static void plan_then_commit(const char *amount, const char *memo,
                             const char *key, struct zcl_command_reply *out)
{
    struct json_value in, commit;
    struct zcl_command_reply plan;
    build_input(&in, amount, memo, key);
    run_leaf(&in, &plan);
    json_free(&in);
    const char *text = json_get_str(json_get(&plan.data, "commit_input"));
    json_init(&commit);
    if (!text || !json_read(&commit, text, strlen(text))) {
        zcl_command_reply_init(out, send_spec()->output_schema);
        zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "NO_PLAN", "test",
                               false, false, "plan failed", "");
        zcl_command_reply_free(&plan);
        return;
    }
    run_leaf(&commit, out);
    json_free(&commit);
    zcl_command_reply_free(&plan);
}

static bool replied_code(const struct zcl_command_reply *r, const char *code)
{
    return r->exit_code != ZCL_COMMAND_EXIT_OK &&
           strcmp(r->error.code, code) == 0;
}

static bool replied_committed(const struct zcl_command_reply *r,
                              bool replayed, uint8_t fill)
{
    struct uint256 id;
    char hex[65];
    memset(id.data, fill, 32);
    uint256_get_hex(&id, hex);
    const char *txid = json_get_str(json_get(&r->data, "txid"));
    return r->exit_code == ZCL_COMMAND_EXIT_OK &&
           json_get_bool(json_get(&r->data, "committed")) &&
           json_get_bool(json_get(&r->data, "replayed")) == replayed &&
           txid && strcmp(txid, hex) == 0;
}

/* ── Real admission fixture ───────────────────────────────────────────── */

/* The real mempool gate, wallet and wallet database, with a signed
 * transparent spend that the gate accepts. */
struct real_fix {
    struct tx_mempool pool;
    struct coins_view null_view;
    struct coins_view_cache coins;
    struct main_state ms;
    struct wallet_sqlite wdb;
    struct privkey key;
    struct pubkey pub;
    struct key_id kid;
    struct script spk;
    uint8_t seq;
};

static struct real_fix g_rfix;
static struct real_fix *g_rf;
#define RF_UTXO_VALUE (100 * COIN_VALUE)

static bool rf_open(struct real_fix *rf, struct fixture *fx)
{
    memset(rf, 0, sizeof(*rf));
    tx_mempool_init(&rf->pool, 0);
    coins_view_cache_init(&rf->coins, &rf->null_view);
    main_state_init(&rf->ms);
    privkey_make_new(&rf->key, true);
    privkey_get_pubkey(&rf->key, &rf->pub);
    rf->kid = pubkey_get_id(&rf->pub);
    script_for_p2pkh(&rf->spk, &rf->kid);
    if (!wallet_sqlite_open_r(&rf->wdb, fx->ndb.db).ok)
        return false;
    wallet_rpc_context_set_base(g_wallet, &rf->ms, fx->dir, &rf->wdb,
                                &rf->pool, NULL);
    wallet_rpc_context_set_coins_tip(&rf->coins);
    g_rf = rf;
    return true;
}

static void rf_close(struct real_fix *rf)
{
    wallet_rpc_context_set_base(g_wallet, NULL, NULL, NULL, NULL, NULL);
    wallet_rpc_context_set_coins_tip(NULL);
    wallet_sqlite_close(&rf->wdb);
    coins_view_cache_free(&rf->coins);
    tx_mempool_free(&rf->pool);
    main_state_free(&rf->ms);
    g_rf = NULL;
}

static void rf_sign(struct real_fix *rf, struct transaction *tx)
{
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 sighash;
    uint256_set_null(&sighash);
    signature_hash(&rf->spk, tx, 0, ht, RF_UTXO_VALUE, 0, NULL, &sighash);
    unsigned char sig[80];
    size_t siglen = sizeof(sig);
    privkey_sign(&rf->key, &sighash, sig, &siglen);
    if (siglen > 72)
        siglen = 72;
    sig[siglen++] = SIGHASH_ALL;
    unsigned char ss[1 + 73 + 1 + 65];
    size_t n = 0;
    ss[n++] = (unsigned char)siglen;
    memcpy(&ss[n], sig, siglen);
    n += siglen;
    size_t pklen = rf->pub.size > 65 ? 65 : rf->pub.size;
    ss[n++] = (unsigned char)pklen;
    memcpy(&ss[n], rf->pub.vch, pklen);
    n += pklen;
    script_set(&tx->vin[0].script_sig, ss, n);
    transaction_compute_hash(tx);
}

/* A fresh funded outpoint and a signed spend of it. */
static bool rf_make_tx(struct real_fix *rf, struct wallet_tx *wtx)
{
    struct uint256 prev;
    memset(prev.data, 0xE0, 32);
    prev.data[0] = ++rf->seq;
    struct coins_cache_entry *e = coins_view_cache_modify_new(&rf->coins, &prev);
    if (!e)
        return false;
    coins_alloc(&e->coins, 1);
    e->coins.vout[0].value = RF_UTXO_VALUE;
    script_for_p2pkh(&e->coins.vout[0].script_pub_key, &rf->kid);
    e->coins.height = 1;
    e->coins.version = 1;
    e->coins.is_coinbase = false;
    memset(wtx, 0, sizeof(*wtx));
    transaction_init(&wtx->tx);
    transaction_alloc(&wtx->tx, 1, 1);
    wtx->tx.version = 1;
    wtx->tx.vin[0].prevout.hash = prev;
    wtx->tx.vin[0].prevout.n = 0;
    wtx->tx.vin[0].sequence = 0xFFFFFFFF;
    wtx->tx.vout[0].value = RF_UTXO_VALUE - 1000000;
    uint8_t op1 = 0x51;
    script_set(&wtx->tx.vout[0].script_pub_key, &op1, 1);
    rf_sign(rf, &wtx->tx);
    wtx->time_received = GetTime();
    wtx->from_me = true;
    wtx->used = true;
    return true;
}

/* The send steps of z_sendmany with the real admission: the gate, the wallet
 * record, the wallet database flush. There is no relay stage in a test node,
 * so CRASH_RELAYED dies where the relay call would return. */
static bool real_admit_plain(const struct json_value *params, bool help,
                             struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_builds, 1);
    struct wallet_tx wtx;
    if (!g_rf || !rf_make_tx(g_rf, &wtx)) {
        json_set_str(result, "fixture transaction unavailable");
        return false;
    }
    const struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    struct zcl_result r = wallet_commit_from_context(ctx, &wtx);
    if (r.ok) {
        if (g_crash == CRASH_IN_POOL)
            _exit(77);
        r = wallet_persist_commit_before_relay(ctx, &wtx);
    }
    if (!r.ok) {
        json_set_str(result, r.message);
        transaction_free(&wtx.tx);
        return false;
    }
    if (g_crash == CRASH_PERSISTED || g_crash == CRASH_RELAYED)
        _exit(77);
    char hex[65];
    uint256_get_hex(&wtx.tx.hash, hex);
    json_set_str(result, hex);
    transaction_free(&wtx.tx);
    return true;
}

/* ── Write-ahead-log sync counting VFS ────────────────────────────────── */

/* Wraps the default VFS and counts xSync on the write-ahead-log file, which
 * is the only sync a WAL commit under synchronous=FULL performs and a commit
 * under NORMAL does not. */
struct cvfs_file {
    sqlite3_file base;
    sqlite3_file *real;
    bool wal;
};

static sqlite3_vfs *g_real_vfs;
static sqlite3_vfs g_cvfs;
static sqlite3_io_methods g_cio;

#define CVFS_REAL(f) (((struct cvfs_file *)(f))->real)

static int cv_close(sqlite3_file *f)
{
    return CVFS_REAL(f)->pMethods->xClose(CVFS_REAL(f));
}
static int cv_read(sqlite3_file *f, void *b, int n, sqlite3_int64 o)
{
    return CVFS_REAL(f)->pMethods->xRead(CVFS_REAL(f), b, n, o);
}
static int cv_write(sqlite3_file *f, const void *b, int n, sqlite3_int64 o)
{
    return CVFS_REAL(f)->pMethods->xWrite(CVFS_REAL(f), b, n, o);
}
static int cv_truncate(sqlite3_file *f, sqlite3_int64 s)
{
    return CVFS_REAL(f)->pMethods->xTruncate(CVFS_REAL(f), s);
}
static int cv_sync(sqlite3_file *f, int flags)
{
    if (((struct cvfs_file *)f)->wal)
        atomic_fetch_add(&g_wal_syncs, 1);
    return CVFS_REAL(f)->pMethods->xSync(CVFS_REAL(f), flags);
}
static int cv_size(sqlite3_file *f, sqlite3_int64 *s)
{
    return CVFS_REAL(f)->pMethods->xFileSize(CVFS_REAL(f), s);
}
static int cv_lock(sqlite3_file *f, int l)
{
    return CVFS_REAL(f)->pMethods->xLock(CVFS_REAL(f), l);
}
static int cv_unlock(sqlite3_file *f, int l)
{
    return CVFS_REAL(f)->pMethods->xUnlock(CVFS_REAL(f), l);
}
static int cv_reserved(sqlite3_file *f, int *r)
{
    return CVFS_REAL(f)->pMethods->xCheckReservedLock(CVFS_REAL(f), r);
}
static int cv_control(sqlite3_file *f, int op, void *a)
{
    return CVFS_REAL(f)->pMethods->xFileControl(CVFS_REAL(f), op, a);
}
static int cv_sector(sqlite3_file *f)
{
    return CVFS_REAL(f)->pMethods->xSectorSize(CVFS_REAL(f));
}
static int cv_chars(sqlite3_file *f)
{
    return CVFS_REAL(f)->pMethods->xDeviceCharacteristics(CVFS_REAL(f));
}
static int cv_shm_map(sqlite3_file *f, int pg, int sz, int ext,
                      void volatile **out)
{
    return CVFS_REAL(f)->pMethods->xShmMap(CVFS_REAL(f), pg, sz, ext, out);
}
static int cv_shm_lock(sqlite3_file *f, int off, int n, int flags)
{
    return CVFS_REAL(f)->pMethods->xShmLock(CVFS_REAL(f), off, n, flags);
}
static void cv_shm_barrier(sqlite3_file *f)
{
    CVFS_REAL(f)->pMethods->xShmBarrier(CVFS_REAL(f));
}
static int cv_shm_unmap(sqlite3_file *f, int del)
{
    return CVFS_REAL(f)->pMethods->xShmUnmap(CVFS_REAL(f), del);
}

static int cv_open(sqlite3_vfs *v, const char *name, sqlite3_file *f,
                   int flags, int *out)
{
    (void)v;
    struct cvfs_file *c = (struct cvfs_file *)f;
    memset(c, 0, sizeof(*c));
    c->real = (sqlite3_file *)(c + 1);
    int rc = g_real_vfs->xOpen(g_real_vfs, name, c->real, flags, out);
    if (rc == SQLITE_OK) {
        c->wal = (flags & SQLITE_OPEN_WAL) != 0;
        c->base.pMethods = &g_cio;
    }
    return rc;
}

static bool cvfs_install(void)
{
    g_real_vfs = sqlite3_vfs_find(NULL);
    if (!g_real_vfs)
        return false;
    g_cvfs = *g_real_vfs;
    g_cvfs.zName = "wso_wal_sync_count";
    g_cvfs.szOsFile = (int)(sizeof(struct cvfs_file)) + g_real_vfs->szOsFile;
    g_cvfs.pNext = NULL;
    g_cvfs.xOpen = cv_open;
    g_cio = (sqlite3_io_methods){
        .iVersion = 2, .xClose = cv_close, .xRead = cv_read,
        .xWrite = cv_write, .xTruncate = cv_truncate, .xSync = cv_sync,
        .xFileSize = cv_size, .xLock = cv_lock, .xUnlock = cv_unlock,
        .xCheckReservedLock = cv_reserved, .xFileControl = cv_control,
        .xSectorSize = cv_sector, .xDeviceCharacteristics = cv_chars,
        .xShmMap = cv_shm_map, .xShmLock = cv_shm_lock,
        .xShmBarrier = cv_shm_barrier, .xShmUnmap = cv_shm_unmap,
    };
    return sqlite3_vfs_register(&g_cvfs, 1) == SQLITE_OK;
}

static void cvfs_remove(void)
{
    (void)sqlite3_vfs_register(g_real_vfs, 1);
    (void)sqlite3_vfs_unregister(&g_cvfs);
}

/* ── Cases ────────────────────────────────────────────────────────────── */

static int case_repeat_after_success(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "repeat", true))
        return 1;
    struct zcl_command_reply r1, r2, r3;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r1);
    WSO_CHECK("first commit sends once",
              replied_committed(&r1, false, 0xA1) && atomic_load(&g_builds) == 1);
    g_txid_fill = 0xB2;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r2);
    WSO_CHECK("repeat returns the earlier txid and builds nothing",
              replied_committed(&r2, true, 0xA1) &&
              atomic_load(&g_builds) == 1 && !r2.error.mutated);
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r3);
    WSO_CHECK("second repeat is still the first txid",
              replied_committed(&r3, true, 0xA1) &&
              atomic_load(&g_builds) == 1);
    WSO_CHECK("one durable row exists", db_wallet_send_once_count(&fx.ndb) == 1);
    zcl_command_reply_free(&r1);
    zcl_command_reply_free(&r2);
    zcl_command_reply_free(&r3);
    fx_close(&fx, true);
    return failures;
}

struct thread_arg {
    struct zcl_command_reply reply;
};

static void *concurrent_commit(void *p)
{
    struct thread_arg *a = p;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &a->reply);
    return NULL;
}

static int case_concurrent(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "concurrent", true))
        return 1;
    g_delay_ms = 400;
    struct thread_arg a[2];
    pthread_t t[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&t[i], NULL, concurrent_commit, &a[i]);
    for (int i = 0; i < 2; i++)
        pthread_join(t[i], NULL);
    int committed = 0, busy = 0;
    for (int i = 0; i < 2; i++) {
        committed += replied_committed(&a[i].reply, false, 0xA1) ||
                     replied_committed(&a[i].reply, true, 0xA1);
        busy += replied_code(&a[i].reply, "SEND_IN_PROGRESS");
    }
    WSO_CHECK("two identical concurrent requests build once",
              atomic_load(&g_builds) == 1);
    WSO_CHECK("each request is committed or in_progress, one committed",
              committed >= 1 && committed + busy == 2);
    g_delay_ms = 0;
    struct zcl_command_reply again;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &again);
    WSO_CHECK("a later repeat reads the committed txid",
              replied_committed(&again, true, 0xA1) &&
              atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&again);
    for (int i = 0; i < 2; i++)
        zcl_command_reply_free(&a[i].reply);
    fx_close(&fx, true);
    return failures;
}

/* Run one commit in a child that dies at `point`; true when it died there. */
static bool crash_child(const struct fixture *fx, int point, const char *key)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        struct fixture child;
        memcpy(child.dir, fx->dir, sizeof(child.dir));
        memcpy(child.path, fx->path, sizeof(child.path));
        reset_counters();
        g_crash = point;
        if (!fx_open(&child, "child", false))
            _exit(70);
        if (point >= CRASH_IN_POOL) {
            g_plain = real_admit_plain;
            if (!rf_open(&g_rfix, &child))
                _exit(70);
        }
        struct zcl_command_reply r;
        plan_then_commit("0.1", WSO_MEMO, key, &r);
        _exit(71);
    }
    int status = 0;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
           WEXITSTATUS(status) == 77;
}

static int case_crash(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    test_make_tmpdir(fx.dir, sizeof(fx.dir), "wallet_send_once", "crash");
    (void)snprintf(fx.path, sizeof(fx.path), "%s/node.db", fx.dir);
    struct zcl_command_reply r;

    /* The request reaches the node and the process dies before the node
     * records anything: nothing exists, a repeat sends once. */
    WSO_CHECK("child died with the request at the node, before any record",
              crash_child(&fx, CRASH_BEFORE_RECORD, "key-before-record"));
    reset_counters();
    WSO_CHECK("reopen after crash before the record", fx_open(&fx, "x", false));
    WSO_CHECK("no row was written", db_wallet_send_once_count(&fx.ndb) == 0);
    plan_then_commit("0.1", WSO_MEMO, "key-before-record", &r);
    WSO_CHECK("repeat after a crash before the record sends once",
              replied_committed(&r, false, 0xA1) && atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&r);
    fx_close(&fx, false);

    /* Died after the record, before anything was built. The txid is made
     * durable before admission, so no transaction can exist: a clean retry. */
    WSO_CHECK("child died after the record",
              crash_child(&fx, CRASH_AFTER_RECORD, "key-after-record"));
    reset_counters();
    WSO_CHECK("reopen after crash", fx_open(&fx, "x", false));
    WSO_CHECK("the record survived the crash",
              db_wallet_send_once_count(&fx.ndb) == 2);
    plan_then_commit("0.1", WSO_MEMO, "key-after-record", &r);
    WSO_CHECK("repeat after a crash between record and build sends once",
              replied_committed(&r, false, 0xA1) &&
              atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&r);
    fx_close(&fx, false);

    /* Died after the txid was made durable, before admission finished. The
     * transaction may exist: unknown, never a second send. */
    WSO_CHECK("child died after the txid record",
              crash_child(&fx, CRASH_AFTER_BUILT, "key-after-built"));
    reset_counters();
    WSO_CHECK("reopen after second crash", fx_open(&fx, "x", false));
    plan_then_commit("0.1", WSO_MEMO, "key-after-built", &r);
    WSO_CHECK("built but absent from the wallet is outcome_unknown",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              atomic_load(&g_builds) == 0);
    WSO_CHECK("the unknown answer carries the txid",
              strlen(r.error.evidence) == 64);
    zcl_command_reply_free(&r);

    /* The wallet holding the transaction is not proof it was relayed. */
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    memset(wtx.tx.hash.data, 0xA1, 32);
    WSO_CHECK("wallet records the transaction",
              wallet_add_to_wallet(g_wallet, &wtx));
    plan_then_commit("0.1", WSO_MEMO, "key-after-built", &r);
    WSO_CHECK("built and held by the wallet is still outcome_unknown",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 &&
              atomic_load(&g_builds) == 0);
    zcl_command_reply_free(&r);
    fx_close(&fx, false);

    /* Deaths inside the real admission: the pool took the transaction, the
     * wallet database persisted it, the send finished before the row was
     * marked committed. The built row is durable before the pool, so each
     * repeat is unknown with the txid and sends nothing. */
    static const struct { int point; const char *key; const char *what; } deaths[] = {
        { CRASH_IN_POOL, "key-in-pool", "in the pool before the wallet persisted it" },
        { CRASH_PERSISTED, "key-persisted", "after the wallet persisted it, before relay" },
        { CRASH_RELAYED, "key-relayed", "after relay, before the row was committed" },
    };
    for (size_t i = 0; i < sizeof(deaths) / sizeof(deaths[0]); i++) {
        char what[120];
        (void)snprintf(what, sizeof(what), "child died %s", deaths[i].what);
        WSO_CHECK(what, crash_child(&fx, deaths[i].point, deaths[i].key));
        reset_counters();
        WSO_CHECK("reopen", fx_open(&fx, "x", false));
        plan_then_commit("0.1", WSO_MEMO, deaths[i].key, &r);
        WSO_CHECK("the repeat is outcome_unknown with the txid and sends nothing",
                  replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
                  strlen(r.error.evidence) == 64 &&
                  atomic_load(&g_builds) == 0);
        zcl_command_reply_free(&r);
        fx_close(&fx, false);
    }
    (void)test_rm_rf_recursive(fx.dir);
    return failures;
}

static int case_changed_parameters(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "params", true))
        return 1;
    struct zcl_command_reply r1, r2, r3, r4;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r1);
    plan_then_commit("0.2", WSO_MEMO, WSO_KEY, &r2);
    WSO_CHECK("same key with a changed amount is refused",
              replied_committed(&r1, false, 0xA1) &&
              replied_code(&r2, "IDEMPOTENCY_KEY_REUSED") &&
              atomic_load(&g_builds) == 1);
    plan_then_commit("0.1", "another memo", WSO_KEY, &r3);
    WSO_CHECK("same key with a changed memo is refused",
              replied_code(&r3, "IDEMPOTENCY_KEY_REUSED") &&
              atomic_load(&g_builds) == 1);
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r4);
    WSO_CHECK("the original request still reads its txid",
              replied_committed(&r4, true, 0xA1));
    zcl_command_reply_free(&r1);
    zcl_command_reply_free(&r2);
    zcl_command_reply_free(&r3);
    zcl_command_reply_free(&r4);
    fx_close(&fx, true);
    return failures;
}

static int case_fee_binding(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "fee", true))
        return 1;
    struct json_value in, commit;
    struct zcl_command_reply plan, r;
    build_input(&in, "0.1", WSO_MEMO, WSO_KEY);
    run_leaf(&in, &plan);
    json_free(&in);
    const char *text = json_get_str(json_get(&plan.data, "commit_input"));
    json_init(&commit);
    WSO_CHECK("plan carries the quoted fee",
              text && json_read(&commit, text, strlen(text)) &&
              json_get_int(json_get(&commit, "fee_zat")) == 250);

    g_wallet->default_fee = 900;
    run_leaf(&commit, &r);
    WSO_CHECK("fee changed between plan and commit is refused by the node "
              "before building, and frees the key",
              replied_code(&r, "FEE_CHANGED") &&
              atomic_load(&g_zsend_calls) == 1 && atomic_load(&g_builds) == 0 &&
              db_wallet_send_once_count(&fx.ndb) == 0);
    zcl_command_reply_free(&r);

    g_stale_fee = -1;
    g_wallet->default_fee = 250;
    struct json_value nofee;
    build_input(&nofee, "0.1", WSO_MEMO, WSO_KEY);
    (void)json_push_kv_bool(&nofee, "confirm", true);
    run_leaf(&nofee, &r);
    WSO_CHECK("commit without the planned fee is refused",
              replied_code(&r, "PLAN_REQUIRED") && atomic_load(&g_builds) == 0);
    zcl_command_reply_free(&r);
    json_free(&nofee);

    int calls_before = atomic_load(&g_zsend_calls);
    struct json_value notoken;
    build_input(&notoken, "0.1", WSO_MEMO, WSO_KEY);
    (void)json_push_kv_int(&notoken, "fee_zat", 250);
    (void)json_push_kv_bool(&notoken, "confirm", true);
    run_leaf(&notoken, &r);
    WSO_CHECK("commit with a fee but no plan token spends nothing",
              replied_code(&r, "PLAN_REQUIRED") && atomic_load(&g_builds) == 0 &&
              atomic_load(&g_zsend_calls) == calls_before);
    zcl_command_reply_free(&r);
    json_free(&notoken);

    struct json_value tampered;
    build_input(&tampered, "0.2", WSO_MEMO, WSO_KEY);
    (void)json_push_kv_int(&tampered, "fee_zat", 250);
    (void)json_push_kv_str(&tampered, "plan_token",
                           json_get_str(json_get(&plan.data, "plan_token")));
    (void)json_push_kv_bool(&tampered, "confirm", true);
    run_leaf(&tampered, &r);
    WSO_CHECK("a changed amount under the plan token is refused",
              replied_code(&r, "PLAN_TOKEN_MISMATCH") &&
              atomic_load(&g_builds) == 0);
    zcl_command_reply_free(&r);
    json_free(&tampered);

    struct zcl_command_reply plan_b;
    g_wallet->default_fee = 300;
    build_input(&in, "0.1", WSO_MEMO, WSO_KEY);
    run_leaf(&in, &plan_b);
    json_free(&in);
    WSO_CHECK("the fee is part of the plan token",
              strcmp(json_get_str(json_get(&plan.data, "plan_token")),
                     json_get_str(json_get(&plan_b.data, "plan_token"))) != 0);
    zcl_command_reply_free(&plan_b);
    zcl_command_reply_free(&plan);
    json_free(&commit);
    fx_close(&fx, true);
    return failures;
}

static int case_refusal_keeps_key(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "keepkey", true))
        return 1;
    struct json_value in, commit;
    struct zcl_command_reply plan, r;
    build_input(&in, "0.1", WSO_MEMO, WSO_KEY);
    run_leaf(&in, &plan);
    json_free(&in);
    const char *text = json_get_str(json_get(&plan.data, "commit_input"));
    json_init(&commit);
    bool parsed = text && json_read(&commit, text, strlen(text));
    g_wallet->default_fee = 900;
    run_leaf(&commit, &r);
    bool fee_refused = replied_code(&r, "FEE_CHANGED");
    zcl_command_reply_free(&r);
    struct json_value bad;
    build_input(&bad, "0.2", WSO_MEMO, WSO_KEY);
    (void)json_push_kv_int(&bad, "fee_zat", 900);
    (void)json_push_kv_str(&bad, "plan_token",
                           json_get_str(json_get(&plan.data, "plan_token")));
    (void)json_push_kv_bool(&bad, "confirm", true);
    run_leaf(&bad, &r);
    bool token_refused = replied_code(&r, "PLAN_TOKEN_MISMATCH");
    zcl_command_reply_free(&r);
    json_free(&bad);
    WSO_CHECK("refusals before any record leave no record",
              parsed && fee_refused && token_refused &&
              db_wallet_send_once_count(&fx.ndb) == 0 &&
              atomic_load(&g_builds) == 0);
    g_wallet->default_fee = 250;
    run_leaf(&commit, &r);
    WSO_CHECK("the same key and parameters then send once",
              replied_committed(&r, false, 0xA1) &&
              atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&r);
    zcl_command_reply_free(&plan);
    json_free(&commit);
    fx_close(&fx, true);
    return failures;
}

static int case_key_required(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "key", true))
        return 1;
    struct json_value in;
    struct zcl_command_reply r;
    build_input(&in, "0.1", WSO_MEMO, NULL);
    run_leaf(&in, &r);
    WSO_CHECK("plan without a key is refused with an explanation",
              replied_code(&r, "MISSING_IDEMPOTENCY_KEY") && r.error.message[0]);
    zcl_command_reply_free(&r);
    (void)json_push_kv_int(&in, "fee_zat", 250);
    (void)json_push_kv_bool(&in, "confirm", true);
    run_leaf(&in, &r);
    WSO_CHECK("commit without a key is refused and sends nothing",
              replied_code(&r, "MISSING_IDEMPOTENCY_KEY") &&
              atomic_load(&g_builds) == 0);
    zcl_command_reply_free(&r);
    json_free(&in);
    const char *bad[] = { "has space", "semi;colon", "" };
    int refused = 0;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        build_input(&in, "0.1", WSO_MEMO, bad[i]);
        run_leaf(&in, &r);
        refused += r.exit_code != ZCL_COMMAND_EXIT_OK;
        zcl_command_reply_free(&r);
        json_free(&in);
    }
    char longkey[130];
    memset(longkey, 'k', sizeof(longkey) - 1);
    longkey[sizeof(longkey) - 1] = '\0';
    build_input(&in, "0.1", WSO_MEMO, longkey);
    run_leaf(&in, &r);
    refused += replied_code(&r, "INVALID_IDEMPOTENCY_KEY");
    zcl_command_reply_free(&r);
    json_free(&in);
    WSO_CHECK("malformed keys are refused", refused == 4);
    fx_close(&fx, true);
    return failures;
}

static int case_failed_run_releases_key(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "release", true))
        return 1;
    struct zcl_command_reply r;
    g_fail = FAIL_BEFORE_BUILD;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a send refused before building fails and leaves no record",
              replied_code(&r, "SEND_REFUSED_KEY_RELEASED") &&
              db_wallet_send_once_count(&fx.ndb) == 0);
    zcl_command_reply_free(&r);
    g_fail = FAIL_AFTER_BUILT;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a send rolled back out of the wallet leaves no record",
              replied_code(&r, "SEND_REFUSED_KEY_RELEASED") &&
              db_wallet_send_once_count(&fx.ndb) == 0);
    zcl_command_reply_free(&r);
    g_fail = FAIL_AFTER_BUILT_KEPT;
    plan_then_commit("0.1", "kept memo", "key-kept", &r);
    WSO_CHECK("a failure after admission is outcome_unknown with the txid, "
              "never released and never a plain error",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 &&
              db_wallet_send_once_count(&fx.ndb) == 1);
    zcl_command_reply_free(&r);
    g_fail = FAIL_NONE;
    plan_then_commit("0.1", "kept memo", "key-kept", &r);
    WSO_CHECK("the kept key is outcome_unknown, never a second send",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 && atomic_load(&g_builds) == 3);
    zcl_command_reply_free(&r);
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("the same key can then send once",
              replied_committed(&r, false, 0xA1));
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}


static bool swap_wallet(const struct fixture *fx)
{
    wallet_free(g_wallet);
    free(g_wallet);
    g_wallet = zcl_calloc(1, sizeof(*g_wallet), "wso_wallet");
    if (!g_wallet)
        return false;
    wallet_init(g_wallet);
    if (!wallet_readiness_initialize(g_wallet, WALLET_READINESS_READY, false, 0))
        return false;
    g_wallet->default_fee = 250;
    wallet_rpc_context_set_base(g_wallet, NULL, fx->dir, NULL, NULL, NULL);
    return true;
}

static int case_replay_needs_wallet(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "needwallet", true))
        return 1;
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("the send commits", replied_committed(&r, false, 0xA1));
    zcl_command_reply_free(&r);
    bool replacement_ready = swap_wallet(&fx);
    WSO_CHECK("replacement wallet is ready", replacement_ready);
    if (!replacement_ready) {
        fx_close(&fx, true);
        return failures;
    }
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a committed row whose wallet lost the transaction is unknown",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 && atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}

/* The real wallet_commit_from_context, with a context that cannot admit. */
static bool real_commit_plain(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    (void)help;
    atomic_fetch_add(&g_builds, 1);
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    memset(wtx.tx.hash.data, 0xC3, 32);
    struct zcl_result r = wallet_commit_from_context(wallet_rpc_context_current(),
                                                     &wtx);
    if (!r.ok) {
        json_set_str(result, r.message);
        return false;
    }
    json_set_str(result, "unexpected admission");
    return true;
}

static void keyed_params(struct json_value *params, const char *key)
{
    json_init(params);
    json_set_array(params);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, WSO_FROM);
    (void)json_push_back(params, &v);
    json_free(&v);
    json_init(&v);
    json_set_array(&v);
    (void)json_push_back(params, &v);
    json_free(&v);
    json_init(&v);
    json_set_int(&v, 1);
    (void)json_push_back(params, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, "0.0000025");
    (void)json_push_back(params, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, key);
    (void)json_push_back(params, &v);
    json_free(&v);
}

static int case_real_commit(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "realcommit", true))
        return 1;
    struct json_value params, result;
    keyed_params(&params, "key-real-commit");
    json_init(&result);
    bool ok = wallet_send_once_dispatch(&params, false, real_commit_plain,
                                        &result);
    const char *state = json_get_str(json_get(&result, "state"));
    WSO_CHECK("admission refused by the real commit path releases the key",
              ok && state && strcmp(state, WALLET_SEND_ONCE_STATE_RELEASED) == 0 &&
              db_wallet_send_once_count(&fx.ndb) == 0);
    json_free(&result);
    json_free(&params);
    fx_close(&fx, true);
    return failures;
}

static int case_admitted_stays(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "admitted", true))
        return 1;
    struct zcl_command_reply r;
    g_fail = FAIL_AFTER_BUILT_KEPT;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("failure after admission is outcome_unknown, not released",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 &&
              db_wallet_send_once_count(&fx.ndb) == 1);
    zcl_command_reply_free(&r);
    g_fail = FAIL_NONE;
    g_txid_fill = 0xB2;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a retry after admission never sends, even on other notes",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 && atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&r);
    /* The row also survives a failed release attempt (memory cleared, disk
     * delete failed): a reopen still finds it. */
    fx_close(&fx, false);
    WSO_CHECK("reopen", fx_open(&fx, "x", false));
    atomic_store(&g_builds, 0);
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("after a restart the key is still not free",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              atomic_load(&g_builds) == 0);
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}

static int case_fee_after_commit(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "feeafter", true))
        return 1;
    struct json_value in, commit;
    struct zcl_command_reply plan, r;
    build_input(&in, "0.1", WSO_MEMO, WSO_KEY);
    run_leaf(&in, &plan);
    json_free(&in);
    const char *text = json_get_str(json_get(&plan.data, "commit_input"));
    json_init(&commit);
    bool parsed = text && json_read(&commit, text, strlen(text));
    run_leaf(&commit, &r);
    WSO_CHECK("the plan commits", parsed && replied_committed(&r, false, 0xA1));
    zcl_command_reply_free(&r);
    g_wallet->default_fee = 900;
    run_leaf(&commit, &r);
    WSO_CHECK("a changed default fee after the send still reads the txid",
              replied_committed(&r, true, 0xA1) && atomic_load(&g_builds) == 1);
    zcl_command_reply_free(&r);
    zcl_command_reply_free(&plan);
    json_free(&commit);
    fx_close(&fx, true);
    return failures;
}

static int case_old_node(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "oldnode", true))
        return 1;
    struct zcl_command_reply r;
    g_old_node = true;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a bare txid from a node without send-once is reported as sent",
              r.exit_code == ZCL_COMMAND_EXIT_OK &&
              json_get_bool(json_get(&r.data, "committed")));
    zcl_command_reply_free(&r);
    g_old_node = false;
    fx_close(&fx, true);
    return failures;
}

static int case_durable_batch(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "lane", true))
        return 1;
    struct db_service svc;
    struct app_runtime_context rt = { .db_service = &svc };
    db_service_init(&svc);
    bool up = db_service_attach(&svc, &fx.ndb) &&
              db_service_start_test_worker(&svc);
    WSO_CHECK("db service lane is up", up);
    if (up) {
        app_runtime_set_current(&rt);
        /* A reducer batch is open on the node connection. */
        WSO_CHECK("batch opened", node_db_begin(&fx.ndb));
        fx.ndb.sync_in_batch = true;
        struct zcl_command_reply r;
        plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
        WSO_CHECK("the keyed send commits through the lane",
                  replied_committed(&r, false, 0xA1));
        zcl_command_reply_free(&r);
        /* A second connection sees only what is committed on disk. */
        struct node_db other;
        memset(&other, 0, sizeof(other));
        WSO_CHECK("second connection opens", node_db_open(&other, fx.path));
        WSO_CHECK("the record is committed on disk before the call returns",
                  db_wallet_send_once_count(&other) == 1);
        node_db_close(&other);
        WSO_CHECK("synchronous level is back to what it was",
                  db_wallet_send_once_sync_level(&fx.ndb) == 1);
        app_runtime_set_current(NULL);
        db_service_stop(&svc);
    }
    fx_close(&fx, true);
    return failures;
}

static int case_unreadable_record(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "unreadable", true))
        return 1;
    WSO_CHECK("record table made unavailable",
              node_db_exec(&fx.ndb,
                           "ALTER TABLE wallet_send_once RENAME TO wso_gone"));
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("an unreadable record is a plain error, never the released code",
              r.exit_code != ZCL_COMMAND_EXIT_OK &&
              strcmp(r.error.code, WALLET_SEND_ONCE_CODE_RELEASED) != 0 &&
              atomic_load(&g_builds) == 0);
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}

static bool file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = strlen(needle), got = 0, cap = 1 << 20;
    unsigned char *buf = zcl_malloc(cap, "wso_scan");
    bool found = false;
    while (buf && !found && (got = fread(buf, 1, cap, f)) >= n) {
        for (size_t i = 0; i + n <= got && !found; i++)
            found = memcmp(buf + i, needle, n) == 0;
        if (got < cap)
            break;
    }
    free(buf);
    fclose(f);
    return found;
}

static int case_one_transaction_per_key(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "double", true))
        return 1;
    struct zcl_command_reply r;
    g_double = true;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a keyed send never admits a second transaction",
              atomic_load(&g_double_admitted) == 0 &&
              replied_committed(&r, false, 0xA1));
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}

static int case_record_privacy(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "privacy", true))
        return 1;
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    zcl_command_reply_free(&r);
    char wal[340];
    (void)snprintf(wal, sizeof(wal), "%s-wal", fx.path);
    const char *secrets[] = { WSO_KEY, WSO_FROM, WSO_TO, WSO_MEMO };
    int leaked = 0;
    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++)
        leaked += file_contains(fx.path, secrets[i]) ||
                  file_contains(wal, secrets[i]);
    WSO_CHECK("node.db holds no key, address or memo from the send",
              leaked == 0 && db_wallet_send_once_count(&fx.ndb) == 1);
    fx_close(&fx, true);
    return failures;
}

static void fill_row(struct wallet_send_once_row *row, int n,
                     enum wallet_send_once_state st, int64_t created)
{
    memset(row, 0, sizeof(*row));
    memcpy(row->key_hash, &n, sizeof(n));
    row->key_hash[31] = 1;
    row->digest[0] = 1;
    row->state = st;
    row->has_txid = st != WALLET_SEND_ONCE_STARTED;
    row->txid[0] = 9;
    row->created_at = row->updated_at = created;
}

static int case_retention(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "retain", true))
        return 1;
    const int64_t now = 2000000000;
    const int64_t day = 86400;
    struct wallet_send_once_row row;
    fill_row(&row, 1, WALLET_SEND_ONCE_COMMITTED, now - 89 * day);
    bool a = db_wallet_send_once_insert(&fx.ndb, &row);
    fill_row(&row, 2, WALLET_SEND_ONCE_COMMITTED, now - 91 * day);
    bool b = db_wallet_send_once_insert(&fx.ndb, &row);
    fill_row(&row, 3, WALLET_SEND_ONCE_STARTED, now - 200 * day);
    bool c = db_wallet_send_once_insert(&fx.ndb, &row);
    fill_row(&row, 4, WALLET_SEND_ONCE_BUILT, now - 366 * day);
    bool d = db_wallet_send_once_insert(&fx.ndb, &row);
    WSO_CHECK("rows inserted", a && b && c && d);
    WSO_CHECK("prune runs", db_wallet_send_once_prune(&fx.ndb, now));
    uint8_t kh[4][32];
    for (int i = 0; i < 4; i++) {
        fill_row(&row, i + 1, WALLET_SEND_ONCE_COMMITTED, now);
        memcpy(kh[i], row.key_hash, 32);
    }
    struct wallet_send_once_row out;
    WSO_CHECK("a committed key younger than 90 days is kept",
              db_wallet_send_once_find(&fx.ndb, kh[0], &out));
    WSO_CHECK("a committed key older than 90 days is dropped",
              !db_wallet_send_once_find(&fx.ndb, kh[1], &out));
    WSO_CHECK("an unresolved key outlives the committed window",
              db_wallet_send_once_find(&fx.ndb, kh[2], &out));
    WSO_CHECK("an unresolved key is dropped after 365 days",
              !db_wallet_send_once_find(&fx.ndb, kh[3], &out));
    (void)db_wallet_send_once_release(&fx.ndb, kh[0]);
    WSO_CHECK("release never removes a committed row",
              db_wallet_send_once_find(&fx.ndb, kh[0], &out));
    WSO_CHECK("advance never moves a row backwards",
              !db_wallet_send_once_advance(&fx.ndb, kh[0],
                  WALLET_SEND_ONCE_BUILT, out.txid, now));
    fx_close(&fx, true);
    return failures;
}

/* The pool took the transaction, then the wallet flush failed and the
 * admission was rolled back; a peer may already hold it. */
static int real_flush_failure(struct fixture *fx, struct real_fix *rf)
{
    int failures = 0;
    struct zcl_command_reply r;
    WSO_CHECK("wallet flush made to fail",
              node_db_exec(&fx->ndb,
                  "CREATE TRIGGER wso_flush_fails BEFORE INSERT ON "
                  "wallet_transactions BEGIN SELECT RAISE(ABORT,'wso'); END"));
    plan_then_commit("0.1", "flush memo", "key-flush-fails", &r);
    WSO_CHECK("a flush failure after pool entry is outcome_unknown with the "
              "txid, not a rolled-back error",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 &&
              tx_mempool_size(&rf->pool) == 1 &&
              db_wallet_send_once_count(&fx->ndb) == 2);
    zcl_command_reply_free(&r);
    int builds = atomic_load(&g_builds);
    plan_then_commit("0.1", "flush memo", "key-flush-fails", &r);
    WSO_CHECK("the key is not free: the repeat sends nothing",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              atomic_load(&g_builds) == builds);
    zcl_command_reply_free(&r);
    (void)node_db_exec(&fx->ndb, "DROP TRIGGER wso_flush_fails");
    return failures;
}

/* Real admission, real wallet database. */
static int case_real_admission(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "realadmit", true))
        return 1;
    struct real_fix rf;
    WSO_CHECK("real admission fixture opens", rf_open(&rf, &fx));
    g_plain = real_admit_plain;
    struct zcl_command_reply r;

    plan_then_commit("0.1", WSO_MEMO, "key-real-ok", &r);
    const char *txid = json_get_str(json_get(&r.data, "txid"));
    char first[65] = "";
    if (txid && strlen(txid) == 64)
        memcpy(first, txid, 65);
    WSO_CHECK("a real admission and wallet flush commit the send",
              r.exit_code == ZCL_COMMAND_EXIT_OK && first[0] &&
              tx_mempool_size(&rf.pool) == 1 && g_wallet->num_wallet_tx == 1);
    zcl_command_reply_free(&r);
    plan_then_commit("0.1", WSO_MEMO, "key-real-ok", &r);
    txid = json_get_str(json_get(&r.data, "txid"));
    WSO_CHECK("the repeat replays it and admits nothing",
              r.exit_code == ZCL_COMMAND_EXIT_OK && txid &&
              strcmp(txid, first) == 0 &&
              json_get_bool(json_get(&r.data, "replayed")) &&
              atomic_load(&g_builds) == 1 && tx_mempool_size(&rf.pool) == 1);
    zcl_command_reply_free(&r);

    failures += real_flush_failure(&fx, &rf);

    rf_close(&rf);
    fx_close(&fx, true);
    return failures;
}

/* wallet_commit_transaction code -3: the pool accepted the transaction, then
 * the wallet record failed and the pool entry was removed again. */
static int case_real_wallet_full(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "walletfull", true))
        return 1;
    struct real_fix rf;
    WSO_CHECK("fixture opens", rf_open(&rf, &fx));
    g_plain = real_admit_plain;
    for (size_t i = 0; i < MAX_WALLET_TX; i++)
        g_wallet->map_wallet[i].used = true;
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, "key-wallet-full", &r);
    WSO_CHECK("a wallet record failing after pool entry is outcome_unknown",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strlen(r.error.evidence) == 64 && atomic_load(&g_builds) == 1 &&
              tx_mempool_size(&rf.pool) == 0 &&
              db_wallet_send_once_count(&fx.ndb) == 1);
    zcl_command_reply_free(&r);
    for (size_t i = 0; i < MAX_WALLET_TX; i++)
        g_wallet->map_wallet[i].used = false;
    rf_close(&rf);
    fx_close(&fx, true);
    return failures;
}

/* The built row reaches disk before the call returns. The default level of
 * node.db (NORMAL) never syncs the write-ahead log on commit, so a sync here
 * can only come from the synchronous=FULL write. */
static int case_built_row_is_synced(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    WSO_CHECK("sync counting VFS installed", cvfs_install());
    if (!fx_open(&fx, "walsync", true)) {
        cvfs_remove();
        return failures + 1;
    }
    int level_before = db_wallet_send_once_sync_level(&fx.ndb);
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("the keyed send commits", replied_committed(&r, false, 0xA1));
    WSO_CHECK("the built row write syncs the write-ahead log",
              g_sync_delta >= 1);
    WSO_CHECK("the synchronous level is restored",
              level_before == 1 &&
              db_wallet_send_once_sync_level(&fx.ndb) == level_before);
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    cvfs_remove();
    return failures;
}

/* Outside a keyed send both hooks are no-ops: an unkeyed send admits through
 * the same commit path and must neither record nor refuse anything. */
static int case_hooks_outside_keyed_send(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "nohooks", true))
        return 1;
    struct uint256 id;
    memset(id.data, 0x5C, 32);
    wallet_send_once_after_commit(true);
    wallet_send_once_after_commit(false);
    WSO_CHECK("an unkeyed commit is not refused by the record hook",
              wallet_send_once_before_commit(&id).ok);
    WSO_CHECK("the hooks write no row outside a keyed send",
              db_wallet_send_once_count(&fx.ndb) == 0);
    fx_close(&fx, true);
    return failures;
}

/* Another writer holds a transaction on the connection when the built row is
 * written. The write must not join it: if that transaction rolls back or the
 * machine loses power the row would be gone while the send went on. */
static int case_built_row_has_own_transaction(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "owntx", true))
        return 1;
    g_foreign_tx = true;
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a busy connection refuses the send before admission",
              replied_code(&r, WALLET_SEND_ONCE_CODE_RELEASED) &&
              db_wallet_send_once_count(&fx.ndb) == 0);
    zcl_command_reply_free(&r);
    g_foreign_tx = false;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("the same key then sends once",
              replied_committed(&r, false, 0xA1));
    zcl_command_reply_free(&r);
    fx_close(&fx, true);

    /* A writer opens a transaction after the level is raised and before the
     * record write begins: BEGIN IMMEDIATE must fail rather than join it. */
    reset_counters();
    if (!fx_open(&fx, "racetx", true))
        return failures + 1;
    (void)sqlite3_trace_v2(g_ndb->db, SQLITE_TRACE_PROFILE, race_profile, NULL);
    g_race_tx = true;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a transaction opened mid-write was seen", g_race_opened);
    WSO_CHECK("a transaction opened before the record write refuses the send",
              replied_code(&r, WALLET_SEND_ONCE_CODE_RELEASED) &&
              db_wallet_send_once_count(&fx.ndb) == 0);
    zcl_command_reply_free(&r);
    (void)sqlite3_trace_v2(g_ndb->db, 0, NULL, NULL);
    g_race_tx = false;
    fx_close(&fx, true);
    return failures;
}

/* The real z_sendmany behind the real dispatch, with a wallet that cannot
 * send: it refuses before building, so the key is released. */
static int case_real_zsendmany(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "realz", true))
        return 1;
    g_real_rpc = true;
    struct zcl_command_reply r;
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("a keyed z_sendmany that cannot build is released",
              replied_code(&r, WALLET_SEND_ONCE_CODE_RELEASED) &&
              db_wallet_send_once_count(&fx.ndb) == 0 &&
              atomic_load(&g_zsend_calls) == 1);
    zcl_command_reply_free(&r);
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    WSO_CHECK("the released key reaches z_sendmany again",
              replied_code(&r, WALLET_SEND_ONCE_CODE_RELEASED) &&
              atomic_load(&g_zsend_calls) == 2);
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}

/* The txid of an unknown outcome belongs to the reply, not the log. */
static int case_txid_not_logged(void)
{
    int failures = 0;
    struct fixture fx;
    reset_counters();
    if (!fx_open(&fx, "logtxid", true))
        return 1;
    char logpath[340];
    (void)snprintf(logpath, sizeof(logpath), "%s/captured.log", fx.dir);
    g_fail = FAIL_AFTER_BUILT_KEPT;
    struct zcl_command_reply r;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (saved >= 0 && fd >= 0)
        (void)dup2(fd, STDERR_FILENO);
    if (fd >= 0)
        close(fd);
    plan_then_commit("0.1", WSO_MEMO, WSO_KEY, &r);
    fflush(stderr);
    if (saved >= 0) {
        (void)dup2(saved, STDERR_FILENO);
        close(saved);
    }
    struct uint256 id;
    char hex[65];
    memset(id.data, 0xA1, 32);
    uint256_get_hex(&id, hex);
    WSO_CHECK("the reply carries the txid",
              replied_code(&r, "SEND_OUTCOME_UNKNOWN") &&
              strcmp(r.error.evidence, hex) == 0);
    WSO_CHECK("the refusal was logged", file_contains(logpath,
              "SEND_OUTCOME_UNKNOWN"));
    WSO_CHECK("the log carries no txid, key, address or memo",
              !file_contains(logpath, hex) && !file_contains(logpath, WSO_KEY) &&
              !file_contains(logpath, WSO_FROM) &&
              !file_contains(logpath, WSO_TO) &&
              !file_contains(logpath, WSO_MEMO));
    zcl_command_reply_free(&r);
    fx_close(&fx, true);
    return failures;
}

int wallet_send_once_edge_tests(void);
int test_wallet_send_once(void);
int test_wallet_send_once(void)
{
    printf("\n=== wallet send-once (keyed shielded send) ===\n");
    int failures = 0;
    WSO_CHECK("handler is the registered leaf",
              send_spec() &&
              send_spec()->handler == zcl_native_handle_wallet_shielded_send);
    failures += case_repeat_after_success();
    failures += case_concurrent();
    failures += case_crash();
    failures += case_changed_parameters();
    failures += case_fee_binding();
    failures += case_key_required();
    failures += case_refusal_keeps_key();
    failures += case_failed_run_releases_key();
    failures += case_replay_needs_wallet();
    failures += case_real_commit();
    failures += case_admitted_stays();
    failures += case_fee_after_commit();
    failures += case_old_node();
    failures += case_durable_batch();
    failures += case_unreadable_record();
    failures += case_one_transaction_per_key();
    failures += case_record_privacy();
    failures += case_real_admission();
    failures += case_real_wallet_full();
    failures += case_built_row_is_synced();
    failures += case_built_row_has_own_transaction();
    failures += case_hooks_outside_keyed_send();
    failures += case_real_zsendmany();
    failures += case_txid_not_logged();
    failures += case_retention();
    failures += wallet_send_once_edge_tests();
    if (failures == 0)
        printf("wallet_send_once: OK\n");
    else
        printf("=== wallet_send_once: %d failure(s) ===\n", failures);
    return failures;
}
