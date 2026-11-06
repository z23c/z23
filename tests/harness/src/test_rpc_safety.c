/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chainstate-backed RPCs must fail cleanly when the active
 * chain height points at a missing block-index entry. */

#include "test/test_core.h"
#include "controllers/blockchain_controller.h"
#include "controllers/chain_inspect_controller.h"
#include "controllers/health_controller.h"
#include "controllers/mining_controller.h"
#include "controllers/misc_controller.h"
#include "controllers/network_controller.h"
#include "controllers/repair_controller.h"
#include "controllers/transaction_controller.h"
#include "controllers/wallet_diagnostic_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_rescan_controller.h"
#include "controllers/vault_intent_controller.h"
#include "base/hex.h"
#include "core/core_io.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "models/block.h"
#include "models/database.h"
#include "models/tx_index.h"
#include "models/wallet_tx.h"
#include "net/connman.h"
#include "rpc/server.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/node_db_runtime.h"
#include "storage/progress_store.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ensure_rpc_warmup_finished_once(void)
{
    char status[32];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();
}

static bool rs_unlock_timeout_case(struct rpc_table *tbl, struct wallet *w,
                                   int64_t timeout, bool present, bool valid)
{
    struct json_value params, value, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&value);
    json_init(&result);
    json_set_str(&value, "public-rpc-timeout-fixture");
    bool built = json_push_back(&params, &value);
    if (present) {
        json_set_int(&value, timeout);
        built = json_push_back(&params, &value) && built;
    }
    wallet_lock_lock(w);
    uint32_t entries_before = wallet_lock_unlock_entries_for_test();
    bool accepted = built && rpc_table_execute(tbl, "walletunlock", &params,
                                               &result);
    uint32_t entries = wallet_lock_unlock_entries_for_test() - entries_before;
    bool ok = built && accepted == valid;
    if (valid)
        ok = ok && json_get_int(json_get(&result, "auto_lock_seconds")) ==
                        (present ? timeout : 300) && entries == 1;
    else
        ok = ok && entries == 0 && !wallet_lock_is_unlocked() &&
             wallet_lock_effective_passphrase() == NULL &&
             !wallet_lock_spend_guard().ok;
    wallet_lock_lock(w);
    json_free(&params);
    json_free(&value);
    json_free(&result);
    if (!ok)
        printf("rpc_safety: walletunlock timeout=%lld present=%d accepted=%d FAIL\n",
               (long long)timeout, present, accepted);
    return ok;
}

static bool rs_build_unlock_params(struct json_value *params, int64_t timeout)
{
    struct json_value value;
    json_init(params);
    json_set_array(params);
    json_init(&value);
    json_set_str(&value, "public-rpc-timeout-fixture");
    bool built = json_push_back(params, &value);
    json_set_int(&value, timeout);
    built = json_push_back(params, &value) && built;
    json_free(&value);
    return built;
}

/* A refused out-of-range timeout must end locked, even from an unlocked
 * wallet: the refusal re-locks, as the range refusal in arm_timeout does. */
static bool rs_refused_unlock_relocks_case(struct rpc_table *tbl,
                                           struct wallet *w, int64_t timeout)
{
    struct json_value params, result;
    json_init(&result);
    bool built = rs_build_unlock_params(&params, 300);
    wallet_lock_lock(w);
    bool ok = built && rpc_table_execute(tbl, "walletunlock", &params,
                                         &result) &&
              wallet_lock_is_unlocked();
    json_free(&params);
    json_free(&result);

    json_init(&result);
    built = rs_build_unlock_params(&params, timeout);
    uint32_t entries_before = wallet_lock_unlock_entries_for_test();
    bool accepted = built && rpc_table_execute(tbl, "walletunlock", &params,
                                               &result);
    uint32_t entries = wallet_lock_unlock_entries_for_test() - entries_before;
    ok = ok && built && !accepted && entries == 0 && !wallet_lock_is_unlocked() &&
         wallet_lock_effective_passphrase() == NULL &&
         !wallet_lock_spend_guard().ok;
    wallet_lock_lock(w);
    json_free(&params);
    json_free(&result);
    if (!ok)
        printf("rpc_safety: refused walletunlock timeout=%lld left wallet unlocked FAIL\n",
               (long long)timeout);
    return ok;
}

/* Register-only unlock: no database, datadir, persisted keys or network. */
static int rs_unlock_timeout_width(void)
{
    static const struct {
        int64_t timeout;
        bool present;
        bool valid;
    } cases[] = {
        {0, false, true}, {1, true, true}, {300, true, true},
        {3600, true, true}, {0, true, false}, {-1, true, false},
        {3601, true, false}, {UINT32_MAX, true, false},
        {INT64_C(4294970896), true, false},
        {-INT64_C(4294963696), true, false},
        {INT64_C(8589938192), true, false},
        {INT64_MIN + INT64_C(3600), true, false},
    };
    struct wallet *w = zcl_calloc(1, sizeof(*w), "RPC timeout fixture wallet");
    struct rpc_table *tbl = zcl_calloc(1, sizeof(*tbl), "RPC timeout fixture table");
    if (!w || !tbl) {
        free(w);
        free(tbl);
        printf("rpc_safety: walletunlock fixture allocation FAIL\n");
        return 1;
    }
    wallet_init(w);
    rpc_table_init(tbl);
    register_wallet_rpc_commands(tbl);
    rpc_wallet_set_state(w, NULL, NULL, NULL, NULL, NULL);
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    ensure_rpc_warmup_finished_once();
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        failures += !rs_unlock_timeout_case(tbl, w, cases[i].timeout,
                                            cases[i].present, cases[i].valid);
    failures += !rs_refused_unlock_relocks_case(tbl, w, 0);
    failures += !rs_refused_unlock_relocks_case(tbl, w, 3601);
    wallet_lock_lock(w);
    wallet_lock_reset_for_test();
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_free(w);
    free(w);
    free(tbl);
    printf("rpc_safety: walletunlock full-width timeout: %d failures\n", failures);
    return failures;
}

static void build_unresolved_tip_state(struct main_state *ms, int tip_height)
{
    main_state_init(ms);
    ms->chain_active.height = tip_height;
    ms->chain_active.capacity = tip_height + 1;
    ms->chain_active.chain = calloc((size_t)(tip_height + 1),
                                    sizeof(*ms->chain_active.chain));
}

static void init_single_str_param(struct json_value *params, const char *s)
{
    struct json_value v;
    json_init(params);
    json_set_array(params);
    json_init(&v);
    json_set_str(&v, s);
    json_push_back(params, &v);
    json_free(&v);
}

static void init_single_int_param(struct json_value *params, int64_t n)
{
    struct json_value v;
    json_init(params);
    json_set_array(params);
    json_init(&v);
    json_set_int(&v, n);
    json_push_back(params, &v);
    json_free(&v);
}

/* parse_amount overflow guards. Pre-fix the JSON_INT path multiplied
 * unchecked (200000000000 ZCL wrapped to a positive 1553255926290448384
 * sats, sailing through every downstream <=0 check), the whole-part loop
 * accumulated unchecked, and the whole*1e8+frac multiply could overflow
 * even for an in-loop in-range whole. Overflow now refuses with 0, the
 * value callers already treat as invalid; in-range negatives (sendmany
 * fee subtraction) and the exact INT64_MAX-sat boundary are unchanged. */
static int t_parse_amount_bounds(void)
{
    int failures = 0;
    struct json_value v;

    printf("rpc_safety: parse_amount in-range semantics unchanged... ");
    {
        json_init(&v); json_set_int(&v, 5);
        bool ok = parse_amount(&v) == 500000000;
        json_free(&v);
        json_init(&v); json_set_str(&v, "1.5");
        ok = ok && parse_amount(&v) == 150000000;
        json_free(&v);
        json_init(&v); json_set_str(&v, "-1.25");
        ok = ok && parse_amount(&v) == -125000000;
        json_free(&v);
        json_init(&v); json_set_str(&v, "0.00000001");
        ok = ok && parse_amount(&v) == 1;
        json_free(&v);
        json_init(&v); json_set_str(&v, " 2");
        ok = ok && parse_amount(&v) == 200000000;
        json_free(&v);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: parse_amount exact money-range boundary... ");
    {
        /* w6 pinned the INT64_MAX magnitude boundary; w23's money-range
         * guard (MAX_MONEY) intentionally refuses beyond supply, so the
         * meaningful exact boundary is the money range itself. */
        json_init(&v); json_set_str(&v, "21000000.00000000");
        bool ok = parse_amount(&v) == MAX_MONEY;
        json_free(&v);
        json_init(&v); json_set_str(&v, "21000000.00000001");
        ok = ok && parse_amount(&v) < 0;
        json_free(&v);
        json_init(&v); json_set_str(&v, "-21000000.00000000");
        ok = ok && parse_amount(&v) == -MAX_MONEY;
        json_free(&v);
        json_init(&v); json_set_str(&v, "-21000000.00000001");
        ok = ok && parse_amount(&v) < 0;
        json_free(&v);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: parse_amount overflow refuses with 0... ");
    {
        json_init(&v); json_set_int(&v, 200000000000);
        bool ok = parse_amount(&v) < 0;
        json_free(&v);
        json_init(&v); json_set_int(&v, -200000000000);
        ok = ok && parse_amount(&v) < 0;
        json_free(&v);
        json_init(&v); json_set_str(&v, "99999999999999999999");
        ok = ok && parse_amount(&v) < 0;
        json_free(&v);
        json_init(&v); json_set_str(&v, "92233720369.0");
        ok = ok && parse_amount(&v) < 0;
        json_free(&v);
        json_init(&v); json_set_str(&v, "92233720368.54775808");
        ok = ok && parse_amount(&v) < 0;
        json_free(&v);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* w38 follow-up (independent-review finding on the w23 guard): the
 * JSON_INT path had no money-range bound, so a whole-coin int inside
 * the int64 range — 92233720368 — parsed to 9.2e18 sats, and
 * z_sendmany's total_amount += then signed-overflowed (UB) with two
 * recipients. The int path must refuse beyond supply exactly like
 * the string path. */
static int t_parse_amount_int_money_range(void)
{
    int failures = 0;
    struct json_value v;

    printf("rpc_safety: parse_amount JSON_INT money-range bound... ");
    {
        json_init(&v); json_set_int(&v, 92233720368);
        bool ok = parse_amount(&v) == -1;
        json_free(&v);
        json_init(&v); json_set_int(&v, -92233720368);
        ok = ok && parse_amount(&v) == -1;
        json_free(&v);
        json_init(&v); json_set_int(&v, 21000000);
        ok = ok && parse_amount(&v) == MAX_MONEY;
        json_free(&v);
        json_init(&v); json_set_int(&v, 21000001);
        ok = ok && parse_amount(&v) == -1;
        json_free(&v);
        json_init(&v); json_set_int(&v, -21000000);
        ok = ok && parse_amount(&v) == -MAX_MONEY;
        json_free(&v);
        json_init(&v); json_set_int(&v, -21000001);
        ok = ok && parse_amount(&v) == -1;
        json_free(&v);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static bool result_is_chainstate_guard_error(const struct json_value *result,
                                             const char *method)
{
    const struct json_value *code = json_get(result, "code");
    const struct json_value *msg = json_get(result, "message");
    const struct json_value *got_method = json_get(result, "method");
    return result->type == JSON_OBJ &&
           code && code->type == JSON_INT &&
           code->val.i == RPC_INTERNAL_ERROR &&
           msg && msg->type == JSON_STR &&
           strstr(json_get_str(msg), "active chain tip height") != NULL &&
           got_method && got_method->type == JSON_STR &&
           strcmp(json_get_str(got_method), method) == 0;
}

static bool result_is_retired_reindex_error(const struct json_value *result)
{
    return result->type == JSON_STR &&
           strstr(json_get_str(result), "Runtime reindexchainstate is retired")
               != NULL &&
           strstr(json_get_str(result), "-reindex-chainstate") != NULL;
}

static struct block_index *rpc_safety_insert_block(struct main_state *ms,
                                                   struct uint256 *hash,
                                                   int height,
                                                   struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = 0x52;

    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nBits = 0x1f07ffff;
    bi->nTime = 1000000 + (uint32_t)height * 150;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    bi->nTx = 1;
    bi->nChainTx = (uint32_t)(height + 1);
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(height + 1));
    bi->pprev = prev;
    return bi;
}

/* A real serialized header is the durable authority's storage form: the stub
 * port below serves these bytes and expectations are deserialized from them,
 * never hardcoded hex. */
static uint8_t rpc_safety_hdr_bytes[256];
static size_t rpc_safety_hdr_len;
static bool rpc_safety_hdr_seeded;

static void rpc_safety_seed_known_header(void)
{
    if (rpc_safety_hdr_seeded)
        return;
    struct block_header hdr;
    block_header_init(&hdr);
    for (size_t i = 0; i < 32; i++) {
        hdr.hashMerkleRoot.data[i] = (uint8_t)(0xa1 + i);
        hdr.nNonce.data[i] = (uint8_t)(0x41 + i);
    }
    hdr.nTime = 1500000000;
    hdr.nBits = 0x1c7397b0;
    struct byte_stream w;
    stream_init(&w, sizeof(rpc_safety_hdr_bytes));
    if (block_header_serialize(&hdr, &w) &&
        w.size <= sizeof(rpc_safety_hdr_bytes)) {
        memcpy(rpc_safety_hdr_bytes, w.data, w.size);
        rpc_safety_hdr_len = w.size;
    }
    stream_free(&w);
    rpc_safety_hdr_seeded = true;
}

static bool rpc_safety_stub_load_header(int height, const uint8_t hash[32],
                                        struct block_header *out)
{
    (void)height;
    (void)hash;
    if (!out)
        return false;
    rpc_safety_seed_known_header();
    if (rpc_safety_hdr_len == 0)
        return false;
    struct byte_stream r;
    stream_init_from_data(&r, rpc_safety_hdr_bytes, rpc_safety_hdr_len);
    block_header_init(out);
    return block_header_deserialize(out, &r);
}

static const struct node_db_runtime_port rpc_safety_header_port = {
    .load_header_by_hash_height = rpc_safety_stub_load_header,
};

static bool rpc_safety_build_chain(struct main_state *ms,
                                   struct block_index **out,
                                   int count)
{
    static struct uint256 hashes[16];

    /* Initialize ms BEFORE the count check: callers run main_state_free(&ms)
     * unconditionally, so an early return must not leave it uninitialized
     * (see tools/lint/lintc/gate_outparam_init.c). */
    main_state_init(ms);

    if (count <= 0 || count > (int)(sizeof(hashes) / sizeof(hashes[0])))
        return false;

    struct block_index *prev = NULL;
    for (int h = 0; h < count; h++) {
        out[h] = rpc_safety_insert_block(ms, &hashes[h], h, prev);
        if (!out[h])
            return false;
        prev = out[h];
    }
    ms->pindex_best_header = out[count - 1];
    return active_chain_move_window_tip(&ms->chain_active, out[count - 1]);
}

static bool rpc_safety_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool rpc_safety_set_applied(sqlite3 *db, int32_t height)
{
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, height);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    return ok;
}

static bool rpc_safety_seed_coin_frontier(sqlite3 *db,
                                          const struct block_index *coin_tip)
{
    if (!db || !coin_tip || !coin_tip->phashBlock)
        return false;
    if (!coins_kv_ensure_schema(db))
        return false;

    uint8_t txid[32] = {0};
    txid[0] = 0x52;
    txid[1] = 0x50;
    if (!coins_kv_add(db, txid, 0, 1000LL, coin_tip->nHeight, false,
                      NULL, 0))
        return false;

    uint8_t one = 1;
    if (!progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1))
        return false;
    if (!rpc_safety_set_applied(db, coin_tip->nHeight + 1))
        return false;

    if (!rpc_safety_exec(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER NOT NULL)"))
        return false;
    if (!rpc_safety_exec(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
            "ok INTEGER NOT NULL, tip_hash BLOB)"))
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,fail_reason,validated_at) VALUES(?,?,1,NULL,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, coin_tip->nHeight);
    sqlite3_bind_blob(st, 2, coin_tip->phashBlock->data, 32,
                      SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture
    sqlite3_finalize(st);
    return ok;
}

static bool rpc_safety_save_projected_block(struct node_db *ndb,
                                            const struct block_index *bi)
{
    if (!ndb || !bi || !bi->phashBlock)
        return false;

    uint8_t solution[1] = {0x51};
    struct db_block b;
    memset(&b, 0, sizeof(b));
    memcpy(b.hash, bi->phashBlock->data, sizeof(b.hash));
    if (bi->pprev && bi->pprev->phashBlock)
        memcpy(b.prev_hash, bi->pprev->phashBlock->data, sizeof(b.prev_hash));
    b.height = bi->nHeight;
    b.version = bi->nVersion;
    struct uint256 rp_merkle = block_index_merkle_root(bi);
    memcpy(b.merkle_root, rp_merkle.data, sizeof(b.merkle_root));
    if (memcmp(b.merkle_root, (uint8_t[32]){0}, sizeof(b.merkle_root)) == 0)
        b.merkle_root[0] = 0x4d;
    b.time = bi->nTime;
    b.bits = bi->nBits;
    struct uint256 rp_nonce = block_index_nonce(bi);
    memcpy(b.nonce, rp_nonce.data, sizeof(b.nonce));
    if (memcmp(b.nonce, (uint8_t[32]){0}, sizeof(b.nonce)) == 0)
        b.nonce[0] = 0x4e;
    b.solution = solution;
    b.solution_len = sizeof(solution);
    b.chain_work[0] = (uint8_t)(bi->nHeight + 1);
    b.status = (int)bi->nStatus;
    b.num_tx = (int)bi->nTx;
    return db_block_save(ndb, &b);
}

/* parse_amount arithmetic guards (RED): a large whole-coin JSON int
 * used to wrap (signed overflow, UB) into a small positive zat value,
 * and both wallet send paths (z_sendmany, multisig sendmany) would
 * build/sign/broadcast a tx paying something other than the requested
 * amount — the wrapped value passes every downstream in-range check.
 * Over-long digit strings and above-supply amounts must be refused
 * too. Returns the failure count. */
static int rs_check_parse_amount_guards(void)
{
    int failures = 0;
    bool refused = true;
    bool ok = true;
    struct json_value v;

    json_init(&v); json_set_int(&v, 184467440738LL);
    refused = refused && parse_amount(&v) < 0;
    json_free(&v);

    json_init(&v); json_set_str(&v, "99999999999999999999.99999999");
    refused = refused && parse_amount(&v) < 0;
    json_free(&v);

    json_init(&v); json_set_str(&v, "25000000.0");
    refused = refused && parse_amount(&v) < 0;
    json_free(&v);

    json_init(&v); json_set_str(&v, "1.5");
    ok = ok && parse_amount(&v) == 150000000;
    json_free(&v);

    json_init(&v); json_set_int(&v, 2);
    ok = ok && parse_amount(&v) == 200000000;
    json_free(&v);

    printf("rpc_safety: parse_amount refuses overflow-scale amounts... ");
    if (refused && ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

/* listunspent decodes a heap script per DB row; rows it filters out (here by
 * minconf) must release it too.  Leak witness: glibc live-heap bytes across
 * repeated calls over rows that are all filtered.  The eligible call then
 * proves the output is unchanged. */
#if defined(__GLIBC__) && !defined(__SANITIZE_ADDRESS__)
#include <malloc.h>
enum { LU_ROWS = 64, LU_SCRIPT = 2048, LU_CALLS = 100 };

static bool lu_seed_rows(struct node_db *ndb)
{
    uint8_t *script = zcl_calloc(1, LU_SCRIPT, "rpc-safety-script");
    bool ok = script != NULL;
    for (int i = 0; ok && i < LU_ROWS; i++) {
        struct db_wallet_utxo u;
        memset(&u, 0, sizeof(u));
        memset(u.txid, 0x40 + (i & 0x3f), 32);
        u.txid[0] = (uint8_t)i;
        u.vout = (uint32_t)i;
        u.value = 1000 + i;
        u.script = script;
        u.script_len = LU_SCRIPT;
        u.height = 5;
        ok = db_wallet_utxo_save(ndb, &u);
    }
    free(script);
    return ok;
}

/* Every seeded row appears exactly once with its own txid and amount. */
static bool lu_rows_match_seed(const struct json_value *result)
{
    bool seen[LU_ROWS] = {false};
    for (size_t i = 0; i < json_size(result); i++) {
        const struct json_value *e = json_at(result, i);
        const struct json_value *jv = json_get(e, "vout");
        if (!jv || jv->type != JSON_INT)
            return false;
        int64_t vout = json_get_int(jv);
        if (vout < 0 || vout >= LU_ROWS || seen[vout])
            return false;
        seen[vout] = true;
        struct uint256 want;
        memset(want.data, 0x40 + (int)(vout & 0x3f), 32);
        want.data[0] = (uint8_t)vout;
        char want_hex[65];
        uint256_get_hex(&want, want_hex);
        const char *txid = json_get_str(json_get(e, "txid"));
        if (!txid || strcmp(txid, want_hex) != 0)
            return false;
        double sats = json_get_real(json_get(e, "amount")) * 1e8;
        if ((int64_t)(sats + 0.5) != 1000 + vout)
            return false;
    }
    return true;
}

/* One listunspent call; minconf 0 means "no argument" (all rows eligible). */
static bool lu_call(struct rpc_table *tbl, int minconf, size_t want_rows)
{
    struct json_value params, arg, result;
    json_init(&params); json_set_array(&params);
    json_init(&arg);
    json_init(&result);
    bool ok = true;
    if (minconf > 0) {
        json_set_int(&arg, minconf);
        ok = json_push_back(&params, &arg);
    }
    ok = ok && rpc_table_execute(tbl, "listunspent", &params, &result) &&
         json_size(&result) == want_rows &&
         (want_rows == 0 || lu_rows_match_seed(&result));
    json_free(&params); json_free(&arg); json_free(&result);
    return ok;
}

static bool lu_measure_leak(struct rpc_table *tbl, size_t *leaked)
{
    size_t before = 0;
    bool ok = true;
    for (int c = 0; ok && c < LU_CALLS + 1; c++) {
        ok = lu_call(tbl, 1000, 0);
        if (c == 0) before = mallinfo2().uordblks; /* after warm-up call */
    }
    size_t after = mallinfo2().uordblks;
    *leaked = after > before ? after - before : 0;
    return ok;
}

static int t_listunspent_frees_filtered_rows(void)
{
    printf("rpc_safety: listunspent frees rows it filters out... ");
    ensure_rpc_warmup_finished_once();
    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet), "rpc-safety-wallet");
    if (!wallet) { printf("FAIL (wallet allocation)\n"); return 1; }
    wallet_init(wallet);
    struct main_state ms;
    build_unresolved_tip_state(&ms, 10);
    char datadir[PATH_MAX];
    if (!test_mkdtemp(datadir, sizeof(datadir), "rpc_safety_lu")) {
        printf("FAIL (fixture datadir)\n");
        main_state_free(&ms); wallet_free(wallet); free(wallet);
        return 1;
    }
    struct node_db ndb;
    bool ok = node_db_open(&ndb, ":memory:") && lu_seed_rows(&ndb);
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    wallet_rpc_context_set_base(wallet, &ms, datadir, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(&ndb);
    wallet_rpc_context_set_coins_tip(NULL);
    register_wallet_rpc_commands(&tbl);
    size_t leaked = 0;
    ok = ok && lu_measure_leak(&tbl, &leaked);
    /* A leak is CALLS*ROWS*SCRIPT = 13 MB; allow 256 KB of allocator noise. */
    bool no_leak = leaked < 256 * 1024;
    ok = ok && lu_call(&tbl, 0, LU_ROWS); /* eligible output unchanged */
    if (!no_leak || !ok)
        printf("(ok=%d leaked=%zu bytes) ", (int)ok, leaked);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(NULL);
    node_db_close(&ndb);
    main_state_free(&ms); wallet_free(wallet); free(wallet);
    if (test_rm_rf_recursive(datadir) != 0) {
        printf("(fixture datadir %s not removed) ", datadir);
        ok = false;
    }
    if (ok && no_leak) { printf("OK\n"); return 0; }
    printf("FAIL\n");
    return 1;
}
#else
#endif

static int rs_case_reindex_replay(void)
{
    int failures = 0;

    printf("rpc_safety: reindexchainstate rejects runtime replay... ");
    {
        ensure_rpc_warmup_finished_once();

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_blockchain_rpc_commands(&tbl);

        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_set_array(&params);
        json_init(&result);

        bool ok = !rpc_table_execute(&tbl, "reindexchainstate", &params,
                                     &result) &&
                  result_is_retired_reindex_error(&result);

        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int rs_case_walletbackup_status(void)
{
    int failures = 0;

    printf("rpc_safety: wallet backup status never exposes local paths... ");
    {
        ensure_rpc_warmup_finished_once();
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_wallet_diagnostic_rpc_commands(&tbl);

        struct json_value params, result;
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&tbl, "walletbackupstatus", &params,
                                    &result) &&
                  json_get(&result, "last_path") == NULL &&
                  json_get(&result, "last_encrypted_path") == NULL &&
                  json_get(&result, "last_error") == NULL &&
                  json_get(&result, "backup_available") != NULL &&
                  json_get(&result, "encrypted_backup_available") != NULL &&
                  json_get(&result, "next_action") != NULL;
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int rs_case_getrawmempool_live(void)
{
    int failures = 0;

    printf("rpc_safety: getrawmempool returns live transaction ids... ");
    {
        ensure_rpc_warmup_finished_once();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 1000);

        struct transaction tx;
        transaction_init(&tx);
        bool ok = transaction_alloc(&tx, 1, 1);
        if (ok) {
            memset(tx.vin[0].prevout.hash.data, 0x6d, 32);
            tx.vin[0].prevout.n = 1;
            tx.vin[0].sequence = UINT32_MAX;
            tx.vout[0].value = 1000;
            transaction_compute_hash(&tx);
        }

        struct mempool_entry entry;
        memset(&entry, 0, sizeof(entry));
        if (ok) {
            mempool_entry_init(&entry, &tx, 10000, 1700000000, 1e9,
                               100, true, false, 0);
            ok = tx_mempool_add_unchecked(&pool, &tx.hash, &entry);
        }

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        rpc_blockchain_set_state(NULL, &pool, NULL);
        register_blockchain_rpc_commands(&tbl);

        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_set_array(&params);
        json_init(&result);

        ok = ok && rpc_table_execute(&tbl, "getrawmempool", &params,
                                     &result);
        char expected[65] = {0};
        if (ok)
            uint256_get_hex(&tx.hash, expected);
        ok = ok && result.type == JSON_ARR && result.num_children == 1 &&
             result.children[0].type == JSON_STR &&
             strcmp(json_get_str(&result.children[0]), expected) == 0;

        json_free(&params);
        json_free(&result);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        if (tx.hash.data[0] || tx.num_vin || tx.num_vout)
            mempool_entry_free(&entry);
        transaction_free(&tx);
        tx_mempool_free(&pool);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int rs_case_rawsign_supplemental(void)
{
    int failures = 0;

    printf("rpc_safety: raw-sign supplemental secrets stay request-local... ");
    {
        struct basic_keystore *ks = calloc(1, sizeof(*ks));
        struct rpc_table *tbl = calloc(1, sizeof(*tbl));
        bool ok = ks && tbl;
        if (ok) {
            keystore_init(ks);
            rpc_table_init(tbl);
            rpc_rawtx_set_state(NULL, NULL, NULL, "/tmp");
            rpc_rawtx_set_keystore(ks);
            register_rawtransaction_rpc_commands(tbl);

            struct transaction tx;
            transaction_init(&tx);
            tx.overwintered = true;
            tx.version = SAPLING_TX_VERSION;
            tx.version_group_id = SAPLING_VERSION_GROUP_ID;
            char tx_hex[1024];
            size_t tx_hex_len = encode_hex_tx(&tx, tx_hex, sizeof(tx_hex));
            ok = tx_hex_len > 0 && tx_hex_len < sizeof(tx_hex);
            tx_hex[tx_hex_len] = 0;
            transaction_free(&tx);

            struct privkey extra = {0};
            struct pubkey extra_pub;
            char wif[128];
            size_t secret_len = 0;
            const unsigned char *secret = chain_params_base58_prefix(
                chain_params_get(), B58_SECRET_KEY, &secret_len);
            privkey_make_new(&extra, true);
            ok = ok && privkey_get_pubkey(&extra, &extra_pub) &&
                 encode_secret(&extra, secret, secret_len, wif, sizeof(wif));
            struct key_id extra_id = pubkey_get_id(&extra_pub);

            struct script redeem = {0};
            redeem.data[0] = OP_1;
            redeem.size = 1;
            struct script_id redeem_id;
            script_id_from_script(&redeem_id, &redeem);

            struct json_value params, prevs, prev, keys, value, result;
            json_init(&params); json_set_array(&params);
            json_init(&value); json_set_str(&value, tx_hex);
            json_push_back(&params, &value); json_free(&value);
            json_init(&prevs); json_set_array(&prevs);
            json_init(&prev); json_set_object(&prev);
            json_push_kv_str(&prev, "txid",
                "0000000000000000000000000000000000000000000000000000000000000000");
            json_push_kv_int(&prev, "vout", 0);
            json_push_kv_str(&prev, "scriptPubKey", "51");
            json_push_kv_real(&prev, "amount", 0.0);
            json_push_kv_str(&prev, "redeemScript", "51");
            json_push_back(&prevs, &prev); json_free(&prev);
            json_push_back(&params, &prevs); json_free(&prevs);
            json_init(&keys); json_set_array(&keys);
            json_init(&value); json_set_str(&value, wif);
            json_push_back(&keys, &value); json_free(&value);
            json_push_back(&params, &keys); json_free(&keys);
            json_init(&result);

            ok = ok && rpc_table_execute(tbl, "signrawtransaction", &params,
                                         &result);
            ok = ok && !keystore_have_key(ks, &extra_id) &&
                 !keystore_have_cscript(ks, &redeem_id.hash);

            json_free(&params);
            json_free(&result);
            memory_cleanse(extra.vch, sizeof(extra.vch));
            rpc_rawtx_set_keystore(NULL);
            keystore_free(ks);
        }
        free(ks);
        free(tbl);
        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int rs_case_wallet_freshness(bool *aborted)
{
    int failures = 0;

    printf("rpc_safety: wallet freshness follows authoritative H*... ");
    /* struct wallet embeds a ~40 MB tx table: heap it (as
     * test_accept_to_mempool does) to fit the default main-thread stack. */
    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                       "rpc-safety-wallet");
    if (!wallet) {
        printf("FAIL (wallet allocation)\n");
        failures++;
        *aborted = true;
        return failures;
    }
    wallet_init(wallet);
    wallet->best_block_height = 1;
    wallet->map_wallet[0].used = true;
    wallet->map_wallet[0].confirms = 1;
    wallet->num_wallet_tx = 1;

    struct main_state ms;
    build_unresolved_tip_state(&ms, 3);
    reducer_frontier_provable_tip_set(1);
    struct wallet_rpc_context ctx = {
        .wallet = wallet,
        .main_state = &ms,
    };
    struct wallet_balance_freshness freshness;
    (void)wallet_transparent_spendable_balance_diagnose(
        &ctx, &freshness);
    bool ok = freshness.chain_height == 1 &&
              freshness.wallet_height == 1 &&
              freshness.source &&
              strcmp(freshness.source, "memory") == 0;

    reducer_frontier_provable_tip_reset();
    main_state_free(&ms);
    wallet_free(wallet);
    free(wallet);
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

static int rs_case_fanout_preflight(bool *aborted)
{
    int failures = 0;

    printf("rpc_safety: fanout preflight failure creates no address... ");
    ensure_rpc_warmup_finished_once();
    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                       "rpc-safety-wallet");
    if (!wallet) {
        printf("FAIL (wallet allocation)\n");
        failures++;
        *aborted = true;
        return failures;
    }
    wallet_init(wallet);
    struct main_state ms; main_state_init(&ms);
    struct rpc_table tbl; rpc_table_init(&tbl);
    register_vault_intent_rpc_commands(&tbl);
    wallet_rpc_context_set_base(wallet, &ms, "/tmp", NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_coins_tip(NULL);
    size_t keys_before = wallet->keystore.num_keys;

    struct json_value params, input, result;
    json_init(&params); json_set_array(&params);
    json_init(&input); json_set_object(&input);
    json_init(&result);
    (void)json_push_kv_str(&input, "wallet_scope", "dev");
    (void)json_push_kv_int(&input, "recipient_value_zat", 1000);
    (void)json_push_kv_int(&input, "maximum_fee_zat", 10000);
    (void)json_push_kv_int(&input, "concurrency", 10);
    (void)json_push_kv_str(&input, "idempotency_key", "rpc-safety-1");
    (void)json_push_back(&params, &input);
    bool handled = rpc_table_execute(
        &tbl, "vault_intent_fanout_plan", &params, &result);
    const char *code = json_get_str(json_get(&result, "code"));
    bool ok = handled && !json_get_bool(json_get(&result, "ok")) &&
        code && strcmp(code, "WALLET_UNAVAILABLE") == 0 &&
        wallet->keystore.num_keys == keys_before &&
        json_get(&result, "address") == NULL &&
        json_get(&result, "effects") == NULL;
    if (!ok)
        printf("(handled=%d code=%s keys=%zu->%zu address=%d effects=%d) ",
               (int)handled, code ? code : "NULL", keys_before,
               wallet->keystore.num_keys,
               json_get(&result, "address") != NULL,
               json_get(&result, "effects") != NULL);
    json_free(&params); json_free(&input); json_free(&result);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_coins_tip(NULL);
    main_state_free(&ms); wallet_free(wallet); free(wallet);
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "confirmed tx uses verified node/wallet locator"
 * phases below. */
struct rs_rawtx_fx {
    char dir[256];
    struct transaction shielded;
    struct block body;
    struct uint256 body_hash;
    struct disk_block_pos pos;
    struct main_state ms;
    struct node_db ndb;
    struct rpc_table tbl;
    char txid_hex[65];
    char block_hex[65];
    struct wallet *owned_wallet;
    bool ok;
};

static void rs_rawtx_build_block(struct rs_rawtx_fx *fx)
{
    transaction_init(&fx->shielded);
    fx->shielded.overwintered = true;
    fx->shielded.version = SAPLING_TX_VERSION;
    fx->shielded.version_group_id = SAPLING_VERSION_GROUP_ID;
    fx->shielded.expiry_height = 100;
    fx->shielded.v_shielded_spend = zcl_calloc(
        1, sizeof(*fx->shielded.v_shielded_spend),
        "rpc_safety.shielded_spend");
    fx->ok = fx->shielded.v_shielded_spend != NULL;
    if (fx->ok) {
        fx->shielded.num_shielded_spend = 1;
        memset(fx->shielded.v_shielded_spend[0].nullifier.data, 0x73, 32);
        transaction_compute_hash(&fx->shielded);
    }

    block_init(&fx->body);
    fx->body.header.nVersion = 4;
    fx->body.header.nTime = 1700000000;
    fx->body.header.nBits = 0x2000ffff;
    if (fx->ok) {
        fx->body.vtx = zcl_calloc(1, sizeof(*fx->body.vtx),
                                  "rpc_safety.rawtx_block");
        fx->ok = fx->body.vtx != NULL;
    }
    if (fx->ok) {
        fx->body.num_vtx = 1;
        transaction_init(&fx->body.vtx[0]);
        fx->ok = transaction_copy(&fx->body.vtx[0], &fx->shielded);
    }

    uint256_set_null(&fx->body_hash);
    disk_block_pos_init(&fx->pos);
    const unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
    if (fx->ok) {
        block_get_hash(&fx->body, &fx->body_hash);
        fx->ok = write_block_to_disk(&fx->body, &fx->pos, fx->dir,
                                     msg_start);
    }
}

static void rs_rawtx_build_index(struct rs_rawtx_fx *fx)
{
    main_state_init(&fx->ms);
    struct block_index *bi = NULL;
    if (fx->ok) {
        bi = chainstate_insert_block_index((struct chainstate *)&fx->ms,
                                           &fx->body_hash);
        fx->ok = bi != NULL;
    }
    if (fx->ok) {
        bi->nHeight = 0;
        bi->nFile = fx->pos.nFile;
        bi->nDataPos = fx->pos.nPos;
        bi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        bi->nTx = 1;
        bi->nChainTx = 1;
        fx->ok = active_chain_move_window_tip(&fx->ms.chain_active, bi);
    }

    memset(&fx->ndb, 0, sizeof(fx->ndb));
    if (fx->ok)
        fx->ok = node_db_open(&fx->ndb, ":memory:");
    if (fx->ok) {
        struct db_tx_index row;
        memset(&row, 0, sizeof(row));
        memcpy(row.txid, fx->shielded.hash.data, sizeof(row.txid));
        memcpy(row.block_hash, fx->body_hash.data, sizeof(row.block_hash));
        row.block_height = 0;
        row.tx_index = 0;
        row.file_num = fx->pos.nFile;
        row.file_pos = (int)fx->pos.nPos;
        fx->ok = db_tx_save(&fx->ndb, &row);
    }

    rpc_table_init(&fx->tbl);
    if (fx->ok) {
        rpc_rawtx_set_state(&fx->ms, NULL, NULL, fx->dir);
        wallet_rpc_context_set_base(NULL, &fx->ms, fx->dir, NULL, NULL,
                                    NULL);
        wallet_rpc_context_set_node_db(&fx->ndb);
        register_rawtransaction_rpc_commands(&fx->tbl);
        rpc_blockchain_set_state(&fx->ms, NULL, fx->dir);
        register_blockchain_rpc_commands(&fx->tbl);
    }
}

/* One getrawtransaction call for the fixture txid; fx->ok folds in whether
 * the result names the same txid, block hash and a single confirmation. */
static void rs_rawtx_lookup(struct rs_rawtx_fx *fx)
{
    struct json_value params, result, txid_arg, verbose_arg;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    json_init(&txid_arg);
    json_init(&verbose_arg);
    if (fx->ok) {
        json_set_str(&txid_arg, fx->txid_hex);
        json_set_int(&verbose_arg, 1);
        (void)json_push_back(&params, &txid_arg);
        (void)json_push_back(&params, &verbose_arg);
        fx->ok = rpc_table_execute(&fx->tbl, "getrawtransaction", &params,
                                   &result);
    }
    const char *got_txid = json_get_str(json_get(&result, "txid"));
    const char *got_block = json_get_str(json_get(&result, "blockhash"));
    const struct json_value *got_confirmations =
        json_get(&result, "confirmations");
    fx->ok = fx->ok && got_txid && strcmp(got_txid, fx->txid_hex) == 0 &&
         got_block && strcmp(got_block, fx->block_hex) == 0 &&
         got_confirmations && json_get_int(got_confirmations) == 1;

    json_free(&params);
    json_free(&result);
    json_free(&txid_arg);
    json_free(&verbose_arg);
}

static void rs_rawtx_first_lookup(struct rs_rawtx_fx *fx)
{
    if (fx->ok)
        uint256_get_hex(&fx->shielded.hash, fx->txid_hex);
    uint256_get_hex(&fx->body_hash, fx->block_hex);
    rs_rawtx_lookup(fx);
}

static void rs_rawtx_wallet_row(struct rs_rawtx_fx *fx)
{
    /* The wallet projection is finalized before the global transaction
     * catalog catches up; removing the catalog row reproduces that
     * window, and chain lookup must still agree with wallet history. */
    struct byte_stream wallet_raw;
    stream_init(&wallet_raw, 512);
    struct db_wallet_tx wallet_row;
    memset(&wallet_row, 0, sizeof(wallet_row));
    if (fx->ok) {
        fx->ok = db_tx_delete(&fx->ndb, fx->shielded.hash.data) &&
            transaction_serialize(&fx->shielded, &wallet_raw);
    }
    if (fx->ok) {
        memcpy(wallet_row.txid, fx->shielded.hash.data,
               sizeof(wallet_row.txid));
        wallet_row.raw_tx = wallet_raw.data;
        wallet_row.raw_tx_len = wallet_raw.size;
        memcpy(wallet_row.block_hash, fx->body_hash.data,
               sizeof(wallet_row.block_hash));
        wallet_row.has_block = true;
        wallet_row.block_height = 0;
        wallet_row.time_received = 1700000000;
        fx->ok = db_wallet_tx_save(&fx->ndb, &wallet_row);
    }
    fx->ok = fx->ok && db_wallet_tx_confirmed_count(&fx->ndb) == 1;

    rs_rawtx_lookup(fx);
    stream_free(&wallet_raw);
}

static void rs_rawtx_owned_wallet(struct rs_rawtx_fx *fx)
{
    /* The finalized in-memory wallet leads even the wallet SQLite row;
     * lookup must stay exact. Heap the ~40 MB struct wallet. */
    fx->owned_wallet = zcl_calloc(1, sizeof(*fx->owned_wallet),
                                  "rpc-safety-owned-wallet");
    fx->ok = fx->ok && fx->owned_wallet != NULL;
    if (fx->owned_wallet)
        wallet_init(fx->owned_wallet);
    struct wallet_tx owned_wtx;
    memset(&owned_wtx, 0, sizeof(owned_wtx));
    if (fx->ok) {
        fx->ok = db_wallet_tx_delete(&fx->ndb, fx->shielded.hash.data) &&
            transaction_copy(&owned_wtx.tx, &fx->shielded);
    }
    fx->ok = fx->ok && db_wallet_tx_confirmed_count(&fx->ndb) == 0;
    if (fx->ok) {
        owned_wtx.hash_block = fx->body_hash;
        owned_wtx.confirms = 1;
        owned_wtx.used = true;
        fx->ok = wallet_add_to_wallet(fx->owned_wallet, &owned_wtx);
        transaction_free(&owned_wtx.tx);
        wallet_rpc_context_set_base(fx->owned_wallet, &fx->ms, fx->dir,
                                    NULL, NULL, NULL);
        wallet_rpc_context_set_node_db(&fx->ndb);
    }

    rs_rawtx_lookup(fx);
}

static void rs_rawtx_no_indexes(struct rs_rawtx_fx *fx)
{
    /* A non-wallet peer must expose a just-confirmed transaction while
     * every derived index is absent. */
    if (fx->ok) {
        wallet_rpc_context_set_base(NULL, &fx->ms, fx->dir,
                                    NULL, NULL, NULL);
        wallet_rpc_context_set_node_db(&fx->ndb);
        fx->ok = db_wallet_tx_delete(&fx->ndb, fx->shielded.hash.data) &&
            db_tx_delete(&fx->ndb, fx->shielded.hash.data);
    }
    rs_rawtx_lookup(fx);
}

static void rs_rawtx_block_txids(struct rs_rawtx_fx *fx)
{
    /* The sibling block lookup must expose the exact transaction ids,
     * not only a count.  This is the recovery path when an operator has
     * a confirmed block identity but not a working transaction index. */
    struct json_value params, result, txid_arg, verbose_arg;
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    json_init(&txid_arg);
    json_init(&verbose_arg);
    if (fx->ok) {
        reducer_frontier_provable_tip_set(0);
        json_set_str(&txid_arg, fx->block_hex);
        json_set_int(&verbose_arg, 1);
        (void)json_push_back(&params, &txid_arg);
        (void)json_push_back(&params, &verbose_arg);
        fx->ok = rpc_table_execute(&fx->tbl, "getblock", &params, &result);
    }
    const struct json_value *block_txids = json_get(&result, "tx");
    const char *block_txid =
        block_txids && block_txids->type == JSON_ARR &&
                json_size(block_txids) == 1
            ? json_get_str(json_at(block_txids, 0)) : NULL;
    fx->ok = fx->ok && json_get_int(json_get(&result, "size")) > 0 &&
         json_get_int(json_get(&result, "tx_count")) == 1 &&
         block_txid && strcmp(block_txid, fx->txid_hex) == 0;
    json_free(&params);
    json_free(&result);
    json_free(&txid_arg);
    json_free(&verbose_arg);
}

static void rs_rawtx_verbose_cases(struct rs_rawtx_fx *fx)
{
    struct json_value params, result, txid_arg, verbose_arg;

    /* Internal callers use JSON booleans; legacy clients use numeric
     * 0/1. Both forms select the same object/raw modes. Unrelated JSON
     * types remain a named parameter refusal. */
    static const struct {
        bool boolean;
        int value;
        bool invalid_object;
        bool expect_ok;
        enum json_type expect_type;
    } verbose_cases[] = {
        {true,  1, false, true,  JSON_OBJ},
        {true,  0, false, true,  JSON_STR},
        {false, 1, false, true,  JSON_OBJ},
        {false, 0, false, true,  JSON_STR},
        {false, 0, true,  false, JSON_STR},
    };
    for (size_t i = 0; fx->ok && i < sizeof(verbose_cases) /
                                  sizeof(verbose_cases[0]); i++) {
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        json_init(&txid_arg);
        json_init(&verbose_arg);
        json_set_str(&txid_arg, fx->block_hex);
        if (verbose_cases[i].invalid_object)
            json_set_object(&verbose_arg);
        else if (verbose_cases[i].boolean)
            json_set_bool(&verbose_arg, verbose_cases[i].value != 0);
        else
            json_set_int(&verbose_arg, verbose_cases[i].value);
        (void)json_push_back(&params, &txid_arg);
        (void)json_push_back(&params, &verbose_arg);
        bool called = rpc_table_execute(&fx->tbl, "getblock", &params,
                                        &result);
        fx->ok = called == verbose_cases[i].expect_ok &&
             result.type == verbose_cases[i].expect_type;
        if (verbose_cases[i].invalid_object)
            fx->ok = fx->ok && strstr(json_get_str(&result),
                              "must be numeric") != NULL;
        json_free(&params);
        json_free(&result);
        json_free(&txid_arg);
        json_free(&verbose_arg);
    }
    reducer_frontier_provable_tip_reset();
}

static void rs_rawtx_cleanup(struct rs_rawtx_fx *fx)
{
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_rawtx_set_state(NULL, NULL, NULL, NULL);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    if (fx->ndb.open)
        node_db_close(&fx->ndb);
    main_state_free(&fx->ms);
    block_free(&fx->body);
    transaction_free(&fx->shielded);
    if (fx->owned_wallet) {
        wallet_free(fx->owned_wallet);
        free(fx->owned_wallet);
    }
    test_rm_rf(fx->dir);
}

static int rs_case_rawtx_locator(void)
{
    int failures = 0;
    struct rs_rawtx_fx fx;

    printf("rpc_safety: confirmed tx uses verified node/wallet locator... ");
    ensure_rpc_warmup_finished_once();
    test_make_tmpdir(fx.dir, sizeof(fx.dir), "rpc_safety", "rawtx_node_db");
    rs_rawtx_build_block(&fx);
    rs_rawtx_build_index(&fx);
    rs_rawtx_first_lookup(&fx);
    rs_rawtx_wallet_row(&fx);
    rs_rawtx_owned_wallet(&fx);
    rs_rawtx_no_indexes(&fx);
    rs_rawtx_block_txids(&fx);
    rs_rawtx_verbose_cases(&fx);
    rs_rawtx_cleanup(&fx);

    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "getbestblockhash follows provable tip" phases. */
struct rs_tip_fx {
    struct main_state ms;
    struct block_index *blocks[4];
    struct rpc_table tbl;
    struct rpc_table health_tbl;
    char hstar_hex[65];
    char active_hex[65];
    char want_merkle[65];
    char want_nonce[65];
    bool ok;
};

static void rs_tip_setup(struct rs_tip_fx *fx)
{
    test_reset_shared_globals();
    ensure_rpc_warmup_finished_once();

    fx->ok = rpc_safety_build_chain(&fx->ms, fx->blocks, 4);
    rpc_blockchain_set_state(&fx->ms, NULL, "/tmp");
    reducer_frontier_provable_tip_set(1);

    rpc_table_init(&fx->tbl);
    register_blockchain_rpc_commands(&fx->tbl);

    rpc_table_init(&fx->health_tbl);
    rpc_health_set_state(&fx->ms, NULL, NULL, NULL);
    register_health_rpc_commands(&fx->health_tbl);

    if (fx->blocks[1] && fx->blocks[1]->phashBlock)
        uint256_get_hex(fx->blocks[1]->phashBlock, fx->hstar_hex);
    if (fx->blocks[3] && fx->blocks[3]->phashBlock)
        uint256_get_hex(fx->blocks[3]->phashBlock, fx->active_hex);
}

static void rs_tip_best_and_chaintip(struct rs_tip_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};
    json_init(&params);
    json_set_array(&params);
    json_init(&result);

    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getbestblockhash",
                                         &params, &result);
    fx->ok = fx->ok && result.type == JSON_STR &&
         strcmp(json_get_str(&result), fx->hstar_hex) == 0 &&
         strcmp(json_get_str(&result), fx->active_hex) != 0;
    json_free(&result);

    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getchaintip", &params,
                                         &result);
    const struct json_value *tip_height = json_get(&result, "height");
    const struct json_value *tip_hash = json_get(&result, "hash");
    fx->ok = fx->ok && tip_height && json_get_int(tip_height) == 1;
    fx->ok = fx->ok && tip_hash && tip_hash->type == JSON_STR &&
         strcmp(json_get_str(tip_hash), fx->hstar_hex) == 0 &&
         strcmp(json_get_str(tip_hash), fx->active_hex) != 0;
    json_free(&result);
    json_free(&params);
}

static void rs_tip_blockhash_header(struct rs_tip_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};

    init_single_int_param(&params, 1);
    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getblockhash", &params,
                                         &result) &&
         result.type == JSON_STR &&
         strcmp(json_get_str(&result), fx->hstar_hex) == 0;
    json_free(&result);
    json_free(&params);

    init_single_int_param(&params, 2);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(&fx->tbl, "getblockhash", &params,
                                          &result);
    fx->ok = fx->ok && result.type == JSON_STR &&
         strcmp(json_get_str(&result), fx->active_hex) != 0 &&
         strstr(json_get_str(&result), "out of range") != NULL;
    json_free(&result);
    json_free(&params);

    init_single_str_param(&params, fx->hstar_hex);
    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getblockheader", &params,
                                         &result);
    const struct json_value *header_height = json_get(&result, "height");
    fx->ok = fx->ok && header_height && json_get_int(header_height) == 1;
    json_free(&result);
    json_free(&params);
}

static void rs_tip_slim_flat_prepare(struct rs_tip_fx *fx)
{
    /* Slim-flat condition: fixture index entries carry zero merkle/nonce
     * (warm boot from the flat cache); with a durable header authority
     * registered, getblockheader must hydrate both through the runtime
     * port. Expectations are deserialized from the stub authority's
     * bytes. The call also pins the era-bits difficulty against legacy
     * zclassicd. */
    rpc_safety_seed_known_header();
    struct block_header want_hdr;
    block_header_init(&want_hdr);
    struct byte_stream hr;
    stream_init_from_data(&hr, rpc_safety_hdr_bytes, rpc_safety_hdr_len);
    fx->ok = fx->ok && block_header_deserialize(&want_hdr, &hr);
    uint256_get_hex(&want_hdr.hashMerkleRoot, fx->want_merkle);
    uint256_get_hex(&want_hdr.nNonce, fx->want_nonce);
    if (fx->blocks[1])
        fx->blocks[1]->nBits = 0x1c7397b0;
    node_db_runtime_port_set(&rpc_safety_header_port);
}

static void rs_tip_slim_flat_check(struct rs_tip_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};

    init_single_str_param(&params, fx->hstar_hex);
    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getblockheader", &params,
                                         &result);
    const struct json_value *got_merkle = json_get(&result, "merkleroot");
    const struct json_value *got_nonce = json_get(&result, "nonce");
    const struct json_value *got_diff = json_get(&result, "difficulty");
    fx->ok = fx->ok && got_merkle && got_merkle->type == JSON_STR &&
         strcmp(json_get_str(got_merkle), fx->want_merkle) == 0;
    fx->ok = fx->ok && got_nonce && got_nonce->type == JSON_STR &&
         strcmp(json_get_str(got_nonce), fx->want_nonce) == 0;
    /* legacy zclassicd renders 1161125.834138388 for bits 0x1c7397b0
     * (oracle h=500000); allow 1e-9 relative for double formatting. */
    const double want_diff = 1161125.834138388;
    double diff_got = got_diff ? json_get_real(got_diff) : 0.0;
    double diff_rel = (diff_got - want_diff) / want_diff;
    if (diff_rel < 0) diff_rel = -diff_rel;
    fx->ok = fx->ok && got_diff && got_diff->type == JSON_REAL &&
         diff_rel < 1e-9;
    json_free(&result);
    json_free(&params);
    node_db_runtime_port_set(NULL);
}

static void rs_tip_not_found(struct rs_tip_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};

    init_single_str_param(&params, fx->active_hex);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(&fx->tbl, "getblockheader",
                                          &params, &result);
    fx->ok = fx->ok && result.type == JSON_STR &&
         strstr(json_get_str(&result), "not found") != NULL;
    json_free(&result);
    json_free(&params);

    init_single_str_param(&params, fx->hstar_hex);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(&fx->tbl, "getblock", &params,
                                          &result) &&
         result.type == JSON_STR &&
         strstr(json_get_str(&result), "body unavailable") != NULL;
    json_free(&result);
    json_free(&params);
}

static void rs_tip_sync(struct rs_tip_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};

    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->health_tbl, "getsyncdetail",
                                         &params, &result);
    const struct json_value *chain = json_get(&result, "chain");
    const struct json_value *chain_height = json_get(chain, "height");
    const struct json_value *best_block = json_get(chain, "best_block");
    fx->ok = fx->ok && chain && chain_height &&
         json_get_int(chain_height) == 1;
    fx->ok = fx->ok && best_block && best_block->type == JSON_STR &&
         strcmp(json_get_str(best_block), fx->hstar_hex) == 0 &&
         strcmp(json_get_str(best_block), fx->active_hex) != 0;
    json_free(&result);
    json_free(&params);

    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->health_tbl, "getsyncdiag",
                                         &params, &result);
    const struct json_value *diag_chain_height =
        json_get(&result, "chain_height");
    const struct json_value *diag_header_height =
        json_get(&result, "best_header_height");
    fx->ok = fx->ok && diag_chain_height &&
         json_get_int(diag_chain_height) == 1;
    fx->ok = fx->ok && diag_header_height &&
         json_get_int(diag_header_height) == 3;
    json_free(&result);
    json_free(&params);
}

static void rs_tip_getblock_missing(struct rs_tip_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};

    init_single_str_param(&params, fx->active_hex);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(&fx->tbl, "getblock", &params,
                                          &result);
    fx->ok = fx->ok && result.type == JSON_STR &&
         strstr(json_get_str(&result), "not found") != NULL;

    json_free(&params);
    json_free(&result);
}

static int rs_case_getbestblockhash(void)
{
    int failures = 0;
    struct rs_tip_fx fx = {0};

    printf("rpc_safety: getbestblockhash follows provable tip... ");
    rs_tip_setup(&fx);
    rs_tip_best_and_chaintip(&fx);
    rs_tip_blockhash_header(&fx);
    rs_tip_slim_flat_prepare(&fx);
    rs_tip_slim_flat_check(&fx);
    rs_tip_not_found(&fx);
    rs_tip_sync(&fx);
    rs_tip_getblock_missing(&fx);
    reducer_frontier_provable_tip_reset();
    rpc_health_set_state(NULL, NULL, NULL, NULL);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    main_state_free(&fx.ms);
    test_reset_shared_globals();

    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "getblockhash resolves sparse H*" phases. */
struct rs_sparse_fx {
    struct main_state ms;
    struct block_index *blocks[3];
    struct node_db ndb;
    bool ndb_open;
    struct rpc_table tbl;
    char hstar_hex[65];
    char active_hex[65];
    bool ok;
};

static void rs_sparse_setup(struct rs_sparse_fx *fx)
{
    test_reset_shared_globals();
    ensure_rpc_warmup_finished_once();

    fx->ndb_open = false;
    fx->ok = rpc_safety_build_chain(&fx->ms, fx->blocks, 3);
    if (fx->ok)
        fx->ms.chain_active.chain[1] = NULL;
    fx->ok = fx->ok && node_db_open(&fx->ndb, ":memory:");
    fx->ndb_open = fx->ok;
    fx->ok = fx->ok && rpc_safety_save_projected_block(&fx->ndb,
                                                       fx->blocks[1]);

    rpc_blockchain_set_state(&fx->ms, NULL, "/tmp");
    rpc_blockchain_set_node_db(&fx->ndb);
    reducer_frontier_provable_tip_set(1);

    rpc_table_init(&fx->tbl);
    register_blockchain_rpc_commands(&fx->tbl);

    if (fx->blocks[1] && fx->blocks[1]->phashBlock)
        uint256_get_hex(fx->blocks[1]->phashBlock, fx->hstar_hex);
    if (fx->blocks[2] && fx->blocks[2]->phashBlock)
        uint256_get_hex(fx->blocks[2]->phashBlock, fx->active_hex);
}

static void rs_sparse_calls(struct rs_sparse_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};
    json_init(&params);
    json_set_array(&params);
    json_init(&result);

    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getbestblockhash",
                                         &params, &result);
    fx->ok = fx->ok && result.type == JSON_STR &&
         strcmp(json_get_str(&result), fx->hstar_hex) == 0 &&
         strcmp(json_get_str(&result), fx->active_hex) != 0;
    json_free(&result);
    json_free(&params);

    init_single_int_param(&params, 1);
    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "getblockhash", &params,
                                         &result) &&
         result.type == JSON_STR &&
         strcmp(json_get_str(&result), fx->hstar_hex) == 0 &&
         strcmp(json_get_str(&result), fx->active_hex) != 0;
    json_free(&result);
    json_free(&params);

    init_single_int_param(&params, 2);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(&fx->tbl, "getblockhash", &params,
                                          &result);
    fx->ok = fx->ok && result.type == JSON_STR &&
         strstr(json_get_str(&result), "out of range") != NULL;

    json_free(&params);
    json_free(&result);
}

static int rs_case_sparse_getblockhash(void)
{
    int failures = 0;
    struct rs_sparse_fx fx = {0};

    printf("rpc_safety: getblockhash resolves sparse H* from node db... ");
    rs_sparse_setup(&fx);
    rs_sparse_calls(&fx);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    rpc_blockchain_set_node_db(NULL);
    reducer_frontier_provable_tip_reset();
    if (fx.ndb_open)
        node_db_close(&fx.ndb);
    main_state_free(&fx.ms);
    test_reset_shared_globals();

    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "gettxoutsetinfo reports coin frontier" phases. */
struct rs_coin_fx {
    char dir[256];
    struct main_state ms;
    struct block_index *blocks[4];
    struct rpc_table tbl;
    char coin_hex[65];
    char active_hex[65];
    bool ok;
};

static void rs_coin_setup(struct rs_coin_fx *fx)
{
    test_reset_shared_globals();
    ensure_rpc_warmup_finished_once();
    progress_store_close();

    test_make_tmpdir(fx->dir, sizeof(fx->dir), "rpc_safety", "coin_frontier");

    fx->ok = rpc_safety_build_chain(&fx->ms, fx->blocks, 4);
    fx->ok = fx->ok && progress_store_open(fx->dir);
    sqlite3 *db = progress_store_db();
    fx->ok = fx->ok && db && rpc_safety_seed_coin_frontier(db,
                                                           fx->blocks[1]);

    rpc_blockchain_set_state(&fx->ms, NULL, "/tmp");

    rpc_table_init(&fx->tbl);
    register_blockchain_rpc_commands(&fx->tbl);

    if (fx->blocks[1] && fx->blocks[1]->phashBlock)
        uint256_get_hex(fx->blocks[1]->phashBlock, fx->coin_hex);
    if (fx->blocks[3] && fx->blocks[3]->phashBlock)
        uint256_get_hex(fx->blocks[3]->phashBlock, fx->active_hex);
}

static void rs_coin_call(struct rs_coin_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};
    json_init(&params);
    json_set_array(&params);
    json_init(&result);

    fx->ok = fx->ok && rpc_table_execute(&fx->tbl, "gettxoutsetinfo",
                                         &params, &result);
    const struct json_value *height = json_get(&result, "height");
    const struct json_value *bestblock = json_get(&result, "bestblock");
    const struct json_value *txs = json_get(&result, "transactions");
    const struct json_value *outs = json_get(&result, "txouts");
    fx->ok = fx->ok && height && json_get_int(height) == 1;
    fx->ok = fx->ok && bestblock && bestblock->type == JSON_STR &&
         strcmp(json_get_str(bestblock), fx->coin_hex) == 0 &&
         strcmp(json_get_str(bestblock), fx->active_hex) != 0;
    fx->ok = fx->ok && txs && json_get_int(txs) == 1;
    fx->ok = fx->ok && outs && json_get_int(outs) == 1;

    json_free(&params);
    json_free(&result);
}

static int rs_case_txoutsetinfo(void)
{
    int failures = 0;
    struct rs_coin_fx fx = {0};

    printf("rpc_safety: gettxoutsetinfo reports coin frontier... ");
    rs_coin_setup(&fx);
    rs_coin_call(&fx);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    progress_store_close();
    test_cleanup_tmpdir(fx.dir);
    main_state_free(&fx.ms);
    test_reset_shared_globals();

    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "summary RPCs do not borrow unresolved active tip"
 * phases. */
struct rs_summary_fx {
    struct main_state ms;
    struct block_index *blocks[4];
    struct connman cm;
    struct rpc_table chain_tbl;
    struct rpc_table misc_tbl;
    struct rpc_table mining_tbl;
    bool ok;
};

static void rs_summary_setup(struct rs_summary_fx *fx)
{
    test_reset_shared_globals();
    ensure_rpc_warmup_finished_once();

    fx->ok = rpc_safety_build_chain(&fx->ms, fx->blocks, 4);
    if (fx->ok)
        fx->ms.chain_active.chain[1] = NULL;
    reducer_frontier_provable_tip_set(1);

    memset(&fx->cm, 0, sizeof(fx->cm));
    net_manager_init(&fx->cm.manager);
    fx->cm.manager.num_nodes = 3;

    rpc_table_init(&fx->chain_tbl);
    rpc_blockchain_set_state(&fx->ms, NULL, "/tmp");
    register_blockchain_rpc_commands(&fx->chain_tbl);

    rpc_table_init(&fx->misc_tbl);
    rpc_misc_set_state(&fx->ms);
    rpc_net_set_connman(&fx->cm);
    register_misc_rpc_commands(&fx->misc_tbl);

    rpc_table_init(&fx->mining_tbl);
    rpc_mining_set_state(&fx->ms, NULL, NULL);
    register_mining_rpc_commands(&fx->mining_tbl);
}

static void rs_summary_calls(struct rs_summary_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};
    json_init(&params);
    json_set_array(&params);
    json_init(&result);

    /* getblockchaininfo must NOT borrow the unresolved active tip
     * (height 3): with the H* slot unresolved it returns a valid
     * IBD-shaped object reporting the PROVABLE height (H* == 1) with
     * initialblockdownload=true. */
    fx->ok = fx->ok && rpc_table_execute(&fx->chain_tbl, "getblockchaininfo",
                                         &params, &result);
    {
        const struct json_value *gbi_blocks = json_get(&result, "blocks");
        const struct json_value *gbi_ibd =
            json_get(&result, "initialblockdownload");
        fx->ok = fx->ok && gbi_blocks && json_get_int(gbi_blocks) == 1;
        fx->ok = fx->ok && gbi_ibd && json_get_bool(gbi_ibd);
    }
    json_free(&result);

    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->misc_tbl, "getinfo", &params,
                                         &result);
    const struct json_value *info_blocks = json_get(&result, "blocks");
    const struct json_value *info_connections =
        json_get(&result, "connections");
    fx->ok = fx->ok && info_blocks && json_get_int(info_blocks) == 1;
    fx->ok = fx->ok && info_connections &&
         json_get_int(info_connections) == 3;
    json_free(&result);

    json_init(&result);
    fx->ok = fx->ok && rpc_table_execute(&fx->mining_tbl, "getmininginfo",
                                         &params, &result);
    const struct json_value *mining_blocks = json_get(&result, "blocks");
    fx->ok = fx->ok && mining_blocks && json_get_int(mining_blocks) == 1;

    json_free(&params);
    json_free(&result);
}

static int rs_case_summary_tip(void)
{
    int failures = 0;
    struct rs_summary_fx fx = {0};

    printf("rpc_safety: summary RPCs do not borrow unresolved active tip... ");
    rs_summary_setup(&fx);
    rs_summary_calls(&fx);
    rpc_blockchain_set_state(NULL, NULL, NULL);
    rpc_misc_set_state(NULL);
    rpc_net_set_connman(NULL);
    rpc_mining_set_state(NULL, NULL, NULL);
    fx.cm.manager.num_nodes = 0;
    net_manager_free(&fx.cm.manager);
    reducer_frontier_provable_tip_reset();
    main_state_free(&fx.ms);
    test_reset_shared_globals();

    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "chainstate guard rejects unresolved active tip"
 * phases. */
struct rs_guard_fx {
    struct main_state *ms;
    struct coins_view_cache *coins_tip;
    struct wallet *wallet;
    struct node_db *ndb;
    struct rpc_table *rawtx_tbl;
    struct rpc_table *inspect_tbl;
    struct rpc_table *wallet_diag_tbl;
    struct rpc_table *wallet_rescan_tbl;
    struct rpc_table *repair_tbl;
    bool ok;
};

static void rs_guard_alloc(struct rs_guard_fx *fx)
{
    fx->ms = calloc(1, sizeof(*fx->ms));
    fx->coins_tip = calloc(1, sizeof(*fx->coins_tip));
    fx->wallet = calloc(1, sizeof(*fx->wallet));
    fx->ndb = calloc(1, sizeof(*fx->ndb));
    fx->rawtx_tbl = calloc(1, sizeof(*fx->rawtx_tbl));
    fx->inspect_tbl = calloc(1, sizeof(*fx->inspect_tbl));
    fx->wallet_diag_tbl = calloc(1, sizeof(*fx->wallet_diag_tbl));
    fx->wallet_rescan_tbl = calloc(1, sizeof(*fx->wallet_rescan_tbl));
    fx->repair_tbl = calloc(1, sizeof(*fx->repair_tbl));

    fx->ok = fx->ms && fx->coins_tip && fx->wallet && fx->ndb &&
             fx->rawtx_tbl && fx->inspect_tbl && fx->wallet_diag_tbl &&
             fx->wallet_rescan_tbl && fx->repair_tbl;
    if (fx->ok) {
        build_unresolved_tip_state(fx->ms, 100);
        wallet_init(fx->wallet);
        fx->ndb->open = true;
    }
}

static void rs_guard_free_all(struct rs_guard_fx *fx)
{
    free(fx->ms);
    free(fx->coins_tip);
    free(fx->wallet);
    free(fx->ndb);
    free(fx->rawtx_tbl);
    free(fx->inspect_tbl);
    free(fx->wallet_diag_tbl);
    free(fx->wallet_rescan_tbl);
    free(fx->repair_tbl);
}

static void rs_guard_register(struct rs_guard_fx *fx)
{
    rpc_table_init(fx->rawtx_tbl);
    rpc_rawtx_set_state(fx->ms, NULL, fx->coins_tip, "/tmp");
    register_rawtransaction_rpc_commands(fx->rawtx_tbl);

    rpc_table_init(fx->inspect_tbl);
    rpc_chain_inspect_set_state(fx->ms, "/tmp", NULL, fx->coins_tip, NULL);
    register_chain_inspect_rpc_commands(fx->inspect_tbl);

    wallet_rpc_context_set_base(fx->wallet, fx->ms, "/tmp", NULL, NULL,
                                NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_coins_tip(fx->coins_tip);

    rpc_table_init(fx->wallet_diag_tbl);
    register_wallet_diagnostic_rpc_commands(fx->wallet_diag_tbl);

    wallet_rpc_context_set_node_db(NULL);
    rpc_table_init(fx->wallet_rescan_tbl);
    register_wallet_rescan_rpc_commands(fx->wallet_rescan_tbl);

    rpc_table_init(fx->repair_tbl);
    rpc_repair_set_state(fx->ms, fx->coins_tip, fx->ndb, "/tmp",
                         chain_params_get());
    register_repair_rpc_commands(fx->repair_tbl);
    register_backfill_header_solutions_rpc_commands(fx->repair_tbl);
}

static void rs_guard_calls(struct rs_guard_fx *fx)
{
    struct json_value params = {0};
    struct json_value result = {0};

    init_single_str_param(
        &params,
        "0000000000000000000000000000000000000000000000000000000000000001");
    json_init(&result);
    fx->ok = !rpc_table_execute(fx->rawtx_tbl, "getrawtransaction", &params,
                                &result) &&
         result_is_chainstate_guard_error(&result, "getrawtransaction");
    json_free(&params);
    json_free(&result);

    init_single_str_param(
        &params,
        "0000000000000000000000000000000000000000000000000000000000000002");
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(fx->inspect_tbl, "gettxdetail",
                                          &params, &result) &&
         result_is_chainstate_guard_error(&result, "gettxdetail");
    json_free(&params);
    json_free(&result);

    init_single_str_param(
        &params,
        "0000000000000000000000000000000000000000000000000000000000000003");
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(fx->wallet_diag_tbl,
                                          "getchaincoins", &params,
                                          &result) &&
         result_is_chainstate_guard_error(&result, "getchaincoins");
    json_free(&params);
    json_free(&result);

    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(fx->wallet_rescan_tbl,
                                          "syncwalletfromdb", &params,
                                          &result) &&
         result_is_chainstate_guard_error(&result, "syncwalletfromdb");
    json_free(&params);
    json_free(&result);

    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    fx->ok = fx->ok && !rpc_table_execute(fx->repair_tbl, "repairutxos",
                                          &params, &result) &&
         result_is_chainstate_guard_error(&result, "repairutxos");
    json_free(&params);
    json_free(&result);
}

static int rs_case_chainstate_guard(bool *aborted)
{
    int failures = 0;
    struct rs_guard_fx fx;

    printf("rpc_safety: chainstate guard rejects unresolved active tip... ");
    ensure_rpc_warmup_finished_once();
    rs_guard_alloc(&fx);

    if (!fx.ok) {
        rs_guard_free_all(&fx);
        printf("FAIL\n");
        *aborted = true;
        return failures + 1;
    }

    rs_guard_register(&fx);
    rs_guard_calls(&fx);

    main_state_free(fx.ms);
    wallet_free(fx.wallet);
    rs_guard_free_all(&fx);

    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* Shared state for the "raw-sign P2SH 2-of-2" phases. */
struct rs_p2sh_fx {
    struct basic_keystore *ks;
    struct rpc_table *tbl;
    struct privkey keys[2];
    struct pubkey pubs[2];
    struct script redeem, p2sh;
    char tx_hex[2048];
    char p2sh_hex[2 * MAX_SCRIPT_SIZE + 1];
    char redeem_hex[2 * MAX_SCRIPT_SIZE + 1];
    struct transaction signed_tx;
    bool ok;
};

static void rs_p2sh_keys(struct rs_p2sh_fx *fx)
{
    keystore_init(fx->ks);
    rpc_table_init(fx->tbl);
    rpc_rawtx_set_state(NULL, NULL, NULL, "/tmp");
    rpc_rawtx_set_keystore(fx->ks);
    register_rawtransaction_rpc_commands(fx->tbl);

    for (size_t i = 0; i < 2 && fx->ok; i++) {
        privkey_make_new(&fx->keys[i], true);
        fx->ok = privkey_get_pubkey(&fx->keys[i], &fx->pubs[i]) &&
             keystore_add_key(fx->ks, &fx->keys[i]);
    }
    script_for_multisig(&fx->redeem, 2, fx->pubs, 2);
    struct script_id redeem_id;
    script_id_from_script(&redeem_id, &fx->redeem);
    script_for_p2sh(&fx->p2sh, &redeem_id);
}

static void rs_p2sh_build_tx(struct rs_p2sh_fx *fx)
{
    struct transaction tx;
    transaction_init(&tx);
    tx.overwintered = true;
    tx.version = SAPLING_TX_VERSION;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.vin = calloc(1, sizeof(*tx.vin));
    tx.vout = calloc(1, sizeof(*tx.vout));
    fx->ok = fx->ok && tx.vin && tx.vout;
    if (fx->ok) {
        tx.num_vin = 1;
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = UINT32_MAX;
        tx.num_vout = 1;
        tx.vout[0].value = 1000;
        struct key_id recipient = {0};
        script_for_p2pkh(&tx.vout[0].script_pub_key, &recipient);
    }
    size_t tx_hex_len = fx->ok ?
        encode_hex_tx(&tx, fx->tx_hex, sizeof(fx->tx_hex)) : 0;
    fx->ok = fx->ok && tx_hex_len > 0 && tx_hex_len < sizeof(fx->tx_hex);
    transaction_free(&tx);

    zcl_hex_encode(fx->p2sh.data, fx->p2sh.size, fx->p2sh_hex);
    zcl_hex_encode(fx->redeem.data, fx->redeem.size, fx->redeem_hex);
}

static void rs_p2sh_sign(struct rs_p2sh_fx *fx)
{
    struct json_value params, prevs, prev, value, result;
    json_init(&params); json_set_array(&params);
    json_init(&value); json_set_str(&value, fx->tx_hex);
    json_push_back(&params, &value); json_free(&value);
    json_init(&prevs); json_set_array(&prevs);
    json_init(&prev); json_set_object(&prev);
    json_push_kv_str(&prev, "txid",
        "0000000000000000000000000000000000000000000000000000000000000000");
    json_push_kv_int(&prev, "vout", 0);
    json_push_kv_str(&prev, "scriptPubKey", fx->p2sh_hex);
    json_push_kv_real(&prev, "amount", 0.00022);
    json_push_kv_str(&prev, "redeemScript", fx->redeem_hex);
    json_push_back(&prevs, &prev); json_free(&prev);
    json_push_back(&params, &prevs); json_free(&prevs);
    json_init(&result);

    fx->ok = fx->ok && rpc_table_execute(fx->tbl, "signrawtransaction",
                                         &params, &result) &&
         json_get_bool(json_get(&result, "complete"));
    const char *signed_hex = json_get_str(json_get(&result, "hex"));
    transaction_init(&fx->signed_tx);
    fx->ok = fx->ok && signed_hex && decode_hex_tx(&fx->signed_tx,
                                                   signed_hex) &&
         fx->signed_tx.num_vin == 1;
    json_free(&params);
    json_free(&result);
}

static void rs_p2sh_check_script_sig(struct rs_p2sh_fx *fx)
{
    if (fx->ok) {
        const struct script *ss = &fx->signed_tx.vin[0].script_sig;
        size_t pos = 0;
        fx->ok = ss->size > fx->redeem.size + 4 &&
             ss->data[pos++] == OP_0;
        for (size_t i = 0; i < 2 && fx->ok; i++) {
            size_t sig_len = ss->data[pos++];
            fx->ok = sig_len >= 70 && sig_len <= SIGNATURE_SIZE + 1 &&
                 pos + sig_len <= ss->size;
            pos += sig_len;
        }
        fx->ok = fx->ok && pos < ss->size &&
             ss->data[pos++] == fx->redeem.size &&
             pos + fx->redeem.size == ss->size &&
             memcmp(ss->data + pos, fx->redeem.data, fx->redeem.size) == 0;
    }
    transaction_free(&fx->signed_tx);
}

static int rs_case_p2sh_2of2(void)
{
    int failures = 0;
    struct rs_p2sh_fx fx = {0};

    printf("rpc_safety: raw-sign P2SH 2-of-2 emits both signatures... ");
    fx.ks = calloc(1, sizeof(*fx.ks));
    fx.tbl = calloc(1, sizeof(*fx.tbl));
    fx.ok = fx.ks && fx.tbl;
    if (fx.ok) {
        rs_p2sh_keys(&fx);
        rs_p2sh_build_tx(&fx);
        rs_p2sh_sign(&fx);
        rs_p2sh_check_script_sig(&fx);
        rpc_rawtx_set_keystore(NULL);
        keystore_free(fx.ks);
    }
    for (size_t i = 0; i < 2; i++)
        memory_cleanse(fx.keys[i].vch, sizeof(fx.keys[i].vch));
    free(fx.ks);
    free(fx.tbl);
    if (fx.ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

int scs_run_tests(void);
int wrc_run_tests(void);
int test_rpc_safety(void);
int test_rpc_safety(void)
{
    int failures = 0;
    bool aborted = false;

    failures += t_parse_amount_bounds();
    failures += t_parse_amount_int_money_range();

    failures += rs_case_wallet_freshness(&aborted);
    if (aborted)
        return failures;

    failures += rs_case_fanout_preflight(&aborted);
    if (aborted)
        return failures;

    failures += rs_case_reindex_replay();
    failures += rs_case_walletbackup_status();
    failures += rs_case_getrawmempool_live();

    failures += rs_case_rawtx_locator();
    failures += rs_case_getbestblockhash();
    failures += rs_case_sparse_getblockhash();
    failures += rs_case_txoutsetinfo();
    failures += rs_case_summary_tip();

    failures += rs_case_chainstate_guard(&aborted);
    if (aborted)
        return failures;

    failures += rs_case_rawsign_supplemental();
    failures += rs_case_p2sh_2of2();
    failures += scs_run_tests();

    /* parse_amount arithmetic guards: see rs_check_parse_amount_guards. */
    failures += rs_check_parse_amount_guards();
    failures += rs_unlock_timeout_width();
    /* Reap the registry-owned wallet auto-lock timers the unlock cases armed. */
    (void)thread_registry_join_all(5);
#if defined(__GLIBC__) && !defined(__SANITIZE_ADDRESS__)
    failures += t_listunspent_frees_filtered_rows();
    failures += wrc_run_tests();
#endif

    return failures;
}
