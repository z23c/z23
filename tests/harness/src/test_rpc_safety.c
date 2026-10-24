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
     * (see tools/lint/check_outparam_init_before_return.sh). */
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

int test_rpc_safety(void);
int test_rpc_safety(void)
{
    int failures = 0;

    failures += t_parse_amount_bounds();
    failures += t_parse_amount_int_money_range();

    printf("rpc_safety: wallet freshness follows authoritative H*... ");
    {
        /* struct wallet embeds a ~40 MB tx table: heap it (as
         * test_accept_to_mempool does) to fit the default main-thread stack. */
        struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                           "rpc-safety-wallet");
        if (!wallet) {
            printf("FAIL (wallet allocation)\n");
            failures++;
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
    }

    printf("rpc_safety: fanout preflight failure creates no address... ");
    {
        ensure_rpc_warmup_finished_once();
        struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                           "rpc-safety-wallet");
        if (!wallet) {
            printf("FAIL (wallet allocation)\n");
            failures++;
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
    }

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

    printf("rpc_safety: confirmed tx uses verified node/wallet locator... ");
    {
        ensure_rpc_warmup_finished_once();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "rpc_safety", "rawtx_node_db");

        struct transaction shielded;
        transaction_init(&shielded);
        shielded.overwintered = true;
        shielded.version = SAPLING_TX_VERSION;
        shielded.version_group_id = SAPLING_VERSION_GROUP_ID;
        shielded.expiry_height = 100;
        shielded.v_shielded_spend = zcl_calloc(
            1, sizeof(*shielded.v_shielded_spend),
            "rpc_safety.shielded_spend");
        bool ok = shielded.v_shielded_spend != NULL;
        if (ok) {
            shielded.num_shielded_spend = 1;
            memset(shielded.v_shielded_spend[0].nullifier.data, 0x73, 32);
            transaction_compute_hash(&shielded);
        }

        struct block body;
        block_init(&body);
        body.header.nVersion = 4;
        body.header.nTime = 1700000000;
        body.header.nBits = 0x2000ffff;
        if (ok) {
            body.vtx = zcl_calloc(1, sizeof(*body.vtx),
                                  "rpc_safety.rawtx_block");
            ok = body.vtx != NULL;
        }
        if (ok) {
            body.num_vtx = 1;
            transaction_init(&body.vtx[0]);
            ok = transaction_copy(&body.vtx[0], &shielded);
        }

        struct uint256 body_hash;
        uint256_set_null(&body_hash);
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        const unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
        if (ok) {
            block_get_hash(&body, &body_hash);
            ok = write_block_to_disk(&body, &pos, dir, msg_start);
        }

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *bi = NULL;
        if (ok) {
            bi = chainstate_insert_block_index((struct chainstate *)&ms,
                                               &body_hash);
            ok = bi != NULL;
        }
        if (ok) {
            bi->nHeight = 0;
            bi->nFile = pos.nFile;
            bi->nDataPos = pos.nPos;
            bi->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
            bi->nTx = 1;
            bi->nChainTx = 1;
            ok = active_chain_move_window_tip(&ms.chain_active, bi);
        }

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (ok)
            ok = node_db_open(&ndb, ":memory:");
        if (ok) {
            struct db_tx_index row;
            memset(&row, 0, sizeof(row));
            memcpy(row.txid, shielded.hash.data, sizeof(row.txid));
            memcpy(row.block_hash, body_hash.data, sizeof(row.block_hash));
            row.block_height = 0;
            row.tx_index = 0;
            row.file_num = pos.nFile;
            row.file_pos = (int)pos.nPos;
            ok = db_tx_save(&ndb, &row);
        }

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        if (ok) {
            rpc_rawtx_set_state(&ms, NULL, NULL, dir);
            wallet_rpc_context_set_base(NULL, &ms, dir, NULL, NULL, NULL);
            wallet_rpc_context_set_node_db(&ndb);
            register_rawtransaction_rpc_commands(&tbl);
            rpc_blockchain_set_state(&ms, NULL, dir);
            register_blockchain_rpc_commands(&tbl);
        }

        struct json_value params, result, txid_arg, verbose_arg;
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        json_init(&txid_arg);
        json_init(&verbose_arg);
        char txid_hex[65] = "";
        if (ok) {
            uint256_get_hex(&shielded.hash, txid_hex);
            json_set_str(&txid_arg, txid_hex);
            json_set_int(&verbose_arg, 1);
            (void)json_push_back(&params, &txid_arg);
            (void)json_push_back(&params, &verbose_arg);
            ok = rpc_table_execute(&tbl, "getrawtransaction", &params,
                                   &result);
        }
        const char *got_txid = json_get_str(json_get(&result, "txid"));
        const char *got_block = json_get_str(json_get(&result, "blockhash"));
        const struct json_value *got_confirmations =
            json_get(&result, "confirmations");
        char block_hex[65] = "";
        uint256_get_hex(&body_hash, block_hex);
        ok = ok && got_txid && strcmp(got_txid, txid_hex) == 0 &&
             got_block && strcmp(got_block, block_hex) == 0 &&
             got_confirmations && json_get_int(got_confirmations) == 1;

        json_free(&params);
        json_free(&result);
        json_free(&txid_arg);
        json_free(&verbose_arg);

        /* The wallet projection is finalized before the global transaction
         * catalog catches up; removing the catalog row reproduces that
         * window, and chain lookup must still agree with wallet history. */
        struct byte_stream wallet_raw;
        stream_init(&wallet_raw, 512);
        struct db_wallet_tx wallet_row;
        memset(&wallet_row, 0, sizeof(wallet_row));
        if (ok) {
            ok = db_tx_delete(&ndb, shielded.hash.data) &&
                transaction_serialize(&shielded, &wallet_raw);
        }
        if (ok) {
            memcpy(wallet_row.txid, shielded.hash.data,
                   sizeof(wallet_row.txid));
            wallet_row.raw_tx = wallet_raw.data;
            wallet_row.raw_tx_len = wallet_raw.size;
            memcpy(wallet_row.block_hash, body_hash.data,
                   sizeof(wallet_row.block_hash));
            wallet_row.has_block = true;
            wallet_row.block_height = 0;
            wallet_row.time_received = 1700000000;
            ok = db_wallet_tx_save(&ndb, &wallet_row);
        }
        ok = ok && db_wallet_tx_confirmed_count(&ndb) == 1;

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        json_init(&txid_arg);
        json_init(&verbose_arg);
        if (ok) {
            json_set_str(&txid_arg, txid_hex);
            json_set_int(&verbose_arg, 1);
            (void)json_push_back(&params, &txid_arg);
            (void)json_push_back(&params, &verbose_arg);
            ok = rpc_table_execute(&tbl, "getrawtransaction", &params,
                                   &result);
        }
        got_txid = json_get_str(json_get(&result, "txid"));
        got_block = json_get_str(json_get(&result, "blockhash"));
        got_confirmations = json_get(&result, "confirmations");
        ok = ok && got_txid && strcmp(got_txid, txid_hex) == 0 &&
             got_block && strcmp(got_block, block_hex) == 0 &&
             got_confirmations && json_get_int(got_confirmations) == 1;
        json_free(&params);
        json_free(&result);
        json_free(&txid_arg);
        json_free(&verbose_arg);
        stream_free(&wallet_raw);

        /* The finalized in-memory wallet leads even the wallet SQLite row;
         * lookup must stay exact. Heap the ~40 MB struct wallet. */
        struct wallet *owned_wallet = zcl_calloc(1, sizeof(*owned_wallet),
                                                 "rpc-safety-owned-wallet");
        ok = ok && owned_wallet != NULL;
        if (owned_wallet)
            wallet_init(owned_wallet);
        struct wallet_tx owned_wtx;
        memset(&owned_wtx, 0, sizeof(owned_wtx));
        if (ok) {
            ok = db_wallet_tx_delete(&ndb, shielded.hash.data) &&
                transaction_copy(&owned_wtx.tx, &shielded);
        }
        ok = ok && db_wallet_tx_confirmed_count(&ndb) == 0;
        if (ok) {
            owned_wtx.hash_block = body_hash;
            owned_wtx.confirms = 1;
            owned_wtx.used = true;
            ok = wallet_add_to_wallet(owned_wallet, &owned_wtx);
            transaction_free(&owned_wtx.tx);
            wallet_rpc_context_set_base(owned_wallet, &ms, dir,
                                        NULL, NULL, NULL);
            wallet_rpc_context_set_node_db(&ndb);
        }

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        json_init(&txid_arg);
        json_init(&verbose_arg);
        if (ok) {
            json_set_str(&txid_arg, txid_hex);
            json_set_int(&verbose_arg, 1);
            (void)json_push_back(&params, &txid_arg);
            (void)json_push_back(&params, &verbose_arg);
            ok = rpc_table_execute(&tbl, "getrawtransaction", &params,
                                   &result);
        }
        got_txid = json_get_str(json_get(&result, "txid"));
        got_block = json_get_str(json_get(&result, "blockhash"));
        got_confirmations = json_get(&result, "confirmations");
        ok = ok && got_txid && strcmp(got_txid, txid_hex) == 0 &&
             got_block && strcmp(got_block, block_hex) == 0 &&
             got_confirmations && json_get_int(got_confirmations) == 1;
        json_free(&params);
        json_free(&result);
        json_free(&txid_arg);
        json_free(&verbose_arg);

        /* A non-wallet peer must expose a just-confirmed transaction while
         * every derived index is absent. */
        if (ok) {
            wallet_rpc_context_set_base(NULL, &ms, dir,
                                        NULL, NULL, NULL);
            wallet_rpc_context_set_node_db(&ndb);
            ok = db_wallet_tx_delete(&ndb, shielded.hash.data) &&
                db_tx_delete(&ndb, shielded.hash.data);
        }
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        json_init(&txid_arg);
        json_init(&verbose_arg);
        if (ok) {
            json_set_str(&txid_arg, txid_hex);
            json_set_int(&verbose_arg, 1);
            (void)json_push_back(&params, &txid_arg);
            (void)json_push_back(&params, &verbose_arg);
            ok = rpc_table_execute(&tbl, "getrawtransaction", &params,
                                   &result);
        }
        got_txid = json_get_str(json_get(&result, "txid"));
        got_block = json_get_str(json_get(&result, "blockhash"));
        got_confirmations = json_get(&result, "confirmations");
        ok = ok && got_txid && strcmp(got_txid, txid_hex) == 0 &&
             got_block && strcmp(got_block, block_hex) == 0 &&
             got_confirmations && json_get_int(got_confirmations) == 1;
        json_free(&params);
        json_free(&result);
        json_free(&txid_arg);
        json_free(&verbose_arg);

        /* The sibling block lookup must expose the exact transaction ids,
         * not only a count.  This is the recovery path when an operator has
         * a confirmed block identity but not a working transaction index. */
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        json_init(&txid_arg);
        json_init(&verbose_arg);
        if (ok) {
            reducer_frontier_provable_tip_set(0);
            json_set_str(&txid_arg, block_hex);
            json_set_int(&verbose_arg, 1);
            (void)json_push_back(&params, &txid_arg);
            (void)json_push_back(&params, &verbose_arg);
            ok = rpc_table_execute(&tbl, "getblock", &params, &result);
        }
        const struct json_value *block_txids = json_get(&result, "tx");
        const char *block_txid =
            block_txids && block_txids->type == JSON_ARR &&
                    json_size(block_txids) == 1
                ? json_get_str(json_at(block_txids, 0)) : NULL;
        ok = ok && json_get_int(json_get(&result, "size")) > 0 &&
             json_get_int(json_get(&result, "tx_count")) == 1 &&
             block_txid && strcmp(block_txid, txid_hex) == 0;
        json_free(&params);
        json_free(&result);
        json_free(&txid_arg);
        json_free(&verbose_arg);

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
        for (size_t i = 0; ok && i < sizeof(verbose_cases) /
                                      sizeof(verbose_cases[0]); i++) {
            json_init(&params);
            json_set_array(&params);
            json_init(&result);
            json_init(&txid_arg);
            json_init(&verbose_arg);
            json_set_str(&txid_arg, block_hex);
            if (verbose_cases[i].invalid_object)
                json_set_object(&verbose_arg);
            else if (verbose_cases[i].boolean)
                json_set_bool(&verbose_arg, verbose_cases[i].value != 0);
            else
                json_set_int(&verbose_arg, verbose_cases[i].value);
            (void)json_push_back(&params, &txid_arg);
            (void)json_push_back(&params, &verbose_arg);
            bool called = rpc_table_execute(&tbl, "getblock", &params,
                                            &result);
            ok = called == verbose_cases[i].expect_ok &&
                 result.type == verbose_cases[i].expect_type;
            if (verbose_cases[i].invalid_object)
                ok = ok && strstr(json_get_str(&result),
                                  "must be numeric") != NULL;
            json_free(&params);
            json_free(&result);
            json_free(&txid_arg);
            json_free(&verbose_arg);
        }
        reducer_frontier_provable_tip_reset();

        wallet_rpc_context_set_node_db(NULL);
        wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
        rpc_rawtx_set_state(NULL, NULL, NULL, NULL);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        if (ndb.open)
            node_db_close(&ndb);
        main_state_free(&ms);
        block_free(&body);
        transaction_free(&shielded);
        if (owned_wallet) {
            wallet_free(owned_wallet);
            free(owned_wallet);
        }
        test_rm_rf(dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: getbestblockhash follows provable tip... ");
    {
        test_reset_shared_globals();
        ensure_rpc_warmup_finished_once();

        struct main_state ms;
        struct block_index *blocks[4] = {0};
        bool ok = rpc_safety_build_chain(&ms, blocks, 4);
        rpc_blockchain_set_state(&ms, NULL, "/tmp");
        reducer_frontier_provable_tip_set(1);

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_blockchain_rpc_commands(&tbl);

        struct rpc_table health_tbl;
        rpc_table_init(&health_tbl);
        rpc_health_set_state(&ms, NULL, NULL, NULL);
        register_health_rpc_commands(&health_tbl);

        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_set_array(&params);
        json_init(&result);

        ok = ok && rpc_table_execute(&tbl, "getbestblockhash", &params,
                                     &result);
        char hstar_hex[65] = {0};
        char active_hex[65] = {0};
        if (blocks[1] && blocks[1]->phashBlock)
            uint256_get_hex(blocks[1]->phashBlock, hstar_hex);
        if (blocks[3] && blocks[3]->phashBlock)
            uint256_get_hex(blocks[3]->phashBlock, active_hex);
        ok = ok && result.type == JSON_STR &&
             strcmp(json_get_str(&result), hstar_hex) == 0 &&
             strcmp(json_get_str(&result), active_hex) != 0;
        json_free(&result);

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getchaintip", &params, &result);
        const struct json_value *tip_height = json_get(&result, "height");
        const struct json_value *tip_hash = json_get(&result, "hash");
        ok = ok && tip_height && json_get_int(tip_height) == 1;
        ok = ok && tip_hash && tip_hash->type == JSON_STR &&
             strcmp(json_get_str(tip_hash), hstar_hex) == 0 &&
             strcmp(json_get_str(tip_hash), active_hex) != 0;
        json_free(&result);
        json_free(&params);

        init_single_int_param(&params, 1);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getblockhash", &params,
                                     &result) &&
             result.type == JSON_STR &&
             strcmp(json_get_str(&result), hstar_hex) == 0;
        json_free(&result);
        json_free(&params);

        init_single_int_param(&params, 2);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "getblockhash", &params,
                                      &result);
        ok = ok && result.type == JSON_STR &&
             strcmp(json_get_str(&result), active_hex) != 0 &&
             strstr(json_get_str(&result), "out of range") != NULL;
        json_free(&result);
        json_free(&params);

        init_single_str_param(&params, hstar_hex);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getblockheader", &params,
                                     &result);
        const struct json_value *header_height = json_get(&result, "height");
        ok = ok && header_height && json_get_int(header_height) == 1;
        json_free(&result);
        json_free(&params);

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
        ok = ok && block_header_deserialize(&want_hdr, &hr);
        char want_merkle[65];
        char want_nonce[65];
        uint256_get_hex(&want_hdr.hashMerkleRoot, want_merkle);
        uint256_get_hex(&want_hdr.nNonce, want_nonce);
        if (blocks[1])
            blocks[1]->nBits = 0x1c7397b0;
        node_db_runtime_port_set(&rpc_safety_header_port);
        init_single_str_param(&params, hstar_hex);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getblockheader", &params,
                                     &result);
        const struct json_value *got_merkle = json_get(&result, "merkleroot");
        const struct json_value *got_nonce = json_get(&result, "nonce");
        const struct json_value *got_diff = json_get(&result, "difficulty");
        ok = ok && got_merkle && got_merkle->type == JSON_STR &&
             strcmp(json_get_str(got_merkle), want_merkle) == 0;
        ok = ok && got_nonce && got_nonce->type == JSON_STR &&
             strcmp(json_get_str(got_nonce), want_nonce) == 0;
        /* legacy zclassicd renders 1161125.834138388 for bits 0x1c7397b0
         * (oracle h=500000); allow 1e-9 relative for double formatting. */
        const double want_diff = 1161125.834138388;
        double diff_got = got_diff ? json_get_real(got_diff) : 0.0;
        double diff_rel = (diff_got - want_diff) / want_diff;
        if (diff_rel < 0) diff_rel = -diff_rel;
        ok = ok && got_diff && got_diff->type == JSON_REAL &&
             diff_rel < 1e-9;
        json_free(&result);
        json_free(&params);
        node_db_runtime_port_set(NULL);

        init_single_str_param(&params, active_hex);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "getblockheader", &params,
                                      &result);
        ok = ok && result.type == JSON_STR &&
             strstr(json_get_str(&result), "not found") != NULL;
        json_free(&result);
        json_free(&params);

        init_single_str_param(&params, hstar_hex);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "getblock", &params, &result) &&
             result.type == JSON_STR &&
             strstr(json_get_str(&result), "body unavailable") != NULL;
        json_free(&result);
        json_free(&params);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&health_tbl, "getsyncdetail", &params,
                                     &result);
        const struct json_value *chain = json_get(&result, "chain");
        const struct json_value *chain_height = json_get(chain, "height");
        const struct json_value *best_block = json_get(chain, "best_block");
        ok = ok && chain && chain_height && json_get_int(chain_height) == 1;
        ok = ok && best_block && best_block->type == JSON_STR &&
             strcmp(json_get_str(best_block), hstar_hex) == 0 &&
             strcmp(json_get_str(best_block), active_hex) != 0;
        json_free(&result);
        json_free(&params);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&health_tbl, "getsyncdiag", &params,
                                     &result);
        const struct json_value *diag_chain_height =
            json_get(&result, "chain_height");
        const struct json_value *diag_header_height =
            json_get(&result, "best_header_height");
        ok = ok && diag_chain_height &&
             json_get_int(diag_chain_height) == 1;
        ok = ok && diag_header_height &&
             json_get_int(diag_header_height) == 3;
        json_free(&result);
        json_free(&params);

        init_single_str_param(&params, active_hex);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "getblock", &params, &result);
        ok = ok && result.type == JSON_STR &&
             strstr(json_get_str(&result), "not found") != NULL;

        json_free(&params);
        json_free(&result);
        reducer_frontier_provable_tip_reset();
        rpc_health_set_state(NULL, NULL, NULL, NULL);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: getblockhash resolves sparse H* from node db... ");
    {
        test_reset_shared_globals();
        ensure_rpc_warmup_finished_once();

        struct main_state ms;
        struct block_index *blocks[3] = {0};
        struct node_db ndb;
        bool ndb_open = false;
        bool ok = rpc_safety_build_chain(&ms, blocks, 3);
        if (ok)
            ms.chain_active.chain[1] = NULL;
        ok = ok && node_db_open(&ndb, ":memory:");
        ndb_open = ok;
        ok = ok && rpc_safety_save_projected_block(&ndb, blocks[1]);

        rpc_blockchain_set_state(&ms, NULL, "/tmp");
        rpc_blockchain_set_node_db(&ndb);
        reducer_frontier_provable_tip_set(1);

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_blockchain_rpc_commands(&tbl);

        char hstar_hex[65] = {0};
        char active_hex[65] = {0};
        if (blocks[1] && blocks[1]->phashBlock)
            uint256_get_hex(blocks[1]->phashBlock, hstar_hex);
        if (blocks[2] && blocks[2]->phashBlock)
            uint256_get_hex(blocks[2]->phashBlock, active_hex);

        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_set_array(&params);
        json_init(&result);

        ok = ok && rpc_table_execute(&tbl, "getbestblockhash", &params,
                                     &result);
        ok = ok && result.type == JSON_STR &&
             strcmp(json_get_str(&result), hstar_hex) == 0 &&
             strcmp(json_get_str(&result), active_hex) != 0;
        json_free(&result);
        json_free(&params);

        init_single_int_param(&params, 1);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "getblockhash", &params,
                                     &result) &&
             result.type == JSON_STR &&
             strcmp(json_get_str(&result), hstar_hex) == 0 &&
             strcmp(json_get_str(&result), active_hex) != 0;
        json_free(&result);
        json_free(&params);

        init_single_int_param(&params, 2);
        json_init(&result);
        ok = ok && !rpc_table_execute(&tbl, "getblockhash", &params,
                                      &result);
        ok = ok && result.type == JSON_STR &&
             strstr(json_get_str(&result), "out of range") != NULL;

        json_free(&params);
        json_free(&result);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        rpc_blockchain_set_node_db(NULL);
        reducer_frontier_provable_tip_reset();
        if (ndb_open)
            node_db_close(&ndb);
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: gettxoutsetinfo reports coin frontier... ");
    {
        test_reset_shared_globals();
        ensure_rpc_warmup_finished_once();
        progress_store_close();

        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "rpc_safety", "coin_frontier");

        struct main_state ms;
        struct block_index *blocks[4] = {0};
        bool ok = rpc_safety_build_chain(&ms, blocks, 4);
        ok = ok && progress_store_open(dir);
        sqlite3 *db = progress_store_db();
        ok = ok && db && rpc_safety_seed_coin_frontier(db, blocks[1]);

        rpc_blockchain_set_state(&ms, NULL, "/tmp");

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_blockchain_rpc_commands(&tbl);

        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_set_array(&params);
        json_init(&result);

        ok = ok && rpc_table_execute(&tbl, "gettxoutsetinfo", &params,
                                     &result);
        const struct json_value *height = json_get(&result, "height");
        const struct json_value *bestblock = json_get(&result, "bestblock");
        const struct json_value *txs = json_get(&result, "transactions");
        const struct json_value *outs = json_get(&result, "txouts");
        char coin_hex[65] = {0};
        char active_hex[65] = {0};
        if (blocks[1] && blocks[1]->phashBlock)
            uint256_get_hex(blocks[1]->phashBlock, coin_hex);
        if (blocks[3] && blocks[3]->phashBlock)
            uint256_get_hex(blocks[3]->phashBlock, active_hex);
        ok = ok && height && json_get_int(height) == 1;
        ok = ok && bestblock && bestblock->type == JSON_STR &&
             strcmp(json_get_str(bestblock), coin_hex) == 0 &&
             strcmp(json_get_str(bestblock), active_hex) != 0;
        ok = ok && txs && json_get_int(txs) == 1;
        ok = ok && outs && json_get_int(outs) == 1;

        json_free(&params);
        json_free(&result);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: summary RPCs do not borrow unresolved active tip... ");
    {
        test_reset_shared_globals();
        ensure_rpc_warmup_finished_once();

        struct main_state ms;
        struct block_index *blocks[4] = {0};
        bool ok = rpc_safety_build_chain(&ms, blocks, 4);
        if (ok)
            ms.chain_active.chain[1] = NULL;
        reducer_frontier_provable_tip_set(1);

        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        cm.manager.num_nodes = 3;

        struct rpc_table chain_tbl;
        rpc_table_init(&chain_tbl);
        rpc_blockchain_set_state(&ms, NULL, "/tmp");
        register_blockchain_rpc_commands(&chain_tbl);

        struct rpc_table misc_tbl;
        rpc_table_init(&misc_tbl);
        rpc_misc_set_state(&ms);
        rpc_net_set_connman(&cm);
        register_misc_rpc_commands(&misc_tbl);

        struct rpc_table mining_tbl;
        rpc_table_init(&mining_tbl);
        rpc_mining_set_state(&ms, NULL, NULL);
        register_mining_rpc_commands(&mining_tbl);

        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_set_array(&params);
        json_init(&result);

        /* getblockchaininfo must NOT borrow the unresolved active tip
         * (height 3): with the H* slot unresolved it returns a valid
         * IBD-shaped object reporting the PROVABLE height (H* == 1) with
         * initialblockdownload=true. */
        ok = ok && rpc_table_execute(&chain_tbl, "getblockchaininfo",
                                     &params, &result);
        {
            const struct json_value *gbi_blocks = json_get(&result, "blocks");
            const struct json_value *gbi_ibd =
                json_get(&result, "initialblockdownload");
            ok = ok && gbi_blocks && json_get_int(gbi_blocks) == 1;
            ok = ok && gbi_ibd && json_get_bool(gbi_ibd);
        }
        json_free(&result);

        json_init(&result);
        ok = ok && rpc_table_execute(&misc_tbl, "getinfo", &params,
                                     &result);
        const struct json_value *info_blocks = json_get(&result, "blocks");
        const struct json_value *info_connections =
            json_get(&result, "connections");
        ok = ok && info_blocks && json_get_int(info_blocks) == 1;
        ok = ok && info_connections &&
             json_get_int(info_connections) == 3;
        json_free(&result);

        json_init(&result);
        ok = ok && rpc_table_execute(&mining_tbl, "getmininginfo", &params,
                                     &result);
        const struct json_value *mining_blocks = json_get(&result, "blocks");
        ok = ok && mining_blocks && json_get_int(mining_blocks) == 1;

        json_free(&params);
        json_free(&result);
        rpc_blockchain_set_state(NULL, NULL, NULL);
        rpc_misc_set_state(NULL);
        rpc_net_set_connman(NULL);
        rpc_mining_set_state(NULL, NULL, NULL);
        cm.manager.num_nodes = 0;
        net_manager_free(&cm.manager);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("rpc_safety: chainstate guard rejects unresolved active tip... ");
    {
        ensure_rpc_warmup_finished_once();

        struct main_state *ms = calloc(1, sizeof(*ms));
        struct coins_view_cache *coins_tip = calloc(1, sizeof(*coins_tip));
        struct wallet *wallet = calloc(1, sizeof(*wallet));
        struct node_db *ndb = calloc(1, sizeof(*ndb));
        struct rpc_table *rawtx_tbl = calloc(1, sizeof(*rawtx_tbl));
        struct rpc_table *inspect_tbl = calloc(1, sizeof(*inspect_tbl));
        struct rpc_table *wallet_diag_tbl = calloc(1, sizeof(*wallet_diag_tbl));
        struct rpc_table *wallet_rescan_tbl = calloc(1, sizeof(*wallet_rescan_tbl));
        struct rpc_table *repair_tbl = calloc(1, sizeof(*repair_tbl));

        bool ok = ms && coins_tip && wallet && ndb && rawtx_tbl &&
                  inspect_tbl && wallet_diag_tbl && wallet_rescan_tbl &&
                  repair_tbl;
        if (ok) {
            build_unresolved_tip_state(ms, 100);
            wallet_init(wallet);
            ndb->open = true;
        }

        if (!ok) {
            free(ms);
            free(coins_tip);
            free(wallet);
            free(ndb);
            free(rawtx_tbl);
            free(inspect_tbl);
            free(wallet_diag_tbl);
            free(wallet_rescan_tbl);
            free(repair_tbl);
            printf("FAIL\n");
            return failures + 1;
        }

        rpc_table_init(rawtx_tbl);
        rpc_rawtx_set_state(ms, NULL, coins_tip, "/tmp");
        register_rawtransaction_rpc_commands(rawtx_tbl);

        rpc_table_init(inspect_tbl);
        rpc_chain_inspect_set_state(ms, "/tmp", NULL, coins_tip, NULL);
        register_chain_inspect_rpc_commands(inspect_tbl);

        wallet_rpc_context_set_base(wallet, ms, "/tmp", NULL, NULL, NULL);
        wallet_rpc_context_set_node_db(NULL);
        wallet_rpc_context_set_coins_tip(coins_tip);

        rpc_table_init(wallet_diag_tbl);
        register_wallet_diagnostic_rpc_commands(wallet_diag_tbl);

        wallet_rpc_context_set_node_db(NULL);
        rpc_table_init(wallet_rescan_tbl);
        register_wallet_rescan_rpc_commands(wallet_rescan_tbl);

        rpc_table_init(repair_tbl);
        rpc_repair_set_state(ms, coins_tip, ndb, "/tmp",
                             chain_params_get());
        register_repair_rpc_commands(repair_tbl);
        register_backfill_header_solutions_rpc_commands(repair_tbl);

        struct json_value params = {0};
        struct json_value result = {0};

        init_single_str_param(
            &params,
            "0000000000000000000000000000000000000000000000000000000000000001");
        json_init(&result);
        ok = !rpc_table_execute(rawtx_tbl, "getrawtransaction", &params,
                                &result) &&
             result_is_chainstate_guard_error(&result, "getrawtransaction");
        json_free(&params);
        json_free(&result);

        init_single_str_param(
            &params,
            "0000000000000000000000000000000000000000000000000000000000000002");
        json_init(&result);
        ok = ok && !rpc_table_execute(inspect_tbl, "gettxdetail", &params,
                                      &result) &&
             result_is_chainstate_guard_error(&result, "gettxdetail");
        json_free(&params);
        json_free(&result);

        init_single_str_param(
            &params,
            "0000000000000000000000000000000000000000000000000000000000000003");
        json_init(&result);
        ok = ok && !rpc_table_execute(wallet_diag_tbl, "getchaincoins",
                                      &params, &result) &&
             result_is_chainstate_guard_error(&result, "getchaincoins");
        json_free(&params);
        json_free(&result);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && !rpc_table_execute(wallet_rescan_tbl, "syncwalletfromdb",
                                      &params, &result) &&
             result_is_chainstate_guard_error(&result, "syncwalletfromdb");
        json_free(&params);
        json_free(&result);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && !rpc_table_execute(repair_tbl, "repairutxos", &params,
                                      &result) &&
             result_is_chainstate_guard_error(&result, "repairutxos");
        json_free(&params);
        json_free(&result);

        main_state_free(ms);
        wallet_free(wallet);
        free(ms);
        free(coins_tip);
        free(wallet);
        free(ndb);
        free(rawtx_tbl);
        free(inspect_tbl);
        free(wallet_diag_tbl);
        free(wallet_rescan_tbl);
        free(repair_tbl);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

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

    printf("rpc_safety: raw-sign P2SH 2-of-2 emits both signatures... ");
    {
        struct basic_keystore *ks = calloc(1, sizeof(*ks));
        struct rpc_table *tbl = calloc(1, sizeof(*tbl));
        struct privkey keys[2] = {0};
        bool ok = ks && tbl;
        if (ok) {
            keystore_init(ks);
            rpc_table_init(tbl);
            rpc_rawtx_set_state(NULL, NULL, NULL, "/tmp");
            rpc_rawtx_set_keystore(ks);
            register_rawtransaction_rpc_commands(tbl);

            struct pubkey pubs[2];
            for (size_t i = 0; i < 2 && ok; i++) {
                privkey_make_new(&keys[i], true);
                ok = privkey_get_pubkey(&keys[i], &pubs[i]) &&
                     keystore_add_key(ks, &keys[i]);
            }
            struct script redeem = {0}, p2sh = {0};
            script_for_multisig(&redeem, 2, pubs, 2);
            struct script_id redeem_id;
            script_id_from_script(&redeem_id, &redeem);
            script_for_p2sh(&p2sh, &redeem_id);

            struct transaction tx;
            transaction_init(&tx);
            tx.overwintered = true;
            tx.version = SAPLING_TX_VERSION;
            tx.version_group_id = SAPLING_VERSION_GROUP_ID;
            tx.vin = calloc(1, sizeof(*tx.vin));
            tx.vout = calloc(1, sizeof(*tx.vout));
            ok = ok && tx.vin && tx.vout;
            if (ok) {
                tx.num_vin = 1;
                tx.vin[0].prevout.n = 0;
                tx.vin[0].sequence = UINT32_MAX;
                tx.num_vout = 1;
                tx.vout[0].value = 1000;
                struct key_id recipient = {0};
                script_for_p2pkh(&tx.vout[0].script_pub_key, &recipient);
            }
            char tx_hex[2048] = {0};
            size_t tx_hex_len = ok ?
                encode_hex_tx(&tx, tx_hex, sizeof(tx_hex)) : 0;
            ok = ok && tx_hex_len > 0 && tx_hex_len < sizeof(tx_hex);
            transaction_free(&tx);

            char p2sh_hex[2 * MAX_SCRIPT_SIZE + 1];
            char redeem_hex[2 * MAX_SCRIPT_SIZE + 1];
            zcl_hex_encode(p2sh.data, p2sh.size, p2sh_hex);
            zcl_hex_encode(redeem.data, redeem.size, redeem_hex);

            struct json_value params, prevs, prev, value, result;
            json_init(&params); json_set_array(&params);
            json_init(&value); json_set_str(&value, tx_hex);
            json_push_back(&params, &value); json_free(&value);
            json_init(&prevs); json_set_array(&prevs);
            json_init(&prev); json_set_object(&prev);
            json_push_kv_str(&prev, "txid",
                "0000000000000000000000000000000000000000000000000000000000000000");
            json_push_kv_int(&prev, "vout", 0);
            json_push_kv_str(&prev, "scriptPubKey", p2sh_hex);
            json_push_kv_real(&prev, "amount", 0.00022);
            json_push_kv_str(&prev, "redeemScript", redeem_hex);
            json_push_back(&prevs, &prev); json_free(&prev);
            json_push_back(&params, &prevs); json_free(&prevs);
            json_init(&result);

            ok = ok && rpc_table_execute(tbl, "signrawtransaction", &params,
                                         &result) &&
                 json_get_bool(json_get(&result, "complete"));
            const char *signed_hex = json_get_str(json_get(&result, "hex"));
            struct transaction signed_tx;
            transaction_init(&signed_tx);
            ok = ok && signed_hex && decode_hex_tx(&signed_tx, signed_hex) &&
                 signed_tx.num_vin == 1;
            if (ok) {
                const struct script *ss = &signed_tx.vin[0].script_sig;
                size_t pos = 0;
                ok = ss->size > redeem.size + 4 &&
                     ss->data[pos++] == OP_0;
                for (size_t i = 0; i < 2 && ok; i++) {
                    size_t sig_len = ss->data[pos++];
                    ok = sig_len >= 70 && sig_len <= SIGNATURE_SIZE + 1 &&
                         pos + sig_len <= ss->size;
                    pos += sig_len;
                }
                ok = ok && pos < ss->size &&
                     ss->data[pos++] == redeem.size &&
                     pos + redeem.size == ss->size &&
                     memcmp(ss->data + pos, redeem.data, redeem.size) == 0;
            }
            transaction_free(&signed_tx);
            json_free(&params);
            json_free(&result);
            rpc_rawtx_set_keystore(NULL);
            keystore_free(ks);
        }
        for (size_t i = 0; i < 2; i++)
            memory_cleanse(keys[i].vch, sizeof(keys[i].vch));
        free(ks);
        free(tbl);
        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    /* parse_amount arithmetic guards: see rs_check_parse_amount_guards. */
    failures += rs_check_parse_amount_guards();
    failures += rs_unlock_timeout_width();

    return failures;
}
