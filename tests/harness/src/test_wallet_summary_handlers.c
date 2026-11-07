/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The walletsummary, wallethistory and walletlatestaddress RPC handlers
 * driven end to end over an isolated node.db and progress store: locked boot,
 * failed reads, unknown tip, witness and spent-set state, memo detail and the
 * log lines they write. No wallet file, key, node or network is involved. */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "controllers/wallet_activity.h"
#include "controllers/wallet_helpers.h"
#include "controllers/network_controller.h"
#include "controllers/wallet_shielded_internal.h"
#include "net/connman.h"
#include "net/net.h"
#include "chain/chainparams.h"
#include "validation/main_state.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/wallet_tx.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "test/wallet_summary_fixture.h"
#include "wallet/wallet.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZCL1 100000000LL
#define FEE 10000LL
#define TIP 300
#define MEMO_TEXT "hello memo for the owner only"
#define ADDRESS_TEXT "zs1testaddressnotforlogs"

static uint8_t g_ivk[32];
static uint8_t g_ivk2[32];

struct rig {
    struct wallet *wallet;
    struct node_db ndb;
    char dir[256];
    struct wallet_sqlite ws;
};

static bool rig_key(struct rig *r, bool present)
{
    struct sapling_keystore *ks = &r->wallet->sapling_keys;
    memset(&ks->keys[0], 0, sizeof(ks->keys[0]));
    memcpy(ks->keys[0].ivk, g_ivk, 32);
    ks->keys[0].used = present;
    ks->num_keys = present ? 1 : 0;
    return true;
}

static bool rig_open_state(struct rig *r, bool with_block, bool ready)
{
    char path[320];
    memset(r, 0, sizeof(*r));
    test_make_tmpdir(r->dir, sizeof(r->dir), "wallet_summary_handlers", "rig");
    snprintf(path, sizeof(path), "%s/node.db", r->dir);
    if (!node_db_open(&r->ndb, path) || !progress_store_open(r->dir))
        return false;
    if (!wallet_sqlite_open_r(&r->ws, r->ndb.db).ok)
        return false;
    if (!nullifier_kv_initialize_history(progress_store_db(), 0))
        return false;
    if (with_block && !wsh_put_block(&r->ndb, TIP))
        return false;
    r->wallet = zcl_calloc(1, sizeof(*r->wallet), "test-wallet");
    if (!r->wallet)
        return false;
    wallet_init(r->wallet);
    if (ready && !wallet_readiness_initialize(r->wallet, WALLET_READINESS_READY, false, 0))
        return false;
    rig_key(r, true);
    wallet_lock_reset_for_test();
    wallet_rpc_context_set_base(r->wallet, NULL, r->dir, &r->ws, NULL, NULL);
    wallet_rpc_context_set_node_db(&r->ndb);
    reducer_frontier_provable_tip_set(TIP);
    return true;
}

static bool rig_open(struct rig *r, bool with_block)
{
    return rig_open_state(r, with_block, true);
}

static void rig_close(struct rig *r)
{
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    reducer_frontier_provable_tip_reset();
    wallet_lock_reset_for_test();
    if (r->wallet) {
        wallet_free(r->wallet);
        free(r->wallet);
    }
    wallet_sqlite_close(&r->ws);
    progress_store_close();
    node_db_close(&r->ndb);
    (void)test_rm_rf_recursive(r->dir);
}

/* A witness for note (tx, 0) as of `height`. */
static bool save_witness(struct node_db *ndb, uint8_t tx, int height)
{
    struct incremental_merkle_tree t;
    struct incremental_witness w;
    struct uint256 leaf;
    struct byte_stream s;
    uint8_t txid[32];
    sapling_tree_init(&t);
    memset(&leaf, tx, sizeof(leaf));
    incremental_tree_append(&t, &leaf);
    incremental_witness_init(&w, &t);
    stream_init(&s, 8192);
    memset(txid, tx, sizeof(txid));
    bool ok = incremental_witness_serialize(&w, &s) &&
              db_sapling_note_save_witness(ndb, txid, 0, s.data, s.size,
                                           height);
    stream_free(&s);
    return ok;
}

/* 0x61 ready, 0x62 no witness, 0x63 stale witness, 0x64 spent on the chain,
 * 0x65 below its threshold. */
static bool rig_notes(struct rig *r)
{
    struct node_db *n = &r->ndb;
    uint8_t nf[32];
    bool ok = wsh_put_note(n, 0x61, 0, g_ivk, 5 * ZCL1, 280, NULL);
    ok = ok && wsh_put_note(n, 0x62, 0, g_ivk, 3 * ZCL1, 270, NULL);
    ok = ok && wsh_put_note(n, 0x63, 0, g_ivk, 2 * ZCL1, 260, NULL);
    ok = ok && wsh_put_note(n, 0x64, 0, g_ivk, 7 * ZCL1, 250, NULL);
    ok = ok && wsh_put_note(n, 0x65, 0, g_ivk, 1 * ZCL1, 299, NULL);
    ok = ok && save_witness(n, 0x61, TIP) && save_witness(n, 0x63, TIP - 1);
    ok = ok && save_witness(n, 0x64, TIP);
    wsh_note_nullifier(0x64, 0, nf);
    return ok && nullifier_kv_add(progress_store_db(), nf,
                                  NULLIFIER_POOL_SAPLING, 290);
}

static void call_summary(struct json_value *out, bool *ok)
{
    struct json_value p;
    json_init(&p);
    json_set_array(&p);
    json_init(out);
    *ok = rpc_walletsummary(&p, false, out);
    json_free(&p);
}

static void call_history(struct json_value *out, bool *ok, const char *cursor,
                         const char *txid)
{
    struct json_value p, v;
    json_init(&p);
    json_set_array(&p);
    json_init(&v);
    json_set_int(&v, 10);
    json_push_back(&p, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, cursor);
    json_push_back(&p, &v);
    json_free(&v);
    json_init(&v);
    json_set_str(&v, txid);
    json_push_back(&p, &v);
    json_free(&v);
    json_init(out);
    *ok = rpc_wallethistory(&p, false, out);
    json_free(&p);
}

static int64_t field(const struct json_value *j, const char *key)
{
    return json_get_int(json_get(j, key));
}

static bool is_null(const struct json_value *j, const char *key)
{
    const struct json_value *v = json_get(j, key);
    return v && v->type == JSON_NULL;
}

static int abort_every_query(void *unused)
{
    (void)unused;
    return 1;
}

static int test_summary_matches_send(struct rig *r)
{
    int failures = 0;
    TEST_CASE("walletsummary: spendable is what send would accept") {
        struct json_value j;
        bool ok;
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")), "ok");
        ASSERT_EQ(field(&j, "spendable_zat"), 5 * ZCL1);
        ASSERT_EQ(field(&j, "unready_zat"), 5 * ZCL1);
        ASSERT_EQ(field(&j, "unready_notes"), 2);
        ASSERT_EQ(field(&j, "reconciling_notes"), 1);
        ASSERT_EQ(field(&j, "pending_zat"), 1 * ZCL1);
        ASSERT_EQ(field(&j, "tip_height"), TIP);
        ASSERT(!json_get_bool(json_get(&j, "locked")));
        ASSERT(!json_get_bool(json_get(&j, "current")));
        json_free(&j);
        (void)r;
    } TEST_END
    return failures;
}

static int test_locked_boot(struct rig *r)
{
    int failures = 0;
    TEST_CASE("locked boot: shielded amounts are unknown, never zero") {
        struct json_value j;
        bool ok;
        rig_key(r, false);
        wallet_lock_note_encrypted_at_rest();
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")),
                      "keys_unavailable");
        ASSERT(is_null(&j, "spendable_zat"));
        ASSERT(is_null(&j, "pending_zat"));
        ASSERT(is_null(&j, "unready_zat"));
        ASSERT(json_get_bool(json_get(&j, "locked")));
        ASSERT(!json_get_bool(json_get(&j, "current")));
        json_free(&j);
        call_history(&j, &ok, "", "");
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")),
                      "keys_unavailable");
        json_free(&j);
        struct json_value p;
        json_init(&p);
        json_init(&j);
        ASSERT(rpc_walletlatestaddress(&p, false, &j));
        ASSERT(is_null(&j, "address"));
        ASSERT_STR_EQ(json_get_str(json_get(&j, "state")), "keys_unavailable");
        json_free(&j);
        wallet_lock_reset_for_test();
        rig_key(r, true);
    } TEST_END
    return failures;
}

/* wallet_lock_unlock marks the wallet unlocked before it reloads the Sapling
 * keys. In that window the keystore is empty although key rows exist. */
static int test_unlock_window(void)
{
    int failures = 0;
    TEST_CASE("unlock window: unloaded Sapling keys read as unknown, not zero") {
        struct rig r;
        struct json_value j, p;
        bool ok;
        ASSERT(rig_open(&r, true));
        rig_key(&r, false);
        json_init(&p);
        /* No wallet database: the key rows cannot be counted, so unknown. */
        wallet_rpc_context_set_base(r.wallet, NULL, r.dir, NULL, NULL, NULL);
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")),
                      "keys_unavailable");
        json_free(&j);
        wallet_rpc_context_set_base(r.wallet, NULL, r.dir, &r.ws, NULL, NULL);
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")), "ok");
        ASSERT(!is_null(&j, "spendable_zat"));
        json_free(&j);
        json_init(&j);
        ASSERT(rpc_walletlatestaddress(&p, false, &j));
        ASSERT_STR_EQ(json_get_str(json_get(&j, "state")), "none");
        json_free(&j);
        struct sapling_key_entry e;
        memset(&e, 0, sizeof(e));
        memcpy(e.ivk, g_ivk, 32);
        e.used = true;
        ASSERT(wallet_sqlite_write_sapling_key(&r.ws, 0, &e));
        ASSERT(wallet_sqlite_sapling_key_count(&r.ws) == 1);
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")),
                      "keys_unavailable");
        ASSERT(is_null(&j, "spendable_zat"));
        ASSERT(is_null(&j, "spendable_total_zat"));
        ASSERT(!json_get_bool(json_get(&j, "current")));
        json_free(&j);
        json_init(&j);
        ASSERT(rpc_walletlatestaddress(&p, false, &j));
        ASSERT(is_null(&j, "address"));
        ASSERT_STR_EQ(json_get_str(json_get(&j, "state")), "keys_unavailable");
        json_free(&j);
        rig_key(&r, true);
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")), "ok");
        json_free(&j);
        /* A key count that cannot be read is unknown too. */
        rig_key(&r, false);
        r.ws.open = false;
        ASSERT(wallet_sqlite_sapling_key_count(&r.ws) < 0);
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")),
                      "keys_unavailable");
        json_free(&j);
        r.ws.open = true;
        json_free(&p);
        rig_close(&r);
    } TEST_END
    return failures;
}

static int test_failed_reads(struct rig *r)
{
    int failures = 0;
    TEST_CASE("handlers: a failed read or allocation fails the command") {
        struct json_value j;
        bool ok;
        sqlite3_progress_handler(r->ndb.db, 1, abort_every_query, NULL);
        call_summary(&j, &ok);
        ASSERT(!ok);
        json_free(&j);
        call_history(&j, &ok, "", "");
        ASSERT(!ok);
        json_free(&j);
        sqlite3_progress_handler(r->ndb.db, 0, NULL, NULL);
        zcl_alloc_fault_fail_next("wallet spenders");
        call_summary(&j, &ok);
        ASSERT(!ok);
        json_free(&j);
        zcl_alloc_fault_fail_next("wallet ivk copy");
        call_history(&j, &ok, "", "");
        ASSERT(!ok);
        json_free(&j);
        zcl_alloc_fault_clear();
        call_summary(&j, &ok);
        ASSERT(ok);
        json_free(&j);
    } TEST_END
    return failures;
}

static int test_unknown_tip(void)
{
    int failures = 0;
    TEST_CASE("handlers: an unknown chain tip fails the command") {
        struct rig empty;
        struct json_value j;
        bool ok;
        ASSERT(rig_open(&empty, false));
        call_summary(&j, &ok);
        ASSERT(!ok);
        json_free(&j);
        call_history(&j, &ok, "", "");
        ASSERT(!ok);
        json_free(&j);
        rig_close(&empty);
    } TEST_END
    return failures;
}

static bool detail_fixture(struct rig *r)
{
    bool ok = wsh_put_note(&r->ndb, 0x66, 0, g_ivk, 250000000LL, 200, NULL);
    ok = ok && wsh_put_note(&r->ndb, 0x66, 1, g_ivk, 350000000LL, 200, MEMO_TEXT);
    return ok && sqlite3_exec(r->ndb.db,
        "UPDATE wallet_sapling_notes SET address='" ADDRESS_TEXT "' "
        "WHERE value IN (250000000, 350000000)", NULL, NULL, NULL) == SQLITE_OK;
}

static size_t count_of(const char *hay, const char *needle)
{
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)); p += strlen(needle))
        n++;
    return n;
}

static int test_memo_detail(struct rig *r)
{
    int failures = 0;
    TEST_CASE("wallethistory: memo and address only in detail, address once") {
        struct json_value j;
        char text[4096];
        bool ok;
        ASSERT(detail_fixture(r));
        call_history(&j, &ok, "", "");
        ASSERT(ok);
        ASSERT(json_write(&j, text, sizeof(text)) > 0);
        ASSERT(strstr(text, "hello") == NULL && strstr(text, "zs1") == NULL);
        json_free(&j);
        call_history(&j, &ok, "",
            "6666666666666666666666666666666666666666666666666666666666666666");
        ASSERT(ok);
        ASSERT(json_write(&j, text, sizeof(text)) > 0);
        ASSERT(strstr(text, MEMO_TEXT) != NULL);
        ASSERT_EQ(count_of(text, "\"address\""), 1);
        json_free(&j);
    } TEST_END
    return failures;
}

/* Sends whose stored transaction gives the fee: a z-to-z with change. */
static bool serialized_zz(uint8_t **raw, size_t *len)
{
    struct transaction tx;
    struct byte_stream s;
    transaction_init(&tx);
    tx.overwintered = true;
    tx.version = SAPLING_TX_VERSION;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.value_balance = FEE;
    stream_init(&s, 1024);
    bool ok = transaction_serialize(&tx, &s);
    *raw = ok ? zcl_malloc(s.size, "test raw tx") : NULL;
    ok = ok && *raw;
    if (ok) {
        memcpy(*raw, s.data, s.size);
        *len = s.size;
    }
    stream_free(&s);
    transaction_free(&tx);
    return ok;
}

static int test_sent_amount_from_stored_tx(struct rig *r)
{
    int failures = 0;
    TEST_CASE("wallethistory: a z-to-z send recovers amount from its tx") {
        struct db_wallet_tx t;
        struct json_value j;
        bool ok;
        memset(&t, 0, sizeof(t));
        ASSERT(wsh_put_note(&r->ndb, 0x50, 0, g_ivk, 10 * ZCL1, 200, NULL));
        ASSERT(wsh_spend_note(&r->ndb, 0x50, 0, 0x53));
        ASSERT(wsh_put_note(&r->ndb, 0x53, 0, g_ivk, 5 * ZCL1 - FEE, 211,
                            NULL));
        ASSERT(serialized_zz(&t.raw_tx, &t.raw_tx_len));
        memset(t.txid, 0x53, 32);
        t.has_block = true;
        t.block_height = 211;
        memset(t.block_hash, 0x40, 32);
        t.time_received = 1700000211;
        t.from_me = true;
        ASSERT(db_wallet_tx_save(&r->ndb, &t));
        free(t.raw_tx);
        call_history(&j, &ok, "",
            "5353535353535353535353535353535353535353535353535353535353535353");
        ASSERT(ok);
        const struct json_value *e = json_get(&j, "entry");
        ASSERT_STR_EQ(json_get_str(json_get(e, "direction")), "sent");
        ASSERT_STR_EQ(json_get_str(json_get(e, "kind")), "private");
        ASSERT_EQ(field(e, "amount_zat"), 5 * ZCL1);
        ASSERT_EQ(field(e, "fee_zat"), FEE);
        json_free(&j);
    } TEST_END
    return failures;
}

static int test_received_privacy_from_stored_tx(struct rig *r)
{
    int failures = 0;
    TEST_CASE("wallethistory: a received payment is private from its stored tx") {
        struct db_wallet_tx t;
        struct json_value j;
        bool ok;
        memset(&t, 0, sizeof(t));
        ASSERT(wsh_put_note(&r->ndb, 0x54, 0, g_ivk, 4 * ZCL1, 211, NULL));
        ASSERT(serialized_zz(&t.raw_tx, &t.raw_tx_len));
        memset(t.txid, 0x54, 32);
        t.has_block = true;
        t.block_height = 211;
        memset(t.block_hash, 0x40, 32);
        t.time_received = 1700000211;
        t.from_me = false;
        ASSERT(db_wallet_tx_save(&r->ndb, &t));
        free(t.raw_tx);
        call_history(&j, &ok, "",
            "5454545454545454545454545454545454545454545454545454545454545454");
        ASSERT(ok);
        const struct json_value *e = json_get(&j, "entry");
        ASSERT_STR_EQ(json_get_str(json_get(e, "direction")), "received");
        ASSERT_STR_EQ(json_get_str(json_get(e, "kind")), "private");
        ASSERT(json_get_bool(json_get(e, "fully_shielded")));
        json_free(&j);
    } TEST_END
    return failures;
}

/* Everything a log line must never carry: amounts, ids, addresses, memos. */
static int test_log_hygiene(const char *log)
{
    int failures = 0;
    TEST_CASE("handlers: no log line carries wallet data") {
        ASSERT(strlen(log) > 0);
        static const char *const secret[] = {
            MEMO_TEXT, ADDRESS_TEXT, "500000000", "5.00000000",
            "6161616161616161", "a1a1a1a1a1a1a1a1", "6666666666666666",
            "5353535353535353", "wallet_spend refused",
        };
        for (size_t i = 0; i < sizeof(secret) / sizeof(secret[0]); i++) {
            if (strstr(log, secret[i]))
                printf("\n  log carries: %s\n", secret[i]);
            ASSERT(strstr(log, secret[i]) == NULL);
        }
    } TEST_END
    return failures;
}

/* One native-path send of `amount` from key `key`, as z_sendmany runs it. The
 * result string explains a refusal. min_conf is the optional z_sendmany
 * minconf, an extra floor over the summary's own depth. */
static void send_try(struct rig *r, size_t key, int64_t amount, int min_conf,
                     struct json_value *res)
{
    struct main_state *ms = zcl_calloc(1, sizeof(*ms), "test main state");
    json_init(res);
    wallet_rpc_context_set_base(r->wallet, ms, r->dir, &r->ws, NULL, NULL);
    (void)z_sendmany_shielded(wallet_ctx(), chain_params_get(),
                              &r->wallet->sapling_keys.keys[key], amount,
                              NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, 0,
                              min_conf, NULL, res, -1);
    wallet_rpc_context_set_base(r->wallet, NULL, r->dir, &r->ws, NULL, NULL);
    free(ms);
}

static bool refused_insufficient(const struct json_value *res)
{
    const char *s = json_get_str(res);
    return s && strcmp(s, "Insufficient shielded funds") == 0;
}

static bool rig_two_keys(struct rig *r)
{
    struct sapling_keystore *ks = &r->wallet->sapling_keys;
    memset(&ks->keys[1], 0, sizeof(ks->keys[1]));
    memcpy(ks->keys[1].ivk, g_ivk2, 32);
    ks->keys[1].used = true;
    ks->num_keys = 2;
    return true;
}

/* (a) A ready 1 ZCL note beside a 2 ZCL note whose witness is stale. */
static int test_send_skips_unready_note(void)
{
    int failures = 0;
    TEST_CASE("send: a note the summary calls unready is skipped") {
        struct rig r;
        struct json_value j, res;
        bool ok;
        ASSERT(rig_open(&r, true));
        ASSERT(wsh_put_note(&r.ndb, 0x71, 0, g_ivk, 1 * ZCL1, 280, NULL));
        ASSERT(wsh_put_note(&r.ndb, 0x72, 0, g_ivk, 2 * ZCL1, 270, NULL));
        ASSERT(save_witness(&r.ndb, 0x71, TIP) &&
               save_witness(&r.ndb, 0x72, TIP - 1));
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_EQ(field(&j, "spendable_zat"), 1 * ZCL1);
        ASSERT_EQ(field(&j, "unready_zat"), 2 * ZCL1);
        json_free(&j);
        /* 1.5 ZCL needs the stale note: refused, not "Witness stale". */
        send_try(&r, 0, ZCL1 + ZCL1 / 2, 0, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        /* An explicit minconf never lifts the rule. */
        send_try(&r, 0, ZCL1 + ZCL1 / 2, 1, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        rig_close(&r);
    } TEST_END
    return failures;
}

/* (b) Two keys each hold a ready 1 ZCL note: one send spends from one key. */
static int test_send_spends_one_key(void)
{
    int failures = 0;
    TEST_CASE("send: spendable is the largest single-key amount") {
        struct rig r;
        struct json_value j, res;
        bool ok;
        ASSERT(rig_open(&r, true));
        rig_two_keys(&r);
        ASSERT(wsh_put_note(&r.ndb, 0x73, 0, g_ivk, 1 * ZCL1, 280, NULL));
        ASSERT(wsh_put_note(&r.ndb, 0x74, 0, g_ivk2, 1 * ZCL1, 280, NULL));
        ASSERT(save_witness(&r.ndb, 0x73, TIP) &&
               save_witness(&r.ndb, 0x74, TIP));
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_EQ(field(&j, "spendable_zat"), 1 * ZCL1);
        ASSERT_EQ(field(&j, "spendable_total_zat"), 2 * ZCL1);
        json_free(&j);
        send_try(&r, 0, ZCL1 + ZCL1 / 2, 0, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        send_try(&r, 1, ZCL1 + ZCL1 / 2, 0, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        rig_close(&r);
    } TEST_END
    return failures;
}

/* (c) A 5 ZCL received note with 2 confirmations is pending, so send does not
 * spend it either. */
static int test_send_waits_for_depth(void)
{
    int failures = 0;
    TEST_CASE("send: a pending note is not spent") {
        struct rig r;
        struct json_value j, res;
        bool ok;
        ASSERT(rig_open(&r, true));
        ASSERT(wsh_put_note(&r.ndb, 0x75, 0, g_ivk, 5 * ZCL1, TIP - 1, NULL));
        ASSERT(save_witness(&r.ndb, 0x75, TIP));
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_EQ(field(&j, "spendable_zat"), 0);
        ASSERT_EQ(field(&j, "pending_zat"), 5 * ZCL1);
        json_free(&j);
        send_try(&r, 0, ZCL1, 0, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        send_try(&r, 0, ZCL1, 10, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        rig_close(&r);
    } TEST_END
    return failures;
}

static int test_send_minconf_param(void)
{
    int failures = 0;
    TEST_CASE("send: minconf is an optional non-negative integer") {
        struct json_value p, v;
        int mc = -1;
        json_init(&p);
        json_set_array(&p);
        for (int i = 0; i < 2; i++) {
            json_init(&v);
            json_set_int(&v, i);
            json_push_back(&p, &v);
            json_free(&v);
        }
        ASSERT(z_sendmany_minconf(&p, &mc) && mc == 0);
        json_init(&v);
        json_set_int(&v, 25);
        json_push_back(&p, &v);
        json_free(&v);
        ASSERT(z_sendmany_minconf(&p, &mc) && mc == 25);
        json_free(&p);
        json_init(&p);
        json_set_array(&p);
        for (int i = 0; i < 3; i++) {
            json_init(&v);
            json_set_int(&v, i == 2 ? -1 : i);
            json_push_back(&p, &v);
            json_free(&v);
        }
        ASSERT(!z_sendmany_minconf(&p, &mc) && mc == -1);
        json_free(&p);
    } TEST_END
    return failures;
}

/* A negative minconf is refused before any note is chosen, even when a ready
 * note would cover the amount. */
static int test_send_negative_minconf(void)
{
    int failures = 0;
    TEST_CASE("send: a negative minconf replies Invalid minconf") {
        struct rig r;
        struct json_value res;
        ASSERT(rig_open(&r, true));
        ASSERT(wsh_put_note(&r.ndb, 0x77, 0, g_ivk, 5 * ZCL1, TIP - 20, NULL));
        ASSERT(save_witness(&r.ndb, 0x77, TIP));
        send_try(&r, 0, ZCL1, -1, &res);
        ASSERT_STR_EQ(json_get_str(&res), "Invalid minconf");
        json_free(&res);
        rig_close(&r);
    } TEST_END
    return failures;
}

/* minconf is an extra floor: a ready 21-confirmation note passes minconf 21
 * and fails minconf 22. */
static int test_send_minconf_floor(void)
{
    int failures = 0;
    TEST_CASE("send: minconf adds a floor above the summary rule") {
        struct rig r;
        struct json_value res;
        ASSERT(rig_open(&r, true));
        ASSERT(wsh_put_note(&r.ndb, 0x76, 0, g_ivk, 5 * ZCL1, TIP - 20, NULL));
        ASSERT(save_witness(&r.ndb, 0x76, TIP));
        send_try(&r, 0, ZCL1, 21, &res);
        ASSERT(!refused_insufficient(&res));
        json_free(&res);
        send_try(&r, 0, ZCL1, 22, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        rig_close(&r);
    } TEST_END
    return failures;
}

/* The per-send cap applies to spendable notes: 100 unready 1 ZCL notes beside
 * 300 ready 0.1 ZCL notes leave a cap's worth of ready notes, 25.6 ZCL. */
static bool save_witness_at(struct node_db *ndb, uint8_t tx, uint32_t idx,
                            int height)
{
    struct incremental_merkle_tree t;
    struct incremental_witness w;
    struct uint256 leaf;
    struct byte_stream s;
    uint8_t txid[32];
    sapling_tree_init(&t);
    memset(&leaf, tx, sizeof(leaf));
    incremental_tree_append(&t, &leaf);
    incremental_witness_init(&w, &t);
    stream_init(&s, 8192);
    memset(txid, tx, sizeof(txid));
    bool ok = incremental_witness_serialize(&w, &s) &&
              db_sapling_note_save_witness(ndb, txid, idx, s.data, s.size,
                                           height);
    stream_free(&s);
    return ok;
}

static int test_send_cap_after_filter(void)
{
    int failures = 0;
    TEST_CASE("send: the note cap counts spendable notes only") {
        struct rig r;
        struct json_value j, res;
        bool ok;
        ASSERT(rig_open(&r, true));
        for (uint32_t i = 0; i < 100; i++)
            ASSERT(wsh_put_note(&r.ndb, 0x91, i, g_ivk, 1 * ZCL1, 270, NULL));
        for (uint32_t i = 0; i < 300; i++) {
            uint8_t tx = (uint8_t)(0x92 + i / 150);
            uint32_t idx = i % 150;
            ASSERT(wsh_put_note(&r.ndb, tx, idx, g_ivk, ZCL1 / 10, 270, NULL));
            ASSERT(save_witness_at(&r.ndb, tx, idx, TIP));
        }
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_EQ(field(&j, "spendable_zat"), 256 * (ZCL1 / 10));
        ASSERT_EQ(field(&j, "spendable_total_zat"), 300 * (ZCL1 / 10));
        ASSERT_EQ(field(&j, "unready_notes"), 100);
        json_free(&j);
        send_try(&r, 0, 26 * ZCL1, 0, &res);
        ASSERT(refused_insufficient(&res));
        json_free(&res);
        send_try(&r, 0, 25 * ZCL1, 0, &res);
        ASSERT(!refused_insufficient(&res));
        json_free(&res);
        rig_close(&r);
    } TEST_END
    return failures;
}

/* The summary reports the peers past the handshake, not every connection. */
static int test_summary_peer_count(void)
{
    int failures = 0;
    TEST_CASE("walletsummary: peer_count counts handshaked peers") {
        struct rig r;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node;
        struct json_value j;
        bool ok;
        ASSERT(rig_open(&r, true));
        memset(&cm, 0, sizeof(cm));
        memset(&addr, 0, sizeof(addr));
        net_manager_init(&cm.manager);
        cm.manager.nodes = zcl_calloc(1, sizeof(*cm.manager.nodes), "nodes");
        ASSERT(cm.manager.nodes != NULL);
        node = p2p_node_create(&cm.manager, ZCL_INVALID_SOCKET, &addr, "p",
                               false);
        ASSERT(node != NULL);
        node->state = PEER_HANDSHAKE_COMPLETE;
        node->services = NODE_NETWORK;
        cm.manager.nodes[0] = node;
        cm.manager.num_nodes = 1;
        rpc_net_set_connman(&cm);
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_EQ(field(&j, "peer_count"), 1);
        json_free(&j);
        node->state = PEER_VERSION_SENT;
        call_summary(&j, &ok);
        ASSERT(ok);
        ASSERT_EQ(field(&j, "peer_count"), 0);
        json_free(&j);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        rig_close(&r);
    } TEST_END
    return failures;
}

/* 1 true, 0 false, -1 null, -2 absent or another type. */
static int held(const struct json_value *j, const char *key)
{
    const struct json_value *v = json_get(j, key);
    if (v && v->type == JSON_BOOL)
        return json_get_bool(v) ? 1 : 0;
    return v && v->type == JSON_NULL ? -1 : -2;
}

static bool holdings_are(int seed, int keys)
{
    struct json_value j;
    bool ok;
    call_summary(&j, &ok);
    bool match = ok && held(&j, "seed_present") == seed &&
                 held(&j, "keys_present") == keys;
    json_free(&j);
    return match;
}

/* An encrypted seed row, written under a passphrase that is then forgotten,
 * with the wallet locked as a boot without the passphrase leaves it. */
static bool rig_locked_seed(struct rig *r, const uint8_t seed[32])
{
    if (!wallet_lock_unlock(NULL, NULL, "summary-holdings-pass").ok ||
        !wallet_sqlite_write_sapling_seed(&r->ws, seed))
        return false;
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    return wallet_sqlite_sapling_seed_state(&r->ws, NULL) ==
           WALLET_SEED_LOCKED;
}

/* One key row stored by insert, with no key loaded, as a locked wallet that
 * kept no viewing key leaves it: keys_present is true and seed_present
 * false. remove deletes the row after. */
static bool stored_key_counts(struct rig *r, const char *insert,
                              const char *remove)
{
    sqlite3 *db = r->ndb.db;
    bool held = sqlite3_exec(db, insert, NULL, NULL, NULL) == SQLITE_OK &&
                holdings_are(0, 1);
    return sqlite3_exec(db, remove, NULL, NULL, NULL) == SQLITE_OK && held;
}

/* seed_present and keys_present read the wallet tables by presence and the
 * loaded keystores: an empty wallet is false and false, a transparent or
 * Sapling key row or a loaded key is a key, a seed row is a seed whether it
 * is plaintext or encrypted and locked, and tables that cannot be read are
 * null. */
static int test_summary_holdings(void)
{
    int failures = 0;
    TEST_CASE("walletsummary: seed_present and keys_present") {
        struct rig r;
        uint8_t seed[32];
        char iters[16], saved[32] = {0};
        const char *old = getenv("ZCL_WALLET_KDF_ITERS");
        bool had = old != NULL;
        if (had)
            snprintf(saved, sizeof(saved), "%s", old);
        memset(seed, 0x5c, sizeof(seed));
        ASSERT(rig_open(&r, true));
        rig_key(&r, false);
        ASSERT(holdings_are(0, 0));
        rig_key(&r, true);
        ASSERT(holdings_are(0, 1));
        rig_key(&r, false);
        r.ws.open = false;
        ASSERT(holdings_are(-1, -1));
        r.ws.open = true;
        ASSERT(stored_key_counts(&r, "INSERT INTO wallet_keys"
            "(pubkey_hash,pubkey,privkey) VALUES"
            "(zeroblob(20),zeroblob(33),zeroblob(32))",
            "DELETE FROM wallet_keys"));
        ASSERT(stored_key_counts(&r, "INSERT INTO wallet_sapling_keys"
            "(ivk,xsk,xfvk,diversifier,pk_d,child_index) VALUES"
            "(zeroblob(32),zeroblob(169),zeroblob(96),zeroblob(11),"
            "zeroblob(32),0)",
            "DELETE FROM wallet_sapling_keys"));
        ASSERT(wallet_sqlite_write_sapling_seed(&r.ws, seed));
        ASSERT(holdings_are(1, 0));
        rig_close(&r);

        snprintf(iters, sizeof(iters), "%u", (unsigned)WKS_MIN_ITERS);
        setenv("ZCL_WALLET_KDF_ITERS", iters, 1);
        ASSERT(rig_open(&r, true));
        rig_key(&r, false);
        ASSERT(rig_locked_seed(&r, seed));
        ASSERT(holdings_are(1, 0));
        struct json_value j;
        bool ok;
        call_summary(&j, &ok);
        ASSERT(ok && json_get_bool(json_get(&j, "locked")));
        json_free(&j);
        rig_close(&r);
        if (had)
            setenv("ZCL_WALLET_KDF_ITERS", saved, 1);
        else
            unsetenv("ZCL_WALLET_KDF_ITERS");
    } TEST_END
    return failures;
}

static int test_summary_readiness(void)
{
    int failures = 0;
    TEST_CASE("walletsummary refuses unknown and pending until replay completion") {
        struct rig r;
        ASSERT(rig_open_state(&r, true, false));
        struct json_value j;
        bool ok;
        call_summary(&j, &ok);
        ASSERT(ok && json_is_null(json_get(&j, "spendable_zat")) &&
               json_is_null(json_get(&j, "public_zat")) &&
               !json_get_bool(json_get(&j, "balance_available")) &&
               json_get(&j, "locked") && json_get(&j, "tip_height"));
        json_free(&j);
        call_history(&j, &ok, "", "");
        ASSERT(!ok);
        json_free(&j);
        ASSERT(wallet_readiness_initialize(r.wallet, WALLET_READINESS_PENDING, true, 42));
        call_summary(&j, &ok);
        ASSERT(ok && json_is_null(json_get(&j, "spendable_zat")) &&
               json_is_null(json_get(&j, "public_zat")) &&
               !json_get_bool(json_get(&j, "balance_available")) &&
               json_get(&j, "locked") && json_get(&j, "tip_height"));
        json_free(&j);
        ASSERT(wallet_readiness_complete(r.wallet, true, 42));
        call_summary(&j, &ok);
        ASSERT(ok && json_get(&j, "spendable_zat") &&
               json_get_bool(json_get(&j, "balance_available")) &&
               strcmp(json_get_str(json_get(&j, "wallet_readiness")), "ready") == 0);
        json_free(&j);
        call_history(&j, &ok, "", "");
        ASSERT(ok);
        json_free(&j);
        rig_close(&r);
    } TEST_END
    return failures;
}

static int run_rig_tests(void)
{
    struct rig r;
    int failures = 0;
    if (!rig_open(&r, true) || !rig_notes(&r)) {
        printf("wallet_summary_handlers: fixture FAIL\n");
        return 1;
    }
    failures += test_summary_matches_send(&r);
    failures += test_locked_boot(&r);
    failures += test_failed_reads(&r);
    failures += test_memo_detail(&r);
    failures += test_sent_amount_from_stored_tx(&r);
    failures += test_received_privacy_from_stored_tx(&r);
    rig_close(&r);
    failures += test_summary_readiness();
    failures += test_unknown_tip();
    failures += test_unlock_window();
    failures += test_send_skips_unready_note();
    failures += test_send_spends_one_key();
    failures += test_send_waits_for_depth();
    failures += test_send_minconf_param();
    failures += test_send_minconf_floor();
    failures += test_send_negative_minconf();
    failures += test_send_cap_after_filter();
    failures += test_summary_peer_count();
    failures += test_summary_holdings();
    return failures;
}

int wallet_summary_handlers_run(void);
int wallet_summary_handlers_run(void)
{
    char path[256], log[16384] = {0};
    int failures;
    printf("\n=== wallet summary handlers ===\n");
    memset(g_ivk, 0xa1, sizeof(g_ivk));
    memset(g_ivk2, 0xb2, sizeof(g_ivk2));
    snprintf(path, sizeof(path), "./test-tmp/wsh_%d.log", (int)getpid());
    (void)mkdir("./test-tmp", 0755);
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    FILE *cap = saved >= 0 ? fopen(path, "w+") : NULL;
    if (cap)
        dup2(fileno(cap), STDERR_FILENO);
    failures = run_rig_tests();
    fflush(stderr);
    if (cap) {
        dup2(saved, STDERR_FILENO);
        rewind(cap);
        size_t got = fread(log, 1, sizeof(log) - 1, cap);
        log[got] = '\0';
        fclose(cap);
        (void)unlink(path);
    }
    if (saved >= 0)
        close(saved);
    return failures + (cap ? test_log_hygiene(log) : 1);
}
