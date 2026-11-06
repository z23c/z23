/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet paths that copy from the SQLite utxos projection must confirm each
 * row against the coins database before it becomes wallet state: the coin
 * exists, its amount and script match the row, and the height comes from the
 * coin. A row that disagrees is skipped and counted; with no coins view the
 * copy is withheld. Covers importprivkey, listunspent's height fix-up and the
 * boot-time wallet_utxos rebuild.
 *
 * Local fixture only: an in-memory node.db, an in-memory coins cache with no
 * backing store and throwaway keys. Nothing is spent and no wallet is read.
 * Called from test_rpc_safety. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "coins/coins_view.h"
#include "config/boot_internal.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/utxo.h"
#include "models/wallet_tx.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "wallet/keystore.h"
#include "wallet/wallet.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define WRC_TIP 200
#define WRC_COIN_AMOUNT 5000
#define WRC_ROW_AMOUNT 7000

/* How one candidate row relates to the coin that backs it. */
enum wrc_kind {
    WRC_AGREE,       /* coin exists, amount and script equal the row's */
    WRC_BAD_AMOUNT,  /* coin exists, row carries another amount */
    WRC_BAD_SCRIPT,  /* coin exists, row carries a foreign script */
    WRC_SPENT,       /* no coin for the outpoint */
};

struct wrc_row {
    enum wrc_kind kind;
    uint8_t tag;          /* distinguishes the txid */
    int row_height;       /* height the projection row claims */
    int coin_height;      /* height of the coin */
    bool coinbase;        /* coin is a coinbase */
};

struct wrc_fx {
    struct wallet *w;
    struct main_state ms;
    struct block_index tip;
    struct node_db ndb;
    struct coins_view nv;
    struct coins_view_cache cache;
    struct rpc_table tbl;
    struct privkey key;
    struct pubkey pub;
    uint8_t addr_hash[20];
    struct script own_script;
    struct script foreign_script;
    char datadir[4096];
    bool ok;
};

static bool wrc_make_chain(struct wrc_fx *fx)
{
    main_state_init(&fx->ms);
    fx->ms.chain_active.height = WRC_TIP;
    fx->ms.chain_active.capacity = WRC_TIP + 1;
    fx->ms.chain_active.chain =
        calloc((size_t)(WRC_TIP + 1), sizeof(*fx->ms.chain_active.chain));
    if (!fx->ms.chain_active.chain)
        return false;
    memset(&fx->tip, 0, sizeof(fx->tip));
    fx->tip.nHeight = WRC_TIP;
    fx->ms.chain_active.chain[WRC_TIP] = &fx->tip;
    return true;
}

static bool wrc_make_keys(struct wrc_fx *fx)
{
    privkey_make_new(&fx->key, true);
    if (!privkey_get_pubkey(&fx->key, &fx->pub))
        return false;
    hash160(fx->pub.vch, fx->pub.size, fx->addr_hash);
    struct key_id own = pubkey_get_id(&fx->pub);
    struct key_id foreign;
    memset(&foreign, 0x77, sizeof(foreign));
    script_for_p2pkh(&fx->own_script, &own);
    script_for_p2pkh(&fx->foreign_script, &foreign);
    return true;
}

static void wrc_txid(uint8_t tag, uint8_t out[32])
{
    memset(out, 0x30 + tag, 32);
    out[0] = tag;
}

static void wrc_ensure_warmup_finished(void)
{
    char status[32];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();
}

static bool wrc_open(struct wrc_fx *fx, bool with_coins_view)
{
    memset(fx, 0, sizeof(*fx));
    wrc_ensure_warmup_finished();
    fx->w = zcl_calloc(1, sizeof(*fx->w), "wrc-wallet");
    if (!fx->w)
        return false;
    wallet_init(fx->w);
    fx->ok = wrc_make_chain(fx) && wrc_make_keys(fx) &&
             test_mkdtemp(fx->datadir, sizeof(fx->datadir), "wrc") &&
             node_db_open(&fx->ndb, ":memory:");
    if (!fx->ok)
        return false;
    memset(&fx->nv, 0, sizeof(fx->nv));
    coins_view_cache_init(&fx->cache, &fx->nv);
    wallet_rpc_context_set_base(fx->w, &fx->ms, fx->datadir, NULL, NULL,
                                NULL);
    wallet_rpc_context_set_node_db(&fx->ndb);
    wallet_rpc_context_set_coins_tip(with_coins_view ? &fx->cache : NULL);
    rpc_table_init(&fx->tbl);
    register_wallet_rpc_commands(&fx->tbl);
    return true;
}

static void wrc_close(struct wrc_fx *fx)
{
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_coins_tip(NULL);
    memory_cleanse(fx->key.vch, sizeof(fx->key.vch));
    coins_view_cache_free(&fx->cache);
    if (fx->ndb.open)
        node_db_close(&fx->ndb);
    if (fx->ms.chain_active.chain) {
        free(fx->ms.chain_active.chain);
        fx->ms.chain_active.chain = NULL;
        fx->ms.chain_active.height = -1;
        fx->ms.chain_active.capacity = 0;
    }
    main_state_free(&fx->ms);
    if (fx->w) {
        wallet_free(fx->w);
        free(fx->w);
    }
    if (fx->datadir[0])
        (void)test_rm_rf_recursive(fx->datadir);
}

static bool wrc_add_coin(struct wrc_fx *fx, const struct wrc_row *r)
{
    struct uint256 txid;
    wrc_txid(r->tag, txid.data);
    struct coins_cache_entry *e = coins_view_cache_modify_new(&fx->cache, &txid);
    if (!e)
        return false;
    coins_alloc(&e->coins, 1);
    e->coins.vout[0].value = WRC_COIN_AMOUNT;
    e->coins.vout[0].script_pub_key = fx->own_script;
    e->coins.height = r->coin_height;
    e->coins.version = 1;
    e->coins.is_coinbase = r->coinbase;
    return true;
}

/* The row the projection holds for r: amount and script per its kind. */
static void wrc_fill_row(const struct wrc_fx *fx, const struct wrc_row *r,
                         struct db_utxo *u)
{
    const struct script *s = r->kind == WRC_BAD_SCRIPT ? &fx->foreign_script
                                                       : &fx->own_script;
    memset(u, 0, sizeof(*u));
    wrc_txid(r->tag, u->txid);
    u->vout = 0;
    u->value = r->kind == WRC_BAD_AMOUNT ? WRC_ROW_AMOUNT : WRC_COIN_AMOUNT;
    u->script = (uint8_t *)s->data;
    u->script_len = s->size;
    u->script_type = SCRIPT_P2PKH;
    memcpy(u->address_hash, fx->addr_hash, 20);
    u->has_address = true;
    u->height = r->row_height;
    u->is_coinbase = false;
}

/* Seed the global utxos projection and, unless spent, the coin. */
static bool wrc_seed_utxos(struct wrc_fx *fx, const struct wrc_row *rows,
                           size_t n)
{
    for (size_t i = 0; i < n; i++) {
        struct db_utxo u;
        wrc_fill_row(fx, &rows[i], &u);
        if (!db_utxo_save(&fx->ndb, &u))
            return false;
        if (rows[i].kind != WRC_SPENT && !wrc_add_coin(fx, &rows[i]))
            return false;
    }
    return true;
}

static int wrc_count(struct wrc_fx *fx, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(fx->ndb.db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int wrc_wallet_rows(struct wrc_fx *fx)
{
    return wrc_count(fx, "SELECT count(*) FROM wallet_utxos");
}

/* The wallet_utxos row for a tag: value, height, coinbase. */
static bool wrc_wallet_row(struct wrc_fx *fx, uint8_t tag, int64_t *value,
                           int *height, bool *coinbase)
{
    uint8_t txid[32];
    wrc_txid(tag, txid);
    sqlite3_stmt *st = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(fx->ndb.db, "SELECT value,height,is_coinbase "
            "FROM wallet_utxos WHERE txid=?1 AND vout=0", -1, &st, NULL) ==
        SQLITE_OK) {
        sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            *value = sqlite3_column_int64(st, 0);
            *height = sqlite3_column_int(st, 1);
            *coinbase = sqlite3_column_int(st, 2) != 0;
            found = true;
        }
    }
    sqlite3_finalize(st);
    return found;
}

/* ---- importprivkey ---- */

static bool wrc_import(struct wrc_fx *fx, struct json_value *result)
{
    unsigned char pfx[8];
    size_t pfx_len = 0;
    const unsigned char *p = chain_params_base58_prefix(
        chain_params_get(), B58_SECRET_KEY, &pfx_len);
    char wif[128];
    if (!p || pfx_len > sizeof(pfx))
        return false;
    memcpy(pfx, p, pfx_len);
    if (!encode_secret(&fx->key, pfx, pfx_len, wif, sizeof(wif)))
        return false;
    struct json_value params, v;
    json_init(&params);
    json_set_array(&params);
    json_init(&v);
    json_set_str(&v, wif);
    bool ok = json_push_back(&params, &v);
    json_free(&v);
    json_init(result);
    ok = ok && rpc_table_execute(&fx->tbl, "importprivkey", &params, result);
    json_free(&params);
    memory_cleanse(wif, sizeof(wif));
    return ok;
}

static bool wrc_reply_has(const struct json_value *r, const char *needle)
{
    const char *s = json_get_str(r);
    return s && strstr(s, needle) != NULL;
}

static int wrc_import_agreeing_row_kept(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importprivkey keeps a row the coin agrees with") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        int64_t value = 0;
        int height = 0;
        bool cb = true;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &cb));
        ASSERT(value == WRC_COIN_AMOUNT && height == 7 && !cb);
        ASSERT(wrc_wallet_rows(&fx) == 1);
        ASSERT(result.type == JSON_NULL);   /* the reply an honest import has today */
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_import_disagreeing_rows_skipped(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importprivkey skips and counts disagreeing rows") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 7, 7, false},
            {WRC_BAD_AMOUNT, 2, 7, 7, false},
            {WRC_BAD_SCRIPT, 3, 7, 7, false},
            {WRC_SPENT, 4, 7, 7, false},
        };
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 4));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        int64_t value;
        int height;
        bool cb;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &cb));
        ASSERT(!wrc_wallet_row(&fx, 2, &value, &height, &cb));
        ASSERT(!wrc_wallet_row(&fx, 3, &value, &height, &cb));
        ASSERT(!wrc_wallet_row(&fx, 4, &value, &height, &cb));
        ASSERT(wrc_wallet_rows(&fx) == 1);
        ASSERT(wrc_reply_has(&result, "3 utxos rows skipped"));
        ASSERT(wrc_reply_has(&result, "rescanwallet"));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_import_height_comes_from_coin(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importprivkey takes height and coinbase from the coin") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 2, 9, true}};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        int64_t value;
        int height = 0;
        bool cb = false;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &cb));
        ASSERT(height == 9 && cb);
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_import_without_coins_view_withholds(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importprivkey withholds coin discovery without a coins view") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, false));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));      /* the key still imports */
        struct key_id kid = pubkey_get_id(&fx.pub);
        ASSERT(keystore_have_key(&fx.w->keystore, &kid));
        ASSERT(wrc_wallet_rows(&fx) == 0);
        ASSERT(wrc_reply_has(&result, "coin discovery withheld"));
        ASSERT(wrc_reply_has(&result, "rescanwallet"));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- importaddress ---- */

static bool wrc_import_address(struct wrc_fx *fx, struct json_value *result)
{
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    dest.id.key = pubkey_get_id(&fx->pub);
    char addr[128];
    if (!wallet_encode_destination(&dest, addr, sizeof(addr)))
        return false;
    struct json_value params, v;
    json_init(&params);
    json_set_array(&params);
    json_init(&v);
    json_set_str(&v, addr);
    bool ok = json_push_back(&params, &v);
    json_free(&v);
    json_init(result);
    ok = ok && rpc_table_execute(&fx->tbl, "importaddress", &params, result);
    json_free(&params);
    return ok;
}

static int wrc_importaddress_skips_disagreeing_rows(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importaddress imports only rows the coin confirms") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 2, 9, true},
            {WRC_BAD_AMOUNT, 2, 7, 7, false},
            {WRC_SPENT, 3, 7, 7, false},
        };
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 3));
        struct json_value result;
        ASSERT(wrc_import_address(&fx, &result));
        ASSERT(json_get_int(json_get(&result, "utxos")) == 1);
        ASSERT(json_get_int(json_get(&result, "utxos_skipped")) == 2);
        int64_t value;
        int height = 0;
        bool cb = false;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &cb));
        ASSERT(height == 9 && cb);
        ASSERT(wrc_wallet_rows(&fx) == 1);
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_importaddress_without_coins_view_withholds(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importaddress withholds coin discovery without a coins view") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, false));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import_address(&fx, &result));
        ASSERT(json_get_bool(json_get(&result, "coin_discovery_withheld")));
        ASSERT(json_get_int(json_get(&result, "utxos")) == 0);
        ASSERT(wrc_wallet_rows(&fx) == 0);
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- listunspent ---- */

static bool wrc_seed_wallet_row(struct wrc_fx *fx, const struct wrc_row *r,
                                int height, bool coinbase)
{
    struct db_utxo u;
    wrc_fill_row(fx, r, &u);
    struct db_wallet_utxo wu;
    memset(&wu, 0, sizeof(wu));
    memcpy(wu.txid, u.txid, 32);
    wu.vout = 0;
    wu.value = u.value;
    memcpy(wu.address_hash, fx->addr_hash, 20);
    wu.script = u.script;
    wu.script_len = u.script_len;
    wu.height = height;
    wu.is_coinbase = coinbase;
    return db_wallet_utxo_save(&fx->ndb, &wu);
}

/* minconf < 0 sends no argument (the RPC default, 1). */
static bool wrc_listunspent_min(struct wrc_fx *fx, struct json_value *result,
                                int minconf)
{
    struct json_value params, arg;
    json_init(&params);
    json_set_array(&params);
    json_init(&arg);
    bool ok = true;
    if (minconf >= 0) {
        json_set_int(&arg, minconf);
        ok = json_push_back(&params, &arg);
    }
    json_free(&arg);
    json_init(result);
    ok = ok && rpc_table_execute(&fx->tbl, "listunspent", &params, result);
    json_free(&params);
    return ok;
}

static bool wrc_listunspent(struct wrc_fx *fx, struct json_value *result)
{
    return wrc_listunspent_min(fx, result, -1);
}

/* Was the row with this tag listed, and with how many confirmations? */
static bool wrc_listed(const struct json_value *result, uint8_t tag,
                       int64_t *confs)
{
    uint8_t raw[32];
    wrc_txid(tag, raw);
    struct uint256 id;
    memcpy(id.data, raw, 32);
    char hex[65];
    uint256_get_hex(&id, hex);
    for (size_t i = 0; i < json_size(result); i++) {
        const struct json_value *e = json_at(result, i);
        const char *t = json_get_str(json_get(e, "txid"));
        if (t && strcmp(t, hex) == 0) {
            *confs = json_get_int(json_get(e, "confirmations"));
            return true;
        }
    }
    return false;
}

/* A height-0 wallet row backed by an agreeing utxos row and coin lists with
 * the coin's confirmations: what the fix-up gave an honest wallet before. */
static int wrc_listunspent_agreeing_row_same(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: listunspent lists an agreeing height-0 row as before") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 5, 5, false}};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        ASSERT(wrc_seed_wallet_row(&fx, &rows[0], 0, false));
        struct json_value result;
        ASSERT(wrc_listunspent(&fx, &result));
        int64_t confs = 0;
        ASSERT(wrc_listed(&result, 1, &confs));
        ASSERT(confs == WRC_TIP - 5 + 1);
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* The stale utxos row says height 1; the coin says 150. */
static int wrc_listunspent_coinbase_height_from_coin(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: listunspent takes a coinbase height from the coin") {
        struct wrc_row stale = {WRC_AGREE, 1, 1, 150, true};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, &stale, 1));
        ASSERT(wrc_seed_wallet_row(&fx, &stale, 0, true));
        struct json_value result;
        ASSERT(wrc_listunspent(&fx, &result));
        int64_t confs = 0;
        /* 51 confirmations on the coin height: immature, so not listed. */
        ASSERT(!wrc_listed(&result, 1, &confs));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_listunspent_disagreeing_rows_skipped(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: listunspent skips height-0 rows the coin disagrees with") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 5, 5, false},
            {WRC_BAD_AMOUNT, 2, 5, 5, false},
            {WRC_BAD_SCRIPT, 3, 5, 5, false},
            {WRC_SPENT, 4, 5, 5, false},
        };
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 4));
        for (size_t i = 0; i < 4; i++)
            ASSERT(wrc_seed_wallet_row(&fx, &rows[i], 0, false));
        struct json_value result;
        ASSERT(wrc_listunspent_min(&fx, &result, 0));
        int64_t confs;
        ASSERT(wrc_listed(&result, 1, &confs));
        ASSERT(!wrc_listed(&result, 2, &confs));   /* amount disagrees */
        ASSERT(!wrc_listed(&result, 3, &confs));   /* script disagrees */
        /* No coin is not a disagreement: see the mempool cases. */
        ASSERT(wrc_listed(&result, 4, &confs) && confs == 0);
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* A mempool output has a height-0 wallet row and no coin yet. */
static int wrc_listunspent_mempool_row_no_coin(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: listunspent lists a mempool row with no coin as unconfirmed") {
        struct wrc_row mempool = {WRC_SPENT, 1, 0, 0, false};
        struct wrc_row change = {WRC_SPENT, 2, 0, 0, false};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_wallet_row(&fx, &mempool, 0, false));
        ASSERT(wrc_seed_wallet_row(&fx, &change, 0, false));
        struct json_value result;
        int64_t confs = -1;
        ASSERT(wrc_listunspent_min(&fx, &result, 0));
        ASSERT(wrc_listed(&result, 1, &confs) && confs == 0);
        ASSERT(wrc_listed(&result, 2, &confs) && confs == 0);
        json_free(&result);
        ASSERT(wrc_listunspent_min(&fx, &result, 1));
        ASSERT(!wrc_listed(&result, 1, &confs));
        ASSERT(!wrc_listed(&result, 2, &confs));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* The projection's height is never used: no coin, no maturity. */
static int wrc_listunspent_coinbase_no_coin_never_mature(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: listunspent never lists a coinbase row that has no coin") {
        struct wrc_row cb = {WRC_SPENT, 1, 1, 1, true};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, &cb, 1));   /* utxos row at height 1 */
        ASSERT(wrc_seed_wallet_row(&fx, &cb, 0, true));
        struct json_value result;
        int64_t confs;
        ASSERT(wrc_listunspent_min(&fx, &result, 0));
        ASSERT(!wrc_listed(&result, 1, &confs));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_listunspent_without_coins_view(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: listunspent does not repair a height from the projection alone") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 5, 5, false},     /* height 0 in the wallet */
            {WRC_AGREE, 2, 5, 5, false},     /* height 6 in the wallet */
        };
        ASSERT(wrc_open(&fx, false));
        ASSERT(wrc_seed_utxos(&fx, rows, 2));
        ASSERT(wrc_seed_wallet_row(&fx, &rows[0], 0, false));
        ASSERT(wrc_seed_wallet_row(&fx, &rows[1], 6, false));
        struct json_value result;
        ASSERT(wrc_listunspent_min(&fx, &result, 0));
        int64_t confs = -1;
        /* No coins view: unconfirmed, never the projection's height. */
        ASSERT(wrc_listed(&result, 1, &confs) && confs == 0);
        json_free(&result);
        ASSERT(wrc_listunspent(&fx, &result));
        ASSERT(!wrc_listed(&result, 1, &confs));
        /* A row that already has a height is not touched by the fix-up. */
        ASSERT(wrc_listed(&result, 2, &confs));
        ASSERT(confs == WRC_TIP - 6 + 1);
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- boot rebuild ---- */

static bool wrc_add_wallet_key(struct wrc_fx *fx)
{
    sqlite3_stmt *st = NULL;
    uint8_t dummy[4] = {1, 2, 3, 4};
    bool ok = sqlite3_prepare_v2(fx->ndb.db, "INSERT INTO wallet_keys "
        "(pubkey_hash,pubkey,privkey) VALUES (?1,?2,?3)", -1, &st, NULL) ==
        SQLITE_OK;
    if (ok) {
        sqlite3_bind_blob(st, 1, fx->addr_hash, 20, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, dummy, 4, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, dummy, 4, SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    return ok;
}

static int wrc_rebuild_mixed_rows(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: rebuild on an empty wallet inserts only confirmed rows") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 2, 9, true},      /* height and coinbase from coin */
            {WRC_BAD_AMOUNT, 2, 7, 7, false},
            {WRC_BAD_SCRIPT, 3, 7, 7, false},
            {WRC_SPENT, 4, 7, 7, false},
            {WRC_AGREE, 5, 4, 4, false},
        };
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_add_wallet_key(&fx));
        ASSERT(wrc_seed_utxos(&fx, rows, 5));
        int skipped = -1;
        ASSERT(boot_wallet_rebuild_confirmed(&fx.ndb, &fx.cache, &skipped) == 2);
        ASSERT(skipped == 3);
        int64_t value;
        int height = 0;
        bool cb = false;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &cb));
        ASSERT(value == WRC_COIN_AMOUNT && height == 9 && cb);
        ASSERT(wrc_wallet_row(&fx, 5, &value, &height, &cb));
        ASSERT(height == 4 && !cb);
        ASSERT(wrc_wallet_rows(&fx) == 2);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_rebuild_without_coins_view(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: rebuild is withheld without a coins view") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, false));
        ASSERT(wrc_add_wallet_key(&fx));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        int skipped = 0;
        ASSERT(boot_wallet_rebuild_confirmed(&fx.ndb, NULL, &skipped) < 0);
        ASSERT(wrc_wallet_rows(&fx) == 0);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

int wrc_run_tests(void);
int wrc_run_tests(void)
{
    int failures = 0;
    failures += wrc_import_agreeing_row_kept();
    failures += wrc_import_disagreeing_rows_skipped();
    failures += wrc_import_height_comes_from_coin();
    failures += wrc_import_without_coins_view_withholds();
    failures += wrc_importaddress_skips_disagreeing_rows();
    failures += wrc_importaddress_without_coins_view_withholds();
    failures += wrc_listunspent_agreeing_row_same();
    failures += wrc_listunspent_coinbase_height_from_coin();
    failures += wrc_listunspent_disagreeing_rows_skipped();
    failures += wrc_listunspent_mempool_row_no_coin();
    failures += wrc_listunspent_coinbase_no_coin_never_mature();
    failures += wrc_listunspent_without_coins_view();
    failures += wrc_rebuild_mixed_rows();
    failures += wrc_rebuild_without_coins_view();
    return failures;
}
