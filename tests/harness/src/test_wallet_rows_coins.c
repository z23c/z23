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
#include "controllers/wallet_row_coins.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/utxo.h"
#include "models/wallet_tx.h"
#include "rpc/server.h"
#include "rpc/httpserver.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "util/util.h"
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
    uint16_t tag;         /* distinguishes the txid */
    int row_height;       /* height the projection row claims */
    int coin_height;      /* height of the coin */
    bool coinbase;        /* coin is a coinbase */
};

struct wrc_fx {
    struct wallet *w;
    struct main_state ms;
    struct block_index tip;
    struct block_index *below;   /* heights 0..WRC_TIP-1 */
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

/* A node with full history: every height 0..WRC_TIP is indexed and claims
 * its block body. wrc_drop_bodies() turns it into a node started from a
 * state bundle. */
static bool wrc_make_chain(struct wrc_fx *fx)
{
    main_state_init(&fx->ms);
    fx->ms.chain_active.height = WRC_TIP;
    fx->ms.chain_active.capacity = WRC_TIP + 1;
    fx->ms.chain_active.chain =
        calloc((size_t)(WRC_TIP + 1), sizeof(*fx->ms.chain_active.chain));
    fx->below = calloc((size_t)WRC_TIP, sizeof(*fx->below));
    if (!fx->ms.chain_active.chain || !fx->below)
        return false;
    for (int h = 0; h < WRC_TIP; h++) {
        fx->below[h].nHeight = h;
        fx->below[h].nStatus = BLOCK_HAVE_DATA;
        fx->ms.chain_active.chain[h] = &fx->below[h];
    }
    memset(&fx->tip, 0, sizeof(fx->tip));
    fx->tip.nHeight = WRC_TIP;
    fx->tip.nStatus = BLOCK_HAVE_DATA;
    fx->ms.chain_active.chain[WRC_TIP] = &fx->tip;
    return true;
}

/* The fast-started node: indexed below the tip, with no block body there. */
static void wrc_drop_bodies(struct wrc_fx *fx)
{
    for (int h = 0; h < WRC_TIP; h++)
        fx->below[h].nStatus &= ~BLOCK_HAVE_DATA;
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

static void wrc_txid(uint16_t tag, uint8_t out[32])
{
    memset(out, 0x30 + (tag & 0x3f), 32);
    out[0] = (uint8_t)(tag & 0xff);
    out[1] = (uint8_t)(tag >> 8);
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
    fx->ok = wallet_readiness_initialize(fx->w, WALLET_READINESS_READY, false, 0) &&
             wrc_make_chain(fx) && wrc_make_keys(fx) &&
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
    free(fx->below);
    fx->below = NULL;
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
static bool wrc_wallet_row(struct wrc_fx *fx, uint16_t tag, int64_t *value,
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

static int wrc_deny_utxo(void *ctx, int action, const char *table,
                         const char *column, const char *db, const char *trigger)
{
    (void)ctx; (void)column; (void)db; (void)trigger;
    return action == SQLITE_READ && table && strcmp(table, "utxos") == 0
        ? SQLITE_DENY : SQLITE_OK;
}

static int wrc_enumeration_empty_and_cap(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: checked enumeration preserves empty and capped results") {
        ASSERT(wrc_open(&fx, true));
        struct db_utxo out[1];
        ASSERT(db_utxo_list_for_address_checked(&fx.ndb, fx.addr_hash, out, 1) == 0);
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false},
                                 {WRC_AGREE, 2, 8, 8, false}};
        ASSERT(wrc_seed_utxos(&fx, rows, 2));
        memset(out, 0xff, sizeof(out));
        db_utxo_list_interrupt_after_row_for_test(true);
        int count = db_utxo_list_for_address_checked(&fx.ndb, fx.addr_hash, out, 1);
        db_utxo_list_interrupt_after_row_for_test(false);
        ASSERT(count == 1);
        ASSERT(out[0].script == NULL && out[0].script_len == 0);
        struct db_utxo legacy[2];
        db_utxo_list_interrupt_after_row_for_test(true);
        count = db_utxo_list_for_address(&fx.ndb, fx.addr_hash, legacy, 2);
        db_utxo_list_interrupt_after_row_for_test(false);
        ASSERT(count == 1 && legacy[0].script == NULL);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}


static int wrc_import_enumeration_failure(bool watch_only, bool partial)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST(watch_only ? "wallet_rows_coins: importaddress reports enumeration failure" :
                      "wallet_rows_coins: importprivkey reports enumeration failure") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false},
                                 {WRC_AGREE, 2, 8, 8, false}};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 2));
        if (partial)
            db_utxo_list_interrupt_after_row_for_test(true);
        else
            ASSERT(sqlite3_set_authorizer(fx.ndb.db, wrc_deny_utxo, NULL) == SQLITE_OK);
        struct json_value result;
        bool imported = watch_only ? wrc_import_address(&fx, &result) :
                                     wrc_import(&fx, &result);
        db_utxo_list_interrupt_after_row_for_test(false);
        sqlite3_set_authorizer(fx.ndb.db, NULL, NULL);
        ASSERT(imported);
        if (watch_only) {
            ASSERT(wrc_reply_has(json_get(&result, "warning"), "coin discovery incomplete"));
            ASSERT(json_get_bool(json_get(&result, "coin_discovery_incomplete")));
        } else {
            ASSERT(wrc_reply_has(&result, "coin discovery incomplete"));
        }
        ASSERT(wrc_wallet_rows(&fx) == 0);
        json_free(&result);
        ASSERT(watch_only ? wrc_import_address(&fx, &result) : wrc_import(&fx, &result));
        ASSERT(wrc_wallet_rows(&fx) == 2);
        int64_t value;
        int height;
        bool coinbase;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &coinbase));
        ASSERT(value == WRC_COIN_AMOUNT && height == 7 && !coinbase);
        ASSERT(wrc_wallet_row(&fx, 2, &value, &height, &coinbase));
        ASSERT(value == WRC_COIN_AMOUNT && height == 8 && !coinbase);
        if (watch_only) {
            ASSERT(json_get_int(json_get(&result, "utxos")) == 2);
            ASSERT(json_get_real(json_get(&result, "balance")) ==
                   (double)(2 * WRC_COIN_AMOUNT) / 1e8);
            ASSERT(json_get(&result, "coin_discovery_incomplete") == NULL);
        }
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}


static int wrc_import_save_failure(bool watch_only)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST(watch_only ? "wallet_rows_coins: importaddress reports save failure" :
                      "wallet_rows_coins: importprivkey reports save failure") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 7, 7, false},
            {WRC_AGREE, 2, 7, 7, false},
            {WRC_BAD_AMOUNT, 3, 7, 7, false},
        };
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 3));
        ASSERT(sqlite3_exec(fx.ndb.db,
            "CREATE TRIGGER refuse_one BEFORE INSERT ON wallet_utxos "
            "WHEN substr(NEW.txid,1,1)=x'02' BEGIN SELECT RAISE(FAIL,'fixture'); END",
            NULL, NULL, NULL) == SQLITE_OK);
        struct json_value result;
        ASSERT(watch_only ? wrc_import_address(&fx, &result) : wrc_import(&fx, &result));
        ASSERT(wrc_wallet_rows(&fx) == 1);
        if (watch_only) {
            ASSERT(json_get_int(json_get(&result, "utxos")) == 1);
            ASSERT(json_get_real(json_get(&result, "balance")) == (double)WRC_COIN_AMOUNT / 1e8);
            ASSERT(json_get_int(json_get(&result, "utxos_save_failed")) == 1);
            ASSERT(json_get_int(json_get(&result, "utxos_skipped")) == 1);
            ASSERT(wrc_reply_has(json_get(&result, "warning"), "1 wallet UTXO row could not be saved"));
        } else {
            ASSERT(wrc_reply_has(&result, "1 wallet UTXO row could not be saved"));
            ASSERT(wrc_reply_has(&result, "1 utxos rows skipped"));
        }
        json_free(&result);
        ASSERT(sqlite3_exec(fx.ndb.db, "DROP TRIGGER refuse_one",
                            NULL, NULL, NULL) == SQLITE_OK);
        ASSERT(watch_only ? wrc_import_address(&fx, &result) :
                            wrc_import(&fx, &result));
        ASSERT(wrc_wallet_rows(&fx) == 2);
        int64_t value;
        int height;
        bool coinbase;
        ASSERT(wrc_wallet_row(&fx, 1, &value, &height, &coinbase));
        ASSERT(value == WRC_COIN_AMOUNT && height == 7 && !coinbase);
        ASSERT(wrc_wallet_row(&fx, 2, &value, &height, &coinbase));
        ASSERT(value == WRC_COIN_AMOUNT && height == 7 && !coinbase);
        if (watch_only) {
            ASSERT(json_get_int(json_get(&result, "utxos")) == 2);
            ASSERT(json_get_real(json_get(&result, "balance")) ==
                   (double)(2 * WRC_COIN_AMOUNT) / 1e8);
            ASSERT(json_get(&result, "utxos_save_failed") == NULL);
        }
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
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

/* ---- the per-import row cap ---- */

/* One more agreeing row than an import looks at. */
static bool wrc_seed_over_cap(struct wrc_fx *fx)
{
    for (int i = 0; i <= WALLET_IMPORT_ROW_CAP; i++) {
        struct wrc_row r = {WRC_AGREE, (uint16_t)(i + 1), 7, 7, false};
        if (!wrc_seed_utxos(fx, &r, 1))
            return false;
    }
    return true;
}

static bool wrc_cap_text(const char *s)
{
    char want[64];
    snprintf(want, sizeof(want), "first %d rows", WALLET_IMPORT_ROW_CAP);
    return s && strstr(s, want) && strstr(s, "rescanwallet");
}

static int wrc_importprivkey_says_when_capped(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importprivkey says when it stopped at the row cap") {
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_over_cap(&fx));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        ASSERT(wrc_wallet_rows(&fx) == WALLET_IMPORT_ROW_CAP);
        ASSERT(wrc_cap_text(json_get_str(&result)));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_importaddress_says_when_capped(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importaddress says when it stopped at the row cap") {
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_over_cap(&fx));
        struct json_value result;
        ASSERT(wrc_import_address(&fx, &result));
        ASSERT(json_get_int(json_get(&result, "utxos")) ==
               WALLET_IMPORT_ROW_CAP);
        ASSERT(json_get_bool(json_get(&result, "rows_capped")));
        ASSERT(wrc_cap_text(json_get_str(json_get(&result, "warning"))));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- the import warning on a node started from a state bundle ---- */

/* The holed-node warning: what is true, and never the rescanwallet advice
 * that would erase the rows this import just copied. */
static bool wrc_holed_text(const char *s)
{
    return s && strstr(s, "no block data for 200 of heights 0..200") &&
           strstr(s, "first missing height 0") &&
           strstr(s, "-bodyhistorybackfill") &&
           !strstr(s, "Run rescanwallet to rebuild") &&
           !strstr(s, "run rescanwallet to rebuild") &&
           !strstr(s, "rescanwallet covers the rest");
}

static int wrc_import_holed_node_skipped(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: importprivkey on a bundle-started node does not advise rescanwallet") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 7, 7, false},
            {WRC_BAD_AMOUNT, 2, 7, 7, false},
        };
        ASSERT(wrc_open(&fx, true));
        wrc_drop_bodies(&fx);
        ASSERT(wrc_seed_utxos(&fx, rows, 2));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        ASSERT(wrc_wallet_rows(&fx) == 1);
        ASSERT(wrc_reply_has(&result, "1 utxos rows skipped"));
        ASSERT(wrc_holed_text(json_get_str(&result)));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_import_holed_node_withheld(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: a withheld import on a bundle-started node does not advise rescanwallet") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, false));
        wrc_drop_bodies(&fx);
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        ASSERT(wrc_reply_has(&result, "coin discovery withheld"));
        ASSERT(wrc_holed_text(json_get_str(&result)));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

static int wrc_import_holed_node_capped(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: a capped import on a bundle-started node says the rest were not copied") {
        ASSERT(wrc_open(&fx, true));
        wrc_drop_bodies(&fx);
        ASSERT(wrc_seed_over_cap(&fx));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        ASSERT(wrc_wallet_rows(&fx) == WALLET_IMPORT_ROW_CAP);
        ASSERT(wrc_reply_has(&result, "the rest were not copied"));
        ASSERT(wrc_holed_text(json_get_str(&result)));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* importaddress: the scan loads no watch-only id, so rescanwallet never
 * rebuilds a watch-only row (on a full-history node it drops it). The
 * warning says so and names no rescanwallet step, on either kind of node. */
static int wrc_importaddress_no_rescan_advice(bool holed)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST(holed ? "wallet_rows_coins: importaddress on a bundle-started node does not advise rescanwallet"
               : "wallet_rows_coins: importaddress on a full-history node does not advise rescanwallet") {
        struct wrc_row rows[] = {
            {WRC_AGREE, 1, 7, 7, false},
            {WRC_BAD_AMOUNT, 2, 7, 7, false},
        };
        ASSERT(wrc_open(&fx, true));
        if (holed)
            wrc_drop_bodies(&fx);
        ASSERT(wrc_seed_utxos(&fx, rows, 2));
        struct json_value result;
        ASSERT(wrc_import_address(&fx, &result));
        ASSERT(json_get_int(json_get(&result, "utxos_skipped")) == 1);
        const char *s = json_get_str(json_get(&result, "warning"));
        ASSERT(s && strstr(s, "1 utxos rows skipped"));
        ASSERT(strstr(s, "rescanwallet does not rediscover watch-only coins"));
        ASSERT(!strstr(s, "Run rescanwallet") && !strstr(s, "run rescanwallet"));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- rescanwallet and reindexdb on a node started from a state bundle ---- */

/* Row count and an FNV-1a fold of every column of every row, in key order:
 * equal before and after means the table is byte-for-byte unchanged. */
static bool wrc_table_digest(struct node_db *ndb, const char *sql,
                             int *rows, uint64_t *fold)
{
    sqlite3_stmt *st = NULL;
    *rows = 0;
    *fold = 1469598103934665603ULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        (*rows)++;
        for (int c = 0; c < sqlite3_column_count(st); c++) {
            const uint8_t *p = sqlite3_column_blob(st, c);
            int n = sqlite3_column_bytes(st, c);
            *fold = (*fold ^ (uint64_t)sqlite3_column_type(st, c)) *
                    1099511628211ULL;
            for (int i = 0; p && i < n; i++)
                *fold = (*fold ^ p[i]) * 1099511628211ULL;
        }
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

struct wrc_rows_state {
    int utxo_rows, tx_rows;
    uint64_t utxo_fold, tx_fold;
    int64_t balance;
};

static bool wrc_rows_state_db(struct node_db *ndb, struct wrc_rows_state *s)
{
    s->balance = db_wallet_utxo_balance(ndb);
    return wrc_table_digest(ndb, "SELECT * FROM wallet_utxos ORDER BY txid, vout",
                            &s->utxo_rows, &s->utxo_fold) &&
           wrc_table_digest(ndb, "SELECT * FROM wallet_transactions ORDER BY txid",
                            &s->tx_rows, &s->tx_fold);
}

static bool wrc_rows_state(struct wrc_fx *fx, struct wrc_rows_state *s)
{
    return wrc_rows_state_db(&fx->ndb, s);
}

/* The row state above as one scalar, for other test files
 * (test_block_scan.c): equal digests mean wallet_utxos and
 * wallet_transactions are byte-for-byte unchanged. False when a table could
 * not be read. */
bool wrc_wallet_rows_digest(struct node_db *ndb, uint64_t *digest);
bool wrc_wallet_rows_digest(struct node_db *ndb, uint64_t *digest)
{
    struct wrc_rows_state s;
    if (!ndb || !digest || !wrc_rows_state_db(ndb, &s))
        return false;
    const uint64_t parts[5] = {
        (uint64_t)s.utxo_rows, (uint64_t)s.tx_rows, (uint64_t)s.balance,
        s.utxo_fold, s.tx_fold,
    };
    uint64_t d = 1469598103934665603ULL;
    for (int i = 0; i < 5; i++)
        d = (d ^ parts[i]) * 1099511628211ULL;
    *digest = d;
    return true;
}

static bool wrc_rows_same(const struct wrc_rows_state *a,
                          const struct wrc_rows_state *b)
{
    return a->utxo_rows == b->utxo_rows && a->tx_rows == b->tx_rows &&
           a->utxo_fold == b->utxo_fold && a->tx_fold == b->tx_fold &&
           a->balance == b->balance;
}

/* One wallet_transactions row beside the imported wallet_utxos row. */
static bool wrc_seed_wallet_tx(struct wrc_fx *fx)
{
    static const uint8_t raw_tx[2] = {0x01, 0x02};
    struct db_wallet_tx tx;
    memset(&tx, 0, sizeof(tx));
    wrc_txid(1, tx.txid);
    tx.raw_tx = (uint8_t *)raw_tx;
    tx.raw_tx_len = sizeof(raw_tx);
    tx.has_block = true;
    memset(tx.block_hash, 0x07, sizeof(tx.block_hash));
    tx.block_height = 7;
    tx.time_received = 1;
    return db_wallet_tx_save(&fx->ndb, &tx);
}

/* Run a row-replacing wallet RPC with the scan's block directory pinned to
 * the fixture, so no path can reach a real datadir. */
static bool wrc_run_repair(struct wrc_fx *fx, const char *method,
                           struct json_value *result)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    json_init(result);
    bool pinned = SetDataDir(fx->datadir);
    bool ok = pinned &&
              rpc_table_execute(&fx->tbl, method, &params, result);
    json_free(&params);
    SetDataDir("");
    ClearDataDirCache();
    return pinned && ok;
}

/* Import the key, or only its address (a wallet holding nothing but a
 * watch-only address: the scan loads no id for it). */
static bool wrc_import_as(struct wrc_fx *fx, bool watch_only,
                          struct json_value *result)
{
    return watch_only ? wrc_import_address(fx, result)
                      : wrc_import(fx, result);
}

/* The imported rows, then `method` on the bundle-started node. */
static int wrc_repair_keeps_rows(const char *method, const char *name,
                                 bool watch_only)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST(name) {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, true));
        wrc_drop_bodies(&fx);
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import_as(&fx, watch_only, &result));
        json_free(&result);
        ASSERT(fx.w->keystore.num_keys == (watch_only ? 0u : 1u) &&
               fx.w->keystore.num_watching == (watch_only ? 1u : 0u));
        ASSERT(wrc_seed_wallet_tx(&fx));
        struct wrc_rows_state before, after;
        ASSERT(wrc_rows_state(&fx, &before));
        ASSERT(before.utxo_rows == 1 && before.tx_rows == 1 &&
               before.balance == WRC_COIN_AMOUNT);
        ASSERT(!wrc_run_repair(&fx, method, &result));
        ASSERT(wrc_rows_state(&fx, &after));
        ASSERT(wrc_rows_same(&before, &after));
        ASSERT(wrc_reply_has(&result, "refused"));
        ASSERT(wrc_reply_has(&result, "no readable block data for 200 of the blocks "
                                      "at heights 0..200"));
        ASSERT(wrc_reply_has(&result, "first missing height 0"));
        ASSERT(wrc_reply_has(&result, "were kept unchanged"));
        ASSERT(wrc_reply_has(&result, "-bodyhistorybackfill"));
        json_free(&result);
        wrc_close(&fx);
        PASS();
    } _test_next:;
    return failures;
}

/* An active chain with no tip: 0..-1 would take the empty-range path and
 * replace the rows with nothing. reindexdb refuses first. */
static int wrc_repair_no_tip_keeps_rows(void)
{
    int failures = 0;
    struct wrc_fx fx;
    TEST("wallet_rows_coins: reindexdb with no chain tip keeps the wallet rows") {
        struct wrc_row rows[] = {{WRC_AGREE, 1, 7, 7, false}};
        ASSERT(wrc_open(&fx, true));
        ASSERT(wrc_seed_utxos(&fx, rows, 1));
        struct json_value result;
        ASSERT(wrc_import(&fx, &result));
        json_free(&result);
        ASSERT(wrc_seed_wallet_tx(&fx));
        struct wrc_rows_state before, after;
        ASSERT(wrc_rows_state(&fx, &before));
        ASSERT(before.utxo_rows == 1 && before.tx_rows == 1);
        fx.ms.chain_active.height = -1;
        ASSERT(!wrc_run_repair(&fx, "reindexdb", &result));
        fx.ms.chain_active.height = WRC_TIP;
        ASSERT(wrc_rows_state(&fx, &after));
        ASSERT(wrc_rows_same(&before, &after));
        ASSERT(wrc_reply_has(&result, "no tip yet"));
        ASSERT(wrc_reply_has(&result, "were kept unchanged"));
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
static bool wrc_listed(const struct json_value *result, uint16_t tag,
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

static int wrc_deny_wallet_read(void *ctx, int operation, const char *a,
                                const char *b, const char *db, const char *trigger)
{
    (void)ctx; (void)b; (void)db; (void)trigger;
    return operation == SQLITE_READ && a && strcmp(a, "wallet_utxos") == 0
        ? SQLITE_DENY : SQLITE_OK;
}


static bool wrc_reserved_output(const struct transaction *tx, uint32_t n, void *ctx)
{
    (void)tx; (void)ctx;
    return n == 2;
}

static bool wrc_listunspent_policy(struct wrc_fx *fx, struct wallet_tx *tx)
{
    struct key_id watch = {0};
    watch.id.data[0] = 0xb9;
    bool ok = keystore_add_watch_only_id(&fx->w->keystore, &watch);
    tx->tx.num_vout = 4;
    script_for_p2pkh(&tx->tx.vout[1].script_pub_key, &watch);
    wallet_set_coin_reservation_probe(wrc_reserved_output, NULL);
    wallet_mark_outpoint_spent(fx->w, &tx->tx.hash, 3);
    struct json_value result = {0};
    ok = ok && wrc_listunspent(fx, &result) && json_size(&result) == 2;
    const struct json_value *first = json_at(&result, 0);
    const struct json_value *second = json_at(&result, 1);
    const struct json_value *a = first ? json_get(first, "spendable") : NULL;
    const struct json_value *b = second ? json_get(second, "spendable") : NULL;
    ok = ok && a && b && a->type == JSON_BOOL && b->type == JSON_BOOL &&
         json_get_bool(a) && !json_get_bool(b);
    json_free(&result);
    wallet_set_coin_reservation_probe(NULL, NULL);
    wallet_unmark_outpoint_spent(fx->w, &tx->tx.hash, 3);
    tx->tx.num_vout = 4096;
    return ok;
}


static bool wrc_listunspent_seed(struct wrc_fx *fx, unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        struct db_wallet_utxo u = {0};
        wrc_txid((uint16_t)i, u.txid);
        u.value = 2000;
        u.script = fx->own_script.data;
        u.script_len = fx->own_script.size;
        if (!db_wallet_utxo_save(&fx->ndb, &u)) return false;
    }
    return true;
}

static bool wrc_count_utxo(struct db_wallet_utxo *u, void *ctx)
{
    (void)u;
    (*(size_t *)ctx)++;
    return true;
}

struct wrc_progress { size_t calls, limit; };

static int wrc_interrupt_after(void *ctx)
{
    struct wrc_progress *p = ctx;
    p->calls++;
    return p->limit && p->calls > p->limit;
}

static bool wrc_listunspent_interrupt(struct wrc_fx *fx)
{
    struct wrc_progress p = {0};
    sqlite3_progress_handler(fx->ndb.db, 1, wrc_interrupt_after, &p);
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT txid,vout,value,address_hash,script,height,is_coinbase"
        " FROM wallet_utxos WHERE spent_txid IS NULL ORDER BY value DESC";
    bool prepared = sqlite3_prepare_v2(fx->ndb.db, sql, -1, &s, NULL) == SQLITE_OK;
    bool row = prepared && sqlite3_step(s) == SQLITE_ROW;
    size_t first_row = p.calls;
    if (s) (void)sqlite3_finalize(s);
    p.calls = 0; p.limit = first_row + 1;
    size_t visited = 0;
    enum db_wallet_utxo_iter_result status = db_wallet_utxo_each_unspent(
        &fx->ndb, 128 * 1024 * 1024, wrc_count_utxo, &visited);
    sqlite3_progress_handler(fx->ndb.db, 0, NULL, NULL);
    return row && status == DB_WALLET_UTXO_ITER_READ_ERROR && visited == 0;
}


static bool wrc_listunspent_db_faults(struct wrc_fx *fx)
{
    struct json_value result = {0};
    bool denied = sqlite3_set_authorizer(fx->ndb.db, wrc_deny_wallet_read, NULL) == SQLITE_OK;
    bool refused = denied && !wrc_listunspent(fx, &result);
    json_free(&result);
    bool reset = sqlite3_set_authorizer(fx->ndb.db, NULL, NULL) == SQLITE_OK;
    bool began = sqlite3_exec(fx->ndb.db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    bool tx_refused = began && !wrc_listunspent(fx, &result);
    json_free(&result);
    bool rollback = began && sqlite3_exec(fx->ndb.db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    size_t visited = 0;
    enum db_wallet_utxo_iter_result limited = db_wallet_utxo_each_unspent(
        &fx->ndb, 1, wrc_count_utxo, &visited);
    bool interrupted = wrc_listunspent_interrupt(fx);
    bool damaged = sqlite3_exec(fx->ndb.db,
        "UPDATE wallet_utxos SET txid=x'01' WHERE value=1000", NULL, NULL, NULL) == SQLITE_OK;
    bool bad_refused = damaged && !wrc_listunspent(fx, &result);
    json_free(&result);
    return refused && reset && tx_refused && rollback && bad_refused && interrupted &&
           limited == DB_WALLET_UTXO_ITER_RESOURCE && visited == 0;
}

static bool wrc_listunspent_db_complete(struct wrc_fx *fx)
{
    if (!wrc_listunspent_seed(fx, 4096)) return false;
    struct json_value result = {0};
    bool ok = wrc_listunspent_min(fx, &result, 0) && json_size(&result) == 4096;
    json_free(&result);
    struct db_wallet_utxo last = {0};
    wrc_txid(4096, last.txid); last.value = 1000; last.height = 6;
    last.script = fx->own_script.data; last.script_len = fx->own_script.size;
    ok = ok && db_wallet_utxo_save(&fx->ndb, &last) &&
         wrc_listunspent_min(fx, &result, 0) && json_size(&result) == 4097;
    size_t bytes = json_write(&result, NULL, 0);
    char *wire = NULL; size_t wire_bytes = 0;
    bool serialized = rpc_http_test_serialize_response(&result, &wire, &wire_bytes);
    free(wire);
    ok = ok && serialized && wire_bytes == bytes;
    json_free(&result);
    ok = ok && wrc_listunspent(fx, &result) && json_size(&result) == 1;
    json_free(&result);
    printf("LIST_DB bytes=%zu ok=%d\n", bytes, ok);
    return wrc_listunspent_db_faults(fx) && ok;
}

static bool wrc_listunspent_memory_make(struct wallet_tx *a, struct wallet_tx *b,
                                         struct wrc_fx *fx)
{
    transaction_init(&a->tx); transaction_init(&b->tx);
    if (!transaction_alloc(&a->tx, 0, 4096)) return false;
    a->used = true; a->confirms = 5; a->tx.hash.data[0] = 1;
    fx->w->num_wallet_tx = 1;
    if (!transaction_alloc(&b->tx, 0, 1)) return false;
    b->used = true; b->confirms = 1; b->tx.hash.data[0] = 2;
    fx->w->num_wallet_tx = 2;
    for (size_t i = 0; i < 4096; i++) {
        a->tx.vout[i].value = 2000;
        a->tx.vout[i].script_pub_key = fx->own_script;
    }
    b->tx.vout[0].value = 1000;
    b->tx.vout[0].script_pub_key = fx->own_script;
    return true;
}

static bool wrc_listunspent_memory_filtered(struct wrc_fx *fx)
{
    struct json_value params = {0}, arg = {0}, result = {0};
    json_set_array(&params); json_set_int(&arg, 1);
    bool ok = json_push_back(&params, &arg) && json_push_back(&params, &arg) &&
              rpc_table_execute(&fx->tbl, "listunspent", &params, &result) &&
              json_size(&result) == 1;
    json_free(&params); json_free(&arg); json_free(&result);
    return ok;
}

static bool wrc_listunspent_memory_complete(struct wrc_fx *fx)
{
    wallet_rpc_context_set_node_db(NULL);
    struct wallet_tx *a = &fx->w->map_wallet[0], *b = &fx->w->map_wallet[1];
    if (!wrc_listunspent_memory_make(a, b, fx)) return false;
    struct json_value result = {0};
    b->used = false; fx->w->num_wallet_tx = 1;
    bool ok = wrc_listunspent_min(fx, &result, 0) && json_size(&result) == 4096;
    json_free(&result);
    b->used = true; fx->w->num_wallet_tx = 2;
    ok = ok && wrc_listunspent_min(fx, &result, 0) && json_size(&result) == 4097;
    json_free(&result);
    ok = ok && wrc_listunspent_memory_filtered(fx);
    b->used = false; fx->w->num_wallet_tx = 1;
    bool policy = wrc_listunspent_policy(fx, a);
    b->used = true; fx->w->num_wallet_tx = 2;
    return ok && policy;
}

static int wrc_listunspent_complete(void)
{
    struct wrc_fx fx;
    if (!wrc_open(&fx, false)) return 1;
    size_t count = 0;
    bool empty = db_wallet_utxo_each_unspent(&fx.ndb, 0, wrc_count_utxo, &count) ==
                 DB_WALLET_UTXO_ITER_OK && count == 0;
    bool key = wallet_import_key(fx.w, &fx.key);
    bool db = empty && key && wrc_listunspent_db_complete(&fx);
    bool memory = key && wrc_listunspent_memory_complete(&fx);
    wrc_close(&fx);
    printf("wallet_rows_coins: listunspent complete database=%d memory=%d\n", db, memory);
    return !db || !memory;
}

int wrc_run_tests(void);
int wrc_run_tests(void)
{
    int failures = 0;
    failures += wrc_listunspent_complete();
    failures += wrc_import_agreeing_row_kept();
    failures += wrc_import_disagreeing_rows_skipped();
    failures += wrc_import_height_comes_from_coin();
    failures += wrc_import_without_coins_view_withholds();
    failures += wrc_enumeration_empty_and_cap();
    failures += wrc_import_enumeration_failure(false, false);
    failures += wrc_import_enumeration_failure(false, true);
    failures += wrc_import_enumeration_failure(true, false);
    failures += wrc_import_enumeration_failure(true, true);
    failures += wrc_import_save_failure(false);
    failures += wrc_import_save_failure(true);
    failures += wrc_importaddress_skips_disagreeing_rows();
    failures += wrc_importaddress_without_coins_view_withholds();
    failures += wrc_importprivkey_says_when_capped();
    failures += wrc_importaddress_says_when_capped();
    failures += wrc_import_holed_node_skipped();
    failures += wrc_import_holed_node_withheld();
    failures += wrc_import_holed_node_capped();
    failures += wrc_repair_keeps_rows("rescanwallet",
        "wallet_rows_coins: rescanwallet on a bundle-started node keeps the imported rows",
        false);
    failures += wrc_repair_keeps_rows("reindexdb",
        "wallet_rows_coins: reindexdb on a bundle-started node keeps the wallet rows",
        false);
    failures += wrc_repair_keeps_rows("rescanwallet",
        "wallet_rows_coins: rescanwallet keeps a watch-only-only wallet's rows on a bundle-started node",
        true);
    failures += wrc_repair_keeps_rows("reindexdb",
        "wallet_rows_coins: reindexdb keeps a watch-only-only wallet's rows on a bundle-started node",
        true);
    failures += wrc_repair_no_tip_keeps_rows();
    failures += wrc_importaddress_no_rescan_advice(false);
    failures += wrc_importaddress_no_rescan_advice(true);
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
