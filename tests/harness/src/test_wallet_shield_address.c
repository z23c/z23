/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z_shieldaddress and core.wallet.shielded.shield: one public address swept
 * into the wallet's own shielded address with no transparent output.
 *
 * Every fixture is an isolated temporary datadir with its own node.db, wallet
 * and synthetic header chain; nothing touches a running node or real funds.
 * The selection, the coinbase-protection check and the leaf run against the
 * real code. The transaction build with a real Sapling output proof runs only
 * when the proving parameters load; without them it is reported as unobserved,
 * never as passed. Mempool admission, relay and replay of a sent sweep need a
 * running node and belong to the regtest group. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_shield_address.h"
#include "controllers/wallet_shielded_internal.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_delta.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "models/database.h"
#include "models/wallet_send_once.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/params_init.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "script/script.h"
#include "script/standard.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WSA_CHECK(name, expr) do {                                          \
    if (expr) { printf("  wallet_shield_address: %s... OK\n", (name)); }      \
    else { printf("  wallet_shield_address: %s... FAIL\n", (name));          \
           failures++; }                                                    \
} while (0)

#define WSA_TIP 300
#define WSA_FEE 100
#define WSA_KEY "shield-key-0001"

struct wsa_fix {
    struct node_db ndb;
    char dir[256];
    char path[320];
    struct wallet *w;
    struct main_state ms;
    struct block_index *bi;
    struct privkey key;
    struct key_id kid;
    struct script spk;
    struct wallet_sqlite wdb;
    bool wdb_open;
    char to[192];
};

static bool g_sovereign = true;

/* ── Fixture ──────────────────────────────────────────────────────────── */

static bool wsa_chain(struct wsa_fix *fx)
{
    fx->bi = zcl_calloc(WSA_TIP + 1, sizeof(*fx->bi), "wsa_chain");
    if (!fx->bi)
        return false;
    main_state_init(&fx->ms);
    for (int h = 0; h <= WSA_TIP; h++) {
        block_index_init(&fx->bi[h]);
        fx->bi[h].nHeight = h;
        fx->bi[h].hashBlock.data[0] = (uint8_t)(h + 1);
        fx->bi[h].hashBlock.data[1] = (uint8_t)((h + 1) >> 8);
        fx->bi[h].phashBlock = &fx->bi[h].hashBlock;
        fx->bi[h].pprev = h ? &fx->bi[h - 1] : NULL;
    }
    return active_chain_move_window_tip(&fx->ms.chain_active,
                                        &fx->bi[WSA_TIP]);
}

static bool wsa_to(struct wsa_fix *fx, uint8_t seed_byte)
{
    uint8_t seed[32], d[ZC_DIVERSIFIER_SIZE], pk[32];
    memset(seed, seed_byte, sizeof(seed));
    const struct chain_params *cp = chain_params_get();
    return sapling_keystore_set_seed(&fx->w->sapling_keys, seed) &&
           sapling_keystore_new_address(&fx->w->sapling_keys, d, pk) &&
           sapling_encode_payment_address(
               d, pk, cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], fx->to,
               sizeof(fx->to));
}

/* A datadir whose coin set is self-derived, so the sovereignty guard allows a
 * spend: the posture of a node that folded its own history. */
static bool wsa_sovereign(const char *dir)
{
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    struct uint256 t1;
    uint256_set_null(&t1);
    t1.data[0] = 0x51;
    t1.data[31] = 0x77;
    unsigned char sc[4] = { 0xE0, 0xE0, 0xE0, 0xE0 };
    reducer_frontier_provable_tip_set(50);
    char *err = NULL;
    bool ok = db && coins_kv_ensure_schema(db) &&
              coins_kv_add(db, t1.data, 0, 1234, 50, true, sc, sizeof(sc)) &&
              sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              coins_kv_set_applied_height_in_tx(db, 51) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err)
        sqlite3_free(err);
    return ok;
}

static bool wsa_open(struct wsa_fix *fx, const char *tag, bool with_private)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "wallet_shield_address", tag);
    (void)snprintf(fx->path, sizeof(fx->path), "%s/node.db", fx->dir);
    if (!node_db_open(&fx->ndb, fx->path) || !wsa_chain(fx) ||
        (g_sovereign && !wsa_sovereign(fx->dir)))
        return false;
    fx->w = zcl_calloc(1, sizeof(*fx->w), "wsa_wallet");
    if (!fx->w)
        return false;
    wallet_init(fx->w);
    fx->w->default_fee = WSA_FEE;
    privkey_make_new(&fx->key, true);
    struct pubkey pub;
    privkey_get_pubkey(&fx->key, &pub);
    fx->kid = pubkey_get_id(&pub);
    script_for_p2pkh(&fx->spk, &fx->kid);
    if (!keystore_add_key(&fx->w->keystore, &fx->key) ||
        (with_private && !wsa_to(fx, 0x5A)))
        return false;
    wallet_rpc_context_set_base(fx->w, &fx->ms, fx->dir, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(&fx->ndb);
    return true;
}

static void wsa_close(struct wsa_fix *fx)
{
    node_rpc_client_set_test_hook(NULL);
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    if (fx->wdb_open)
        wallet_sqlite_close(&fx->wdb);
    node_db_close(&fx->ndb);
    if (g_sovereign) {
        progress_store_close();
        reducer_frontier_provable_tip_reset();
    }
    main_state_free(&fx->ms);
    free(fx->bi);
    if (fx->w) {
        wallet_free(fx->w);
        free(fx->w);
    }
    memory_cleanse(&fx->key, sizeof(fx->key));
    (void)test_rm_rf_recursive(fx->dir);
}

/* One unspent coin of `addr` (the wallet key's address when NULL). */
static bool wsa_coin(struct wsa_fix *fx, unsigned id, int64_t value,
                     int height, bool coinbase, const struct key_id *addr)
{
    struct script spk;
    const struct key_id *kid = addr ? addr : &fx->kid;
    script_for_p2pkh(&spk, kid);
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    u.txid[0] = (uint8_t)id;
    u.txid[1] = (uint8_t)(id >> 8);
    u.txid[31] = 0xC7;
    u.value = value;
    memcpy(u.address_hash, kid->id.data, 20);
    u.script = spk.data;
    u.script_len = spk.size;
    u.height = height;
    u.is_coinbase = coinbase;
    return db_wallet_utxo_save(&fx->ndb, &u);
}

static void wsa_other_key(struct key_id *kid, uint8_t tag)
{
    memset(kid, 0, sizeof(*kid));
    memset(kid->id.data, tag, 20);
}

static void wsa_addr(const struct key_id *kid, char *out, size_t cap)
{
    struct tx_destination d;
    memset(&d, 0, sizeof(d));
    d.type = DEST_KEY_ID;
    d.id.key = *kid;
    out[0] = '\0';
    (void)wallet_encode_destination(&d, out, cap);
}

/* ── RPC helpers ──────────────────────────────────────────────────────── */

static bool wsa_rpc(const char *json, struct json_value *result)
{
    struct json_value params;
    json_init(&params);
    json_init(result);
    bool ok = json_read(&params, json, strlen(json)) &&
              rpc_z_shieldaddress(&params, false, result);
    json_free(&params);
    return ok;
}

static bool wsa_msg_has(const struct json_value *r, const char *needle)
{
    const char *s = r->type == JSON_STR ? json_get_str(r)
                                        : json_get_str(json_get(r, "message"));
    return s && strstr(s, needle);
}

static int64_t wsa_int(const struct json_value *r, const char *key)
{
    const struct json_value *v = json_get(r, key);
    return v ? json_get_int(v) : -1;
}

static bool wsa_state_is(const struct json_value *r, const char *state)
{
    const char *s = json_get_str(json_get(r, "state"));
    return s && strcmp(s, state) == 0;
}

/* ── Leg: selection, maturity, cap ────────────────────────────────────── */

static int wsa_test_selection(void)
{
    int failures = 0;
    struct wsa_fix fx;
    WSA_CHECK("selection fixture opens", wsa_open(&fx, "select", true));
    struct key_id other;
    wsa_other_key(&other, 0x77);
    char from[128], other_s[128];
    wsa_addr(&fx.kid, from, sizeof(from));
    wsa_addr(&other, other_s, sizeof(other_s));

    /* Address A: two plain coins, a coinbase exactly 100 deep (included), one
     * 99 deep (maturing), and a spent coin. Address B: one larger coin. */
    WSA_CHECK("coins saved",
              wsa_coin(&fx, 1, 500, 10, false, NULL) &&
                  wsa_coin(&fx, 2, 700, 11, false, NULL) &&
                  wsa_coin(&fx, 3, 1000, WSA_TIP - 100, true, NULL) &&
                  wsa_coin(&fx, 4, 2000, WSA_TIP - 99, true, NULL) &&
                  wsa_coin(&fx, 5, 4000, 12, false, NULL) &&
                  wsa_coin(&fx, 6, 9000, 13, false, &other));
    uint8_t spent_by[32] = { 0xEE };
    uint8_t txid5[32] = { 5, 0 };
    txid5[31] = 0xC7;
    WSA_CHECK("one coin marked spent",
              db_wallet_utxo_mark_spent(&fx.ndb, txid5, 0, spent_by, 0));

    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    struct wallet_shield_plan *p = zcl_calloc(1, sizeof(*p), "wsa_plan");
    struct json_value res;
    json_init(&res);
    p->floor = -1;
    WSA_CHECK("plan loads for A",
              p && wallet_shield_load(ctx, from, p, &res) ==
                       WALLET_SHIELD_LOAD_OK);
    WSA_CHECK("every mature coin of A and none of B (3 coins)", p->count == 3);
    WSA_CHECK("total is 500+700+1000", p->total == 2200);
    WSA_CHECK("coinbase at tip-100 is taken, tip-99 is not",
              p->coinbase_count == 1 && p->maturing == 2000);
    WSA_CHECK("fee is the wallet fee, nothing beyond the cap",
              p->fee == WSA_FEE && p->remaining == 0);
    WSA_CHECK("destination is the wallet's own address",
              strcmp(p->to, fx.to) == 0);

    struct wallet_tx wtx;
    WSA_CHECK("assembles", wallet_shield_assemble(p, &wtx, &res));
    WSA_CHECK("zero transparent outputs, one input per coin",
              wtx.tx.num_vout == 0 && wtx.tx.num_vin == 3);
    WSA_CHECK("no change: value_balance is -(total - fee)",
              wtx.tx.value_balance == -(2200 - WSA_FEE));
    WSA_CHECK("expiry is tip + 20",
              wtx.tx.expiry_height == (uint32_t)(WSA_TIP + 20));
    transaction_free(&wtx.tx);
    wallet_shield_plan_free(p);

    memset(p, 0, sizeof(*p));
    p->floor = -1;
    WSA_CHECK("from omitted picks the address with the largest mature total",
              wallet_shield_load(ctx, NULL, p, &res) ==
                      WALLET_SHIELD_LOAD_OK &&
                  p->count == 1 && p->total == 9000 &&
                  strcmp(p->from, other_s) == 0);
    wallet_shield_plan_free(p);
    free(p);
    json_free(&res);
    wsa_close(&fx);
    return failures;
}

static int wsa_test_cap(void)
{
    int failures = 0;
    struct wsa_fix fx;
    WSA_CHECK("cap fixture opens", wsa_open(&fx, "cap", true));
    char from[128];
    wsa_addr(&fx.kid, from, sizeof(from));
    bool saved = true;
    for (unsigned i = 1; i <= 300; i++)
        saved = wsa_coin(&fx, i, 1000, 5, false, NULL) && saved;
    WSA_CHECK("300 coins saved", saved);

    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    struct wallet_shield_plan *p = zcl_calloc(1, sizeof(*p), "wsa_plan");
    struct json_value res;
    json_init(&res);
    p->floor = -1;
    WSA_CHECK("first run loads",
              wallet_shield_load(ctx, from, p, &res) == WALLET_SHIELD_LOAD_OK);
    WSA_CHECK("256 inputs and 44 remaining",
              p->count == 256 && p->remaining == 44 &&
                  p->total == 256 * 1000);
    bool deleted = true;
    for (size_t i = 0; i < p->count; i++)
        deleted = db_wallet_utxo_delete(&fx.ndb, p->coins[i].txid,
                                        p->coins[i].vout) && deleted;
    wallet_shield_plan_free(p);
    WSA_CHECK("taken coins removed", deleted);
    memset(p, 0, sizeof(*p));
    p->floor = -1;
    WSA_CHECK("second run takes the rest",
              wallet_shield_load(ctx, from, p, &res) ==
                      WALLET_SHIELD_LOAD_OK &&
                  p->count == 44 && p->remaining == 0);
    wallet_shield_plan_free(p);
    free(p);
    json_free(&res);
    wsa_close(&fx);
    return failures;
}

/* ── Leg: refusals ────────────────────────────────────────────────────── */

static int wsa_test_refusals(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128], body[512];
    struct json_value res;

    WSA_CHECK("refusal fixture opens (no private address)",
              wsa_open(&fx, "refuse", false));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coin saved", wsa_coin(&fx, 1, 5000, 5, false, NULL));
    (void)snprintf(body, sizeof(body), "[\"%s\"]", from);
    bool answered = wsa_rpc(body, &res);
    const char *code = json_get_str(json_get(&res, "code"));
    WSA_CHECK("no shielded address: plan refuses NO_PRIVATE_ADDRESS",
              answered && wsa_state_is(&res, "refused") && code &&
                  strcmp(code, WALLET_SHIELD_NO_ADDRESS) == 0);
    WSA_CHECK("it created no address", fx.w->sapling_keys.num_keys == 0);
    json_free(&res);
    wsa_close(&fx);

    WSA_CHECK("fee-sized fixture opens", wsa_open(&fx, "fee", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coin worth exactly the fee",
              wsa_coin(&fx, 1, WSA_FEE, 5, false, NULL));
    (void)snprintf(body, sizeof(body), "[\"%s\"]", from);
    answered = wsa_rpc(body, &res);
    code = json_get_str(json_get(&res, "code"));
    WSA_CHECK("total equal to the fee: plan refuses NOTHING_TO_SHIELD",
              answered && wsa_state_is(&res, "refused") && code &&
                  strcmp(code, WALLET_SHIELD_NOTHING) == 0);
    json_free(&res);
    (void)snprintf(body, sizeof(body),
                   "[\"%s\",\"%s\",null,\"0.00000100\",\"%s\",1,%d]", from,
                   fx.to, WSA_KEY, WSA_FEE);
    answered = wsa_rpc(body, &res);
    WSA_CHECK("keyed call refuses with the code and frees the key",
              answered && wsa_state_is(&res, "released") &&
                  wsa_msg_has(&res, WALLET_SHIELD_NOTHING) &&
                  db_wallet_send_once_count(&fx.ndb) == 0);
    json_free(&res);
    wsa_close(&fx);

    if (!sapling_proving_available()) {
        WSA_CHECK("prover fixture opens", wsa_open(&fx, "prover", true));
        wsa_addr(&fx.kid, from, sizeof(from));
        WSA_CHECK("coin saved", wsa_coin(&fx, 1, 5000, 5, false, NULL));
        (void)snprintf(body, sizeof(body), "[\"%s\"]", from);
        answered = wsa_rpc(body, &res);
        code = json_get_str(json_get(&res, "code"));
        WSA_CHECK("no proving parameters: plan refuses PROVING_UNAVAILABLE",
                  answered && wsa_state_is(&res, "refused") && code &&
                      strcmp(code, WALLET_SHIELD_NO_PROVER) == 0);
        json_free(&res);
        wsa_close(&fx);
    } else {
        printf("  wallet_shield_address: PROVING_UNAVAILABLE refusal... "
               "UNOBSERVED (proving already available in this process)\n");
    }
    return failures;
}

/* ── Leg: sovereignty guard ───────────────────────────────────────────── */

static int wsa_test_sovereignty(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128], body[512];
    struct json_value res;
    g_sovereign = false;
    WSA_CHECK("borrowed-history fixture opens", wsa_open(&fx, "sov", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coin saved", wsa_coin(&fx, 1, 5000, 5, false, NULL));
    (void)snprintf(body, sizeof(body), "[\"%s\"]", from);
    bool answered = wsa_rpc(body, &res);
    WSA_CHECK("guard refuses the plan",
              !answered && wsa_msg_has(&res, "spend refused"));
    json_free(&res);
    (void)snprintf(body, sizeof(body),
                   "[\"%s\",\"%s\",null,\"0.00000100\",\"%s\",1,5000]", from,
                   fx.to, WSA_KEY);
    answered = wsa_rpc(body, &res);
    WSA_CHECK("guard refuses the keyed call, key freed, nothing built",
              answered && wsa_state_is(&res, "released") &&
                  wsa_msg_has(&res, "spend refused") &&
                  db_wallet_send_once_count(&fx.ndb) == 0);
    json_free(&res);
    wsa_close(&fx);
    g_sovereign = true;
    return failures;
}

/* ── Leg: wallet lock and the plan while locked ───────────────────────── */

static int wsa_test_lock(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128], body[512];
    struct json_value res;
    WSA_CHECK("lock fixture opens", wsa_open(&fx, "lock", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coin saved", wsa_coin(&fx, 1, 5000, 5, false, NULL));

    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    (void)snprintf(body, sizeof(body),
                   "[\"%s\",\"%s\",null,\"0.00000100\",\"%s\",1,5000]", from,
                   fx.to, WSA_KEY);
    bool answered = wsa_rpc(body, &res);
    WSA_CHECK("locked wallet: the keyed call is refused before anything is "
              "built and the key is freed",
              answered && wsa_state_is(&res, "released") &&
                  wsa_msg_has(&res, "locked") &&
                  db_wallet_send_once_count(&fx.ndb) == 0);
    json_free(&res);

    (void)snprintf(body, sizeof(body), "[\"%s\"]", from);
    answered = wsa_rpc(body, &res);
    WSA_CHECK("locked wallet: planning still works",
              answered && (wsa_state_is(&res, "plan") ||
                           wsa_state_is(&res, "refused")));
    json_free(&res);
    wallet_lock_reset_for_test();
    wsa_close(&fx);
    return failures;
}

/* ── Leg: the destination is the wallet's, never the caller's ─────────── */

static int wsa_test_destination(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128], body[512], foreign[192];
    struct json_value res;
    WSA_CHECK("destination fixture opens", wsa_open(&fx, "dest", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coin saved", wsa_coin(&fx, 1, 5000, 5, false, NULL));

    /* A different shielded address: another seed in a scratch keystore. */
    struct sapling_keystore scratch;
    memset(&scratch, 0, sizeof(scratch));
    uint8_t seed[32], d[ZC_DIVERSIFIER_SIZE], pk[32];
    memset(seed, 0x33, sizeof(seed));
    const struct chain_params *cp = chain_params_get();
    WSA_CHECK("foreign address derived",
              sapling_keystore_set_seed(&scratch, seed) &&
                  sapling_keystore_new_address(&scratch, d, pk) &&
                  sapling_encode_payment_address(
                      d, pk, cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                      foreign, sizeof(foreign)));
    memory_cleanse(&scratch, sizeof(scratch));
    WSA_CHECK("the foreign address is not the wallet's",
              strcmp(foreign, fx.to) != 0);

    (void)snprintf(body, sizeof(body),
                   "[\"%s\",\"%s\",null,\"0.00000100\",\"%s\",1,5000]", from,
                   foreign, WSA_KEY);
    bool answered = wsa_rpc(body, &res);
    WSA_CHECK("a keyed call naming another address is refused "
              "PLAN_TOKEN_MISMATCH, nothing sent",
              answered && wsa_state_is(&res, "released") &&
                  wsa_msg_has(&res, WALLET_SHIELD_CHANGED) &&
                  db_wallet_send_once_count(&fx.ndb) == 0);
    json_free(&res);

    (void)snprintf(body, sizeof(body),
                   "[\"%s\",\"%s\",null,\"0.00000100\",\"%s\",2,5000]", from,
                   fx.to, "shield-key-0002");
    answered = wsa_rpc(body, &res);
    WSA_CHECK("a wrong input count is refused PLAN_TOKEN_MISMATCH",
              answered && wsa_state_is(&res, "released") &&
                  wsa_msg_has(&res, WALLET_SHIELD_CHANGED));
    json_free(&res);

    (void)snprintf(body, sizeof(body),
                   "[\"%s\",\"%s\",null,\"0.00000100\",\"%s\",1,4999]", from,
                   fx.to, "shield-key-0003");
    answered = wsa_rpc(body, &res);
    WSA_CHECK("a wrong total is refused PLAN_TOKEN_MISMATCH",
              answered && wsa_state_is(&res, "released") &&
                  wsa_msg_has(&res, WALLET_SHIELD_CHANGED));
    json_free(&res);
    wsa_close(&fx);

    /* An issued receive address wins over the keystore address. */
    WSA_CHECK("receive fixture opens", wsa_open(&fx, "recv", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coin saved", wsa_coin(&fx, 1, 5000, 5, false, NULL));
    WSA_CHECK("wallet database opens",
              wallet_sqlite_open_r(&fx.wdb, fx.ndb.db).ok);
    fx.wdb_open = true;
    wallet_rpc_context_set_base(fx.w, &fx.ms, fx.dir, &fx.wdb, NULL, NULL);
    struct sapling_key_entry acct;
    uint8_t rd[ZC_DIVERSIFIER_SIZE], rpk[32];
    char issued[192];
    WSA_CHECK("a receive address is issued",
              sapling_keystore_copy_account(&fx.w->sapling_keys, &acct) &&
                  wallet_sqlite_diversifier_reserve(&fx.wdb, &acct, rd, rpk) &&
                  sapling_encode_payment_address(
                      rd, rpk, cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                      issued, sizeof(issued)));
    memory_cleanse(&acct, sizeof(acct));
    (void)snprintf(body, sizeof(body), "[\"%s\"]", from);
    answered = wsa_rpc(body, &res);
    const char *to = json_get_str(json_get(&res, "to"));
    WSA_CHECK("the plan pays the most recently issued receive address",
              answered && to && strcmp(to, issued) == 0 &&
                  strcmp(issued, fx.to) != 0);
    json_free(&res);
    wsa_close(&fx);
    return failures;
}

/* ── Leg: coinbase protection ─────────────────────────────────────────── */

struct wsa_coinset {
    struct db_wallet_utxo *coins;
    size_t n;
};

static bool wsa_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    const struct wsa_coinset *set = user;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < set->n; i++) {
        if (set->coins[i].vout == vout &&
            memcmp(set->coins[i].txid, txid->data, 32) == 0) {
            out->found = true;
            out->value = set->coins[i].value;
            out->height = set->coins[i].height;
            out->is_coinbase = true;
        }
    }
    return true;
}

static bool wsa_block(struct block *b, const struct transaction *spend)
{
    block_init(b);
    b->num_vtx = 2;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "wsa_vtx");
    if (!b->vtx)
        return false;
    struct transaction *cb = &b->vtx[0];
    transaction_init(cb);
    (void)transaction_alloc(cb, 1, 1);
    outpoint_set_null(&cb->vin[0].prevout);
    cb->vout[0].value = 1000000000LL;
    uint8_t pk[3] = { 0x76, 0xa9, 0x01 };
    script_set(&cb->vout[0].script_pub_key, pk, 3);
    cb->hash.data[0] = 0xC0;
    b->vtx[1] = *spend;
    transaction_compute_hash(&b->vtx[1]);
    return true;
}

/* Run `spend` as the second transaction of a block through the reducer's
 * delta rules. *protect is set when it was rejected coinbase_protect. The
 * block holds a copy of the transaction's pointers and gives them back. */
static bool wsa_delta_ok(const struct transaction *spend,
                         struct wsa_coinset *set, bool *protect)
{
    struct transaction copy = *spend;
    struct block b;
    struct delta_summary out;
    if (!wsa_block(&b, &copy))
        return false;
    utxo_apply_compute_block_delta(&b, 1, wsa_lookup, set, &out);
    bool ok = out.ok;
    *protect = out.status && strcmp(out.status, "coinbase_protect") == 0;
    free_delta(&out);
    memset(&b.vtx[1], 0, sizeof(b.vtx[1]));
    block_free(&b);
    return ok;
}

static int wsa_test_coinbase_protect(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128];
    WSA_CHECK("protection fixture opens", wsa_open(&fx, "protect", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("three mature coinbase coins",
              wsa_coin(&fx, 1, 1000000, 5, true, NULL) &&
                  wsa_coin(&fx, 2, 2000000, 6, true, NULL) &&
                  wsa_coin(&fx, 3, 3000000, 7, true, NULL));
    WSA_CHECK("main-network rule is in force",
              chain_params_get()->consensus.fCoinbaseMustBeProtected);

    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    struct wallet_shield_plan *p = zcl_calloc(1, sizeof(*p), "wsa_plan");
    struct json_value res;
    json_init(&res);
    p->floor = -1;
    WSA_CHECK("plan loads", wallet_shield_load(ctx, from, p, &res) ==
                                WALLET_SHIELD_LOAD_OK &&
                                p->count == 3 && p->coinbase_count == 3);
    struct wsa_coinset set = { p->coins, p->count };
    struct wallet_tx wtx;
    WSA_CHECK("assembles", wallet_shield_assemble(p, &wtx, &res));
    WSA_CHECK("the sweep has num_vout == 0", wtx.tx.num_vout == 0);

    /* The same sweep with one transparent change output, as a plain
     * z_sendmany of less than the balance would make. */
    struct transaction with_change = wtx.tx;
    with_change.vout = zcl_calloc(1, sizeof(*with_change.vout), "wsa_vout");
    with_change.num_vout = 1;
    if (with_change.vout) {
        with_change.vout[0].value = 1;
        script_set(&with_change.vout[0].script_pub_key, fx.spk.data,
                   fx.spk.size);
    }
    bool protect = false;
    bool ok = with_change.vout &&
              wsa_delta_ok(&with_change, &set, &protect);
    WSA_CHECK("control: a coinbase spend with a transparent change output is "
              "rejected coinbase_protect", !ok && protect);
    ok = wsa_delta_ok(&wtx.tx, &set, &protect);
    WSA_CHECK("the sweep passes the coinbase_protect check", ok && !protect);
    free(with_change.vout);
    transaction_free(&wtx.tx);
    wallet_shield_plan_free(p);
    free(p);
    json_free(&res);
    wsa_close(&fx);
    return failures;
}

/* ── Leg: the real build ──────────────────────────────────────────────── */

static int wsa_test_build(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128];
    WSA_CHECK("build fixture opens", wsa_open(&fx, "build", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("two mature coinbase coins",
              wsa_coin(&fx, 1, 1000000, 5, true, NULL) &&
                  wsa_coin(&fx, 2, 2000000, 6, true, NULL));
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    struct wallet_shield_plan *p = zcl_calloc(1, sizeof(*p), "wsa_plan");
    struct json_value res;
    json_init(&res);
    p->floor = -1;
    WSA_CHECK("plan loads", wallet_shield_load(ctx, from, p, &res) ==
                                WALLET_SHIELD_LOAD_OK && p->count == 2);
    struct wallet_tx wtx;
    bool built = wallet_shield_build(ctx, p, &wtx, &res);
    WSA_CHECK("builds with the real prover", built);
    if (built) {
        struct wsa_coinset set = { p->coins, p->count };
        bool protect = false;
        WSA_CHECK("one Sapling output, no transparent output",
                  wtx.tx.num_shielded_output == 1 && wtx.tx.num_vout == 0);
        WSA_CHECK("every input is signed",
                  wtx.tx.vin[0].script_sig.size > 0 &&
                      wtx.tx.vin[1].script_sig.size > 0);
        WSA_CHECK("value_balance is -(total - fee)",
                  wtx.tx.value_balance == -(3000000 - WSA_FEE));
        WSA_CHECK("the built sweep passes the coinbase_protect check",
                  wsa_delta_ok(&wtx.tx, &set, &protect) && !protect);
        transaction_free(&wtx.tx);
        wallet_shield_plan_free(p);
        free(p);
        json_free(&res);
        wsa_close(&fx);
        return failures;
    }
    wallet_shield_plan_free(p);
    free(p);
    json_free(&res);
    wsa_close(&fx);
    return failures;
}

/* ── Leg: the native leaf ─────────────────────────────────────────────── */

enum wsa_hook_mode { WSA_HOOK_REAL, WSA_HOOK_STUB_SEND, WSA_HOOK_DRIFT };

static struct wsa_fix *g_fix;
static int g_hook_mode;
static int g_keyed_calls;
static char g_keyed_params[1024];

static char *wsa_error_body(const char *msg)
{
    char buf[512];
    (void)snprintf(buf, sizeof(buf),
                   "{\"error\":{\"code\":-1,\"message\":\"%s\"}}", msg);
    return strdup(buf);
}

static char *wsa_hook(const char *method, const char *params_json)
{
    if (strcmp(method, "z_shieldaddress") != 0)
        return strdup("null");
    struct json_value params, result;
    json_init(&params);
    json_init(&result);
    if (!json_read(&params, params_json, strlen(params_json)))
        return wsa_error_body("bad params");
    const struct json_value *key = json_at(&params, 4);
    bool keyed = key && !json_is_null(key);
    if (keyed) {
        g_keyed_calls++;
        (void)snprintf(g_keyed_params, sizeof(g_keyed_params), "%s",
                       params_json);
        if (g_hook_mode == WSA_HOOK_STUB_SEND) {
            json_free(&params);
            return strdup("{\"state\":\"committed\",\"txid\":\""
                          "abababababababababababababababababababababababababababababababab"
                          "\",\"replayed\":false}");
        }
        if (g_hook_mode == WSA_HOOK_DRIFT)
            (void)wsa_coin(g_fix, 900, 12345, 20, false, NULL);
    }
    bool ok = rpc_z_shieldaddress(&params, false, &result);
    char out[4096];
    char *body = NULL;
    if (ok && json_write(&result, out, sizeof(out)) > 0)
        body = strdup(out);
    else
        body = wsa_error_body(json_get_str(&result) ? json_get_str(&result)
                                                    : "failed");
    json_free(&params);
    json_free(&result);
    return body;
}

static const struct zcl_command_spec *wsa_spec(void)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, "core.wallet.shielded.shield") == 0)
            return &reg->commands[i];
    return NULL;
}

static void wsa_leaf(const char *input_json, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = wsa_spec();
    struct json_value in;
    json_init(&in);
    (void)json_read(&in, input_json, strlen(input_json));
    struct zcl_command_request req = {
        .spec = spec, .input = &in, .view = "normal",
    };
    zcl_command_reply_init(reply, spec->output_schema);
    spec->handler(&req, reply);
    json_free(&in);
}

static bool wsa_replied_code(const struct zcl_command_reply *r,
                             const char *code)
{
    return r->exit_code != ZCL_COMMAND_EXIT_OK &&
           strcmp(r->error.code, code) == 0;
}

static void wsa_plan(const char *from, struct zcl_command_reply *plan,
                     char *commit, size_t cap)
{
    char in[512];
    (void)snprintf(in, sizeof(in),
                   "{\"wallet_scope\":\"dev\",\"from\":\"%s\","
                   "\"idempotency_key\":\"%s\"}", from, WSA_KEY);
    wsa_leaf(in, plan);
    const char *c = json_get_str(json_get(&plan->data, "commit_input"));
    (void)snprintf(commit, cap, "%s", c ? c : "{}");
}

static int wsa_test_leaf_plan(struct wsa_fix *fx, const char *from)
{
    int failures = 0;
    struct zcl_command_reply plan;
    char commit[1024];
    wsa_plan(from, &plan, commit, sizeof(commit));
    const struct json_value *d = &plan.data;
    WSA_CHECK("plan stage answers", plan.exit_code == ZCL_COMMAND_EXIT_OK &&
                  strcmp(json_get_str(json_get(d, "stage")), "plan") == 0);
    WSA_CHECK("plan: from, to, counts and amounts",
              strcmp(json_get_str(json_get(d, "from")), from) == 0 &&
                  strcmp(json_get_str(json_get(d, "to")), fx->to) == 0 &&
                  wsa_int(d, "input_count") == 2 &&
                  wsa_int(d, "coinbase_input_count") == 1 &&
                  wsa_int(d, "total_zat") == 3000 &&
                  wsa_int(d, "fee_zat") == WSA_FEE &&
                  wsa_int(d, "amount_zat") == 3000 - WSA_FEE &&
                  wsa_int(d, "remaining_inputs") == 0 &&
                  wsa_int(d, "maturing_zat") == 7000);
    WSA_CHECK("plan: the commit input names no destination and no amount",
              !strstr(commit, "\"to\"") && !strstr(commit, "amount") &&
                  strstr(commit, "plan_token"));
    zcl_command_reply_free(&plan);
    return failures;
}

static int wsa_test_leaf_commit(struct wsa_fix *fx, const char *from)
{
    int failures = 0;
    struct zcl_command_reply plan, out;
    char commit[1024], with_to[1400];

    /* A caller-supplied destination is ignored: the node's address is what the
     * RPC receives. */
    g_hook_mode = WSA_HOOK_STUB_SEND;
    g_keyed_calls = 0;
    wsa_plan(from, &plan, commit, sizeof(commit));
    (void)snprintf(with_to, sizeof(with_to), "%.*s,\"to\":\"zs1callerchosen\"}",
                   (int)strlen(commit) - 1, commit);
    wsa_leaf(with_to, &out);
    WSA_CHECK("commit with a stub node: committed, mutated",
              out.exit_code == ZCL_COMMAND_EXIT_OK &&
                  json_get_bool(json_get(&out.data, "committed")) &&
                  out.error.mutated);
    WSA_CHECK("the RPC got the node's own address, never the caller's",
              g_keyed_calls == 1 && strstr(g_keyed_params, fx->to) &&
                  !strstr(g_keyed_params, "callerchosen"));
    WSA_CHECK("the RPC got the planned count and total",
              strstr(g_keyed_params, ",2,3000]") != NULL);
    WSA_CHECK("the reply echoes the destination the node chose",
              strcmp(json_get_str(json_get(&out.data, "to")), fx->to) == 0);
    zcl_command_reply_free(&out);
    zcl_command_reply_free(&plan);

    /* The token binds the coin set: a coin that arrives after the plan. */
    g_hook_mode = WSA_HOOK_REAL;
    wsa_plan(from, &plan, commit, sizeof(commit));
    WSA_CHECK("extra coin saved", wsa_coin(fx, 50, 777, 21, false, NULL));
    g_keyed_calls = 0;
    wsa_leaf(commit, &out);
    WSA_CHECK("a coin arriving after the plan: PLAN_TOKEN_MISMATCH, no "
              "keyed call", wsa_replied_code(&out, WALLET_SHIELD_CHANGED) &&
                                g_keyed_calls == 0);
    zcl_command_reply_free(&out);
    zcl_command_reply_free(&plan);

    /* Same total, different count: two coins replace one. */
    uint8_t t50[32] = { 50, 0 };
    t50[31] = 0xC7;
    wsa_plan(from, &plan, commit, sizeof(commit));
    WSA_CHECK("one coin replaced by two of the same total",
              db_wallet_utxo_delete(&fx->ndb, t50, 0) &&
                  wsa_coin(fx, 51, 300, 21, false, NULL) &&
                  wsa_coin(fx, 52, 477, 21, false, NULL));
    wsa_leaf(commit, &out);
    WSA_CHECK("same total, different input count: PLAN_TOKEN_MISMATCH",
              wsa_replied_code(&out, WALLET_SHIELD_CHANGED));
    zcl_command_reply_free(&out);
    zcl_command_reply_free(&plan);
    return failures;
}

static int wsa_test_leaf_races(struct wsa_fix *fx, const char *from)
{
    int failures = 0;
    struct zcl_command_reply plan, out;
    char commit[1024];

    /* A coin arrives between the leaf's check and the node's build. */
    g_hook_mode = WSA_HOOK_DRIFT;
    g_keyed_calls = 0;
    wsa_plan(from, &plan, commit, sizeof(commit));
    wsa_leaf(commit, &out);
    WSA_CHECK("a coin arriving during the commit: the node refuses "
              "PLAN_TOKEN_MISMATCH and frees the key",
              g_keyed_calls == 1 &&
                  wsa_replied_code(&out, WALLET_SHIELD_CHANGED) &&
                  db_wallet_send_once_count(&fx->ndb) == 0);
    zcl_command_reply_free(&out);
    zcl_command_reply_free(&plan);

    /* The fee moves after the plan. */
    g_hook_mode = WSA_HOOK_REAL;
    uint8_t t900[32] = { 0x84, 0x03 };
    t900[31] = 0xC7;
    WSA_CHECK("drift coin removed", db_wallet_utxo_delete(&fx->ndb, t900, 0));
    wsa_plan(from, &plan, commit, sizeof(commit));
    fx->w->default_fee = WSA_FEE * 2;
    wsa_leaf(commit, &out);
    WSA_CHECK("the wallet fee moved: FEE_CHANGED, key freed",
              wsa_replied_code(&out, "FEE_CHANGED") &&
                  db_wallet_send_once_count(&fx->ndb) == 0);
    fx->w->default_fee = WSA_FEE;
    zcl_command_reply_free(&out);
    zcl_command_reply_free(&plan);

    /* A plan token from another sweep. */
    (void)snprintf(commit, sizeof(commit),
                   "{\"wallet_scope\":\"dev\",\"from\":\"%s\",\"fee_zat\":%d,"
                   "\"idempotency_key\":\"%s\",\"confirm\":true,"
                   "\"plan_token\":\"0000000000000000\"}", from, WSA_FEE,
                   WSA_KEY);
    wsa_leaf(commit, &out);
    WSA_CHECK("a forged plan token: PLAN_TOKEN_MISMATCH",
              wsa_replied_code(&out, WALLET_SHIELD_CHANGED));
    zcl_command_reply_free(&out);
    return failures;
}

static int wsa_test_leaf(void)
{
    int failures = 0;
    struct wsa_fix fx;
    char from[128];
    WSA_CHECK("registered in the command catalog", wsa_spec() != NULL);
    if (!wsa_spec())
        return failures;
    WSA_CHECK("leaf fixture opens", wsa_open(&fx, "leaf", true));
    wsa_addr(&fx.kid, from, sizeof(from));
    WSA_CHECK("coins saved (one coinbase, one maturing)",
              wsa_coin(&fx, 1, 1000, 5, false, NULL) &&
                  wsa_coin(&fx, 2, 2000, WSA_TIP - 100, true, NULL) &&
                  wsa_coin(&fx, 3, 7000, WSA_TIP - 50, true, NULL));
    g_fix = &fx;
    g_hook_mode = WSA_HOOK_REAL;
    node_rpc_client_set_test_hook(wsa_hook);
    failures += wsa_test_leaf_plan(&fx, from);
    failures += wsa_test_leaf_commit(&fx, from);
    failures += wsa_test_leaf_races(&fx, from);
    g_fix = NULL;
    wsa_close(&fx);
    return failures;
}

/* The production prover, as the spend-rule end-to-end test loads it. */
static bool wsa_load_prover(void)
{
    char params_dir[512];
    const char *home = getenv("HOME");
    (void)snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
                   (home && *home) ? home : ".");
    return sapling_init_params(params_dir) &&
           zclassic_sapling_prover_is_ready();
}

int test_wallet_shield_address(void);
int test_wallet_shield_address(void)
{
    printf("\n=== wallet shield address (z_shieldaddress) tests ===\n");
    int failures = 0;
    failures += wsa_test_refusals();
    bool prover = wsa_load_prover();
    WSA_CHECK("sapling proving parameters load (a missing set is a failure, "
              "not a skip)", prover);
    if (!prover)
        return failures;
    failures += wsa_test_selection();
    failures += wsa_test_cap();
    failures += wsa_test_sovereignty();
    failures += wsa_test_lock();
    failures += wsa_test_destination();
    failures += wsa_test_coinbase_protect();
    failures += wsa_test_leaf();
    failures += wsa_test_build();
    return failures;
}
