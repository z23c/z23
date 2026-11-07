/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * signrawtransaction takes the script and amount of an input that the caller
 * did not describe from the coins database, which is the authority; the
 * SQLite utxos table is a projection of it. Local fixture only: an isolated
 * node.db in a temp file, an in-memory coins cache with no backing store, and
 * a throwaway key. Nothing is spent and no wallet is read. Called from
 * test_rpc_safety. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "controllers/transaction_controller.h"
#include "controllers/wallet_helpers.h"
#include "core/core_io.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/utxo.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "wallet/keystore.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SCS_COIN_AMOUNT 5000
#define SCS_ROW_AMOUNT 7000

struct scs_spec {
    bool pending;
    bool has_coin;
    bool has_row;
    bool row_foreign_script;
    int64_t row_amount;
    bool unresolved_tip;
};

struct scs_fx {
    struct wallet *wallet;
    struct rpc_table tbl;
    struct privkey key;
    struct pubkey pub;
    struct key_id kid;
    struct key_id foreign;
    struct node_db ndb;
    char dbpath[256];
    struct coins_view nv;
    struct coins_view_cache cache;
    struct main_state ms;
    struct uint256 txid;
    struct script coin_script;
    char tx_hex[2048];
    char out_hex[4096];
    bool executed;
    bool complete;
    bool ok;
};

static bool scs_add_coin(struct scs_fx *fx)
{
    struct coins_cache_entry *e =
        coins_view_cache_modify_new(&fx->cache, &fx->txid);
    if (!e)
        return false;
    coins_alloc(&e->coins, 1);
    e->coins.vout[0].value = SCS_COIN_AMOUNT;
    e->coins.vout[0].script_pub_key = fx->coin_script;
    e->coins.height = 1;
    e->coins.version = 1;
    e->coins.is_coinbase = false;
    return true;
}

static bool scs_add_row(struct scs_fx *fx, const struct scs_spec *sp)
{
    struct script s;
    script_for_p2pkh(&s, sp->row_foreign_script ? &fx->foreign : &fx->kid);
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, fx->txid.data, sizeof(u.txid));
    u.vout = 0;
    u.value = sp->row_amount;
    u.script = s.data;
    u.script_len = s.size;
    u.script_type = SCRIPT_P2PKH;
    u.has_address = true;
    u.height = 1;
    return db_utxo_save(&fx->ndb, &u);
}

static bool scs_build_tx(struct scs_fx *fx)
{
    struct transaction tx;
    transaction_init(&tx);
    tx.overwintered = true;
    tx.version = SAPLING_TX_VERSION;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.vin = calloc(1, sizeof(*tx.vin));
    tx.vout = calloc(1, sizeof(*tx.vout));
    bool ok = tx.vin && tx.vout;
    if (ok) {
        tx.num_vin = 1;
        tx.vin[0].prevout.hash = fx->txid;
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = UINT32_MAX;
        tx.num_vout = 1;
        tx.vout[0].value = 1000;
        struct key_id recipient = {0};
        script_for_p2pkh(&tx.vout[0].script_pub_key, &recipient);
    }
    size_t n = ok ? encode_hex_tx(&tx, fx->tx_hex, sizeof(fx->tx_hex)) : 0;
    transaction_free(&tx);
    return n > 0 && n < sizeof(fx->tx_hex);
}

static bool scs_open_stores(struct scs_fx *fx)
{
    int fd = test_mkstemp(fx->dbpath, sizeof(fx->dbpath), "scs");
    if (fd < 0)
        return false;
    close(fd);
    if (!node_db_open(&fx->ndb, fx->dbpath))
        return false;
    memset(&fx->nv, 0, sizeof(fx->nv));
    coins_view_cache_init(&fx->cache, &fx->nv);
    return true;
}

static bool scs_open_keys(struct scs_fx *fx, const struct scs_spec *sp)
{
    fx->wallet = zcl_calloc(1, sizeof(*fx->wallet), "scs_wallet");
    if (!fx->wallet) return false;
    wallet_init(fx->wallet);
    if (!wallet_readiness_initialize(fx->wallet, sp->pending ? WALLET_READINESS_PENDING : WALLET_READINESS_READY, false, 0)) return false;
    privkey_make_new(&fx->key, true);
    if (!privkey_get_pubkey(&fx->key, &fx->pub) ||
        !keystore_add_key(&fx->wallet->keystore, &fx->key))
        return false;
    fx->kid = pubkey_get_id(&fx->pub);
    memset(&fx->foreign, 0x77, sizeof(fx->foreign));
    script_for_p2pkh(&fx->coin_script, &fx->kid);
    memset(fx->txid.data, 0x5c, sizeof(fx->txid.data));
    return true;
}

static void scs_wire(struct scs_fx *fx, const struct scs_spec *sp)
{
    struct main_state *ms = NULL;
    if (sp->unresolved_tip) {
        main_state_init(&fx->ms);
        fx->ms.chain_active.height = 5;
        fx->ms.chain_active.capacity = 6;
        fx->ms.chain_active.chain =
            calloc(6, sizeof(*fx->ms.chain_active.chain));
        ms = &fx->ms;
    }
    wallet_rpc_context_set_base(fx->wallet, ms, NULL, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(&fx->ndb);
    rpc_rawtx_set_state(ms, NULL, &fx->cache, NULL);
    rpc_rawtx_set_keystore(&fx->wallet->keystore);
    rpc_table_init(&fx->tbl);
    register_rawtransaction_rpc_commands(&fx->tbl);
}

static bool scs_open(struct scs_fx *fx, const struct scs_spec *sp)
{
    memset(fx, 0, sizeof(*fx));
    fx->ok = scs_open_keys(fx, sp) && scs_open_stores(fx) && scs_build_tx(fx);
    if (!fx->ok)
        return false;
    scs_wire(fx, sp);
    if (sp->has_coin)
        fx->ok = scs_add_coin(fx);
    if (fx->ok && sp->has_row)
        fx->ok = scs_add_row(fx, sp);
    return fx->ok;
}

static void scs_close(struct scs_fx *fx, const struct scs_spec *sp)
{
    wallet_rpc_context_set_node_db(NULL);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_rawtx_set_state(NULL, NULL, NULL, NULL);
    rpc_rawtx_set_keystore(NULL);
    if (sp->unresolved_tip) {
        free(fx->ms.chain_active.chain);
        fx->ms.chain_active.chain = NULL;
        fx->ms.chain_active.height = -1;
        fx->ms.chain_active.capacity = 0;
        main_state_free(&fx->ms);
    }
    if (fx->wallet) { wallet_free(fx->wallet); free(fx->wallet); fx->wallet = NULL; }
    coins_view_cache_free(&fx->cache);
    if (fx->ndb.open)
        node_db_close(&fx->ndb);
    unlink(fx->dbpath);
    memory_cleanse(fx->key.vch, sizeof(fx->key.vch));
}

/* Run signrawtransaction over the fixture tx with no caller-supplied
 * prevouts, so the input is resolved by the node. */
static void scs_sign_with_keys(struct scs_fx *fx, bool caller_key)
{
    struct json_value params, value, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&value);
    json_set_str(&value, fx->tx_hex);
    json_push_back(&params, &value);
    json_free(&value);
    if (caller_key) {
        struct json_value prevs = {0}, prev = {0};
        char txid[65], script_hex[2 * MAX_SCRIPT_SIZE + 1];
        uint256_get_hex(&fx->txid, txid);
        zcl_hex_encode(fx->coin_script.data, fx->coin_script.size, script_hex);
        json_set_array(&prevs); json_set_object(&prev);
        json_push_kv_str(&prev, "txid", txid); json_push_kv_int(&prev, "vout", 0);
        json_push_kv_str(&prev, "scriptPubKey", script_hex);
        json_push_kv_real(&prev, "amount", (double)SCS_COIN_AMOUNT / 100000000.0);
        json_push_back(&prevs, &prev); json_free(&prev);
        json_push_back(&params, &prevs); json_free(&prevs);
        char wif[128] = {0}; size_t prefix_len = 0;
        const unsigned char *prefix = chain_params_base58_prefix(chain_params_get(), B58_SECRET_KEY, &prefix_len);
        struct json_value keys = {0}; json_set_array(&keys);
        if (encode_secret(&fx->key, prefix, prefix_len, wif, sizeof(wif))) {
            json_init(&value); json_set_str(&value, wif); json_push_back(&keys, &value); json_free(&value);
        }
        memory_cleanse(wif, sizeof(wif)); json_push_back(&params, &keys); json_free(&keys);
    }
    json_init(&result);
    fx->executed = rpc_table_execute(&fx->tbl, "signrawtransaction", &params,
                                     &result);
    fx->complete = false;
    fx->out_hex[0] = '\0';
    if (fx->executed) {
        fx->complete = json_get_bool(json_get(&result, "complete"));
        const char *h = json_get_str(json_get(&result, "hex"));
        if (h)
            snprintf(fx->out_hex, sizeof(fx->out_hex), "%s", h);
    }
    json_free(&params);
    json_free(&result);
}

/* True iff vin[0] of the returned tx carries a signature by the fixture key
 * over the signature hash for (script, amount). */
static void scs_sign(struct scs_fx *fx) { scs_sign_with_keys(fx, false); }

static bool scs_signed_over(const struct scs_fx *fx, const struct script *sc,
                            int64_t amount)
{
    struct transaction tx;
    transaction_init(&tx);
    bool ok = fx->out_hex[0] && decode_hex_tx(&tx, fx->out_hex) &&
              tx.num_vin == 1 && tx.vin[0].script_sig.size > 2;
    if (ok) {
        const struct script *ss = &tx.vin[0].script_sig;
        size_t siglen = ss->data[0];
        struct sighash_type ht = { .raw = SIGHASH_ALL };
        struct uint256 h;
        uint32_t branch = consensus_current_epoch_branch_id(
            1, &chain_params_get()->consensus);
        ok = siglen > 1 && siglen < ss->size &&
             signature_hash(sc, &tx, 0, ht, amount, branch, NULL, &h) &&
             pubkey_verify(&fx->pub, &h, ss->data + 1, siglen - 1);
    }
    transaction_free(&tx);
    return ok;
}

static bool scs_left_unsigned(const struct scs_fx *fx)
{
    struct transaction tx;
    transaction_init(&tx);
    bool ok = fx->out_hex[0] && decode_hex_tx(&tx, fx->out_hex) &&
              tx.num_vin == 1 && tx.vin[0].script_sig.size == 0;
    transaction_free(&tx);
    return ok;
}

static void scs_report(const char *name, bool ok, int *failures)
{
    printf("rpc_safety: raw-sign %s... %s\n", name, ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

static int scs_case_agree(void)
{
    int failures = 0;
    struct scs_spec sp = { .has_coin = true, .has_row = true,
                           .row_amount = SCS_COIN_AMOUNT };
    struct scs_fx *fx = zcl_calloc(1, sizeof(*fx), "scs_fx");
    bool ok = fx && scs_open(fx, &sp);
    if (ok) {
        scs_sign(fx);
        ok = fx->executed && fx->complete &&
             scs_signed_over(fx, &fx->coin_script, SCS_COIN_AMOUNT);
    }
    if (fx) {
        scs_close(fx, &sp);
        free(fx);
    }
    scs_report("agreeing index row and coin sign", ok, &failures);
    return failures;
}

static int scs_case_amount(void)
{
    int failures = 0;
    struct scs_spec sp = { .has_coin = true, .has_row = true,
                           .row_amount = SCS_ROW_AMOUNT };
    struct scs_fx *fx = zcl_calloc(1, sizeof(*fx), "scs_fx");
    bool ok = fx && scs_open(fx, &sp);
    if (ok) {
        scs_sign(fx);
        ok = fx->executed && fx->complete &&
             scs_signed_over(fx, &fx->coin_script, SCS_COIN_AMOUNT) &&
             !scs_signed_over(fx, &fx->coin_script, SCS_ROW_AMOUNT);
    }
    if (fx) {
        scs_close(fx, &sp);
        free(fx);
    }
    scs_report("amount comes from the coin, not the index row", ok,
               &failures);
    return failures;
}

static int scs_case_script(void)
{
    int failures = 0;
    struct scs_spec sp = { .has_coin = true, .has_row = true,
                           .row_foreign_script = true,
                           .row_amount = SCS_COIN_AMOUNT };
    struct scs_fx *fx = zcl_calloc(1, sizeof(*fx), "scs_fx");
    bool ok = fx && scs_open(fx, &sp);
    if (ok) {
        scs_sign(fx);
        ok = fx->executed && fx->complete &&
             scs_signed_over(fx, &fx->coin_script, SCS_COIN_AMOUNT);
    }
    if (fx) {
        scs_close(fx, &sp);
        free(fx);
    }
    scs_report("script comes from the coin, not the index row", ok,
               &failures);
    return failures;
}

static int scs_case_spent(void)
{
    int failures = 0;
    struct scs_spec sp = { .has_coin = false, .has_row = true,
                           .row_amount = SCS_COIN_AMOUNT };
    struct scs_fx *fx = zcl_calloc(1, sizeof(*fx), "scs_fx");
    bool ok = fx && scs_open(fx, &sp);
    if (ok) {
        scs_sign(fx);
        ok = fx->executed && !fx->complete && scs_left_unsigned(fx);
    }
    if (fx) {
        scs_close(fx, &sp);
        free(fx);
    }
    scs_report("index row for a coin the coins database lacks is refused", ok,
               &failures);
    return failures;
}

static int scs_case_not_ready(void)
{
    int failures = 0;
    struct scs_spec sp = { .has_coin = true, .has_row = true,
                           .row_amount = SCS_COIN_AMOUNT,
                           .unresolved_tip = true };
    struct scs_fx *fx = zcl_calloc(1, sizeof(*fx), "scs_fx");
    bool ok = fx && scs_open(fx, &sp);
    if (ok) {
        scs_sign(fx);
        ok = !fx->executed && !fx->out_hex[0];
    }
    if (fx) {
        scs_close(fx, &sp);
        free(fx);
    }
    scs_report("refuses, not index fallback, when chainstate is not ready",
               ok, &failures);
    return failures;
}

static int scs_case_pending_signing(void)
{
    int failures = 0;
    struct scs_spec sp = { .pending = true, .has_coin = true, .has_row = true,
                           .row_amount = SCS_COIN_AMOUNT };
    struct scs_fx *fx = zcl_calloc(1, sizeof(*fx), "scs_fx");
    bool ok = fx && scs_open(fx, &sp);
    if (ok) {
        scs_sign(fx);
        ok = fx->executed && !fx->complete && scs_left_unsigned(fx);
        scs_sign_with_keys(fx, true);
        ok = ok && fx->executed && fx->complete &&
             scs_signed_over(fx, &fx->coin_script, SCS_COIN_AMOUNT);
    }
    if (fx) { scs_close(fx, &sp); free(fx); }
    scs_report("pending disables wallet keys but permits caller keys", ok, &failures);
    return failures;
}

int scs_run_tests(void);
int scs_run_tests(void)
{
    int failures = 0;
    failures += scs_case_pending_signing();
    failures += scs_case_agree();
    failures += scs_case_amount();
    failures += scs_case_script();
    failures += scs_case_spent();
    failures += scs_case_not_ready();
    return failures;
}
