/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the shared mempool-acceptance gate
 * accept_to_mempool() (core/modules/validation): the relay paths (P2P `tx` +
 * RPC sendrawtransaction) must reject a tx with an INVALID transparent
 * signature instead of admitting and relaying it until block-connect.
 *
 * The core assertion: a tx with a BAD signature is REJECTED (and so
 * never relayed); the same tx with a VALID signature is ACCEPTED. */

#include "test/test_core.h"
#include "validation/accept_to_mempool.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "validation/sighash.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "script/standard.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "primitives/transaction.h"
#include "wallet/wallet.h"
#include "util/safe_alloc.h"
#include "storage/progress_store.h"
#include <pthread.h>

#ifdef ZCL_TESTING
bool boot_install_mempool_backend_guard(void);
void boot_test_set_mempool_guard_attempt(void (*hook)(void));
static pthread_mutex_t atm_guard_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t atm_guard_changed = PTHREAD_COND_INITIALIZER;
static bool atm_guard_attempted, atm_guard_continue, atm_guard_probed, atm_guard_busy;
static int atm_guard_calls;
static int atm_guard_target;
static void atm_note_guard_attempt(void)
{
    pthread_mutex_lock(&atm_guard_lock);
    if (++atm_guard_calls != atm_guard_target) {
        pthread_mutex_unlock(&atm_guard_lock);
        return;
    }
    atm_guard_attempted = true;
    pthread_cond_broadcast(&atm_guard_changed);
    while (!atm_guard_continue)
        pthread_cond_wait(&atm_guard_changed, &atm_guard_lock);
    bool acquired = progress_store_tx_trylock();
    if (acquired) progress_store_tx_unlock();
    atm_guard_busy = !acquired;
    atm_guard_probed = true;
    pthread_cond_broadcast(&atm_guard_changed);
    pthread_mutex_unlock(&atm_guard_lock);
}
struct atm_guard_job {
    struct tx_mempool *pool;
    struct coins_view_cache *coins;
    struct main_state *state;
    const struct chain_params *params;
    struct transaction *tx;
    enum mempool_accept_result result;
    bool done;
};
static void *atm_guard_worker(void *opaque)
{
    struct atm_guard_job *job = opaque;
    job->result = accept_to_mempool(job->pool, job->coins, job->state,
                                    job->params, job->tx);
    pthread_mutex_lock(&atm_guard_lock);
    job->done = true;
    pthread_cond_broadcast(&atm_guard_changed);
    pthread_mutex_unlock(&atm_guard_lock);
    return NULL;
}
#endif

/* Stamp a P2PKH UTXO (scriptPubKey = DUP HASH160 <pkh> EQUALVERIFY
 * CHECKSIG) into the view at `txid`:0 with `value`. */
static bool atm_add_p2pkh_utxo(struct coins_view_cache *cache,
                               const struct uint256 *txid, int64_t value,
                               const struct key_id *kid)
{
    struct coins_cache_entry *entry =
        coins_view_cache_modify_new(cache, txid);
    if (!entry) return false;
    coins_alloc(&entry->coins, 1);
    entry->coins.vout[0].value = value;
    script_for_p2pkh(&entry->coins.vout[0].script_pub_key, kid);
    entry->coins.height = 1;
    entry->coins.version = 1;
    entry->coins.is_coinbase = false;
    return true;
}

/* Build a v1 transparent 1-in/1-out tx spending `prev`:0. scriptSig is
 * filled in by the caller after sighash. */
static void atm_build_spend(struct transaction *tx,
                            const struct uint256 *prev, int64_t out_value)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->version = 1;
    tx->vin[0].prevout.hash = *prev;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = out_value;
    /* Give the output a trivial non-empty scriptPubKey so
     * check_transaction's standardness probes are satisfied. */
    uint8_t spk[] = {0x51}; /* OP_1 */
    script_set(&tx->vout[0].script_pub_key, spk, 1);
    tx->lock_time = 0;
}

/* Sign vin[0] of `tx` against `prev_spk`/`amount` with `key`, then
 * install the P2PKH scriptSig: <sig+hashtype> <pubkey>. If `corrupt`,
 * flip a byte of the DER signature so the signature is INVALID while
 * the structure stays well-formed. */
static void atm_sign_input(struct transaction *tx,
                           const struct script *prev_spk, int64_t amount,
                           const struct privkey *key, const struct pubkey *pub,
                           bool corrupt)
{
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 sighash;
    uint256_set_null(&sighash);
    /* branch_id 0: v1 / Sprout transparent sighash. */
    signature_hash(prev_spk, tx, 0, ht, amount, 0, NULL, &sighash);

    unsigned char sig[80];
    size_t siglen = sizeof(sig);
    privkey_sign(key, &sighash, sig, &siglen);
    /* A DER ECDSA signature is <= 72 bytes; clamp defensively. */
    if (siglen > 72) siglen = 72;
    if (corrupt && siglen > 10)
        sig[siglen - 4] ^= 0xFF; /* still a valid DER int, wrong value */
    sig[siglen] = SIGHASH_ALL;   /* append hashtype */
    siglen += 1;

    /* Assemble the P2PKH scriptSig (<push sig+ht> <push pubkey>) into a
     * fixed local buffer and install via script_set. Both items are well
     * under 76 bytes, so each push is a single length-prefix byte. Hand-
     * rolled rather than script_push_data to keep the push length a
     * statically-bounded value (avoids a false -Warray-bounds under -O3
     * inlining). */
    size_t pklen = pub->size; if (pklen > 65) pklen = 65;
    unsigned char ss_buf[1 + 73 + 1 + 65];
    size_t n = 0;
    ss_buf[n++] = (unsigned char)siglen;
    memcpy(&ss_buf[n], sig, siglen); n += siglen;
    ss_buf[n++] = (unsigned char)pklen;
    memcpy(&ss_buf[n], pub->vch, pklen); n += pklen;

    struct script ss;
    script_init(&ss);
    script_set(&ss, ss_buf, n);
    tx->vin[0].script_sig = ss;
    transaction_compute_hash(tx);
}

#ifdef ZCL_TESTING
static bool atm_guard_contend(struct atm_guard_job *job)
{
    pthread_t worker;
    if (pthread_create(&worker, NULL, atm_guard_worker, job) != 0) return false;
    pthread_mutex_lock(&atm_guard_lock);
    while (!atm_guard_attempted && !job->done)
        pthread_cond_wait(&atm_guard_changed, &atm_guard_lock);
    bool observed = atm_guard_attempted;
    pthread_mutex_unlock(&atm_guard_lock);
    if (!observed) { pthread_join(worker, NULL); return false; }
    progress_store_tx_lock();
    pthread_mutex_lock(&atm_guard_lock);
    atm_guard_continue = true;
    pthread_cond_broadcast(&atm_guard_changed);
    while (!atm_guard_probed)
        pthread_cond_wait(&atm_guard_changed, &atm_guard_lock);
    bool blocked = atm_guard_busy && !job->done;
    pthread_mutex_unlock(&atm_guard_lock);
    bool main_available = zcl_mutex_trylock(&job->state->cs_main);
    if (main_available) zcl_mutex_unlock(&job->state->cs_main);
    progress_store_tx_unlock();
    pthread_join(worker, NULL);
    return blocked && main_available && job->result == MEMPOOL_ACCEPT_OK &&
           tx_mempool_exists(job->pool, &job->tx->hash);
}

static bool atm_guard_case(int target, struct main_state *state,
                           const struct chain_params *params,
                           const struct key_id *kid, const struct script *spk,
                           const struct privkey *key, const struct pubkey *pub,
                           int64_t value)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);
    struct coins_view null_view = {0};
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);
    struct uint256 utxo;
    memset(utxo.data, 0xD8, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, value, kid);
    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    atm_sign_input(&tx, spk, value, key, pub, false);
    struct atm_guard_job job = {
        .pool = &pool, .coins = &coins, .state = state,
        .params = params, .tx = &tx, .result = MEMPOOL_ACCEPT_INTERNAL_ERROR,
    };
    atm_guard_target = target;
    atm_guard_attempted = atm_guard_continue = atm_guard_probed = atm_guard_busy = false;
    atm_guard_calls = 0;
    ok = ok && boot_install_mempool_backend_guard();
    boot_test_set_mempool_guard_attempt(atm_note_guard_attempt);
    if (ok) ok = atm_guard_contend(&job);
    boot_test_set_mempool_guard_attempt(NULL);
    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static int atm_guard_test(struct main_state *state,
                          const struct chain_params *params,
                          const struct key_id *kid, const struct script *spk,
                          const struct privkey *key, const struct pubkey *pub,
                          int64_t value)
{
    int failures = 0;
    for (int target = 1; target <= 2; ++target) {
        printf("accept_to_mempool: progress/main ordering guard %d... ", target);
        if (atm_guard_case(target, state, params, kid, spk, key, pub, value))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}
#endif

/* ================================================================
 * Characterization of accept_to_mempool_detailed(): one table row per
 * reachable branch. Expectations are the literal results of the current
 * code path (detail is reset to "" on entry; only the rejecting branches
 * that name a reason write detail_out).
 * ================================================================ */
struct atm_ctx {
    struct main_state *state;
    const struct chain_params *params;
    const struct key_id *kid;
    const struct script *spk;
    const struct privkey *key;
    const struct pubkey *pub;
};

struct atm_fix {
    struct tx_mempool pool;
    struct coins_view null_view;
    struct coins_view_cache coins;
    struct uint256 utxo;
    struct transaction tx;
};

static const int64_t atm_det_utxo = 100 * COIN_VALUE;

/* Initialise every container unconditionally so atm_fix_free is always
 * safe; returns false only when the UTXO could not be seeded. */
static bool atm_fix_init(struct atm_fix *f, const struct atm_ctx *c,
                         int64_t min_fee, int tag, int64_t utxo_value,
                         int64_t out_value, bool corrupt)
{
    tx_mempool_init(&f->pool, min_fee);
    memset(&f->null_view, 0, sizeof(f->null_view));
    coins_view_cache_init(&f->coins, &f->null_view);
    memset(f->utxo.data, tag, 32);
    bool seeded = atm_add_p2pkh_utxo(&f->coins, &f->utxo, utxo_value, c->kid);
    atm_build_spend(&f->tx, &f->utxo, out_value);
    atm_sign_input(&f->tx, c->spk, utxo_value, c->key, c->pub, corrupt);
    return seeded;
}

static void atm_fix_free(struct atm_fix *f)
{
    transaction_free(&f->tx);
    coins_view_cache_free(&f->coins);
    tx_mempool_free(&f->pool);
}

static bool atm_expect(enum mempool_accept_result got,
                       enum mempool_accept_result want,
                       const char *detail, const char *want_detail,
                       size_t size, size_t want_size)
{
    return got == want && strcmp(detail, want_detail) == 0 &&
           size == want_size;
}

static bool atm_case_null_pool(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE1, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        NULL, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && r == MEMPOOL_ACCEPT_INTERNAL_ERROR &&
              strcmp(detail, "") == 0;
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_coinbase(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE2, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    /* A single null-outpoint input is a coinbase shape. */
    uint256_set_null(&f.tx.vin[0].prevout.hash);
    f.tx.vin[0].prevout.n = UINT32_MAX;
    char detail[64] = "";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INVALID, detail,
                                   "coinbase-standalone",
                                   tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_structural_reject(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE3, atm_det_utxo, -1, false);
    char detail[64] = "";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INVALID, detail,
                                   "bad-txns-vout-negative",
                                   tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_null_coins(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE4, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, NULL, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INTERNAL_ERROR, detail,
                                   "", tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_null_params(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE5, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, NULL, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INTERNAL_ERROR, detail,
                                   "", tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_duplicate(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE6, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    enum mempool_accept_result first = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, NULL, 0);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && first == MEMPOOL_ACCEPT_OK &&
              atm_expect(r, MEMPOOL_ACCEPT_DUPLICATE, detail, "",
                         tx_mempool_size(&f.pool), 1);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_conflict(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xE7, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    enum mempool_accept_result first = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, NULL, 0);
    /* Same prevout, different output value: a distinct txid that double
     * spends the pooled transaction. */
    struct transaction rival;
    atm_build_spend(&rival, &f.utxo, 40 * COIN_VALUE);
    atm_sign_input(&rival, c->spk, atm_det_utxo, c->key, c->pub, false);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &rival, detail,
        sizeof(detail));
    bool ok = seeded && first == MEMPOOL_ACCEPT_OK &&
              atm_expect(r, MEMPOOL_ACCEPT_CONFLICT, detail, "",
                         tx_mempool_size(&f.pool), 1);
    transaction_free(&rival);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_input_value_invalid(const struct atm_ctx *c)
{
    struct atm_fix f;
    /* Deciding check: coins_view_cache_get_value_in rejects a prevout above
     * MAX_MONEY (MoneyRange) and returns -1. The seed must not be -1
     * itself: that is the null-output marker, so have_inputs would fail
     * first and yield MISSING_INPUTS with an empty detail. */
    bool seeded = atm_fix_init(&f, c, 0, 0xE8, MAX_MONEY + 1,
                               50 * COIN_VALUE, false);
    char detail[64] = "";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INVALID, detail,
                                   "input-value-invalid",
                                   tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_value_balance_invalid(const struct atm_ctx *c)
{
    struct atm_fix f;
    /* 150 out of 100 in: value_in < value_out. */
    bool seeded = atm_fix_init(&f, c, 0, 0xE9, atm_det_utxo, 150 * COIN_VALUE,
                               false);
    char detail[64] = "";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INVALID, detail,
                                   "value-balance-invalid",
                                   tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_below_fee(const struct atm_ctx *c)
{
    struct atm_fix f;
    /* Zero fee against a one-coin relay floor. */
    bool seeded = atm_fix_init(&f, c, COIN_VALUE, 0xEA, atm_det_utxo,
                               atm_det_utxo, false);
    char detail[64] = "";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_BELOW_FEE, detail, "",
                                   tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_script_invalid(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xEB, atm_det_utxo, 50 * COIN_VALUE,
                               true);
    char detail[64] = "";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_INVALID, detail,
                                   "transparent-script-invalid",
                                   tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_missing_inputs(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xEC, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    /* Point the spend at an outpoint the view never held. */
    memset(f.tx.vin[0].prevout.hash.data, 0xEE, 32);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_MISSING_INPUTS, detail,
                                   "", tx_mempool_size(&f.pool), 0);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_success_clears_detail(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xED, atm_det_utxo, 50 * COIN_VALUE,
                               false);
    char detail[64] = "stale";
    enum mempool_accept_result r = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, sizeof(detail));
    bool ok = seeded && atm_expect(r, MEMPOOL_ACCEPT_OK, detail, "",
                                   tx_mempool_size(&f.pool), 1);
    atm_fix_free(&f);
    return ok;
}

static bool atm_case_zero_cap_and_null_detail(const struct atm_ctx *c)
{
    struct atm_fix f;
    bool seeded = atm_fix_init(&f, c, 0, 0xEE, atm_det_utxo, 50 * COIN_VALUE,
                               true);
    char detail[8] = "keep";
    enum mempool_accept_result r1 = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, detail, 0);
    enum mempool_accept_result r2 = accept_to_mempool_detailed(
        &f.pool, &f.coins, c->state, c->params, &f.tx, NULL, 0);
    bool ok = seeded && r1 == MEMPOOL_ACCEPT_INVALID &&
              strcmp(detail, "keep") == 0 &&
              r2 == MEMPOOL_ACCEPT_INVALID && tx_mempool_size(&f.pool) == 0;
    atm_fix_free(&f);
    return ok;
}

struct atm_det_case {
    const char *name;
    bool (*run)(const struct atm_ctx *c);
};

static const struct atm_det_case atm_det_cases[] = {
    { "null pool -> INTERNAL_ERROR, detail cleared", atm_case_null_pool },
    { "coinbase-shaped tx -> coinbase-standalone", atm_case_coinbase },
    { "structural reject -> reason forwarded", atm_case_structural_reject },
    { "null coins_tip -> INTERNAL_ERROR", atm_case_null_coins },
    { "null params -> INTERNAL_ERROR", atm_case_null_params },
    { "pooled txid resubmitted -> DUPLICATE", atm_case_duplicate },
    { "double spend of pooled prevout -> CONFLICT", atm_case_conflict },
    { "get_value_in MoneyRange -> input-value-invalid",
      atm_case_input_value_invalid },
    { "outputs exceed inputs -> value-balance-invalid",
      atm_case_value_balance_invalid },
    { "zero fee under relay floor -> BELOW_FEE", atm_case_below_fee },
    { "bad transparent sig -> transparent-script-invalid",
      atm_case_script_invalid },
    { "unknown prevout -> MISSING_INPUTS", atm_case_missing_inputs },
    { "accepted tx clears detail -> OK", atm_case_success_clears_detail },
    { "zero detail cap writes nothing; NULL detail ok",
      atm_case_zero_cap_and_null_detail },
};

static int atm_detail_branches(const struct atm_ctx *c)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(atm_det_cases) / sizeof(atm_det_cases[0]);
         ++i) {
        printf("accept_to_mempool: detail branch %s... ",
               atm_det_cases[i].name);
        if (atm_det_cases[i].run(c)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int atm_report(bool ok)
{
    if (ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL\n");
    return 1;
}

static bool atm_gate_bad_sig(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD1, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);

    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    atm_sign_input(&tx, c->spk, atm_det_utxo, c->key, c->pub,
                   /*corrupt=*/true);

    enum mempool_accept_result r =
        accept_to_mempool(&pool, &coins, c->state, c->params, &tx);

    ok = ok && (r == MEMPOOL_ACCEPT_INVALID);
    ok = ok && (tx_mempool_size(&pool) == 0);

    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_valid_sig(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD2, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);

    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    atm_sign_input(&tx, c->spk, atm_det_utxo, c->key, c->pub,
                   /*corrupt=*/false);

    enum mempool_accept_result r =
        accept_to_mempool(&pool, &coins, c->state, c->params, &tx);

    ok = ok && (r == MEMPOOL_ACCEPT_OK);
    ok = ok && (tx_mempool_size(&pool) == 1);
    ok = ok && tx_mempool_exists(&pool, &tx.hash);

    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_missing_input(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD3, 32); /* never added to the view */

    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    atm_sign_input(&tx, c->spk, atm_det_utxo, c->key, c->pub,
                   /*corrupt=*/false);

    enum mempool_accept_result r =
        accept_to_mempool(&pool, &coins, c->state, c->params, &tx);

    bool ok = (r == MEMPOOL_ACCEPT_MISSING_INPUTS);
    ok = ok && (tx_mempool_size(&pool) == 0);

    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_incomplete_ctx(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);
    struct uint256 utxo;
    memset(utxo.data, 0xD8, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);
    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    atm_sign_input(&tx, c->spk, atm_det_utxo, c->key, c->pub,
                   /*corrupt=*/false);

    enum mempool_accept_result r =
        accept_to_mempool(&pool, &coins, NULL, c->params, &tx);
    ok = ok && r == MEMPOOL_ACCEPT_INTERNAL_ERROR;
    ok = ok && tx_mempool_size(&pool) == 0;

    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_nonfinal(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD4, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);

    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    /* Make the tx NON-FINAL: future height-domain lock_time + a
     * non-final input sequence (so the lock is not overridden). Set
     * BEFORE signing so the sighash commits to them. */
    tx.lock_time = 10000000u;          /* height domain, far future */
    tx.vin[0].sequence = 0xFFFFFFFEu;  /* NOT 0xFFFFFFFF → lock active */
    atm_sign_input(&tx, c->spk, atm_det_utxo, c->key, c->pub,
                   /*corrupt=*/false);

    enum mempool_accept_result r =
        accept_to_mempool(&pool, &coins, c->state, c->params, &tx);

    ok = ok && (r == MEMPOOL_ACCEPT_NONFINAL);
    ok = ok && (tx_mempool_size(&pool) == 0);

    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_expiring(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD7, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);

    struct transaction tx;
    atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
    tx.overwintered = true;
    tx.version = OVERWINTER_TX_VERSION;
    tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
    /* Empty test chain: next_height=0; 0+3 > 2, so relay policy
     * classifies this as expiring soon before expensive proof/script work. */
    tx.expiry_height = 2;
    transaction_compute_hash(&tx);

    enum mempool_accept_result r =
        accept_to_mempool(&pool, &coins, c->state, c->params, &tx);

    ok = ok && (r == MEMPOOL_ACCEPT_EXPIRING_SOON);
    ok = ok && (tx_mempool_size(&pool) == 0);

    transaction_free(&tx);
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_wallet_committed(struct wallet *wallet,
                                      struct wallet_tx *wtx,
                                      struct tx_mempool *pool,
                                      const struct uint256 *utxo, bool ok)
{
    ok = ok && tx_mempool_size(pool) == 1;
    ok = ok && tx_mempool_exists(pool, &wtx->tx.hash);
    ok = ok && wallet->num_wallet_tx == 1;
    ok = ok && wallet->num_spent == 1;
    ok = ok && wallet_is_outpoint_spent(wallet, utxo, 0);
    return ok;
}

static bool atm_gate_wallet_rolled_back(struct wallet *wallet,
                                        struct tx_mempool *pool,
                                        const struct uint256 *utxo, bool ok)
{
    ok = ok && tx_mempool_size(pool) == 0;
    ok = ok && wallet->num_wallet_tx == 0;
    ok = ok && wallet->num_spent == 0;
    ok = ok && !wallet_is_outpoint_spent(wallet, utxo, 0);
    return ok;
}

static bool atm_gate_wallet_reaccepted(struct wallet *wallet,
                                       struct wallet_tx *wtx,
                                       struct tx_mempool *pool, bool ok)
{
    ok = ok && tx_mempool_exists(pool, &wtx->tx.hash);
    ok = ok && wallet->num_wallet_tx == 0;
    ok = ok && wallet->num_spent == 0;
    return ok;
}

static bool atm_gate_wallet_bad_sig(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD5, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);

    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                       "atm_bad_sig_wallet");
    ok = ok && wallet != NULL;
    if (wallet) {
        wallet_init(wallet);
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        atm_build_spend(&wtx.tx, &utxo, 50 * COIN_VALUE);
        atm_sign_input(&wtx.tx, c->spk, atm_det_utxo, c->key, c->pub,
                       /*corrupt=*/true);

        struct wallet_tx_admission admission = {
            .mempool = &pool,
            .coins_tip = &coins,
            .main_state = c->state,
            .params = c->params,
        };
        struct zcl_result r =
            wallet_commit_transaction(wallet, &wtx, &admission);

        ok = ok && !r.ok;
        ok = ok && tx_mempool_size(&pool) == 0;
        ok = ok && wallet->num_wallet_tx == 0;
        ok = ok && wallet->num_spent == 0;

        transaction_free(&wtx.tx);
        wallet_free(wallet);
        free(wallet);
    }
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

static bool atm_gate_wallet_valid(const struct atm_ctx *c)
{
    struct tx_mempool pool;
    tx_mempool_init(&pool, 0);

    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache coins;
    coins_view_cache_init(&coins, &null_view);

    struct uint256 utxo;
    memset(utxo.data, 0xD6, 32);
    bool ok = atm_add_p2pkh_utxo(&coins, &utxo, atm_det_utxo, c->kid);

    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                       "atm_valid_wallet");
    ok = ok && wallet != NULL;
    if (wallet) {
        wallet_init(wallet);
        struct wallet_tx wtx;
        memset(&wtx, 0, sizeof(wtx));
        atm_build_spend(&wtx.tx, &utxo, 50 * COIN_VALUE);
        atm_sign_input(&wtx.tx, c->spk, atm_det_utxo, c->key, c->pub,
                       /*corrupt=*/false);

        struct wallet_tx_admission admission = {
            .mempool = &pool,
            .coins_tip = &coins,
            .main_state = c->state,
            .params = c->params,
        };
        struct zcl_result r =
            wallet_commit_transaction(wallet, &wtx, &admission);

        ok = ok && r.ok;
        ok = atm_gate_wallet_committed(wallet, &wtx, &pool, &utxo, ok);

        struct zcl_result rollback =
            wallet_rollback_transaction(wallet, &wtx, &pool);
        ok = ok && rollback.ok;
        ok = atm_gate_wallet_rolled_back(wallet, &pool, &utxo, ok);

        /* Restart recovery re-admits the same signed bytes without
         * recreating the already-durable wallet mutation. */
        struct zcl_result reaccepted =
            wallet_reaccept_transaction(&wtx, &admission);
        ok = ok && reaccepted.ok;
        ok = atm_gate_wallet_reaccepted(wallet, &wtx, &pool, ok);
        tx_mempool_remove(&pool, &wtx.tx.hash);

        transaction_free(&wtx.tx);
        wallet_free(wallet);
        free(wallet);
    }
    coins_view_cache_free(&coins);
    tx_mempool_free(&pool);
    return ok;
}

int test_accept_to_mempool(void)
{
    int failures = 0;

    /* Use the same complete consensus context production callers provide.
     * Tests must not accidentally prove only the permissive NULL-context
     * scaffolding path. */
    struct main_state main_state;
    main_state_init(&main_state);
    const struct chain_params *params = chain_params_get();

    struct privkey key;
    privkey_make_new(&key, true);
    struct pubkey pub;
    privkey_get_pubkey(&key, &pub);
    struct key_id kid = pubkey_get_id(&pub);

    struct script prev_spk;
    script_for_p2pkh(&prev_spk, &kid);
    const int64_t utxo_value = 100 * COIN_VALUE;
    struct atm_ctx ctx = {
        .state = &main_state, .params = params, .kid = &kid,
        .spk = &prev_spk, .key = &key, .pub = &pub,
    };

    /* ================================================================
     * 1. BAD signature → REJECTED before relay.
     *    Structurally valid tx, prevout exists, fee positive, forged
     *    transparent signature: the gate returns MEMPOOL_ACCEPT_INVALID and
     *    leaves the mempool empty.
     * ================================================================ */
    printf("accept_to_mempool: bad-sig tx REJECTED before relay... ");
    failures += atm_report(atm_gate_bad_sig(&ctx));

    /* ================================================================
     * 2. VALID signature → ACCEPTED (so it can be relayed).
     *    Same shape, correctly-signed. The gate must admit it
     *    (MEMPOOL_ACCEPT_OK) and the mempool holds it.
     * ================================================================ */
    printf("accept_to_mempool: valid-sig tx ACCEPTED... ");
    failures += atm_report(atm_gate_valid_sig(&ctx));

    /* The real progress mutex must be acquired before the input-dependent
     * cs_main section. Simulate the finalizer holding progress and needing
     * cs_main while a valid transaction reaches the shared gate. */
#ifdef ZCL_TESTING
    failures += atm_guard_test(&main_state, params, &kid, &prev_spk,
                               &key, &pub, utxo_value);
#endif

    /* ================================================================
     * 3. Missing inputs → MISSING_INPUTS (orphan, not relayed).
     *    No UTXO seeded for the prevout. Even with a valid-looking
     *    signature the gate reports the input is unknown.
     * ================================================================ */
    printf("accept_to_mempool: missing-input tx → MISSING_INPUTS... ");
    failures += atm_report(atm_gate_missing_input(&ctx));

    /* The shared gate is a production boundary, not a best-effort helper:
     * missing chain context must never skip crypto/input checks and admit. */
    printf("accept_to_mempool: incomplete context fails closed... ");
    failures += atm_report(atm_gate_incomplete_ctx(&ctx));

    /* ================================================================
     * 4. D5 PARITY: NON-FINAL tx REJECTED without punishing the peer.
     *    zclassicd applies CheckFinalTx/BIP113 during mempool acceptance,
     *    against the next height and tip MedianTimePast. This is relay
     *    policy; block-connect finality remains a separate consensus check.
     *
     *    The lock_time is a huge HEIGHT-domain value (10,000,000, below
     *    LOCKTIME_THRESHOLD 5e8 so it is interpreted as a height far above
     *    any plausible tip) and the single input's sequence is NON-final
     *    (not 0xFFFFFFFF), so the lock is ACTIVE. lock_time + sequence are
     *    set BEFORE signing so the signature covers them.
     * ================================================================ */
    printf("accept_to_mempool: NON-FINAL tx rejected by policy... ");
    failures += atm_report(atm_gate_nonfinal(&ctx));

    /* ================================================================
     * 5. L5 PARITY: a transaction expiring inside the three-block relay
     *    horizon is rejected. This is mempool policy, not block consensus.
     * ================================================================ */
    printf("accept_to_mempool: expiring-soon tx rejected by policy... ");
    failures += atm_report(atm_gate_expiring(&ctx));

    /* ================================================================
     * 6. Wallet commit with a forged signature fails atomically: an
     *    invalid transaction changes neither wallet nor mempool state.
     * ================================================================ */
    printf("wallet commit: bad-sig tx rejected with no state mutation... ");
    failures += atm_report(atm_gate_wallet_bad_sig(&ctx));

    /* ================================================================
     * 7. Wallet commit accepts a valid transaction only after the shared
     *    gate, then updates the mempool and wallet together.
     * ================================================================ */
    printf("wallet commit: valid tx admitted through shared gate... ");
    failures += atm_report(atm_gate_wallet_valid(&ctx));

    failures += atm_detail_branches(&ctx);

    main_state_free(&main_state);

    return failures;
}
