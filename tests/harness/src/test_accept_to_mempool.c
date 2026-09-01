/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the shared mempool-acceptance gate
 * accept_to_mempool() (core/modules/validation). The bug it closes: the relay
 * paths (P2P `tx` + RPC sendrawtransaction) admitted and fluffed a tx
 * with a structurally-valid shape and existing prevouts but an INVALID
 * transparent signature — only block-connect rejected it, after the
 * invalid-sig flood had already wasted every node's bandwidth.
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

    /* ================================================================
     * 1. BAD signature → REJECTED before relay.
     *    A tx structurally valid, prevout exists, fee positive, but the
     *    transparent signature is forged. Old relay path accepted+fluffed
     *    this; the gate must now reject it (MEMPOOL_ACCEPT_INVALID) and
     *    leave the mempool empty.
     * ================================================================ */
    printf("accept_to_mempool: bad-sig tx REJECTED before relay... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 utxo;
        memset(utxo.data, 0xD1, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);

        struct transaction tx;
        atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
        atm_sign_input(&tx, &prev_spk, utxo_value, &key, &pub,
                       /*corrupt=*/true);

        enum mempool_accept_result r =
            accept_to_mempool(&pool, &coins, &main_state, params, &tx);

        ok = ok && (r == MEMPOOL_ACCEPT_INVALID);
        ok = ok && (tx_mempool_size(&pool) == 0);

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 2. VALID signature → ACCEPTED (so it can be relayed).
     *    Same shape, correctly-signed. The gate must admit it
     *    (MEMPOOL_ACCEPT_OK) and the mempool holds it.
     * ================================================================ */
    printf("accept_to_mempool: valid-sig tx ACCEPTED... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 utxo;
        memset(utxo.data, 0xD2, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);

        struct transaction tx;
        atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
        atm_sign_input(&tx, &prev_spk, utxo_value, &key, &pub,
                       /*corrupt=*/false);

        enum mempool_accept_result r =
            accept_to_mempool(&pool, &coins, &main_state, params, &tx);

        ok = ok && (r == MEMPOOL_ACCEPT_OK);
        ok = ok && (tx_mempool_size(&pool) == 1);
        ok = ok && tx_mempool_exists(&pool, &tx.hash);

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 3. Missing inputs → MISSING_INPUTS (orphan, not relayed).
     *    No UTXO seeded for the prevout. Even with a valid-looking
     *    signature the gate reports the input is unknown.
     * ================================================================ */
    printf("accept_to_mempool: missing-input tx → MISSING_INPUTS... ");
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
        atm_sign_input(&tx, &prev_spk, utxo_value, &key, &pub,
                       /*corrupt=*/false);

        enum mempool_accept_result r =
            accept_to_mempool(&pool, &coins, &main_state, params, &tx);

        bool ok = (r == MEMPOOL_ACCEPT_MISSING_INPUTS);
        ok = ok && (tx_mempool_size(&pool) == 0);

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* The shared gate is a production boundary, not a best-effort helper:
     * missing chain context must never skip crypto/input checks and admit. */
    printf("accept_to_mempool: incomplete context fails closed... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);
        struct uint256 utxo;
        memset(utxo.data, 0xD8, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);
        struct transaction tx;
        atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
        atm_sign_input(&tx, &prev_spk, utxo_value, &key, &pub,
                       /*corrupt=*/false);

        enum mempool_accept_result r =
            accept_to_mempool(&pool, &coins, NULL, params, &tx);
        ok = ok && r == MEMPOOL_ACCEPT_INTERNAL_ERROR;
        ok = ok && tx_mempool_size(&pool) == 0;

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

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
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 utxo;
        memset(utxo.data, 0xD4, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);

        struct transaction tx;
        atm_build_spend(&tx, &utxo, 50 * COIN_VALUE);
        /* Make the tx NON-FINAL: future height-domain lock_time + a
         * non-final input sequence (so the lock is not overridden). Set
         * BEFORE signing so the sighash commits to them. */
        tx.lock_time = 10000000u;          /* height domain, far future */
        tx.vin[0].sequence = 0xFFFFFFFEu;  /* NOT 0xFFFFFFFF → lock active */
        atm_sign_input(&tx, &prev_spk, utxo_value, &key, &pub,
                       /*corrupt=*/false);

        enum mempool_accept_result r =
            accept_to_mempool(&pool, &coins, &main_state, params, &tx);

        ok = ok && (r == MEMPOOL_ACCEPT_NONFINAL);
        ok = ok && (tx_mempool_size(&pool) == 0);

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 5. L5 PARITY: a transaction expiring inside the three-block relay
     *    horizon is rejected. This is mempool policy, not block consensus.
     * ================================================================ */
    printf("accept_to_mempool: expiring-soon tx rejected by policy... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 utxo;
        memset(utxo.data, 0xD7, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);

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
            accept_to_mempool(&pool, &coins, &main_state, params, &tx);

        ok = ok && (r == MEMPOOL_ACCEPT_EXPIRING_SOON);
        ok = ok && (tx_mempool_size(&pool) == 0);

        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 6. Wallet commit with a forged signature fails atomically.
     *    Locally-created transactions used to bypass accept_to_mempool()
     *    through tx_mempool_add_unchecked(). Pin the invariant that an
     *    invalid transaction changes neither wallet nor mempool state.
     * ================================================================ */
    printf("wallet commit: bad-sig tx rejected with no state mutation... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 utxo;
        memset(utxo.data, 0xD5, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);

        struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                           "atm_bad_sig_wallet");
        ok = ok && wallet != NULL;
        if (wallet) {
            wallet_init(wallet);
            struct wallet_tx wtx;
            memset(&wtx, 0, sizeof(wtx));
            atm_build_spend(&wtx.tx, &utxo, 50 * COIN_VALUE);
            atm_sign_input(&wtx.tx, &prev_spk, utxo_value, &key, &pub,
                           /*corrupt=*/true);

            struct wallet_tx_admission admission = {
                .mempool = &pool,
                .coins_tip = &coins,
                .main_state = &main_state,
                .params = params,
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * 7. Wallet commit accepts a valid transaction only after the shared
     *    gate, then updates the mempool and wallet together.
     * ================================================================ */
    printf("wallet commit: valid tx admitted through shared gate... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);

        struct uint256 utxo;
        memset(utxo.data, 0xD6, 32);
        bool ok = atm_add_p2pkh_utxo(&coins, &utxo, utxo_value, &kid);

        struct wallet *wallet = zcl_calloc(1, sizeof(*wallet),
                                           "atm_valid_wallet");
        ok = ok && wallet != NULL;
        if (wallet) {
            wallet_init(wallet);
            struct wallet_tx wtx;
            memset(&wtx, 0, sizeof(wtx));
            atm_build_spend(&wtx.tx, &utxo, 50 * COIN_VALUE);
            atm_sign_input(&wtx.tx, &prev_spk, utxo_value, &key, &pub,
                           /*corrupt=*/false);

            struct wallet_tx_admission admission = {
                .mempool = &pool,
                .coins_tip = &coins,
                .main_state = &main_state,
                .params = params,
            };
            struct zcl_result r =
                wallet_commit_transaction(wallet, &wtx, &admission);

            ok = ok && r.ok;
            ok = ok && tx_mempool_size(&pool) == 1;
            ok = ok && tx_mempool_exists(&pool, &wtx.tx.hash);
            ok = ok && wallet->num_wallet_tx == 1;
            ok = ok && wallet->num_spent == 1;
            ok = ok && wallet_is_outpoint_spent(wallet, &utxo, 0);

            struct zcl_result rollback =
                wallet_rollback_transaction(wallet, &wtx, &pool);
            ok = ok && rollback.ok;
            ok = ok && tx_mempool_size(&pool) == 0;
            ok = ok && wallet->num_wallet_tx == 0;
            ok = ok && wallet->num_spent == 0;
            ok = ok && !wallet_is_outpoint_spent(wallet, &utxo, 0);

            /* Restart recovery re-admits the same signed bytes without
             * recreating the already-durable wallet mutation. */
            struct zcl_result reaccepted =
                wallet_reaccept_transaction(&wtx, &admission);
            ok = ok && reaccepted.ok;
            ok = ok && tx_mempool_exists(&pool, &wtx.tx.hash);
            ok = ok && wallet->num_wallet_tx == 0;
            ok = ok && wallet->num_spent == 0;
            tx_mempool_remove(&pool, &wtx.tx.hash);

            transaction_free(&wtx.tx);
            wallet_free(wallet);
            free(wallet);
        }
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    main_state_free(&main_state);

    return failures;
}
