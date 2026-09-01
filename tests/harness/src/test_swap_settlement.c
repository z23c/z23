/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the HTLC swap settlement service (swap_redeem / swap_refund).
 *
 * These are HERMETIC end-to-end proofs: each case builds a real HTLC P2SH
 * contract, signs a spending transaction via swap_settlement_build_redeem /
 * _build_refund (the production settlement service), then runs the actual
 * consensus script interpreter (verify_script with SCRIPT_VERIFY_P2SH +
 * CHECKLOCKTIMEVERIFY) against the P2SH scriptPubKey. If the interpreter
 * accepts the input, a live node would too — no chain needed.
 *
 * Coverage:
 *   - redeem happy path (correct secret unlocks the claim branch)
 *   - redeem with the WRONG secret is rejected (hash-preimage mismatch)
 *   - refund AFTER locktime is accepted (nLockTime == contract CLTV)
 *   - refund BEFORE locktime is rejected (nLockTime < contract CLTV)
 *   - refund with a FINAL input sequence is rejected (CLTV skipped)
 *   - state transitions PENDING -> FUNDED -> REDEEMED persist via AR save */

#include "test/test_core.h"
#include "services/swap_settlement_service.h"
#include "script/htlc.h"
#include "script/interpreter.h"
#include "script/script_flags.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "validation/tx_verifier.h"
#include "validation/sighash.h"
#include "script/sighashtype.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "core/hash.h"
#include "crypto/sha256.h"
#include "models/database.h"
#include "models/swap_contract.h"
#include <sqlite3.h>

/* Self-consistent branch id for sign/verify (value is opaque to the test). */
#define TEST_BRANCH_ID 0x76b809bbU

/* Build the 23-byte P2SH scriptPubKey for a redeem script:
 * OP_HASH160 <20:hash160(script)> OP_EQUAL. */
static void p2sh_spk_of(const uint8_t *script, size_t slen, struct script *out)
{
    uint8_t h[20];
    hash160(script, slen, h);
    script_init(out);
    out->data[out->size++] = 0xa9;      /* OP_HASH160 */
    out->data[out->size++] = 0x14;      /* push 20 */
    memcpy(out->data + out->size, h, 20);
    out->size += 20;
    out->data[out->size++] = 0x87;      /* OP_EQUAL */
}

/* Run the consensus interpreter: does `scriptsig` satisfy the P2SH output? */
static bool htlc_spend_ok(const struct script *scriptsig,
                          const struct script *p2sh_spk,
                          const struct transaction *tx, int64_t amount)
{
    struct precomputed_tx_data td;
    precompute_tx_data(tx, &td);
    struct tx_sig_checker tsc;
    tx_sig_checker_init(&tsc, tx, 0, amount, TEST_BRANCH_ID, &td);
    struct sig_checker chk = tx_make_sig_checker(&tsc);
    ScriptError serr = 0;
    return verify_script(scriptsig, p2sh_spk,
                         SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                         &chk, TEST_BRANCH_ID, &serr);
}

/* Sign a refund input by hand (for adversarial nLockTime/sequence cases the
 * production service intentionally will not produce). tx must already have
 * vin[0]/vout[0], lock_time and sequence set. */
static bool sign_refund_input(const uint8_t *contract, size_t clen,
                              const struct privkey *key,
                              const struct pubkey *pub,
                              int64_t amount, struct transaction *tx)
{
    struct script sc;
    script_init(&sc);
    memcpy(sc.data, contract, clen);
    sc.size = clen;

    struct precomputed_tx_data td;
    precompute_tx_data(tx, &td);
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 sh;
    if (!signature_hash(&sc, tx, 0, ht, amount, TEST_BRANCH_ID, &td, &sh))
        return false;

    unsigned char sig[SIGNATURE_SIZE + 1];
    size_t sl = 0;
    if (!privkey_sign(key, &sh, sig, &sl))
        return false;
    sig[sl++] = (unsigned char)SIGHASH_ALL;

    uint8_t ss[512];
    size_t ssl = htlc_build_refund_scriptsig(ss, sizeof(ss), sig, sl,
                                             pub->vch, pub->size, contract, clen);
    if (ssl == 0)
        return false;
    memcpy(tx->vin[0].script_sig.data, ss, ssl);
    tx->vin[0].script_sig.size = ssl;
    transaction_compute_hash(tx);
    return true;
}

int test_swap_settlement(void)
{
    int failures = 0;
    printf("\n=== HTLC Swap Settlement (redeem/refund) Tests ===\n");

    /* ── Key material: recipient (claims) + refunder (times out) ── */
    struct privkey rkey, fkey;
    privkey_make_new(&rkey, true);
    privkey_make_new(&fkey, true);
    struct pubkey rpub, fpub;
    privkey_get_pubkey(&rkey, &rpub);
    privkey_get_pubkey(&fkey, &fpub);
    struct key_id rkid = pubkey_get_id(&rpub);
    struct key_id fkid = pubkey_get_id(&fpub);

    /* ── Secret + HTLC contract ── */
    uint8_t secret[32], secret_hash[32];
    htlc_generate_secret(secret, secret_hash);

    const uint32_t LOCKTIME = 800000;
    struct htlc_params hp;
    memset(&hp, 0, sizeof(hp));
    memcpy(hp.secret_hash, secret_hash, 32);
    memcpy(hp.recipient_pkh, rkid.id.data, 20);
    memcpy(hp.refunder_pkh, fkid.id.data, 20);
    hp.locktime = LOCKTIME;

    uint8_t contract[128];
    size_t clen = htlc_build_script(&hp, contract, sizeof(contract));

    struct script p2sh_spk;
    p2sh_spk_of(contract, clen, &p2sh_spk);

    /* Funding facts */
    struct outpoint funding;
    memset(&funding, 0, sizeof(funding));
    memset(funding.hash.data, 0x42, 32);
    funding.n = 0;
    const int64_t FUND = 100000000;   /* 1 ZCL */
    const int64_t FEE  = 1000;

    struct script redeemer_spk, refunder_spk;
    script_for_p2pkh(&redeemer_spk, &rkid);
    script_for_p2pkh(&refunder_spk, &fkid);

    struct swap_settle_ctx base;
    memset(&base, 0, sizeof(base));
    base.contract = contract;
    base.contract_len = clen;
    base.funding = funding;
    base.funding_value = FUND;
    base.fee = FEE;
    base.branch_id = TEST_BRANCH_ID;
    base.expiry_height = 0;

    /* ── 1. Redeem happy path ── */
    printf("swap_redeem: correct secret unlocks the claim branch... ");
    {
        struct swap_settle_ctx c = base;
        c.dest_spk = redeemer_spk;
        struct transaction tx;
        transaction_init(&tx);
        struct zcl_result r =
            swap_settlement_build_redeem(&c, &rkey, &rpub, secret, &tx);
        bool ok = r.ok &&
                  htlc_spend_ok(&tx.vin[0].script_sig, &p2sh_spk, &tx, FUND) &&
                  tx.vout[0].value == FUND - FEE &&
                  tx.lock_time == 0;
        if (r.ok) transaction_free(&tx);
        if (ok) printf("OK\n");
        else { printf("FAIL (r.ok=%d msg=%s)\n", r.ok, r.message); failures++; }
    }

    /* ── 2. Redeem with WRONG secret is rejected ── */
    printf("swap_redeem: wrong secret is rejected by interpreter... ");
    {
        struct swap_settle_ctx c = base;
        c.dest_spk = redeemer_spk;
        uint8_t bad[32];
        memset(bad, 0x99, 32);
        struct transaction tx;
        transaction_init(&tx);
        struct zcl_result r =
            swap_settlement_build_redeem(&c, &rkey, &rpub, bad, &tx);
        /* The build succeeds (it just embeds the pushed bytes); the SCRIPT
         * must reject it because SHA256(bad) != secret_hash. */
        bool ok = r.ok &&
                  !htlc_spend_ok(&tx.vin[0].script_sig, &p2sh_spk, &tx, FUND);
        if (r.ok) transaction_free(&tx);
        if (ok) printf("OK\n");
        else { printf("FAIL (r.ok=%d)\n", r.ok); failures++; }
    }

    /* ── 3. Refund AFTER locktime is accepted ── */
    printf("swap_refund: nLockTime == CLTV is accepted... ");
    {
        struct swap_settle_ctx c = base;
        c.dest_spk = refunder_spk;
        struct transaction tx;
        transaction_init(&tx);
        struct zcl_result r =
            swap_settlement_build_refund(&c, &fkey, &fpub, LOCKTIME, &tx);
        bool ok = r.ok &&
                  tx.lock_time == LOCKTIME &&
                  tx.vin[0].sequence == 0xFFFFFFFEu &&
                  htlc_spend_ok(&tx.vin[0].script_sig, &p2sh_spk, &tx, FUND);
        if (r.ok) transaction_free(&tx);
        if (ok) printf("OK\n");
        else { printf("FAIL (r.ok=%d msg=%s)\n", r.ok, r.message); failures++; }
    }

    /* ── 4. Refund BEFORE locktime is rejected (CLTV) ── */
    printf("swap_refund: nLockTime < CLTV is rejected... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.lock_time = LOCKTIME - 1;           /* too early */
        tx.vin[0].prevout = funding;
        tx.vin[0].sequence = 0xFFFFFFFEu;
        tx.vout[0].value = FUND - FEE;
        tx.vout[0].script_pub_key = refunder_spk;

        bool signed_ok = sign_refund_input(contract, clen, &fkey, &fpub,
                                           FUND, &tx);
        bool ok = signed_ok &&
                  !htlc_spend_ok(&tx.vin[0].script_sig, &p2sh_spk, &tx, FUND);
        transaction_free(&tx);
        if (ok) printf("OK\n");
        else { printf("FAIL (signed=%d)\n", signed_ok); failures++; }
    }

    /* ── 5. Refund with a FINAL sequence is rejected (CLTV skipped) ── */
    printf("swap_refund: final input sequence is rejected... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.lock_time = LOCKTIME;
        tx.vin[0].prevout = funding;
        tx.vin[0].sequence = 0xFFFFFFFFu;      /* final -> CLTV fails */
        tx.vout[0].value = FUND - FEE;
        tx.vout[0].script_pub_key = refunder_spk;

        bool signed_ok = sign_refund_input(contract, clen, &fkey, &fpub,
                                           FUND, &tx);
        bool ok = signed_ok &&
                  !htlc_spend_ok(&tx.vin[0].script_sig, &p2sh_spk, &tx, FUND);
        transaction_free(&tx);
        if (ok) printf("OK\n");
        else { printf("FAIL (signed=%d)\n", signed_ok); failures++; }
    }

    /* ── 6. Refund service refuses a zero locktime ── */
    printf("swap_refund: rejects locktime==0 contract... ");
    {
        struct swap_settle_ctx c = base;
        c.dest_spk = refunder_spk;
        struct transaction tx;
        transaction_init(&tx);
        struct zcl_result r =
            swap_settlement_build_refund(&c, &fkey, &fpub, 0, &tx);
        if (!r.ok) printf("OK\n");
        else { printf("FAIL (built a refund with no deadline)\n");
               transaction_free(&tx); failures++; }
    }

    /* ── 7. Settlement service rejects a fee that eats the whole output ── */
    printf("swap settle: fee >= funding value is rejected... ");
    {
        struct swap_settle_ctx c = base;
        c.dest_spk = redeemer_spk;
        c.fee = FUND;                          /* nothing left */
        struct transaction tx;
        transaction_init(&tx);
        struct zcl_result r =
            swap_settlement_build_redeem(&c, &rkey, &rpub, secret, &tx);
        if (!r.ok) printf("OK\n");
        else { printf("FAIL\n"); transaction_free(&tx); failures++; }
    }

    /* ── 8. State transitions persist: PENDING -> FUNDED -> REDEEMED ── */
    printf("swap state transitions persist via AR save... ");
    {
        sqlite3 *db = NULL;
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
            printf("FAIL (open)\n"); failures++;
        } else {
            sqlite3_exec(db,
                "CREATE TABLE zswp_contracts("
                "swap_id TEXT PRIMARY KEY, role INTEGER, state INTEGER,"
                "chain INTEGER, secret_hash BLOB, secret BLOB,"
                "amount INTEGER, locktime INTEGER,"
                "my_address TEXT, counter_address TEXT,"
                "funding_txid BLOB, funding_vout INTEGER,"
                "redeem_script BLOB, redeem_script_len INTEGER,"
                "p2sh_address TEXT, created_at INTEGER)",
                NULL, NULL, NULL);
            struct node_db ndb = { .db = db, .open = true };

            struct swap_contract sw = {0};
            swap_compute_id("t1me", "t1them", secret_hash, sw.swap_id);
            sw.role = SWAP_INITIATOR;
            sw.state = SWAP_PENDING;
            sw.chain = SWAP_CHAIN_ZCL;
            memcpy(sw.secret_hash, secret_hash, 32);
            sw.amount = FUND;
            sw.locktime = LOCKTIME;
            snprintf(sw.my_address, sizeof(sw.my_address), "t1me");
            snprintf(sw.counter_address, sizeof(sw.counter_address), "t1them");
            memcpy(sw.redeem_script, contract, clen);
            sw.redeem_script_len = clen;
            snprintf(sw.p2sh_address, sizeof(sw.p2sh_address), "t3contract");
            sw.created_at = 1700000000;

            bool save_ok = db_swap_save(&ndb, &sw);
            bool fund_ok = db_swap_update_state(&ndb, sw.swap_id,
                                                SWAP_FUNDED, NULL);
            struct swap_contract after_fund = {0};
            db_swap_find(&ndb, sw.swap_id, &after_fund);
            bool redeem_ok = db_swap_update_state(&ndb, sw.swap_id,
                                                  SWAP_REDEEMED, secret);
            struct swap_contract after_redeem = {0};
            db_swap_find(&ndb, sw.swap_id, &after_redeem);

            if (save_ok && fund_ok && after_fund.state == SWAP_FUNDED &&
                redeem_ok && after_redeem.state == SWAP_REDEEMED &&
                after_redeem.has_secret &&
                memcmp(after_redeem.secret, secret, 32) == 0)
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }

            sqlite3_close(db);
        }
    }

    printf("\n%d swap-settlement test(s) failed\n", failures);
    return failures;
}
