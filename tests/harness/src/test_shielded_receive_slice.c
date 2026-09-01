/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_receive_slice — the MVP "C4" RECEIVE slice gate.
 *
 * WHAT THIS PROVES (the v1 "receive a shielded payment" guarantee)
 * ----------------------------------------------------------------
 * A wallet can RECEIVE a Sapling shielded note end-to-end: a payer
 * encrypts a note plaintext to the wallet's payment address (ivk / pk_d /
 * diversifier), and the wallet trial-decrypts it out of a transaction's
 * shielded output, credits the value, and reflects it in its z-balance —
 * AND a note encrypted to a DIFFERENT viewing key is NOT credited (no
 * false positive). This is the consensus-critical receive half of MVP #4.
 *
 * WHY THIS IS PARAMS-FREE (no ~/.zcash-params, fully in-process)
 * -------------------------------------------------------------
 * RECEIVING a shielded note only needs note DECRYPTION:
 *   dhsecret = [ivk] * epk  (sapling_ka_agree)
 *   key      = KDF(dhsecret, epk)  (sapling_kdf)
 *   plaintext = AEAD_decrypt(key, enc_ciphertext)  (sapling_note_decrypt)
 *   verify   cm == sapling_compute_cm(d, pk_d, value, rcm)
 * None of that touches the Groth16 PROVING keys (the ~770 MB
 * sapling-spend/output.params). The payer-side construction here uses
 * sapling_build_output_description(), whose proof step degrades to a
 * zeroed proof when no proving key is loaded (sapling_get_output_pk()
 * returns NULL) — the cv/cm/epk/enc_ciphertext are computed purely from
 * the recipient's PUBLIC address material, exactly as a real payer would,
 * with NO proving params. The wallet's receive path
 * (wallet_try_sapling_decrypt) never inspects the proof, so the slice is
 * a faithful, hermetic exercise of the production RECEIVE code.
 *
 * THE REAL SUBSYSTEM FUNCTIONS UNDER TEST (no tautologies)
 * -------------------------------------------------------
 *   - sapling_keystore_set_seed / sapling_keystore_new_address  (key/ivk gen)
 *   - sapling_build_output_description                          (payer encrypt)
 *   - wallet_try_sapling_decrypt                                (RECEIVE path)
 *   - wallet_get_sapling_balance                                (credited value)
 * Each assertion invokes the real function and asserts the correct result.
 */

#include "test/test_core.h"

#include "core/uint256.h"
#include "primitives/transaction.h"
#include "sapling/constants.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define SRS_CHECK(name, expr) do {                          \
    printf("shielded_receive_slice: %s... ", (name));       \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* Build a single-output shielded transaction whose v_shielded_output[0]
 * carries a Sapling note for value `value` encrypted to (to_d, to_pk_d).
 * The cv/cm/epk/enc_ciphertext are produced by the PRODUCTION payer path
 * (sapling_build_output_description); od_proof is zeroed (no proving
 * params). On success fills *tx (caller transaction_free) and returns true. */
static bool srs_build_received_output_tx(struct transaction *tx,
                                         const uint8_t to_d[11],
                                         const uint8_t to_pk_d[32],
                                         uint64_t value)
{
    /* ovk is sender-side material only (out_ciphertext for the SENDER's
     * own recovery). For a pure RECEIVE test any 32 bytes work; use a
     * fixed non-zero pattern so the payer path runs its full course. */
    uint8_t ovk[32];
    memset(ovk, 0x5a, 32);

    uint8_t od_cv[32], od_cm[32], od_epk[32];
    uint8_t od_enc[ZC_SAPLING_ENCCIPHERTEXT_SIZE];   /* 580 */
    uint8_t od_out[ZC_SAPLING_OUTCIPHERTEXT_SIZE];   /* 80  */
    uint8_t od_proof[GROTH_PROOF_SIZE];              /* 192 */
    memset(od_cv, 0, sizeof(od_cv));
    memset(od_cm, 0, sizeof(od_cm));
    memset(od_epk, 0, sizeof(od_epk));
    memset(od_enc, 0, sizeof(od_enc));
    memset(od_out, 0, sizeof(od_out));
    memset(od_proof, 0, sizeof(od_proof));

    if (!sapling_build_output_description(ovk, to_d, to_pk_d, value,
                                          NULL /*default memo*/,
                                          od_cv, od_cm, od_epk,
                                          od_enc, od_out, od_proof,
                                          NULL /*rcv unused*/))
        return false;

    transaction_init(tx);
    tx->version = 4;            /* Sapling */
    tx->overwintered = true;
    tx->value_balance = -(int64_t)value; /* shielding into one output */

    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "srs_output_desc");
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return false;
    }
    tx->num_shielded_output = 1;

    struct output_description *od = &tx->v_shielded_output[0];
    memcpy(od->cv.data, od_cv, 32);
    memcpy(od->cm.data, od_cm, 32);
    memcpy(od->ephemeral_key.data, od_epk, 32);
    memcpy(od->enc_ciphertext, od_enc, ZC_SAPLING_ENCCIPHERTEXT_SIZE);
    memcpy(od->out_ciphertext, od_out, ZC_SAPLING_OUTCIPHERTEXT_SIZE);
    memcpy(od->zkproof, od_proof, GROTH_PROOF_SIZE);
    return true;
}

int test_shielded_receive_slice(void);
int test_shielded_receive_slice(void)
{
    printf("\n=== shielded receive slice "
           "(MVP C4: encrypt to wallet ivk -> wallet decrypts -> z-balance) ===\n");
    int failures = 0;

    /* This slice is pure in-memory crypto over per-call keystores/wallets —
     * no process-global singletons, no disk, no params. It is therefore
     * safe in the parallel pool, but we keep it OPT-IN behind
     * ZCL_STRESS_TESTS to match the established MVP-gate discipline (the
     * gate runs for real via its dedicated ZCL_TEST_ONLY=shielded_receive
     * selector / `make mvp-shielded-receive`, in a fresh process). */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("shielded_receive_slice: SKIP "
               "(set ZCL_STRESS_TESTS=1 and run isolated via "
               "`make mvp-shielded-receive`)\n");
        return 0;
    }

    const uint64_t RECV_VALUE = 125000000ULL; /* 1.25000000 ZCL in zatoshi */

    /* ── (1) Generate a Sapling spending key / address for the RECIPIENT
     * wallet. sapling_keystore_new_address derives the ivk + pk_d +
     * diversifier from a deterministic seed (the spending key). ─────────── */
    struct wallet *w = zcl_calloc(1, sizeof(struct wallet), "srs_wallet");
    SRS_CHECK("recipient wallet allocated", w != NULL);
    if (!w) {
        printf("=== shielded receive slice: %d failure(s) (alloc) ===\n",
               failures);
        return failures;
    }
    wallet_init(w);

    uint8_t recipient_seed[32];
    memset(recipient_seed, 0x11, 32);
    SRS_CHECK("recipient sapling seed set",
              sapling_keystore_set_seed(&w->sapling_keys, recipient_seed));

    uint8_t to_d[ZC_DIVERSIFIER_SIZE];
    uint8_t to_pk_d[32];
    SRS_CHECK("recipient sapling address (ivk/pk_d) derived",
              sapling_keystore_new_address(&w->sapling_keys, to_d, to_pk_d));
    SRS_CHECK("wallet holds exactly one sapling key",
              w->sapling_keys.num_keys == 1);

    /* The address material the wallet will trial-decrypt against. */
    uint8_t recipient_ivk[32];
    memcpy(recipient_ivk, w->sapling_keys.keys[0].ivk, 32);
    SRS_CHECK("wallet has the spending key for this ivk",
              sapling_keystore_have_spending_key(&w->sapling_keys,
                                                 recipient_ivk));

    /* Sanity: ivk really reconstructs pk_d from the diversifier — i.e. the
     * keystore handed us a self-consistent address (the same identity the
     * decrypt path re-derives). */
    {
        uint8_t pkd_from_ivk[32];
        bool ok = sapling_ivk_to_pkd(recipient_ivk, to_d, pkd_from_ivk);
        SRS_CHECK("ivk * g_d(diversifier) == pk_d (address self-consistent)",
                  ok && memcmp(pkd_from_ivk, to_pk_d, 32) == 0);
    }

    /* ── (2) PAYER constructs a Sapling output paying the wallet's address.
     * Uses the production sapling_build_output_description — NO proving
     * params required (proof degrades to zero). ─────────────────────────── */
    struct transaction tx;
    bool built = srs_build_received_output_tx(&tx, to_d, to_pk_d, RECV_VALUE);
    SRS_CHECK("payer built shielded output encrypted to wallet (params-free)",
              built);
    if (built) {
        SRS_CHECK("tx carries exactly one shielded output",
                  tx.num_shielded_output == 1);
        /* The enc_ciphertext is real AEAD output, not zeros. */
        bool nonzero = false;
        for (size_t i = 0; i < ZC_SAPLING_ENCCIPHERTEXT_SIZE; i++)
            if (tx.v_shielded_output[0].enc_ciphertext[i] != 0) {
                nonzero = true;
                break;
            }
        SRS_CHECK("enc_ciphertext is real AEAD ciphertext (non-zero)", nonzero);
    }

    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    txid.data[0] = 0xC4; /* arbitrary but distinct txid for the received tx */

    /* Pre-condition: an empty wallet has zero shielded balance. */
    SRS_CHECK("wallet z-balance is 0 before receiving",
              wallet_get_sapling_balance(w) == 0);

    /* ── (3) RECEIVE: drive the output through wallet_try_sapling_decrypt —
     * the real wallet receive path (key-agree -> KDF -> AEAD decrypt ->
     * cm re-derivation -> note credit). ─────────────────────────────────── */
    int found = built ? wallet_try_sapling_decrypt(w, &tx, &txid) : 0;
    SRS_CHECK("wallet decrypted exactly one note from the output", found == 1);
    SRS_CHECK("wallet recorded exactly one sapling note",
              w->num_sapling_notes == 1);

    /* The credited note carries the right value and the right address. */
    if (w->num_sapling_notes == 1) {
        const struct sapling_received_note *n = &w->sapling_notes[0];
        SRS_CHECK("received note value equals paid amount",
                  n->value == RECV_VALUE);
        SRS_CHECK("received note bound to the recipient ivk",
                  memcmp(n->ivk, recipient_ivk, 32) == 0);
        SRS_CHECK("received note bound to the recipient pk_d",
                  memcmp(n->pk_d, to_pk_d, 32) == 0);
        SRS_CHECK("received note carries the output's txid",
                  memcmp(n->txid.data, txid.data, 32) == 0);
    }

    /* ── (4) ASSERT: the shielded balance reflects the received value. ───── */
    SRS_CHECK("wallet z-balance equals the received value (1.25000000 ZCL)",
              wallet_get_sapling_balance(w) == (int64_t)RECV_VALUE);

    /* ── (5) NEGATIVE: a note encrypted to a DIFFERENT viewing key must NOT
     * be credited (no false positive / no double-credit). ───────────────── */
    {
        /* A second, unrelated wallet address (different seed -> different
         * ivk/pk_d). The payer encrypts the note to THAT address. */
        struct sapling_keystore other;
        sapling_keystore_init(&other);
        uint8_t other_seed[32];
        memset(other_seed, 0x22, 32);
        bool seeded = sapling_keystore_set_seed(&other, other_seed);

        uint8_t other_d[ZC_DIVERSIFIER_SIZE];
        uint8_t other_pk_d[32];
        bool addr = seeded &&
                    sapling_keystore_new_address(&other, other_d, other_pk_d);
        SRS_CHECK("foreign sapling address derived (different ivk)", addr);

        /* The foreign ivk is genuinely not ours (the whole point). */
        SRS_CHECK("foreign ivk differs from wallet ivk",
                  addr &&
                  memcmp(other.keys[0].ivk, recipient_ivk, 32) != 0);
        /* And our wallet does NOT hold the spending key for it. */
        SRS_CHECK("wallet does NOT hold the foreign spending key",
                  addr &&
                  !sapling_keystore_have_spending_key(&w->sapling_keys,
                                                      other.keys[0].ivk));

        struct transaction foreign_tx;
        bool fbuilt = addr &&
            srs_build_received_output_tx(&foreign_tx, other_d, other_pk_d,
                                         999000000ULL);
        SRS_CHECK("payer built an output for the FOREIGN address", fbuilt);

        struct uint256 ftxid;
        memset(&ftxid, 0, sizeof(ftxid));
        ftxid.data[0] = 0xFE;

        int64_t bal_before = wallet_get_sapling_balance(w);
        int ffound = fbuilt ? wallet_try_sapling_decrypt(w, &foreign_tx, &ftxid)
                            : -1;
        SRS_CHECK("wallet does NOT decrypt the foreign-addressed note",
                  fbuilt && ffound == 0);
        SRS_CHECK("no new note credited for the foreign output",
                  w->num_sapling_notes == 1);
        SRS_CHECK("wallet z-balance unchanged after foreign note (no false credit)",
                  wallet_get_sapling_balance(w) == bal_before &&
                  wallet_get_sapling_balance(w) == (int64_t)RECV_VALUE);

        if (fbuilt)
            transaction_free(&foreign_tx);
        sapling_keystore_free(&other);
    }

    /* ── (6) Teardown ───────────────────────────────────────────────────── */
    if (built)
        transaction_free(&tx);
    wallet_free(w);
    free(w);

    printf("=== shielded receive slice: %d failure(s) ===\n", failures);
    return failures;
}
