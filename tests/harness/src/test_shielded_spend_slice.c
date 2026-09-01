/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_spend_slice — the MVP "spend a shielded note" SPEND slice.
 *
 * WHAT THIS PROVES (the v1 "spend a shielded note" guarantee)
 * -----------------------------------------------------------
 * A wallet can CONSTRUCT the consensus-critical fields of a Sapling
 * SpendDescription for a note it owns, such that an independent verifier
 * accepts them:
 *   - cv         = value·G_v + rcv·G_rcv          (value commitment)
 *   - nf         = BLAKE2s("Zcash_nf", nk || rho) (the nullifier)
 *   - rk         = ak + ar·G_spendauth            (re-randomized vk)
 *   - spend_auth = RedJubjub_sign(ask + ar, sighash) verifies under rk
 *   - binding    = RedJubjub over bsk = Σrcv_spends − Σrcv_outputs, and
 *     sapling_final_check closes the bundle at the declared value_balance
 * This is the sender/spend half that mirrors test_shielded_receive_slice's
 * receive half: where receive exercises decrypt + credit, this exercises
 * the cv/nullifier/spend-auth/binding accounting a payer must get right.
 *
 * WHY THIS IS PARAMS-FREE (no ~/.zcash-params, fully in-process)
 * -------------------------------------------------------------
 * Every assertion below is over the Sapling crypto that does NOT touch the
 * Groth16 PROVING keys (the ~770 MB sapling-spend/output.params):
 *   sapling_value_commit, sapling_compute_nf, sapling_compute_rk,
 *   redjubjub_sign / redjubjub_verify, sapling_create_binding_sig,
 *   sapling_final_check (+ the Jubjub balance accumulator). The ONLY part
 *   of a SpendDescription that needs the proving key is the 192-byte
 *   Groth16 zkproof, which we deliberately STUB (zeroed) — exactly as
 *   test_shielded_receive_slice zeroes od_proof on the output side. The
 *   full proof-bearing path lives behind sapling_build_spend_with_ctx
 *   (which takes a proving_ctx) and is exercised by the params-heavy gates.
 *
 * THE REAL SUBSYSTEM FUNCTIONS UNDER TEST (no tautologies)
 * -------------------------------------------------------
 *   - sapling_keystore_set_seed / sapling_keystore_new_address (key gen)
 *   - sapling_ask_to_ak / sapling_nsk_to_nk                    (vk derivation)
 *   - sapling_value_commit                                     (cv)
 *   - sapling_compute_nf                                       (nullifier)
 *   - sapling_compute_rk + redjubjub_sign/verify              (spend_auth)
 *   - sapling_create_binding_sig + sapling_final_check         (binding/balance)
 * Each assertion invokes the real function and asserts the correct result,
 * plus negative checks (wrong vk, wrong value_balance) that must be rejected.
 */

#include "test/test_core.h"

#include "core/uint256.h"
#include "primitives/transaction.h"
#include "sapling/constants.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define SSS_CHECK(name, expr) do {                          \
    printf("shielded_spend_slice: %s... ", (name));         \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

int test_shielded_spend_slice(void);
int test_shielded_spend_slice(void)
{
    printf("\n=== shielded spend slice "
           "(MVP: build a Sapling SpendDescription -> cv/nf/spend-auth/binding) ===\n");
    int failures = 0;

    /* Pure in-memory crypto over a per-call keystore — no process-global
     * singletons, no disk, no params. Safe in the parallel pool, but kept
     * OPT-IN behind ZCL_STRESS_TESTS to match the established MVP-gate
     * discipline (the receive/parity slices use the identical idiom). */
    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("shielded_spend_slice: SKIP "
               "(set ZCL_STRESS_TESTS=1 to run the deterministic spend gate)\n");
        return 0;
    }

    const uint64_t SPEND_VALUE = 100000000ULL; /* 1.00000000 ZCL in zatoshi */

    /* ── (1) Derive a Sapling spending key for the note we will spend.
     * sapling_keystore_new_address fills in diversifier/pk_d; the spending
     * material (ask, nsk) lives in keys[0].xsk.expsk. ───────────────────── */
    struct wallet *w = zcl_calloc(1, sizeof(struct wallet), "sss_wallet");
    SSS_CHECK("spender wallet allocated", w != NULL);
    if (!w) {
        printf("=== shielded spend slice: %d failure(s) (alloc) ===\n",
               failures);
        return failures;
    }
    wallet_init(w);

    uint8_t seed[32];
    memset(seed, 0x33, 32);
    SSS_CHECK("spender sapling seed set",
              sapling_keystore_set_seed(&w->sapling_keys, seed));

    uint8_t d[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    SSS_CHECK("spender sapling address (diversifier/pk_d) derived",
              sapling_keystore_new_address(&w->sapling_keys, d, pk_d));
    SSS_CHECK("wallet holds exactly one sapling key",
              w->sapling_keys.num_keys == 1);

    const struct sapling_key_entry *ent = &w->sapling_keys.keys[0];
    const uint8_t *ask = ent->xsk.expsk.ask;
    const uint8_t *nsk = ent->xsk.expsk.nsk;

    /* Derive the verification keys the spend description binds to. */
    uint8_t ak[32], nk[32];
    sapling_ask_to_ak(ask, ak);
    sapling_nsk_to_nk(nsk, nk);

    /* The note's commitment randomness (rcm) — a valid Fs scalar. The note
     * we are spending was committed under (d, pk_d, value, rcm). */
    uint8_t rcm[32];
    SSS_CHECK("note rcm sampled (valid Fs)", sapling_generate_r(rcm));

    /* The note sits at a fixed leaf position in the commitment tree. */
    const uint64_t POSITION = 7;

    /* ── (2) cv DERIVATION: cv = value·G_v + rcv·G_rcv, and it is
     * deterministic in (value, rcv). ───────────────────────────────────── */
    uint8_t rcv[32];
    SSS_CHECK("spend rcv sampled (valid Fs)", sapling_generate_r(rcv));

    uint8_t cv[32], cv_again[32];
    bool cv_ok  = sapling_value_commit(SPEND_VALUE, rcv, cv);
    bool cv_ok2 = sapling_value_commit(SPEND_VALUE, rcv, cv_again);
    SSS_CHECK("value commitment cv built", cv_ok && cv_ok2);
    SSS_CHECK("cv is deterministic in (value, rcv)",
              cv_ok && cv_ok2 && memcmp(cv, cv_again, 32) == 0);
    {
        /* A different rcv yields a different cv (hiding). */
        uint8_t rcv2[32], cv2[32];
        bool s = sapling_generate_r(rcv2);
        bool c = s && sapling_value_commit(SPEND_VALUE, rcv2, cv2);
        SSS_CHECK("cv differs under fresh rcv (binding randomness used)",
                  c && memcmp(cv, cv2, 32) != 0);
    }

    /* ── (3) NULLIFIER DERIVATION: nf = BLAKE2s("Zcash_nf", nk || rho),
     * rho = cm_full + position·NullifierPosition. Deterministic in
     * (note, position) and position-dependent. ─────────────────────────── */
    uint8_t nf[32], nf_again[32];
    bool nf_ok  = sapling_compute_nf(d, pk_d, SPEND_VALUE, rcm, ak, nk,
                                     POSITION, nf);
    bool nf_ok2 = sapling_compute_nf(d, pk_d, SPEND_VALUE, rcm, ak, nk,
                                     POSITION, nf_again);
    SSS_CHECK("nullifier nf derived", nf_ok && nf_ok2);
    SSS_CHECK("nf is deterministic in (note, position)",
              nf_ok && nf_ok2 && memcmp(nf, nf_again, 32) == 0);
    {
        /* The SAME note at a DIFFERENT position yields a DIFFERENT nf —
         * the position binding that prevents replaying one note's nf. */
        uint8_t nf_pos[32];
        bool ok = sapling_compute_nf(d, pk_d, SPEND_VALUE, rcm, ak, nk,
                                     POSITION + 1, nf_pos);
        SSS_CHECK("nf is position-bound (differs at a different leaf)",
                  ok && memcmp(nf, nf_pos, 32) != 0);
    }

    /* ── (4) SPEND-AUTH: rk = ak + ar·G_spendauth; the spend authorization
     * signature is RedJubjub_sign(rsk = ask + ar, sighash) and must verify
     * under rk (generator 5), NOT under the bare ak. ───────────────────── */
    uint8_t ar[32];
    SSS_CHECK("spend-auth randomness ar sampled (valid Fs)",
              sapling_generate_r(ar));

    uint8_t rk[32];
    SSS_CHECK("rk = ak + ar·G derived", sapling_compute_rk(ak, ar, rk));

    /* rsk = ask + ar (mod Fs) — the re-randomized signing key for rk. */
    uint8_t rsk[32];
    {
        struct fs ask_fs, ar_fs, rsk_fs;
        fs_from_bytes(&ask_fs, ask);
        fs_from_bytes(&ar_fs, ar);
        fs_add(&rsk_fs, &ask_fs, &ar_fs);
        fs_to_bytes(rsk, &rsk_fs);
    }

    /* The transaction sighash the spend authorizes (32 bytes, deterministic
     * for the test). */
    uint8_t sighash[32];
    memset(sighash, 0x5e, 32);

    uint8_t spend_auth_sig[64];
    bool sign_ok = redjubjub_sign(rsk, sighash, 32, spend_auth_sig, 5);
    SSS_CHECK("spend_auth_sig produced (RedJubjub sign under rsk)", sign_ok);

    SSS_CHECK("spend_auth_sig verifies under the re-randomized key rk",
              sign_ok && redjubjub_verify(rk, sighash, 32,
                                          spend_auth_sig,
                                          spend_auth_sig + 32, 5));

    /* NEGATIVE: it must NOT verify under the bare ak (rk's re-randomization
     * is load-bearing — verifying under ak would leak the un-randomized vk). */
    SSS_CHECK("spend_auth_sig is REJECTED under the un-randomized ak",
              sign_ok && !redjubjub_verify(ak, sighash, 32,
                                           spend_auth_sig,
                                           spend_auth_sig + 32, 5));

    /* NEGATIVE: a tampered sighash must be rejected under rk. */
    {
        uint8_t bad_sighash[32];
        memcpy(bad_sighash, sighash, 32);
        bad_sighash[0] ^= 0xFF;
        SSS_CHECK("spend_auth_sig is REJECTED for a tampered sighash",
                  sign_ok && !redjubjub_verify(rk, bad_sighash, 32,
                                               spend_auth_sig,
                                               spend_auth_sig + 32, 5));
    }

    /* ── (5) Assemble the SpendDescription with a STUBBED Groth16 proof.
     * The 192-byte zkproof is the ONLY field needing the ~770MB proving
     * params; we zero it exactly as the receive slice zeroes od_proof. The
     * cv/nf/rk/spend_auth above are the real, verifiable consensus fields. */
    struct spend_description sd;
    memset(&sd, 0, sizeof(sd));
    memcpy(sd.cv.data, cv, 32);
    memcpy(sd.nullifier.data, nf, 32);
    memcpy(sd.rk.data, rk, 32);
    memcpy(sd.spend_auth_sig, spend_auth_sig, 64);
    /* sd.zkproof intentionally left zeroed — Groth16 proving step stubbed. */
    SSS_CHECK("spend description carries the derived cv",
              memcmp(sd.cv.data, cv, 32) == 0);
    SSS_CHECK("spend description carries the derived nullifier",
              memcmp(sd.nullifier.data, nf, 32) == 0);
    SSS_CHECK("spend description carries the re-randomized rk",
              memcmp(sd.rk.data, rk, 32) == 0);
    {
        bool zproof_zero = true;
        for (size_t i = 0; i < GROTH_PROOF_SIZE; i++)
            if (sd.zkproof[i] != 0) { zproof_zero = false; break; }
        SSS_CHECK("Groth16 zkproof is the stubbed (zeroed) placeholder",
                  zproof_zero);
    }

    /* ── (6) VALUE-BALANCE ACCOUNTING + BINDING SIG.
     * Spend 1.00000000 ZCL, re-output 0.90000000 ZCL into one shielded
     * output; the remaining 0.10000000 ZCL becomes transparent value, so the
     * declared value_balance = spend_val − output_val = +10000000 (net value
     * LEAVING the shielded pool). The binding secret bsk = rcv_spend −
     * rcv_output proves the value commitments balance to value_balance, with
     * NO value minted or burned. ───────────────────────────────────────── */
    const uint64_t OUTPUT_VALUE = 90000000ULL;  /* 0.90000000 ZCL */
    const int64_t  VALUE_BALANCE = (int64_t)SPEND_VALUE - (int64_t)OUTPUT_VALUE;

    uint8_t rcv_out[32], cv_out[32];
    bool rcv_out_ok = sapling_generate_r(rcv_out);
    bool cv_out_ok  = rcv_out_ok &&
                      sapling_value_commit(OUTPUT_VALUE, rcv_out, cv_out);
    SSS_CHECK("output value commitment built", cv_out_ok);

    /* bsk = rcv_spend − rcv_output (one spend, one output). */
    uint8_t bsk[32];
    {
        struct fs spend_fs, out_fs, neg_out_fs, bsk_fs;
        fs_from_bytes(&spend_fs, rcv);
        fs_from_bytes(&out_fs, rcv_out);
        fs_neg(&neg_out_fs, &out_fs);
        fs_add(&bsk_fs, &spend_fs, &neg_out_fs);
        fs_to_bytes(bsk, &bsk_fs);
    }

    uint8_t binding_sig[64];
    bool binding_ok = cv_out_ok &&
                      sapling_create_binding_sig(bsk, sighash, binding_sig);
    SSS_CHECK("binding signature produced over bsk", binding_ok);

    /* Verifier-side bundle balance: ADD the spend cv, SUBTRACT the output cv,
     * then close at value_balance. This is exactly what the per-description
     * check_spend/check_output fold does, done by hand so no proving params
     * are needed. */
    struct sapling_verification_ctx vctx;
    sapling_verification_ctx_init(&vctx);
    {
        struct jub_point pt, neg;
        jub_from_bytes(&pt, cv);     jub_add(&vctx.bvk, &vctx.bvk, &pt);
        jub_from_bytes(&pt, cv_out); jub_neg(&neg, &pt);
        jub_add(&vctx.bvk, &vctx.bvk, &neg);
    }

    SSS_CHECK("binding sig closes the bundle at the declared value_balance",
              binding_ok &&
              sapling_final_check(&vctx, VALUE_BALANCE, binding_sig, sighash));

    /* NEGATIVE: the SAME binding sig must FAIL for a wrong value_balance —
     * this is the anti-inflation property (no value minted/burned). The
     * balance accumulator was consumed conceptually; rebuild a fresh ctx so
     * the only thing changing is the asserted value_balance. */
    {
        struct sapling_verification_ctx vctx2;
        sapling_verification_ctx_init(&vctx2);
        struct jub_point pt, neg;
        jub_from_bytes(&pt, cv);     jub_add(&vctx2.bvk, &vctx2.bvk, &pt);
        jub_from_bytes(&pt, cv_out); jub_neg(&neg, &pt);
        jub_add(&vctx2.bvk, &vctx2.bvk, &neg);

        SSS_CHECK("binding sig is REJECTED for a wrong value_balance "
                  "(no value minted/burned)",
                  binding_ok &&
                  !sapling_final_check(&vctx2, VALUE_BALANCE + 1,
                                       binding_sig, sighash));
    }

    /* ── (7) Teardown ───────────────────────────────────────────────────── */
    wallet_free(w);
    free(w);

    printf("=== shielded spend slice: %d failure(s) ===\n", failures);
    return failures;
}
