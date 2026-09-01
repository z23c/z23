/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Golden SNARK KAT — positive verification pin for the zk-SNARK engines.
 * =====================================================================
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * A PHGR13 G2-generator consensus bug class can ship GREEN: a
 * corrupted hardcoded generator constant makes the zk-SNARK verifier
 * silently regress to *always-reject* — it false-rejects EVERY proof
 * at pairing check 1. Negative-only tests still pass because the
 * suite only pins the NEGATIVE direction:
 *   - reject when the VK is NULL (fail-closed),
 *   - reject a tampered params file,
 *   - on-curve guards on the generator constant itself.
 * NOTHING pinned the POSITIVE direction — that the pairing engine
 * AGREES with itself on a real, valid relation. An always-reject
 * verifier is indistinguishable from a correct one under negative-only
 * tests, which is exactly the hole the bug slipped through.
 *
 * This file closes that hole with a HARD positive pin on the live
 * BLS12-381 pairing engine (`bls12_381_pairing`) — the exact math
 * whose corruption produced the PHGR13-class always-reject — and pairs
 * it with the negative direction (tamper rejection) on the same engine:
 *
 *   POSITIVE (HARD):
 *     - bilinearity:  e([s]·P, Q) == e(P, [s]·Q)     for real on-curve
 *       VK points P (G1) and Q (G2) and a nontrivial scalar s. A
 *       corrupted generator / broken subgroup / broken Miller loop or
 *       final exponentiation breaks bilinearity → this fails LOUDLY.
 *       This is the single property an always-reject regression cannot
 *       satisfy, and the one a correct engine always does.
 *     - non-degeneracy: e([s]·P, Q) != e(P, Q) for s != 1, and
 *       e(P, Q) != 1 for real non-identity points.
 *
 *   NEGATIVE:
 *     - groth16_proof_read rejects a corrupted proof byte string
 *       (compressed-point decode must fail),
 *     - sapling_check_output rejects a tampered public input / proof
 *       byte (fail-closed consensus verify path).
 *
 * Together these catch a silent always-reject regression:
 * a verifier that regresses to rejecting valid relations fails the
 * bilinearity leg.
 *
 * REAL prover->verify round-trip (HARD)
 * -------------------------------------
 * We additionally drive the production statically-linked Sapling prover
 * (sapling_build_output_with_ctx) and feed its proof to the consensus
 * verifier (sapling_check_output). This MUST verify TRUE. An always-invalid
 * prover can no longer false-green behind negative-only proof tests; the
 * positive cross-implementation result is a release gate. The negative
 * tamper legs on the same produced proof are asserted too.
 *
 * HONEST SCOPE NOTE
 * -----------------
 * The PHGR13 (BN254) verifier has no prover in this codebase, so a fresh
 * prover->verifier round-trip cannot be created here. A separate immutable
 * canonical mainnet fixture in test_sprout_phgr13_kat.c now pins the complete
 * positive Sprout transaction/signature/proof verification direction. The
 * BN254 subgroup/generator regression class also stays pinned by test_phgr13_fix.c
 * (g2_one on-curve + the on-curve guard rejecting a corrupted
 * generator); this file adds the missing POSITIVE pairing pin on the
 * sibling BLS12-381 engine that powers Sapling consensus verification.
 */

#include "test/test_core.h"
#include "sapling/sapling.h"
#include "sapling/bls12_381.h"
#include "sapling/params_init.h"
#include "sapling/sapling_prover.h"
#include "util/safe_alloc.h"

#define KAT_CHECK(name, expr) do {              \
    printf("  %s... ", (name));                 \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* Read a whole file (bounded) into a heap buffer. */
static uint8_t *read_file_bounded(const char *path, size_t cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    size_t want = ((size_t)sz < cap) ? (size_t)sz : cap;
    uint8_t *buf = zcl_malloc(want, "snark_kat_vk_buf");
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, want, f);
    fclose(f);
    if (n != want) { free(buf); return NULL; }
    *out_len = want;
    return buf;
}

static bool find_diversifier(uint8_t diversifier[11])
{
    memset(diversifier, 0, 11);
    for (int i = 0; i < 256; i++) {
        diversifier[0] = (uint8_t)i;
        if (sapling_check_diversifier(diversifier))
            return true;
    }
    return false;
}

/* fp12 equality via subtraction (the engine exposes fp12_sub + is_zero). */
static bool fp12_equal(const struct fp12 *a, const struct fp12 *b)
{
    struct fp12 d;
    fp12_sub(&d, a, b);
    return fp12_is_zero(&d);
}

/* Compute [7]Q on G2 from g2_double + g2_add only (no g2_scalar_mul in
 * the public API). [7]Q = [4]Q + [2]Q + Q. */
static void g2_mul7(struct g2_point *out, const struct g2_point *Q)
{
    struct g2_point q2, q4, tmp;
    g2_double(&q2, Q);     /* [2]Q */
    g2_double(&q4, &q2);   /* [4]Q */
    g2_add(&tmp, &q4, &q2); /* [6]Q */
    g2_add(out, &tmp, Q);   /* [7]Q */
}

int test_snark_kat(void)
{
    printf("\n=== Golden SNARK KAT (BLS12-381 pairing positive pin) ===\n");
    int failures = 0;

    /* ───────────────────────────────────────────────────────────────
     * KAT A — bilinearity of the live pairing engine, anchored on REAL
     * on-curve VK points read straight from the Sapling output params.
     * This is the positive pin: an always-reject regression (corrupted
     * generator / broken subgroup / Miller loop / final exp) cannot
     * satisfy e([s]P,Q) == e(P,[s]Q).
     * ─────────────────────────────────────────────────────────────── */
    printf("KAT A: BLS12-381 bilinearity on real Sapling VK points\n");
    {
        const char *home = getenv("HOME");
        char path[512];
        snprintf(path, sizeof(path),
                 "%s/.zcash-params/sapling-output.params",
                 (home && *home) ? home : ".");

        size_t len = 0;
        /* VK lives at the front of the params blob; 200 KB is ample. */
        uint8_t *buf = read_file_bounded(path, 200000, &len);

        if (!buf) {
            printf("  sapling-output.params not found at %s — SKIPPING\n",
                   path);
            printf("  (the params blob is not vendored into the repo; the\n");
            printf("   real-VK pairing pin is unavailable on this host)\n");
            printf("Golden SNARK KAT: SKIPPED (params absent)\n");
            return 0;
        }

        struct groth16_vk vk = {0};
        bool vk_ok = groth16_vk_read(&vk, buf, len);
        free(buf);
        KAT_CHECK("groth16_vk_read(sapling-output) parses real VK", vk_ok);
        /* Output VK: 6 IC elements (5 public inputs + 1). */
        KAT_CHECK("sapling-output VK has ic_len == 6", vk_ok && vk.ic_len == 6);

        if (vk_ok) {
            /* P = alpha_g1 (real, on-curve, non-identity G1 point),
             * Q = beta_g2  (real, on-curve, non-identity G2 point). */
            const struct g1_point *P = &vk.alpha_g1;
            const struct g2_point *Q = &vk.beta_g2;

            KAT_CHECK("VK alpha_g1 is non-identity", !g1_is_identity(P));
            KAT_CHECK("VK beta_g2 is non-identity", !g2_is_identity(Q));

            /* [7]P via the production g1 scalar mul; [7]Q via doublings. */
            uint64_t s7[4] = {7, 0, 0, 0};
            struct g1_point sP;
            g1_scalar_mul(&sP, P, s7);
            struct g2_point sQ;
            g2_mul7(&sQ, Q);

            struct fp12 lhs, rhs;
            bls12_381_pairing(&lhs, &sP, Q);   /* e([7]P, Q)  */
            bls12_381_pairing(&rhs, P, &sQ);   /* e(P, [7]Q)  */

            /* POSITIVE (HARD): bilinearity must hold. An always-reject /
             * broken pairing engine fails right here. */
            KAT_CHECK("e([7]P, Q) == e(P, [7]Q)  (bilinearity, HARD)",
                      fp12_equal(&lhs, &rhs));

            /* Non-degeneracy: e([7]P,Q) must differ from e(P,Q). */
            struct fp12 base;
            bls12_381_pairing(&base, P, Q);
            KAT_CHECK("e([7]P, Q) != e(P, Q)  (non-degenerate)",
                      !fp12_equal(&lhs, &base));

            /* The pairing of real non-identity points must not be the
             * trivial 1 (a degenerate/zeroed engine collapses to one). */
            struct fp12 one;
            fp12_one(&one);
            KAT_CHECK("e(P, Q) != 1  (engine not degenerate)",
                      !fp12_equal(&base, &one));

            /* NEGATIVE: groth16_proof_read must reject a proof whose A
             * point is a compressed encoding with an out-of-field x.
             * Byte 0 = 0xbf keeps the compression flag (bit7) set and
             * the infinity flag (bit6) CLEAR, so the decoder must parse
             * the x-coordinate — which is all-0xff here, i.e. >= the
             * BLS12-381 base field modulus → on-curve decode must fail. */
            uint8_t junk_proof[192];
            memset(junk_proof, 0xff, sizeof(junk_proof));
            junk_proof[0] = 0xbf; /* compressed, not infinity, x >= p */
            struct groth16_proof gp;
            KAT_CHECK("groth16_proof_read rejects out-of-field compressed A",
                      !groth16_proof_read(&gp, junk_proof));

            if (vk.ic) free(vk.ic);
        }
    }

    /* ───────────────────────────────────────────────────────────────
     * KAT B — production prover -> consensus verifier.
     *
     * POSITIVE is HARD (see header). A flipped proof byte and a tampered
     * public input MUST also be rejected by the consensus verifier.
     * ─────────────────────────────────────────────────────────────── */
    printf("KAT B: canonical prover -> sapling_check_output (consensus path)\n");
    {
        const char *home = getenv("HOME");
        char params_dir[512];
        snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
                 (home && *home) ? home : ".");

        if (!sapling_init_params(params_dir)) {
            printf("  zcash-params init failed — skipping prover round-trip\n");
        } else if (!zclassic_sapling_prover_is_ready()) {
            printf("  SKIP (KAT B prover round-trip) — %s (status=%s). "
                   "KAT A above is pure C23 and ran.\n",
                   zclassic_sapling_prover_backend(),
                   zclassic_sapling_prover_status());
        } else {
            uint8_t diversifier[11];
            bool div_ok = find_diversifier(diversifier);

            uint8_t ask[32], nsk[32], ovk[32];
            sapling_generate_r(ask);
            sapling_generate_r(nsk);
            sapling_generate_r(ovk);
            uint8_t ak[32], nk[32], ivk[32], pk_d[32];
            sapling_ask_to_ak(ask, ak);
            sapling_nsk_to_nk(nsk, nk);
            sapling_crh_ivk(ak, nk, ivk);
            bool pk_ok = div_ok && sapling_ivk_to_pkd(ivk, diversifier, pk_d);

            void *pctx = zclassic_sapling_proving_ctx_init();
            uint8_t cv[32], cm[32], epk[32];
            uint8_t enc[580], out_ct[80], proof[192];
            bool built = pctx && pk_ok &&
                sapling_build_output_with_ctx(pctx, ovk, diversifier, pk_d,
                                              12345, NULL,
                                              cv, cm, epk, enc, out_ct, proof);
            KAT_CHECK("canonical prover produced an output proof", built);

            if (built) {
                /* POSITIVE (HARD): the production prover must satisfy the
                 * independent consensus verifier. */
                struct sapling_verification_ctx vctx;
                sapling_verification_ctx_init(&vctx);
                bool accept = sapling_check_output(&vctx, cv, cm, epk, proof);
                KAT_CHECK("verify(real prover proof) == true (HARD)", accept);

                /* NEGATIVE (HARD): flip one proof byte -> reject. */
                uint8_t bad_proof[192];
                memcpy(bad_proof, proof, 192);
                bad_proof[0] ^= 0x01;
                sapling_verification_ctx_init(&vctx);
                KAT_CHECK("verify(flipped-byte proof) == false",
                          !sapling_check_output(&vctx, cv, cm, epk, bad_proof));

                /* NEGATIVE (HARD): tamper a public input (cm) -> reject. */
                uint8_t bad_cm[32];
                memcpy(bad_cm, cm, 32);
                bad_cm[0] ^= 0x01;
                sapling_verification_ctx_init(&vctx);
                KAT_CHECK("verify(real proof, tampered cm) == false",
                          !sapling_check_output(&vctx, cv, bad_cm, epk, proof));
            }

            if (pctx) zclassic_sapling_proving_ctx_free(pctx);
        }
    }

    printf("Golden SNARK KAT: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
