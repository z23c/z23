/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial + known-answer coverage of the pure-C23 BLS12-381 / Groth16
 * CONSENSUS verifier (core/modules/sapling/src/bls12_381.c). This is the highest-value
 * consensus-critical crypto surface: it validates OTHER peers' shielded
 * Sapling proofs, so a soundness gap here = a forgeable "valid" proof.
 *
 * WHAT THIS FILE PINS (all params-FREE — runs on every host, unlike
 * test_snark_kat.c which SKIPs when ~/.zcash-params is absent):
 *
 *  1. Field-arithmetic self-consistency KATs (fp / fp2 / fp12 inverse,
 *     Montgomery byte round-trip). These give the whole verifier teeth:
 *     an always-reject or corrupted-constant regression breaks them loudly.
 *  2. Pairing KATs on the CANONICAL BLS12-381 generators (hardcoded
 *     compressed bytes — no trusted-setup params needed): bilinearity
 *     e([7]P,Q)==e(P,[7]Q), non-degeneracy e(P,Q)!=1, and the multi-pairing
 *     accept/reject anchor e(P,Q)*e(-P,Q)==1.
 *  3. Point-deserialization adversarial vectors: point-at-infinity encodings
 *     (canonical AND non-canonical), x/y >= field modulus (non-canonical),
 *     all-zero, all-0xFF, bad compression flags — for G1 and G2, compressed
 *     and uncompressed. Each asserts the verifier's ACTUAL accept/reject and
 *     documents it, so any future change to the decode path is caught.
 *  4. SUBGROUP-membership regression anchor: an on-curve-but-NOT-prime-order
 *     G1 point is rejected by g1_in_subgroup AND by groth16_proof_read. The
 *     subgroup check IS present on this branch (bls12_381.c:1778/1782/1786);
 *     this pins it so a future refactor cannot silently drop it (dropping it
 *     is a Groth16 soundness hole — small-subgroup proof forgery).
 *
 * BOUNDARY: this test NEVER changes what the verifier accepts/rejects. It
 * only observes and pins current behavior. Where current behavior is more
 * permissive than the librustzcash reference (non-canonical infinity
 * encodings — see the findings in the lane report), the test documents the
 * CURRENT behavior with a comment; tightening it is a consensus change that
 * must go through a full-chain replay first (CONSENSUS_PARITY_DOCTRINE).
 */

#include "test/test_core.h"
#include "sapling/bls12_381.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define ADV_CHECK(name, expr) do {              \
    printf("  %s... ", (name));                 \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* ── Canonical BLS12-381 generators (compressed, big-endian, with flags).
 * These are the fixed group generators (zkcrypto / librustzcash constants);
 * decompressing them exercises the full sqrt + sign-recovery + subgroup path
 * with zero external params. A corrupted decode or curve constant fails the
 * "generator decompresses AND is in subgroup" leg loudly. ── */
static const uint8_t G1_GEN_COMPRESSED[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,
    0x4f,0xa9,0xac,0x0f,0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,0x6c,0x55,0xe8,0x3f,
    0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};
static const uint8_t G2_GEN_COMPRESSED[96] = {
    0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,0x7d,0xac,0xd3,0xa0,
    0x88,0x27,0x4f,0x65,0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,0x33,0x4c,0xf1,0x12,
    0x13,0x94,0x5d,0x57,0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,0x26,0x08,0x05,0x27,
    0x2d,0xc5,0x10,0x51,0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,0x0b,0xac,0x03,0x26,
    0xa8,0x05,0xbb,0xef,0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};

/* fp12 equality via the public API (fp12_sub + fp12_is_zero). */
static bool fp12_equal(const struct fp12 *a, const struct fp12 *b)
{
    struct fp12 d;
    fp12_sub(&d, a, b);
    return fp12_is_zero(&d);
}

/* fp equality helper via subtraction (fp_eq exists; use it directly). */

/* [7]Q on G2 from doublings + adds (no public g2_scalar_mul). */
static void g2_mul7(struct g2_point *out, const struct g2_point *Q)
{
    struct g2_point q2, q4, tmp;
    g2_double(&q2, Q);
    g2_double(&q4, &q2);
    g2_add(&tmp, &q4, &q2);   /* [6]Q */
    g2_add(out, &tmp, Q);     /* [7]Q */
}

/* Build an on-curve-but-NOT-prime-order-subgroup G1 point deterministically:
 * pick the smallest x >= 2 for which x^3 + 4 is a QR, take its affine point.
 * G1's cofactor is ~76-bit, so a curve point chosen this way lies in the
 * prime-order-r subgroup only with probability ~2^-76 — i.e. essentially
 * never. Returns true and fills *out (affine, z=1) on success. */
static bool make_g1_offcurve_torsion(struct g1_point *out)
{
    struct fp four; /* 4 in Montgomery form == G1 B coefficient */
    /* Recompute 4 = 1+1+1+1 to avoid depending on the private G1_B constant. */
    struct fp one, x;
    fp_one(&one);
    fp_add(&four, &one, &one);
    fp_add(&four, &four, &one);
    fp_add(&four, &four, &one);

    for (unsigned k = 2; k < 64; k++) {
        /* x = k (Montgomery form): start from 1 and add. */
        fp_zero(&x);
        struct fp acc; fp_zero(&acc);
        for (unsigned j = 0; j < k; j++)
            fp_add(&acc, &acc, &one);
        x = acc;

        struct fp x3b, y;
        fp_sq(&x3b, &x);
        fp_mul(&x3b, &x3b, &x);
        fp_add(&x3b, &x3b, &four);   /* x^3 + 4 */
        if (!fp_sqrt(&y, &x3b))
            continue;                /* not a QR — try next x */

        out->x = x;
        out->y = y;
        fp_one(&out->z);
        return true;
    }
    return false;
}

/* Serialize an affine G1 point to the 48-byte compressed encoding this
 * verifier expects (mirrors g1_from_compressed's own flag layout). */
static void g1_affine_to_compressed(uint8_t out[48], const struct g1_point *p)
{
    /* p must be affine (z==1). */
    fp_to_bytes(out, &p->x);
    out[0] |= 0x80; /* compression flag */
    if (fp_lexicographically_largest(&p->y))
        out[0] |= 0x20; /* sort/greatest flag */
}

int test_bls12_381_adversarial(void);
int test_bls12_381_adversarial(void)
{
    printf("\n=== BLS12-381 / Groth16 adversarial + KAT ===\n");
    int failures = 0;

    /* ============================================================
     * 1. Field arithmetic self-consistency KATs
     * ============================================================ */
    printf("Field KATs (fp / fp2 / fp12 inverse, Montgomery round-trip)\n");
    {
        /* Montgomery byte round-trip: from_bytes -> to_bytes -> from_bytes
         * must be the identity on a canonical (< q) value. */
        uint8_t seed[48];
        for (int i = 0; i < 48; i++) seed[i] = (uint8_t)(0x11 * (i + 1));
        seed[0] &= 0x1f; /* keep well below q so fp_from_bytes accepts */
        struct fp a;
        bool a_ok = fp_from_bytes(&a, seed);
        ADV_CHECK("fp_from_bytes accepts a canonical (< q) value", a_ok);

        uint8_t rt[48];
        fp_to_bytes(rt, &a);
        struct fp a2;
        bool a2_ok = fp_from_bytes(&a2, rt);
        ADV_CHECK("fp Montgomery byte round-trip is identity",
                  a_ok && a2_ok && fp_eq(&a, &a2));

        /* fp inverse: a * a^-1 == 1. */
        struct fp inv, prod, one;
        fp_one(&one);
        fp_inv(&inv, &a);
        fp_mul(&prod, &a, &inv);
        ADV_CHECK("fp: a * a^-1 == 1", fp_eq(&prod, &one));

        /* fp2 inverse: b * b^-1 == 1 for a nontrivial b. */
        struct fp2 b, binv, bprod, fp2one;
        b.c0 = a; b.c1 = one;
        fp2_one(&fp2one);
        fp2_inv(&binv, &b);
        fp2_mul(&bprod, &b, &binv);
        ADV_CHECK("fp2: b * b^-1 == 1", fp2_eq(&bprod, &fp2one));

        /* fp2 -1 is a non-residue: sqrt(-1) does not exist in Fp
         * (documents fp_sqrt's reject path). */
        struct fp neg1, sq;
        fp_sub(&neg1, &one, &one);   /* 0 */
        fp_sub(&neg1, &neg1, &one);  /* -1 mod q */
        bool has_sqrt = fp_sqrt(&sq, &neg1);
        ADV_CHECK("fp_sqrt(-1) == false (q == 3 mod 4, -1 is a non-residue)",
                  !has_sqrt);
    }

    /* ============================================================
     * 2. Pairing KATs on the canonical generators (params-free)
     * ============================================================ */
    printf("Pairing KATs on canonical BLS12-381 generators\n");
    struct g1_point G1;
    struct g2_point G2;
    bool g1_ok = g1_from_compressed(&G1, G1_GEN_COMPRESSED);
    bool g2_ok = g2_from_compressed(&G2, G2_GEN_COMPRESSED);
    ADV_CHECK("canonical G1 generator decompresses", g1_ok);
    ADV_CHECK("canonical G2 generator decompresses", g2_ok);
    ADV_CHECK("canonical G1 generator IS in prime-order subgroup",
              g1_ok && g1_in_subgroup(&G1));
    ADV_CHECK("canonical G2 generator IS in prime-order subgroup",
              g2_ok && g2_in_subgroup(&G2));

    if (g1_ok && g2_ok) {
        uint64_t s7[4] = {7, 0, 0, 0};
        struct g1_point s7G1;
        g1_scalar_mul(&s7G1, &G1, s7);
        struct g2_point s7G2;
        g2_mul7(&s7G2, &G2);

        struct fp12 lhs, rhs, base, one12;
        bls12_381_pairing(&lhs, &s7G1, &G2);  /* e([7]G1, G2) */
        bls12_381_pairing(&rhs, &G1, &s7G2);  /* e(G1, [7]G2) */
        bls12_381_pairing(&base, &G1, &G2);   /* e(G1, G2)    */
        fp12_one(&one12);

        /* Bilinearity — the single property an always-reject / corrupted
         * pairing engine cannot satisfy. HARD. */
        ADV_CHECK("e([7]G1,G2) == e(G1,[7]G2)  (bilinearity, HARD)",
                  fp12_equal(&lhs, &rhs));
        ADV_CHECK("e([7]G1,G2) != e(G1,G2)  (non-degenerate)",
                  !fp12_equal(&lhs, &base));
        ADV_CHECK("e(G1,G2) != 1  (engine not degenerate)",
                  !fp12_equal(&base, &one12));

        /* fp12 inverse self-consistency on a real GT element. */
        struct fp12 ginv, gprod;
        fp12_inv(&ginv, &base);
        fp12_mul(&gprod, &base, &ginv);
        ADV_CHECK("fp12: e(G1,G2) * e(G1,G2)^-1 == 1", fp12_equal(&gprod, &one12));

        /* Multi-pairing accept/reject anchor: e(P,Q)*e(-P,Q) == 1 ACCEPTS,
         * e(P,Q)*e(P,Q) does NOT. This is the exact primitive groth16_verify
         * relies on (bls12_381_multi_pairing_check). */
        struct g1_point negG1;
        g1_neg(&negG1, &G1);
        struct g1_point acc_g1[2] = { G1, negG1 };
        struct g2_point acc_g2[2] = { G2, G2 };
        ADV_CHECK("multi_pairing e(P,Q)*e(-P,Q) == 1  (ACCEPT)",
                  bls12_381_multi_pairing_check(acc_g1, acc_g2, 2));

        struct g1_point rej_g1[2] = { G1, G1 };
        struct g2_point rej_g2[2] = { G2, G2 };
        ADV_CHECK("multi_pairing e(P,Q)*e(P,Q) != 1  (REJECT)",
                  !bls12_381_multi_pairing_check(rej_g1, rej_g2, 2));
    }

    /* ============================================================
     * 3. Point deserialization adversarial vectors
     *    (each asserts + documents CURRENT accept/reject)
     * ============================================================ */
    printf("G1 compressed deserialization vectors\n");
    {
        struct g1_point p;

        /* All-zero: byte0 bit7 (compression) clear -> the compressed decoder
         * rejects (it demands the compression flag). */
        uint8_t zero48[48] = {0};
        ADV_CHECK("g1 compressed all-zero -> REJECT (compression flag unset)",
                  !g1_from_compressed(&p, zero48));

        /* Canonical point-at-infinity: compression + infinity flags, rest 0. */
        uint8_t inf_ok[48] = {0};
        inf_ok[0] = 0xc0; /* 1100 0000: compressed + infinity */
        ADV_CHECK("g1 compressed canonical infinity -> ACCEPT (identity)",
                  g1_from_compressed(&p, inf_ok) && g1_is_identity(&p));

        /* NON-CANONICAL infinity: infinity flag set BUT x-bytes nonzero and
         * the sort flag set. librustzcash REJECTS this (infinity requires the
         * remaining bits to be zero); the C23 decoder currently ACCEPTS it
         * (returns identity, ignoring the trailing bytes). This asserts the
         * CURRENT behavior — see the "non-canonical infinity" finding. Do NOT
         * flip this to reject without a full-chain replay (consensus change). */
        uint8_t inf_dirty[48];
        memset(inf_dirty, 0xff, 48);
        inf_dirty[0] = 0xe0; /* compressed + infinity + sort, x = all-1s */
        ADV_CHECK("g1 compressed NON-CANONICAL infinity -> ACCEPT (documents finding)",
                  g1_from_compressed(&p, inf_dirty) && g1_is_identity(&p));

        /* x >= field modulus: compression set, infinity clear, x = all-0xff
         * (>= q) -> on-curve decode must fail at fp_from_bytes. */
        uint8_t x_oob[48];
        memset(x_oob, 0xff, 48);
        x_oob[0] = 0xbf; /* 1011 1111: compressed, not infinity, x >= q */
        ADV_CHECK("g1 compressed x >= q -> REJECT (non-canonical field elem)",
                  !g1_from_compressed(&p, x_oob));

        /* All-0xFF: byte0 == 0xff has the infinity bit (bit6) set, so the
         * decoder short-circuits to identity BEFORE inspecting x. Documents
         * that the infinity flag dominates (same class as the finding above). */
        uint8_t all_ff[48];
        memset(all_ff, 0xff, 48);
        ADV_CHECK("g1 compressed all-0xFF -> ACCEPT as infinity (flag dominates)",
                  g1_from_compressed(&p, all_ff) && g1_is_identity(&p));
    }

    printf("G1 uncompressed deserialization vectors\n");
    {
        struct g1_point p;

        /* All-zero uncompressed: compression clear, infinity clear -> reads
         * x=0,y=0 and checks on-curve (0 == 0 + 4 is false) -> REJECT. */
        uint8_t zero96[96] = {0};
        ADV_CHECK("g1 uncompressed all-zero -> REJECT (0 not on curve)",
                  !g1_from_uncompressed(&p, zero96));

        /* Canonical infinity uncompressed: infinity flag only. */
        uint8_t inf96[96] = {0};
        inf96[0] = 0x40; /* infinity, compression clear */
        ADV_CHECK("g1 uncompressed canonical infinity -> ACCEPT (identity)",
                  g1_from_uncompressed(&p, inf96) && g1_is_identity(&p));

        /* Compression flag set in an UNCOMPRESSED call -> REJECT. */
        uint8_t compflag[96] = {0};
        compflag[0] = 0x80;
        ADV_CHECK("g1 uncompressed with compression flag -> REJECT",
                  !g1_from_uncompressed(&p, compflag));

        /* x >= q uncompressed -> REJECT at fp_from_bytes(x). */
        uint8_t xoob96[96];
        memset(xoob96, 0xff, 96);
        xoob96[0] = 0x1f; /* clear flag bits; x limb still >= q */
        ADV_CHECK("g1 uncompressed x >= q -> REJECT",
                  !g1_from_uncompressed(&p, xoob96));
    }

    printf("G2 compressed / uncompressed deserialization vectors\n");
    {
        struct g2_point q;

        uint8_t zero96[96] = {0};
        ADV_CHECK("g2 compressed all-zero -> REJECT (compression flag unset)",
                  !g2_from_compressed(&q, zero96));

        uint8_t inf_ok[96] = {0};
        inf_ok[0] = 0xc0;
        ADV_CHECK("g2 compressed canonical infinity -> ACCEPT (identity)",
                  g2_from_compressed(&q, inf_ok) && g2_is_identity(&q));

        uint8_t inf_dirty[96];
        memset(inf_dirty, 0xff, 96);
        inf_dirty[0] = 0xe0;
        ADV_CHECK("g2 compressed NON-CANONICAL infinity -> ACCEPT (documents finding)",
                  g2_from_compressed(&q, inf_dirty) && g2_is_identity(&q));

        uint8_t x_oob[96];
        memset(x_oob, 0xff, 96);
        x_oob[0] = 0xbf;
        ADV_CHECK("g2 compressed x >= q -> REJECT",
                  !g2_from_compressed(&q, x_oob));

        uint8_t zero192[192] = {0};
        ADV_CHECK("g2 uncompressed all-zero -> REJECT (0 not on curve)",
                  !g2_from_uncompressed(&q, zero192));

        uint8_t inf192[192] = {0};
        inf192[0] = 0x40;
        ADV_CHECK("g2 uncompressed canonical infinity -> ACCEPT (identity)",
                  g2_from_uncompressed(&q, inf192) && g2_is_identity(&q));
    }

    /* ============================================================
     * 4. Subgroup-membership regression anchor
     * ============================================================ */
    printf("Subgroup-membership anchor (soundness-critical)\n");
    {
        struct g1_point torsion;
        bool built = make_g1_offcurve_torsion(&torsion);
        ADV_CHECK("constructed an on-curve non-subgroup G1 point", built);

        if (built) {
            /* On-curve sanity: y^2 == x^3 + 4 (re-derive 4). */
            struct fp one, four, lhs, rhs;
            fp_one(&one);
            fp_add(&four, &one, &one);
            fp_add(&four, &four, &one);
            fp_add(&four, &four, &one);
            fp_sq(&lhs, &torsion.y);
            fp_sq(&rhs, &torsion.x);
            fp_mul(&rhs, &rhs, &torsion.x);
            fp_add(&rhs, &rhs, &four);
            ADV_CHECK("constructed point is on-curve (y^2 == x^3 + 4)",
                      fp_eq(&lhs, &rhs));

            /* THE anchor: an on-curve point outside the prime-order subgroup
             * MUST be rejected by g1_in_subgroup. If this ever flips to true,
             * the Groth16 soundness check (small-subgroup forgery guard) has
             * regressed. */
            ADV_CHECK("g1_in_subgroup rejects on-curve non-subgroup point",
                      !g1_in_subgroup(&torsion));

            /* End-to-end: a Groth16 proof whose A point is this on-curve
             * non-subgroup point MUST be rejected by groth16_proof_read.
             * (It decodes fine on-curve but fails the subgroup gate at
             * bls12_381.c:1778.) */
            uint8_t proof[192];
            memset(proof, 0, sizeof(proof));
            g1_affine_to_compressed(proof, &torsion);        /* A = torsion */
            memcpy(proof + 48, G2_GEN_COMPRESSED, 96);       /* B = valid G2 */
            g1_affine_to_compressed(proof + 144, &G1);       /* C = valid G1 */
            struct groth16_proof gp;
            ADV_CHECK("groth16_proof_read rejects proof with non-subgroup A",
                      !groth16_proof_read(&gp, proof));

            /* Positive control: a proof built from in-subgroup generators
             * decodes+subgroup-passes (returns true). This proves the
             * rejection above is due to the subgroup gate, not a blanket
             * failure of proof_read on any input. */
            uint8_t good[192];
            memcpy(good, G1_GEN_COMPRESSED, 48);
            memcpy(good + 48, G2_GEN_COMPRESSED, 96);
            memcpy(good + 144, G1_GEN_COMPRESSED, 48);
            struct groth16_proof gp2;
            ADV_CHECK("groth16_proof_read ACCEPTS all-in-subgroup points (control)",
                      groth16_proof_read(&gp2, good));
        }
    }

    /* ============================================================
     * 5. Groth16 BATCH verification — random-linear-combination
     *    (params-free): parity with the per-proof sweep + the
     *    soundness property that the per-batch random scalars defeat
     *    a naive-cancellation forgery.
     * ============================================================ */
    printf("Groth16 batch verify (RLC parity + cancellation soundness)\n");
    if (g1_ok && g2_ok) {
        /* Build a synthetic VK + a family of DISTINCT valid proofs sharing it,
         * using only the canonical generators — no trusted-setup params.
         *
         * Recipe (algebraic identity, verified below by groth16_verify itself):
         *   alpha=G1, beta=gamma=delta=G2, IC=[O, G1], n_inputs=1.
         *   proof j: A=G1(=alpha), B=G2(=beta), input t_j (nonzero) so
         *            vk_x_j = t_j*G1, and C_j = -vk_x_j.
         *   => e(A,B)e(-alpha,beta) = 1  and  e(vk_x_j,-gamma)e(C_j,-delta)
         *      = e(vk_x_j + C_j, -G2) = e(O,-G2) = 1  (gamma==delta). Valid. */
        struct g1_point O1;
        g1_identity(&O1);

        struct groth16_vk vk = {0};   /* zero-init: ic_combs must start NULL */
        vk.alpha_g1 = G1;
        vk.beta_g2  = G2;
        vk.gamma_g2 = G2;
        vk.delta_g2 = G2;
        vk.ic_len   = 2;
        vk.ic = malloc(2 * sizeof(struct g1_point));
        ADV_CHECK("batch: VK IC allocation", vk.ic != NULL);

        if (vk.ic) {
            vk.ic[0] = O1;  /* IC[0] = identity */
            vk.ic[1] = G1;  /* IC[1] = G1 base for vk_x */

            enum { NB = 8 };
            struct groth16_proof proofs[NB];
            uint64_t inputs[NB][4];
            for (int j = 0; j < NB; j++) {
                uint64_t t[4] = { (uint64_t)(j + 3), 0, 0, 0 };
                struct g1_point vk_x_j;
                g1_scalar_mul(&vk_x_j, &G1, t);   /* t_j * G1 */
                proofs[j].a = G1;
                proofs[j].b = G2;
                g1_neg(&proofs[j].c, &vk_x_j);    /* C_j = -vk_x_j */
                inputs[j][0] = t[0];
                inputs[j][1] = 0; inputs[j][2] = 0; inputs[j][3] = 0;
            }

            /* (a) Each proof individually verifies under the canonical
             *     single-proof verifier — establishes the "accept set". */
            bool all_single_ok = true;
            for (int j = 0; j < NB; j++)
                if (!groth16_verify(&vk, &proofs[j],
                                    (const uint64_t (*)[4])&inputs[j], 1))
                    all_single_ok = false;
            ADV_CHECK("batch: every synthetic proof passes per-proof verify",
                      all_single_ok);

            /* (b) PARITY: batch ACCEPTS exactly the set per-proof accepts.
             *     A valid set yields the exact GT identity — deterministic
             *     accept, never a false negative. */
            ADV_CHECK("batch: groth16_batch_verify ACCEPTS the all-valid set",
                      groth16_batch_verify(&vk, proofs,
                                           (const uint64_t (*)[4])inputs,
                                           1, NB));

            /* (c) REJECT-on-corruption + fallback attribution: flip proof k's
             *     C point (add G1). Per-proof sweep must flag exactly k; batch
             *     must FAIL so the caller falls back to that per-proof sweep. */
            {
                struct groth16_proof bad[NB];
                memcpy(bad, proofs, sizeof(bad));
                const int k = 5;
                g1_add(&bad[k].c, &bad[k].c, &G1);   /* corrupt proof k */

                ADV_CHECK("batch: corrupted proof fails per-proof verify at k",
                          !groth16_verify(&vk, &bad[k],
                                          (const uint64_t (*)[4])&inputs[k], 1));
                ADV_CHECK("batch: groth16_batch_verify REJECTS a set with one bad proof",
                          !groth16_batch_verify(&vk, bad,
                                                (const uint64_t (*)[4])inputs,
                                                1, NB));
                /* Fallback sweep attributes the failure to exactly index k. */
                int first_bad = -1;
                for (int j = 0; j < NB; j++)
                    if (!groth16_verify(&vk, &bad[j],
                                        (const uint64_t (*)[4])&inputs[j], 1)) {
                        first_bad = j; break;
                    }
                ADV_CHECK("batch: per-proof fallback attributes failure to k",
                          first_bad == k);
            }

            /* (d) Tamper a PUBLIC INPUT (not the proof) -> reject + fallback. */
            {
                uint64_t bad_in[NB][4];
                memcpy(bad_in, inputs, sizeof(bad_in));
                bad_in[2][0] ^= 0x1;   /* changes vk_x_2, breaks C_2 = -vk_x_2 */
                ADV_CHECK("batch: tampered public input -> per-proof reject",
                          !groth16_verify(&vk, &proofs[2],
                                          (const uint64_t (*)[4])&bad_in[2], 1));
                ADV_CHECK("batch: tampered public input -> batch REJECTS",
                          !groth16_batch_verify(&vk, proofs,
                                                (const uint64_t (*)[4])bad_in,
                                                1, NB));
            }

            /* (e) SOUNDNESS: two proofs that are each INVALID but whose GT
             *     errors are exact negatives — a naive equal-weight (r=1) batch
             *     would false-ACCEPT (errors cancel). With per-batch random
             *     scalars r_0 != r_1 the combined error e((r0-r1)*D, -G2) != 1,
             *     so groth16_batch_verify MUST REJECT. This is the property a
             *     fixed constant scalar would violate. */
            {
                struct g1_point D;
                uint64_t two[4] = {2, 0, 0, 0};
                g1_scalar_mul(&D, &G1, two);   /* D = [2]G1, nonzero */

                struct groth16_proof cx[2];
                uint64_t cin[2][4];
                for (int j = 0; j < 2; j++) {
                    uint64_t t[4] = { (uint64_t)(j + 3), 0, 0, 0 };
                    struct g1_point vk_x_j, negvkx;
                    g1_scalar_mul(&vk_x_j, &G1, t);
                    g1_neg(&negvkx, &vk_x_j);
                    cx[j].a = G1;
                    cx[j].b = G2;
                    cin[j][0] = t[0]; cin[j][1] = 0; cin[j][2] = 0; cin[j][3] = 0;
                    if (j == 0)                 /* C_0 = -vk_x_0 + D  (err +D) */
                        g1_add(&cx[j].c, &negvkx, &D);
                    else {                      /* C_1 = -vk_x_1 - D  (err -D) */
                        struct g1_point negD;
                        g1_neg(&negD, &D);
                        g1_add(&cx[j].c, &negvkx, &negD);
                    }
                }
                /* Each is individually invalid. */
                ADV_CHECK("batch soundness: crafted proof 0 is individually INVALID",
                          !groth16_verify(&vk, &cx[0],
                                          (const uint64_t (*)[4])&cin[0], 1));
                ADV_CHECK("batch soundness: crafted proof 1 is individually INVALID",
                          !groth16_verify(&vk, &cx[1],
                                          (const uint64_t (*)[4])&cin[1], 1));
                /* Equal-weight cancellation would accept; RLC must reject. */
                ADV_CHECK("batch soundness: RLC scalars defeat naive cancellation (REJECT)",
                          !groth16_batch_verify(&vk, cx,
                                                (const uint64_t (*)[4])cin,
                                                1, 2));
            }

            /* (f) Throughput: N single verifies vs one batch (informational). */
            {
                clock_t t0 = clock();
                for (int j = 0; j < NB; j++)
                    (void)groth16_verify(&vk, &proofs[j],
                                         (const uint64_t (*)[4])&inputs[j], 1);
                clock_t t1 = clock();
                (void)groth16_batch_verify(&vk, proofs,
                                           (const uint64_t (*)[4])inputs, 1, NB);
                clock_t t2 = clock();
                double single_ms = 1000.0 * (double)(t1 - t0) / CLOCKS_PER_SEC;
                double batch_ms  = 1000.0 * (double)(t2 - t1) / CLOCKS_PER_SEC;
                printf("  [throughput] %d proofs: per-proof=%.1f ms  batch=%.1f ms"
                       "  speedup=%.2fx\n", NB, single_ms, batch_ms,
                       batch_ms > 0.0 ? single_ms / batch_ms : 0.0);
            }

            free(vk.ic);
        }
    }

    printf("BLS12-381 adversarial + KAT: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
