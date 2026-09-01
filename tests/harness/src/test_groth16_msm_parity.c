/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Differential parity gate for the fixed-base windowed MSM over the constant
 * Groth16 VK IC[] points (core/modules/sapling/src/bls12_381.c: g1_comb_* +
 * groth16_vk_build_combs). The optimization replaces the per-verify 256-bit
 * double-and-add on the FIXED VK IC base points with precomputed table lookups.
 *
 * INVARIANT UNDER TEST: the comb path is VALUE-identical to the naive
 * double-and-add for every scalar, so groth16_verify / groth16_batch_verify must
 * return the SAME accept/reject verdict whether or not the VK carries comb
 * tables. This is a consensus invariant — the optimization changes HOW FAST the
 * same checks run, never WHICH proofs are accepted.
 *
 * Method (params-free, deterministic, host-invariant): build two copies of a
 * synthetic VK — one with comb tables (groth16_vk_build_combs), one without
 * (naive fallback) — and assert their verdicts are byte-for-byte equal across a
 * battery of public-input vectors (zeros, ones, small, full-256-bit, r-1, mixed)
 * and both accept AND reject controls. A single divergence in the comb-computed
 * vk_x flips a crafted-accept case to reject and fails the test.
 */

#include "sapling/bls12_381.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Canonical BLS12-381 compressed generators (big-endian, with flag bits). */
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

/* r - 1, the largest valid Fr scalar (little-endian limbs). r itself is
 * 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001. */
static const uint64_t FR_MINUS_1[4] = {
    0xffffffff00000000ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};

#define K_INPUTS 4   /* number of public inputs / scalar-mul'd IC points */

/* splitmix64: deterministic, host-invariant pseudo-random 64-bit stream. */
static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Reference vk_x = IC[0] + sum(input[i] * IC[i+1]) via the naive public API. */
static void ref_vk_x(struct g1_point *vk_x, const struct groth16_vk *vk,
                     const uint64_t (*inputs)[4], size_t n)
{
    *vk_x = vk->ic[0];
    for (size_t i = 0; i < n; i++) {
        if (inputs[i][0] == 0 && inputs[i][1] == 0 &&
            inputs[i][2] == 0 && inputs[i][3] == 0)
            continue;
        struct g1_point term;
        g1_scalar_mul(&term, &vk->ic[i + 1], inputs[i]);
        g1_add(vk_x, vk_x, &term);
    }
}

/* Verdict must be identical whether the VK carries comb tables or not. Returns
 * the (shared) verdict, or -1 if the naive and comb verdicts DIVERGE. */
static int verdict_parity(const struct groth16_vk *vk_naive,
                          const struct groth16_vk *vk_comb,
                          const struct groth16_proof *proof,
                          const uint64_t (*inputs)[4], size_t n)
{
    bool a = groth16_verify(vk_naive, proof, inputs, n);
    bool b = groth16_verify(vk_comb,  proof, inputs, n);
    if (a != b) return -1;
    return a ? 1 : 0;
}

int test_groth16_msm_parity(void)
{
    int failures = 0;

    struct g1_point G1, O1;
    struct g2_point G2;
    if (!g1_from_compressed(&G1, G1_GEN_COMPRESSED) ||
        !g2_from_compressed(&G2, G2_GEN_COMPRESSED)) {
        printf("groth16_msm_parity: generator decode... FAIL\n");
        return 1;
    }
    g1_identity(&O1);

    /* Synthetic VK: alpha=G1, beta=gamma=delta=G2; IC[0]=O, IC[i]=i*G1 (distinct
     * fixed bases so ic_combs[0..K-1] each get exercised). */
    struct g1_point ic[K_INPUTS + 1];
    ic[0] = O1;
    for (int i = 1; i <= K_INPUTS; i++) {
        uint64_t m[4] = { (uint64_t)(i * 7 + 1), 0, 0, 0 };
        g1_scalar_mul(&ic[i], &G1, m);
    }

    struct groth16_vk vk_naive = {0};
    vk_naive.alpha_g1 = G1;
    vk_naive.beta_g2  = G2;
    vk_naive.gamma_g2 = G2;
    vk_naive.delta_g2 = G2;
    vk_naive.ic       = ic;
    vk_naive.ic_len   = K_INPUTS + 1;
    vk_naive.ic_combs = NULL;                /* forced naive path */

    struct groth16_vk vk_comb = vk_naive;    /* same bases */
    vk_comb.ic_combs = NULL;
    if (!groth16_vk_build_combs(&vk_comb)) {
        printf("groth16_msm_parity: build_combs... FAIL\n");
        return 1;
    }

    /* ---- Battery of public-input vectors ---- */
    printf("groth16_msm_parity: comb==naive verdict over input battery... ");
    {
        /* Deterministic edge + pseudo-random K-tuples. */
        uint64_t battery[][K_INPUTS][4] = {
            {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}},               /* all-zero */
            {{1,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}},               /* single 1 */
            {{1,0,0,0},{2,0,0,0},{3,0,0,0},{4,0,0,0}},               /* small mix */
            {{0xFFFFFFFFFFFFFFFFULL,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}},
            {{0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
              0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL},           /* all 256 bits */
             {0,0,0,0},{0,0,0,0},{0,0,0,0}},
            {{FR_MINUS_1[0],FR_MINUS_1[1],FR_MINUS_1[2],FR_MINUS_1[3]},
             {FR_MINUS_1[0],FR_MINUS_1[1],FR_MINUS_1[2],FR_MINUS_1[3]},
             {1,0,0,0},{2,0,0,0}},                                   /* r-1 heavy */
        };
        size_t n_edge = sizeof(battery) / sizeof(battery[0]);

        /* Add pseudo-random tuples via a deterministic splitmix64 stream. */
        uint64_t s = 0x123456789ABCDEF0ULL;

        bool ok = true;
        /* edge vectors */
        for (size_t e = 0; e < n_edge && ok; e++) {
            struct g1_point vk_x;
            ref_vk_x(&vk_x, &vk_naive, battery[e], K_INPUTS);
            struct groth16_proof pr;
            pr.a = G1; pr.b = G2;
            g1_neg(&pr.c, &vk_x);            /* valid: e(vk_x+C,-G2)=1 */
            int v = verdict_parity(&vk_naive, &vk_comb, &pr, battery[e], K_INPUTS);
            if (v != 1) ok = false;          /* must agree AND accept */

            /* reject control: flip one input bit -> both must reject */
            uint64_t bad[K_INPUTS][4];
            memcpy(bad, battery[e], sizeof(bad));
            bad[0][0] ^= 0x1;
            int vr = verdict_parity(&vk_naive, &vk_comb, &pr, bad, K_INPUTS);
            if (vr != 0) ok = false;         /* must agree AND reject */
        }
        /* random vectors */
        for (int r = 0; r < 128 && ok; r++) {
            uint64_t inp[K_INPUTS][4];
            for (int i = 0; i < K_INPUTS; i++)
                for (int limb = 0; limb < 4; limb++)
                    inp[i][limb] = splitmix64(&s);
            struct g1_point vk_x;
            ref_vk_x(&vk_x, &vk_naive, inp, K_INPUTS);
            struct groth16_proof pr;
            pr.a = G1; pr.b = G2;
            g1_neg(&pr.c, &vk_x);
            if (verdict_parity(&vk_naive, &vk_comb, &pr, inp, K_INPUTS) != 1)
                ok = false;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ---- Batch verify parity ---- */
    printf("groth16_msm_parity: batch comb==naive verdict... ");
    {
        struct groth16_proof proofs[4];
        uint64_t flat[4 * K_INPUTS][4];
        bool ok = true;
        for (int j = 0; j < 4; j++) {
            uint64_t inp[K_INPUTS][4];
            for (int i = 0; i < K_INPUTS; i++) {
                inp[i][0] = (uint64_t)(j * 11 + i + 1);
                inp[i][1] = inp[i][2] = inp[i][3] = 0;
                memcpy(flat[j * K_INPUTS + i], inp[i], sizeof(inp[i]));
            }
            struct g1_point vk_x;
            ref_vk_x(&vk_x, &vk_naive, inp, K_INPUTS);
            proofs[j].a = G1; proofs[j].b = G2;
            g1_neg(&proofs[j].c, &vk_x);
        }
        bool bn = groth16_batch_verify(&vk_naive, proofs, flat, K_INPUTS, 4);
        bool bc = groth16_batch_verify(&vk_comb,  proofs, flat, K_INPUTS, 4);
        if (bn != bc || !bn) ok = false;     /* must agree AND accept */

        /* corrupt one -> both must reject, still agreeing */
        g1_add(&proofs[2].c, &proofs[2].c, &G1);
        bool bn2 = groth16_batch_verify(&vk_naive, proofs, flat, K_INPUTS, 4);
        bool bc2 = groth16_batch_verify(&vk_comb,  proofs, flat, K_INPUTS, 4);
        if (bn2 != bc2 || bn2) ok = false;   /* must agree AND reject */

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ---- Rebuild idempotency + free ---- */
    printf("groth16_msm_parity: build_combs rebuild + free... ");
    {
        bool ok = groth16_vk_build_combs(&vk_comb);  /* second call: frees + rebuilds */
        groth16_vk_free_combs(&vk_comb);
        groth16_vk_free_combs(&vk_comb);             /* double-free must be safe */
        if (ok && vk_comb.ic_combs == NULL) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    if (failures == 0)
        printf("groth16_msm_parity: ALL PASS\n");
    return failures;
}
