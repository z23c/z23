/* Frozen reference for test_bn254_engine_parity: the pre-engine bn254.h API under legacy_ names.
 * Generated from origin/main 1047fb4c8b; see bn254_legacy_reference.c. */

/* Copyright (c) 2014-2017 The Zcash developers
 * Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * BN-254 (alt_bn128) pairing — pure C23 implementation.
 * Used for PHGR13 zk-SNARK verification (Sprout pre-Sapling).
 *
 * Curve: y^2 = x^3 + 3 over Fq
 * q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */

#ifndef ZCL_TEST_BN254_LEGACY_REFERENCE_H
#define ZCL_TEST_BN254_LEGACY_REFERENCE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Fq: 254-bit prime field, 4 x 64-bit limbs, Montgomery form. */
struct legacy_bn_fq {
    uint64_t d[4];
};

void legacy_bn_fq_zero(struct legacy_bn_fq *r);
void legacy_bn_fq_one(struct legacy_bn_fq *r);
bool legacy_bn_fq_is_zero(const struct legacy_bn_fq *a);
bool legacy_bn_fq_eq(const struct legacy_bn_fq *a, const struct legacy_bn_fq *b);

void legacy_bn_fq_add(struct legacy_bn_fq *r, const struct legacy_bn_fq *a, const struct legacy_bn_fq *b);
void legacy_bn_fq_sub(struct legacy_bn_fq *r, const struct legacy_bn_fq *a, const struct legacy_bn_fq *b);
void legacy_bn_fq_neg(struct legacy_bn_fq *r, const struct legacy_bn_fq *a);
void legacy_bn_fq_mul(struct legacy_bn_fq *r, const struct legacy_bn_fq *a, const struct legacy_bn_fq *b);
void legacy_bn_fq_sq(struct legacy_bn_fq *r, const struct legacy_bn_fq *a);
void legacy_bn_fq_inv(struct legacy_bn_fq *r, const struct legacy_bn_fq *a);
bool legacy_bn_fq_sqrt(struct legacy_bn_fq *r, const struct legacy_bn_fq *a);
bool legacy_bn_fq_from_bytes_be(struct legacy_bn_fq *r, const uint8_t s[32]);
void legacy_bn_fq_to_bytes_be(uint8_t s[32], const struct legacy_bn_fq *a);
void legacy_bn_fq_from_u64(struct legacy_bn_fq *r, uint64_t v);

/* Fq2 = Fq[u] / (u^2 + 1) */
struct legacy_bn_fq2 {
    struct legacy_bn_fq c0, c1; /* c0 + c1 * u */
};

void legacy_bn_fq2_zero(struct legacy_bn_fq2 *r);
void legacy_bn_fq2_one(struct legacy_bn_fq2 *r);
bool legacy_bn_fq2_is_zero(const struct legacy_bn_fq2 *a);
bool legacy_bn_fq2_eq(const struct legacy_bn_fq2 *a, const struct legacy_bn_fq2 *b);

void legacy_bn_fq2_add(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a, const struct legacy_bn_fq2 *b);
void legacy_bn_fq2_sub(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a, const struct legacy_bn_fq2 *b);
void legacy_bn_fq2_neg(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a);
void legacy_bn_fq2_mul(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a, const struct legacy_bn_fq2 *b);
void legacy_bn_fq2_sq(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a);
void legacy_bn_fq2_inv(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a);
void legacy_bn_fq2_mul_by_nonresidue(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a);
/* Square root in Fq2. False iff a is not a square (the accept set of libsnark's
 * Fp2_model::sqrt). Which root is returned is unspecified. r may alias a. */
bool legacy_bn_fq2_sqrt(struct legacy_bn_fq2 *r, const struct legacy_bn_fq2 *a);

/* Fq6 = Fq2[v] / (v^3 - xi)  where xi = 9+u */
struct legacy_bn_fq6 {
    struct legacy_bn_fq2 c0, c1, c2;
};

void legacy_bn_fq6_zero(struct legacy_bn_fq6 *r);
void legacy_bn_fq6_one(struct legacy_bn_fq6 *r);
void legacy_bn_fq6_add(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a, const struct legacy_bn_fq6 *b);
void legacy_bn_fq6_sub(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a, const struct legacy_bn_fq6 *b);
void legacy_bn_fq6_neg(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a);
void legacy_bn_fq6_mul(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a, const struct legacy_bn_fq6 *b);
void legacy_bn_fq6_sq(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a);
void legacy_bn_fq6_inv(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a);
void legacy_bn_fq6_mul_by_nonresidue(struct legacy_bn_fq6 *r, const struct legacy_bn_fq6 *a);

/* Fq12 = Fq6[w] / (w^2 - v) */
struct legacy_bn_fq12 {
    struct legacy_bn_fq6 c0, c1;
};

void legacy_bn_fq12_zero(struct legacy_bn_fq12 *r);
void legacy_bn_fq12_one(struct legacy_bn_fq12 *r);
bool legacy_bn_fq12_eq(const struct legacy_bn_fq12 *a, const struct legacy_bn_fq12 *b);
void legacy_bn_fq12_mul(struct legacy_bn_fq12 *r, const struct legacy_bn_fq12 *a, const struct legacy_bn_fq12 *b);
void legacy_bn_fq12_sq(struct legacy_bn_fq12 *r, const struct legacy_bn_fq12 *a);
void legacy_bn_fq12_inv(struct legacy_bn_fq12 *r, const struct legacy_bn_fq12 *a);
void legacy_bn_fq12_conjugate(struct legacy_bn_fq12 *a);
void legacy_bn_fq12_frobenius_map(struct legacy_bn_fq12 *r, const struct legacy_bn_fq12 *a, int power);

/* G1: y^2 = x^3 + 3 over Fq (Jacobian coordinates) */
struct legacy_bn_g1 {
    struct legacy_bn_fq x, y, z;
};

void legacy_bn_g1_identity(struct legacy_bn_g1 *p);
bool legacy_bn_g1_is_identity(const struct legacy_bn_g1 *p);
void legacy_bn_g1_neg(struct legacy_bn_g1 *r, const struct legacy_bn_g1 *p);
void legacy_bn_g1_add(struct legacy_bn_g1 *r, const struct legacy_bn_g1 *a, const struct legacy_bn_g1 *b);
void legacy_bn_g1_double(struct legacy_bn_g1 *r, const struct legacy_bn_g1 *a);
void legacy_bn_g1_to_affine(struct legacy_bn_fq *ax, struct legacy_bn_fq *ay, const struct legacy_bn_g1 *p);
void legacy_bn_g1_scalar_mul(struct legacy_bn_g1 *r, const struct legacy_bn_g1 *p, const uint64_t scalar[4]);

/* Decode a zclassicd CompressedG1 (33 bytes: lead byte 0x02|y_lsb, then x as
 * 32 big-endian bytes, x < q). Any other lead byte is refused; there is no
 * encoding of the point at infinity (zclassicd Proof.hpp:97-111). */
bool legacy_bn_g1_decompress(struct legacy_bn_g1 *p, const uint8_t data[33]);

/* G2: y^2 = x^3 + b' over Fq2 (Jacobian coordinates) */
struct legacy_bn_g2 {
    struct legacy_bn_fq2 x, y, z;
};

void legacy_bn_g2_identity(struct legacy_bn_g2 *p);
bool legacy_bn_g2_is_identity(const struct legacy_bn_g2 *p);
void legacy_bn_g2_neg(struct legacy_bn_g2 *r, const struct legacy_bn_g2 *p);
void legacy_bn_g2_add(struct legacy_bn_g2 *r, const struct legacy_bn_g2 *a, const struct legacy_bn_g2 *b);
void legacy_bn_g2_double(struct legacy_bn_g2 *r, const struct legacy_bn_g2 *a);
void legacy_bn_g2_to_affine(struct legacy_bn_fq2 *ax, struct legacy_bn_fq2 *ay, const struct legacy_bn_g2 *p);
/* Canonical alt_bn128 G2 generator (libsnark G2::one) — single source of
 * truth shared by the PHGR13 verifier and its tests. */
void legacy_bn254_g2_one(struct legacy_bn_g2 *out);
/* True iff the affine G2 point (z assumed 1) is on the BN254 twist curve. */
bool legacy_bn_g2_is_on_curve(const struct legacy_bn_g2 *p);

/* Decode a zclassicd CompressedG2 (65 bytes: lead byte 0x0a|y_gt, then x as a
 * 64-byte big-endian FE2IP integer c1*q + c0 < q^2). Refuses any other lead
 * byte, a non-square x^3 + b', and a point outside the order-r subgroup
 * (zclassicd Proof.hpp:147-161, Proof.cpp:147-171). */
bool legacy_bn_g2_decompress(struct legacy_bn_g2 *p, const uint8_t data[65]);

/* Optimal Ate pairing on BN-254 */
void legacy_bn254_pairing(struct legacy_bn_fq12 *result,
                   const struct legacy_bn_g1 *p,
                   const struct legacy_bn_g2 *q);

/* Multi-pairing: computes product of pairings and checks == 1 */
bool legacy_bn254_multi_pairing_check(
    const struct legacy_bn_g1 *a_pts, const struct legacy_bn_g2 *b_pts,
    size_t n_pairs);

/* ── PPZKSNARK (PHGR13) verification ────────────────────────── */

struct legacy_ppzksnark_vk {
    struct legacy_bn_g2 alpha_a_g2;
    struct legacy_bn_g1 alpha_b_g1;
    struct legacy_bn_g2 alpha_c_g2;
    struct legacy_bn_g2 gamma_g2;
    struct legacy_bn_g1 gamma_beta_g1;
    struct legacy_bn_g2 gamma_beta_g2;
    struct legacy_bn_g2 rc_z_g2;
    struct legacy_bn_g1 *ic;        /* IC query (g1 points) */
    size_t ic_len;           /* Number of IC elements */
};

struct legacy_ppzksnark_proof {
    struct legacy_bn_g1 a;          /* g_A */
    struct legacy_bn_g1 a_prime;    /* g_A' */
    struct legacy_bn_g2 b;          /* g_B */
    struct legacy_bn_g1 b_prime;    /* g_B' */
    struct legacy_bn_g1 c;          /* g_C */
    struct legacy_bn_g1 c_prime;    /* g_C' */
    struct legacy_bn_g1 k;          /* g_K */
    struct legacy_bn_g1 h;          /* g_H */
};

/* Read PPZKSNARK proof from 296-byte serialized form */
bool legacy_ppzksnark_proof_read(struct legacy_ppzksnark_proof *proof, const uint8_t data[296]);

/* Read PPZKSNARK verification key from sprout-verifying.key file */
bool legacy_ppzksnark_vk_read(struct legacy_ppzksnark_vk *vk, const uint8_t *data, size_t len);

/* Free VK's IC array */
void legacy_ppzksnark_vk_free(struct legacy_ppzksnark_vk *vk);

/* Verify PPZKSNARK proof (5 pairing checks).
 * public_inputs: Fr scalars (BN-254 scalar field), 4 x uint64_t each.
 * n_inputs must equal vk->ic_len - 1. */
bool legacy_ppzksnark_verify(const struct legacy_ppzksnark_vk *vk,
                      const struct legacy_ppzksnark_proof *proof,
                      const uint64_t (*public_inputs)[4],
                      size_t n_inputs);

/* ── Sprout PHGR13 high-level API ───────────────────────────── */

/* Set the PHGR13 verification key (loaded at boot) */
void legacy_sprout_phgr_set_vk(struct legacy_ppzksnark_vk *vk);

#ifdef ZCL_TESTING
/* See sapling_test_published_spend_vk in sapling.h. */
const struct legacy_ppzksnark_vk *legacy_sprout_test_published_phgr_vk(void);
#endif
/* True iff a PHGR13 verification key is installed, i.e. iff a PHGR13
 * JoinSplit proof can actually be CHECKED right now.
 *
 * This is deliberately separate from sapling_params_loaded(): the PHGR13
 * key lives in its own file (sprout-verifying.key) and, off mainnet, a
 * failure to load it is non-fatal — params_init.c still publishes
 * sapling_params_loaded()==true with this key absent. Without this
 * predicate a caller cannot distinguish "this PHGR13 proof is forged"
 * from "we hold no key to judge it with", because legacy_sprout_verify_phgr13()
 * fail-closes to the same `false` in both cases. */
bool legacy_sprout_phgr_vk_loaded(void);

/* Verify a Sprout PHGR13 JoinSplit proof.
 * proof: 296-byte serialized PHGR13 proof
 * Public inputs: rt, h_sig, {nf,mac}x2, {cm}x2, vpub_old, vpub_new */
bool legacy_sprout_verify_phgr13(const uint8_t proof[296],
                          const uint8_t rt[32],
                          const uint8_t h_sig[32],
                          const uint8_t mac1[32],
                          const uint8_t mac2[32],
                          const uint8_t nf1[32],
                          const uint8_t nf2[32],
                          const uint8_t cm1[32],
                          const uint8_t cm2[32],
                          uint64_t vpub_old,
                          uint64_t vpub_new);


/* Test-only exports of the reference's static internals (see the .c file). */
void legacy_bn254_x_init(void);
void legacy_bn254_x_miller(struct legacy_bn_fq12 *r, const struct legacy_bn_g1 *p,
                           const struct legacy_bn_g2 *q);
void legacy_bn254_x_final_exp(struct legacy_bn_fq12 *f);
bool legacy_bn254_x_g2_in_subgroup(const struct legacy_bn_g2 *p);

#endif
