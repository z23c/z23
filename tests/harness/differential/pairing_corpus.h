/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared, deterministic BLS12-381 pairing corpus + canonical Fp12
 * serialization, used by BOTH differential harnesses:
 *
 *   groth16_comb_bench.c    `pairing` mode — in-process baseline-vs-candidate
 *                           Fp12 BIT equality (+ timing of both).
 *   groth16_parity_oracle.c `check`/`record` — pins the same Fp12 values to
 *                           groth16_pairing_values.bin, so a change that moves
 *                           BOTH in-process paths together is still caught.
 *
 * The corpus lives in one header on purpose: two harnesses that each grew
 * their own vector list would silently drift, and "the gate passed" would stop
 * meaning "the thing the bench measured is the thing the gate froze".
 *
 * No RNG anywhere — every point is a fixed integer multiple of a canonical
 * generator, so the corpus is byte-identical on every host and every run.
 */

#ifndef ZCL_TEST_PAIRING_CORPUS_H
#define ZCL_TEST_PAIRING_CORPUS_H

#include "sapling/bls12_381.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ── the candidate hook ──────────────────────────────────────────────
 *
 * Job 2.2 (the pairing restructure) plugs its new implementation in by
 * defining a NON-static
 *
 *     void bls12_381_pairing_candidate(struct fp12 *out,
 *                                      const struct g1_point *p,
 *                                      const struct g2_point *q);
 *
 * in core/modules/sapling/src/bls12_381.c. Nothing else needs to change: both harnesses
 * pick it up through this weak declaration.
 *
 * While the symbol does not exist the weak reference resolves to NULL and the
 * harnesses SAY SO, loudly, instead of printing a green tautology. A harness
 * that quietly compares an implementation to itself is worse than no harness:
 * it manufactures confidence for a change nobody checked.
 */
__attribute__((weak)) void bls12_381_pairing_candidate(
    struct fp12 *out, const struct g1_point *p, const struct g2_point *q);

static inline bool pc_have_candidate(void)
{
    return bls12_381_pairing_candidate != NULL;
}

/* ── canonical Fp12 serialization ────────────────────────────────────
 *
 * 12 x fp_to_bytes = 12 x 48 = 576 bytes. fp_to_bytes leaves Montgomery form
 * and emits the fully-reduced big-endian integer, so this encoding is
 * independent of the internal representation: a future change to Montgomery
 * radix, limb count, or endianness cannot make a DIFFERENT field element
 * compare equal, and cannot make the SAME field element compare unequal.
 * memcmp on the raw struct would fail both of those properties.
 */
#define PC_FP12_BYTES 576

static inline void pc_fp12_to_bytes(uint8_t out[PC_FP12_BYTES],
                                    const struct fp12 *f)
{
    const struct fp *c[12] = {
        &f->c0.c0.c0, &f->c0.c0.c1, &f->c0.c1.c0, &f->c0.c1.c1,
        &f->c0.c2.c0, &f->c0.c2.c1, &f->c1.c0.c0, &f->c1.c0.c1,
        &f->c1.c1.c0, &f->c1.c1.c1, &f->c1.c2.c0, &f->c1.c2.c1,
    };
    for (int i = 0; i < 12; i++)
        fp_to_bytes(out + (size_t)i * 48, c[i]);
}

/* Index of the first differing byte, or -1 when the two elements are equal.
 * Reported so a divergence names the Fp12 coefficient, not just "differs". */
static inline int pc_fp12_first_diff(const struct fp12 *a, const struct fp12 *b)
{
    uint8_t ba[PC_FP12_BYTES], bb[PC_FP12_BYTES];
    pc_fp12_to_bytes(ba, a);
    pc_fp12_to_bytes(bb, b);
    for (int i = 0; i < PC_FP12_BYTES; i++)
        if (ba[i] != bb[i]) return i;
    return -1;
}

static inline const char *pc_fp12_coeff_name(int byte_index)
{
    static const char *n[12] = {
        "c0.c0.c0", "c0.c0.c1", "c0.c1.c0", "c0.c1.c1",
        "c0.c2.c0", "c0.c2.c1", "c1.c0.c0", "c1.c0.c1",
        "c1.c1.c0", "c1.c1.c1", "c1.c2.c0", "c1.c2.c1",
    };
    if (byte_index < 0 || byte_index >= PC_FP12_BYTES) return "(none)";
    return n[byte_index / 48];
}

/* ── canonical generators (RFC 9380 / zcash BLS12-381 test vectors) ── */
static const uint8_t PC_G1_GEN[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,
    0x4f,0xa9,0xac,0x0f,0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,0x6c,0x55,0xe8,0x3f,
    0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};
static const uint8_t PC_G2_GEN[96] = {
    0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,0x7d,0xac,0xd3,0xa0,
    0x88,0x27,0x4f,0x65,0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,0x33,0x4c,0xf1,0x12,
    0x13,0x94,0x5d,0x57,0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,0x26,0x08,0x05,0x27,
    0x2d,0xc5,0x10,0x51,0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,0x0b,0xac,0x03,0x26,
    0xa8,0x05,0xbb,0xef,0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};

/* G2 scalar multiply. bls12_381.c keeps its own g2_scalar_mul static, so the
 * harness carries a plain double-and-add over the exposed g2_add/g2_double.
 * Not constant-time — it multiplies PUBLIC test constants, never a secret. */
static inline void pc_g2_mul(struct g2_point *r, const struct g2_point *p,
                             const uint64_t k[4])
{
    struct g2_point acc;
    g2_identity(&acc);
    bool started = false;
    for (int limb = 3; limb >= 0; limb--) {
        for (int bit = 63; bit >= 0; bit--) {
            if (started) g2_double(&acc, &acc);
            if ((k[limb] >> bit) & 1u) {
                if (started) g2_add(&acc, &acc, p);
                else { acc = *p; started = true; }
            }
        }
    }
    *r = acc;
}

/* ── the corpus ──────────────────────────────────────────────────────
 *
 * Chosen to move every branch the pairing has: the identity short-circuits in
 * both arguments, negated points (conjugate GT elements), small multiples,
 * and full-width 256-bit multipliers so no vector lets a lazy implementation
 * pass by only handling short scalars. The last two are the shapes a Groth16
 * verify actually feeds the pairing.
 */
struct pc_vec {
    const char *label;
    struct g1_point p;
    struct g2_point q;
};

#define PC_MAX_VECS 16

static inline size_t pc_build(struct pc_vec *v)
{
    struct g1_point g1, o1;
    struct g2_point g2, o2;
    if (!g1_from_compressed(&g1, PC_G1_GEN) ||
        !g2_from_compressed(&g2, PC_G2_GEN))
        return 0;
    g1_identity(&o1);
    g2_identity(&o2);

    /* Full-width multipliers below r = 0x73eda753...00000001. Both stay under
     * the group order, so every product is a genuine prime-order-subgroup
     * element and the pairing is the real one, not a torsion artefact. */
    static const uint64_t S_WIDE_A[4] = {
        0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL,
        0x94D049BB133111EBULL, 0x0339d80809a1d805ULL };
    static const uint64_t S_WIDE_B[4] = {
        0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
        0x0F1E2D3C4B5A6978ULL, 0x0112233445566778ULL };
    static const uint64_t S_TWO[4]   = { 2, 0, 0, 0 };
    static const uint64_t S_THREE[4] = { 3, 0, 0, 0 };
    static const uint64_t S_FIVE[4]  = { 5, 0, 0, 0 };
    static const uint64_t S_SEVEN[4] = { 7, 0, 0, 0 };
    static const uint64_t S_ELEVEN[4]= { 11, 0, 0, 0 };
    static const uint64_t S_P32[4]   = { 0x0000000100000001ULL, 0, 0, 0 };
    static const uint64_t S_P40[4]   = { 0x0000010000000007ULL, 0, 0, 0 };

    size_t n = 0;
    struct g1_point a2, a3, a7, a32, awide, aneg;
    struct g2_point b2, b5, b11, b40, bwide, bneg;
    g1_scalar_mul(&a2, &g1, S_TWO);
    g1_scalar_mul(&a3, &g1, S_THREE);
    g1_scalar_mul(&a7, &g1, S_SEVEN);
    g1_scalar_mul(&a32, &g1, S_P32);
    g1_scalar_mul(&awide, &g1, S_WIDE_A);
    g1_neg(&aneg, &g1);
    pc_g2_mul(&b2, &g2, S_TWO);
    pc_g2_mul(&b5, &g2, S_FIVE);
    pc_g2_mul(&b11, &g2, S_ELEVEN);
    pc_g2_mul(&b40, &g2, S_P40);
    pc_g2_mul(&bwide, &g2, S_WIDE_B);
    g2_neg(&bneg, &g2);

#define PC_PUSH(lbl, P, Q) do {                     \
        if (n < PC_MAX_VECS) {                      \
            v[n].label = (lbl);                     \
            v[n].p = (P);                           \
            v[n].q = (Q);                           \
            n++;                                    \
        }                                           \
    } while (0)

    PC_PUSH("e(G1, G2)",                    g1,    g2);
    PC_PUSH("e([2]G1, G2)",                 a2,    g2);
    PC_PUSH("e(G1, [2]G2)",                 g1,    b2);
    PC_PUSH("e([3]G1, [5]G2)",              a3,    b5);
    PC_PUSH("e([7]G1, [11]G2)",             a7,    b11);
    PC_PUSH("e([2^32+1]G1, [2^40+7]G2)",    a32,   b40);
    PC_PUSH("e(-G1, G2)  [GT conjugate]",   aneg,  g2);
    PC_PUSH("e(G1, -G2)  [GT conjugate]",   g1,    bneg);
    PC_PUSH("e(O1, G2)   [identity short-circuit]", o1, g2);
    PC_PUSH("e(G1, O2)   [identity short-circuit]", g1, o2);
    PC_PUSH("e(O1, O2)   [both identity]",  o1,    o2);
    PC_PUSH("e([wide]G1, G2)   [256-bit multiplier]",   awide, g2);
    PC_PUSH("e(G1, [wide]G2)   [256-bit multiplier]",   g1,    bwide);
    PC_PUSH("e([wide]G1, [wide]G2) [both 256-bit]",     awide, bwide);
#undef PC_PUSH
    return n;
}

#endif /* ZCL_TEST_PAIRING_CORPUS_H */
