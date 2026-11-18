/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/sapling/src/bn254.c
 *
 * BN254 pairing engine parity: the optimised pairing, decoders and PHGR13
 * verifier (core/modules/sapling/src/bn254.c + bn254_engine.inc) against the
 * frozen pre-engine implementation (tests/harness/src/bn254_legacy_reference.c)
 * on identical inputs.
 *
 * The engine only changes HOW the same functions are computed, so the bar is
 * equality of results, not agreement of verdicts:
 *   E1  Fq12 / Fq6 / Fq tower operations, sparse line multiply, cyclotomic
 *       squaring and Frobenius maps return the same field elements;
 *   E2  the Miller loop (before the final exponentiation), the final
 *       exponentiation and the full pairing return the same Fq12 element, for
 *       Jacobian and affine inputs and with identity operands;
 *   E3  G1/G2 decompression and the Fq2 square root accept the same encodings
 *       and return the same points, on valid, corrupted and off-subgroup input;
 *   E4  the G2 subgroup test psi(P) == [6u^2]P accepts exactly the points the
 *       original r*P == O accepts (random G2 points, random twist points,
 *       cofactor-torsion points and mixtures), with the numeric identities its
 *       proof relies on checked here;
 *   E5  the IC multi-scalar multiplication returns the same point, with edge
 *       scalars, identity / repeated / negated bases, and more inputs than the
 *       prepared tables hold;
 *   E6  ppzksnark_verify returns the same verdict as the legacy verifier for
 *       the real height-241 proof, 1200 single-bit corruptions of it and of its
 *       public inputs, an edited verifying key (in place, so a cached key is
 *       stale) and the key restored;
 *   E7  concurrent verification, one thread per core, valid and invalid
 *       proofs, through the shared key tables;
 *   E8  E1/E2 again on edge-valued Fq12 inputs (0, 1, -1, q-1, sparse), which
 *       reach fq_neg(0) and the other zero-coefficient paths;
 *   E9  ACCEPTING proofs whose pairing products contain identity operands
 *       (A+acc = O, A+acc+C = O, C = O, A = O, B = O, identity key elements),
 *       built on keys with known discrete logs, plus one-point tweaks of each:
 *       the same verdict as the original, and every valid one accepted.
 * E1-E6, E8 and E9 run once per engine instance: the portable multiply and, when the CPU
 * has BMI2+ADX, the MULX one. */

#include "test/test_core.h"
#include "base/log_level.h"
#include "platform/barrier.h"
#include "sapling/bn254.h"
#include "sapling/bn254_accel.h"
#include "sapling/params_vk_embedded.h"
#include "test/bn254_legacy_reference.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#ifndef ZCL_TESTING
#error "test_bn254_engine_parity needs the ZCL_TESTING hooks of bn254.c"
#endif

#define ENG_CHECK(name, expr) do {             \
    printf("%s... ", (name));                  \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

/* ── deterministic test randomness ────────────────────────────── */

static uint64_t g_rs = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
    g_rs ^= g_rs << 13;
    g_rs ^= g_rs >> 7;
    g_rs ^= g_rs << 17;
    return g_rs * 0x2545F4914F6CDD1DULL;
}

static void rand_fq(struct bn_fq *f)
{
    uint8_t b[32];
    for (int i = 0; i < 32; i++)
        b[i] = (uint8_t)rnd();
    b[0] &= 0x1f; /* below 2^253 < q */
    if (!bn_fq_from_bytes_be(f, b))
        bn_fq_zero(f);
}

static void rand_fq2(struct bn_fq2 *f)
{
    rand_fq(&f->c0);
    rand_fq(&f->c1);
}

static void rand_fq12(struct bn_fq12 *f)
{
    struct bn_fq2 c[6];
    for (int i = 0; i < 6; i++)
        rand_fq2(&c[i]);
    memcpy(f, c, sizeof *f);
}

static void rand_scalar(uint64_t s[4])
{
    for (int i = 0; i < 4; i++)
        s[i] = rnd();
    s[3] >>= 3;
}

_Static_assert(sizeof(struct bn_g1) == sizeof(struct legacy_bn_g1), "G1 layout");
_Static_assert(sizeof(struct bn_g2) == sizeof(struct legacy_bn_g2), "G2 layout");
_Static_assert(sizeof(struct bn_fq12) == sizeof(struct legacy_bn_fq12), "Fq12 layout");
_Static_assert(sizeof(struct bn_fq2) == sizeof(struct legacy_bn_fq2), "Fq2 layout");
_Static_assert(sizeof(struct bn_fq6) == sizeof(struct legacy_bn_fq6), "Fq6 layout");
_Static_assert(sizeof(struct ppzksnark_vk) == sizeof(struct legacy_ppzksnark_vk), "vk layout");
_Static_assert(sizeof(struct ppzksnark_proof) == sizeof(struct legacy_ppzksnark_proof), "proof layout");

#define SAME(a, b) (sizeof(a) == sizeof(b) && memcmp(&(a), &(b), sizeof(a)) == 0)

static void g1_generator(struct bn_g1 *g)
{
    bn_fq_from_u64(&g->x, 1);
    bn_fq_from_u64(&g->y, 2);
    bn_fq_one(&g->z);
}

static void rand_g1(struct bn_g1 *p, bool jacobian)
{
    struct bn_g1 g;
    uint64_t s[4];
    g1_generator(&g);
    rand_scalar(s);
    bn_g1_scalar_mul(p, &g, s);
    if (!jacobian) {
        struct bn_fq x, y;
        bn_g1_to_affine(&x, &y, p);
        p->x = x;
        p->y = y;
        bn_fq_one(&p->z);
    }
}

static void g2_scalar_mul(struct bn_g2 *out, const struct bn_g2 *p, const uint64_t s[4])
{
    struct bn_g2 acc, base = *p;
    bn_g2_identity(&acc);
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 64; b++) {
            if ((s[i] >> b) & 1)
                bn_g2_add(&acc, &acc, &base);
            bn_g2_double(&base, &base);
        }
    *out = acc;
}

static void rand_g2(struct bn_g2 *p, bool jacobian)
{
    struct bn_g2 g;
    uint64_t s[4];
    bn254_g2_one(&g);
    rand_scalar(s);
    g2_scalar_mul(p, &g, s);
    if (!jacobian) {
        struct bn_fq2 x, y;
        bn_g2_to_affine(&x, &y, p);
        p->x = x;
        p->y = y;
        bn_fq2_one(&p->z);
    }
}

/* ── E1: tower operations ─────────────────────────────────────── */

static int check_tower_ops(void)
{
    int failures = 0;
    int bad = 0;
    for (int i = 0; i < 120; i++) {
        struct bn_fq12 a, b, r, ra;
        struct legacy_bn_fq12 la, lb, lr;
        rand_fq12(&a);
        rand_fq12(&b);
        memcpy(&la, &a, sizeof a);
        memcpy(&lb, &b, sizeof b);

        bn254_test_fq12_mul(&r, &a, &b);
        legacy_bn_fq12_mul(&lr, &la, &lb);
        bad += !SAME(r, lr);
        bn254_test_fq12_sqr(&r, &a);
        legacy_bn_fq12_sq(&lr, &la);
        bad += !SAME(r, lr);
        bn254_test_fq12_inv(&r, &a);
        legacy_bn_fq12_inv(&lr, &la);
        bad += !SAME(r, lr);
        for (int p = 1; p <= 3; p++) {
            bn254_test_fq12_frob(&r, &a, p);
            legacy_bn_fq12_frobenius_map(&lr, &la, p);
            bad += !SAME(r, lr);
        }
        /* in place */
        ra = a;
        bn254_test_fq12_mul(&ra, &ra, &b);
        bn254_test_fq12_mul(&r, &a, &b);
        bad += !SAME(r, ra);
        ra = a;
        bn254_test_fq12_sqr(&ra, &ra);
        bn254_test_fq12_sqr(&r, &a);
        bad += !SAME(r, ra);

        /* sparse line multiply == dense multiply by the same sparse element */
        struct bn_fq2 x0, x4, x2;
        struct legacy_bn_fq12 sp;
        rand_fq2(&x0);
        rand_fq2(&x4);
        rand_fq2(&x2);
        legacy_bn_fq12_zero(&sp);
        memcpy(&sp.c0.c0, &x0, sizeof x0);
        memcpy(&sp.c0.c2, &x2, sizeof x2);
        memcpy(&sp.c1.c1, &x4, sizeof x4);
        ra = a;
        bn254_test_fq12_mul_by_024(&ra, &x0, &x4, &x2);
        legacy_bn_fq12_mul(&lr, &la, &sp);
        bad += !SAME(ra, lr);

        /* cyclotomic squaring on the cyclotomic subgroup (easy part of the
         * final exponentiation of a) */
        struct legacy_bn_fq12 t0, t1, c;
        t0 = la;
        legacy_bn_fq12_conjugate(&t0);
        legacy_bn_fq12_inv(&t1, &la);
        legacy_bn_fq12_mul(&c, &t0, &t1);
        legacy_bn_fq12_frobenius_map(&t0, &c, 2);
        legacy_bn_fq12_mul(&c, &t0, &c);
        memcpy(&ra, &c, sizeof ra);
        bn254_test_fq12_cyc_sqr(&r, &ra);
        legacy_bn_fq12_sq(&lr, &c);
        bad += !SAME(r, lr);

        struct bn_fq6 s, s2, sr;
        struct legacy_bn_fq6 ls, ls2, lsr;
        memcpy(&s, &a.c0, sizeof s);
        memcpy(&s2, &b.c1, sizeof s2);
        memcpy(&ls, &s, sizeof s);
        memcpy(&ls2, &s2, sizeof s2);
        bn254_test_fq6_mul(&sr, &s, &s2);
        legacy_bn_fq6_mul(&lsr, &ls, &ls2);
        bad += !SAME(sr, lsr);
        bn254_test_fq6_sqr(&sr, &s);
        legacy_bn_fq6_sq(&lsr, &ls);
        bad += !SAME(sr, lsr);

        struct bn_fq fa, fr;
        struct legacy_bn_fq lfa, lfr;
        rand_fq(&fa);
        if (i % 20 == 0)
            bn_fq_zero(&fa);
        memcpy(&lfa, &fa, sizeof fa);
        bn254_test_fq_inv(&fr, &fa);
        legacy_bn_fq_inv(&lfr, &lfa);
        bad += !SAME(fr, lfr);
        bool o = bn254_test_fq_sqrt(&fr, &fa);
        bool lo = legacy_bn_fq_sqrt(&lfr, &lfa);
        bad += !(o == lo && SAME(fr, lfr));
    }
    printf("E1: tower, sparse multiply, cyclotomic square, Frobenius, inverse "
           "(%d of 120 rounds differ)... ", bad);
    if (bad == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

/* ── E2: Miller loop, final exponentiation, pairing ───────────── */

static int check_pairing(void)
{
    int failures = 0;
    int bad_fe = 0, bad_ml = 0, bad_pair = 0, bad_check = 0;

    legacy_bn254_x_init();
    for (int i = 0; i < 24; i++) {
        struct bn_fq12 f;
        struct legacy_bn_fq12 lf;
        rand_fq12(&f);
        memcpy(&lf, &f, sizeof f);
        bn254_test_final_exp(&f);
        legacy_bn254_x_final_exp(&lf);
        bad_fe += !SAME(f, lf);
    }
    for (int i = 0; i < 28; i++) {
        size_t n = 1 + (size_t)(rnd() % 3);
        struct bn_g1 p[3];
        struct bn_g2 q[3];
        struct legacy_bn_g1 lp[3];
        struct legacy_bn_g2 lq[3];
        for (size_t k = 0; k < n; k++) {
            rand_g1(&p[k], rnd() & 1);
            rand_g2(&q[k], rnd() & 1);
            if (i % 7 == 3 && k == 0)
                bn_g1_identity(&p[k]);
            if (i % 7 == 5 && k == n - 1)
                bn_g2_identity(&q[k]);
            memcpy(&lp[k], &p[k], sizeof p[k]);
            memcpy(&lq[k], &q[k], sizeof q[k]);
        }
        struct bn_fq12 ml;
        struct legacy_bn_fq12 lml, lone;
        bn254_test_miller(&ml, p, q, n);
        legacy_bn_fq12_one(&lml);
        for (size_t k = 0; k < n; k++) {
            legacy_bn254_x_miller(&lone, &lp[k], &lq[k]);
            legacy_bn_fq12_mul(&lml, &lml, &lone);
        }
        bad_ml += !SAME(ml, lml);

        struct bn_fq12 e;
        struct legacy_bn_fq12 le;
        bn254_pairing(&e, &p[0], &q[0]);
        legacy_bn254_pairing(&le, &lp[0], &lq[0]);
        bad_pair += !SAME(e, le);
        bad_check += (bn254_multi_pairing_check(p, q, n) !=
                      legacy_bn254_multi_pairing_check(lp, lq, n));
    }
    ENG_CHECK("E2: final exponentiation equals the original on arbitrary Fq12", bad_fe == 0);
    ENG_CHECK("E2: Miller loop (1-3 pairs, Jacobian/affine, identities) equals the original product",
              bad_ml == 0);
    ENG_CHECK("E2: pairing equals the original", bad_pair == 0);
    ENG_CHECK("E2: multi-pairing check agrees with the original", bad_check == 0);

    /* e(2G1, G2) e(-G1, 2G2) == 1, and a perturbed copy is not 1 */
    struct bn_g1 g, g2p, ng, pts[2];
    struct bn_g2 q, q2, qs[2];
    g1_generator(&g);
    bn_g1_double(&g2p, &g);
    bn_g1_neg(&ng, &g);
    bn254_g2_one(&q);
    bn_g2_double(&q2, &q);
    pts[0] = g2p;
    pts[1] = ng;
    qs[0] = q;
    qs[1] = q2;
    bool bilinear = bn254_multi_pairing_check(pts, qs, 2);
    pts[1] = g;
    bool perturbed = bn254_multi_pairing_check(pts, qs, 2);
    ENG_CHECK("E2: bilinearity e(2P,Q) = e(P,2Q), and a wrong product is refused",
              bilinear && !perturbed);
    struct bn_fq12 e, one;
    bn254_pairing(&e, &g, &q);
    bn_fq12_one(&one);
    ENG_CHECK("E2: e(G1, G2) is not 1", !bn_fq12_eq(&e, &one));
    return failures;
}

/* ── E3: decoders ─────────────────────────────────────────────── */

static void be_from_fq(uint8_t out[32], const struct bn_fq *a) { bn_fq_to_bytes_be(out, a); }

/* FE2IP (Proof.cpp:25-34): c1*q + c0 as 64 big-endian bytes. */
static void fe2ip_encode(uint8_t out[64], const struct bn_fq2 *x)
{
    static const uint64_t Q[4] = {
        0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL,
        0xb85045b68181585dULL, 0x30644e72e131a029ULL
    };
    uint8_t b0[32], b1[32];
    uint64_t c0[4] = {0}, c1[4] = {0}, r[9] = {0};
    be_from_fq(b0, &x->c0);
    be_from_fq(b1, &x->c1);
    for (int i = 0; i < 32; i++) {
        c0[(31 - i) / 8] |= (uint64_t)b0[i] << (((31 - i) % 8) * 8);
        c1[(31 - i) / 8] |= (uint64_t)b1[i] << (((31 - i) % 8) * 8);
    }
    for (int i = 0; i < 4; i++) {
        __uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (__uint128_t)c1[i] * Q[j] + r[i + j];
            r[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        r[i + 4] += (uint64_t)carry;
    }
    __uint128_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (__uint128_t)r[i] + (i < 4 ? c0[i] : 0);
        r[i] = (uint64_t)c;
        c >>= 64;
    }
    for (int i = 0; i < 64; i++)
        out[i] = (uint8_t)(r[(63 - i) / 8] >> (((63 - i) % 8) * 8));
}

static bool fq2_larger_than_neg(const struct bn_fq2 *y)
{
    struct bn_fq2 n;
    uint8_t a[32], b[32];
    bn_fq2_neg(&n, y);
    be_from_fq(a, &y->c1);
    be_from_fq(b, &n.c1);
    int c = memcmp(a, b, 32);
    if (c == 0) {
        be_from_fq(a, &y->c0);
        be_from_fq(b, &n.c0);
        c = memcmp(a, b, 32);
    }
    return c > 0;
}

static void g1_compress(uint8_t out[33], const struct bn_g1 *p)
{
    uint64_t one[4] = {1, 0, 0, 0}, raw[4];
    bn_fq_mont_mul_accel(raw, p->y.d, one);
    out[0] = (uint8_t)(0x02 | (raw[0] & 1));
    be_from_fq(out + 1, &p->x);
}

static void g2_compress(uint8_t out[65], const struct bn_g2 *p)
{
    out[0] = (uint8_t)(0x0a | (fq2_larger_than_neg(&p->y) ? 1 : 0));
    fe2ip_encode(out + 1, &p->x);
}

/* A random point of the twist curve y^2 = x^3 + b'; almost never in G2. */
static bool rand_twist_point(struct bn_g2 *p)
{
    struct legacy_bn_g2 gen;
    struct legacy_bn_fq2 gy2, gx2, gx3, b;
    struct bn_g2 g;
    bn254_g2_one(&g);
    memcpy(&gen, &g, sizeof gen);
    legacy_bn_fq2_sq(&gy2, &gen.y);
    legacy_bn_fq2_sq(&gx2, &gen.x);
    legacy_bn_fq2_mul(&gx3, &gx2, &gen.x);
    legacy_bn_fq2_sub(&b, &gy2, &gx3); /* b' = y^2 - x^3 at the generator */
    for (int tries = 0; tries < 64; tries++) {
        struct bn_fq2 x;
        struct legacy_bn_fq2 lx, x2, x3, rhs, y;
        rand_fq2(&x);
        memcpy(&lx, &x, sizeof x);
        legacy_bn_fq2_sq(&x2, &lx);
        legacy_bn_fq2_mul(&x3, &x2, &lx);
        legacy_bn_fq2_add(&rhs, &x3, &b);
        if (legacy_bn_fq2_sqrt(&y, &rhs)) {
            p->x = x;
            memcpy(&p->y, &y, sizeof y);
            bn_fq2_one(&p->z);
            return true;
        }
    }
    return false;
}

/* 1 when the two decoders disagree on the accept set or on the point. */
static int g1_decode_differs(const uint8_t e[33], bool *accepted)
{
    struct bn_g1 a;
    struct legacy_bn_g1 b;
    bool oa = bn_g1_decompress(&a, e);
    bool ob = legacy_bn_g1_decompress(&b, e);
    *accepted = oa;
    return (oa != ob) || (oa && !SAME(a, b));
}

static int g2_decode_differs(const uint8_t e[65], bool *accepted)
{
    struct bn_g2 a;
    struct legacy_bn_g2 b;
    bool oa = bn_g2_decompress(&a, e);
    bool ob = legacy_bn_g2_decompress(&b, e);
    *accepted = oa;
    return (oa != ob) || (oa && !SAME(a, b));
}

/* Variant 0 keeps the valid encoding; 1 flips the sign bit; 2 replaces the lead
 * byte; 3 flips one bit of the coordinate; 4 clears the first coordinate byte. */
static void corrupt_encoding(uint8_t *e, size_t len, int variant)
{
    if (variant == 1) e[0] ^= 1;
    if (variant == 2) e[0] = (uint8_t)rnd();
    if (variant == 3) e[1 + (rnd() % (len - 1))] ^= (uint8_t)(1u << (rnd() % 8));
    if (variant == 4) e[1] = 0;
}

static int check_g1_decoder(void)
{
    int failures = 0, bad = 0, missed = 0;
    for (int i = 0; i < 120; i++) {
        struct bn_g1 p;
        uint8_t enc[33];
        rand_g1(&p, false);
        g1_compress(enc, &p);
        for (int v = 0; v < 4; v++) {
            uint8_t e[33];
            bool accepted;
            memcpy(e, enc, 33);
            corrupt_encoding(e, 33, v);
            bad += g1_decode_differs(e, &accepted);
            missed += (v == 0 && !accepted);
        }
    }
    ENG_CHECK("E3: G1 decompression equals the original (valid, parity, lead byte, bit flips)", bad == 0);
    ENG_CHECK("E3: every valid G1 encoding is accepted", missed == 0);
    return failures;
}

static int check_g2_decoder(void)
{
    int failures = 0, bad = 0, missed = 0;
    for (int i = 0; i < 30; i++) {
        struct bn_g2 p;
        uint8_t enc[65];
        rand_g2(&p, false);
        g2_compress(enc, &p);
        for (int v = 0; v < 5; v++) {
            uint8_t e[65];
            bool accepted;
            memcpy(e, enc, 65);
            corrupt_encoding(e, 65, v);
            bad += g2_decode_differs(e, &accepted);
            missed += (v == 0 && !accepted);
        }
    }
    /* encodings of twist points outside G2: both must refuse, identically */
    for (int i = 0; i < 80; i++) {
        struct bn_g2 t;
        uint8_t enc[65];
        bool accepted;
        if (!rand_twist_point(&t))
            continue;
        g2_compress(enc, &t);
        bad += g2_decode_differs(enc, &accepted);
    }
    ENG_CHECK("E3: G2 decompression equals the original (valid, corrupted, off-subgroup)", bad == 0);
    ENG_CHECK("E3: every valid G2 encoding is accepted", missed == 0);
    return failures;
}

static int check_fq2_sqrt_cases(void)
{
    int failures = 0, bad = 0;
    for (int i = 0; i < 400; i++) {
        struct bn_fq2 a, r1;
        struct legacy_bn_fq2 la, r2;
        rand_fq2(&a);
        if (i & 1) bn_fq_zero(&a.c1);
        if (i % 11 == 0) bn_fq2_zero(&a);
        memcpy(&la, &a, sizeof a);
        bool x = bn_fq2_sqrt(&r1, &a), y = legacy_bn_fq2_sqrt(&r2, &la);
        bad += (x != y) || (x && !SAME(r1, r2));
    }
    ENG_CHECK("E3: Fq2 square root equals the original, residues and non-residues", bad == 0);
    return failures;
}

static int check_decoders(void)
{
    return check_g1_decoder() + check_g2_decoder() + check_fq2_sqrt_cases();
}

/* ── E4: the G2 subgroup test ─────────────────────────────────── */

/* Numeric identities the psi test is proved from (see bn254_engine.inc):
 * q - r = 6u^2 (so q = 6u^2 mod r, the eigenvalue of psi on G2) and
 * t = q + 1 - r = 6u^2 + 1. */
static void u256_mul_add_u64(uint64_t a[4], uint64_t m, uint64_t add)
{
    __uint128_t carry = add;
    for (int i = 0; i < 4; i++) {
        carry += (__uint128_t)a[i] * m;
        a[i] = (uint64_t)carry;
        carry >>= 64;
    }
}

static int check_subgroup_identities(void)
{
    int failures = 0;
    static const uint64_t q[4] = {
        0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL,
        0xb85045b68181585dULL, 0x30644e72e131a029ULL
    };
    static const uint64_t r[4] = {
        0x43e1f593f0000001ULL, 0x2833e84879b97091ULL,
        0xb85045b68181585dULL, 0x30644e72e131a029ULL
    };
    const uint64_t u = 4965661367192848881ULL;

    /* r = 36u^4 + 36u^3 + 18u^2 + 6u + 1 by Horner: (((36u + 36)u + 18)u + 6)u + 1 */
    uint64_t acc[4] = {36, 0, 0, 0};
    u256_mul_add_u64(acc, u, 36);
    u256_mul_add_u64(acc, u, 18);
    u256_mul_add_u64(acc, u, 6);
    u256_mul_add_u64(acc, u, 1);
    ENG_CHECK("E4: r = 36u^4 + 36u^3 + 18u^2 + 6u + 1 for the BN parameter u",
              memcmp(acc, r, sizeof r) == 0);

    /* q = 36u^4 + 36u^3 + 24u^2 + 6u + 1, so q - r = 6u^2 */
    uint64_t qa[4] = {36, 0, 0, 0};
    u256_mul_add_u64(qa, u, 36);
    u256_mul_add_u64(qa, u, 24);
    u256_mul_add_u64(qa, u, 6);
    u256_mul_add_u64(qa, u, 1);
    ENG_CHECK("E4: q = 36u^4 + 36u^3 + 24u^2 + 6u + 1 (the BN family the psi proof uses)",
              memcmp(qa, q, sizeof q) == 0);

    uint64_t d[4];
    __int128_t bw = 0;
    for (int i = 0; i < 4; i++) {
        bw += (__int128_t)q[i] - r[i];
        d[i] = (uint64_t)bw;
        bw >>= 64;
    }
    __uint128_t six_u2 = (__uint128_t)u * u * 6;
    ENG_CHECK("E4: q - r = 6u^2, so psi acts on G2 as multiplication by 6u^2",
              d[0] == (uint64_t)six_u2 && d[1] == (uint64_t)(six_u2 >> 64) && d[2] == 0 && d[3] == 0);
    return failures;
}

struct sg_tally {
    int bad, in_ok, out_ok, h_ok, tors_ok, mixed_ok;
};

/* psi test against the original r*P == O on one point; counts a disagreement
 * in s->bad and returns the shared verdict (false when they differ). */
static bool sg_compare(const struct bn_g2 *p, struct sg_tally *s)
{
    struct legacy_bn_g2 lp;
    memcpy(&lp, p, sizeof lp);
    bool a = bn254_test_g2_in_subgroup(p), b = legacy_bn254_x_g2_in_subgroup(&lp);
    s->bad += (a != b);
    return a && b;
}

/* [2q - r] t is in G2 (the twist has order r * (2q - r)); [r] t lies in the
 * cofactor part and never in G2; their mixtures with G2 neither. */
static void sg_cofactor_points(const struct bn_g2 *t, struct sg_tally *s)
{
    static const uint64_t R[4] = {
        0x43e1f593f0000001ULL, 0x2833e84879b97091ULL,
        0xb85045b68181585dULL, 0x30644e72e131a029ULL
    };
    static const uint64_t Q[4] = {
        0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL,
        0xb85045b68181585dULL, 0x30644e72e131a029ULL
    };
    uint64_t H[4]; /* 2q - r */
    __uint128_t c = 0;
    __int128_t bw = 0;
    for (int i = 0; i < 4; i++) {
        c += (__uint128_t)Q[i] * 2;
        H[i] = (uint64_t)c;
        c >>= 64;
    }
    for (int i = 0; i < 4; i++) {
        bw += (__int128_t)H[i] - R[i];
        H[i] = (uint64_t)bw;
        bw >>= 64;
    }
    struct bn_g2 inh, tors, g, mixed;
    g2_scalar_mul(&inh, t, H);
    g2_scalar_mul(&tors, t, R);
    rand_g2(&g, true);
    bn_g2_add(&mixed, &tors, &g);
    if (!bn_g2_is_identity(&inh))
        s->h_ok += sg_compare(&inh, s);
    if (!bn_g2_is_identity(&tors))
        s->tors_ok += !sg_compare(&tors, s);
    if (!bn_g2_is_identity(&mixed))
        s->mixed_ok += !sg_compare(&mixed, s);
}

static int check_subgroup_test(void)
{
    int failures = 0;
    struct sg_tally s = {0};
    struct bn_g2 gen;
    bn254_g2_one(&gen);
    ENG_CHECK("E4: the G2 generator passes the psi test", bn254_test_g2_in_subgroup(&gen));

    for (int i = 0; i < 40; i++) {
        struct bn_g2 p;
        rand_g2(&p, i & 1);
        s.in_ok += sg_compare(&p, &s);
    }
    for (int i = 0; i < 60; i++) {
        struct bn_g2 t;
        if (!rand_twist_point(&t))
            continue;
        s.out_ok += !sg_compare(&t, &s);
        sg_cofactor_points(&t, &s);
    }
    ENG_CHECK("E4: the psi test equals r*P == O on every point tried", s.bad == 0);
    ENG_CHECK("E4: random G2 points are accepted", s.in_ok == 40);
    ENG_CHECK("E4: random twist points are refused (as r*P != O says)", s.out_ok >= 50);
    ENG_CHECK("E4: [2q-r]t is accepted, [r]t and [r]t + G2 point are refused",
              s.h_ok >= 50 && s.tors_ok >= 50 && s.mixed_ok >= 50);
    return failures;
}

/* ── E5: IC multi-scalar multiplication ───────────────────────── */

static const uint64_t k_msm_edge[12][4] = {
    {0, 0, 0, 0}, {1, 0, 0, 0}, {2, 0, 0, 0}, {15, 0, 0, 0}, {16, 0, 0, 0},
    {~0ULL, ~0ULL, ~0ULL, ~0ULL}, {~0ULL, ~0ULL, ~0ULL, 0x1fffffffffffffffULL},
    {0x43e1f593f0000001ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL},
    {0x43e1f593f0000000ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL},
    {0x43e1f593f0000002ULL, 0x2833e84879b97091ULL, 0xb85045b68181585dULL, 0x30644e72e131a029ULL},
    {0, 0, 0, 1ULL << 63},
    {0xf0f0f0f0f0f0f0f0ULL, 0x0f0f0f0f0f0f0f0fULL, 0xffffffff00000000ULL, 0x00000000ffffffffULL}
};

/* A key with n inputs: random IC points, with an identity, repeated or negated
 * base in some variants; odd variants use Jacobian points. */
static bool msm_make_vk(struct ppzksnark_vk *vk, size_t n, int variant)
{
    memset(vk, 0, sizeof *vk);
    vk->ic_len = n + 1;
    vk->ic = calloc(n + 1, sizeof(struct bn_g1));
    if (!vk->ic)
        return false;
    for (size_t i = 0; i <= n; i++)
        rand_g1(&vk->ic[i], variant & 1);
    if (variant == 2)
        bn_g1_identity(&vk->ic[3]);
    if (variant == 3) {
        vk->ic[4] = vk->ic[2];
        bn_g1_neg(&vk->ic[5], &vk->ic[2]);
    }
    return true;
}

/* Round t of the scalar schedule: edge scalars first, then random ones. */
static void msm_scalars(uint64_t in[20][4], size_t n, int t)
{
    for (size_t i = 0; i < n; i++) {
        if (t < 10)
            memcpy(in[i], k_msm_edge[(t + i) % 12], 32);
        else
            rand_scalar(in[i]);
        if (t == 11 && (i % 2))
            memcpy(in[i], k_msm_edge[i % 12], 32);
    }
}

/* 1 when the engine accumulation and the original double-and-add sum differ. */
static int msm_case_differs(const struct ppzksnark_vk *vk, const uint64_t (*in)[4], size_t n)
{
    struct bn_g1 acc;
    struct legacy_bn_g1 lacc;
    bn254_test_msm(&acc, vk, in, n);
    memcpy(&lacc, &vk->ic[0], sizeof lacc);
    for (size_t i = 0; i < n; i++) {
        struct legacy_bn_g1 base, term;
        memcpy(&base, &vk->ic[i + 1], sizeof base);
        legacy_bn_g1_scalar_mul(&term, &base, in[i]);
        legacy_bn_g1_add(&lacc, &lacc, &term);
    }
    bool ai = bn_g1_is_identity(&acc), li = legacy_bn_g1_is_identity(&lacc);
    if (ai || li)
        return ai != li;
    struct bn_fq ax, ay;
    struct legacy_bn_fq lx, ly;
    bn_g1_to_affine(&ax, &ay, &acc);
    legacy_bn_g1_to_affine(&lx, &ly, &lacc);
    return !(SAME(ax, lx) && SAME(ay, ly));
}

static int check_msm(void)
{
    int failures = 0;
    int bad = 0, cases = 0;
    for (int variant = 0; variant < 6; variant++) {
        size_t n = (variant == 4) ? 20 : (variant == 5 ? 1 : 9);
        struct ppzksnark_vk vk;
        if (!msm_make_vk(&vk, n, variant))
            return failures + 1;
        for (int t = 0; t < 12; t++) {
            uint64_t in[20][4];
            msm_scalars(in, n, t);
            bad += msm_case_differs(&vk, (const uint64_t (*)[4])in, n);
            cases++;
        }
        free(vk.ic);
    }
    printf("E5: IC accumulation equals the original (%d cases, edge scalars, identity/repeated/negated "
           "bases, 1/9/20 inputs; %d differ)... ", cases, bad);
    if (bad == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

/* ── E6: whole-proof verification ─────────────────────────────── */

/* Mainnet height 241, tx 1, JoinSplit 0 (same fixture as test_sprout_phgr13_kat). */
static const char k_proof_hex[] =
    "03285153c3029f3e5955395ca617498d8ae3db7d2c5904103f71b4d67ccc1e408a021e63826bac468e89a96f47d4878a"
    "775af18971b5b94167e3772402b735cac47b0a0521402661d91c8d7bd00ac04da33e6604c5d578f9d6317ecb0618d4f7"
    "a6755e94fca74453a74a328b09dc11831210442ed7ef2ebabcde71187f92f6be87455503201c1713b784fa09e5657a67"
    "a917515a9e833ab65c9a773e8f96993b4777de850309af0cb0a057a18c17e956d5db9066c2d38c4b885e3931f1f9cf8a"
    "1b380a7688032ec70722fff9ecd43afc06ee53a580cf6d139844f1bc7c6b0a1e762e64509417020ed0097f4ea82d6b1f"
    "ba4eb831743f1dfe220e48d26a356d2ba19345850cbb0a0312f3b2990da9df24195260c531b4b17c726cb9a2f03503ea"
    "16044cf9306e201f";
static const char k_in_hex[] =
    "d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"   /* rt */
    "ce79461df91ca43c3da7e715e43845fc7054b4cf8fc1291f72015bebc56e31cd"   /* h_sig */
    "b65e0e165f5daef5311098467772c00486739c420f1c47d7ecf490cb5b1df051"   /* mac1 */
    "957b152d1ce122fdbe75debbde06b3fb26264e2414939c62fb715a6bec723d4a"   /* mac2 */
    "c2f4f6342207af5ffa181fb1d1b6bac3496f2ae476b55a4a1da0d7ff2584d34b"   /* nf1 */
    "99fe254e53c66639a81140a64e277dfe3eaf251e302122794e3dc30d6e563b3b"   /* nf2 */
    "869e92d09df2362aed6cb367554d94fa9ec2dd40211aef204e4a963fbb56bc04"   /* cm1 */
    "dfee184b5cb8a50461ca21f0f409fd4a1b17d3139a367af95367556a9acf77e0";  /* cm2 */

struct js {
    uint8_t proof[296];
    uint8_t in[8][32]; /* rt, h_sig, mac1, mac2, nf1, nf2, cm1, cm2 */
    uint64_t vpub_old, vpub_new;
};

static bool hex_decode(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != n * 2)
        return false;
    for (size_t i = 0; i < n; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char ch = hex[i * 2 + (size_t)k];
            int d = (ch >= '0' && ch <= '9') ? ch - '0' : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10 : -1;
            if (d < 0)
                return false;
            v = v * 16 + d;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

static bool load_kat(struct js *j)
{
    uint8_t in[256];
    if (!hex_decode(k_proof_hex, j->proof, 296) || !hex_decode(k_in_hex, in, 256))
        return false;
    memcpy(j->in, in, 256);
    j->vpub_old = 1249990000ULL;
    j->vpub_new = 0;
    return true;
}

static bool verify_new(const struct js *j)
{
    return sprout_verify_phgr13(j->proof, j->in[0], j->in[1], j->in[2], j->in[3], j->in[4],
                                j->in[5], j->in[6], j->in[7], j->vpub_old, j->vpub_new);
}

static bool verify_legacy(const struct js *j)
{
    return legacy_sprout_verify_phgr13(j->proof, j->in[0], j->in[1], j->in[2], j->in[3], j->in[4],
                                       j->in[5], j->in[6], j->in[7], j->vpub_old, j->vpub_new);
}

/* Corrupt the proof and the public inputs one bit at a time; returns how many
 * verdicts of the two implementations differ. *accepted counts proofs either
 * implementation accepted (none may be). */
static int verify_mutations(const struct js *kat, int *total, int *accepted)
{
    int bad = 0;
    /* every byte of the proof, two bit flips each (a different bit in each pass) */
    for (size_t pos = 0; pos < 296; pos++)
        for (int k = 0; k < 2; k++) {
            struct js m = *kat;
            m.proof[pos] ^= (uint8_t)(1u << (k ? (pos % 8) : ((pos + 3) % 8)));
            bool a = verify_new(&m), b = verify_legacy(&m);
            bad += (a != b);
            *accepted += a + b;
            (*total)++;
        }
    /* public inputs: a few bits of each of the eight 32-byte fields */
    for (int f = 0; f < 8; f++)
        for (int bit = 0; bit < 256; bit += 61) {
            struct js m = *kat;
            m.in[f][bit / 8] ^= (uint8_t)(1u << (bit % 8));
            bool a = verify_new(&m), b = verify_legacy(&m);
            bad += (a != b);
            *accepted += a + b;
            (*total)++;
        }
    /* the amounts */
    struct js m = *kat;
    m.vpub_old ^= 1;
    bad += (verify_new(&m) != verify_legacy(&m));
    m = *kat;
    m.vpub_new = 1;
    bad += (verify_new(&m) != verify_legacy(&m));
    *total += 2;
    return bad;
}

/* An in-place edit of the key must not be served from stale tables: the proof
 * stops verifying, in both implementations, and verifies again once the key is
 * restored. */
static int check_key_edits(struct ppzksnark_vk *vk, struct legacy_ppzksnark_vk *lvk,
                           const struct js *kat)
{
    int failures = 0;
    struct bn_g1 saved = vk->ic[3];
    struct legacy_bn_g1 lsaved = lvk->ic[3];
    vk->ic[3] = vk->ic[2];
    lvk->ic[3] = lvk->ic[2];
    bool edited_new = verify_new(kat), edited_old = verify_legacy(kat);
    vk->ic[3] = saved;
    lvk->ic[3] = lsaved;
    bool restored_new = verify_new(kat);
    ENG_CHECK("E6: an edited key refuses the proof exactly as the original does, the restored key accepts",
              !edited_new && !edited_old && restored_new);

    struct bn_g2 savedg = vk->gamma_beta_g2;
    struct legacy_bn_g2 lsavedg = lvk->gamma_beta_g2;
    bn_g2_double(&vk->gamma_beta_g2, &savedg);
    legacy_bn_g2_double(&lvk->gamma_beta_g2, &lsavedg);
    bool edited2_new = verify_new(kat), edited2_old = verify_legacy(kat);
    vk->gamma_beta_g2 = savedg;
    lvk->gamma_beta_g2 = lsavedg;
    ENG_CHECK("E6: an edited G2 key element refuses the proof in both implementations",
              !edited2_new && !edited2_old && verify_new(kat));

    bn_g1_identity(&vk->ic[0]);
    legacy_bn_g1_identity(&lvk->ic[0]);
    ENG_CHECK("E6: an identity IC[0] gives the same (refusing) verdict",
              verify_new(kat) == verify_legacy(kat) && !verify_new(kat));
    return failures;
}

static int check_verify_engine(void)
{
    int failures = 0;
    const struct zcl_embedded_vk *emb = &zcl_embedded_vks[3];
    struct ppzksnark_vk vk;
    struct legacy_ppzksnark_vk lvk;
    struct js kat;
    bool ok = strcmp(emb->name, "sprout-phgr") == 0 && load_kat(&kat) &&
              ppzksnark_vk_read(&vk, emb->bytes, emb->len) &&
              legacy_ppzksnark_vk_read(&lvk, emb->bytes, emb->len);
    ENG_CHECK("E6: embedded PHGR13 key and KAT fixture load", ok);
    if (!ok)
        return failures;
    sprout_phgr_set_vk(&vk);
    legacy_sprout_phgr_set_vk(&lvk);
    /* every rejection below is a LOG_FAIL line (hundreds of them): keep the run readable */
    enum zcl_log_level saved_level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    ENG_CHECK("E6: the height-241 proof verifies, old and new", verify_new(&kat) && verify_legacy(&kat));

    int total = 0, accepted = 0;
    int bad = verify_mutations(&kat, &total, &accepted);
    printf("E6: %d corrupted proofs / inputs, verdicts differ in %d, accepted %d... ", total, bad, accepted);
    if (bad == 0 && accepted == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }

    failures += check_key_edits(&vk, &lvk, &kat);

    sprout_phgr_set_vk(NULL);
    legacy_sprout_phgr_set_vk(NULL);
    zcl_log_level_set(saved_level);
    ppzksnark_vk_free(&vk);
    legacy_ppzksnark_vk_free(&lvk);
    return failures;
}

/* ── E8: edge-valued field elements ───────────────────────────── */

/* Coefficient kinds: 0, 1, the limbs of q-1, -1 (Montgomery), random. Zero
 * coefficients reach fq_neg(0) through conjugation and the Frobenius maps,
 * which random inputs almost never do. */
static void edge_fq(struct bn_fq *f, int kind)
{
    static const uint64_t q_minus_1[4] = {
        0x3c208c16d87cfd46ULL, 0x97816a916871ca8dULL,
        0xb85045b68181585dULL, 0x30644e72e131a029ULL
    };
    switch (kind) {
    case 0: bn_fq_zero(f); break;
    case 1: bn_fq_one(f); break;
    case 2: memcpy(f->d, q_minus_1, sizeof q_minus_1); break;
    case 3: bn_fq_one(f); bn_fq_neg(f, f); break;
    default: rand_fq(f); break;
    }
}

/* Coefficient i of f is of `kind` when bit i of mask is set, else 0. */
static void edge_fq12(struct bn_fq12 *f, int kind, unsigned mask)
{
    struct bn_fq c[12];
    _Static_assert(sizeof c == sizeof *f, "Fq12 is 12 Fq");
    for (int i = 0; i < 12; i++) {
        if ((mask >> i) & 1u)
            edge_fq(&c[i], kind);
        else
            bn_fq_zero(&c[i]);
    }
    memcpy(f, c, sizeof *f);
}

/* Number of results that differ between the engine and the original for the
 * final exponentiation, product, square, inverse, Frobenius maps and the sparse
 * multiply by g's line slots. */
static int edge_tower_differs(const struct bn_fq12 *f, const struct bn_fq12 *g)
{
    struct bn_fq12 r;
    struct legacy_bn_fq12 lf, lg, lr, sp;
    int bad = 0;
    memcpy(&lf, f, sizeof lf);
    memcpy(&lg, g, sizeof lg);
    r = *f;
    bn254_test_final_exp(&r);
    lr = lf;
    legacy_bn254_x_final_exp(&lr);
    bad += !SAME(r, lr);
    bn254_test_fq12_mul(&r, f, g);
    legacy_bn_fq12_mul(&lr, &lf, &lg);
    bad += !SAME(r, lr);
    bn254_test_fq12_sqr(&r, f);
    legacy_bn_fq12_sq(&lr, &lf);
    bad += !SAME(r, lr);
    bn254_test_fq12_inv(&r, f);
    legacy_bn_fq12_inv(&lr, &lf);
    bad += !SAME(r, lr);
    for (int p = 1; p <= 3; p++) {
        bn254_test_fq12_frob(&r, f, p);
        legacy_bn_fq12_frobenius_map(&lr, &lf, p);
        bad += !SAME(r, lr);
    }
    legacy_bn_fq12_zero(&sp);
    sp.c0.c0 = lg.c0.c0;
    sp.c0.c2 = lg.c0.c2;
    sp.c1.c1 = lg.c1.c1;
    r = *f;
    bn254_test_fq12_mul_by_024(&r, &g->c0.c0, &g->c1.c1, &g->c0.c2);
    legacy_bn_fq12_mul(&lr, &lf, &sp);
    bad += !SAME(r, lr);
    return bad;
}

/* Cyclotomic squaring of the easy-part image of f against the generic square. */
static int edge_cyc_differs(const struct bn_fq12 *f)
{
    struct legacy_bn_fq12 lf, t0, t1, c, lr;
    struct bn_fq12 cc, r;
    memcpy(&lf, f, sizeof lf);
    t0 = lf;
    legacy_bn_fq12_conjugate(&t0);
    legacy_bn_fq12_inv(&t1, &lf);
    legacy_bn_fq12_mul(&c, &t0, &t1);
    legacy_bn_fq12_frobenius_map(&t0, &c, 2);
    legacy_bn_fq12_mul(&c, &t0, &c);
    memcpy(&cc, &c, sizeof cc);
    bn254_test_fq12_cyc_sqr(&r, &cc);
    legacy_bn_fq12_sq(&lr, &c);
    return !SAME(r, lr);
}

static int check_edge_values(void)
{
    int failures = 0, bad = 0, n = 0;
    static const unsigned masks[8] = { 0xfffu, 0x001u, 0x041u, 0x015u, 0x2a0u, 0x800u, 0x555u, 0xaaau };
    legacy_bn254_x_init();
    for (int kind = 0; kind < 5; kind++)
        for (int m = 0; m < 8; m++) {
            struct bn_fq12 f, g;
            edge_fq12(&f, kind, masks[m]);
            edge_fq12(&g, (kind + 2) % 5, masks[(m + 3) % 8]);
            bad += edge_tower_differs(&f, &g);
            bad += edge_cyc_differs(&f);
            n++;
        }
    printf("E8: tower ops, sparse multiply, cyclotomic square, final exponentiation on edge values "
           "(0, 1, -1, q-1, sparse; %d pairs, %d results differ)... ", n, bad);
    if (bad == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

/* ── E9: accepting proofs with identity operands ──────────────── */

/* Keys with known discrete logs, so valid proofs come from point operations
 * alone. Flavour 0: rC_Z = gamma = G2. Flavour 1: alpha_A, rC_Z, gamma and
 * gamma_beta (G1 and G2) are the identity. IC holds an identity and a repeated
 * point; points are Jacobian. */
struct syn_key {
    struct ppzksnark_vk vk;
    struct bn_g1 ic[10];
    uint64_t beta[4], aa[4], ab[4], ac[4];
    int flavour;
};

static void syn_key_identities(struct syn_key *k)
{
    bn_g2_identity(&k->vk.alpha_a_g2);
    bn_g2_identity(&k->vk.rc_z_g2);
    bn_g2_identity(&k->vk.gamma_g2);
    bn_g2_identity(&k->vk.gamma_beta_g2);
    bn_g1_identity(&k->vk.gamma_beta_g1);
}

static void syn_key_make(struct syn_key *k, int flavour)
{
    struct bn_g1 g;
    struct bn_g2 h;
    memset(k, 0, sizeof *k);
    k->flavour = flavour;
    g1_generator(&g);
    bn254_g2_one(&h);
    rand_scalar(k->beta);
    rand_scalar(k->aa);
    rand_scalar(k->ab);
    rand_scalar(k->ac);
    for (int i = 0; i < 10; i++)
        rand_g1(&k->ic[i], true);
    bn_g1_identity(&k->ic[4]);
    k->ic[6] = k->ic[2];
    g2_scalar_mul(&k->vk.alpha_a_g2, &h, k->aa);
    bn_g1_scalar_mul(&k->vk.alpha_b_g1, &g, k->ab);
    g2_scalar_mul(&k->vk.alpha_c_g2, &h, k->ac);
    k->vk.gamma_g2 = h;
    bn_g1_scalar_mul(&k->vk.gamma_beta_g1, &g, k->beta);
    g2_scalar_mul(&k->vk.gamma_beta_g2, &h, k->beta);
    k->vk.rc_z_g2 = h;
    if (flavour == 1)
        syn_key_identities(k);
    k->vk.ic = k->ic;
    k->vk.ic_len = 10;
}

/* Public inputs: random, with 0, r, r-1, r+1, 2^256-1 and the other edge
 * scalars mixed in. */
static void syn_inputs(uint64_t in[9][4])
{
    for (int i = 0; i < 9; i++) {
        rand_scalar(in[i]);
        if (rnd() & 1)
            memcpy(in[i], k_msm_edge[rnd() % 12], 32);
    }
}

static void syn_acc(struct bn_g1 *acc, const struct syn_key *k, const uint64_t in[9][4])
{
    *acc = k->ic[0];
    for (int i = 0; i < 9; i++) {
        struct bn_g1 t;
        bn_g1_scalar_mul(&t, &k->ic[i + 1], in[i]);
        bn_g1_add(acc, acc, &t);
    }
}

/* H, K (and C for flavour 1) that satisfy checks 4 and 5 for the key. */
static void syn_proof_finish(struct ppzksnark_proof *p, const struct syn_key *k,
                             const struct bn_g1 *aacc, const struct bn_g1 *bg, const uint64_t b[4])
{
    struct bn_g1 t, s;
    if (k->flavour == 1) {
        bn_g1_identity(&p->a_prime);         /* alpha_A = O */
        bn_g1_scalar_mul(&p->c, aacc, b);    /* rC_Z = O: C = b (A + acc) */
        bn_g1_scalar_mul(&p->c_prime, &p->c, k->ac);
        rand_g1(&p->h, true);                /* H and K meet only identities */
        rand_g1(&p->k, true);
        return;
    }
    bn_g1_scalar_mul(&t, aacc, b);           /* rC_Z = 1: H = b (A + acc) - C */
    bn_g1_neg(&s, &p->c);
    bn_g1_add(&p->h, &t, &s);
    bn_g1_add(&t, aacc, &p->c);              /* gamma = 1: K = beta (A + acc + C + b G1) */
    bn_g1_add(&t, &t, bg);
    bn_g1_scalar_mul(&p->k, &t, k->beta);
}

/* shape 0 random, 1 A = -acc, 2 C = -(A + acc), 3 C = O, 4 A = O, 5 B = O */
static void syn_proof(struct ppzksnark_proof *p, const struct syn_key *k,
                      const uint64_t in[9][4], int shape)
{
    struct bn_g1 g, acc, aacc, bg;
    struct bn_g2 h;
    uint64_t b[4];
    g1_generator(&g);
    bn254_g2_one(&h);
    rand_scalar(b);
    if (shape == 5)
        memset(b, 0, sizeof b);
    syn_acc(&acc, k, in);
    rand_g1(&p->a, true);
    if (shape == 1)
        bn_g1_neg(&p->a, &acc);
    if (shape == 4)
        bn_g1_identity(&p->a);
    g2_scalar_mul(&p->b, &h, b);
    bn_g1_scalar_mul(&bg, &g, b);
    rand_g1(&p->c, true);
    bn_g1_add(&aacc, &p->a, &acc);
    if (shape == 2)
        bn_g1_neg(&p->c, &aacc);
    if (shape == 3)
        bn_g1_identity(&p->c);
    bn_g1_scalar_mul(&p->a_prime, &p->a, k->aa);
    bn_g1_scalar_mul(&p->b_prime, &bg, k->ab);
    bn_g1_scalar_mul(&p->c_prime, &p->c, k->ac);
    syn_proof_finish(p, k, &aacc, &bg, b);
}

static bool syn_verify_legacy(const struct syn_key *k, const struct ppzksnark_proof *p,
                              const uint64_t in[9][4])
{
    struct legacy_ppzksnark_vk lvk;
    struct legacy_bn_g1 lic[10];
    struct legacy_ppzksnark_proof lp;
    memcpy(&lvk, &k->vk, sizeof lvk);
    memcpy(lic, k->ic, sizeof lic);
    lvk.ic = lic;
    memcpy(&lp, p, sizeof lp);
    return legacy_ppzksnark_verify(&lvk, &lp, in, 9);
}

/* Moves one proof element off its valid value (7 = g_B). */
static void syn_tweak(struct ppzksnark_proof *p, int which)
{
    struct bn_g1 g;
    struct bn_g2 h;
    struct bn_g1 *pts[7] = { &p->a, &p->a_prime, &p->b_prime, &p->c, &p->c_prime, &p->k, &p->h };
    g1_generator(&g);
    bn254_g2_one(&h);
    if (which < 7)
        bn_g1_add(pts[which], pts[which], &g);
    else
        bn_g2_add(&p->b, &p->b, &h);
}

struct syn_tally { int n, accepted, differ, refused; };

static void syn_case(const struct syn_key *k, int shape, struct syn_tally *t)
{
    uint64_t in[9][4];
    struct ppzksnark_proof p;
    syn_inputs(in);
    syn_proof(&p, k, (const uint64_t (*)[4])in, shape);
    for (int tw = -1; tw < 8; tw++) {
        struct ppzksnark_proof q = p;
        if (tw >= 0)
            syn_tweak(&q, tw);
        bool a = ppzksnark_verify(&k->vk, &q, (const uint64_t (*)[4])in, 9);
        bool b = syn_verify_legacy(k, &q, (const uint64_t (*)[4])in);
        t->n++;
        t->accepted += a;
        t->differ += (a != b);
        t->refused += (tw < 0 && !a);
    }
}

static int check_identity_proofs(void)
{
    int failures = 0;
    static struct syn_key keys[3];
    struct syn_tally t = {0};
    syn_key_make(&keys[0], 0);
    syn_key_make(&keys[1], 1);
    syn_key_make(&keys[2], 0);
    enum zcl_log_level saved_level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    for (int round = 0; round < 2; round++)
        for (int ki = 0; ki < 3; ki++)
            for (int shape = 0; shape < 6; shape++)
                syn_case(&keys[(ki + round) % 3], shape, &t);
    zcl_log_level_set(saved_level);
    printf("E9: %d synthetic verifications (3 keys interleaved; A+acc = O, A+acc+C = O, C = O, "
           "A = O, B = O, identity key elements; one-point tweaks): %d accepted, %d differ, "
           "%d valid refused\n", t.n, t.accepted, t.differ, t.refused);
    ENG_CHECK("E9: verdicts equal the original on every synthetic case", t.differ == 0);
    ENG_CHECK("E9: every valid synthetic proof (identity operands included) is accepted", t.refused == 0);
    return failures;
}

/* ── E7: concurrent verification ──────────────────────────────── */

#define PAR_THREADS 16
#define PAR_ROUNDS 6

struct par_shared {
    zcl_barrier_t barrier;
    struct js kat;
    atomic_int wrong;
};

struct par_arg {
    struct par_shared *sh;
    int idx;
};

static void *par_worker(void *p)
{
    struct par_arg *a = p;
    zcl_barrier_wait(&a->sh->barrier);
    for (int round = 0; round < PAR_ROUNDS; round++) {
        struct js m = a->sh->kat;
        bool want = true;
        if ((a->idx + round) % 3 == 1) { /* some threads corrupt the proof */
            m.proof[(size_t)(a->idx * 13 + round * 29) % 296] ^= 0x40;
            want = false;
        }
        if (verify_new(&m) != want)
            atomic_fetch_add(&a->sh->wrong, 1);
    }
    return NULL;
}

static int check_concurrency(void)
{
    int failures = 0;
    static struct par_shared sh;
    const struct zcl_embedded_vk *emb = &zcl_embedded_vks[3];
    struct ppzksnark_vk vk;
    pthread_t th[PAR_THREADS];
    struct par_arg args[PAR_THREADS];
    memset(&sh, 0, sizeof sh);
    bool ok = load_kat(&sh.kat) && ppzksnark_vk_read(&vk, emb->bytes, emb->len);
    ENG_CHECK("E7: fixture loads", ok);
    if (!ok)
        return failures;
    sprout_phgr_set_vk(&vk);
    atomic_init(&sh.wrong, 0);
    enum zcl_log_level saved_level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    zcl_barrier_init(&sh.barrier, PAR_THREADS);
    for (int i = 0; i < PAR_THREADS; i++) {
        args[i].sh = &sh;
        args[i].idx = i;
        if (pthread_create(&th[i], NULL, par_worker, &args[i]) != 0) {
            printf("E7: only %d/%d threads started... FAIL\n", i, PAR_THREADS);
            fflush(stdout);
            exit(1);
        }
    }
    for (int i = 0; i < PAR_THREADS; i++)
        pthread_join(th[i], NULL);
    zcl_barrier_destroy(&sh.barrier);
    zcl_log_level_set(saved_level);
    printf("E7: %d threads x %d verifications through one key, %d wrong verdicts... ",
           PAR_THREADS, PAR_ROUNDS, atomic_load(&sh.wrong));
    if (atomic_load(&sh.wrong) == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    sprout_phgr_set_vk(NULL);
    ppzksnark_vk_free(&vk);
    return failures;
}

/* ── driver ───────────────────────────────────────────────────── */

static int run_engine(int which, const char *label)
{
    int failures = 0;
    if (!bn254_test_select_engine(which)) {
        printf("engine %s: not available on this CPU, skipped\n", label);
        return 0;
    }
    printf("\n-- engine instance: %s (%s) --\n", label, bn254_test_engine_name());
    failures += check_tower_ops();
    failures += check_pairing();
    failures += check_decoders();
    failures += check_subgroup_test();
    failures += check_msm();
    failures += check_verify_engine();
    failures += check_edge_values();
    failures += check_identity_proofs();
    return failures;
}

int test_bn254_engine_parity(void);
int test_bn254_engine_parity(void)
{
    printf("\n=== BN254 pairing engine parity with the original implementation ===\n");
    int failures = 0;

    /* The concurrent run goes first, on the automatically selected engine, so
     * the first-use initialisation of the shared tables races for real. */
    failures += check_concurrency();
    failures += check_subgroup_identities();
    failures += run_engine(1, "portable multiply");
    failures += run_engine(2, "BMI2+ADX multiply");
    (void)bn254_test_select_engine(0);
    failures += check_concurrency();

    printf("BN254 pairing engine parity: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
