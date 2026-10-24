/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/sapling/src/bls12_381.c
 * Parity of the endomorphism subgroup tests g1_in_subgroup / g2_in_subgroup
 * (phi(P) == -[x^2]P on G1, psi(P) == [x]P on G2; Scott eprint 2021/1130,
 * El Housni-Guillevic-Piellard eprint 2022/352) against the definitional
 * oracle [r]P == O, built here from the public API only (g1_scalar_mul by r;
 * a test-local g2 double-and-add over g2_add/g2_double). Also re-derives the
 * endomorphism constants from field arithmetic and compares them with the
 * ones the implementation uses.
 *
 * Inputs (deterministic, counter-seeded, no clock): generators, the identity,
 * negations, raw on-curve points (almost all NON-members), members ([k]G and
 * cofactor-cleared raw G1 points), pure torsion [r]Q, member+torsion sums,
 * order-3 G1 torsion (0, +-2), and Jacobian representations with Z != 1. The
 * accepted and rejected counts are each asserted >= 200 per group so the
 * test cannot pass vacuously. */

#pragma GCC diagnostic ignored "-Wpedantic"

#include "test/test_core.h"
#include "sapling/bls12_381.h"

#include <stdio.h>
#include <string.h>

#define SP_RAW 512
#define SP_MEMBERS 256
#define SP_MIN_SIDE 200

static const uint64_t SP_R[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};
/* G1 cofactor h1 = 0x396c8c005555e1568c00aaab0000aaab */
static const uint64_t SP_H1[4] = { 0x8c00aaab0000aaabULL, 0x396c8c005555e156ULL, 0, 0 };
/* p - 1 (little-endian limbs) */
static const uint64_t SP_PM1[6] = {
    0xb9feffffffffaaaaULL, 0x1eabfffeb153ffffULL, 0x6730d2a0f6b0f624ULL,
    0x64774b84f38512bfULL, 0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL
};

static const uint8_t SP_G1[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,
    0x4f,0xa9,0xac,0x0f,0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,0x6c,0x55,0xe8,0x3f,
    0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};
static const uint8_t SP_G2[96] = {
    0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,0x7d,0xac,0xd3,0xa0,
    0x88,0x27,0x4f,0x65,0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,0x33,0x4c,0xf1,0x12,
    0x13,0x94,0x5d,0x57,0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,0x26,0x08,0x05,0x27,
    0x2d,0xc5,0x10,0x51,0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,0x0b,0xac,0x03,0x26,
    0xa8,0x05,0xbb,0xef,0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};

static uint64_t g_state = 0x5b1d0c0de5eed001ULL;

static uint64_t rnd(void)
{
    uint64_t z = (g_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void rnd_fp(struct fp *r)
{
    uint8_t b[48];
    for (int i = 0; i < 48; i += 8) {
        uint64_t v = rnd();
        memcpy(b + i, &v, 8);
    }
    b[0] &= 0x0f; /* < q */
    if (!fp_from_bytes(r, b)) fp_zero(r);
}

static void rnd_fp2(struct fp2 *r) { rnd_fp(&r->c0); rnd_fp(&r->c1); }

/* ---- constants re-derived from field arithmetic ---- */

static void sp_div(uint64_t out[6], unsigned d)
{
    unsigned __int128 rem = 0;
    for (int i = 5; i >= 0; i--) {
        unsigned __int128 cur = (rem << 64) | SP_PM1[i];
        out[i] = (uint64_t)(cur / d);
        rem = cur % d;
    }
}

static void sp_fp_pow(struct fp *r, const struct fp *a, const uint64_t e[6])
{
    struct fp res, base = *a;
    fp_one(&res);
    for (int i = 0; i < 6; i++)
        for (int b = 0; b < 64; b++) {
            if ((e[i] >> b) & 1) fp_mul(&res, &res, &base);
            fp_sq(&base, &base);
        }
    *r = res;
}

static void sp_fp2_pow(struct fp2 *r, const struct fp2 *a, const uint64_t e[6])
{
    struct fp2 res, base = *a;
    fp2_one(&res);
    for (int i = 0; i < 6; i++)
        for (int b = 0; b < 64; b++) {
            if ((e[i] >> b) & 1) fp2_mul(&res, &res, &base);
            fp2_sq(&base, &base);
        }
    *r = res;
}

static bool check_constants(void)
{
    struct fp beta, one;
    struct fp2 cx, cy;
    bls12_381_endo_consts_for_test(&beta, &cx, &cy);
    fp_one(&one);
    struct fp b2, b3;
    fp_sq(&b2, &beta);
    fp_mul(&b3, &b2, &beta);
    if (!fp_eq(&b3, &one) || fp_eq(&beta, &one)) return false;

    uint64_t e3[6], e2[6];
    sp_div(e3, 3);
    sp_div(e2, 2);
    struct fp two, want_beta;
    fp_add(&two, &one, &one);
    sp_fp_pow(&want_beta, &two, e3); /* 2 is a non-cube, so this is nontrivial */
    if (!fp_eq(&want_beta, &beta)) return false;

    struct fp2 w, t, want;
    fp2_one(&w);
    fp_one(&w.c1);                   /* 1 + u */
    sp_fp2_pow(&t, &w, e3);
    fp2_inv(&want, &t);
    if (!fp2_eq(&want, &cx)) return false;
    sp_fp2_pow(&t, &w, e2);
    fp2_inv(&want, &t);
    return fp2_eq(&want, &cy);
}

/* ---- oracles ---- */

static bool ref_g1(const struct g1_point *p)
{
    struct g1_point rp;
    g1_scalar_mul(&rp, p, SP_R);
    return g1_is_identity(&rp);
}

static void g2_mul(struct g2_point *r, const struct g2_point *p, const uint64_t s[4])
{
    struct g2_point acc, base = *p, t;
    g2_identity(&acc);
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 64; b++) {
            if ((s[i] >> b) & 1) { g2_add(&t, &acc, &base); acc = t; }
            g2_double(&t, &base);
            base = t;
        }
    *r = acc;
}

static bool ref_g2(const struct g2_point *p)
{
    struct g2_point rp;
    g2_mul(&rp, p, SP_R);
    return g2_is_identity(&rp);
}

/* ---- counting checker ---- */

struct tally { int acc, rej, bad; };

static void chk1(struct tally *t, const struct g1_point *p)
{
    bool n = g1_in_subgroup(p), o = ref_g1(p);
    if (n != o) t->bad++;
    if (o) t->acc++; else t->rej++;
}

static void chk2(struct tally *t, const struct g2_point *p)
{
    bool n = g2_in_subgroup(p), o = ref_g2(p);
    if (n != o) t->bad++;
    if (o) t->acc++; else t->rej++;
}

static void chk1_all(struct tally *t, const struct g1_point *p)
{
    struct g1_point n, j = *p;
    chk1(t, p);
    g1_neg(&n, p);
    chk1(t, &n);
    if (!g1_is_identity(p)) {            /* Jacobian rescale with Z != 1 */
        struct fp l, l2, l3;
        rnd_fp(&l);
        fp_sq(&l2, &l);
        fp_mul(&l3, &l2, &l);
        fp_mul(&j.x, &p->x, &l2);
        fp_mul(&j.y, &p->y, &l3);
        fp_mul(&j.z, &p->z, &l);
        chk1(t, &j);
    }
}

static void chk2_all(struct tally *t, const struct g2_point *p)
{
    struct g2_point n, j = *p;
    chk2(t, p);
    g2_neg(&n, p);
    chk2(t, &n);
    if (!g2_is_identity(p)) {
        struct fp2 l, l2, l3;
        rnd_fp2(&l);
        fp2_sq(&l2, &l);
        fp2_mul(&l3, &l2, &l);
        fp2_mul(&j.x, &p->x, &l2);
        fp2_mul(&j.y, &p->y, &l3);
        fp2_mul(&j.z, &p->z, &l);
        chk2(t, &j);
    }
}

/* ---- raw on-curve point generators ---- */

static bool raw_g1(struct g1_point *p)
{
    struct fp x, y, rhs, four, one;
    fp_one(&one);
    fp_add(&four, &one, &one);
    fp_add(&four, &four, &four);
    rnd_fp(&x);
    fp_sq(&rhs, &x);
    fp_mul(&rhs, &rhs, &x);
    fp_add(&rhs, &rhs, &four);
    if (!fp_sqrt(&y, &rhs)) return false;
    p->x = x;
    p->y = y;
    fp_one(&p->z);
    return true;
}

static bool raw_g2(struct g2_point *p)
{
    struct fp2 x, y, rhs, b;
    struct fp one, four;
    fp_one(&one);
    fp_add(&four, &one, &one);
    fp_add(&four, &four, &four);
    b.c0 = four;
    b.c1 = four;                      /* 4(1+u) */
    rnd_fp2(&x);
    fp2_sq(&rhs, &x);
    fp2_mul(&rhs, &rhs, &x);
    fp2_add(&rhs, &rhs, &b);
    if (!fp2_sqrt(&y, &rhs)) return false;
    p->x = x;
    p->y = y;
    fp2_one(&p->z);
    return true;
}

static void rnd_scalar(uint64_t k[4])
{
    k[0] = rnd(); k[1] = rnd(); k[2] = rnd(); k[3] = 0;
}

static bool run_g1(struct tally *t, const struct g1_point *gen)
{
    struct g1_point id, p, m, q, s, tor;
    g1_identity(&id);
    chk1_all(t, &id);
    chk1_all(t, gen);
    /* order-3 torsion (0, +-2): x=0 gives y^2 = 4 */
    struct fp one, two;
    fp_one(&one);
    fp_add(&two, &one, &one);
    fp_zero(&p.x); p.y = two; fp_one(&p.z);
    chk1_all(t, &p);
    uint64_t k[4];
    for (int n = 0; n < SP_RAW;) {
        if (!raw_g1(&q)) continue;
        n++;
        chk1_all(t, &q);
        g1_scalar_mul(&tor, &q, SP_R);         /* pure torsion [r]Q */
        chk1_all(t, &tor);
        rnd_scalar(k);
        g1_scalar_mul(&m, gen, k);             /* member [k]G */
        chk1_all(t, &m);
        g1_add(&s, &m, &tor);                  /* member + torsion */
        chk1_all(t, &s);
        g1_add(&s, &m, &p);                    /* member + order-3 point */
        chk1_all(t, &s);
        if (n <= SP_MEMBERS) {
            g1_scalar_mul(&s, &q, SP_H1);      /* cofactor-cleared raw point */
            chk1_all(t, &s);
        }
    }
    return t->bad == 0 && t->acc >= SP_MIN_SIDE && t->rej >= SP_MIN_SIDE;
}

static bool run_g2(struct tally *t, const struct g2_point *gen)
{
    struct g2_point id, m, q, s, tor;
    g2_identity(&id);
    chk2_all(t, &id);
    chk2_all(t, gen);
    uint64_t k[4];
    for (int n = 0; n < SP_RAW;) {
        if (!raw_g2(&q)) continue;
        n++;
        chk2_all(t, &q);
        g2_mul(&tor, &q, SP_R);
        chk2_all(t, &tor);
        rnd_scalar(k);
        g2_mul(&m, gen, k);
        chk2_all(t, &m);
        g2_add(&s, &m, &tor);
        chk2_all(t, &s);
    }
    return t->bad == 0 && t->acc >= SP_MIN_SIDE && t->rej >= SP_MIN_SIDE;
}

int test_bls12_381_subgroup_parity(void);
int test_bls12_381_subgroup_parity(void)
{
    int failures = 0;
    struct g1_point g1;
    struct g2_point g2;

    printf("bls12_381_subgroup_parity: endomorphism constants re-derived... ");
    if (check_constants()) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }

    if (!g1_from_compressed(&g1, SP_G1) || !g2_from_compressed(&g2, SP_G2)) {
        printf("bls12_381_subgroup_parity: generators decode... FAIL\n");
        return failures + 1;
    }

    struct tally t1 = {0, 0, 0}, t2 = {0, 0, 0};
    bool ok1 = run_g1(&t1, &g1);
    printf("bls12_381_subgroup_parity: G1 vs [r]P (accepted %d, rejected %d, mismatches %d)... ",
           t1.acc, t1.rej, t1.bad);
    if (ok1) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }

    bool ok2 = run_g2(&t2, &g2);
    printf("bls12_381_subgroup_parity: G2 vs [r]P (accepted %d, rejected %d, mismatches %d)... ",
           t2.acc, t2.rej, t2.bad);
    if (ok2) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}
