/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FROZEN ORACLE: the BLS12-381 Fp add/sub/neg exactly as they were before the
 * branch-free inline rewrite (compare-then-conditional-subtract). Copied
 * verbatim and renamed with an oracle_ prefix. NEVER EDIT. Included by
 * tests/harness/src/test_bls12_381_fp_addsub_parity.c. */
#include "sapling/bls12_381.h"
#include <string.h>
#include <stdint.h>

static const uint64_t ORACLE_FP_Q[6] = {
    0xb9feffffffffaaabULL, 0x1eabfffeb153ffffULL,
    0x6730d2a0f6b0f624ULL, 0x64774b84f38512bfULL,
    0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL
};

static bool oracle_fp_gte(const uint64_t a[6], const uint64_t b[6])
{
    for (int i = 5; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

static void oracle_fp_sub_noborrow(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 tmp = (unsigned __int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)tmp;
        borrow = (tmp >> 127) & 1;
    }
}

static void oracle_fp_zero(struct fp *r) { memset(r->d, 0, 48); }

static bool oracle_fp_is_zero(const struct fp *a)
{
    for (int i = 0; i < 6; i++)
        if (a->d[i] != 0) return false;
    return true;
}

static void oracle_fp_add(struct fp *r, const struct fp *a, const struct fp *b)
{
    unsigned __int128 carry = 0;
    uint64_t tmp[6];
    for (int i = 0; i < 6; i++) {
        unsigned __int128 sum = (unsigned __int128)a->d[i] + b->d[i] + carry;
        tmp[i] = (uint64_t)sum;
        carry = sum >> 64;
    }
    if (carry || oracle_fp_gte(tmp, ORACLE_FP_Q))
        oracle_fp_sub_noborrow(r->d, tmp, ORACLE_FP_Q);
    else
        memcpy(r->d, tmp, 48);
}

static void oracle_fp_sub(struct fp *r, const struct fp *a, const struct fp *b)
{
    if (oracle_fp_gte(a->d, b->d)) {
        oracle_fp_sub_noborrow(r->d, a->d, b->d);
    } else {
        uint64_t tmp[6];
        unsigned __int128 carry = 0;
        for (int i = 0; i < 6; i++) {
            unsigned __int128 sum = (unsigned __int128)a->d[i] + ORACLE_FP_Q[i] + carry;
            tmp[i] = (uint64_t)sum;
            carry = sum >> 64;
        }
        oracle_fp_sub_noborrow(r->d, tmp, b->d);
    }
}

static void oracle_fp_neg(struct fp *r, const struct fp *a)
{
    if (oracle_fp_is_zero(a))
        oracle_fp_zero(r);
    else
        oracle_fp_sub_noborrow(r->d, ORACLE_FP_Q, a->d);
}

/* ---- Final exponentiation exactly as at d8225b30f (generic fp12_sq inside
 * exp-by-x), before the cyclotomic-squaring rewrite. Verbatim, oracle_
 * prefix; the fp12 field ops it calls are the public ones. Included by
 * tests/harness/src/test_bls12_381_final_exp_parity.c. NEVER EDIT. */
#ifdef ORACLE_WITH_FINAL_EXP
#define ORACLE_BLS_X 0xd201000000010000ULL

static void oracle_fp12_pow_u64(struct fp12 *r, const struct fp12 *a, uint64_t exp)
{
    struct fp12 result;
    fp12_one(&result);
    struct fp12 base = *a;

    while (exp > 0) {
        if (exp & 1)
            fp12_mul(&result, &result, &base);
        fp12_sq(&base, &base);
        exp >>= 1;
    }
    *r = result;
}

static void oracle_bls12_381_final_exp(struct fp12 *result, const struct fp12 *f_in)
{
    struct fp12 f = *f_in;

    struct fp12 f1 = f;
    fp12_conjugate(&f1);

    struct fp12 f2;
    fp12_inv(&f2, &f);
    fp12_mul(&f, &f1, &f2);
    f2 = f;
    fp12_frobenius_map(&f, 2);
    fp12_mul(&f, &f, &f2);

    struct fp12 y0, y1, y2, y3;

    struct fp12 r_save = f;

    fp12_sq(&y0, &f);

    oracle_fp12_pow_u64(&y1, &y0, ORACLE_BLS_X);
    fp12_conjugate(&y1);

    oracle_fp12_pow_u64(&y2, &y1, ORACLE_BLS_X >> 1);
    fp12_conjugate(&y2);

    y3 = r_save;
    fp12_conjugate(&y3);
    fp12_mul(&y1, &y1, &y3);
    fp12_conjugate(&y1);
    fp12_mul(&y1, &y1, &y2);

    oracle_fp12_pow_u64(&y2, &y1, ORACLE_BLS_X);
    fp12_conjugate(&y2);

    oracle_fp12_pow_u64(&y3, &y2, ORACLE_BLS_X);
    fp12_conjugate(&y3);

    fp12_conjugate(&y1);
    fp12_mul(&y3, &y3, &y1);

    fp12_conjugate(&y1);
    fp12_frobenius_map(&y1, 3);

    fp12_frobenius_map(&y2, 2);
    fp12_mul(&y1, &y1, &y2);

    oracle_fp12_pow_u64(&y2, &y3, ORACLE_BLS_X);
    fp12_conjugate(&y2);
    fp12_mul(&y2, &y2, &y0);
    fp12_mul(&y2, &y2, &r_save);
    fp12_mul(&y1, &y1, &y2);

    y2 = y3;
    fp12_frobenius_map(&y2, 1);
    fp12_mul(&y1, &y1, &y2);

    *result = y1;
}
#endif /* ORACLE_WITH_FINAL_EXP */
