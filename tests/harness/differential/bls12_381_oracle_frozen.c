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
