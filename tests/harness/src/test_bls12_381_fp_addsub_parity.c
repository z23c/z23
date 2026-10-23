/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/sapling/src/bls12_381.c
 * Bit-for-bit parity of the branch-free inline BLS12-381 fp_add / fp_sub /
 * fp_neg (core/modules/sapling/src/bls12_381_fp_inline.h) against the FROZEN
 * pre-rewrite implementation (tests/harness/differential/
 * bls12_381_oracle_frozen.c, oracle_ prefix, never edited). Covers random
 * canonical pairs, boundary values, and non-canonical 384-bit inputs, since
 * the old code's behaviour for inputs >= q (single conditional subtract,
 * wrap mod 2^384) is preserved exactly. */

#pragma GCC diagnostic ignored "-Wpedantic"

#include "test/test_core.h"
#include "sapling/bls12_381.h"
#include "../differential/bls12_381_oracle_frozen.c"

#include <stdio.h>

#define PARITY_RANDOM_PAIRS 10000000ULL

static uint64_t g_state = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
    uint64_t z = (g_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static bool parity_one(const struct fp *a, const struct fp *b)
{
    struct fp x, y;
    fp_add(&x, a, b);
    oracle_fp_add(&y, a, b);
    if (memcmp(&x, &y, sizeof x) != 0) return false;
    fp_sub(&x, a, b);
    oracle_fp_sub(&y, a, b);
    if (memcmp(&x, &y, sizeof x) != 0) return false;
    fp_neg(&x, a);
    oracle_fp_neg(&y, a);
    if (memcmp(&x, &y, sizeof x) != 0) return false;
    /* aliasing: r == a */
    struct fp t = *a, u = *a;
    fp_add(&t, &t, b);
    oracle_fp_add(&u, &u, b);
    if (memcmp(&t, &u, sizeof t) != 0) return false;
    t = *a; u = *a;
    fp_sub(&t, &t, b);
    oracle_fp_sub(&u, &u, b);
    return memcmp(&t, &u, sizeof t) == 0;
}

/* q +/- small, built from ORACLE_FP_Q */
static void q_plus(struct fp *r, int64_t delta)
{
    memcpy(r->d, ORACLE_FP_Q, 48);
    if (delta >= 0) {
        uint64_t add = (uint64_t)delta;
        for (int i = 0; i < 6 && add; i++) {
            uint64_t old = r->d[i];
            r->d[i] += add;
            add = r->d[i] < old;
        }
    } else {
        uint64_t sub = (uint64_t)(-delta);
        for (int i = 0; i < 6 && sub; i++) {
            uint64_t old = r->d[i];
            r->d[i] -= sub;
            sub = r->d[i] > old;
        }
    }
}

static void raw_sub(uint64_t r[6], const uint64_t a[6], const uint64_t b[6])
{
    unsigned __int128 br = 0;
    for (int i = 0; i < 6; i++) {
        unsigned __int128 d = (unsigned __int128)a[i] - b[i] - br;
        r[i] = (uint64_t)d;
        br = (d >> 64) & 1;
    }
}

static void half_q_minus_1(struct fp *r)
{
    q_plus(r, -1);
    uint64_t c = 0;
    for (int i = 5; i >= 0; i--) {
        uint64_t n = (r->d[i] >> 1) | (c << 63);
        c = r->d[i] & 1;
        r->d[i] = n;
    }
}

static void limb_fill(struct fp *r, uint64_t v)
{
    for (int i = 0; i < 6; i++) r->d[i] = v;
}

static int boundary_values(struct fp *v)
{
    int n = 0;
    memset(&v[n++], 0, sizeof(struct fp));
    memset(&v[n], 0, sizeof(struct fp)); v[n++].d[0] = 1;
    q_plus(&v[n++], -1);
    q_plus(&v[n++], -2);
    half_q_minus_1(&v[n++]);
    q_plus(&v[n++], 0);
    q_plus(&v[n++], 1);
    q_plus(&v[n++], 2);
    limb_fill(&v[n++], ~0ULL);
    limb_fill(&v[n++], 0x8000000000000000ULL);
    memset(&v[n], 0, sizeof(struct fp)); v[n++].d[5] = ~0ULL;
    memset(&v[n], 0, sizeof(struct fp)); v[n++].d[0] = ~0ULL;
    return n;
}

static bool boundary_pairs(void)
{
    struct fp v[16];
    int n = boundary_values(v);
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            if (!parity_one(&v[i], &v[j])) return false;
    /* pairs summing exactly to q-1, q, q+1 (a + b = q + k) */
    for (int64_t k = -1; k <= 1; k++) {
        struct fp s, a, b;
        q_plus(&s, k);
        for (int t = 0; t < 64; t++) {
            for (int i = 0; i < 6; i++) a.d[i] = rnd() >> (t % 3);
            a.d[5] &= 0x0fffffffffffffffULL;
            raw_sub(b.d, s.d, a.d);
            if (!parity_one(&a, &b) || !parity_one(&b, &a)) return false;
            if (!parity_one(&a, &a)) return false;
        }
    }
    return true;
}

static bool random_pairs(uint64_t count)
{
    for (uint64_t k = 0; k < count; k++) {
        struct fp a, b;
        for (int i = 0; i < 6; i++) { a.d[i] = rnd(); b.d[i] = rnd(); }
        if (k & 1) {                      /* mostly canonical: clear top bits */
            a.d[5] &= 0x1a0111ea397fe69aULL;
            b.d[5] &= 0x1a0111ea397fe69aULL;
        }
        if ((k & 7) == 2) { b = a; }
        if ((k & 7) == 4) { memcpy(b.d, a.d, 40); b.d[5] = a.d[5] ^ (rnd() & 3); }
        if (!parity_one(&a, &b)) {
            printf("  mismatch at pair %llu\n", (unsigned long long)k);
            return false;
        }
    }
    return true;
}

int test_bls12_381_fp_addsub_parity(void);
int test_bls12_381_fp_addsub_parity(void)
{
    int failures = 0;
    printf("bls12_381_fp_addsub_parity: boundaries + sum-to-q pairs... ");
    if (boundary_pairs()) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }

    printf("bls12_381_fp_addsub_parity: %llu random pairs vs frozen oracle... ",
           (unsigned long long)PARITY_RANDOM_PAIRS);
    if (random_pairs(PARITY_RANDOM_PAIRS)) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}
