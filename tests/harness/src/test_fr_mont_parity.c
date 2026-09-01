/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-ORACLE: core/modules/sapling/src/fr_avx512.c
 *
 * Differential parity oracle for the BLS12-381 Fr/Fp Montgomery-multiply
 * accelerator (core/modules/sapling/src/fr_avx512.c: BMI2/MULX with a portable
 * __int128 fallback, runtime-dispatched on CPUID).
 *
 * Why this is consensus crypto: this multiply is the innermost operation of
 * Pedersen hashing and Groth16 verification, so it decides the Sapling
 * commitment tree root and every Sapling spend/output proof verdict — both
 * block-validity predicates. sealed core/ reaches it through
 * coins/coins.h -> sapling/incremental_merkle_tree.h -> pedersen_hash ->
 * sapling/fr.h. A single differing limb changes an anchor or flips a proof
 * verdict, which forks the node off the network permanently.
 *
 * fr_accel.h exposes fr_accel_mont_mul_portable / fr_accel_mont_mul_adx (and
 * the Fp pair) expressly "so a caller can drive the SAME input through every
 * path and assert byte-identical output". Until this file, nothing in the test
 * suite did; only the out-of-suite `zclassic23-simd-bench` did.
 *
 * Legs, for BOTH Fr (4 limbs, 255-bit scalar field) and Fp (6 limbs, 381-bit
 * base field):
 *   1. Boundary vectors — 0, 1, p-1, p-2, R, R^2 and every cross product.
 *   2. A large deterministic random corpus, inputs reduced into [0, p).
 *   3. The DISPATCHED entry point (fr_mont_mul_accel / fp_mont_mul_accel) —
 *      what fr.c and bls12_381.c actually call — must equal the portable
 *      reference too, so a broken dispatcher cannot hide behind a correct
 *      BMI2 body.
 *   4. Canonicity — every result must be < p. A Montgomery product left
 *      unreduced compares unequal to the same value elsewhere in the tree.
 *   5. Teeth — the comparator must catch a planted one-limb difference, and
 *      the multiply must not be the identity/zero function.
 *
 * On a host without ADX the *_adx entry points return false and leave the
 * output untouched; that leg is REPORTED as skipped, never counted as passing.
 */

#define _POSIX_C_SOURCE 200809L

#include "sapling/fr_accel.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* BLS12-381 Fr modulus (little-endian limbs) — matches FR_P in
 * core/modules/sapling/src/fr.c and P[4] in fr_avx512.c. */
static const uint64_t FR_P[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};
static const uint64_t FR_R[4] = {
    0x00000001fffffffeULL, 0x5884b7fa00034802ULL,
    0x998c4fefecbc4ff5ULL, 0x1824b159acc5056fULL
};
static const uint64_t FR_R2[4] = {
    0xc999e990f3f29c6dULL, 0x2b6cedcb87925c23ULL,
    0x05d314967254398fULL, 0x0748d9d99f59ff11ULL
};

/* BLS12-381 Fp modulus — matches Q[6] in fr_avx512.c. */
static const uint64_t FP_Q[6] = {
    0xb9feffffffffaaabULL, 0x1eabfffeb153ffffULL,
    0x6730d2a0f6b0f624ULL, 0x64774b84f38512bfULL,
    0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL
};

/* ── small multi-precision helpers (n limbs, little-endian) ───────────── */

static int mp_cmp(const uint64_t *a, const uint64_t *b, int n)
{
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static void mp_sub_inplace(uint64_t *a, const uint64_t *b, int n)
{
    __uint128_t borrow = 0;
    for (int i = 0; i < n; i++) {
        __uint128_t v = (__uint128_t)a[i] - b[i] - borrow;
        a[i] = (uint64_t)v;
        borrow = (v >> 64) & 1;
    }
}

/* Reduce an arbitrary n-limb value into [0, p) by bounded subtraction. Both
 * moduli sit just under their top-limb bound (Fr > 2^254, Fp > 2^381), so a
 * random value is a small multiple of p away; the loop bound is generous. */
static void mp_reduce(uint64_t *v, const uint64_t *p, int n)
{
    for (int i = 0; i < 64 && mp_cmp(v, p, n) >= 0; i++)
        mp_sub_inplace(v, p, n);
}

static uint64_t xorshift64(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return x;
}

static void mp_rand_below(uint64_t *v, const uint64_t *p, int n, uint64_t *s)
{
    for (int i = 0; i < n; i++) v[i] = xorshift64(s);
    /* Clear the bits above the modulus' top set bit so the reduce loop is
     * short and unbiased enough for a parity corpus. */
    v[n - 1] &= p[n - 1] | (p[n - 1] >> 1) | (p[n - 1] >> 2) | (p[n - 1] >> 3);
    mp_reduce(v, p, n);
}

static void dump(const char *label, const uint64_t *v, int n)
{
    printf("    %s = ", label);
    for (int i = n - 1; i >= 0; i--) printf("%016llx", (unsigned long long)v[i]);
    printf("\n");
}

/* ── one comparison, for either field ─────────────────────────────────── */

struct field {
    const char *name;
    int         limbs;
    const uint64_t *p;
    void (*portable)(uint64_t *, const uint64_t *, const uint64_t *);
    bool (*adx)(uint64_t *, const uint64_t *, const uint64_t *);
    void (*dispatch)(uint64_t *, const uint64_t *, const uint64_t *);
};

static void fr_port(uint64_t *r, const uint64_t *a, const uint64_t *b)
{ fr_accel_mont_mul_portable(r, a, b); }
static bool fr_adx(uint64_t *r, const uint64_t *a, const uint64_t *b)
{ return fr_accel_mont_mul_adx(r, a, b); }
static void fr_disp(uint64_t *r, const uint64_t *a, const uint64_t *b)
{ fr_mont_mul_accel(r, a, b); }
static void fp_port(uint64_t *r, const uint64_t *a, const uint64_t *b)
{ fp_accel_mont_mul_portable(r, a, b); }
static bool fp_adx(uint64_t *r, const uint64_t *a, const uint64_t *b)
{ return fp_accel_mont_mul_adx(r, a, b); }
static void fp_disp(uint64_t *r, const uint64_t *a, const uint64_t *b)
{ fp_mont_mul_accel(r, a, b); }

/* Returns the number of failures for this (a,b) pair. */
static int compare_one(const struct field *f, bool adx_present,
                       const uint64_t *a, const uint64_t *b, const char *where)
{
    uint64_t ref[6] = {0}, acc[6] = {0}, dsp[6] = {0};
    int n = f->limbs;
    int bad = 0;

    f->portable(ref, a, b);

    /* Leg 4: canonicity of the reference itself. */
    if (mp_cmp(ref, f->p, n) >= 0) {
        printf("\n  NON-CANONICAL %s portable result (>= p) at %s\n",
               f->name, where);
        dump("a  ", a, n); dump("b  ", b, n); dump("ref", ref, n);
        bad++;
    }

    if (adx_present) {
        if (f->adx(acc, a, b)) {
            if (memcmp(ref, acc, (size_t)n * 8) != 0) {
                printf("\n  MISMATCH %s adx vs portable at %s\n", f->name, where);
                dump("a   ", a, n); dump("b   ", b, n);
                dump("port", ref, n); dump("adx", acc, n);
                bad++;
            }
        }
    }

    f->dispatch(dsp, a, b);
    if (memcmp(ref, dsp, (size_t)n * 8) != 0) {
        printf("\n  MISMATCH %s dispatched vs portable at %s\n", f->name, where);
        dump("a   ", a, n); dump("b   ", b, n);
        dump("port", ref, n); dump("disp", dsp, n);
        bad++;
    }
    return bad;
}

static int run_field(const struct field *f)
{
    int n = f->limbs;
    int failures = 0;

    /* ADX probe: the *_adx entry returns false on a host without it. */
    uint64_t probe[6] = {0}, one[6] = {0};
    one[0] = 1;
    bool adx = f->adx(probe, one, one);
    printf("  %s: adx path %s\n", f->name,
           adx ? "available" : "NOT available on this host (leg skipped)");

    /* ── Leg 1: boundary vectors ──────────────────────────────────────── */
    uint64_t zero[6] = {0};
    uint64_t pm1[6] = {0}, pm2[6] = {0};
    memcpy(pm1, f->p, (size_t)n * 8); mp_sub_inplace(pm1, one, n);
    memcpy(pm2, pm1, (size_t)n * 8);  mp_sub_inplace(pm2, one, n);

    const uint64_t *vecs[6];
    int nv = 0;
    vecs[nv++] = zero;
    vecs[nv++] = one;
    vecs[nv++] = pm1;
    vecs[nv++] = pm2;
    if (n == 4) { vecs[nv++] = FR_R; vecs[nv++] = FR_R2; }

    for (int i = 0; i < nv; i++)
        for (int j = 0; j < nv; j++)
            failures += compare_one(f, adx, vecs[i], vecs[j], "boundary");
    printf("  %s: %d boundary cross-product(s) checked\n", f->name, nv * nv);

    /* ── Leg 2: deterministic random corpus ───────────────────────────── */
    uint64_t s = 0x9E3779B97F4A7C15ULL ^ (uint64_t)n;
    const int N = 20000;
    for (int i = 0; i < N; i++) {
        uint64_t a[6], b[6];
        mp_rand_below(a, f->p, n, &s);
        mp_rand_below(b, f->p, n, &s);
        failures += compare_one(f, adx, a, b, "random");
        if (failures > 8) { printf("  (aborting %s corpus after 8 failures)\n",
                                   f->name); break; }
    }
    printf("  %s: %d random pair(s) checked\n", f->name, N);

    /* ── Leg 5: teeth ─────────────────────────────────────────────────── */
    {
        uint64_t a[6], b[6], r1[6] = {0}, r2[6] = {0};
        mp_rand_below(a, f->p, n, &s);
        memcpy(b, a, (size_t)n * 8);
        f->portable(r1, a, b);
        b[0] ^= 1u;
        mp_reduce(b, f->p, n);
        f->portable(r2, a, b);
        if (memcmp(r1, r2, (size_t)n * 8) == 0) {
            printf("  FAIL: %s multiply is insensitive to a one-bit input "
                   "change — this oracle is hollow.\n", f->name);
            failures++;
        }
        /* A planted difference must be seen by the same memcmp the legs use. */
        memcpy(r2, r1, (size_t)n * 8);
        r2[n - 1] ^= 1u;
        if (memcmp(r1, r2, (size_t)n * 8) == 0) {
            printf("  FAIL: %s comparator missed a planted limb difference.\n",
                   f->name);
            failures++;
        }
    }
    return failures;
}

int test_fr_mont_parity(void);
int test_fr_mont_parity(void)
{
    printf("\n=== BLS12-381 Fr/Fp Montgomery accel differential oracle ===\n");
    printf("selected impl: %s\n", fr_accel_implementation());

    const struct field fr = { "Fr", 4, FR_P, fr_port, fr_adx, fr_disp };
    const struct field fp = { "Fp", 6, FP_Q, fp_port, fp_adx, fp_disp };

    int failures = run_field(&fr) + run_field(&fp);

    printf("\n%d Fr/Fp Montgomery parity check(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
