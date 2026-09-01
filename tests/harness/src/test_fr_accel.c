/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Differential parity oracle for the BLS12-381 Fr (4-limb) and Fp (6-limb)
 * Montgomery-multiply accelerators (core/modules/sapling/src/fr_avx512.c).
 *
 * BN254 Fq already had test_bn254_accel; Fr and Fp did not, even though every
 * Sapling Groth16 proof verifies through them and they carry the same
 * accept/reject consequence. The only in-tree parity check they had was
 * simd_bench's single vector, which is a smoke test, not an oracle. This is the
 * oracle: the accelerated path must be BIT-IDENTICAL to the portable __int128
 * reference on every input, or a Sapling proof could accept or reject
 * differently — a chain split.
 *
 * Corpus: boundary vectors (0, 1, p-1, p-2, and every cross product of them,
 * which is what exercises the final conditional subtraction in both directions)
 * plus a large deterministic random corpus reduced into [0, p). */

#include "test/test_core.h"
#include "sapling/fr_accel.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static const uint64_t FR_P[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};
static const uint64_t FP_Q[6] = {
    0xb9feffffffffaaabULL, 0x1eabfffeb153ffffULL,
    0x6730d2a0f6b0f624ULL, 0x64774b84f38512bfULL,
    0x4b1ba7b6434bacd7ULL, 0x1a0111ea397fe69aULL
};

static bool ge_n(const uint64_t *a, const uint64_t *b, int n)
{
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

static void sub_n(uint64_t *a, const uint64_t *b, int n)
{
    uint64_t borrow = 0;
    for (int i = 0; i < n; i++) {
        uint64_t ai = a[i], bi = b[i];
        uint64_t p = ai - bi;
        uint64_t b1 = (uint64_t)(ai < bi);
        a[i] = p - borrow;
        borrow = b1 | (uint64_t)(p < borrow);
    }
}

/* A random 4-limb value is at most ~3.6x p and a 6-limb one at most ~9.8x q, so
 * a bounded subtract loop reduces exactly. */
static void reduce_n(uint64_t *v, const uint64_t *m, int n)
{
    for (int k = 0; k < 16 && ge_n(v, m, n); k++)
        sub_n(v, m, n);
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static uint64_t next_rand(void)
{
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return x;
}

static void rand_field(uint64_t *v, const uint64_t *m, int n)
{
    for (int i = 0; i < n; i++) v[i] = next_rand();
    reduce_n(v, m, n);
}

static int cmp_report(const char *label, const uint64_t *ref,
                      const uint64_t *got, int n,
                      const uint64_t *a, const uint64_t *b)
{
    if (memcmp(ref, got, (size_t)n * 8) == 0)
        return 0;
    printf("\n  MISMATCH %s: a[0]=%016llx b[0]=%016llx ref[0]=%016llx got[0]=%016llx\n",
           label, (unsigned long long)a[0], (unsigned long long)b[0],
           (unsigned long long)ref[0], (unsigned long long)got[0]);
    return 1;
}

static int check_fr(const uint64_t a[4], const uint64_t b[4], bool have_adx)
{
    uint64_t ref[4] = {0}, acc[4] = {0}, disp[4] = {0};
    fr_accel_mont_mul_portable(ref, a, b);
    fr_mont_mul_accel(disp, a, b);
    int bad = cmp_report("Fr dispatch vs portable", ref, disp, 4, a, b);
    if (have_adx && fr_accel_mont_mul_adx(acc, a, b))
        bad += cmp_report("Fr adx vs portable", ref, acc, 4, a, b);
    return bad;
}

static int check_fp(const uint64_t a[6], const uint64_t b[6], bool have_adx)
{
    uint64_t ref[6] = {0}, acc[6] = {0}, disp[6] = {0};
    fp_accel_mont_mul_portable(ref, a, b);
    fp_mont_mul_accel(disp, a, b);
    int bad = cmp_report("Fp dispatch vs portable", ref, disp, 6, a, b);
    if (have_adx && fp_accel_mont_mul_adx(acc, a, b))
        bad += cmp_report("Fp adx vs portable", ref, acc, 6, a, b);
    return bad;
}

int test_fr_accel(void);

int test_fr_accel(void)
{
    int failures = 0;

    printf("\n=== BLS12-381 Fr/Fp accel differential oracle ===\n");
    printf("selected impl: %s\n", fr_accel_implementation());

    uint64_t probe4[4] = {0}, probe6[6] = {0};
    bool adx4 = fr_accel_mont_mul_adx(probe4, FR_P, FR_P);
    bool adx6 = fp_accel_mont_mul_adx(probe6, FP_Q, FP_Q);
    if (!adx4 || !adx6)
        printf("(host lacks BMI2+ADX — portable/dispatch coverage only)\n");

    /* ── Boundary vectors ─────────────────────────────────────────── */
    printf("boundary vectors... ");
    {
        uint64_t one4[4] = {1, 0, 0, 0};
        uint64_t z4[4] = {0}, m1_4[4], m2_4[4];
        memcpy(m1_4, FR_P, 32); sub_n(m1_4, one4, 4);
        memcpy(m2_4, m1_4, 32); sub_n(m2_4, one4, 4);
        const uint64_t *v4[] = { z4, one4, m1_4, m2_4 };
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                failures += check_fr(v4[i], v4[j], adx4);

        uint64_t one6[6] = {1, 0, 0, 0, 0, 0};
        uint64_t z6[6] = {0}, m1_6[6], m2_6[6];
        memcpy(m1_6, FP_Q, 48); sub_n(m1_6, one6, 6);
        memcpy(m2_6, m1_6, 48); sub_n(m2_6, one6, 6);
        const uint64_t *v6[] = { z6, one6, m1_6, m2_6 };
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                failures += check_fp(v6[i], v6[j], adx6);
    }
    printf("%s\n", failures ? "FAILED" : "OK");

    /* ── Random corpus ────────────────────────────────────────────── */
    {
        const int N = 100000;
        int before = failures;
        printf("random corpus (%d Fr + %d Fp vectors)... ", N, N);
        for (int k = 0; k < N; k++) {
            uint64_t a[4], b[4];
            rand_field(a, FR_P, 4);
            rand_field(b, FR_P, 4);
            /* Bias a slice of the corpus onto p-1, the value that most often
             * forces the final conditional subtraction. */
            if ((k & 15) == 0) { memcpy(b, FR_P, 32); b[0]--; }
            failures += check_fr(a, b, adx4);
            if (failures > before + 4) break;
        }
        for (int k = 0; k < N; k++) {
            uint64_t a[6], b[6];
            rand_field(a, FP_Q, 6);
            rand_field(b, FP_Q, 6);
            if ((k & 15) == 0) { memcpy(b, FP_Q, 48); b[0]--; }
            failures += check_fp(a, b, adx6);
            if (failures > before + 4) break;
        }
        printf("%s\n", failures > before ? "FAILED" : "OK");
    }

    printf("\n%d BLS12-381 Fr/Fp accel test(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
