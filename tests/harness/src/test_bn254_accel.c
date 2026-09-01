/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/sapling/src/bn254_accel.c
 *
 * Differential parity oracle for the BN254 Fq Montgomery-multiply accelerator
 * (core/modules/sapling/src/bn254_accel.c). BN254 Fq is consensus-frozen crypto — every
 * accelerated path (BMI2+ADX, and the runtime-dispatched entry) MUST return a
 * BIT-IDENTICAL canonical product to the portable __uint128 reference for every
 * input, or a Sprout Groth16 proof could accept/reject differently.
 *
 * This asserts byte-identity of every implementation against the portable
 * reference over:
 *   - a large deterministic random corpus (inputs reduced into [0, q)),
 *   - boundary vectors: 0, 1, q-1, q-2, R, R^2, and cross products of them,
 *   - the dispatched bn_fq_mont_mul_accel (what bn254.c actually calls).
 * The self-consistency Montgomery identities (mul by R == to-Montgomery, etc.)
 * are covered by test_bn254; here the sole job is scalar-vs-accel equality. */

#include "test/test_core.h"
#include "sapling/bn254_accel.h"
#include "platform/time_compat.h"

#include <stdint.h>
#include <string.h>

/* q, R = 2^256 mod q, R^2 mod q (little-endian) — the same constants as
 * bn254.c / bn254_accel.c. */
static const uint64_t Q[4] = {
    0x3c208c16d87cfd47ULL, 0x97816a916871ca8dULL,
    0xb85045b68181585dULL, 0x30644e72e131a029ULL
};
static const uint64_t R[4] = {
    0xd35d438dc58f0d9dULL, 0x0a78eb28f5c70b3dULL,
    0x666ea36f7879462cULL, 0x0e0a77c19a07df2fULL
};
static const uint64_t R2[4] = {
    0xf32cfc5b538afa89ULL, 0xb5e71911d44501fbULL,
    0x47ab1eff0a417ff6ULL, 0x06d89f71cab8351fULL
};

static int u256_cmp(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static void u256_sub_inplace(uint64_t a[4], const uint64_t b[4])
{
    __uint128_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        __uint128_t v = (__uint128_t)a[i] - b[i] - borrow;
        a[i] = (uint64_t)v;
        borrow = (v >> 64) & 1;
    }
}

/* Reduce an arbitrary 256-bit value into [0, q). q > 2^253 so a random 256-bit
 * value is at most ~5.35q; a bounded subtract loop is exact. */
static void reduce_mod_q(uint64_t v[4])
{
    for (int guard = 0; guard < 8 && u256_cmp(v, Q) >= 0; guard++)
        u256_sub_inplace(v, Q);
}

static uint64_t splitmix64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void rand_fq(uint64_t v[4], uint64_t *s)
{
    for (int i = 0; i < 4; i++)
        v[i] = splitmix64(s);
    reduce_mod_q(v);
}

/* Assert every accel path agrees with portable for a*b. Returns 1 on mismatch
 * (and prints the offending vector), 0 on agreement. */
static int check_pair(const uint64_t a[4], const uint64_t b[4],
                      bool adx_available)
{
    uint64_t ref[4], disp[4];
    bn254_accel_mont_mul_portable(ref, a, b);
    bn_fq_mont_mul_accel(disp, a, b);
    if (memcmp(ref, disp, 32) != 0) {
        printf("\n  MISMATCH dispatch vs portable: "
               "a=%016llx.. b=%016llx.. ref[0]=%016llx disp[0]=%016llx\n",
               (unsigned long long)a[0], (unsigned long long)b[0],
               (unsigned long long)ref[0], (unsigned long long)disp[0]);
        return 1;
    }
    if (adx_available) {
        uint64_t adx[4] = {0};
        bool ran = bn254_accel_mont_mul_adx(adx, a, b);
        if (ran && memcmp(ref, adx, 32) != 0) {
            printf("\n  MISMATCH adx vs portable: "
                   "a=%016llx.. b=%016llx.. ref[0]=%016llx adx[0]=%016llx\n",
                   (unsigned long long)a[0], (unsigned long long)b[0],
                   (unsigned long long)ref[0], (unsigned long long)adx[0]);
            return 1;
        }
    }
    return 0;
}

int test_bn254_accel(void);
int test_bn254_accel(void)
{
    int failures = 0;

    printf("\n=== BN254 Fq accel differential oracle ===\n");
    printf("selected impl: %s\n", bn254_accel_implementation());

    /* Probe BMI2+ADX availability once: a false return means the host lacks it
     * (the differential test then covers portable+dispatch only). */
    uint64_t probe[4] = {0};
    bool adx = bn254_accel_mont_mul_adx(probe, R, R);

    /* ── Boundary vectors ─────────────────────────────────────────── */
    printf("boundary vectors... ");
    {
        uint64_t zero[4] = {0, 0, 0, 0};
        uint64_t one[4]  = {1, 0, 0, 0};
        uint64_t qm1[4]; memcpy(qm1, Q, 32); u256_sub_inplace(qm1, one);
        uint64_t qm2[4]; memcpy(qm2, qm1, 32); u256_sub_inplace(qm2, one);

        const uint64_t *vecs[] = { zero, one, qm1, qm2, R, R2 };
        int nv = (int)(sizeof(vecs) / sizeof(vecs[0]));
        int bad = 0;
        for (int i = 0; i < nv; i++)
            for (int j = 0; j < nv; j++)
                bad += check_pair(vecs[i], vecs[j], adx);
        if (bad) { failures += bad; printf("FAIL (%d)\n", bad); }
        else printf("OK\n");
    }

    /* ── Large random corpus ──────────────────────────────────────── */
    printf("random corpus (200000 vectors)... ");
    {
        uint64_t s = 0xB19254ACCE1D0001ULL;
        int bad = 0;
        for (int k = 0; k < 200000; k++) {
            uint64_t a[4], b[4];
            rand_fq(a, &s);
            rand_fq(b, &s);
            bad += check_pair(a, b, adx);
            if (bad >= 4) break;   /* stop spamming once clearly broken */
        }
        if (bad) { failures += bad; printf("FAIL (%d)\n", bad); }
        else printf("OK\n");
    }

    /* ── Squaring path (a == b), a common hot case (fp_sq) ─────────── */
    printf("squaring corpus (50000 vectors)... ");
    {
        uint64_t s = 0x5340F1EEDCA5B002ULL;
        int bad = 0;
        for (int k = 0; k < 50000; k++) {
            uint64_t a[4];
            rand_fq(a, &s);
            bad += check_pair(a, a, adx);
            if (bad >= 4) break;
        }
        if (bad) { failures += bad; printf("FAIL (%d)\n", bad); }
        else printf("OK\n");
    }

    /* ── Micro-benchmark (diagnostic; not an assertion) ───────────── */
    printf("micro-benchmark (portable vs selected accel)...\n");
    {
        enum { N = 400000 };
        uint64_t s = 0xBEEFC0DE12345678ULL;
        uint64_t a[4], b[4], acc[4];
        rand_fq(a, &s);
        rand_fq(b, &s);
        memcpy(acc, a, 32);

        int64_t t0, t1;
        /* portable */
        t0 = platform_time_monotonic_us();
        for (int k = 0; k < N; k++)
            bn254_accel_mont_mul_portable(acc, acc, b);
        t1 = platform_time_monotonic_us();
        double ns_port = (double)(t1 - t0) * 1000.0 / (double)N;

        /* dispatched (BMI2+ADX where available) */
        memcpy(acc, a, 32);
        t0 = platform_time_monotonic_us();
        for (int k = 0; k < N; k++)
            bn_fq_mont_mul_accel(acc, acc, b);
        t1 = platform_time_monotonic_us();
        double ns_disp = (double)(t1 - t0) * 1000.0 / (double)N;

        printf("  dependent-chain (latency-bound):\n");
        printf("    portable : %.2f ns/mul\n", ns_port);
        printf("    accel    : %.2f ns/mul  (%.2fx)\n",
               ns_disp, ns_disp > 0 ? ns_port / ns_disp : 0.0);
        if (acc[0] == 0x1234567890abcdefULL) printf("  (nonce %llx)\n",
                                                    (unsigned long long)acc[1]);

        /* Independent lanes (throughput-bound) — closer to how the pairing
         * tower (Fp2/Fp6/Fp12 Karatsuba, G1/G2 formulas) consumes fp_mul: many
         * data-independent products whose latency overlaps. */
        enum { LANES = 8 };
        uint64_t la[LANES][4], lb[LANES][4];
        for (int l = 0; l < LANES; l++) { rand_fq(la[l], &s); rand_fq(lb[l], &s); }

        t0 = platform_time_monotonic_us();
        for (int k = 0; k < N; k++)
            for (int l = 0; l < LANES; l++)
                bn254_accel_mont_mul_portable(la[l], la[l], lb[l]);
        t1 = platform_time_monotonic_us();
        double tp_port = (double)(t1 - t0) * 1000.0 / ((double)N * LANES);

        for (int l = 0; l < LANES; l++) { rand_fq(la[l], &s); }
        t0 = platform_time_monotonic_us();
        for (int k = 0; k < N; k++)
            for (int l = 0; l < LANES; l++)
                bn_fq_mont_mul_accel(la[l], la[l], lb[l]);
        t1 = platform_time_monotonic_us();
        double tp_disp = (double)(t1 - t0) * 1000.0 / ((double)N * LANES);

        printf("  independent-lanes (throughput-bound):\n");
        printf("    portable : %.2f ns/mul\n", tp_port);
        printf("    accel    : %.2f ns/mul  (%.2fx)\n",
               tp_disp, tp_disp > 0 ? tp_port / tp_disp : 0.0);
        if (la[0][0] == 0x1234567890abcdefULL) printf("  (nonce %llx)\n",
                                                    (unsigned long long)la[1][1]);
    }

    printf("\n%d BN254 accel test(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
