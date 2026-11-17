/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-ORACLE: core/modules/sapling/src/fr_avx512.c
 *
 * Differential parity oracle for the BLS12-381 Fr/Fp Montgomery-multiply
 * accelerator (core/modules/sapling/src/fr_avx512.c: BMI2/MULX with a portable
 * __int128 fallback, runtime-dispatched on CPUID).
 *
 * Consensus crypto: this multiply is the innermost operation of Pedersen
 * hashing and Groth16 verification, so it decides the Sapling commitment
 * tree root and every Sapling proof verdict. A differing limb forks the node.
 *
 * fr_accel.h exposes fr_accel_mont_mul_portable / fr_accel_mont_mul_adx (and
 * the Fp pair) so the same input can be driven through every path and
 * compared byte-for-byte.
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
#include "sapling/fr.h"

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

/* ── Unbiased blinds: fr_from_bytes canonicalisation + fr_sample_uniform ──
 *
 * The Groth16 prover used to feed 32 raw random bytes to fr_from_bytes. A value
 * >= r reached the Montgomery multiply, where the ADX and portable tiers
 * disagree (and the result was biased besides). These legs pin the fix:
 *   a. fr_from_bytes on non-canonical bytes returns false AND yields the same
 *      element on both tiers, equal to the input reduced mod r.
 *   b. fr_sample_uniform with a scripted RNG that opens with adversarial
 *      candidates (all 0xff, exactly r, r+1) rejects them, never returns a
 *      value >= r, and accepts r-1; both tiers agree.
 *   c. A stuck source (constant 0xff) fails closed instead of looping.
 *   d. Statistics over 20000 draws: every value canonical, draws per sample
 *      near 1/0.9063 = 1.103, and the top-bit frequency near uniform-on-[0,r).
 *   e. A fixed seed reproduces the same scalar. */

#define BLIND_CHECK(name, expr) do {                          \
    printf("  blind: %s... ", (name));                        \
    if ((expr)) printf("OK\n");                               \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

struct script_rng {
    const uint8_t (*fixed)[32]; /* scripted candidates, then xorshift */
    int nfixed;
    int used;
    int total;
    uint64_t state;
    bool stuck_ff;
};

static bool script_fill(void *user, uint8_t *out, size_t n)
{
    struct script_rng *g = user;
    g->total++;
    if (g->stuck_ff) { memset(out, 0xff, n); return true; }
    if (g->used < g->nfixed) { memcpy(out, g->fixed[g->used++], n); return true; }
    for (size_t i = 0; i < n; i += 8) {
        uint64_t w = xorshift64(&g->state);
        memcpy(out + i, &w, 8);
    }
    return true;
}

static void limbs_to_le(uint8_t out[32], const uint64_t v[4])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(v[i] >> (8 * j));
}

static void le_to_limbs(uint64_t v[4], const uint8_t b[32])
{
    for (int i = 0; i < 4; i++) {
        v[i] = 0;
        for (int j = 0; j < 8; j++) v[i] |= (uint64_t)b[i * 8 + j] << (8 * j);
    }
}

static bool fr_is_canonical_bytes(const uint8_t b[32])
{
    uint64_t v[4];
    le_to_limbs(v, b);
    return mp_cmp(v, FR_P, 4) < 0;
}

static uint8_t g_cand[6][32];

static void blind_build_candidates(void)
{
    uint64_t t[4];
    memset(g_cand[0], 0xff, 32);                                /* 2^256 - 1 */
    limbs_to_le(g_cand[1], FR_P);                               /* r         */
    memcpy(t, FR_P, sizeof t); t[0] += 1;  limbs_to_le(g_cand[2], t); /* r + 1 */
    memset(g_cand[3], 0, 32); g_cand[3][31] = 0x80;             /* 2^255     */
    memcpy(t, FR_P, sizeof t); t[0] -= 1;  limbs_to_le(g_cand[4], t); /* r - 1 */
    memset(g_cand[5], 0, 32); g_cand[5][31] = 0xe0; g_cand[5][0] = 7; /* high bits */
}

/* a. fr_from_bytes: non-canonical -> false, tier-independent, == x mod r. */
static int blind_check_from_bytes(void)
{
    int failures = 0;
    bool a_ok = true;
    for (int k = 0; k < 6; k++) {
        uint64_t raw[4], red[4];
        le_to_limbs(raw, g_cand[k]);
        memcpy(red, raw, sizeof red);
        mp_reduce(red, FR_P, 4);
        uint8_t red_le[32];
        limbs_to_le(red_le, red);
        bool canon = fr_is_canonical_bytes(g_cand[k]);

        struct fr port, disp;
        uint8_t pb[32], db[32];
        fr_accel_force_portable(true);
        bool rp = fr_from_bytes(&port, g_cand[k]);
        fr_to_bytes(pb, &port);
        fr_accel_force_portable(false);
        bool rd = fr_from_bytes(&disp, g_cand[k]);
        fr_to_bytes(db, &disp);
        bool tiers = memcmp(port.d, disp.d, sizeof port.d) == 0;
        bool modr = memcmp(pb, red_le, 32) == 0 && memcmp(db, red_le, 32) == 0;
        if (rp != canon || rd != canon || !tiers || !modr) {
            printf("\n    candidate %d: ret port=%d disp=%d want %d, tiers %s, mod-r %s\n",
                   k, rp, rd, canon, tiers ? "agree" : "DIFFER", modr ? "ok" : "WRONG");
            a_ok = false;
        }
    }
    BLIND_CHECK("fr_from_bytes reduces non-canonical input, same on both tiers", a_ok);
    return failures;
}

/* b. scripted adversarial opening, both tiers. */
static int blind_check_scripted(void)
{
    int failures = 0;
    uint8_t got[2][32];
    bool b_ok = true;
    for (int tier = 0; tier < 2; tier++) {
        struct script_rng g = { .fixed = (const uint8_t (*)[32])g_cand, .nfixed = 5,
                                .state = 0x1234567890abcdefULL };
        struct fr x;
        fr_accel_force_portable(tier == 0);
        bool ok = fr_sample_uniform(&x, script_fill, &g);
        fr_to_bytes(got[tier], &x);
        /* g_cand[0..2] are rejected (>= r after masking bit 255); g_cand[3]
         * masks to 0 and is accepted on draw 4. */
        uint8_t zero[32] = {0};
        b_ok = b_ok && ok && g.used == 4 && g.total == 4 &&
               memcmp(got[tier], zero, 32) == 0;
    }
    fr_accel_force_portable(false);
    BLIND_CHECK("0xff.., r, r+1 rejected; 2^255 masks to 0 and is accepted", b_ok);
    BLIND_CHECK("tiers draw identical scalar", memcmp(got[0], got[1], 32) == 0);

    {   /* r - 1 is the largest canonical value: accepted verbatim. */
        struct script_rng g = { .fixed = (const uint8_t (*)[32])&g_cand[4], .nfixed = 1 };
        struct fr x; uint8_t xb[32];
        bool ok = fr_sample_uniform(&x, script_fill, &g);
        fr_to_bytes(xb, &x);
        BLIND_CHECK("r - 1 accepted on the first draw",
                    ok && g.total == 1 && memcmp(xb, g_cand[4], 32) == 0);
    }
    {   /* Garbage above bit 254 is masked (bit 255 only), then judged. */
        struct script_rng g = { .fixed = (const uint8_t (*)[32])&g_cand[5], .nfixed = 1 };
        struct fr x; uint8_t xb[32];
        bool ok = fr_sample_uniform(&x, script_fill, &g);
        fr_to_bytes(xb, &x);
        uint8_t want[32]; memcpy(want, g_cand[5], 32); want[31] &= 0x7f;
        bool canon = fr_is_canonical_bytes(want);
        BLIND_CHECK("bit 255 is masked before the < r test",
                    ok && g.total == (canon ? 1 : 2) &&
                    (!canon || memcmp(xb, want, 32) == 0));
    }
    return failures;
}

/* c. stuck source fails closed with a zeroed output; e. fixed seed repeats. */
static int blind_check_failclosed_repeat(void)
{
    int failures = 0;
    {
        struct script_rng g = { .stuck_ff = true };
        struct fr x; fr_one(&x);
        bool ok = fr_sample_uniform(&x, script_fill, &g);
        BLIND_CHECK("stuck all-0xff source fails closed after the draw cap",
                    !ok && g.total == FR_SAMPLE_MAX_DRAWS && fr_is_zero(&x));
    }
    {
        struct script_rng a = { .state = 77 }, b = { .state = 77 };
        struct fr xa, xb;
        bool oka = fr_sample_uniform(&xa, script_fill, &a);
        bool okb = fr_sample_uniform(&xb, script_fill, &b);
        BLIND_CHECK("fixed-seed draw is reproducible",
                    oka && okb && memcmp(xa.d, xb.d, sizeof xa.d) == 0);
    }
    return failures;
}

/* d. statistics over 20000 draws. */
static int blind_check_statistics(void)
{
    int failures = 0;
    struct script_rng g = { .state = 0x9E3779B97F4A7C15ULL };
    const int N = 20000;
    int hi_bit = 0, canon_all = 1;
    for (int i = 0; i < N; i++) {
        struct fr x; uint8_t xb[32];
        if (!fr_sample_uniform(&x, script_fill, &g)) { canon_all = 0; break; }
        fr_to_bytes(xb, &x);
        canon_all &= fr_is_canonical_bytes(xb);
        hi_bit += (xb[31] >> 6) & 1; /* bit 254: uniform on [0,r) -> 0.448 */
    }
    double per = (double)g.total / N, f = (double)hi_bit / N;
    printf("  blind: %d samples, %.3f draws/sample (expect 1.103), "
           "bit254 freq %.4f (expect 0.4479)\n", N, per, f);
    BLIND_CHECK("every sampled scalar is canonical", canon_all);
    BLIND_CHECK("draws per sample ~ 1/0.9063", per > 1.07 && per < 1.14);
    BLIND_CHECK("top-bit frequency matches uniform on [0, r)",
                f > 0.4479 - 0.02 && f < 0.4479 + 0.02);
    return failures;
}

static int blind_sampling_checks(void)
{
    blind_build_candidates();
    return blind_check_from_bytes() + blind_check_scripted() +
           blind_check_failclosed_repeat() + blind_check_statistics();
}

int test_fr_mont_parity(void);
int test_fr_mont_parity(void)
{
    printf("\n=== BLS12-381 Fr/Fp Montgomery accel differential oracle ===\n");
    printf("selected impl: %s\n", fr_accel_implementation());

    const struct field fr = { "Fr", 4, FR_P, fr_port, fr_adx, fr_disp };
    const struct field fp = { "Fp", 6, FP_Q, fp_port, fp_adx, fp_disp };

    int failures = run_field(&fr) + run_field(&fp);
    failures += blind_sampling_checks();

    printf("\n%d Fr/Fp Montgomery parity check(s) %s\n", failures,
           failures ? "FAILED" : "all passed");
    return failures;
}
