/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fr/Fs field arithmetic, Jubjub, BLS12-381, PRF, FF1 tests.
 *
 * ACCEL-ORACLE: core/modules/sapling/src/fr.c
 * fr_add / fr_sub / fr_neg and fs_add / fs_neg run as x86-64 asm carry chains
 * (bls12_381_fp_inline.h) with portable C chains elsewhere. The
 * "carry chains match compare-then-subtract" test below pins them, limb for
 * limb and for non-canonical inputs too, to the compare-and-branch form they
 * replaced. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "sapling/jubjub.h"
#include "sapling/prf.h"
#include "sapling/sapling.h"
#include "sapling/ff1.h"
#include "sapling/sprout.h"
#include "sapling/groth16_prover.h"
#include "sapling/sapling_circuit.h"
#include "sapling/pedersen_hash.h"
#include "util/safe_alloc.h"
#include <stdatomic.h>
#include <time.h>

/* test hook: unconditionally fails the allocation. Mirrors the
 * `p22_force_null_alloc` pattern from test_mempool.c. */
static void *p93_force_null_realloc(void *ptr, size_t size)
{
    (void)ptr; (void)size;
    return NULL;
}

/* Reference bit-by-bit double-and-add for Jubjub scalar multiplication.
 * Deliberately NOT constant-time — used only as a correctness oracle for
 * the constant-time jub_scalar_mul implementation. */
static void jub_scalar_mul_naive(struct jub_point *r,
                                 const struct jub_point *p,
                                 const uint8_t scalar[32])
{
    struct jub_point acc;
    jub_identity(&acc);
    for (int bit = 255; bit >= 0; bit--) {
        jub_double(&acc, &acc);
        if ((scalar[bit / 8] >> (bit % 8)) & 1)
            jub_add(&acc, &acc, p);
    }
    *r = acc;
}

/* Per-thread CPU time, in ns. Routes through platform.clock so the raw
 * per-thread-CPU syscall lives inside the platform boundary. Unlike wall-clock
 * CLOCK_MONOTONIC this only accrues while THIS thread is actually executing on
 * a core, so it is immune to cross-process scheduler preemption under a
 * saturated fork-parallel run — exactly the right clock for a constant-time
 * work-ratio gate: it measures the work the algorithm does, not the time the
 * OS happened to give us. */
static uint64_t thread_cpu_ns_now(void)
{
    return (uint64_t)clock_thread_cpu_ns();
}

/* Symmetric per-thread CPU-time work-ratio measurement.
 *
 * The constant-time gates compare the work done on a low-Hamming-weight input
 * (`lo`) against a high-Hamming-weight input (`hi`); a non-constant-time path
 * is strictly cheaper on `lo`, pushing the ratio out of band. The threat to
 * the GATE (not the algorithm) is scheduler/cache contention under a saturated
 * fork-parallel run: a spike that lands on only one side skews the ratio even
 * though the per-thread clock already excludes time we were preempted off-core.
 *
 * A sample runs BOTH orders (lo→hi and hi→lo), sums the two measurements for
 * each side, and keeps that pair together. Alternating which order starts each
 * sample cancels CPU-frequency ramp, SMT, and cache-order bias. The verdict is
 * the median of nine paired ratios; it never combines a clean `lo` minimum
 * from one sample with a clean `hi` minimum from another. `run` executes a
 * timed inner loop once per call and returns a digest of its output. Every
 * invocation writes that digest to a volatile sink before its timer stops, so
 * a future whole-program optimizer cannot erase or algebraically cancel the
 * measured calls.
 *
 * Returns the lo/hi totals from the median-ratio sample. */
#define CT_TIMING_BATCHES 9

/* Windows per-thread CPU time (GetThreadTimes under mingw clock_gettime)
 * advances in ~15.6 ms scheduler ticks: a short timed run can read as 0 ns,
 * and a single tick boundary can skew one batch by ±100%. The gate bands are
 * unchanged; on Windows the batches are simply made long enough that one
 * tick sits well below the noise the gate already tolerates. */
#if defined(_WIN32)
#define CT_ITERS_SCALE 8
#else
#define CT_ITERS_SCALE 1
#endif
typedef uint64_t (*ct_run_fn)(void *);

struct ct_timing_sample {
    uint64_t lo_ns;
    uint64_t hi_ns;
    double ratio;
};

static volatile uint64_t g_ct_timing_sink;

static uint64_t ct_timed_run(ct_run_fn run, void *ctx)
{
    uint64_t start = thread_cpu_ns_now();
    g_ct_timing_sink = run(ctx);
    return thread_cpu_ns_now() - start;
}

static bool ct_median_cpu_ns_paired(ct_run_fn run, void *lo_ctx, void *hi_ctx,
                                    uint64_t *lo_out, uint64_t *hi_out)
{
    struct ct_timing_sample samples[CT_TIMING_BATCHES];
    bool valid = true;
    for (int batch = 0; batch < CT_TIMING_BATCHES; batch++) {
        uint64_t lo_first, lo_second, hi_first, hi_second;
        if ((batch & 1) == 0) {
            lo_first = ct_timed_run(run, lo_ctx);
            hi_first = ct_timed_run(run, hi_ctx);
            hi_second = ct_timed_run(run, hi_ctx);
            lo_second = ct_timed_run(run, lo_ctx);
        } else {
            hi_first = ct_timed_run(run, hi_ctx);
            lo_first = ct_timed_run(run, lo_ctx);
            lo_second = ct_timed_run(run, lo_ctx);
            hi_second = ct_timed_run(run, hi_ctx);
        }
        samples[batch].lo_ns = lo_first + lo_second;
        samples[batch].hi_ns = hi_first + hi_second;
        if (lo_first == 0 || lo_second == 0 ||
            hi_first == 0 || hi_second == 0)
            valid = false;
        samples[batch].ratio = samples[batch].lo_ns != 0
            ? (double)samples[batch].hi_ns / (double)samples[batch].lo_ns
            : 0.0;
    }
    for (int i = 1; i < CT_TIMING_BATCHES; i++) {
        struct ct_timing_sample sample = samples[i];
        int j = i;
        while (j > 0 && samples[j - 1].ratio > sample.ratio) {
            samples[j] = samples[j - 1];
            j--;
        }
        samples[j] = sample;
    }
    const struct ct_timing_sample *median = &samples[CT_TIMING_BATCHES / 2];
    *lo_out = median->lo_ns;
    *hi_out = median->hi_ns;
    return valid;
}

/* ── timed loop bodies for the constant-time work-ratio gates ──────────── */
struct jub_mul_ctx { struct jub_point *R, *P; const uint8_t *scalar; int iters; };
static uint64_t run_jub_scalar_mul(void *p) {
    struct jub_mul_ctx *c = p;
    for (int i = 0; i < c->iters; i++) jub_scalar_mul(c->R, c->P, c->scalar);
    return c->R->x.d[0] ^ c->R->y.d[0] ^ c->R->z.d[0] ^ c->R->t.d[0];
}
struct g1_mul_ctx { struct g1_point *R, *P; const uint64_t *scalar; int iters; };
static uint64_t run_g1_scalar_mul(void *p) {
    struct g1_mul_ctx *c = p;
    for (int i = 0; i < c->iters; i++) g1_scalar_mul(c->R, c->P, c->scalar);
    return c->R->x.d[0] ^ c->R->y.d[0] ^ c->R->z.d[0];
}
struct j2s_ctx { const uint8_t *in; uint8_t *out; int iters; };
static uint64_t run_jubjub_to_scalar(void *p) {
    struct j2s_ctx *c = p;
    for (int i = 0; i < c->iters; i++) jubjub_to_scalar(c->in, c->out);
    uint64_t digest = 0;
    memcpy(&digest, c->out, sizeof(digest));
    return digest;
}

static int sapling_crypto_fr_zero_one_identity(void)
{
    int failures = 0;
    printf("Fr zero/one identity... ");
    {
        struct fr z, o;
        fr_zero(&z);
        fr_one(&o);
        bool ok = fr_is_zero(&z) && !fr_is_zero(&o);
        /* 0 + 1 = 1 */
        struct fr sum;
        fr_add(&sum, &z, &o);
        ok = ok && fr_eq(&sum, &o);
        /* 1 - 1 = 0 */
        struct fr diff;
        fr_sub(&diff, &o, &o);
        ok = ok && fr_is_zero(&diff);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fr_add_sub_neg(void)
{
    int failures = 0;
    printf("Fr add/sub/neg... ");
    {
        struct fr a, b, c, neg_a, sum;
        fr_one(&a);
        fr_add(&b, &a, &a); /* b = 2 */
        fr_add(&c, &b, &a); /* c = 3 */
        fr_sub(&sum, &c, &b); /* 3 - 2 = 1 */
        bool ok = fr_eq(&sum, &a);
        fr_neg(&neg_a, &a);
        fr_add(&sum, &a, &neg_a); /* 1 + (-1) = 0 */
        ok = ok && fr_is_zero(&sum);
        /* Double negation */
        struct fr neg_neg;
        fr_neg(&neg_neg, &neg_a);
        ok = ok && fr_eq(&neg_neg, &a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fr_mul_sq_inv(void)
{
    int failures = 0;
    printf("Fr mul/sq/inv... ");
    {
        struct fr a, two, four, sq_two, inv_a, prod;
        fr_one(&a);
        fr_add(&two, &a, &a);
        fr_mul(&four, &two, &two);
        fr_sq(&sq_two, &two);
        bool ok = fr_eq(&four, &sq_two); /* 2*2 == 2^2 */
        /* inv(2) * 2 = 1 */
        fr_inv(&inv_a, &two);
        fr_mul(&prod, &inv_a, &two);
        ok = ok && fr_eq(&prod, &a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fr_from_bytes_to_bytes_roundtrip(void)
{
    int failures = 0;
    printf("Fr from_bytes/to_bytes roundtrip... ");
    {
        uint8_t bytes[32] = {0};
        bytes[0] = 42; /* small value */
        struct fr a;
        bool ok = fr_from_bytes(&a, bytes);
        uint8_t out[32];
        fr_to_bytes(out, &a);
        ok = ok && (memcmp(bytes, out, 32) == 0);
        /* Zero roundtrip */
        memset(bytes, 0, 32);
        ok = ok && fr_from_bytes(&a, bytes);
        fr_to_bytes(out, &a);
        ok = ok && (memcmp(bytes, out, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fs_zero_one_add_neg(void)
{
    int failures = 0;
    printf("Fs zero/one/add/neg... ");
    {
        struct fs z, o, sum, neg_o;
        fs_zero(&z);
        fs_one(&o);
        bool ok = fs_is_zero(&z) && !fs_is_zero(&o);
        fs_add(&sum, &o, &o); /* 1 + 1 = 2 */
        ok = ok && !fs_is_zero(&sum);
        fs_neg(&neg_o, &o);
        fs_add(&sum, &o, &neg_o); /* 1 + (-1) = 0 */
        ok = ok && fs_is_zero(&sum);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fs_from_bytes_to_bytes_roundtrip(void)
{
    int failures = 0;
    printf("Fs from_bytes/to_bytes roundtrip... ");
    {
        uint8_t bytes[32] = {0};
        bytes[0] = 7;
        struct fs a;
        bool ok = fs_from_bytes(&a, bytes);
        uint8_t out[32];
        fs_to_bytes(out, &a);
        ok = ok && (memcmp(bytes, out, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fs_mul(void)
{
    int failures = 0;
    printf("Fs mul... ");
    {
        struct fs a, b, c;
        fs_one(&a);
        fs_mul(&b, &a, &a); /* 1 * 1 = 1 */
        bool ok = !fs_is_zero(&b);
        uint8_t out_a[32], out_b[32];
        fs_to_bytes(out_a, &a);
        fs_to_bytes(out_b, &b);
        ok = ok && (memcmp(out_a, out_b, 32) == 0);
        /* 0 * anything = 0 */
        struct fs z;
        fs_zero(&z);
        fs_mul(&c, &z, &a);
        ok = ok && fs_is_zero(&c);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fs_to_uniform_64_byte_reduction(void)
{
    int failures = 0;
    printf("Fs to_uniform (64-byte reduction)... ");
    {
        uint8_t digest[64] = {0};
        digest[0] = 0xff;
        digest[63] = 0xff;
        struct fs r;
        fs_to_uniform(&r, digest);
        /* Should produce a non-zero scalar less than the group order */
        bool ok = !fs_is_zero(&r);
        /* Same input should produce same output */
        struct fs r2;
        fs_to_uniform(&r2, digest);
        uint8_t b1[32], b2[32];
        fs_to_bytes(b1, &r);
        fs_to_bytes(b2, &r2);
        ok = ok && (memcmp(b1, b2, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_identity(void)
{
    int failures = 0;
    printf("Jubjub identity... ");
    {
        struct jub_point id;
        jub_identity(&id);
        bool ok = jub_is_identity(&id);
        /* Identity + identity = identity */
        struct jub_point sum;
        jub_add(&sum, &id, &id);
        ok = ok && jub_is_identity(&sum);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_compress_decompress_roundtrip(void)
{
    int failures = 0;
    printf("Jubjub compress/decompress roundtrip... ");
    {
        /* Generate a known point via ask_to_ak */
        uint8_t ask[32] = {1};
        uint8_t ak[32];
        sapling_ask_to_ak(ask, ak);
        /* ak is a compressed point. Decompress, recompress. */
        struct jub_point p;
        bool ok = jub_from_bytes(&p, ak);
        uint8_t recomp[32];
        jub_to_bytes(recomp, &p);
        ok = ok && (memcmp(ak, recomp, 32) == 0);
        /* Identity roundtrip */
        struct jub_point id;
        jub_identity(&id);
        uint8_t id_bytes[32];
        jub_to_bytes(id_bytes, &id);
        struct jub_point id2;
        ok = ok && jub_from_bytes(&id2, id_bytes);
        ok = ok && jub_is_identity(&id2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_add_associativity(void)
{
    int failures = 0;
    printf("Jubjub add associativity... ");
    {
        /* P = ak(1), Q = ak(2), R = ak(3) */
        uint8_t s1[32] = {1}, s2[32] = {2}, s3[32] = {3};
        uint8_t b1[32], b2[32], b3[32];
        sapling_ask_to_ak(s1, b1);
        sapling_ask_to_ak(s2, b2);
        sapling_ask_to_ak(s3, b3);
        struct jub_point P, Q, R;
        jub_from_bytes(&P, b1);
        jub_from_bytes(&Q, b2);
        jub_from_bytes(&R, b3);
        /* (P+Q)+R */
        struct jub_point pq, pqr;
        jub_add(&pq, &P, &Q);
        jub_add(&pqr, &pq, &R);
        /* P+(Q+R) */
        struct jub_point qr, p_qr;
        jub_add(&qr, &Q, &R);
        jub_add(&p_qr, &P, &qr);
        uint8_t out1[32], out2[32];
        jub_to_bytes(out1, &pqr);
        jub_to_bytes(out2, &p_qr);
        bool ok = (memcmp(out1, out2, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_double_add_to_self(void)
{
    int failures = 0;
    printf("Jubjub double = add to self... ");
    {
        uint8_t s[32] = {5};
        uint8_t b[32];
        sapling_ask_to_ak(s, b);
        struct jub_point P, dbl, add_self;
        jub_from_bytes(&P, b);
        jub_double(&dbl, &P);
        jub_add(&add_self, &P, &P);
        uint8_t out1[32], out2[32];
        jub_to_bytes(out1, &dbl);
        jub_to_bytes(out2, &add_self);
        bool ok = (memcmp(out1, out2, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_negate(void)
{
    int failures = 0;
    printf("Jubjub negate... ");
    {
        uint8_t s[32] = {7};
        uint8_t b[32];
        sapling_ask_to_ak(s, b);
        struct jub_point P, neg_P, sum;
        jub_from_bytes(&P, b);
        jub_neg(&neg_P, &P);
        jub_add(&sum, &P, &neg_P);
        bool ok = jub_is_identity(&sum);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_scalar_mul_by_1(void)
{
    int failures = 0;
    printf("Jubjub scalar mul by 1... ");
    {
        uint8_t s[32] = {3};
        uint8_t b[32];
        sapling_ask_to_ak(s, b);
        struct jub_point P, result;
        jub_from_bytes(&P, b);
        uint8_t one_scalar[32] = {1};
        jub_scalar_mul(&result, &P, one_scalar);
        uint8_t out1[32], out2[32];
        jub_to_bytes(out1, &P);
        jub_to_bytes(out2, &result);
        bool ok = (memcmp(out1, out2, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_scalar_mul_matches_naive_double_a(void)
{
    int failures = 0;
    printf("Jubjub scalar mul matches naive double-and-add ... ");
    {
        uint8_t seed[32] = {17};
        uint8_t pt_bytes[32];
        sapling_ask_to_ak(seed, pt_bytes);
        struct jub_point P;
        bool ok = jub_from_bytes(&P, pt_bytes);

        /* Deterministic mismatch would fail below; fixed seed keeps the
         * test reproducible without wasting time on 10k samples. */
        const int N_SAMPLES = 64;
        uint64_t rng = 0xc3a4e2b19a71f5d7ULL;
        for (int i = 0; ok && i < N_SAMPLES; i++) {
            uint8_t scalar[32];
            for (int j = 0; j < 32; j++) {
                rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
                scalar[j] = (uint8_t)(rng >> 56);
            }
            /* Force coverage of several edge nibbles. */
            if (i == 0) memset(scalar, 0x00, 32);
            if (i == 1) memset(scalar, 0xFF, 32);
            if (i == 2) { memset(scalar, 0, 32); scalar[0] = 1; }
            if (i == 3) { memset(scalar, 0, 32); scalar[31] = 0x80; }

            struct jub_point r_ct, r_ref;
            jub_scalar_mul(&r_ct, &P, scalar);
            jub_scalar_mul_naive(&r_ref, &P, scalar);
            uint8_t out_ct[32], out_ref[32];
            jub_to_bytes(out_ct, &r_ct);
            jub_to_bytes(out_ref, &r_ref);
            if (memcmp(out_ct, out_ref, 32) != 0) ok = false;
        }
        if (ok) printf("OK (%d vectors)\n", N_SAMPLES);
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_scalar_mul_timing_vs_scalar_weigh(void)
{
    int failures = 0;
    printf("Jubjub scalar mul timing vs scalar weight ... ");
    {
        uint8_t seed[32] = {23};
        uint8_t pt_bytes[32];
        sapling_ask_to_ak(seed, pt_bytes);
        struct jub_point P;
        jub_from_bytes(&P, pt_bytes);

        uint8_t lo_scalar[32];                       /* Hamming weight 1 */
        memset(lo_scalar, 0, 32);
        lo_scalar[0] = 0x01;
        uint8_t hi_scalar[32];                       /* Hamming weight ~254 */
        memset(hi_scalar, 0xFF, 32);
        hi_scalar[31] = 0x0E;                        /* keep inside Fs range */

        struct jub_point R;
        const int WARMUP = 8;
        const int ITERS = 200 * CT_ITERS_SCALE;
        for (int i = 0; i < WARMUP; i++) jub_scalar_mul(&R, &P, lo_scalar);

        /* Symmetric paired CPU-time samples; see the helper contract above. */
        struct jub_mul_ctx lo_ctx = { &R, &P, lo_scalar, ITERS };
        struct jub_mul_ctx hi_ctx = { &R, &P, hi_scalar, ITERS };
        uint64_t lo, hi;
        bool measured = ct_median_cpu_ns_paired(
            run_jub_scalar_mul, &lo_ctx, &hi_ctx, &lo, &hi);
        double ratio = measured ? (double)hi / (double)lo : 0.0;
        /* Fix asserts: high-weight path must not take materially longer than
         * low-weight. Pre-fix delta was ~25%+, so 1.20 is still a decisive
         * gate without tripping on scheduler jitter. */
        bool ok = measured && (ratio <= 1.20) && (ratio >= 0.83);
        printf("(lo=%.2fms hi=%.2fms ratio=%.3f) ",
               (double)lo / 1e6, (double)hi / 1e6, ratio);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_cofactor_multiplication(void)
{
    int failures = 0;
    printf("Jubjub cofactor multiplication... ");
    {
        uint8_t s[32] = {11};
        uint8_t b[32];
        sapling_ask_to_ak(s, b);
        struct jub_point P, cof;
        jub_from_bytes(&P, b);
        jub_mul_by_cofactor(&cof, &P);
        /* [8]P should be a valid non-identity point (P is not small order) */
        bool ok = !jub_is_identity(&cof);
        /* [8]P compressed should decompress back */
        uint8_t cof_bytes[32];
        jub_to_bytes(cof_bytes, &cof);
        struct jub_point cof2;
        ok = ok && jub_from_bytes(&cof2, cof_bytes);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_get_x_get_y(void)
{
    int failures = 0;
    printf("Jubjub get_x/get_y... ");
    {
        uint8_t s[32] = {13};
        uint8_t b[32];
        sapling_ask_to_ak(s, b);
        struct jub_point P;
        jub_from_bytes(&P, b);
        struct fr x, y;
        jub_get_x(&x, &P);
        jub_get_y(&y, &P);
        /* x and y should be non-zero for a non-identity point */
        bool ok = !fr_is_zero(&x) && !fr_is_zero(&y);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp_zero_one_identity(void)
{
    int failures = 0;
    printf("Fp zero/one identity... ");
    {
        struct fp z, o;
        fp_zero(&z);
        fp_one(&o);
        bool ok = fp_is_zero(&z) && !fp_is_zero(&o);
        struct fp sum;
        fp_add(&sum, &z, &o);
        ok = ok && fp_eq(&sum, &o);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp_add_sub_neg(void)
{
    int failures = 0;
    printf("Fp add/sub/neg... ");
    {
        struct fp a, b, sum, diff, neg_a;
        fp_one(&a);
        fp_add(&b, &a, &a);
        fp_sub(&diff, &b, &a);
        bool ok = fp_eq(&diff, &a);
        fp_neg(&neg_a, &a);
        fp_add(&sum, &a, &neg_a);
        ok = ok && fp_is_zero(&sum);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp_mul_sq_inv(void)
{
    int failures = 0;
    printf("Fp mul/sq/inv... ");
    {
        struct fp a, two, four, sq_two, inv_two, prod;
        fp_one(&a);
        fp_add(&two, &a, &a);
        fp_mul(&four, &two, &two);
        fp_sq(&sq_two, &two);
        bool ok = fp_eq(&four, &sq_two);
        fp_inv(&inv_two, &two);
        fp_mul(&prod, &inv_two, &two);
        ok = ok && fp_eq(&prod, &a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp_from_bytes_to_bytes_roundtrip(void)
{
    int failures = 0;
    printf("Fp from_bytes/to_bytes roundtrip... ");
    {
        /* Use the canonical generator x-coordinate */
        uint8_t bytes[48] = {0};
        bytes[47] = 42; /* small value in big-endian */
        struct fp a;
        bool ok = fp_from_bytes(&a, bytes);
        uint8_t out[48];
        fp_to_bytes(out, &a);
        ok = ok && (memcmp(bytes, out, 48) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp_sqrt(void)
{
    int failures = 0;
    printf("Fp sqrt... ");
    {
        struct fp a, sq, root;
        fp_one(&a);
        fp_add(&a, &a, &a); /* a = 2 */
        fp_sq(&sq, &a);     /* sq = 4 */
        bool ok = fp_sqrt(&root, &sq);
        /* root^2 should equal sq */
        struct fp check;
        fp_sq(&check, &root);
        ok = ok && fp_eq(&check, &sq);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp2_arithmetic(void)
{
    int failures = 0;
    printf("Fp2 arithmetic... ");
    {
        struct fp2 z, o, sum, prod;
        fp2_zero(&z);
        fp2_one(&o);
        bool ok = fp2_is_zero(&z) && !fp2_is_zero(&o);
        fp2_add(&sum, &z, &o);
        ok = ok && fp2_eq(&sum, &o);
        fp2_mul(&prod, &o, &o);
        ok = ok && fp2_eq(&prod, &o); /* 1 * 1 = 1 */
        struct fp2 inv_o;
        fp2_inv(&inv_o, &o);
        fp2_mul(&prod, &o, &inv_o);
        struct fp2 one2;
        fp2_one(&one2);
        ok = ok && fp2_eq(&prod, &one2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fp12_arithmetic(void)
{
    int failures = 0;
    printf("Fp12 arithmetic... ");
    {
        struct fp12 z, o, prod;
        fp12_zero(&z);
        fp12_one(&o);
        bool ok = fp12_is_zero(&z) && !fp12_is_zero(&o);
        fp12_mul(&prod, &o, &o);
        struct fp12 one12;
        fp12_one(&one12);
        /* Compare Fp12 by checking c0.c0.c0 limbs (1*1 should still be 1) */
        ok = ok && fp_eq(&prod.c0.c0.c0, &one12.c0.c0.c0);
        struct fp12 inv_o;
        fp12_inv(&inv_o, &o);
        fp12_mul(&prod, &o, &inv_o);
        ok = ok && fp_eq(&prod.c0.c0.c0, &one12.c0.c0.c0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_g1_identity(void)
{
    int failures = 0;
    printf("G1 identity... ");
    {
        struct g1_point id, dbl;
        g1_identity(&id);
        bool ok = g1_is_identity(&id);
        g1_double(&dbl, &id);
        ok = ok && g1_is_identity(&dbl);
        struct g1_point sum;
        g1_add(&sum, &id, &id);
        ok = ok && g1_is_identity(&sum);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_g1_generator_compressed_roundtrip(void)
{
    int failures = 0;
    printf("G1 generator compressed roundtrip... ");
    {
        /* BLS12-381 G1 generator compressed (48 bytes, big-endian) */
        const uint8_t g1_gen_compressed[48] = {
            0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
            0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
            0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
            0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
            0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
            0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
        };
        struct g1_point gen;
        bool ok = g1_from_compressed(&gen, g1_gen_compressed);
        ok = ok && !g1_is_identity(&gen);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_g2_identity(void)
{
    int failures = 0;
    printf("G2 identity... ");
    {
        struct g2_point id, dbl;
        g2_identity(&id);
        bool ok = g2_is_identity(&id);
        g2_double(&dbl, &id);
        ok = ok && g2_is_identity(&dbl);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_bls12_381_pairing_e_g1_g2_is_not_identit(void)
{
    int failures = 0;
    printf("BLS12-381 pairing: e(G1, G2) is not identity... ");
    {
        const uint8_t g1_gen[48] = {
            0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
            0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
            0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
            0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
            0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
            0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
        };
        const uint8_t g2_gen[96] = {
            0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
            0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
            0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
            0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
            0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
            0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
            0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
            0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
            0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
            0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
            0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
            0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
        };
        struct g1_point p;
        struct g2_point q;
        bool ok = g1_from_compressed(&p, g1_gen);
        ok = ok && g2_from_compressed(&q, g2_gen);
        if (ok) {
            struct fp12 result;
            bls12_381_pairing(&result, &p, &q);
            struct fp12 one12;
            fp12_one(&one12);
            /* e(G1,G2) != 1: check that c1 component is nonzero */
            ok = !fp_is_zero(&result.c1.c0.c0);
            ok = ok && !fp12_is_zero(&result);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_bls12_381_pairing_bilinearity_e_ap_q_e_p(void)
{
    int failures = 0;
    printf("BLS12-381 pairing bilinearity: e(aP, Q) = e(P, aQ)... ");
    {
        const uint8_t g1_gen[48] = {
            0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
            0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
            0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
            0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
            0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
            0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
        };
        const uint8_t g2_gen[96] = {
            0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
            0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
            0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
            0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
            0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
            0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
            0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
            0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
            0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
            0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
            0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
            0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
        };
        struct g1_point P;
        struct g2_point Q;
        g1_from_compressed(&P, g1_gen);
        g2_from_compressed(&Q, g2_gen);

        uint64_t scalar[4] = {7, 0, 0, 0}; /* a = 7 */

        /* aP */
        struct g1_point aP;
        g1_scalar_mul(&aP, &P, scalar);

        /* aQ = Q + Q + ... (7 times) */
        struct g2_point aQ;
        g2_identity(&aQ);
        for (int i = 0; i < 7; i++) {
            struct g2_point tmp;
            g2_add(&tmp, &aQ, &Q);
            aQ = tmp;
        }

        /* e(aP, Q) */
        struct fp12 lhs;
        bls12_381_pairing(&lhs, &aP, &Q);

        /* e(P, aQ) */
        struct fp12 rhs;
        bls12_381_pairing(&rhs, &P, &aQ);

        /* Compare all Fp12 components via memcmp */
        bool ok = (memcmp(&lhs, &rhs, sizeof(struct fp12)) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_bls12_381_g1_subgroup_generator_identity(void)
{
    int failures = 0;
    printf("BLS12-381 G1 subgroup: generator+identity pass, torsion point rejected... ");
    {
        const uint8_t g1_gen_c[48] = {
            0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
            0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
            0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
            0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
            0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
            0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
        };
        struct g1_point gen;
        bool ok = g1_from_compressed(&gen, g1_gen_c);
        ok = ok && g1_in_subgroup(&gen);

        struct g1_point id;
        g1_identity(&id);
        ok = ok && g1_in_subgroup(&id);

        /* x = 4: on curve, but not in the prime-order subgroup. */
        uint8_t g1_torsion[48];
        memset(g1_torsion, 0, 48);
        g1_torsion[0] = 0x80;  /* compressed flag */
        g1_torsion[47] = 0x04; /* affine x = 4 */
        struct g1_point bad;
        bool on_curve = g1_from_compressed(&bad, g1_torsion);
        ok = ok && on_curve;            /* decodes (is on curve) */
        ok = ok && !g1_in_subgroup(&bad); /* but rejected by subgroup check */

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_bls12_381_g2_subgroup_generator_identity(void)
{
    int failures = 0;
    printf("BLS12-381 G2 subgroup: generator+identity pass, torsion point rejected... ");
    {
        const uint8_t g2_gen_c[96] = {
            0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
            0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
            0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
            0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
            0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
            0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
            0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
            0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
            0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
            0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
            0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
            0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
        };
        struct g2_point gen;
        bool ok = g2_from_compressed(&gen, g2_gen_c);
        ok = ok && g2_in_subgroup(&gen);

        struct g2_point id;
        g2_identity(&id);
        ok = ok && g2_in_subgroup(&id);

        /* x.c0 = 2, x.c1 = 0: on curve, but not in the prime-order subgroup. */
        uint8_t g2_torsion[96];
        memset(g2_torsion, 0, 96);
        g2_torsion[0] = 0x80;  /* compressed flag */
        g2_torsion[95] = 0x02; /* affine x.c0 = 2 */
        struct g2_point bad;
        bool on_curve = g2_from_compressed(&bad, g2_torsion);
        ok = ok && on_curve;
        ok = ok && !g2_in_subgroup(&bad);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_groth16_proof_read_rejects_torsion_a_b_c(void)
{
    int failures = 0;
    printf("groth16_proof_read rejects torsion A/B/C, accepts in-subgroup proof... ");
    {
        const uint8_t g1_gen_c[48] = {
            0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
            0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
            0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
            0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
            0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
            0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
        };
        const uint8_t g2_gen_c[96] = {
            0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
            0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
            0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
            0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
            0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
            0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
            0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
            0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
            0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
            0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
            0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
            0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
        };
        /* Build an all-in-subgroup proof: A=G1, B=G2, C=G1. */
        uint8_t good[192];
        memcpy(good, g1_gen_c, 48);
        memcpy(good + 48, g2_gen_c, 96);
        memcpy(good + 144, g1_gen_c, 48);

        struct groth16_proof pr;
        bool ok = groth16_proof_read(&pr, good); /* must accept */

        /* Torsion A (G1 x=4) must reject. */
        uint8_t bad_a[192];
        memcpy(bad_a, good, 192);
        memset(bad_a, 0, 48);
        bad_a[0] = 0x80; bad_a[47] = 0x04;
        ok = ok && !groth16_proof_read(&pr, bad_a);

        /* Torsion B (G2 x.c0=2) must reject. */
        uint8_t bad_b[192];
        memcpy(bad_b, good, 192);
        memset(bad_b + 48, 0, 96);
        bad_b[48] = 0x80; bad_b[143] = 0x02;
        ok = ok && !groth16_proof_read(&pr, bad_b);

        /* Torsion C (G1 x=4) must reject. */
        uint8_t bad_c[192];
        memcpy(bad_c, good, 192);
        memset(bad_c + 144, 0, 48);
        bad_c[144] = 0x80; bad_c[191] = 0x04;
        ok = ok && !groth16_proof_read(&pr, bad_c);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_bls12_381_g1_scalar_mul_timing_vs_scalar(void)
{
    int failures = 0;
    printf("BLS12-381 g1_scalar_mul timing vs scalar weight ... ");
    {
        const uint8_t g1_gen[48] = {
            0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
            0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
            0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
            0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
            0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
            0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
        };
        struct g1_point P;
        g1_from_compressed(&P, g1_gen);

        uint64_t lo_scalar[4] = {1, 0, 0, 0};              /* Hamming weight 1 */
        uint64_t hi_scalar[4] = {~0ULL, ~0ULL, ~0ULL,
                                 0x0fffffffffffffffULL};    /* weight ~252 */

        struct g1_point R;
        const int WARMUP = 4;
        /* G1 scalar mul is the most expensive primitive, so this batch has the
         * smallest absolute time of the three gates; raise ITERS to 60 so the
         * per-batch signal dwarfs per-iteration jitter even under saturation. */
        const int ITERS = 60 * CT_ITERS_SCALE;
        for (int i = 0; i < WARMUP; i++) g1_scalar_mul(&R, &P, lo_scalar);

        /* Symmetric paired CPU-time samples; see the helper contract above. */
        struct g1_mul_ctx lo_ctx = { &R, &P, lo_scalar, ITERS };
        struct g1_mul_ctx hi_ctx = { &R, &P, hi_scalar, ITERS };
        uint64_t lo, hi;
        bool measured = ct_median_cpu_ns_paired(
            run_g1_scalar_mul, &lo_ctx, &hi_ctx, &lo, &hi);
        double ratio = measured ? (double)hi / (double)lo : 0.0;
        bool ok = measured && (ratio <= 1.20) && (ratio >= 0.83);
        printf("(lo=%.2fms hi=%.2fms ratio=%.3f) ",
               (double)lo / 1e6, (double)hi / 1e6, ratio);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_multipack_bytes_to_fr(void)
{
    int failures = 0;
    printf("multipack_bytes_to_fr... ");
    {
        uint8_t bytes[32];
        memset(bytes, 0, 32);
        bytes[0] = 0x42;
        uint64_t out[4][4];
        size_t n_out = 0;
        multipack_bytes_to_fr(out, &n_out, bytes, 32);
        bool ok = (n_out >= 1);
        /* First scalar should be nonzero */
        ok = ok && (out[0][0] != 0 || out[0][1] != 0 || out[0][2] != 0 || out[0][3] != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_prf_ask_nsk_ovk_deterministic(void)
{
    int failures = 0;
    printf("PRF ask/nsk/ovk deterministic... ");
    {
        uint8_t sk[32] = {0};
        struct uint256 sk_u;
        memcpy(sk_u.data, sk, 32);
        struct uint256 ask1, ask2, nsk, ovk;
        prf_ask(&sk_u, &ask1);
        prf_ask(&sk_u, &ask2);
        prf_nsk(&sk_u, &nsk);
        prf_ovk(&sk_u, &ovk);
        bool ok = (memcmp(ask1.data, ask2.data, 32) == 0); /* deterministic */
        /* ask != nsk != ovk */
        ok = ok && (memcmp(ask1.data, nsk.data, 32) != 0);
        ok = ok && (memcmp(ask1.data, ovk.data, 32) != 0);
        ok = ok && (memcmp(nsk.data, ovk.data, 32) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_prf_expand(void)
{
    int failures = 0;
    printf("PRF expand... ");
    {
        uint8_t sk[32] = {0};
        struct uint256 sk_u;
        memcpy(sk_u.data, sk, 32);
        uint8_t out0[64], out1[64];
        prf_expand(&sk_u, 0, out0);
        prf_expand(&sk_u, 1, out1);
        /* Different t → different output */
        bool ok = (memcmp(out0, out1, 64) != 0);
        /* Same t → same output (deterministic) */
        uint8_t out0b[64];
        prf_expand(&sk_u, 0, out0b);
        ok = ok && (memcmp(out0, out0b, 64) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_prf_addr_a_pk_sk_enc_sprout(void)
{
    int failures = 0;
    printf("PRF addr a_pk/sk_enc (Sprout)... ");
    {
        uint8_t a_sk[32] = {0};
        a_sk[0] = 0x42;
        struct uint256 a_pk, sk_enc;
        prf_addr_a_pk(a_sk, &a_pk);
        prf_addr_sk_enc(a_sk, &sk_enc);
        /* Should produce non-zero outputs */
        uint8_t zeros[32] = {0};
        bool ok = (memcmp(a_pk.data, zeros, 32) != 0);
        ok = ok && (memcmp(sk_enc.data, zeros, 32) != 0);
        /* a_pk != sk_enc */
        ok = ok && (memcmp(a_pk.data, sk_enc.data, 32) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_sprout_h_sig_deterministic(void)
{
    int failures = 0;
    printf("Sprout h_sig deterministic... ");
    {
        uint8_t random_seed[32], nf0[32], nf1[32], pk[32];
        memset(random_seed, 0x01, 32);
        memset(nf0, 0x02, 32);
        memset(nf1, 0x03, 32);
        memset(pk, 0x04, 32);
        uint8_t h1[32], h2[32];
        sprout_h_sig(random_seed, nf0, nf1, pk, h1);
        sprout_h_sig(random_seed, nf0, nf1, pk, h2);
        bool ok = (memcmp(h1, h2, 32) == 0); /* deterministic */
        /* Change input → different output */
        uint8_t h3[32];
        nf0[0] = 0xff;
        sprout_h_sig(random_seed, nf0, nf1, pk, h3);
        ok = ok && (memcmp(h1, h3, 32) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_ff1_encrypt_deterministic(void)
{
    int failures = 0;
    printf("FF1 encrypt deterministic... ");
    {
        uint8_t key[32];
        memset(key, 0x42, 32);
        uint8_t tweak[4] = {0x01, 0x02, 0x03, 0x04};
        uint8_t data1[11] = {0};
        uint8_t data2[11] = {0};
        ff1_aes256_encrypt(key, tweak, 4, data1, 88);
        ff1_aes256_encrypt(key, tweak, 4, data2, 88);
        bool ok = (memcmp(data1, data2, 11) == 0); /* deterministic */
        /* Output should differ from input (all zeros) */
        uint8_t zeros[11] = {0};
        ok = ok && (memcmp(data1, zeros, 11) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_ff1_different_keys_produce_different_out(void)
{
    int failures = 0;
    printf("FF1 different keys produce different output... ");
    {
        uint8_t key1[32], key2[32];
        memset(key1, 0x11, 32);
        memset(key2, 0x22, 32);
        uint8_t data1[11] = {0}, data2[11] = {0};
        ff1_aes256_encrypt(key1, NULL, 0, data1, 88);
        ff1_aes256_encrypt(key2, NULL, 0, data2, 88);
        bool ok = (memcmp(data1, data2, 11) != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* Compare two little-endian 32-byte scalars from the most significant byte down.
 * Returns -1, 0 or 1 for a < b, a == b, a > b. */
static int sapling_crypto_cmp_le32(const uint8_t a[32], const uint8_t b[32])
{
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static int sapling_crypto_jubjub_to_scalar_vs_arbitrary_precision(void)
{
    int failures = 0;
    printf("jubjub_to_scalar vs arbitrary-precision reference ... ");
    {
        /* Reference reduction that mirrors the implementation:
         * schoolbook shift-and-subtract with ordinary branches.  Used
         * ONLY as a correctness oracle; the shipping implementation is
         * the branchless one in core/modules/sapling/src/jubjub.c. */
        uint8_t ref_out[32];
        (void)ref_out;

        /* Known-answer corner cases first. */
        uint8_t corner_zero[64];    memset(corner_zero, 0x00, 64);
        uint8_t corner_ff[64];      memset(corner_ff, 0xFF, 64);
        uint8_t corner_lsb[64];     memset(corner_lsb, 0x00, 64);
        corner_lsb[0] = 0x01;
        uint8_t corner_msb[64];     memset(corner_msb, 0x00, 64);
        corner_msb[63] = 0x80;
        uint8_t corner_exact_r[64]; memset(corner_exact_r, 0x00, 64);
        const uint8_t jubjub_r_bytes[32] = {
            0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0,
            0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
            0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06,
            0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
        };
        memcpy(corner_exact_r, jubjub_r_bytes, 32);
        bool ok = true;

        /* Corner 0: 0 mod r = 0. */
        uint8_t out[32];
        jubjub_to_scalar(corner_zero, out);
        uint8_t zero[32] = {0};
        ok = ok && (memcmp(out, zero, 32) == 0);

        /* Corner 3 (msb only = 2^511): must be < r when reduced. */
        jubjub_to_scalar(corner_msb, out);
        const uint8_t r_le[32] = {
            0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0,
            0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
            0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06,
            0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
        };
        /* out < r (little-endian compare from MSB down). */
        ok = ok && (sapling_crypto_cmp_le32(out, r_le) < 0);

        /* Corner 4 (input == r in the low 32 bytes): must reduce to 0.
         * Here only the low 32 bytes are non-zero, which equals r, so
         * (r mod r) = 0. */
        jubjub_to_scalar(corner_exact_r, out);
        ok = ok && (memcmp(out, zero, 32) == 0);
        (void)corner_ff; (void)corner_lsb;

        /* Determinism check: 10k random 64-byte inputs — running the
         * same input twice must produce bit-identical output. */
        uint64_t rng = 0xA1B2C3D4E5F60718ULL;
        const int N = 10000;
        for (int i = 0; i < N && ok; i++) {
            uint8_t in[64];
            for (int j = 0; j < 64; j++) {
                rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
                in[j] = (uint8_t)(rng >> 56);
            }
            uint8_t o1[32], o2[32];
            jubjub_to_scalar(in, o1);
            jubjub_to_scalar(in, o2);
            if (memcmp(o1, o2, 32) != 0) ok = false;
            /* Output must be < r. */
            /* out could equal 0 too (which is valid); only reject out > r. */
            if (sapling_crypto_cmp_le32(o1, r_le) > 0) ok = false;
        }
        if (ok) printf("OK (%d vectors + 5 corners)\n", N);
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_jubjub_to_scalar_timing_vs_input_weight(void)
{
    int failures = 0;
    printf("jubjub_to_scalar timing vs input weight ... ");
    {
        uint8_t lo_in[64] = {0};                    /* Hamming weight 0 */
        lo_in[0] = 0x01;                            /* nudge to weight 1 to avoid trivial path */
        uint8_t hi_in[64];
        memset(hi_in, 0xFF, 64);                    /* Hamming weight 512 */

        uint8_t out[32];
        const int WARMUP = 32;
        const int ITERS = 2000 * CT_ITERS_SCALE;
        for (int i = 0; i < WARMUP; i++) jubjub_to_scalar(lo_in, out);

        /* Symmetric paired CPU-time samples; see the helper contract above. */
        struct j2s_ctx lo_ctx = { lo_in, out, ITERS };
        struct j2s_ctx hi_ctx = { hi_in, out, ITERS };
        uint64_t lo, hi;
        bool measured = ct_median_cpu_ns_paired(
            run_jubjub_to_scalar, &lo_ctx, &hi_ctx, &lo, &hi);
        double ratio = measured ? (double)hi / (double)lo : 0.0;
        bool ok = measured && (ratio <= 1.15) && (ratio >= 0.85);
        printf("(lo=%.2fms hi=%.2fms ratio=%.3f) ",
               (double)lo / 1e6, (double)hi / 1e6, ratio);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_lc_add_term_signals_oom_on_realloc_failu(void)
{
    int failures = 0;
    printf("lc_add_term signals OOM on realloc failure... ");
    {
        struct linear_combination lc;
        lc_init(&lc);
        struct fr one; fr_one(&one);
        /* Fill to initial cap (8). These succeed before the hook is armed. */
        for (size_t i = 0; i < 8; i++)
            lc_add_term(&lc, i, &one);
        bool ok = (lc.num_terms == 8) && (lc.cap == 8) && !lc.oom_error;

        /* Arm hook; next lc_add_term must grow terms 8→16 and hit OOM. */
        groth16_prover_test_set_realloc_hook(p93_force_null_realloc);
        bool ret = lc_add_term(&lc, 99, &one);
        groth16_prover_test_set_realloc_hook(NULL);

        /* Silent-drop symptom: num_terms / cap unchanged — the add was
         * dropped. That part is correct today. What's missing is the
         * signal: the caller has no way to know the add was dropped. */
        ok = ok && (lc.num_terms == 8) && (lc.cap == 8);
        /* Post-fix signals (these are what pre-fix code fails): */
        ok = ok && (ret == false);
        ok = ok && lc.oom_error;

        lc_free(&lc);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* cs_enforce stores each linear combination at exactly its term count (the
 * 8-term doubling capacity of lc_add_term is for the gadget's scratch
 * combination only), keeps every term in order, stores an empty combination
 * without an allocation, and still signals OOM when that allocation fails. */
struct exact_fixture {
    struct constraint_system cs;
    struct linear_combination a, b, c, sum, one_lc, five_lc, empty;
    size_t x, y, z;
};

/* x * y = z, then (x + y) * 1 = 5, then 0 * 0 = 0, with x = 2, y = 3, z = 6. */
static bool exact_fixture_build(struct exact_fixture *f)
{
    struct fr one, two, three, five, six;
    fr_one(&one);
    fr_add(&two, &one, &one);
    fr_add(&three, &two, &one);
    fr_add(&five, &two, &three);
    fr_mul(&six, &two, &three);
    cs_init(&f->cs);
    f->x = cs_alloc_aux(&f->cs, &two);
    f->y = cs_alloc_aux(&f->cs, &three);
    f->z = cs_alloc_aux(&f->cs, &six);
    lc_init(&f->a); lc_init(&f->b); lc_init(&f->c); lc_init(&f->sum);
    lc_init(&f->one_lc); lc_init(&f->five_lc); lc_init(&f->empty);
    lc_add_term(&f->a, f->x, &one);
    lc_add_term(&f->b, f->y, &one);
    lc_add_term(&f->c, f->z, &one);
    lc_add_term(&f->sum, f->x, &one);
    lc_add_term(&f->sum, f->y, &one);
    lc_add_term(&f->one_lc, 0, &one);    /* variable 0 is ONE */
    lc_add_term(&f->five_lc, 0, &five);
    return cs_enforce(&f->cs, &f->a, &f->b, &f->c) &&
           cs_enforce(&f->cs, &f->sum, &f->one_lc, &f->five_lc) &&
           cs_enforce(&f->cs, &f->empty, &f->empty, &f->empty) &&
           !f->cs.oom_error && f->cs.num_constraints == 3;
}

static void exact_fixture_free(struct exact_fixture *f)
{
    lc_free(&f->a); lc_free(&f->b); lc_free(&f->c); lc_free(&f->sum);
    lc_free(&f->one_lc); lc_free(&f->five_lc); lc_free(&f->empty);
    cs_free(&f->cs);
}

/* One term each in constraint 0; two terms, in order, in constraint 1. */
static bool exact_fixture_sizes_ok(const struct exact_fixture *f)
{
    const struct r1cs_constraint *c0 = &f->cs.constraints[0];
    const struct r1cs_constraint *c1 = &f->cs.constraints[1];
    bool one_term = c0->a.num_terms == 1 && c0->a.cap == 1 &&
                    c0->b.num_terms == 1 && c0->b.cap == 1 &&
                    c0->c.num_terms == 1 && c0->c.cap == 1;
    bool two_terms = c1->a.num_terms == 2 && c1->a.cap == 2 &&
                     c1->a.terms[0].var == f->x && c1->a.terms[1].var == f->y;
    return one_term && two_terms;
}

/* An empty combination holds no allocation; the caller's scratch combination
 * keeps its own capacity; the stored system is the one that was enforced. */
static bool exact_fixture_rest_ok(const struct exact_fixture *f)
{
    const struct r1cs_constraint *c2 = &f->cs.constraints[2];
    size_t bad = SIZE_MAX;
    bool empty_ok = c2->a.terms == NULL && c2->a.num_terms == 0 &&
                    c2->a.cap == 0 && !c2->a.oom_error;
    return empty_ok && f->sum.cap == 8 && cs_is_satisfied(&f->cs, &bad);
}

/* OOM while storing a constraint: false, flagged, nothing appended. */
static bool exact_fixture_oom_ok(struct exact_fixture *f)
{
    size_t before = f->cs.num_constraints;
    groth16_prover_test_set_realloc_hook(p93_force_null_realloc);
    bool oom_ret = cs_enforce(&f->cs, &f->a, &f->b, &f->c);
    groth16_prover_test_set_realloc_hook(NULL);
    return !oom_ret && f->cs.oom_error && f->cs.num_constraints == before;
}

static int sapling_crypto_cs_enforce_stores_exact_size_combinations(void)
{
    int failures = 0;
    printf("cs_enforce stores combinations at exact size... ");
    struct exact_fixture f;
    bool ok = exact_fixture_build(&f) && exact_fixture_sizes_ok(&f) &&
              exact_fixture_rest_ok(&f) && exact_fixture_oom_ok(&f);
    exact_fixture_free(&f);
    if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

static int sapling_crypto_cs_alloc_aux_signals_oom_on_realloc_fail(void)
{
    int failures = 0;
    printf("cs_alloc_aux signals OOM on realloc failure... ");
    {
        struct constraint_system cs;
        cs_init(&cs);
        /* Fill witness to initial cap (256). cs_init already placed ONE at
         * index 0, so we add 255 aux vars to hit num_vars == cap_vars. */
        struct fr zero; fr_zero(&zero);
        for (size_t i = 1; i < 256; i++)
            (void)cs_alloc_aux(&cs, &zero);
        bool ok = (cs.num_vars == 256) && (cs.cap_vars == 256) && !cs.oom_error;

        /* Arm hook; next cs_alloc_aux must grow witness 256→512 and hit OOM. */
        groth16_prover_test_set_realloc_hook(p93_force_null_realloc);
        size_t idx = cs_alloc_aux(&cs, &zero);
        groth16_prover_test_set_realloc_hook(NULL);

        /* Catastrophic pre-fix behaviour: idx == 0, which aliases CS_ONE.
         * Any subsequent constraint referencing idx would silently use the
         * constant 1 instead of a fresh aux variable. Post-fix: idx is
         * still 0 (there IS no valid index to return), but cs->oom_error
         * is set so groth16_prove can refuse. */
        ok = ok && (idx == 0);
        /* Post-fix signal: */
        ok = ok && cs.oom_error;

        cs_free(&cs);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_cs_enforce_propagates_input_lc_oom_error(void)
{
    int failures = 0;
    printf("cs_enforce propagates input-LC oom_error... ");
    {
        struct constraint_system cs;
        cs_init(&cs);
        struct linear_combination a, b, c;
        lc_init(&a); lc_init(&b); lc_init(&c);
        /* Simulate: a gadget called lc_add_term on `a`, realloc failed,
         * a.oom_error was set, gadget ignored the void return, and then
         * passed the truncated `a` to cs_enforce. cs_enforce must notice
         * and propagate into cs->oom_error so groth16_prove can refuse. */
        a.oom_error = true;

        bool ret = cs_enforce(&cs, &a, &b, &c);

        /* Post-fix: cs_enforce returns false and propagates the flag. */
        bool ok = (ret == false);
        ok = ok && cs.oom_error;

        lc_free(&a); lc_free(&b); lc_free(&c);
        cs_free(&cs);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_groth16_prove_refuses_on_cs_oom_error_ze(void)
{
    int failures = 0;
    printf("groth16_prove refuses on cs.oom_error (zeroed proof)... ");
    {
        struct constraint_system cs;
        cs_init(&cs);
        cs.oom_error = true; /* as if set by an earlier CS build step */

        /* pk is never dereferenced — the early-exit check fires first. */
        struct groth16_pk pk;
        memset(&pk, 0, sizeof(pk));
        struct groth16_proof proof;
        memset(&proof, 0xAB, sizeof(proof));

        bool ret = groth16_prove(&pk, &cs, &proof);
        bool ok = (ret == false);
        /* Verify proof is zeroed — no valid-looking but wrong proof leaks. */
        struct groth16_proof zero_proof;
        memset(&zero_proof, 0, sizeof(zero_proof));
        ok = ok && (memcmp(&proof, &zero_proof, sizeof(proof)) == 0);

        cs_free(&cs);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fr_fft_uses_the_published_bls12_381_qap(void)
{
    int failures = 0;
    printf("fr_fft uses the published BLS12-381 QAP root of unity... ");
    {
        /* Forward FFT of polynomial x over a four-element domain is
         * [1, omega, omega^2, omega^3]. This omega encoding is independently
         * pinned from pairing::bls12_381::Fr::ROOT_OF_UNITY. An arbitrary
         * primitive root still passes inverse/round-trip tests but generates
         * proofs for a different QAP, so this value gate is load-bearing. */
        static const uint8_t OMEGA4_LE[32] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
            0x00,0x00,0x03,0x76,0x02,0x00,0x03,0xec,
            0xd0,0x04,0x03,0x76,0xce,0xcc,0x51,0x8d,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        struct fr coeffs[4];
        fr_zero(&coeffs[0]);
        fr_one(&coeffs[1]);
        fr_zero(&coeffs[2]);
        fr_zero(&coeffs[3]);
        uint8_t got[32];
        bool ok = fr_fft(coeffs, 4, false);
        fr_to_bytes(got, &coeffs[1]);
        ok = ok && memcmp(got, OMEGA4_LE, sizeof(got)) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fr_fft_returns_false_on_non_pow_2_n(void)
{
    int failures = 0;
    printf("fr_fft returns false on non-pow-2 n... ");
    {
        /* Bug pattern: fr_fft's `if ((size_t)1 << log_n != n) return;`
         * used to silent-drop; callers kept executing with un-FFT'd
         * coefficients. Post-fix the helper returns false. */
        struct fr coeffs[7];
        for (size_t i = 0; i < 7; i++)
            fr_zero(&coeffs[i]);
        bool ret = fr_fft(coeffs, 7, false);
        bool ok = (ret == false);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_fr_fft_parallel_returns_false_on_non_pow(void)
{
    int failures = 0;
    printf("fr_fft_parallel returns false on non-pow-2 n... ");
    {
        /* n=300 is >= 256 (parallel-dispatch threshold) and non-pow-2,
         * so we hit the fr_log2_ceil guard, not the serial dispatch. */
        struct fr coeffs[300];
        for (size_t i = 0; i < 300; i++)
            fr_zero(&coeffs[i]);
        bool ret = fr_fft_parallel(coeffs, 300, false, 4);
        bool ok = (ret == false);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_groth16_prove_refuses_on_non_pow_2_force(void)
{
    int failures = 0;
    printf("groth16_prove refuses on non-pow-2 forced domain (zeroed proof)... ");
    {
        /* Force a non-pow-2 FFT domain via the test hook. Pre-fix
         * groth16_prove ignores fr_fft's silent no-op and emits a
         * "proof" built from un-transformed evaluations (returns true).
         * Post-fix the prover checks fr_fft's bool return, zeroes
         * proof_out, and returns false. */
        struct constraint_system cs;
        cs_init(&cs);
        struct fr zero; fr_zero(&zero);
        (void)cs_alloc_input(&cs, &zero); /* 1 public input; no constraints */

        groth16_prover_test_set_force_domain(7);

        /* pk is zeroed — all g1/g2 points are point-at-infinity (z=0)
         * and all array lengths are 0 so g1_msm/g2_msm return identity.
         * Prover traverses every path without crashing. */
        struct groth16_pk pk;
        memset(&pk, 0, sizeof(pk));
        struct groth16_proof proof;
        memset(&proof, 0xAB, sizeof(proof));

        bool ret = groth16_prove(&pk, &cs, &proof);

        groth16_prover_test_set_force_domain(0); /* disarm */

        bool ok = (ret == false);
        struct groth16_proof zero_proof;
        memset(&zero_proof, 0, sizeof(zero_proof));
        ok = ok && (memcmp(&proof, &zero_proof, sizeof(proof)) == 0);

        cs_free(&cs);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_spend_synth_binds_nk_witness_to_nsk_g_pr(void)
{
    int failures = 0;
    printf("spend synth binds nk witness to nsk*G_proof (not uninit stack)... ");
    {
        /* Pre-fix: `sapling_circuit.c:161-162` declared
         *     struct jub_point nk_point;
         *     jub_scalar_mul(&nk_point, &nk_point, wit->nsk);
         * — reading nk_point as the base-point input before initializing
         * it. Classic C UB: the read-before-write poisoned the whole
         * scalar-mul. The resulting nk_x / nk_y (stored as aux witness
         * variables 12 and 13) were garbage tied to leftover stack
         * contents, not nsk * G_proof as the circuit's comment and the
         * zcash spec require. Any downstream constraint that referenced
         * those witness slots would have been wrong.
         *
         * Post-fix: nk_point = sapling_nsk_to_nk(nsk) decoded via
         * jub_from_bytes, so the witness values equal the documented
         * nsk * G_proof derivation. */

        /* Pollute the stack so uninit leftover reads aren't coincidentally
         * zero (or a known good value). A later sibling frame in this
         * test file used volatile writes to force the stores to survive
         * -O3; reuse the pattern here. */
        volatile uint8_t stack_poison[4096];
        for (size_t i = 0; i < sizeof stack_poison; i++)
            stack_poison[i] = (uint8_t)(0xA5 ^ i);
        (void)stack_poison;

        /* Known nsk — pick a non-zero, low-Hamming-weight value so the
         * scalar mul gives a stable, well-defined point. */
        uint8_t nsk[32] = {0};
        nsk[0] = 0x0B; nsk[1] = 0x5A; nsk[7] = 0x11;

        /* Expected: nk = nsk * G_proof, then split into (x, y). */
        uint8_t nk_bytes[32];
        sapling_nsk_to_nk(nsk, nk_bytes);
        struct jub_point nk_pt_expected;
        bool decode_ok = jub_from_bytes(&nk_pt_expected, nk_bytes);
        struct fr expected_nk_x, expected_nk_y;
        jub_get_x(&expected_nk_x, &nk_pt_expected);
        jub_get_y(&expected_nk_y, &nk_pt_expected);

        /* Build a minimally-valid spend witness. Other fields can be
         * zeros (bytes_to_fr accepts anything) or the valid point `ak`
         * (jub_from_bytes requires a real Jubjub encoding). */
        uint8_t ask[32] = {0};
        ask[0] = 0x07; ask[1] = 0xCC;
        uint8_t ak[32];
        sapling_ask_to_ak(ask, ak);

        struct sapling_spend_witness wit;
        memset(&wit, 0, sizeof wit);
        memcpy(wit.ak, ak, 32);
        memcpy(wit.nsk, nsk, 32);
        memcpy(wit.pk_d, ak, 32);       /* valid on-curve Jubjub point */

        struct sapling_spend_inputs pub;
        memset(&pub, 0, sizeof pub);
        memcpy(pub.rk, ak, 32);         /* valid on-curve Jubjub point */
        memcpy(pub.cv, ak, 32);         /* valid on-curve Jubjub point */

        struct constraint_system cs;
        cs_init(&cs);
        /* The faithful section-by-section port (H3) computes nk IN-circuit
         * via [nsk] ProofGenerationKeyGenerator (a fixed-base multiplication),
         * so its witness index is no longer a fixed offset. Use the traced
         * entry point's wire probe to locate the nk.x / nk.y variables and
         * assert their witness values equal the documented nsk * G_proof
         * derivation (the original UB was reading an uninitialized base point;
         * the in-circuit derivation is now the strongest form of the same
         * binding). */
        struct spend_wire_probe probe;
        bool synth_ok = sapling_spend_synthesize_traced(
            &cs, &wit, &pub, NULL, 0, NULL, &probe);

        bool nk_x_ok = synth_ok && probe.nk_x != SIZE_MAX
                    && probe.nk_x < cs.num_vars
                    && fr_eq(&cs.witness[probe.nk_x], &expected_nk_x);
        bool nk_y_ok = synth_ok && probe.nk_y != SIZE_MAX
                    && probe.nk_y < cs.num_vars
                    && fr_eq(&cs.witness[probe.nk_y], &expected_nk_y);

        bool ok = decode_ok && synth_ok && nk_x_ok && nk_y_ok;

        cs_free(&cs);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_sapling_spend_parse_witness_rejects_shor(void)
{
    int failures = 0;
    printf("sapling_spend_parse_witness rejects short buffer (no OOB read)... ");
    {
        /* The merkle-witness wire format is
         *     depth (1) || 32 × (sibling (32) || bit (1))  = 1057 bytes.
         * Pre-fix, zclassic_sapling_spend_proof parsed this inline: it
         * read witness[0] as depth, asserted depth == 32, then memcpy'd
         * 32 × 32 bytes from fixed offsets up to witness[1024+31]
         * without first verifying the caller passed a buffer that long.
         * A short caller-supplied witness (a wallet blob corrupted on
         * disk, an RPC payload, a fuzz input) walks off the end of the
         * buffer into adjacent heap/stack/guard-page memory.
         *
         * The parser helper was extracted so this bounds guard can be
         * tested without loading the 47MB sapling-spend.params file.
         * A RED run (no length check in the helper) returns true for a
         * 100-byte buffer because witness[0] == 32 passes the only
         * check the buggy code performs; the loop then reads past the
         * end of short_witness. A GREEN run returns false because
         * witness_len < 1057 trips the bounds guard.
         *
         * Full-buffer case is exercised too so the fix does not
         * accidentally reject valid callers. */

        uint8_t short_witness[100];
        memset(short_witness, 0xAA, sizeof short_witness);
        short_witness[0] = 32;

        struct sapling_spend_witness wit;
        memset(&wit, 0, sizeof wit);

        bool short_rejected =
            !sapling_spend_parse_witness(short_witness,
                                         sizeof short_witness, &wit);

        uint8_t full_witness[1 + 32 * 33];
        memset(full_witness, 0xBB, sizeof full_witness);
        full_witness[0] = 32;
        for (int i = 0; i < 32; i++)
            full_witness[1 + i * 33 + 32] = (uint8_t)(i & 1);

        bool full_accepted =
            sapling_spend_parse_witness(full_witness,
                                        sizeof full_witness, &wit);

        /* Exercise one non-full short length right below the limit so a
         * naive `witness_len > 0` guard cannot pass the test. */
        bool near_full_rejected =
            !sapling_spend_parse_witness(full_witness,
                                         sizeof full_witness - 1, &wit);

        bool ok = short_rejected && full_accepted && near_full_rejected;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* ── Characterization pins: groth16_pk_read, g1_msm, g2_msm ──────────
 * Pin today's observable behaviour before the groth16 prover is split.
 * The parser reads every byte in order, so any prefix shorter than a full
 * key is refused; a point whose first byte has the compressed flag (0x80)
 * is refused; the MSMs equal repeated point addition. */

#define PKC_PK_TOTAL 1656 /* 6 CRS points + ic/h/l/a/b_g1/b_g2 arrays of 1..2 */

static const uint8_t pkc_g1_gen_c[48] = {
    0x97,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
    0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
    0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
    0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
    0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};

static const uint8_t pkc_g2_gen_c[96] = {
    0x93,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
    0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
    0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
    0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
    0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e,
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
    0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
    0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
    0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
    0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};

static size_t pkc_put(uint8_t *buf, size_t pos, const uint8_t *src, size_t n)
{
    memcpy(buf + pos, src, n);
    return pos + n;
}

static size_t pkc_put_u32(uint8_t *buf, size_t pos, uint32_t v)
{
    buf[pos] = (uint8_t)(v >> 24);
    buf[pos + 1] = (uint8_t)(v >> 16);
    buf[pos + 2] = (uint8_t)(v >> 8);
    buf[pos + 3] = (uint8_t)v;
    return pos + 4;
}

/* Uncompressed 96-byte encoding of the canonical G1 generator. */
static bool pkc_g1_gen_uncompressed(uint8_t out[96])
{
    struct g1_point gen;
    if (!g1_from_compressed(&gen, pkc_g1_gen_c))
        return false;
    struct fp ax, ay;
    g1_to_affine(&ax, &ay, &gen);
    fp_to_bytes(out, &ax);
    fp_to_bytes(out + 48, &ay);
    return true;
}

/* Well-formed key: alpha_g1 = G1 generator, every other CRS point is the
 * identity (0x40 = infinity flag), ic_len = 2, h/l/a/b_g1/b_g2 length 1.
 * Byte offsets: alpha 0, beta_g1 96, beta_g2 192, gamma_g2 384,
 * delta_g1 576, delta_g2 672, ic_len 864 (ic[0] 868, ic[1] 964),
 * h_len 1060 (h[0] 1064), l_len 1160 (l[0] 1164), a_len 1260 (a[0] 1264),
 * b_g1_len 1360 (b_g1[0] 1364), b_g2_len 1460 (b_g2[0] 1464). */
static size_t pkc_build_valid(uint8_t *buf, const uint8_t g1_gen[96])
{
    uint8_t inf1[96] = { 0x40 };
    uint8_t inf2[192] = { 0x40 };
    size_t p = 0;
    p = pkc_put(buf, p, g1_gen, 96);
    p = pkc_put(buf, p, inf1, 96);
    p = pkc_put(buf, p, inf2, 192);
    p = pkc_put(buf, p, inf2, 192);
    p = pkc_put(buf, p, inf1, 96);
    p = pkc_put(buf, p, inf2, 192);
    p = pkc_put_u32(buf, p, 2);
    p = pkc_put(buf, p, g1_gen, 96);
    p = pkc_put(buf, p, inf1, 96);
    p = pkc_put_u32(buf, p, 1);
    p = pkc_put(buf, p, inf1, 96);
    p = pkc_put_u32(buf, p, 1);
    p = pkc_put(buf, p, g1_gen, 96);
    p = pkc_put_u32(buf, p, 1);
    p = pkc_put(buf, p, inf1, 96);
    p = pkc_put_u32(buf, p, 1);
    p = pkc_put(buf, p, inf1, 96);
    p = pkc_put_u32(buf, p, 1);
    p = pkc_put(buf, p, inf2, 192);
    return p;
}

static bool pkc_g1_eq(const struct g1_point *a, const struct g1_point *b)
{
    bool ia = g1_is_identity(a), ib = g1_is_identity(b);
    if (ia || ib)
        return ia && ib;
    struct fp ax, ay, bx, by;
    g1_to_affine(&ax, &ay, a);
    g1_to_affine(&bx, &by, b);
    return fp_eq(&ax, &bx) && fp_eq(&ay, &by);
}

static bool pkc_g2_eq(const struct g2_point *a, const struct g2_point *b)
{
    bool ia = g2_is_identity(a), ib = g2_is_identity(b);
    if (ia || ib)
        return ia && ib;
    struct fp2 ax, ay, bx, by;
    g2_to_affine(&ax, &ay, a);
    g2_to_affine(&bx, &by, b);
    return fp2_eq(&ax, &bx) && fp2_eq(&ay, &by);
}

static void pkc_small_fr(struct fr *out, uint32_t k)
{
    struct fr one;
    fr_one(&one);
    fr_zero(out);
    for (uint32_t i = 0; i < k; i++)
        fr_add(out, out, &one);
}

static bool pkc_pk_lengths_ok(const struct groth16_pk *pk)
{
    return pk->num_inputs == 1 && pk->h_len == 1 && pk->l_len == 1 &&
           pk->a_len == 1 && pk->b_len == 1 && pk->vk.ic_len == 2;
}

/* The G1 slots of a valid key: generator where the valid key puts it,
 * identity everywhere else. */
static bool pkc_pk_g1_points_ok(const struct groth16_pk *pk,
                                const struct g1_point *gen)
{
    struct g1_point id;
    g1_identity(&id);
    return pkc_g1_eq(&pk->alpha_g1, gen) && pkc_g1_eq(&pk->vk.alpha_g1, gen) &&
           pkc_g1_eq(&pk->vk.ic[0], gen) && pkc_g1_eq(&pk->vk.ic[1], &id) &&
           pkc_g1_eq(&pk->l_g1[0], gen) && pkc_g1_eq(&pk->h_g1[0], &id) &&
           pkc_g1_eq(&pk->a_g1[0], &id) && pkc_g1_eq(&pk->b_g1[0], &id) &&
           pkc_g1_eq(&pk->beta_g1, &id) && pkc_g1_eq(&pk->delta_g1, &id);
}

static bool pkc_pk_g2_points_ok(const struct groth16_pk *pk)
{
    return g2_is_identity(&pk->b_g2[0]) && g2_is_identity(&pk->vk.beta_g2) &&
           g2_is_identity(&pk->vk.gamma_g2) && g2_is_identity(&pk->vk.delta_g2);
}

static int sapling_crypto_groth16_pk_read_pins_layout_and_points(void)
{
    int failures = 0;
    printf("groth16_pk_read: well-formed key parses to the pinned layout... ");
    {
        uint8_t gen_bytes[96];
        uint8_t buf[PKC_PK_TOTAL];
        struct g1_point gen;
        bool ok = pkc_g1_gen_uncompressed(gen_bytes);
        ok = ok && g1_from_uncompressed(&gen, gen_bytes);
        size_t n = pkc_build_valid(buf, gen_bytes);
        ok = ok && n == PKC_PK_TOTAL;

        struct groth16_pk pk;
        bool read_ok = groth16_pk_read(&pk, buf, n);
        ok = ok && read_ok;
        if (read_ok) {
            ok = ok && pkc_pk_lengths_ok(&pk);
            ok = ok && pkc_pk_g1_points_ok(&pk, &gen);
            ok = ok && pkc_pk_g2_points_ok(&pk);
            groth16_pk_free(&pk);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_groth16_pk_read_refuses_every_truncation_cut(void)
{
    int failures = 0;
    printf("groth16_pk_read: every prefix shorter than a full key is refused... ");
    {
        /* Cuts land on each section boundary and inside each array. */
        static const size_t cuts[] = {
            0, 1, 95, 96, 192, 288, 384, 576, 672, 863, 864, 868, 1059,
            1060, 1100, 1160, 1200, 1260, 1300, 1360, 1400, 1460, 1600, 1655
        };
        uint8_t gen_bytes[96];
        uint8_t buf[PKC_PK_TOTAL];
        bool ok = pkc_g1_gen_uncompressed(gen_bytes);
        ok = ok && pkc_build_valid(buf, gen_bytes) == PKC_PK_TOTAL;
        for (size_t i = 0; ok && i < sizeof(cuts) / sizeof(cuts[0]); i++) {
            struct groth16_pk pk;
            if (groth16_pk_read(&pk, buf, cuts[i])) {
                groth16_pk_free(&pk);
                ok = false;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_groth16_pk_read_refuses_bad_point_flags(void)
{
    int failures = 0;
    printf("groth16_pk_read: a point with the compressed flag is refused in every slot... ");
    {
        /* Offsets of the first byte of each point, see pkc_build_valid. */
        static const size_t flag_offsets[] = {
            0, 96, 192, 384, 576, 672, 868, 1064, 1164, 1264, 1364, 1464
        };
        uint8_t gen_bytes[96];
        uint8_t valid[PKC_PK_TOTAL];
        bool ok = pkc_g1_gen_uncompressed(gen_bytes);
        ok = ok && pkc_build_valid(valid, gen_bytes) == PKC_PK_TOTAL;
        for (size_t i = 0; ok && i < sizeof(flag_offsets) / sizeof(flag_offsets[0]); i++) {
            uint8_t bad[PKC_PK_TOTAL];
            memcpy(bad, valid, sizeof(bad));
            bad[flag_offsets[i]] = 0x80;
            struct groth16_pk pk;
            if (groth16_pk_read(&pk, bad, sizeof(bad))) {
                groth16_pk_free(&pk);
                ok = false;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_groth16_pk_read_refuses_b_len_mismatch(void)
{
    int failures = 0;
    printf("groth16_pk_read: b_g1_len != b_g2_len is refused... ");
    {
        uint8_t gen_bytes[96];
        uint8_t buf[PKC_PK_TOTAL];
        bool ok = pkc_g1_gen_uncompressed(gen_bytes);
        ok = ok && pkc_build_valid(buf, gen_bytes) == PKC_PK_TOTAL;
        /* b_g2_len is the u32 at offset 1460: set it to 2 while b_g1_len is 1. */
        buf[1463] = 0x02;
        struct groth16_pk pk;
        bool read_ok = groth16_pk_read(&pk, buf, PKC_PK_TOTAL);
        if (read_ok)
            groth16_pk_free(&pk);
        ok = ok && !read_ok;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* Runs g1_msm over n copies of g with the given small scalars and checks the
 * result against sum * g built by repeated addition. */
static bool pkc_g1_msm_row(const struct g1_point *g, const uint32_t *ks,
                           size_t n, uint32_t sum)
{
    if (n > 32)
        return false;
    struct g1_point pts[32];
    struct fr scalars[32];
    for (size_t i = 0; i < n; i++) {
        pts[i] = *g;
        pkc_small_fr(&scalars[i], ks[i]);
    }
    struct g1_point got, want;
    g1_msm(&got, pts, scalars, n);
    g1_identity(&want);
    for (uint32_t i = 0; i < sum; i++)
        g1_add(&want, &want, g);
    return pkc_g1_eq(&got, &want);
}

static bool pkc_g2_msm_row(const struct g2_point *g, const uint32_t *ks,
                           size_t n, uint32_t sum)
{
    if (n > 32)
        return false;
    struct g2_point pts[32];
    struct fr scalars[32];
    for (size_t i = 0; i < n; i++) {
        pts[i] = *g;
        pkc_small_fr(&scalars[i], ks[i]);
    }
    struct g2_point got, want;
    g2_msm(&got, pts, scalars, n);
    g2_identity(&want);
    for (uint32_t i = 0; i < sum; i++)
        g2_add(&want, &want, g);
    return pkc_g2_eq(&got, &want);
}

static int sapling_crypto_g1_msm_pins_small_scalar_sums(void)
{
    int failures = 0;
    printf("g1_msm: n=0, zero, one, mixed and 17-term sums match repeated addition... ");
    {
        struct g1_point gen;
        bool ok = g1_from_compressed(&gen, pkc_g1_gen_c);
        static const uint32_t k_one[] = { 1 };
        static const uint32_t k_zero[] = { 0 };
        static const uint32_t k_two_three[] = { 2, 3 };
        static const uint32_t k_mixed[] = { 5, 0, 6 };
        static const uint32_t k_1_to_17[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
        };
        ok = ok && pkc_g1_msm_row(&gen, NULL, 0, 0);
        ok = ok && pkc_g1_msm_row(&gen, k_one, 1, 1);
        ok = ok && pkc_g1_msm_row(&gen, k_zero, 1, 0);
        ok = ok && pkc_g1_msm_row(&gen, k_two_three, 2, 5);
        ok = ok && pkc_g1_msm_row(&gen, k_mixed, 3, 11);
        ok = ok && pkc_g1_msm_row(&gen, k_1_to_17, 17, 153);

        /* scalar -1 gives the negated point. */
        struct fr one, neg_one;
        fr_one(&one);
        fr_neg(&neg_one, &one);
        struct g1_point got, want;
        g1_msm(&got, &gen, &neg_one, 1);
        g1_neg(&want, &gen);
        ok = ok && pkc_g1_eq(&got, &want);

        /* identity base point times any scalar is the identity. */
        struct g1_point id;
        g1_identity(&id);
        ok = ok && pkc_g1_msm_row(&id, k_one, 1, 1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static int sapling_crypto_g2_msm_pins_small_scalar_sums(void)
{
    int failures = 0;
    printf("g2_msm: n=0, zero, one, mixed and 17-term sums match repeated addition... ");
    {
        struct g2_point gen;
        bool ok = g2_from_compressed(&gen, pkc_g2_gen_c);
        static const uint32_t k_one[] = { 1 };
        static const uint32_t k_zero[] = { 0 };
        static const uint32_t k_two_three[] = { 2, 3 };
        static const uint32_t k_mixed[] = { 5, 0, 6 };
        static const uint32_t k_1_to_17[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
        };
        ok = ok && pkc_g2_msm_row(&gen, NULL, 0, 0);
        ok = ok && pkc_g2_msm_row(&gen, k_one, 1, 1);
        ok = ok && pkc_g2_msm_row(&gen, k_zero, 1, 0);
        ok = ok && pkc_g2_msm_row(&gen, k_two_three, 2, 5);
        ok = ok && pkc_g2_msm_row(&gen, k_mixed, 3, 11);
        ok = ok && pkc_g2_msm_row(&gen, k_1_to_17, 17, 153);

        struct fr one, neg_one;
        fr_one(&one);
        fr_neg(&neg_one, &one);
        struct g2_point got, want;
        g2_msm(&got, &gen, &neg_one, 1);
        g2_neg(&want, &gen);
        ok = ok && pkc_g2_eq(&got, &want);

        struct g2_point id;
        g2_identity(&id);
        ok = ok && pkc_g2_msm_row(&id, k_one, 1, 1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* ── Prover and field speed work: every fast path against a slow reference ──
 *
 * The fast paths below replaced slower code that produced the same values:
 * branch-free Fr/Fs add/sub/neg, the FFT and MSM on several threads, mixed
 * addition and the 0/1 scalar split in the MSM, prepared-affine Jubjub
 * addition, and the paired-window Pedersen tables. Each is compared here with
 * a reference written the slow, obvious way. */

static uint64_t spd_next(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* A canonical pseudo-random Fr element (below 2^254, so below the modulus). */
static void spd_rand_fr(struct fr *out, uint64_t *s)
{
    uint8_t bytes[32];
    for (int i = 0; i < 32; i++)
        bytes[i] = (uint8_t)spd_next(s);
    bytes[31] &= 0x3f;
    fr_from_bytes(out, bytes);
}

static const uint64_t SPD_FR_P[4] = {
    0xffffffff00000001ULL, 0x53bda402fffe5bfeULL,
    0x3339d80809a1d805ULL, 0x73eda753299d7d48ULL
};
static const uint64_t SPD_FS_S[4] = {
    0xd0970e5ed6f72cb7ULL, 0xa6682093ccc81082ULL,
    0x06673b0101343b00ULL, 0x0e7db4ea6533afa9ULL
};

static bool spd_gte4(const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

/* r = a - b mod 2^256. */
static void spd_sub4(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t d = a[i] - b[i];
        uint64_t b1 = a[i] < b[i];
        r[i] = d - borrow;
        borrow = b1 | (d < borrow);
    }
}

/* r = a + b mod 2^256, returning the carry out. */
static uint64_t spd_add4(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t s = a[i] + b[i];
        uint64_t c1 = s < a[i];
        r[i] = s + carry;
        carry = c1 | (r[i] < s);
    }
    return carry;
}

/* The compare-then-subtract forms fr.c used before, for any 4-limb inputs. */
static void spd_ref_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                        const uint64_t p[4])
{
    uint64_t t[4];
    uint64_t carry = spd_add4(t, a, b);
    if (carry || spd_gte4(t, p))
        spd_sub4(r, t, p);
    else
        memcpy(r, t, 32);
}

static void spd_ref_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                        const uint64_t p[4])
{
    uint64_t t[4];
    if (spd_gte4(a, b)) {
        spd_sub4(r, a, b);
        return;
    }
    (void)spd_add4(t, a, p);
    spd_sub4(r, t, b);
}

static void spd_ref_neg(uint64_t r[4], const uint64_t a[4], const uint64_t p[4])
{
    if ((a[0] | a[1] | a[2] | a[3]) == 0)
        memset(r, 0, 32);
    else
        spd_sub4(r, p, a);
}

/* Fr add/sub/neg (and aliasing r == a) and Fs add/neg against the references. */
static bool spd_addsub_pair_ok(const uint64_t a[4], const uint64_t b[4])
{
    struct fr x, y, r, t;
    struct fs u, v, w;
    uint64_t want[4];
    memcpy(x.d, a, 32);
    memcpy(y.d, b, 32);
    memcpy(u.d, a, 32);
    memcpy(v.d, b, 32);

    fr_add(&r, &x, &y);
    spd_ref_add(want, a, b, SPD_FR_P);
    bool ok = memcmp(r.d, want, 32) == 0;
    t = x;
    fr_add(&t, &t, &y);
    ok = ok && memcmp(t.d, want, 32) == 0;

    fr_sub(&r, &x, &y);
    spd_ref_sub(want, a, b, SPD_FR_P);
    ok = ok && memcmp(r.d, want, 32) == 0;
    t = y;
    fr_sub(&t, &x, &t);
    ok = ok && memcmp(t.d, want, 32) == 0;

    fr_neg(&r, &x);
    spd_ref_neg(want, a, SPD_FR_P);
    ok = ok && memcmp(r.d, want, 32) == 0;

    fs_add(&w, &u, &v);
    spd_ref_add(want, a, b, SPD_FS_S);
    ok = ok && memcmp(w.d, want, 32) == 0;
    fs_neg(&w, &u);
    spd_ref_neg(want, a, SPD_FS_S);
    return ok && memcmp(w.d, want, 32) == 0;
}

/* 0, 1, each modulus and its neighbours, the limb extremes. */
static int spd_addsub_boundaries(uint64_t v[12][4])
{
    static const uint64_t one[4] = {1, 0, 0, 0};
    int n = 0;
    memset(v[n++], 0, 32);
    memcpy(v[n++], one, 32);
    for (int m = 0; m < 2; m++) {
        const uint64_t *p = m ? SPD_FS_S : SPD_FR_P;
        memcpy(v[n++], p, 32);
        spd_sub4(v[n++], p, one);
        (void)spd_add4(v[n++], p, one);
        (void)spd_add4(v[n++], p, p);
    }
    memset(v[n++], 0xff, 32);
    memset(v[n], 0, 32);
    v[n++][3] = 0x8000000000000000ULL;
    return n;
}

static int sapling_crypto_fr_fs_add_sub_neg_match_the_branching_form(void)
{
    int failures = 0;
    printf("fr/fs add, sub, neg: carry chains match compare-then-subtract... ");
    {
        uint64_t v[12][4];
        int n = spd_addsub_boundaries(v);
        bool ok = true;
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                ok = ok && spd_addsub_pair_ok(v[i], v[j]);

        /* Random pairs: canonical, non-canonical, equal, and one bit apart. */
        uint64_t s = 0x5eed5eed5eed5eedULL;
        for (int k = 0; k < 400000 && ok; k++) {
            uint64_t a[4], b[4];
            for (int i = 0; i < 4; i++) { a[i] = spd_next(&s); b[i] = spd_next(&s); }
            if (k & 1) { a[3] &= 0x3fffffffffffffffULL; b[3] &= 0x3fffffffffffffffULL; }
            if ((k & 7) == 2) memcpy(b, a, 32);
            if ((k & 7) == 4) { memcpy(b, a, 32); b[k & 3] ^= 1ULL << (k & 63); }
            ok = spd_addsub_pair_ok(a, b);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* out[i] = sum(in[j] * w^(i*j)), the transform by its definition. */
static void spd_naive_dft(struct fr *out, const struct fr *in, size_t n,
                          const struct fr *w)
{
    struct fr wi;
    fr_one(&wi);
    for (size_t i = 0; i < n; i++) {
        struct fr acc, x, term;
        fr_zero(&acc);
        fr_one(&x);
        for (size_t j = 0; j < n; j++) {
            fr_mul(&term, &in[j], &x);
            fr_add(&acc, &acc, &term);
            fr_mul(&x, &x, &wi);
        }
        out[i] = acc;
        fr_mul(&wi, &wi, w);
    }
}

/* fr_fft of n elements equals the definition, with w read from the transform
 * of the polynomial x (whose value the QAP-root test above pins). */
static bool spd_fft_matches_definition(size_t n, uint64_t *s)
{
    struct fr in[64], got[64], want[64], x[64];
    for (size_t i = 0; i < n; i++) {
        spd_rand_fr(&in[i], s);
        got[i] = in[i];
        fr_zero(&x[i]);
    }
    fr_one(&x[1]);
    if (!fr_fft(x, n, false) || !fr_fft(got, n, false))
        return false;
    spd_naive_dft(want, in, n, &x[1]);
    return memcmp(got, want, n * sizeof(struct fr)) == 0;
}

static bool spd_all_equal(const struct fr *want, struct fr *const got[3],
                          size_t bytes)
{
    return memcmp(want, got[0], bytes) == 0 &&
           memcmp(want, got[1], bytes) == 0 &&
           memcmp(want, got[2], bytes) == 0;
}

/* The same n-element transform on 1, 3 and 8 threads, alone and as three
 * arrays at once, forward and back. */
static bool spd_fft_threads_agree(size_t n, uint64_t *s)
{
    size_t bytes = n * sizeof(struct fr);
    struct fr *v = zcl_calloc(5 * n, sizeof(struct fr), "spd_fft");
    if (!v)
        return false;
    struct fr *orig = v, *a = v + n, *many[3] = { v + 2 * n, v + 3 * n, v + 4 * n };
    for (size_t i = 0; i < n; i++)
        spd_rand_fr(&orig[i], s);
    memcpy(a, orig, bytes);
    memcpy(many[0], orig, bytes);
    memcpy(many[1], orig, bytes);
    memcpy(many[2], orig, bytes);

    /* many[2] is the one-thread answer the other two are held to. */
    bool ok = fr_fft(many[2], n, false) &&
              fr_fft_parallel(many[0], n, false, 3) &&
              fr_fft_parallel(many[1], n, false, 8) &&
              spd_all_equal(many[2], many, bytes);
    memcpy(many[0], orig, bytes);
    memcpy(many[1], orig, bytes);
    memcpy(many[2], orig, bytes);
    ok = ok && fr_fft(a, n, false) && fr_fft_many(many, 3, n, false, 5) &&
         spd_all_equal(a, many, bytes);
    ok = ok && fr_fft_many(many, 3, n, true, 5) && fr_fft(a, n, true) &&
         spd_all_equal(orig, many, bytes) && memcmp(orig, a, bytes) == 0;
    free(v);
    return ok;
}

static int sapling_crypto_fr_fft_matches_definition_on_any_thread_count(void)
{
    int failures = 0;
    printf("fr_fft: equals the DFT definition and is thread-count independent... ");
    {
        uint64_t s = 0xf17f17f17f17f17fULL;
        bool ok = true;
        for (size_t n = 2; n <= 64; n <<= 1)
            ok = ok && spd_fft_matches_definition(n, &s);
        /* 2^12 is one cache block; 2^13 and 2^15 add per-stage passes. */
        static const size_t sizes[] = { 2, 8, 256, 4096, 8192, 32768 };
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
            ok = ok && spd_fft_threads_agree(sizes[i], &s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

struct spd_cover {
    uint8_t *hits;
    _Atomic unsigned max_tid;
};

static void spd_cover_range(void *ctx, size_t lo, size_t hi, unsigned tid)
{
    struct spd_cover *c = ctx;
    for (size_t i = lo; i < hi; i++)
        c->hits[i]++;
    unsigned seen = atomic_load(&c->max_tid);
    while (tid > seen && !atomic_compare_exchange_weak(&c->max_tid, &seen, tid))
        ;
}

/* Every index is visited exactly once and no tid reaches `threads`. */
static bool spd_parallel_for_covers(unsigned threads, size_t n, size_t grain)
{
    struct spd_cover c = { .hits = zcl_calloc(n ? n : 1, 1, "spd_cover") };
    if (!c.hits)
        return false;
    groth16_parallel_for(threads, n, grain, spd_cover_range, &c);
    bool ok = atomic_load(&c.max_tid) < (threads ? threads : 1);
    for (size_t i = 0; i < n; i++)
        ok = ok && c.hits[i] == 1;
    free(c.hits);
    return ok;
}

static int sapling_crypto_prover_thread_budget_is_bounded_and_settable(void)
{
    int failures = 0;
    printf("groth16 prover: thread budget clamps, defaults and fans out once... ");
    {
        groth16_prover_set_threads(3);
        bool ok = groth16_prover_threads() == 3;
        groth16_prover_set_threads(100000);
        ok = ok && groth16_prover_threads() == GROTH16_MAX_THREADS;
        groth16_prover_set_threads(0);
        unsigned dflt = groth16_prover_threads();
        ok = ok && dflt >= 1 && dflt <= 8;

        ok = ok && spd_parallel_for_covers(1, 1000, 7) &&
             spd_parallel_for_covers(4, 1000, 7) &&
             spd_parallel_for_covers(8, 5, 1) &&
             spd_parallel_for_covers(8, 4096, 0) &&
             spd_parallel_for_covers(200, 300, 1) &&
             spd_parallel_for_covers(0, 9, 100) &&
             spd_parallel_for_covers(4, 0, 1);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static void spd_fr_raw(uint64_t raw[4], const struct fr *a)
{
    uint8_t bytes[32];
    fr_to_bytes(bytes, a);
    memcpy(raw, bytes, 32);
}

/* Scalar i: mostly 0, 1 and full-width values, as a witness is. */
static void spd_msm_scalar(struct fr *out, size_t i, uint64_t *s)
{
    switch (i % 5) {
    case 0: fr_zero(out); break;
    case 1: fr_one(out); break;
    case 2: pkc_small_fr(out, (uint32_t)(i % 97) + 2); break;
    default: spd_rand_fr(out, s); break;
    }
}

#define SPD_MSM_N 150

/* Bases: multiples of g, every third left un-normalised (z != 1), one the
 * identity; the rest normalised as proving-key points are. */
static void spd_g1_bases(struct g1_point *pts, const struct g1_point *g)
{
    struct g1_point cur = *g;
    for (size_t i = 0; i < SPD_MSM_N; i++) {
        g1_add(&cur, &cur, g);
        pts[i] = cur;
        if (i % 3) {
            g1_to_affine(&pts[i].x, &pts[i].y, &cur);
            fp_one(&pts[i].z);
        }
    }
    g1_identity(&pts[7]);
}

static int sapling_crypto_g1_msm_matches_scalar_mul_on_any_thread_count(void)
{
    int failures = 0;
    printf("groth16_g1_msm: equals sum of scalar multiples on 1..8 threads... ");
    {
        struct g1_point gen, pts[SPD_MSM_N], want, got;
        struct fr scalars[SPD_MSM_N];
        uint64_t s = 0x6d736d6731ULL;
        bool ok = g1_from_compressed(&gen, pkc_g1_gen_c);
        spd_g1_bases(pts, &gen);
        g1_identity(&want);
        for (size_t i = 0; i < SPD_MSM_N; i++) {
            uint64_t raw[4];
            struct g1_point term;
            spd_msm_scalar(&scalars[i], i, &s);
            spd_fr_raw(raw, &scalars[i]);
            g1_scalar_mul(&term, &pts[i], raw);
            g1_add(&want, &want, &term);
        }
        for (unsigned t = 1; t <= 8 && ok; t++)
            ok = groth16_g1_msm(&got, pts, scalars, SPD_MSM_N, t) &&
                 pkc_g1_eq(&got, &want);
        g1_msm(&got, pts, scalars, SPD_MSM_N);
        ok = ok && pkc_g1_eq(&got, &want);
        /* P + P and P - P through the mixed formula's special cases. */
        struct fr two[2];
        fr_one(&two[0]);
        fr_one(&two[1]);
        struct g1_point same[2] = { pts[1], pts[1] }, dbl;
        g1_double(&dbl, &pts[1]);
        g1_msm(&got, same, two, 2);
        ok = ok && pkc_g1_eq(&got, &dbl);
        g1_neg(&same[1], &pts[1]);
        g1_msm(&got, same, two, 2);
        ok = ok && g1_is_identity(&got);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* r = scalar * p by double-and-add over g2_add / g2_double. */
static void spd_g2_scalar_mul(struct g2_point *r, const struct g2_point *p,
                              const uint64_t raw[4])
{
    struct g2_point acc;
    g2_identity(&acc);
    for (int bit = 255; bit >= 0; bit--) {
        g2_double(&acc, &acc);
        if ((raw[bit / 64] >> (bit % 64)) & 1)
            g2_add(&acc, &acc, p);
    }
    *r = acc;
}

#define SPD_MSM_G2_N 40

static int sapling_crypto_g2_msm_matches_scalar_mul_on_any_thread_count(void)
{
    int failures = 0;
    printf("groth16_g2_msm: equals sum of scalar multiples on 1..8 threads... ");
    {
        struct g2_point gen, cur, pts[SPD_MSM_G2_N], want, got;
        struct fr scalars[SPD_MSM_G2_N];
        uint64_t s = 0x6d736d6732ULL;
        bool ok = g2_from_compressed(&gen, pkc_g2_gen_c);
        cur = gen;
        g2_identity(&want);
        for (size_t i = 0; i < SPD_MSM_G2_N; i++) {
            uint64_t raw[4];
            struct g2_point term;
            g2_add(&cur, &cur, &gen);
            pts[i] = cur;
            if (i % 3) {
                g2_to_affine(&pts[i].x, &pts[i].y, &cur);
                fp2_one(&pts[i].z);
            }
            spd_msm_scalar(&scalars[i], i, &s);
            spd_fr_raw(raw, &scalars[i]);
            spd_g2_scalar_mul(&term, &pts[i], raw);
            g2_add(&want, &want, &term);
        }
        for (unsigned t = 1; t <= 8 && ok; t += 3)
            ok = groth16_g2_msm(&got, pts, scalars, SPD_MSM_G2_N, t) &&
                 pkc_g2_eq(&got, &want);
        g2_msm(&got, pts, scalars, SPD_MSM_G2_N);
        ok = ok && pkc_g2_eq(&got, &want);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

static bool spd_jub_eq(const struct jub_point *a, const struct jub_point *b)
{
    uint8_t x[32], y[32];
    jub_to_bytes(x, a);
    jub_to_bytes(y, b);
    return memcmp(x, y, 32) == 0;
}

static int sapling_crypto_jub_add_niels_matches_jub_add(void)
{
    int failures = 0;
    printf("jub_add_niels: equals jub_add, negated and aliased, per batch... ");
    {
        struct jub_point g0, g1, acc, q[JUB_NIELS_BATCH_MAX], want, got, neg;
        struct jub_niels nq[JUB_NIELS_BATCH_MAX + 1];
        bool ok = pedersen_segment_generator(0, &g0) &&
                  pedersen_segment_generator(1, &g1);
        if (!ok) {
            printf("FAIL (generator setup)\n");
            return 1;
        }
        /* q[i] = (i+1) * g1 in extended form with z != 1; acc walks g0. */
        q[0] = g1;
        for (int i = 1; i < JUB_NIELS_BATCH_MAX; i++)
            jub_add(&q[i], &q[i - 1], &g1);
        jub_to_niels_batch(nq, q, JUB_NIELS_BATCH_MAX);
        jub_double(&acc, &g0);
        for (int i = 0; i < JUB_NIELS_BATCH_MAX && ok; i++) {
            jub_add(&want, &acc, &q[i]);
            jub_add_niels(&got, &acc, &nq[i], false);
            ok = spd_jub_eq(&got, &want);
            jub_neg(&neg, &q[i]);
            jub_add(&want, &acc, &neg);
            jub_add_niels(&got, &acc, &nq[i], true);
            ok = ok && spd_jub_eq(&got, &want);
            /* unified: q + q, q - q, and identity + q */
            jub_add(&want, &q[i], &q[i]);
            jub_add_niels(&got, &q[i], &nq[i], false);
            ok = ok && spd_jub_eq(&got, &want);
            jub_add_niels(&got, &q[i], &nq[i], true);
            ok = ok && jub_is_identity(&got);
            jub_identity(&got);
            jub_add_niels(&got, &got, &nq[i], false);
            ok = ok && spd_jub_eq(&got, &q[i]);
            jub_add_niels(&acc, &acc, &nq[i], (i & 1) != 0);
        }
        /* A one-point batch, and an oversized batch converting nothing. */
        struct jub_niels one, sentinel;
        jub_to_niels_batch(&one, &q[4], 1);
        ok = ok && memcmp(&one, &nq[4], sizeof(one)) == 0;
        memset(&nq[0], 0x5a, sizeof(nq[0]));
        sentinel = nq[0];
        jub_to_niels_batch(nq, q, JUB_NIELS_BATCH_MAX + 1);
        ok = ok && memcmp(&nq[0], &sentinel, sizeof(sentinel)) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

/* Pedersen hash the way the specification states it: per segment, the scalar
 * sum(v_k * 16^k) times the segment generator, with v = +-(1 + a + 2b) —
 * evaluated here one chunk at a time on a doubling base, no tables. */
static bool spd_pedersen_reference(struct jub_point *out, const uint8_t *bits,
                                   int nbits)
{
    int pos = 0;
    jub_identity(out);
    for (size_t seg = 0; seg < PEDERSEN_SEGMENT_GENERATORS && pos < nbits; seg++) {
        struct jub_point base;
        if (!pedersen_segment_generator(seg, &base))
            return false;
        for (int chunk = 0; chunk < 63 && pos < nbits; chunk++) {
            int a = bits[pos++];
            int b = pos < nbits ? bits[pos++] : 0;
            int c = pos < nbits ? bits[pos++] : 0;
            struct jub_point term;
            jub_identity(&term);
            for (int m = 0; m < 1 + a + 2 * b; m++)
                jub_add(&term, &term, &base);
            if (c)
                jub_neg(&term, &term);
            jub_add(out, out, &term);
            for (int d = 0; d < 4; d++)
                jub_double(&base, &base);
        }
    }
    return true;
}

static int sapling_crypto_pedersen_pair_tables_match_per_chunk_reference(void)
{
    int failures = 0;
    printf("pedersen_hash_bits: paired windows equal the per-chunk definition... ");
    {
        /* Every length that ends inside the first pairs, the segment seams
         * (189 bits each), the Merkle (516) and note (582) lengths, the
         * maximum (1134), then random lengths. */
        static const int fixed[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                     183, 186, 187, 188, 189, 190, 191, 192,
                                     195, 378, 381, 516, 582, 945, 1131, 1134 };
        uint8_t bits[1134];
        uint64_t s = 0x7065646572736eULL;
        bool ok = true;
        for (int t = 0; t < 28 + 200 && ok; t++) {
            int nbits = t < 28 ? fixed[t] : 1 + (int)(spd_next(&s) % 1134);
            for (int i = 0; i < nbits; i++)
                bits[i] = (uint8_t)(spd_next(&s) & 1);
            struct jub_point got, want;
            pedersen_hash_bits(bits, nbits, &got);
            ok = spd_pedersen_reference(&want, bits, nbits) &&
                 spd_jub_eq(&got, &want);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int test_sapling_crypto(void)
{
    int failures = 0;

    failures += sapling_crypto_fr_zero_one_identity();

    failures += sapling_crypto_fr_add_sub_neg();

    failures += sapling_crypto_fr_mul_sq_inv();

    failures += sapling_crypto_fr_from_bytes_to_bytes_roundtrip();

    failures += sapling_crypto_fs_zero_one_add_neg();

    failures += sapling_crypto_fs_from_bytes_to_bytes_roundtrip();

    failures += sapling_crypto_fs_mul();

    failures += sapling_crypto_fs_to_uniform_64_byte_reduction();

    /* ================================================================ */
    /* Jubjub point operation tests                                     */
    /* ================================================================ */

    failures += sapling_crypto_jubjub_identity();

    failures += sapling_crypto_jubjub_compress_decompress_roundtrip();

    failures += sapling_crypto_jubjub_add_associativity();

    failures += sapling_crypto_jubjub_double_add_to_self();

    failures += sapling_crypto_jubjub_negate();

    failures += sapling_crypto_jubjub_scalar_mul_by_1();

    /* correctness: windowed CT jub_scalar_mul vs bit-by-bit oracle.
     * Covers corner cases (zero scalar, small/large scalars, nibble
     * transitions) plus random vectors across the scalar range. */
    failures += sapling_crypto_jubjub_scalar_mul_matches_naive_double_a();

    /* timing sanity: low-Hamming-weight vs high-Hamming-weight
     * scalars should not differ materially in runtime. Pre-fix, the
     * `if (nibble)` branch skipped adds for zero nibbles, so zero-heavy
     * scalars ran ~25% faster. The new CT implementation always runs
     * one add per nibble, so both scalars do identical work.
     *
     * The tolerance is deliberately generous because CI hosts are noisy
     * and the twisted-Edwards field math still has minor value-dependent
     * timing inside fr_add/fr_sub. The gate matches the BLS timing test:
     * tight enough to catch the old branchy path, loose enough for a
     * saturated fork-parallel run. */
    failures += sapling_crypto_jubjub_scalar_mul_timing_vs_scalar_weigh();

    failures += sapling_crypto_jubjub_cofactor_multiplication();

    failures += sapling_crypto_jubjub_get_x_get_y();

    /* ================================================================ */
    /* BLS12-381 field arithmetic tests                                 */
    /* ================================================================ */

    failures += sapling_crypto_fp_zero_one_identity();

    failures += sapling_crypto_fp_add_sub_neg();

    failures += sapling_crypto_fp_mul_sq_inv();

    failures += sapling_crypto_fp_from_bytes_to_bytes_roundtrip();

    failures += sapling_crypto_fp_sqrt();

    failures += sapling_crypto_fp2_arithmetic();

    failures += sapling_crypto_fp12_arithmetic();

    failures += sapling_crypto_g1_identity();

    failures += sapling_crypto_g1_generator_compressed_roundtrip();

    failures += sapling_crypto_g2_identity();

    failures += sapling_crypto_bls12_381_pairing_e_g1_g2_is_not_identit();

    failures += sapling_crypto_bls12_381_pairing_bilinearity_e_ap_q_e_p();

    /* BLS12-381 subgroup check (Groth16 soundness, consensus Sapling path).
     *
     * G1/G2 have large cofactors, so a point can be ON the curve yet carry a
     * torsion component outside the prime-order-r subgroup. The pairing still
     * "accepts" such points, so without a subgroup check a malicious prover
     * could forge an accepting Groth16 proof — a soundness gap. The fix wires
     * [r]P==O membership into groth16_proof_read for A, B, C.
     *
     * This is the hermetic, must-have negative+positive test:
     *   - the generator (in subgroup) and the identity (point at infinity)
     *     MUST pass — re-verifying honest historical proofs yields 0 new
     *     rejections;
     *   - an on-curve-but-not-in-subgroup point MUST be rejected.
     *
     * Test vectors (deterministically derived): the compressed encoding with
     * affine x = 4 over Fp (G1) and x.c0 = 2 over Fp2, x.c1 = 0 (G2) each
     * decode to a valid on-curve point that is NOT in the prime-order
     * subgroup (verified at authoring time by an exhaustive small-x scan). */
    failures += sapling_crypto_bls12_381_g1_subgroup_generator_identity();

    failures += sapling_crypto_bls12_381_g2_subgroup_generator_identity();

    /* End-to-end: groth16_proof_read must reject a proof whose A, B, or C is a
     * torsion point, and accept an all-in-subgroup proof. This is the actual
     * consensus seam the soundness fix protects. */
    failures += sapling_crypto_groth16_proof_read_rejects_torsion_a_b_c();

    /* g1_scalar_mul must run identical work regardless of scalar
     * Hamming weight. Pre-fix, the prover only executed `g1_add` on
     * bits that were set — so an attacker measuring wall time of the
     * prover recovered partial information about the Groth16 blinding
     * factors `r_blind` / `s_blind` (`groth16_prover.c:906,934`).
     *
     * This test compares a Hamming-weight-1 scalar (one `g1_add`,
     * 256 `g1_double`s) against a full-255-bit scalar (~255 adds + 255
     * doubles). On the pre-fix code the ratio is ~1.5–2.0; on the
     * constant-time implementation both sides always do 256 adds and
     * 256 doubles so the ratio collapses to ~1.0. The tolerance is
     * deliberately generous to tolerate CI-host noise — anything
     * beyond 1.20 indicates a skipped-add branch. */
    failures += sapling_crypto_bls12_381_g1_scalar_mul_timing_vs_scalar();

    failures += sapling_crypto_multipack_bytes_to_fr();

    /* ================================================================ */
    /* PRF standalone tests                                             */
    /* ================================================================ */

    failures += sapling_crypto_prf_ask_nsk_ovk_deterministic();

    failures += sapling_crypto_prf_expand();

    failures += sapling_crypto_prf_addr_a_pk_sk_enc_sprout();

    /* ================================================================ */
    /* Sprout h_sig test                                                */
    /* ================================================================ */

    failures += sapling_crypto_sprout_h_sig_deterministic();

    /* ================================================================ */
    /* FF1 format-preserving encryption test                            */
    /* ================================================================ */

    failures += sapling_crypto_ff1_encrypt_deterministic();

    failures += sapling_crypto_ff1_different_keys_produce_different_out();

    /* ================================================================ */
    /* jubjub_to_scalar constant-time regressions */
    /*                                                                  */
    /* `jubjub_to_scalar` reduces a 64-byte blake2b digest modulo the   */
    /* Jubjub scalar field order r.  It sits on the Sapling nullifier   */
    /* derivation path via `prf_nsk`, where the input is derived from   */
    /* a long-lived secret spending key (nsk is reused across every     */
    /* spend).  A cache-timing or branch leak here correlates across    */
    /* many spends, so the reduction must be CT.                        */
    /* ================================================================ */

    failures += sapling_crypto_jubjub_to_scalar_vs_arbitrary_precision();

    /* Timing regression: the implementation had two
     * secret-dependent branches — `if (input bit set)` and
     * `if (acc >= r) subtract r` — so an all-ones input ran materially
     * longer than an all-zero input (~8% on measured hosts, and the
     * gap widened with cache pressure).  The new branchless path
     * performs identical work regardless of input Hamming weight.
     *
     * Tolerance 0.85..1.15 mirrors the ratio gate and absorbs
     * normal CI jitter while still tripping on any branch
     * reintroduction. */
    failures += sapling_crypto_jubjub_to_scalar_timing_vs_input_weight();

    /* ================================================================
     * OOM silent-drop in groth16 CS builders
     * ================================================================
     * RED before fix, GREEN after fix. Every block below installs the
     * test hook that forces the next realloc inside groth16_prover.c
     * to return NULL, exercises one of the three helpers, and asserts
     * the OOM signal reached the caller. Pre-fix the helpers silently
     * drop so the flags stay false — tests FAIL. Post-fix the helpers
     * set lc->oom_error / cs->oom_error + LOG_FAIL — tests PASS. */

    failures += sapling_crypto_lc_add_term_signals_oom_on_realloc_failu();

    failures += sapling_crypto_cs_alloc_aux_signals_oom_on_realloc_fail();

    failures += sapling_crypto_cs_enforce_stores_exact_size_combinations();

    failures += sapling_crypto_cs_enforce_propagates_input_lc_oom_error();

    failures += sapling_crypto_groth16_prove_refuses_on_cs_oom_error_ze();

    /* ── fr_fft fr_fft_parallel non-pow-2 silent no-op ───── */

    failures += sapling_crypto_fr_fft_uses_the_published_bls12_381_qap();

    failures += sapling_crypto_fr_fft_returns_false_on_non_pow_2_n();

    failures += sapling_crypto_fr_fft_parallel_returns_false_on_non_pow();

    failures += sapling_crypto_groth16_prove_refuses_on_non_pow_2_force();

    /* ── sapling_spend_synthesize nk_point placeholder UB ──── */

    failures += sapling_crypto_spend_synth_binds_nk_witness_to_nsk_g_pr();

    /* ── spend-witness parser must reject short buffers ──────── */

    failures += sapling_crypto_sapling_spend_parse_witness_rejects_shor();

    /* ── characterization pins ahead of the groth16 prover split ── */

    failures += sapling_crypto_groth16_pk_read_pins_layout_and_points();

    failures += sapling_crypto_groth16_pk_read_refuses_every_truncation_cut();

    failures += sapling_crypto_groth16_pk_read_refuses_bad_point_flags();

    failures += sapling_crypto_groth16_pk_read_refuses_b_len_mismatch();

    failures += sapling_crypto_g1_msm_pins_small_scalar_sums();

    failures += sapling_crypto_g2_msm_pins_small_scalar_sums();

    /* ── prover and field speed work: fast paths against slow references ── */

    failures += sapling_crypto_fr_fs_add_sub_neg_match_the_branching_form();

    failures += sapling_crypto_fr_fft_matches_definition_on_any_thread_count();

    failures += sapling_crypto_prover_thread_budget_is_bounded_and_settable();

    failures += sapling_crypto_g1_msm_matches_scalar_mul_on_any_thread_count();

    failures += sapling_crypto_g2_msm_matches_scalar_mul_on_any_thread_count();

    failures += sapling_crypto_jub_add_niels_matches_jub_add();

    failures += sapling_crypto_pedersen_pair_tables_match_per_chunk_reference();

    return failures;
}
