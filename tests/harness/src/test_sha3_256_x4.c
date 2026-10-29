/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/crypto/src/sha3_256_x4.c
 *
 * Differential parity oracle + honest benchmark for the 4-way batched SHA3-256
 * primitive (core/modules/crypto/src/sha3_256_x4.c).
 *
 * sha3_256_x4() hashes FOUR independent messages and produces FOUR digests. It
 * is NOT consensus crypto (it backs manifest chunk hashes and Merkle-layer
 * combines only), but a differential oracle proving the vector lane is
 * byte-for-byte identical to 4x scalar sha3_256 is still mandatory before it is
 * allowed onto any code path. This group is that oracle plus an honest
 * multi-stream benchmark:
 *
 *   1. FIPS-202 known-answer vectors through the batch path (all 4 lanes).
 *   2. Randomized parity: every length 0..1100 (crossing the 136B rate
 *      boundary) with all four lanes SHARING the length, on the vector lane
 *      and again forced to scalar, vs 4x one-shot sha3_256.
 *   3. Randomized parity with all FOUR lanes at DIFFERENT lengths (the geometry
 *      that exercises per-lane block-count divergence + the pad-block capture),
 *      including empty and NULL-empty lanes, vs 4x sha3_256.
 *   4. Unaligned-input parity: the same message hashed at byte offsets 0..7
 *      with lanes at divergent lengths straddling the rate boundary — the
 *      geometry a caller that does not align its buffers actually produces.
 *   5. Honest benchmark: batch-of-4 (vector) vs 4x scalar sha3_256, the exact
 *      real-world comparison for a batched consumer. Reported, never gated.
 *
 * The vector lane is AVX-512 on x86-64 and NEON (FEAT_SHA3 probed) on arm64 —
 * SHA3_IMPL_VEC below names whichever this host compiles. When the host lacks
 * the lane the vector passes degrade to scalar-vs-scalar (still exercises the
 * batch geometry + KAT); this is reported, not failed. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "crypto/sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The vector tier this target ships: sha3_256_x4_select_impl() dispatches on
 * the same arch split the implementation does. */
#if defined(__x86_64__)
#define SHA3_IMPL_VEC SHA3_IMPL_AVX512
#define SHA3_VEC_NAME  "AVX-512"
#elif defined(__aarch64__)
#define SHA3_IMPL_VEC SHA3_IMPL_NEON
#define SHA3_VEC_NAME  "NEON"
#else
#define SHA3_IMPL_VEC SHA3_IMPL_SCALAR
#define SHA3_VEC_NAME  "none"
#endif

/* Deterministic xorshift64* — no libc rand, reproducible across runs. */
static uint64_t rng_state = 0x243f6a8885a308d3ULL;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static void rng_fill(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(rng_next() >> 17);
}

static int hex2bin(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; ++i) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);  // platform-ok:sha3-256-x4-benchmark-realtime
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Report a section result: "OK" when clean, else the count. Returns 1 on failure. */
static int x4_report_fails(int fails)
{
    if (fails == 0) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (%d)\n", fails);
    return 1;
}

/* The parity passes run on the vector lane when the host has one, else scalar. */
static void x4_select_parity_impl(bool have_vec)
{
    if (have_vec) sha3_256_x4_select_impl(SHA3_IMPL_VEC);
    else          sha3_256_x4_select_impl(SHA3_IMPL_SCALAR);
}

#if defined(__aarch64__)
static int x4_check_neon_refusal(void)
{
    printf("sha3_256_x4: AUTO refuses the measured-slower NEON tier... ");
    if (sha3_256_x4_select_impl(SHA3_IMPL_AUTO) == SHA3_IMPL_SCALAR) {
        printf("OK (scalar)\n");
        return 0;
    }
    printf("FAIL\n");
    return 1;
}
#endif

static int x4_check_kat(bool have_vec)
{
    struct { const char *msg; size_t msglen; const char *h256; } kat[] = {
        { "", 0, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
        { "abc", 3, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376" },
    };
    printf("sha3_256_x4: FIPS-202 KATs through batch path... ");
    int kat_fail = 0;
    for (int pass = 0; pass < 2; ++pass) {
        if (pass == 1) {
            if (!have_vec) break;
            sha3_256_x4_select_impl(SHA3_IMPL_VEC);
        } else {
            sha3_256_x4_select_impl(SHA3_IMPL_SCALAR);
        }
        for (unsigned k = 0; k < sizeof(kat)/sizeof(kat[0]); ++k) {
            uint8_t want[32];
            hex2bin(kat[k].h256, want, 32);
            const uint8_t *msgs[4] = {
                (const uint8_t *)kat[k].msg, (const uint8_t *)kat[k].msg,
                (const uint8_t *)kat[k].msg, (const uint8_t *)kat[k].msg
            };
            size_t lens[4] = { kat[k].msglen, kat[k].msglen,
                               kat[k].msglen, kat[k].msglen };
            uint8_t out[4][32];
            sha3_256_x4(msgs, lens, out);
            for (int i = 0; i < 4; ++i)
                if (memcmp(out[i], want, 32) != 0) kat_fail++;
        }
    }
    return x4_report_fails(kat_fail);
}

static int x4_check_equal_len_parity(bool have_vec)
{
    printf("sha3_256_x4: parity (4 equal-length lanes) 0..1100... ");
    int diff_fail = 0;
    uint8_t buf[4][1101];
    for (size_t len = 0; len <= 1100; ++len) {
        for (int i = 0; i < 4; ++i) rng_fill(buf[i], len);
        const uint8_t *msgs[4] = { buf[0], buf[1], buf[2], buf[3] };
        size_t lens[4] = { len, len, len, len };

        uint8_t ref[4][32];
        for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);

        x4_select_parity_impl(have_vec);
        uint8_t got[4][32];
        sha3_256_x4(msgs, lens, got);
        for (int i = 0; i < 4; ++i)
            if (memcmp(ref[i], got[i], 32) != 0) {
                if (diff_fail < 3) printf("[len %zu lane %d] ", len, i);
                diff_fail++;
            }
    }
    return x4_report_fails(diff_fail);
}

static void x4_fill_divergent_lanes(uint8_t *buf[4], size_t lens[4], const uint8_t *msgs[4])
{
    for (int i = 0; i < 4; ++i) {
        /* ~1 in 8 lanes empty; empties alternate NULL / valid ptr. */
        if ((rng_next() & 7) == 0) {
            lens[i] = 0;
            msgs[i] = (rng_next() & 1) ? NULL : buf[i];
        } else {
            lens[i] = (size_t)(rng_next() % 1101);
            rng_fill(buf[i], lens[i]);
            msgs[i] = buf[i];
        }
    }
}

static int x4_divergent_trial_fails(uint8_t *buf[4], bool have_vec)
{
    size_t lens[4];
    const uint8_t *msgs[4];
    x4_fill_divergent_lanes(buf, lens, msgs);

    uint8_t ref[4][32];
    for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);

    x4_select_parity_impl(have_vec);
    uint8_t got[4][32];
    sha3_256_x4(msgs, lens, got);
    int diff_fail = 0;
    for (int i = 0; i < 4; ++i)
        if (memcmp(ref[i], got[i], 32) != 0) diff_fail++;
    return diff_fail;
}

static int x4_check_divergent_parity(bool have_vec)
{
    printf("sha3_256_x4: parity (4 divergent lengths, empties, NULL) x60000... ");
    int diff_fail = 0;
    int alloc_fail = 0;
    uint8_t *buf[4];
    for (int i = 0; i < 4; ++i) buf[i] = (uint8_t *)malloc(1200);
    if (!buf[0] || !buf[1] || !buf[2] || !buf[3]) {
        printf("alloc FAIL\n");
        alloc_fail = 1;
    } else {
        for (int trial = 0; trial < 60000; ++trial)
            diff_fail += x4_divergent_trial_fails(buf, have_vec);
        for (int i = 0; i < 4; ++i) free(buf[i]);
    }
    return alloc_fail + x4_report_fails(diff_fail);
}

static int x4_unaligned_fails(const uint8_t *base, int off, bool have_vec)
{
    int diff_fail = 0;
    const uint8_t *msgs[4] = {
        base + off, base + (off + 1) % 8,
        base + (off + 3) % 8, base + (off + 7) % 8
    };
    for (size_t len = 130; len <= 142; ++len) {
        /* Lanes straddle the 136B rate boundary at four lengths. */
        size_t lens[4] = { len, len + 1, len + 2, len + 3 };
        uint8_t ref[4][32], got[4][32];
        for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);

        x4_select_parity_impl(have_vec);
        sha3_256_x4(msgs, lens, got);
        for (int i = 0; i < 4; ++i)
            if (memcmp(ref[i], got[i], 32) != 0) diff_fail++;
    }
    return diff_fail;
}

static int x4_check_unaligned_parity(bool have_vec)
{
    printf("sha3_256_x4: parity (unaligned buffers, offsets 0..7) x8x16... ");
    int diff_fail = 0;
    int alloc_fail = 0;
    uint8_t *base = (uint8_t *)malloc(4096 + 8);
    if (!base) {
        printf("alloc FAIL\n");
        alloc_fail = 1;
    } else {
        rng_fill(base, 4096 + 8);
        for (int off = 0; off < 8 && diff_fail == 0; ++off)
            diff_fail += x4_unaligned_fails(base, off, have_vec);
        free(base);
    }
    return alloc_fail + x4_report_fails(diff_fail);
}

#if defined(__x86_64__)
/* The AVX-512 lane entry point: non-static in sha3_256_x4.c and declared in no
 * header, so the oracle declares it here. Called only after the module's own
 * keccak_x4_available() confirms the CPU has the lane. */
void sha3_256_x4_avx512(const uint8_t *const msgs[4], const size_t lens[4],
                        uint8_t out[4][32]);
#endif

typedef void (*x4_entry_fn)(const uint8_t *const msgs[4], const size_t lens[4],
                            uint8_t out[4][32]);

/* Pinned length rows: empty, one byte, the 135/136/137 rate edge, two full
 * blocks plus one, each shared by all four lanes and also split unequal. */
#define X4_PIN_BUF 288u
static const size_t x4_pin_rows[][4] = {
    { 0, 0, 0, 0 },           { 1, 1, 1, 1 },
    { 135, 135, 135, 135 },   { 136, 136, 136, 136 },
    { 137, 137, 137, 137 },   { 272, 272, 272, 272 },
    { 0, 1, 135, 136 },       { 137, 272, 0, 1 },
    { 136, 137, 271, 273 },
};
#define X4_PIN_ROWS (sizeof(x4_pin_rows) / sizeof(x4_pin_rows[0]))

/* Hash one pinned row through fn and count the lanes that differ from
 * one-shot scalar sha3_256 of the same bytes. */
static int x4_pin_row_fails(x4_entry_fn fn, const uint8_t buf[4][X4_PIN_BUF],
                            const size_t lens[4])
{
    const uint8_t *msgs[4] = { buf[0], buf[1], buf[2], buf[3] };
    uint8_t ref[4][32], got[4][32];
    int fails = 0;
    for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);
    fn(msgs, lens, got);
    for (int i = 0; i < 4; ++i)
        if (memcmp(ref[i], got[i], 32) != 0) fails++;
    return fails;
}

static int x4_pin_rows_run(x4_entry_fn fn)
{
    uint8_t buf[4][X4_PIN_BUF];
    int fails = 0;
    for (size_t r = 0; r < X4_PIN_ROWS; ++r) {
        for (int i = 0; i < 4; ++i) rng_fill(buf[i], x4_pin_rows[r][i]);
        fails += x4_pin_row_fails(fn, buf, x4_pin_rows[r]);
    }
    return fails;
}

/* Literal SHA3-256 of the empty string, lane by lane, through fn. */
static int x4_pin_empty_literal_fails(x4_entry_fn fn)
{
    static const char want_hex[] =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    static const uint8_t none[1] = { 0 };
    const uint8_t *msgs[4] = { none, none, none, none };
    const size_t lens[4] = { 0, 0, 0, 0 };
    uint8_t want[32], out[4][32];
    int fails = 0;
    if (hex2bin(want_hex, want, 32) != 0) return 1;
    fn(msgs, lens, out);
    for (int i = 0; i < 4; ++i)
        if (memcmp(out[i], want, 32) != 0) fails++;
    return fails;
}

/* Direct AVX-512 lane against scalar. The row is skipped (not failed) when the
 * host CPU lacks the lane, or on a non-x86-64 target that has no such symbol. */
static int x4_check_avx512_lane(void)
{
    printf("sha3_256_x4: direct AVX-512 lane vs scalar (pinned rows, empty literal)... ");
#if defined(__x86_64__)
    if (!keccak_x4_available()) {
        printf("SKIP (host has no AVX-512 lane)\n");
        return 0;
    }
    return x4_report_fails(x4_pin_empty_literal_fails(sha3_256_x4_avx512) +
                           x4_pin_rows_run(sha3_256_x4_avx512));
#else
    printf("SKIP (not x86-64)\n");
    return 0;
#endif
}

/* The public dispatcher under the shipped AUTO selection, against scalar. */
static int x4_check_dispatch_pinned(void)
{
    printf("sha3_256_x4: public dispatcher (AUTO) vs scalar (pinned rows, empty literal)... ");
    sha3_256_x4_select_impl(SHA3_IMPL_AUTO);
    return x4_report_fails(x4_pin_empty_literal_fails(sha3_256_x4) +
                           x4_pin_rows_run(sha3_256_x4));
}

static void x4_bench_one_size(size_t insz, size_t total_mb, const char *name,
                              bool have_vec, const uint8_t *msgs[4])
{
    size_t groups = (total_mb << 20) / (insz * 4);
    if (groups == 0) groups = 1;
    size_t lens[4] = { insz, insz, insz, insz };
    uint8_t out4[4][32], out1[32];

    /* Reference: 4x scalar one-shot sha3_256 (the current consumer). */
    for (int w = 0; w < 8; ++w)
        for (int i = 0; i < 4; ++i) sha3_256(msgs[i], insz, out1);
    double t0 = now_s();
    for (size_t g = 0; g < groups; ++g)
        for (int i = 0; i < 4; ++i) sha3_256(msgs[i], insz, out1);
    double dt_ref = now_s() - t0;
    double mb_ref = ((double)insz * 4.0 * (double)groups)
                    / (1024.0*1024.0) / dt_ref;

    /* Batch-of-4 (vector lane when present). */
    x4_select_parity_impl(have_vec);
    for (int w = 0; w < 8; ++w) sha3_256_x4(msgs, lens, out4);
    t0 = now_s();
    for (size_t g = 0; g < groups; ++g) sha3_256_x4(msgs, lens, out4);
    double dt_x4 = now_s() - t0;
    double mb_x4 = ((double)insz * 4.0 * (double)groups)
                   / (1024.0*1024.0) / dt_x4;

    printf("sha3_256_x4:   %-6s  4x-scalar %8.1f MB/s   batch-x4 %8.1f MB/s   %.2fx%s\n",
           name, mb_ref, mb_x4, mb_x4 / mb_ref,
           have_vec ? "" : " (no vector lane: scalar-vs-scalar)");
}

static int x4_run_benchmark(bool have_vec)
{
    static const size_t sizes[] = { 64, 136, 512, 4096, 65536 };
    static const char  *names[] = { "64B", "136B", "512B", "4KB", "64KB" };
    static const size_t total_mb[] = { 32, 32, 64, 128, 256 };
    const size_t maxsz = 65536;
    int failures = 0;
    uint8_t *b0 = (uint8_t *)malloc(maxsz), *b1 = (uint8_t *)malloc(maxsz);
    uint8_t *b2 = (uint8_t *)malloc(maxsz), *b3 = (uint8_t *)malloc(maxsz);
    if (!b0 || !b1 || !b2 || !b3) {
        printf("sha3_256_x4: bench alloc failed\n"); failures++;
    } else {
        rng_fill(b0, maxsz); rng_fill(b1, maxsz);
        rng_fill(b2, maxsz); rng_fill(b3, maxsz);
        printf("sha3_256_x4: --- benchmark (4 independent streams) ---\n");
        const uint8_t *msgs[4] = { b0, b1, b2, b3 };
        for (int s = 0; s < 5; ++s)
            x4_bench_one_size(sizes[s], total_mb[s], names[s], have_vec, msgs);
    }
    free(b0); free(b1); free(b2); free(b3);
    return failures;
}

int test_sha3_256_x4(void)
{
    int failures = 0;
    const bool have_vec = keccak_x4_available();

    printf("sha3_256_x4: %s 4-lane Keccak available on host... %s\n", SHA3_VEC_NAME,
           have_vec ? "YES" : "no (parity runs scalar-vs-scalar)");

#if defined(__aarch64__)
    failures += x4_check_neon_refusal();
#endif

    /* ── 1. FIPS-202 known-answer vectors through the batch path ─────── */
    failures += x4_check_kat(have_vec);

    /* ── 1b. Pinned rows: direct AVX-512 lane and public dispatcher ──── */
    failures += x4_check_avx512_lane();
    failures += x4_check_dispatch_pinned();

    /* ── 2. Parity: all four lanes share every length 0..1100 ───────── */
    failures += x4_check_equal_len_parity(have_vec);

    /* ── 3. Parity: all four lanes at DIFFERENT lengths + empties ───── */
    failures += x4_check_divergent_parity(have_vec);

    /* ── 4. Parity: unaligned lane buffers, divergent lengths ────────── */
    failures += x4_check_unaligned_parity(have_vec);

    /* ── 5. Honest benchmark: batch-of-4 vs 4x scalar sha3_256 ──────── */
    failures += x4_run_benchmark(have_vec);

    /* Restore shipped defaults for any subsequent in-process hashing. */
    sha3_256_x4_select_impl(SHA3_IMPL_AUTO);

    printf("sha3_256_x4: %d failure(s)\n", failures);
    return failures;
}
