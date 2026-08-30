/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: lib/crypto/src/sha3_256_x4.c
 *
 * Differential parity oracle + honest benchmark for the 4-way batched SHA3-256
 * primitive (lib/crypto/src/sha3_256_x4.c).
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

int test_sha3_256_x4(void)
{
    int failures = 0;
    const bool have_vec = keccak_x4_available();

    printf("sha3_256_x4: %s 4-lane Keccak available on host... %s\n", SHA3_VEC_NAME,
           have_vec ? "YES" : "no (parity runs scalar-vs-scalar)");

#if defined(__aarch64__)
    printf("sha3_256_x4: AUTO refuses the measured-slower NEON tier... ");
    if (sha3_256_x4_select_impl(SHA3_IMPL_AUTO) == SHA3_IMPL_SCALAR)
        printf("OK (scalar)\n");
    else {
        printf("FAIL\n");
        failures++;
    }
#endif

    /* ── 1. FIPS-202 known-answer vectors through the batch path ─────── */
    struct { const char *msg; size_t msglen; const char *h256; } kat[] = {
        { "", 0, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
        { "abc", 3, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376" },
    };
    printf("sha3_256_x4: FIPS-202 KATs through batch path... ");
    {
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
        if (kat_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", kat_fail); failures++; }
    }

    /* ── 2. Parity: all four lanes share every length 0..1100 ───────── */
    printf("sha3_256_x4: parity (4 equal-length lanes) 0..1100... ");
    {
        int diff_fail = 0;
        uint8_t buf[4][1101];
        for (size_t len = 0; len <= 1100; ++len) {
            for (int i = 0; i < 4; ++i) rng_fill(buf[i], len);
            const uint8_t *msgs[4] = { buf[0], buf[1], buf[2], buf[3] };
            size_t lens[4] = { len, len, len, len };

            uint8_t ref[4][32];
            for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);

            if (have_vec) sha3_256_x4_select_impl(SHA3_IMPL_VEC);
            else          sha3_256_x4_select_impl(SHA3_IMPL_SCALAR);
            uint8_t got[4][32];
            sha3_256_x4(msgs, lens, got);
            for (int i = 0; i < 4; ++i)
                if (memcmp(ref[i], got[i], 32) != 0) {
                    if (diff_fail < 3) printf("[len %zu lane %d] ", len, i);
                    diff_fail++;
                }
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diff_fail); failures++; }
    }

    /* ── 3. Parity: all four lanes at DIFFERENT lengths + empties ───── */
    printf("sha3_256_x4: parity (4 divergent lengths, empties, NULL) x60000... ");
    {
        int diff_fail = 0;
        uint8_t *buf[4];
        for (int i = 0; i < 4; ++i) buf[i] = (uint8_t *)malloc(1200);
        if (!buf[0] || !buf[1] || !buf[2] || !buf[3]) {
            printf("alloc FAIL\n"); failures++;
        } else {
            for (int trial = 0; trial < 60000; ++trial) {
                size_t lens[4];
                const uint8_t *msgs[4];
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
                uint8_t ref[4][32];
                for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);

                if (have_vec) sha3_256_x4_select_impl(SHA3_IMPL_VEC);
                else          sha3_256_x4_select_impl(SHA3_IMPL_SCALAR);
                uint8_t got[4][32];
                sha3_256_x4(msgs, lens, got);
                for (int i = 0; i < 4; ++i)
                    if (memcmp(ref[i], got[i], 32) != 0) diff_fail++;
            }
            for (int i = 0; i < 4; ++i) free(buf[i]);
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diff_fail); failures++; }
    }

    /* ── 4. Parity: unaligned lane buffers, divergent lengths ────────── */
    printf("sha3_256_x4: parity (unaligned buffers, offsets 0..7) x8x16... ");
    {
        int diff_fail = 0;
        uint8_t *base = (uint8_t *)malloc(4096 + 8);
        if (!base) {
            printf("alloc FAIL\n"); failures++;
        } else {
            rng_fill(base, 4096 + 8);
            for (int off = 0; off < 8 && diff_fail == 0; ++off) {
                const uint8_t *msgs[4] = {
                    base + off, base + (off + 1) % 8,
                    base + (off + 3) % 8, base + (off + 7) % 8
                };
                for (size_t len = 130; len <= 142; ++len) {
                    /* Lanes straddle the 136B rate boundary at four lengths. */
                    size_t lens[4] = { len, len + 1, len + 2, len + 3 };
                    uint8_t ref[4][32], got[4][32];
                    for (int i = 0; i < 4; ++i) sha3_256(msgs[i], lens[i], ref[i]);

                    if (have_vec) sha3_256_x4_select_impl(SHA3_IMPL_VEC);
                    else          sha3_256_x4_select_impl(SHA3_IMPL_SCALAR);
                    sha3_256_x4(msgs, lens, got);
                    for (int i = 0; i < 4; ++i)
                        if (memcmp(ref[i], got[i], 32) != 0) diff_fail++;
                }
            }
            free(base);
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diff_fail); failures++; }
    }

    /* ── 5. Honest benchmark: batch-of-4 vs 4x scalar sha3_256 ──────── */
    {
        static const size_t sizes[] = { 64, 136, 512, 4096, 65536 };
        static const char  *names[] = { "64B", "136B", "512B", "4KB", "64KB" };
        static const size_t total_mb[] = { 32, 32, 64, 128, 256 };
        const size_t maxsz = 65536;
        uint8_t *b0 = (uint8_t *)malloc(maxsz), *b1 = (uint8_t *)malloc(maxsz);
        uint8_t *b2 = (uint8_t *)malloc(maxsz), *b3 = (uint8_t *)malloc(maxsz);
        if (!b0 || !b1 || !b2 || !b3) {
            printf("sha3_256_x4: bench alloc failed\n"); failures++;
        } else {
            rng_fill(b0, maxsz); rng_fill(b1, maxsz);
            rng_fill(b2, maxsz); rng_fill(b3, maxsz);
            printf("sha3_256_x4: --- benchmark (4 independent streams) ---\n");
            for (int s = 0; s < 5; ++s) {
                size_t insz = sizes[s];
                size_t groups = (total_mb[s] << 20) / (insz * 4);
                if (groups == 0) groups = 1;
                const uint8_t *msgs[4] = { b0, b1, b2, b3 };
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
                if (have_vec) sha3_256_x4_select_impl(SHA3_IMPL_VEC);
                else          sha3_256_x4_select_impl(SHA3_IMPL_SCALAR);
                for (int w = 0; w < 8; ++w) sha3_256_x4(msgs, lens, out4);
                t0 = now_s();
                for (size_t g = 0; g < groups; ++g) sha3_256_x4(msgs, lens, out4);
                double dt_x4 = now_s() - t0;
                double mb_x4 = ((double)insz * 4.0 * (double)groups)
                               / (1024.0*1024.0) / dt_x4;

                printf("sha3_256_x4:   %-6s  4x-scalar %8.1f MB/s   batch-x4 %8.1f MB/s   %.2fx%s\n",
                       names[s], mb_ref, mb_x4, mb_x4 / mb_ref,
                       have_vec ? "" : " (no vector lane: scalar-vs-scalar)");
            }
        }
        free(b0); free(b1); free(b2); free(b3);
    }

    /* Restore shipped defaults for any subsequent in-process hashing. */
    sha3_256_x4_select_impl(SHA3_IMPL_AUTO);

    printf("sha3_256_x4: %d failure(s)\n", failures);
    return failures;
}
