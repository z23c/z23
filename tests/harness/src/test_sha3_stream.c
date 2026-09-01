/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Correctness oracle for the single-stream SHA3-256/512 surface (sha3.c).
 *
 *   1. FIPS-202 known-answer vectors for SHA3-256 and SHA3-512.
 *   2. Streaming-vs-one-shot differential across every input length 0..1100,
 *      which crosses each rate boundary (136 bytes for SHA3-256, 72 for
 *      SHA3-512) and the empty case.
 *   3. Incremental-absorb differential at random split points: writing a
 *      message in arbitrary chunks must equal hashing the concatenation.
 *   4. Honest throughput report for short / medium / long inputs. Reported,
 *      never gated — perf is measured, not wished.
 *
 * Was `keccak_avx512`, a differential oracle for an AVX-512 single-stream
 * permutation that sat beside the scalar one. That permutation measured 0.70x
 * the scalar path on Zen 4 (`make bench-simd`) and was default-off, so nothing
 * but this test ever executed it; it has been deleted. What is left here is the
 * half of the group that was never about AVX-512: the FIPS-202 vectors and the
 * streaming machinery, which are worth keeping on their own. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "crypto/sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Deterministic xorshift64* — no libc rand, reproducible across runs. */
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
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
    clock_gettime(CLOCK_MONOTONIC, &t);  // platform-ok:sha3-stream-benchmark-realtime
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int test_sha3_stream(void)
{
    int failures = 0;

    /* ── 1. FIPS-202 known-answer vectors ────────────────────────────── */
    struct { const char *msg; size_t msglen; const char *h256; const char *h512; } kat[] = {
        { "", 0,
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
          "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
          "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
        { "abc", 3,
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
          "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
    };
    for (unsigned k = 0; k < sizeof(kat)/sizeof(kat[0]); ++k) {
        uint8_t want256[32], want512[64];
        hex2bin(kat[k].h256, want256, 32);
        hex2bin(kat[k].h512, want512, 64);

        uint8_t got256[32], got512[64];
        sha3_256((const unsigned char *)kat[k].msg, kat[k].msglen, got256);
        sha3_512((const unsigned char *)kat[k].msg, kat[k].msglen, got512);
        printf("sha3_stream: FIPS-202 KAT[%u] SHA3-256/512... ", k);
        if (memcmp(got256, want256, 32) == 0 && memcmp(got512, want512, 64) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. Streamed vs one-shot, every length 0..1100 ───────────────── */
    printf("sha3_stream: streamed == one-shot, lengths 0..1100... ");
    {
        int diff_fail = 0;
        uint8_t buf[1101];
        for (size_t len = 0; len <= 1100; ++len) {
            rng_fill(buf, len);
            uint8_t one256[32], str256[32], one512[64], str512[64];
            sha3_256(buf, len, one256);
            sha3_512(buf, len, one512);

            /* Byte-at-a-time absorb: the worst case for the rate bookkeeping. */
            struct sha3_256_ctx c256;
            struct sha3_512_ctx c512;
            sha3_256_init(&c256);
            sha3_512_init(&c512);
            for (size_t i = 0; i < len; ++i) {
                sha3_256_write(&c256, buf + i, 1);
                sha3_512_write(&c512, buf + i, 1);
            }
            sha3_256_finalize(&c256, str256);
            sha3_512_finalize(&c512, str512);

            if (memcmp(one256, str256, 32) != 0 || memcmp(one512, str512, 64) != 0) {
                if (diff_fail < 3) printf("[len %zu MISMATCH] ", len);
                diff_fail++;
            }
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d mismatches)\n", diff_fail); failures++; }
    }

    /* ── 3. Incremental absorb at random split points ────────────────── */
    printf("sha3_stream: incremental absorb vs one-shot (random splits)... ");
    {
        int inc_fail = 0;
        uint8_t buf[2048];
        for (int trial = 0; trial < 4000; ++trial) {
            size_t len = (size_t)(rng_next() % 2000) + 1;
            rng_fill(buf, len);

            uint8_t oneshot[32], streamed[32];
            sha3_256(buf, len, oneshot);

            struct sha3_256_ctx ctx;
            sha3_256_init(&ctx);
            size_t off = 0;
            while (off < len) {
                size_t chunk = (size_t)(rng_next() % 200);
                if (chunk == 0) chunk = 1;
                if (off + chunk > len) chunk = len - off;
                sha3_256_write(&ctx, buf + off, chunk);
                off += chunk;
            }
            sha3_256_finalize(&ctx, streamed);
            if (memcmp(oneshot, streamed, 32) != 0) inc_fail++;
        }
        if (inc_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", inc_fail); failures++; }
    }

    /* ── 4. SHAKE KATs, multi-block squeeze and checked pointers ────── */
    printf("sha3_stream: FIPS-202 SHAKE128/256 KATs... ");
    {
        static const char *shake128_empty =
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
        static const char *shake256_empty =
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
        uint8_t want128[32], want256[64];
        uint8_t got128[32], got256[64];
        hex2bin(shake128_empty, want128, sizeof(want128));
        hex2bin(shake256_empty, want256, sizeof(want256));
        bool ok = zcl_shake128(NULL, 0, got128, sizeof(got128)) &&
                  zcl_shake256(NULL, 0, got256, sizeof(got256)) &&
                  memcmp(got128, want128, sizeof(got128)) == 0 &&
                  memcmp(got256, want256, sizeof(got256)) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("sha3_stream: SHAKE multi-block prefix/canary/NULL contract... ");
    {
        uint8_t msg[169], long_out[402], prefix[169], untouched[8];
        memset(msg, 0x3c, sizeof(msg));
        memset(long_out, 0xa5, sizeof(long_out));
        memset(prefix, 0, sizeof(prefix));
        memset(untouched, 0x6d, sizeof(untouched));
        bool ok = zcl_shake128(msg, sizeof(msg), long_out + 1, 400) &&
                  zcl_shake128(msg, sizeof(msg), prefix, sizeof(prefix)) &&
                  long_out[0] == 0xa5 && long_out[401] == 0xa5 &&
                  memcmp(long_out + 1, prefix, sizeof(prefix)) == 0 &&
                  zcl_shake128(NULL, 0, NULL, 0) &&
                  zcl_shake256(msg, sizeof(msg), NULL, 0) &&
                  !zcl_shake128(NULL, 1, untouched, sizeof(untouched)) &&
                  !zcl_shake256(msg, sizeof(msg), NULL, 1);
        for (size_t i = 0; i < sizeof(untouched); i++)
            ok = ok && untouched[i] == 0x6d;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 5. Honest throughput report (informational, never gated) ────── */
    {
        static const size_t sizes[] = { 136, 4096, 1u << 20 };
        static const char  *names[] = { "short(136B)", "medium(4KB)", "long(1MB)" };
        /* Total bytes hashed per measurement, tuned so each is ~0.1-0.3s. */
        static const size_t total_mb[] = { 64, 256, 512 };
        uint8_t *buf = (uint8_t *)malloc(1u << 20);
        if (!buf) { printf("sha3_stream: bench alloc failed\n"); failures++; }
        else {
            rng_fill(buf, 1u << 20);
            uint8_t out[32];
            printf("sha3_stream: --- SHA3-256 throughput ---\n");
            for (int s = 0; s < 3; ++s) {
                size_t insz = sizes[s];
                size_t iters = (total_mb[s] << 20) / insz;
                if (iters == 0) iters = 1;
                for (int w = 0; w < 8; ++w) sha3_256(buf, insz, out);
                double t0 = now_s();
                for (size_t i = 0; i < iters; ++i) sha3_256(buf, insz, out);
                double dt = now_s() - t0;
                printf("sha3_stream:   %-11s  %8.1f MB/s\n", names[s],
                       ((double)insz * (double)iters) / (1024.0*1024.0) / dt);
            }
            printf("sha3_stream: --- one permutation, no dispatch (see sha3.c) ---\n");
            free(buf);
        }
    }

    printf("sha3_stream: %d failure(s)\n", failures);
    return failures;
}
