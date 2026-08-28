/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: lib/crypto/src/sha3_avx512.c
 *
 * Differential parity oracle + honest benchmark for the 4-way SHA3-512
 * keystream primitive (lib/crypto/src/sha3_avx512.c).
 *
 * sha3_512_x4(key, nonce, ctr, out) produces 256 bytes: SHA3-512(key || nonce ||
 * le64(ctr+i)) for i in 0..3. It is NOT consensus crypto — it is the frame
 * cipher keystream for the file-transfer service (lib/net/src/file_service.c) —
 * but it IS wire-visible: a vector build whose keystream diverged by one bit
 * from a scalar build could not exchange a single file-market frame with it. So
 * a byte-identity oracle is mandatory before the vector lane is allowed on.
 *
 * This group exists because the vector lane used to be unreachable: it sat
 * behind `#ifdef __AVX512F__`, which the shipped -march=x86-64-v3 does not
 * define, so every shipped binary silently ran the scalar fallback. Nothing
 * detected that, because nothing compared the two lanes.
 *
 *   1. Known-answer: the four lanes vs four independent one-shot sha3_512
 *      hashes of the exact 72-byte preimage, on BOTH implementations.
 *   2. Randomized parity: 20000 random (key, nonce, counter) triples, vector
 *      lane vs scalar lane, all 256 bytes compared.
 *   3. Counter-carry geometry: counter_base values that make the +0..+3 lanes
 *      straddle a 2^8 / 2^16 / 2^32 / 2^64 boundary (little-endian byte carry
 *      into higher preimage bytes, and the wrap at UINT64_MAX).
 *   4. TEETH: a one-bit flip in the key, in the nonce, and a +1 on the counter
 *      must each change the keystream — on BOTH lanes. A hollow-fast keystream
 *      (e.g. one that returned zeros) would be caught here, not in the bench.
 *   5. Honest benchmark: one 64 KiB file_service frame = 256 calls. Reported,
 *      never gated.
 *
 * The vector lane is AVX-512 on x86-64 and NEON on arm64. When the host lacks
 * its vector tier the parity passes degrade to scalar-vs-scalar;
 * that is reported, not failed. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_helpers.h"
#include "crypto/sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__)
#define SHA3_IMPL_VEC SHA3_IMPL_AVX512
#define SHA3_VEC_NAME "AVX-512"
#elif defined(__aarch64__)
#define SHA3_IMPL_VEC SHA3_IMPL_NEON
#define SHA3_VEC_NAME "NEON"
#else
#define SHA3_IMPL_VEC SHA3_IMPL_SCALAR
#define SHA3_VEC_NAME "none"
#endif

/* Deterministic xorshift64* — no libc rand, reproducible across runs. */
static uint64_t x4_rng = 0x9e3779b97f4a7c15ULL;
static uint64_t x4_rand(void)
{
    uint64_t x = x4_rng;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    x4_rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static void x4_fill(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(x4_rand() >> 21);
}

static double x4_now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);  // platform-ok:sha3-512-x4-benchmark-realtime
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* The contract, spelled out independently of the primitive: four one-shot
 * SHA3-512 hashes over key(32) || nonce(32) || le64(counter_base + i). */
static void x4_reference(const uint8_t key[32], const uint8_t nonce[32],
                         uint64_t counter_base, uint8_t out[256])
{
    for (int i = 0; i < 4; ++i) {
        uint8_t pre[72];
        memcpy(pre, key, 32);
        memcpy(pre + 32, nonce, 32);
        uint64_t ctr = counter_base + (uint64_t)i;
        for (int b = 0; b < 8; ++b)
            pre[64 + b] = (uint8_t)(ctr >> (8 * b));
        sha3_512(pre, sizeof(pre), out + i * 64);
    }
}

int test_sha3_512_x4(void)
{
    int failures = 0;
    const bool have_vec = keccak_x4_available();

    printf("\n=== sha3_512_x4 (4-way SHA3-512 keystream parity oracle) ===\n");
    printf("sha3_512_x4: %s 4-lane Keccak available on host... %s\n",
           SHA3_VEC_NAME,
           have_vec ? "YES" : "no (parity runs scalar-vs-scalar)");

    /* ── 1. Contract: both lanes == 4x independent one-shot sha3_512 ──── */
    printf("sha3_512_x4: matches 4x one-shot sha3_512(key||nonce||le64(ctr))... ");
    {
        int bad = 0;
        for (int pass = 0; pass < 2; ++pass) {
            if (pass == 1) {
                if (!have_vec) break;
                if (sha3_512_x4_select_impl(SHA3_IMPL_VEC) != SHA3_IMPL_VEC)
                    bad++;
            } else {
                sha3_512_x4_select_impl(SHA3_IMPL_SCALAR);
            }
            for (int trial = 0; trial < 64; ++trial) {
                uint8_t key[32], nonce[32], want[256], got[256];
                x4_fill(key, 32);
                x4_fill(nonce, 32);
                uint64_t ctr = (trial == 0) ? 0 : x4_rand();
                x4_reference(key, nonce, ctr, want);
                sha3_512_x4(key, nonce, ctr, got);
                if (memcmp(want, got, 256) != 0) bad++;
            }
        }
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", bad); failures++; }
    }

    /* ── 2. Randomized parity: vector lane vs scalar lane, 20000 triples ─ */
    printf("sha3_512_x4: parity vector-vs-scalar x20000 random triples... ");
    {
        int bad = 0;
        for (int trial = 0; trial < 20000; ++trial) {
            uint8_t key[32], nonce[32], ref[256], got[256];
            x4_fill(key, 32);
            x4_fill(nonce, 32);
            uint64_t ctr = x4_rand();

            sha3_512_x4_select_impl(SHA3_IMPL_SCALAR);
            sha3_512_x4(key, nonce, ctr, ref);

            if (have_vec) sha3_512_x4_select_impl(SHA3_IMPL_VEC);
            sha3_512_x4(key, nonce, ctr, got);

            if (memcmp(ref, got, 256) != 0) {
                if (bad < 3) {
                    printf("[trial %d ctr %llu lanes", trial,
                           (unsigned long long)ctr);
                    for (int L = 0; L < 4; ++L)
                        if (memcmp(ref + L * 64, got + L * 64, 64) != 0)
                            printf(" %d", L);
                    printf("] ");
                }
                bad++;
            }
        }
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", bad); failures++; }
    }

    /* ── 3. Counter-carry geometry across the 4 lanes ─────────────────── */
    printf("sha3_512_x4: counter carry/wrap boundaries (both lanes)... ");
    {
        static const uint64_t bases[] = {
            0, 1, 253, 254, 255,
            65533, 65534, 65535,
            0xFFFFFFFEULL, 0xFFFFFFFFULL, 0x100000000ULL,
            0xFFFFFFFFFFFFFFFDULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,
        };
        int bad = 0;
        uint8_t key[32], nonce[32];
        memset(key, 0xa5, 32);
        memset(nonce, 0x5a, 32);
        for (unsigned k = 0; k < sizeof(bases) / sizeof(bases[0]); ++k) {
            uint8_t want[256], ref[256], got[256];
            x4_reference(key, nonce, bases[k], want);

            sha3_512_x4_select_impl(SHA3_IMPL_SCALAR);
            sha3_512_x4(key, nonce, bases[k], ref);

            if (have_vec) sha3_512_x4_select_impl(SHA3_IMPL_VEC);
            sha3_512_x4(key, nonce, bases[k], got);

            if (memcmp(want, ref, 256) != 0 || memcmp(want, got, 256) != 0) {
                if (bad < 3) printf("[base %llu] ", (unsigned long long)bases[k]);
                bad++;
            }
        }
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", bad); failures++; }
    }

    /* ── 4. TEETH: the keystream must actually depend on every input ──── */
    printf("sha3_512_x4: teeth (key/nonce/counter each change keystream)... ");
    {
        int bad = 0;
        for (int pass = 0; pass < 2; ++pass) {
            if (pass == 1) {
                if (!have_vec) break;
                sha3_512_x4_select_impl(SHA3_IMPL_VEC);
            } else {
                sha3_512_x4_select_impl(SHA3_IMPL_SCALAR);
            }
            uint8_t key[32], nonce[32], base[256], flip[256];
            memset(key, 0, 32);
            memset(nonce, 0, 32);
            sha3_512_x4(key, nonce, 0, base);

            /* A zero keystream would be a hollow primitive — reject it. */
            {
                uint8_t zeros[256];
                memset(zeros, 0, 256);
                if (memcmp(base, zeros, 256) == 0) bad++;
            }
            /* The four lanes must differ from each other (they are four
             * DIFFERENT counters, not one hash memcpy'd four times). */
            for (int L = 1; L < 4; ++L)
                if (memcmp(base, base + L * 64, 64) == 0) bad++;

            key[7] ^= 0x01;
            sha3_512_x4(key, nonce, 0, flip);
            if (memcmp(base, flip, 256) == 0) bad++;
            key[7] ^= 0x01;

            nonce[31] ^= 0x80;
            sha3_512_x4(key, nonce, 0, flip);
            if (memcmp(base, flip, 256) == 0) bad++;
            nonce[31] ^= 0x80;

            sha3_512_x4(key, nonce, 1, flip);
            if (memcmp(base, flip, 256) == 0) bad++;
        }
        if (bad == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", bad); failures++; }
    }

    /* ── 5. Honest benchmark: one 64 KiB file_service frame = 256 calls ── */
    {
        uint8_t key[32], nonce[32], out[256];
        memset(key, 0xa5, 32);
        memset(nonce, 0x5a, 32);
        const long frames = 300;                 /* 300 * 64 KiB = 18.75 MiB */
        const long calls_per_frame = 256;
        volatile uint8_t sink = 0;

        printf("sha3_512_x4: --- benchmark (256 B keystream / call) ---\n");
        for (int pass = 0; pass < 2; ++pass) {
            const char *lbl;
            if (pass == 1) {
                if (!have_vec) break;
                sha3_512_x4_select_impl(SHA3_IMPL_VEC);
                lbl = SHA3_VEC_NAME;
            } else {
                sha3_512_x4_select_impl(SHA3_IMPL_SCALAR);
                lbl = "scalar-x4  ";
            }
            for (long w = 0; w < 20; ++w)
                for (long i = 0; i < calls_per_frame; ++i) {
                    sha3_512_x4(key, nonce, (uint64_t)i * 4, out);
                    sink ^= out[0];
                }
            double t0 = x4_now_s();
            for (long f = 0; f < frames; ++f)
                for (long i = 0; i < calls_per_frame; ++i) {
                    sha3_512_x4(key, nonce, (uint64_t)i * 4, out);
                    sink ^= out[0];
                }
            double dt = x4_now_s() - t0;
            double calls = (double)frames * (double)calls_per_frame;
            printf("sha3_512_x4:   %s  %8.1f ns/call  %8.1f MiB/s  %7.1f us / 64KiB frame\n",
                   lbl, dt * 1e9 / calls,
                   ((double)frames * 64.0 / 1024.0) / dt,
                   dt * 1e6 / (double)frames);
        }
        (void)sink;
    }

    /* Restore the shipped default for any subsequent in-process use. */
    sha3_512_x4_select_impl(SHA3_IMPL_AUTO);

    printf("sha3_512_x4: %d failure(s)\n", failures);
    return failures;
}
