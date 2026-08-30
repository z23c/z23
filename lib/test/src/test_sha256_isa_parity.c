/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-ORACLE: lib/crypto/src/sha256.c
 *
 * Differential parity oracle for the two SHA-256 compression transforms in
 * lib/crypto/src/sha256.c: the portable C reference and the native hardware
 * transform (Intel SHA-NI or ARMv8 FEAT_SHA256).
 *
 * SHA-256 is consensus crypto here — block hashes, merkle roots, txids and
 * signature hashes all bottom out in it. A single differing verdict forks the
 * node off the network permanently, so the hardware transform is guilty until
 * proven byte-identical to the frozen portable reference. This group is that
 * proof, in the same shape as test_sha3_256_x4.c:
 *
 *   1. Reachability. On a CPU whose OS/CPUID feature authority advertises a
 *      SHA-256 tier, the node MUST actually run it. This is the regression
 *      guard for the defect this
 *      test was written for: sha256.c used to wrap the hardware transform and
 *      its dispatch in `#ifdef __SHA__`, and the shipped -march=x86-64-v3 does
 *      not define __SHA__, so the accelerated path was compiled out of every
 *      released binary while /proc/cpuinfo reported sha_ni. Re-introducing any
 *      compile-time guard fails HERE.
 *   2. FIPS-180-4 known-answer vectors through BOTH transforms.
 *   3. Exhaustive-length parity 0..600 — covers every padding geometry
 *      (the 55/56 length-field spill and both sides of each 64-byte block).
 *   4. Randomized parity over random lengths up to 4 KiB.
 *   5. Chunked-write parity: identical data fed as one write vs. random-sized
 *      writes, exercising the partial-block buffer under both transforms.
 *   6. Midstate parity: sha256_finalize_no_padding, the second dispatch
 *      consumer (tagged-hash / midstate constructions).
 *   7. Teeth. A valid input must hash to the published digest and a one-bit
 *      flip must not — a benchmark or a parity run over a hollow hash is worse
 *      than none.
 *   8. The boot self-test path (sha256_selftest) is still reachable and green.
 *   9. Honest benchmark, reported and never gated.
 *
 * On a host without a SHA hardware tier every parity leg degrades to
 * portable-vs-portable (still exercises padding/chunking geometry); that is
 * reported, not self-skipped.
 */

#define _POSIX_C_SOURCE 200809L

#include "crypto/sha256.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

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
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(rng_next() >> 19);
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);  // platform-ok:sha256-isa-parity-benchmark-realtime
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
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

static void sha256_oneshot(const uint8_t *in, size_t len, uint8_t out[32])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, in, len);
    sha256_finalize(&c, out);
}

/* Does the HOST advertise its native SHA-256 tier? Deliberately probed
 * independently of sha256.c so leg 1 cannot be satisfied by the code under
 * test agreeing with itself. */
static bool host_advertises_sha_hardware(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("sha") != 0;
#elif defined(__aarch64__) && defined(__APPLE__)
    int present = 0;
    size_t size = sizeof(present);
    return sysctlbyname("hw.optional.arm.FEAT_SHA256", &present, &size,
                        NULL, 0) == 0 &&
           size == sizeof(present) && present == 1;
#elif defined(__aarch64__) && defined(__linux__)
    return (getauxval(AT_HWCAP) & (1UL << 6)) != 0; /* HWCAP_SHA2 */
#else
    return false;
#endif
}

static const char *hardware_tier_name(void)
{
#if defined(__aarch64__)
    return "ARMv8 SHA";
#else
    return "SHA-NI";
#endif
}

int test_sha256_isa_parity(void)
{
    printf("\n=== sha256_isa_parity (portable vs native-hardware differential oracle) ===\n");
    int failures = 0;

    const bool hw = host_advertises_sha_hardware();
    const int  got_shani = sha256_select_impl(SHA256_IMPL_SHANI);
    const bool have_shani = (got_shani == SHA256_IMPL_SHANI);

    printf("sha256_isa_parity: host advertises %-10s... %s\n",
           hardware_tier_name(), hw ? "YES" : "no");
    printf("sha256_isa_parity: node selects................ %s\n",
           sha256_implementation());

    /* ── 1. Reachability — the regression guard ──────────────────────── */
    printf("sha256_isa_parity: hardware path reachable when CPU has it... ");
    if (!hw) {
        printf("not applicable (host advertises no SHA hardware)\n");
    } else if (have_shani && strstr(sha256_implementation(), "hardware")) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        printf("  The host reports %s but sha256.c refuses to install it.\n"
               "  This is the compile-time feature-guard defect: the\n"
               "  hardware transform has been compiled out of the shipped\n"
               "  binary again. The guard must be a RUNTIME check, never a\n"
               "  preprocessor one — see lib/crypto/src/sha256.c.\n",
               hardware_tier_name());
        failures++;
    }

    /* Every parity leg below compares the two transforms. Without hardware both
     * sides resolve to portable — still worth running for the geometry. */
    if (hw && !have_shani)
        printf("sha256_isa_parity: NOTE parity legs degrade to portable-vs-portable\n");

    /* ── 2. FIPS-180-4 known-answer vectors through BOTH transforms ──── */
    static const struct { const char *msg; size_t len; const char *want; } kat[] = {
        { "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
    };
    printf("sha256_isa_parity: FIPS-180-4 KATs on both transforms... ");
    {
        int kat_fail = 0;
        for (int pass = 0; pass < 2; ++pass) {
            sha256_select_impl(pass == 0 ? SHA256_IMPL_PORTABLE : SHA256_IMPL_SHANI);
            for (unsigned k = 0; k < sizeof(kat)/sizeof(kat[0]); ++k) {
                uint8_t want[32], got[32];
                hex2bin(kat[k].want, want, 32);
                sha256_oneshot((const uint8_t *)kat[k].msg, kat[k].len, got);
                if (memcmp(got, want, 32) != 0) kat_fail++;
            }
        }
        if (kat_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", kat_fail); failures++; }
    }

    /* ── 3. Exhaustive-length parity 0..600 ─────────────────────────── */
    printf("sha256_isa_parity: parity over every length 0..600... ");
    {
        int diff_fail = 0;
        uint8_t buf[601];
        for (size_t len = 0; len <= 600; ++len) {
            rng_fill(buf, len);
            uint8_t ref[32], got[32];
            sha256_select_impl(SHA256_IMPL_PORTABLE);
            sha256_oneshot(buf, len, ref);
            sha256_select_impl(SHA256_IMPL_SHANI);
            sha256_oneshot(buf, len, got);
            if (memcmp(ref, got, 32) != 0) {
                if (diff_fail < 3) printf("[len %zu] ", len);
                diff_fail++;
            }
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diff_fail); failures++; }
    }

    /* ── 4. Randomized parity, random lengths up to 4 KiB ───────────── */
    printf("sha256_isa_parity: randomized parity x20000 (len 0..4096)... ");
    {
        int diff_fail = 0;
        uint8_t *buf = (uint8_t *)malloc(4097);
        if (!buf) { printf("alloc FAIL\n"); failures++; }
        else {
            for (int trial = 0; trial < 20000; ++trial) {
                size_t len = (size_t)(rng_next() % 4097);
                rng_fill(buf, len);
                uint8_t ref[32], got[32];
                sha256_select_impl(SHA256_IMPL_PORTABLE);
                sha256_oneshot(buf, len, ref);
                sha256_select_impl(SHA256_IMPL_SHANI);
                sha256_oneshot(buf, len, got);
                if (memcmp(ref, got, 32) != 0) diff_fail++;
            }
            free(buf);
            if (diff_fail == 0) printf("OK\n");
            else { printf("FAIL (%d)\n", diff_fail); failures++; }
        }
    }

    /* ── 5. Chunked-write parity (partial-block buffer path) ────────── */
    printf("sha256_isa_parity: chunked-write parity x4000... ");
    {
        int diff_fail = 0;
        uint8_t *buf = (uint8_t *)malloc(2048);
        if (!buf) { printf("alloc FAIL\n"); failures++; }
        else {
            for (int trial = 0; trial < 4000; ++trial) {
                size_t len = (size_t)(rng_next() % 2049);
                rng_fill(buf, len);

                uint8_t ref[32], got[32];
                sha256_select_impl(SHA256_IMPL_PORTABLE);
                sha256_oneshot(buf, len, ref);

                /* Same bytes, arbitrary write boundaries, hardware transform. */
                sha256_select_impl(SHA256_IMPL_SHANI);
                struct sha256_ctx c;
                sha256_init(&c);
                size_t off = 0;
                while (off < len) {
                    size_t chunk = (size_t)(rng_next() % 97) + 1;
                    if (chunk > len - off) chunk = len - off;
                    sha256_write(&c, buf + off, chunk);
                    off += chunk;
                }
                sha256_finalize(&c, got);
                if (memcmp(ref, got, 32) != 0) diff_fail++;
            }
            free(buf);
            if (diff_fail == 0) printf("OK\n");
            else { printf("FAIL (%d)\n", diff_fail); failures++; }
        }
    }

    /* ── 6. Midstate parity: sha256_finalize_no_padding ─────────────── */
    printf("sha256_isa_parity: midstate (finalize_no_padding) parity x4000... ");
    {
        int diff_fail = 0;
        uint8_t block[64];
        for (int trial = 0; trial < 4000; ++trial) {
            rng_fill(block, sizeof block);
            uint8_t ref[32], got[32];
            struct sha256_ctx c;

            sha256_select_impl(SHA256_IMPL_PORTABLE);
            sha256_init(&c); sha256_write(&c, block, sizeof block);
            sha256_finalize_no_padding(&c, ref, 1);

            sha256_select_impl(SHA256_IMPL_SHANI);
            sha256_init(&c); sha256_write(&c, block, sizeof block);
            sha256_finalize_no_padding(&c, got, 1);

            if (memcmp(ref, got, 32) != 0) diff_fail++;
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diff_fail); failures++; }
    }

    /* ── 7. Teeth — both directions, on each transform ───────────────── */
    printf("sha256_isa_parity: teeth (KAT hit + one-bit-flip miss)\n");
    {
        static const uint8_t abc_digest[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,
            0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
        for (int pass = 0; pass < 2; ++pass) {
            const char *nm = pass == 0 ? "portable" : "hardware";
            sha256_select_impl(pass == 0 ? SHA256_IMPL_PORTABLE : SHA256_IMPL_SHANI);
            uint8_t good[32], bad[32];
            uint8_t msg[3] = { 'a', 'b', 'c' };
            sha256_oneshot(msg, 3, good);
            msg[2] ^= 0x01;                    /* "abc" -> "abb" */
            sha256_oneshot(msg, 3, bad);
            printf("  %s valid -> published digest... ", nm);
            if (memcmp(good, abc_digest, 32) == 0) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
            printf("  %s one-bit-flipped -> different... ", nm);
            if (memcmp(bad, abc_digest, 32) != 0) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }
    }

    /* ── 8. Boot self-test path still reachable ──────────────────────── */
    printf("sha256_isa_parity: boot self-test (sha256_selftest) green... ");
    {
        sha256_select_impl(SHA256_IMPL_AUTO);
        if (sha256_selftest()) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    printf("sha256_isa_parity: implementation string agrees with probe... ");
    {
        const char *impl = sha256_implementation();
        bool says_hw = strstr(impl, "hardware") != NULL;
        if (says_hw == have_shani) printf("OK (%s)\n", impl);
        else { printf("FAIL (%s)\n", impl); failures++; }
    }

    /* ── 9. Honest benchmark — reported, never gated ─────────────────── */
    {
        static const size_t sizes[] = { 64, 80, 1024, 65536 };
        static const char  *names[] = { "64B (merkle)", "80B (header)",
                                        "1KiB", "64KiB" };
        static const size_t iters[] = { 300000, 300000, 60000, 2000 };
        const size_t maxsz = 65536;
        uint8_t *b = (uint8_t *)malloc(maxsz);
        if (!b) { printf("sha256_isa_parity: bench alloc failed\n"); failures++; }
        else {
            rng_fill(b, maxsz);
            printf("sha256_isa_parity: --- benchmark (median-free, single run) ---\n");
            for (int s = 0; s < 4; ++s) {
                uint8_t out[32];
                double ns[2];
                for (int pass = 0; pass < 2; ++pass) {
                    sha256_select_impl(pass == 0 ? SHA256_IMPL_PORTABLE
                                                 : SHA256_IMPL_SHANI);
                    for (size_t w = 0; w < iters[s] / 8 + 1; ++w)
                        sha256_oneshot(b, sizes[s], out);
                    double t0 = now_s();
                    for (size_t i = 0; i < iters[s]; ++i)
                        sha256_oneshot(b, sizes[s], out);
                    ns[pass] = (now_s() - t0) * 1e9 / (double)iters[s];
                }
                printf("sha256_isa_parity:   %-13s portable %9.1f ns   hardware %9.1f ns   %.2fx%s\n",
                       names[s], ns[0], ns[1], ns[0] / ns[1],
                       have_shani ? "" : " (no hardware: portable-vs-portable)");
            }
            free(b);
        }
    }

    /* Restore the shipped default for any subsequent in-process hashing. */
    sha256_select_impl(SHA256_IMPL_AUTO);

    printf("sha256_isa_parity: %d failure(s)\n", failures);
    return failures;
}
