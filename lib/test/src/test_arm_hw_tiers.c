/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ACCEL-REACH: arm64 hardware crypto tiers reach the dispatch.
 *
 * lib/crypto/src/sha256.c and lib/util/src/crc32c.c each carry an arm64
 * hardware tier — the ARMv8 SHA extension (FEAT_SHA256) and the Castagnoli
 * instruction (FEAT_CRC32) — compiled into every arm64 binary through
 * per-function `target(...)` attributes and selected at RUNTIME through the
 * OS feature report. The x86 tiers have the same shape, and the x86 oracle
 * test_sha256_isa_parity guards their reachability with an INDEPENDENT
 * cpuid probe; its probe is x86-only, so on arm64 its reachability leg
 * degrades to SKIP and a silent compile-out of either tier here would turn
 * every parity leg into portable-vs-portable — green forever, proving
 * nothing. That is the defect class sha256.c actually shipped once on x86
 * (`#ifdef __SHA__` deleted the accelerated path from the released binary
 * while cpuinfo still advertised it).
 *
 * This group is the arm64 mirror of that guard: the host feature report is
 * probed here, independently of the code under test, and if the OS says the
 * extension is present the dispatch MUST have the tier active. On a host
 * without the extensions — and on x86 — every leg degrades to SKIP and the
 * group passes.
 *
 * Legs:
 *   1. sha256 reachability: FEAT_SHA256 advertised -> the node selects the
 *      hardware tier and sha256_implementation() says so.
 *   2. sha256 FIPS-180-4 KATs through the ACTIVE (auto) dispatch: published
 *      digests for the empty string, "abc", and the 56-byte and 112-byte
 *      two-block vectors.
 *   3. sha256 parity: portable vs selected hardware over random lengths —
 *      a bounded sweep here; the exhaustive differential is
 *      sha256_isa_parity's job, this one only has to prove the tier
 *      computes and agrees.
 *   4. crc32c reachability: FEAT_CRC32 advertised -> the self-checked
 *      hardware tier is active and the report says "hardware-*".
 *   5. crc32c parity: zcl_crc32c() (active tier) vs zcl_crc32c_sw() (the
 *      reference table) over every length 0..300 and a few odd sizes —
 *      exercising the 8/4/1-byte instruction split at both boundaries.
 *   6. Teeth: a planted wrong constant must be caught by this group's own
 *      comparator, so a hollow pass is distinguishable from a real one.
 */

#include "crypto/sha256.h"
#include "util/crc32c.h"

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Independent OS feature probe — deliberately NOT routed through the code
 * under test, so leg 1 cannot be satisfied by a module agreeing with
 * itself. */
static bool host_has(const char *sysctl_name)
{
#if defined(__APPLE__)
    int v = 0;
    size_t vlen = sizeof(v);
    if (sysctlbyname(sysctl_name, &v, &vlen, NULL, 0) != 0)
        return false;
    return v == 1;
#else
    (void)sysctl_name;
    return false;
#endif
}

/* Deterministic xorshift64* — no libc rand, reproducible across runs. */
static uint64_t rng_state = 0x94d049bb133111ebULL;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void sha256_oneshot(const uint8_t *in, size_t len, uint8_t out[32])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, in, len);
    sha256_finalize(&c, out);
}

static void hex32(const uint8_t *d, char out[65])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = hx[d[i] >> 4];
        out[2 * i + 1] = hx[d[i] & 0x0f];
    }
    out[64] = '\0';
}

int test_arm_hw_tiers(void)
{
    printf("\n=== arm_hw_tiers (arm64 hardware tier reachability) ===\n");
    int failures = 0;

    if (!host_has("hw.optional.arm.FEAT_SHA256") &&
        !host_has("hw.optional.arm.FEAT_CRC32")) {
        printf("arm_hw_tiers: SKIP (host advertises neither FEAT_SHA256 nor "
               "FEAT_CRC32)\n");
        return 0;
    }

    /* ── 1. sha256 reachability — the regression guard ───────────────── */
    if (host_has("hw.optional.arm.FEAT_SHA256")) {
        printf("arm_hw_tiers: FEAT_SHA256 advertised, tier selected... ");
        int installed = sha256_select_impl(SHA256_IMPL_SHANI);
        const char *impl = sha256_implementation();
        if (installed == SHA256_IMPL_SHANI &&
            strstr(impl, "hardware") != NULL &&
            strstr(impl, "ARMv8 SHA") == impl) {
            printf("OK (%s)\n", impl);
        } else {
            printf("FAIL (%s)\n", impl);
            printf("  The OS reports FEAT_SHA256 but sha256.c did not install\n"
                   "  the ARMv8 SHA transform. This is the silent compile-out\n"
                   "  defect: the hardware transform must be reached through a\n"
                   "  RUNTIME gate, never a preprocessor one — see the mirror\n"
                   "  comment in lib/crypto/src/sha256.c.\n");
            failures++;
        }
    } else {
        printf("arm_hw_tiers: SKIP sha256 legs (no FEAT_SHA256)\n");
    }

    /* ── 2. FIPS-180-4 KATs through the ACTIVE dispatch ──────────────── */
    printf("arm_hw_tiers: FIPS-180-4 KATs through the active dispatch... ");
    {
        static const struct { const char *msg; size_t len; const char *want; } kat[] = {
            { "", 0,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            { "abc", 3,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
            { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
              "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
        };
        int kat_fail = 0;
        for (unsigned k = 0; k < sizeof(kat) / sizeof(kat[0]); k++) {
            uint8_t got[32];
            char hex[65];
            sha256_oneshot((const uint8_t *)kat[k].msg, kat[k].len, got);
            hex32(got, hex);
            if (strcmp(hex, kat[k].want) != 0) {
                if (kat_fail < 2)
                    printf("[len %zu got %s] ", kat[k].len, hex);
                kat_fail++;
            }
        }
        if (kat_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", kat_fail); failures++; }
    }

    /* ── 3. portable vs selected-hardware parity, bounded ───────────── */
    printf("arm_hw_tiers: portable vs selected parity over random lengths... ");
    {
        int diff_fail = 0;
        uint8_t buf[4097];
        for (int trial = 0; trial < 300; trial++) {
            size_t len = (size_t)(rng_next() % (sizeof buf));
            for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t)(rng_next() >> 19);
            sha256_select_impl(SHA256_IMPL_PORTABLE);
            uint8_t ref[32];
            sha256_oneshot(buf, len, ref);
            sha256_select_impl(SHA256_IMPL_SHANI);
            uint8_t got[32];
            sha256_oneshot(buf, len, got);
            if (memcmp(ref, got, 32) != 0) {
                if (diff_fail < 3) printf("[len %zu] ", len);
                diff_fail++;
            }
        }
        if (diff_fail == 0) printf("OK\n");
        else { printf("FAIL (%d)\n", diff_fail); failures++; }
        sha256_select_impl(SHA256_IMPL_AUTO);
    }

    /* ── 4. crc32c reachability ──────────────────────────────────────── */
    if (host_has("hw.optional.arm.FEAT_CRC32")) {
        printf("arm_hw_tiers: FEAT_CRC32 advertised, tier active... ");
        (void)zcl_crc32c("", 0);   /* force the once-only probe + self-check */
        const char *impl = zcl_crc32c_impl_name();
        if (zcl_crc32c_hw_available() && strstr(impl, "hardware") == impl) {
            printf("OK (%s)\n", impl);
        } else {
            printf("FAIL (%s)\n", impl);
            printf("  The OS reports FEAT_CRC32 but the self-checked hardware\n"
                   "  tier is not active. Either the sysctl gate or the\n"
                   "  startup self-check in lib/util/src/crc32c.c refused it;\n"
                   "  a compile-time guard there would be the silent\n"
                   "  compile-out defect this group exists to catch.\n");
            failures++;
        }
    } else {
        printf("arm_hw_tiers: SKIP crc32c legs (no FEAT_CRC32)\n");
    }

    /* ── 5. active tier vs reference table over the width boundaries ─── */
    printf("arm_hw_tiers: crc32c active vs software reference, 0..300+odd... ");
    {
        int diff_fail = 0;
        uint8_t *buf = (uint8_t *)malloc(1024);
        if (!buf) {
            printf("alloc FAIL\n");
            failures++;
        } else {
            for (size_t i = 0; i < 1024; i++)
                buf[i] = (uint8_t)(i * 31u + 7u);
            size_t lens[320];
            size_t n = 0;
            for (size_t l = 0; l <= 300; l++) lens[n++] = l;
            lens[n++] = 1000; lens[n++] = 1008; lens[n++] = 1009;
            lens[n++] = 1015; lens[n++] = 1016; lens[n++] = 1023;
            for (size_t k = 0; k < n; k++) {
                if (zcl_crc32c(buf, lens[k]) != zcl_crc32c_sw(buf, lens[k])) {
                    if (diff_fail < 3) printf("[len %zu] ", lens[k]);
                    diff_fail++;
                }
            }
            free(buf);
            if (diff_fail == 0) printf("OK\n");
            else { printf("FAIL (%d)\n", diff_fail); failures++; }
        }
    }

    /* ── 6. Teeth — the comparator catches a planted wrong answer ────── */
    printf("arm_hw_tiers: teeth (published digest hits, mutants miss)... ");
    {
        const char *want = "ba7816bf8f01cfea414140de5dae2223"
                           "b00361a396177a9cb410ff61f20015ad";
        char planted[65];
        memcpy(planted, want, 65);
        planted[7] = planted[7] == 'a' ? 'b' : 'a';   /* corrupt one nibble */

        uint8_t got[32], flipped[32];
        char hex[65], fliphex[65];
        sha256_oneshot((const uint8_t *)"abc", 3, got);
        hex32(got, hex);
        sha256_oneshot((const uint8_t *)"abb", 3, flipped);  /* one-bit flip */
        hex32(flipped, fliphex);

        int hits   = strcmp(hex, want) == 0;
        int mutant = strcmp(hex, planted) != 0;      /* comparator has teeth */
        int differs = strcmp(fliphex, want) != 0;    /* the flip must not hit */
        if (hits && mutant && differs) printf("OK\n");
        else {
            printf("FAIL (hits=%d mutant_rejected=%d flip_differs=%d)\n",
                   hits, mutant, differs);
            failures++;
        }
    }

    /* ── honest tier report (evidence, not a gate) ───────────────────── */
    printf("arm_hw_tiers: sha256=%s crc32c=%s\n",
           sha256_implementation(), zcl_crc32c_impl_name());

    printf("arm_hw_tiers: %d failure(s)\n", failures);
    return failures;
}
