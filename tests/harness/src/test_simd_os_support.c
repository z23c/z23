/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/crypto/src/simd_dispatch.c
 *
 * SIMD dispatch OS-support test.
 *
 * WHY THIS COUNTS AS AN ACCEL ORACLE
 * ----------------------------------
 * simd_dispatch.c computes no field arithmetic, so it has no portable
 * reference to be byte-identical to. What it decides is WHICH arithmetic runs
 * under a sealed consensus predicate — Equihash's batched BLAKE2b and the SHA3
 * lanes both route their tier selection through it — so getting it wrong
 * silently changes which implementation validates a block, exactly the drift
 * the registry exists to catch. Its reference is therefore a table of register
 * words with the correct answer written out by hand, including the answers
 * that must be "no", plus a live check that the tier it actually selects on
 * this host still agrees with sequential BLAKE2b.
 *
 * THE MACHINE WE CANNOT BUY
 * -------------------------
 * The failure this guards is a host whose CPUID advertises AVX-512F while
 * its OS has NOT enabled the ZMM state components in XCR0 — `noxsave`,
 * `clearcpuid=avx512f`, a hypervisor that masks XCR0. On that host, code
 * that dispatches on the CPUID bit alone executes a ZMM instruction and
 * takes #UD: SIGILL, from a predicate that said "supported". This host
 * is a normal AVX-512 machine with XCR0 fully enabled, so the bad
 * configuration is not reachable here by running anything.
 *
 * That is exactly why crypto/simd_dispatch.h splits the PROBE (touches
 * hardware) from the POLICY (a pure function of three register words).
 * The policy can be handed the register contents of a machine we do not
 * have. Every case below is a synthetic CPUID/XCR0 triple.
 *
 * core/modules/crypto/src/blake2b_avx2.c shipped with the CPUID-only bug on the
 * Equihash verification path. It is now routed through this policy, and
 * the lint gate `check-no-adx-overclaim`'s sibling
 * `check-simd-os-support` keeps any future AVX dispatch site from
 * skipping the check. */

#include "test/test_core.h"
#include "crypto/simd_dispatch.h"
#include "crypto/blake2b.h"
#include <stdio.h>
#include <string.h>

/* Bit positions the policy reads, restated here so the test does not
 * borrow the implementation's own constants. */
#define ECX_XSAVE   (1u << 26)
#define ECX_OSXSAVE (1u << 27)
#define ECX_AVX     (1u << 28)
#define EBX_AVX2     (1u << 5)
#define EBX_AVX512F  (1u << 16)
#define EBX_AVX512DQ (1u << 17)
#define EBX_AVX512VL (1u << 31)

/* XCR0 layouts, spelled out. */
#define XCR0_X87_SSE_YMM 0x7ull  /* bits 0,1,2 — a normal AVX2 host      */
#define XCR0_X87_SSE     0x3ull  /* bits 0,1   — SSE only, no YMM state  */
#define XCR0_FULL_AVX512 0xE7ull /* bits 0,1,2,5,6,7 — full ZMM state    */

static int g_fail;

static void expect(bool got, bool want, const char *what)
{
    if (got == want) return;
    printf("FAIL (%s: got %d, expected %d)\n", what, got, want);
    g_fail++;
}

int test_simd_os_support(void)
{
    g_fail = 0;
    printf("\n=== simd_os_support (CPUID is not permission; XCR0 is) ===\n");

    /* ── The regression case, stated first ───────────────────────────
     * CPUID says AVX-512F. The OS enabled SSE and YMM state but NOT the
     * three ZMM components. A CPUID-only predicate returns true here and
     * the process dies on the first zmm instruction. */
    printf("AVX-512F in CPUID + ZMM state OFF in XCR0 -> unusable... ");
    {
        struct simd_cpu_words w = {
            .leaf1_ecx = ECX_XSAVE | ECX_OSXSAVE | ECX_AVX,
            .leaf7_ebx = EBX_AVX2 | EBX_AVX512F | EBX_AVX512DQ | EBX_AVX512VL,
            .xcr0 = XCR0_X87_SSE_YMM,   /* no bits 5/6/7 */
            .leaf1_valid = true, .leaf7_valid = true, .xcr0_valid = true,
        };
        expect(simd_avx512f_usable(&w), false, "avx512f with ZMM state off");
        expect(simd_avx512_dq_vl_usable(&w), false, "avx512dq/vl with ZMM state off");
        /* AVX2 is still fine on that machine — the fix must not over-disable. */
        expect(simd_avx2_usable(&w), true, "avx2 with YMM state on");
        printf("%s\n", g_fail ? "FAIL" : "OK");
    }

    /* ── Partial ZMM enablement: each of the three bits alone is not
     * enough. A hypervisor that masks one component is the realistic
     * shape of this. */
    printf("each single missing ZMM state bit -> unusable... ");
    {
        int before = g_fail;
        const uint64_t bits[3] = {
            SIMD_XCR0_OPMASK, SIMD_XCR0_ZMM_HI256, SIMD_XCR0_HI16_ZMM
        };
        for (int i = 0; i < 3; i++) {
            struct simd_cpu_words w = {
                .leaf1_ecx = ECX_XSAVE | ECX_OSXSAVE | ECX_AVX,
                .leaf7_ebx = EBX_AVX2 | EBX_AVX512F | EBX_AVX512DQ | EBX_AVX512VL,
                .xcr0 = XCR0_FULL_AVX512 & ~bits[i],
                .leaf1_valid = true, .leaf7_valid = true, .xcr0_valid = true,
            };
            expect(simd_avx512f_usable(&w), false, "avx512f missing one ZMM bit");
        }
        printf("%s\n", g_fail > before ? "FAIL" : "OK");
    }

    /* ── YMM state off: AVX2 must be refused even though CPUID says AVX2.
     * `noxsave`-style boots land here. */
    printf("AVX2 in CPUID + YMM state OFF -> unusable... ");
    {
        int before = g_fail;
        struct simd_cpu_words w = {
            .leaf1_ecx = ECX_XSAVE | ECX_OSXSAVE | ECX_AVX,
            .leaf7_ebx = EBX_AVX2 | EBX_AVX512F,
            .xcr0 = XCR0_X87_SSE,
            .leaf1_valid = true, .leaf7_valid = true, .xcr0_valid = true,
        };
        expect(simd_avx2_usable(&w), false, "avx2 with YMM state off");
        expect(simd_avx512f_usable(&w), false, "avx512f with YMM state off");
        printf("%s\n", g_fail > before ? "FAIL" : "OK");
    }

    /* ── OSXSAVE clear: XGETBV itself is #UD, so no XCR0 reading is even
     * legal and every wide tier must be refused regardless of CPUID. */
    printf("OSXSAVE clear -> every tier unusable... ");
    {
        int before = g_fail;
        struct simd_cpu_words w = {
            .leaf1_ecx = ECX_XSAVE | ECX_AVX,   /* no OSXSAVE */
            .leaf7_ebx = EBX_AVX2 | EBX_AVX512F | EBX_AVX512DQ | EBX_AVX512VL,
            .xcr0 = XCR0_FULL_AVX512,           /* stale/unreadable */
            .leaf1_valid = true, .leaf7_valid = true, .xcr0_valid = false,
        };
        expect(simd_avx2_usable(&w), false, "avx2 without OSXSAVE");
        expect(simd_avx512f_usable(&w), false, "avx512f without OSXSAVE");
        printf("%s\n", g_fail > before ? "FAIL" : "OK");
    }

    /* ── A CPUID leaf that could not be read is never a yes. */
    printf("unreadable CPUID leaf -> unusable... ");
    {
        int before = g_fail;
        struct simd_cpu_words w = {
            .leaf1_ecx = ECX_XSAVE | ECX_OSXSAVE | ECX_AVX,
            .leaf7_ebx = EBX_AVX2 | EBX_AVX512F,
            .xcr0 = XCR0_FULL_AVX512,
            .leaf1_valid = true, .leaf7_valid = false, .xcr0_valid = true,
        };
        expect(simd_avx2_usable(&w), false, "avx2 with leaf7 unreadable");
        expect(simd_avx512f_usable(&w), false, "avx512f with leaf7 unreadable");

        struct simd_cpu_words z;
        memset(&z, 0, sizeof z);
        expect(simd_avx2_usable(&z), false, "avx2 on all-zero words");
        expect(simd_avx512f_usable(&z), false, "avx512f on all-zero words");
        expect(simd_avx512_dq_vl_usable(&z), false, "avx512dq/vl on all-zero words");
        printf("%s\n", g_fail > before ? "FAIL" : "OK");
    }

    /* ── The positive case must still say yes, or the fix is just a
     * blanket disable dressed up as a check. */
    printf("fully enabled AVX-512 host -> usable... ");
    {
        int before = g_fail;
        struct simd_cpu_words w = {
            .leaf1_ecx = ECX_XSAVE | ECX_OSXSAVE | ECX_AVX,
            .leaf7_ebx = EBX_AVX2 | EBX_AVX512F | EBX_AVX512DQ | EBX_AVX512VL,
            .xcr0 = XCR0_FULL_AVX512,
            .leaf1_valid = true, .leaf7_valid = true, .xcr0_valid = true,
        };
        expect(simd_avx2_usable(&w), true, "avx2 on a full host");
        expect(simd_avx512f_usable(&w), true, "avx512f on a full host");
        expect(simd_avx512_dq_vl_usable(&w), true, "avx512dq/vl on a full host");

        /* DQ/VL are a strict superset requirement of F. */
        w.leaf7_ebx &= ~EBX_AVX512VL;
        expect(simd_avx512f_usable(&w), true, "avx512f without VL");
        expect(simd_avx512_dq_vl_usable(&w), false, "avx512dq/vl without VL");
        printf("%s\n", g_fail > before ? "FAIL" : "OK");
    }

    /* ── Live host: whatever the probe says, it must be SELF-CONSISTENT.
     * A "yes" that is not backed by the XCR0 bits would mean the probe
     * and the policy disagree. */
    printf("live probe is self-consistent... ");
    {
        int before = g_fail;
        struct simd_cpu_words w;
        simd_cpu_words_probe(&w);

        if (simd_avx512f_usable(&w)) {
            expect(w.xcr0_valid, true, "avx512f yes implies xcr0 was read");
            expect((w.xcr0 & SIMD_XCR0_AVX512_MASK) == SIMD_XCR0_AVX512_MASK,
                   true, "avx512f yes implies every ZMM state bit set");
        }
        if (simd_avx2_usable(&w)) {
            expect(w.xcr0_valid, true, "avx2 yes implies xcr0 was read");
            expect((w.xcr0 & SIMD_XCR0_AVX_MASK) == SIMD_XCR0_AVX_MASK,
                   true, "avx2 yes implies SSE+YMM state set");
        }
        /* The cached accessors must agree with the one-shot policy. */
        expect(simd_host_has_avx2(), simd_avx2_usable(&w), "cached avx2 answer");
        expect(simd_host_has_avx512f(), simd_avx512f_usable(&w),
               "cached avx512f answer");
        printf("%s\n", g_fail > before ? "FAIL" : "OK");

        printf("  host: avx2=%d avx512f=%d xcr0=0x%llx (valid=%d)\n",
               (int)simd_host_has_avx2(), (int)simd_host_has_avx512f(),
               (unsigned long long)w.xcr0, (int)w.xcr0_valid);
    }

    /* ── The consumer still hashes correctly. Whichever tier the fixed
     * predicate selects on THIS host, the 4-way and 8-way batch APIs must
     * agree with sequential BLAKE2b — the dispatch fix must not have
     * silently changed which lane runs into a wrong one. */
    printf("blake2b batch dispatch matches sequential... ");
    {
        int before = g_fail;
        struct blake2b_ctx base;
        uint8_t personal[BLAKE2B_PERSONALBYTES] = {0};
        memcpy(personal, "ZcashPoW", 8);
        blake2b_init_salt_personal(&base, 50, NULL, 0, NULL, personal);
        blake2b_update(&base, (const uint8_t *)"dispatch-fix", 12);

        uint32_t idx[8];
        for (int i = 0; i < 8; i++) idx[i] = (uint32_t)(i * 7919u + 3u);

        unsigned char got[8][64];
        unsigned char *gp[8];
        for (int i = 0; i < 8; i++) gp[i] = got[i];
        equihash_generate_hash_batch8(&base, idx, gp, 50);

        for (int i = 0; i < 8; i++) {
            unsigned char want[64];
            struct blake2b_ctx s = base;
            blake2b_update(&s, (const uint8_t *)&idx[i], sizeof(uint32_t));
            blake2b_final(&s, want, 50);
            if (memcmp(want, got[i], 50) != 0) {
                printf("\n  batch8 lane %d differs from sequential\n", i);
                g_fail++;
            }
        }

        unsigned char a[64], b[64], c[64], d[64];
        equihash_generate_hash_batch4(&base, idx, a, b, c, d, 50);
        unsigned char *four[4] = {a, b, c, d};
        for (int i = 0; i < 4; i++) {
            if (memcmp(four[i], got[i], 50) != 0) {
                printf("\n  batch4 lane %d differs from batch8\n", i);
                g_fail++;
            }
        }
        printf("%s\n", g_fail > before ? "FAIL" : "OK");
    }

    printf("simd_os_support: %d failure(s)\n", g_fail);
    return g_fail;
}
