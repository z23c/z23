/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Runtime capability probe for the 4-way Keccak permutation in
 * keccak_x4_internal.h. Both batched SHA3 surfaces (sha3_avx512.c,
 * sha3_256_x4.c) gate on this before dispatching to their vector lane —
 * AVX-512 on x86-64, NEON on arm64.
 *
 * x86: CPUID alone is not enough; the OS must also have enabled ZMM state, or
 * the first wide instruction raises #UD. The decision lives in the audited
 * predicate crypto/simd_dispatch.h — this file used to check the three ZMM
 * bits directly but executed XGETBV without first confirming OSXSAVE, which is
 * itself a #UD on a host booted with `noxsave`.
 *
 * arm64: ASIMD register state is architecturally mandatory and always saved,
 * so there is no XSAVE-style opt-in to misread — the failure mode the x86 side
 * guards against cannot be reconstructed. What the OS can still take away is a
 * silicon feature, so the probe asks the KERNEL's own feature word (macOS
 * sysctl, Linux AT_HWCAP) for FEAT_SHA3 and refuses the tier when the kernel
 * does not report it: EOR3 that the kernel has not advertised is exactly the
 * "silicon says yes, the machine we actually run on says no" trap this file
 * exists to keep out of dispatch decisions. */

#include "keccak_x4_internal.h"

#include <stdatomic.h>

#if defined(__x86_64__)

#include "crypto/simd_dispatch.h"

bool keccak_x4_available(void)
{
    return simd_host_has_avx512_dq_vl();
}

#elif defined(__aarch64__)

#if defined(__APPLE__)
#include <sys/sysctl.h>

static bool neon_sha3_host_probe(void)
{
    int v = 0;
    size_t len = sizeof(v);
    if (sysctlbyname("hw.optional.arm.FEAT_SHA3", &v, &len, NULL, 0) != 0)
        return false;
    return v == 1;
}

#elif defined(__linux__)
#include <sys/auxv.h>

#ifndef HWCAP_SHA3
#define HWCAP_SHA3 (1UL << 17)
#endif

static bool neon_sha3_host_probe(void)
{
    return (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
}

#else /* no known kernel feature word: refuse the tier. */
static bool neon_sha3_host_probe(void) { return false; }
#endif

/* Same publish-once shape as the x86 predicate in crypto/simd_dispatch.c:
 * two threads may both probe (the probe is a pure read of fixed kernel
 * state, so both compute the same answer), but no reader may observe
 * "probe done" beside a still-unwritten answer. */
static _Atomic bool g_neon_sha3_done = false;
static _Atomic bool g_neon_sha3 = false;

bool keccak_x4_available(void)
{
    if (atomic_load_explicit(&g_neon_sha3_done, memory_order_acquire))
        return atomic_load_explicit(&g_neon_sha3, memory_order_relaxed);

    bool ok = neon_sha3_host_probe();
    atomic_store_explicit(&g_neon_sha3, ok, memory_order_relaxed);
    atomic_store_explicit(&g_neon_sha3_done, true, memory_order_release);
    return ok;
}

#else /* no vector lane on this target; dispatch always resolves to scalar. */

bool keccak_x4_available(void) { return false; }

#endif
