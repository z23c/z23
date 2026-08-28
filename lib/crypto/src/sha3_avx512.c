/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 4-way parallel SHA3-512 keystream generator (one key/nonce across 4
 * consecutive counters) for the file-transfer service's frame cipher.
 *
 * Four independent Keccak states are interleaved across the low 4 of the 8
 * 64-bit slots of each __m512i, so theta/rho/pi/chi are entirely lane-parallel
 * — no cross-lane shuffle. The permutation itself lives in
 * keccak_x4_internal.h, shared with sha3_256_x4.c; this file is only the
 * keystream geometry (absorb 72 bytes, two permutations, squeeze 64).
 *
 * The AVX-512 lane carries a target attribute so it compiles into the shipped
 * -march=x86-64-v3 baseline, and is reached only after keccak_x4_available()
 * confirms CPUID + OS (XCR0) support. The scalar lane (four sequential sha3_512
 * hashes) is the always-available reference AND the differential-oracle
 * reference: test group `sha3_512_x4` proves the two are byte-for-byte
 * identical.
 *
 * Was: the whole vector body sat behind `#ifdef __AVX512F__`. The shipped
 * flags never define that macro, so every binary we ship carried only the
 * scalar fallback — on a CPU that has the instructions. (It had also never
 * been compiled even once: the absorb loaded 64 bytes out of a 32-byte
 * `uint64_t lanes[4]`, which -Wall -Wextra -Werror would have rejected.) */

#include "crypto/sha3.h"
#include "keccak_x4_internal.h"

#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>

/* Scalar reference: four sequential SHA3-512 hashes. Always safe, always
 * compiled, and the oracle the AVX-512 lane is proven identical to. */
static void sha3_512_x4_scalar(const uint8_t key[32], const uint8_t nonce[32],
                               uint64_t counter_base, uint8_t out[256])
{
    for (int i = 0; i < 4; i++) {
        struct sha3_512_ctx ctx;
        sha3_512_init(&ctx);
        sha3_512_write(&ctx, key, 32);
        sha3_512_write(&ctx, nonce, 32);
        uint64_t ctr = counter_base + (uint64_t)i;
        sha3_512_write(&ctx, (const unsigned char *)&ctr, 8);
        sha3_512_finalize(&ctx, out + i * 64);
    }
}

#if defined(__x86_64__)

/* Generate 4 SHA3-512 hashes in parallel.
 * Each input is: key(32) || nonce(32) || counter(8) = 72 bytes.
 * SHA3-512 rate = 72 bytes, so exactly one block per input.
 * Output: 4 × 64 = 256 bytes of keystream.
 *
 * Target matches keccak_x4_permute's exactly, so the permutation inlines here
 * instead of becoming a call that spills 25 zmm registers per block. The
 * extra features over plain avx512f cost nothing: keccak_x4_available()
 * already requires f+vl+dq before this function can be reached. */
__attribute__((target("avx512f,avx512vl,avx512dq")))
static void sha3_512_x4_avx512(const uint8_t key[32], const uint8_t nonce[32],
                               uint64_t counter_base, uint8_t out[256])
{
    /* Build 4 input blocks with consecutive counters */
    uint8_t inputs[4][72];
    for (int i = 0; i < 4; i++) {
        memcpy(inputs[i], key, 32);
        memcpy(inputs[i] + 32, nonce, 32);
        uint64_t ctr = counter_base + (uint64_t)i;
        memcpy(inputs[i] + 64, &ctr, 8);
    }

    /* Initialize 4-way state (all zeros) */
    __m512i st[25];
    for (int i = 0; i < 25; i++)
        st[i] = _mm512_setzero_si512();

    /* Absorb: XOR each 72-byte input into its lane.
     * SHA3-512 rate = 72 bytes = 9 uint64_t words. The staging array is EIGHT
     * slots wide because _mm512_loadu_si512 reads the full 64-byte register;
     * only the low 4 slots carry live lanes, slots 4..7 stay zero. (The
     * never-compiled original declared uint64_t[4] here and read 32 bytes past
     * the end of it.) */
    for (int w = 0; w < 9; w++) {
        uint64_t lanes[8] __attribute__((aligned(64))) = {0};
        for (int i = 0; i < 4; i++)
            memcpy(&lanes[i], inputs[i] + w * 8, 8);
        st[w] = _mm512_xor_si512(st[w], _mm512_loadu_si512(lanes));
    }

    /* SHA3-512 rate = 72 bytes = 9 lanes (words 0..8); words 9..24 are CAPACITY
     * and must never be touched by absorb/pad. The 72-byte input exactly FILLS
     * the rate, so finalization needs TWO permutations — identical to the scalar
     * sha3_512_finalize (sha3.c): permute the absorbed rate block, THEN absorb a
     * pad block (domain byte 0x06 at rate byte 0; pad10*1 terminator 0x80 at rate
     * byte 71 = word 8, bit 63) and permute again. */
    keccak_x4_permute(st);  /* permute the full first (rate) block */
    st[0] = _mm512_xor_si512(st[0], _mm512_set1_epi64(0x06));  /* domain sep, rate byte 0 */
    st[8] = _mm512_xor_si512(st[8],
                _mm512_set1_epi64((long long)0x8000000000000000ULL));  /* pad terminator, rate byte 71 */
    keccak_x4_permute(st);  /* permute the pad block */

    /* Squeeze: extract first 8 words (64 bytes) from each lane */
    for (int w = 0; w < 8; w++) {
        uint64_t lanes[8] __attribute__((aligned(64)));
        _mm512_storeu_si512(lanes, st[w]);
        for (int i = 0; i < 4; i++)
            memcpy(out + i * 64 + w * 8, &lanes[i], 8);
    }
}

#endif /* __x86_64__ */

#if defined(__aarch64__)

/* The arm64 twin of sha3_512_x4_avx512: same keystream geometry — 72-byte
 * input blocks (key||nonce||counter fill the SHA3-512 rate exactly), two
 * permutations (full rate block, then the pad block), 64 bytes squeezed per
 * lane. Four batched instances held as two 25-word uint64x2_t arrays
 * (instance k in slot k of st_a, instance 2+k in slot k of st_b), permutation
 * shared with sha3_256_x4_neon via keccak_x4_internal.h. Reached only when
 * keccak_x4_available() confirms FEAT_SHA3. */
static void sha3_512_x4_neon(const uint8_t key[32], const uint8_t nonce[32],
                             uint64_t counter_base, uint8_t out[256])
{
    /* Build 4 input blocks with consecutive counters */
    uint8_t inputs[4][72];
    for (int i = 0; i < 4; i++) {
        memcpy(inputs[i], key, 32);
        memcpy(inputs[i] + 32, nonce, 32);
        uint64_t ctr = counter_base + (uint64_t)i;
        memcpy(inputs[i] + 64, &ctr, 8);
    }

    uint64x2_t st_a[25], st_b[25];
    for (int i = 0; i < 25; ++i) {
        st_a[i] = vdupq_n_u64(0);
        st_b[i] = vdupq_n_u64(0);
    }

    /* Absorb: SHA3-512 rate = 72 bytes = 9 words (slots 0..8); words 9..24
     * are capacity and are never touched by absorb or pad. */
    for (int w = 0; w < 9; w++) {
        uint64_t slot[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4; i++)
            memcpy(&slot[i], inputs[i] + w * 8, 8);
        st_a[w] = veorq_u64(st_a[w], vld1q_u64(slot));
        st_b[w] = veorq_u64(st_b[w], vld1q_u64(slot + 2));
    }

    /* Two-permutation finalization, identical to scalar sha3_512_finalize:
     * permute the full rate block, then absorb the pad block (domain 0x06 at
     * rate byte 0 = word 0 low byte; pad10*1 terminator 0x80 at rate byte 71
     * = word 8, bit 63) and permute again. */
    keccak_x4_permute_neon(st_a, st_b);
    st_a[0] = veorq_u64(st_a[0], vdupq_n_u64(0x06));
    st_b[0] = veorq_u64(st_b[0], vdupq_n_u64(0x06));
    st_a[8] = veorq_u64(st_a[8], vdupq_n_u64(0x8000000000000000ULL));
    st_b[8] = veorq_u64(st_b[8], vdupq_n_u64(0x8000000000000000ULL));
    keccak_x4_permute_neon(st_a, st_b);

    /* Squeeze: first 8 words (64 bytes) of each lane. */
    for (int w = 0; w < 8; w++) {
        uint64_t lo[2], hi[2];
        vst1q_u64(lo, st_a[w]);
        vst1q_u64(hi, st_b[w]);
        for (int i = 0; i < 4; i++) {
            uint64_t v = (i < 2) ? lo[i] : hi[i - 2];
            memcpy(out + i * 64 + w * 8, &v, 8);
        }
    }
}

#endif /* __aarch64__ */

/* ── Runtime dispatch ─────────────────────────────────────────────
 *
 * Selected once at first use. AVX-512 is the shipped default: measured 1.65x
 * the scalar lane on this host class (Zen 4), and unlike the single-stream
 * permutation the geometry is lane-parallel with no cross-lane gather. Set
 * SHA3_512_X4_AVX512_DEFAULT_ENABLED to 0 to ship scalar if a host measures a
 * loss. The parity oracle / bench force a path via sha3_512_x4_select_impl.
 * One-time initialization and subsequent selector overrides are atomically
 * published, so concurrent first use is valid ISO C. */
#ifndef SHA3_512_X4_AVX512_DEFAULT_ENABLED
#define SHA3_512_X4_AVX512_DEFAULT_ENABLED 1
#endif

typedef void (*sha3_512_x4_fn)(const uint8_t[32], const uint8_t[32],
                               uint64_t, uint8_t[256]);

static _Atomic(sha3_512_x4_fn) g_x4 = sha3_512_x4_scalar;
static pthread_once_t g_x4_once = PTHREAD_ONCE_INIT;

static void x4_init_default(void)
{
#if defined(__x86_64__)
    if (SHA3_512_X4_AVX512_DEFAULT_ENABLED && keccak_x4_available())
        atomic_store_explicit(&g_x4, sha3_512_x4_avx512,
                              memory_order_release);
    else
        atomic_store_explicit(&g_x4, sha3_512_x4_scalar,
                              memory_order_release);
#elif defined(__aarch64__)
    if (keccak_x4_available())
        atomic_store_explicit(&g_x4, sha3_512_x4_neon,
                              memory_order_release);
    else
        atomic_store_explicit(&g_x4, sha3_512_x4_scalar,
                              memory_order_release);
#else
    atomic_store_explicit(&g_x4, sha3_512_x4_scalar, memory_order_release);
#endif
}

int sha3_512_x4_select_impl(enum sha3_impl which)
{
    pthread_once(&g_x4_once, x4_init_default);
    switch (which) {
    case SHA3_IMPL_SCALAR:
        atomic_store_explicit(&g_x4, sha3_512_x4_scalar,
                              memory_order_release);
        return SHA3_IMPL_SCALAR;
    case SHA3_IMPL_AVX512:
#if defined(__x86_64__)
        if (keccak_x4_available()) {
            atomic_store_explicit(&g_x4, sha3_512_x4_avx512,
                                  memory_order_release);
            return SHA3_IMPL_AVX512;
        }
#endif
        atomic_store_explicit(&g_x4, sha3_512_x4_scalar,
                              memory_order_release);
        return SHA3_IMPL_SCALAR;
    case SHA3_IMPL_NEON:
#if defined(__aarch64__)
        if (keccak_x4_available()) {
            atomic_store_explicit(&g_x4, sha3_512_x4_neon,
                                  memory_order_release);
            return SHA3_IMPL_NEON;
        }
#endif
        atomic_store_explicit(&g_x4, sha3_512_x4_scalar,
                              memory_order_release);
        return SHA3_IMPL_SCALAR;
    case SHA3_IMPL_AUTO:
    default:
        x4_init_default();
#if defined(__x86_64__)
        return atomic_load_explicit(&g_x4, memory_order_acquire) ==
                       sha3_512_x4_avx512 ? SHA3_IMPL_AVX512 : SHA3_IMPL_SCALAR;
#elif defined(__aarch64__)
        return atomic_load_explicit(&g_x4, memory_order_acquire) ==
                       sha3_512_x4_neon ? SHA3_IMPL_NEON : SHA3_IMPL_SCALAR;
#else
        return SHA3_IMPL_SCALAR;
#endif
    }
}

void sha3_512_x4(const uint8_t key[32], const uint8_t nonce[32],
                 uint64_t counter_base, uint8_t out[256])
{
    pthread_once(&g_x4_once, x4_init_default);
    sha3_512_x4_fn fn = atomic_load_explicit(&g_x4, memory_order_acquire);
    fn(key, nonce, counter_base, out);
}
