/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 4-way batched SHA3-256: hash FOUR independent messages, produce FOUR digests.
 *
 * This is the right shape for batching many independent hashes — unlike
 * sha3_512_x4 (a keystream generator: one key/nonce across 4 counters), and
 * unlike a single-stream AVX-512 Keccak, which this tree measured at 0.70x the
 * plain C it would replace and has therefore deleted rather than carried. Here
 * the four Keccak states are interleaved across the 4 low 64-bit slots of each
 * __m512i, so theta/rho/pi/chi are embarrassingly lane-parallel (NO cross-lane
 * shuffle) — this is where a double-pumped 512-bit unit genuinely amortizes:
 * 4 hashes for ~1 permutation's front-end cost. The permutation is shared with
 * sha3_avx512.c and lives in keccak_x4_internal.h.
 *
 * The AVX-512 lane carries __attribute__((target(...))) so it compiles into the
 * x86-64-v3 baseline and is reached only when keccak_x4_available() confirms
 * avx512f/vl/dq. arm64 carries the mirror-image NEON lane (sha3_256_x4_neon,
 * permutation in keccak_x4_internal.h), reached only when
 * keccak_x4_available() confirms FEAT_SHA3. The scalar fallback (four
 * sha3_256 calls) is the always-available reference and the differential
 * parity oracle (test group `sha3_256_x4`) proves the vector lane is
 * byte-for-byte identical to it on both ISAs.
 *
 * SHA3-256 rate = 1088 bits = 136 bytes = 17 uint64 words. Each lane may have a
 * different length; the absorb walks max(blockcount) blocks, XORing each lane's
 * block only while that lane still has one, and captures each lane's 4-word
 * digest at the permutation that follows its final (padded) block. */

#include "crypto/sha3.h"
#include "crypto/common.h"

#include <pthread.h>
#include <stdatomic.h>
#include "keccak_x4_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SHA3_256_RATE_BYTES 136u  /* 17 * 8 */

/* Scalar reference: four independent one-shot SHA3-256 hashes. Always safe. */
static void sha3_256_x4_scalar(const uint8_t *const msgs[4], const size_t lens[4],
                               uint8_t out[4][32])
{
    for (int i = 0; i < 4; ++i)
        sha3_256(msgs[i], lens[i], out[i]);
}

#if defined(__x86_64__)

__attribute__((target("avx512f,avx512vl,avx512dq")))
void sha3_256_x4_avx512(const uint8_t *const msgs[4], const size_t lens[4],
                        uint8_t out[4][32])
{
    /* Per-lane geometry. blockcount = full_blocks + 1 (the +1 is the pad block,
     * present even for len%136==0 and len==0). */
    size_t full_blocks[4], rem[4], blockcount[4], maxblocks = 1;
    uint8_t padbuf[4][SHA3_256_RATE_BYTES];
    for (int i = 0; i < 4; ++i) {
        full_blocks[i] = lens[i] / SHA3_256_RATE_BYTES;
        rem[i]         = lens[i] % SHA3_256_RATE_BYTES;
        blockcount[i]  = full_blocks[i] + 1;
        if (blockcount[i] > maxblocks) maxblocks = blockcount[i];

        /* Build the final (padded) rate block for lane i: trailing rem bytes of
         * message, domain byte 0x06 at offset rem, pad10*1 terminator 0x80 at
         * the last rate byte (135). When rem==135 the two collapse to 0x86. */
        memset(padbuf[i], 0, SHA3_256_RATE_BYTES);
        if (rem[i] > 0)
            memcpy(padbuf[i], msgs[i] + full_blocks[i] * SHA3_256_RATE_BYTES, rem[i]);
        padbuf[i][rem[i]] |= 0x06;
        padbuf[i][SHA3_256_RATE_BYTES - 1] |= 0x80;
    }

    __m512i st[25];
    for (int i = 0; i < 25; ++i) st[i] = _mm512_setzero_si512();

    for (size_t b = 0; b < maxblocks; ++b) {
        /* Resolve each lane's 136-byte block for this index (NULL = lane done). */
        const uint8_t *blk[4];
        for (int i = 0; i < 4; ++i) {
            if (b < full_blocks[i])
                blk[i] = msgs[i] + b * SHA3_256_RATE_BYTES;
            else if (b == full_blocks[i])
                blk[i] = padbuf[i];
            else
                blk[i] = NULL;
        }

        for (int w = 0; w < 17; ++w) {
            uint64_t slot[8] __attribute__((aligned(64))) = {0};
            for (int i = 0; i < 4; ++i)
                if (blk[i])
                    slot[i] = ReadLE64(blk[i] + w * 8);
            st[w] = _mm512_xor_si512(st[w], _mm512_load_si512((const void *)slot));
        }

        keccak_x4_permute(st);

        /* A lane finishes at b == blockcount[i]-1 == full_blocks[i]; its 32-byte
         * digest is words 0..3 of the state right after THIS permutation. */
        bool any_done = false;
        for (int i = 0; i < 4; ++i)
            if (full_blocks[i] == b) { any_done = true; break; }
        if (any_done) {
            uint64_t w0[8], w1[8], w2[8], w3[8];
            _mm512_storeu_si512((void *)w0, st[0]);
            _mm512_storeu_si512((void *)w1, st[1]);
            _mm512_storeu_si512((void *)w2, st[2]);
            _mm512_storeu_si512((void *)w3, st[3]);
            for (int i = 0; i < 4; ++i) {
                if (full_blocks[i] != b) continue;
                WriteLE64(out[i] + 0,  w0[i]);
                WriteLE64(out[i] + 8,  w1[i]);
                WriteLE64(out[i] + 16, w2[i]);
                WriteLE64(out[i] + 24, w3[i]);
            }
        }
    }
}

#else /* non-x86 */

#if defined(__aarch64__)

/* The arm64 twin of sha3_256_x4_avx512: same per-lane geometry (pad block,
 * per-lane block counts, digest captured after the lane's final permutation),
 * with the four batched instances held as two 25-word uint64x2_t arrays —
 * slot k of st_a[] is instance k, slot k of st_b[] is instance 2 + k.
 * Compiles into any arm64 baseline: the SHA3-extension EOR3 inside the
 * permutation is compile-time guarded, and the runtime probe
 * (keccak_x4_available) decides whether this lane may be selected explicitly.
 * AUTO stays scalar on arm64: the native Apple-Silicon oracle measures this
 * two-register-pair geometry below scalar on every tested message size. */
void sha3_256_x4_neon(const uint8_t *const msgs[4], const size_t lens[4],
                      uint8_t out[4][32])
{
    size_t full_blocks[4], rem[4], blockcount[4], maxblocks = 1;
    uint8_t padbuf[4][SHA3_256_RATE_BYTES];
    for (int i = 0; i < 4; ++i) {
        full_blocks[i] = lens[i] / SHA3_256_RATE_BYTES;
        rem[i]         = lens[i] % SHA3_256_RATE_BYTES;
        blockcount[i]  = full_blocks[i] + 1;
        if (blockcount[i] > maxblocks) maxblocks = blockcount[i];

        memset(padbuf[i], 0, SHA3_256_RATE_BYTES);
        if (rem[i] > 0)
            memcpy(padbuf[i], msgs[i] + full_blocks[i] * SHA3_256_RATE_BYTES, rem[i]);
        padbuf[i][rem[i]] |= 0x06;
        padbuf[i][SHA3_256_RATE_BYTES - 1] |= 0x80;
    }

    uint64x2_t st_a[25], st_b[25];
    for (int i = 0; i < 25; ++i) {
        st_a[i] = vdupq_n_u64(0);
        st_b[i] = vdupq_n_u64(0);
    }

    for (size_t b = 0; b < maxblocks; ++b) {
        const uint8_t *blk[4];
        for (int i = 0; i < 4; ++i) {
            if (b < full_blocks[i])
                blk[i] = msgs[i] + b * SHA3_256_RATE_BYTES;
            else if (b == full_blocks[i])
                blk[i] = padbuf[i];
            else
                blk[i] = NULL;
        }

        for (int w = 0; w < 17; ++w) {
            uint64_t slot[4] = {0, 0, 0, 0};
            for (int i = 0; i < 4; ++i)
                if (blk[i])
                    slot[i] = ReadLE64(blk[i] + w * 8);
            st_a[w] = veorq_u64(st_a[w], vld1q_u64(slot));
            st_b[w] = veorq_u64(st_b[w], vld1q_u64(slot + 2));
        }

        keccak_x4_permute_neon(st_a, st_b);

        bool any_done = false;
        for (int i = 0; i < 4; ++i)
            if (full_blocks[i] == b) { any_done = true; break; }
        if (any_done) {
            uint64_t w0[4], w1[4], w2[4], w3[4];
            vst1q_u64(w0, st_a[0]); vst1q_u64(w0 + 2, st_b[0]);
            vst1q_u64(w1, st_a[1]); vst1q_u64(w1 + 2, st_b[1]);
            vst1q_u64(w2, st_a[2]); vst1q_u64(w2 + 2, st_b[2]);
            vst1q_u64(w3, st_a[3]); vst1q_u64(w3 + 2, st_b[3]);
            for (int i = 0; i < 4; ++i) {
                if (full_blocks[i] != b) continue;
                WriteLE64(out[i] + 0,  w0[i]);
                WriteLE64(out[i] + 8,  w1[i]);
                WriteLE64(out[i] + 16, w2[i]);
                WriteLE64(out[i] + 24, w3[i]);
            }
        }
    }
}

#else /* neither x86-64 nor arm64: no vector lane; dispatch resolves to scalar. */

void sha3_256_x4_avx512(const uint8_t *const msgs[4], const size_t lens[4],
                        uint8_t out[4][32])
{
    sha3_256_x4_scalar(msgs, lens, out);
}

#endif /* __aarch64__ */

#endif /* __x86_64__ */

/* ── Dispatch ──────────────────────────────────────────────────────────
 *
 * Default: use AVX-512 on x86-64 where the registered oracle measures a win.
 * Keep arm64 AUTO scalar: on Apple Silicon, two sequential 2-lane NEON
 * permutations are about 0.55x four scalar permutations because 64-bit scalar
 * rotates map to one instruction while ASIMD rotates expand and the 25-word
 * vector state exhausts the register file. The NEON tier remains compiled,
 * runtime-gated and explicitly selectable so its parity and future performance
 * can be proved without imposing a regression on the public node. One-time
 * initialization and selector overrides are atomically published, so
 * concurrent first use is valid ISO C. */
#ifndef SHA3_256_X4_AVX512_DEFAULT_ENABLED
#define SHA3_256_X4_AVX512_DEFAULT_ENABLED 1
#endif
#ifndef SHA3_256_X4_NEON_DEFAULT_ENABLED
#define SHA3_256_X4_NEON_DEFAULT_ENABLED 0
#endif

typedef void (*sha3_256_x4_fn)(const uint8_t *const[4], const size_t[4],
                               uint8_t[4][32]);
static _Atomic(sha3_256_x4_fn) g_x4 = sha3_256_x4_scalar;
static pthread_once_t g_x4_once = PTHREAD_ONCE_INIT;

static void x4_init_default(void)
{
#if defined(__x86_64__)
    if (SHA3_256_X4_AVX512_DEFAULT_ENABLED && keccak_x4_available())
        atomic_store_explicit(&g_x4, sha3_256_x4_avx512,
                              memory_order_release);
    else
        atomic_store_explicit(&g_x4, sha3_256_x4_scalar,
                              memory_order_release);
#elif defined(__aarch64__)
    if (SHA3_256_X4_NEON_DEFAULT_ENABLED && keccak_x4_available())
        atomic_store_explicit(&g_x4, sha3_256_x4_neon,
                              memory_order_release);
    else
        atomic_store_explicit(&g_x4, sha3_256_x4_scalar,
                              memory_order_release);
#else
    atomic_store_explicit(&g_x4, sha3_256_x4_scalar, memory_order_release);
#endif
}

int sha3_256_x4_select_impl(enum sha3_impl which)
{
    pthread_once(&g_x4_once, x4_init_default);
    switch (which) {
    case SHA3_IMPL_SCALAR:
        atomic_store_explicit(&g_x4, sha3_256_x4_scalar,
                              memory_order_release);
        return SHA3_IMPL_SCALAR;
    case SHA3_IMPL_AVX512:
#if defined(__x86_64__)
        if (keccak_x4_available()) {
            atomic_store_explicit(&g_x4, sha3_256_x4_avx512,
                                  memory_order_release);
            return SHA3_IMPL_AVX512;
        }
#endif
        atomic_store_explicit(&g_x4, sha3_256_x4_scalar,
                              memory_order_release);
        return SHA3_IMPL_SCALAR;
    case SHA3_IMPL_NEON:
#if defined(__aarch64__)
        if (keccak_x4_available()) {
            atomic_store_explicit(&g_x4, sha3_256_x4_neon,
                                  memory_order_release);
            return SHA3_IMPL_NEON;
        }
#endif
        atomic_store_explicit(&g_x4, sha3_256_x4_scalar,
                              memory_order_release);
        return SHA3_IMPL_SCALAR;
    case SHA3_IMPL_AUTO:
    default:
        x4_init_default();
#if defined(__x86_64__)
        return atomic_load_explicit(&g_x4, memory_order_acquire) ==
                       sha3_256_x4_avx512 ? SHA3_IMPL_AVX512 : SHA3_IMPL_SCALAR;
#elif defined(__aarch64__)
        return atomic_load_explicit(&g_x4, memory_order_acquire) ==
                       sha3_256_x4_neon ? SHA3_IMPL_NEON : SHA3_IMPL_SCALAR;
#else
        return SHA3_IMPL_SCALAR;
#endif
    }
}

void sha3_256_x4(const uint8_t *const msgs[4], const size_t lens[4],
                 uint8_t out[4][32])
{
    pthread_once(&g_x4_once, x4_init_default);
    sha3_256_x4_fn fn = atomic_load_explicit(&g_x4,
                                             memory_order_acquire);
    fn(msgs, lens, out);
}
