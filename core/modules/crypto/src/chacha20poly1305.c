/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ChaCha20-Poly1305 AEAD (RFC 7539) — pure C23 implementation.
 * Replaces libsodium crypto_aead_chacha20poly1305_ietf_encrypt/decrypt. */

#include "crypto/chacha20poly1305.h"
#include "crypto/simd_dispatch.h"
#include "support/cleanse.h"
#include "platform/time_compat.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__)
#include <arm_neon.h>
#define ZCL_CHACHA20_VECTOR4 1
#define ZCL_CHACHA20_VECTOR4_NAME "NEON four-block"
typedef uint32x4_t chacha_vec4;
static inline chacha_vec4 cv_broadcast(uint32_t v) { return vdupq_n_u32(v); }
static inline chacha_vec4 cv_add(chacha_vec4 a, chacha_vec4 b) { return vaddq_u32(a, b); }
static inline chacha_vec4 cv_xor(chacha_vec4 a, chacha_vec4 b) { return veorq_u32(a, b); }
static inline chacha_vec4 cv_rotl16(chacha_vec4 v) { return vorrq_u32(vshlq_n_u32(v, 16), vshrq_n_u32(v, 16)); }
static inline chacha_vec4 cv_rotl12(chacha_vec4 v) { return vorrq_u32(vshlq_n_u32(v, 12), vshrq_n_u32(v, 20)); }
static inline chacha_vec4 cv_rotl8(chacha_vec4 v) { return vorrq_u32(vshlq_n_u32(v, 8), vshrq_n_u32(v, 24)); }
static inline chacha_vec4 cv_rotl7(chacha_vec4 v) { return vorrq_u32(vshlq_n_u32(v, 7), vshrq_n_u32(v, 25)); }
static inline chacha_vec4 cv_counters(uint32_t counter)
{
    const uint32_t v[4] = {counter, counter + 1u, counter + 2u, counter + 3u};
    return vld1q_u32(v);
}
static inline void cv_store_transposed(uint8_t *out, chacha_vec4 a,
                                       chacha_vec4 b, chacha_vec4 c,
                                       chacha_vec4 d)
{
    uint32x4x2_t ab = vtrnq_u32(a, b), cd = vtrnq_u32(c, d);
    uint32x4_t o0 = vcombine_u32(vget_low_u32(ab.val[0]),
                                 vget_low_u32(cd.val[0]));
    uint32x4_t o1 = vcombine_u32(vget_low_u32(ab.val[1]),
                                 vget_low_u32(cd.val[1]));
    uint32x4_t o2 = vcombine_u32(vget_high_u32(ab.val[0]),
                                 vget_high_u32(cd.val[0]));
    uint32x4_t o3 = vcombine_u32(vget_high_u32(ab.val[1]),
                                 vget_high_u32(cd.val[1]));
    vst1q_u8(out + 0u, vreinterpretq_u8_u32(o0));
    vst1q_u8(out + 64u, vreinterpretq_u8_u32(o1));
    vst1q_u8(out + 128u, vreinterpretq_u8_u32(o2));
    vst1q_u8(out + 192u, vreinterpretq_u8_u32(o3));
}
#elif defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#define ZCL_CHACHA20_VECTOR4 1
#define ZCL_CHACHA20_VECTOR4_NAME "SSE2 four-block"
typedef __m128i chacha_vec4;
static inline chacha_vec4 cv_broadcast(uint32_t v) { return _mm_set1_epi32((int32_t)v); }
static inline chacha_vec4 cv_add(chacha_vec4 a, chacha_vec4 b) { return _mm_add_epi32(a, b); }
static inline chacha_vec4 cv_xor(chacha_vec4 a, chacha_vec4 b) { return _mm_xor_si128(a, b); }
static inline chacha_vec4 cv_rotl16(chacha_vec4 v) { return _mm_or_si128(_mm_slli_epi32(v, 16), _mm_srli_epi32(v, 16)); }
static inline chacha_vec4 cv_rotl12(chacha_vec4 v) { return _mm_or_si128(_mm_slli_epi32(v, 12), _mm_srli_epi32(v, 20)); }
static inline chacha_vec4 cv_rotl8(chacha_vec4 v) { return _mm_or_si128(_mm_slli_epi32(v, 8), _mm_srli_epi32(v, 24)); }
static inline chacha_vec4 cv_rotl7(chacha_vec4 v) { return _mm_or_si128(_mm_slli_epi32(v, 7), _mm_srli_epi32(v, 25)); }
static inline chacha_vec4 cv_counters(uint32_t counter)
{
    return _mm_set_epi32((int32_t)(counter + 3u), (int32_t)(counter + 2u),
                         (int32_t)(counter + 1u), (int32_t)counter);
}
static inline void cv_store_transposed(uint8_t *out, chacha_vec4 a,
                                       chacha_vec4 b, chacha_vec4 c,
                                       chacha_vec4 d)
{
    __m128i ab_lo = _mm_unpacklo_epi32(a, b);
    __m128i ab_hi = _mm_unpackhi_epi32(a, b);
    __m128i cd_lo = _mm_unpacklo_epi32(c, d);
    __m128i cd_hi = _mm_unpackhi_epi32(c, d);
    _mm_storeu_si128((__m128i *)(void *)(out + 0u),
                     _mm_unpacklo_epi64(ab_lo, cd_lo));
    _mm_storeu_si128((__m128i *)(void *)(out + 64u),
                     _mm_unpackhi_epi64(ab_lo, cd_lo));
    _mm_storeu_si128((__m128i *)(void *)(out + 128u),
                     _mm_unpacklo_epi64(ab_hi, cd_hi));
    _mm_storeu_si128((__m128i *)(void *)(out + 192u),
                     _mm_unpackhi_epi64(ab_hi, cd_hi));
}
#else
#define ZCL_CHACHA20_VECTOR4 0
#define ZCL_CHACHA20_VECTOR4_NAME "portable C"
#endif

/* Forced VECTOR4 exists for parity and physical measurement. AUTO promotion
 * is architecture-specific: an Apple receipt must never promote x86 SSE2 (or
 * vice versa). A passing correctness KAT is necessary, never sufficient. */
#define ZCL_CHACHA20_AUTO_VECTOR4_APPLE_ARM64 0
/* x86-64 AUTO ceiling: the widest tier AUTO may use (0 portable, 1 SSE2,
 * 2 AVX2, 3 AVX-512F). AUTO takes the widest tier at or below the ceiling
 * that is also available and KAT-verified. */
#define ZCL_CHACHA20_AUTO_X86_64_TIER        3
#if defined(__APPLE__) && defined(__aarch64__)
#define ZCL_CHACHA20_AUTO_TIER ZCL_CHACHA20_AUTO_VECTOR4_APPLE_ARM64
#elif defined(__x86_64__) || defined(_M_X64)
#define ZCL_CHACHA20_AUTO_TIER ZCL_CHACHA20_AUTO_X86_64_TIER
#else
#define ZCL_CHACHA20_AUTO_TIER 0
#endif

/* Wide x86-64 tiers need GNU-style target attributes. */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define ZCL_CHACHA20_X86_WIDE 1
#else
#define ZCL_CHACHA20_X86_WIDE 0
#endif

/* Authentication failures are attacker-controlled input on encrypted public
 * transports.  Preserve the first occurrence and a five-minute keepalive with
 * its cumulative suppressed count; never let a remote sender turn the crypto
 * primitive into an unbounded disk-log writer. */
static struct log_throttle g_auth_failure_log = LOG_THROTTLE_INIT;

static pthread_once_t g_chacha20_vector_once = PTHREAD_ONCE_INIT;
static bool g_chacha20_vector_usable = false;
static _Atomic int g_chacha20_requested_impl = CHACHA20_IMPL_AUTO;

static uint32_t rotl32(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void store64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

#define QR(a, b, c, d)         \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7)

void chacha20_block(const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t state[16];
    state[0] = 0x61707865; /* "expa" */
    state[1] = 0x3320646e; /* "nd 3" */
    state[2] = 0x79622d32; /* "2-by" */
    state[3] = 0x6b206574; /* "te k" */
    for (int i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + 4 * i);
    state[12] = counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    uint32_t working[16];
    memcpy(working, state, 64);

    for (int i = 0; i < 10; i++) {
        QR(working[0], working[4], working[ 8], working[12]);
        QR(working[1], working[5], working[ 9], working[13]);
        QR(working[2], working[6], working[10], working[14]);
        QR(working[3], working[7], working[11], working[15]);
        QR(working[0], working[5], working[10], working[15]);
        QR(working[1], working[6], working[11], working[12]);
        QR(working[2], working[7], working[ 8], working[13]);
        QR(working[3], working[4], working[ 9], working[14]);
    }

    for (int i = 0; i < 16; i++)
        store32_le(out + 4 * i, working[i] + state[i]);
}

#if ZCL_CHACHA20_VECTOR4
#define VQR(a, b, c, d)                    \
    a = cv_add(a, b); d = cv_xor(d, a); d = cv_rotl16(d); \
    c = cv_add(c, d); b = cv_xor(b, c); b = cv_rotl12(b); \
    a = cv_add(a, b); d = cv_xor(d, a); d = cv_rotl8(d);  \
    c = cv_add(c, d); b = cv_xor(b, c); b = cv_rotl7(b)

static void chacha20_blocks4(const uint8_t key[32], uint32_t counter,
                             const uint8_t nonce[12], uint8_t out[256])
{
    uint32_t scalar[16];
    scalar[0] = 0x61707865u; scalar[1] = 0x3320646eu;
    scalar[2] = 0x79622d32u; scalar[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) scalar[4 + i] = load32_le(key + 4 * i);
    scalar[12] = counter;
    scalar[13] = load32_le(nonce + 0);
    scalar[14] = load32_le(nonce + 4);
    scalar[15] = load32_le(nonce + 8);

    chacha_vec4 base[16], work[16];
    for (int i = 0; i < 16; i++) base[i] = cv_broadcast(scalar[i]);
    base[12] = cv_counters(counter);
    memcpy(work, base, sizeof work);
    for (int i = 0; i < 10; i++) {
        VQR(work[0], work[4], work[ 8], work[12]);
        VQR(work[1], work[5], work[ 9], work[13]);
        VQR(work[2], work[6], work[10], work[14]);
        VQR(work[3], work[7], work[11], work[15]);
        VQR(work[0], work[5], work[10], work[15]);
        VQR(work[1], work[6], work[11], work[12]);
        VQR(work[2], work[7], work[ 8], work[13]);
        VQR(work[3], work[4], work[ 9], work[14]);
    }
    for (int word = 0; word < 16; word++)
        work[word] = cv_add(work[word], base[word]);
    for (int word = 0; word < 16; word += 4)
        cv_store_transposed(out + (size_t)word * 4u, work[word],
                            work[word + 1], work[word + 2], work[word + 3]);
    memory_cleanse(work, sizeof work);
    memory_cleanse(base, sizeof base);
    memory_cleanse(scalar, sizeof scalar);
}

static bool chacha20_vector4_kat(void)
{
    uint8_t key[32], nonce[12], got[256], want[256];
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(0xa0u + i);
    chacha20_blocks4(key, 7u, nonce, got);
    for (uint32_t lane = 0; lane < 4; lane++)
        chacha20_block(key, 7u + lane, nonce, want + (size_t)lane * 64u);
    bool ok = memcmp(got, want, sizeof got) == 0;
    memory_cleanse(got, sizeof got);
    memory_cleanse(want, sizeof want);
    return ok;
}

static void chacha20_xor4(const uint8_t key[32], uint32_t counter,
                          const uint8_t nonce[12], const uint8_t *in,
                          uint8_t *out)
{
    uint8_t blocks[256];
    chacha20_blocks4(key, counter, nonce, blocks);
    for (size_t i = 0; i < sizeof blocks; i++)
        out[i] = in[i] ^ blocks[i];
    memory_cleanse(blocks, sizeof blocks);
}
#undef VQR
#endif

typedef void (*chacha20_xor_fn)(const uint8_t key[32], uint32_t counter,
                                const uint8_t nonce[12], const uint8_t *in,
                                uint8_t *out);

#if ZCL_CHACHA20_X86_WIDE
#define CC_TGT_AVX2   __attribute__((target("avx2")))
#define CC_TGT_AVX512 __attribute__((target("avx512f")))

static void chacha20_state_words(uint32_t s[16], const uint8_t key[32],
                                 uint32_t counter, const uint8_t nonce[12])
{
    s[0] = 0x61707865u; s[1] = 0x3320646eu;
    s[2] = 0x79622d32u; s[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) s[4 + i] = load32_le(key + 4 * i);
    s[12] = counter;
    s[13] = load32_le(nonce + 0);
    s[14] = load32_le(nonce + 4);
    s[15] = load32_le(nonce + 8);
}

#define CC_QR(ADD, XOR, R16, R12, R8, R7, a, b, c, d) \
    a = ADD(a, b); d = XOR(d, a); d = R16(d);          \
    c = ADD(c, d); b = XOR(b, c); b = R12(b);          \
    a = ADD(a, b); d = XOR(d, a); d = R8(d);           \
    c = ADD(c, d); b = XOR(b, c); b = R7(b)

#define CC_ROUNDS(ADD, XOR, R16, R12, R8, R7, w)                         \
    for (int round_ = 0; round_ < 10; round_++) {                        \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[0], w[4], w[ 8], w[12]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[1], w[5], w[ 9], w[13]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[2], w[6], w[10], w[14]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[3], w[7], w[11], w[15]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[0], w[5], w[10], w[15]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[1], w[6], w[11], w[12]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[2], w[7], w[ 8], w[13]);     \
        CC_QR(ADD, XOR, R16, R12, R8, R7, w[3], w[4], w[ 9], w[14]);     \
    }

/* ---- AVX2: eight blocks, one ymm per state word ---- */
CC_TGT_AVX2 static inline __m256i y_add(__m256i a, __m256i b) { return _mm256_add_epi32(a, b); }
CC_TGT_AVX2 static inline __m256i y_xor(__m256i a, __m256i b) { return _mm256_xor_si256(a, b); }
/* Byte-shuffle rotations share one helper; the selector picks the rotate. */
CC_TGT_AVX2 static inline __m256i y_shuf_bytes(__m256i v, __m256i sel)
{ return _mm256_shuffle_epi8(v, sel); }
#define Y_ROT16(v) y_shuf_bytes((v), _mm256_setr_epi8(                    \
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,             \
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13))
#define Y_ROT8(v) y_shuf_bytes((v), _mm256_setr_epi8(                     \
        3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,             \
        3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14))
CC_TGT_AVX2 static inline __m256i y_rotl12(__m256i v)
{ return _mm256_or_si256(_mm256_slli_epi32(v, 12), _mm256_srli_epi32(v, 20)); }
CC_TGT_AVX2 static inline __m256i y_rotl7(__m256i v)
{ return _mm256_or_si256(_mm256_slli_epi32(v, 7), _mm256_srli_epi32(v, 25)); }

CC_TGT_AVX2 static inline void y_xor_store(uint8_t *out, const uint8_t *in,
                                           __m256i ks)
{
    __m256i d = _mm256_loadu_si256((const __m256i *)(const void *)in);
    _mm256_storeu_si256((__m256i *)(void *)out, _mm256_xor_si256(d, ks));
}

/* One 4x4 word transpose per 128-bit lane, for one vector width: the template
 * body is shared, and LO32..HI64 are that width's unpack intrinsics. */
#define CC_DEFINE_TRANSPOSE4(NAME, TGT, VEC, LO32, HI32, LO64, HI64)          \
TGT static inline void NAME(const VEC *x, VEC r[4])                           \
{                                                                             \
    VEC t0 = LO32(x[0], x[1]);                                                \
    VEC t1 = HI32(x[0], x[1]);                                                \
    VEC t2 = LO32(x[2], x[3]);                                                \
    VEC t3 = HI32(x[2], x[3]);                                                \
    r[0] = LO64(t0, t2);                                                      \
    r[1] = HI64(t0, t2);                                                      \
    r[2] = LO64(t1, t3);                                                      \
    r[3] = HI64(t1, t3);                                                      \
}

/* Transpose words 4g..4g+3 of eight lanes: r[j] holds block j's four words in
 * its low 128 bits and block 4+j's in its high 128 bits. */
CC_DEFINE_TRANSPOSE4(y_transpose4, CC_TGT_AVX2, __m256i,
                     _mm256_unpacklo_epi32, _mm256_unpackhi_epi32,
                     _mm256_unpacklo_epi64, _mm256_unpackhi_epi64)

CC_TGT_AVX2 static void chacha20_xor8(const uint8_t key[32], uint32_t counter,
                                      const uint8_t nonce[12],
                                      const uint8_t *in, uint8_t *out)
{
    uint32_t s[16];
    __m256i base[16], x[16];
    chacha20_state_words(s, key, counter, nonce);
    for (int i = 0; i < 16; i++) base[i] = _mm256_set1_epi32((int32_t)s[i]);
    base[12] = _mm256_add_epi32(
        base[12], _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    memcpy(x, base, sizeof x);
    CC_ROUNDS(y_add, y_xor, Y_ROT16, y_rotl12, Y_ROT8, y_rotl7, x)
    for (int i = 0; i < 16; i++) x[i] = _mm256_add_epi32(x[i], base[i]);
    for (int h = 0; h < 2; h++) {
        __m256i lo[4], hi[4];
        y_transpose4(x + 8 * h, lo);
        y_transpose4(x + 8 * h + 4, hi);
        for (int j = 0; j < 4; j++) {
            size_t off0 = (size_t)j * 64u + (size_t)h * 32u;
            size_t off1 = (size_t)(4 + j) * 64u + (size_t)h * 32u;
            y_xor_store(out + off0, in + off0,
                        _mm256_permute2x128_si256(lo[j], hi[j], 0x20));
            y_xor_store(out + off1, in + off1,
                        _mm256_permute2x128_si256(lo[j], hi[j], 0x31));
        }
        memory_cleanse(lo, sizeof lo);
        memory_cleanse(hi, sizeof hi);
    }
    memory_cleanse(x, sizeof x);
    memory_cleanse(base, sizeof base);
    memory_cleanse(s, sizeof s);
}

/* ---- AVX-512F: sixteen blocks, one zmm per state word ---- */
CC_TGT_AVX512 static inline __m512i z_add(__m512i a, __m512i b) { return _mm512_add_epi32(a, b); }
CC_TGT_AVX512 static inline __m512i z_xor(__m512i a, __m512i b) { return _mm512_xor_si512(a, b); }
CC_TGT_AVX512 static inline __m512i z_rotl16(__m512i v) { return _mm512_rol_epi32(v, 16); }
CC_TGT_AVX512 static inline __m512i z_rotl12(__m512i v) { return _mm512_rol_epi32(v, 12); }
CC_TGT_AVX512 static inline __m512i z_rotl8(__m512i v) { return _mm512_rol_epi32(v, 8); }
CC_TGT_AVX512 static inline __m512i z_rotl7(__m512i v) { return _mm512_rol_epi32(v, 7); }

CC_TGT_AVX512 static inline void z_xor_store(uint8_t *out, const uint8_t *in,
                                             __m512i ks)
{
    __m512i d = _mm512_loadu_si512((const void *)in);
    _mm512_storeu_si512((void *)out, _mm512_xor_si512(d, ks));
}

/* Within each 128-bit lane k (blocks 4k..4k+3): r[j] = block 4k+j's words
 * 4g..4g+3 for the four word vectors x[0..3]. */
CC_DEFINE_TRANSPOSE4(z_transpose4, CC_TGT_AVX512, __m512i,
                     _mm512_unpacklo_epi32, _mm512_unpackhi_epi32,
                     _mm512_unpacklo_epi64, _mm512_unpackhi_epi64)

/* Fixed j: r[g] lane k = words 4g..4g+3 of block 4k+j. Gather the four 128-bit
 * lanes of one block into a contiguous 64-byte keystream block and XOR it. */
CC_TGT_AVX512 static inline void z_store_j(uint8_t *out, const uint8_t *in,
                                           const __m512i r[4], int j)
{
    __m512i t0 = _mm512_shuffle_i32x4(r[0], r[1], 0x88);
    __m512i t1 = _mm512_shuffle_i32x4(r[0], r[1], 0xdd);
    __m512i t2 = _mm512_shuffle_i32x4(r[2], r[3], 0x88);
    __m512i t3 = _mm512_shuffle_i32x4(r[2], r[3], 0xdd);
    size_t o0 = (size_t)j * 64u, o1 = (size_t)(4 + j) * 64u;
    size_t o2 = (size_t)(8 + j) * 64u, o3 = (size_t)(12 + j) * 64u;
    z_xor_store(out + o0, in + o0, _mm512_shuffle_i32x4(t0, t2, 0x88));
    z_xor_store(out + o1, in + o1, _mm512_shuffle_i32x4(t1, t3, 0x88));
    z_xor_store(out + o2, in + o2, _mm512_shuffle_i32x4(t0, t2, 0xdd));
    z_xor_store(out + o3, in + o3, _mm512_shuffle_i32x4(t1, t3, 0xdd));
}

CC_TGT_AVX512 static void chacha20_xor16(const uint8_t key[32],
                                         uint32_t counter,
                                         const uint8_t nonce[12],
                                         const uint8_t *in, uint8_t *out)
{
    uint32_t s[16];
    __m512i base[16], x[16], rows[4][4];
    chacha20_state_words(s, key, counter, nonce);
    for (int i = 0; i < 16; i++) base[i] = _mm512_set1_epi32((int32_t)s[i]);
    base[12] = _mm512_add_epi32(
        base[12], _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7,
                                    8, 9, 10, 11, 12, 13, 14, 15));
    memcpy(x, base, sizeof x);
    CC_ROUNDS(z_add, z_xor, z_rotl16, z_rotl12, z_rotl8, z_rotl7, x)
    for (int i = 0; i < 16; i++) x[i] = _mm512_add_epi32(x[i], base[i]);
    for (int g = 0; g < 4; g++) z_transpose4(x + 4 * g, rows[g]);
    for (int j = 0; j < 4; j++) {
        __m512i col[4] = {rows[0][j], rows[1][j], rows[2][j], rows[3][j]};
        z_store_j(out, in, col, j);
        memory_cleanse(col, sizeof col);
    }
    memory_cleanse(rows, sizeof rows);
    memory_cleanse(x, sizeof x);
    memory_cleanse(base, sizeof base);
    memory_cleanse(s, sizeof s);
}
/* Compare one wide kernel against the frozen portable block function. The
 * kernel is run at a plain counter and at one whose lane counters cross the
 * 32-bit wrap, with in != out. Any divergent byte fails the tier. */
static bool chacha20_wide_kat(chacha20_xor_fn fn, unsigned blocks)
{
    static const uint32_t counters[2] = {7u, UINT32_MAX - 4u};
    uint8_t key[32], nonce[12], in[1024], got[1024], want[64];
    size_t len = (size_t)blocks * 64u;
    bool ok = len <= sizeof in;
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i * 3u + 1u);
    for (size_t i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(0x50u + i);
    for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 7u + 3u);
    for (size_t c = 0; ok && c < 2; c++) {
        fn(key, counters[c], nonce, in, got);
        for (uint32_t lane = 0; lane < blocks; lane++) {
            chacha20_block(key, counters[c] + lane, nonce, want);
            for (size_t i = 0; i < 64; i++)
                if (got[(size_t)lane * 64u + i] !=
                    (uint8_t)(in[(size_t)lane * 64u + i] ^ want[i]))
                    ok = false;
        }
    }
    memory_cleanse(key, sizeof key);
    memory_cleanse(got, sizeof got);
    memory_cleanse(want, sizeof want);
    return ok;
}

static pthread_once_t g_chacha20_avx2_once = PTHREAD_ONCE_INIT;
static bool g_chacha20_avx2_usable = false;
static pthread_once_t g_chacha20_avx512_once = PTHREAD_ONCE_INIT;
static bool g_chacha20_avx512_usable = false;

static void chacha20_avx2_init(void)
{
    if (!simd_host_has_avx2()) return;
    g_chacha20_avx2_usable = chacha20_wide_kat(chacha20_xor8, 8u);
    if (!g_chacha20_avx2_usable)
        LOG_ERROR("chacha20", "AVX2 eight-block portable-oracle KAT failed; tier disabled");
}

static void chacha20_avx512_init(void)
{
    if (!simd_host_has_avx512f()) return;
    g_chacha20_avx512_usable = chacha20_wide_kat(chacha20_xor16, 16u);
    if (!g_chacha20_avx512_usable)
        LOG_ERROR("chacha20", "AVX-512F sixteen-block portable-oracle KAT failed; tier disabled");
}

#undef CC_ROUNDS
#undef CC_QR
#endif /* ZCL_CHACHA20_X86_WIDE */

static void chacha20_vector4_init(void)
{
#if ZCL_CHACHA20_VECTOR4
    g_chacha20_vector_usable = chacha20_vector4_kat();
    if (!g_chacha20_vector_usable)
        LOG_ERROR("chacha20", "four-block portable-oracle KAT failed; vector tier disabled");
#endif
}

bool chacha20_vector4_available(void)
{
    pthread_once(&g_chacha20_vector_once, chacha20_vector4_init);
    return g_chacha20_vector_usable;
}

bool chacha20_vector4_compiled(void)
{
    return ZCL_CHACHA20_VECTOR4 != 0;
}

bool chacha20_tier_compiled(enum chacha20_impl tier)
{
    switch (tier) {
    case CHACHA20_IMPL_PORTABLE: return true;
    case CHACHA20_IMPL_VECTOR4:  return ZCL_CHACHA20_VECTOR4 != 0;
    case CHACHA20_IMPL_AVX2:
    case CHACHA20_IMPL_AVX512:   return ZCL_CHACHA20_X86_WIDE != 0;
    default:                     return false;
    }
}

/* Usable = compiled, host/OS permits it, and its one-time portable-oracle KAT
 * passed. Concurrent first callers converge through pthread_once. */
bool chacha20_tier_available(enum chacha20_impl tier)
{
    switch (tier) {
    case CHACHA20_IMPL_PORTABLE:
        return true;
    case CHACHA20_IMPL_VECTOR4:
        return chacha20_vector4_available();
#if ZCL_CHACHA20_X86_WIDE
    case CHACHA20_IMPL_AVX2:
        pthread_once(&g_chacha20_avx2_once, chacha20_avx2_init);
        return g_chacha20_avx2_usable;
    case CHACHA20_IMPL_AVX512:
        pthread_once(&g_chacha20_avx512_once, chacha20_avx512_init);
        return g_chacha20_avx512_usable;
#endif
    default:
        return false;
    }
}

/* The tier AUTO resolves to: the widest available, KAT-verified tier at or
 * below the per-architecture ceiling. */
int chacha20_auto_impl(void)
{
    for (int tier = ZCL_CHACHA20_AUTO_TIER; tier > 0; tier--)
        if (chacha20_tier_available((enum chacha20_impl)tier))
            return tier;
    return CHACHA20_IMPL_PORTABLE;
}

bool chacha20_auto_uses_vector4(void)
{
    return chacha20_auto_impl() != CHACHA20_IMPL_PORTABLE;
}

int chacha20_select_impl(enum chacha20_impl which)
{
    int selected;
    if (which == CHACHA20_IMPL_AUTO) {
        atomic_store_explicit(&g_chacha20_requested_impl,
                              CHACHA20_IMPL_AUTO, memory_order_release);
        return chacha20_auto_impl();
    }
    selected = (which != CHACHA20_IMPL_PORTABLE &&
                chacha20_tier_available(which))
        ? (int)which : CHACHA20_IMPL_PORTABLE;
    atomic_store_explicit(&g_chacha20_requested_impl, selected,
                          memory_order_release);
    return selected;
}

static int chacha20_effective_impl(void)
{
    int requested = atomic_load_explicit(&g_chacha20_requested_impl,
                                         memory_order_acquire);
    if (requested == CHACHA20_IMPL_AUTO)
        return chacha20_auto_impl();
    return chacha20_tier_available((enum chacha20_impl)requested)
        ? requested : CHACHA20_IMPL_PORTABLE;
}

const char *chacha20_implementation(void)
{
    switch (chacha20_effective_impl()) {
    case CHACHA20_IMPL_AVX512: return "AVX-512F sixteen-block";
    case CHACHA20_IMPL_AVX2:   return "AVX2 eight-block";
    case CHACHA20_IMPL_VECTOR4: return ZCL_CHACHA20_VECTOR4_NAME;
    default:                   return "portable C";
    }
}

#if ZCL_CHACHA20_VECTOR4
struct chacha20_wide {
    int tier;
    unsigned blocks;
    chacha20_xor_fn fn;
};

/* Widest first. A tier at or below the requested one is used while a whole
 * wide block remains and no lane counter can wrap; the next narrower tier and
 * finally the portable block loop take the rest. */
static const struct chacha20_wide g_chacha20_wide[] = {
#if ZCL_CHACHA20_X86_WIDE
    {CHACHA20_IMPL_AVX512, 16u, chacha20_xor16},
    {CHACHA20_IMPL_AVX2, 8u, chacha20_xor8},
#endif
    {CHACHA20_IMPL_VECTOR4, 4u, chacha20_xor4},
};

static size_t chacha20_bulk(const uint8_t key[32], uint32_t *counter,
                            const uint8_t nonce[12], const uint8_t *in,
                            uint8_t *out, size_t len)
{
    size_t pos = 0;
    int top = chacha20_effective_impl();
    for (size_t i = 0; top > 0 && i < sizeof g_chacha20_wide /
                                       sizeof g_chacha20_wide[0]; i++) {
        const struct chacha20_wide *w = &g_chacha20_wide[i];
        if (w->tier > top ||
            !chacha20_tier_available((enum chacha20_impl)w->tier))
            continue;
        size_t step = (size_t)w->blocks * 64u;
        while (len - pos >= step && *counter <= UINT32_MAX - (w->blocks - 1u)) {
            w->fn(key, *counter, nonce, in + pos, out + pos);
            pos += step;
            *counter += w->blocks;
        }
    }
    return pos;
}
#endif

bool chacha20_encrypt(const uint8_t key[32], uint32_t counter,
                       const uint8_t nonce[12],
                       const uint8_t *plaintext, size_t len,
                       uint8_t *ciphertext)
{
    uint64_t blocks_needed = (uint64_t)(len / 64u) + (len % 64u != 0u);
    uint64_t counters_left = (uint64_t)UINT32_MAX - counter + 1u;
    if (blocks_needed > counters_left)
        LOG_FAIL("chacha20", "encrypt length %zu exhausts counter space from %u",
                 len, counter);
    size_t pos = 0;
#if ZCL_CHACHA20_VECTOR4
    pos = chacha20_bulk(key, &counter, nonce, plaintext, ciphertext, len);
#endif
    uint8_t block[64];
    while (pos < len) {
        chacha20_block(key, counter, nonce, block);
        counter++;
        size_t take = len - pos;
        if (take > 64) take = 64;
        for (size_t i = 0; i < take; i++)
            ciphertext[pos + i] = plaintext[pos + i] ^ block[i];
        pos += take;
    }
    /* Wipe the keystream block: its last read was the XOR above, and it is
     * key/nonce-derived secret material. Output already written. */
    memory_cleanse(block, sizeof(block));
    return true;
}

/* Poly1305 — RFC 7539 Section 2.5 */

struct poly1305_state {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
};

static void poly1305_init(struct poly1305_state *st, const uint8_t key[32])
{
    st->r[0] = (load32_le(key + 0)) & 0x3ffffff;
    st->r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;

    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    st->pad[0] = load32_le(key + 16);
    st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24);
    st->pad[3] = load32_le(key + 28);
}

static void poly1305_blocks(struct poly1305_state *st,
                             const uint8_t *data, size_t len, uint32_t hibit)
{
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2];
    uint32_t r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    uint32_t h3 = st->h[3], h4 = st->h[4];

    while (len >= 16) {
        h0 += load32_le(data + 0) & 0x3ffffff;
        h1 += (load32_le(data + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(data + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(data + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(data + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 +
                       (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 +
                       (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 +
                       (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 +
                       (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 +
                       (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        data += 16;
        len -= 16;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static void poly1305_finish(struct poly1305_state *st, uint8_t tag[16])
{
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    uint32_t h3 = st->h[3], h4 = st->h[4];

    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    uint64_t f;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32_le(tag + 0, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);
}

void poly1305_mac(const uint8_t *message, size_t len,
                   const uint8_t key[32], uint8_t tag[16])
{
    struct poly1305_state st;
    poly1305_init(&st, key);

    size_t full_blocks = len & ~15u;
    if (full_blocks > 0)
        poly1305_blocks(&st, message, full_blocks, 1u << 24);

    if (len & 15) {
        uint8_t block[16] = {0};
        size_t rem = len & 15;
        memcpy(block, message + full_blocks, rem);
        block[rem] = 1;
        poly1305_blocks(&st, block, 16, 0);
    }

    poly1305_finish(&st, tag);
}

/* AEAD construction per RFC 7539 Section 2.8 */

static void pad16(uint8_t *mac_data, size_t *mac_pos, size_t data_len)
{
    size_t rem = data_len % 16;
    if (rem > 0) {
        uint8_t zeros[15] = {0};
        memcpy(mac_data + *mac_pos, zeros, 16 - rem);
        *mac_pos += 16 - rem;
    }
}

bool chacha20poly1305_encrypt(const uint8_t *plaintext, size_t plen,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t nonce[12],
                                const uint8_t key[32],
                                uint8_t *ciphertext)
{
    /* Generate Poly1305 one-time key from ChaCha20 block 0 */
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    /* Encrypt plaintext with ChaCha20 starting at counter 1 */
    if (!chacha20_encrypt(key, 1, nonce, plaintext, plen, ciphertext)) {
        memory_cleanse(poly_key, sizeof poly_key);
        LOG_FAIL("chacha20poly1305", "encrypt plaintext exhausts counter space");
    }

    /* Construct Poly1305 MAC input:
     * aad || pad(aad) || ciphertext || pad(ciphertext) || le64(aad_len) || le64(plen) */
    size_t mac_len = 0;
    if (aad_len > 0) mac_len += aad_len;
    mac_len += (16 - (aad_len % 16)) % 16;
    mac_len += plen;
    mac_len += (16 - (plen % 16)) % 16;
    mac_len += 16;

    uint8_t mac_stack[2048];
    uint8_t *mac_data = mac_stack;
    if (mac_len > sizeof(mac_stack)) {
        mac_data = zcl_malloc(mac_len, "chacha20poly1305_mac");
        if (!mac_data)
            LOG_FAIL("chacha20poly1305", "encrypt: MAC allocation failed");
    }

    size_t pos = 0;
    if (aad_len > 0) {
        memcpy(mac_data + pos, aad, aad_len);
        pos += aad_len;
    }
    pad16(mac_data, &pos, aad_len);
    memcpy(mac_data + pos, ciphertext, plen);
    pos += plen;
    pad16(mac_data, &pos, plen);
    store64_le(mac_data + pos, aad_len); pos += 8;
    store64_le(mac_data + pos, plen); pos += 8;

    poly1305_mac(mac_data, pos, poly_key, ciphertext + plen);
    if (mac_data != mac_stack) {
        memory_cleanse(mac_data, mac_len);
        free(mac_data);
    }
    /* Wipe the Poly1305 one-time key: last read was the MAC call above; tag
     * already written to ciphertext+plen. */
    memory_cleanse(poly_key, sizeof(poly_key));
    return true;
}

bool chacha20poly1305_decrypt(const uint8_t *ciphertext, size_t clen,
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t nonce[12],
                                const uint8_t key[32],
                                uint8_t *plaintext)
{
    if (clen < POLY1305_TAG_SIZE)
        LOG_FAIL("chacha20poly1305",
                 "decrypt: ciphertext shorter than Poly1305 tag: clen=%zu tag=%d",
                 clen, POLY1305_TAG_SIZE);

    size_t plen = clen - POLY1305_TAG_SIZE;

    /* Generate Poly1305 one-time key */
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    /* Verify MAC */
    size_t mac_len = 0;
    if (aad_len > 0) mac_len += aad_len;
    mac_len += (16 - (aad_len % 16)) % 16;
    mac_len += plen;
    mac_len += (16 - (plen % 16)) % 16;
    mac_len += 16;

    uint8_t mac_stack[2048];
    uint8_t *mac_data = mac_stack;
    if (mac_len > sizeof(mac_stack)) {
        mac_data = zcl_malloc(mac_len, "chacha20poly1305_mac");
        if (!mac_data)
            LOG_FAIL("chacha20poly1305", "decrypt: MAC allocation failed");
    }

    size_t pos = 0;
    if (aad_len > 0) {
        memcpy(mac_data + pos, aad, aad_len);
        pos += aad_len;
    }
    pad16(mac_data, &pos, aad_len);
    memcpy(mac_data + pos, ciphertext, plen);
    pos += plen;
    pad16(mac_data, &pos, plen);
    store64_le(mac_data + pos, aad_len); pos += 8;
    store64_le(mac_data + pos, plen); pos += 8;

    uint8_t computed_tag[16];
    poly1305_mac(mac_data, pos, poly_key, computed_tag);
    if (mac_data != mac_stack) {
        memory_cleanse(mac_data, mac_len);
        free(mac_data);
    }

    /* Constant-time comparison. Tag mismatch is the expected path when an
     * attacker tampers with ciphertext — do not log the tag itself. */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= computed_tag[i] ^ ciphertext[plen + i];
    /* Both secrets are fully consumed at this point: poly_key's last read was
     * the MAC call, computed_tag's last read was the compare loop above. Wipe
     * before the branch so BOTH the mismatch (LOG_FAIL returns) and success
     * return paths are covered. `diff` (the verdict) is preserved. */
    memory_cleanse(poly_key, sizeof(poly_key));
    memory_cleanse(computed_tag, sizeof(computed_tag));
    if (diff != 0) {
        uint64_t suppressed = 0;
        if (log_throttle_should_emit(
                &g_auth_failure_log, 1,
                (int64_t)platform_time_wall_time_t(), 300, &suppressed)) {
            LOG_WARN("chacha20poly1305",
                     "decrypt: Poly1305 tag mismatch (authentication failed): "
                     "clen=%zu aad_len=%zu suppressed=%llu",
                     clen, aad_len, (unsigned long long)suppressed);
        }
        return false;
    }

    /* Decrypt */
    if (!chacha20_encrypt(key, 1, nonce, ciphertext, plen, plaintext))
        LOG_FAIL("chacha20poly1305", "decrypt ciphertext exhausts counter space");
    return true;
}
