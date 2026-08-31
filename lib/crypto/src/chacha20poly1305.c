/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ChaCha20-Poly1305 AEAD (RFC 7539) — pure C23 implementation.
 * Replaces libsodium crypto_aead_chacha20poly1305_ietf_encrypt/decrypt. */

#include "crypto/chacha20poly1305.h"
#include "support/cleanse.h"
#include "platform/time_compat.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
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

/* Forced VECTOR4 exists for parity and physical measurement. AUTO remains
 * portable until caller-shaped p95 and worst-case receipts promote it on each
 * architecture; a passing correctness KAT is necessary, never sufficient. */
#define ZCL_CHACHA20_AUTO_VECTOR4 0

/* Authentication failures are attacker-controlled input on encrypted public
 * transports.  Preserve the first occurrence and a five-minute keepalive with
 * its cumulative suppressed count; never let a remote sender turn the crypto
 * primitive into an unbounded disk-log writer. */
static struct log_throttle g_auth_failure_log = LOG_THROTTLE_INIT;

static _Atomic int g_chacha20_vector_state = -1;
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
#undef VQR
#endif

static bool chacha20_vector4_state(void)
{
#if ZCL_CHACHA20_VECTOR4
    int state = atomic_load_explicit(&g_chacha20_vector_state,
                                     memory_order_acquire);
    if (state >= 0) return state == 1;
    if (state == -2) return false;
    int expected = -1;
    if (!atomic_compare_exchange_strong_explicit(
            &g_chacha20_vector_state, &expected, -2,
            memory_order_acq_rel, memory_order_acquire))
        return expected == 1;
    bool ok = chacha20_vector4_kat();
    atomic_store_explicit(&g_chacha20_vector_state, ok ? 1 : 0,
                          memory_order_release);
    state = ok ? 1 : 0;
    if (state == 0)
        LOG_ERROR("chacha20", "four-block portable-oracle KAT failed; vector tier disabled");
    return state == 1;
#else
    return false;
#endif
}

bool chacha20_vector4_available(void)
{
    return chacha20_vector4_state();
}

bool chacha20_vector4_compiled(void)
{
    return ZCL_CHACHA20_VECTOR4 != 0;
}

int chacha20_select_impl(enum chacha20_impl which)
{
    if (which == CHACHA20_IMPL_PORTABLE) {
        atomic_store_explicit(&g_chacha20_requested_impl,
                              CHACHA20_IMPL_PORTABLE, memory_order_release);
        return CHACHA20_IMPL_PORTABLE;
    }
    if (which == CHACHA20_IMPL_AUTO) {
        atomic_store_explicit(&g_chacha20_requested_impl,
                              CHACHA20_IMPL_AUTO, memory_order_release);
        return ZCL_CHACHA20_AUTO_VECTOR4 && chacha20_vector4_state()
            ? CHACHA20_IMPL_VECTOR4 : CHACHA20_IMPL_PORTABLE;
    }
    int selected = chacha20_vector4_state()
        ? CHACHA20_IMPL_VECTOR4 : CHACHA20_IMPL_PORTABLE;
    atomic_store_explicit(&g_chacha20_requested_impl, selected,
                          memory_order_release);
    return selected;
}

const char *chacha20_implementation(void)
{
    int requested = atomic_load_explicit(&g_chacha20_requested_impl,
                                         memory_order_acquire);
    if ((requested == CHACHA20_IMPL_VECTOR4 ||
         (requested == CHACHA20_IMPL_AUTO && ZCL_CHACHA20_AUTO_VECTOR4)) &&
        chacha20_vector4_state())
        return ZCL_CHACHA20_VECTOR4_NAME;
    return "portable C";
}

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
    int requested = atomic_load_explicit(&g_chacha20_requested_impl,
                                         memory_order_acquire);
    if ((requested == CHACHA20_IMPL_VECTOR4 ||
         (requested == CHACHA20_IMPL_AUTO && ZCL_CHACHA20_AUTO_VECTOR4)) &&
        chacha20_vector4_state()) {
        uint8_t blocks[256];
        while (len - pos >= sizeof blocks && counter <= UINT32_MAX - 3u) {
            chacha20_blocks4(key, counter, nonce, blocks);
            for (size_t i = 0; i < sizeof blocks; i++)
                ciphertext[pos + i] = plaintext[pos + i] ^ blocks[i];
            pos += sizeof blocks;
            counter += 4u;
        }
        memory_cleanse(blocks, sizeof blocks);
    }
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
