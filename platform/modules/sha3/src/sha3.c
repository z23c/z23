/* Copyright (c) 2020 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Based on https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * by Markku-Juhani O. Saarinen <mjos@iki.fi> */

#include "sha3/sha3.h"
#include "base/serialize_le.h"
#include <string.h>

static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

/* Overwrites len bytes in a way the optimizer cannot remove. Kept local so the
 * module links without base/src/cleanse.c, which several standalone tools omit. */
static void sha3_wipe(void *ptr, size_t len)
{
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

/* One Keccak-f round, theta/rho/pi/chi/iota fully unrolled over locals, a -> e. */
static inline void keccak_round(const uint64_t a[restrict 25], uint64_t e[restrict 25], uint64_t rc)
{
    uint64_t c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    uint64_t c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    uint64_t c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    uint64_t c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    uint64_t c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    uint64_t d0 = c4 ^ rotl64(c1, 1);
    uint64_t d1 = c0 ^ rotl64(c2, 1);
    uint64_t d2 = c1 ^ rotl64(c3, 1);
    uint64_t d3 = c2 ^ rotl64(c4, 1);
    uint64_t d4 = c3 ^ rotl64(c0, 1);
    uint64_t b0 = a[0] ^ d0;
    uint64_t b10 = rotl64(a[1] ^ d1, 1);
    uint64_t b7 = rotl64(a[10] ^ d0, 3);
    uint64_t b11 = rotl64(a[7] ^ d2, 6);
    uint64_t b17 = rotl64(a[11] ^ d1, 10);
    uint64_t b18 = rotl64(a[17] ^ d2, 15);
    uint64_t b3 = rotl64(a[18] ^ d3, 21);
    uint64_t b5 = rotl64(a[3] ^ d3, 28);
    uint64_t b16 = rotl64(a[5] ^ d0, 36);
    uint64_t b8 = rotl64(a[16] ^ d1, 45);
    uint64_t b21 = rotl64(a[8] ^ d3, 55);
    uint64_t b24 = rotl64(a[21] ^ d1, 2);
    uint64_t b4 = rotl64(a[24] ^ d4, 14);
    uint64_t b15 = rotl64(a[4] ^ d4, 27);
    uint64_t b23 = rotl64(a[15] ^ d0, 41);
    uint64_t b19 = rotl64(a[23] ^ d3, 56);
    uint64_t b13 = rotl64(a[19] ^ d4, 8);
    uint64_t b12 = rotl64(a[13] ^ d3, 25);
    uint64_t b2 = rotl64(a[12] ^ d2, 43);
    uint64_t b20 = rotl64(a[2] ^ d2, 62);
    uint64_t b14 = rotl64(a[20] ^ d0, 18);
    uint64_t b22 = rotl64(a[14] ^ d4, 39);
    uint64_t b9 = rotl64(a[22] ^ d2, 61);
    uint64_t b6 = rotl64(a[9] ^ d4, 20);
    uint64_t b1 = rotl64(a[6] ^ d1, 44);
    e[0] = b0 ^ (~b1 & b2) ^ rc;
    e[1] = b1 ^ (~b2 & b3);
    e[2] = b2 ^ (~b3 & b4);
    e[3] = b3 ^ (~b4 & b0);
    e[4] = b4 ^ (~b0 & b1);
    e[5] = b5 ^ (~b6 & b7);
    e[6] = b6 ^ (~b7 & b8);
    e[7] = b7 ^ (~b8 & b9);
    e[8] = b8 ^ (~b9 & b5);
    e[9] = b9 ^ (~b5 & b6);
    e[10] = b10 ^ (~b11 & b12);
    e[11] = b11 ^ (~b12 & b13);
    e[12] = b12 ^ (~b13 & b14);
    e[13] = b13 ^ (~b14 & b10);
    e[14] = b14 ^ (~b10 & b11);
    e[15] = b15 ^ (~b16 & b17);
    e[16] = b16 ^ (~b17 & b18);
    e[17] = b17 ^ (~b18 & b19);
    e[18] = b18 ^ (~b19 & b15);
    e[19] = b19 ^ (~b15 & b16);
    e[20] = b20 ^ (~b21 & b22);
    e[21] = b21 ^ (~b22 & b23);
    e[22] = b22 ^ (~b23 & b24);
    e[23] = b23 ^ (~b24 & b20);
    e[24] = b24 ^ (~b20 & b21);
}

void sha3_keccakf_scalar(uint64_t st[25])
{
    static const uint64_t RNDC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    uint64_t tmp[25];

    for (int round = 0; round < 24; round += 2) {
        keccak_round(st, tmp, RNDC[round]);
        keccak_round(tmp, st, RNDC[round + 1]);
    }
    sha3_wipe(tmp, sizeof(tmp));
}

/* There is ONE single-stream permutation, and it is the scalar one above.
 *
 * An AVX-512 single-stream Keccak-f used to live beside it behind a function
 * pointer and a default-off switch. It was measured at 0.70x the scalar path it
 * would have replaced (`make bench-simd`, Zen 4: 10047 ns vs 7012 ns for a 4 KiB
 * SHA3-256) and, being default-off, was reached by nothing but its own test. A
 * permutation that is both slower and unreachable is not an accelerator, so it
 * was deleted rather than carried; the function pointer went with it, and every
 * sha3_*_write/finalize now calls sha3_keccakf_scalar directly.
 *
 * The reason it lost is structural, not a tuning miss: a single Keccak state
 * spread across the lanes of one register makes pi a cross-lane gather, and the
 * gather costs more than the vector width saves. Batching INDEPENDENT streams
 * has no such gather and does win — that is sha3_256_x4 / sha3_512_x4 (2.2x /
 * 2.5x), sharing one permutation in keccak_x4_internal.h. If a future host
 * wants more SHA3 throughput, widen the batch there; do not resurrect this. */

void sha3_256_init(struct sha3_256_ctx *ctx)
{
    ctx->bufsize = 0;
    ctx->pos = 0;
    memset(ctx->state, 0, sizeof(ctx->state));
}

void sha3_256_write(struct sha3_256_ctx *ctx, const unsigned char *data, size_t len)
{
    if (ctx->bufsize && ctx->bufsize + len >= sizeof(ctx->buffer)) {
        memcpy(ctx->buffer + ctx->bufsize, data, sizeof(ctx->buffer) - ctx->bufsize);
        data += sizeof(ctx->buffer) - ctx->bufsize;
        len -= sizeof(ctx->buffer) - ctx->bufsize;
        ctx->state[ctx->pos++] ^= zcl_read_u64_le(ctx->buffer);
        ctx->bufsize = 0;
        if (ctx->pos == SHA3_256_RATE_BUFFERS) {
            sha3_keccakf_scalar(ctx->state);
            ctx->pos = 0;
        }
    }
    while (len >= sizeof(ctx->buffer)) {
        ctx->state[ctx->pos++] ^= zcl_read_u64_le(data);
        data += 8;
        len -= 8;
        if (ctx->pos == SHA3_256_RATE_BUFFERS) {
            sha3_keccakf_scalar(ctx->state);
            ctx->pos = 0;
        }
    }
    if (len) {
        memcpy(ctx->buffer + ctx->bufsize, data, len);
        ctx->bufsize += len;
    }
}

void sha3_256_finalize(struct sha3_256_ctx *ctx, unsigned char output[32])
{
    memset(ctx->buffer + ctx->bufsize, 0, sizeof(ctx->buffer) - ctx->bufsize);
    ctx->buffer[ctx->bufsize] ^= 0x06;
    ctx->state[ctx->pos] ^= zcl_read_u64_le(ctx->buffer);
    ctx->state[SHA3_256_RATE_BUFFERS - 1] ^= 0x8000000000000000ull;
    sha3_keccakf_scalar(ctx->state);
    for (unsigned i = 0; i < 4; ++i) {
        zcl_write_u64_le(output + 8 * i, ctx->state[i]);
    }
    sha3_wipe(ctx, sizeof(*ctx));
}

/* SHA3-512: rate = 576 bits (9 uint64s), capacity = 1024, output = 64 bytes */

void sha3_512_init(struct sha3_512_ctx *ctx)
{
    ctx->bufsize = 0;
    ctx->pos = 0;
    memset(ctx->state, 0, sizeof(ctx->state));
}

void sha3_512_write(struct sha3_512_ctx *ctx, const unsigned char *data, size_t len)
{
    if (ctx->bufsize && ctx->bufsize + len >= sizeof(ctx->buffer)) {
        memcpy(ctx->buffer + ctx->bufsize, data, sizeof(ctx->buffer) - ctx->bufsize);
        data += sizeof(ctx->buffer) - ctx->bufsize;
        len -= sizeof(ctx->buffer) - ctx->bufsize;
        ctx->state[ctx->pos++] ^= zcl_read_u64_le(ctx->buffer);
        ctx->bufsize = 0;
        if (ctx->pos == SHA3_512_RATE_BUFFERS) {
            sha3_keccakf_scalar(ctx->state);
            ctx->pos = 0;
        }
    }
    while (len >= sizeof(ctx->buffer)) {
        ctx->state[ctx->pos++] ^= zcl_read_u64_le(data);
        data += 8;
        len -= 8;
        if (ctx->pos == SHA3_512_RATE_BUFFERS) {
            sha3_keccakf_scalar(ctx->state);
            ctx->pos = 0;
        }
    }
    if (len) {
        memcpy(ctx->buffer + ctx->bufsize, data, len);
        ctx->bufsize += len;
    }
}

void sha3_512_finalize(struct sha3_512_ctx *ctx, unsigned char output[64])
{
    memset(ctx->buffer + ctx->bufsize, 0, sizeof(ctx->buffer) - ctx->bufsize);
    ctx->buffer[ctx->bufsize] ^= 0x06;
    ctx->state[ctx->pos] ^= zcl_read_u64_le(ctx->buffer);
    ctx->state[SHA3_512_RATE_BUFFERS - 1] ^= 0x8000000000000000ull;
    sha3_keccakf_scalar(ctx->state);
    for (unsigned i = 0; i < 8; ++i)
        zcl_write_u64_le(output + 8 * i, ctx->state[i]);
    sha3_wipe(ctx, sizeof(*ctx));
}

void zcl_sha3_256(const unsigned char *data, size_t len, unsigned char output[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, len);
    sha3_256_finalize(&ctx, output);
}

void zcl_sha3_512(const unsigned char *data, size_t len, unsigned char output[64])
{
    struct sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_write(&ctx, data, len);
    sha3_512_finalize(&ctx, output);
}

static bool shake(const unsigned char *data, size_t len,
                  unsigned char *output, size_t output_len,
                  unsigned rate_words)
{
    uint64_t state[25] = {0};
    unsigned char partial[8] = {0};
    unsigned char word[8];
    unsigned partial_len = 0;
    unsigned pos = 0;

    if ((!data && len != 0) || (!output && output_len != 0))
        return false;

    while (len != 0) {
        size_t take = sizeof(partial) - partial_len;
        if (take > len)
            take = len;
        memcpy(partial + partial_len, data, take);
        partial_len += (unsigned)take;
        data += take;
        len -= take;
        if (partial_len == sizeof(partial)) {
            state[pos++] ^= zcl_read_u64_le(partial);
            partial_len = 0;
            memset(partial, 0, sizeof(partial));
            if (pos == rate_words) {
                sha3_keccakf_scalar(state);
                pos = 0;
            }
        }
    }

    partial[partial_len] ^= 0x1f;
    state[pos] ^= zcl_read_u64_le(partial);
    state[rate_words - 1] ^= UINT64_C(0x8000000000000000);
    sha3_keccakf_scalar(state);

    while (output_len != 0) {
        for (unsigned i = 0; i < rate_words && output_len != 0; i++) {
            zcl_write_u64_le(word, state[i]);
            size_t take = output_len < sizeof(word) ? output_len
                                                    : sizeof(word);
            memcpy(output, word, take);
            output += take;
            output_len -= take;
        }
        if (output_len != 0)
            sha3_keccakf_scalar(state);
    }
    sha3_wipe(state, sizeof(state));
    sha3_wipe(partial, sizeof(partial));
    sha3_wipe(word, sizeof(word));
    return true;
}

bool zcl_shake128(const unsigned char *data, size_t len,
                  unsigned char *output, size_t output_len)
{
    return shake(data, len, output, output_len, 21);
}

bool zcl_shake256(const unsigned char *data, size_t len,
                  unsigned char *output, size_t output_len)
{
    return shake(data, len, output, output_len, 17);
}
