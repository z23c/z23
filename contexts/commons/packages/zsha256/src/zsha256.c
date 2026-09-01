#include "zsha256/zsha256.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static void compress(zsha256_ctx *ctx, const uint8_t block[ZSHA256_BLOCK_LEN])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[4 * i] << 24)
             | ((uint32_t)block[4 * i + 1] << 16)
             | ((uint32_t)block[4 * i + 2] << 8)
             | (uint32_t)block[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
    uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

void zsha256_init(zsha256_ctx *ctx)
{
    if (!ctx) return;
    ctx->h[0] = 0x6a09e667; ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372; ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f; ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab; ctx->h[7] = 0x5be0cd19;
    ctx->block_used = 0;
    ctx->total_len = 0;
}

void zsha256_update(zsha256_ctx *ctx, const void *data, size_t len)
{
    if (!ctx || (!data && len > 0)) return;
    const uint8_t *p = data;
    ctx->total_len += len;

    if (ctx->block_used > 0) {
        size_t take = ZSHA256_BLOCK_LEN - ctx->block_used;
        if (take > len) take = len;
        memcpy(ctx->block + ctx->block_used, p, take);
        ctx->block_used += take;
        p += take;
        len -= take;
        if (ctx->block_used == ZSHA256_BLOCK_LEN) {
            compress(ctx, ctx->block);
            ctx->block_used = 0;
        }
    }
    while (len >= ZSHA256_BLOCK_LEN) {
        compress(ctx, p);
        p += ZSHA256_BLOCK_LEN;
        len -= ZSHA256_BLOCK_LEN;
    }
    if (len > 0) {
        memcpy(ctx->block, p, len);
        ctx->block_used = len;
    }
}

void zsha256_final(zsha256_ctx *ctx, uint8_t out[ZSHA256_DIGEST_LEN])
{
    if (!ctx || !out) return;
    uint64_t bit_len = ctx->total_len * 8;

    uint8_t pad = 0x80;
    zsha256_update(ctx, &pad, 1);
    uint8_t zero = 0x00;
    while (ctx->block_used != 56)
        zsha256_update(ctx, &zero, 1);

    uint8_t len_be[8];
    for (int i = 0; i < 8; i++)
        len_be[i] = (uint8_t)(bit_len >> (56 - 8 * i));
    zsha256_update(ctx, len_be, 8);

    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(ctx->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(ctx->h[i]);
    }
    /* Leave no usable state behind. */
    memset(ctx, 0, sizeof *ctx);
}

void zsha256(const void *data, size_t len, uint8_t out[ZSHA256_DIGEST_LEN])
{
    zsha256_ctx ctx;
    zsha256_init(&ctx);
    zsha256_update(&ctx, data, len);
    zsha256_final(&ctx, out);
}

void zsha256_hex(const void *data, size_t len, char out[ZSHA256_HEX_LEN])
{
    if (!out) return;
    uint8_t d[ZSHA256_DIGEST_LEN];
    zsha256(data, len, d);
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < ZSHA256_DIGEST_LEN; i++) {
        out[2 * i]     = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 0x0f];
    }
    out[ZSHA256_HEX_LEN - 1] = '\0';
}

void zsha256_hmac_init(zsha256_hmac_ctx *ctx, const void *key, size_t key_len)
{
    if (!ctx) return;
    uint8_t k[ZSHA256_BLOCK_LEN];
    memset(k, 0, sizeof k);
    if (key && key_len > 0) {
        if (key_len > ZSHA256_BLOCK_LEN) {
            uint8_t kh[ZSHA256_DIGEST_LEN];
            zsha256(key, key_len, kh);
            memcpy(k, kh, ZSHA256_DIGEST_LEN);
            memset(kh, 0, sizeof kh);
        } else {
            memcpy(k, key, key_len);
        }
    }

    uint8_t pad[ZSHA256_BLOCK_LEN];
    for (int i = 0; i < ZSHA256_BLOCK_LEN; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    zsha256_init(&ctx->inner);
    zsha256_update(&ctx->inner, pad, ZSHA256_BLOCK_LEN);
    for (int i = 0; i < ZSHA256_BLOCK_LEN; i++) pad[i] = (uint8_t)(k[i] ^ 0x5c);
    zsha256_init(&ctx->outer);
    zsha256_update(&ctx->outer, pad, ZSHA256_BLOCK_LEN);
    memset(k, 0, sizeof k);
    memset(pad, 0, sizeof pad);
}

void zsha256_hmac_update(zsha256_hmac_ctx *ctx, const void *data, size_t len)
{
    if (!ctx) return;
    zsha256_update(&ctx->inner, data, len);
}

void zsha256_hmac_final(zsha256_hmac_ctx *ctx, uint8_t out[ZSHA256_DIGEST_LEN])
{
    if (!ctx || !out) return;
    uint8_t ih[ZSHA256_DIGEST_LEN];
    zsha256_final(&ctx->inner, ih);
    zsha256_update(&ctx->outer, ih, ZSHA256_DIGEST_LEN);
    zsha256_final(&ctx->outer, out);
    memset(ih, 0, sizeof ih);
}

void zsha256_hmac(const void *key, size_t key_len,
                  const void *data, size_t data_len,
                  uint8_t out[ZSHA256_DIGEST_LEN])
{
    zsha256_hmac_ctx ctx;
    zsha256_hmac_init(&ctx, key, key_len);
    zsha256_hmac_update(&ctx, data, data_len);
    zsha256_hmac_final(&ctx, out);
}

int zsha256_compare(const uint8_t a[ZSHA256_DIGEST_LEN],
                    const uint8_t b[ZSHA256_DIGEST_LEN])
{
    if (!a || !b) return (a == b) ? 0 : 1;
    uint8_t diff = 0;
    for (int i = 0; i < ZSHA256_DIGEST_LEN; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff;
}
