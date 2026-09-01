#include "zsha1/zsha1.h"

#include <string.h>

static uint32_t rotl32(uint32_t x, unsigned c)
{
    return (x << c) | (x >> (32u - c));
}

static void sha1_block(zsha1 *ctx, const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3]);
    for (int i = 16; i < 80; i++)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
    uint32_t d = ctx->state[3], e = ctx->state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        switch (i / 20) {
        case 0: f = (b & c) | (~b & d);       k = 0x5a827999; break;
        case 1: f = b ^ c ^ d;                k = 0x6ed9eba1; break;
        case 2: f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; break;
        default: f = b ^ c ^ d;               k = 0xca62c1d6; break;
        }
        uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = tmp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void zsha1_init(zsha1 *ctx)
{
    if (!ctx) return;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->total_len = 0;
    ctx->block_len = 0;
}

void zsha1_update(zsha1 *ctx, const void *data, size_t n)
{
    if (!ctx || (n > 0 && !data)) return;
    const uint8_t *p = data;

    ctx->total_len += n;

    if (ctx->block_len > 0) {
        size_t take = 64 - ctx->block_len;
        if (take > n) take = n;
        memcpy(ctx->block + ctx->block_len, p, take);
        ctx->block_len += take;
        p += take;
        n -= take;
        if (ctx->block_len == 64) {
            sha1_block(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
    while (n >= 64) {
        sha1_block(ctx, p);
        p += 64;
        n -= 64;
    }
    if (n > 0) {
        memcpy(ctx->block, p, n);
        ctx->block_len = n;
    }
}

void zsha1_final(zsha1 *ctx, uint8_t out[ZSHA1_DIGEST_LEN])
{
    if (!ctx || !out) return;
    uint64_t bit_len = ctx->total_len * 8u;

    /* Padding: 0x80 then zeros until 56 mod 64, then 8-byte BE length. */
    uint8_t pad = 0x80;
    zsha1_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->block_len != 56) zsha1_update(ctx, &zero, 1);
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++)
        len_bytes[i] = (uint8_t)(bit_len >> (56 - 8 * i));
    /* total_len growth from the padding updates is harmless: bit_len
     * was captured before padding began. */
    zsha1_update(ctx, len_bytes, 8);

    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
    memset(ctx, 0, sizeof(*ctx));
}

void zsha1_digest(const void *data, size_t n, uint8_t out[ZSHA1_DIGEST_LEN])
{
    zsha1 ctx;
    zsha1_init(&ctx);
    zsha1_update(&ctx, data, n);
    zsha1_final(&ctx, out);
}

void zsha1_hex(const uint8_t digest[ZSHA1_DIGEST_LEN], char out[ZSHA1_HEX_LEN])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[i * 2]     = hexd[digest[i] >> 4];
        out[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
}

void zsha1_digest_hex(const void *data, size_t n, char out[ZSHA1_HEX_LEN])
{
    uint8_t d[ZSHA1_DIGEST_LEN];
    zsha1_digest(data, n, d);
    zsha1_hex(d, out);
}
