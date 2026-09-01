#include "zmd5/zmd5.h"

#include <string.h>

/* Per-round shift schedule and sine-derived constants, RFC 1321. */
static const uint8_t S[64] = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static const uint32_t K[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static uint32_t rotl32(uint32_t x, unsigned c)
{
    return (x << c) | (x >> (32u - c));
}

static void md5_block(zmd5 *ctx, const uint8_t block[64])
{
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)block[i * 4]
             | ((uint32_t)block[i * 4 + 1] << 8)
             | ((uint32_t)block[i * 4 + 2] << 16)
             | ((uint32_t)block[i * 4 + 3] << 24);

    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];

    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        switch (i >> 4) {
        case 0: f = (b & c) | (~b & d);       g = i;                break;
        case 1: f = (d & b) | (~d & c);       g = (5 * i + 1) % 16; break;
        case 2: f = b ^ c ^ d;                g = (3 * i + 5) % 16; break;
        default: f = c ^ (b | ~d);            g = (7 * i) % 16;     break;
        }
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + K[i] + m[g], S[i]);
        a = tmp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

void zmd5_init(zmd5 *ctx)
{
    if (!ctx) return;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->total_len = 0;
    ctx->block_len = 0;
}

void zmd5_update(zmd5 *ctx, const void *data, size_t n)
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
            md5_block(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
    while (n >= 64) {
        md5_block(ctx, p);
        p += 64;
        n -= 64;
    }
    if (n > 0) {
        memcpy(ctx->block, p, n);
        ctx->block_len = n;
    }
}

void zmd5_final(zmd5 *ctx, uint8_t out[ZMD5_DIGEST_LEN])
{
    if (!ctx || !out) return;
    uint64_t bit_len = ctx->total_len * 8u;

    /* Padding: 0x80 then zeros until 56 mod 64, then 8-byte LE length. */
    uint8_t pad = 0x80;
    zmd5_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->block_len != 56) zmd5_update(ctx, &zero, 1);
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++)
        len_bytes[i] = (uint8_t)(bit_len >> (8 * i));
    /* zmd5_update here must not disturb bit_len (already captured);
     * total_len growth is harmless since the digest is taken below. */
    zmd5_update(ctx, len_bytes, 8);

    for (int i = 0; i < 4; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i]);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }
    memset(ctx, 0, sizeof(*ctx));
}

void zmd5_digest(const void *data, size_t n, uint8_t out[ZMD5_DIGEST_LEN])
{
    zmd5 ctx;
    zmd5_init(&ctx);
    zmd5_update(&ctx, data, n);
    zmd5_final(&ctx, out);
}

void zmd5_hex(const uint8_t digest[ZMD5_DIGEST_LEN], char out[ZMD5_HEX_LEN])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i * 2]     = hexd[digest[i] >> 4];
        out[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
}

void zmd5_digest_hex(const void *data, size_t n, char out[ZMD5_HEX_LEN])
{
    uint8_t d[ZMD5_DIGEST_LEN];
    zmd5_digest(data, n, d);
    zmd5_hex(d, out);
}
