#include "zripemd/zripemd.h"

#include <string.h>

static uint32_t rotl32(uint32_t v, unsigned c)
{
    return v << c | v >> (32 - c);
}

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void store32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* RIPEMD-160 round functions, rounds 1..5. */
#define F1(x, y, z) ((x) ^ (y) ^ (z))
#define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F3(x, y, z) (((x) | ~(y)) ^ (z))
#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F5(x, y, z) ((x) ^ ((y) | ~(z)))

/* Message word selection and rotation per step, left line. */
static const uint8_t RL[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
};
static const uint8_t RR[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
};
static const uint8_t SL[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
};
static const uint8_t SR[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
};

static void compress(uint32_t h[5], const uint8_t block[64])
{
    uint32_t x[16];
    uint32_t al, bl, cl, dl, el;
    uint32_t ar, br, cr, dr, er;

    for (int i = 0; i < 16; i++)
        x[i] = load32le(block + 4 * i);

    al = ar = h[0];
    bl = br = h[1];
    cl = cr = h[2];
    dl = dr = h[3];
    el = er = h[4];

    for (int i = 0; i < 80; i++) {
        uint32_t t, f, k;
        unsigned round = (unsigned)i / 16;

        switch (round) {
        case 0: f = F1(bl, cl, dl); k = 0x00000000u; break;
        case 1: f = F2(bl, cl, dl); k = 0x5a827999u; break;
        case 2: f = F3(bl, cl, dl); k = 0x6ed9eba1u; break;
        case 3: f = F4(bl, cl, dl); k = 0x8f1bbcdcu; break;
        default: f = F5(bl, cl, dl); k = 0xa953fd4eu; break;
        }
        t = rotl32(al + f + x[RL[i]] + k, SL[i]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = t;

        switch (round) {
        case 0: f = F5(br, cr, dr); k = 0x50a28be6u; break;
        case 1: f = F4(br, cr, dr); k = 0x5c4dd124u; break;
        case 2: f = F3(br, cr, dr); k = 0x6d703ef3u; break;
        case 3: f = F2(br, cr, dr); k = 0x7a6d76e9u; break;
        default: f = F1(br, cr, dr); k = 0x00000000u; break;
        }
        t = rotl32(ar + f + x[RR[i]] + k, SR[i]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = t;
    }

    {
        uint32_t t = h[1] + cl + dr;
        h[1] = h[2] + dl + er;
        h[2] = h[3] + el + ar;
        h[3] = h[4] + al + br;
        h[4] = h[0] + bl + cr;
        h[0] = t;
    }
}

void zripemd160_init(zripemd160_ctx *ctx)
{
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xefcdab89u;
    ctx->h[2] = 0x98badcfeu;
    ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xc3d2e1f0u;
    ctx->block_used = 0;
    ctx->total_len = 0;
}

void zripemd160_update(zripemd160_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = data;

    ctx->total_len += len;
    while (len) {
        size_t want = ZRIPEMD160_BLOCK_LEN - ctx->block_used;
        size_t take = len < want ? len : want;

        memcpy(ctx->block + ctx->block_used, p, take);
        ctx->block_used += take;
        p += take;
        len -= take;
        if (ctx->block_used == ZRIPEMD160_BLOCK_LEN) {
            compress(ctx->h, ctx->block);
            ctx->block_used = 0;
        }
    }
}

void zripemd160_final(zripemd160_ctx *ctx, uint8_t out[ZRIPEMD160_DIGEST_LEN])
{
    uint64_t bit_len = ctx->total_len * 8;
    uint8_t pad = 0x80;

    zripemd160_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->block_used != 56)
        zripemd160_update(ctx, &pad, 1);

    {
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; i++)
            lenbuf[i] = (uint8_t)(bit_len >> (8 * i));
        zripemd160_update(ctx, lenbuf, 8);
    }
    for (int i = 0; i < 5; i++)
        store32le(out + 4 * i, ctx->h[i]);
}

void zripemd160(const void *data, size_t len,
                uint8_t out[ZRIPEMD160_DIGEST_LEN])
{
    zripemd160_ctx ctx;

    zripemd160_init(&ctx);
    zripemd160_update(&ctx, data, len);
    zripemd160_final(&ctx, out);
}

void zripemd160_hex(const void *data, size_t len,
                    char out[ZRIPEMD160_HEX_LEN])
{
    static const char hexdig[] = "0123456789abcdef";
    uint8_t digest[ZRIPEMD160_DIGEST_LEN];

    zripemd160(data, len, digest);
    for (int i = 0; i < ZRIPEMD160_DIGEST_LEN; i++) {
        out[2 * i] = hexdig[digest[i] >> 4];
        out[2 * i + 1] = hexdig[digest[i] & 15];
    }
    out[ZRIPEMD160_HEX_LEN - 1] = '\0';
}
