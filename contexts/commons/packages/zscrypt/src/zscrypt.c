#include "zscrypt/zscrypt.h"

#include <stdlib.h>
#include <string.h>

#include <zsha256/zsha256.h>

int zpbkdf2_sha256(const void *pw, size_t pw_len,
                   const void *salt, size_t salt_len,
                   uint32_t iters,
                   uint8_t *dk, size_t dk_len)
{
    uint8_t u[ZSHA256_DIGEST_LEN], t[ZSHA256_DIGEST_LEN];
    uint32_t block = 1;

    if ((!pw && pw_len) || (!salt && salt_len) || !dk || !dk_len || !iters)
        return -1;

    while (dk_len) {
        zsha256_hmac_ctx ctx;
        uint8_t ctr[4] = {
            (uint8_t)(block >> 24), (uint8_t)(block >> 16),
            (uint8_t)(block >> 8), (uint8_t)block
        };
        size_t take = dk_len < sizeof t ? dk_len : sizeof t;

        zsha256_hmac_init(&ctx, pw, pw_len);
        if (salt_len)
            zsha256_hmac_update(&ctx, salt, salt_len);
        zsha256_hmac_update(&ctx, ctr, 4);
        zsha256_hmac_final(&ctx, u);
        memcpy(t, u, sizeof t);

        for (uint32_t i = 1; i < iters; i++) {
            zsha256_hmac(pw, pw_len, u, sizeof u, u);
            for (size_t j = 0; j < sizeof t; j++)
                t[j] ^= u[j];
        }
        memcpy(dk, t, take);
        dk += take;
        dk_len -= take;
        block++;
    }
    return 0;
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

static uint32_t rotl32(uint32_t v, unsigned c)
{
    return v << c | v >> (32 - c);
}

#define QR(a, b, c, d)                \
    b ^= rotl32(a + d, 7);            \
    c ^= rotl32(b + a, 9);            \
    d ^= rotl32(c + b, 13);           \
    a ^= rotl32(d + c, 18)

/* Salsa20/8 core: 64-byte block in, 64-byte block out. */
static void salsa20_8(uint8_t out[64], const uint8_t in[64])
{
    uint32_t x[16], w[16];

    for (int i = 0; i < 16; i++)
        x[i] = w[i] = load32le(in + 4 * i);
    for (int i = 0; i < 8; i += 2) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[5], x[9], x[13], x[1]);
        QR(x[10], x[14], x[2], x[6]);
        QR(x[15], x[3], x[7], x[11]);
        QR(x[0], x[1], x[2], x[3]);
        QR(x[5], x[6], x[7], x[4]);
        QR(x[10], x[11], x[8], x[9]);
        QR(x[15], x[12], x[13], x[14]);
    }
    for (int i = 0; i < 16; i++)
        store32le(out + 4 * i, x[i] + w[i]);
}

/* BlockMix: transform 2r 64-byte blocks B into out.  tmp is 64 bytes
 * of scratch. */
static void block_mix(uint8_t *out, const uint8_t *b, uint32_t r,
                      uint8_t tmp[64])
{
    uint8_t x[64];
    uint32_t i;

    memcpy(x, b + (size_t)(2 * r - 1) * 64, 64);
    for (i = 0; i < 2 * r; i++) {
        for (int j = 0; j < 64; j++)
            x[j] ^= b[(size_t)i * 64 + j];
        salsa20_8(tmp, x);
        memcpy(x, tmp, 64);
        memcpy(out + ((size_t)i / 2 + (i & 1) * r) * 64, x, 64);
    }
}

/* ROMix: N rounds of BlockMix with a memory array v of N*r*128 bytes.
 * b holds r*128 bytes on entry and exit.  scratch is r*128 bytes. */
static void ro_mix(uint8_t *b, uint64_t n, uint32_t r,
                   uint8_t *v, uint8_t *scratch)
{
    const size_t block_span = (size_t)r * 128;
    uint8_t tmp[64];
    uint64_t i;

    for (i = 0; i < n; i++) {
        memcpy(v + i * block_span, b, block_span);
        block_mix(scratch, b, r, tmp);
        memcpy(b, scratch, block_span);
    }
    for (i = 0; i < n; i++) {
        uint64_t j = (uint64_t)load32le(b + (2 * (size_t)r - 1) * 64) |
                     (uint64_t)load32le(b + (2 * (size_t)r - 1) * 64 + 4) << 32;
        const uint8_t *vj;

        j &= n - 1; /* n is a power of two */
        vj = v + j * block_span;
        for (size_t k = 0; k < block_span; k++)
            b[k] ^= vj[k];
        block_mix(scratch, b, r, tmp);
        memcpy(b, scratch, block_span);
    }
}

static int is_power_of_two(uint64_t v)
{
    return v > 1 && (v & (v - 1)) == 0;
}

int zscrypt(const void *passwd, size_t passwd_len,
            const void *salt, size_t salt_len,
            uint64_t n, uint32_t r, uint32_t p,
            uint8_t *dk, size_t dk_len)
{
    uint8_t *b = NULL, *v = NULL, *scratch = NULL;
    size_t block_span, b_len;
    int rc = -2;

    if ((!passwd && passwd_len) || (!salt && salt_len) || !dk || !dk_len)
        return -1;
    if (!is_power_of_two(n) || !r || !p)
        return -1;
    /* Guard the multiplications below against overflow. */
    if (r > UINT32_MAX / 128 || p > UINT32_MAX / (128 * r))
        return -1;
    if (n > SIZE_MAX / (128 * (size_t)r))
        return -1;

    block_span = (size_t)r * 128;
    b_len = (size_t)p * block_span;

    b = malloc(b_len);
    v = malloc(n * block_span);
    scratch = malloc(block_span);
    if (!b || !v || !scratch)
        goto out;

    if (zpbkdf2_sha256(passwd, passwd_len, salt, salt_len, 1, b, b_len) != 0)
        goto out;
    for (uint32_t i = 0; i < p; i++)
        ro_mix(b + (size_t)i * block_span, n, r, v, scratch);
    if (zpbkdf2_sha256(passwd, passwd_len, b, b_len, 1, dk, dk_len) != 0)
        goto out;
    rc = 0;
out:
    free(scratch);
    free(v);
    free(b);
    return rc;
}
