#include "zotp/zotp.h"

#include <string.h>

#include "zsha1/zsha1.h"

void zotp_hmac_sha1(const void *key, size_t key_len,
                    const void *data, size_t data_len,
                    uint8_t out[20])
{
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        zsha1_digest(key, key_len, k); /* long keys are hashed first */
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }

    uint8_t pad[64];
    zsha1 ctx;

    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    zsha1_init(&ctx);
    zsha1_update(&ctx, pad, 64);
    zsha1_update(&ctx, data, data_len);
    uint8_t inner[20];
    zsha1_final(&ctx, inner);

    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x5c);
    zsha1_init(&ctx);
    zsha1_update(&ctx, pad, 64);
    zsha1_update(&ctx, inner, 20);
    zsha1_final(&ctx, out);

    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}

uint32_t zotp_truncate(const uint8_t hmac[20])
{
    unsigned off = hmac[19] & 0x0f;
    return ((uint32_t)(hmac[off] & 0x7f) << 24) |
           ((uint32_t)hmac[off + 1] << 16) |
           ((uint32_t)hmac[off + 2] << 8) |
           (uint32_t)hmac[off + 3];
}

uint32_t zotp_hotp_value(const void *secret, size_t secret_len,
                         uint64_t counter)
{
    uint8_t msg[8];
    for (int i = 0; i < 8; i++)
        msg[i] = (uint8_t)(counter >> (56 - 8 * i)); /* big-endian */
    uint8_t h[20];
    zotp_hmac_sha1(secret, secret_len, msg, sizeof(msg), h);
    uint32_t v = zotp_truncate(h);
    memset(h, 0, sizeof(h));
    memset(msg, 0, sizeof(msg));
    return v;
}

int zotp_hotp(const void *secret, size_t secret_len, uint64_t counter,
              unsigned digits, char *out)
{
    if (!secret || !out) return 0;
    if (digits < ZOTP_MIN_DIGITS || digits > ZOTP_MAX_DIGITS) return 0;
    uint32_t mod = 1;
    for (unsigned i = 0; i < digits; i++) mod *= 10u;
    uint32_t v = zotp_hotp_value(secret, secret_len, counter) % mod;
    for (unsigned i = 0; i < digits; i++) {
        out[digits - 1 - i] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    out[digits] = '\0';
    return 1;
}
