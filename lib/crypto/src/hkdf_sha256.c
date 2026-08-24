/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HKDF-SHA256 (RFC 5869) implementation over hmac_sha256 — extract, expand,
 * the one-shot convenience, and the two-output Noise HKDF2 helper. Pure C23,
 * no allocation, no external deps. See crypto/hkdf_sha256.h. */

#include "crypto/hkdf_sha256.h"

#include "crypto/hmac_sha256.h"
#include "support/cleanse.h"

#include <string.h>

void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[HKDF_SHA256_PRK_SIZE])
{
    /* RFC 5869: a NULL/zero-length salt keys HMAC with the empty string. */
    static const uint8_t empty = 0;
    if (salt == NULL || salt_len == 0) { salt = &empty; salt_len = 0; }

    struct hmac_sha256_ctx ctx;
    hmac_sha256_init(&ctx, salt, salt_len);
    if (ikm != NULL && ikm_len > 0)
        hmac_sha256_write(&ctx, ikm, ikm_len);
    hmac_sha256_finalize(&ctx, prk);
    memory_cleanse(&ctx, sizeof(ctx));
}

bool hkdf_sha256_expand(const uint8_t prk[HKDF_SHA256_PRK_SIZE],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    /* RFC 5869 §2.3: N = ceil(L/HashLen) must be <= 255. */
    if (out_len > (size_t)255 * HMAC_SHA256_OUTPUT_SIZE)
        return false;
    if (out_len == 0)
        return true;

    uint8_t t[HMAC_SHA256_OUTPUT_SIZE];
    size_t t_len = 0; /* 0 for T(0); 32 for subsequent iterations */
    size_t done = 0;
    uint8_t counter = 0;

    while (done < out_len) {
        counter++; /* i = 1, 2, ... */
        struct hmac_sha256_ctx ctx;
        hmac_sha256_init(&ctx, prk, HKDF_SHA256_PRK_SIZE);
        if (t_len > 0)
            hmac_sha256_write(&ctx, t, t_len);
        if (info != NULL && info_len > 0)
            hmac_sha256_write(&ctx, info, info_len);
        hmac_sha256_write(&ctx, &counter, 1);
        hmac_sha256_finalize(&ctx, t);
        memory_cleanse(&ctx, sizeof(ctx));
        t_len = HMAC_SHA256_OUTPUT_SIZE;

        size_t take = out_len - done;
        if (take > HMAC_SHA256_OUTPUT_SIZE) take = HMAC_SHA256_OUTPUT_SIZE;
        memcpy(out + done, t, take);
        done += take;
    }

    memory_cleanse(t, sizeof(t));
    return true;
}

bool hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len)
{
    uint8_t prk[HKDF_SHA256_PRK_SIZE];
    hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    bool ok = hkdf_sha256_expand(prk, info, info_len, out, out_len);
    memory_cleanse(prk, sizeof(prk));
    return ok;
}

void hkdf_sha256_2(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t out1[32], uint8_t out2[32])
{
    uint8_t prk[HKDF_SHA256_PRK_SIZE];
    uint8_t okm[64];
    hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    /* out_len 64 <= 255*32, never fails; info is empty (Noise HKDF). */
    (void)hkdf_sha256_expand(prk, NULL, 0, okm, sizeof(okm));
    memcpy(out1, okm, 32);
    memcpy(out2, okm + 32, 32);
    memory_cleanse(prk, sizeof(prk));
    memory_cleanse(okm, sizeof(okm));
}
