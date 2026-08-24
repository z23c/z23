/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HKDF-SHA3-256 (RFC 5869) over hmac_sha3_256 — extract, expand, and the
 * one-shot convenience. Overlay only; Noise stays on hkdf_sha256. */

#include "crypto/hkdf_sha3.h"

#include "crypto/hmac_sha3.h"
#include "support/cleanse.h"

#include <string.h>

void hkdf_sha3_256_extract(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[HKDF_SHA3_256_PRK_SIZE])
{
    static const uint8_t empty = 0;
    if (salt == NULL || salt_len == 0) {
        salt = &empty;
        salt_len = 0;
    }

    struct hmac_sha3_256_ctx ctx;
    hmac_sha3_256_init(&ctx, salt, salt_len);
    if (ikm != NULL && ikm_len > 0)
        hmac_sha3_256_write(&ctx, ikm, ikm_len);
    hmac_sha3_256_finalize(&ctx, prk);
    memory_cleanse(&ctx, sizeof(ctx));
}

bool hkdf_sha3_256_expand(const uint8_t prk[HKDF_SHA3_256_PRK_SIZE],
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len)
{
    if (out_len > (size_t)255 * HMAC_SHA3_256_OUTPUT_SIZE)
        return false;
    if (out_len == 0)
        return true;

    uint8_t t[HMAC_SHA3_256_OUTPUT_SIZE];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 0;

    while (done < out_len) {
        counter++;
        struct hmac_sha3_256_ctx ctx;
        hmac_sha3_256_init(&ctx, prk, HKDF_SHA3_256_PRK_SIZE);
        if (t_len > 0)
            hmac_sha3_256_write(&ctx, t, t_len);
        if (info != NULL && info_len > 0)
            hmac_sha3_256_write(&ctx, info, info_len);
        hmac_sha3_256_write(&ctx, &counter, 1);
        hmac_sha3_256_finalize(&ctx, t);
        memory_cleanse(&ctx, sizeof(ctx));
        t_len = HMAC_SHA3_256_OUTPUT_SIZE;

        size_t take = out_len - done;
        if (take > HMAC_SHA3_256_OUTPUT_SIZE)
            take = HMAC_SHA3_256_OUTPUT_SIZE;
        memcpy(out + done, t, take);
        done += take;
    }

    memory_cleanse(t, sizeof(t));
    return true;
}

bool hkdf_sha3_256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len)
{
    uint8_t prk[HKDF_SHA3_256_PRK_SIZE];
    hkdf_sha3_256_extract(salt, salt_len, ikm, ikm_len, prk);
    bool ok = hkdf_sha3_256_expand(prk, info, info_len, out, out_len);
    memory_cleanse(prk, sizeof(prk));
    return ok;
}
