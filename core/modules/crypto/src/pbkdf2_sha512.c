/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PBKDF2-HMAC-SHA512 (RFC 8018 §5.2).
 *
 * Same block-wise construction as PBKDF2-SHA256 but with
 * HMAC-SHA512 as PRF and 64-byte output blocks.
 */

#include "crypto/pbkdf2_sha512.h"
#include "crypto/hmac_sha512.h"

#include <string.h>

#define HLEN HMAC_SHA512_OUTPUT_SIZE /* 64 */

void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations,
                         uint8_t *out, size_t out_len)
{
    if (!out || out_len == 0) return;
    if (out_len > (1u << 20)) return; /* 1 MiB cap */
    if (iterations == 0) iterations = 1;

    uint32_t blocks = (uint32_t)((out_len + HLEN - 1) / HLEN);
    uint8_t  u[HLEN];
    uint8_t  t[HLEN];

    for (uint32_t i = 1; i <= blocks; i++) {
        /* U_1 = HMAC(P, S || INT(i)) */
        struct hmac_sha512_ctx ctx;
        hmac_sha512_init(&ctx, password, password_len);
        hmac_sha512_write(&ctx, salt, salt_len);
        uint8_t ibytes[4] = {
            (uint8_t)(i >> 24),
            (uint8_t)(i >> 16),
            (uint8_t)(i >>  8),
            (uint8_t) i,
        };
        hmac_sha512_write(&ctx, ibytes, 4);
        hmac_sha512_finalize(&ctx, u);
        memcpy(t, u, HLEN);

        /* U_j = HMAC(P, U_{j-1}); T ^= U_j */
        for (uint32_t j = 2; j <= iterations; j++) {
            hmac_sha512_init(&ctx, password, password_len);
            hmac_sha512_write(&ctx, u, HLEN);
            hmac_sha512_finalize(&ctx, u);
            for (size_t k = 0; k < HLEN; k++)
                t[k] ^= u[k];
        }

        /* Copy this block's worth of output. */
        size_t offset = (size_t)(i - 1) * HLEN;
        size_t take   = out_len - offset;
        if (take > HLEN) take = HLEN;
        memcpy(out + offset, t, take);
    }

    /* Scrub local copies of derived material. */
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
}
