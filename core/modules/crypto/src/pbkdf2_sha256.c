/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PBKDF2-HMAC-SHA256 (RFC 8018 §5.2).
 *
 * Block-wise construction:
 *
 *   DK = T_1 || T_2 || ... || T_l
 *   T_i = F(P, S, c, i)
 *   F(P, S, c, i) = U_1 XOR U_2 XOR ... XOR U_c
 *     U_1 = PRF(P, S || INT(i))
 *     U_j = PRF(P, U_{j-1})       for j = 2..c
 *
 * where PRF = HMAC-SHA256, INT(i) is the big-endian 4-byte
 * encoding of the block index (starting at 1), and `l` is
 * ceil(dkLen / hLen).
 */

#include "crypto/pbkdf2_sha256.h"
#include "crypto/hmac_sha256.h"

#include <string.h>

#define HLEN HMAC_SHA256_OUTPUT_SIZE /* 32 */

void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
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
        struct hmac_sha256_ctx ctx;
        hmac_sha256_init(&ctx, password, password_len);
        hmac_sha256_write(&ctx, salt, salt_len);
        uint8_t ibytes[4] = {
            (uint8_t)(i >> 24),
            (uint8_t)(i >> 16),
            (uint8_t)(i >>  8),
            (uint8_t) i,
        };
        hmac_sha256_write(&ctx, ibytes, 4);
        hmac_sha256_finalize(&ctx, u);
        memcpy(t, u, HLEN);

        /* U_j = HMAC(P, U_{j-1}); T ^= U_j */
        for (uint32_t j = 2; j <= iterations; j++) {
            hmac_sha256_init(&ctx, password, password_len);
            hmac_sha256_write(&ctx, u, HLEN);
            hmac_sha256_finalize(&ctx, u);
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
