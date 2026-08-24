/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HMAC-SHA3-256 over the in-tree SHA3-256 sponge. Block size is the FIPS-202
 * rate (136 bytes). See crypto/hmac_sha3.h. */

#include "crypto/hmac_sha3.h"

#include "support/cleanse.h"

#include <string.h>

void hmac_sha3_256_init(struct hmac_sha3_256_ctx *ctx, const unsigned char *key,
                        size_t keylen)
{
    unsigned char rkey[HMAC_SHA3_256_BLOCK_SIZE];

    if (keylen <= HMAC_SHA3_256_BLOCK_SIZE) {
        if (keylen > 0)
            memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, HMAC_SHA3_256_BLOCK_SIZE - keylen);
    } else {
        struct sha3_256_ctx tmp;
        sha3_256_init(&tmp);
        sha3_256_write(&tmp, key, keylen);
        sha3_256_finalize(&tmp, rkey);
        memset(rkey + HMAC_SHA3_256_OUTPUT_SIZE, 0,
               HMAC_SHA3_256_BLOCK_SIZE - HMAC_SHA3_256_OUTPUT_SIZE);
        memory_cleanse(&tmp, sizeof(tmp));
    }

    for (int n = 0; n < HMAC_SHA3_256_BLOCK_SIZE; n++)
        rkey[n] ^= 0x5c;
    sha3_256_init(&ctx->outer);
    sha3_256_write(&ctx->outer, rkey, HMAC_SHA3_256_BLOCK_SIZE);

    for (int n = 0; n < HMAC_SHA3_256_BLOCK_SIZE; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    sha3_256_init(&ctx->inner);
    sha3_256_write(&ctx->inner, rkey, HMAC_SHA3_256_BLOCK_SIZE);
    memory_cleanse(rkey, sizeof(rkey));
}

void hmac_sha3_256_write(struct hmac_sha3_256_ctx *ctx,
                         const unsigned char *data, size_t len)
{
    sha3_256_write(&ctx->inner, data, len);
}

void hmac_sha3_256_finalize(struct hmac_sha3_256_ctx *ctx,
                            unsigned char hash[HMAC_SHA3_256_OUTPUT_SIZE])
{
    unsigned char temp[HMAC_SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&ctx->inner, temp);
    sha3_256_write(&ctx->outer, temp, HMAC_SHA3_256_OUTPUT_SIZE);
    memory_cleanse(temp, sizeof(temp));
    sha3_256_finalize(&ctx->outer, hash);
}
