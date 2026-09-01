/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "crypto/hmac_sha256.h"
#include "support/cleanse.h"
#include <string.h>

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const unsigned char *key, size_t keylen)
{
    unsigned char rkey[64];
    if (keylen <= 64) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 64 - keylen);
    } else {
        struct sha256_ctx tmp;
        sha256_init(&tmp);
        sha256_write(&tmp, key, keylen);
        sha256_finalize(&tmp, rkey);
        memset(rkey + 32, 0, 32);
        memory_cleanse(&tmp, sizeof(tmp));
    }

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c;
    sha256_init(&ctx->outer);
    sha256_write(&ctx->outer, rkey, 64);

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    sha256_init(&ctx->inner);
    sha256_write(&ctx->inner, rkey, 64);
    memory_cleanse(rkey, sizeof(rkey));
}

void hmac_sha256_write(struct hmac_sha256_ctx *ctx, const unsigned char *data, size_t len)
{
    sha256_write(&ctx->inner, data, len);
}

void hmac_sha256_finalize(struct hmac_sha256_ctx *ctx, unsigned char hash[HMAC_SHA256_OUTPUT_SIZE])
{
    unsigned char temp[32];
    sha256_finalize(&ctx->inner, temp);
    sha256_write(&ctx->outer, temp, 32);
    memory_cleanse(temp, sizeof(temp));
    sha256_finalize(&ctx->outer, hash);
}
