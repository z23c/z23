/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "crypto/hmac_sha512.h"
#include "support/cleanse.h"
#include <string.h>

void hmac_sha512_init(struct hmac_sha512_ctx *ctx, const unsigned char *key, size_t keylen)
{
    unsigned char rkey[128];
    if (keylen <= 128) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 128 - keylen);
    } else {
        struct sha512_ctx tmp;
        sha512_init(&tmp);
        sha512_write(&tmp, key, keylen);
        sha512_finalize(&tmp, rkey);
        memset(rkey + 64, 0, 64);
        memory_cleanse(&tmp, sizeof(tmp));
    }

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c;
    sha512_init(&ctx->outer);
    sha512_write(&ctx->outer, rkey, 128);

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    sha512_init(&ctx->inner);
    sha512_write(&ctx->inner, rkey, 128);
    memory_cleanse(rkey, sizeof(rkey));
}

void hmac_sha512_write(struct hmac_sha512_ctx *ctx, const unsigned char *data, size_t len)
{
    sha512_write(&ctx->inner, data, len);
}

void hmac_sha512_finalize(struct hmac_sha512_ctx *ctx, unsigned char hash[HMAC_SHA512_OUTPUT_SIZE])
{
    unsigned char temp[64];
    sha512_finalize(&ctx->inner, temp);
    sha512_write(&ctx->outer, temp, 64);
    memory_cleanse(temp, sizeof(temp));
    sha512_finalize(&ctx->outer, hash);
}
