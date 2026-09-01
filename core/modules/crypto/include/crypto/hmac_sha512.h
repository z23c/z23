/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_HMAC_SHA512_H
#define BITCOIN_CRYPTO_HMAC_SHA512_H

#include "crypto/sha512.h"

#define HMAC_SHA512_OUTPUT_SIZE 64

struct hmac_sha512_ctx {
    struct sha512_ctx outer;
    struct sha512_ctx inner;
};

void hmac_sha512_init(struct hmac_sha512_ctx *ctx, const unsigned char *key, size_t keylen);
void hmac_sha512_write(struct hmac_sha512_ctx *ctx, const unsigned char *data, size_t len);
void hmac_sha512_finalize(struct hmac_sha512_ctx *ctx, unsigned char hash[HMAC_SHA512_OUTPUT_SIZE]);

#endif
