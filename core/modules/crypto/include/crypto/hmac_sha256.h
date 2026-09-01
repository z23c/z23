/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_HMAC_SHA256_H
#define BITCOIN_CRYPTO_HMAC_SHA256_H

#include "crypto/sha256.h"

#define HMAC_SHA256_OUTPUT_SIZE 32

struct hmac_sha256_ctx {
    struct sha256_ctx outer;
    struct sha256_ctx inner;
};

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const unsigned char *key, size_t keylen);
void hmac_sha256_write(struct hmac_sha256_ctx *ctx, const unsigned char *data, size_t len);
void hmac_sha256_finalize(struct hmac_sha256_ctx *ctx, unsigned char hash[HMAC_SHA256_OUTPUT_SIZE]);

#endif
