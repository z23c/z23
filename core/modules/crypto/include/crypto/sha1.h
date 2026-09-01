/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_SHA1_H
#define BITCOIN_CRYPTO_SHA1_H

#include <stdint.h>
#include <stdlib.h>

#define SHA1_OUTPUT_SIZE 20
#define SHA1_BLOCK_SIZE 64

struct sha1_ctx {
    uint32_t s[5];
    unsigned char buf[SHA1_BLOCK_SIZE];
    size_t bytes;
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_write(struct sha1_ctx *ctx, const unsigned char *data, size_t len);
void sha1_finalize(struct sha1_ctx *ctx, unsigned char hash[SHA1_OUTPUT_SIZE]);

#endif
