/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_SHA512_H
#define BITCOIN_CRYPTO_SHA512_H

#include <stdint.h>
#include <stdlib.h>

#define SHA512_OUTPUT_SIZE 64
#define SHA512_BLOCK_SIZE 128

struct sha512_ctx {
    uint64_t s[8];
    unsigned char buf[SHA512_BLOCK_SIZE];
    size_t bytes;
};

void sha512_init(struct sha512_ctx *ctx);
void sha512_write(struct sha512_ctx *ctx, const unsigned char *data, size_t len);
void sha512_finalize(struct sha512_ctx *ctx, unsigned char hash[SHA512_OUTPUT_SIZE]);

#endif
