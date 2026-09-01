/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_RIPEMD160_H
#define BITCOIN_CRYPTO_RIPEMD160_H

#include <stdint.h>
#include <stdlib.h>

#define RIPEMD160_OUTPUT_SIZE 20
#define RIPEMD160_BLOCK_SIZE 64

struct ripemd160_ctx {
    uint32_t s[5];
    unsigned char buf[RIPEMD160_BLOCK_SIZE];
    size_t bytes;
};

void ripemd160_init(struct ripemd160_ctx *ctx);
void ripemd160_write(struct ripemd160_ctx *ctx, const unsigned char *data, size_t len);
void ripemd160_finalize(struct ripemd160_ctx *ctx, unsigned char hash[RIPEMD160_OUTPUT_SIZE]);

#endif
