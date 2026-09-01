/* Copyright (c) 2020 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license; see platform/modules/sha3/LICENSE. */
#ifndef ZCL_SHA3_SHA3_H
#define ZCL_SHA3_SHA3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHA3_256_OUTPUT_SIZE 32
#define SHA3_256_RATE_BITS 1088
#define SHA3_256_RATE_BUFFERS (SHA3_256_RATE_BITS / 64)

#define SHA3_512_OUTPUT_SIZE 64
#define SHA3_512_RATE_BITS 576
#define SHA3_512_RATE_BUFFERS (SHA3_512_RATE_BITS / 64)

struct sha3_256_ctx {
    uint64_t state[25];
    unsigned char buffer[8];
    unsigned bufsize;
    unsigned pos;
};

struct sha3_512_ctx {
    uint64_t state[25];
    unsigned char buffer[8];
    unsigned bufsize;
    unsigned pos;
};

void sha3_256_init(struct sha3_256_ctx *ctx);
void sha3_256_write(struct sha3_256_ctx *ctx, const unsigned char *data,
                    size_t len);
void sha3_256_finalize(struct sha3_256_ctx *ctx,
                       unsigned char output[SHA3_256_OUTPUT_SIZE]);

void sha3_512_init(struct sha3_512_ctx *ctx);
void sha3_512_write(struct sha3_512_ctx *ctx, const unsigned char *data,
                    size_t len);
void sha3_512_finalize(struct sha3_512_ctx *ctx,
                       unsigned char output[SHA3_512_OUTPUT_SIZE]);

void zcl_sha3_256(const unsigned char *data, size_t len,
                  unsigned char output[SHA3_256_OUTPUT_SIZE]);
void zcl_sha3_512(const unsigned char *data, size_t len,
                  unsigned char output[SHA3_512_OUTPUT_SIZE]);
#define sha3_256 zcl_sha3_256
#define sha3_512 zcl_sha3_512

/* Checked FIPS-202 extendable-output functions.  NULL is accepted only for a
 * corresponding zero length.  Output is caller-owned and may span any number
 * of squeeze blocks.  Invalid inputs are rejected before output is touched. */
bool zcl_shake128(const unsigned char *data, size_t len,
                  unsigned char *output, size_t output_len);
bool zcl_shake256(const unsigned char *data, size_t len,
                  unsigned char *output, size_t output_len);

/* The one scalar Keccak-f[1600] permutation, also used as the differential
 * oracle for crypto-owned batched implementations. */
void sha3_keccakf_scalar(uint64_t state[25]);

#endif /* ZCL_SHA3_SHA3_H */
