/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HMAC-SHA3-256 (FIPS 198-1 / FIPS 202). The HMAC block size is the SHA3-256
 * rate (136 bytes), not the SHA-256 64-byte block. Overlay / file-service
 * key derivation uses this; consensus hashes and Noise HKDF-SHA256 do not. */

#ifndef ZCL_CRYPTO_HMAC_SHA3_H
#define ZCL_CRYPTO_HMAC_SHA3_H

#include "sha3/sha3.h"

#include <stddef.h>

#define HMAC_SHA3_256_OUTPUT_SIZE 32
#define HMAC_SHA3_256_BLOCK_SIZE  (SHA3_256_RATE_BITS / 8)

#if HMAC_SHA3_256_BLOCK_SIZE != 136
#error HMAC-SHA3-256 block size must equal the SHA3-256 rate (136 bytes)
#endif

struct hmac_sha3_256_ctx {
    struct sha3_256_ctx outer;
    struct sha3_256_ctx inner;
};

void hmac_sha3_256_init(struct hmac_sha3_256_ctx *ctx, const unsigned char *key,
                        size_t keylen);
void hmac_sha3_256_write(struct hmac_sha3_256_ctx *ctx,
                         const unsigned char *data, size_t len);
void hmac_sha3_256_finalize(struct hmac_sha3_256_ctx *ctx,
                            unsigned char hash[HMAC_SHA3_256_OUTPUT_SIZE]);

#endif /* ZCL_CRYPTO_HMAC_SHA3_H */
