/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Compatibility surface for crypto-owned four-lane SHA3 acceleration. */
#ifndef BITCOIN_CRYPTO_SHA3_H
#define BITCOIN_CRYPTO_SHA3_H

#include "sha3/sha3.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void sha3_512_x4(const uint8_t key[32], const uint8_t nonce[32],
                 uint64_t counter_base, uint8_t out[256]);

enum sha3_impl {
    SHA3_IMPL_AUTO = -1,
    SHA3_IMPL_SCALAR = 0,
    SHA3_IMPL_AVX512 = 1,
    SHA3_IMPL_NEON = 2
};

bool keccak_x4_available(void);
int sha3_512_x4_select_impl(enum sha3_impl which);
void sha3_256_x4(const uint8_t *const msgs[4], const size_t lens[4],
                 uint8_t out[4][32]);
int sha3_256_x4_select_impl(enum sha3_impl which);

#endif /* BITCOIN_CRYPTO_SHA3_H */
