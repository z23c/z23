/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Curve25519 scalar multiplication — pure C23 implementation.
 * Replaces libsodium crypto_scalarmult and crypto_scalarmult_base. */

#ifndef ZCL_CRYPTO_CURVE25519_H
#define ZCL_CRYPTO_CURVE25519_H

#include <stdint.h>
#include <stdbool.h>

#define CURVE25519_BYTES 32
#define CURVE25519_SCALAR_BYTES 32

bool curve25519_scalarmult(uint8_t result[32], const uint8_t scalar[32],
                            const uint8_t point[32]);

bool curve25519_scalarmult_base(uint8_t result[32], const uint8_t scalar[32]);

#endif
