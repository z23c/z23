/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * x25519_safe — X25519 ECDH with the mandatory contributory-behaviour guard.
 * curve25519_scalarmult() returns true even for low-order input points that
 * yield an all-zero shared secret (it omits the RFC 7748 §6.1 check). This thin
 * wrapper rejects that all-zero output in constant time, so Noise DH steps
 * (docs/work/secure-transport-design.md §9 primitive #1) never mix a degenerate
 * zero secret into the chaining key. No external dependencies. */

#ifndef ZCL_CRYPTO_X25519_SAFE_H
#define ZCL_CRYPTO_X25519_SAFE_H

#include <stdbool.h>
#include <stdint.h>

/* Compute out = X25519(scalar, point). Returns false — and zeroizes out — if
 * the shared secret is all-zero (a low-order / small-subgroup point) or if the
 * underlying scalarmult fails. Returns true on a usable, non-zero secret.
 * The all-zero test is a branch-free OR-accumulate over the 32 output bytes. */
bool x25519_safe(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]);

#endif /* ZCL_CRYPTO_X25519_SAFE_H */
