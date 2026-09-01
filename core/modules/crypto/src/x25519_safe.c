/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * x25519_safe implementation — wraps curve25519_scalarmult with a constant-time
 * all-zero shared-secret reject (RFC 7748 §6.1 contributory guard). See
 * crypto/x25519_safe.h. */

#include "crypto/x25519_safe.h"

#include "crypto/curve25519.h"
#include "support/cleanse.h"

bool x25519_safe(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32])
{
    if (!curve25519_scalarmult(out, scalar, point)) {
        memory_cleanse(out, 32);
        return false;
    }

    /* Constant-time OR-accumulate: acc stays 0 iff every output byte is 0. */
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++)
        acc |= out[i];

    if (acc == 0) {
        /* Low-order / small-subgroup point → degenerate all-zero secret. */
        memory_cleanse(out, 32);
        return false;
    }
    return true;
}
