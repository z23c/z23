/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SHA3 stream cipher: post-quantum authenticated encryption.
 * Zero new primitives — built entirely from SHA3-256 and HMAC-SHA3-512. */

#include "crypto/sha3_crypt.h"
#include "sha3/sha3.h"
#include <string.h>

void sha3_crypt_derive_key(const uint8_t utxo_root[32],
                            const uint8_t nonce_a[32],
                            const uint8_t nonce_b[32],
                            uint8_t key_out[32])
{
    /* Sort nonces lexicographically for deterministic key derivation.
     * Both peers must derive the same key regardless of who is A vs B. */
    const uint8_t *lo = nonce_a;
    const uint8_t *hi = nonce_b;
    if (memcmp(nonce_a, nonce_b, 32) > 0) {
        lo = nonce_b;
        hi = nonce_a;
    }

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, utxo_root, 32);
    sha3_256_write(&ctx, lo, 32);
    sha3_256_write(&ctx, hi, 32);
    sha3_256_finalize(&ctx, key_out);
}
