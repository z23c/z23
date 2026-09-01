/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SHA3 Stream Cipher — post-quantum authenticated encryption.
 *
 * Encryption: SHA3-256 in counter mode generates keystream.
 *   keystream[i] = SHA3-256(key || nonce || counter_i)
 *   ciphertext = plaintext XOR keystream
 *
 * Authentication: SHA3-512(key || nonce || ciphertext).
 *
 * Wire format: [32-byte nonce][64-byte tag][ciphertext]
 * Overhead: 96 bytes per message.
 *
 * Quantum security: pure symmetric — 256-bit key = 128-bit post-quantum. */

#ifndef ZCL_SHA3_CRYPT_H
#define ZCL_SHA3_CRYPT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Derive the 32-byte shared session key from chain state + both peer nonces:
 *   key_out = SHA3-256(utxo_root || min(nonce_a,nonce_b) || max(...)).
 * The two nonces are sorted lexicographically before hashing, so the result
 * is SYMMETRIC in (nonce_a, nonce_b) — both peers compute the identical key
 * regardless of which side they call A vs B. Binding `utxo_root` means the
 * key is tied to a shared view of chain state. Always writes 32 bytes. */
void sha3_crypt_derive_key(const uint8_t utxo_root[32],
                            const uint8_t nonce_a[32],
                            const uint8_t nonce_b[32],
                            uint8_t key_out[32]);

#endif
