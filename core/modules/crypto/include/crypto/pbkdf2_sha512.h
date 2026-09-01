/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PBKDF2-HMAC-SHA512 (RFC 8018) — password-based key derivation.
 *
 * Used by BIP39 to derive a 512-bit seed from a mnemonic phrase
 * and optional passphrase (2048 iterations, salt = "mnemonic" + passphrase).
 */

#ifndef ZCL_CRYPTO_PBKDF2_SHA512_H
#define ZCL_CRYPTO_PBKDF2_SHA512_H

#include <stddef.h>
#include <stdint.h>

/* Derive `out_len` bytes of key material from `password` + `salt`
 * using PBKDF2-HMAC-SHA512 with `iterations` rounds.
 * `out_len` is capped at 1 MiB; requests exceeding this (or
 * out_len == 0 / out == NULL) are silently ignored, leaving `out`
 * unchanged. */
void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations,
                         uint8_t *out, size_t out_len);

#endif /* ZCL_CRYPTO_PBKDF2_SHA512_H */
