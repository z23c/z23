/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PBKDF2-HMAC-SHA256 (RFC 8018) — password-based key derivation.
 *
 * Used by the wallet backup service to turn a user-supplied
 * password into a 256-bit AEAD key. The plan originally called
 * for scrypt, but this codebase doesn't link one and PBKDF2 with
 * a high iteration count (200 000+) is still a reasonable choice
 * for wallet backup files that sit on disk — the attacker model
 * is an adversary who grabs a copy of the file, not one who can
 * run a GPU farm against billions of candidate passwords in
 * parallel (which is the scrypt case).
 *
 * For higher-sensitivity use cases (e.g. deriving the wallet seed
 * itself), prefer scrypt or argon2 when they're integrated.
 */

#ifndef ZCL_CRYPTO_PBKDF2_SHA256_H
#define ZCL_CRYPTO_PBKDF2_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Derive `out_len` bytes of key material from `password` + `salt`
 * using PBKDF2-HMAC-SHA256 with `iterations` rounds. `out_len` is
 * capped at 1 MiB so a typo'd call can't allocate indefinitely. */
void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations,
                         uint8_t *out, size_t out_len);

#endif /* ZCL_CRYPTO_PBKDF2_SHA256_H */
