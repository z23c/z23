/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HKDF-SHA3-256 (RFC 5869 extract-then-expand over HMAC-SHA3-256). This is
 * the overlay KDF for FlyClient-adjacent file-service / swarm handshakes.
 * Noise v2 and consensus hashes stay on HKDF-SHA256 / SHA-256d. */

#ifndef ZCL_CRYPTO_HKDF_SHA3_H
#define ZCL_CRYPTO_HKDF_SHA3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HKDF_SHA3_256_PRK_SIZE 32

/* RFC 5869 §2.2 Extract: PRK = HMAC-SHA3-256(salt, IKM).
 * `salt` may be NULL (treated as a zero-length salt, i.e. HMAC keyed with the
 * empty string, matching the in-tree HKDF-SHA256 empty-salt convention). */
void hkdf_sha3_256_extract(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t prk[HKDF_SHA3_256_PRK_SIZE]);

/* RFC 5869 §2.3 Expand: OKM truncated to out_len. `info` may be NULL when
 * info_len==0. Returns false if out_len > 255*32 (the RFC ceiling). */
bool hkdf_sha3_256_expand(const uint8_t prk[HKDF_SHA3_256_PRK_SIZE],
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len);

/* Convenience: full extract-then-expand in one call. */
bool hkdf_sha3_256(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *out, size_t out_len);

#endif /* ZCL_CRYPTO_HKDF_SHA3_H */
