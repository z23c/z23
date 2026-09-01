/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HKDF-SHA256 (RFC 5869) — extract-then-expand key derivation over the
 * in-tree HMAC-SHA256. Provides the RFC extract/expand primitives plus the
 * two-output "HKDF2" helper the Noise SymmetricState uses (MixKey / Split);
 * see docs/work/secure-transport-design.md §3. No external dependencies. */

#ifndef ZCL_CRYPTO_HKDF_SHA256_H
#define ZCL_CRYPTO_HKDF_SHA256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HKDF_SHA256_PRK_SIZE 32

/* RFC 5869 §2.2 Extract: PRK = HMAC-SHA256(salt, IKM).
 * `salt` may be NULL (treated as a zero-length salt, i.e. HMAC keyed with the
 * empty string, matching RFC 5869 when no salt is provided by the caller). */
void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[HKDF_SHA256_PRK_SIZE]);

/* RFC 5869 §2.3 Expand: OKM = T(1) | T(2) | ... truncated to out_len, where
 * T(0)="", T(i)=HMAC-SHA256(PRK, T(i-1) | info | byte(i)). `info` may be NULL
 * when info_len==0. Returns false if out_len > 255*32 (the RFC ceiling). */
bool hkdf_sha256_expand(const uint8_t prk[HKDF_SHA256_PRK_SIZE],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len);

/* Convenience: full extract-then-expand in one call. Returns false on the same
 * out_len ceiling as hkdf_sha256_expand. */
bool hkdf_sha256(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len);

/* Noise HKDF2: (o1, o2) = Expand(Extract(salt, ikm), info="")[0..64] split into
 * two 32-byte halves. This is exactly the Noise `HKDF(ck, ikm, 2)` used by
 * MixKey (salt=ck, ikm=dh) and Split (salt=ck, ikm=""). */
void hkdf_sha256_2(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t out1[32], uint8_t out2[32]);

#endif /* ZCL_CRYPTO_HKDF_SHA256_H */
