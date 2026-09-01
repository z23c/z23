/* zhkdf — RFC 5869 HKDF key derivation over HMAC-SHA256 (C23).
 *
 * HKDF turns input keying material of arbitrary entropy into one or
 * more strong, domain-separated keys:
 *
 *   PRK = HMAC-SHA256(salt, IKM)                       (extract)
 *   T(0) = empty
 *   T(i) = HMAC-SHA256(PRK, T(i-1) | info | byte(i))   (expand)
 *   OKM  = first L bytes of T(1) | T(2) | ...
 *
 * A NULL or empty salt is replaced by HashLen zero bytes per the RFC.
 * okm_len may be at most 255 * HashLen (8160 bytes).
 *
 * Depends on the Commons package zsha256 for HMAC-SHA256.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZHKDF_H
#define ZHKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZHKDF_SHA256_PRK_LEN 32
#define ZHKDF_SHA256_MAX_OKM_LEN (255u * ZHKDF_SHA256_PRK_LEN)

/* Extract step: derive a pseudorandom key from input keying material.
 * Returns 0 on success, -1 on invalid arguments. */
int zhkdf_sha256_extract(const void *salt, size_t salt_len,
                         const void *ikm, size_t ikm_len,
                         uint8_t prk[ZHKDF_SHA256_PRK_LEN]);

/* Expand step: derive okm_len bytes of output keying material from a
 * PRK and optional context info.  Returns 0 on success, -1 on invalid
 * arguments (okm_len out of range, bad pointers). */
int zhkdf_sha256_expand(const uint8_t prk[ZHKDF_SHA256_PRK_LEN],
                        const void *info, size_t info_len,
                        uint8_t *okm, size_t okm_len);

/* One-shot extract + expand.  Returns 0 on success, -1 on invalid
 * arguments. */
int zhkdf_sha256(const void *salt, size_t salt_len,
                 const void *ikm, size_t ikm_len,
                 const void *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* ZHKDF_H */
