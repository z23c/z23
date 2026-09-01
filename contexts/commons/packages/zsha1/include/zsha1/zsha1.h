/* zsha1 — SHA-1 message digest (FIPS 180-1 / RFC 3174)
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * One-shot and streaming SHA-1. SHA-1 is cryptographically broken
 * for collision resistance (SHAttered, 2017): do NOT use it for
 * signatures, new integrity designs, or key derivation. It remains
 * required for legacy interoperability — git object identities,
 * rsync-era manifests, HMAC-SHA1 in older protocols — which is what
 * this implementation is for. For new designs use zsha256.
 *
 * The context is plain caller-owned storage; no global state.
 */
#ifndef ZSHA1_H
#define ZSHA1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZSHA1_DIGEST_LEN 20u
#define ZSHA1_HEX_LEN 40u

typedef struct {
  uint32_t state[5];    /* chaining state H0..H4 */
  uint64_t total_len;   /* bytes fed so far */
  uint8_t block[64];    /* partial block buffer */
  size_t block_len;     /* bytes buffered in block */
} zsha1;

/* Streaming interface. init must be called before update; final
 * writes the 20-byte digest and zeroizes the context. */
void zsha1_init(zsha1 *ctx);
void zsha1_update(zsha1 *ctx, const void *data, size_t n);
void zsha1_final(zsha1 *ctx, uint8_t out[ZSHA1_DIGEST_LEN]);

/* One-shot digest. NULL data with n == 0 hashes as empty. */
void zsha1_digest(const void *data, size_t n, uint8_t out[ZSHA1_DIGEST_LEN]);

/* Lowercase hex rendering. out must hold ZSHA1_HEX_LEN bytes; it is
 * not NUL-terminated. */
void zsha1_hex(const uint8_t digest[ZSHA1_DIGEST_LEN], char out[ZSHA1_HEX_LEN]);

/* One-shot hex digest convenience: hex of the digest of data. */
void zsha1_digest_hex(const void *data, size_t n, char out[ZSHA1_HEX_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ZSHA1_H */
