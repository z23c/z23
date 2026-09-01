/* zmd5 — MD5 message digest (RFC 1321)
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * One-shot and streaming MD5. MD5 is cryptographically broken for
 * collision resistance: do NOT use it for signatures, integrity
 * against adversaries, or key derivation. It remains required for
 * legacy interoperability (ETags, Content-MD5, rsync-era checksums,
 * digest auth) and for non-adversarial dedup/identity, which is what
 * this implementation is for. For new designs use zsha256.
 *
 * The context is plain caller-owned storage; no global state.
 */
#ifndef ZMD5_H
#define ZMD5_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZMD5_DIGEST_LEN 16u
#define ZMD5_HEX_LEN 32u

typedef struct {
  uint32_t state[4];    /* chaining state A,B,C,D */
  uint64_t total_len;   /* bytes fed so far */
  uint8_t block[64];    /* partial block buffer */
  size_t block_len;     /* bytes buffered in block */
} zmd5;

/* Streaming interface. init must be called before update; final
 * writes the 16-byte digest and zeroizes the context. */
void zmd5_init(zmd5 *ctx);
void zmd5_update(zmd5 *ctx, const void *data, size_t n);
void zmd5_final(zmd5 *ctx, uint8_t out[ZMD5_DIGEST_LEN]);

/* One-shot digest. NULL data with n == 0 hashes as empty. */
void zmd5_digest(const void *data, size_t n, uint8_t out[ZMD5_DIGEST_LEN]);

/* Lowercase hex rendering. out must hold ZMD5_HEX_LEN bytes; it is
 * not NUL-terminated. */
void zmd5_hex(const uint8_t digest[ZMD5_DIGEST_LEN], char out[ZMD5_HEX_LEN]);

/* One-shot hex digest convenience: hex of the digest of data. */
void zmd5_digest_hex(const void *data, size_t n, char out[ZMD5_HEX_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ZMD5_H */
