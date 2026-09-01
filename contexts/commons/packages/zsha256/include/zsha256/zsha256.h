/* zsha256 — SHA-256 and HMAC-SHA256 (C23).
 *
 * FIPS 180-4 SHA-256 with an incremental context API and RFC 2104
 * HMAC, plus one-shot helpers. Self-contained; no dependencies beyond
 * libc.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZSHA256_H
#define ZSHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZSHA256_DIGEST_LEN 32
#define ZSHA256_BLOCK_LEN 64
/* 64 lowercase hex chars plus NUL. */
#define ZSHA256_HEX_LEN 65

typedef struct {
    uint32_t h[8];          /* chaining state */
    uint8_t  block[ZSHA256_BLOCK_LEN];
    size_t   block_used;    /* bytes buffered in block */
    uint64_t total_len;     /* total message bytes */
} zsha256_ctx;

void zsha256_init(zsha256_ctx *ctx);
void zsha256_update(zsha256_ctx *ctx, const void *data, size_t len);
void zsha256_final(zsha256_ctx *ctx, uint8_t out[ZSHA256_DIGEST_LEN]);

/* One-shot. */
void zsha256(const void *data, size_t len, uint8_t out[ZSHA256_DIGEST_LEN]);

/* One-shot into lowercase hex (NUL-terminated). */
void zsha256_hex(const void *data, size_t len, char out[ZSHA256_HEX_LEN]);

/* RFC 2104 HMAC-SHA256, incremental. */
typedef struct {
    zsha256_ctx inner;
    zsha256_ctx outer;
} zsha256_hmac_ctx;

void zsha256_hmac_init(zsha256_hmac_ctx *ctx, const void *key, size_t key_len);
void zsha256_hmac_update(zsha256_hmac_ctx *ctx, const void *data, size_t len);
void zsha256_hmac_final(zsha256_hmac_ctx *ctx, uint8_t out[ZSHA256_DIGEST_LEN]);

/* One-shot HMAC. */
void zsha256_hmac(const void *key, size_t key_len,
                  const void *data, size_t data_len,
                  uint8_t out[ZSHA256_DIGEST_LEN]);

/* Constant-time digest comparison: 0 if equal. */
int zsha256_compare(const uint8_t a[ZSHA256_DIGEST_LEN],
                    const uint8_t b[ZSHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ZSHA256_H */
