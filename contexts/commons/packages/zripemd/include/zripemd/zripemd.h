/* zripemd — RIPEMD-160 hash (C23).
 *
 * RIPEMD-160 (ISO/IEC 10118-3) produces a 160-bit digest via two
 * parallel 80-step compression lines.  It is the hash behind
 * Bitcoin-style HASH160 addresses (RIPEMD-160 of SHA-256) and remains
 * in wide use for legacy address and identifier schemes.
 *
 * Incremental context API plus one-shot helpers.  Self-contained;
 * no dependencies beyond libc.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZRIPEMD_H
#define ZRIPEMD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZRIPEMD160_DIGEST_LEN 20
#define ZRIPEMD160_BLOCK_LEN 64
/* 40 lowercase hex chars plus NUL. */
#define ZRIPEMD160_HEX_LEN 41

typedef struct {
    uint32_t h[5];          /* chaining state */
    uint8_t  block[ZRIPEMD160_BLOCK_LEN];
    size_t   block_used;    /* bytes buffered in block */
    uint64_t total_len;     /* total message bytes */
} zripemd160_ctx;

void zripemd160_init(zripemd160_ctx *ctx);
void zripemd160_update(zripemd160_ctx *ctx, const void *data, size_t len);
void zripemd160_final(zripemd160_ctx *ctx, uint8_t out[ZRIPEMD160_DIGEST_LEN]);

/* One-shot. */
void zripemd160(const void *data, size_t len,
                uint8_t out[ZRIPEMD160_DIGEST_LEN]);

/* One-shot into lowercase hex (NUL-terminated). */
void zripemd160_hex(const void *data, size_t len,
                    char out[ZRIPEMD160_HEX_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ZRIPEMD_H */
