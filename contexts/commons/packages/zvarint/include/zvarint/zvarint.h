/* zvarint — LEB128 variable-length integer encoding (C23).
 *
 * Unsigned LEB128 and zigzag-mapped signed LEB128, buffer-based with
 * explicit lengths, canonical-form checking, and a bounded reader.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZVARINT_H
#define ZVARINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Worst-case encoded length of a 64-bit value. */
#define ZVARINT_MAX_LEN 10

typedef enum {
    ZVARINT_OK = 0,
    ZVARINT_ERR_NULL,
    ZVARINT_ERR_TRUNCATED,  /* buffer ended mid-varint */
    ZVARINT_ERR_OVERFLOW,   /* more than 64 bits of payload */
    ZVARINT_ERR_NONCANONICAL /* trailing zero-padding byte(s) */
} zvarint_err;

/* Encode v as unsigned LEB128 into out (capacity out_cap).
 * Returns bytes written via *out_len. */
zvarint_err zvarint_encode_u64(uint64_t v, uint8_t *out, size_t out_cap,
                               size_t *out_len);

/* Encode s with zigzag mapping (0→0, -1→1, 1→2, -2→3, …). */
zvarint_err zvarint_encode_i64(int64_t s, uint8_t *out, size_t out_cap,
                               size_t *out_len);

/* Decode unsigned LEB128 from buf[0..len). On success *value receives
 * the value and *consumed the byte count (1..10). Trailing bytes are
 * not an error; *consumed tells the caller where the varint ended.
 * With strict_canonical non-zero, non-minimal encodings (e.g. 0x80 0x00
 * for zero) are rejected with ZVARINT_ERR_NONCANONICAL. */
zvarint_err zvarint_decode_u64(const uint8_t *buf, size_t len,
                               uint64_t *value, size_t *consumed,
                               int strict_canonical);

/* Decode zigzag-mapped signed LEB128. */
zvarint_err zvarint_decode_i64(const uint8_t *buf, size_t len,
                               int64_t *value, size_t *consumed,
                               int strict_canonical);

/* Exact encoded lengths. */
size_t zvarint_len_u64(uint64_t v);
size_t zvarint_len_i64(int64_t s);

/* Zigzag mapping helpers (also useful standalone). */
uint64_t zvarint_zigzag_encode(int64_t s);
int64_t  zvarint_zigzag_decode(uint64_t v);

const char *zvarint_err_str(zvarint_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZVARINT_H */
