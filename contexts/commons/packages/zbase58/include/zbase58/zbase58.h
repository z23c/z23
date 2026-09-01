/* zbase58 — Base58 encoding and decoding (C23).
 *
 * The Bitcoin alphabet (no 0, O, I, l) with leading-zero-byte ↔ '1'
 * mapping, both cases rejected where invalid, exact buffer sizing and
 * strict error positions on decode.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZBASE58_H
#define ZBASE58_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZBASE58_OK = 0,
    ZBASE58_ERR_NULL,
    ZBASE58_ERR_SMALL,     /* output buffer too small */
    ZBASE58_ERR_BAD_CHAR   /* character outside the alphabet */
} zbase58_err;

/* Exact maximum encoded size for n input bytes (ceil(n * 138/100) + 1
 * is the classic bound; we return the safe upper bound). */
size_t zbase58_encoded_max(size_t bin_len);

/* Exact maximum decoded size for n input characters. */
size_t zbase58_decoded_max(size_t b58_len);

/* Encode bin[0..bin_len) into out (capacity cap), NUL-terminated on
 * success; *out_len receives the string length. Empty input encodes
 * to the empty string. */
zbase58_err zbase58_encode(const uint8_t *bin, size_t bin_len,
                           char *out, size_t cap, size_t *out_len);

/* Decode b58[0..b58_len) into out (capacity cap); *out_len receives
 * the byte count. On ZBASE58_ERR_BAD_CHAR, *bad_pos (if non-NULL) is
 * the index of the first invalid character. Leading '1's decode to
 * leading zero bytes. Empty input decodes to zero bytes. */
zbase58_err zbase58_decode(const char *b58, size_t b58_len,
                           uint8_t *out, size_t cap,
                           size_t *out_len, size_t *bad_pos);

/* Value of one Base58 character, or -1. */
int zbase58_char_value(char c);

const char *zbase58_err_str(zbase58_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZBASE58_H */
