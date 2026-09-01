/* zhex — strict hexadecimal encoding and decoding (C23).
 *
 * Lowercase output by default; uppercase on request. Decoding is strict:
 * even input length, both cases accepted, position of the first bad
 * character reported.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZHEX_H
#define ZHEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZHEX_OK = 0,
    ZHEX_ERR_NULL,      /* NULL argument */
    ZHEX_ERR_ODD_LEN,   /* decode input has odd length */
    ZHEX_ERR_BAD_CHAR,  /* decode input has a non-hex character */
    ZHEX_ERR_SMALL      /* output buffer too small */
} zhex_err;

/* Exact buffer sizes (excluding any terminator). */
size_t zhex_encoded_len(size_t bin_len);   /* always 2 * bin_len */
size_t zhex_decoded_len(size_t hex_len);   /* hex_len / 2, even if odd */

/* Encode bin[0..bin_len) into out as lowercase hex.
 * out must hold 2*bin_len bytes; out is NOT NUL-terminated.
 * Returns ZHEX_OK or ZHEX_ERR_NULL. */
zhex_err zhex_encode(const uint8_t *bin, size_t bin_len, char *out);

/* Same, uppercase. */
zhex_err zhex_encode_upper(const uint8_t *bin, size_t bin_len, char *out);

/* Decode hex[0..hex_len) into out (both cases accepted).
 * out must hold hex_len/2 bytes; hex_len must be even.
 * On ZHEX_ERR_BAD_CHAR, *bad_pos (if non-NULL) is the index of the
 * first invalid character. Output bytes before the error are valid. */
zhex_err zhex_decode(const char *hex, size_t hex_len,
                     uint8_t *out, size_t *bad_pos);

/* Convenience: decode a NUL-terminated string. */
zhex_err zhex_decode_cstr(const char *hex, uint8_t *out, size_t *bad_pos);

/* Value of one hex digit, or -1. Accepts both cases. */
int zhex_digit_value(char c);

/* Human-readable error name. */
const char *zhex_err_str(zhex_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZHEX_H */
