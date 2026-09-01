/* zescape — C-style string escaping and unescaping (C23).
 *
 * Escape renders control characters, quotes and backslashes in the
 * classic C notation (\n, \t, \x1b, …). Unescape reverses it strictly:
 * unknown escapes, truncated sequences, and bad hex digits are errors
 * with an exact position.
 *
 * Buffer API with exact size queries; no allocation.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZESCAPE_H
#define ZESCAPE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZESCAPE_OK = 0,
    ZESCAPE_ERR_NULL,
    ZESCAPE_ERR_SMALL,       /* output buffer too small */
    ZESCAPE_ERR_BAD_ESCAPE,  /* unknown escape letter */
    ZESCAPE_ERR_TRUNCATED,   /* input ends mid-escape */
    ZESCAPE_ERR_BAD_HEX      /* \x not followed by 2 hex digits */
} zescape_err;

/* Worst-case escaped length of n input bytes (every byte -> \xNN). */
size_t zescape_escaped_max(size_t n);

/* Escape in[0..len) into out (capacity cap), writing *out_len bytes
 * (not NUL-terminated). Bytes are emitted as:
 *   \\ \" \n \r \t \0 through \x1f and 0x7f..0xff as \xNN, other
 * printable bytes verbatim.
 * On ZESCAPE_ERR_SMALL, *out_len receives the required capacity. */
zescape_err zescape_escape(const void *in, size_t len,
                           char *out, size_t cap, size_t *out_len);

/* Unescape in[0..len) into out (capacity cap), writing *out_len bytes.
 * Supported escapes: \\ \" \' \n \r \t \0 \a \b \f \v \xHH (exactly
 * two hex digits). A trailing backslash is ZESCAPE_ERR_TRUNCATED.
 * On error *err_pos (if non-NULL) is the offset of the offending
 * backslash or digit. */
zescape_err zescape_unescape(const char *in, size_t len,
                             void *out, size_t cap,
                             size_t *out_len, size_t *err_pos);

const char *zescape_err_str(zescape_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZESCAPE_H */
