/* zpct — RFC 3986 percent-encoding, bounded and zero-allocation
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Encoding: emit every byte outside a caller-selected unreserved set
 * as %XX (uppercase hex). Decoding: strict — '%' must be followed by
 * two hex digits; invalid sequences are an error, never passed
 * through silently.
 *
 * All producers use the measuring convention: return the needed byte
 * count (excluding NUL); return >= cap means truncated output (still
 * NUL-terminated when cap > 0). SIZE_MAX signals invalid input
 * (NULL, over-long, or malformed percent sequence when decoding).
 */
#ifndef ZPCT_H
#define ZPCT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZPCT_MAX
#define ZPCT_MAX 65535u
#endif

/* Byte-set selectors for encoding. */
typedef enum {
  ZPCT_UNRESERVED = 0, /* A-Z a-z 0-9 - _ . ~  (RFC 3986 §2.3) */
  ZPCT_SUBDELIM = 1,   /* unreserved + ! $ & ' ( ) * + , ; = */
  ZPCT_PCHAR = 2       /* sub-delim + : @  (path-segment chars) */
} zpct_set;

/* Encode src[0..n) percent-escaping every byte outside `set`.
 * Returns needed length (always <= 3*n), or SIZE_MAX when src is NULL
 * with n > 0 or n > ZPCT_MAX. */
size_t zpct_encode(char *dst, size_t cap, const void *src, size_t n,
                   zpct_set set);

/* Decode src[0..n), resolving %XX triplets. A literal '%' must be
 * written %25. Returns needed length (always <= n), or SIZE_MAX on
 * malformed input (bad hex, truncated triplet) or NULL/over-long
 * input. Decoded output may contain NUL bytes; `out_len` (when
 * non-NULL) receives the true decoded length regardless of cap. */
size_t zpct_decode(char *dst, size_t cap, const void *src, size_t n,
                   size_t *out_len);

/* Round-trip helper: nonzero when byte c is in `set` unescaped. */
int zpct_is_unescaped(unsigned char c, zpct_set set);

#ifdef __cplusplus
}
#endif

#endif /* ZPCT_H */
