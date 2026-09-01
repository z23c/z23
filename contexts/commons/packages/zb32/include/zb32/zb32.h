/* zb32 — RFC 4648 base32 encoding/decoding, bounded
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Standard base32 alphabet (A-Z2-7) with '=' padding. Encoding is
 * canonical. Decoding is strict: invalid characters, bad padding
 * placement, and non-canonical leftover bits are errors.
 *
 * Measuring convention: producers return the needed byte count
 * (excluding NUL); return >= cap means truncated output (still
 * NUL-terminated when cap > 0). SIZE_MAX signals invalid input.
 * Inputs capped at ZB32_MAX (default 65535) source bytes.
 */
#ifndef ZB32_H
#define ZB32_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZB32_MAX
#define ZB32_MAX 65535u
#endif

/* Encode n bytes. Output length is always a multiple of 8. */
size_t zb32_encode(char *dst, size_t cap, const void *src, size_t n);

/* Decode a padded base32 string of n chars. n must be a multiple of
 * 8. Returns the decoded byte count, SIZE_MAX on any malformed
 * input (bad char, misplaced/insufficient padding, nonzero leftover
 * bits, bad length). */
size_t zb32_decode(void *dst, size_t cap, const char *src, size_t n);

/* Exact output sizes, or SIZE_MAX when the input is invalid/too
 * large to encode within the bound. */
size_t zb32_encoded_len(size_t n);                 /* SIZE_MAX if n > ZB32_MAX */
size_t zb32_decoded_len(const char *src, size_t n); /* SIZE_MAX if malformed */

#ifdef __cplusplus
}
#endif

#endif /* ZB32_H */
