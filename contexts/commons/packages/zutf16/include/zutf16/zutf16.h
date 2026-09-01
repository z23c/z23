/* zutf16 — strict UTF-8 <-> UTF-16LE transcoding, bounded
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Decoding UTF-8: rejects overlong encodings, surrogates, codepoints
 * above U+10FFFF, and truncated sequences. Decoding UTF-16: rejects
 * unpaired surrogates and truncated pairs. All errors are SIZE_MAX.
 *
 * UTF-16 units are little-endian byte sequences on the wire API
 * (portable across hosts); unit-array helpers use uint16_t.
 *
 * Measuring convention: producers return the needed byte (or unit)
 * count; return >= cap means truncated output. SIZE_MAX signals
 * invalid input. Inputs are capped at ZUTF16_MAX (default 65535)
 * source bytes/units.
 */
#ifndef ZUTF16_H
#define ZUTF16_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZUTF16_MAX
#define ZUTF16_MAX 65535u
#endif

/* UTF-8 -> UTF-16LE bytes. Returns needed byte count (always even),
 * SIZE_MAX on invalid UTF-8. */
size_t zutf16_from_utf8(void *dst, size_t cap, const void *src,
                        size_t n);

/* UTF-16LE bytes -> UTF-8. `n` is the source byte count (must be
 * even). Returns needed byte count, SIZE_MAX on invalid UTF-16. */
size_t zutf16_to_utf8(void *dst, size_t cap, const void *src, size_t n);

/* Decode one UTF-8 codepoint at src[0..n): writes the codepoint,
 * returns bytes consumed (1..4), 0 on invalid, SIZE_MAX on
 * truncation. */
size_t zutf16_decode_cp(const void *src, size_t n, uint32_t *cp);

/* Encode one codepoint as UTF-16 units (1 or 2). Returns unit count,
 * 0 when the codepoint is invalid (surrogate, > U+10FFFF). */
size_t zutf16_encode_cp(uint16_t *units, uint32_t cp);

/* Length queries without producing output. */
size_t zutf16_units_from_utf8(const void *src, size_t n); /* SIZE_MAX bad */
size_t zutf8_bytes_from_utf16(const void *src, size_t n);  /* SIZE_MAX bad */

#ifdef __cplusplus
}
#endif

#endif /* ZUTF16_H */
