/* zhtml — bounded HTML escaping and unescaping
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Escape: &, <, >, ", ' become &amp; &lt; &gt; &quot; &#39;
 * (the XML/HTML5-safe five). Unescape: the five named entities plus
 * numeric &#NN; and &#xHH; references, emitted as UTF-8. Strict:
 * unknown or malformed entities are an error, never passed through.
 *
 * Measuring convention: producers return the needed byte count
 * (excluding NUL); return >= cap means truncated output (still
 * NUL-terminated when cap > 0). SIZE_MAX signals invalid input
 * (NULL, over-long, or malformed entity when unescaping).
 */
#ifndef ZHTML_H
#define ZHTML_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZHTML_MAX
#define ZHTML_MAX 65535u
#endif

/* Escape src[0..n) for HTML text/attribute context. */
size_t zhtml_escape(char *dst, size_t cap, const void *src, size_t n);

/* Unescape src[0..n): named (amp lt gt quot apos) and numeric
 * (decimal/hex) character references. Codepoints above U+10FFFF,
 * lone surrogates, and C0 controls other than tab/LF/CR are rejected
 * (SIZE_MAX). Unknown entities are rejected. */
size_t zhtml_unescape(char *dst, size_t cap, const void *src, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* ZHTML_H */
