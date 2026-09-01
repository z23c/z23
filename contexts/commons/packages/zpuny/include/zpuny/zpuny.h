/* zpuny — Punycode encoder/decoder (RFC 3492) for IDNA labels (C23).
 *
 * Converts between Unicode code-point sequences and the ASCII
 * bootstring encoding used by internationalized domain names
 * (the "xn--" labels). This library works on raw code points; it
 * does not implement full IDNA (Nameprep, ToASCII label framing,
 * or the ACE prefix) — compose it with your own label handling.
 *
 * Buffers are caller-provided; all functions report the exact
 * required length through an out parameter so a two-pass
 * size-then-fill pattern works without guessing.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZPUNY_H
#define ZPUNY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZPUNY_OK = 0,
    ZPUNY_OVERFLOW,    /* output buffer too small */
    ZPUNY_BAD_INPUT,   /* invalid encoding or code point > 0x10FFFF */
    ZPUNY_BIG_OUTPUT   /* decode would exceed uint32 range */
} zpuny_status;

/* Encode code points cp[0..cp_len) into ASCII out[0..out_cap).
 * On success returns ZPUNY_OK, stores the encoded length in
 * *out_len (excluding NUL). If out is NULL or out_cap too small,
 * returns ZPUNY_OVERFLOW and *out_len still receives the required
 * length. Basic code points are lower-cased only by the caller's
 * policy — this encoder preserves case (annotate flags omitted). */
zpuny_status zpuny_encode(const uint32_t *cp, size_t cp_len,
                          char *out, size_t out_cap, size_t *out_len);

/* Decode ASCII punycode in[0..in_len) into cp[0..cp_cap).
 * Length semantics mirror zpuny_encode. Case-insensitive input. */
zpuny_status zpuny_decode(const char *in, size_t in_len,
                          uint32_t *cp, size_t cp_cap, size_t *cp_len);

/* Convenience: UTF-8 front-ends. Encode/decode between UTF-8 and
 * punycode in one call. Invalid UTF-8 yields ZPUNY_BAD_INPUT. */
zpuny_status zpuny_encode_utf8(const char *utf8, size_t utf8_len,
                               char *out, size_t out_cap, size_t *out_len);
zpuny_status zpuny_decode_utf8(const char *in, size_t in_len,
                               char *utf8, size_t utf8_cap, size_t *utf8_len);

#ifdef __cplusplus
}
#endif

#endif /* ZPUNY_H */
