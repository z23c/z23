/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared x-www-form-urlencoded parsing for the site controllers and
 * wallet views (store / name / yardsale mounts). One bounded scanner
 * replaces the per-controller copies of the same parser.
 *
 * The invariant this exists to enforce: form bodies arrive as
 * length-delimited slices [body, body+len) carved out of HTTP dispatch.
 * They are NOT NUL-terminated, so nothing here may call strstr,
 * strncmp, or any sentinel-based scan — every read below stays inside
 * the slice by index arithmetic. A field matches only as a complete
 * ampersand-delimited segment; its value runs to the next '&' or the
 * end of the slice. Embedded NULs, malformed percent escapes, decoded
 * NULs, duplicate names, and values that do not fit the destination
 * are refused with an empty output. */

#ifndef ZCL_CONTROLLERS_WEB_FORM_H
#define ZCL_CONTROLLERS_WEB_FORM_H

#include "base/hex.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static inline bool web_form_encoding_valid(const char *body, size_t len)
{
    if (!body)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)body[i];
        if (c == '\0')
            return false;
        if (c != '%')
            continue;
        if (i + 2 >= len)
            return false;
        int hi = zcl_hex_nibble(body[i + 1], true);
        int lo = zcl_hex_nibble(body[i + 2], true);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0))
            return false;
        i += 2;
    }
    return true;
}

/* Decode one already bounded value. Failure always clears dst. */
static inline bool web_form_url_decode(char *dst, size_t dstmax,
                                       const char *src, size_t srclen)
{
    size_t di = 0;
    if (!dst || dstmax == 0)
        return false;
    dst[0] = '\0';
    if (!src || !web_form_encoding_valid(src, srclen))
        return false;
    for (size_t si = 0; si < srclen; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '%') {
            int hi = zcl_hex_nibble(src[si + 1], true);
            int lo = zcl_hex_nibble(src[si + 2], true);
            c = (unsigned char)((hi << 4) | lo);
            si += 2;
        } else if (c == '+') {
            c = ' ';
        }
        if (di + 1 >= dstmax) {
            dst[0] = '\0';
            return false;
        }
        dst[di++] = (char)c;
    }
    dst[di] = '\0';
    return di > 0;
}

/* Find `field=value` in the slice body[0..len) and URL-decode the value
 * into out. Returns true on a hit, false when the field is absent,
 * holds no value, or is supplied MORE THAN ONCE — a payment form that
 * says fee=100 twice is lying by construction, and a parser that picks
 * one of its sides helps the lie, so ambiguity is refused outright the
 * moment a second `field=` appears anywhere in the slice. On false the
 * buffer is LEFT EMPTY (not partially filled): refusal must be visible
 * to readers who follow the established ignore-the-return style and
 * only look at the output. out is always NUL-terminated either way. */
static inline bool web_form_field(const char *body, size_t len,
                                  const char *field,
                                  char *out, size_t out_max)
{
    if (!out || out_max == 0)
        return false;
    out[0] = '\0';
    if (!body || !len || !field || !web_form_encoding_valid(body, len))
        return false;
    size_t klen = strlen(field);
    if (klen == 0 || klen >= len)
        return false;

    size_t occurrences = 0;
    size_t value_start = 0;
    size_t value_len = 0;
    for (size_t pos = 0; pos < len;) {
        size_t end = pos;
        while (end < len && body[end] != '&')
            end++;
        size_t segment_len = end - pos;
        if (segment_len > klen && body[pos + klen] == '=' &&
            memcmp(body + pos, field, klen) == 0) {
            occurrences++;
            value_start = pos + klen + 1;
            value_len = end - value_start;
        }
        pos = end < len ? end + 1 : len;
    }
    if (occurrences != 1 || value_len == 0 ||
        !web_form_url_decode(out, out_max, body + value_start, value_len)) {
        out[0] = '\0';
        return false;
    }
    return true;
}

#endif /* ZCL_CONTROLLERS_WEB_FORM_H */
