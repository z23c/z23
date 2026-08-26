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
 * the slice by index arithmetic. A field matches at the slice start or
 * directly after '&' or '?'; its value runs to the next '&', ' ', an
 * embedded NUL, or the end of the slice; decoded output is clamped
 * into [out, out+out_max) exactly as the parsers these helpers
 * replaced did. A name that appears twice in one body is refused, not
 * disambiguated. Downstream validators (address checks, CSRF compares,
 * PoW echoes) still own acceptance of truncated values. */

#ifndef ZCL_CONTROLLERS_WEB_FORM_H
#define ZCL_CONTROLLERS_WEB_FORM_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Decode `%XX` and `+` escapes from src[0..srclen), writing at most
 * dstmax-1 bytes plus a terminator into dst. Reads only srclen bytes
 * of src regardless of its contents. */
static inline void web_form_url_decode(char *dst, size_t dstmax,
                                       const char *src, size_t srclen)
{
    size_t di = 0;
    if (!dst || !dstmax || !src)
        return;
    for (size_t si = 0; si < srclen && di < dstmax - 1; si++) {
        char c = src[si];
        if (c == '%' && si + 2 < srclen) {
            int hi = (src[si + 1] >= '0' && src[si + 1] <= '9') ? src[si + 1] - '0' :
                     (src[si + 1] >= 'a' && src[si + 1] <= 'f') ? src[si + 1] - 'a' + 10 :
                     (src[si + 1] >= 'A' && src[si + 1] <= 'F') ? src[si + 1] - 'A' + 10 : -1;
            int lo = (src[si + 2] >= '0' && src[si + 2] <= '9') ? src[si + 2] - '0' :
                     (src[si + 2] >= 'a' && src[si + 2] <= 'f') ? src[si + 2] - 'a' + 10 :
                     (src[si + 2] >= 'A' && src[si + 2] <= 'F') ? src[si + 2] - 'A' + 10 : -1;
            if (hi >= 0 && lo >= 0) {
                dst[di++] = (char)((hi << 4) | lo);
                si += 2;
                continue;
            }
        }
        dst[di++] = (c == '+') ? ' ' : c;
    }
    dst[di] = '\0';
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
    if (!body || !len || !field)
        return false;
    size_t klen = strlen(field);
    if (klen == 0 || klen + 1 > len)
        return false;

    size_t occurrences = 0;
    for (size_t i = 0; i + klen < len; i++) {
        bool at_boundary =
            (i == 0 || body[i - 1] == '&' || body[i - 1] == '?');
        if (!at_boundary)
            continue;
        if (memcmp(body + i, field, klen) != 0)
            continue;
        if (body[i + klen] != '=')
            continue;

        occurrences++;
        if (occurrences > 1)
            break;              /* ambiguity needs no second opinion */
        size_t vstart = i + klen + 1;
        size_t vlen = 0;
        while (vstart + vlen < len && body[vstart + vlen] != '&' &&
               body[vstart + vlen] != ' ' && body[vstart + vlen] != '\0')
            vlen++;
        if (vlen > 0)
            web_form_url_decode(out, out_max, body + vstart, vlen);
    }
    if (occurrences != 1) {
        out[0] = '\0';      /* leave no survivor for ignore-the-bool callers */
        return false;
    }
    if (out[0] == '\0')     /* the lone occurrence carried no value */
        return false;
    return true;
}

#endif /* ZCL_CONTROLLERS_WEB_FORM_H */
