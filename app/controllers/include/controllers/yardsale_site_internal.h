/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Module-internal plumbing shared by the Yardsale web mount TUs
 * (msg_internal.h idiom): not part of any public API. The page mount
 * lives in yardsale_site_controller.c; the money-touching buy route
 * lives in yardsale_site_controller_buy.c so each file fits the E1
 * size ceiling along a real seam.
 */

#ifndef ZCL_CONTROLLERS_YARDSALE_SITE_INTERNAL_H
#define ZCL_CONTROLLERS_YARDSALE_SITE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "base/hex.h"

#include <stdio.h>
#include <string.h>

#define YARDSALE_PAGE_STYLE \
    "body{background:#0a0a0a;color:#e0e0e0;font-family:monospace;" \
    "padding:40px 24px;max-width:1100px;margin:auto}" \
    "a{color:#00ff88}table{border-collapse:collapse;width:100%%}" \
    "td,th{border:1px solid #333;padding:6px 8px;text-align:left;" \
    "font-size:13px}th{color:#00ff88}input{width:100%%;background:#111;" \
    "color:#e0e0e0;border:1px solid #333;font-family:monospace;" \
    "padding:4px}label{font-size:12px;color:#999}" \
    ".seller{margin:10px 0}.desc{color:#999;font-size:12px}"

/* ── HTTP plumbing (blog_post_controller.c idiom) ────────────────── */

static inline size_t yardsale_http_response(
    const char *status, const char *content_type, const uint8_t *body,
    size_t body_len, uint8_t *response, size_t response_max)
{
    if (!status || !content_type || !response)
        return 0;
    int header_len = snprintf((char *)response, response_max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; frame-ancestors 'none'\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, content_type, body_len);
    if (header_len < 0 || (size_t)header_len >= response_max)
        return 0;
    if (body_len > 0 && body) {
        if (body_len > response_max - (size_t)header_len)
            return 0;
        memcpy(response + header_len, body, body_len);
    }
    return (size_t)header_len + body_len;
}

static inline size_t yardsale_error_page(const char *status,
                                         const char *title,
                                         const char *detail,
                                         uint8_t *response,
                                         size_t response_max)
{
    char body[1024];
    int n = snprintf(body, sizeof(body),
        "<!doctype html><html><head><title>%s</title>"
        "<style>body{background:#0a0a0a;color:#e0e0e0;font-family:monospace;"
        "padding:60px 24px}a{color:#00ff88}</style></head><body>"
        "<h1>%s</h1><p>%s</p><p><a href='/yardsale'>Back to the yard</a>"
        "</p></body></html>", title, title, detail);
    if (n < 0)
        return 0;
    return yardsale_http_response(status, "text/html; charset=utf-8",
                                  (const uint8_t *)body, (size_t)n,
                                  response, response_max);
}

static inline void hex_short(const uint8_t *bytes, size_t len, size_t keep,
                             char *out, size_t out_cap)
{
    if (keep > len)
        keep = len;
    size_t need = 2 * keep + 1;
    if (out_cap < need + 3)
        return;
    zcl_hex_encode(bytes, keep, out);
    memcpy(out + 2 * keep, "...", 4);
}

/* ── Form parsing (name_site_controller.c idiom) ─────────────────── */

static inline void url_decode(char *dst, size_t dstmax, const char *src,
                              size_t srclen)
{
    size_t di = 0;
    if (!dstmax)
        return;
    for (size_t si = 0; si < srclen && di < dstmax - 1; si++) {
        char c = src[si];
        if (c == '%' && si + 2 < srclen) {
            int hi = zcl_hex_nibble(src[si + 1], true);
            int lo = zcl_hex_nibble(src[si + 2], true);
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

static inline const char *parse_form_field(const char *body, size_t len,
                                           const char *field, char *out,
                                           size_t outmax)
{
    if (!body || !len || !field || !out || outmax == 0)
        return NULL;
    size_t field_len = strlen(field);
    const char *found = NULL;
    size_t found_len = 0;
    size_t pos = 0;
    while (pos < len) {
        size_t end = pos;
        while (end < len && body[end] != '&')
            end++;
        size_t eq = pos;
        while (eq < end && body[eq] != '=')
            eq++;
        if (eq < end && eq - pos == field_len &&
            memcmp(body + pos, field, field_len) == 0) {
            if (found) {
                out[0] = '\0';
                return NULL;
            }
            found = body + eq + 1;
            found_len = end - eq - 1;
        }
        pos = end + (end < len);
    }
    if (!found)
        return NULL;
    url_decode(out, outmax, found, found_len);
    return out;
}

/* The plan-gated buy route (yardsale_site_controller_buy.c). */
size_t yardsale_site_handle_buy_post(const uint8_t *body, size_t body_len,
                                     uint8_t *response,
                                     size_t response_max);

#endif /* ZCL_CONTROLLERS_YARDSALE_SITE_INTERNAL_H */
