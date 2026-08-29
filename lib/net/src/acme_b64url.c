/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * base64url, RFC 4648 §5, unpadded. See net/acme_b64url.h.
 */

#include "net/acme_b64url.h"

#include <stdint.h>
#include <string.h>

#include "base/log_macros.h"

static const char B64URL[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t acme_b64url_encoded_len(size_t len)
{
    const size_t whole = len / 3;
    const size_t rest = len % 3;
    return whole * 4 + (rest == 0 ? 0 : rest + 1);
}

size_t acme_b64url_encode(const void *data, size_t len, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (len && !data)
        return 0;
    const size_t need = acme_b64url_encoded_len(len);
    if (need + 1 > out_len)
        return 0;

    const unsigned char *in = data;
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                           (uint32_t)in[i + 2];
        out[o++] = B64URL[(v >> 18) & 0x3f];
        out[o++] = B64URL[(v >> 12) & 0x3f];
        out[o++] = B64URL[(v >> 6) & 0x3f];
        out[o++] = B64URL[v & 0x3f];
    }
    if (len - i == 1) {
        const uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64URL[(v >> 18) & 0x3f];
        out[o++] = B64URL[(v >> 12) & 0x3f];
    } else if (len - i == 2) {
        const uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = B64URL[(v >> 18) & 0x3f];
        out[o++] = B64URL[(v >> 12) & 0x3f];
        out[o++] = B64URL[(v >> 6) & 0x3f];
    }
    out[o] = '\0';
    return o;
}

static int b64url_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool acme_b64url_decode(const char *text, void *out, size_t out_len,
                        size_t *decoded)
{
    if (!text || !decoded)
        return false;
    *decoded = 0;
    const size_t n = strlen(text);
    if (n % 4 == 1)
        LOG_FAIL("acme", "refusing base64url of length %zu: encodes no whole byte", n);
    const size_t need = (n / 4) * 3 + (n % 4 == 0 ? 0 : n % 4 - 1);
    if (need > out_len)
        LOG_FAIL("acme", "refusing base64url decode: %zu bytes into a %zu-byte buffer",
                 need, out_len);

    unsigned char *dst = out;
    size_t o = 0;
    size_t i = 0;
    while (i < n) {
        const size_t chunk = (n - i >= 4) ? 4 : n - i;
        int v[4] = {0, 0, 0, 0};
        for (size_t k = 0; k < chunk; k++) {
            v[k] = b64url_value(text[i + k]);
            if (v[k] < 0)
                LOG_FAIL("acme", "refusing a byte outside the base64url alphabet");
        }
        const uint32_t acc = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                             ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        if (chunk >= 2) dst[o++] = (unsigned char)((acc >> 16) & 0xff);
        if (chunk >= 3) dst[o++] = (unsigned char)((acc >> 8) & 0xff);
        if (chunk == 4) dst[o++] = (unsigned char)(acc & 0xff);
        i += chunk;
    }
    *decoded = o;
    return true;
}

