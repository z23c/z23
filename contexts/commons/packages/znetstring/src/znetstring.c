#include "znetstring/znetstring.h"

#include <string.h>

static size_t digit_count(size_t n)
{
    size_t d = 1;
    while (n >= 10) { n /= 10; d++; }
    return d;
}

size_t znetstring_encoded_len(size_t n)
{
    if (n > ZNETSTRING_MAX) return 0;
    size_t d = digit_count(n);
    if (n > SIZE_MAX - d - 2) return 0;
    return d + 1 + n + 1;
}

znetstring_err znetstring_encode(const uint8_t *payload, size_t n,
                                 char *out, size_t cap, size_t *out_len)
{
    if ((n > 0 && !payload) || !out) return ZNETSTRING_ERR_ARG;
    size_t total = znetstring_encoded_len(n);
    if (total == 0) return ZNETSTRING_ERR_RANGE;
    if (cap < total) return ZNETSTRING_ERR_CAP;

    size_t d = digit_count(n);
    for (size_t i = 0; i < d; i++) {
        out[d - 1 - i] = (char)('0' + (n % 10));
        n /= 10;
    }
    out[d] = ':';
    if (total - d - 2 > 0)
        memcpy(out + d + 1, payload, total - d - 2);
    out[total - 1] = ',';
    if (out_len) *out_len = total;
    return ZNETSTRING_OK;
}

znetstring_err znetstring_parse(const char *buf, size_t n, znetstring *out)
{
    if (!buf || !out) return ZNETSTRING_ERR_ARG;
    out->payload = NULL;
    out->payload_len = 0;
    out->consumed = 0;

    /* Length field: 1..ZNETSTRING_MAX_DIGITS digits, then ':'. */
    size_t i = 0;
    uint64_t len = 0;
    size_t digits = 0;
    while (i < n && buf[i] >= '0' && buf[i] <= '9') {
        if (digits == ZNETSTRING_MAX_DIGITS) return ZNETSTRING_ERR_FORMAT;
        len = len * 10 + (uint64_t)(buf[i] - '0');
        digits++;
        i++;
    }
    if (digits == 0) return ZNETSTRING_ERR_FORMAT;
    if (digits > 1 && buf[0] == '0') return ZNETSTRING_ERR_FORMAT;
    if (len > ZNETSTRING_MAX) return ZNETSTRING_ERR_RANGE;
    if (i >= n) return ZNETSTRING_ERR_FORMAT; /* truncated: no ':' yet */
    if (buf[i] != ':') return ZNETSTRING_ERR_FORMAT;
    i++;
    if (n - i < len + 1) return ZNETSTRING_ERR_FORMAT; /* truncated payload/comma */
    if (buf[i + len] != ',') return ZNETSTRING_ERR_FORMAT;

    out->payload = (const uint8_t *)buf + i;
    out->payload_len = (size_t)len;
    out->consumed = i + (size_t)len + 1;
    return ZNETSTRING_OK;
}

int znetstring_prefix(const char *buf, size_t n)
{
    if (!buf || n == 0) return 0;
    size_t i = 0;
    uint64_t len = 0;
    size_t digits = 0;
    while (i < n && buf[i] >= '0' && buf[i] <= '9') {
        if (digits == ZNETSTRING_MAX_DIGITS) return 0;
        len = len * 10 + (uint64_t)(buf[i] - '0');
        digits++;
        i++;
    }
    if (digits == 0) return 0;
    if (digits > 1 && buf[0] == '0') return 0;
    if (len > ZNETSTRING_MAX) return 0;
    if (i == n) return 1; /* length field complete, ':' not yet read */
    if (buf[i] != ':') return 0;
    i++;
    /* Any remaining prefix of payload+comma is completable. */
    if (n - i > len + 1) return 0; /* more bytes than the netstring needs */
    if (n - i == len + 1 && buf[n - 1] != ',') return 0;
    return 1;
}

const char *znetstring_err_str(znetstring_err e)
{
    switch (e) {
    case ZNETSTRING_OK: return "ok";
    case ZNETSTRING_ERR_ARG: return "null argument";
    case ZNETSTRING_ERR_RANGE: return "payload length out of range";
    case ZNETSTRING_ERR_CAP: return "output buffer too small";
    case ZNETSTRING_ERR_FORMAT: return "malformed or truncated netstring";
    }
    return "unknown error";
}
