#include "zescape/zescape.h"

#include <string.h>

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t zescape_escaped_max(size_t n)
{
    return n * 4;
}

static size_t escaped_len_of(const uint8_t *in, size_t len)
{
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = in[i];
        switch (c) {
        case '\\': case '"': case '\n': case '\r': case '\t':
            n += 2;
            break;
        default:
            n += (c >= 0x20 && c <= 0x7e) ? 1 : 4;
            break;
        }
    }
    return n;
}

zescape_err zescape_escape(const void *in, size_t len,
                           char *out, size_t cap, size_t *out_len)
{
    if (!out || !out_len) return ZESCAPE_ERR_NULL;
    if (!in && len > 0) return ZESCAPE_ERR_NULL;

    size_t need = escaped_len_of(in, len);
    if (cap < need) {
        *out_len = need;
        return ZESCAPE_ERR_SMALL;
    }

    static const char digits[] = "0123456789abcdef";
    const uint8_t *p = in;
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = p[i];
        switch (c) {
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c >= 0x20 && c <= 0x7e) {
                out[o++] = (char)c;
            } else {
                out[o++] = '\\';
                out[o++] = 'x';
                out[o++] = digits[c >> 4];
                out[o++] = digits[c & 0x0f];
            }
            break;
        }
    }
    *out_len = o;
    return ZESCAPE_OK;
}

zescape_err zescape_unescape(const char *in, size_t len,
                             void *out, size_t cap,
                             size_t *out_len, size_t *err_pos)
{
    if (!in || !out || !out_len) return ZESCAPE_ERR_NULL;
    if (err_pos) *err_pos = 0;

    uint8_t *dst = out;
    size_t o = 0, i = 0;
    while (i < len) {
        char c = in[i];
        if (c != '\\') {
            if (o >= cap) return ZESCAPE_ERR_SMALL;
            dst[o++] = (uint8_t)c;
            i++;
            continue;
        }
        size_t esc = i;
        i++;
        if (i >= len) {
            if (err_pos) *err_pos = esc;
            return ZESCAPE_ERR_TRUNCATED;
        }
        uint8_t v;
        switch (in[i]) {
        case '\\': v = '\\'; break;
        case '"':  v = '"';  break;
        case '\'': v = '\''; break;
        case 'n':  v = '\n'; break;
        case 'r':  v = '\r'; break;
        case 't':  v = '\t'; break;
        case '0':  v = '\0'; break;
        case 'a':  v = '\a'; break;
        case 'b':  v = '\b'; break;
        case 'f':  v = '\f'; break;
        case 'v':  v = '\v'; break;
        case 'x': {
            if (i + 2 >= len) {
                if (err_pos) *err_pos = esc;
                return ZESCAPE_ERR_TRUNCATED;
            }
            int hi = hexval(in[i + 1]);
            int lo = hexval(in[i + 2]);
            if (hi < 0 || lo < 0) {
                if (err_pos) *err_pos = (hi < 0) ? i + 1 : i + 2;
                return ZESCAPE_ERR_BAD_HEX;
            }
            v = (uint8_t)((hi << 4) | lo);
            i += 2;
            break;
        }
        default:
            if (err_pos) *err_pos = esc;
            return ZESCAPE_ERR_BAD_ESCAPE;
        }
        if (o >= cap) return ZESCAPE_ERR_SMALL;
        dst[o++] = v;
        i++;
    }
    *out_len = o;
    return ZESCAPE_OK;
}

const char *zescape_err_str(zescape_err e)
{
    switch (e) {
    case ZESCAPE_OK:            return "ok";
    case ZESCAPE_ERR_NULL:      return "null argument";
    case ZESCAPE_ERR_SMALL:     return "output buffer too small";
    case ZESCAPE_ERR_BAD_ESCAPE: return "unknown escape letter";
    case ZESCAPE_ERR_TRUNCATED: return "truncated escape sequence";
    case ZESCAPE_ERR_BAD_HEX:   return "bad hex in \\x escape";
    }
    return "unknown error";
}
