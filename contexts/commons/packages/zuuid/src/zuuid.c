#include "zuuid/zuuid.h"

#include <string.h>

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

zuuid zuuid_nil(void)
{
    zuuid u;
    memset(u.b, 0, sizeof u.b);
    return u;
}

bool zuuid_is_nil(const zuuid *u)
{
    if (!u) return false;
    uint8_t acc = 0;
    for (size_t i = 0; i < ZUUID_BYTES; i++) acc |= u->b[i];
    return acc == 0;
}

/* Decode 2*n hex chars starting at s into the next n bytes of out. */
static zuuid_err decode_hex(const char *s, size_t n, uint8_t *out)
{
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(s[2 * i]);
        int lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return ZUUID_ERR_BAD_CHAR;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return ZUUID_OK;
}

zuuid_err zuuid_parse(const char *str, zuuid *out)
{
    if (!str || !out) return ZUUID_ERR_NULL;
    if (strlen(str) != 36) return ZUUID_ERR_FORMAT;
    if (str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-')
        return ZUUID_ERR_FORMAT;
    zuuid_err e;
    if ((e = decode_hex(str,      4, out->b))      != ZUUID_OK) return e;
    if ((e = decode_hex(str + 9,  2, out->b + 4))  != ZUUID_OK) return e;
    if ((e = decode_hex(str + 14, 2, out->b + 6))  != ZUUID_OK) return e;
    if ((e = decode_hex(str + 19, 2, out->b + 8))  != ZUUID_OK) return e;
    if ((e = decode_hex(str + 24, 6, out->b + 10)) != ZUUID_OK) return e;
    return ZUUID_OK;
}

zuuid_err zuuid_parse_lenient(const char *str, zuuid *out)
{
    if (!str || !out) return ZUUID_ERR_NULL;

    /* Strip "urn:uuid:" and {braces} in either nesting order. */
    char inner[48]; /* longest wrapped form: "{" + "urn:uuid:" + 36 + "}" */
    for (int pass = 0; pass < 2; pass++) {
        if (strncmp(str, "urn:uuid:", 9) == 0) {
            str += 9;
            continue;
        }
        size_t len = strlen(str);
        if (len >= 2 && str[0] == '{' && str[len - 1] == '}') {
            if (len - 2 >= sizeof inner) return ZUUID_ERR_FORMAT;
            memcpy(inner, str + 1, len - 2);
            inner[len - 2] = '\0';
            str = inner;
        }
    }

    size_t len = strlen(str);

    if (len == 36)
        return zuuid_parse(str, out);

    if (len == 32) { /* bare hex */
        for (size_t i = 0; i < 32; i++)
            if (hexval(str[i]) < 0) return ZUUID_ERR_BAD_CHAR;
        return decode_hex(str, ZUUID_BYTES, out->b);
    }
    return ZUUID_ERR_FORMAT;
}

static zuuid_err format_with(const zuuid *u, char *out, bool upper)
{
    if (!u || !out) return ZUUID_ERR_NULL;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    static const size_t hyphen_after[5] = {4, 6, 8, 10, 16}; /* byte counts */
    size_t o = 0, i = 0;
    for (size_t group = 0; group < 5; group++) {
        size_t end = hyphen_after[group];
        for (; i < end; i++) {
            out[o++] = digits[u->b[i] >> 4];
            out[o++] = digits[u->b[i] & 0x0f];
        }
        if (group < 4) out[o++] = '-';
    }
    out[o] = '\0';
    return ZUUID_OK;
}

zuuid_err zuuid_format(const zuuid *u, char *out)
{
    return format_with(u, out, false);
}

zuuid_err zuuid_format_upper(const zuuid *u, char *out)
{
    return format_with(u, out, true);
}

int zuuid_compare(const zuuid *a, const zuuid *b)
{
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    return memcmp(a->b, b->b, ZUUID_BYTES);
}

bool zuuid_equal(const zuuid *a, const zuuid *b)
{
    return zuuid_compare(a, b) == 0;
}

int zuuid_version(const zuuid *u)
{
    if (!u) return 0;
    return (u->b[6] >> 4) & 0x0f;
}

int zuuid_variant(const zuuid *u)
{
    if (!u) return -1;
    uint8_t c = u->b[8];
    if ((c & 0x80) == 0x00) return 0;
    if ((c & 0xc0) == 0x80) return 1;
    if ((c & 0xe0) == 0xc0) return 2;
    return 3;
}

zuuid_err zuuid_generate_v4(zuuid *out,
                            int (*rng)(void *ctx, uint8_t *buf, size_t n),
                            void *ctx)
{
    if (!out || !rng) return ZUUID_ERR_NULL;
    if (rng(ctx, out->b, ZUUID_BYTES) != 0) return ZUUID_ERR_RNG;
    out->b[6] = (uint8_t)((out->b[6] & 0x0f) | 0x40); /* version 4 */
    out->b[8] = (uint8_t)((out->b[8] & 0x3f) | 0x80); /* RFC variant */
    return ZUUID_OK;
}

const char *zuuid_err_str(zuuid_err e)
{
    switch (e) {
    case ZUUID_OK:           return "ok";
    case ZUUID_ERR_NULL:     return "null argument";
    case ZUUID_ERR_FORMAT:   return "not a UUID shape";
    case ZUUID_ERR_BAD_CHAR: return "non-hex digit";
    case ZUUID_ERR_RNG:      return "random source failed";
    }
    return "unknown error";
}
