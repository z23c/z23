/* zpuny — Punycode (RFC 3492) implementation. */
#include "zpuny/zpuny.h"

#include <string.h>

enum {
    BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700,
    INITIAL_BIAS = 72, INITIAL_N = 128, DELIMITER = '-'
};

static uint32_t digit_value(uint32_t d)
{
    /* 0..25 -> a..z, 26..35 -> 0..9 */
    return d < 26 ? d + 'a' : d - 26 + '0';
}

static int decode_digit(uint32_t cp)
{
    if (cp - 'a' < 26) return (int)(cp - 'a');
    if (cp - 'A' < 26) return (int)(cp - 'A');
    if (cp - '0' < 10) return (int)(cp - '0' + 26);
    return -1;
}

static bool is_basic(uint32_t cp) { return cp < 0x80; }

static uint32_t adapt(uint32_t delta, uint32_t numpoints, bool firsttime)
{
    delta = firsttime ? delta / DAMP : delta / 2;
    delta += delta / numpoints;
    uint32_t k = 0;
    while (delta > ((BASE - TMIN) * TMAX) / 2) {
        delta /= BASE - TMIN;
        k += BASE;
    }
    return k + (BASE - TMIN + 1) * delta / (delta + SKEW);
}

zpuny_status zpuny_encode(const uint32_t *cp, size_t cp_len,
                          char *out, size_t out_cap, size_t *out_len)
{
    if (!out_len || (!cp && cp_len > 0)) return ZPUNY_BAD_INPUT;

    size_t o = 0;
    uint32_t n = INITIAL_N, delta = 0, bias = INITIAL_BIAS;

    /* Copy basic code points, count them. */
    size_t b = 0;
    for (size_t i = 0; i < cp_len; i++) {
        if (cp[i] > 0x10FFFF || (cp[i] >= 0xD800 && cp[i] <= 0xDFFF))
            return ZPUNY_BAD_INPUT;
        if (is_basic(cp[i])) {
            if (out && o < out_cap) out[o] = (char)cp[i];
            o++;
            b++;
        }
    }
    size_t h = b;
    /* RFC 3492 6.3: append the delimiter whenever any basic code
       point was copied — even when the input is entirely basic
       ("abc" -> "abc-"). */
    if (b > 0) {
        if (out && o < out_cap) out[o] = DELIMITER;
        o++;
    }

    while (h < cp_len) {
        /* m = smallest code point >= n */
        uint32_t m = 0x10FFFF + 1;
        for (size_t i = 0; i < cp_len; i++)
            if (cp[i] >= n && cp[i] < m) m = cp[i];

        /* overflow guard: delta += (m - n) * (h + 1) */
        uint64_t step = (uint64_t)(m - n) * (h + 1);
        if (step > UINT32_MAX - delta) return ZPUNY_BIG_OUTPUT;
        delta += (uint32_t)step;
        n = m;

        for (size_t i = 0; i < cp_len; i++) {
            if (cp[i] < n) {
                if (delta == UINT32_MAX) return ZPUNY_BIG_OUTPUT;
                delta++;
            } else if (cp[i] == n) {
                uint32_t q = delta;
                for (uint32_t k = BASE;; k += BASE) {
                    uint32_t t = k <= bias ? TMIN
                               : k >= bias + TMAX ? TMAX
                               : k - bias;
                    if (q < t) break;
                    if (out && o < out_cap)
                        out[o] = (char)digit_value(t + (q - t) % (BASE - t));
                    o++;
                    q = (q - t) / (BASE - t);
                }
                if (out && o < out_cap) out[o] = (char)digit_value(q);
                o++;
                bias = adapt(delta, (uint32_t)(h + 1), h == b);
                delta = 0;
                h++;
            }
        }
        delta++;
        n++;
    }

    *out_len = o;
    if (!out || o > out_cap) return ZPUNY_OVERFLOW;
    return ZPUNY_OK;
}

zpuny_status zpuny_decode(const char *in, size_t in_len,
                          uint32_t *cp, size_t cp_cap, size_t *cp_len)
{
    if (!cp_len || (!in && in_len > 0)) return ZPUNY_BAD_INPUT;

    uint32_t n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
    size_t o = 0;

    /* Consume basic code points before the last delimiter. */
    size_t b = 0; /* index just past the last delimiter, or 0 */
    for (size_t j = 0; j < in_len; j++)
        if (in[j] == (char)DELIMITER) b = j + 1;
    size_t basic_end = b > 0 ? b - 1 : 0;
    for (size_t j = 0; j < basic_end; j++) {
        int d = decode_digit((unsigned char)in[j]);
        /* basic segment must be basic code points; decode_digit
           accepts letters/digits, but a raw basic char like '_' or
           uppercase is still basic — RFC: copy anything < 0x80. */
        (void)d;
        if ((unsigned char)in[j] >= 0x80) return ZPUNY_BAD_INPUT;
        if (cp && o < cp_cap) cp[o] = (unsigned char)in[j];
        o++;
    }
    size_t in_pos = b > 0 ? b : 0;

    while (in_pos < in_len) {
        uint32_t oldi = i, w = 1;
        for (uint32_t k = BASE;; k += BASE) {
            if (in_pos >= in_len) return ZPUNY_BAD_INPUT;
            int d = decode_digit((unsigned char)in[in_pos++]);
            if (d < 0) return ZPUNY_BAD_INPUT;
            if ((uint32_t)d > (UINT32_MAX - i) / w) return ZPUNY_BIG_OUTPUT;
            i += (uint32_t)d * w;
            uint32_t t = k <= bias ? TMIN
                       : k >= bias + TMAX ? TMAX
                       : k - bias;
            if ((uint32_t)d < t) break;
            if (w > UINT32_MAX / (BASE - t)) return ZPUNY_BIG_OUTPUT;
            w *= BASE - t;
        }
        /* bias adaption uses the total output length after insert */
        if (o + 1 > UINT32_MAX) return ZPUNY_BIG_OUTPUT;
        bias = adapt(i - oldi, (uint32_t)(o + 1), oldi == 0);

        if (i / (o + 1) > UINT32_MAX - n) return ZPUNY_BIG_OUTPUT;
        n += i / (uint32_t)(o + 1);
        i %= (uint32_t)(o + 1);

        if (n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF))
            return ZPUNY_BAD_INPUT;

        if (cp && o < cp_cap) {
            /* insert at position i */
            if (o + 1 <= cp_cap)
                memmove(&cp[i + 1], &cp[i], (o - i) * sizeof *cp);
            cp[i] = n;
        }
        o++;
        i++;
    }

    *cp_len = o;
    if (!cp || o > cp_cap) return ZPUNY_OVERFLOW;
    return ZPUNY_OK;
}

/* --- UTF-8 front-ends (self-contained, no external UTF-8 lib) --- */

static size_t utf8_decode_all(const char *s, size_t len,
                              uint32_t *cp, size_t cap, bool *ok)
{
    size_t n = 0, p = 0;
    *ok = true;
    while (p < len) {
        unsigned char c = (unsigned char)s[p];
        uint32_t v; size_t adv;
        if (c < 0x80) { v = c; adv = 1; }
        else if ((c >> 5) == 0x6) { v = c & 0x1F; adv = 2; }
        else if ((c >> 4) == 0xE) { v = c & 0x0F; adv = 3; }
        else if ((c >> 3) == 0x1E) { v = c & 0x07; adv = 4; }
        else { *ok = false; return n; }
        if (p + adv > len) { *ok = false; return n; }
        uint32_t min = adv == 1 ? 0 : adv == 2 ? 0x80
                     : adv == 3 ? 0x800 : 0x10000;
        for (size_t j = 1; j < adv; j++) {
            unsigned char cc = (unsigned char)s[p + j];
            if ((cc >> 6) != 0x2) { *ok = false; return n; }
            v = (v << 6) | (cc & 0x3F);
        }
        if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) {
            *ok = false;
            return n;
        }
        if (cp && n < cap) cp[n] = v;
        n++;
        p += adv;
    }
    return n;
}

static size_t utf8_encode_one(uint32_t cp, char *out)
{
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

zpuny_status zpuny_encode_utf8(const char *utf8, size_t utf8_len,
                               char *out, size_t out_cap, size_t *out_len)
{
    /* Two-pass: count code points, then encode using a stack buffer
       for small inputs, else stream in chunks. Simpler: bound code
       points by utf8_len and use a VLA-free fixed stack window. */
    enum { STACK_CP = 256 };
    uint32_t stack_cp[STACK_CP];
    uint32_t *cp = stack_cp;
    bool ok;
    size_t n = utf8_decode_all(utf8, utf8_len, cp, STACK_CP, &ok);
    if (!ok) return ZPUNY_BAD_INPUT;
    if (n > STACK_CP) {
        /* oversized label; process not supported without heap */
        return ZPUNY_OVERFLOW;
    }
    return zpuny_encode(cp, n, out, out_cap, out_len);
}

zpuny_status zpuny_decode_utf8(const char *in, size_t in_len,
                               char *utf8, size_t utf8_cap, size_t *utf8_len)
{
    enum { STACK_CP = 256 };
    uint32_t stack_cp[STACK_CP];
    size_t n = 0;
    zpuny_status st = zpuny_decode(in, in_len, stack_cp, STACK_CP, &n);
    if (st != ZPUNY_OK) return st;

    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        char tmp[4];
        size_t adv = utf8_encode_one(stack_cp[i], tmp);
        if (utf8 && o + adv <= utf8_cap)
            memcpy(utf8 + o, tmp, adv);
        o += adv;
    }
    *utf8_len = o;
    if (!utf8 || o > utf8_cap) return ZPUNY_OVERFLOW;
    return ZPUNY_OK;
}
