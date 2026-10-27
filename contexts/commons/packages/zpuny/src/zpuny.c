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

/* RFC 3492 digit threshold for digit k at the given bias. */
static uint32_t puny_threshold(uint32_t k, uint32_t bias)
{
    return k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
}

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

/* Copy the basic code points to out, count them in *b and append the
   delimiter when any were copied; *o receives the output length. */
static zpuny_status encode_basic_segment(const uint32_t *cp, size_t cp_len,
                                         char *out, size_t out_cap,
                                         size_t *o, size_t *b)
{
    /* Copy basic code points, count them. */
    *o = 0;
    *b = 0;
    for (size_t i = 0; i < cp_len; i++) {
        if (cp[i] > 0x10FFFF || (cp[i] >= 0xD800 && cp[i] <= 0xDFFF))
            return ZPUNY_BAD_INPUT;
        if (is_basic(cp[i])) {
            if (out && *o < out_cap) out[*o] = (char)cp[i];
            (*o)++;
            (*b)++;
        }
    }
    /* RFC 3492 6.3: append the delimiter whenever any basic code
       point was copied — even when the input is entirely basic
       ("abc" -> "abc-"). */
    if (*b > 0) {
        if (out && *o < out_cap) out[*o] = DELIMITER;
        (*o)++;
    }
    return ZPUNY_OK;
}

/* Emit one generalized variable-length integer (RFC 3492 6.3) for the
   pending delta at the given bias. */
static void emit_delta_digits(uint32_t q, uint32_t bias,
                              char *out, size_t out_cap, size_t *o)
{
    for (uint32_t k = BASE;; k += BASE) {
        uint32_t t = puny_threshold(k, bias);
        if (q < t) break;
        if (out && *o < out_cap)
            out[*o] = (char)digit_value(t + (q - t) % (BASE - t));
        (*o)++;
        q = (q - t) / (BASE - t);
    }
    if (out && *o < out_cap) out[*o] = (char)digit_value(q);
    (*o)++;
}

/* Return the smallest input code point >= n, or 0x110000 if none. */
static uint32_t smallest_cp_at_least(const uint32_t *cp, size_t cp_len,
                                     uint32_t n)
{
    uint32_t m = 0x10FFFF + 1;
    for (size_t i = 0; i < cp_len; i++)
        if (cp[i] >= n && cp[i] < m) m = cp[i];
    return m;
}

/* One encoder pass: raise delta for code points below n and emit it as
   digits at n, updating bias and the handled count *h. */
static zpuny_status encode_scan_pass(const uint32_t *cp, size_t cp_len,
                                     uint32_t n, uint32_t *delta,
                                     uint32_t *bias, char *out,
                                     size_t out_cap, size_t *o, size_t *h,
                                     size_t b)
{
    for (size_t i = 0; i < cp_len; i++) {
        if (cp[i] < n) {
            if (*delta == UINT32_MAX) return ZPUNY_BIG_OUTPUT;
            (*delta)++;
        } else if (cp[i] == n) {
            emit_delta_digits(*delta, *bias, out, out_cap, o);
            *bias = adapt(*delta, (uint32_t)(*h + 1), *h == b);
            *delta = 0;
            (*h)++;
        }
    }
    return ZPUNY_OK;
}

zpuny_status zpuny_encode(const uint32_t *cp, size_t cp_len,
                          char *out, size_t out_cap, size_t *out_len)
{
    if (!out_len || (!cp && cp_len > 0)) return ZPUNY_BAD_INPUT;

    size_t o = 0;
    uint32_t n = INITIAL_N, delta = 0, bias = INITIAL_BIAS;

    size_t b = 0;
    zpuny_status st = encode_basic_segment(cp, cp_len, out, out_cap, &o, &b);
    if (st != ZPUNY_OK) return st;
    size_t h = b;

    while (h < cp_len) {
        /* m = smallest code point >= n */
        uint32_t m = smallest_cp_at_least(cp, cp_len, n);

        /* overflow guard: delta += (m - n) * (h + 1) */
        uint64_t step = (uint64_t)(m - n) * (h + 1);
        if (step > UINT32_MAX - delta) return ZPUNY_BIG_OUTPUT;
        delta += (uint32_t)step;
        n = m;

        st = encode_scan_pass(cp, cp_len, n, &delta, &bias,
                              out, out_cap, &o, &h, b);
        if (st != ZPUNY_OK) return st;
        delta++;
        n++;
    }

    *out_len = o;
    if (!out || o > out_cap) return ZPUNY_OVERFLOW;
    return ZPUNY_OK;
}

/* Copy the basic segment before the last delimiter into cp and report
   the input position just past it via *in_pos. */
static zpuny_status decode_basic_segment(const char *in, size_t in_len,
                                         uint32_t *cp, size_t cp_cap,
                                         size_t *o, size_t *in_pos)
{
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
        if (cp && *o < cp_cap) cp[*o] = (unsigned char)in[j];
        (*o)++;
    }
    *in_pos = b > 0 ? b : 0;
    return ZPUNY_OK;
}

/* Read one generalized variable-length integer (RFC 3492 6.3), folding
   its value into *i; returns ZPUNY_OK or an error status. */
static zpuny_status decode_delta_digits(const char *in, size_t in_len,
                                        size_t *in_pos, uint32_t *i,
                                        uint32_t bias)
{
    uint32_t w = 1;
    for (uint32_t k = BASE;; k += BASE) {
        if (*in_pos >= in_len) return ZPUNY_BAD_INPUT;
        int d = decode_digit((unsigned char)in[(*in_pos)++]);
        if (d < 0) return ZPUNY_BAD_INPUT;
        if ((uint32_t)d > (UINT32_MAX - *i) / w) return ZPUNY_BIG_OUTPUT;
        *i += (uint32_t)d * w;
        uint32_t t = puny_threshold(k, bias);
        if ((uint32_t)d < t) break;
        if (w > UINT32_MAX / (BASE - t)) return ZPUNY_BIG_OUTPUT;
        w *= BASE - t;
    }
    return ZPUNY_OK;
}

/* Fold the decoded delta into n and the insert index i, rejecting
   out-of-range or surrogate code points. */
static zpuny_status decode_advance_n(uint32_t *i, uint32_t *n, size_t o)
{
    if (*i / (o + 1) > UINT32_MAX - *n) return ZPUNY_BIG_OUTPUT;
    *n += *i / (uint32_t)(o + 1);
    *i %= (uint32_t)(o + 1);

    if (*n > 0x10FFFF || (*n >= 0xD800 && *n <= 0xDFFF))
        return ZPUNY_BAD_INPUT;
    return ZPUNY_OK;
}

/* Insert code point n at index i, shifting the tail right by one. */
static void decode_insert_cp(uint32_t *cp, size_t cp_cap, size_t o,
                             uint32_t i, uint32_t n)
{
    if (cp && o < cp_cap) {
        /* insert at position i */
        if (o + 1 <= cp_cap)
            memmove(&cp[i + 1], &cp[i], (o - i) * sizeof *cp);
        cp[i] = n;
    }
}

zpuny_status zpuny_decode(const char *in, size_t in_len,
                          uint32_t *cp, size_t cp_cap, size_t *cp_len)
{
    if (!cp_len || (!in && in_len > 0)) return ZPUNY_BAD_INPUT;

    uint32_t n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
    size_t o = 0;

    size_t in_pos = 0;
    zpuny_status st = decode_basic_segment(in, in_len, cp, cp_cap,
                                           &o, &in_pos);
    if (st != ZPUNY_OK) return st;

    while (in_pos < in_len) {
        uint32_t oldi = i;
        st = decode_delta_digits(in, in_len, &in_pos, &i, bias);
        if (st != ZPUNY_OK) return st;
        /* bias adaption uses the total output length after insert */
        if (o + 1 > UINT32_MAX) return ZPUNY_BIG_OUTPUT;
        bias = adapt(i - oldi, (uint32_t)(o + 1), oldi == 0);

        st = decode_advance_n(&i, &n, o);
        if (st != ZPUNY_OK) return st;

        decode_insert_cp(cp, cp_cap, o, i, n);
        o++;
        i++;
    }

    *cp_len = o;
    if (!cp || o > cp_cap) return ZPUNY_OVERFLOW;
    return ZPUNY_OK;
}

/* --- UTF-8 front-ends (self-contained, no external UTF-8 lib) --- */

/* Length of the UTF-8 sequence led by c (0 if c is not a lead byte);
   *v receives the code point bits carried by the lead byte. */
static size_t utf8_lead_length(unsigned char c, uint32_t *v)
{
    if (c < 0x80) { *v = c; return 1; }
    if ((c >> 5) == 0x6) { *v = c & 0x1F; return 2; }
    if ((c >> 4) == 0xE) { *v = c & 0x0F; return 3; }
    if ((c >> 3) == 0x1E) { *v = c & 0x07; return 4; }
    return 0;
}

/* Smallest code point a UTF-8 sequence of adv bytes may encode. */
static uint32_t utf8_min_code_point(size_t adv)
{
    return adv == 1 ? 0 : adv == 2 ? 0x80
         : adv == 3 ? 0x800 : 0x10000;
}

/* Decode the UTF-8 sequence starting at s[p]; store its code point in
   *v and return its byte length, or 0 if it is invalid or truncated. */
static size_t utf8_decode_one(const char *s, size_t len, size_t p, uint32_t *v)
{
    size_t adv = utf8_lead_length((unsigned char)s[p], v);
    if (adv == 0) return 0;
    if (p + adv > len) return 0;
    uint32_t min = utf8_min_code_point(adv);
    for (size_t j = 1; j < adv; j++) {
        unsigned char cc = (unsigned char)s[p + j];
        if ((cc >> 6) != 0x2) return 0;
        *v = (*v << 6) | (cc & 0x3F);
    }
    if (*v < min || *v > 0x10FFFF || (*v >= 0xD800 && *v <= 0xDFFF))
        return 0;
    return adv;
}

static size_t utf8_decode_all(const char *s, size_t len,
                              uint32_t *cp, size_t cap, bool *ok)
{
    size_t n = 0, p = 0;
    *ok = true;
    while (p < len) {
        uint32_t v;
        size_t adv = utf8_decode_one(s, len, p, &v);
        if (adv == 0) { *ok = false; return n; }
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
    if (!out_len || (!utf8 && utf8_len > 0)) return ZPUNY_BAD_INPUT;

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
