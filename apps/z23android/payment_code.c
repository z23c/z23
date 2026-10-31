/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "payment_code.h"

#include "zutf8/zutf8.h"

#include <stdio.h>
#include <string.h>

#define URI_SCHEME "zclassic:"
#define NET_BIT(net) (1u << (net))
#define BECH32_CHARS "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define BASE58_CHARS "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#define TRANSPARENT_LEN 35u
#define ZAT_PER_ZCL 100000000u
#define MAX_ZCL 21000000u
#define MAX_DECIMALS 8u
#define RECEIVE_AMOUNT_MAX 24u

enum decode_status { DEC_OK, DEC_BAD, DEC_LONG };

struct address_form {
    const char *prefix;
    size_t length;
    const char *charset;
    enum zapp_pay_kind kind;
    unsigned networks;
};

/* The checksum is deliberately absent: validateaddress on the node is the check. */
static const struct address_form ADDRESS_FORMS[] = {
    { "zs1", 78, BECH32_CHARS, ZAPP_PAY_PRIVATE, NET_BIT(ZAPP_PAY_MAINNET) },
    { "ztestsapling1", 88, BECH32_CHARS, ZAPP_PAY_PRIVATE, NET_BIT(ZAPP_PAY_TESTNET) },
    { "zregtestsapling1", 91, BECH32_CHARS, ZAPP_PAY_PRIVATE, NET_BIT(ZAPP_PAY_REGTEST) },
    { "t1", TRANSPARENT_LEN, BASE58_CHARS, ZAPP_PAY_PUBLIC, NET_BIT(ZAPP_PAY_MAINNET) },
    { "t3", TRANSPARENT_LEN, BASE58_CHARS, ZAPP_PAY_PUBLIC, NET_BIT(ZAPP_PAY_MAINNET) },
    { "tm", TRANSPARENT_LEN, BASE58_CHARS, ZAPP_PAY_PUBLIC,
      NET_BIT(ZAPP_PAY_TESTNET) | NET_BIT(ZAPP_PAY_REGTEST) },
    { "t2", TRANSPARENT_LEN, BASE58_CHARS, ZAPP_PAY_PUBLIC,
      NET_BIT(ZAPP_PAY_TESTNET) | NET_BIT(ZAPP_PAY_REGTEST) },
};

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_alnum(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static char ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* Case-insensitive prefix test; prefix is lower case. */
static bool starts_ci(const char *s, size_t n, const char *prefix)
{
    size_t p = strlen(prefix);
    if (n < p)
        return false;
    for (size_t i = 0; i < p; i++) {
        if (ascii_lower(s[i]) != prefix[i])
            return false;
    }
    return true;
}

/* Case-sensitive prefix test, so an upper-case address prefix is not an address. */
static bool has_prefix(const char *s, size_t n, const char *prefix)
{
    size_t p = strlen(prefix);
    return n >= p && memcmp(s, prefix, p) == 0;
}

static bool name_is(const char *name, size_t nlen, const char *want)
{
    size_t w = strlen(want);
    return nlen == w && memcmp(name, want, w) == 0;
}

static bool fits(int written, size_t cap)
{
    return written >= 0 && (size_t)written < cap;
}

static const struct address_form *find_form(const char *s, size_t n)
{
    for (size_t i = 0; i < sizeof ADDRESS_FORMS / sizeof ADDRESS_FORMS[0]; i++) {
        if (has_prefix(s, n, ADDRESS_FORMS[i].prefix))
            return &ADDRESS_FORMS[i];
    }
    return NULL;
}

static bool in_charset(const char *s, size_t from, size_t n, const char *charset)
{
    for (size_t i = from; i < n; i++) {
        if (s[i] == '\0' || strchr(charset, s[i]) == NULL)
            return false;
    }
    return true;
}

/* Length, prefix and charset of an address, then whether its network is the one asked for. */
static enum zapp_pay_refusal address_check(const char *s, size_t n, enum zapp_pay_network network,
                                           enum zapp_pay_kind *kind)
{
    const struct address_form *f = find_form(s, n);
    if (f == NULL || n != f->length || !in_charset(s, strlen(f->prefix), n, f->charset))
        return ZAPP_PAY_REFUSE_BAD_ADDRESS;
    *kind = f->kind;
    return (f->networks & NET_BIT(network)) != 0 ? ZAPP_PAY_OK : ZAPP_PAY_REFUSE_WRONG_NETWORK;
}

static void store_address(struct zapp_payment *out, const char *s, size_t n, enum zapp_pay_kind kind)
{
    memcpy(out->address, s, n);
    out->address[n] = '\0';
    out->kind = kind;
}

static enum zapp_pay_refusal bare_address(const char *s, size_t n, enum zapp_pay_network network,
                                          struct zapp_payment *out)
{
    enum zapp_pay_kind kind = ZAPP_PAY_PRIVATE;
    enum zapp_pay_refusal r = address_check(s, n, network, &kind);
    if (r == ZAPP_PAY_OK)
        store_address(out, s, n, kind);
    return r;
}

/* Percent-decodes in[0..n) into out, which holds cap bytes. DEC_LONG when the decoded length
 * exceeds cap; the bytes past cap are counted but not written. */
static enum decode_status percent_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t produced = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t byte = (uint8_t)in[i];
        if (in[i] == '%') {
            if (i + 2 >= n)
                return DEC_BAD;
            int hi = hex_value(in[i + 1]);
            int lo = hex_value(in[i + 2]);
            if (hi < 0 || lo < 0)
                return DEC_BAD;
            byte = (uint8_t)(hi * 16 + lo);
            i += 2;
        }
        if (produced < cap)
            out[produced] = byte;
        produced++;
    }
    if (produced > cap)
        return DEC_LONG;
    *out_len = produced;
    return DEC_OK;
}

static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    return -1;
}

/* Unpadded or canonically padded base64url. Trailing bits that the decoder does not use must be zero. */
static enum decode_status base64url_decode(const uint8_t *in, size_t n, uint8_t *out, size_t cap,
                                           size_t *out_len)
{
    size_t data = n;
    while (data > 0 && n - data < 2 && in[data - 1] == '=')
        data--;
    if (data != n && n % 4 != 0)
        return DEC_BAD;
    if (data % 4 == 1)
        return DEC_BAD;
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t produced = 0;
    for (size_t i = 0; i < data; i++) {
        int v = b64_value(in[i]);
        if (v < 0)
            return DEC_BAD;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (produced < cap)
                out[produced] = (uint8_t)(acc >> bits);
            produced++;
            acc &= (1u << bits) - 1u;
        }
    }
    if (acc != 0)
        return DEC_BAD;
    if (produced > cap)
        return DEC_LONG;
    *out_len = produced;
    return DEC_OK;
}

/* Whether a bidirectional mark or control starts at s[i]: U+200E and U+200F (marks), U+061C
 * (Arabic letter mark), U+202A..U+202E (embeddings and overrides) or U+2066..U+2069 (isolates).
 * They reorder or change the direction of the text shown beside an address. */
static bool bidi_control_at(const uint8_t *s, size_t n, size_t i)
{
    if (i + 1 < n && s[i] == 0xD8u && s[i + 1] == 0x9Cu)
        return true;
    if (i + 2 >= n || s[i] != 0xE2u)
        return false;
    if (s[i + 1] == 0x80u)
        return (s[i + 2] >= 0xAAu && s[i + 2] <= 0xAEu) || s[i + 2] == 0x8Eu || s[i + 2] == 0x8Fu;
    return s[i + 1] == 0x81u && s[i + 2] >= 0xA6u && s[i + 2] <= 0xA9u;
}

/* Valid UTF-8 with no C0 control, no DEL, no C1 control (U+0080..U+009F) and no bidi control. */
static bool text_is_clean(const uint8_t *s, size_t n)
{
    if (!zutf8_validate_n((const char *)s, n))
        return false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < 0x20u || s[i] == 0x7Fu)
            return false;
        if (s[i] == 0xC2u && i + 1 < n && s[i + 1] >= 0x80u && s[i + 1] <= 0x9Fu)
            return false;
        if (bidi_control_at(s, n, i))
            return false;
    }
    return true;
}

/* Shape of a decimal amount: digits, then at most 8 decimals after a point with digits after it. */
static enum zapp_pay_refusal amount_shape(const char *s, size_t n, size_t *whole, size_t *frac)
{
    *whole = 0;
    while (*whole < n && is_digit(s[*whole]))
        (*whole)++;
    *frac = 0;
    if (*whole < n && s[*whole] == '.') {
        size_t first = *whole + 1;
        while (first + *frac < n && is_digit(s[first + *frac]))
            (*frac)++;
        if (*frac == 0 || first + *frac != n)
            return ZAPP_PAY_REFUSE_AMOUNT_FORMAT;
    } else if (*whole != n) {
        return ZAPP_PAY_REFUSE_AMOUNT_FORMAT;
    }
    if (*whole == 0)
        return ZAPP_PAY_REFUSE_AMOUNT_FORMAT;
    if (*frac > MAX_DECIMALS)
        return ZAPP_PAY_REFUSE_AMOUNT_PRECISION;
    return ZAPP_PAY_OK;
}

/* The amount in zatoshi, with every step checked against the 21000000 ZCL ceiling before it is made. */
static enum zapp_pay_refusal amount_value(const char *s, size_t n, uint64_t *zat)
{
    size_t whole = 0;
    size_t frac = 0;
    enum zapp_pay_refusal r = amount_shape(s, n, &whole, &frac);
    if (r != ZAPP_PAY_OK)
        return r;
    uint64_t units = 0;
    for (size_t i = 0; i < whole; i++) {
        units = units * 10u + (uint64_t)(s[i] - '0');
        if (units > MAX_ZCL)
            return ZAPP_PAY_REFUSE_AMOUNT_RANGE;
    }
    uint64_t fraction = 0;
    for (size_t i = 0; i < MAX_DECIMALS; i++) {
        fraction *= 10u;
        if (i < frac)
            fraction += (uint64_t)(s[whole + 1 + i] - '0');
    }
    uint64_t total = units * ZAT_PER_ZCL + fraction;
    if (total > ZAPP_PAY_MAX_ZAT)
        return ZAPP_PAY_REFUSE_AMOUNT_RANGE;
    *zat = total;
    return ZAPP_PAY_OK;
}

static enum zapp_pay_refusal apply_amount(const char *s, size_t n, struct zapp_payment *out)
{
    uint64_t zat = 0;
    enum zapp_pay_refusal r = amount_value(s, n, &zat);
    if (r == ZAPP_PAY_OK) {
        out->has_amount = true;
        out->amount_zat = zat;
    }
    return r;
}

static enum zapp_pay_refusal apply_memo(const char *s, size_t n, struct zapp_payment *out)
{
    uint8_t raw[ZAPP_PAY_INPUT_MAX];
    size_t raw_len = 0;
    if (out->kind == ZAPP_PAY_PUBLIC)
        return ZAPP_PAY_REFUSE_MEMO_ON_PUBLIC;
    /* raw holds the whole input, so percent_decode cannot report DEC_LONG here. */
    if (percent_decode(s, n, raw, sizeof raw, &raw_len) != DEC_OK)
        return ZAPP_PAY_REFUSE_PERCENT;
    enum decode_status st = base64url_decode(raw, raw_len, out->memo, ZAPP_PAY_MEMO_MAX, &out->memo_len);
    if (st == DEC_LONG)
        return ZAPP_PAY_REFUSE_MEMO_TOO_LONG;
    return st == DEC_OK ? ZAPP_PAY_OK : ZAPP_PAY_REFUSE_MEMO_ENCODING;
}

static enum zapp_pay_refusal apply_text(const char *s, size_t n, bool label, struct zapp_payment *out)
{
    uint8_t buf[ZAPP_PAY_TEXT_MAX];
    size_t len = 0;
    enum decode_status st = percent_decode(s, n, buf, sizeof buf, &len);
    if (st == DEC_BAD)
        return ZAPP_PAY_REFUSE_PERCENT;
    if (st == DEC_LONG)
        return label ? ZAPP_PAY_REFUSE_LABEL_TOO_LONG : ZAPP_PAY_REFUSE_MESSAGE_TOO_LONG;
    if (memchr(buf, '\0', len) != NULL)
        return ZAPP_PAY_REFUSE_EMBEDDED_NUL;
    if (!text_is_clean(buf, len))
        return label ? ZAPP_PAY_REFUSE_LABEL_INVALID : ZAPP_PAY_REFUSE_MESSAGE_INVALID;
    char *dst = label ? out->label : out->message;
    memcpy(dst, buf, len);
    dst[len] = '\0';
    return ZAPP_PAY_OK;
}

static bool valid_name(const char *name, size_t nlen)
{
    if (nlen == 0)
        return false;
    for (size_t i = 0; i < nlen; i++) {
        char c = name[i];
        if (!is_alnum(c) && c != '-' && c != '_' && c != '.')
            return false;
    }
    return true;
}

/* Whether a parameter earlier in the query has the same name, whatever its value. before is the
 * index of the current parameter; each earlier one ends in '&' at before - 1 or before. */
static bool name_seen_before(const char *q, size_t before, const char *name, size_t nlen)
{
    size_t s = 0;
    while (s < before) {
        size_t e = s;
        while (e < before && q[e] != '&')
            e++;
        size_t other = 0;
        while (s + other < e && q[s + other] != '=')
            other++;
        if (other == nlen && memcmp(q + s, name, nlen) == 0)
            return true;
        s = e + 1;
    }
    return false;
}

/* A dot marks an indexed name such as amount.1, and address is a second payment. A req- name is
 * required and unknown here, so it is refused in any letter case. A repeated name is refused. */
static enum zapp_pay_refusal check_name(const char *q, size_t start, const char *name, size_t nlen)
{
    if (memchr(name, '.', nlen) != NULL || name_is(name, nlen, "address"))
        return ZAPP_PAY_REFUSE_MULTIPLE;
    if (starts_ci(name, nlen, "req-"))
        return ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED;
    if (name_seen_before(q, start, name, nlen))
        return ZAPP_PAY_REFUSE_DUPLICATE;
    return ZAPP_PAY_OK;
}

static enum zapp_pay_refusal apply_param(const char *name, size_t nlen, const char *value, size_t vlen,
                                         struct zapp_payment *out)
{
    if (name_is(name, nlen, "amount"))
        return apply_amount(value, vlen, out);
    if (name_is(name, nlen, "memo"))
        return apply_memo(value, vlen, out);
    if (name_is(name, nlen, "label"))
        return apply_text(value, vlen, true, out);
    if (name_is(name, nlen, "message"))
        return apply_text(value, vlen, false, out);
    return ZAPP_PAY_OK; /* unknown and not required: ignored, as ZIP 321 says */
}

static enum zapp_pay_refusal parse_param(const char *q, size_t start, size_t end, struct zapp_payment *out)
{
    const char *seg = q + start;
    size_t seg_len = end - start;
    size_t nlen = 0;
    while (nlen < seg_len && seg[nlen] != '=')
        nlen++;
    if (nlen == seg_len || !valid_name(seg, nlen))
        return ZAPP_PAY_REFUSE_MALFORMED;
    enum zapp_pay_refusal r = check_name(q, start, seg, nlen);
    if (r != ZAPP_PAY_OK)
        return r;
    return apply_param(seg, nlen, seg + nlen + 1, seg_len - nlen - 1, out);
}

static enum zapp_pay_refusal parse_query(const char *q, size_t n, struct zapp_payment *out)
{
    size_t start = 0;
    for (;;) {
        size_t end = start;
        while (end < n && q[end] != '&')
            end++;
        enum zapp_pay_refusal r = parse_param(q, start, end, out);
        if (r != ZAPP_PAY_OK || end == n)
            return r;
        start = end + 1;
    }
}

static enum zapp_pay_refusal parse_uri(const char *body, size_t n, enum zapp_pay_network network,
                                       struct zapp_payment *out)
{
    const char *query = memchr(body, '?', n);
    size_t alen = query != NULL ? (size_t)(query - body) : n;
    enum zapp_pay_refusal r = bare_address(body, alen, network, out);
    if (r != ZAPP_PAY_OK || query == NULL)
        return r;
    return parse_query(query + 1, n - alen - 1, out);
}

static enum zapp_pay_refusal parse_request(const char *text, size_t len, enum zapp_pay_network network,
                                           struct zapp_payment *out)
{
    if (len > ZAPP_PAY_INPUT_MAX)
        return ZAPP_PAY_REFUSE_INPUT_TOO_LONG;
    if (len == 0)
        return ZAPP_PAY_REFUSE_MALFORMED;
    if (memchr(text, '\0', len) != NULL)
        return ZAPP_PAY_REFUSE_EMBEDDED_NUL;
    if (starts_ci(text, len, URI_SCHEME))
        return parse_uri(text + strlen(URI_SCHEME), len - strlen(URI_SCHEME), network, out);
    return bare_address(text, len, network, out);
}

enum zapp_pay_refusal zapp_payment_parse(const char *text, size_t len, enum zapp_pay_network network,
                                         struct zapp_payment *out)
{
    if (out == NULL)
        return ZAPP_PAY_REFUSE_MALFORMED;
    memset(out, 0, sizeof *out);
    if (text == NULL || (unsigned)network > (unsigned)ZAPP_PAY_REGTEST)
        return ZAPP_PAY_REFUSE_MALFORMED;
    enum zapp_pay_refusal r = parse_request(text, len, network, out);
    if (r != ZAPP_PAY_OK)
        memset(out, 0, sizeof *out);
    return r;
}

/* An address for the Receive screen: letters and digits only, so nothing can change the URI. */
static bool plain_address(const char *a)
{
    size_t n = 0;
    while (n < ZAPP_PAY_ADDRESS_MAX && a[n] != '\0' && is_alnum(a[n]))
        n++;
    return n > 0 && n < ZAPP_PAY_ADDRESS_MAX && a[n] == '\0';
}

/* Formats zat as ZCL in decimal: no point for a whole amount, otherwise trailing zeros dropped. */
static bool format_zcl(uint64_t zat, char out[RECEIVE_AMOUNT_MAX])
{
    unsigned long long whole = zat / ZAT_PER_ZCL;
    unsigned long long frac = zat % ZAT_PER_ZCL;
    if (frac == 0)
        return fits(snprintf(out, RECEIVE_AMOUNT_MAX, "%llu", whole), RECEIVE_AMOUNT_MAX);
    char digits[9];
    (void)snprintf(digits, sizeof digits, "%08llu", frac);
    size_t keep = 8;
    while (digits[keep - 1] == '0')
        keep--;
    return fits(snprintf(out, RECEIVE_AMOUNT_MAX, "%llu.%.*s", whole, (int)keep, digits), RECEIVE_AMOUNT_MAX);
}

bool zapp_payment_receive_code(const char *address, bool has_amount, uint64_t amount_zat, char *out, size_t cap)
{
    if (address == NULL || out == NULL || cap == 0 || !plain_address(address))
        return false;
    if (!has_amount)
        return fits(snprintf(out, cap, "%s", address), cap);
    if (amount_zat > ZAPP_PAY_MAX_ZAT)
        return false;
    char amount[RECEIVE_AMOUNT_MAX];
    if (!format_zcl(amount_zat, amount))
        return false;
    return fits(snprintf(out, cap, URI_SCHEME "%s?amount=%s", address, amount), cap);
}
