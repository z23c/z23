/* zu256 — fixed-size 256-bit unsigned integer arithmetic. */
#include "zu256/zu256.h"

#include <string.h>

const zu256256 ZU256256_ZERO = { { 0, 0, 0, 0 } };
const zu256256 ZU256256_ONE = { { 1, 0, 0, 0 } };
const zu256256 ZU256256_MAX = {
    { UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX }
};

zu256256 zu256_from_u64(uint64_t v)
{
    return (zu256256){ { v, 0, 0, 0 } };
}

bool zu256_is_zero(zu256256 a)
{
    return (a.l[0] | a.l[1] | a.l[2] | a.l[3]) == 0;
}

int zu256_cmp(zu256256 a, zu256256 b)
{
    for (int i = 3; i >= 0; i--) {
        if (a.l[i] != b.l[i]) return a.l[i] < b.l[i] ? -1 : 1;
    }
    return 0;
}

unsigned zu256_bitlen(zu256256 a)
{
    for (int i = 3; i >= 0; i--) {
        uint64_t x = a.l[i];
        if (x) {
            unsigned n = (unsigned)(i * 64);
            while (x) { n++; x >>= 1; }
            return n;
        }
    }
    return 0;
}

zu256256 zu256_add(zu256256 a, zu256256 b, bool *overflow)
{
    zu256256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t s = a.l[i] + carry;
        uint64_t c1 = s < a.l[i];
        uint64_t t = s + b.l[i];
        uint64_t c2 = t < s;
        r.l[i] = t;
        carry = c1 | c2;
    }
    if (overflow) *overflow = carry != 0;
    return r;
}

zu256256 zu256_sub(zu256256 a, zu256256 b, bool *underflow)
{
    zu256256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t bi = b.l[i] + borrow;
        uint64_t b1 = bi < b.l[i];
        uint64_t d = a.l[i] - bi;
        uint64_t b2 = a.l[i] < bi;
        r.l[i] = d;
        borrow = b1 | b2;
    }
    if (underflow) *underflow = borrow != 0;
    return r;
}

/* Ripple-normalize acc (base 2^32 limbs stored in u64) from slot k:
 * carries propagate upward; slot 16 collects any 512-bit overflow. */
static void ripple(uint64_t acc[17], int k)
{
    while (k <= 16 && (acc[k] >> 32)) {
        uint64_t c = acc[k] >> 32;
        acc[k] &= 0xFFFFFFFFu;
        acc[k + 1] += c;
        k++;
    }
}

zu256256 zu256_mul(zu256256 a, zu256256 b, bool *overflow)
{
    /* schoolbook over 32-bit limbs: every product fits u64, every
       accumulator slot is renormalized after each add — no
       carry-tracking subtleties */
    uint32_t al[8], bl[8];
    for (int i = 0; i < 4; i++) {
        al[2 * i] = (uint32_t)a.l[i];
        al[2 * i + 1] = (uint32_t)(a.l[i] >> 32);
        bl[2 * i] = (uint32_t)b.l[i];
        bl[2 * i + 1] = (uint32_t)(b.l[i] >> 32);
    }
    uint64_t acc[17] = { 0 };
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            uint64_t p = (uint64_t)al[i] * bl[j];
            acc[i + j] += p & 0xFFFFFFFFu;
            ripple(acc, i + j);
            acc[i + j + 1] += p >> 32;
            ripple(acc, i + j + 1);
        }
    }
    if (overflow) {
        uint64_t hi = acc[16];
        for (int k = 8; k < 16; k++) hi |= acc[k];
        *overflow = hi != 0;
    }
    zu256256 r;
    for (int i = 0; i < 4; i++)
        r.l[i] = acc[2 * i] | (acc[2 * i + 1] << 32);
    return r;
}

bool zu256_divmod(zu256256 a, zu256256 b,
                    zu256256 *q, zu256256 *r)
{
    if (zu256_is_zero(b)) return false;
    /* classic binary long division over 256 bits */
    zu256256 quot = ZU256256_ZERO;
    zu256256 rem = ZU256256_ZERO;
    unsigned n = zu256_bitlen(a);
    for (int i = (int)n - 1; i >= 0; i--) {
        rem = zu256_shl(rem, 1);
        if (zu256_bit(a, (unsigned)i)) rem.l[0] |= 1;
        if (zu256_cmp(rem, b) >= 0) {
            rem = zu256_sub(rem, b, NULL);
            quot.l[i / 64] |= (uint64_t)1 << (i % 64);
        }
    }
    if (q) *q = quot;
    if (r) *r = rem;
    return true;
}

zu256256 zu256_shl(zu256256 a, unsigned n)
{
    if (n >= 256) return ZU256256_ZERO;
    if (n == 0) return a;
    zu256256 r = ZU256256_ZERO;
    unsigned limb = n / 64, bits = n % 64;
    for (int i = 3; i >= 0; i--) {
        if (i - (int)limb >= 0) {
            r.l[i] |= a.l[i - (int)limb] << bits;
            if (bits && i - (int)limb - 1 >= 0)
                r.l[i] |= a.l[i - (int)limb - 1] >> (64 - bits);
        }
    }
    return r;
}

zu256256 zu256_shr(zu256256 a, unsigned n)
{
    if (n >= 256) return ZU256256_ZERO;
    if (n == 0) return a;
    zu256256 r = ZU256256_ZERO;
    unsigned limb = n / 64, bits = n % 64;
    for (int i = 0; i < 4; i++) {
        if (i + (int)limb < 4) {
            r.l[i] |= a.l[i + (int)limb] >> bits;
            if (bits && i + (int)limb + 1 < 4)
                r.l[i] |= a.l[i + (int)limb + 1] << (64 - bits);
        }
    }
    return r;
}

bool zu256_bit(zu256256 a, unsigned n)
{
    if (n >= 256) return false;
    return (a.l[n / 64] >> (n % 64)) & 1;
}

void zu256_to_be32(zu256256 a, uint8_t out[32])
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(a.l[3 - i] >> (56 - 8 * j));
}

zu256256 zu256_from_be32(const uint8_t in[32])
{
    zu256256 r = ZU256256_ZERO;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            r.l[3 - i] |= (uint64_t)in[i * 8 + j] << (56 - 8 * j);
    return r;
}

void zu256_to_hex(zu256256 a, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        unsigned nib = 63 - (unsigned)i;
        out[i] = hexd[(a.l[nib / 16] >> ((nib % 16) * 4)) & 0xF];
    }
    out[64] = '\0';
}

bool zu256_from_hex(const char *s, zu256256 *out)
{
    if (!s || !out) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    size_t n = strlen(s);
    if (n == 0 || n > 64) return false;
    zu256256 r = ZU256256_ZERO;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        unsigned v;
        if (c >= '0' && c <= '9') v = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = (unsigned)(c - 'A' + 10);
        else return false;
        size_t nib = n - 1 - i;
        r.l[nib / 16] |= (uint64_t)v << ((nib % 16) * 4);
    }
    *out = r;
    return true;
}

bool zu256_to_dec(zu256256 a, char *out, size_t out_cap)
{
    if (!out || out_cap == 0) return false;
    char tmp[79]; /* 2^256-1 has 78 digits */
    size_t n = 0;
    if (zu256_is_zero(a)) {
        tmp[n++] = '0';
    } else {
        zu256256 ten = zu256_from_u64(10);
        while (!zu256_is_zero(a)) {
            zu256256 q, r;
            zu256_divmod(a, ten, &q, &r);
            tmp[n++] = (char)('0' + r.l[0]);
            a = q;
        }
    }
    if (n + 1 > out_cap) return false;
    for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = '\0';
    return true;
}

bool zu256_from_dec(const char *s, zu256256 *out)
{
    if (!s || !out || !*s) return false;
    zu256256 r = ZU256256_ZERO;
    zu256256 ten = zu256_from_u64(10);
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        bool ovf = false;
        r = zu256_mul(r, ten, &ovf);
        if (ovf) return false;
        r = zu256_add(r, zu256_from_u64((uint64_t)(*p - '0')), &ovf);
        if (ovf) return false;
    }
    *out = r;
    return true;
}
