/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact integer-zatoshi amounts. Decimal text is parsed exactly;
 * JSON reals are converted once with llround after a MAX_MONEY bound check
 * (exact because 21e14 < 2^53). Doubles never reach display or decisions. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "zw.h"

/* Digits at s[*i..]: accumulate into *v (bounded by max) and return the count,
 * or -1 on overflow or when more than maxn digits (maxn < 0: unlimited). */
static int take_digits(const char *s, size_t len, size_t *i, int64_t *v, int64_t max, int maxn)
{
    int n = 0;
    while (*i < len && s[*i] >= '0' && s[*i] <= '9') {
        if (maxn >= 0 && n >= maxn) return -1;
        *v = *v * 10 + (s[*i] - '0');
        if (*v > max) return -1;
        n++;
        (*i)++;
    }
    return n;
}

bool zw_amount_parse(const char *s, size_t len, int64_t *zat)
{
    if (!s || !len || len > 32) return false;
    int64_t whole = 0, frac = 0;
    size_t i = 0;
    int nw = take_digits(s, len, &i, &whole, ZW_MAX_MONEY / 100000000, -1), nf = 0;
    if (nw < 0) return false;
    if (i < len && s[i] == '.') {
        i++;
        nf = take_digits(s, len, &i, &frac, INT64_MAX, 8);
        if (nf < 0) return false;
    }
    if (i != len || (nw == 0 && nf == 0)) return false;
    for (int k = nf; k < 8; k++) frac *= 10;
    int64_t v = whole * 100000000 + frac;
    if (v > ZW_MAX_MONEY) return false;
    *zat = v;
    return true;
}

bool zw_amount_from_json(const struct json_value *v, int64_t *zat)
{
    if (!v || !zat) return false;
    if (v->type == JSON_INT) {
        if (v->val.i < 0 || v->val.i > ZW_MAX_MONEY) return false;
        *zat = v->val.i;
        return true;
    }
    if (v->type == JSON_REAL) {
        double d = v->val.d;
        if (!(d >= 0.0) || d > 21000000.0) return false;
        *zat = (int64_t)llround(d * 1e8);
        return *zat <= ZW_MAX_MONEY;
    }
    if (v->type == JSON_STR && v->val.s) return zw_amount_parse(v->val.s, strlen(v->val.s), zat);
    return false;
}

size_t zw_amount_format(int64_t zat, char *buf, size_t cap, bool unit)
{
    if (!cap) return 0;
    bool neg = zat < 0;
    uint64_t u = neg ? (uint64_t)(-(zat + 1)) + 1u : (uint64_t)zat;
    uint64_t whole = u / 100000000u, frac = u % 100000000u;
    char digits[24];
    int nd = snprintf(digits, sizeof(digits), "%llu", (unsigned long long)whole);
    char out[64];
    size_t o = 0;
    if (neg) out[o++] = '-';
    for (int i = 0; i < nd; i++) {
        if (i && (nd - i) % 3 == 0) out[o++] = ',';
        out[o++] = digits[i];
    }
    if (frac) {
        char f[16];
        snprintf(f, sizeof(f), "%08llu", (unsigned long long)frac);
        size_t fl = 8;
        while (fl > 0 && f[fl - 1] == '0') fl--;
        out[o++] = '.';
        memcpy(out + o, f, fl);
        o += fl;
    }
    out[o] = 0;
    int n = snprintf(buf, cap, "%s%s", out, unit ? " ZCL" : "");
    return n < 0 ? 0 : (size_t)n;
}
