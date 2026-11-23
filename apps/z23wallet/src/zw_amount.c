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

/* Settings::getDecimalString + getZCLDisplayFormat: 8 decimals with trailing
 * zeros (and then a trailing ".") stripped, no grouping, "-0" is "0". */
size_t zw_amount_format_net(int64_t zat, char *buf, size_t cap, bool testnet)
{
    if (!cap) return 0;
    bool neg = zat < 0;
    uint64_t u = neg ? (uint64_t)(-(zat + 1)) + 1u : (uint64_t)zat;
    uint64_t whole = u / 100000000u, frac = u % 100000000u;
    char f[16] = "";
    if (frac) {
        snprintf(f, sizeof(f), ".%08llu", (unsigned long long)frac);
        size_t fl = strlen(f);
        while (fl > 1 && f[fl - 1] == '0') f[--fl] = 0;
    }
    int n = snprintf(buf, cap, "%s%llu%s%s", neg && u ? "-" : "", (unsigned long long)whole, f,
                     testnet ? " ZCT" : " ZCL");
    return n < 0 ? 0 : (size_t)n;
}

size_t zw_amount_format(int64_t zat, char *buf, size_t cap, bool unit)
{
    size_t n = zw_amount_format_net(zat, buf, cap, false);
    if (!unit && n >= 4 && n < cap) {
        buf[n - 4] = 0;
        n -= 4;
    }
    return n;
}

void zw_fmt_int(int64_t v, char *buf, size_t cap)
{
    char d[24], out[40];
    uint64_t u = v < 0 ? (uint64_t)(-(v + 1)) + 1u : (uint64_t)v;
    int n = snprintf(d, sizeof(d), "%llu", (unsigned long long)u);
    size_t o = 0;
    if (v < 0) out[o++] = '-';
    for (int i = 0; i < n; i++) {
        if (i && (n - i) % 3 == 0) out[o++] = ',';
        out[o++] = d[i];
    }
    out[o] = 0;
    snprintf(buf, cap, "%s", out);
}

/* SyncState::formatAge. */
void zw_fmt_age(int64_t s, char *buf, size_t cap)
{
    if (s < 0) s = 0;
    if (s < 90) snprintf(buf, cap, "%lld s", (long long)s);
    else if (s < 90 * 60) snprintf(buf, cap, "%lld min", (long long)((s + 30) / 60));
    else if (s < 36 * 3600) snprintf(buf, cap, "%lld h", (long long)((s + 1800) / 3600));
    else if (s >= 400 * 86400) {
        int64_t tenths = (s * 10 + 365 * 86400 / 2) / (365 * 86400);
        snprintf(buf, cap, "%lld.%lld years", (long long)(tenths / 10), (long long)(tenths % 10));
    } else snprintf(buf, cap, "%lld days", (long long)((s + 43200) / 86400));
}
