/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the pure plan of one send, as beta13's sendtab.cpp and
 * settings.cpp decide it: address shape plus checksum (bech32 for Sapling,
 * base58check with double SHA-256 for transparent and Sprout), the amount
 * validator, the four-way privacy category (an unrecognised recipient counts
 * as public), doSendTxValidations in its order with the integer-zatoshi
 * funds guard, the live badge and totals line, and the exact z_sendmany
 * parameters. No node I/O, no floating point, no logging. */
#include <stdio.h>
#include <string.h>

#include "zw_send.h"

/* ---- SHA-256 (FIPS 180-4), for the base58check checksum only ---- */

static const uint32_t k_sha_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha_block(uint32_t h[8], const uint8_t b[64])
{
    uint32_t w[64], v[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 | (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, h, sizeof(v));
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = v[7] + (ror(v[4], 6) ^ ror(v[4], 11) ^ ror(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) +
                      k_sha_k[i] + w[i];
        uint32_t t2 = (ror(v[0], 2) ^ ror(v[0], 13) ^ ror(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof(v[0]));
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) h[i] += v[i];
}

void zw_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t h[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    uint8_t blk[64];
    size_t i = 0;
    for (; len - i >= 64; i += 64) sha_block(h, data + i);
    size_t rest = len - i;
    memset(blk, 0, sizeof(blk));
    memcpy(blk, data + i, rest);
    blk[rest] = 0x80;
    if (rest >= 56) {
        sha_block(h, blk);
        memset(blk, 0, sizeof(blk));
    }
    uint64_t bits = (uint64_t)len * 8u;
    for (int k = 0; k < 8; k++) blk[63 - k] = (uint8_t)(bits >> (8 * k));
    sha_block(h, blk);
    for (int k = 0; k < 8; k++)
        for (int j = 0; j < 4; j++) out[4 * k + j] = (uint8_t)(h[k] >> (24 - 8 * j));
}

/* ---- address shape and checksums ---- */

static bool is_alnum_ascii(char c)
{
    static const char alnum[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return c && strchr(alnum, c) != NULL;
}

static bool alnum_from(const char *s, size_t from, size_t n)
{
    for (size_t i = from; i < n; i++)
        if (!is_alnum_ascii(s[i])) return false;
    return true;
}

static bool starts_ci(const char *s, const char *prefix)
{
    for (; *prefix; s++, prefix++) {
        char c = *s >= 'A' && *s <= 'Z' ? (char)(*s - 'A' + 'a') : *s;
        if (c != *prefix) return false;
    }
    return true;
}

static uint32_t bech32_step(uint32_t chk, uint32_t v)
{
    static const uint32_t gen[5] = { 0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u };
    uint32_t b = chk >> 25;
    chk = ((chk & 0x1ffffffu) << 5) ^ v;
    for (int i = 0; i < 5; i++)
        if ((b >> i) & 1u) chk ^= gen[i];
    return chk;
}

/* One case throughout; returns the separator (the last "1"), 0 when unusable. */
static size_t bech32_sep(const char *a, size_t n)
{
    bool lower = false, upper = false;
    size_t sep = 0;
    for (size_t i = 0; i < n; i++) {
        lower = lower || (a[i] >= 'a' && a[i] <= 'z');
        upper = upper || (a[i] >= 'A' && a[i] <= 'Z');
        if (a[i] == '1') sep = i;
    }
    return lower && upper ? 0 : sep;
}

static bool bech32_ok(const char *a, size_t n)
{
    static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    size_t sep = bech32_sep(a, n);
    if (sep < 1 || sep + 7 > n) return false;
    uint32_t chk = 1;
    for (size_t i = 0; i < sep; i++) chk = bech32_step(chk, (uint32_t)((a[i] | 0x20) >> 5));
    chk = bech32_step(chk, 0);
    for (size_t i = 0; i < sep; i++) chk = bech32_step(chk, (uint32_t)((a[i] | 0x20) & 31));
    for (size_t i = sep + 1; i < n; i++) {
        const char *p = strchr(charset, a[i] | 0x20);
        if (!p || !*p) return false;
        chk = bech32_step(chk, (uint32_t)(p - charset));
    }
    return chk == 1;
}

static int b58_digit(char c)
{
    static const char alpha[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const char *p = strchr(alpha, c);
    return p && *p ? (int)(p - alpha) : -1;
}

/* Big-endian base58 decode into out (at most cap bytes); returns the length. */
static size_t b58_decode(const char *s, size_t n, uint8_t *out, size_t cap)
{
    uint8_t buf[96] = { 0 };
    size_t zeros = 0, used = 0;
    while (zeros < n && s[zeros] == '1') zeros++;
    for (size_t i = zeros; i < n; i++) {
        int d = b58_digit(s[i]);
        if (d < 0) return 0;
        uint32_t carry = (uint32_t)d;
        for (size_t k = 0; k < used; k++) {
            carry += (uint32_t)buf[sizeof(buf) - 1 - k] * 58u;
            buf[sizeof(buf) - 1 - k] = (uint8_t)carry;
            carry >>= 8;
        }
        while (carry) {
            if (used == sizeof(buf)) return 0;
            buf[sizeof(buf) - 1 - used++] = (uint8_t)carry;
            carry >>= 8;
        }
    }
    if (zeros + used > cap) return 0;
    memset(out, 0, zeros);
    memcpy(out + zeros, buf + sizeof(buf) - used, used);
    return zeros + used;
}

static bool base58check_ok(const char *a, size_t n)
{
    uint8_t raw[96], h1[32], h2[32];
    size_t len = b58_decode(a, n, raw, sizeof(raw));
    if (len < 5) return false;
    zw_sha256(raw, len - 4, h1);
    zw_sha256(h1, sizeof(h1), h2);
    return !memcmp(h2, raw + len - 4, 4);
}

/* ^z[a-z0-9]{77}$ or ^z(regtest|test)sapling[a-z0-9]{76}, case-insensitive. */
static bool sapling_shape(const char *a, size_t n)
{
    if (n == 78 && alnum_from(a, 1, n)) return true;
    if (starts_ci(a, "ztestsapling")) return n == 88 && alnum_from(a, 12, n);
    return starts_ci(a, "zregtestsapling") && n == 91 && alnum_from(a, 15, n);
}

/* ^t[a-z0-9]{34}$ or ^z[a-z0-9]{94}$ (case-insensitive) plus base58check. */
static enum zw_addr_type base58_type(const char *a, size_t n)
{
    bool t = (a[0] == 't' || a[0] == 'T') && n == 35, z = (a[0] == 'z' || a[0] == 'Z') && n == 95;
    if (!(t || z) || !alnum_from(a, 1, n) || !base58check_ok(a, n)) return ZW_AT_INVALID;
    return t ? ZW_AT_TRANSPARENT : ZW_AT_SPROUT;
}

enum zw_addr_type zw_addr_check(const char *a)
{
    if (!a) return ZW_AT_INVALID;
    size_t n = strnlen(a, ZW_ADDR_MAX);
    if (n >= ZW_ADDR_MAX) return ZW_AT_INVALID;
    if (starts_ci(a, "zs") || starts_ci(a, "ztestsapling") || starts_ci(a, "zregtestsapling"))
        return sapling_shape(a, n) && bech32_ok(a, n) ? ZW_AT_SAPLING : ZW_AT_INVALID;
    return base58_type(a, n);
}

/* Settings::isZAddress / isTAddress: valid, then a case-sensitive prefix. */
bool zw_addr_is_z(const char *a) { return zw_addr_check(a) != ZW_AT_INVALID && a[0] == 'z'; }
bool zw_addr_is_t(const char *a) { return zw_addr_check(a) != ZW_AT_INVALID && a[0] == 't'; }

bool zw_addr_lookalike(const char *a, const char *known)
{
    size_t n = strlen(a), k = strlen(known);
    if (n < 2 * ZW_LOOKALIKE_EDGE || k < 2 * ZW_LOOKALIKE_EDGE || !strcmp(a, known)) return false;
    return !memcmp(a, known, ZW_LOOKALIKE_EDGE) &&
           !memcmp(a + n - ZW_LOOKALIKE_EDGE, known + k - ZW_LOOKALIKE_EDGE, ZW_LOOKALIKE_EDGE);
}

/* ---- amounts ---- */

/* The digits at t[*i..]: the value of the first nine (no overflow on long
 * input), and in *count how many there were. */
static int64_t digits(const char *t, size_t n, size_t *i, size_t *count)
{
    int64_t v = 0;
    for (*count = 0; *i < n && t[*i] >= '0' && t[*i] <= '9'; (*i)++, (*count)++)
        if (*count < 9) v = v * 10 + (t[*i] - '0');
    return v;
}

enum zw_amt zw_amount_text(const char *s, int64_t *zat)
{
    const char *t;
    size_t n = zw_trimmed(s, &t), i = 0, nw = 0, nf = 0;
    *zat = 0;
    if (!n) return ZW_AMT_EMPTY;
    int64_t whole = digits(t, n, &i, &nw);
    if (i < n && t[i] == '.') i++;
    int64_t frac = digits(t, n, &i, &nf);
    if (i != n || nw > 8 || nf > 8) return ZW_AMT_BAD;
    for (size_t k = nf; k < 8; k++) frac *= 10;
    int64_t v = whole * 100000000 + frac;
    if (v > ZW_MAX_MONEY) return ZW_AMT_BAD;
    *zat = v;
    return v ? ZW_AMT_OK : ZW_AMT_ZERO;
}

void zw_decimal(int64_t zat, char *buf, size_t cap)
{
    bool neg = zat < 0;
    uint64_t u = neg ? (uint64_t)(-(zat + 1)) + 1u : (uint64_t)zat;
    char frac[16];
    snprintf(frac, sizeof(frac), "%08llu", (unsigned long long)(u % 100000000u));
    size_t fl = strlen(frac);
    while (fl && frac[fl - 1] == '0') frac[--fl] = 0;
    snprintf(buf, cap, "%s%llu%s%s", neg && u ? "-" : "", (unsigned long long)(u / 100000000u), fl ? "." : "",
             frac);
}

void zw_copy(char *dst, size_t cap, const char *src)
{
    if (!cap) return;
    size_t n = strnlen(src, cap - 1);
    memcpy(dst, src, n);
    dst[n] = 0;
}

/* ---- QString::trimmed (QChar::isSpace, in UTF-8) ---- */

static bool space3(unsigned cp)
{
    static const unsigned list[] = { 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 };
    if (cp >= 0x2000 && cp <= 0x200a) return true;
    for (size_t i = 0; i < sizeof(list) / sizeof(list[0]); i++)
        if (cp == list[i]) return true;
    return false;
}

static size_t space_len(const unsigned char *s, size_t n)
{
    if (!n) return 0;
    if (s[0] == ' ' || (s[0] >= 0x09 && s[0] <= 0x0d)) return 1;
    if (n >= 2 && s[0] == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0)) return 2;
    if (n < 3 || (s[0] & 0xf0) != 0xe0) return 0;
    unsigned cp = (unsigned)(s[0] & 0x0f) << 12 | (unsigned)(s[1] & 0x3f) << 6 | (unsigned)(s[2] & 0x3f);
    return space3(cp) ? 3 : 0;
}

static size_t space_len_back(const unsigned char *s, size_t n)
{
    for (size_t k = 1; k <= 3 && k <= n; k++)
        if (space_len(s + n - k, k) == k) return k;
    return 0;
}

size_t zw_trimmed(const char *s, const char **start)
{
    const unsigned char *u = (const unsigned char *)s;
    size_t n = strlen(s), k;
    while ((k = space_len(u, n)) > 0) { u += k; n -= k; }
    while ((k = space_len_back(u, n)) > 0) n -= k;
    *start = (const char *)u;
    return n;
}

static void trimmed_copy(const char *s, char *out, size_t cap)
{
    const char *t;
    size_t n = zw_trimmed(s, &t);
    snprintf(out, cap, "%.*s", (int)(n < cap ? n : cap - 1), t);
}

/* ---- category, validation, totals, badge ---- */

enum zw_send_cat zw_send_category(const struct zw_send_plan *p)
{
    bool any_public = false;
    char a[ZW_ADDR_MAX];
    for (size_t i = 0; i < p->n && !any_public; i++) {
        trimmed_copy(p->to[i].addr, a, sizeof(a));
        any_public = !zw_addr_is_z(a);
    }
    bool from_z = zw_addr_is_z(p->from);
    if (any_public) return from_z ? ZW_CAT_DESHIELD : ZW_CAT_PUBLIC;
    return from_z ? ZW_CAT_PRIVATE : ZW_CAT_SHIELDING;
}

void zw_money(int64_t zat, bool testnet, char *buf, size_t cap)
{
    char d[40];
    zw_decimal(zat, d, sizeof(d));
    snprintf(buf, cap, "%s %s", d, testnet ? "ZCT" : "ZCL");
}

bool zw_send_amounts(const struct zw_send_plan *p, int64_t *sum)
{
    *sum = 0;
    for (size_t i = 0; i < p->n; i++) {
        int64_t z;
        if (zw_amount_text(p->to[i].amount, &z) == ZW_AMT_BAD) return false;
        *sum += z;
    }
    return true;
}

static bool recipient_error(const struct zw_rcpt *r, char *err, size_t cap)
{
    char a[ZW_ADDR_MAX];
    trimmed_copy(r->addr, a, sizeof(a));
    if (zw_addr_check(a) == ZW_AT_INVALID) {
        if (!a[0]) snprintf(err, cap, "Recipient Address is Invalid");
        else snprintf(err, cap, "Recipient Address %.100s%s is Invalid", a, strlen(a) > 100 ? "..." : "");
        return true;
    }
    int64_t z;
    enum zw_amt k = zw_amount_text(r->amount, &z);
    if (k == ZW_AMT_BAD) {
        trimmed_copy(r->amount, a, sizeof(a));
        snprintf(err, cap, "Amount '%s' is invalid!", a);
        return true;
    }
    if (k != ZW_AMT_OK) {
        snprintf(err, cap, "Enter an amount greater than 0 for each recipient.");
        return true;
    }
    return false;
}

/* The three-way guard of doSendTxValidations, in integer zatoshi. */
static bool funds_error(int64_t total, const struct zw_funds *f, bool testnet, char *err, size_t cap)
{
    char a[48], b[48];
    if (f->confirmed >= total) return false;
    if (f->displayed >= total) {
        zw_money(total > f->confirmed ? total - f->confirmed : 0, testnet, a, sizeof(a));
        snprintf(err, cap, "%s of these funds is still confirming (about a few minutes). "
                 "You can shield or send it as soon as it confirms.", a);
        return true;
    }
    zw_money(total, testnet, a, sizeof(a));
    zw_money(f->displayed, testnet, b, sizeof(b));
    snprintf(err, cap, "Not enough funds. You're trying to send %s (including the fee), but this address only "
             "holds %s.", a, b);
    return true;
}

bool zw_send_validate(const struct zw_send_plan *p, const struct zw_funds *f, bool syncing, bool testnet,
                      char *err, size_t cap)
{
    if (zw_addr_check(p->from) == ZW_AT_INVALID) {
        snprintf(err, cap, "From Address is Invalid");
        return false;
    }
    for (size_t i = 0; i < p->n; i++)
        if (recipient_error(&p->to[i], err, cap)) return false;
    int64_t sum = 0;
    if (!syncing && f && f->known && zw_send_amounts(p, &sum) && funds_error(sum + p->fee, f, testnet, err, cap))
        return false;
    err[0] = 0;
    return true;
}

void zw_send_totals(const struct zw_send_plan *p, bool testnet, char *buf, size_t cap)
{
    int64_t sum = 0;
    bool any = false;
    for (size_t i = 0; i < p->n; i++) {
        int64_t z;
        if (zw_amount_text(p->to[i].amount, &z) == ZW_AMT_OK) { sum += z; any = true; }
    }
    buf[0] = 0;
    if (!any) return;
    char a[48], f[48], t[48];
    zw_money(sum, testnet, a, sizeof(a));
    zw_money(p->fee, testnet, f, sizeof(f));
    zw_money(sum + p->fee, testnet, t, sizeof(t));
    snprintf(buf, cap, "You'll send %s + %s fee = %s", a, f, t);
}

const char *zw_send_badge(const struct zw_send_plan *p, enum gui_style *style)
{
    struct zw_send_plan echo = { .n = 0 };
    snprintf(echo.from, sizeof(echo.from), "%s", p->from);
    for (size_t i = 0; i < p->n; i++) {
        trimmed_copy(p->to[i].addr, echo.to[echo.n].addr, sizeof(echo.to[0].addr));
        if (echo.to[echo.n].addr[0]) echo.n++;
    }
    *style = GS_MUTED;
    if (!echo.n || !p->from[0]) return "Set who you are paying to see if this send is private";
    switch (zw_send_category(&echo)) {
    case ZW_CAT_PRIVATE:
        *style = GS_BADGE_PRIVATE;
        return "\xE2\x97\x8F Private \xE2\x80\x94 only you and the recipient can see this";
    case ZW_CAT_SHIELDING:
        *style = GS_BADGE_PRIVATE;
        return "\xE2\x97\x8F Shielding \xE2\x80\x94 this becomes private";
    case ZW_CAT_PUBLIC:
        *style = GS_BADGE_PUBLIC;
        return "\xE2\x97\x8F Public \xE2\x80\x94 the amount and recipient are visible to everyone";
    default:
        *style = GS_BADGE_DANGER;
        return "\xE2\x97\x8F De-shield \xE2\x80\x94 this leaves your private balance and becomes public forever";
    }
}

const char *zw_send_confirm_title(enum zw_send_cat c)
{
    switch (c) {
    case ZW_CAT_PRIVATE: return "Confirm private transaction";
    case ZW_CAT_SHIELDING: return "Confirm shielding transaction";
    case ZW_CAT_PUBLIC: return "Confirm public transaction";
    default: return "Confirm DE-SHIELD (public) transaction";
    }
}

/* ---- z_sendmany parameters ---- */

bool zw_memo_hex(const struct zw_rcpt *r, char *out, size_t cap)
{
    static const char hx[] = "0123456789abcdef";
    const char *m, *a;
    size_t n = zw_trimmed(r->memo, &m);
    zw_trimmed(r->addr, &a);
    out[0] = 0;
    if (a[0] != 'z' || !n) return true; /* fillTxJsonParams: z recipients only */
    if (n > ZW_MEMO_MAX || 2 * n + 1 > cap) return false;
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[(unsigned char)m[i] >> 4];
        out[2 * i + 1] = hx[(unsigned char)m[i] & 15];
    }
    out[2 * n] = 0;
    return true;
}

/* Only [A-Za-z0-9._:-] reaches the JSON text: addresses and keys need no escape. */
static bool plain_token(const char *s)
{
    for (; *s; s++)
        if (!is_alnum_ascii(*s) && !strchr("._:-", *s)) return false;
    return true;
}

struct jbuf { char *p; size_t cap, len; bool ok; };

static void jput(struct jbuf *b, const char *s)
{
    size_t n = strlen(s);
    if (!b->ok || b->len + n + 1 > b->cap) { b->ok = false; return; }
    memcpy(b->p + b->len, s, n + 1);
    b->len += n;
}

static void put_recipient(struct jbuf *b, const struct zw_rcpt *r)
{
    char a[ZW_ADDR_MAX], amt[40], memo[2 * ZW_MEMO_MAX + 1];
    int64_t zat = 0;
    trimmed_copy(r->addr, a, sizeof(a));
    zw_amount_text(r->amount, &zat);
    zw_decimal(zat, amt, sizeof(amt));
    if (!plain_token(a) || !zw_memo_hex(r, memo, sizeof(memo))) { b->ok = false; return; }
    jput(b, "{\"address\":\"");
    jput(b, a);
    jput(b, "\",\"amount\":\"");
    jput(b, amt);
    jput(b, "\"");
    if (memo[0]) {
        jput(b, ",\"memo\":\"");
        jput(b, memo);
        jput(b, "\"");
    }
    jput(b, "}");
}

bool zw_send_params(const struct zw_send_plan *p, const char *key, char *out, size_t cap)
{
    struct jbuf b = { out, cap, 0, cap > 0 };
    if (!plain_token(p->from) || (key && !plain_token(key)) || !p->n) return false;
    jput(&b, "[\"");
    jput(&b, p->from);
    jput(&b, "\",[");
    for (size_t i = 0; i < p->n; i++) {
        if (i) jput(&b, ",");
        put_recipient(&b, &p->to[i]);
    }
    jput(&b, "]");
    if (key) {
        char fee[40];
        zw_decimal(p->fee, fee, sizeof(fee));
        jput(&b, ",1,");
        jput(&b, fee);
        jput(&b, ",\"");
        jput(&b, key);
        jput(&b, "\"");
    }
    jput(&b, "]");
    return b.ok;
}
