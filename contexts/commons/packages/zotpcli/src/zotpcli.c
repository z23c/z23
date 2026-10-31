/* zotpcli — implementation. See include/zotpcli/zotpcli.h for the
 * contract and the honesty note on the store MAC. */
#include "zotpcli/zotpcli.h"

#include <stdlib.h>
#include <string.h>

#include "zb32/zb32.h"
#include "zbase64/zbase64.h"
#include "zhkdf/zhkdf.h"
#include "zjson/zjson.h"
#include "zjsonp/zjsonp.h"
#include "zotp/zotp.h"
#include "zpct/zpct.h"
#include "zscrypt/zscrypt.h"
#include "zsha256/zsha256.h"
#include "zstr/zstr.h"
#include "zurl/zurl.h"
#include "zutf8/zutf8.h"
#include "zvarint/zvarint.h"
#include "zfmt/zfmt.h"

#define STORE_MAGIC "ZOTPCLI1"
#define STORE_MAGIC_LEN 8u
#define MAX_RECORD_LEN 65536u

/* base64 of ZOTPCLI_MAX_SECRET bytes: 4*ceil(128/3) = 172, plus NUL */
#define SECRET_B64_CAP 176u
/* base32 of ZOTPCLI_MAX_SECRET bytes: ceil(128/5)*8 = 208 chars */
#define SECRET_B32_MAX 208u
#define SECRET_B32_CAP (SECRET_B32_MAX + 8u) /* padding + NUL */

const char *zotpcli_err_str(zotpcli_err e)
{
    switch (e) {
    case ZOTPCLI_OK:         return "ok";
    case ZOTPCLI_ERR_ARG:    return "bad argument";
    case ZOTPCLI_ERR_NOMEM:  return "out of memory";
    case ZOTPCLI_ERR_LABEL:  return "invalid or duplicate label";
    case ZOTPCLI_ERR_FULL:   return "store full";
    case ZOTPCLI_ERR_NOTFOUND: return "no such entry";
    case ZOTPCLI_ERR_SECRET: return "invalid base32 secret";
    case ZOTPCLI_ERR_URI:    return "malformed otpauth URI";
    case ZOTPCLI_ERR_FORMAT: return "malformed store data";
    case ZOTPCLI_ERR_MAC:    return "integrity check failed";
    case ZOTPCLI_ERR_KDF:    return "key derivation failed";
    case ZOTPCLI_ERR_TRUNC:  return "output buffer too small";
    }
    return "unknown error";
}

void zotpcli_entry_init(zotpcli_entry *e)
{
    if (!e) return;
    memset(e, 0, sizeof *e);
    e->kind = ZOTPCLI_TOTP;
    e->digits = ZOTPCLI_DEFAULT_DIGITS;
    e->period = ZOTPCLI_DEFAULT_PERIOD;
}

/* --- store container ---------------------------------------------- */

zotpcli_err zotpcli_store_init(zotpcli_store *s)
{
    if (!s) return ZOTPCLI_ERR_ARG;
    memset(s, 0, sizeof *s);
    s->entries = calloc(ZOTPCLI_MAX_ENTRIES, sizeof *s->entries);
    if (!s->entries) return ZOTPCLI_ERR_NOMEM;
    return ZOTPCLI_OK;
}

void zotpcli_store_free(zotpcli_store *s)
{
    if (!s) return;
    if (s->entries) {
        /* zeroize secret material before releasing the heap block */
        memset(s->entries, 0, ZOTPCLI_MAX_ENTRIES * sizeof *s->entries);
        free(s->entries);
    }
    memset(s, 0, sizeof *s);
}

size_t zotpcli_store_count(const zotpcli_store *s)
{
    return s ? s->count : 0;
}

const zotpcli_entry *zotpcli_store_get(const zotpcli_store *s, size_t i)
{
    if (!s || i >= s->count) return NULL;
    return &s->entries[i];
}

const zotpcli_entry *zotpcli_store_find(const zotpcli_store *s,
                                        const char *label)
{
    if (!s || !label) return NULL;
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->entries[i].label, label) == 0)
            return &s->entries[i];
    return NULL;
}

zotpcli_entry *zotpcli_store_find_mut(zotpcli_store *s, const char *label)
{
    if (!s || !label) return NULL;
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->entries[i].label, label) == 0)
            return &s->entries[i];
    return NULL;
}

static zotpcli_err entry_validate(const zotpcli_entry *e)
{
    if (!e) return ZOTPCLI_ERR_ARG;
    size_t label_len = strlen(e->label);
    if (label_len == 0 || label_len > ZOTPCLI_MAX_LABEL)
        return ZOTPCLI_ERR_LABEL;
    if (!zutf8_validate_n(e->label, label_len))
        return ZOTPCLI_ERR_LABEL;
    if (strlen(e->issuer) > ZOTPCLI_MAX_ISSUER ||
        !zutf8_validate_n(e->issuer, strlen(e->issuer)))
        return ZOTPCLI_ERR_LABEL;
    if (e->secret_len == 0 || e->secret_len > ZOTPCLI_MAX_SECRET)
        return ZOTPCLI_ERR_SECRET;
    if (e->digits < ZOTP_MIN_DIGITS || e->digits > ZOTPCLI_MAX_DIGITS)
        return ZOTPCLI_ERR_ARG;
    if (e->period == 0 || e->period > ZOTPCLI_MAX_PERIOD)
        return ZOTPCLI_ERR_ARG;
    if (e->kind != ZOTPCLI_TOTP && e->kind != ZOTPCLI_HOTP)
        return ZOTPCLI_ERR_ARG;
    return ZOTPCLI_OK;
}

zotpcli_err zotpcli_store_add(zotpcli_store *s, const zotpcli_entry *e)
{
    if (!s || !s->entries || !e) return ZOTPCLI_ERR_ARG;
    zotpcli_err ve = entry_validate(e);
    if (ve != ZOTPCLI_OK) return ve;
    if (zotpcli_store_find(s, e->label)) return ZOTPCLI_ERR_LABEL;
    if (s->count >= ZOTPCLI_MAX_ENTRIES) return ZOTPCLI_ERR_FULL;
    s->entries[s->count++] = *e;
    return ZOTPCLI_OK;
}

bool zotpcli_store_remove(zotpcli_store *s, const char *label)
{
    if (!s || !s->entries || !label) return false;
    for (size_t i = 0; i < s->count; i++) {
        if (strcmp(s->entries[i].label, label) == 0) {
            if (i + 1 < s->count)
                memmove(&s->entries[i], &s->entries[i + 1],
                        (s->count - i - 1) * sizeof *s->entries);
            s->count--;
            memset(&s->entries[s->count], 0, sizeof *s->entries);
            return true;
        }
    }
    return false;
}

/* --- code generation ----------------------------------------------- */

int zotpcli_hotp_code(const zotpcli_entry *e, uint64_t counter,
                      char *out)
{
    if (!e || !out) return 0;
    if (e->secret_len == 0 || e->secret_len > ZOTPCLI_MAX_SECRET)
        return 0;
    if (e->digits < ZOTP_MIN_DIGITS || e->digits > ZOTPCLI_MAX_DIGITS)
        return 0;
    return zotp_hotp(e->secret, e->secret_len, counter, e->digits, out);
}

uint64_t zotpcli_totp_counter(const zotpcli_entry *e, int64_t now)
{
    if (!e || now < 0 || e->period == 0) return 0;
    return (uint64_t)now / e->period;
}

int zotpcli_totp_code(const zotpcli_entry *e, int64_t now, char *out)
{
    if (!e || !out || now < 0) return 0;
    if (e->period == 0 || e->period > ZOTPCLI_MAX_PERIOD) return 0;
    return zotpcli_hotp_code(e, zotpcli_totp_counter(e, now), out);
}

int zotpcli_code(const zotpcli_entry *e, int64_t now, char *out)
{
    if (!e) return 0;
    if (e->kind == ZOTPCLI_HOTP)
        return zotpcli_hotp_code(e, e->counter, out);
    return zotpcli_totp_code(e, now, out);
}

/* --- base32 secrets -------------------------------------------------- */

/* Normalize a base32 secret in buf: strip existing '=' padding, check
 * the length remainder, re-pad to a multiple of 8 and NUL-terminate.
 * Returns the new length, or SIZE_MAX on an impossible length. */
static size_t b32_normalize_pad(char *buf, size_t n)
{
    /* Strip any existing padding, then re-pad to a multiple of 8. */
    while (n > 0 && buf[n - 1] == '=') n--;
    if (n > SECRET_B32_MAX) return SIZE_MAX;
    size_t rem = n % 8u;
    /* Unpadded base32 of whole bytes has rem in {0,2,4,5,7}. */
    if (rem == 1 || rem == 3 || rem == 6) return SIZE_MAX;
    size_t pad = rem ? 8u - rem : 0u;
    for (size_t i = 0; i < pad; i++) buf[n + i] = '=';
    n += pad;
    buf[n] = '\0';
    return n;
}

zotpcli_err zotpcli_b32_decode_secret(const char *text, uint8_t *out,
                                      size_t cap, size_t *out_len)
{
    if (!text || !out || !out_len) return ZOTPCLI_ERR_ARG;
    size_t n = strlen(text);
    if (n == 0 || n >= SECRET_B32_CAP) return ZOTPCLI_ERR_SECRET;

    char buf[SECRET_B32_CAP];
    memcpy(buf, text, n + 1);
    zstr_to_upper(buf); /* otpauth secrets are often lowercase */

    n = b32_normalize_pad(buf, n);
    if (n == SIZE_MAX) return ZOTPCLI_ERR_SECRET;

    size_t need = zb32_decoded_len(buf, n);
    if (need == SIZE_MAX || need == 0 || need > ZOTPCLI_MAX_SECRET)
        return ZOTPCLI_ERR_SECRET;
    if (need > cap) return ZOTPCLI_ERR_TRUNC;
    if (zb32_decode(out, cap, buf, n) == SIZE_MAX)
        return ZOTPCLI_ERR_SECRET;
    *out_len = need;
    return ZOTPCLI_OK;
}

zotpcli_err zotpcli_b32_encode_secret(const uint8_t *secret, size_t len,
                                      char *out, size_t cap)
{
    if (!secret || !out || len == 0 || len > ZOTPCLI_MAX_SECRET)
        return ZOTPCLI_ERR_ARG;
    size_t need = zb32_encode(out, cap, secret, len);
    if (need == SIZE_MAX || need >= cap) return ZOTPCLI_ERR_TRUNC;
    while (need > 0 && out[need - 1] == '=') /* unpadded otpauth form */
        out[--need] = '\0';
    return ZOTPCLI_OK;
}

/* --- otpauth:// URIs ------------------------------------------------- */

/* Parse a decimal u64, no signs, no whitespace; false on junk/overflow. */
static bool parse_u64(const char *s, size_t n, uint64_t *out)
{
    if (n == 0) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        unsigned d = (unsigned)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10u) return false;
        v = v * 10u + d;
    }
    *out = v;
    return true;
}

static bool copy_cstr(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap) return false;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return true;
}

/* The URI host names the kind: "totp" or "hotp". */
static zotpcli_err otpauth_parse_kind(const char *uri, const zurl *u,
                                      zotpcli_entry *e)
{
    char host[8];
    /* zurl_copy copies the span bytes WITHOUT a NUL (see zurl.h); host is
     * compared as a C string below, so terminate it explicitly. Reading it
     * unterminated is an uninitialized read that only happened to work when
     * the stack bytes after the copy were zero. */
    size_t host_len = zurl_copy(uri, &u->host, host, sizeof host);
    if (host_len >= sizeof host)
        return ZOTPCLI_ERR_URI;
    host[host_len] = '\0';
    if (zstr_casecmp(host, "totp") == 0)
        e->kind = ZOTPCLI_TOTP;
    else if (zstr_casecmp(host, "hotp") == 0)
        e->kind = ZOTPCLI_HOTP;
    else
        return ZOTPCLI_ERR_URI;
    return ZOTPCLI_OK;
}

/* "issuer:label" split at the colon into path_issuer and e->label. */
static zotpcli_err otpauth_issuer_label(const char *decoded, size_t dlen,
                                        const char *colon, zotpcli_entry *e,
                                        char *path_issuer)
{
    size_t ilen = (size_t)(colon - decoded);
    if (ilen == 0 || ilen > ZOTPCLI_MAX_ISSUER)
        return ZOTPCLI_ERR_LABEL;
    if (!copy_cstr(path_issuer, ZOTPCLI_MAX_ISSUER + 1, decoded, ilen))
        return ZOTPCLI_ERR_LABEL;
    if (!zutf8_validate(path_issuer)) return ZOTPCLI_ERR_LABEL;
    size_t llen = dlen - ilen - 1;
    if (llen == 0 || llen > ZOTPCLI_MAX_LABEL)
        return ZOTPCLI_ERR_LABEL;
    if (!copy_cstr(e->label, sizeof e->label, colon + 1, llen))
        return ZOTPCLI_ERR_LABEL;
    return ZOTPCLI_OK;
}

/* Path: "/label" or "/issuer:label", percent-encoded. Fills e->label and
 * path_issuer (empty when the path names none). */
static zotpcli_err otpauth_parse_path(const char *uri, const zurl *u,
                                      zotpcli_entry *e, char *path_issuer)
{
    if (u->path.len < 2 || uri[u->path.off] != '/') return ZOTPCLI_ERR_URI;
    char decoded[ZOTPCLI_MAX_LABEL + ZOTPCLI_MAX_ISSUER + 2];
    size_t dlen = 0;
    size_t dneed = zpct_decode(decoded, sizeof decoded,
                               uri + u->path.off + 1, u->path.len - 1, &dlen);
    if (dneed == SIZE_MAX || dneed >= sizeof decoded || dlen == 0 ||
        dlen > sizeof decoded)
        return ZOTPCLI_ERR_URI;
    if (memchr(decoded, '\0', dlen)) return ZOTPCLI_ERR_URI;
    decoded[dlen] = '\0';

    char *colon = memchr(decoded, ':', dlen);
    if (colon) {
        zotpcli_err r = otpauth_issuer_label(decoded, dlen, colon, e,
                                             path_issuer);
        if (r != ZOTPCLI_OK) return r;
    } else {
        if (dlen > ZOTPCLI_MAX_LABEL) return ZOTPCLI_ERR_LABEL;
        if (!copy_cstr(e->label, sizeof e->label, decoded, dlen))
            return ZOTPCLI_ERR_LABEL;
    }
    if (!zutf8_validate(e->label)) return ZOTPCLI_ERR_LABEL;
    return ZOTPCLI_OK;
}

/* What the query string contributed beyond plain entry fields. */
struct otpauth_query {
    bool have_secret;
    bool have_q_issuer;
    char q_issuer[ZOTPCLI_MAX_ISSUER + 1];
};

/* Numeric parameters: digits, period and counter. Returns 1 when the key was
 * one of them (result in *rc), 0 otherwise. */
static int otpauth_apply_numeric(const char *key, const char *val,
                                 size_t vdec, zotpcli_entry *e,
                                 zotpcli_err *rc)
{
    uint64_t num;
    *rc = ZOTPCLI_ERR_URI;
    if (zstr_casecmp(key, "digits") == 0) {
        if (!parse_u64(val, vdec, &num) || num < ZOTP_MIN_DIGITS ||
            num > ZOTPCLI_MAX_DIGITS)
            return 1;
        e->digits = (unsigned)num;
    } else if (zstr_casecmp(key, "period") == 0) {
        if (!parse_u64(val, vdec, &num) || num == 0 ||
            num > ZOTPCLI_MAX_PERIOD)
            return 1;
        e->period = (unsigned)num;
    } else if (zstr_casecmp(key, "counter") == 0) {
        if (!parse_u64(val, vdec, &num)) return 1;
        e->counter = num;
    } else {
        return 0;
    }
    *rc = ZOTPCLI_OK;
    return 1;
}

/* Applies one decoded key=value pair. Unknown keys are ignored for forward
 * compatibility. */
static zotpcli_err otpauth_apply_param(const char *key, const char *val,
                                       size_t vdec, zotpcli_entry *e,
                                       struct otpauth_query *q)
{
    zotpcli_err rc;
    if (zstr_casecmp(key, "secret") == 0) {
        zotpcli_err se = zotpcli_b32_decode_secret(
            val, e->secret, sizeof e->secret, &e->secret_len);
        if (se != ZOTPCLI_OK) return se;
        q->have_secret = true;
    } else if (zstr_casecmp(key, "issuer") == 0) {
        if (vdec > ZOTPCLI_MAX_ISSUER) return ZOTPCLI_ERR_LABEL;
        if (!zutf8_validate(val)) return ZOTPCLI_ERR_LABEL;
        memcpy(q->q_issuer, val, vdec + 1);
        q->have_q_issuer = true;
    } else if (otpauth_apply_numeric(key, val, vdec, e, &rc)) {
        return rc;
    } else if (zstr_casecmp(key, "algorithm") == 0) {
        /* Only SHA-1 is implemented (RFC 4226/6238 defaults); refuse
         * anything else rather than silently computing the wrong
         * algorithm. */
        if (zstr_casecmp(val, "SHA1") != 0)
            return ZOTPCLI_ERR_URI;
    }
    return ZOTPCLI_OK;
}

/* One "key[=value]" query field: percent-decode both and apply them. */
static zotpcli_err otpauth_parse_field(const zstr_span *field,
                                       zotpcli_entry *e,
                                       struct otpauth_query *q)
{
    const char *eq = memchr(field->ptr, '=', field->len);
    size_t klen = eq ? (size_t)(eq - field->ptr) : field->len;
    size_t vlen = eq ? field->len - klen - 1 : 0;
    const char *vptr = eq ? eq + 1 : field->ptr + field->len;

    char key[16];
    if (klen == 0 || klen >= sizeof key) return ZOTPCLI_ERR_URI;
    size_t kdec = 0;
    if (zpct_decode(key, sizeof key, field->ptr, klen, &kdec) == SIZE_MAX ||
        kdec >= sizeof key)
        return ZOTPCLI_ERR_URI;
    key[kdec] = '\0';

    char val[ZOTPCLI_MAX_URI + 1];
    size_t vdec = 0;
    if (zpct_decode(val, sizeof val, vptr, vlen, &vdec) == SIZE_MAX ||
        vdec >= sizeof val)
        return ZOTPCLI_ERR_URI;
    if (memchr(val, '\0', vdec)) return ZOTPCLI_ERR_URI;
    val[vdec] = '\0';
    return otpauth_apply_param(key, val, vdec, e, q);
}

/* Query parameters: secret, issuer, digits, period, counter, algorithm. */
static zotpcli_err otpauth_parse_query(const char *uri, const zurl *u,
                                       zotpcli_entry *e,
                                       struct otpauth_query *q)
{
    if (!u->has_query || u->query.len == 0) return ZOTPCLI_OK;
    char qbuf[ZOTPCLI_MAX_URI + 1];
    if (u->query.len > ZOTPCLI_MAX_URI) return ZOTPCLI_ERR_URI;
    if (!copy_cstr(qbuf, sizeof qbuf, uri + u->query.off, u->query.len))
        return ZOTPCLI_ERR_URI;

    zstr_split_it it;
    zstr_span field;
    zstr_split_init(&it, qbuf, '&');
    while (zstr_split_next(&it, &field)) {
        zotpcli_err err = otpauth_parse_field(&field, e, q);
        if (err != ZOTPCLI_OK) return err;
    }
    return ZOTPCLI_OK;
}

zotpcli_err zotpcli_otpauth_parse_n(const char *uri, size_t len,
                                    zotpcli_entry *out)
{
    if (!uri || !out) return ZOTPCLI_ERR_ARG;
    if (len == 0 || len > ZOTPCLI_MAX_URI) return ZOTPCLI_ERR_URI;

    zurl u;
    if (!zurl_parse_n(uri, len, &u)) return ZOTPCLI_ERR_URI;
    if (!zurl_scheme_is(&u, uri, "otpauth")) return ZOTPCLI_ERR_URI;
    if (!u.has_authority) return ZOTPCLI_ERR_URI;

    zotpcli_entry e;
    zotpcli_entry_init(&e);
    zotpcli_err err = otpauth_parse_kind(uri, &u, &e);
    if (err != ZOTPCLI_OK) return err;

    char path_issuer[ZOTPCLI_MAX_ISSUER + 1] = "";
    err = otpauth_parse_path(uri, &u, &e, path_issuer);
    if (err != ZOTPCLI_OK) return err;

    struct otpauth_query q = {0};
    err = otpauth_parse_query(uri, &u, &e, &q);
    if (err != ZOTPCLI_OK) return err;
    if (!q.have_secret) return ZOTPCLI_ERR_SECRET;

    if (q.have_q_issuer) {
        /* Fail closed when both issuers exist and disagree. */
        if (path_issuer[0] && strcmp(path_issuer, q.q_issuer) != 0)
            return ZOTPCLI_ERR_URI;
        memcpy(e.issuer, q.q_issuer, sizeof e.issuer);
    } else {
        memcpy(e.issuer, path_issuer, sizeof e.issuer);
    }

    *out = e;
    return ZOTPCLI_OK;
}

zotpcli_err zotpcli_otpauth_parse(const char *uri, zotpcli_entry *out)
{
    if (!uri) return ZOTPCLI_ERR_ARG;
    return zotpcli_otpauth_parse_n(uri, strlen(uri), out);
}

/* Percent-encode one entry string field into tmp (unreserved set);
 * returns the encoded length in *need. */
static zotpcli_err otpauth_encode_field(const char *s, char *tmp,
                                        size_t tcap, size_t *need)
{
    size_t n = zpct_encode(tmp, tcap, s, strlen(s), ZPCT_UNRESERVED);
    if (n == SIZE_MAX || n >= tcap) return ZOTPCLI_ERR_TRUNC;
    *need = n;
    return ZOTPCLI_OK;
}

/* otpauth scheme name for the entry kind. */
static const char *otpauth_kind_name(const zotpcli_entry *e)
{
    return e->kind == ZOTPCLI_HOTP ? "hotp" : "totp";
}

zotpcli_err zotpcli_otpauth_format(const zotpcli_entry *e, char *out,
                                   size_t cap)
{
    if (!e || !out) return ZOTPCLI_ERR_ARG;
    zotpcli_err ve = entry_validate(e);
    if (ve != ZOTPCLI_OK) return ve;

    char tmp[3u * ZOTPCLI_MAX_LABEL + 1];
    char b32[SECRET_B32_CAP];
    zotpcli_err be = zotpcli_b32_encode_secret(e->secret, e->secret_len,
                                               b32, sizeof b32);
    if (be != ZOTPCLI_OK) return be;

    zfmt f;
    zfmt_init(&f, out, cap);
    zfmt_str(&f, "otpauth://");
    zfmt_str(&f, otpauth_kind_name(e));
    zfmt_char(&f, '/');
    if (e->issuer[0]) {
        size_t need = 0;
        if (otpauth_encode_field(e->issuer, tmp, sizeof tmp, &need) !=
            ZOTPCLI_OK)
            return ZOTPCLI_ERR_TRUNC;
        zfmt_span(&f, tmp, need);
        zfmt_char(&f, ':');
    }
    size_t need = 0;
    if (otpauth_encode_field(e->label, tmp, sizeof tmp, &need) !=
        ZOTPCLI_OK)
        return ZOTPCLI_ERR_TRUNC;
    zfmt_span(&f, tmp, need);
    zfmt_str(&f, "?secret=");
    zfmt_str(&f, b32);
    if (e->issuer[0]) {
        zfmt_str(&f, "&issuer=");
        if (otpauth_encode_field(e->issuer, tmp, sizeof tmp, &need) !=
            ZOTPCLI_OK)
            return ZOTPCLI_ERR_TRUNC;
        zfmt_span(&f, tmp, need);
    }
    zfmt_str(&f, "&digits=");
    zfmt_u64(&f, e->digits);
    zfmt_str(&f, "&period=");
    zfmt_u64(&f, e->period);
    if (e->kind == ZOTPCLI_HOTP) {
        zfmt_str(&f, "&counter=");
        zfmt_u64(&f, e->counter);
    }
    return zfmt_ok(&f) ? ZOTPCLI_OK : ZOTPCLI_ERR_TRUNC;
}

/* --- store serialization --------------------------------------------- */

static zotpcli_err derive_mac_key(const char *passphrase,
                                  const uint8_t salt[ZOTPCLI_SALT_LEN],
                                  uint8_t key[ZOTPCLI_MAC_LEN])
{
    static const char info[] = "zotpcli-store-mac-v1";
    const char *pw = passphrase ? passphrase : "";
    uint8_t dk[ZSHA256_DIGEST_LEN];

    if (zscrypt(pw, strlen(pw), salt, ZOTPCLI_SALT_LEN,
                ZOTPCLI_SCRYPT_N, ZOTPCLI_SCRYPT_R, ZOTPCLI_SCRYPT_P,
                dk, sizeof dk) != 0)
        return ZOTPCLI_ERR_KDF;
    int rc = zhkdf_sha256(NULL, 0, dk, sizeof dk,
                          info, sizeof(info) - 1, key, ZOTPCLI_MAC_LEN);
    memset(dk, 0, sizeof dk);
    return rc == 0 ? ZOTPCLI_OK : ZOTPCLI_ERR_KDF;
}

/* Frame one JSON record as LEB128 length + payload. */
static zotpcli_err write_record(zbuf *out, const char *json, size_t len)
{
    uint8_t vi[ZVARINT_MAX_LEN];
    size_t vlen = 0;
    if (zvarint_encode_u64(len, vi, sizeof vi, &vlen) != ZVARINT_OK)
        return ZOTPCLI_ERR_FORMAT;
    zbuf_write(out, vi, vlen);
    zbuf_write(out, json, len);
    switch (zbuf_status(out)) {
    case ZBUF_OK: return ZOTPCLI_OK;
    case ZBUF_ERR_OOM: return ZOTPCLI_ERR_NOMEM;
    default: return ZOTPCLI_ERR_TRUNC;
    }
}

static zotpcli_err b64_of(const uint8_t *bin, size_t n, char *out,
                          size_t cap)
{
    if (!zbase64_encode(bin, n, out, cap)) return ZOTPCLI_ERR_FORMAT;
    return ZOTPCLI_OK;
}

static zotpcli_err header_json(const uint8_t salt[ZOTPCLI_SALT_LEN],
                               char *buf, size_t cap, size_t *len_out)
{
    char b64[32];
    zotpcli_err e = b64_of(salt, ZOTPCLI_SALT_LEN, b64, sizeof b64);
    if (e != ZOTPCLI_OK) return e;

    zjson w;
    zjson_init(&w, buf, cap);
    zjson_obj_open(&w);
    zjson_key(&w, "v");
    zjson_u64(&w, 1);
    zjson_key(&w, "kdf");
    zjson_str(&w, "scrypt");
    zjson_key(&w, "n");
    zjson_u64(&w, ZOTPCLI_SCRYPT_N);
    zjson_key(&w, "r");
    zjson_u64(&w, ZOTPCLI_SCRYPT_R);
    zjson_key(&w, "p");
    zjson_u64(&w, ZOTPCLI_SCRYPT_P);
    zjson_key(&w, "salt");
    zjson_str(&w, b64);
    zjson_obj_close(&w);
    if (zjson_finish(&w, len_out) != ZJSON_OK) return ZOTPCLI_ERR_FORMAT;
    return ZOTPCLI_OK;
}

static zotpcli_err entry_json(const zotpcli_entry *e, char *buf, size_t cap,
                              size_t *len_out)
{
    char b64[SECRET_B64_CAP];
    zotpcli_err be = b64_of(e->secret, e->secret_len, b64, sizeof b64);
    if (be != ZOTPCLI_OK) return be;

    zjson w;
    zjson_init(&w, buf, cap);
    zjson_obj_open(&w);
    zjson_key(&w, "label");
    zjson_str(&w, e->label);
    zjson_key(&w, "issuer");
    zjson_str(&w, e->issuer);
    zjson_key(&w, "secret");
    zjson_str(&w, b64);
    zjson_key(&w, "type");
    zjson_str(&w, e->kind == ZOTPCLI_HOTP ? "hotp" : "totp");
    zjson_key(&w, "digits");
    zjson_u64(&w, e->digits);
    zjson_key(&w, "period");
    zjson_u64(&w, e->period);
    zjson_key(&w, "counter");
    zjson_u64(&w, e->counter);
    zjson_obj_close(&w);
    if (zjson_finish(&w, len_out) != ZJSON_OK) return ZOTPCLI_ERR_FORMAT;
    return ZOTPCLI_OK;
}

zotpcli_err zotpcli_store_encode(const zotpcli_store *s,
                                 const char *passphrase,
                                 const uint8_t salt[ZOTPCLI_SALT_LEN],
                                 zbuf *out)
{
    if (!s || !out || !salt) return ZOTPCLI_ERR_ARG;

    zbuf_write(out, STORE_MAGIC, STORE_MAGIC_LEN);
    if (zbuf_status(out) != ZBUF_OK) return ZOTPCLI_ERR_TRUNC;

    char rec[2048];
    size_t rlen = 0;
    zotpcli_err e = header_json(salt, rec, sizeof rec, &rlen);
    if (e != ZOTPCLI_OK) return e;
    if ((e = write_record(out, rec, rlen)) != ZOTPCLI_OK) return e;

    for (size_t i = 0; i < s->count; i++) {
        e = entry_json(&s->entries[i], rec, sizeof rec, &rlen);
        if (e != ZOTPCLI_OK) return e;
        if ((e = write_record(out, rec, rlen)) != ZOTPCLI_OK) return e;
    }

    /* MAC over every byte written so far (magic + header + entries). */
    uint8_t key[ZOTPCLI_MAC_LEN];
    e = derive_mac_key(passphrase, salt, key);
    if (e != ZOTPCLI_OK) return e;
    uint8_t mac[ZOTPCLI_MAC_LEN];
    zsha256_hmac(key, sizeof key, out->data, out->len, mac);
    memset(key, 0, sizeof key);

    char macb64[48];
    e = b64_of(mac, sizeof mac, macb64, sizeof macb64);
    memset(mac, 0, sizeof mac);
    if (e != ZOTPCLI_OK) return e;

    zjson w;
    zjson_init(&w, rec, sizeof rec);
    zjson_obj_open(&w);
    zjson_key(&w, "mac");
    zjson_str(&w, macb64);
    zjson_obj_close(&w);
    if (zjson_finish(&w, &rlen) != ZJSON_OK) return ZOTPCLI_ERR_FORMAT;
    return write_record(out, rec, rlen);
}

/* --- parsing helpers (flat JSON objects via zjsonp) ------------------ */

typedef struct {
    const char *text;
    size_t len;
    zjsonp p;
    char key[16];
    bool have_key;
} rec_parser;

/* Decode one hex digit, -1 on non-hex. */
static int hex_dig(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode four hex digits at p[0..3] into *out. */
static zotpcli_err json_hex4(const char *p, uint32_t *out)
{
    uint32_t v = 0;
    for (size_t k = 0; k < 4; k++) {
        int d = hex_dig(p[k]);
        if (d < 0) return ZOTPCLI_ERR_FORMAT;
        v = (v << 4) | (uint32_t)d;
    }
    *out = v;
    return ZOTPCLI_OK;
}

/* Combine a \uXXXX high surrogate v with the following \uXXXX low. */
static zotpcli_err json_surrogate_pair(const char *text, size_t i,
                                       size_t end, uint32_t v,
                                       uint32_t *cp, size_t *adv)
{
    if (i + 11 >= end || text[i + 6] != '\\' ||
        text[i + 7] != 'u')
        return ZOTPCLI_ERR_FORMAT;
    uint32_t lo = 0;
    if (json_hex4(text + i + 8, &lo) != ZOTPCLI_OK)
        return ZOTPCLI_ERR_FORMAT;
    if (lo < 0xdc00 || lo > 0xdfff) return ZOTPCLI_ERR_FORMAT;
    *cp = 0x10000u + ((v - 0xd800u) << 10) + (lo - 0xdc00u);
    *adv = 12;
    return ZOTPCLI_OK;
}

/* Decode a \uXXXX escape (incl. surrogate pairs) at text[i]. */
static zotpcli_err json_decode_uesc(const char *text, size_t i, size_t end,
                                    uint32_t *cp, size_t *adv)
{
    if (i + 5 >= end) return ZOTPCLI_ERR_FORMAT;
    uint32_t v = 0;
    if (json_hex4(text + i + 2, &v) != ZOTPCLI_OK)
        return ZOTPCLI_ERR_FORMAT;
    *adv = 6;
    if (v >= 0xd800 && v <= 0xdbff) /* high surrogate */
        return json_surrogate_pair(text, i, end, v, cp, adv);
    if (v >= 0xdc00 && v <= 0xdfff)
        return ZOTPCLI_ERR_FORMAT; /* lone low surrogate */
    *cp = v;
    return ZOTPCLI_OK;
}

/* Decode the escape sequence at text[i]: sets *cp and the number of
 * source bytes it consumed in *adv. */
static zotpcli_err json_decode_escape(const char *text, size_t i,
                                      size_t end, uint32_t *cp,
                                      size_t *adv)
{
    if (i + 1 >= end) return ZOTPCLI_ERR_FORMAT;
    char e = text[i + 1];
    *adv = 2;
    switch (e) {
    case '"': *cp = '"'; break;
    case '\\': *cp = '\\'; break;
    case '/': *cp = '/'; break;
    case 'b': *cp = 0x08; break;
    case 'f': *cp = 0x0c; break;
    case 'n': *cp = 0x0a; break;
    case 'r': *cp = 0x0d; break;
    case 't': *cp = 0x09; break;
    case 'u':
        return json_decode_uesc(text, i, end, cp, adv);
    default:
        return ZOTPCLI_ERR_FORMAT;
    }
    return ZOTPCLI_OK;
}

/* Decode a KEY/STR payload into buf[0..cap), NUL-terminated. Raw bytes
 * (already validated UTF-8 by the parser) are copied VERBATIM; only
 * the RFC 8259 escapes are resolved, \uXXXX (incl. surrogate pairs)
 * via zutf8_encode.
 *
 * NOTE: upstream zjsonp_str_decode (zjsonp 0.1.0) re-encodes every
 * raw byte >= 0x80 as a code point, double-encoding non-ASCII UTF-8
 * payloads; this local decoder is the reason zjsonp_str_decode is not
 * a call site of this package. Returns ZOTPCLI_ERR_FORMAT on malformed
 * escapes or insufficient capacity. */
static zotpcli_err json_str_decode(const char *text,
                                   const zjsonp_event *ev,
                                   char *buf, size_t cap, size_t *len_out)
{
    size_t i = ev->off, end = ev->off + ev->len, n = 0;
    while (i < end) {
        unsigned char c = (unsigned char)text[i];
        if (c != '\\') { /* raw payload byte: copy unchanged */
            if (n >= cap) return ZOTPCLI_ERR_FORMAT;
            buf[n++] = (char)c;
            i++;
            continue;
        }
        uint32_t cp = 0;
        size_t adv = 2;
        if (json_decode_escape(text, i, end, &cp, &adv) != ZOTPCLI_OK)
            return ZOTPCLI_ERR_FORMAT;
        char enc[4];
        size_t en = zutf8_encode(cp, enc);
        if (en == 0 || n + en > cap) return ZOTPCLI_ERR_FORMAT;
        memcpy(buf + n, enc, en);
        n += en;
        i += adv;
    }
    if (n >= cap) return ZOTPCLI_ERR_FORMAT;
    buf[n] = '\0';
    if (len_out) *len_out = n;
    return ZOTPCLI_OK;
}

/* Validate a container event's parser state (depth 1, no dangling key). */
static bool rec_container_ok(const rec_parser *r, const zjsonp_event *ev)
{
    if (r->have_key) return false;
    if (ev->kind == ZJRP_OBJ_OPEN && r->p.depth != 1) return false;
    return true;
}

/* Consume a KEY event: decode it into r->key. Returns 0 on success,
 * -1 on deviation. */
static int rec_take_key(rec_parser *r, const zjsonp_event *ev)
{
    if (r->have_key || r->p.depth != 1) return -1;
    if (json_str_decode(r->text, ev, r->key, sizeof r->key,
                        NULL) != ZOTPCLI_OK)
        return -1;
    r->have_key = true;
    return 0;
}

/* Advance to the next structural or VALUE event of a flat object:
 * OBJ_OPEN/OBJ_CLOSE are returned to the caller, KEY events are
 * consumed internally (recorded in r->key), and STR/NUM values are
 * returned with r->key set. Returns ZOTPCLI_ERR_FORMAT on any
 * deviation (nested containers, bool/null, syntax error, dangling
 * key). */
static zotpcli_err rec_next(rec_parser *r, zjsonp_event *ev)
{
    for (;;) {
        zjsonp_status st = zjsonp_next(&r->p, ev);
        if (st == ZJRP_DONE) return ZOTPCLI_ERR_FORMAT; /* caller stops first */
        if (st != ZJRP_OK) return ZOTPCLI_ERR_FORMAT;
        switch (ev->kind) {
        case ZJRP_OBJ_OPEN:
        case ZJRP_OBJ_CLOSE:
            if (!rec_container_ok(r, ev)) return ZOTPCLI_ERR_FORMAT;
            return ZOTPCLI_OK;
        case ZJRP_KEY: {
            if (rec_take_key(r, ev) != 0) return ZOTPCLI_ERR_FORMAT;
            continue; /* the value follows in the next event */
        }
        case ZJRP_STR:
        case ZJRP_NUM:
            if (!r->have_key) return ZOTPCLI_ERR_FORMAT;
            return ZOTPCLI_OK;
        default:
            return ZOTPCLI_ERR_FORMAT; /* nested container, bool, null */
        }
    }
}

static void rec_value_done(rec_parser *r)
{
    r->have_key = false;
}

/* Decode the current string value into buf. */
static zotpcli_err rec_str(const rec_parser *r, const zjsonp_event *ev,
                           char *buf, size_t cap, size_t *len_out)
{
    return json_str_decode(r->text, ev, buf, cap, len_out);
}

static zotpcli_err rec_u64(const rec_parser *r, const zjsonp_event *ev,
                           uint64_t *out)
{
    int64_t v;
    if (!zjsonp_num_i64(r->text, ev, &v) || v < 0)
        return ZOTPCLI_ERR_FORMAT;
    *out = (uint64_t)v;
    return ZOTPCLI_OK;
}

static bool rec_done(rec_parser *r)
{
    zjsonp_event ev;
    return zjsonp_next(&r->p, &ev) == ZJRP_DONE && !r->have_key;
}

/* Numeric header fields and their required values (v, n, r, p). */
static const struct { const char *key; uint64_t val; } header_num_fields[] = {
    { "v", 1 },
    { "n", ZOTPCLI_SCRYPT_N },
    { "r", ZOTPCLI_SCRYPT_R },
    { "p", ZOTPCLI_SCRYPT_P },
};

/* Decode the numeric value of the already-matched header field k and
 * check it against its required value; records presence in have[k]. */
static zotpcli_err parse_header_numeric(const rec_parser *r,
                                        const zjsonp_event *ev,
                                        bool have[4], size_t k)
{
    uint64_t num;
    zotpcli_err e = rec_u64(r, ev, &num);
    if (e != ZOTPCLI_OK) return e;
    if (num != header_num_fields[k].val)
        return ZOTPCLI_ERR_FORMAT;
    have[k] = true;
    return ZOTPCLI_OK;
}

/* Decode the "kdf" string value; only "scrypt" is accepted. */
static zotpcli_err parse_header_kdf(const rec_parser *r,
                                    const zjsonp_event *ev)
{
    char sbuf[64];
    if (rec_str(r, ev, sbuf, sizeof sbuf, NULL) != ZOTPCLI_OK)
        return ZOTPCLI_ERR_FORMAT;
    if (strcmp(sbuf, "scrypt") != 0) return ZOTPCLI_ERR_FORMAT;
    return ZOTPCLI_OK;
}

/* Decode the "salt" string value from base64 into salt. */
static zotpcli_err parse_header_salt(const rec_parser *r,
                                     const zjsonp_event *ev,
                                     uint8_t salt[ZOTPCLI_SALT_LEN])
{
    char sbuf[64];
    size_t slen = 0;
    if (rec_str(r, ev, sbuf, sizeof sbuf, &slen) != ZOTPCLI_OK)
        return ZOTPCLI_ERR_FORMAT;
    size_t blen = 0;
    if (!zbase64_decode(sbuf, slen, salt, ZOTPCLI_SALT_LEN, &blen) ||
        blen != ZOTPCLI_SALT_LEN)
        return ZOTPCLI_ERR_FORMAT;
    return ZOTPCLI_OK;
}

/* Apply one header field: validate the key first, then its value kind;
 * records presence in have[0..5] (v, n, r, p, kdf, salt). */
static zotpcli_err parse_header_field(rec_parser *r,
                                      const zjsonp_event *ev,
                                      uint8_t salt[ZOTPCLI_SALT_LEN],
                                      bool have[6])
{
    zotpcli_err e;
    if (strcmp(r->key, "kdf") == 0) {
        if (ev->kind != ZJRP_STR) return ZOTPCLI_ERR_FORMAT;
        e = parse_header_kdf(r, ev);
        if (e != ZOTPCLI_OK) return e;
        have[4] = true;
        return ZOTPCLI_OK;
    }
    if (strcmp(r->key, "salt") == 0) {
        if (ev->kind != ZJRP_STR) return ZOTPCLI_ERR_FORMAT;
        e = parse_header_salt(r, ev, salt);
        if (e != ZOTPCLI_OK) return e;
        have[5] = true;
        return ZOTPCLI_OK;
    }
    for (size_t k = 0; k < 4; k++)
        if (strcmp(r->key, header_num_fields[k].key) == 0) {
            if (ev->kind != ZJRP_NUM) return ZOTPCLI_ERR_FORMAT;
            return parse_header_numeric(r, ev, have, k);
        }
    return ZOTPCLI_ERR_FORMAT; /* unexpected key/kind */
}

/* Parse the header record: version, KDF parameters, salt. Fail-closed
 * on any parameter this build does not implement. */
static zotpcli_err parse_header(const char *text, size_t len,
                                uint8_t salt[ZOTPCLI_SALT_LEN])
{
    rec_parser r = { text, len, {0}, "", false };
    zjsonp_init(&r.p, text, len);

    bool have[6] = { false };
    zjsonp_event ev;
    zotpcli_err e;

    while ((e = rec_next(&r, &ev)) == ZOTPCLI_OK) {
        if (ev.kind == ZJRP_OBJ_OPEN) continue;
        if (ev.kind == ZJRP_OBJ_CLOSE) break;
        e = parse_header_field(&r, &ev, salt, have);
        if (e != ZOTPCLI_OK) return e;
        rec_value_done(&r);
    }
    for (size_t k = 0; k < 6; k++)
        if (!have[k]) return ZOTPCLI_ERR_FORMAT;
    return rec_done(&r) ? ZOTPCLI_OK : ZOTPCLI_ERR_FORMAT;
}

static zotpcli_err parse_mac_record(const char *text, size_t len,
                                    uint8_t mac[ZOTPCLI_MAC_LEN])
{
    rec_parser r = { text, len, {0}, "", false };
    zjsonp_init(&r.p, text, len);

    bool have_mac = false;
    zjsonp_event ev;
    zotpcli_err e;
    while ((e = rec_next(&r, &ev)) == ZOTPCLI_OK) {
        if (ev.kind == ZJRP_OBJ_OPEN) continue;
        if (ev.kind == ZJRP_OBJ_CLOSE) break;
        char sbuf[64];
        size_t slen = 0;
        if (strcmp(r.key, "mac") != 0 || ev.kind != ZJRP_STR)
            return ZOTPCLI_ERR_FORMAT;
        if ((e = rec_str(&r, &ev, sbuf, sizeof sbuf, &slen)) != ZOTPCLI_OK)
            return e;
        size_t blen = 0;
        if (!zbase64_decode(sbuf, slen, mac, ZOTPCLI_MAC_LEN, &blen) ||
            blen != ZOTPCLI_MAC_LEN)
            return ZOTPCLI_ERR_FORMAT;
        have_mac = true;
        rec_value_done(&r);
    }
    if (!have_mac) return ZOTPCLI_ERR_FORMAT;
    return rec_done(&r) ? ZOTPCLI_OK : ZOTPCLI_ERR_FORMAT;
}

/* Decode the "secret" base64 string value into e0. */
static zotpcli_err parse_entry_secret(const rec_parser *r,
                                      const zjsonp_event *ev,
                                      zotpcli_entry *e0)
{
    char sbuf[SECRET_B64_CAP];
    size_t slen = 0;
    if (rec_str(r, ev, sbuf, sizeof sbuf, &slen) != ZOTPCLI_OK)
        return ZOTPCLI_ERR_FORMAT;
    if (!zbase64_decode(sbuf, slen, e0->secret, sizeof e0->secret,
                        &e0->secret_len) ||
        e0->secret_len == 0)
        return ZOTPCLI_ERR_FORMAT;
    return ZOTPCLI_OK;
}

/* Decode the "type" string value into e0->kind. */
static zotpcli_err parse_entry_type(const rec_parser *r,
                                    const zjsonp_event *ev,
                                    zotpcli_entry *e0)
{
    char sbuf[SECRET_B64_CAP];
    if (rec_str(r, ev, sbuf, sizeof sbuf, NULL) != ZOTPCLI_OK)
        return ZOTPCLI_ERR_FORMAT;
    if (strcmp(sbuf, "totp") == 0) {
        e0->kind = ZOTPCLI_TOTP;
    } else if (strcmp(sbuf, "hotp") == 0) {
        e0->kind = ZOTPCLI_HOTP;
    } else {
        return ZOTPCLI_ERR_FORMAT;
    }
    return ZOTPCLI_OK;
}

/* Decode the numeric digits/period/counter values into e0; the key is
 * validated before the value is decoded. */
static zotpcli_err parse_entry_numeric(rec_parser *r,
                                       const zjsonp_event *ev,
                                       zotpcli_entry *e0)
{
    zotpcli_err e;
    uint64_t num;
    if (strcmp(r->key, "digits") != 0 &&
        strcmp(r->key, "period") != 0 &&
        strcmp(r->key, "counter") != 0)
        return ZOTPCLI_ERR_FORMAT;
    if (strcmp(r->key, "digits") == 0) {
        if ((e = rec_u64(r, ev, &num)) != ZOTPCLI_OK) return e;
        if (num < ZOTP_MIN_DIGITS || num > ZOTPCLI_MAX_DIGITS)
            return ZOTPCLI_ERR_FORMAT;
        e0->digits = (unsigned)num;
    } else if (strcmp(r->key, "period") == 0) {
        if ((e = rec_u64(r, ev, &num)) != ZOTPCLI_OK) return e;
        if (num == 0 || num > ZOTPCLI_MAX_PERIOD)
            return ZOTPCLI_ERR_FORMAT;
        e0->period = (unsigned)num;
    } else if (strcmp(r->key, "counter") == 0) {
        if ((e = rec_u64(r, ev, &e0->counter)) != ZOTPCLI_OK) return e;
    }
    return ZOTPCLI_OK;
}

/* Apply one string-valued entry field (label, issuer, secret, type);
 * records presence flags as fields are seen. */
static zotpcli_err parse_entry_str_field(rec_parser *r,
                                         const zjsonp_event *ev,
                                         zotpcli_entry *e0,
                                         bool *have_label,
                                         bool *have_secret,
                                         bool *have_type)
{
    zotpcli_err e;
    if (strcmp(r->key, "label") == 0) {
        if ((e = rec_str(r, ev, e0->label, sizeof e0->label, NULL)) !=
            ZOTPCLI_OK)
            return e;
        *have_label = true;
    } else if (strcmp(r->key, "issuer") == 0) {
        if ((e = rec_str(r, ev, e0->issuer, sizeof e0->issuer, NULL)) !=
            ZOTPCLI_OK)
            return e;
    } else if (strcmp(r->key, "secret") == 0) {
        if ((e = parse_entry_secret(r, ev, e0)) != ZOTPCLI_OK)
            return e;
        *have_secret = true;
    } else if (strcmp(r->key, "type") == 0) {
        if ((e = parse_entry_type(r, ev, e0)) != ZOTPCLI_OK)
            return e;
        *have_type = true;
    } else {
        return ZOTPCLI_ERR_FORMAT;
    }
    return ZOTPCLI_OK;
}

/* Apply one entry field by kind: strings to the string fields,
 * numbers to the numeric parameters. */
static zotpcli_err parse_entry_field(rec_parser *r,
                                     const zjsonp_event *ev,
                                     zotpcli_entry *e0,
                                     bool *have_label, bool *have_secret,
                                     bool *have_type)
{
    if (ev->kind == ZJRP_STR)
        return parse_entry_str_field(r, ev, e0, have_label, have_secret,
                                     have_type);
    if (ev->kind == ZJRP_NUM)
        return parse_entry_numeric(r, ev, e0);
    return ZOTPCLI_ERR_FORMAT;
}

static zotpcli_err parse_entry_record(const char *text, size_t len,
                                      zotpcli_entry *out)
{
    rec_parser r = { text, len, {0}, "", false };
    zjsonp_init(&r.p, text, len);

    zotpcli_entry e0;
    zotpcli_entry_init(&e0);
    bool have_label = false, have_secret = false, have_type = false;
    zjsonp_event ev;
    zotpcli_err e;

    while ((e = rec_next(&r, &ev)) == ZOTPCLI_OK) {
        if (ev.kind == ZJRP_OBJ_OPEN) continue;
        if (ev.kind == ZJRP_OBJ_CLOSE) break;

        e = parse_entry_field(&r, &ev, &e0, &have_label, &have_secret,
                              &have_type);
        if (e != ZOTPCLI_OK) return e;
        rec_value_done(&r);
    }
    if (!rec_done(&r)) return ZOTPCLI_ERR_FORMAT;
    if (!have_label || !have_secret || !have_type)
        return ZOTPCLI_ERR_FORMAT;
    *out = e0;
    return ZOTPCLI_OK;
}

/* Read one framed record at *pos; advances *pos past the payload. */
static zotpcli_err read_record(const uint8_t *data, size_t len, size_t *pos,
                               const uint8_t **rec, size_t *rec_len)
{
    uint64_t v;
    size_t consumed = 0;
    if (zvarint_decode_u64(data + *pos, len - *pos, &v, &consumed, 1) !=
        ZVARINT_OK)
        return ZOTPCLI_ERR_FORMAT;
    if (v == 0 || v > MAX_RECORD_LEN) return ZOTPCLI_ERR_FORMAT;
    if (v > len - *pos - consumed) return ZOTPCLI_ERR_FORMAT;
    *rec = data + *pos + consumed;
    *rec_len = (size_t)v;
    *pos += consumed + (size_t)v;
    return ZOTPCLI_OK;
}

/* Argument sanity for zotpcli_store_decode. */
static bool store_decode_args_ok(const zotpcli_store *s,
                                 const uint8_t *data, size_t len)
{
    return s && s->entries && (data || len == 0);
}

/* Walk the remaining records; the last one must be the MAC. */
static zotpcli_err store_scan_to_mac(const uint8_t *data, size_t len,
                                     size_t pos, size_t *mac_off,
                                     const uint8_t **mac_rec,
                                     size_t *mac_len, size_t *nrecs)
{
    while (pos < len) {
        *mac_off = pos;
        zotpcli_err e = read_record(data, len, &pos, mac_rec, mac_len);
        if (e != ZOTPCLI_OK) return e;
        (*nrecs)++;
    }
    return ZOTPCLI_OK;
}

/* Verify the MAC BEFORE accepting any entry. */
static zotpcli_err store_verify_mac(const char *passphrase,
                                    const uint8_t salt[ZOTPCLI_SALT_LEN],
                                    const uint8_t *data, size_t mac_off,
                                    const uint8_t *mac_rec, size_t mac_len)
{
    uint8_t key[ZOTPCLI_MAC_LEN];
    zotpcli_err e = derive_mac_key(passphrase, salt, key);
    if (e != ZOTPCLI_OK) return e;
    uint8_t expect[ZOTPCLI_MAC_LEN];
    zsha256_hmac(key, sizeof key, data, mac_off, expect);
    memset(key, 0, sizeof key);

    uint8_t actual[ZOTPCLI_MAC_LEN];
    e = parse_mac_record((const char *)mac_rec, mac_len, actual);
    if (e != ZOTPCLI_OK) return e;
    if (zsha256_compare(expect, actual) != 0) {
        memset(expect, 0, sizeof expect);
        memset(actual, 0, sizeof actual);
        return ZOTPCLI_ERR_MAC;
    }
    memset(expect, 0, sizeof expect);
    memset(actual, 0, sizeof actual);
    return ZOTPCLI_OK;
}

/* MAC valid: decode the entry records between header and MAC. */
static zotpcli_err store_load_entries(zotpcli_store *s,
                                      const uint8_t *data, size_t len,
                                      size_t pos, size_t end)
{
    while (pos < end) {
        const uint8_t *rec;
        size_t rec_len;
        zotpcli_err e = read_record(data, len, &pos, &rec, &rec_len);
        if (e != ZOTPCLI_OK) return e;
        zotpcli_entry ent;
        e = parse_entry_record((const char *)rec, rec_len, &ent);
        if (e != ZOTPCLI_OK) return e;
        e = zotpcli_store_add(s, &ent);
        if (e != ZOTPCLI_OK) return e;
    }
    return ZOTPCLI_OK;
}

zotpcli_err zotpcli_store_decode(zotpcli_store *s, const void *data_,
                                 size_t len, const char *passphrase)
{
    const uint8_t *data = data_;
    if (!store_decode_args_ok(s, data, len)) return ZOTPCLI_ERR_ARG;
    if (len < STORE_MAGIC_LEN || len > ZOTPCLI_MAX_FILE)
        return ZOTPCLI_ERR_FORMAT;
    if (memcmp(data, STORE_MAGIC, STORE_MAGIC_LEN) != 0)
        return ZOTPCLI_ERR_FORMAT;

    /* Record 0: header (KDF parameters and salt). */
    size_t pos = STORE_MAGIC_LEN;
    const uint8_t *rec;
    size_t rec_len;
    zotpcli_err e = read_record(data, len, &pos, &rec, &rec_len);
    if (e != ZOTPCLI_OK) return e;

    uint8_t salt[ZOTPCLI_SALT_LEN];
    e = parse_header((const char *)rec, rec_len, salt);
    if (e != ZOTPCLI_OK) return e;
    size_t entries_begin = pos;

    size_t mac_off = 0, mac_len = 0;
    const uint8_t *mac_rec = NULL;
    size_t nrecs = 0;
    e = store_scan_to_mac(data, len, pos, &mac_off, &mac_rec, &mac_len,
                          &nrecs);
    if (e != ZOTPCLI_OK) return e;
    if (nrecs == 0) return ZOTPCLI_ERR_FORMAT;

    e = store_verify_mac(passphrase, salt, data, mac_off, mac_rec,
                         mac_len);
    if (e != ZOTPCLI_OK) return e;

    e = store_load_entries(s, data, len, entries_begin, mac_off);
    if (e != ZOTPCLI_OK) return e;
    memcpy(s->salt, salt, ZOTPCLI_SALT_LEN);
    return ZOTPCLI_OK;
}
