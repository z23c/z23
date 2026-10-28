/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Purpose: encode and parse bounded PEM frames with matching labels. */
#include "zpem/zpem.h"

#include <stdbool.h>
#include <string.h>

#include "zbase64/zbase64.h"

static int label_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == ' ' || c == '-';
}

static zpem_err label_check(const char *label, size_t n)
{
    if (!label || n == 0) return ZPEM_ERR_ARG;
    if (n > ZPEM_MAX_LABEL) return ZPEM_ERR_RANGE;
    for (size_t i = 0; i < n; i++)
        if (!label_char(label[i])) return ZPEM_ERR_LABEL;
    if (label[0] == ' ' || label[0] == '-' ||
        label[n - 1] == ' ' || label[n - 1] == '-')
        return ZPEM_ERR_LABEL;
    /* A run of five dashes would be misparsed as a marker. */
    for (size_t i = 0; i + 5 <= n; i++)
        if (memcmp(label + i, "-----", 5) == 0) return ZPEM_ERR_LABEL;
    return ZPEM_OK;
}

size_t zpem_encoded_len(size_t der_len, size_t label_len)
{
    if (label_len == 0 || label_len > ZPEM_MAX_LABEL) return 0;
    size_t b64 = zbase64_encode_len(der_len);
    if (b64 == 0 && der_len > 0) return 0;
    size_t lines = b64 / 64 + (b64 % 64 ? 1 : 0);
    if (lines == 0) lines = 1; /* empty body still gets its newline */
    /* "-----BEGIN "+L+"-----\n" + b64+lines + "-----END "+L+"-----\n" */
    size_t fixed = 11 + 6 + 9 + 6; /* markers and their newlines */
    if (b64 > SIZE_MAX - fixed - 2 * label_len - lines) return 0;
    return fixed + 2 * label_len + b64 + lines;
}

zpem_err zpem_encode(const char *label, size_t label_len,
                     const uint8_t *der, size_t der_len,
                     char *out, size_t cap, size_t *out_len)
{
    zpem_err e = label_check(label, label_len);
    if (e != ZPEM_OK) return e;
    if ((der_len > 0 && !der) || !out) return ZPEM_ERR_ARG;
    size_t total = zpem_encoded_len(der_len, label_len);
    if (total == 0) return ZPEM_ERR_RANGE;
    if (cap < total) return ZPEM_ERR_CAP;

    size_t pos = 0;
    memcpy(out + pos, "-----BEGIN ", 11); pos += 11;
    memcpy(out + pos, label, label_len); pos += label_len;
    memcpy(out + pos, "-----\n", 6); pos += 6;

    /* Encode the base64 text directly at its final position.
     * zbase64_encode writes enc_len+1 bytes including a NUL; the NUL
     * lands where the final line break goes and is overwritten by the
     * shifting pass below. */
    size_t b64 = zbase64_encode_len(der_len);
    if (!zbase64_encode(der, der_len, out + pos, cap - pos))
        return ZPEM_ERR_CAP;

    /* Insert a line break after every 64 chars and at the end, moving
     * from the back so writes never clobber unread data. Line i
     * (1-based) moves its take chars from (i-1)*64 to (i-1)*65. */
    size_t lines = b64 / 64 + (b64 % 64 ? 1 : 0);
    if (lines == 0) lines = 1; /* empty body still ends with '\n' */
    for (size_t line = lines; line > 0; line--) {
        size_t src = (line - 1) * 64;
        size_t take = b64 - src;
        if (take > 64) take = 64;
        size_t dst = (line - 1) * 65;
        memmove(out + pos + dst, out + pos + src, take);
        out[pos + dst + take] = '\n';
    }
    pos += b64 + lines;

    memcpy(out + pos, "-----END ", 9); pos += 9;
    memcpy(out + pos, label, label_len); pos += label_len;
    memcpy(out + pos, "-----\n", 6); pos += 6;

    if (out_len) *out_len = pos;
    return ZPEM_OK;
}

static bool span_fits(size_t n, size_t start, size_t bytes)
{
    return start <= n && bytes <= n - start;
}

static const char end_marker[] = "-----END ";

static bool end_marker_matches(const char *pem, size_t n,
                               size_t body_start, size_t marker)
{
    if (!span_fits(n, marker, sizeof end_marker - 1) || marker < body_start)
        return false;
    return (marker == body_start || pem[marker - 1] == '\n' ||
            pem[marker - 1] == '\r') &&
           memcmp(pem + marker, end_marker, sizeof end_marker - 1) == 0;
}

static bool trailer_fits(size_t n, size_t start, size_t label_len)
{
    return span_fits(n, start, label_len) &&
           span_fits(n, start + label_len, 5);
}

static int line_end(const char *buf, size_t n, size_t i, size_t *next)
{
    /* Returns bytes of line ending (1 for \n, 2 for \r\n) at i, or 0. */
    if (i < n && buf[i] == '\n') { *next = i + 1; return 1; }
    if (span_fits(n, i, 2) && buf[i] == '\r' && buf[i + 1] == '\n') {
        *next = i + 2;
        return 2;
    }
    return 0;
}

static zpem_err parse_begin(const char *pem, size_t n, size_t *label_len,
                            size_t *body_start)
{
    static const char begin[] = "-----BEGIN ";
    if (n < sizeof(begin) - 1 || memcmp(pem, begin, sizeof(begin) - 1) != 0)
        return ZPEM_ERR_FORMAT;

    /* Label ends at the next '-' run: find "-----\n". */
    size_t i = sizeof(begin) - 1;
    size_t label_end = n;
    for (; span_fits(n, i, 6); i++) {
        if (memcmp(pem + i, "-----", 5) == 0) {
            size_t after;
            int eol = line_end(pem, n, i + 5, &after);
            if (eol) { label_end = i; i = after; break; }
            return ZPEM_ERR_FORMAT; /* marker without newline */
        }
    }
    if (label_end == n) return ZPEM_ERR_FORMAT; /* no closing marker */
    *label_len = label_end - (sizeof(begin) - 1);
    zpem_err le = label_check(pem + sizeof(begin) - 1, *label_len);
    if (le != ZPEM_OK) return le == ZPEM_ERR_ARG ? ZPEM_ERR_FORMAT : le;
    *body_start = i;
    return ZPEM_OK;
}

static zpem_err parse_body(const char *pem, size_t n, size_t body_start,
                           size_t *body_end)
{
    size_t j = body_start;
    while (span_fits(n, j, sizeof end_marker - 1)) {
        if (end_marker_matches(pem, n, body_start, j)) break;
        char c = pem[j];
        /* Body chars: base64 alphabet, '=', CR, LF only. */
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' ||
              c == '=' || c == '\n' || c == '\r'))
            return ZPEM_ERR_FORMAT;
        j++;
    }
    if (!span_fits(n, j, sizeof end_marker - 1)) return ZPEM_ERR_FORMAT; /* no END */
    *body_end = j;
    return ZPEM_OK;
}

static zpem_err parse_end(const char *pem, size_t n, const char *label,
                          size_t label_len, size_t body_end, size_t *consumed)
{
    size_t k = body_end + sizeof end_marker - 1;
    if (!trailer_fits(n, k, label_len)) return ZPEM_ERR_FORMAT;
    if (memcmp(pem + k, label, label_len) != 0) return ZPEM_ERR_FORMAT;
    k += label_len;
    if (memcmp(pem + k, "-----", 5) != 0) return ZPEM_ERR_FORMAT;
    k += 5;
    size_t after;
    int eol = line_end(pem, n, k, &after);
    if (!eol) return ZPEM_ERR_FORMAT;
    *consumed = after;
    return ZPEM_OK;
}

zpem_err zpem_parse(const char *pem, size_t n, zpem_block *blk)
{
    if (!pem || !blk) return ZPEM_ERR_ARG;
    memset(blk, 0, sizeof(*blk));
    size_t label_len, b64_start, body_end, consumed;
    zpem_err e = parse_begin(pem, n, &label_len, &b64_start);
    if (e != ZPEM_OK) return e;
    e = parse_body(pem, n, b64_start, &body_end);
    if (e != ZPEM_OK) return e;
    const char *label = pem + sizeof("-----BEGIN ") - 1;
    e = parse_end(pem, n, label, label_len, body_end, &consumed);
    if (e != ZPEM_OK) return e;

    blk->label = label;
    blk->label_len = label_len;
    blk->b64 = pem + b64_start;
    blk->b64_len = body_end - b64_start;
    blk->consumed = consumed;
    return ZPEM_OK;
}

zpem_err zpem_decode(const zpem_block *blk, char *scratch, size_t scratch_cap,
                     uint8_t *der_out, size_t der_cap, size_t *der_len)
{
    if (!blk || !scratch || !der_out) return ZPEM_ERR_ARG;
    if (scratch_cap < blk->b64_len) return ZPEM_ERR_CAP;
    size_t m = 0;
    for (size_t i = 0; i < blk->b64_len; i++) {
        char c = blk->b64[i];
        if (c != '\n' && c != '\r') scratch[m++] = c;
    }
    if (!zbase64_decode(scratch, m, der_out, der_cap, der_len))
        return ZPEM_ERR_BASE64;
    return ZPEM_OK;
}

zpem_err zpem_read(const char *pem, size_t n, char *scratch, size_t scratch_cap,
                   uint8_t *der_out, size_t der_cap, size_t *der_len,
                   zpem_block *blk)
{
    zpem_block tmp;
    if (!blk) blk = &tmp;
    zpem_err e = zpem_parse(pem, n, blk);
    if (e != ZPEM_OK) return e;
    return zpem_decode(blk, scratch, scratch_cap, der_out, der_cap, der_len);
}

const char *zpem_err_str(zpem_err e)
{
    switch (e) {
    case ZPEM_OK: return "ok";
    case ZPEM_ERR_ARG: return "null argument";
    case ZPEM_ERR_RANGE: return "size out of range";
    case ZPEM_ERR_CAP: return "buffer too small";
    case ZPEM_ERR_FORMAT: return "malformed or truncated PEM";
    case ZPEM_ERR_LABEL: return "illegal label";
    case ZPEM_ERR_BASE64: return "invalid base64 body";
    }
    return "unknown error";
}
