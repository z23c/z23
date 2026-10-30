/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: parsing half of check-hotswap-service-islands: the fixed-storage
 * violation buffer, bounded copy/slurp/line helpers and the HOTSWAP_SERVICE
 * manifest and HOTSHADOW pair parsers. Row checks and entry points live in
 * gate_hotswap_service_islands.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_hotswap_service_islands_priv.h"

/* ---------- violation buffer (fixed static storage) ---------- */

int hsi_vadd(struct hsi_vio *v, const char *fmt, ...)
{
    char tmp[HSI_LINE + 256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof tmp)
        return -1;
    if (v->len + (size_t)n + 1 > sizeof v->buf) {
        fprintf(stderr, "%s: violations exceed %d bytes\n", k_hsi_gate,
                HSI_VBUF);
        return -1;
    }
    memcpy(v->buf + v->len, tmp, (size_t)n);
    v->len += (size_t)n;
    v->buf[v->len] = '\0';
    return 0;
}

/* ---------- slurp / copy helpers ---------- */

/* Checked string copy (replaces snprintf "%s"): 0 ok, 2 exceeds cap. */
int hsi_cpy(char *dst, size_t cap, const char *s)
{
    size_t n = strlen(s);
    if (n >= cap) {
        fprintf(stderr, "%s: field '%s' exceeds %zu bytes\n", k_hsi_gate, s,
                cap - 1);
        return 2;
    }
    memcpy(dst, s, n + 1);
    return 0;
}

/* Checked pre/suf decoration (replaces snprintf "\"%s\"" style builds). */
int hsi_decor(char *dst, size_t cap, const char *pre, const char *s,
                     const char *suf)
{
    size_t a = strlen(pre), b = strlen(s), c = strlen(suf);
    if (a + b + c + 1 > cap) {
        fprintf(stderr, "%s: field '%s%s%s' exceeds %zu bytes\n", k_hsi_gate,
                pre, s, suf, cap - 1);
        return 2;
    }
    memcpy(dst, pre, a);
    memcpy(dst + a, s, b);
    memcpy(dst + a + b, suf, c + 1);
    return 0;
}

/* Reads the whole file into buf (statically sized). 0 ok, 1 could not open,
 * 2 internal error or file exceeds capacity. */
int hsi_slurp(const char *path, char *buf, size_t cap, size_t *outn)
{
    *outn = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, cap - 1, f);
    int bad = ferror(f);
    if (!bad && n == cap - 1 && fgetc(f) != EOF)
        bad = 1;
    fclose(f);
    if (bad) {
        fprintf(stderr, "%s: %s exceeds %zu bytes\n", k_hsi_gate, path,
                cap - 1);
        return 2;
    }
    buf[n] = '\0';
    *outn = n;
    return 0;
}

int hsi_copy_line(char *dst, size_t cap, const char *line, size_t len,
                         const char *path, long ln)
{
    if (len && line[len - 1] == '\n')
        len--;
    if (len >= cap) {
        fprintf(stderr, "%s: line %ld of %s exceeds %zu bytes\n", k_hsi_gate,
                ln, path, cap);
        return 2;
    }
    memcpy(dst, line, len);
    dst[len] = '\0';
    return 0;
}

/* Bounded substring test (no memmem: not relying on GNU extensions). */
int hsi_line_has(const char *s, size_t n, const char *needle,
                        size_t nl)
{
    if (nl == 0 || nl > n)
        return 0;
    for (size_t i = 0; i + nl <= n; i++)
        if (memcmp(s + i, needle, nl) == 0)
            return 1;
    return 0;
}

/* ---------- manifest / pair parsing ---------- */

/* Finds the matching ')' for the '(' at open (string/escape aware); *end is
 * the index one past it. Returns nonzero when unbalanced. */
static int hsi_close_paren(const char *b, size_t n, size_t open, size_t *end)
{
    size_t j = open;
    int depth = 1, ins = 0, esc = 0;
    while (j < n && depth > 0) {
        char c = b[j];
        if (ins) {
            if (esc)
                esc = 0;
            else if (c == '\\')
                esc = 1;
            else if (c == '"')
                ins = 0;
        } else if (c == '"') {
            ins = 1;
        } else if (c == '(') {
            depth++;
        } else if (c == ')') {
            depth--;
        }
        j++;
    }
    if (depth != 0)
        return 1;
    *end = j;
    return 0;
}

/* Splits the first ten quoted strings of spec[0..n) into the row fields. The
 * shell original joined them with tabs and re-split with IFS=tab read, which
 * collapses runs of tabs: an empty field vanishes and the later ones shift
 * left. Kept byte-for-byte, so empty strings are skipped, not stored. */
static int hsi_fields(const char *s, size_t n, struct hsi_row *r)
{
    char *dst[10] = { r->id, r->source, r->headers, r->contract, r->imports,
                      r->abi, r->schema, r->wire, r->kat, r->probe };
    const size_t sizes[10] = { HSI_FLD, HSI_SRC, HSI_BIG, HSI_BIG, HSI_BIG,
                               HSI_FLD, HSI_FLD, HSI_FLD, HSI_FLD, HSI_FLD };
    int f = 0, q = 0;
    size_t i = 0;
    while (i < n && q < 10) {
        if (s[i] == '"') {
            size_t k = i + 1;
            while (k < n && s[k] != '"')
                k++;
            if (k >= n)
                break;
            size_t len = k - i - 1;
            const char *st = s + i + 1;
            q++;
            i = k + 1;
            if (!len)
                continue;
            if (len >= sizes[f]) {
                fprintf(stderr, "%s: manifest field exceeds %zu bytes\n",
                        k_hsi_gate, sizes[f] - 1);
                return 2;
            }
            memcpy(dst[f], st, len);
            dst[f][len] = '\0';
            f++;
        } else {
            i++;
        }
    }
    for (; f < 10; f++)
        dst[f][0] = '\0';
    return 0;
}

/* Extracts every line-start HOTSWAP_SERVICE(...) macro body into rows. */
int hsi_parse_manifest(const char *b, size_t n, struct hsi_row *rows,
                              int cap, int *count)
{
    static const char tok[] = "HOTSWAP_SERVICE(";
    const size_t tl = sizeof tok - 1;
    *count = 0;
    size_t i = 0;
    while (i < n) {
        if ((i == 0 || b[i - 1] == '\n') && i + tl <= n &&
            strncmp(b + i, tok, tl) == 0) {
            if (*count >= cap) {
                fprintf(stderr, "%s: more than %d HOTSWAP_SERVICE rows\n",
                        k_hsi_gate, cap);
                return 2;
            }
            size_t end;
            if (hsi_close_paren(b, n, i + tl, &end)) {
                fprintf(stderr,
                        "%s: unterminated HOTSWAP_SERVICE( at byte %zu\n",
                        k_hsi_gate, i);
                return 2;
            }
            if (hsi_fields(b + i + tl, end - (i + tl) - 1, &rows[*count]))
                return 2;
            (*count)++;
            i = end;
            continue;
        }
        i++;
    }
    return 0;
}

static int hsi_pair_over(size_t cap)
{
    fprintf(stderr, "%s: manifest field exceeds %zu bytes\n", k_hsi_gate,
            cap - 1);
    return 2;
}

/* Collects quoted fields of one line into the pending pair slots; 2 when a
 * field overflows its slot (never truncated silently). */
static int hsi_pair_take(struct hsi_pair *cur, int *cnt, const char *s,
                          size_t ll)
{
    size_t j = 0;
    while (j < ll) {
        if (s[j] != '"') {
            j++;
            continue;
        }
        size_t k = j + 1;
        while (k < ll && s[k] != '"')
            k++;
        if (k >= ll)
            break;
        size_t len = k - j - 1;
        if (*cnt == 0) {
            if (len >= HSI_SRC)
                return hsi_pair_over(HSI_SRC);
            memcpy(cur->a, s + j + 1, len);
            cur->a[len] = '\0';
        } else if (*cnt == 1) {
            if (len >= HSI_BIG)
                return hsi_pair_over(HSI_BIG);
            memcpy(cur->b, s + j + 1, len);
            cur->b[len] = '\0';
        }
        (*cnt)++;
        j = k + 1;
    }
    return 0;
}

/* Handles one line of the marker stream; emits a pair once both fields are
 * seen (mirrors the awk pass). */
static int hsi_pair_line(const char *s, size_t ll, const char *marker,
                         size_t ml, struct hsi_pair *cur, int *act, int *cnt,
                         struct hsi_pair *out, int cap, int *count)
{
    if (ll >= ml && strncmp(s, marker, ml) == 0) {
        *act = 1;
        *cnt = 0;
        cur->a[0] = cur->b[0] = '\0';
    }
    if (!*act)
        return 0;
    if (hsi_pair_take(cur, cnt, s, ll))
        return 2;
    if (*cnt < 2)
        return 0;
    if (*count >= cap) {
        fprintf(stderr, "%s: more than %d %s rows\n", k_hsi_gate, cap,
                marker);
        return 2;
    }
    out[(*count)++] = *cur;
    *act = 0;
    return 0;
}

/* Extracts MARKER(...) rows: the first two quoted strings collected from the
 * marker line onward, stopping once both are seen. */
int hsi_parse_pairs(const char *b, size_t n, const char *marker,
                           struct hsi_pair *out, int cap, int *count)
{
    const size_t ml = strlen(marker);
    *count = 0;
    size_t i = 0;
    int act = 0, cnt = 0;
    struct hsi_pair cur;
    cur.a[0] = cur.b[0] = '\0';
    while (i <= n) {
        size_t end = i;
        while (end < n && b[end] != '\n')
            end++;
        int eol = end == n;
        if (!eol || i < n)
            if (hsi_pair_line(b + i, end - i, marker, ml, &cur, &act, &cnt,
                              out, cap, count))
                return 2;
        if (eol)
            break;
        i = end + 1;
    }
    return 0;
}
