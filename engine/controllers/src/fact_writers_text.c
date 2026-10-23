/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Source-text primitives for the writer census: the whole-file + line cache, the
 * string-valued macro table, adjacent string-literal joining, call-argument
 * extraction, and key resolution. Every one of these reads bytes out of the
 * checkout and holds nothing between runs — the census is a pure function of the
 * tree, and this is the half that does the reading.
 *
 * See fact_writers_priv.h for the contracts and fact_writers.c for the census.
 */

#define _GNU_SOURCE
#include "fact_writers_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── small text helpers ─────────────────────────────────────────────────── */


bool fw_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* Skip leading whitespace (any byte <= ' '); returns the first other byte. */
static const char *fw_skip_blank(const char *p)
{
    while (*p && (unsigned char)*p <= ' ') p++;
    return p;
}

/* Word-boundary substring search. Returns the offset, or -1. */
long fw_find_word(const char *hay, const char *needle, long from)
{
    size_t nl = strlen(needle);
    if (nl == 0) return -1; // raw-return-ok:not-found-sentinel
    for (const char *p = hay + from; (p = strstr(p, needle)) != NULL; p++) {
        long off = (long)(p - hay);
        if (off > 0 && fw_ident_char(hay[off - 1])) continue;
        if (fw_ident_char(p[nl])) continue;
        return off;
    }
    return -1; // raw-return-ok:not-found-sentinel
}

void fw_trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (unsigned char)s[n - 1] <= ' ') s[--n] = '\0';
    size_t i = 0;
    while (s[i] && (unsigned char)s[i] <= ' ') i++;
    if (i) memmove(s, s + i, n - i + 1);
}

/* A line whose first visible characters open or continue a comment. Codeindex
 * blanks comments before tokenising, so its refs should already exclude these;
 * this is a belt-and-braces guard whose skip count is reported. */
bool fw_comment_line(const char *line)
{
    while (*line && (unsigned char)*line <= ' ') line++;
    return line[0] == '*' ||
           (line[0] == '/' && (line[1] == '/' || line[1] == '*'));
}

/* ── file cache: whole content + line offsets ───────────────────────────── */

void fw_file_free(struct fw_file *f)
{
    if (!f) return;
    free(f->buf);
    free(f->line_off);
    f->buf = NULL;
    f->line_off = NULL;
    f->len = f->nlines = 0;
}

bool fw_file_load_unindexed(const char *root, const char *rel,
                            struct fw_file *out)
{
    memset(out, 0, sizeof(*out));
    char full[FACT_PATH_MAX + 512];
    if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full))
        LOG_FAIL(FW_DOMAIN, "path too long: %s", rel);
    FILE *fp = fopen(full, "rb");
    if (!fp) return false;   /* absent file is not an error for the census */
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return false; }
    long sz = ftell(fp);
    if (sz < 0 || sz > (long)(24 * 1024 * 1024)) { fclose(fp); return false; }
    rewind(fp);
    char *buf = zcl_malloc((size_t)sz + 1, "fw_file");
    if (!buf) { fclose(fp); LOG_FAIL(FW_DOMAIN, "alloc %ld", sz); }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';
    out->buf = buf;
    out->len = got;
    return true;
}

bool fw_file_index_lines(struct fw_file *out)
{
    if (!out || !out->buf) return false;
    if (out->line_off) return true;
    /* Index line starts. */
    size_t cap = 256, n = 0;
    size_t *off = zcl_malloc(cap * sizeof(*off), "fw_lines");
    if (!off) LOG_FAIL(FW_DOMAIN, "alloc lines");
    off[n++] = 0;
    for (size_t i = 0; i < out->len; i++) {
        if (out->buf[i] != '\n') continue;
        if (n == cap) {
            size_t ncap = cap * 2;
            size_t *nb = zcl_realloc(off, ncap * sizeof(*off), "fw_lines");
            if (!nb) { free(off); LOG_FAIL(FW_DOMAIN, "grow lines"); }
            off = nb;
            cap = ncap;
        }
        off[n++] = i + 1;
    }
    out->line_off = off;
    out->nlines = n;
    return true;
}

bool fw_file_load(const char *root, const char *rel, struct fw_file *out)
{
    if (!fw_file_load_unindexed(root, rel, out)) return false;
    if (fw_file_index_lines(out)) return true;
    fw_file_free(out);
    return false;
}

/* Copy line `lineno` (1-based) into dst[cap], sans newline. "" when absent. */
void fw_file_line(const struct fw_file *f, size_t lineno,
                         char *dst, size_t cap)
{
    dst[0] = '\0';
    if (lineno == 0 || lineno > f->nlines) return;
    size_t s = f->line_off[lineno - 1];
    size_t e = (lineno < f->nlines) ? f->line_off[lineno] : f->len;
    while (e > s && (f->buf[e - 1] == '\n' || f->buf[e - 1] == '\r')) e--;
    size_t n = e - s;
    if (n > cap - 1) n = cap - 1;
    memcpy(dst, f->buf + s, n);
    dst[n] = '\0';
}

/* ── string-valued macro table ──────────────────────────────────────────── */


static bool fw_macros_push(struct fw_macros *m, const char *name,
                           const char *value)
{
    if (m->n == m->cap) {
        size_t ncap = m->cap ? m->cap * 2 : 512;
        struct fw_macro *nb = zcl_realloc(m->v, ncap * sizeof(*nb), "fw_macros");
        if (!nb) LOG_FAIL(FW_DOMAIN, "grow macro table");
        m->v = nb;
        m->cap = ncap;
    }
    snprintf(m->v[m->n].name, sizeof(m->v[m->n].name), "%s", name);
    snprintf(m->v[m->n].value, sizeof(m->v[m->n].value), "%s", value);
    m->n++;
    return true;
}

const char *fw_macro_lookup(const struct fw_macros *m, const char *name)
{
    for (size_t i = 0; i < m->n; i++)
        if (strcmp(m->v[i].name, name) == 0) return m->v[i].value;
    return NULL;
}

/* Append the body of a string literal (`p` is just past its opening quote) to
 * out[*o], decoding the common escapes. Returns the byte after the closing quote. */
static const char *fw_join_quoted(const char *p, char *out, size_t cap,
                                  size_t *o)
{
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            /* keep common escapes readable; drop the rest */
            char c = p[1];
            char decoded = (c == 'n') ? '\n' : (c == 't') ? '\t' : c;
            if (*o + 1 < cap) out[(*o)++] = decoded;
            p += 2;
            continue;
        }
        if (*o + 1 < cap) out[(*o)++] = *p;
        p++;
    }
    if (*p == '"') p++;
    return p;
}

/* Append the string value of the macro named at `p` to out[*o]. Returns the
 * byte after the name, or NULL when no string-valued macro has that name. */
static const char *fw_join_macro(const char *p, const struct fw_macros *m,
                                 char *out, size_t cap, size_t *o)
{
    char id[FW_MACRO_NAME_MAX];
    size_t k = 0;
    const char *q = p;
    while (fw_ident_char(*q) && k + 1 < sizeof(id)) id[k++] = *q++;
    id[k] = '\0';
    const char *val = fw_macro_lookup(m, id);
    if (!val) return NULL;
    for (const char *v = val; *v; v++)
        if (*o + 1 < cap) out[(*o)++] = *v;
    return q;
}

/* Concatenate the adjacent string-literal pieces starting at `p` (which must
 * point at the opening quote), resolving an interleaved string-valued macro
 * identifier. Returns the byte after the last consumed piece. */
const char *fw_join_literals(const char *p, const struct fw_macros *m,
                                    char *out, size_t cap)
{
    size_t o = 0;
    out[0] = '\0';
    for (;;) {
        p = fw_skip_blank(p);
        if (*p == '"') {
            p = fw_join_quoted(p + 1, out, cap, &o);
            continue;
        }
        if (m && fw_ident_char(*p) && !(*p >= '0' && *p <= '9')) {
            const char *q = fw_join_macro(p, m, out, cap, &o);
            if (!q) break;
            p = q;
            continue;
        }
        break;
    }
    out[o < cap ? o : cap - 1] = '\0';
    return p;
}

/* Locate the value of a `#define NAME "…"` line. Stores NAME in name[cap] and
 * returns the opening quote of the value, or NULL when the line is not an
 * object-like define with a string-literal value. */
static const char *fw_define_value(const char *line, char *name, size_t cap)
{
    const char *p = fw_skip_blank(line);
    if (*p != '#') return NULL;
    p = fw_skip_blank(p + 1);
    if (strncmp(p, "define", 6) != 0 || fw_ident_char(p[6])) return NULL;
    p = fw_skip_blank(p + 6);
    size_t k = 0;
    while (fw_ident_char(*p) && k + 1 < cap) name[k++] = *p++;
    name[k] = '\0';
    if (k == 0 || *p == '(') return NULL;   /* function-like macro */
    p = fw_skip_blank(p);
    return (*p == '"') ? p : NULL;
}

/* Record one source line if it is a string-valued macro definition. Returns
 * false only when the macro table cannot grow; a non-matching line is true. */
static bool fw_collect_line(const char *line, struct fw_macros *m)
{
    char name[FW_MACRO_NAME_MAX];
    const char *p = fw_define_value(line, name, sizeof(name));
    if (!p) return true;
    char value[FACT_KEY_MAX];
    (void)fw_join_literals(p, m, value, sizeof(value));
    if (value[0] == '\0') return true;
    return fw_macros_push(m, name, value);
}

/* Harvest `#define NAME "…"` (including adjacent-literal concatenations) from
 * one loaded file. Macro VALUES may themselves reference earlier macros; that
 * one indirection is resolved because the table is consulted as it grows. */
bool fw_collect_macros(const struct fw_file *f, struct fw_macros *m)
{
    if (!f || !f->buf) return false;
    char line[1024];
    const char *at = f->buf;
    const char *end = f->buf + f->len;
    while (at < end) {
        const char *nl = memchr(at, '\n', (size_t)(end - at));
        const char *line_end = nl ? nl : end;
        size_t line_len = (size_t)(line_end - at);
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        memcpy(line, at, line_len);
        line[line_len] = '\0';
        at = nl ? nl + 1 : end;
        if (!fw_collect_line(line, m)) return false;
    }
    return true;
}

/* ── call-argument extraction ───────────────────────────────────────────── */

/* Join up to FW_LINE_JOIN raw lines from `lineno` so a call split over lines is
 * one string. Stops early once parenthesis depth returns to zero. */
void fw_join_call(const struct fw_file *f, size_t lineno,
                         char *out, size_t cap)
{
    out[0] = '\0';
    size_t o = 0;
    int depth = 0;
    bool seen_open = false;
    for (size_t i = 0; i < FW_LINE_JOIN && lineno + i <= f->nlines; i++) {
        char line[1024];
        fw_file_line(f, lineno + i, line, sizeof(line));
        for (const char *p = line; *p; p++) {
            if (o + 2 < cap) out[o++] = *p;
            if (*p == '(') { depth++; seen_open = true; }
            else if (*p == ')') depth--;
        }
        if (o + 2 < cap) out[o++] = ' ';
        out[o] = '\0';
        if (seen_open && depth <= 0) break;
    }
    out[o < cap ? o : cap - 1] = '\0';
}

/* Skip a string or character literal. `p` is just past the opening quote `q`;
 * returns the closing quote, or the NUL that ends the text. */
static const char *fw_skip_literal(const char *p, char q)
{
    while (*p && *p != q) {
        if (*p == '\\' && p[1]) p++;
        p++;
    }
    return p;
}

/* Pointer just past the '(' of the first `fn(` call in `text`, or NULL. */
static const char *fw_call_open(const char *text, const char *fn)
{
    long at = fw_find_word(text, fn, 0);
    if (at < 0) return NULL;
    const char *p = fw_skip_blank(text + at + strlen(fn));
    if (*p != '(') return NULL;
    return p + 1;
}

/* Find the byte range [*start, *end) of argument `idx` in the argument list
 * beginning at `p` (just past the call's '('). False when that argument is
 * absent; the range is still set to where the scan stopped. */
static bool fw_call_arg_range(const char *p, int idx, const char **start,
                              const char **end)
{
    int depth = 1, arg = 0;
    *start = p;
    for (; *p; p++) {
        if (*p == '"' || *p == '\'') {
            p = fw_skip_literal(p + 1, *p);
            if (!*p) break;
            continue;
        }
        if (*p == '(' || *p == '[') depth++;
        else if (*p == ')' || *p == ']') {
            if (--depth == 0) break;
        } else if (*p == ',' && depth == 1) {
            if (arg == idx) break;
            arg++;
            *start = p + 1;
        }
    }
    *end = p;
    return arg == idx;
}

/* Extract argument `idx` (0-based) of the first `fn(` call in `text`.
 * Returns false when the call or the argument is not present. */
bool fw_call_arg(const char *text, const char *fn, int idx,
                        char *out, size_t cap)
{
    const char *p = fw_call_open(text, fn);
    if (!p) return false;
    const char *start = NULL, *end = NULL;
    if (!fw_call_arg_range(p, idx, &start, &end)) return false;
    size_t n = (size_t)(end - start);
    if (n > cap - 1) n = cap - 1;
    memcpy(out, start, n);
    out[n] = '\0';
    fw_trim(out);
    return out[0] != '\0';
}

/* Resolve an argument's source text to the key string it denotes. */
bool fw_resolve_key(const char *argtext, const struct fw_macros *m,
                           char *out, size_t cap)
{
    out[0] = '\0';
    if (argtext[0] == '"') {
        (void)fw_join_literals(argtext, m, out, cap);
        return out[0] != '\0';
    }
    /* a bare identifier: a string-valued macro, else unresolvable */
    for (const char *p = argtext; *p; p++)
        if (!fw_ident_char(*p)) return false;
    const char *val = fw_macro_lookup(m, argtext);
    if (!val) return false;
    snprintf(out, cap, "%s", val);
    return true;
}

bool fw_key_plausible(const char *key)
{
    size_t n = strlen(key);
    if (n == 0 || n >= FACT_KEY_MAX) return false;
    for (const char *p = key; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= ' ' || c == '%' || c == '?' || c == '\'' || c == '"' ||
            c == '(' || c == ')' || c == ',' || c == '=' || c == '*')
            return false;
        if (c > 126) return false;
    }
    return true;
}

/* True when the parameter text in [start, start + n) is a `const char *`. */
static bool fw_param_is_str(const char *start, size_t n)
{
    char one[256];
    if (n >= sizeof(one)) n = sizeof(one) - 1;
    memcpy(one, start, n);
    one[n] = '\0';
    return strstr(one, "const char *") || strstr(one, "const char*");
}

int fw_key_param_index(const char *decl)
{
    const char *open = strchr(decl, '(');
    if (!open) return -1; // raw-return-ok:no-param-list
    int idx = 0, depth = 1;
    const char *start = open + 1;
    for (const char *p = start;; p++) {
        bool end = (*p == '\0');
        if (*p == '(' || *p == '[') { depth++; continue; }
        if (*p == ')' || *p == ']') {
            depth--;
            if (depth > 0) continue;
        }
        if (end || (*p == ',' && depth == 1) || depth == 0) {
            if (fw_param_is_str(start, (size_t)(p - start)))
                return idx;
            if (end || depth == 0) return -1; // raw-return-ok:no-keyed-param
            idx++;
            start = p + 1;
        }
    }
}

/* Walk back from `ln` to the nearest function definition opening at column 0,
 * and register it as this file's keyed write entry point for `sr`. */
