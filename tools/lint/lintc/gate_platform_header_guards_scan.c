// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// purpose: conditional-depth scanner for check-platform-header-guards.
// Ported from the scan.awk program of tools/lint/check_platform_header_guards.sh
// (deleted). Tracks a stack of #if/#ifdef/#elif frames per file, inverts a
// frame on #else, strips comments, joins backslash continuations, and emits
// one record per angle-bracket include to a callback.

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_platform_header_guards_priv.h"

enum { PHG_DEP = 32, PHG_TOK = 256, PHG_JOIN = 2 * PHG_LINE };

static const char k_phgs_gate[] = "check-platform-header-guards";

struct phg_st {
    int incomment, depth, pending;
    int inelse[PHG_DEP];
    char ctok[PHG_DEP][PHG_TOK], etok[PHG_DEP][PHG_TOK];
    char craw[PHG_DEP][PHG_TOK];
    char pend[PHG_JOIN];
    const char *rel;
    long lineno;
    phg_inc_fn fn;
    void *ctx;
    struct phg_inc inc;
};

// Strip block comments (state across lines) and cut at a line comment.
static void phg_cstrip(struct phg_st *s, const char *in, char *out)
{
    size_t i = 0, o = 0, n = strlen(in);
    while (i < n) {
        if (s->incomment) {
            if (i + 1 < n && in[i] == '*' && in[i + 1] == '/') {
                s->incomment = 0;
                i += 2;
            } else {
                i++;
            }
        } else if (i + 1 < n && in[i] == '/' && in[i + 1] == '*') {
            s->incomment = 1;
            i += 2;
        } else if (i + 1 < n && in[i] == '/' && in[i + 1] == '/') {
            break;
        } else {
            out[o++] = in[i++];
        }
    }
    out[o] = '\0';
}

// Every identifier in cond, space fenced: " A B ". -1 on overflow.
static int phg_tokens_of(const char *cond, char *out, size_t cap)
{
    size_t o = 0, i = 0;
    int sp = 1;
    out[o++] = ' ';
    for (; cond[i]; i++) {
        unsigned char c = (unsigned char)cond[i];
        if (isalnum(c) || c == '_') {
            if (o + 2 >= cap)
                return -1;
            out[o++] = (char)c;
            sp = 0;
        } else if (!sp) {
            if (o + 3 >= cap)
                return -1;
            out[o++] = ' ';
            sp = 1;
        }
    }
    if (sp && o > 1)
        o--;
    out[o++] = ' ';
    out[o] = '\0';
    return 0;
}

// Whitespace removed entirely.
static int phg_squeeze(const char *src, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; src[i]; i++)
        if (src[i] != ' ' && src[i] != '\t') {
            if (o + 1 >= cap)
                return -1;
            out[o++] = src[i];
        }
    out[o] = '\0';
    return 0;
}

static const char *phg_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

// Copy the identifier at p into mac; its length, 0 when none or too long.
static size_t phg_ident(const char *p, char *mac, size_t cap)
{
    size_t n = 0;
    if (!(isalpha((unsigned char)p[0]) || p[0] == '_'))
        return 0;
    while (isalnum((unsigned char)p[n]) || p[n] == '_') {
        if (n + 1 >= cap)
            return 0;
        mac[n] = p[n];
        n++;
    }
    mac[n] = '\0';
    return n;
}

// Does conj claim a macro in the #else branch? Only the exact negation
// shapes "!defined(X)", "!defined X", "!X" (after outer-paren stripping).
static int phg_conj_claim(const char *cj, char *mac, size_t cap)
{
    const char *p = phg_ws(cj);
    if (*p != '!')
        return 0;
    p = phg_ws(p + 1);
    if (!strncmp(p, "defined", 7))
        p = phg_ws(p + 7);
    int paren = *p == '(';
    if (paren)
        p = phg_ws(p + 1);
    size_t n = phg_ident(p, mac, cap);
    if (n == 0)
        return 0;
    p = phg_ws(p + n);
    if (paren) {
        if (*p != ')')
            return 0;
        p = phg_ws(p + 1);
    }
    return *p == '\0';
}

static void phg_trim_ws(char *s)
{
    const char *p = phg_ws(s);
    size_t q = strlen(p);
    while (q && (p[q - 1] == ' ' || p[q - 1] == '\t'))
        q--;
    memmove(s, p, q);
    s[q] = '\0';
}

// Flush one top-level && conjunct: trim, strip outer parens, maybe claim.
static int phg_conj_flush(const char *seg, size_t len, char *out)
{
    char cj[PHG_TOK], mac[64];
    if (len >= sizeof cj)
        return 0;
    memcpy(cj, seg, len);
    cj[len] = '\0';
    phg_trim_ws(cj);
    for (size_t n = strlen(cj); n >= 2 && cj[0] == '(' && cj[n - 1] == ')';
         n = strlen(cj)) {
        memmove(cj, cj + 1, n - 2);
        cj[n - 2] = '\0';
        phg_trim_ws(cj);
    }
    if (!phg_conj_claim(cj, mac, sizeof mac))
        return 0;
    size_t o = strlen(out);
    if (o + strlen(mac) + 3 > PHG_TOK)
        return -1;
    strcat(out, mac);
    strcat(out, " ");
    return 0;
}

// Macros an #else of this condition may claim (" X " form, or " ").
static int phg_else_tokens(const char *cond, char *out)
{
    strcpy(out, " ");
    size_t i = 0, n = strlen(cond), start = 0;
    int d = 0;
    while (i <= n) {
        if (i == n || (d == 0 && cond[i] == '&' && cond[i + 1] == '&')) {
            int rc = phg_conj_flush(cond + start, i - start, out);
            if (rc)
                return rc == -1 ? -1 : 0;
            if (i == n)
                return 0;
            start = i + 2;
            i += 2;
            continue;
        }
        if (cond[i] == '(')
            d++;
        else if (cond[i] == ')')
            d--;
        i++;
    }
    return 0;
}

// Push or replace the top frame. replace = 1 for #elif.
static int phg_frame(struct phg_st *s, const char *ctok, const char *etok,
                     const char *craw, int replace)
{
    int i = replace && s->depth > 0 ? s->depth - 1 : s->depth;
    if (i >= PHG_DEP) {
        fprintf(stderr, "%s: conditional depth exceeds %d in %s\n",
                k_phgs_gate, PHG_DEP, s->rel);
        return 2;
    }
    if (strlen(ctok) >= PHG_TOK || strlen(etok) >= PHG_TOK ||
        strlen(craw) >= PHG_TOK)
        return 2;
    strcpy(s->ctok[i], ctok);
    strcpy(s->etok[i], etok);
    strcpy(s->craw[i], craw);
    if (!replace) {
        s->inelse[s->depth] = 0;
        s->depth++;
    } else {
        s->inelse[i] = 0;
    }
    return 0;
}

static int phg_hit(const char *d, const char *kw, const char *sep)
{
    size_t n = strlen(kw);
    if (strncmp(d, kw, n) != 0)
        return 0;
    return d[n] == '\0' || strchr(sep, d[n]) != NULL;
}

// #include <H>: extract the header into inc.hdr. 1 when one was found.
static int phg_parse_hdr(struct phg_st *s, const char *d)
{
    d = phg_ws(d);
    if (*d != '<')
        return 0;
    const char *e = strchr(d + 1, '>');
    if (!e)
        return 0;
    size_t n = (size_t)(e - d - 1);
    while (n && (d[n] == ' ' || d[n] == '\t'))
        n--;
    if (n == 0 || n >= sizeof s->inc.hdr)
        return 0;
    memcpy(s->inc.hdr, d + 1, n);
    s->inc.hdr[n] = '\0';
    return 1;
}

// Concatenate the active token (and raw text) of every open frame.
static int phg_join_frames(const struct phg_st *s, char *act, size_t acap,
                           char *raw, size_t rcap)
{
    size_t ao = 1, ro = 0;
    act[0] = ' ';
    for (int j = 0; j < s->depth; j++) {
        const char *t = s->inelse[j] ? s->etok[j] : s->ctok[j];
        const char *c = s->inelse[j] ? "" : s->craw[j];
        if (ao + strlen(t) + 1 >= acap || ro + strlen(c) + 2 >= rcap)
            return 2;
        strcpy(act + ao, t);
        ao += strlen(t);
        strcpy(raw + ro, c);
        ro += strlen(c);
        raw[ro++] = ' ';
    }
    act[ao] = '\0';
    raw[ro] = '\0';
    return 0;
}

// Collapse runs of spaces to one space (awk gsub), keeping the fences.
static int phg_collapse(const char *act, char *norm, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; act[i]; i++) {
        if (act[i] == ' ' && o && norm[o - 1] == ' ')
            continue;
        if (o + 1 >= cap)
            return 2;
        norm[o++] = act[i];
    }
    norm[o] = '\0';
    return 0;
}

static int phg_do_include(struct phg_st *s, const char *d)
{
    char act[2048], raw[2048], norm[1024];
    if (!phg_parse_hdr(s, d))
        return 0;
    if (phg_join_frames(s, act, sizeof act, raw, sizeof raw) ||
        phg_collapse(act, norm, sizeof norm))
        return 2;
    if (strlen(norm) >= sizeof s->inc.act || strlen(raw) >= sizeof s->inc.raw)
        return 2;
    strcpy(s->inc.act, norm);
    strcpy(s->inc.raw, raw);
    s->inc.file = s->rel;
    s->inc.ln = s->lineno;
    return s->fn(&s->inc, s->ctx);
}

// Trimmed macro text m: tok = " m ", raw = m. Non-zero when too long.
static int phg_macro_of(const char *src, char *tok, char *raw, size_t cap)
{
    while (*src == ' ' || *src == '\t')
        src++;
    size_t n = strlen(src);
    while (n && (src[n - 1] == ' ' || src[n - 1] == '\t'))
        n--;
    if (n + 3 > cap)
        return 1;
    tok[0] = ' ';
    memcpy(tok + 1, src, n);
    tok[n + 1] = ' ';
    tok[n + 2] = '\0';
    memcpy(raw, src, n);
    raw[n] = '\0';
    return 0;
}

// #if / #elif body m: tokens, squeezed raw, else-tokens, then the frame.
static int phg_dir_if(struct phg_st *s, const char *m, int replace)
{
    char tok[PHG_TOK], etok[PHG_TOK], craw[PHG_TOK];
    if (phg_tokens_of(m, tok, sizeof tok) ||
        phg_squeeze(m, craw, sizeof craw) || phg_else_tokens(m, etok))
        return 2;
    return phg_frame(s, tok, etok, craw, replace);
}

// Conditional openers; -1 when d is none of them.
static int phg_dir_cond(struct phg_st *s, const char *d)
{
    char mac[PHG_TOK], craw[PHG_TOK];
    if (phg_hit(d, "ifdef", " \t")) {
        if (phg_macro_of(d + 5, mac, craw, sizeof mac))
            return 2;
        return phg_frame(s, mac, " ", craw, 0);
    }
    if (phg_hit(d, "ifndef", " \t")) {
        if (phg_macro_of(d + 6, mac, craw, sizeof mac))
            return 2;
        return phg_frame(s, " ", mac, "", 0);
    }
    if (phg_hit(d, "if", " \t(!"))
        return phg_dir_if(s, d + 2, 0);
    if (phg_hit(d, "elif", " \t(!"))
        return phg_dir_if(s, d + 4, 1);
    return -1;
}

static int phg_directive(struct phg_st *s, const char *d)
{
    int rc = phg_dir_cond(s, d);
    if (rc >= 0)
        return rc;
    if (phg_hit(d, "else", " \t")) {
        if (s->depth > 0)
            s->inelse[s->depth - 1] = 1;
        return 0;
    }
    if (phg_hit(d, "endif", " \t")) {
        if (s->depth > 0)
            s->depth--;
        return 0;
    }
    if (phg_hit(d, "include", " \t"))
        return phg_do_include(s, d + 7);
    return 0;
}

// Comment-strip one raw line into code. 1 when the line cannot matter.
static int phg_code(struct phg_st *s, const char *in, char *code)
{
    if (s->pending || s->incomment || strchr(in, '/') || strchr(in, '*')) {
        phg_cstrip(s, in, code);
        return 0;
    }
    if (*phg_ws(in) != '#')
        return 1;
    snprintf(code, PHG_LINE, "%s", in);
    return 0;
}

// Backslash continuation: 0 = line complete in *base, 1 = more to come,
// 2 = overflow.
static int phg_join(struct phg_st *s, char *code, char **base)
{
    *base = code;
    if (s->pending) {
        if (strlen(s->pend) + strlen(code) + 2 > sizeof s->pend)
            return 2;
        strcat(s->pend, " ");
        strcat(s->pend, code);
        *base = s->pend;
    }
    char *b = *base;
    size_t n = strlen(b);
    while (n && (b[n - 1] == ' ' || b[n - 1] == '\t'))
        n--;
    if (n && b[n - 1] == '\\') {
        b[n - 1] = '\0';
        if (!s->pending)
            snprintf(s->pend, sizeof s->pend, "%s", b);
        s->pending = 1;
        return 1;
    }
    s->pending = 0;
    return 0;
}

// One raw input line: comment strip, continuation join, then directives.
static int phg_line(struct phg_st *s, const char *in)
{
    char code[PHG_LINE], *base;
    if (phg_code(s, in, code))
        return 0;
    int j = phg_join(s, code, &base);
    if (j)
        return j == 1 ? 0 : 2;
    const char *p = phg_ws(base);
    if (*p != '#')
        return 0;
    return phg_directive(s, phg_ws(p + 1));
}

static int phg_cb(void *ctx, const char *line, size_t len)
{
    struct phg_st *s = ctx;
    char raw[PHG_LINE];
    s->lineno++;
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len >= sizeof raw) {
        fprintf(stderr, "%s: line %ld of %s exceeds %d bytes\n", k_phgs_gate,
                s->lineno, s->rel, PHG_LINE);
        return 2;
    }
    memcpy(raw, line, len);
    raw[len] = '\0';
    return phg_line(s, raw);
}

int phg_scan_file(const char *path, const char *rel, phg_inc_fn fn, void *ctx)
{
    struct phg_st s;
    memset(&s, 0, sizeof s);
    s.rel = rel;
    s.fn = fn;
    s.ctx = ctx;
    int rc = lc_each_line(path, phg_cb, &s, 1);
    if (rc == 1)
        return 1;
    if (rc)
        return 2;
    return 0;
}
