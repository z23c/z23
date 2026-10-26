/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-split-preserved of the C23 lint runtime, the
 * lexical half. Reads one C text into the facts a behaviour-preserving
 * refactor (a complexity split or a duplicate removal) must keep: comment
 * lines, LOG_*( calls with their containing function, include lines and the
 * licence header. A single pass blanks comments and flags string and char
 * literals, so comment-like text inside a string is never a comment and a
 * brace or LOG_ name inside a string never counts. Functions are the
 * depth-0 brace groups whose declaration holds a name followed by '('.
 * The comparison and the CLI are gate_split_preserved_check.c; the
 * selftest is gate_split_preserved_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "gate_split_preserved_priv.h"

static int sp_isid(int c)
{
    return isalnum((unsigned char)c) || c == '_';
}

static char *sp_dup(const char *s, size_t n)
{
    char *p = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (p) {
        memcpy(p, s, n);
        p[n] = '\0';
    }
    return p;
}

/* Appends a fact, taking ownership of key and func (func may be NULL). */
static void sp_add(struct sp_list *l, char *key, char *func, unsigned line, size_t off)
{
    if (!key || l->err) {
        free(key);
        free(func);
        l->err = 1;
        return;
    }
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 32;
        struct sp_ent *nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv) {
            free(key);
            free(func);
            l->err = 1;
            return;
        }
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n++] = (struct sp_ent){ key, func, line, off, 0 };
}

/* s[a..b) with every whitespace run outside a literal collapsed to one space
 * and the ends trimmed. */
static char *sp_norm(const char *s, const unsigned char *lit, size_t a, size_t b)
{
    char *o = malloc(b - a + 1); // raw-alloc-ok:lint-runtime
    size_t k = 0;
    int gap = 0;
    for (size_t i = a; o && i < b; i++) {
        if (!lit[i] && isspace((unsigned char)s[i])) {
            gap = 1;
            continue;
        }
        if (gap && k)
            o[k++] = ' ';
        gap = 0;
        o[k++] = s[i];
    }
    if (o)
        o[k] = '\0';
    return o;
}

/* ---- lexer: comments and literals ---- */

struct sp_lex {
    struct sp_file *f;
    const char *s;
    size_t n, i;
    unsigned line;
};

static void sp_emit_comment(struct sp_lex *lx, size_t a, size_t b, unsigned line)
{
    while (a < b && isspace((unsigned char)lx->s[a]))
        a++;
    while (b > a && isspace((unsigned char)lx->s[b - 1]))
        b--;
    if (b > a)
        sp_add(&lx->f->cm, sp_dup(lx->s + a, b - a), NULL, line, a);
}

static int sp_continued(const char *s, size_t i)
{
    return (i > 0 && s[i - 1] == '\\') || (i > 1 && s[i - 1] == '\r' && s[i - 2] == '\\');
}

static int sp_comment_ends(const struct sp_lex *lx, int block)
{
    if (block)
        return lx->s[lx->i] == '*' && lx->i + 1 < lx->n && lx->s[lx->i + 1] == '/';
    return lx->s[lx->i] == '\n' && !sp_continued(lx->s, lx->i);
}

/* At a comment opener: blanks the comment in code and records one trimmed
 * fact per source line it covers (a block's last line includes the closer). */
static void sp_comment(struct sp_lex *lx, int block)
{
    char *code = lx->f->code;
    size_t seg = lx->i;
    unsigned segline = lx->line;
    code[lx->i] = code[lx->i + 1] = ' ';
    lx->i += 2;
    while (lx->i < lx->n && !sp_comment_ends(lx, block)) {
        if (lx->s[lx->i] == '\n') {
            sp_emit_comment(lx, seg, lx->i, segline);
            seg = lx->i + 1;
            segline = ++lx->line;
        } else {
            code[lx->i] = ' ';
        }
        lx->i++;
    }
    if (block && lx->i < lx->n) {
        code[lx->i] = code[lx->i + 1] = ' ';
        lx->i += 2;
    }
    sp_emit_comment(lx, seg, lx->i, segline);
}

/* At a quote: flags the whole literal, escapes included. An unterminated
 * literal ends at the newline. */
static void sp_quoted(struct sp_lex *lx, char q)
{
    unsigned char *lit = lx->f->lit;
    lit[lx->i++] = 1;
    while (lx->i < lx->n && lx->s[lx->i] != q && lx->s[lx->i] != '\n') {
        if (lx->s[lx->i] == '\\' && lx->i + 1 < lx->n && lx->s[lx->i + 1] != '\n')
            lit[lx->i++] = 1;
        lit[lx->i++] = 1;
    }
    if (lx->i < lx->n && lx->s[lx->i] == q)
        lit[lx->i++] = 1;
}

/* A C23 digit separator (1'000) is not a char literal: the quote follows a
 * token that starts with a digit. */
static int sp_digit_sep(const char *s, size_t i)
{
    size_t j = i;
    while (j > 0 && (sp_isid(s[j - 1]) || s[j - 1] == '\''))
        j--;
    return j < i && isdigit((unsigned char)s[j]);
}

static void sp_lex_all(struct sp_lex *lx)
{
    const char *s = lx->s;
    while (lx->i < lx->n) {
        char c = s[lx->i];
        char d = lx->i + 1 < lx->n ? s[lx->i + 1] : '\0';
        if (c == '/' && (d == '/' || d == '*'))
            sp_comment(lx, d == '*');
        else if (c == '"' || (c == '\'' && !sp_digit_sep(s, lx->i)))
            sp_quoted(lx, c);
        else {
            lx->line += c == '\n';
            lx->i++;
        }
    }
}

/* ---- functions ---- */

struct sp_sc {
    struct sp_file *f;
    size_t i, decl, from;
    long depth;
    char *name; /* the function being scanned, or NULL */
};

static size_t sp_next_line(const struct sp_file *f, size_t p)
{
    while (p < f->n && f->code[p] != '\n')
        p++;
    return p < f->n ? p + 1 : f->n;
}

static int sp_is_noise(const char *w, size_t n)
{
    static const char *const k_noise[] = { "__attribute__", "__attribute", "alignas",
                                           "_Alignas", "__declspec", "_Static_assert" };
    for (size_t i = 0; i < sizeof k_noise / sizeof k_noise[0]; i++) {
        if (strlen(k_noise[i]) == n && memcmp(k_noise[i], w, n) == 0)
            return 1;
    }
    return 0;
}

/* The last "name(" outside any parenthesis in a declaration, or NULL. */
static char *sp_decl_name(const char *d, size_t len)
{
    int depth = 0;
    const char *best = NULL;
    size_t bl = 0;
    for (size_t i = 0; i < len;) {
        if (isalpha((unsigned char)d[i]) || d[i] == '_') {
            size_t j = i, k;
            while (j < len && sp_isid(d[j]))
                j++;
            for (k = j; k < len && isspace((unsigned char)d[k]); k++)
                ;
            if (depth == 0 && k < len && d[k] == '(' && !sp_is_noise(d + i, j - i)) {
                best = d + i;
                bl = j - i;
            }
            i = j;
            continue;
        }
        depth += d[i] == '(';
        depth -= d[i] == ')' && depth > 0;
        i++;
    }
    return best ? sp_dup(best, bl) : NULL;
}

static void sp_span_add(struct sp_sc *sc, size_t to)
{
    struct sp_file *f = sc->f;
    if (f->nspan == f->capspan) {
        size_t nc = f->capspan ? f->capspan * 2 : 32;
        struct sp_span *nv = realloc(f->span, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv) {
            f->err = 1;
            free(sc->name);
            sc->name = NULL;
            return;
        }
        f->span = nv;
        f->capspan = nc;
    }
    f->span[f->nspan++] = (struct sp_span){ sc->name, sc->from, to };
    sc->name = NULL;
}

static void sp_sc_open(struct sp_sc *sc)
{
    if (sc->depth++ == 0)
        sc->name = sp_decl_name(sc->f->code + sc->decl, sc->i - sc->decl);
}

static void sp_sc_boundary(struct sp_sc *sc, size_t end)
{
    sc->decl = end;
    sc->from = sp_next_line(sc->f, end);
}

static void sp_sc_close(struct sp_sc *sc)
{
    if (sc->depth > 0 && --sc->depth == 0) {
        if (sc->name)
            sp_span_add(sc, sc->i + 1);
        sp_sc_boundary(sc, sc->i + 1);
    }
}

/* Skips a preprocessor line (continuations included). */
static void sp_sc_directive(struct sp_sc *sc)
{
    const struct sp_file *f = sc->f;
    while (sc->i < f->n && !(f->code[sc->i] == '\n' && !sp_continued(f->code, sc->i)))
        sc->i++;
    if (sc->depth == 0) {
        sc->decl = sc->i;
        sc->from = sp_next_line(f, sc->i);
    }
}

static void sp_sc_char(struct sp_sc *sc, char c)
{
    if (c == '{')
        sp_sc_open(sc);
    else if (c == '}')
        sp_sc_close(sc);
    else if (c == ';' && sc->depth == 0)
        sp_sc_boundary(sc, sc->i + 1);
}

static void sp_spans(struct sp_file *f)
{
    struct sp_sc sc = { .f = f };
    int bol = 1;
    for (; sc.i < f->n; sc.i++) {
        char c = f->code[sc.i];
        if (c != '\n' && isspace((unsigned char)c))
            continue;
        if (bol && c == '#' && !f->lit[sc.i])
            sp_sc_directive(&sc);
        else if (c != '\n' && !f->lit[sc.i])
            sp_sc_char(&sc, c);
        bol = f->code[sc.i] == '\n';
    }
    if (sc.name)
        sp_span_add(&sc, f->n);
}

static const char *sp_func_at(const struct sp_file *f, size_t off)
{
    for (size_t i = 0; i < f->nspan; i++) {
        if (off >= f->span[i].from && off < f->span[i].to)
            return f->span[i].name;
    }
    return "";
}

/* ---- LOG calls, includes, header ---- */

/* Index just past the ')' that closes the '(' at p, or n when unterminated. */
static size_t sp_call_end(const struct sp_file *f, size_t p)
{
    int depth = 0;
    for (; p < f->n; p++) {
        if (f->lit[p])
            continue;
        depth += f->code[p] == '(';
        depth -= f->code[p] == ')';
        if (depth == 0)
            return p + 1;
    }
    return f->n;
}

/* Length of the LOG_* name at i followed by '(', else 0. */
static size_t sp_log_name(const struct sp_file *f, size_t i, size_t *paren)
{
    size_t j = i, k;
    if (f->lit[i] || strncmp(f->code + i, "LOG_", 4) != 0 || (i > 0 && sp_isid(f->code[i - 1])))
        return 0;
    while (j < f->n && sp_isid(f->code[j]))
        j++;
    for (k = j; k < f->n && isspace((unsigned char)f->code[k]); k++)
        ;
    *paren = k;
    return k < f->n && f->code[k] == '(' ? j - i : 0;
}

static void sp_add_log(struct sp_file *f, size_t i, size_t end, unsigned line)
{
    char *call = sp_norm(f->code, f->lit, i, end);
    const char *fn = sp_func_at(f, i);
    size_t cl = call ? strlen(call) : 0;
    char *key = call ? malloc(strlen(fn) + cl + 2) : NULL; // raw-alloc-ok:lint-runtime
    if (key)
        sprintf(key, "%s\t%s", fn, call);
    free(call);
    sp_add(&f->lg, key, sp_dup(fn, strlen(fn)), line, i);
}

static void sp_logs(struct sp_file *f)
{
    unsigned line = 1;
    for (size_t i = 0; i < f->n; i++) {
        size_t paren;
        line += f->code[i] == '\n';
        if (f->code[i] == 'L' && sp_log_name(f, i, &paren))
            sp_add_log(f, i, sp_call_end(f, paren), line);
    }
}

/* Whether the directive at l[i..n) is the word w, advancing i past it. */
static int sp_word(const char *l, size_t n, size_t *i, const char *w)
{
    size_t k = strlen(w), j = *i;
    if (n - j < k || memcmp(l + j, w, k) != 0 || (n - j > k && sp_isid(l[j + k])))
        return 0;
    for (j += k; j < n && isspace((unsigned char)l[j]); j++)
        ;
    *i = j;
    return 1;
}

static int sp_is_include_line(const char *l, size_t n)
{
    size_t i = 0;
    while (i < n && isspace((unsigned char)l[i]))
        i++;
    if (i == n || l[i++] != '#')
        return 0;
    while (i < n && isspace((unsigned char)l[i]))
        i++;
    if (sp_word(l, n, &i, "include"))
        return 1;
    if (!sp_word(l, n, &i, "if") && !sp_word(l, n, &i, "elif"))
        return 0;
    return n - i >= 13 && memcmp(l + i, "__has_include", 13) == 0;
}

static void sp_includes(struct sp_file *f)
{
    unsigned line = 0;
    for (size_t a = 0; a < f->n; line++) {
        size_t b = a;
        while (b < f->n && f->code[b] != '\n')
            b++;
        if (sp_is_include_line(f->code + a, b - a))
            sp_add(&f->inc, sp_norm(f->code, f->lit, a, b), sp_dup("", 0), line + 1, a);
        a = b + 1;
    }
}

static void sp_header(struct sp_file *f, const char *text, size_t n)
{
    size_t a = 0;
    for (int k = 0; k < 5 && a < n; k++) {
        size_t b = a;
        while (b < n && text[b] != '\n')
            b++;
        f->hdr[k] = sp_dup(text + a, b - a);
        a = b + 1;
    }
}

static void sp_name_comments(struct sp_file *f)
{
    for (size_t i = 0; i < f->cm.n; i++) {
        const char *fn = sp_func_at(f, f->cm.v[i].off);
        f->cm.v[i].func = sp_dup(fn, strlen(fn));
        f->err |= f->cm.v[i].func == NULL;
    }
}

int sp_analyze(struct sp_file *f, const char *text, size_t n)
{
    struct sp_lex lx = { f, text, n, 0, 1 };
    f->n = n;
    f->code = sp_dup(text, n);
    f->lit = calloc(n + 1, 1); // raw-alloc-ok:lint-runtime
    if (!f->code || !f->lit)
        return f->err = 1;
    sp_lex_all(&lx);
    sp_spans(f);
    sp_logs(f);
    sp_includes(f);
    sp_header(f, text, n);
    sp_name_comments(f);
    return f->err || f->cm.err || f->lg.err || f->inc.err;
}

static void sp_list_free(struct sp_list *l)
{
    for (size_t i = 0; i < l->n; i++) {
        free(l->v[i].key);
        free(l->v[i].func);
    }
    free(l->v);
}

void sp_free(struct sp_file *f)
{
    sp_list_free(&f->cm);
    sp_list_free(&f->lg);
    sp_list_free(&f->inc);
    for (size_t i = 0; i < f->nspan; i++)
        free(f->span[i].name);
    for (int k = 0; k < 5; k++)
        free(f->hdr[k]);
    free(f->span);
    free(f->code);
    free(f->lit);
    memset(f, 0, sizeof *f);
}
