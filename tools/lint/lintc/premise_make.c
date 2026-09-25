/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: extract the textual Makefile values a gate reads, for its
 * premise. The parent does this so a unit never needs the whole Makefile:
 * every definition of each named variable (all assignment operators, any
 * conditional branch, define/endef blocks, override/export prefixes), then
 * every variable those definitions reference, to a fixpoint. Unexpanded
 * text is the value: a change anywhere in that text flips the premise, and
 * a Makefile edit elsewhere does not. A name ending in ':' names a target:
 * its rule headers and recipe lines are the value, so the command a gate
 * runs is premise too. premise_make_residue() is the complement a catalog
 * needs: the text left once the owned variables' definitions are removed.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <stdlib.h>
#include <string.h>

enum { MK_VARS_MAX = 512 };

struct mk_text {
    char *buf;
    size_t len;
};

static int text_add(struct mk_text *t, const char *p, size_t n)
{
    char *grown = realloc(t->buf, t->len + n + 2); // raw-alloc-ok:lint-runtime
    if (!grown)
        return 2;
    memcpy(grown + t->len, p, n);
    t->len += n;
    grown[t->len++] = '\n';
    grown[t->len] = '\0';
    t->buf = grown;
    return 0;
}

static bool ident_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
           || (c >= '0' && c <= '9') || c == '_';
}

static const char *skip_sp(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t'))
        p++;
    return p;
}

static const char *skip_prefix(const char *p, const char *end)
{
    static const char *const k_prefix[] = { "override", "export", "private" };
    for (size_t i = 0; i < sizeof k_prefix / sizeof *k_prefix; i++) {
        size_t n = strlen(k_prefix[i]);
        if ((size_t)(end - p) > n && memcmp(p, k_prefix[i], n) == 0
            && (p[n] == ' ' || p[n] == '\t'))
            return skip_prefix(skip_sp(p + n, end), end);
    }
    return p;
}

static bool is_assign(const char *p, const char *end)
{
    static const char *const k_ops[] = { "::=", ":=", "+=", "?=", "!=", "=" };
    for (size_t i = 0; i < sizeof k_ops / sizeof *k_ops; i++) {
        size_t n = strlen(k_ops[i]);
        if ((size_t)(end - p) >= n && memcmp(p, k_ops[i], n) == 0)
            return true;
    }
    return false;
}

/* 1: the logical line assigns name; 2: it opens `define name`. */
static int defines(const char *p, const char *end, const char *name)
{
    size_t n = strlen(name);
    p = skip_prefix(skip_sp(p, end), end);
    bool block = (size_t)(end - p) > 7 && memcmp(p, "define", 6) == 0
                 && (p[6] == ' ' || p[6] == '\t');
    if (block)
        p = skip_sp(p + 6, end);
    if ((size_t)(end - p) < n || memcmp(p, name, n) != 0
        || (p + n < end && ident_char(p[n])))
        return 0;
    if (block)
        return 2;
    return is_assign(skip_sp(p + n, end), end) ? 1 : 0;
}

/* End of the logical line starting at p (backslash continuations joined). */
static const char *logical_end(const char *p, const char *end)
{
    for (;;) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl)
            return end;
        if (nl == p || nl[-1] != '\\')
            return nl;
        p = nl + 1;
    }
}

static const char *block_end(const char *p, const char *end)
{
    while (p < end) {
        const char *stop = logical_end(p, end);
        const char *q = skip_sp(p, stop);
        if ((size_t)(stop - q) >= 5 && memcmp(q, "endef", 5) == 0)
            return stop;
        p = stop < end ? stop + 1 : end;
    }
    return end;
}

/* A rule header naming target: a column-0 logical line whose text before
 * its first ':' holds target as a whole word, with no '=' before that ':'
 * and no '=' right after it (an assignment is not a rule). */
static bool blank(char c)
{
    return c == ' ' || c == '\t';
}

/* target appears in [p, colon) as a whole blank-separated word. */
static bool header_names(const char *p, const char *colon, const char *target,
                         size_t n)
{
    for (const char *w = p; w + n <= colon; w++)
        if (memcmp(w, target, n) == 0 && (w == p || blank(w[-1]))
            && (w + n == colon || blank(w[n])))
            return true;
    return false;
}

static bool rule_header(const char *p, const char *stop, const char *target,
                        size_t n)
{
    if (p >= stop || *p == '\t' || *p == '#')
        return false;
    const char *colon = memchr(p, ':', (size_t)(stop - p));
    if (!colon || memchr(p, '=', (size_t)(colon - p))
        || (colon + 1 < stop && colon[1] == '='))
        return false;
    return header_names(p, colon, target, n);
}

/* "target:" — every rule header for target and the recipe lines under it.
 * The gate's invocation is this text, so it is premise like a value. */
static int collect_rule(const char *mk, size_t len, const char *name,
                        struct mk_text *out)
{
    const char *p = mk, *end = mk + len;
    size_t n = strlen(name) - 1;
    int rc = 0;
    while (rc == 0 && p < end) {
        const char *stop = logical_end(p, end);
        bool hit = rule_header(p, stop, name, n);
        while (hit && stop + 1 < end && stop[1] == '\t')
            stop = logical_end(stop + 1, end);
        if (hit)
            rc = text_add(out, p, (size_t)(stop - p));
        p = stop < end ? stop + 1 : end;
    }
    return rc;
}

static int collect_var(const char *mk, size_t len, const char *name,
                       struct mk_text *out)
{
    size_t k = strlen(name);
    if (k > 1 && name[k - 1] == ':')
        return collect_rule(mk, len, name, out);
    const char *p = mk, *end = mk + len;
    int rc = 0;
    while (rc == 0 && p < end) {
        const char *stop = logical_end(p, end);
        int kind = defines(p, stop, name);
        if (kind == 2)
            stop = block_end(stop < end ? stop + 1 : end, end);
        if (kind)
            rc = text_add(out, p, (size_t)(stop - p));
        p = stop < end ? stop + 1 : end;
    }
    return rc;
}

struct mk_work {
    char *names[MK_VARS_MAX];
    size_t n;
};

static int work_add(struct mk_work *w, const char *p, size_t n)
{
    for (size_t i = 0; i < w->n; i++)
        if (strlen(w->names[i]) == n && memcmp(w->names[i], p, n) == 0)
            return 0;
    if (w->n == MK_VARS_MAX)
        return 2;
    w->names[w->n] = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!w->names[w->n])
        return 2;
    memcpy(w->names[w->n], p, n);
    w->names[w->n][n] = '\0';
    w->n++;
    return 0;
}

static int add_references(struct mk_work *w, const char *text)
{
    int rc = 0;
    for (const char *p = text; rc == 0 && (p = strchr(p, '$')) != NULL; p++) {
        if (p[1] != '(' && p[1] != '{')
            continue;
        const char *q = p + 2;
        while (ident_char(*q))
            q++;
        if (q > p + 2)
            rc = work_add(w, p + 2, (size_t)(q - p - 2));
    }
    return rc;
}

static int cmp_value(const void *a, const void *b)
{
    const struct premise_make_value *x = a, *y = b;
    return strcmp(x->name, y->name);
}

static int eval_work(const uint8_t *mk, size_t len, struct mk_work *w,
                     struct premise_make_value *vals)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < w->n; i++) {
        struct mk_text text = { 0 };
        rc = collect_var((const char *)mk, len, w->names[i], &text);
        vals[i].name = strdup(w->names[i]);
        if (!vals[i].name)
            rc = 2;
        vals[i].text = text.buf;
        if (rc == 0 && text.buf)
            rc = add_references(w, text.buf);
    }
    return rc;
}

int premise_make_values(const uint8_t *mk, size_t len,
                        const char *const *vars, size_t nvars,
                        struct premise_make_value **out, size_t *nout)
{
    struct mk_work w = { .n = 0 };
    struct premise_make_value *vals = calloc(MK_VARS_MAX, sizeof *vals); // raw-alloc-ok:lint-runtime
    int rc = vals ? 0 : 2;
    for (size_t i = 0; rc == 0 && i < nvars; i++)
        rc = work_add(&w, vars[i], strlen(vars[i]));
    if (rc == 0)
        rc = eval_work(mk, len, &w, vals);
    for (size_t i = 0; i < w.n; i++)
        free(w.names[i]);
    if (rc) {
        premise_make_values_free(vals, MK_VARS_MAX);
        return rc;
    }
    qsort(vals, w.n, sizeof *vals, cmp_value);
    *out = vals;
    *nout = w.n;
    return 0;
}

/* ── residue: the text no owned variable accounts for ─────────────────── */

static bool comment_line(const char *p, const char *stop)
{
    p = skip_sp(p, stop);
    return p < stop && *p == '#';
}

/* A `define` block of any name is one span: its body is the variable's
 * value, so a '#' line inside it is text, never a comment. */
static bool opens_block(const char *p, const char *stop)
{
    p = skip_prefix(skip_sp(p, stop), stop);
    return (size_t)(stop - p) > 7 && memcmp(p, "define", 6) == 0
           && (p[6] == ' ' || p[6] == '\t');
}

static bool owned_line(const char *p, const char *stop,
                       const char *const *owned, size_t nowned)
{
    for (size_t i = 0; i < nowned; i++)
        if (defines(p, stop, owned[i]))
            return true;
    return false;
}

int premise_make_residue(const uint8_t *mk, size_t len,
                         const char *const *owned, size_t nowned, char **out,
                         size_t *out_len)
{
    const char *p = (const char *)mk, *end = p + len;
    struct mk_text text = { 0 };
    int rc = 0;
    while (rc == 0 && p < end) {
        const char *stop = logical_end(p, end);
        bool block = opens_block(p, stop);
        bool skip = owned_line(p, stop, owned, nowned)
                    || (!block && comment_line(p, stop));
        if (block)
            stop = block_end(stop < end ? stop + 1 : end, end);
        if (!skip)
            rc = text_add(&text, p, (size_t)(stop - p));
        p = stop < end ? stop + 1 : end;
    }
    if (rc) {
        free(text.buf);
        return rc;
    }
    *out = text.buf;
    *out_len = text.len;
    return 0;
}

void premise_make_values_free(struct premise_make_value *v, size_t n)
{
    if (!v)
        return;
    for (size_t i = 0; i < n; i++) {
        free(v[i].name);
        free(v[i].text);
    }
    free(v);
}
