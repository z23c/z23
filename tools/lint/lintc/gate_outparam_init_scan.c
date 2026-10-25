/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the out-parameter scan of check-outparam-init-before-return — for
 * every function, each non-const `struct T *name` parameter whose first
 * *_init(name) / memset(name, ...) lands after a data-dependent return or
 * LOG_* line (the compact-block bug class). A line-order scanner over
 * stripped C text, ported rule for rule from the shell gate's awk analyzer;
 * see gate_outparam_init.c for what it can and cannot see.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_outparam_init_priv.h"

/* `struct T *` in a parameter: non-const, with a star, T copied to ty.
 * 1 found, 0 not a struct pointer, -1 type name too long. */
static int op_param_type(const char *p, char *ty)
{
    if (op_has_word(p, "const") || !strchr(p, '*'))
        return 0;
    for (const char *q = strstr(p, "struct"); q; q = strstr(q + 1, "struct")) {
        size_t i = (size_t)(q - p), k = i + 6, a;
        if (!op_word_before_ok(p, i) || (p[k] != ' ' && p[k] != '\t'))
            continue;
        k = op_skipws(p, k);
        if (!op_id1((unsigned char)p[k]))
            continue;
        a = k;
        while (op_idc((unsigned char)p[k]))
            k++;
        if (p[op_skipws(p, k)] != '*')
            continue;
        if (k - a >= OP_NAME)
            return -1;
        memcpy(ty, p + a, k - a);
        ty[k - a] = '\0';
        return 1;
    }
    return 0;
}

/* A pointer to pointer (star, blanks, star): an owner-out, out of scope. */
static int op_double_star(const char *p)
{
    for (const char *q = strchr(p, '*'); q; q = strchr(q + 1, '*'))
        if (p[op_skipws(p, (size_t)(q - p) + 1)] == '*')
            return 1;
    return 0;
}

/* The first IDENT_init(ARG call on the line names nm. A `&` before the name
 * never matches: the address of the parameter is not the pointee. */
static int op_init_call(const char *s, const char *nm)
{
    size_t i = 0, nl = strlen(nm);
    while (s[i]) {
        size_t e, b, k, a;
        int amp;
        if (!op_idc((unsigned char)s[i])) {
            i++;
            continue;
        }
        e = i;
        while (op_idc((unsigned char)s[e]))
            e++;
        b = i;
        while (b < e && !op_id1((unsigned char)s[b]))
            b++;
        i = e;
        if (e - b < 6 || memcmp(s + e - 5, "_init", 5) != 0)
            continue;
        k = op_skipws(s, e);
        if (s[k] != '(')
            continue;
        k = op_skipws(s, k + 1);
        amp = s[k] == '&';
        k += amp;
        if (!op_id1((unsigned char)s[k]))
            continue;
        a = k;
        while (op_idc((unsigned char)s[k]))
            k++;
        return !amp && k - a == nl && memcmp(s + a, nm, nl) == 0;
    }
    return 0;
}

/* line ~ /memset[ \t]*\([ \t]*NM[ \t]*,/ */
static int op_memset_call(const char *s, const char *nm)
{
    size_t nl = strlen(nm);
    for (const char *p = strstr(s, "memset"); p; p = strstr(p + 1, "memset")) {
        size_t k = op_skipws(p, 6);
        if (p[k] != '(')
            continue;
        k = op_skipws(p, k + 1);
        if (strncmp(p + k, nm, nl) != 0)
            continue;
        if (p[op_skipws(p, k + nl)] == ',')
            return 1;
    }
    return 0;
}

/* 1-based line of the first init / memset of nm, 0 for none. */
static size_t op_first_init(const struct op_fn *f, const char *nm, char *tag)
{
    for (size_t j = 1; j <= f->nbody; j++) {
        const char *line = op_body(f, j);
        if (op_init_call(line, nm)) {
            *tag = 'i';
            return j;
        }
        if (op_memset_call(line, nm)) {
            *tag = 'm';
            return j;
        }
    }
    return 0;
}

static int op_cls_log(int c)
{
    return (c >= 'A' && c <= 'Z') || c == '_' || (c >= '0' && c <= '9');
}

/* LOG_[A-Z_0-9]+ starting at i (preceded by a non-word); its end in *e. */
static int op_log_run(const char *s, size_t i, size_t *e)
{
    size_t k = i + 4;
    if (strncmp(s + i, "LOG_", 4) != 0 || !op_word_before_ok(s, i))
        return 0;
    while (op_cls_log((unsigned char)s[k]))
        k++;
    *e = k;
    return k > i + 4;
}

static int op_has_logcall(const char *s)
{
    size_t e;
    for (const char *p = strstr(s, "LOG_"); p; p = strstr(p + 1, "LOG_"))
        if (op_log_run(s, (size_t)(p - s), &e) && s[op_skipws(s, e)] == '(')
            return 1;
    return 0;
}

/* RSTART of the first (^|non-word)(return|LOG_X+)(non-word|$) match: how many
 * leading characters the guard region keeps. 0 when the line has none. */
static size_t op_kw_keep(const char *s)
{
    size_t e;
    for (size_t i = 0; s[i]; i++) {
        if (!op_word_before_ok(s, i))
            continue;
        if ((strncmp(s + i, "return", 6) == 0 && !op_idc((unsigned char)s[i + 6]))
            || (op_log_run(s, i, &e) && !op_idc((unsigned char)s[e])))
            return i ? i : 1;
    }
    return 0;
}

/* A declaration with no initializer computes nothing and cannot exit. */
static int op_plain_decl(const char *s)
{
    return !strchr(s, '=') && !strchr(s, '<') && !strchr(s, '>')
        && !strchr(s, '(') && op_ends_semi(s);
}

static int op_put_star_free(struct op_buf *r, const char *line)
{
    if (op_buf_put(r, " ", 1))
        return 2;
    for (; *line; line++)
        if (*line != '*' && op_buf_put(r, line, 1))
            return 2;
    return 0;
}

/* Everything above and including line k, with each return / LOG_ statement
 * (and its multi-line payload) replaced by the text ahead of it. */
static int op_region_build(const struct op_fn *f, size_t k, struct op_buf *r)
{
    size_t m = 1;
    int rc;
    op_buf_clear(r);
    while (m <= k) {
        const char *line = op_body(f, m);
        size_t keep = op_kw_keep(line);
        if (keep) {
            if (op_buf_put(r, " ", 1) || op_buf_put(r, line, keep))
                return 2;
            while (m <= k && !strchr(op_body(f, m), ';'))
                m++;
            m++;
            continue;
        }
        rc = op_plain_decl(line) ? op_put_star_free(r, line)
                                 : (op_buf_put(r, " ", 1) || op_buf_put(r, line, strlen(line)));
        if (rc)
            return 2;
        m++;
    }
    return 0;
}

/* Characters to delete at p, 0 to keep it: one pass of a gsub. */
typedef size_t (*op_skip_fn)(const char *p);

static size_t op_skip_quoted(const char *p)
{
    const char *q;
    if (*p != '"')
        return 0;
    q = strchr(p + 1, '"');
    return q ? (size_t)(q - p) + 1 : 0;
}

static size_t op_skip_blank(const char *p)
{
    return *p == ' ' || *p == '\t';
}

static size_t op_skip_zero_sub(const char *p)
{
    return strncmp(p, "[0]", 3) == 0 ? 3 : 0;
}

static size_t op_skip_empty_sub(const char *p)
{
    return strncmp(p, "[]", 2) == 0 ? 2 : 0;
}

static size_t op_skip_ident(const char *p)
{
    size_t n = 0;
    if (!op_id1((unsigned char)*p))
        return 0;
    while (op_idc((unsigned char)p[n]) || p[n] == '.')
        n++;
    return n;
}

static size_t op_skip_punct(const char *p)
{
    if (strncmp(p, "||", 2) == 0 || strncmp(p, "&&", 2) == 0
        || strncmp(p, "==", 2) == 0 || strncmp(p, "!=", 2) == 0)
        return 2;
    return *p && strchr("()!{};,", *p) ? 1 : 0;
}

static void op_gsub_del(char *s, op_skip_fn skip)
{
    size_t i = 0, o = 0;
    while (s[i]) {
        size_t n = skip(s + i);
        if (n)
            i += n;
        else
            s[o++] = s[i++];
    }
    s[o] = '\0';
}

/* gsub(/->/, ".") */
static void op_arrows(char *s)
{
    size_t i = 0, o = 0;
    while (s[i]) {
        if (s[i] == '-' && s[i + 1] == '>') {
            s[o++] = '.';
            i += 2;
        } else {
            s[o++] = s[i++];
        }
    }
    s[o] = '\0';
}

/* After the guard text is reduced to what a pure pointer-nullness test is made
 * of, anything left — a literal, a relational operator, arithmetic — makes the
 * exit DATA-dependent. */
static int op_region_data(struct op_buf *r)
{
    char *s = r->p;
    op_gsub_del(s, op_skip_quoted);
    op_arrows(s);
    op_gsub_del(s, op_skip_blank);
    op_gsub_del(s, op_skip_zero_sub);
    op_gsub_del(s, op_skip_ident);
    op_gsub_del(s, op_skip_empty_sub);
    op_gsub_del(s, op_skip_punct);
    return s[0] != '\0';
}

/* The first exit above `init` reachable with well-formed arguments. */
static int op_first_exit(struct op_scan *s, const struct op_fn *f,
                         size_t init, size_t *exit_j)
{
    *exit_j = 0;
    for (size_t j = 1; j < init; j++) {
        const char *line = op_body(f, j);
        size_t k = j;
        if (!op_has_word(line, "return") && !op_has_logcall(line))
            continue;
        while (k < init && !strchr(op_body(f, k), ';'))
            k++;
        if (op_region_build(f, k, &s->region))
            return 2;
        if (op_region_data(&s->region)) {
            *exit_j = j;
            return 0;
        }
        j = k;
    }
    return 0;
}

static int op_in_scope(const struct op_scan *s, const struct op_fn *f,
                       const char *ty)
{
    char want[OP_NAME + 8];
    size_t tl = strlen(ty);
    if (snprintf(want, sizeof want, "%s_free", ty) < 0 || !op_hset_has(s->frees, want))
        return 0;
    if (strcmp(f->fnname, want) == 0)
        return 0;
    return !(strncmp(f->fnname, ty, tl) == 0
             && (strcmp(f->fnname + tl, "_init") == 0
                 || strcmp(f->fnname + tl, "_reset") == 0));
}

static int op_record(struct op_scan *s, const struct op_fn *f, const char *ty,
                     const char *nm, size_t ex, size_t in, char tag)
{
    struct op_finding *fd;
    if (!op_in_scope(s, f, ty))
        return 0;
    if (s->nfind >= s->capfind) {
        int cap = s->capfind ? s->capfind * 2 : 512;
        struct op_finding *nf = realloc(s->find, (size_t)cap * sizeof *nf); // raw-alloc-ok:lint-runtime
        if (!nf)
            return die("z23-lint: outparam-init: out of memory\n", "");
        s->find = nf;
        s->capfind = cap;
    }
    fd = &s->find[s->nfind++];
    if (ovf(snprintf(fd->key, sizeof fd->key, "%s|%s|%s", f->fnname, nm, ty),
            sizeof fd->key)
        || ovf(snprintf(fd->file, sizeof fd->file, "%s", f->file), sizeof fd->file))
        return 2;
    fd->exit_line = op_body_lineno(f, ex);
    fd->init_line = op_body_lineno(f, in);
    fd->tag = tag;
    return 0;
}

static int op_scan_param(struct op_scan *s, const struct op_fn *f, const char *p)
{
    char ty[OP_NAME], nm[OP_NAME], tag = 0;
    size_t init, ex;
    int r = op_param_type(p, ty);
    if (r < 0)
        return die("z23-lint: outparam-init: %s\n", "struct type name too long");
    if (r == 0 || op_double_star(p))
        return 0;
    r = op_decl_name(p, nm, sizeof nm);
    if (r < 0)
        return die("z23-lint: outparam-init: %s\n", "parameter name too long");
    if (r == 0)
        return 0;
    s->nparams++;
    init = op_first_init(f, nm, &tag);
    if (init == 0)
        return 0;
    if (op_first_exit(s, f, init, &ex))
        return 2;
    return ex ? op_record(s, f, ty, nm, ex, init, tag) : 0;
}

int op_scan_emit(struct op_fn *f, void *ctx)
{
    struct op_scan *s = ctx;
    int np, rc = 0;
    if (!op_buf_str(&f->sig)[0] || f->nbody == 0)
        return 0;
    s->nfuncs++;
    np = op_params(f->sig.p, &s->parms);
    if (np < 0)
        return 2;
    for (int i = 0; rc == 0 && i < np; i++)
        rc = op_scan_param(s, f, op_param_at(&s->parms, i));
    return rc;
}

void op_scan_free(struct op_scan *s)
{
    free(s->find);
    op_buf_free(&s->parms);
    op_buf_free(&s->region);
    memset(s, 0, sizeof *s);
}
