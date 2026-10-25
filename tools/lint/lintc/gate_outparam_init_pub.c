/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: leg 2 of check-outparam-init-before-return — the same bug class
 * with a PUBLISHED GLOBAL as the out-parameter. The publisher finder derives,
 * from the code and never from a name, every function that stores a
 * caller-supplied pointer into a file-scope variable; the publish/free
 * analyzer then reports a body that publishes &obj and later frees obj with
 * no unpublish and no module teardown in between (the sapling_init_params
 * verifying-key use-after-free, fixed in 69518f2f3).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_outparam_init_priv.h"

/* Leftmost match of /[A-Za-z_][A-Za-z0-9_]*$/ : the trailing identifier. */
static int op_tail_ident(const char *p, char *out, size_t cap)
{
    size_t n = strlen(p), b = n;
    while (b > 0 && op_idc((unsigned char)p[b - 1]))
        b--;
    while (b < n && !op_id1((unsigned char)p[b]))
        b++;
    if (b >= n)
        return 0;
    if (n - b >= cap)
        return -1;
    memcpy(out, p + b, n - b + 1);
    return 1;
}

/* The first `SINK = NM ;` on the line (SINK an identifier at a word start):
 * its SINK in out. 1 matched, 0 none, -1 name too long. */
static int op_sink_match(const char *line, const char *nm, char *out, size_t cap)
{
    size_t nl = strlen(nm);
    for (size_t s = 0; line[s]; s++) {
        size_t e = s, k;
        if (!op_id1((unsigned char)line[s]) || !op_word_before_ok(line, s))
            continue;
        while (op_idc((unsigned char)line[e]))
            e++;
        k = op_skipws(line, e);
        if (line[k] != '=')
            continue;
        k = op_skipws(line, k + 1);
        if (strncmp(line + k, nm, nl) != 0 || line[op_skipws(line, k + nl)] != ';')
            continue;
        if (e - s >= cap)
            return -1;
        memcpy(out, line + s, e - s);
        out[e - s] = '\0';
        return 1;
    }
    return 0;
}

/* atomic_store ( & IDENT , NM ) anywhere on the line. */
static int op_atomic_store(const char *s, const char *nm)
{
    size_t nl = strlen(nm);
    for (const char *p = strstr(s, "atomic_store"); p; p = strstr(p + 1, "atomic_store")) {
        size_t k = op_skipws(p, 12);
        if (p[k] != '(')
            continue;
        k = op_skipws(p, k + 1);
        if (p[k] != '&' || !op_id1((unsigned char)p[k + 1]))
            continue;
        k++;
        while (op_idc((unsigned char)p[k]))
            k++;
        k = op_skipws(p, k);
        if (p[k] != ',')
            continue;
        k = op_skipws(p, k + 1);
        if (strncmp(p + k, nm, nl) != 0)
            continue;
        if (p[op_skipws(p, k + nl)] == ')')
            return 1;
    }
    return 0;
}

/* One parameter of a publisher candidate: does any line store it into a
 * file-scope object (or atomic_store its address-of sink)? */
static int op_pubfind_param(const struct op_fn *f,
                            const char *part, int *hit)
{
    char nm[OP_NAME], sink[OP_NAME];
    int r;
    *hit = 0;
    if (!strchr(part, '*'))
        return 0;
    r = op_tail_ident(part, nm, sizeof nm);
    if (r < 0)
        return die("z23-lint: outparam-init: %s\n", "parameter name too long");
    if (r == 0)
        return 0;
    for (size_t j = 1; j <= f->nbody && !*hit; j++) {
        const char *line = op_body(f, j);
        r = op_sink_match(line, nm, sink, sizeof sink);
        if (r < 0)
            return die("z23-lint: outparam-init: %s\n", "sink name too long");
        *hit = (r == 1 && strcmp(sink, nm) != 0 && op_hset_has(f->objs, sink))
            || op_atomic_store(line, nm);
    }
    return 0;
}

int op_pubfind_emit(struct op_fn *f, void *ctx)
{
    struct op_pub *p = ctx;
    int np, hit = 0, rc = 0;
    if (!op_buf_str(&f->sig)[0] || f->nbody == 0)
        return 0;
    np = op_params(f->sig.p, &p->parms);
    if (np < 0)
        return 2;
    for (int i = 0; rc == 0 && !hit && i < np; i++)
        rc = op_pubfind_param(f, op_param_at(&p->parms, i), &hit);
    if (rc == 0 && hit)
        rc = op_hset_add(p->found, f->fnname);
    return rc;
}

/* One IDENT ( ARG ) call with a paren- and comma-free argument. */
struct op_call {
    const char *id, *arg;
    size_t idn, argn;
};

/* Leftmost /IDENT[ \t]*\([ \t]*[^(),]*\)/ at or after *pos; *pos moves past it. */
static int op_next_call(const char *s, size_t *pos, struct op_call *c)
{
    for (size_t i = *pos; s[i]; i++) {
        size_t b = i, e = i, k, z, a;
        if (!op_id1((unsigned char)s[i]))
            continue;
        while (op_idc((unsigned char)s[e]))
            e++;
        i = e - 1;
        k = op_skipws(s, e);
        if (s[k] != '(')
            continue;
        z = k + 1;
        while (s[z] && !strchr("(),", s[z]))
            z++;
        if (s[z] != ')')
            continue;
        a = op_skipws(s, k + 1);
        c->id = s + b;
        c->idn = e - b;
        c->arg = s + a;
        c->argn = z - a;
        while (c->argn > 0 && (c->arg[c->argn - 1] == ' ' || c->arg[c->argn - 1] == '\t'))
            c->argn--;
        *pos = z + 1;
        return 1;
    }
    return 0;
}

/* Cut at the first '.' or '[' and drop a leading '&': base() in the awk. */
static void op_base(char *v)
{
    if (v[0] == '&')
        memmove(v, v + 1, strlen(v));
    v[strcspn(v, ".[")] = '\0';
}

static int op_mark_set(struct op_pubmark *m, int *n, const char *name, size_t j)
{
    for (int i = 0; i < *n; i++)
        if (strcmp(m[i].name, name) == 0) {
            m[i].j = j;
            return 0;
        }
    if (*n >= OP_PUBMAX)
        return die("z23-lint: outparam-init: %s\n", "too many unpublish marks in one function");
    memcpy(m[*n].name, name, strlen(name) + 1);
    m[(*n)++].j = j;
    return 0;
}

static int op_pub_set(struct op_pub *p, const char *setter, const char *obj, size_t j)
{
    for (int i = 0; i < p->nat; i++)
        if (strcmp(p->at[i].setter, setter) == 0 && strcmp(p->at[i].obj, obj) == 0) {
            p->at[i].j = j;
            return 0;
        }
    if (p->nat >= OP_PUBMAX)
        return die("z23-lint: outparam-init: %s\n", "too many publishes in one function");
    memcpy(p->at[p->nat].setter, setter, strlen(setter) + 1);
    memcpy(p->at[p->nat].obj, obj, strlen(obj) + 1);
    p->at[p->nat++].j = j;
    return 0;
}

/* A publisher call on body line j: NULL / 0 unpublishes, &obj publishes. */
static int op_pf_call(struct op_pub *p, const struct op_call *c, size_t j)
{
    char setter[OP_NAME], arg[OP_NAME];
    if (c->idn >= OP_NAME)
        return 0;
    memcpy(setter, c->id, c->idn);
    setter[c->idn] = '\0';
    if (!op_hset_has(p->known, setter))
        return 0;
    if (c->argn >= OP_NAME)
        return die("z23-lint: outparam-init: %s\n", "publisher argument too long");
    memcpy(arg, c->arg, c->argn);
    arg[c->argn] = '\0';
    if (strcmp(arg, "NULL") == 0 || strcmp(arg, "0") == 0)
        return op_mark_set(p->clr, &p->nclr, setter, j);
    if (arg[0] != '&')
        return 0;
    op_base(arg);
    return op_pub_set(p, setter, arg, j);
}

static const char *const k_pf_suffix[] = {
    "shutdown", "reset", "clear", "close", "free"
};

/* The first IDENT_(shutdown|reset|clear|close|free)( on the line: the module
 * name ahead of the suffix. 1 found, 0 none, -1 too long. */
static int op_teardown(const char *s, char *td, size_t cap)
{
    for (size_t i = 0; s[i]; i++) {
        size_t e = i, k;
        if (!op_id1((unsigned char)s[i]))
            continue;
        while (op_idc((unsigned char)s[e]))
            e++;
        k = op_skipws(s, e);
        for (size_t x = 0; s[k] == '(' && x < sizeof k_pf_suffix / sizeof *k_pf_suffix; x++) {
            size_t sl = strlen(k_pf_suffix[x]);
            if (e - i < sl + 2 || s[e - sl - 1] != '_'
                || memcmp(s + e - sl, k_pf_suffix[x], sl) != 0)
                continue;
            if (e - sl - 1 - i >= cap)
                return -1;
            memcpy(td, s + i, e - sl - 1 - i);
            td[e - sl - 1 - i] = '\0';
            return 1;
        }
        i = e - 1;
    }
    return 0;
}

static int op_cls_lower(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

/* The first (^|non-word)([a-z0-9_]*_)?free ( &?IDENT call: its object, cut
 * at the first '.'. 1 found, 0 none, -1 too long. */
static int op_free_call(const char *s, char *v, size_t cap)
{
    for (size_t u = 0; s[u]; u++) {
        size_t r = u, e, k, a;
        if (!op_word_before_ok(s, u))
            continue;
        while (op_cls_lower((unsigned char)s[r]))
            r++;
        if (r - u < 4 || memcmp(s + r - 4, "free", 4) != 0)
            continue;
        e = r - 4;
        if (e != u && s[e - 1] != '_')
            continue;
        k = op_skipws(s, r);
        if (s[k] != '(')
            continue;
        k = op_skipws(s, k + 1);
        k += s[k] == '&';
        if (!op_id1((unsigned char)s[k]))
            continue;
        a = k;
        while (op_idc((unsigned char)s[k]) || s[k] == '.')
            k++;
        if (k - a >= cap)
            return -1;
        memcpy(v, s + a, k - a);
        v[k - a] = '\0';
        v[strcspn(v, ".")] = '\0';
        return 1;
    }
    return 0;
}

/* mod = setter with its trailing _init / _set_* removed (leftmost match). */
static void op_module_of(const char *setter, char *mod)
{
    const char *set = strstr(setter, "_set_");
    size_t n = strlen(setter), cut = n;
    if (set)
        cut = (size_t)(set - setter);
    if (n >= 5 && strcmp(setter + n - 5, "_init") == 0 && n - 5 < cut)
        cut = n - 5;
    memcpy(mod, setter, cut);
    mod[cut] = '\0';
}

/* name was marked strictly between the publish at pj and the free at j. */
static int op_mark_between(const struct op_pubmark *m, int n, const char *name,
                           size_t pj, size_t j)
{
    for (int i = 0; i < n; i++)
        if (strcmp(m[i].name, name) == 0)
            return m[i].j > pj && m[i].j < j;
    return 0;
}

static int op_hit_add(struct op_pub *p, const struct op_fn *f,
                      const struct op_pubat *a, const char *v, size_t j)
{
    struct op_pubhit *h;
    if (p->nhit >= p->caphit) {
        int cap = p->caphit ? p->caphit * 2 : 64;
        struct op_pubhit *nh = realloc(p->hit, (size_t)cap * sizeof *nh); // raw-alloc-ok:lint-runtime
        if (!nh)
            return die("z23-lint: outparam-init: out of memory\n", "");
        p->hit = nh;
        p->caphit = cap;
    }
    h = &p->hit[p->nhit++];
    if (ovf(snprintf(h->file, sizeof h->file, "%s", f->file), sizeof h->file))
        return 2;
    memcpy(h->fn, f->fnname, strlen(f->fnname) + 1);
    memcpy(h->setter, a->setter, strlen(a->setter) + 1);
    memcpy(h->obj, v, strlen(v) + 1);
    h->pub_line = op_body_lineno(f, a->j);
    h->free_line = op_body_lineno(f, j);
    return 0;
}

/* A free of v on body line j: report each publish of v with no unpublish and
 * no module teardown between it and here. */
static int op_pf_free(struct op_pub *p, const struct op_fn *f, size_t j, const char *line)
{
    char v[OP_NAME], mod[OP_NAME];
    int r = op_free_call(line, v, sizeof v);
    if (r < 0)
        return die("z23-lint: outparam-init: %s\n", "freed name too long");
    for (int i = 0; r == 1 && i < p->nat; i++) {
        const struct op_pubat *a = &p->at[i];
        if (strcmp(a->obj, v) != 0 || a->j >= j
            || op_mark_between(p->clr, p->nclr, a->setter, a->j, j))
            continue;
        op_module_of(a->setter, mod);
        if (op_mark_between(p->tear, p->ntear, mod, a->j, j))
            continue;
        if (op_hit_add(p, f, a, v, j))
            return 2;
    }
    return 0;
}

static int op_pf_line(struct op_pub *p, const struct op_fn *f, size_t j)
{
    const char *line = op_body(f, j);
    struct op_call c;
    char td[OP_NAME];
    size_t pos = 0;
    int r;
    while (op_next_call(line, &pos, &c))
        if (op_pf_call(p, &c, j))
            return 2;
    r = op_teardown(line, td, sizeof td);
    if (r < 0)
        return die("z23-lint: outparam-init: %s\n", "teardown name too long");
    if (r == 1 && op_mark_set(p->tear, &p->ntear, td, j))
        return 2;
    return op_pf_free(p, f, j, line);
}

int op_pubfree_emit(struct op_fn *f, void *ctx)
{
    struct op_pub *p = ctx;
    if (f->nbody == 0)
        return 0;
    p->nfuncs++;
    p->nat = 0;
    p->nclr = 0;
    p->ntear = 0;
    for (size_t j = 1; j <= f->nbody; j++)
        if (op_pf_line(p, f, j))
            return 2;
    return 0;
}

void op_pub_free(struct op_pub *p)
{
    free(p->hit);
    op_buf_free(&p->parms);
    p->hit = NULL;
    p->nhit = 0;
    p->caphit = 0;
}
