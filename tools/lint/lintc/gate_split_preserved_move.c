/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-split-preserved --mode=move of the C23 lint
 * runtime. A refactor that MOVES whole functions from a pinned file into a
 * new sibling file (to keep the source under its shrink-only size pin)
 * cannot pass the per-file split comparison, so this mode compares the SET of
 * files the commit touches. Files that exist at the base are sources, the rest
 * are new, and a new file must sit in the directory of a source. Every base
 * comment line must survive somewhere in the union of the current files;
 * every base LOG_* call must stay in a function of the same name with the same
 * text, in whichever file the function now lives; a new file opens with the
 * licence lines of one source; a source may drop an include only when a new
 * file has it; a new file may include only what a source included at the
 * base, plus one new header of the move (the *_internal.h in the same
 * directory) and the standard type headers that header's declarations need.
 * LIMIT: move mode does NOT compare function bodies. It compares comments,
 * LOG calls, includes, licence lines and directory only; a moved function
 * whose code changed but whose comments and LOG calls did not passes here.
 * check-core-seal and review cover the bodies. Dropping `static` is not
 * checked either. Facts come
 * from gate_split_preserved.c; split and dedup modes are
 * gate_split_preserved_check.c. Selftest: gate_split_preserved_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdlib.h>
#include <string.h>
#include "gate_split_preserved_priv.h"

struct mv {
    const struct sp_mfile *f;
    size_t n;
    struct sp_file *b, *c; /* b[i] is zeroed for a new file */
    FILE *out;
    int fails;
    const char *newhdr;    /* the one new header seen so far */
};

static void mv_fail(struct mv *m, size_t i, unsigned line, const char *what, const char *text)
{
    fprintf(m->out, "FAIL %s:%u: %s%s%s\n", m->f[i].path, line, what, *text ? ": " : "", text);
    m->fails++;
}

static size_t mv_dirlen(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? (size_t)(s - p) + 1 : 0;
}

static int mv_same_dir(const char *a, const char *b)
{
    size_t la = mv_dirlen(a);
    return la == mv_dirlen(b) && strncmp(a, b, la) == 0;
}

static int mv_is_new(const struct mv *m, size_t i)
{
    return m->f[i].base == NULL;
}

/* Appends every entry of src (by value; keys stay owned by src) to dst. */
static int mv_append(struct sp_list *dst, const struct sp_list *src, size_t **own, size_t who)
{
    for (size_t i = 0; i < src->n; i++) {
        if (dst->n == dst->cap) {
            size_t cap = dst->cap ? dst->cap * 2 : 256;
            struct sp_ent *v = realloc(dst->v, cap * sizeof *v); // raw-alloc-ok:lint-runtime
            size_t *o = own ? realloc(*own, cap * sizeof *o) : NULL; // raw-alloc-ok:lint-runtime
            if (v)
                dst->v = v;
            if (o)
                *own = o;
            if (!v || (own && !o))
                return 1;
            dst->cap = cap;
        }
        if (own)
            (*own)[dst->n] = who;
        dst->v[dst->n++] = src->v[i];
        dst->v[dst->n - 1].miss = 0;
    }
    return 0;
}

/* Whether the header entry's key is listed in l. */
static int mv_has_key(const struct sp_list *l, const char *key)
{
    for (size_t i = 0; i < l->n; i++) {
        if (strcmp(l->v[i].key, key) == 0)
            return 1;
    }
    return 0;
}

/* A standard header that only supplies types (or atomics) to declarations. */
static int mv_std_header(const char *key)
{
    static const char *const ok[] = { "stdbool", "stddef", "stdint", "stdarg", "limits",
                                      "inttypes", "stdatomic", "stdio", "stdlib", "string" };
    const char *a = strchr(key, '<'), *e = a ? strchr(a, '>') : NULL;
    if (!a || !e || strncmp(key, "#include", 8) != 0)
        return 0;
    for (size_t k = 0; k < sizeof ok / sizeof ok[0]; k++) {
        size_t l = strlen(ok[k]);
        if ((size_t)(e - a) == l + 3 && strncmp(a + 1, ok[k], l) == 0 && strncmp(a + 1 + l, ".h", 2) == 0)
            return 1;
    }
    return 0;
}

/* Whether key is `#include "x.h"` of a header that is itself a new file of the
 * move in the includer's directory; at most one such header per move. */
static int mv_new_header(struct mv *m, size_t who, const char *key)
{
    const char *a = strchr(key, '"'), *e = a ? strchr(a + 1, '"') : NULL;
    char want[512];
    size_t dl = mv_dirlen(m->f[who].path), l;
    if (!a || !e || strncmp(key, "#include", 8) != 0)
        return 0;
    l = (size_t)(e - a - 1);
    if (l < 3 || dl + l >= sizeof want || memchr(a + 1, '/', l) ||
        strncmp(a + 1 + l - 2, ".h", 2) != 0)
        return 0;
    memcpy(want, m->f[who].path, dl);
    memcpy(want + dl, a + 1, l);
    want[dl + l] = '\0';
    for (size_t i = 0; i < m->n; i++) {
        if (mv_is_new(m, i) && strcmp(m->f[i].path, want) == 0) {
            if (m->newhdr && strcmp(m->newhdr, m->f[i].path) != 0)
                return 0;
            m->newhdr = m->f[i].path;
            return 1;
        }
    }
    return 0;
}

static void mv_check_new(struct mv *m)
{
    for (size_t i = 0; i < m->n; i++) {
        int dir = 0, lic = 0;
        if (!mv_is_new(m, i))
            continue;
        for (size_t s = 0; s < m->n; s++) {
            if (mv_is_new(m, s))
                continue;
            dir |= mv_same_dir(m->f[i].path, m->f[s].path);
            lic |= sp_hdr_same(&m->b[s], &m->c[i]);
        }
        if (!dir)
            mv_fail(m, i, 1, "new file is not in the directory of a source file", "");
        if (!lic)
            mv_fail(m, i, 1, "licence lines match no source file", m->c[i].hdr[0] ? m->c[i].hdr[0] : "(missing)");
    }
}

/* Sources' base includes, as one list. */
static int mv_base_incs(const struct mv *m, struct sp_list *u)
{
    for (size_t s = 0; s < m->n; s++) {
        if (!mv_is_new(m, s) && mv_append(u, &m->b[s].inc, NULL, s))
            return 1;
    }
    return 0;
}

static int mv_in_new_files(const struct mv *m, const char *key)
{
    for (size_t i = 0; i < m->n; i++) {
        if (mv_is_new(m, i) && mv_has_key(&m->c[i].inc, key))
            return 1;
    }
    return 0;
}

static int mv_check_includes(struct mv *m)
{
    struct sp_list u = { 0 };
    int bad = mv_base_incs(m, &u);
    for (size_t i = 0; !bad && i < m->n; i++) {
        struct sp_file *b = &m->b[i], *c = &m->c[i];
        if (!mv_is_new(m, i)) {
            bad = sp_diff(&b->inc, &c->inc);
            for (size_t k = 0; !bad && k < b->inc.n; k++) {
                if (b->inc.v[k].miss && !mv_in_new_files(m, b->inc.v[k].key))
                    mv_fail(m, i, b->inc.v[k].line, "base include removed and not in any new file", b->inc.v[k].key);
            }
        }
        for (size_t k = 0; !bad && k < c->inc.n; k++) {
            const struct sp_ent *e = &c->inc.v[k];
            if (!mv_is_new(m, i) && !e->miss)
                continue;
            if (!mv_has_key(&u, e->key) && !mv_std_header(e->key) && !mv_new_header(m, i, e->key))
                mv_fail(m, i, e->line, "include is neither a source include nor the move's one new header", e->key);
        }
    }
    free(u.v);
    return bad;
}

static void mv_report(struct mv *m, const struct sp_list *l, const size_t *own, const char *what, int log)
{
    for (size_t i = 0; i < l->n; i++) {
        const struct sp_ent *e = &l->v[i];
        if (!e->miss)
            continue;
        if (log)
            fprintf(m->out, "FAIL %s:%u: %s %s: %s\n", m->f[own[i]].path, e->line, what, e->func,
                    e->key + strlen(e->func) + 1);
        else
            mv_fail(m, own[i], e->line, what, e->key);
        if (log)
            m->fails++;
    }
}

/* Multiset-compares base facts of all sources with current facts of all files. */
static int mv_check_facts(struct mv *m, int log)
{
    struct sp_list bl = { 0 }, cl = { 0 };
    size_t *bo = NULL, *co = NULL;
    int bad = 0;
    for (size_t i = 0; !bad && i < m->n; i++) {
        if (!mv_is_new(m, i))
            bad = mv_append(&bl, log ? &m->b[i].lg : &m->b[i].cm, &bo, i);
        bad = bad || mv_append(&cl, log ? &m->c[i].lg : &m->c[i].cm, &co, i);
    }
    bad = bad || sp_diff(&bl, &cl);
    if (!bad && log)
        sp_pair_alts(&bl, &cl);
    if (!bad) {
        mv_report(m, &bl, bo, log ? "base LOG call missing from" : "base comment line lost or reworded", log);
        if (log)
            mv_report(m, &cl, co, "LOG call not in the base, or not in the same function, in", 1);
    }
    free(bl.v);
    free(cl.v);
    free(bo);
    free(co);
    return bad;
}

int sp_compare_move(const struct sp_mfile *f, size_t n, FILE *out)
{
    struct sp_file *base = calloc(n, sizeof *base); // raw-alloc-ok:lint-runtime
    struct sp_file *cur = calloc(n, sizeof *cur); // raw-alloc-ok:lint-runtime
    struct mv m = { f, n, base, cur, out, 0, NULL };
    int bad = !m.b || !m.c, nsrc = 0;
    for (size_t i = 0; !bad && i < n; i++) {
        nsrc += f[i].base != NULL;
        bad = (f[i].base && sp_analyze(&m.b[i], f[i].base, f[i].base_len)) ||
              sp_analyze(&m.c[i], f[i].cur, f[i].cur_len);
    }
    if (!bad && !nsrc) {
        fputs("check_split_preserved: --mode=move needs at least one file that exists at the base\n", stderr);
        bad = 1;
    }
    if (!bad) {
        mv_check_new(&m);
        bad = mv_check_includes(&m) || mv_check_facts(&m, 0) || mv_check_facts(&m, 1);
    }
    for (size_t i = 0; m.b && m.c && i < n; i++) {
        sp_free(&m.b[i]);
        sp_free(&m.c[i]);
    }
    free(m.b);
    free(m.c);
    return bad ? 2 : m.fails > 0;
}
