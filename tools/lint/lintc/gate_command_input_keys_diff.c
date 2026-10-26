/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the verdict of check-command-input-keys. Follows calls across the
 * indexed functions until every function holds the keys and literal words of
 * everything it reaches, then compares each leaf's declared keys with the
 * keys its handler reads. A read key that is not declared is MISSING unless
 * the shrink-only baseline pins it; a baseline pin that matched nothing is
 * STALE; a declared key whose name appears nowhere in the closure is only
 * counted. Handlers bound by several leaves cannot be attributed per leaf,
 * but two such leaves with the same input and output schema must declare the
 * same keys.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "gate_command_input_keys_priv.h"
#include "lintc.h"

enum { CIK_ROUNDS = 64 };

struct cik_pin { char *path, *key; bool hit; };
struct cik_grp { int hid; const char *schema, *out, *leaf; char *canon; };

struct cik_ctx {
    struct cik_index *x;
    struct cik_report *r;
    struct cik_set decl;
    struct cik_pin *pin;
    size_t npin, cpin;
    struct cik_grp *grp;
    size_t ngrp, cgrp;
};

static bool cik_merge(struct cik_set *dst, const struct cik_set *src)
{
    bool changed = false;
    for (size_t i = 0; i < src->n; i++)
        changed |= cik_set_add(dst, src->v[i]);
    return changed;
}

static bool cik_close_fn(struct cik_index *x, size_t i)
{
    struct cik_fn *f = &x->fn[i];
    bool changed = false;
    for (size_t k = 0; k < f->calls.n; k++) {
        struct cik_fn *callee = cik_index_find(x, f->calls.v[k]);
        if (!callee || callee == f)
            continue;
        changed |= cik_merge(&f->keys, &callee->keys);
        changed |= cik_merge(&f->lits, &callee->lits);
    }
    return changed;
}

/* Rounds taken; CIK_ROUNDS or more means the closure did not settle. */
static int cik_closure(struct cik_index *x)
{
    bool changed = true;
    int rounds = 0;
    while (changed && rounds < CIK_ROUNDS) {
        changed = false;
        rounds++;
        for (size_t i = 0; i < x->nfn; i++)
            changed |= cik_close_fn(x, i);
    }
    return rounds;
}

static struct cik_pin *cik_pin_find(struct cik_ctx *c, const char *path,
                                    const char *key)
{
    for (size_t i = 0; i < c->npin; i++)
        if (strcmp(c->pin[i].path, path) == 0 && strcmp(c->pin[i].key, key) == 0)
            return &c->pin[i];
    return NULL;
}

static void cik_pin_line(struct cik_ctx *c, char *line)
{
    char *hash = strchr(line, '#'), *tok[2] = { "", "" };
    int nt = 0;
    if (hash)
        *hash = '\0';
    for (char *s = strtok(line, " \t\n"); s && nt < 2; s = strtok(NULL, " \t\n"))
        tok[nt++] = s;
    if (nt == 0 || cik_pin_find(c, tok[0], tok[1]))
        return;
    if (c->npin == c->cpin) {
        c->cpin = c->cpin ? c->cpin * 2 : 64;
        c->pin = cik_mem(c->pin, c->cpin * sizeof *c->pin, "cik_pin");
    }
    c->pin[c->npin++] = (struct cik_pin){ cik_dup(tok[0], strlen(tok[0])),
                                          cik_dup(tok[1], strlen(tok[1])), false };
}

static int cik_pin_cb(void *vctx, const char *line, size_t len)
{
    char *copy = cik_dup(line, len);
    cik_pin_line(vctx, copy);
    free(copy);
    return 0;
}

/* Loads the baseline; a missing file is created empty, as the script's touch
 * did. Any other open error or a read error is FATAL (2): an unreadable
 * baseline must never read as "no pins". */
static int cik_pins_load(struct cik_ctx *c, const char *path, FILE *err)
{
    int rc = lc_each_line(path, cik_pin_cb, c, 1);
    if (rc == 2) {
        fprintf(err, "check_command_input_keys: FATAL — cannot read baseline"
                " %s: %s\n", path, strerror(errno));
        return 2;
    }
    if (rc == 1) {
        FILE *f = fopen(path, "a");
        if (!f) {
            fprintf(err, "touch: cannot touch '%s': %s\n", path,
                    strerror(errno));
            return 1;
        }
        fclose(f);
    }
    return 0;
}

static void cik_decl_csv(struct cik_ctx *c, const char *csv)
{
    while (*csv) {
        size_t n = strcspn(csv, ",");
        if (n)
            cik_set_add(&c->decl, cik_intern(&c->x->dict, csv, n));
        csv += n + (csv[n] ? 1 : 0);
    }
}

static void cik_put_fmt(struct cik_buf *b, const char *fmt, ...)
{
    va_list ap, cp;
    int n;
    char *line;
    va_start(ap, fmt);
    va_copy(cp, ap);
    n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    line = cik_mem(NULL, (size_t)n + 1, "cik_put_fmt");
    vsnprintf(line, (size_t)n + 1, fmt, ap);
    va_end(ap);
    cik_buf_put(b, line, (size_t)n);
    free(line);
}


static void cik_leaf_plain(struct cik_ctx *c, const struct cik_leaf *l,
                           const struct cik_fn *fn)
{
    struct cik_report *r = c->r;
    const struct cik_dict *d = &c->x->dict;
    for (size_t i = 0; i < fn->keys.n; i++) {
        const char *key = d->word[fn->keys.v[i]];
        struct cik_pin *pin;
        if (cik_set_has(&c->decl, fn->keys.v[i]))
            continue;
        if ((pin = cik_pin_find(c, l->path, key))) {
            pin->hit = true;
            r->ngrand++;
            continue;
        }
        r->nmiss++;
        cik_put_fmt(&r->miss, "  %s:%d: %s reads \"%s\" (handler %s)\n",
                    l->file, l->line, l->path, key, l->handler);
    }
    for (size_t i = 0; i < c->decl.n; i++) {
        int id = c->decl.v[i];
        if (cik_set_has(&fn->keys, id) || cik_set_has(&fn->lits, id))
            continue;
        r->nunread++;
        cik_put_fmt(&r->unread, "    %s: %s (handler %s)\n", l->path,
                    d->word[id], l->handler);
    }
}

/* The declared keys of one leaf, unique, sorted and comma-joined. */
static char *cik_canon(struct cik_ctx *c)
{
    const char **w = cik_mem(NULL, (c->decl.n + 1) * sizeof *w, "cik_canon");
    struct cik_buf out = { 0 };
    for (size_t i = 0; i < c->decl.n; i++)
        w[i] = c->x->dict.word[c->decl.v[i]];
    qsort(w, c->decl.n, sizeof *w, lintc_strcmp_ptr);
    for (size_t i = 0; i < c->decl.n; i++) {
        if (i)
            cik_buf_putc(&out, ',');
        cik_buf_puts(&out, w[i]);
    }
    free(w);
    return out.p ? out.p : cik_dup("", 0);
}

static struct cik_grp *cik_grp_find(struct cik_ctx *c, const struct cik_leaf *l)
{
    for (size_t i = 0; i < c->ngrp; i++)
        if (c->grp[i].hid == l->hid && strcmp(c->grp[i].schema, l->schema) == 0
            && strcmp(c->grp[i].out, l->out) == 0)
            return &c->grp[i];
    return NULL;
}

static void cik_leaf_shared(struct cik_ctx *c, const struct cik_leaf *l)
{
    struct cik_grp *g;
    char *canon;
    c->r->nshared++;
    if (!l->schema[0] || !l->out[0])
        return;
    canon = cik_canon(c);
    if (!(g = cik_grp_find(c, l))) {
        if (c->ngrp == c->cgrp) {
            c->cgrp = c->cgrp ? c->cgrp * 2 : 32;
            c->grp = cik_mem(c->grp, c->cgrp * sizeof *c->grp, "cik_grp");
        }
        c->grp[c->ngrp++] = (struct cik_grp){ l->hid, l->schema, l->out,
                                              l->path, canon };
        return;
    }
    if (strcmp(g->canon, canon) != 0) {
        c->r->ndiv++;
        cik_put_fmt(&c->r->divg, "  %s declares [%s]\n  %s declares [%s]\n"
                    "    (handler %s, input schema %s)\n", l->path, canon,
                    g->leaf, g->canon, l->handler, l->schema);
    }
    free(canon);
}

static void cik_leaves(struct cik_ctx *c, const struct cik_defs *d)
{
    int *bound = cik_mem(NULL, (c->x->dict.n + 1) * sizeof *bound, "cik_bound");
    memset(bound, 0, (c->x->dict.n + 1) * sizeof *bound);
    for (size_t i = 0; i < d->n; i++)
        bound[d->leaf[i].hid]++;
    for (size_t i = 0; i < d->n; i++) {
        const struct cik_leaf *l = &d->leaf[i];
        const struct cik_fn *fn = cik_index_find(c->x, l->hid);
        if (!fn) {
            c->r->unresolved++;
            cik_put_fmt(&c->r->unres, "    %s -> %s\n", l->path,
                        l->handler);
            continue;
        }
        c->r->resolved++;
        cik_set_clear(&c->decl);
        cik_decl_csv(c, l->in);
        cik_decl_csv(c, l->pos);
        if (bound[l->hid] > 1)
            cik_leaf_shared(c, l);
        else
            cik_leaf_plain(c, l, fn);
    }
    free(bound);
}

static void cik_ctx_free(struct cik_ctx *c)
{
    for (size_t i = 0; i < c->npin; i++) {
        free(c->pin[i].path);
        free(c->pin[i].key);
    }
    for (size_t i = 0; i < c->ngrp; i++)
        free(c->grp[i].canon);
    free(c->pin);
    free(c->grp);
    cik_set_free(&c->decl);
}

int cik_analyze(const char *baseline, struct cik_index *x,
                const struct cik_defs *d, struct cik_report *r, FILE *err)
{
    struct cik_ctx c = { .x = x, .r = r };
    int rc = cik_pins_load(&c, baseline, err);
    if (rc == 0 && cik_closure(x) >= CIK_ROUNDS)
        rc = 3;
    if (rc == 0)
        cik_leaves(&c, d);
    for (size_t i = 0; rc == 0 && i < c.npin; i++)
        if (!c.pin[i].hit) {
            r->nstale++;
            cik_put_fmt(&r->stale, "  %s %s\n", c.pin[i].path, c.pin[i].key);
        }
    cik_ctx_free(&c);
    return rc;
}

void cik_report_free(struct cik_report *r)
{
    cik_buf_free(&r->miss);
    cik_buf_free(&r->divg);
    cik_buf_free(&r->stale);
    cik_buf_free(&r->unread);
    cik_buf_free(&r->unres);
    *r = (struct cik_report){ 0 };
}
