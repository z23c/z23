/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: premise roots and the would-inherit decision for one gate's
 * units. The same fold runs over the candidate generation and over the
 * verified base tree; the base side reuses the candidate's closure path
 * list, which is sound because the closure is a function of the path set
 * and the bytes of the files in it — if every one of those is equal, the
 * base closure is the same list. The decision is information only.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <stdlib.h>
#include <string.h>

#include "sha3/sha3.h"

enum { SIDE_BASELINES = 8 };

struct side {
    struct premise_tree *t;
    uint8_t code[PREMISE_HASH_BYTES];
    uint8_t make[PREMISE_HASH_BYTES];
    uint8_t pin[PREMISE_HASH_BYTES];
    uint8_t gate[PREMISE_HASH_BYTES];
    struct premise_make_value *vals;
    size_t nvals;
    uint8_t *baseline[SIDE_BASELINES];
    size_t baseline_len[SIDE_BASELINES];
};

static void put_str(struct sha3_256_ctx *h, const char *s)
{
    sha3_256_write(h, (const unsigned char *)s, strlen(s) + 1);
}

static void put_file(struct sha3_256_ctx *h, struct premise_entry *e)
{
    static const unsigned char absent = 0, present = 1;
    if (!e || !e->present) {
        sha3_256_write(h, &absent, 1);
        return;
    }
    sha3_256_write(h, &present, 1);
    sha3_256_write(h, e->hash, PREMISE_HASH_BYTES);
}

/* Hash e (NULL-safe). An absent path is a hashed state, not an error. */
static int hash_path(struct premise_tree *t, const char *path,
                     struct premise_entry **out, FILE *err)
{
    *out = premise_tree_find(t, path);
    return *out ? premise_tree_hash(t, *out, err) : 0;
}

static int side_code(struct side *s, const struct premise_gate *g, FILE *err)
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.gate_code.v1");
    put_str(&h, g->name);
    for (size_t i = 0; i < g->n_gate_files; i++) {
        struct premise_entry *e = NULL;
        if (hash_path(s->t, g->gate_files[i], &e, err))
            return 2;
        put_str(&h, g->gate_files[i]);
        put_file(&h, e);
    }
    sha3_256_finalize(&h, s->code);
    struct premise_entry *pin = NULL;
    if (hash_path(s->t, g->pin ? g->pin : "tools/dev/toolchain.pin", &pin, err))
        return 2;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.pin.v1");
    put_file(&h, pin);
    sha3_256_finalize(&h, s->pin);
    return 0;
}

static int side_make(struct side *s, const struct premise_gate *g, FILE *err)
{
    uint8_t *mk = NULL;
    size_t len = 0;
    int rc = premise_tree_read(s->t, g->makefile ? g->makefile : "Makefile",
                               &mk, &len, err);
    if (rc == 2)
        return 2;
    rc = premise_make_values(mk, len, g->make_vars, g->n_make_vars, &s->vals,
                             &s->nvals);
    free(mk);
    if (rc)
        return rc;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.make_values.v1");
    for (size_t i = 0; i < s->nvals; i++) {
        put_str(&h, s->vals[i].name);
        put_str(&h, s->vals[i].text ? s->vals[i].text : "\x01undefined");
    }
    sha3_256_finalize(&h, s->make);
    return 0;
}

static int side_load(struct side *s, const struct premise_gate *g, FILE *err)
{
    if (g->n_baselines > SIDE_BASELINES || side_code(s, g, err)
        || side_make(s, g, err))
        return 2;
    for (size_t i = 0; i < g->n_baselines; i++)
        if (premise_tree_read(s->t, g->baselines[i], &s->baseline[i],
                              &s->baseline_len[i], err) == 2)
            return 2;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.gate.v1");
    sha3_256_write(&h, s->code, PREMISE_HASH_BYTES);
    sha3_256_write(&h, s->make, PREMISE_HASH_BYTES);
    sha3_256_write(&h, s->pin, PREMISE_HASH_BYTES);
    sha3_256_finalize(&h, s->gate);
    return 0;
}

static void side_free(struct side *s)
{
    premise_make_values_free(s->vals, s->nvals);
    for (size_t i = 0; i < SIDE_BASELINES; i++)
        free(s->baseline[i]);
}

/* The unit's rows: lines whose first whitespace-delimited token is unit. */
static void put_rows(struct sha3_256_ctx *h, const uint8_t *text, size_t len,
                     const char *unit)
{
    size_t u = strlen(unit);
    const char *p = (const char *)text, *end = p ? p + len : p;
    while (p && p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *stop = nl ? nl : end;
        if ((size_t)(stop - p) >= u && memcmp(p, unit, u) == 0
            && (p + u == stop || p[u] == ' ' || p[u] == '\t'))
            sha3_256_write(h, (const unsigned char *)p, (size_t)(stop - p) + 1);
        p = nl ? nl + 1 : end;
    }
}

static void rows_root(const struct side *s, const struct premise_gate *g,
                      const char *unit, uint8_t out[PREMISE_HASH_BYTES])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.baseline_rows.v1");
    for (size_t i = 0; i < g->n_baselines; i++) {
        put_str(&h, g->baselines[i]);
        put_rows(&h, s->baseline[i], s->baseline_len[i], unit);
    }
    sha3_256_finalize(&h, out);
}

struct closure {
    size_t *idx;
    size_t n;
    char **ext;
    size_t next;
    bool computed;
};

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int closure_root(struct side *s, const struct premise_tree *cand,
                        const struct closure *c, uint8_t out[PREMISE_HASH_BYTES],
                        const char **first_diff, FILE *err)
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.closure.v1");
    for (size_t i = 0; i < c->n; i++) {
        const char *path = cand->entries[c->idx[i]].path;
        struct premise_entry *e = NULL;
        if (hash_path(s->t, path, &e, err))
            return 2;
        struct premise_entry *mine = &cand->entries[c->idx[i]];
        if (first_diff && !*first_diff
            && (!e || memcmp(e->hash, mine->hash, PREMISE_HASH_BYTES) != 0))
            *first_diff = path;
        put_str(&h, path);
        put_file(&h, e);
    }
    for (size_t i = 0; i < c->next; i++)
        if (i == 0 || strcmp(c->ext[i - 1], c->ext[i]) != 0)
            put_str(&h, c->ext[i]);
    sha3_256_finalize(&h, out);
    return 0;
}

struct unit_parts {
    uint8_t closure[PREMISE_HASH_BYTES];
    uint8_t rows[PREMISE_HASH_BYTES];
    uint8_t root[PREMISE_HASH_BYTES];
};

static int unit_parts(struct side *s, const struct premise_tree *cand,
                      const struct premise_gate *g, const char *unit,
                      const struct closure *c, struct unit_parts *p,
                      const char **first_diff, FILE *err)
{
    if (closure_root(s, cand, c, p->closure, first_diff, err))
        return 2;
    rows_root(s, g, unit, p->rows);
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_str(&h, "zcl.lint.premise.unit.v1");
    sha3_256_write(&h, s->gate, PREMISE_HASH_BYTES);
    sha3_256_write(&h, s->t->path_set_root, PREMISE_HASH_BYTES);
    put_str(&h, unit);
    sha3_256_write(&h, p->closure, PREMISE_HASH_BYTES);
    sha3_256_write(&h, p->rows, PREMISE_HASH_BYTES);
    sha3_256_finalize(&h, p->root);
    return 0;
}

static const char *first_gate_file_diff(const struct premise_gate *g,
                                        struct side *c, struct side *b)
{
    for (size_t i = 0; i < g->n_gate_files; i++) {
        struct premise_entry *x = premise_tree_find(c->t, g->gate_files[i]);
        struct premise_entry *y = premise_tree_find(b->t, g->gate_files[i]);
        bool xp = x && x->present, yp = y && y->present;
        if (xp != yp || (xp && memcmp(x->hash, y->hash, PREMISE_HASH_BYTES)))
            return g->gate_files[i];
    }
    return "?";
}

static const char *first_make_diff(const struct side *c, const struct side *b)
{
    for (size_t i = 0; i < c->nvals && i < b->nvals; i++) {
        const char *x = c->vals[i].text ? c->vals[i].text : "";
        const char *y = b->vals[i].text ? b->vals[i].text : "";
        if (strcmp(c->vals[i].name, b->vals[i].name) != 0 || strcmp(x, y) != 0)
            return c->vals[i].name;
    }
    return c->nvals != b->nvals ? "(variable set)" : "?";
}

static bool differ(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, PREMISE_HASH_BYTES) != 0;
}

static void gate_reason(struct premise_unit *u, const struct premise_gate *g,
                        struct side *c, struct side *b)
{
    if (differ(c->code, b->code))
        snprintf(u->reason, sizeof u->reason, "gate-code:%s",
                 first_gate_file_diff(g, c, b));
    else if (differ(c->make, b->make))
        snprintf(u->reason, sizeof u->reason, "make-value:%s",
                 first_make_diff(c, b));
    else
        snprintf(u->reason, sizeof u->reason, "pin");
}

static void decide(struct premise_session *s, const struct premise_gate *g,
                   struct premise_unit *u, struct side *c, struct side *b,
                   const struct unit_parts *pc, const struct unit_parts *pb,
                   const char *first_diff)
{
    u->would_inherit = false;
    if (differ(c->gate, b->gate))
        gate_reason(u, g, c, b);
    else if (differ(s->cand.path_set_root, s->base.path_set_root))
        snprintf(u->reason, sizeof u->reason, "path-set-changed");
    else if (differ(pc->rows, pb->rows))
        snprintf(u->reason, sizeof u->reason, "baseline-rows-changed");
    else if (differ(pc->closure, pb->closure))
        snprintf(u->reason, sizeof u->reason, "closure-changed:%s",
                 first_diff ? first_diff : "(external names)");
    else if (s->disabled[0])
        snprintf(u->reason, sizeof u->reason, "%s", s->disabled);
    else {
        u->would_inherit = true;
        snprintf(u->reason, sizeof u->reason, "premise-equal");
    }
}

static void closure_free(struct closure *c)
{
    free(c->idx);
    free(c->ext);
    memset(c, 0, sizeof *c);
}

static int unit_closure(struct premise_session *s, const char *unit,
                        struct closure *c, FILE *err)
{
    int rc = premise_include_closure(&s->cand, unit, &c->idx, &c->n, &c->ext,
                                     &c->next, &c->computed, err);
    if (rc == 0 && c->next > 1)
        qsort(c->ext, c->next, sizeof *c->ext, cmp_str);
    return rc;
}

static int unit_eval(struct premise_session *s, const struct premise_gate *g,
                     struct side *c, struct side *b, struct premise_unit *u,
                     FILE *err)
{
    struct closure cl = { 0 };
    int rc = unit_closure(s, u->unit, &cl, err);
    if (rc == 1) {
        snprintf(u->reason, sizeof u->reason, "unit-missing");
        return 0;
    }
    struct unit_parts pc = { 0 }, pb = { 0 };
    const char *first_diff = NULL;
    if (rc == 0)
        rc = unit_parts(c, &s->cand, g, u->unit, &cl, &pc, NULL, err);
    memcpy(u->action_root, pc.root, PREMISE_HASH_BYTES);
    if (rc == 0 && s->base_verified) {
        rc = unit_parts(b, &s->cand, g, u->unit, &cl, &pb, &first_diff, err);
        memcpy(u->base_root, pb.root, PREMISE_HASH_BYTES);
        u->base_root_known = rc == 0;
    }
    if (rc == 0 && cl.computed)
        snprintf(u->reason, sizeof u->reason, "computed-include");
    else if (rc == 0 && !s->base_verified)
        snprintf(u->reason, sizeof u->reason, "%s", s->disabled);
    else if (rc == 0 && !premise_tree_find(&s->base, u->unit))
        snprintf(u->reason, sizeof u->reason, "unit-new");
    else if (rc == 0)
        decide(s, g, u, c, b, &pc, &pb, first_diff);
    closure_free(&cl);
    return rc;
}

int premise_gate_eval(struct premise_session *s, const struct premise_gate *g,
                      struct premise_unit *units, size_t n, FILE *err)
{
    struct side c = { .t = &s->cand }, b = { .t = &s->base };
    int rc = side_load(&c, g, err);
    if (rc == 0 && s->base_verified)
        rc = side_load(&b, g, err);
    for (size_t i = 0; rc == 0 && i < n; i++) {
        units[i].would_inherit = false;
        units[i].base_root_known = false;
        rc = unit_eval(s, g, &c, &b, &units[i], err);
    }
    side_free(&c);
    side_free(&b);
    return rc;
}

int premise_session_open(struct premise_session *s, const char *root,
                         const struct premise_base_opts *opts, bool confined,
                         FILE *err)
{
    memset(s, 0, sizeof *s);
    s->confined = confined;
    if (premise_tree_walk(&s->cand, root, err))
        return 2;
    if (!opts) {
        snprintf(s->disabled, sizeof s->disabled, "no-base");
        return 0;
    }
    char why[PREMISE_REASON_MAX] = "";
    int rc = premise_git_open(opts, &s->base, why, sizeof why, err);
    s->base_verified = rc == 0;
    if (rc)
        snprintf(s->disabled, sizeof s->disabled, "%s",
                 why[0] ? why : "base-unverified:private store unavailable");
    else if (!confined)
        snprintf(s->disabled, sizeof s->disabled, "landlock-unavailable");
    return 0;
}

void premise_session_close(struct premise_session *s)
{
    premise_tree_free(&s->cand);
    premise_tree_free(&s->base);
}

static int grant_line(FILE *out, struct premise_tree *t, const char *path)
{
    const struct premise_entry *e = premise_tree_find(t, path);
    if (!e || e->symlink)
        return 0;
    return fprintf(out, "%s\n", path) < 0 ? 2 : 0;
}

int premise_unit_grants(struct premise_session *s, const struct premise_gate *g,
                        const char *unit, FILE *out, FILE *err)
{
    struct closure cl = { 0 };
    int rc = unit_closure(s, unit, &cl, err);
    if (rc == 0 && cl.computed)
        rc = 1;
    for (size_t i = 0; rc == 0 && i < cl.n; i++)
        rc = grant_line(out, &s->cand, s->cand.entries[cl.idx[i]].path);
    for (size_t i = 0; rc == 0 && i < g->n_gate_files; i++)
        rc = grant_line(out, &s->cand, g->gate_files[i]);
    for (size_t i = 0; rc == 0 && i < g->n_baselines; i++)
        rc = grant_line(out, &s->cand, g->baselines[i]);
    if (rc == 0)
        rc = grant_line(out, &s->cand, g->pin ? g->pin : "tools/dev/toolchain.pin");
    closure_free(&cl);
    return rc;
}
