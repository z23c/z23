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
    struct premise_catalog cat;          /* catalog-row gates only */
    uint8_t residue[PREMISE_HASH_BYTES];
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

/* A catalog-row gate's residue is gate-wide: every row carries it. */
static int side_catalog(struct side *s, const struct premise_gate *g, FILE *err)
{
    if (!g->catalog)
        return 0;
    if (premise_catalog_open(s->t, g->catalog, &s->cat, err)
        || premise_catalog_residue(&s->cat, s->residue))
        return 2;
    return 0;
}

static int side_load(struct side *s, const struct premise_gate *g, FILE *err)
{
    if (g->n_baselines > SIDE_BASELINES || side_code(s, g, err)
        || side_make(s, g, err) || side_catalog(s, g, err))
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
    if (g->catalog)
        sha3_256_write(&h, s->residue, PREMISE_HASH_BYTES);
    sha3_256_finalize(&h, s->gate);
    return 0;
}

static void side_free(struct side *s)
{
    premise_make_values_free(s->vals, s->nvals);
    for (size_t i = 0; i < SIDE_BASELINES; i++)
        free(s->baseline[i]);
    premise_catalog_close(&s->cat);
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
    uint8_t row[PREMISE_HASH_BYTES];     /* catalog-row gates: own text */
    uint8_t root[PREMISE_HASH_BYTES];
};

static int unit_parts(struct side *s, const struct premise_tree *cand,
                      const struct premise_gate *g, const char *unit,
                      const struct closure *c, struct unit_parts *p,
                      const char **first_diff, FILE *err)
{
    bool computed = false;
    if (closure_root(s, cand, c, p->closure, first_diff, err)
        || (g->catalog
            && premise_catalog_row_root(&s->cat, unit, p->row, &computed)))
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
    if (g->catalog)
        sha3_256_write(&h, p->row, PREMISE_HASH_BYTES);
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
    else if (g->catalog && differ(c->residue, b->residue))
        snprintf(u->reason, sizeof u->reason, "catalog-residue:%s",
                 g->catalog);
    else
        snprintf(u->reason, sizeof u->reason, "pin");
}

/* The unit's own text: its baseline rows, or its catalog row. */
static const char *text_reason(const struct premise_gate *g,
                               const struct unit_parts *pc,
                               const struct unit_parts *pb)
{
    if (differ(pc->rows, pb->rows))
        return "baseline-rows-changed";
    if (g->catalog && differ(pc->row, pb->row))
        return "catalog-row-changed";
    return NULL;
}

static void decide(struct premise_session *s, const struct premise_gate *g,
                   struct premise_unit *u, struct side *c, struct side *b,
                   const struct unit_parts *pc, const struct unit_parts *pb,
                   const char *first_diff)
{
    const char *text = text_reason(g, pc, pb);
    u->would_inherit = false;
    if (differ(c->gate, b->gate))
        gate_reason(u, g, c, b);
    else if (differ(s->cand.path_set_root, s->base.path_set_root))
        snprintf(u->reason, sizeof u->reason, "path-set-changed");
    else if (text)
        snprintf(u->reason, sizeof u->reason, "%s", text);
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

static int unit_closure(struct premise_session *s, const struct premise_gate *g,
                        const char *unit, struct closure *c, FILE *err)
{
    if (g->unit_self) {
        const struct premise_entry *e = premise_tree_find(&s->cand, unit);
        if (!e)
            return 1;
        c->idx = malloc(sizeof *c->idx); // raw-alloc-ok:lint-runtime
        if (!c->idx)
            return 2;
        c->idx[0] = (size_t)(e - s->cand.entries);
        c->n = 1;
        return 0;
    }
    int rc = g->catalog
                 ? premise_catalog_row_closure(&s->cand, g->catalog, unit,
                                               &c->idx, &c->n, &c->ext,
                                               &c->next, &c->computed, err)
             : g->doc_claims
                 ? premise_doc_claims_closure(&s->cand, unit, &c->idx, &c->n,
                                              &c->ext, &c->next, &c->computed,
                                              err)
                 : premise_include_closure(&s->cand, unit, &c->idx, &c->n,
                                           &c->ext, &c->next, &c->computed,
                                           err);
    if (rc == 0 && c->next > 1)
        qsort(c->ext, c->next, sizeof *c->ext, cmp_str);
    return rc;
}

/* A path unit exists in the base tree; a catalog row, in the base list. */
static bool unit_in_base(const struct premise_session *s,
                         const struct premise_gate *g, const struct side *b,
                         const char *unit)
{
    return g->catalog ? premise_catalog_has(&b->cat, unit)
                      : premise_tree_find(&s->base, unit) != NULL;
}

static int unit_eval(struct premise_session *s, const struct premise_gate *g,
                     struct side *c, struct side *b, struct premise_unit *u,
                     FILE *err)
{
    struct closure cl = { 0 };
    int rc = unit_closure(s, g, u->unit, &cl, err);
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
    else if (rc == 0 && !unit_in_base(s, g, b, u->unit))
        snprintf(u->reason, sizeof u->reason, "unit-new");
    else if (rc == 0)
        decide(s, g, u, c, b, &pc, &pb, first_diff);
    closure_free(&cl);
    return rc;
}

/* ── gate code expansion ─────────────────────────────────────────────── */

/* The gate code a unit's verdict can depend on, as candidate paths: each
 * declared gate file ("dir/" = every path under dir), each path a word of
 * the declared Makefile values names, and the include closure of every
 * .c/.h among them. The base side hashes this same list; a path the base
 * adds under a prefix or a closure also changes the path set. */
struct code_list {
    const char **v;
    size_t n, cap;
    bool computed;
};

static int code_push(struct code_list *cl, const char *path)
{
    if (cl->n == cl->cap) {
        size_t cap = cl->cap ? cl->cap * 2 : 64;
        const char **grown = realloc(cl->v, cap * sizeof *grown); // raw-alloc-ok:lint-runtime
        if (!grown)
            return 2;
        cl->v = grown;
        cl->cap = cap;
    }
    cl->v[cl->n++] = path;
    return 0;
}

static int code_prefix(struct code_list *cl, const struct premise_tree *t,
                       const char *prefix)
{
    size_t k = strlen(prefix);
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < t->count; i++)
        if (strncmp(t->entries[i].path, prefix, k) == 0)
            rc = code_push(cl, t->entries[i].path);
    return rc;
}

static bool word_sep(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\\';
}

/* Push the tree path spelled by p[0..n), if there is one. */
static int code_word(struct code_list *cl, const struct premise_tree *t,
                     const char *p, size_t n)
{
    char word[PREMISE_PATH_MAX];
    if (n == 0 || n >= sizeof word)
        return 0;
    memcpy(word, p, n);
    word[n] = '\0';
    const struct premise_entry *e = premise_tree_find(t, word);
    return e ? code_push(cl, e->path) : 0;
}

/* Every whitespace- or backslash-separated word of text that is a path. */
static int code_words(struct code_list *cl, const struct premise_tree *t,
                      const char *text)
{
    int rc = 0;
    for (const char *p = text; rc == 0 && p && *p;) {
        while (*p && word_sep(*p))
            p++;
        const char *q = p;
        while (*q && !word_sep(*q))
            q++;
        rc = code_word(cl, t, p, (size_t)(q - p));
        p = q;
    }
    return rc;
}

static int code_make(struct code_list *cl, struct premise_tree *t,
                     const struct premise_gate *g, FILE *err)
{
    if (g->n_make_vars == 0)
        return 0;
    uint8_t *mk = NULL;
    size_t len = 0;
    int rc = premise_tree_read(t, g->makefile ? g->makefile : "Makefile", &mk,
                               &len, err);
    if (rc == 2)
        return 2;
    struct premise_make_value *vals = NULL;
    size_t nvals = 0;
    rc = premise_make_values(mk, len, g->make_vars, g->n_make_vars, &vals,
                             &nvals);
    free(mk);
    for (size_t i = 0; rc == 0 && i < nvals; i++)
        rc = code_words(cl, t, vals[i].text);
    premise_make_values_free(vals, nvals);
    return rc;
}

static bool code_is_c(const char *path)
{
    size_t n = strlen(path);
    return n > 2 && path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

static int code_closures(struct code_list *cl, struct premise_tree *t,
                         FILE *err)
{
    size_t declared = cl->n;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < declared; i++) {
        if (!code_is_c(cl->v[i]) || !premise_tree_find(t, cl->v[i]))
            continue;
        size_t *idx = NULL, nidx = 0, next = 0;
        char **ext = NULL;
        bool computed = false;
        rc = premise_include_closure(t, cl->v[i], &idx, &nidx, &ext, &next,
                                     &computed, err);
        cl->computed = cl->computed || computed;
        for (size_t j = 0; rc == 0 && j < nidx; j++)
            rc = code_push(cl, t->entries[idx[j]].path);
        free(idx);
        free(ext);
    }
    return rc;
}

static int cmp_cstr(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int code_expand(struct premise_session *s, const struct premise_gate *g,
                       struct code_list *cl, FILE *err)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < g->n_gate_files; i++) {
        const char *f = g->gate_files[i];
        size_t k = strlen(f);
        rc = k > 0 && f[k - 1] == '/' ? code_prefix(cl, &s->cand, f)
                                      : code_push(cl, f);
    }
    if (rc == 0)
        rc = code_make(cl, &s->cand, g, err);
    if (rc == 0)
        rc = code_closures(cl, &s->cand, err);
    if (rc || cl->n < 2)
        return rc;
    qsort(cl->v, cl->n, sizeof *cl->v, cmp_cstr);
    size_t w = 1;
    for (size_t i = 1; i < cl->n; i++)
        if (strcmp(cl->v[i], cl->v[w - 1]) != 0)
            cl->v[w++] = cl->v[i];
    cl->n = w;
    return 0;
}

int premise_gate_eval(struct premise_session *s, const struct premise_gate *g,
                      struct premise_unit *units, size_t n, FILE *err)
{
    struct code_list cl = { 0 };
    int rc = code_expand(s, g, &cl, err);
    struct premise_gate eg = *g;
    eg.gate_files = cl.v;
    eg.n_gate_files = cl.n;
    struct side c = { .t = &s->cand }, b = { .t = &s->base };
    if (rc == 0)
        rc = side_load(&c, &eg, err);
    if (rc == 0 && s->base_verified)
        rc = side_load(&b, &eg, err);
    for (size_t i = 0; rc == 0 && i < n; i++) {
        units[i].would_inherit = false;
        units[i].base_root_known = false;
        rc = unit_eval(s, &eg, &c, &b, &units[i], err);
        if (rc == 0 && cl.computed) {
            units[i].would_inherit = false;
            snprintf(units[i].reason, sizeof units[i].reason,
                     "gate-computed-include");
        }
    }
    side_free(&c);
    side_free(&b);
    free(cl.v);
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
    struct code_list code = { 0 };
    int rc = code_expand(s, g, &code, err);
    if (rc == 0)
        rc = unit_closure(s, g, unit, &cl, err);
    if (rc == 0 && (cl.computed || code.computed))
        rc = 1;
    for (size_t i = 0; rc == 0 && i < cl.n; i++)
        rc = grant_line(out, &s->cand, s->cand.entries[cl.idx[i]].path);
    for (size_t i = 0; rc == 0 && i < code.n; i++)
        rc = grant_line(out, &s->cand, code.v[i]);
    for (size_t i = 0; rc == 0 && i < g->n_baselines; i++)
        rc = grant_line(out, &s->cand, g->baselines[i]);
    if (rc == 0)
        rc = grant_line(out, &s->cand, g->pin ? g->pin : "tools/dev/toolchain.pin");
    if (rc == 0 && g->catalog)
        rc = grant_line(out, &s->cand, g->catalog);
    closure_free(&cl);
    free(code.v);
    return rc;
}
