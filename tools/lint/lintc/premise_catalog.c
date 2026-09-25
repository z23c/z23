/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: catalog-row units for premise selection — one unit per row of a
 * make catalog whose rows each build one program (today the Windows
 * acceptance catalog). A row's premise is the text of its own variables,
 * the include closure of every tree path those variables name, and the
 * catalog residue: every line no row owns. Nothing here is authority.
 *
 * Row id X owns the definitions of <P>X_SOURCES, <P>X_FLAGS, <P>X_LIBS and
 * <P>X_LIBDEPS (P = ZCL_WINDOWS_ACCEPTANCE_), the four variables the
 * generated rule in the Makefile reads. The list variable <P>TESTS, which
 * names the rows, is owned by the gate's global part: it decides which rows
 * exist, never how one row builds. Everything else in the catalog (shared
 * variables, conditionals, rules, a fifth per-row suffix a later template
 * might read) is residue and in every row's premise. Comment lines outside
 * a define block are not residue. A row's text is followed through every
 * variable it references, so a row reading another row's variable carries
 * that text too. Any expansion other than a plain $(NAME) reference makes
 * the row's premise unbounded, and the row then never inherits.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <stdlib.h>
#include <string.h>

#include "sha3/sha3.h"

#define CAT_PREFIX "ZCL_WINDOWS_ACCEPTANCE_"
#define CAT_LIST CAT_PREFIX "TESTS"
#define CAT_ID_MAX 128

static const char *const k_suffix[] = { "_SOURCES", "_FLAGS", "_LIBS",
                                        "_LIBDEPS" };
enum { CAT_NSUFFIX = sizeof k_suffix / sizeof k_suffix[0] };

static bool id_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
           || (c >= '0' && c <= '9') || c == '_';
}

static void put_tag(struct sha3_256_ctx *h, const char *s)
{
    sha3_256_write(h, (const unsigned char *)s, strlen(s) + 1);
}

static bool word_is(const char *p, size_t n, const char *w)
{
    return strlen(w) == n && memcmp(p, w, n) == 0;
}

static bool list_sep(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\\';
}

static int ids_push(struct premise_catalog *c, const char *p, size_t n)
{
    char **grown = realloc(c->ids, (c->nids + 1) * sizeof *grown); // raw-alloc-ok:lint-runtime
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!grown || !copy) {
        if (grown)
            c->ids = grown;
        free(copy);
        return 2;
    }
    memcpy(copy, p, n);
    copy[n] = '\0';
    grown[c->nids++] = copy;
    c->ids = grown;
    return 0;
}

/* One word of the list's text: its own name, an assignment operator right
 * after it, or a literal row id. Anything else (a reference, a prefix, a
 * conditional assignment) is a list this parser will not guess at. */
static int list_word(struct premise_catalog *c, const char *p, size_t n,
                     bool *after_name)
{
    if (word_is(p, n, CAT_LIST)) {
        *after_name = true;
        return 0;
    }
    bool op = word_is(p, n, ":=") || word_is(p, n, "=") || word_is(p, n, "+=");
    if (*after_name) {
        *after_name = false;
        return op ? 0 : 2;
    }
    for (size_t i = 0; i < n; i++)
        if (!id_char(p[i]))
            return 2;
    if (n >= CAT_ID_MAX || word_is(p, n, "override") || word_is(p, n, "export")
        || word_is(p, n, "private"))
        return 2;
    return ids_push(c, p, n);
}

static int parse_ids(struct premise_catalog *c, const char *text, FILE *err)
{
    bool after_name = false;
    int rc = text ? 0 : 2;
    for (const char *p = text; rc == 0 && *p;) {
        while (*p && list_sep(*p))
            p++;
        const char *q = p;
        while (*q && !list_sep(*q))
            q++;
        if (q > p)
            rc = list_word(c, p, (size_t)(q - p), &after_name);
        p = q;
    }
    if (rc == 0 && (after_name || c->nids == 0))
        rc = 2;
    if (rc == 2)
        fprintf(err, "premise: %s is not a literal list of row ids\n", CAT_LIST);
    return rc;
}

int premise_catalog_open(struct premise_tree *t, const char *path,
                         struct premise_catalog *c, FILE *err)
{
    memset(c, 0, sizeof *c);
    int rc = premise_tree_read(t, path, &c->mk, &c->len, err);
    if (rc == 1)
        return 0;
    if (rc)
        return 2;
    c->present = true;
    static const char *const list[] = { CAT_LIST };
    struct premise_make_value *vals = NULL;
    size_t nvals = 0;
    rc = premise_make_values(c->mk, c->len, list, 1, &vals, &nvals);
    const char *text = NULL;
    for (size_t i = 0; rc == 0 && i < nvals; i++)
        if (strcmp(vals[i].name, CAT_LIST) == 0)
            text = vals[i].text;
    if (rc == 0 && text && strchr(text, '$'))
        text = NULL;
    if (rc == 0)
        rc = parse_ids(c, text, err);
    premise_make_values_free(vals, nvals);
    return rc;
}

void premise_catalog_close(struct premise_catalog *c)
{
    for (size_t i = 0; i < c->nids; i++)
        free(c->ids[i]);
    free(c->ids);
    free(c->mk);
    memset(c, 0, sizeof *c);
}

bool premise_catalog_has(const struct premise_catalog *c, const char *id)
{
    for (size_t i = 0; i < c->nids; i++)
        if (strcmp(c->ids[i], id) == 0)
            return true;
    return false;
}

/* The four variable names row id owns, in buf. */
static bool row_names(const char *id, char buf[CAT_NSUFFIX][CAT_ID_MAX * 2],
                      const char *names[CAT_NSUFFIX])
{
    for (size_t i = 0; i < CAT_NSUFFIX; i++) {
        int k = snprintf(buf[i], sizeof buf[i], "%s%s%s", CAT_PREFIX, id,
                         k_suffix[i]);
        if (k < 0 || (size_t)k >= sizeof buf[i])
            return false;
        names[i] = buf[i];
    }
    return true;
}

/* Every name any row of the list owns, plus the list itself. */
static int owned_names(const struct premise_catalog *c, char ***out, size_t *n)
{
    size_t cap = c->nids * CAT_NSUFFIX + 1;
    char **v = calloc(cap, sizeof *v); // raw-alloc-ok:lint-runtime
    if (!v)
        return 2;
    size_t k = 0;
    v[k++] = strdup(CAT_LIST);
    for (size_t i = 0; i < c->nids; i++) {
        char buf[CAT_NSUFFIX][CAT_ID_MAX * 2];
        const char *names[CAT_NSUFFIX];
        if (!row_names(c->ids[i], buf, names))
            break;
        for (size_t j = 0; j < CAT_NSUFFIX; j++)
            v[k++] = strdup(names[j]);
    }
    int rc = 0;
    for (size_t i = 0; i < cap; i++)
        if (!v[i])
            rc = 2;
    *out = v;
    *n = cap;
    return rc;
}

static void names_free(char **v, size_t n)
{
    for (size_t i = 0; v && i < n; i++)
        free(v[i]);
    free(v);
}

int premise_catalog_residue(const struct premise_catalog *c,
                            uint8_t out[PREMISE_HASH_BYTES])
{
    char **owned = NULL;
    size_t nowned = 0;
    char *text = NULL;
    size_t len = 0;
    int rc = owned_names(c, &owned, &nowned);
    if (rc == 0 && c->present)
        rc = premise_make_residue(c->mk, c->len, (const char *const *)owned,
                                  nowned, &text, &len);
    names_free(owned, nowned);
    if (rc)
        return rc;
    static const unsigned char absent = 0, present = 1;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_tag(&h, "zcl.lint.premise.catalog_residue.v1");
    sha3_256_write(&h, c->present ? &present : &absent, 1);
    if (text)
        sha3_256_write(&h, (const unsigned char *)text, len);
    sha3_256_finalize(&h, out);
    free(text);
    return 0;
}

/* The only expansions a row may hold: $$ and $(NAME) / ${NAME}. */
static bool text_bounded(const char *s)
{
    for (const char *p = s ? strchr(s, '$') : NULL; p; p = strchr(p, '$')) {
        if (p[1] == '$') {
            p += 2;
            continue;
        }
        char close = p[1] == '(' ? ')' : p[1] == '{' ? '}' : '\0';
        const char *q = p + 2;
        while (close && id_char(*q))
            q++;
        if (!close || q == p + 2 || *q != close)
            return false;
        p = q;
    }
    return true;
}

static int row_values(const struct premise_catalog *c, const char *id,
                      struct premise_make_value **vals, size_t *nvals,
                      bool *computed)
{
    char buf[CAT_NSUFFIX][CAT_ID_MAX * 2];
    const char *names[CAT_NSUFFIX];
    *vals = NULL;
    *nvals = 0;
    if (!row_names(id, buf, names))
        return 2;
    int rc = premise_make_values(c->mk, c->len, names, CAT_NSUFFIX, vals,
                                 nvals);
    for (size_t i = 0; rc == 0 && i < *nvals; i++)
        *computed = *computed || !text_bounded((*vals)[i].text);
    return rc;
}

int premise_catalog_row_root(const struct premise_catalog *c, const char *id,
                             uint8_t out[PREMISE_HASH_BYTES], bool *computed)
{
    struct premise_make_value *vals = NULL;
    size_t nvals = 0;
    int rc = row_values(c, id, &vals, &nvals, computed);
    if (rc)
        return rc;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    put_tag(&h, "zcl.lint.premise.catalog_row.v1");
    for (size_t i = 0; i < nvals; i++) {
        const char *text = vals[i].text ? vals[i].text : "\x01undefined";
        sha3_256_write(&h, (const unsigned char *)vals[i].name,
                       strlen(vals[i].name) + 1);
        sha3_256_write(&h, (const unsigned char *)text, strlen(text) + 1);
    }
    sha3_256_finalize(&h, out);
    premise_make_values_free(vals, nvals);
    return 0;
}

/* ── row closure (candidate side) ──────────────────────────────────────── */

struct row_walk {
    struct premise_tree *t;
    size_t *idx;
    size_t n;
    char **ext;
    size_t next;
    bool computed;
    FILE *err;
};

static int walk_push(struct row_walk *w, size_t x)
{
    size_t *grown = realloc(w->idx, (w->n + 1) * sizeof *grown); // raw-alloc-ok:lint-runtime
    if (!grown)
        return 2;
    grown[w->n++] = x;
    w->idx = grown;
    return 0;
}

static int walk_ext(struct row_walk *w, char **ext, size_t n)
{
    if (n == 0)
        return 0;
    char **grown = realloc(w->ext, (w->next + n) * sizeof *grown); // raw-alloc-ok:lint-runtime
    if (!grown)
        return 2;
    memcpy(grown + w->next, ext, n * sizeof *ext);
    w->next += n;
    w->ext = grown;
    return 0;
}

static bool is_c_source(const char *path)
{
    size_t n = strlen(path);
    return n > 2 && path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

/* One tree path named by the row: itself, and its include closure when it
 * is a C source or header. */
static int walk_path(struct row_walk *w, const struct premise_entry *e)
{
    if (!is_c_source(e->path))
        return walk_push(w, (size_t)(e - w->t->entries));
    size_t *idx = NULL, nidx = 0, next = 0;
    char **ext = NULL;
    bool computed = false;
    int rc = premise_include_closure(w->t, e->path, &idx, &nidx, &ext, &next,
                                     &computed, w->err);
    w->computed = w->computed || computed;
    for (size_t i = 0; rc == 0 && i < nidx; i++)
        rc = walk_push(w, idx[i]);
    if (rc == 0)
        rc = walk_ext(w, ext, next);
    free(idx);
    free(ext);
    return rc;
}

/* Words of a row's text, split at blanks, backslashes and the punctuation a
 * compiler flag wraps a file name in (-Wl,a,b  --opt=path  @file  -l:x),
 * so every tree path the text can name reaches the premise. */
static bool path_sep(char c)
{
    return list_sep(c) || c == '=' || c == ',' || c == '@' || c == ':';
}

static int walk_text(struct row_walk *w, const char *text)
{
    int rc = 0;
    for (const char *p = text; rc == 0 && p && *p;) {
        while (*p && path_sep(*p))
            p++;
        const char *q = p;
        while (*q && !path_sep(*q))
            q++;
        char word[PREMISE_PATH_MAX];
        size_t n = (size_t)(q - p);
        const struct premise_entry *e = NULL;
        if (n > 0 && n < sizeof word) {
            memcpy(word, p, n);
            word[n] = '\0';
            e = premise_tree_find(w->t, word);
        }
        if (e)
            rc = walk_path(w, e);
        p = q;
    }
    return rc;
}

static int cmp_idx(const void *a, const void *b)
{
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return (x > y) - (x < y);
}

static void walk_unique(struct row_walk *w)
{
    if (w->n < 2)
        return;
    qsort(w->idx, w->n, sizeof *w->idx, cmp_idx);
    size_t k = 1;
    for (size_t i = 1; i < w->n; i++)
        if (w->idx[i] != w->idx[k - 1])
            w->idx[k++] = w->idx[i];
    w->n = k;
}

/* A row can link a make-built artifact through a variable the catalog does
 * not define (today $(ZCL_WINDOWS_ACCEPTANCE_SQLITE), the private archive).
 * For every variable the row's text reaches, its Makefile definitions and
 * the rule whose target is spelled $(NAME) or ${NAME} join the row: every
 * tree path in that text (the archive's vendored source) is walked like a
 * row source. The rest of the Makefile is gate code already. */
static int walk_makefile(struct row_walk *w, const char *makefile,
                         const struct premise_make_value *vals, size_t nvals)
{
    enum { REF_FORMS = 3 };
    char (*names)[CAT_ID_MAX * 2] = calloc(nvals * REF_FORMS + 1, sizeof *names); // raw-alloc-ok:lint-runtime
    const char **list = calloc(nvals * REF_FORMS + 1, sizeof *list); // raw-alloc-ok:lint-runtime
    uint8_t *mk = NULL;
    size_t len = 0, n = 0;
    int rc = names && list ? 0 : 2;
    for (size_t i = 0; rc == 0 && i < nvals; i++, n += REF_FORMS) {
        const char *v = vals[i].name;
        size_t cap = sizeof names[n];
        int a = snprintf(names[n], cap, "%s", v);
        int b = snprintf(names[n + 1], cap, "$(%s):", v);
        int c = snprintf(names[n + 2], cap, "${%s}:", v);
        rc = a < 0 || b < 0 || c < 0 || (size_t)b >= cap || (size_t)c >= cap
                 ? 2 : 0;
        for (size_t j = 0; j < REF_FORMS; j++)
            list[n + j] = names[n + j];
    }
    if (rc == 0 && premise_tree_read(w->t, makefile, &mk, &len, w->err) == 2)
        rc = 2;
    struct premise_make_value *mv = NULL;
    size_t nmv = 0;
    if (rc == 0)
        rc = premise_make_values(mk, len, list, n, &mv, &nmv);
    for (size_t i = 0; rc == 0 && i < nmv; i++)
        rc = walk_text(w, mv[i].text);
    premise_make_values_free(mv, nmv);
    free(mk);
    free(list);
    free(names);
    return rc;
}

int premise_catalog_row_closure(struct premise_tree *t, const char *catalog,
                                const char *makefile,
                                const char *id, size_t **out, size_t *nout,
                                char ***ext, size_t *next, bool *computed,
                                FILE *err)
{
    struct premise_catalog c;
    struct row_walk w = { .t = t, .err = err };
    int rc = premise_catalog_open(t, catalog, &c, err);
    if (rc == 0 && !premise_catalog_has(&c, id))
        rc = 1;
    struct premise_make_value *vals = NULL;
    size_t nvals = 0;
    if (rc == 0)
        rc = row_values(&c, id, &vals, &nvals, &w.computed);
    for (size_t i = 0; rc == 0 && i < nvals; i++)
        rc = walk_text(&w, vals[i].text);
    if (rc == 0)
        rc = walk_makefile(&w, makefile, vals, nvals);
    premise_make_values_free(vals, nvals);
    premise_catalog_close(&c);
    if (rc) {
        free(w.idx);
        free(w.ext);
        return rc;
    }
    walk_unique(&w);
    *out = w.idx;
    *nout = w.n;
    *ext = w.ext;
    *next = w.next;
    *computed = w.computed;
    return 0;
}
