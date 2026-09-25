/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the over-approximate textual include closure of one lint unit.
 * Every #include, #include_next, #import and #embed line is followed,
 * ignoring #if, and each name resolves to EVERY tracked path it could name
 * under any -I order: the includer-relative path for a quoted name plus
 * every path equal to or ending in "/<name>". That superset is independent
 * of the gate's search order, so no -I list enters the premise; the path-set
 * root covers every existence lookup. A macro-computed include marks the
 * unit as having no finite premise. Names no tracked path matches are
 * toolchain headers, kept by name. Misses fail closed later: unit-exec
 * denies any read outside the premise this closure produced.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <stdlib.h>
#include <string.h>

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int push_size(size_t **v, size_t *n, size_t x)
{
    size_t *grown = realloc(*v, (*n + 1) * sizeof **v); // raw-alloc-ok:lint-runtime
    if (!grown)
        return 2;
    grown[(*n)++] = x;
    *v = grown;
    return 0;
}

static int push_str(char ***v, size_t *n, const char *s, size_t len)
{
    char **grown = realloc(*v, (*n + 1) * sizeof **v); // raw-alloc-ok:lint-runtime
    char *copy = malloc(len + 1); // raw-alloc-ok:lint-runtime
    if (!grown || !copy) {
        if (grown)
            *v = grown;
        free(copy);
        return 2;
    }
    memcpy(copy, s, len);
    copy[len] = '\0';
    grown[(*n)++] = copy;
    *v = grown;
    return 0;
}

/* Join dir and a relative name, folding "." and "..". Returns false when
 * the result would leave the tree or overflow. */
static bool join_norm(const char *dir, const char *name, char *out, size_t cap)
{
    char buf[PREMISE_PATH_MAX * 2];
    int k = snprintf(buf, sizeof buf, "%s%s%s", dir, dir[0] ? "/" : "", name);
    if (k < 0 || (size_t)k >= sizeof buf)
        return false;
    size_t used = 0;
    for (char *save = NULL, *c = strtok_r(buf, "/", &save); c;
         c = strtok_r(NULL, "/", &save)) {
        if (strcmp(c, ".") == 0)
            continue;
        if (strcmp(c, "..") == 0) {
            if (used == 0)
                return false;
            while (used > 0 && out[used - 1] != '/')
                used--;
            used = used > 0 ? used - 1 : 0;
            continue;
        }
        size_t n = strlen(c);
        if (used + n + 2 > cap)
            return false;
        if (used)
            out[used++] = '/';
        memcpy(out + used, c, n);
        used += n;
    }
    out[used] = '\0';
    return used > 0;
}

static size_t lower_bound(const struct premise_tree *t, const char *base)
{
    size_t lo = 0, hi = t->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(base_name(t->entries[t->by_base[mid]].path), base) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static bool suffix_match(const char *path, const char *rest)
{
    size_t p = strlen(path), r = strlen(rest);
    if (p == r)
        return strcmp(path, rest) == 0;
    return p > r && path[p - r - 1] == '/' && strcmp(path + p - r, rest) == 0;
}

/* Every tracked path the name could reach through any search directory. */
static int suffix_deps(const struct premise_tree *t, const char *name,
                       struct premise_entry *e, bool *found)
{
    while (strncmp(name, "./", 2) == 0 || strncmp(name, "../", 3) == 0)
        name += name[1] == '/' ? 2 : 3;
    const char *base = base_name(name);
    for (size_t i = lower_bound(t, base); i < t->count; i++) {
        size_t idx = t->by_base[i];
        if (strcmp(base_name(t->entries[idx].path), base) != 0)
            break;
        if (!suffix_match(t->entries[idx].path, name))
            continue;
        *found = true;
        if (push_size(&e->deps, &e->ndeps, idx))
            return 2;
    }
    return 0;
}

static int resolve(struct premise_tree *t, size_t self, const char *name,
                   bool quoted)
{
    struct premise_entry *e = &t->entries[self];
    bool found = false;
    if (name[0] != '/' && quoted) {
        char dir[PREMISE_PATH_MAX], joined[PREMISE_PATH_MAX];
        const char *slash = strrchr(e->path, '/');
        size_t n = slash ? (size_t)(slash - e->path) : 0;
        memcpy(dir, e->path, n);
        dir[n] = '\0';
        struct premise_entry *hit = join_norm(dir, name, joined, sizeof joined)
                                        ? premise_tree_find(t, joined) : NULL;
        if (hit) {
            found = true;
            if (push_size(&e->deps, &e->ndeps, (size_t)(hit - t->entries)))
                return 2;
        }
    }
    if (name[0] != '/' && suffix_deps(t, name, e, &found))
        return 2;
    return found ? 0 : push_str(&e->externals, &e->nexternals, name,
                                strlen(name));
}

static const char *skip_blank(const char *p, const char *end)
{
    for (;;) {
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        if (end - p < 2 || p[0] != '/' || p[1] != '*')
            return p;
        const char *close = p + 2;
        while (close + 1 < end && !(close[0] == '*' && close[1] == '/'))
            close++;
        if (close + 1 >= end)
            return end;
        p = close + 2;
    }
}

static bool is_directive(const char *p, size_t n)
{
    static const char *const k_names[] = { "include", "include_next",
                                           "import", "embed" };
    for (size_t i = 0; i < sizeof k_names / sizeof *k_names; i++)
        if (strlen(k_names[i]) == n && memcmp(p, k_names[i], n) == 0)
            return true;
    return false;
}

/* '"' or '>' for a literal header name at p; 0 for a computed include. */
static char closing_delimiter(const char *p, const char *end)
{
    if (p >= end)
        return 0;
    if (*p == '"')
        return '"';
    return *p == '<' ? '>' : 0;
}

/* One line. Returns 0, or 2 on allocation failure. */
static int scan_line(struct premise_tree *t, size_t self, const char *p,
                     const char *end)
{
    p = skip_blank(p, end);
    if (p >= end || *p != '#')
        return 0;
    p = skip_blank(p + 1, end);
    const char *word = p;
    while (p < end && ((*p >= 'a' && *p <= 'z') || *p == '_'))
        p++;
    if (!is_directive(word, (size_t)(p - word)))
        return 0;
    p = skip_blank(p, end);
    char close = closing_delimiter(p, end);
    const char *stop = close ? memchr(p + 1, close, (size_t)(end - p - 1)) : NULL;
    if (!stop || stop == p + 1 || stop - p >= PREMISE_PATH_MAX) {
        t->entries[self].computed_include = true;
        return 0;
    }
    char name[PREMISE_PATH_MAX];
    memcpy(name, p + 1, (size_t)(stop - p - 1));
    name[stop - p - 1] = '\0';
    return resolve(t, self, name, close == '"');
}

static int parse_entry(struct premise_tree *t, size_t self, FILE *err)
{
    struct premise_entry *e = &t->entries[self];
    if (e->parsed)
        return 0;
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (premise_tree_read(t, e->path, &bytes, &len, err))
        return 2;
    const char *p = (const char *)bytes, *end = p + len;
    int rc = 0;
    while (rc == 0 && p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *stop = nl ? nl : end;
        rc = scan_line(t, self, p, stop);
        p = nl ? nl + 1 : end;
    }
    free(bytes);
    e->parsed = rc == 0;
    return rc;
}

struct closure_walk {
    struct premise_tree *t;
    unsigned char *seen;
    size_t *order;
    size_t norder;
    bool computed;
    FILE *err;
};

static int visit(struct closure_walk *w, size_t root)
{
    size_t *stack = NULL, depth = 0;
    int rc = push_size(&stack, &depth, root);
    w->seen[root] = 1;
    while (rc == 0 && depth > 0) {
        size_t idx = stack[--depth];
        rc = push_size(&w->order, &w->norder, idx);
        if (rc == 0)
            rc = parse_entry(w->t, idx, w->err);
        struct premise_entry *e = &w->t->entries[idx];
        w->computed |= e->computed_include;
        for (size_t i = 0; rc == 0 && i < e->ndeps; i++) {
            if (w->seen[e->deps[i]])
                continue;
            w->seen[e->deps[i]] = 1;
            rc = push_size(&stack, &depth, e->deps[i]);
        }
    }
    free(stack);
    return rc;
}

static int cmp_size(const void *a, const void *b)
{
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return (x > y) - (x < y);
}

static int collect_externals(const struct closure_walk *w, char ***ext,
                             size_t *next)
{
    for (size_t i = 0; i < w->norder; i++) {
        const struct premise_entry *e = &w->t->entries[w->order[i]];
        for (size_t j = 0; j < e->nexternals; j++) {
            char **grown = realloc(*ext, (*next + 1) * sizeof **ext); // raw-alloc-ok:lint-runtime
            if (!grown)
                return 2;
            grown[(*next)++] = e->externals[j];
            *ext = grown;
        }
    }
    return 0;
}

int premise_include_closure(struct premise_tree *t, const char *unit,
                            size_t **out, size_t *nout, char ***ext,
                            size_t *next, bool *computed, FILE *err)
{
    *out = NULL;
    *nout = 0;
    *ext = NULL;
    *next = 0;
    *computed = false;
    struct premise_entry *root = premise_tree_find(t, unit);
    if (!root)
        return 1;
    struct closure_walk w = { .t = t, .err = err,
                              .seen = calloc(t->count ? t->count : 1, 1) }; // raw-alloc-ok:lint-runtime
    int rc = w.seen ? visit(&w, (size_t)(root - t->entries)) : 2;
    if (rc == 0)
        rc = collect_externals(&w, ext, next);
    free(w.seen);
    if (rc) {
        free(w.order);
        free(*ext);
        *ext = NULL;
        *next = 0;
        return rc;
    }
    qsort(w.order, w.norder, sizeof *w.order, cmp_size);
    *out = w.order;
    *nout = w.norder;
    *computed = w.computed;
    return 0;
}
