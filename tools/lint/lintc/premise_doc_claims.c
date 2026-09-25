/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: per-document units for check-doc-claims premise selection — the
 * tree paths a document's bound claims read, so a document whose claims
 * resolve against unchanged bytes can keep a verified base's verdict.
 * Nothing here is authority.
 *
 * The gate's per-document part (check_doc_claims.sh --doc=PATH) evaluates
 * every annotation whose first token is not gate-passes or gate-fails; the
 * global part owns those, because they run other gates. What the others
 * read:
 *   file-present/file-absent P   `[ -e P ]`: the path set answers it when
 *       P is not pruned, crosses no symlink, and the candidate file system
 *       agrees with the path set about P. Anything else is unbounded.
 *   symbol-present/symbol-absent S SPEC   `git grep -lwF S -- SPEC`: the
 *       bytes of every tracked file SPEC can match. Git's default pathspec
 *       matches only paths that begin with SPEC's literal prefix (the text
 *       before its first '*', '?' or '['), so every tree path with that
 *       prefix is in the premise. Pathspec magic (':'), an absolute path, a
 *       backslash escape, a '.' or '..' component, or a prefix that can
 *       reach a pruned directory is unbounded.
 *   anything else (malformed, unknown, wrong argument count): the
 *       document's own bytes only.
 * Parsing over-approximates the gate's: every line holding "claim:" is
 * read as an annotation, fenced or not, and cut exactly as the shell cuts
 * it (after the first "claim:", before the first "-->", before the first
 * '#', split on spaces and tabs). A NUL byte, or an annotation line that is
 * not valid UTF-8, makes the document unbounded. An unbounded document
 * never inherits.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { DOC_TOKENS_MAX = 4 };

struct doc_walk {
    struct premise_tree *t;
    size_t *idx;
    size_t n, cap;
    bool computed;
};

static int push(struct doc_walk *w, size_t i)
{
    if (w->n == w->cap) {
        size_t cap = w->cap ? w->cap * 2 : 64;
        size_t *grown = realloc(w->idx, cap * sizeof *grown); // raw-alloc-ok:lint-runtime
        if (!grown)
            return 2;
        w->idx = grown;
        w->cap = cap;
    }
    w->idx[w->n++] = i;
    return 0;
}

/* The first entry whose path sorts at or after key (entries are sorted by
 * strcmp, so every path beginning with key follows contiguously). */
static size_t lower_bound(const struct premise_tree *t, const char *key)
{
    size_t lo = 0, hi = t->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(t->entries[mid].path, key) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static bool has_prefix(const char *s, const char *p, size_t k)
{
    return strncmp(s, p, k) == 0;
}

static int push_prefix(struct doc_walk *w, const char *lit)
{
    size_t k = strlen(lit);
    int rc = 0;
    for (size_t i = lower_bound(w->t, lit);
         rc == 0 && i < w->t->count && has_prefix(w->t->entries[i].path, lit, k);
         i++)
        rc = push(w, i);
    return rc;
}

/* The path set says p exists: p is an entry, or a directory holding one. */
static bool tree_has(const struct premise_tree *t, const char *p)
{
    char dir[PREMISE_PATH_MAX];
    if (premise_tree_find(t, p))
        return true;
    int k = snprintf(dir, sizeof dir, "%s/", p);
    if (k < 0 || (size_t)k >= sizeof dir)
        return false;
    size_t i = lower_bound(t, dir);
    return i < t->count && has_prefix(t->entries[i].path, dir, (size_t)k);
}

/* p, or a directory on the way to it, is a symlink entry. */
static bool crosses_symlink(const struct premise_tree *t, const char *p)
{
    char pre[PREMISE_PATH_MAX];
    size_t n = strlen(p);
    if (n >= sizeof pre)
        return true;
    for (size_t j = 1; j <= n; j++) {
        if (j < n && p[j] != '/')
            continue;
        memcpy(pre, p, j);
        pre[j] = '\0';
        const struct premise_entry *e = premise_tree_find(t, pre);
        if (e && e->symlink)
            return true;
    }
    return false;
}

static void file_claim(struct doc_walk *w, const char *p)
{
    if (p[0] == '/' || strstr(p, ".."))
        return;                              /* malformed: the doc alone */
    char full[PREMISE_PATH_MAX * 2];
    struct stat st;
    int k = snprintf(full, sizeof full, "%s/%s", w->t->root, p);
    if (k < 0 || (size_t)k >= sizeof full || premise_path_pruned(p)
        || crosses_symlink(w->t, p)) {
        w->computed = true;
        return;
    }
    bool exists = stat(full, &st) == 0;
    if (exists != tree_has(w->t, p))
        w->computed = true;
}

static bool dot_component(const char *s)
{
    for (const char *c = s; *c;) {
        const char *e = strchr(c, '/');
        size_t n = e ? (size_t)(e - c) : strlen(c);
        if ((n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.'))
            return true;
        c = e ? e + 1 : c + n;
    }
    return false;
}

static int symbol_claim(struct doc_walk *w, const char *spec)
{
    char lit[PREMISE_PATH_MAX];
    size_t n = strcspn(spec, "*?[");
    if (spec[0] == ':' || spec[0] == '/' || strchr(spec, '\\')
        || dot_component(spec) || n >= sizeof lit) {
        w->computed = true;
        return 0;
    }
    memcpy(lit, spec, n);
    lit[n] = '\0';
    if (premise_prefix_reaches_pruned(lit)) {
        w->computed = true;
        return 0;
    }
    return push_prefix(w, lit);
}

/* Split body on spaces and tabs in place, as the shell's default IFS
 * splits a line (no newline can occur). Returns the token count; only the
 * first DOC_TOKENS_MAX are stored. */
static size_t split_tokens(char *body, char **tok)
{
    size_t n = 0;
    for (char *p = body; *p;) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        char *q = p;
        while (*q && *q != ' ' && *q != '\t')
            q++;
        if (n < DOC_TOKENS_MAX)
            tok[n] = p;
        n++;
        if (*q)
            *q++ = '\0';
        p = q;
    }
    return n;
}

static bool is_either(const char *s, const char *a, const char *b)
{
    return strcmp(s, a) == 0 || strcmp(s, b) == 0;
}

/* One annotation body, already cut. */
static int claim_body(struct doc_walk *w, char *body)
{
    char *tok[DOC_TOKENS_MAX];
    size_t n = split_tokens(body, tok);
    if (n == 2 && is_either(tok[0], "file-present", "file-absent"))
        file_claim(w, tok[1]);
    else if (n == 3 && is_either(tok[0], "symbol-present", "symbol-absent"))
        return symbol_claim(w, tok[2]);
    return 0;
}

/* The length of the UTF-8 sequence led by c, or 0 for a byte no sequence
 * starts with (a continuation byte, an overlong 2-byte lead, above U+10FFFF). */
static size_t utf8_lead(unsigned c)
{
    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        return 2;
    if ((c & 0xF0) == 0xE0)
        return 3;
    return c >= 0xF0 && c <= 0xF4 ? 4 : 0;
}

/* The second byte's range, which excludes overlongs and surrogates. */
static bool utf8_second_ok(unsigned c, unsigned b)
{
    unsigned lo = c == 0xE0 ? 0xA0 : c == 0xF0 ? 0x90 : 0x80;
    unsigned hi = c == 0xED ? 0x9F : c == 0xF4 ? 0x8F : 0xBF;
    return b >= lo && b <= hi;
}

static bool utf8_valid(const unsigned char *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        size_t len = utf8_lead(s[i]);
        if (len == 0 || len > n - i)
            return false;
        if (len > 1 && !utf8_second_ok(s[i], s[i + 1]))
            return false;
        for (size_t j = 2; j < len; j++)
            if ((s[i + j] & 0xC0) != 0x80)
                return false;
        i += len;
    }
    return true;
}

static const char *find_in(const char *p, const char *end, const char *needle)
{
    size_t k = strlen(needle);
    for (; (size_t)(end - p) >= k; p++)
        if (memcmp(p, needle, k) == 0)
            return p;
    return NULL;
}

/* A line holding "claim:": the body after its first "claim:", cut before
 * the first "-->" and the first '#'. */
static int claim_line(struct doc_walk *w, const char *p, const char *end)
{
    const char *at = find_in(p, end, "claim:");
    if (!at)
        return 0;
    if (!utf8_valid((const unsigned char *)p, (size_t)(end - p))) {
        w->computed = true;
        return 0;
    }
    const char *b = at + 6;
    const char *stop = find_in(b, end, "-->");
    stop = stop ? stop : end;
    const char *hash = memchr(b, '#', (size_t)(stop - b));
    stop = hash ? hash : stop;
    size_t n = (size_t)(stop - b);
    char *body = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!body)
        return 2;
    memcpy(body, b, n);
    body[n] = '\0';
    int rc = claim_body(w, body);
    free(body);
    return rc;
}

static int cmp_idx(const void *a, const void *b)
{
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return (x > y) - (x < y);
}

static void walk_unique(struct doc_walk *w)
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

static int doc_lines(struct doc_walk *w, const uint8_t *bytes, size_t len)
{
    if (len && memchr(bytes, '\0', len)) {
        w->computed = true;
        return 0;
    }
    const char *p = (const char *)bytes, *end = p + len;
    int rc = 0;
    while (rc == 0 && p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *stop = nl ? nl : end;
        rc = claim_line(w, p, stop);
        p = nl ? nl + 1 : end;
    }
    return rc;
}

int premise_doc_claims_closure(struct premise_tree *t, const char *unit,
                               size_t **out, size_t *nout, char ***ext,
                               size_t *next, bool *computed, FILE *err)
{
    *out = NULL;
    *nout = 0;
    *ext = NULL;
    *next = 0;
    *computed = false;
    const struct premise_entry *self = premise_tree_find(t, unit);
    if (!self)
        return 1;
    struct doc_walk w = { .t = t };
    uint8_t *bytes = NULL;
    size_t len = 0;
    int rc = push(&w, (size_t)(self - t->entries));
    /* A symlink document's evaluated bytes are its target's, which the path
     * set does not bind; it never inherits. */
    if (self->symlink)
        w.computed = true;
    if (rc == 0 && !self->symlink)
        rc = premise_tree_read(t, unit, &bytes, &len, err);
    if (rc == 0 && !self->symlink)
        rc = doc_lines(&w, bytes, len);
    free(bytes);
    if (rc) {
        free(w.idx);
        return rc;
    }
    walk_unique(&w);
    *out = w.idx;
    *nout = w.n;
    *computed = w.computed;
    return 0;
}
