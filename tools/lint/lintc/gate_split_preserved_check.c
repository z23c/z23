/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-split-preserved of the C23 lint runtime, the
 * comparison and the CLI. `z23-lint check-split-preserved [--base=REV]
 * [--mode=split|dedup] PATH...` compares each C file in the working tree with
 * `git show REV:PATH` (REV defaults to origin/main) for the checks an
 * AI-written, behaviour-preserving refactor must pass before a reviewer sees
 * it: the licence lines, the include set, the LOG_* calls per function and
 * every comment line. split mode demands all four equal; dedup mode allows
 * added includes of existing headers and whole functions removed with their
 * LOG calls and comments. Facts come from gate_split_preserved.c. Paths are
 * repo-relative. Exit 0 clean, 1 findings, 2 usage or I/O error. Selftest:
 * gate_split_preserved_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"
#include "gate_split_preserved_priv.h"

struct sp_ctx {
    const char *path;
    const struct sp_file *base, *cur;
    int dedup;
    sp_exists_fn exists;
    FILE *out;
    int fails;
};

static void sp_fail(struct sp_ctx *c, unsigned line, const char *what, const char *text)
{
    fprintf(c->out, "FAIL %s:%u: %s%s%s\n", c->path, line, what, *text ? ": " : "", text);
    c->fails++;
}

static int sp_cmp_ent(const void *a, const void *b)
{
    const struct sp_ent *x = *(const struct sp_ent *const *)a, *y = *(const struct sp_ent *const *)b;
    int c = strcmp(x->key, y->key);
    return c ? c : (x->line > y->line) - (x->line < y->line);
}

static struct sp_ent **sp_sorted(const struct sp_list *l)
{
    struct sp_ent **p = malloc((l->n + 1) * sizeof *p); // raw-alloc-ok:lint-runtime
    for (size_t i = 0; p && i < l->n; i++)
        p[i] = &l->v[i];
    if (p)
        qsort(p, l->n, sizeof *p, sp_cmp_ent);
    return p;
}

/* Multiset difference: sets miss on every entry of a with no partner in b and
 * on every entry of b with no partner in a. Returns 1 when memory ran out. */
static int sp_diff(struct sp_list *a, struct sp_list *b)
{
    struct sp_ent **x = sp_sorted(a), **y = sp_sorted(b);
    size_t i = 0, j = 0;
    int bad = !x || !y;
    while (!bad && (i < a->n || j < b->n)) {
        int c = i == a->n ? 1 : j == b->n ? -1 : strcmp(x[i]->key, y[j]->key);
        if (c == 0) {
            i++;
            j++;
        } else if (c < 0) {
            x[i++]->miss = 1;
        } else {
            y[j++]->miss = 1;
        }
    }
    free(x);
    free(y);
    return bad;
}

static int sp_marker(const char *l)
{
    return l && (strstr(l, "Copyright") || strstr(l, "SPDX") || strstr(l, "Licensed under"));
}

static void sp_check_header(struct sp_ctx *c)
{
    for (int k = 0; k < 5; k++) {
        const char *b = c->base->hdr[k], *n = c->cur->hdr[k];
        if ((sp_marker(b) || sp_marker(n)) && strcmp(b ? b : "", n ? n : "") != 0)
            sp_fail(c, (unsigned)k + 1, "licence line changed", n ? n : "(missing)");
    }
}

/* An added dedup include: #include "x/y.h" or <x/y.h> of an existing header. */
static int sp_include_ok(const char *line, sp_exists_fn exists)
{
    char path[512];
    const char *p = line + strlen("#include");
    char close;
    if (strncmp(line, "#include", 8) != 0)
        return 0;
    while (isspace((unsigned char)*p))
        p++;
    close = *p == '"' ? '"' : *p == '<' ? '>' : 0;
    const char *e = close ? strchr(p + 1, close) : NULL;
    if (!e || e[1] != '\0' || (size_t)(e - p) >= sizeof path || e - p < 4)
        return 0;
    memcpy(path, p + 1, (size_t)(e - p - 1));
    path[e - p - 1] = '\0';
    return strcmp(path + strlen(path) - 2, ".h") == 0 && exists(path);
}

static void sp_check_includes(struct sp_ctx *c, struct sp_file *b, struct sp_file *n)
{
    for (size_t i = 0; i < b->inc.n; i++) {
        if (b->inc.v[i].miss)
            sp_fail(c, b->inc.v[i].line, "base include line removed or changed", b->inc.v[i].key);
    }
    for (size_t i = 0; i < n->inc.n; i++) {
        const struct sp_ent *e = &n->inc.v[i];
        if (!e->miss)
            continue;
        if (!c->dedup)
            sp_fail(c, e->line, "include line added or changed", e->key);
        else if (!sp_include_ok(e->key, c->exists))
            sp_fail(c, e->line, "added line is not an #include of a header that exists in the tree", e->key);
    }
}

static int sp_has_func(const struct sp_file *f, const char *name)
{
    for (size_t i = 0; i < f->nspan; i++) {
        if (strcmp(f->span[i].name, name) == 0)
            return 1;
    }
    return 0;
}

/* A LOG finding names the function and the call, not the raw "FUNC\tCALL" key. */
static void sp_fail_log(struct sp_ctx *c, const struct sp_ent *e, const char *what)
{
    fprintf(c->out, "FAIL %s:%u: %s %s: %s\n", c->path, e->line, what, e->func,
            e->key + strlen(e->func) + 1);
    c->fails++;
}

static void sp_check_logs(struct sp_ctx *c, struct sp_file *b, struct sp_file *n)
{
    for (size_t i = 0; i < b->lg.n; i++) {
        const struct sp_ent *e = &b->lg.v[i];
        if (e->miss && !(c->dedup && !sp_has_func(c->cur, e->func)))
            sp_fail_log(c, e, "base LOG call missing from");
    }
    for (size_t i = 0; !c->dedup && i < n->lg.n; i++) {
        if (n->lg.v[i].miss)
            sp_fail_log(c, &n->lg.v[i], "LOG call not in the base, or not in the same function, in");
    }
}

static void sp_check_comments(struct sp_ctx *c, struct sp_file *b)
{
    for (size_t i = 0; i < b->cm.n; i++) {
        const struct sp_ent *e = &b->cm.v[i];
        if (e->miss && !(c->dedup && *e->func && !sp_has_func(c->cur, e->func)))
            sp_fail(c, e->line, "base comment line lost or reworded", e->key);
    }
}

int sp_compare(const char *path, const char *base, size_t base_len,
               const char *cur, size_t cur_len, int dedup,
               sp_exists_fn exists, FILE *out)
{
    struct sp_file b = { 0 }, n = { 0 };
    struct sp_ctx c = { path, &b, &n, dedup, exists, out, 0 };
    int bad = sp_analyze(&b, base, base_len) || sp_analyze(&n, cur, cur_len) ||
              sp_diff(&b.inc, &n.inc) || sp_diff(&b.lg, &n.lg) || sp_diff(&b.cm, &n.cm);
    if (!bad) {
        sp_check_header(&c);
        sp_check_includes(&c, &b, &n);
        sp_check_logs(&c, &b, &n);
        sp_check_comments(&c, &b);
    }
    sp_free(&b);
    sp_free(&n);
    return bad ? 2 : c.fails > 0;
}

/* ---- CLI ---- */

struct sp_opts {
    const char *base;
    int dedup;
    int first; /* index of the first PATH in argv */
};

static int sp_parse(int argc, char **argv, struct sp_opts *o)
{
    o->base = "origin/main";
    for (o->first = 0; o->first < argc && strncmp(argv[o->first], "--", 2) == 0; o->first++) {
        const char *a = argv[o->first];
        if (strncmp(a, "--base=", 7) == 0 && a[7])
            o->base = a + 7;
        else if (strcmp(a, "--mode=dedup") == 0)
            o->dedup = 1;
        else if (strcmp(a, "--mode=split") != 0)
            return die("check_split_preserved: unknown option: %s\n", a);
    }
    return o->first < argc ? 0 : 2;
}

static char *sp_read_file(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    size_t cap = 1 << 16, n = 0, got = 1;
    char *buf = fp ? malloc(cap) : NULL; // raw-alloc-ok:lint-runtime
    while (buf && got) {
        if (n + 1 == cap) {
            char *nb = realloc(buf, cap * 2); // raw-alloc-ok:lint-runtime
            if (!nb) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = nb;
            cap *= 2;
        }
        got = fread(buf + n, 1, cap - n - 1, fp);
        n += got;
    }
    if (buf && ferror(fp)) {
        free(buf);
        buf = NULL;
    }
    if (fp)
        fclose(fp);
    if (buf) {
        buf[n] = '\0';
        *len = n;
    }
    return buf;
}

/* `git show REV:PATH`; NULL when git fails or the output is incomplete. */
static char *sp_git_show(const char *rev, const char *path, size_t *len)
{
    char spec[4096];
    char *argv[] = { (char *)"git", (char *)"show", spec, NULL };
    struct lcp_spec s = { argv, NULL, NULL, LCP_OUT, 2000, NULL };
    struct lcp_buf out = { 0 };
    int code = 1;
    char *copy = NULL;
    if (snprintf(spec, sizeof spec, "%s:%s", rev, path) >= (int)sizeof spec)
        return NULL;
    if (lcp_run(&s, &out, &code) == 0 && code == 0 && !out.lost) {
        copy = malloc(out.len + 1); // raw-alloc-ok:lint-runtime
        if (copy) {
            memcpy(copy, out.data ? out.data : "", out.len);
            copy[out.len] = '\0';
            *len = out.len;
        }
    }
    lcp_buf_free(&out);
    return copy;
}

/* Whether a header path exists as a tracked or new file anywhere in the tree. */
static int sp_header_exists(const char *header)
{
    char deep[600];
    char *argv[] = { (char *)"git", (char *)"ls-files", (char *)"-co", (char *)"--exclude-standard",
                     (char *)"--", (char *)header, deep, NULL };
    struct lcp_spec s = { argv, NULL, NULL, LCP_OUT, 2000, NULL };
    struct lcp_buf out = { 0 };
    int code = 1, found = 0;
    for (const char *p = header; *p; p++) {
        if (!isalnum((unsigned char)*p) && !strchr("_./+-", *p))
            return 0;
    }
    if (strstr(header, "..") || header[0] == '/')
        return 0;
    snprintf(deep, sizeof deep, "*/%s", header);
    if (lcp_run(&s, &out, &code) == 0 && code == 0)
        found = out.len > 0;
    lcp_buf_free(&out);
    return found;
}

static int sp_one(const char *rev, const char *path, int dedup)
{
    size_t bl = 0, cl = 0;
    char *base = sp_git_show(rev, path, &bl);
    char *cur = sp_read_file(path, &cl);
    int rc = 2;
    if (!base)
        fprintf(stderr, "check_split_preserved: cannot read %s at %s\n", path, rev);
    else if (!cur)
        fprintf(stderr, "check_split_preserved: cannot read %s\n", path);
    else
        rc = sp_compare(path, base, bl, cur, cl, dedup, sp_header_exists, stdout);
    if (rc == 0)
        printf("check_split_preserved: %s preserved\n", path);
    free(base);
    free(cur);
    return rc;
}

int check_split_preserved_run(int argc, char **argv)
{
    struct sp_opts o = { 0 };
    char root[4096];
    int rc = 0, sig;
    if (sp_parse(argc, argv, &o)) {
        fputs("usage: z23-lint check-split-preserved [--base=REV] [--mode=split|dedup] PATH...\n", stderr);
        return 2;
    }
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0 || lsc_install() != 0)
        return die("z23-lint: cannot enter the repository\n", "");
    for (int i = o.first; i < argc && !lsc_pending(); i++) {
        int one = sp_one(o.base, argv[i], o.dedup);
        rc = one > rc ? one : rc;
    }
    fflush(stdout);
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}
