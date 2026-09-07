/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — raw malloc/calloc/realloc freeze (check-raw-malloc).
 * .git probe first; lint_git_index_foreach only when .git exists.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { RMA_MAX = 8192, RMA_LINE = 8192, RMA_HIT = 512 };

struct rma_set { char p[RMA_MAX][RS_PATH]; int n; };
struct rma_idx { struct rma_set *s; const char (*roots)[RS_PATH]; int nr; };

static const char k_rma_allow[] = "tools/scripts/raw_malloc_allowlist.txt";
static const char k_rma_call[] =
    "(^|[^[:alnum:]_])(malloc|calloc|realloc)[[:space:]]*\\(";

static int rma_add(struct rma_set *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= RMA_MAX || n >= RS_PATH)
        return die("z23-lint: raw-malloc overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int rma_has(const struct rma_set *s, const char *path)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int rma_under(const char *path, const char (*roots)[RS_PATH], int nr)
{
    int i;
    for (i = 0; i < nr; i++) {
        size_t k = strlen(roots[i]);
        if (strncmp(path, roots[i], k) == 0
            && (path[k] == '/' || path[k] == '\0'))
            return 1;
    }
    return 0;
}

static int rma_is_ch(const char *path)
{
    size_t n = strlen(path);
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strstr(path, "vendor/") || strstr(path, "/test/")
        || strstr(path, "safe_alloc"))
        return 0;
    if (strncmp(base, "test_", 5) == 0 && n >= 2 && path[n - 2] == '.'
        && path[n - 1] == 'c')
        return 0;
    return n >= 2 && path[n - 2] == '.'
        && (path[n - 1] == 'c' || path[n - 1] == 'h');
}

static int rma_on_idx(const char *path, int stage, void *ctx)
{
    struct rma_idx *c = ctx;
    (void)stage;
    if (!rma_is_ch(path) || lint_path_is_excluded(path))
        return 0;
    if (!rma_under(path, c->roots, c->nr))
        return 0;
    return rma_add(c->s, path);
}

static int rma_on_walk(const char *path, void *ctx)
{
    if (!rma_is_ch(path) || lint_path_is_excluded(path))
        return 0;
    return rma_add(ctx, path);
}

static int rma_fill_roots(char out[][RS_PATH], int *n)
{
    int na = 0, nl = 0, rc, i;
    char app[RS_MAX][RS_PATH], lib[RS_MAX][RS_PATH];
    const char *extra[] = { "engine/composition", "tools" };
    *n = 0;
    rc = repo_shape_dirs("app", "", app, RS_MAX, &na);
    if (rc)
        return rc;
    rc = repo_shape_dirs("lib", "", lib, RS_MAX, &nl);
    if (rc)
        return rc;
    for (i = 0; i < na; i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s", app[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    for (i = 0; i < nl; i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s", lib[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    for (i = 0; i < 2; i++) {
        struct stat st;
        if (stat(extra[i], &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        if (ovf(snprintf(out[*n], RS_PATH, "%s", extra[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    return 0;
}

static int rma_collect(struct rma_set *s, const char (*roots)[RS_PATH], int nr)
{
    struct rma_idx ix = { .s = s, .roots = roots, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    int rc = 0, i;
    s->n = 0;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(rma_on_idx, &ix, bad);
        if (rc)
            fprintf(stderr, "check_raw_malloc: UNPROVEN — git index%s%s\n",
                    bad[0] ? " extension " : "", bad);
        return rc;
    }
    for (i = 0; rc == 0 && i < nr; i++)
        rc = walk_src(roots[i], 1, rma_on_walk, s);
    return rc;
}

static int rma_load_allow(struct rma_set *a, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[RMA_LINE];
    a->n = 0;
    if (!f)
        return 0;
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        if (rma_add(a, buf)) {
            fclose(f);
            return 2;
        }
    }
    fclose(f);
    return 0;
}

static int rma_skip_line(const char *line)
{
    if (strstr(line, "zcl_malloc") || strstr(line, "zcl_calloc")
        || strstr(line, "zcl_realloc"))
        return 1;
    if (strstr(line, "raw-alloc-ok:"))
        return 1;
    if (strchr(line, '"') && (strstr(line, "malloc") || strstr(line, "calloc")
                              || strstr(line, "realloc")))
        return 1;
    if (strstr(line, "/*") || strstr(line, "* "))
        return 1;
    return 0;
}

static int rma_scan_file(const char *path, const regex_t *re,
                         const struct rma_set *allow, int *nallow,
                         char viol[][RMA_LINE], int *nv)
{
    FILE *f = fopen(path, "r");
    char buf[RMA_LINE];
    int lineno = 0;
    if (!f) {
        fprintf(stderr, "check_raw_malloc: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        lineno++;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (regexec(re, buf, 0, NULL, 0) != 0)
            continue;
        if (rma_skip_line(buf))
            continue;
        if (rma_has(allow, path)) {
            (*nallow)++;
            continue;
        }
        if (*nv < RMA_HIT
            && !ovf(snprintf(viol[*nv], RMA_LINE, "%s:%d:%s", path, lineno,
                             buf), RMA_LINE))
            (*nv)++;
    }
    fclose(f);
    return 0;
}

static int rma_run(void)
{
    static struct rma_set files, allow;
    static char viol[RMA_HIT][RMA_LINE];
    char roots[RS_MAX][RS_PATH];
    regex_t re;
    int nr = 0, nv = 0, nallow = 0, rc, i;
    rc = rma_fill_roots(roots, &nr);
    if (rc)
        return rc;
    rc = rma_load_allow(&allow, k_rma_allow);
    if (rc)
        return rc;
    rc = rma_collect(&files, roots, nr);
    if (rc)
        return rc;
    if (reg_fail(&re, regcomp(&re, k_rma_call, REG_EXTENDED)))
        return 2;
    for (i = 0; rc == 0 && i < files.n; i++)
        rc = rma_scan_file(files.p[i], &re, &allow, &nallow, viol, &nv);
    regfree(&re);
    if (rc)
        return rc;
    if (nv) {
        for (i = 0; i < nv; i++)
            printf("%s\n", viol[i]);
        fputs("FAIL: raw malloc/calloc/realloc in production code\n"
              "  Use zcl_malloc / zcl_calloc / zcl_realloc (see\n"
              "  platform/modules/util/include/util/safe_alloc.h) — the "
              "wrappers log + emit an\n"
              "  EV_OOM event on failure. For unavoidable cases, add a\n"
              "  // raw-alloc-ok:<reason-slug> comment on the line — no space\n"
              "  after the colon, slug is one word, e.g. "
              "raw-alloc-ok:build-tool.\n", stdout);
        if (nallow > 0)
            printf("  Allowlisted (still pending migration):\n"
                   "    %d raw call sites\n", nallow);
        return 1;
    }
    if (nallow > 0) {
        printf("check_raw_malloc: clean outside allowlist\n"
               "  Allowlisted: %d raw call sites across %d files\n", nallow,
               allow.n);
        return 0;
    }
    fputs("OK: check_raw_malloc - no raw malloc/calloc/realloc in production "
          "code\n", stdout);
    return 0;
}

int check_raw_malloc_selftest(void)
{
    int rc = rma_run();
    if (rc != 0) {
        fprintf(stderr, "check_raw_malloc selftest: FAIL — clean tree rc=%d "
                        "want=0\n", rc);
        return 1;
    }
    fputs("check_raw_malloc selftest: PASS — clean tree has no unallowlisted "
          "raw malloc\n", stdout);
    return 0;
}

int check_raw_malloc_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return rma_run();
}
