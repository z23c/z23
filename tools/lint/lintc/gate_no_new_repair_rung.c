/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — no new repair rung (check-no-new-repair-rung).
 * .git probe first; lint_git_index_foreach only when .git exists.
 * The original script mentions `make lint` only as operator text.
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

enum { NRR_MAX = 8192, NRR_LINE = 8192, NRR_HIT = 256 };

struct nrr_set { char p[NRR_MAX][RS_PATH]; int n; };
struct nrr_idx { struct nrr_set *s; const char (*roots)[RS_PATH]; int nr; };

static const char k_nrr_base[] = "tools/scripts/repair_rung_baseline.txt";
static const char k_nrr_ok[] =
    "//[[:space:]]*repair-rung-ok:[A-Za-z][A-Za-z0-9_./-]*";

static int nrr_add(struct nrr_set *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= NRR_MAX || n >= RS_PATH)
        return die("z23-lint: no-new-repair-rung overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int nrr_has(const struct nrr_set *s, const char *path)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int nrr_under(const char *path, const char (*roots)[RS_PATH], int nr)
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

static int nrr_is_rung_base(const char *base)
{
    if (strstr(base, "repair") || strstr(base, "reconcile")
        || strstr(base, "backfill"))
        return 1;
    return strstr(base, "heal") != NULL && strstr(base, "health") == NULL;
}

static int nrr_is_c(const char *path)
{
    size_t n = strlen(path);
    const char *base;
    if (n < 2 || path[n - 2] != '.' || path[n - 1] != 'c')
        return 0;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return nrr_is_rung_base(base);
}

static int nrr_on_idx(const char *path, int stage, void *ctx)
{
    struct nrr_idx *c = ctx;
    (void)stage;
    if (!nrr_is_c(path) || lint_path_is_excluded(path))
        return 0;
    if (!nrr_under(path, c->roots, c->nr))
        return 0;
    return nrr_add(c->s, path);
}

static int nrr_on_walk(const char *path, void *ctx)
{
    if (!nrr_is_c(path) || lint_path_is_excluded(path))
        return 0;
    return nrr_add(ctx, path);
}

static int nrr_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

static int nrr_collect(struct nrr_set *s, const char (*roots)[RS_PATH], int nr)
{
    struct nrr_idx ix = { .s = s, .roots = roots, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    int rc = 0, i;
    s->n = 0;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(nrr_on_idx, &ix, bad);
        if (rc)
            fprintf(stderr,
                    "check_no_new_repair_rung: UNPROVEN — git index%s%s\n",
                    bad[0] ? " extension " : "", bad);
        if (rc == 0)
            qsort(s->p, (size_t)s->n, RS_PATH, nrr_cmp);
        return rc;
    }
    for (i = 0; rc == 0 && i < nr; i++)
        rc = walk_src(roots[i], 0, nrr_on_walk, s);
    if (rc == 0)
        qsort(s->p, (size_t)s->n, RS_PATH, nrr_cmp);
    return rc;
}

static int nrr_load_base(struct nrr_set *b, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[NRR_LINE];
    b->n = 0;
    if (!f)
        return 0;
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (n && buf[n - 1] == '\r')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        if (nrr_add(b, buf)) {
            fclose(f);
            return 2;
        }
    }
    fclose(f);
    return 0;
}

static int nrr_has_marker(const char *path, const regex_t *re)
{
    FILE *f = fopen(path, "r");
    char buf[NRR_LINE];
    int hit = 0;
    if (!f) {
        fprintf(stderr, "check_no_new_repair_rung: UNPROVEN — cannot read %s\n",
                path);
        return -1;
    }
    while (fgets(buf, (int)sizeof buf, f))
        if (regexec(re, buf, 0, NULL, 0) == 0) {
            hit = 1;
            break;
        }
    fclose(f);
    return hit;
}

static int nrr_run(void)
{
    static struct nrr_set files, base;
    static char viol[NRR_HIT][RS_PATH];
    char rooms[RS_MAX][RS_PATH];
    regex_t ok;
    int nr = 0, nv = 0, rc, i;
    FILE *bf;
    rc = repo_shape_dirs("app", "", rooms, RS_MAX, &nr);
    if (rc)
        return rc;
    bf = fopen(k_nrr_base, "a");
    if (bf)
        fclose(bf);
    rc = nrr_load_base(&base, k_nrr_base);
    if (rc)
        return rc;
    rc = nrr_collect(&files, rooms, nr);
    if (rc)
        return rc;
    if (reg_fail(&ok, regcomp(&ok, k_nrr_ok, REG_EXTENDED)))
        return 2;
    for (i = 0; i < files.n; i++) {
        int m;
        if (nrr_has(&base, files.p[i]))
            continue;
        m = nrr_has_marker(files.p[i], &ok);
        if (m < 0) {
            regfree(&ok);
            return 2;
        }
        if (m)
            continue;
        if (nv < NRR_HIT)
            snprintf(viol[nv++], RS_PATH, "%s", files.p[i]);
    }
    regfree(&ok);
    if (!nv) {
        printf("check_no_new_repair_rung: clean — %d grandfathered rung(s), "
               "no new ones\n", base.n);
        return 0;
    }
    printf("\ncheck_no_new_repair_rung: %d NEW repair rung(s) with no "
           "justification\n\n", nv);
    for (i = 0; i < nv; i++)
        printf("  %s\n", viol[i]);
    fputs("\nA new repair/reconcile/backfill/heal rung is almost always the "
          "WRONG\nfix (TENACITY I3). Prefer fixing the WRITER so the bad "
          "state is never\nproduced. If a rung is genuinely required:\n"
          "  1. Add a marker '// repair-rung-ok:<test_name>' citing the "
          "write-time-\n     invariant test that proves the producing path "
          "now refuses to emit\n     the state this rung repairs.\n"
          "  2. As a last resort (grandfathering an unavoidable existing "
          "rung),\n     add the file path to ", stdout);
    fputs(k_nrr_base, stdout);
    fputs(".\n", stdout);
    return 1;
}

int check_no_new_repair_rung_selftest(void)
{
    int rc = nrr_run();
    if (rc != 0) {
        fprintf(stderr, "check_no_new_repair_rung selftest: FAIL — clean tree "
                        "rc=%d want=0\n", rc);
        return 1;
    }
    fputs("check_no_new_repair_rung selftest: PASS — clean tree has no new "
          "unjustified rungs\n", stdout);
    return 0;
}

int check_no_new_repair_rung_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return nrr_run();
}
