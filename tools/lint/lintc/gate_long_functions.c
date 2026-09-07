/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — long-function ratchet of the C23 lint runtime
 * (check-long-functions). Tracked files via lint_git_index_foreach.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { LF_LIMIT = 500, LF_MAX = 4096, LF_HIT = 512, LF_KEY = 384,
       LF_LINE = 8192 };

struct lf_set { char p[LF_MAX][RS_PATH]; int n; };
struct lf_base { char key[LF_HIT][LF_KEY]; int pin[LF_HIT]; int n; };
struct lf_hits { char m[LF_HIT][LF_LINE]; int n; };
struct lf_coll {
    const char (*roots)[RS_PATH];
    int nroots, depth1;
    struct lf_set *set;
};

static const char k_lf_ebase[] =
    "tools/scripts/check_long_functions_baseline.txt";
static const char k_lf_lbase[] =
    "tools/scripts/check_long_functions_lib_baseline.txt";
static const char k_lf_ok[] = "long-function-ok:";

static int lf_is_c(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && path[n - 1] == 'c';
}

static int lf_under(const char *path, const char *root)
{
    size_t n = strlen(root);
    if (strncmp(path, root, n) != 0)
        return 0;
    return path[n] == '/' || path[n] == '\0';
}

static int lf_depth1(const char *path, const char *root)
{
    size_t n = strlen(root);
    const char *rest;
    if (strncmp(path, root, n) != 0 || path[n] != '/')
        return 0;
    rest = path + n + 1;
    return lf_is_c(rest) && strchr(rest, '/') == NULL;
}

static int lf_has(const struct lf_set *s, const char *path)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int lf_add(struct lf_set *s, const char *path)
{
    size_t n;
    if (lf_has(s, path))
        return 0;
    n = strlen(path);
    if (s->n >= LF_MAX || n >= RS_PATH)
        return die("z23-lint: long-functions path overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int lf_skip_warn(const char *path)
{
    return strncmp(path, "tests/harness/include/test/", 27) == 0
        || lint_path_is_excluded(path);
}

static int lf_on_index(const char *path, void *ctx)
{
    struct lf_coll *c = ctx;
    int i, ok = 0;
    if (!lf_is_c(path) || lf_skip_warn(path))
        return 0;
    for (i = 0; i < c->nroots; i++) {
        if (c->depth1 ? lf_depth1(path, c->roots[i])
                      : lf_under(path, c->roots[i]))
            ok = 1;
    }
    return ok ? lf_add(c->set, path) : 0;
}

static int lf_walk(const char *dir, int depth1, struct lf_set *s);

static int lf_visit(const char *dir, const char *nm, int depth1,
                    struct lf_set *s)
{
    char path[4096];
    struct stat st;
    int k;
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
        return 0;
    k = snprintf(path, sizeof path, "%s/%s", dir, nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", dir);
    if (lstat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (S_ISDIR(st.st_mode) && !depth1)
        return lf_walk(path, 0, s);
    if (S_ISREG(st.st_mode) && lf_is_c(path) && !lf_skip_warn(path))
        return lf_add(s, path);
    return 0;
}

static int lf_walk(const char *dir, int depth1, struct lf_set *s)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < n; i++) {
        if (rc == 0)
            rc = lf_visit(dir, names[i]->d_name, depth1, s);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int lf_collect(struct lf_set *s, const char (*roots)[RS_PATH], int nr,
                      int depth1)
{
    struct lf_coll c = { .roots = roots, .nroots = nr, .depth1 = depth1,
                         .set = s };
    int rc, i;
    s->n = 0;
    if (lint_prod_scan())
        return lint_git_index_foreach(lf_on_index, &c);
    rc = 0;
    for (i = 0; rc == 0 && i < nr; i++)
        rc = lf_walk(roots[i], depth1, s);
    return rc;
}

static int lf_sig(const char *line)
{
    if (!(isalpha((unsigned char)line[0]) || line[0] == '_'))
        return 0;
    if (!strchr(line, '(') || !strchr(line, ')'))
        return 0;
    return strchr(line, ';') == NULL;
}

static int lf_close(const char *line)
{
    const char *p;
    if (line[0] != '}')
        return 0;
    p = line + 1;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0')
        return 1;
    return (p[0] == '/' && (p[1] == '/' || p[1] == '*'));
}

static void lf_name(const char *sig, char *out, size_t cap)
{
    const char *p = sig, *best = NULL, *q;
    size_t n = 0;
    out[0] = '\0';
    while (*p) {
        if (isalpha((unsigned char)*p) || *p == '_') {
            const char *s = p;
            while (isalnum((unsigned char)*p) || *p == '_')
                p++;
            q = p;
            while (*q == ' ' || *q == '\t')
                q++;
            if (*q == '(') {
                best = s;
                n = (size_t)(p - s);
            }
        } else {
            p++;
        }
    }
    if (!best || n == 0 || n >= cap)
        return;
    memcpy(out, best, n);
    out[n] = '\0';
}

static int lf_pin(const struct lf_base *base, const char *key)
{
    int i;
    for (i = 0; i < base->n; i++)
        if (strcmp(base->key[i], key) == 0)
            return base->pin[i];
    return -1;
}

static int lf_record(const char *path, const char *sig, int start, int lineno,
                     int ok, struct lf_hits *newh, struct lf_hits *grown,
                     struct lf_hits *shrink, const struct lf_base *base)
{
    char name[128], key[LF_KEY];
    int len = lineno - start, rec;
    if (len <= LF_LIMIT || ok)
        return 0;
    lf_name(sig, name, sizeof name);
    if (!name[0])
        return 0;
    if (ovf(snprintf(key, sizeof key, "%s::%s", path, name), sizeof key))
        return 2;
    rec = lf_pin(base, key);
    if (rec >= 0 && len > rec && grown->n < LF_HIT)
        snprintf(grown->m[grown->n++], LF_LINE,
                 "%s:%d  %s() grew to %d lines (baseline %d)",
                 path, lineno - len, name, len, rec);
    else if (rec >= 0 && len < rec && len > LF_LIMIT && shrink->n < LF_HIT)
        snprintf(shrink->m[shrink->n++], LF_LINE,
                 "%s %s is now %d lines (baseline %d, cap %d) — "
                 "tighten the baseline entry to %d",
                 path, name, len, rec, LF_LIMIT, len);
    else if (rec < 0 && newh->n < LF_HIT)
        snprintf(newh->m[newh->n++], LF_LINE,
                 "%s:%d  %s() spans %d lines (cap %d)",
                 path, lineno - len, name, len, LF_LIMIT);
    return 0;
}

static int lf_scan_file(const char *path, struct lf_hits *newh,
                        struct lf_hits *grown, struct lf_hits *shrink,
                        const struct lf_base *base)
{
    FILE *f = fopen(path, "r");
    char buf[LF_LINE], sig[LF_LINE];
    int rc = 0, lineno = 0, start = 0, ok = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    sig[0] = '\0';
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        lineno++;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (lf_sig(buf)) {
            memcpy(sig, buf, n + 1);
            start = lineno;
            ok = strstr(buf, k_lf_ok) != NULL;
        } else if (start && strstr(buf, k_lf_ok)) {
            ok = 1;
        }
        if (!(start && lf_close(buf)))
            continue;
        rc = lf_record(path, sig, start, lineno, ok, newh, grown, shrink, base);
        start = 0;
        sig[0] = '\0';
        ok = 0;
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int lf_base_line(struct lf_base *b, char *buf)
{
    char *h, *p, fp[RS_PATH], fn[128];
    int loc;
    size_t n = strlen(buf);
    if (n && buf[n - 1] == '\n')
        buf[--n] = '\0';
    h = strchr(buf, '#');
    if (h)
        *h = '\0';
    p = buf;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0')
        return 0;
    if (sscanf(p, "%191s %127s %d", fp, fn, &loc) != 3)
        return 0;
    if (b->n >= LF_HIT)
        return die("z23-lint: long-functions baseline overflow\n", "");
    if (ovf(snprintf(b->key[b->n], LF_KEY, "%s::%s", fp, fn), LF_KEY))
        return 2;
    b->pin[b->n++] = loc;
    return 0;
}

static int lf_load_base(struct lf_base *b, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[LF_LINE];
    int rc = 0;
    b->n = 0;
    if (!f)
        return 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f))
        rc = lf_base_line(b, buf);
    if (ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int lf_fill_enforced(char out[][RS_PATH], int *n)
{
    char rooms[RS_MAX][RS_PATH];
    int nr = 0, i, rc;
    *n = 0;
    rc = repo_shape_room_dirs("controllers", rooms, RS_MAX, &nr);
    if (rc)
        return rc;
    for (i = 0; i < nr; i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s/src", rooms[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    rc = repo_shape_room_dirs("services", rooms, RS_MAX, &nr);
    if (rc)
        return rc;
    for (i = 0; i < nr; i++) {
        if (ovf(snprintf(out[*n], RS_PATH, "%s/src", rooms[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    if (ovf(snprintf(out[*n], RS_PATH, "engine/composition/src"), RS_PATH))
        return 2;
    (*n)++;
    return 0;
}

static int lf_cov_root_ok(const char *root, int depth1)
{
    struct lf_set s = {0};
    struct lf_coll c;
    char one[1][RS_PATH];
    if (ovf(snprintf(one[0], RS_PATH, "%s", root), RS_PATH))
        return 2;
    c.roots = one;
    c.nroots = 1;
    c.depth1 = depth1;
    c.set = &s;
    if (lint_git_index_foreach(lf_on_index, &c))
        return 2;
    if (s.n == 0) {
        fprintf(stderr, "check_long_functions: UNPROVEN — declared scan root\n"
                        "  '%s' tracks no *.c at all. A renamed/emptied\n"
                        "  root removes its surface from BOTH the find and the\n"
                        "  expectation, so the shortfall cancels and reads clean.\n"
                        "  Refusing to grade. Fix ENFORCED_ROOTS_DEFAULT /\n"
                        "  LIB_ROOTS_DEFAULT, or drop the root if the code is gone.\n",
                root);
        return 2;
    }
    return 0;
}

static int lf_missing(const struct lf_set *exp, const struct lf_set *got)
{
    int i, m = 0;
    for (i = 0; i < exp->n; i++)
        if (!lf_has(got, exp->p[i]))
            m++;
    return m;
}

static int lf_coverage(const struct lf_set *enf, const struct lf_set *lib,
                       const char (*er)[RS_PATH], int ne,
                       const char (*lr)[RS_PATH], int nl, int allow)
{
    struct lf_set eexp = {0}, lexp = {0};
    struct lf_coll ce = { .roots = er, .nroots = ne, .depth1 = 1, .set = &eexp };
    struct lf_coll cl = { .roots = lr, .nroots = nl, .depth1 = 0, .set = &lexp };
    int rc, i, me, ml;
    for (i = 0; i < ne; i++) {
        rc = lf_cov_root_ok(er[i], 1);
        if (rc)
            return rc;
    }
    for (i = 0; i < nl; i++) {
        rc = lf_cov_root_ok(lr[i], 0);
        if (rc)
            return rc;
    }
    rc = lint_git_index_foreach(lf_on_index, &ce);
    if (rc)
        return rc;
    rc = lint_git_index_foreach(lf_on_index, &cl);
    if (rc)
        return rc;
    me = lf_missing(&eexp, enf);
    ml = lf_missing(&lexp, lib);
    if (allow > 0 && me == 0 && ml == 0) {
        fprintf(stderr, "check_long_functions: stale coverage allowance %d "
                        "(true shortfall 0)\n", allow);
        return 1;
    }
    if (me > allow || ml > allow) {
        fprintf(stderr, "check_long_functions: UNPROVEN — coverage shortfall "
                        "enforced=%d warn=%d allowance=%d\n", me, ml, allow);
        return 2;
    }
    return 0;
}

static int lf_split_roots(const char *s, char out[][RS_PATH], int max, int *n)
{
    char buf[4096], *p;
    *n = 0;
    if (ovf(snprintf(buf, sizeof buf, "%s", s), sizeof buf))
        return 2;
    p = buf;
    while (*p) {
        char *t, save;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (*n >= max)
            return die("z23-lint: long-functions roots overflow\n", "");
        t = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        save = *p;
        *p = '\0';
        if (ovf(snprintf(out[*n], RS_PATH, "%s", t), RS_PATH))
            return 2;
        (*n)++;
        if (!save)
            break;
        *p++ = save;
    }
    return 0;
}

static int lf_scan_sets(const struct lf_set *enf, const struct lf_set *lib,
                        struct lf_hits *enew, struct lf_hits *egrow,
                        struct lf_hits *eshrink, struct lf_hits *lnew,
                        struct lf_hits *lgrow, struct lf_hits *lshrink,
                        const struct lf_base *ebase, const struct lf_base *lbase)
{
    int rc = 0, i;
    for (i = 0; rc == 0 && i < enf->n; i++)
        rc = lf_scan_file(enf->p[i], enew, egrow, eshrink, ebase);
    if (rc)
        return rc;
    for (i = 0; rc == 0 && i < lib->n; i++)
        rc = lf_scan_file(lib->p[i], lnew, lgrow, lshrink, lbase);
    return rc;
}

static void lf_print_shrink(const struct lf_hits *s, const char *hdr)
{
    int i;
    if (!s->n)
        return;
    printf("\n  %s\n", hdr);
    for (i = 0; i < s->n; i++)
        printf("    %s\n", s->m[i]);
}

static int lf_print_enf(const struct lf_hits *enew, const struct lf_hits *egrow,
                        const struct lf_hits *eshrink, int nbase)
{
    int i, fail = 0;
    if (enew->n || egrow->n) {
        fail = 1;
        fputs("\ncheck_long_functions: FAIL — long-function violations "
              "(gate #12, ratchet, controllers/services/config-src)\n\n",
              stdout);
        for (i = 0; i < enew->n; i++)
            printf("  NEW long function (not in baseline): %s\n", enew->m[i]);
        for (i = 0; i < egrow->n; i++)
            printf("  REGRESSION (grew past its baselined length): %s\n",
                   egrow->m[i]);
        printf("\nFix options (preferred -> fallback):\n"
               "  1. Split the function along its seams (named helpers per "
               "phase/case)\n     so it stays under %d lines.\n"
               "  2. For a baselined function that grew, shrink it back at or "
               "below its\n     recorded baseline length in %s.\n"
               "  3. Tag the signature line '// long-function-ok:<tag>' if it "
               "is truly\n     one state machine, explaining why in the tag.\n"
               "  4. As last resort, record a NEW function in %s at its\n"
               "     current length (a reviewable line; shrink-only over "
               "time —\n     raising an existing entry needs an ADR, not this "
               "gate).\n", LF_LIMIT, k_lf_ebase, k_lf_ebase);
    } else {
        printf("check_long_functions: clean — %d baselined, no new/grown "
               "long functions (cap %d, controllers/services/config-src)\n",
               nbase, LF_LIMIT);
    }
    lf_print_shrink(eshrink,
                    "Baseline can tighten (functions shrank but are still "
                    "over cap):");
    return fail;
}

static void lf_print_lib(const struct lf_hits *lnew, const struct lf_hits *lgrow,
                         const struct lf_hits *lshrink, int nbase)
{
    int i;
    if (lnew->n || lgrow->n) {
        fputs("\ncheck_long_functions: WARN — long-function watch "
              "(gate #12, lib/, non-blocking)\n\n", stdout);
        for (i = 0; i < lnew->n; i++)
            printf("  NEW long function (not in %s): %s\n", k_lf_lbase,
                   lnew->m[i]);
        for (i = 0; i < lgrow->n; i++)
            printf("  grew past its baselined length in %s: %s\n", k_lf_lbase,
                   lgrow->m[i]);
        fputs("\n  This tier is WARN-only — it does not fail the build. "
              "Consider\n  splitting the function, tagging it "
              "'// long-function-ok:<tag>', or\n  if it's baselined "
              "intentionally, add/adjust its line in ", stdout);
        fputs(k_lf_lbase, stdout);
        fputs(".\n", stdout);
    } else {
        printf("check_long_functions: clean — %d baselined, no new/grown "
               "long functions (cap %d, lib/, WARN tier)\n",
               nbase, LF_LIMIT);
    }
    lf_print_shrink(lshrink,
                    "lib/ baseline can tighten (functions shrank but are "
                    "still over cap):");
}

static int lf_finish(struct lf_set *enf, struct lf_set *lib,
                     const char (*edef)[RS_PATH], int nde,
                     const char (*ldef)[RS_PATH], int ndl,
                     struct lf_hits *enew, struct lf_hits *egrow,
                     struct lf_hits *eshrink, struct lf_hits *lnew,
                     struct lf_hits *lgrow, struct lf_hits *lshrink)
{
    struct lf_base ebase = {0}, lbase = {0};
    int rc, allow, cov, only;
    rc = gate_require_scanned(enf->n, 1, "check_long_functions",
                              "ENFORCED roots empty");
    if (rc)
        return rc;
    rc = gate_require_scanned(lib->n, 1, "check_long_functions",
                              "WARN roots empty");
    if (rc)
        return rc;
    allow = atoi(env_or("ZCL_LONGFN_COVERAGE_ALLOWANCE", "0"));
    cov = lint_prod_scan()
        && strcmp(env_or("ZCL_LONGFN_COVERAGE", "1"), "1") == 0;
    only = strcmp(env_or("ZCL_LONGFN_COVERAGE_ONLY", "0"), "1") == 0;
    if (cov) {
        rc = lf_coverage(enf, lib, edef, nde, ldef, ndl, allow);
        if (rc)
            return rc;
    }
    if (only) {
        printf("check_long_functions: coverage-only PASS (%d ENFORCED "
               "+ %d WARN files reached)\n", enf->n, lib->n);
        return 0;
    }
    rc = lf_load_base(&ebase, env_or("ZCL_LONGFN_BASELINE", k_lf_ebase));
    if (rc)
        return rc;
    rc = lf_load_base(&lbase, env_or("ZCL_LONGFN_LIB_BASELINE", k_lf_lbase));
    if (rc)
        return rc;
    rc = lf_scan_sets(enf, lib, enew, egrow, eshrink, lnew, lgrow, lshrink,
                      &ebase, &lbase);
    if (rc)
        return rc;
    rc = lf_print_enf(enew, egrow, eshrink, ebase.n);
    lf_print_lib(lnew, lgrow, lshrink, lbase.n);
    return rc;
}

int check_long_functions_run(int argc, char **argv)
{
    char er[RS_MAX][RS_PATH], lr[RS_MAX][RS_PATH];
    char edef[RS_MAX][RS_PATH], ldef[RS_MAX][RS_PATH];
    int ne = 0, nl = 0, nde = 0, ndl = 0, rc;
    static struct lf_set enf, lib;
    static struct lf_hits enew, egrow, eshrink, lnew, lgrow, lshrink;
    const char *ov;
    (void)argc;
    (void)argv;
    enew.n = egrow.n = eshrink.n = 0;
    lnew.n = lgrow.n = lshrink.n = 0;
    rc = lf_fill_enforced(edef, &nde);
    if (rc)
        return rc;
    rc = repo_shape_dirs("lib", "", ldef, RS_MAX, &ndl);
    if (rc)
        return rc;
    ov = env_or("ZCL_LONGFN_ENFORCED_ROOTS", "");
    rc = ov[0] ? lf_split_roots(ov, er, RS_MAX, &ne)
               : (memcpy(er, edef, sizeof edef), ne = nde, 0);
    if (rc)
        return rc;
    ov = env_or("ZCL_LONGFN_LIB_ROOTS", "");
    rc = ov[0] ? lf_split_roots(ov, lr, RS_MAX, &nl)
               : (memcpy(lr, ldef, sizeof ldef), nl = ndl, 0);
    if (rc)
        return rc;
    rc = lf_collect(&enf, er, ne, 1);
    if (rc)
        return rc;
    rc = lf_collect(&lib, lr, nl, 0);
    if (rc)
        return rc;
    return lf_finish(&enf, &lib, edef, nde, ldef, ndl,
                     &enew, &egrow, &eshrink, &lnew, &lgrow, &lshrink);
}

static int lf_st_sig(void)
{
    return lf_sig("int foo(void)") && !lf_sig(" int foo(void)")
        && !lf_sig("int foo(void);") && lf_close("}")
        && lf_close("} // x");
}

static int lf_st_name(void)
{
    char n[32];
    lf_name("static int foo(void)", n, sizeof n);
    return strcmp(n, "foo") == 0;
}

static int lf_quiet_run(void)
{
    int rc, oldout, olderr, nfd;
    fflush(stdout);
    fflush(stderr);
    nfd = open("/dev/null", O_WRONLY);
    if (nfd < 0)
        return 2;
    oldout = dup(1);
    olderr = dup(2);
    if (oldout < 0 || olderr < 0) {
        close(nfd);
        return 2;
    }
    dup2(nfd, 1);
    dup2(nfd, 2);
    close(nfd);
    rc = check_long_functions_run(0, NULL);
    fflush(stdout);
    fflush(stderr);
    dup2(oldout, 1);
    dup2(olderr, 2);
    close(oldout);
    close(olderr);
    return rc;
}

static int lf_st_want(int got, int want, const char *msg)
{
    if (got == want)
        return 0;
    fprintf(stderr, "check_long_functions: SELFTEST FAILED — %s "
                    "(wanted exit %d, got %d)\n", msg, want, got);
    return 2;
}

static int lf_st_cov(void)
{
    int rc;
    if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0
        || setenv("ZCL_LONGFN_COVERAGE_ONLY", "1", 1) != 0)
        return 2;
    rc = lf_st_want(lf_quiet_run(), 0,
                    "the complete scan did not pass its coverage expectation");
    if (rc)
        return rc;
    if (setenv("ZCL_LONGFN_ENFORCED_ROOTS",
               "engine/controllers/src engine/services/src", 1) != 0)
        return 2;
    rc = lf_st_want(lf_quiet_run(), 2,
                    "an ENFORCED scan missing a whole declared root was not "
                    "UNPROVEN");
    unsetenv("ZCL_LONGFN_ENFORCED_ROOTS");
    if (rc)
        return rc;
    if (setenv("ZCL_LONGFN_LIB_ROOTS", "platform/modules/util", 1) != 0)
        return 2;
    rc = lf_st_want(lf_quiet_run(), 2,
                    "a WARN-tier scan narrowed below lib/ was not UNPROVEN");
    unsetenv("ZCL_LONGFN_LIB_ROOTS");
    if (rc)
        return rc;
    if (setenv("ZCL_LONGFN_COVERAGE_ALLOWANCE", "1", 1) != 0)
        return 2;
    rc = lf_st_want(lf_quiet_run(), 1,
                    "an allowance above the true shortfall was silently "
                    "tolerated");
    unsetenv("ZCL_LONGFN_COVERAGE_ALLOWANCE");
    unsetenv("ZCL_LONGFN_COVERAGE_ONLY");
    unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    return rc;
}

int check_long_functions_selftest(void)
{
    int bad = !(lf_st_sig() && lf_st_name()) || lf_st_cov();
    return st_ok(bad,
                 "[check_long_functions] SELFTEST PASS (a full scan passes "
                 "coverage in both tiers, an ENFORCED scan short one declared "
                 "root and a WARN scan narrowed below lib/ are each UNPROVEN "
                 "exit 2, and an allowance above the true shortfall is a "
                 "stale-ratchet exit 1)\n");
}
