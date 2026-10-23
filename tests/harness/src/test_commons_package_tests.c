/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: every Commons package builds with its own library sources and
 * passes its own tests/test_<pkg>.c.
 *
 * A package under contexts/commons/packages/ is a self-contained zcode
 * package: include/, src/ sources and tests/test_<pkg>.c. This group compiles
 * each one the way a package consumer would (-Iinclude, strict warnings,
 * nothing from the rest of the tree), runs the resulting binary and fails
 * if any package fails to build or its test exits nonzero. It is the land
 * proof for every package source, header, test and manifest. */

#include "test/test_core.h"

#include "dev/devloop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#endif

enum { CPT_NAME = 64, CPT_MAX_PKGS = 256, CPT_MAX_SRC = 16,
       CPT_MAX_ARGV = 160, CPT_MAX_DEPS = 24, CPT_MANIFEST_MAX = 65536,
       CPT_BUILD_MS = 120000, CPT_RUN_MS = 60000 };

static const char k_cpt_root[] = "contexts/commons/packages";

/* Packages whose test cannot build here, each with the reason. Never let a
 * package pass silently: an entry is printed as SKIP on every run. */
static const struct { const char *name; const char *why; } k_cpt_skip[] = {
    { NULL, NULL },
};

static struct zcl_devloop_process_result g_cpt_res;
static char g_cpt_why[320];

static const char *cpt_skip_reason(const char *pkg)
{
    for (size_t i = 0; k_cpt_skip[i].name; i++)
        if (strcmp(k_cpt_skip[i].name, pkg) == 0)
            return k_cpt_skip[i].why;
    return NULL;
}

static bool cpt_is_c_file(const char *name)
{
    size_t n = strlen(name);
    return n > 2 && strcmp(name + n - 2, ".c") == 0;
}

static int cpt_name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Collect the entries of `dir` (directories or .c files), sorted. */
static size_t cpt_list(const char *dir, bool want_dirs,
                       char names[][CPT_NAME], size_t cap)
{
    size_t n = 0;
#if !defined(_WIN32)
    DIR *d = opendir(dir);
    if (!d) return 0;
    for (struct dirent *e; (e = readdir(d)) != NULL && n < cap;) {
        if (e->d_name[0] == '.' || strlen(e->d_name) >= CPT_NAME) continue;
        if (!want_dirs && !cpt_is_c_file(e->d_name)) continue;
        memcpy(names[n], e->d_name, strlen(e->d_name) + 1);
        n++;
    }
    closedir(d);
    qsort(names, n, CPT_NAME, cpt_name_cmp);
#else
    (void)dir; (void)want_dirs; (void)names; (void)cap;
#endif
    return n;
}

static bool cpt_run(const char *cwd, const char *const argv[], int ms,
                    const char *pkg, const char *what)
{
    bool ok = zcl_devloop_process_run(cwd, argv, ms, &g_cpt_res) &&
              !g_cpt_res.timed_out && g_cpt_res.term_signal == 0 &&
              g_cpt_res.exit_code == 0;
    if (!ok) {
        /* One line, so the runner's failure excerpt carries the cause. */
        char first[160];
        size_t k = strcspn(g_cpt_res.output, "\n");
        (void)snprintf(first, sizeof first, "%.*s",
                       (int)(k < sizeof first - 1 ? k : sizeof first - 1),
                       g_cpt_res.output);
        (void)snprintf(g_cpt_why, sizeof g_cpt_why,
                       "%s exit=%d signal=%d: %s", what,
                       g_cpt_res.exit_code, g_cpt_res.term_signal, first);
        (void)pkg;
    }
    return ok;
}

/* The packages `pkg` depends on, transitively, read from the "dependencies"
 * array of each zcode-package.json (a dependency is spelled "name":
 * "<pkg>/<pkg>"). `deps` collects them in discovery order. */
static void cpt_deps(const char *pkg, char deps[][CPT_NAME], size_t *nd)
{
    static char text[CPT_MANIFEST_MAX];
    char path[512];
    (void)snprintf(path, sizeof path, "%s/%s/zcode-package.json",
                   k_cpt_root, pkg);
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    size_t len = fread(text, 1, sizeof text - 1, fp);
    (void)fclose(fp);
    text[len] = '\0';
    const char *p = strstr(text, "\"dependencies\"");
    char found[CPT_MAX_DEPS][CPT_NAME];
    size_t nf = 0;
    while (p && nf < CPT_MAX_DEPS && (p = strstr(p, "\"name\": \"")) != NULL) {
        p += strlen("\"name\": \"");
        size_t k = strcspn(p, "/\"");
        if (k > 0 && k < CPT_NAME) {
            memcpy(found[nf], p, k);
            found[nf++][k] = '\0';
        }
    }
    for (size_t i = 0; i < nf; i++) {
        bool seen = false;
        for (size_t j = 0; j < *nd; j++)
            seen |= strcmp(deps[j], found[i]) == 0;
        if (seen || *nd >= CPT_MAX_DEPS) continue;
        memcpy(deps[*nd], found[i], CPT_NAME);
        (*nd)++;
        cpt_deps(found[i], deps, nd);
    }
}

struct cpt_argv {
    const char *v[CPT_MAX_ARGV];
    char pool[CPT_MAX_ARGV][128];
    int n;
};

static void cpt_push(struct cpt_argv *a, const char *s)
{
    if (a->n < CPT_MAX_ARGV - 1) {
        (void)snprintf(a->pool[a->n], sizeof a->pool[0], "%s", s);
        a->v[a->n] = a->pool[a->n];
        a->n++;
    }
}

/* -I and every source file of one package, addressed from the package under
 * test (all packages are siblings). */
static void cpt_push_pkg(struct cpt_argv *a, const char *pkg)
{
    static char srcs[CPT_MAX_SRC][CPT_NAME];
    char dir[512], arg[160];
    (void)snprintf(arg, sizeof arg, "-I../%s/include", pkg);
    cpt_push(a, arg);
    (void)snprintf(dir, sizeof dir, "%s/%s/src", k_cpt_root, pkg);
    size_t ns = cpt_list(dir, false, srcs, CPT_MAX_SRC);
    for (size_t i = 0; i < ns; i++) {
        (void)snprintf(arg, sizeof arg, "../%s/src/%s", pkg, srcs[i]);
        cpt_push(a, arg);
    }
}

/* cc <flags> include and source dirs of the package and its dependencies, its own test. */
static bool cpt_build(const char *dir, const char *pkg, const char *out)
{
    static struct cpt_argv a;
    static char deps[CPT_MAX_DEPS][CPT_NAME];
    char arg[160];
    size_t nd = 0;

    a.n = 0;
    cpt_deps(pkg, deps, &nd);
    for (const char *f = "cc -std=c23 -O1 -Wall -Wextra -Werror -pedantic";
         *f;) {
        size_t k = strcspn(f, " ");
        (void)snprintf(arg, sizeof arg, "%.*s", (int)k, f);
        cpt_push(&a, arg);
        f += k + (f[k] == ' ');
    }
    /* tests/test_zpem.c hands the CLI a stack object on a grow path that must
     * refuse before realloc; GCC -O1 sees the dead realloc call and warns.
     * The refusal is what the test proves, so only zpem drops the warning. */
    if (strcmp(pkg, "zpem") == 0)
        cpt_push(&a, "-Wno-free-nonheap-object");
    cpt_push_pkg(&a, pkg);
    for (size_t i = 0; i < nd; i++)
        cpt_push_pkg(&a, deps[i]);
    (void)snprintf(arg, sizeof arg, "tests/test_%s.c", pkg);
    cpt_push(&a, arg);
    cpt_push(&a, "-lm");
    cpt_push(&a, "-o");
    cpt_push(&a, out);
    a.v[a.n] = NULL;
    return cpt_run(dir, a.v, CPT_BUILD_MS, pkg, "build");
}

/* 1 = passed, 0 = failed, -1 = skipped (reported). */
static int cpt_one(const char *pkg, const char *tmp)
{
    char dir[512], out[640];
    const char *why = cpt_skip_reason(pkg);
    if (why) {
        printf("commons_package_tests: %s... SKIP (%s)\n", pkg, why);
        return -1;
    }
    (void)snprintf(dir, sizeof dir, "%s/%s", k_cpt_root, pkg);
    (void)snprintf(out, sizeof out, "%s/%s.bin", tmp, pkg);
    int ok = cpt_build(dir, pkg, out);
    if (ok) {
        const char *run_argv[] = { out, NULL };
        ok = cpt_run(dir, run_argv, CPT_RUN_MS, pkg, "test");
    }
    printf("commons_package_tests: %s... %s%s%s\n", pkg, ok ? "OK" : "FAIL",
           ok ? "" : " ", ok ? "" : g_cpt_why);
    return ok;
}

int test_commons_package_tests(void)
{
    static char pkgs[CPT_MAX_PKGS][CPT_NAME];
    char tmp[512];
    int failures = 0, ran = 0;

    printf("\n=== commons_package_tests: every package builds and passes "
           "its own test ===\n");
    /* The fixture opts in to process execution; the group runs in its own
     * process, so the variable does not leak to another group. */
    (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    size_t n = cpt_list(k_cpt_root, true, pkgs, CPT_MAX_PKGS);
    if (n == 0 || !test_mkdtemp(tmp, sizeof tmp, "commons_pkg")) {
        printf("commons_package_tests: no packages or no tmpdir... FAIL\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int r = cpt_one(pkgs[i], tmp);
        failures += r == 0;
        ran += r == 1;
    }
    test_cleanup_tmpdir(tmp);
    printf("commons_package_tests: %d of %zu package(s) passed, %d "
           "failure(s)\n", ran, n, failures);
    return failures;
}
