/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `z23-lint precheck` (tools/lint/lintc/precheck.c) names the gates
 *          a tree newly breaks. It runs against a fixture gate table, so this
 *          test binary never links the real gates. Fixtures are throwaway
 *          trees and git repositories under test-tmp/.
 * NOT proven here: the real gates' behaviour in either tree. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"

#include "lint/lintc/lintc.h"
#include "lint/lintc/precheck_base.h"

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(_WIN32)



/* precheck runs against a fixture gate table, so this test binary never links
 * the real gates. check-no-python fails while a .py file sits in the cwd;
 * check-clean always passes. */
static int lsel_pc_no_python_run(int argc, char **argv)
{
    DIR *d;
    struct dirent *e;
    int found = 0;
    (void)argc;
    (void)argv;
    d = opendir(".");
    if (!d)
        return 2;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n > 3 && strcmp(e->d_name + n - 3, ".py") == 0)
            found = 1;
    }
    closedir(d);
    return found;
}

static int lsel_pc_clean_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

/* Refuses any extra argument like a real gate does (gate_flag_registry.c:771):
 * a gate run as `z23-lint GATE` gets argc 0, so precheck must pass argc 0 too
 * or this gate fails in both trees and nothing is reported NEW. */
static int lsel_pc_argv_run(int argc, char **argv)
{
    if (argc != 0)
        return 2;
    return lsel_pc_no_python_run(argc, argv);
}

/* Fails while <cic_repo_root>/MARKER exists. A gate that resolves its root
 * from the executable would see the same tree in both runs. */
static int lsel_pc_root_marker_run(int argc, char **argv)
{
    char root[PATH_MAX], marker[PATH_MAX + 8];
    (void)argc;
    (void)argv;
    if (cic_repo_root(root, sizeof root) != 0)
        return 2;
    (void)snprintf(marker, sizeof marker, "%s/MARKER", root);
    return access(marker, F_OK) == 0;
}

/* Appends one line to $LSEL_PC_COUNT per run: counts how often it executes. */
static int lsel_pc_count_run(int argc, char **argv)
{
    const char *path = getenv("LSEL_PC_COUNT");
    FILE *f = path ? fopen(path, "a") : NULL;
    (void)argc;
    (void)argv;
    if (!f)
        return 2;
    (void)fputs("x\n", f);
    return fclose(f) != 0;
}

static const struct lint_gate k_lsel_pc_gates[] = {
    { "check-no-python", lsel_pc_no_python_run, NULL },
    { "check-clean", lsel_pc_clean_run, NULL },
    { "check-argv-no-python", lsel_pc_argv_run, NULL },
    { "check-root-marker", lsel_pc_root_marker_run, NULL },
    { "check-count", lsel_pc_count_run, NULL },
};

const struct lint_gate *lint_gate_table(size_t *n)
{
    *n = sizeof(k_lsel_pc_gates) / sizeof(k_lsel_pc_gates[0]);
    return k_lsel_pc_gates;
}

struct lsel_pc_fx {
    char root[PATH_MAX];
    char dirty[PATH_MAX];
    char clean[PATH_MAX];
    char out[PATH_MAX];
    char cwd[PATH_MAX];
};

static bool lsel_pc_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    return fputs(text, f) >= 0 && fclose(f) == 0;
}

/* test-tmp/lintpc_XXXXXX/{dirty,clean}: only dirty holds a .py file. */
static bool lsel_pc_plant(struct lsel_pc_fx *fx)
{
    char py[PATH_MAX * 2];
    memset(fx, 0, sizeof(*fx));
    if (!test_mkdtemp(fx->root, sizeof(fx->root), "lintpc"))
        return false;
    (void)snprintf(fx->dirty, sizeof(fx->dirty), "%s/dirty", fx->root);
    (void)snprintf(fx->clean, sizeof(fx->clean), "%s/clean", fx->root);
    (void)snprintf(fx->out, sizeof(fx->out), "%s/out.txt", fx->root);
    (void)snprintf(py, sizeof(py), "%s/tool.py", fx->dirty);
    return getcwd(fx->cwd, sizeof(fx->cwd)) != NULL
        && mkdir(fx->dirty, 0755) == 0 && mkdir(fx->clean, 0755) == 0
        && lsel_pc_file(py, "x = 1\n");
}

/* Runs lint_precheck_main with cwd = tree and its stdout captured into out. */
static int lsel_pc_run(const struct lsel_pc_fx *fx, const char *tree,
                       char **argv, int argc, char *out, size_t cap)
{
    int rc = 2, saved = -1, fd = -1;
    FILE *f;
    if (chdir(tree) != 0)
        return 2;
    fflush(stdout);
    saved = dup(STDOUT_FILENO);
    fd = open(fx->out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (saved >= 0 && fd >= 0 && dup2(fd, STDOUT_FILENO) >= 0) {
        rc = lint_precheck_main(argc, argv);
        fflush(stdout);
        (void)dup2(saved, STDOUT_FILENO);
    }
    if (fd >= 0)
        close(fd);
    if (saved >= 0)
        close(saved);
    out[0] = '\0';
    /* Every later case resolves paths from the original cwd. */
    if (chdir(fx->cwd) != 0)
        return 2;
    f = fopen(fx->out, "r");
    if (f) {
        size_t got = fread(out, 1, cap - 1, f);
        out[got] = '\0';
        fclose(f);
    }
    return rc;
}

static int test_lsel_precheck(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: precheck names the gate a tree newly breaks, exit 1") {
        struct lsel_pc_fx fx;
        char base_arg[PATH_MAX + 16], out[512];
        ASSERT(lsel_pc_plant(&fx));
        (void)snprintf(base_arg, sizeof(base_arg), "--base=%s", fx.clean);
        char *argv[] = { base_arg, (char *)"--gates=check-no-python" };
        ASSERT_EQ(lsel_pc_run(&fx, fx.dirty, argv, 2, out, sizeof(out)), 1);
        ASSERT(strstr(out, "NEW check-no-python rc=1\n") != NULL);
        ASSERT(strstr(out, "precheck: 1 new failure(s) of 1 gates\n") != NULL);
        ASSERT_EQ(lsel_pc_run(&fx, fx.clean, argv, 2, out, sizeof(out)), 0);
        ASSERT(strstr(out, "NEW ") == NULL);
        ASSERT(strstr(out, "precheck: 0 new failure(s) of 1 gates\n") != NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

/* Witness for the argv convention: check-argv-no-python fails on any extra
 * argument. Before the fix precheck passed argc 1, so it failed in both trees
 * and printed nothing; after the fix it reports NEW here and not in clean. */
static int test_lsel_precheck_argv(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: precheck runs a gate with the plain CLI argv (argc 0)") {
        struct lsel_pc_fx fx;
        char base_arg[PATH_MAX + 16], out[512];
        ASSERT(lsel_pc_plant(&fx));
        (void)snprintf(base_arg, sizeof(base_arg), "--base=%s", fx.clean);
        char *argv[] = { base_arg, (char *)"--gates=check-argv-no-python" };
        ASSERT_EQ(lsel_pc_run(&fx, fx.dirty, argv, 2, out, sizeof(out)), 1);
        ASSERT(strstr(out, "NEW check-argv-no-python rc=1\n") != NULL);
        ASSERT(strstr(out, "precheck: 1 new failure(s) of 1 gates\n") != NULL);
        ASSERT_EQ(lsel_pc_run(&fx, fx.clean, argv, 2, out, sizeof(out)), 0);
        ASSERT(strstr(out, "NEW ") == NULL);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

/* Witness for the root override: check-root-marker asks cic_repo_root, which
 * used to answer from the executable path, so both runs saw one tree and the
 * gate could never be NEW. */
static int test_lsel_precheck_repo_root(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: precheck points cic_repo_root at each tree it lints") {
        struct lsel_pc_fx fx;
        char base_arg[PATH_MAX + 16], out[512], path[PATH_MAX * 2];
        char root[PATH_MAX], want[PATH_MAX], argv0[PATH_MAX * 2];
        const char *saved_argv0 = g_lint_argv0;
        ASSERT(lsel_pc_plant(&fx));
        (void)snprintf(path, sizeof(path), "%s/MARKER", fx.dirty);
        ASSERT(lsel_pc_file(path, "x\n"));
        (void)snprintf(base_arg, sizeof(base_arg), "--base=%s", fx.clean);
        char *argv[] = { base_arg, (char *)"--gates=check-root-marker" };
        ASSERT_EQ(lsel_pc_run(&fx, fx.dirty, argv, 2, out, sizeof(out)), 1);
        ASSERT(strstr(out, "NEW check-root-marker rc=1\n") != NULL);
        ASSERT_EQ(lsel_pc_run(&fx, fx.clean, argv, 2, out, sizeof(out)), 0);
        ASSERT(strstr(out, "NEW ") == NULL);
        /* Unset: the root still comes from the executable path. */
        (void)snprintf(path, sizeof(path), "%s/exe", fx.root);
        ASSERT(mkdir(path, 0755) == 0);
        (void)snprintf(path, sizeof(path), "%s/exe/build", fx.root);
        ASSERT(mkdir(path, 0755) == 0);
        (void)snprintf(path, sizeof(path), "%s/exe/build/bin", fx.root);
        ASSERT(mkdir(path, 0755) == 0);
        (void)snprintf(argv0, sizeof(argv0), "%s/z23-lint", path);
        ASSERT(realpath(fx.root, want) != NULL);
        (void)snprintf(want + strlen(want), sizeof(want) - strlen(want), "/exe");
        ASSERT_EQ(unsetenv("ZCL_LINT_REPO_ROOT"), 0);
        g_lint_argv0 = argv0;
        ASSERT_EQ(cic_repo_root(root, sizeof(root)), 0);
        g_lint_argv0 = saved_argv0;
        ASSERT_STR_EQ(root, want);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lsel_precheck_usage(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: precheck refuses a bad option as a usage error") {
        struct lsel_pc_fx fx;
        char base_arg[PATH_MAX + 16], out[512];
        ASSERT(lsel_pc_plant(&fx));
        (void)snprintf(base_arg, sizeof(base_arg), "--base=%s", fx.clean);
        char *argv[] = { base_arg, (char *)"--jobs=0" };
        ASSERT_EQ(lsel_pc_run(&fx, fx.dirty, argv, 2, out, sizeof(out)), 2);
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

/* A git repo at <root>/repo with one commit; the cache lives in <root>/cache. */
static bool lsel_pc_git_repo(const struct lsel_pc_fx *fx, char *repo, size_t cap)
{
    char cache[PATH_MAX + 8], f[PATH_MAX + 16];
    const char *init[] = { "init", "-q", NULL };
    (void)snprintf(repo, cap, "%s/repo", fx->root);
    (void)snprintf(cache, sizeof(cache), "%s/cache", fx->root);
    (void)snprintf(f, sizeof(f), "%s/a.txt", repo);
    return mkdir(repo, 0755) == 0 && setenv("ZCL_PRECHECK_CACHE", cache, 1) == 0
        && precheck_base_git(repo, init, NULL, 0) == 0
        && lsel_pc_file(f, "a\n");
}

static bool lsel_pc_commit(const char *repo)
{
    const char *add[] = { "add", "-A", NULL };
    const char *ci[] = { "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                         "commit.gpgsign=false", "commit", "-q", "-m", "c",
                         NULL };
    return precheck_base_git(repo, add, NULL, 0) == 0
        && precheck_base_git(repo, ci, NULL, 0) == 0;
}

static size_t lsel_pc_file_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (size_t)st.st_size : 0;
}

static int test_lsel_precheck_no_origin(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: precheck without --base needs origin/main, exit 2") {
        struct lsel_pc_fx fx;
        char repo[PATH_MAX], out[512];
        char *argv[] = { (char *)"--gates=check-clean" };
        ASSERT(lsel_pc_plant(&fx));
        ASSERT(lsel_pc_git_repo(&fx, repo, sizeof(repo)) && lsel_pc_commit(repo));
        ASSERT_EQ(lsel_pc_run(&fx, repo, argv, 1, out, sizeof(out)), 2);
        (void)unsetenv("ZCL_PRECHECK_CACHE");
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}

static int test_lsel_precheck_auto_base(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: precheck auto base is the merge-base and its results are cached") {
        struct lsel_pc_fx fx;
        char repo[PATH_MAX], out[512], cnt[PATH_MAX + 16], res[PATH_MAX * 2];
        char sha[72], text[64] = "", tag[48];
        const char *head[] = { "rev-parse", "HEAD", NULL };
        char *argv[] = { (char *)"--gates=check-no-python,check-count" };
        ASSERT(lsel_pc_plant(&fx));
        ASSERT(lsel_pc_git_repo(&fx, repo, sizeof(repo)) && lsel_pc_commit(repo));
        ASSERT_EQ(precheck_base_git(repo, head, sha, sizeof(sha)), 0);
        const char *ref[] = { "update-ref", "refs/remotes/origin/main", sha, NULL };
        ASSERT_EQ(precheck_base_git(repo, ref, NULL, 0), 0);
        (void)snprintf(res, sizeof(res), "%s/tool.py", repo);
        ASSERT(lsel_pc_file(res, "x = 1\n") && lsel_pc_commit(repo));
        (void)snprintf(cnt, sizeof(cnt), "%s/count.txt", fx.root);
        ASSERT_EQ(setenv("LSEL_PC_COUNT", cnt, 1), 0);
        /* HEAD has tool.py, the merge-base does not: NEW only if the base is it. */
        ASSERT_EQ(lsel_pc_run(&fx, repo, argv, 1, out, sizeof(out)), 1);
        ASSERT(strstr(out, "NEW check-no-python rc=1\n") != NULL);
        ASSERT_EQ(lsel_pc_file_size(cnt), 4U);
        (void)snprintf(res, sizeof(res), "%s/cache/base-native-%s-%s.txt", fx.root, sha,
                       precheck_base_binary_tag(tag, sizeof(tag)));
        FILE *f = fopen(res, "r");
        ASSERT(f != NULL);
        ASSERT(fread(text, 1, sizeof(text) - 1, f) > 0);
        fclose(f);
        ASSERT(strstr(text, "check-no-python 0\n") != NULL);
        /* Second call: the cached base rcs are used, only the tree here reruns. */
        ASSERT_EQ(lsel_pc_run(&fx, repo, argv, 1, out, sizeof(out)), 1);
        ASSERT(strstr(out, "NEW check-no-python rc=1\n") != NULL);
        ASSERT_EQ(lsel_pc_file_size(cnt), 6U);
        (void)unsetenv("LSEL_PC_COUNT");
        (void)unsetenv("ZCL_PRECHECK_CACHE");
        test_rm_rf_recursive(fx.root);
    } TEST_END
    return failures;
}


int test_lint_precheck(void)
{
    int failures = 0;
    failures += test_lsel_precheck();
    failures += test_lsel_precheck_usage();
    failures += test_lsel_precheck_no_origin();
    failures += test_lsel_precheck_auto_base();
    failures += test_lsel_precheck_argv();
    failures += test_lsel_precheck_repo_root();
    return failures;
}

#else

int test_lint_precheck(void)
{
    printf("lint_precheck: SKIP — precheck forks gate children and drives "
           "POSIX Git; not built on Windows\n");
    return 0;
}

#endif
