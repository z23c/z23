/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the cross-worktree proof for the check-windows-cross-syntax result
 * cache (--selftest). A land proof builds a fresh worktree per stack, so the
 * cache only saves time if (1) its default home is outside the worktree, and
 * (2) an identical tree at a different path hits what the first one stored.
 * Both are proved over two synthetic trees with the stub compiler, run as the
 * real gate runs: cwd at the tree root, root ".", repo-relative source rows.
 * A changed header in the second tree must still miss every TU.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <dirent.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>
#include "lintc.h"
#include "gate_windows_cross_syntax_priv.h"

enum { SH_P = 1024, SH_UNITS = 6 };

/* snprintf behind a call so an over-long path truncates visibly (the later
 * stat or open fails closed) instead of tripping format-truncation. */
static int shp_(char *dst, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static int shp_(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n < 0 || (size_t)n >= cap;
}

/* A truncated path ends the proof with the setup-error code 2 instead of
 * running against a half path. Only used as a statement in int functions. */
#define shp(...)                                                           \
    do {                                                                   \
        if (shp_(__VA_ARGS__)) return 2;                                   \
    } while (0)

static int sh_fail(const char *msg)
{
    printf("FAIL: --self-test — tu-cache shared store: %s\n", msg);
    return 1;
}

/* One tree: src/shared.h plus SH_UNITS units that include it. */
static int sh_producers(const char *tree)
{
    static const char *const names[] = { "cache", "digest", "sweep" };
    char path[SH_P];
    shp(path, sizeof path, "%s/tools/lint/lintc", tree);
    if (csr_mkdirs(path) != 0) return 2;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        shp(path, sizeof path, "%s/tools/lint/lintc/gate_windows_cross_syntax_%s.c", tree, names[i]);
        if (csr_write(path, "/* producer fixture */\n") != 0) return 2;
    }
    return 0;
}

static int sh_tree(const char *tree, const char *list)
{
    char p[SH_P], text[128];
    if (sh_producers(tree) != 0) return 2;
    shp(p, sizeof p, "%s/src", tree);
    if (csr_mkdirs(p) != 0) return 2;
    shp(p, sizeof p, "%s/src/shared.h", tree);
    if (csr_write(p, "#define SHARED_ST 1\n") != 0) return 2;
    FILE *l = fopen(list, "w");
    if (!l) return 2;
    for (int i = 0; i < SH_UNITS; i++) {
        if (shp_(p, sizeof p, "%s/src/s%d.c", tree, i) ||
            shp_(text, sizeof text, "#include \"shared.h\"\nint s_%d(void);\n",
                 i) ||
            csr_write(p, text) != 0) { fclose(l); return 2; }
        fprintf(l, "src/s%d.c\n", i);
    }
    fclose(l);
    return 0;
}

/* Sweeps the tree whose root is the cwd, through the default store. */
static int sh_sweep(const char *work, const char *list, const char *stub,
                    const char *cc, const char *flags, int *h, int *m, int *s)
{
    char miss[SH_P], out[SH_P], log[SH_P], rc[SH_P];
    shp(miss, sizeof miss, "%s/miss.txt", work);
    shp(out, sizeof out, "%s/out", work);
    if (csr_mkdirs(out) != 0) return 2;
    wcs_cache_setup("tu-cache-shared-selftest", stub, cc, flags, work, ".",
                    NULL);
    if (!wcs_cache_on())
        return sh_fail("the default store refused to enable");
    if (wcs_cache_plan(list, miss, out, 1) != 0) return 2;
    FILE *mf = fopen(miss, "r");
    if (!mf) return 2;
    static char src[SH_P];
    while (fgets(src, sizeof src, mf)) {
        src[strcspn(src, "\n")] = '\0';
        if (!src[0]) continue;
        char *const cargv[] = { (char *)cc, (char *)"-c", src, NULL };
        char dir[SH_P];
        if (shp_(log, sizeof log, "%s/%s.log", out, src) ||
            shp_(rc, sizeof rc, "%s/%s.rc", out, src) ||
            shp_(dir, sizeof dir, "%s/src", out) || csr_mkdirs(dir) != 0) {
            fclose(mf);
            return 2;
        }
        wcs_cache_compile(log, rc, cc, cargv, src);
    }
    fclose(mf);
    wcs_cache_counts(h, m, s);
    return 0;
}

static int sh_expect(const char *what, int h, int m, int s, int eh, int em,
                     int es)
{
    if (h == eh && m == em && s == es) return 0;
    char msg[256];
    shp(msg, sizeof msg, "%s reported %d hit / %d miss / %d stored, "
             "wanted %d/%d/%d", what, h, m, s, eh, em, es);
    return sh_fail(msg);
}

struct sh_env { char home[SH_P], tree[2][SH_P], work[2][SH_P], list[2][SH_P]; };

static int sh_paths(const char *base, struct sh_env *e)
{
    shp(e->home, sizeof e->home, "%s/home", base);
    for (int i = 0; i < 2; i++) {
        shp(e->work[i], sizeof e->work[i], "%s/w%d", base, i);
        shp(e->tree[i], sizeof e->tree[i], "%s/w%d/tree", base, i);
        shp(e->list[i], sizeof e->list[i], "%s/w%d/srcs.txt", base, i);
        if (csr_mkdirs(e->work[i]) != 0 || sh_tree(e->tree[i], e->list[i]))
            return 2;
    }
    return csr_mkdirs(e->home) == 0 ? 0 : 2;
}

/* Sweep tree i from inside it; cwd is restored by the caller. */
static int sh_run(const struct sh_env *e, int i, const char *stub,
                  const char *cc, const char *flags, int *h, int *m, int *s)
{
    if (chdir(e->tree[i]) != 0) return 2;
    return sh_sweep(e->work[i], e->list[i], stub, cc, flags, h, m, s);
}

/* A compiler whose --version line is unchanged but whose bytes differ (the
 * stub plus a trailing comment) must miss every TU: the version line alone
 * does not identify a compiler. */
static int sh_cc_identity(struct sh_env *e, const char *stub,
                          const char *flags)
{
    static char body[4096];
    char alt[SH_P];
    int h, m, s, rc;
    FILE *f = fopen(stub, "rb");
    if (!f) return 2;
    size_t n = fread(body, 1, sizeof body - 32, f);
    int bad = ferror(f) || !feof(f);
    fclose(f);
    if (bad) return 2;
    memcpy(body + n, "\n# other compiler bytes\n", 25);
    shp(alt, sizeof alt, "%s/stub_cc_alt.sh", e->work[1]);
    if (csr_write(alt, body) != 0 || chmod(alt, 0755) != 0) return 2;
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("the unchanged compiler (control)", h, m, s, SH_UNITS,
                        0, 0)) != 0) return rc;
    if ((rc = sh_run(e, 1, stub, alt, flags, &h, &m, &s)) != 0) return rc;
    return sh_expect("a compiler with the same version line but other bytes",
                     h, m, s, 0, SH_UNITS, SH_UNITS);
}

static int sh_producer_cases(struct sh_env *e, const char *stub, const char *flags)
{
    int h, m, s, rc;
    char p[SH_P];
    shp(p, sizeof p, "%s/tools/lint/lintc/gate_windows_cross_syntax_sweep.c", e->tree[1]);
    if (csr_write(p, "/* changed producer */\n") != 0) return 2;
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("a changed sweep producer", h, m, s, 0, SH_UNITS, SH_UNITS)) != 0) return rc;
    if (csr_write(p, "/* producer fixture */\n") != 0) return 2;
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("a restored sweep producer", h, m, s, SH_UNITS, 0, 0)) != 0) return rc;
    if (unlink(p) != 0) return 2;
    wcs_cache_setup("tu-cache-shared-selftest", stub, stub, flags, e->work[1], ".", NULL);
    if (wcs_cache_on()) return sh_fail("missing sweep producer enabled cache");
    return csr_write(p, "/* producer fixture */\n") == 0 ? 0 : 2;
}

static int sh_generation_count(const char *root)
{
    DIR *dir = opendir(root);
    if (!dir) return -1;
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL)
        if (entry->d_name[0] != '.') ++count;
    closedir(dir);
    return count;
}

static int sh_retention_case(struct sh_env *e, const char *stub, const char *flags)
{
    int h, m, s, rc;
    char root[SH_P], peer[SH_P];
    struct stat st;
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    shp(root, sizeof root, "%s/.cache/z23/lint-tu/tu-cache-shared-selftest", e->home);
    shp(peer, sizeof peer, "%s/future-generation", root);
    if (stat(root, &st) != 0 || csr_mkdirs(peer) != 0) return 2;
    struct utimbuf future = {.actime = st.st_mtime + 3600, .modtime = st.st_mtime + 3600};
    if (utime(peer, &future) != 0) return 2;
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("the selected generation beside a newer peer", h, m, s,
                        SH_UNITS, 0, 0)) != 0) return rc;
    return sh_generation_count(root) == 1 ? 0 : sh_fail("the one-generation limit was exceeded");
}

static int sh_retention(struct sh_env *e, const char *stub, const char *flags)
{
    const char *value = getenv("ZCL_LINT_TU_CACHE_GENERATIONS");
    char *saved = value ? strdup(value) : NULL;
    if (value && !saved) return 2;
    int rc = setenv("ZCL_LINT_TU_CACHE_GENERATIONS", "1", 1) == 0 ?
        sh_retention_case(e, stub, flags) : 2;
    int restored = saved ? setenv("ZCL_LINT_TU_CACHE_GENERATIONS", saved, 1) :
        unsetenv("ZCL_LINT_TU_CACHE_GENERATIONS");
    free(saved);
    return restored == 0 ? rc : 2;
}

static int sh_cases(struct sh_env *e, const char *stub, const char *flags)
{
    int h, m, s, rc;
    char p[SH_P];
    if ((rc = sh_run(e, 0, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("a cold run in the first tree", h, m, s, 0,
                        SH_UNITS, SH_UNITS)) != 0) return rc;
    struct stat st;
    shp(p, sizeof p, "%s/.cache/z23/lint-tu", e->home);
    if (stat(p, &st) != 0)
        return sh_fail("the default store is not under the host cache root");
    shp(p, sizeof p, "%s/.cache", e->tree[0]);
    if (stat(p, &st) == 0)
        return sh_fail("the default store was created inside the worktree");
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("an identical tree at another path", h, m, s,
                        SH_UNITS, 0, 0)) != 0) return rc;
    if ((rc = sh_producer_cases(e, stub, flags)) != 0) return rc;
    shp(p, sizeof p, "%s/src/shared.h", e->tree[1]);
    if (csr_write(p, "#define SHARED_ST 2\n") != 0) return 2;
    if ((rc = sh_run(e, 1, stub, stub, flags, &h, &m, &s)) != 0) return rc;
    if ((rc = sh_expect("a changed header in the second tree", h, m, s, 0,
                        SH_UNITS, SH_UNITS)) != 0) return rc;
    if ((rc = sh_cc_identity(e, stub, flags)) != 0) return rc;
    return sh_retention(e, stub, flags);
}

int wcs_selftest_shared_store(const char *base, const char *stub,
                              const char *flags)
{
    struct sh_env e;
    char cwd[PATH_MAX], sbase[SH_P];
    shp(sbase, sizeof sbase, "%s/shared-store", base);
    rap_rm_rf(sbase);
    if (!getcwd(cwd, sizeof cwd) || sh_paths(sbase, &e) != 0) return 2;
    char *old_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    char *old_xdg = getenv("XDG_CACHE_HOME") ? strdup(getenv("XDG_CACHE_HOME"))
                                             : NULL;
    char *old_dir = getenv("ZCL_LINT_TU_CACHE_DIR")
                        ? strdup(getenv("ZCL_LINT_TU_CACHE_DIR")) : NULL;
    char *old_off = getenv("ZCL_LINT_TU_CACHE")
                        ? strdup(getenv("ZCL_LINT_TU_CACHE")) : NULL;
    setenv("HOME", e.home, 1);
    unsetenv("XDG_CACHE_HOME");
    unsetenv("ZCL_LINT_TU_CACHE_DIR");
    unsetenv("ZCL_LINT_TU_CACHE");
    int rc = sh_cases(&e, stub, flags);
    if (chdir(cwd) != 0 && rc == 0) rc = 2;
    if (old_home) setenv("HOME", old_home, 1); else unsetenv("HOME");
    if (old_xdg) setenv("XDG_CACHE_HOME", old_xdg, 1);
    if (old_dir) setenv("ZCL_LINT_TU_CACHE_DIR", old_dir, 1);
    if (old_off) setenv("ZCL_LINT_TU_CACHE", old_off, 1);
    free(old_home); free(old_xdg); free(old_dir); free(old_off);
    rap_rm_rf(sbase);
    return rc;
}
static void worker_test_child(int mode, int index, const char *missing)
{
    if (index == 0 && mode == 2) raise(SIGKILL);
    if (index == 0 && mode == 3) wcs_worker_child(missing, 1, 0);
    if (index == 0 && mode == 4) wcs_worker_child(".", 1, 0);
    _exit(index == 0 && mode == 1 ? 7 : 0);
}

static int worker_status_case(int mode)
{
    pid_t pids[2];
    char missing[WCS_PATH];
    struct stat st;
    if (snprintf(missing, sizeof missing, "%s/worker-list-absent", g_wcs_work) >= (int)sizeof missing ||
        stat(missing, &st) == 0 || errno != ENOENT) return 2;
    for (int i = 0; i < 2; i++) {
        pids[i] = fork();
        if (pids[i] < 0) { wcs_reap_workers(pids, i); return 2; }
        if (pids[i] == 0) worker_test_child(mode, i, missing);
    }
    int rc = wcs_reap_workers(pids, 2);
    for (int i = 0; i < 2; i++) {
        int st2;
        if (waitpid(pids[i], &st2, WNOHANG) != -1 || errno != ECHILD) return 1;
    }
    return (mode == 0 ? rc == 0 : rc != 0) ? 0 : 1;
}

int wcs_worker_status_test(void)
{
    pid_t other = fork();
    if (other < 0) return 2;
    if (other == 0) _exit(42);
    int failed = 0;
    for (int mode = 0; mode < 5; mode++)
        if (worker_status_case(mode)) failed = 1;
    int st; pid_t waited;
    do { waited = waitpid(other, &st, 0); } while (waited < 0 && errno == EINTR);
    if (waited != other || !WIFEXITED(st) || WEXITSTATUS(st) != 42) failed = 1;
    if (failed) fprintf(stderr, "worker ownership or status check failed\n");
    return failed;
}
