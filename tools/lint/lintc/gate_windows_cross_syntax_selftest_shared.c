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
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
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

/* Exercise the real cache directory helper on existing and colliding paths. */
int wcs_mkdir_selftest(const char *base)
{
    char root[SH_P], dir[SH_P], file[SH_P], link[SH_P], child[SH_P];
    shp(root, sizeof root, "%s/mkdir-scope", base);
    shp(dir, sizeof dir, "%s/a/b", root);
    shp(file, sizeof file, "%s/file", root);
    shp(link, sizeof link, "%s/link", root);
    shp(child, sizeof child, "%s/link/child", root);
    if (wcs_mkdirs_p(dir) != 0 || wcs_mkdirs_p(dir) != 0 ||
        csr_write(file, "fixture") != 0 || symlink("a", link) != 0 ||
        wcs_mkdirs_p(link) != 0 || wcs_mkdirs_p(child) != 0)
        return sh_fail("mkdir directory creation or symlink traversal");
    if (wcs_mkdirs_p(file) == 0)
        return sh_fail("mkdir accepted an existing regular file");
    shp(link, sizeof link, "%s/file-link", root);
    if (symlink("file", link) != 0 || wcs_mkdirs_p(link) == 0)
        return sh_fail("mkdir accepted a symlink to a regular file");
    char longpath[WCS_PATH + 1];
    memset(longpath, 'x', sizeof longpath - 1);
    longpath[sizeof longpath - 1] = 0;
    if (wcs_mkdirs_p(longpath) == 0)
        return sh_fail("mkdir accepted an overlong path");
    shp(child, sizeof child, "%s/file/child", root);
    if (wcs_mkdirs_p(child) == 0)
        return sh_fail("mkdir accepted a regular-file ancestor");
    return 0;
}

/* Run the real worker dispatcher against empty, nonempty and broken lists. */
int wcs_worker_empty_test(const char *base)
{
    char path[SH_P], absent[SH_P];
    int started = -1;
    shp(path, sizeof path, "%s/worker-empty-list", base);
    shp(absent, sizeof absent, "%s/worker-absent-list", base);
    if (csr_write(path, "") != 0) return 2;
    if (wcs_worker_run(path, 2, &started) != 0 || started != 0)
        return sh_fail("empty miss list started workers");
    if (wcs_worker_run(path, 0, &started) == 0 ||
        wcs_worker_run(path, 33, &started) == 0)
        return sh_fail("invalid worker count accepted");
    if (geteuid() != 0) {
        if (chmod(path, 0) != 0) return 2;
        int refused = wcs_worker_run(path, 2, &started) != 0;
        if (chmod(path, 0600) != 0 || !refused)
            return sh_fail("unreadable miss list accepted");
    }
    if (wcs_worker_run(absent, 2, &started) == 0 ||
        wcs_worker_run(base, 2, &started) == 0)
        return sh_fail("invalid miss list accepted");
    return 0;
}

static int sh_worker_results(const char *out, int rows)
{
    char name[64], log[SH_P], rc[SH_P];
    for (int i = 0; i < rows; i++) {
        shp(name, sizeof name, "unit%d.c", i);
        if (wcs_paths_for(name, out, log, sizeof log, rc, sizeof rc)) return 2;
        struct stat st;
        if (stat(log, &st) != 0 || stat(rc, &st) != 0) return 1;
        FILE *result = fopen(rc, "r");
        int status = -1;
        if (!result) return 1;
        int ok = fscanf(result, "%d", &status) == 1 && status == 0;
        if (fclose(result) != 0 || !ok) return 1;
    }
    return 0;
}

/* Each real worker writes its own fixture result; the final row lacks newline. */
static int sh_worker_case(const char *base, int rows, int limit)
{
    char list[SH_P], out[SH_P];
    shp(list, sizeof list, "%s/cap-%d.list", base, rows);
    shp(out, sizeof out, "%s/cap-%d.out", base, rows);
    if (mkdir(out, 0700) != 0) return 2;
    FILE *f = fopen(list, "w");
    if (!f) return 2;
    for (int i = 0; i < rows; i++)
        if (fprintf(f, "unit%d.c%s", i, i + 1 == rows ? "" : "\n") < 0) {
            fclose(f); return 2;
        }
    if (fclose(f) != 0 || wcs_copy(g_wcs_out, sizeof g_wcs_out, out)) return 2;
    int started = 0;
    if (wcs_worker_run(list, limit, &started) != 0) return 1;
    if (sh_worker_results(out, rows) != 0) return 1;
    return started == (rows < limit ? rows : limit) ? 0 : 1;
}

int wcs_worker_cap_test(const char *base)
{
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
        if (wcs_copy(g_wcs_cc, sizeof g_wcs_cc, "/bin/true")) _exit(2);
        g_wcs_nflag = 0;
        int rc = sh_worker_case(base, 1, 3) || sh_worker_case(base, 2, 3) ||
                 sh_worker_case(base, 5, 3);
        _exit(rc ? 1 : 0);
    }
    int status;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return sh_fail("worker cap or per-row result");
    return 0;
}

/* Observe the actual persisted plan and its cache-disabled miss-list copy. */
static int sh_plan_read(const char *path, const char *const *expected, int n)
{
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char line[WCS_PATH + 2];
    int ok = 1;
    for (int i = 0; i < n; i++) {
        if (!fgets(line, sizeof line, f)) { ok = 0; break; }
        size_t len = strlen(line);
        if (!len || line[len - 1] != '\n') { ok = 0; break; }
        line[len - 1] = 0;
        if (strcmp(line, expected[i]) != 0) { ok = 0; break; }
    }
    if (fgetc(f) != EOF || ferror(f)) ok = 0;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : 1;
}

static int sh_plan_setup(char paths[5][WCS_PATH], const char *base)
{
    static const char *const names[] = {"a.c", "b.c", "c.c", "d.c", "missing.c"};
    static const char *const data[] = {"a", "bbb", "ccc", "ddddddd"};
    for (int i = 0; i < 5; i++) {
        shp(paths[i], WCS_PATH, "%s/%s", base, names[i]);
        if (i < 4 && csr_write(paths[i], data[i]) != 0) return 2;
    }
    return 0;
}

static int sh_plan_cache(const char *base, const char *plan, const char *miss,
                         const char *const *expected)
{
    return setenv("ZCL_LINT_TU_CACHE", "0", 1) != 0 ||
           wcs_cache_setup("test", "", "", "", base, ".", NULL) ||
           wcs_cache_plan(plan, miss, base, 0) || sh_plan_read(miss, expected, 4);
}

static int sh_plan_fallback(char paths[5][WCS_PATH], const char *plan)
{
    const char *const expected[] = {paths[3], paths[4]};
    g_wcs_nsrc = 2;
    if (wcs_copy(g_wcs_src[0], WCS_PATH, paths[4]) ||
        wcs_copy(g_wcs_src[1], WCS_PATH, paths[3]) ||
        wcs_finish_src_list(plan)) return 1;
    if (sh_plan_read(plan, expected, 2)) return 1;
    return strcmp(g_wcs_src[0], expected[0]) || strcmp(g_wcs_src[1], expected[1]);
}

static int sh_plan_order(const char *base)
{
    char p[5][WCS_PATH], plan[SH_P], miss[SH_P];
    if (sh_plan_setup(p, base)) return 2;
    shp(plan, sizeof plan, "%s/ordered-srcs", base);
    shp(miss, sizeof miss, "%s/ordered-misses", base);
    const char *const input[] = {p[0], p[3], p[2], p[1], p[0]};
    const char *const expected[] = {p[3], p[1], p[2], p[0]};
    g_wcs_nsrc = 5;
    for (int i = 0; i < 5; i++)
        if (wcs_copy(g_wcs_src[i], WCS_PATH, input[i])) return 2;
    if (wcs_finish_src_list(plan) || g_wcs_nsrc != 4 ||
        sh_plan_read(plan, expected, 4)) return 1;
    for (int i = 0; i < 4; i++)
        if (strcmp(g_wcs_src[i], expected[i]) != 0) return 1;
    if (sh_plan_cache(base, plan, miss, expected)) return 1;
    return sh_plan_fallback(p, plan);
}

int wcs_plan_order_test(const char *base)
{
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) _exit(sh_plan_order(base));
    int status;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return sh_fail("persisted source plan order");
    return 0;
}

int wcs_inc_scope_fixture(void)
{
    return mkdir(".cache", 0700) == 0 &&
           mkdir(".cache/fixture", 0700) == 0 &&
           mkdir(".cache/fixture/include", 0700) == 0 &&
           mkdir("project", 0700) == 0 &&
           mkdir("project/include", 0700) == 0 &&
           mkdir("project/.cache", 0700) == 0 &&
           mkdir("project/.cache/include", 0700) == 0;
}

static int sh_dirent_probes;
static int sh_dirent_lstat(const char *path, struct stat *st)
{
    sh_dirent_probes++;
    return lstat(path, st);
}

#if defined(_DIRENT_HAVE_D_TYPE) && defined(DT_UNKNOWN) && defined(DT_DIR) && defined(DT_REG) && defined(DT_LNK)
static int sh_dirent_known(const char *dir, const char *file, const char *link,
                           struct dirent *de)
{
    de->d_type = DT_REG;
    if (wcs_inc_entry_dir(file, de, sh_dirent_lstat) || sh_dirent_probes) return 1;
    de->d_type = DT_DIR;
    if (!wcs_inc_entry_dir(dir, de, sh_dirent_lstat) || sh_dirent_probes) return 1;
    de->d_type = DT_LNK;
    if (wcs_inc_entry_dir(link, de, sh_dirent_lstat) || sh_dirent_probes) return 1;
    de->d_type = DT_UNKNOWN;
    return 0;
}
#endif

int wcs_inc_dirent_test(const char *base)
{
    char dir[SH_P], file[SH_P], link[SH_P];
    shp(dir, sizeof dir, "%s/project", base);
    shp(file, sizeof file, "%s/dirent-file", base);
    shp(link, sizeof link, "%s/dirent-link", base);
    if (csr_write(file, "x") != 0 || symlink("project", link) != 0) return 2;
    struct dirent de = {0};
    sh_dirent_probes = 0;
#if defined(_DIRENT_HAVE_D_TYPE) && defined(DT_UNKNOWN) && defined(DT_DIR) && defined(DT_REG) && defined(DT_LNK)
    if (sh_dirent_known(dir, file, link, &de))
        return sh_fail("dirent hint classification or redundant stat");
#endif
    if (!wcs_inc_entry_dir(dir, &de, sh_dirent_lstat) || sh_dirent_probes != 1 ||
        wcs_inc_entry_dir(file, &de, sh_dirent_lstat) || sh_dirent_probes != 2 ||
        wcs_inc_entry_dir(link, &de, sh_dirent_lstat) || sh_dirent_probes != 3)
        return sh_fail("dirent unknown fallback");
    return 0;
}

/* Created in ascending order: tmpfs then enumerates them newest first. */
static const char *const sh_order_dirs[] = { "alpha", "beta", "delta",
    "gamma", "kappa", "omega", "sigma", "zeta", NULL };
enum { SH_ORDER_N = 8 };

static int sh_order_tree(void)
{
    static const char *const roots[] = { "r1", "r2" };
    char p[SH_P];
    for (int i = 0; i < SH_ORDER_N; i++) {
        shp(p, sizeof p, "ord/%s/include", sh_order_dirs[i]);
        if (csr_mkdirs(p) != 0) return 2;
        for (int r = 0; r < 2; r++) {
            shp(p, sizeof p, "%s/%s/src", roots[r], sh_order_dirs[i]);
            if (csr_mkdirs(p) != 0) return 2;
            shp(p, sizeof p, "%s/%s/src/h.h", roots[r], sh_order_dirs[i]);
            if (csr_write(p, "#define H 1\n") != 0) return 2;
        }
    }
    return 0;
}

static bool sh_ascending(int from, int to, const char *prefix)
{
    for (int i = from; i < to; i++)
        if (strncmp(g_wcs_flag[i], prefix, strlen(prefix)) != 0 ||
            (i > from && strcmp(g_wcs_flag[i - 1], g_wcs_flag[i]) >= 0))
            return false;
    return true;
}

/* Each walk's flags are bytewise ascending; an earlier flag and the order of
 * walk roots (r2 before r1 here) are kept. */
static int sh_order_check(void)
{
    int before = g_wcs_nflag;
    if (before >= WCS_FLAGS - 3 * SH_ORDER_N) return 2;
    snprintf(g_wcs_flag[g_wcs_nflag++], WCS_FLAGLEN, "-Izz-earlier");
    int walk = g_wcs_nflag;
    if (wcs_inc_walk(".") != 0) return 2;
    int mid = g_wcs_nflag;
    if (wcs_src_walk("r2") != 0 || wcs_src_walk("r1") != 0) return 2;
    bool ok = strcmp(g_wcs_flag[before], "-Izz-earlier") == 0 &&
              mid - walk == SH_ORDER_N && g_wcs_nflag - mid == 2 * SH_ORDER_N &&
              sh_ascending(walk, mid, "-I./ord/") &&
              sh_ascending(mid, mid + SH_ORDER_N, "-Ir2/") &&
              sh_ascending(mid + SH_ORDER_N, g_wcs_nflag, "-Ir1/");
    return ok ? 0 : sh_fail("walked include flags follow directory enumeration order");
}

int wcs_inc_order_test(const char *base)
{
    char root[SH_P];
    shp(root, sizeof root, "%s/inc-order", base);
    int old = open(".", O_RDONLY | O_CLOEXEC), before = g_wcs_nflag;
    if (old < 0) return 2;
    int rc = csr_mkdirs(root) == 0 && chdir(root) == 0 ? sh_order_tree() : 2;
    if (rc == 0) rc = sh_order_check();
    g_wcs_nflag = before;
    if (fchdir(old) != 0 && rc == 0) rc = 2;
    close(old);
    rap_rm_rf(root);
    return rc;
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

static int sh_active_child(const struct sh_env *e, const char *stub, const char *flags,
                           int ready, int resume)
{
    int h, m, s;
    char miss[SH_P], out[SH_P], token = 'x';
    if (sh_run(e, 0, stub, stub, flags, &h, &m, &s) != 0 ||
        shp_(miss, sizeof miss, "%s/active-miss", e->work[0]) ||
        shp_(out, sizeof out, "%s/out", e->work[0]) || write(ready, &token, 1) != 1 ||
        read(resume, &token, 1) != 1) return 2;
    if (wcs_cache_plan(e->list[0], miss, out, 1) != 0) return 2;
    struct stat st;
    return stat(miss, &st) == 0 && st.st_size == 0 ? 0 : 1;
}

static int sh_active_peer(struct sh_env *e, const char *stub, const char *flags)
{
    char path[SH_P];
    if (chdir(e->tree[0]) != 0 ||
        wcs_cache_setup("tu-cache-shared-selftest", stub, stub, flags,
                        e->work[1], ".", NULL) != 0 || !wcs_cache_on()) return 2;
    if (shp_(path, sizeof path, "%s/src/shared.h", e->tree[1]) ||
        csr_write(path, "#define SHARED_ST 99\n") != 0) return 2;
    if (chdir(e->tree[1]) != 0 ||
        wcs_cache_setup("tu-cache-shared-selftest", stub, stub, flags,
                        e->work[1], ".", NULL) != 0 || wcs_cache_on()) return 2;
    return 0;
}


static int sh_active_retention(struct sh_env *e, const char *stub, const char *flags)
{
    int ready[2], resume[2], status;
    char token;
    if (pipe(ready) != 0) return 2;
    if (pipe(resume) != 0) { close(ready[0]); close(ready[1]); return 2; }
    pid_t pid = fork();
    if (pid < 0) { close(ready[0]); close(ready[1]); close(resume[0]); close(resume[1]); return 2; }
    if (pid == 0) {
        close(ready[0]); close(resume[1]);
        _exit(sh_active_child(e, stub, flags, ready[1], resume[0]));
    }
    close(ready[1]); close(resume[0]);
    int ready_seen = read(ready[0], &token, 1) == 1;
    int ok = ready_seen;
    if (ok && sh_active_peer(e, stub, flags) != 0) ok = 0;
    if (ready_seen && write(resume[1], "x", 1) != 1) ok = 0;
    close(ready[0]); close(resume[1]);
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) ok = 0;
    if (!ok) return sh_fail("active generation was pruned during a peer sweep");
    return 0;
}


static bool sh_exclusive_misses(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    int n = 0, ch;
    while ((ch = fgetc(f)) != EOF) if (ch == '\n') n++;
    int failed = ferror(f);
    if (fclose(f) != 0) failed = 1;
    return !failed && n == SH_UNITS;
}


static int sh_exclusive_peer(const struct sh_env *e, const char *stub, const char *flags)
{
    char miss[SH_P], out[SH_P], log[SH_P], rc[SH_P];
    if (chdir(e->tree[0]) != 0 ||
        wcs_cache_setup("tu-cache-shared-selftest", stub, stub, flags,
                        e->work[0], ".", NULL) != 0 || wcs_cache_on()) return 2;
    shp(miss, sizeof miss, "%s/exclusive-miss", e->work[0]);
    shp(out, sizeof out, "%s/out", e->work[0]);
    shp(log, sizeof log, "%s/exclusive.log", e->work[0]);
    shp(rc, sizeof rc, "%s/exclusive.rc", e->work[0]);
    if (wcs_cache_plan(e->list[0], miss, out, 1) != 0) return 2;
    if (!sh_exclusive_misses(miss)) return 2;
    char *const args[] = {(char *)stub, (char *)"-c", (char *)"src/s0.c", NULL};
    if (wcs_cache_compile(log, rc, stub, args, "src/s0.c") != 0) return 2;
    FILE *f = fopen(rc, "r");
    if (!f) return 2;
    int status = -1, ok = fscanf(f, "%d", &status) == 1 && status == 0;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : 2;
}

static int sh_exclusive_wait(pid_t pid, int read_fd, int lock_fd)
{
    struct pollfd pfd = {.fd = read_fd, .events = POLLIN};
    int polled = poll(&pfd, 1, 10000);
    char result = 2;
    bool ok = polled == 1 && read(read_fd, &result, 1) == 1 && result == 0;
    if (!ok) (void)kill(pid, SIGKILL);
    close(read_fd);
    int status;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    close(lock_fd);
    if (!ok || got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return sh_fail("exclusive cache lock stalled or prevented uncached compile");
    return 0;
}


static int sh_exclusive_case(const struct sh_env *e, const char *stub, const char *flags)
{
    char lock[SH_P];
    shp(lock, sizeof lock, "%s/.cache/z23/lint-tu/tu-cache-shared-selftest/.generation.lock", e->home);
    wcs_cache_release();
    int fd = open(lock, O_RDWR | O_CLOEXEC);
    if (fd < 0) return 2;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) { close(fd); return 2; }
    int done[2];
    if (pipe(done) != 0) { close(fd); return 2; }
    pid_t pid = fork();
    if (pid < 0) { close(done[0]); close(done[1]); close(fd); return 2; }
    if (pid == 0) {
        close(done[0]); close(fd);
        char result = (char)sh_exclusive_peer(e, stub, flags);
        int sent = write(done[1], &result, 1) == 1;
        close(done[1]);
        _exit(sent ? 0 : 2);
    }
    close(done[1]);
    return sh_exclusive_wait(pid, done[0], fd);
}


static int sh_retention(struct sh_env *e, const char *stub, const char *flags)
{
    const char *value = getenv("ZCL_LINT_TU_CACHE_GENERATIONS");
    char *saved = value ? strdup(value) : NULL;
    if (value && !saved) return 2;
    int rc = setenv("ZCL_LINT_TU_CACHE_GENERATIONS", "1", 1) == 0 ?
        sh_active_retention(e, stub, flags) : 2;
    if (rc == 0) rc = sh_retention_case(e, stub, flags);
    if (rc == 0) rc = sh_exclusive_case(e, stub, flags);
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

/* The same include roots, created in opposite orders in the two trees. */
static int sh_order_includes(const char *tree, bool reverse)
{
    char p[SH_P];
    for (int k = 0; k < SH_ORDER_N; k++) {
        shp(p, sizeof p, "%s/%s/include", tree,
            sh_order_dirs[reverse ? SH_ORDER_N - 1 - k : k]);
        if (csr_mkdirs(p) != 0) return 2;
    }
    shp(p, sizeof p, "%s/zeta/include/pick.h", tree);
    return csr_write(p, "#define PICK 1\n") == 0 ? 0 : 2;
}

/* Derive tree i's include flags as the gate does (cwd = tree), then sweep. */
static int sh_order_run(const struct sh_env *e, int i, const char *stub,
                        int *h, int *m, int *s)
{
    char flags[SH_P];
    shp(flags, sizeof flags, "%s/flags.nul", e->work[i]);
    if (chdir(e->tree[i]) != 0) return 2;
    int before = g_wcs_nflag, rc = wcs_inc_walk(".") == 0 ? 0 : 2;
    FILE *f = rc == 0 ? fopen(flags, "wb") : NULL;
    if (rc == 0 && !f) rc = 2;
    for (int k = before; rc == 0 && k < g_wcs_nflag; k++)
        if (fprintf(f, "%s%c", g_wcs_flag[k], '\0') < 0) rc = 2;
    if (f && fclose(f) != 0) rc = 2;
    g_wcs_nflag = before;
    return rc ? rc : sh_sweep(e->work[i], e->list[i], stub, stub, flags, h, m, s);
}

/* Enumeration order must not split the store; header edits and a new
 * header that shadows a later include root must still miss every TU. */
static int sh_order_cases(const struct sh_env *e, const char *stub)
{
    static const struct { int tree; const char *file, *text, *what; int hit; } step[] = {
        { 0, NULL, NULL, "a cold run over walked include roots", 0 },
        { 1, NULL, NULL, "the same include roots created in the opposite order", 1 },
        { 1, "zeta/include/pick.h", "#define PICK 2\n", "an edited header under a walked include root", 0 },
        { 1, "alpha/include/pick.h", "#define PICK 3\n", "a shadowing header in an earlier include root", 0 },
    };
    int h, m, s, rc;
    char p[SH_P];
    for (size_t i = 0; i < sizeof step / sizeof step[0]; i++) {
        if (step[i].file) {
            shp(p, sizeof p, "%s/%s", e->tree[step[i].tree], step[i].file);
            if (csr_write(p, step[i].text) != 0) return 2;
        }
        if ((rc = sh_order_run(e, step[i].tree, stub, &h, &m, &s)) != 0) return rc;
        int eh = step[i].hit ? SH_UNITS : 0, em = SH_UNITS - eh;
        if ((rc = sh_expect(step[i].what, h, m, s, eh, em, em)) != 0) return rc;
    }
    return 0;
}

static int sh_order_store(const char *sbase, const char *stub)
{
    struct sh_env e;
    char obase[SH_P];
    shp(obase, sizeof obase, "%s/order", sbase);
    if (sh_paths(obase, &e) != 0 || setenv("HOME", e.home, 1) != 0 ||
        sh_order_includes(e.tree[0], false) != 0 ||
        sh_order_includes(e.tree[1], true) != 0)
        return 2;
    return sh_order_cases(&e, stub);
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
    if (rc == 0) rc = sh_order_store(sbase, stub);
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
