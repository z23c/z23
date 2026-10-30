/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-windows-cross-syntax — syntax-only mingw sweep of
 * every translation unit the release node binary compiles (NODE_C23_SRCS
 * via `make print-node-c23-srcs`). Ported from
 * tools/lint/check_windows_cross_syntax.sh (deleted). Selftest:
 * gate_windows_cross_syntax_selftest.c. Per-TU result cache:
 * gate_windows_cross_syntax_cache.c.
 *
 * SKIP contract: mingw absent prints SKIP and exits 0 (SKIP is not a
 * pass) unless ZCL_REQUIRE_MINGW=1, which is a hard exit 2. Fail closed
 * everywhere else: missing baseline, hollow scan, or compiler
 * infrastructure failure is never a clean verdict.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_windows_cross_syntax_priv.h"

const char k_wcs_gate[] = "check-windows-cross-syntax";
const char k_wcs_baseline[] =
    "tools/lint/windows_cross_syntax_baseline.txt";
static const char *const k_wcs_scan_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools/command",
    "apps/skycombat", NULL,
};

char g_wcs_work[WCS_PATH];
char g_wcs_out[WCS_PATH];
char g_wcs_cc[WCS_PATH];
char g_wcs_flag[WCS_FLAGS][WCS_FLAGLEN];
int g_wcs_nflag;
char g_wcs_src[WCS_TUS][WCS_PATH];
int g_wcs_nsrc;

/* ── subprocess helpers ─────────────────────────────────────────────── */

static int devnull_fd(void)
{
    return open("/dev/null", O_WRONLY);
}

int wcs_run_capture(const char *out_path, const char *err_path,
                    char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return 127;
    if (pid == 0) {
        int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) _exit(126);
        dup2(fd, 1);
        if (err_path && strcmp(err_path, out_path) == 0) dup2(fd, 2);
        else {
            int e = err_path ? open(err_path, O_WRONLY | O_CREAT | O_TRUNC, 0644)
                             : devnull_fd();
            if (e < 0) _exit(126);
            dup2(e, 2);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int st;
    pid_t w;
    do { w = waitpid(pid, &st, 0); } while (w < 0 && errno == EINTR);
    if (w < 0) return 127;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 127;
}

int wcs_run_status(char *const argv[])
{
    return wcs_run_capture("/dev/null", "/dev/null", argv);
}

/* 1 when name is executable on PATH, 0 when it is absent, -1 when a PATH
 * entry is too long to probe: an error, never a quiet absence. */
int wcs_have_cmd(const char *name)
{
    if (strchr(name, '/')) return access(name, X_OK) == 0;
    const char *path = getenv("PATH");
    if (!path) return 0;
    static char buf[WCS_PATH];
    const char *p = path;
    while (*p) {
        const char *e = strchr(p, ':');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == 0) { p = e ? e + 1 : p + l; continue; }
        if (l + strlen(name) + 2 > sizeof buf) {
            fprintf(stderr, "%s: PATH entry exceeds %d bytes; cannot "
                    "probe for '%s'\n", k_wcs_gate, WCS_PATH, name);
            return -1;
        }
        memcpy(buf, p, l);
        buf[l] = '/';
        strcpy(buf + l + 1, name);
        if (access(buf, X_OK) == 0) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

/* ── classifier (port of classify.awk + compile_result_kind) ────────── */

static int lc_contains(const char *lower, const char *needle)
{
    return strstr(lower, needle) != NULL;
}

static int driver_phrase(const char *lower)
{
    static const char *const ph[] = {
        "internal compiler error", "cannot execute", "createprocess",
        "unable to execute command", "frontend command failed",
        "please submit a bug report", "segmentation fault", "stack dump",
        "out of memory", "killed signal", "error in backend", "llvm error",
        "access violation", "cc1.exe:", NULL,
    };
    for (int i = 0; ph[i]; i++)
        if (lc_contains(lower, ph[i])) return 1;
    return 0;
}

/* classify.awk: prefix !~ /:[0-9]+(:[0-9]+)?$/ . Any ":digits" tail already
 * satisfies it (the optional second group only widens the same tail), so a
 * single trailing-digits check is the whole regex. */
static int ends_with_location(const char *prefix, size_t n)
{
    size_t i = n;
    while (i > 0 && isdigit((unsigned char)prefix[i - 1])) i--;
    return i < n && i > 0 && prefix[i - 1] == ':';
}

/* 1 generated-command header, 2 openssl header, 0 anything else */
static int missing_header_kind(const char *line)
{
    const char *fat = strstr(line, "fatal error: ");
    if (!fat) return 0;
    const char *rest = fat + 13;
    const char *ns = strstr(rest, ": No such file or directory");
    if (!ns) return 0;
    size_t hl = (size_t)(ns - rest);
    char hdr[WCS_LINE];
    if (hl >= sizeof hdr) return 0;
    memcpy(hdr, rest, hl);
    hdr[hl] = '\0';
    if (strcmp(hdr, "command/native_command.h") == 0 ||
        strcmp(hdr, "command/native_dev_hotswap.h") == 0)
        return 1;
    return strncmp(hdr, "openssl/", 8) == 0 ? 2 : 0;
}

/* Bounded copy: 0 when src fits with its NUL, -1 otherwise (never truncates). */
int wcs_copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static int classify_line(const char *line, int *errors, int *gen,
                         int *ossl, int *other, int *driver)
{
    char lower[WCS_LINE];
    if (wcs_copy(lower, sizeof lower, line)) return -1;
    for (char *c = lower; *c; c++) *c = (char)tolower((unsigned char)*c);
    if (driver_phrase(lower)) (*driver)++;
    int fat = strstr(line, ": fatal error: ") != NULL;
    if (!fat && !strstr(line, ": error: ")) return 0;
    (*errors)++;
    const char *marker = fat ? ": fatal error: " : ": error: ";
    size_t prefix_len = (size_t)(strstr(line, marker) - line);
    if (*driver > 0 || !ends_with_location(line, prefix_len)) {
        (*driver)++;
        return 0;
    }
    int mk = fat ? missing_header_kind(line) : 0;
    if (mk == 1) (*gen)++;
    else if (mk == 2) (*ossl)++;
    else (*other)++;
    return 0;
}

static int classify_log(const char *log, char *kind, size_t cap)
{
    int errors = 0, gen = 0, ossl = 0, other = 0, driver = 0;
    FILE *f = fopen(log, "r");
    static char line[WCS_LINE];
    int bad = 0;
    if (f) {
        while (!bad && fgets(line, sizeof line, f))
            bad = classify_line(line, &errors, &gen, &ossl, &other,
                                &driver) != 0;
        fclose(f);
    }
    if (bad) return -1;
    if (driver > 0) return wcs_copy(kind, cap, "COMPILER_FAILURE");
    if (errors == 0) return wcs_copy(kind, cap, "CLEAN");
    if (other > 0) return wcs_copy(kind, cap, "ERROR");
    if (gen == errors) return wcs_copy(kind, cap, "SKIP_GENERATED");
    if (ossl == errors) return wcs_copy(kind, cap, "SKIP_OPENSSL");
    return wcs_copy(kind, cap, "SKIP_HEADERS");
}

/* 0 on success; -1 when a kind does not fit cap (a caller bug, never silent). */
int wcs_compile_kind(const char *log, const char *rc, char *kind, size_t cap)
{
    if (strcmp(rc, "0") == 0) {
        if (classify_log(log, kind, cap)) return -1;
        if (strcmp(kind, "CLEAN") != 0)
            return wcs_copy(kind, cap, "INCONSISTENT_SUCCESS");
        return 0;
    }
    if (!rc[0]) return wcs_copy(kind, cap, "MISSING_RESULT");
    for (const char *c = rc; *c; c++)
        if (*c < '0' || *c > '9') return wcs_copy(kind, cap, "MISSING_RESULT");
    if (classify_log(log, kind, cap)) return -1;
    if (strcmp(kind, "CLEAN") == 0)
        return wcs_copy(kind, cap, "COMPILER_FAILURE");
    return 0;
}

/* ── Makefile parsing ───────────────────────────────────────────────── */

static int assign_match(const char *line, const char *var, const char **val)
{
    size_t n = strlen(var);
    if (strncmp(line, var, n) != 0) return 0;
    size_t i = n;
    while (line[i] == ' ' || line[i] == '\t') i++;
    if (line[i] == ':') {
        i++;
        while (line[i] == ' ' || line[i] == '\t') i++;
    }
    if (line[i] != '=') return 0;
    *val = line + i + 1;
    return 1;
}

static int strip_line(char *line)
{
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    return (int)n;
}

/* 0 on success. -1 when the input line, a token, or the token table does not
 * fit: each is named on stderr and the gate fails closed (no silent cap). */
static int split_tokens(const char *s, const char *seps, const char *prefix,
                        char out[][WCS_FLAGLEN], int *n, int max)
{
    static char buf[WCS_LINE];
    if (wcs_copy(buf, sizeof buf, s)) {
        fprintf(stderr, "%s: makefile line exceeds %d bytes\n", k_wcs_gate,
                WCS_LINE);
        return -1;
    }
    char *save = NULL;
    for (char *t = strtok_r(buf, seps, &save); t;
         t = strtok_r(NULL, seps, &save)) {
        if (!t[0]) continue;
        if (prefix && strncmp(t, prefix, strlen(prefix)) != 0) continue;
        if (*n >= max) {
            fprintf(stderr, "%s: makefile flag table exceeds %d\n", k_wcs_gate,
                    max);
            return -1;
        }
        if (wcs_copy(out[*n], WCS_FLAGLEN, t)) {
            fprintf(stderr, "%s: makefile flag exceeds %d bytes\n", k_wcs_gate,
                    WCS_FLAGLEN);
            return -1;
        }
        (*n)++;
    }
    return 0;
}

static int floor_from_makefile(char out[WCS_FLAGLEN])
{
    static char toks[8][WCS_FLAGLEN];
    int n = 0;
    FILE *f = fopen("Makefile", "r");
    static char line[WCS_LINE];
    if (!f) return -1;
    while (n == 0 && fgets(line, sizeof line, f)) {
        const char *val = NULL;
        if (!assign_match(line, "ZCL_WINDOWS_API_FLOOR", &val)) continue;
        if (split_tokens(val, " \t", "-D_WIN32_WINNT=", toks, &n, 8)) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    if (n != 1) return -1;
    strcpy(out, toks[0]);
    return 0;
}

static int platform_flags(char block[WCS_LINE], char out[][WCS_FLAGLEN],
                          int *n)
{
    FILE *f = fopen("Makefile", "r");
    static char line[WCS_LINE], acc[WCS_LINE];
    if (!f) return -1;
    size_t alen = 0;
    acc[0] = '\0';
    int inblock = 0, done = 0;
    while (!done && fgets(line, sizeof line, f)) {
        size_t l = (size_t)strip_line(line);
        if (!inblock) {
            const char *val = NULL;
            if (line[0] == 'Z' &&
                assign_match(line, "ZCL_PLATFORM_CPPFLAGS", &val)) {
                inblock = 1;
            } else continue;
        }
        if (alen + l + 2 > sizeof acc) { fclose(f); return -1; }
        memcpy(acc + alen, line, l);
        alen += l;
        acc[alen++] = ' ';
        acc[alen] = '\0';
        if (l < 1 || line[l - 1] != '\\') done = 1;
    }
    fclose(f);
    if (!inblock) return -1;
    if (!strstr(acc, "ZCL_WINDOWS_API_FLOOR")) return -2;
    strcpy(block, acc);
    *n = 0;
    if (split_tokens(acc, " \t\\", "-D", out, n, 64)) return -4;
    if (*n == 0) return -3;
    return 0;
}

static int test_compat_bound(void)
{
    FILE *f = fopen("Makefile", "r");
    static char line[WCS_LINE];
    if (!f) return -1;
    while (fgets(line, sizeof line, f)) {
        const char *val = NULL;
        if (!assign_match(line, "ZCL_TEST_WINDOWS_COMPAT_FLAGS", &val)) continue;
        fclose(f);
        return strstr(val, "-include test/windows_compat.h") ? 0 : -2;
    }
    fclose(f);
    return -1;
}

/* ── include-path walk ──────────────────────────────────────────────── */

static const char *skip_dot(const char *p)
{
    return (p[0] == '.' && p[1] == '/') ? p + 2 : p;
}

/* 1 when name equals one entry of the NULL-terminated list. */
int wcs_name_in(const char *name, const char *const *list)
{
    for (int i = 0; list[i]; i++)
        if (strcmp(name, list[i]) == 0) return 1;
    return 0;
}

static const char *const inc_pruned[] = { ".git", "build", "test-tmp",
    ".claude", "vendor/tor", "vendor/raylib", NULL };


/* Appends one compiler flag; fails closed when the table or the flag is full. */
static int wcs_flag_add(const char *s)
{
    if (g_wcs_nflag >= WCS_FLAGS) {
        fprintf(stderr, "%s: flag table exceeds %d\n", k_wcs_gate, WCS_FLAGS);
        return 2;
    }
    if (wcs_copy(g_wcs_flag[g_wcs_nflag], WCS_FLAGLEN, s)) {
        fprintf(stderr, "%s: flag exceeds %d bytes\n", k_wcs_gate, WCS_FLAGLEN);
        return 2;
    }
    g_wcs_nflag++;
    return 0;
}

static int inc_add(const char *dir)
{
    char flag[WCS_PATH + 2];
    if (ovf(snprintf(flag, sizeof flag, "-I%s", dir), sizeof flag)) return 2;
    return wcs_flag_add(flag);
}

/* Include roots, as the reference find does: every directory named include
 * under the tree, pruning the top-level build, test-tmp, .git, .claude,
 * vendor/tor and vendor/raylib subtrees. Manual recursion: nftw stops early
 * on FTW_SKIP_SUBTREE in this libc, so a pruned directory ends the walk. */
static int inc_scan(const char *dir, int depth)
{
    if (depth > 64) return 2;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char p[WCS_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, de->d_name), sizeof p)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (lstat(p, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (wcs_name_in(skip_dot(p), inc_pruned)) continue;
        if (!strcmp(de->d_name, "include") && inc_add(p) != 0) {
            rc = 2;
            break;
        }
        rc = inc_scan(p, depth + 1);
    }
    closedir(d);
    return rc;
}

/* 1 when dir holds a non-hidden regular header whose name ends in .h (the
 * script glob, with -f), 0 when not, -1 when a name is too long to test. */
static int dir_has_header(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int has = 0, rc = 0;
    while (!has && rc == 0 && (de = readdir(d)) != NULL) {
        size_t n = strlen(de->d_name);
        if (de->d_name[0] == '.' || n < 3 ||
            strcmp(de->d_name + n - 2, ".h") != 0)
            continue;
        char p[WCS_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, de->d_name), sizeof p)) {
            rc = -1;
            break;
        }
        struct stat st;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) has = 1;
    }
    closedir(d);
    return rc != 0 ? -1 : has;
}

static int src_walk_cb(const char *fpath, const struct stat *st, int type,
                       struct FTW *ftw)
{
    (void)st; (void)ftw;
    if (type != FTW_D) return 0;
    const char *bn = strrchr(fpath, '/');
    bn = bn ? bn + 1 : fpath;
    if (strcmp(bn, "src") != 0) return 0;
    int h = dir_has_header(fpath);
    if (h < 0) return 1;
    if (h && inc_add(fpath) != 0) return 1;
    return 0;
}

static int add_root(char roots[][WCS_PATH], int *nr, const char *p)
{
    if (*nr >= 16 || wcs_copy(roots[*nr], WCS_PATH, p)) {
        fprintf(stderr, "%s: scan root table exceeds 16\n", k_wcs_gate);
        return 2;
    }
    (*nr)++;
    return 0;
}

static int build_include_flags(void)
{
    if (inc_add(".") != 0) return 2;
    if (inc_add("tools") != 0 || inc_add("tools/dev") != 0 ||
        inc_add("tools/mind") != 0)
        return 2;
    if (inc_scan(".", 0) != 0) return 2;
    /* other walk errors: a walk that found too little is caught by the floor */
    static char roots[16][WCS_PATH];
    int nr = 0;
    for (int i = 0; k_wcs_scan_roots[i]; i++)
        if (lintc_is_dir(k_wcs_scan_roots[i]) &&
            add_root(roots, &nr, k_wcs_scan_roots[i]))
            return 2;
    if (add_root(roots, &nr, "tools")) return 2;
    for (int i = 0; i < nr; i++)
        if (nftw(roots[i], src_walk_cb, 16, FTW_PHYS) == 1) return 2;
    return 0;
}

/* ── source list ────────────────────────────────────────────────────── */

static int src_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void show_make_failure(const char *errp)
{
    fprintf(stderr, "%s: FATAL — 'make -s ZCL_TARGET=windows-x86_64 "
            "print-node-c23-srcs' failed:\n", k_wcs_gate);
    FILE *f = fopen(errp, "r");
    static char line[WCS_LINE];
    if (!f) return;
    while (fgets(line, sizeof line, f))
        fprintf(stderr, "  %s", line);
    fclose(f);
}

static int read_src_raw(const char *raw)
{
    FILE *in = fopen(raw, "r");
    if (!in) return 2;
    static char line[WCS_PATH];
    while (g_wcs_nsrc < WCS_TUS && fgets(line, sizeof line, in)) {
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n') line[--l] = '\0';
        if (l < 3 || strcmp(line + l - 2, ".c") != 0) continue;
        memcpy(g_wcs_src[g_wcs_nsrc], line, l + 1);
        g_wcs_nsrc++;
    }
    fclose(in);
    if (g_wcs_nsrc >= WCS_TUS) {
        fprintf(stderr, "%s: translation units exceed %d\n", k_wcs_gate,
                WCS_TUS);
        return 2;
    }
    return 0;
}

static int dedupe_srcs(void)
{
    qsort(g_wcs_src, (size_t)g_wcs_nsrc, WCS_PATH, src_cmp);
    int n = 0;
    for (int i = 0; i < g_wcs_nsrc; i++) {
        if (n > 0 && strcmp(g_wcs_src[n - 1], g_wcs_src[i]) == 0) continue;
        if (n != i) memcpy(g_wcs_src[n], g_wcs_src[i], WCS_PATH);
        n++;
    }
    g_wcs_nsrc = n;
    return n;
}

static int get_src_list(void)
{
    char raw[WCS_PATH], errp[WCS_PATH], srclist[WCS_PATH];
    if (ovf(snprintf(raw, sizeof raw, "%s/srcs.raw", g_wcs_work), sizeof raw) ||
        ovf(snprintf(errp, sizeof errp, "%s/print-node-c23-srcs.err",
                     g_wcs_work), sizeof errp) ||
        ovf(snprintf(srclist, sizeof srclist, "%s/srcs.txt", g_wcs_work),
            sizeof srclist))
        return 2;
    char *mk[5] = { (char *)"make", (char *)"-s",
                    (char *)"ZCL_TARGET=windows-x86_64",
                    (char *)"print-node-c23-srcs", NULL };
    if (wcs_run_capture(raw, errp, mk) != 0) {
        show_make_failure(errp);
        return 2;
    }
    if (read_src_raw(raw) != 0) return 2;
    int n = dedupe_srcs();
    FILE *o = fopen(srclist, "w");
    if (!o) return 2;
    for (int i = 0; i < n; i++) fprintf(o, "%s\n", g_wcs_src[i]);
    fclose(o);
    return 0;
}

struct size_ent { long long size; char path[WCS_PATH]; };

static int size_cmp(const void *a, const void *b)
{
    const struct size_ent *x = a, *y = b;
    if (x->size != y->size) return x->size > y->size ? -1 : 1;
    return strcmp(x->path, y->path);
}

/* LPT dispatch: largest TU first; fails open (original order) on any
 * stat failure, never drops a file. */
static void sort_by_size(void)
{
    static struct size_ent ents[WCS_TUS];
    static char tmp[WCS_TUS][WCS_PATH];
    for (int i = 0; i < g_wcs_nsrc; i++) {
        struct stat st;
        if (stat(g_wcs_src[i], &st) != 0) return;
        ents[i].size = (long long)st.st_size;
        memcpy(ents[i].path, g_wcs_src[i], WCS_PATH);
    }
    qsort(ents, (size_t)g_wcs_nsrc, sizeof ents[0], size_cmp);
    for (int i = 0; i < g_wcs_nsrc; i++) memcpy(tmp[i], ents[i].path, WCS_PATH);
    for (int i = 0; i < g_wcs_nsrc; i++) memcpy(g_wcs_src[i], tmp[i], WCS_PATH);
}

/* ── setup: everything before the self-test phase ───────────────────── */

/* The Makefile-derived floor, platform flags and test-compat binding, plus
 * the compat header's presence. 0 ok; 1 refusal (already reported); 2 error. */
static int wcs_setup_floor(char api[WCS_FLAGLEN], char block[WCS_LINE],
                           char plat[][WCS_FLAGLEN],
                           int *nplat)
{
    if (floor_from_makefile(api) != 0) {
        fprintf(stderr, "  %s: FAIL — expected exactly one _WIN32_WINNT floor "
                "in the\n      Makefile; refusing to compile against mingw's "
                "default.\n", k_wcs_gate);
        return 1;
    }
    int prc = platform_flags(block, plat, nplat);
    if (prc == -2) {
        fprintf(stderr, "  %s: FAIL — ZCL_PLATFORM_CPPFLAGS does not reference"
                "\n      ZCL_WINDOWS_API_FLOOR; the product and gate can "
                "drift.\n", k_wcs_gate);
        return 1;
    }
    if (prc != 0) {
        fprintf(stderr, "  %s: FAIL — could not read ZCL_PLATFORM_CPPFLAGS "
                "from the\n      Makefile. Refusing to cross-compile at a "
                "guessed API floor.\n", k_wcs_gate);
        return 1;
    }
    if (test_compat_bound() != 0) {
        fprintf(stderr, "  %s: FAIL — could not bind the Windows test "
                "compatibility\n      include to ZCL_TEST_WINDOWS_COMPAT_FLAGS"
                " in Makefile.\n", k_wcs_gate);
        return 1;
    }
    struct stat st;
    if (stat("tests/harness/include/test/windows_compat.h", &st) != 0) {
        fprintf(stderr, "  %s: FAIL — missing tests/harness/include/test/"
                "windows_compat.h.\n", k_wcs_gate);
        return 1;
    }
    return 0;
}

/* The source list and the sweep-size floor. 0 ok; nonzero is the exit code. */
static int wcs_setup_sources(void)
{
    if (get_src_list() != 0) return 2;
    int r = gate_require_scanned(g_wcs_nsrc, 150, k_wcs_gate,
        "'make -s ZCL_TARGET=windows-x86_64 print-node-c23-srcs' printed no "
        "translation units — NODE_C23_SRCS moved or the target broke");
    if (r) return r;
    sort_by_size();
    return 0;
}

static int wcs_setup(void)
{
    static char api[WCS_FLAGLEN], block[WCS_LINE];
    static char plat[64][WCS_FLAGLEN];
    int nplat = 0;
    if (ovf(snprintf(g_wcs_out, sizeof g_wcs_out, "%s/out", g_wcs_work),
            sizeof g_wcs_out))
        return 2;
    int rc = wcs_setup_floor(api, block, plat, &nplat);
    if (rc) return rc;
    if (wcs_flag_add("-std=c2x") || wcs_flag_add("-fsyntax-only") ||
        wcs_flag_add(api))
        return 2;
    for (int i = 0; i < nplat; i++)
        if (wcs_flag_add(plat[i])) return 2;
    if (build_include_flags() != 0) return 2;
    int r = gate_require_scanned(g_wcs_nflag, 50, k_wcs_gate,
        "no include/ roots found — the layout moved or find was pruned too hard");
    if (r) return r;
    r = wcs_setup_sources();
    if (r) return r;
    char flagsnul[WCS_PATH];
    if (ovf(snprintf(flagsnul, sizeof flagsnul, "%s/flags.nul", g_wcs_work),
            sizeof flagsnul))
        return 2;
    FILE *f = fopen(flagsnul, "wb");
    if (!f) return 2;
    for (int i = 0; i < g_wcs_nflag; i++) fprintf(f, "%s%c", g_wcs_flag[i], '\0');
    fclose(f);
    return 0;
}

/* ── top-level flow ─────────────────────────────────────────────────── */

int wcs_selftest_phase(void); /* gate_windows_cross_syntax_selftest.c */

int wcs_begin(int selftest_only)
{
    const char *cc = env_or("ZCL_MINGW_CC", "x86_64-w64-mingw32-gcc");
    if (wcs_copy(g_wcs_cc, sizeof g_wcs_cc, cc)) {
        fprintf(stderr, "%s: compiler name exceeds %d bytes\n", k_wcs_gate,
                WCS_PATH);
        return 2;
    }
    printf("══ LINT: Windows cross-syntax (mingw -fsyntax-only over every "
           "_WIN32 TU) ══\n");
    if (!selftest_only && wcs_have_cmd(g_wcs_cc) < 0) return 2;
    if (!selftest_only && wcs_have_cmd(g_wcs_cc) == 0) {
        if (env_or("ZCL_REQUIRE_MINGW", "0")[0] == '1') {
            fprintf(stderr, "  %s: FAIL — required compiler '%s' is "
                    "unavailable;\n  acceptance cannot succeed after "
                    "compiling zero files.\n", k_wcs_gate, g_wcs_cc);
            return 2;
        }
        printf("  %s: SKIP — '%s' is not installed on this box.\n"
               "  0 files were compiled. This is not a pass: it is an "
               "unobserved\n  leg. Install mingw-w64 (apt install "
               "gcc-mingw-w64-x86-64) or set\n  ZCL_MINGW_CC=<path> to "
               "actually run this gate.\n", k_wcs_gate, g_wcs_cc);
        return 0;
    }
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(g_wcs_work, sizeof g_wcs_work,
                     "%s/zcl-wincross-syntax.XXXXXX", td), sizeof g_wcs_work)) {
        fprintf(stderr, "%s: work path exceeds %d\n", k_wcs_gate, WCS_PATH);
        return 2;
    }
    if (!mkdtemp(g_wcs_work)) {
        fprintf(stderr, "%s: FATAL — mktemp failed.\n", k_wcs_gate);
        return 2;
    }
    int rc = wcs_setup();
    if (rc == 0) rc = wcs_selftest_phase();
    if (selftest_only || rc != 0) {
        rap_rm_rf(g_wcs_work);
        return rc;
    }
    rc = wcs_sweep();
    rap_rm_rf(g_wcs_work);
    return rc;
}

int check_windows_cross_syntax_run(int argc, char **argv)
{
    if (argc >= 1 && argv[0] && strcmp(argv[0], "--self-test") == 0)
        return wcs_begin(1);
    return wcs_begin(0);
}
