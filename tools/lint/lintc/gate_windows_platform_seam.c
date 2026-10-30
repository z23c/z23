/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-windows-platform-seam — Windows CROSS-COMPILE check
 * of the platform seam (platform/modules/platform/src). Ported from
 * tools/lint/check_windows_platform_seam.sh (deleted). Runs
 * x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only over every seam .c file
 * minus the files the Makefile's own non-Linux LIB_SRCS filter drops, and
 * ratchets the realized diagnostic sites against
 * tools/lint/windows_platform_seam_baseline.txt. The Windows API floor
 * defines are parsed from the Makefile, never guessed. Absent compiler is
 * UNOBSERVED (exit 0, never printed as a pass) unless ZCL_REQUIRE_MINGW=1.
 * Selftest: gate_windows_platform_seam_selftest.c drives wps_check_root
 * over a fixture tree; the shell --self-test compiler probes are kept in
 * the WPS_SELFTEST mode of run().
 *
 * Exit codes: 0 pass or UNOBSERVED, 1 new diagnostic site or refuse-to-
 * grade condition, 2 usage or internal error (missing baseline, hollow
 * scan, overflow).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

#define WPS_GATE "check-windows-platform-seam"
#define WPS_SEAM "platform/modules/platform/src"
#define WPS_BASE "tools/lint/windows_platform_seam_baseline.txt"
#define WPS_CC_DEF "x86_64-w64-mingw32-gcc"
#define WPS_DIAG_RE \
    "^[A-Za-z0-9_./-]+\\.[ch]:[0-9]+:[0-9]+: (fatal error|error|warning): .*$"

enum {
    WPS_FLAGS = 64, WPS_FLAG = 128,
    WPS_INCS = 128, WPS_INC = 512, WPS_INCARG = 520,
    WPS_EXEMPT = 32, WPS_EX = 300,
    WPS_SRCS = 64, WPS_SRC = 300,
    WPS_SITES = 1024, WPS_SITE = 512,
    WPS_BASES = 256, WPS_BPATH = 300,
    WPS_ROWS = 64, WPS_ROW = 384,
    WPS_PATH = 1024, WPS_LINE = 4096, WPS_TEXT = 32768,
    WPS_OUTBUF = 65536, WPS_ARGV = 256,
    WPS_SRC_FLOOR = 8, WPS_INC_FLOOR = 15, WPS_DEPTH = 4,
};

/* Modes; the selftest file mirrors these values. */
enum { WPS_SCAN = 0, WPS_MODE_SITES = 1, WPS_UPDATE = 2, WPS_SELFTEST = 3 };

struct wps_env {
    char cc[128];
    char flags[WPS_FLAGS][WPS_FLAG];
    int nflags;
    char incs[WPS_INCS][WPS_INC];
    char incargs[WPS_INCS][WPS_INCARG];
    int nincs;
    char exempt[WPS_EXEMPT][WPS_EX];
    int nexempt;
    char srcs[WPS_SRCS][WPS_SRC];
    int nsrcs;
    char sites[WPS_SITES][WPS_SITE];
    int nsites;
    int counts[WPS_SRCS];
};

struct wps_base {
    char path[WPS_BASES][WPS_BPATH];
    int allowed[WPS_BASES];
    int n;
};

int wps_check_root(const char *root, FILE *out, FILE *err, int mode);

/* ── small shared helpers ─────────────────────────────────────────── */

/* Loud limit failure: one stderr line naming the gate and the limit,
 * then the internal-error exit code 2. */
static int wps_fail(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: FAIL (", WPS_GATE);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs(")\n", stderr);
    return 2;
}

static int wps_pathov(void)
{
    return wps_fail("path over %d bytes", WPS_PATH);
}

/* A wps_getline failure: 3 = line over WPS_LINE, else a read error. */
static int wps_lineerr(int g, const char *what)
{
    if (g == 3)
        return wps_fail("%s line over %d bytes", what, WPS_LINE);
    return wps_fail("read error on %s", what);
}

static int wps_app(char *dst, size_t cap, size_t *len, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (*len >= cap - 1)
        return wps_fail("text buffer over %zu bytes", cap);
    va_start(ap, fmt);
    n = vsnprintf(dst + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (ovf(n, cap - *len))
        return wps_fail("text buffer over %zu bytes", cap);
    *len += (size_t)n;
    return 0;
}

static int wps_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Reads one chomped line. 0 = line, 1 = EOF, 3 = line exceeds cap. */
static int wps_getline(FILE *f, char *buf, size_t cap)
{
    size_t n;
    if (!fgets(buf, (int)cap, f))
        return feof(f) ? 1 : 2;
    n = strlen(buf);
    if (n == cap - 1 && buf[n - 1] != '\n')
        return 3;
    if (n && buf[n - 1] == '\n')
        buf[n - 1] = '\0';
    return 0;
}

/* True when line opens a make assignment of name ("NAME ws* ':'? '='). */
static int wps_assign_start(const char *s, const char *name)
{
    size_t n = strlen(name), i = n;
    if (strncmp(s, name, n) != 0)
        return 0;
    while (s[i] == ' ' || s[i] == '\t')
        i++;
    if (s[i] == ':')
        i++;
    return s[i] == '=';
}

/* ── process spawning (fork + execvp, argv array, never a shell) ──── */

static void wps_child(char *const argv[], int devnull, int outfd, int execfd)
{
    int dn = devnull ? open("/dev/null", O_RDWR) : outfd;
    ssize_t w;
    int en;
    if (dn < 0)
        _exit(126);
    dup2(dn, 1);
    dup2(dn, 2);
    execvp(argv[0], argv);
    en = errno;
    w = write(execfd, &en, sizeof en);
    (void)w;
    _exit(127);
}

static int wps_read_all(int fd, char *out, size_t cap)
{
    size_t have = 0;
    for (;;) {
        char tmp[4096];
        ssize_t r = read(fd, tmp, sizeof tmp);
        if (r < 0)
            return wps_fail("read error on child output");
        if (r == 0)
            break;
        if (have + (size_t)r >= cap)
            return wps_fail("child output over %zu bytes", cap);
        memcpy(out + have, tmp, (size_t)r);
        have += (size_t)r;
    }
    out[have] = '\0';
    return 0;
}

/* Reads the close-on-exec status pipe: 1 = the child reported an exec
 * failure (an errno arrived), 0 = exec succeeded (EOF), 2 = the read itself
 * failed (named here). */
static int wps_exec_status(int fd)
{
    int en = 0;
    ssize_t r = read(fd, &en, sizeof en);
    if (r < 0)
        return wps_fail("read error on exec status: %s", strerror(errno));
    return r > 0; /* any byte means the child wrote an errno: exec failed */
}

/* Runs argv. 0 = ran (*status set), 1 = exec failed, 2 = internal error
 * (including output larger than cap), already named on stderr. Combined
 * stdout+stderr in out. */
static int wps_spawn(char *const argv[], int devnull, char *out, size_t cap,
                     int *status)
{
    int exep[2], outp[2], xs, rd = 0, st = 0;
    pid_t pid, wr;
    if (pipe(exep) != 0 || pipe(outp) != 0)
        return wps_fail("pipe failed: %s", strerror(errno));
    (void)fcntl(exep[1], F_SETFD, FD_CLOEXEC);
    pid = fork();
    if (pid < 0)
        return wps_fail("fork failed: %s", strerror(errno));
    if (pid == 0) {
        close(exep[0]);
        close(outp[0]);
        wps_child(argv, devnull, outp[1], exep[1]);
    }
    close(exep[1]);
    close(outp[1]);
    /* A failed read still closes the pipe and reaps the child: a writer
     * left with no reader gets SIGPIPE, so waitpid cannot hang. */
    if (!devnull && out)
        rd = wps_read_all(outp[0], out, cap);
    close(outp[0]);
    xs = wps_exec_status(exep[0]);
    close(exep[0]);
    while ((wr = waitpid(pid, &st, 0)) < 0 && errno == EINTR)
        ;
    if (wr < 0)
        return wps_fail("waitpid failed: %s", strerror(errno));
    if (rd)
        return 2; /* wps_read_all already named the failure */
    if (xs)
        return xs;
    if (WIFEXITED(st))
        *status = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        *status = 128 + WTERMSIG(st);
    else
        *status = 1;
    return 0;
}

/* command -v semantics: a name with a slash is a path; otherwise search
 * PATH. 1 = found, 0 = absent, -1 = internal error (path too long). */
static int wps_cc_ok(const char *cc)
{
    const char *p = getenv("PATH");
    char cand[WPS_PATH];
    struct stat st;
    if (strchr(cc, '/'))
        return stat(cc, &st) == 0 && S_ISREG(st.st_mode) &&
               access(cc, X_OK) == 0;
    while (p && *p) {
        const char *c = strchr(p, ':');
        size_t n = c ? (size_t)(c - p) : strlen(p);
        if (ovf(snprintf(cand, sizeof cand, "%.*s/%s", (int)n, n ? p : ".", cc),
                sizeof cand)) {
            wps_fail("PATH candidate over %d bytes", WPS_PATH);
            return -1;
        }
        if (stat(cand, &st) == 0 && S_ISREG(st.st_mode) &&
            access(cand, X_OK) == 0)
            return 1;
        p = c ? c + 1 : NULL;
    }
    return 0;
}

static void wps_cc_ver(const char *cc, char *buf, size_t cap)
{
    static char tmp[WPS_OUTBUF];
    char *av[3];
    char *nl;
    size_t n;
    int st = 0;
    buf[0] = '\0';
    av[0] = (char *)cc;
    av[1] = "--version";
    av[2] = NULL;
    if (wps_spawn(av, 0, tmp, sizeof tmp, &st) != 0)
        return;
    nl = strchr(tmp, '\n');
    n = nl ? (size_t)(nl - tmp) : strlen(tmp);
    if (n >= cap)
        n = cap - 1;
    memcpy(buf, tmp, n);
    buf[n] = '\0';
}

/* ── Makefile parsing: API floor, platform defines, exemptions ────── */

static int wps_winnt_line(const char *line, char *def, size_t cap, int *nhits)
{
    const char *p = line;
    while (*p) {
        const char *e;
        size_t len;
        while (*p == ' ' || *p == '\t')
            p++;
        e = p;
        while (*e && *e != ' ' && *e != '\t')
            e++;
        if (e > p && strncmp(p, "-D_WIN32_WINNT=", 15) == 0) {
            (*nhits)++;
            len = (size_t)(e - p);
            if (len >= cap)
                return wps_fail("_WIN32_WINNT token over %d bytes", (int)cap);
            memcpy(def, p, len);
            def[len] = '\0';
        }
        p = *e ? e + 1 : e;
    }
    return 0;
}

static int wps_winnt(const char *root, char *def, size_t cap)
{
    char path[WPS_PATH], line[WPS_LINE];
    FILE *f;
    int nhits = 0, rc = 0;
    def[0] = '\0';
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return wps_pathov();
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: cannot open %s\n", WPS_GATE, path);
        return 1;
    }
    for (;;) {
        int g = wps_getline(f, line, sizeof line);
        if (g == 1)
            break;
        if (g) {
            rc = wps_lineerr(g, "Makefile");
            break;
        }
        if (wps_assign_start(line, "ZCL_WINDOWS_API_FLOOR")) {
            rc = wps_winnt_line(line, def, cap, &nhits);
            break;
        }
    }
    fclose(f);
    if (rc)
        return rc;
    if (nhits != 1) {
        fprintf(stderr,
                "  %s: FAIL — expected exactly one _WIN32_WINNT floor in the\n"
                "      Makefile; refusing to compile against mingw's default.\n",
                WPS_GATE);
        return 1;
    }
    return 0;
}

static int wps_split_d(const char *text, char defs[][WPS_FLAG], int max, int *n)
{
    const char *p = text;
    *n = 0;
    while (*p) {
        const char *e = p;
        while (*p == ' ' || *p == '\t' || *p == '\\')
            p++;
        e = p;
        while (*e && *e != ' ' && *e != '\t' && *e != '\\')
            e++;
        if (e > p && p[0] == '-' && p[1] == 'D') {
            if (*n >= max) {
                fprintf(stderr, "%s: platform defines exceed %d\n", WPS_GATE,
                        max);
                return 2;
            }
            if ((size_t)(e - p) >= WPS_FLAG)
                return wps_fail("platform define over %d bytes", WPS_FLAG);
            memcpy(defs[*n], p, (size_t)(e - p));
            defs[*n][e - p] = '\0';
            (*n)++;
        }
        p = *e ? e + 1 : e;
    }
    return 0;
}

static int wps_platform(const char *root, char defs[][WPS_FLAG], int max,
                        int *n)
{
    static char text[WPS_TEXT];
    char path[WPS_PATH], line[WPS_LINE];
    FILE *f;
    size_t len = 0;
    int rc = 0, started = 0;
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return wps_pathov();
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: cannot open %s\n", WPS_GATE, path);
        return 1;
    }
    while (!rc) {
        int g = wps_getline(f, line, sizeof line);
        if (g == 1)
            break;
        if (g) {
            rc = wps_lineerr(g, "Makefile");
            break;
        }
        if (!started && !wps_assign_start(line, "ZCL_PLATFORM_CPPFLAGS"))
            continue;
        started = 1;
        rc = wps_app(text, sizeof text, &len, " %s", line);
        if (!rc && (line[0] == '\0' || line[strlen(line) - 1] != '\\'))
            break;
    }
    fclose(f);
    if (rc)
        return rc;
    if (!strstr(text, "$(ZCL_WINDOWS_API_FLOOR)")) {
        fprintf(stderr,
                "  %s: FAIL — ZCL_PLATFORM_CPPFLAGS does not reference\n"
                "      ZCL_WINDOWS_API_FLOOR; the product and gate can drift.\n",
                WPS_GATE);
        return 1;
    }
    rc = wps_split_d(text, defs, max, n);
    if (rc)
        return rc;
    if (*n == 0) {
        fprintf(stderr,
                "  %s: FAIL — could not read ZCL_PLATFORM_CPPFLAGS from the\n"
                "      Makefile. Refusing to cross-compile at a guessed API\n"
                "      floor, which would silently grade an easier question.\n",
                WPS_GATE);
        return 1;
    }
    return 0;
}

static int wps_add_unique(char list[][WPS_EX], int max, int *n, const char *s,
                          size_t len)
{
    char ent[WPS_EX];
    int i;
    if (len >= sizeof ent) {
        fprintf(stderr, "%s: exempt entry exceeds %d\n", WPS_GATE, WPS_EX);
        return 2;
    }
    memcpy(ent, s, len);
    ent[len] = '\0';
    for (i = 0; i < *n; i++)
        if (strcmp(list[i], ent) == 0)
            return 0;
    if (*n >= max) {
        fprintf(stderr, "%s: exempt entries exceed %d\n", WPS_GATE, max);
        return 2;
    }
    strcpy(list[*n], ent);
    (*n)++;
    return 0;
}

/* Grep-style extraction of every seam-dir .c mention in one Makefile line. */
static int wps_grab_seam(const char *line, char list[][WPS_EX], int max, int *n)
{
    const char *p = line;
    while ((p = strstr(p, WPS_SEAM)) != NULL) {
        const char *f = p + strlen(WPS_SEAM);
        const char *e = f + 1;
        if (*f == '/') {
            while (isalnum((unsigned char)*e) || *e == '_')
                e++;
            if (e > f + 1 && e[0] == '.' && e[1] == 'c') {
                int rc = wps_add_unique(list, max, n, p, (size_t)(e + 2 - p));
                if (rc)
                    return rc;
                p = e + 2;
                continue;
            }
        }
        p = f;
    }
    return 0;
}

static int wps_exempt_line(const char *line, struct wps_env *e, int *inblk,
                           int *branch)
{
    if (strcmp(line, "ifeq ($(ZCL_HOST_OS),Linux)") == 0 ||
        strcmp(line, "ifneq ($(filter Linux,$(ZCL_HOST_OS)),)") == 0) {
        *inblk = 1;
        *branch = 0;
    } else if (*inblk && strncmp(line, "else", 4) == 0) {
        *branch = 1;
    } else if (*inblk && strcmp(line, "endif") == 0) {
        *inblk = 0;
    } else if (*inblk && *branch == 1) {
        return wps_grab_seam(line, e->exempt, WPS_EXEMPT, &e->nexempt);
    }
    return 0;
}

static int wps_exempt(const char *root, struct wps_env *e)
{
    char path[WPS_PATH], line[WPS_LINE];
    FILE *f;
    int inblk = 0, branch = 0, rc = 0;
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return wps_pathov();
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: cannot open %s\n", WPS_GATE, path);
        return 1;
    }
    for (;;) {
        int g = wps_getline(f, line, sizeof line);
        if (g == 1)
            break;
        if (g) {
            rc = wps_lineerr(g, "Makefile");
            break;
        }
        rc = wps_exempt_line(line, e, &inblk, &branch);
        if (rc)
            break;
    }
    fclose(f);
    if (rc)
        return rc;
    qsort(e->exempt, (size_t)e->nexempt, WPS_EX, wps_cmp);
    return 0;
}

/* ── include roots (superset of the module include set) ───────────── */

static int wps_skippable(const char *name)
{
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
           strcmp(name, ".git") == 0;
}

/* A module directory is <top>/.../modules/<name>, two to four levels
 * below its authority top (find -mindepth 2 -maxdepth 4 in repo_shape.sh). */
static int wps_is_module(const char *rel, int depth)
{
    const char *slash = strrchr(rel, '/');
    size_t n;
    if (depth < 2 || !slash)
        return 0;
    n = (size_t)(slash - rel);
    return n >= 8 && strncmp(slash - 8, "/modules", 8) == 0;
}

static int wps_note_mod(const char *rel, struct wps_env *e)
{
    char inc[WPS_PATH];
    struct stat st;
    if (ovf(snprintf(inc, sizeof inc, "%s/include", rel), sizeof inc))
        return wps_pathov();
    if (stat(inc, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    if (e->nincs >= WPS_INCS) {
        fprintf(stderr, "%s: include roots exceed %d\n", WPS_GATE, WPS_INCS);
        return 2;
    }
    if (strlen(rel) + sizeof "/include" > WPS_INC) {
        fprintf(stderr, "%s: include path exceeds %d\n", WPS_GATE, WPS_INC);
        return 2;
    }
    strcpy(e->incs[e->nincs], rel);
    e->nincs++;
    return 0;
}

static int wps_walk_entry(const char *rel, int depth, struct wps_env *e)
{
    struct stat st;
    int rc;
    if (lstat(rel, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    rc = wps_is_module(rel, depth) ? wps_note_mod(rel, e) : 0;
    return rc;
}

static int wps_walk(const char *rel, int depth, struct wps_env *e)
{
    DIR *d = opendir(rel);
    struct dirent *de;
    int rc = 0;
    if (!d)
        return 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        char sub[WPS_PATH];
        struct stat st;
        if (wps_skippable(de->d_name))
            continue;
        if (ovf(snprintf(sub, sizeof sub, "%s/%s", rel, de->d_name),
                sizeof sub)) {
            rc = wps_pathov();
            break;
        }
        rc = wps_walk_entry(sub, depth, e);
        if (rc == 0 && depth < WPS_DEPTH && lstat(sub, &st) == 0 &&
            S_ISDIR(st.st_mode))
            rc = wps_walk(sub, depth + 1, e);
    }
    closedir(d);
    return rc;
}

static int wps_collect_incs(const char *root, struct wps_env *e)
{
    static const char *const tops[] = {"core", "engine", "cognition",
                                       "platform", "contexts"};
    size_t t;
    int i, rc = 0;
    (void)root;
    for (t = 0; rc == 0 && t < sizeof tops / sizeof tops[0]; t++)
        rc = wps_walk(tops[t], 1, e);
    if (rc)
        return rc;
    qsort(e->incs, (size_t)e->nincs, WPS_INC, wps_cmp);
    for (i = 0; i < e->nincs; i++) {
        if (ovf(snprintf(e->incargs[i], WPS_INCARG, "-I%s/include", e->incs[i]),
                WPS_INCARG))
            return wps_pathov();
        if (ovf(snprintf(e->incs[i], WPS_INC, "%s", e->incargs[i] + 2),
                WPS_INC))
            return wps_pathov();
    }
    return 0;
}

/* ── source set ───────────────────────────────────────────────────── */

static int wps_is_exempt(const struct wps_env *e, const char *rel)
{
    int i;
    for (i = 0; i < e->nexempt; i++)
        if (strcmp(e->exempt[i], rel) == 0)
            return 1;
    return 0;
}

static int wps_maybe_src(const char *dir, const char *name, struct wps_env *e)
{
    char rel[WPS_SRC], full[WPS_PATH];
    struct stat st;
    size_t n = strlen(name);
    if (n < 3 || strcmp(name + n - 2, ".c") != 0)
        return 0;
    if (ovf(snprintf(rel, sizeof rel, "%s/%s", WPS_SEAM, name), sizeof rel) ||
        ovf(snprintf(full, sizeof full, "%s/%s", dir, name), sizeof full))
        return wps_pathov();
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (wps_is_exempt(e, rel))
        return 0;
    if (e->nsrcs >= WPS_SRCS) {
        fprintf(stderr, "%s: seam sources exceed %d\n", WPS_GATE, WPS_SRCS);
        return 2;
    }
    strcpy(e->srcs[e->nsrcs], rel);
    e->counts[e->nsrcs] = 0;
    e->nsrcs++;
    return 0;
}

static int wps_list_srcs(const char *root, struct wps_env *e)
{
    char dir[WPS_PATH];
    DIR *d;
    struct dirent *de;
    int rc = 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/%s", root, WPS_SEAM), sizeof dir))
        return wps_pathov();
    d = opendir(dir);
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        rc = wps_maybe_src(dir, de->d_name, e);
        if (rc)
            break;
    }
    closedir(d);
    if (rc)
        return rc;
    qsort(e->srcs, (size_t)e->nsrcs, WPS_SRC, wps_cmp);
    return 0;
}

/* ── the scan ─────────────────────────────────────────────────────── */

static int wps_seen(const struct wps_env *e, int start, const char *ln)
{
    int j;
    for (j = start; j < e->nsites; j++)
        if (strcmp(e->sites[j], ln) == 0)
            return 1;
    return 0;
}

static int wps_extract_sites(const char *out, const regex_t *re,
                             struct wps_env *e, int i, FILE *err)
{
    int start = e->nsites;
    const char *p = out;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char ln[WPS_SITE];
        if (n >= WPS_SITE) {
            fprintf(err, "%s: diagnostic line exceeds %d\n", WPS_GATE,
                    WPS_SITE);
            return 2;
        }
        memcpy(ln, p, n);
        ln[n] = '\0';
        if (regexec(re, ln, 0, NULL, 0) == 0 && !wps_seen(e, start, ln)) {
            if (e->nsites >= WPS_SITES) {
                fprintf(err, "%s: diagnostic sites exceed %d\n", WPS_GATE,
                        WPS_SITES);
                return 2;
            }
            strcpy(e->sites[e->nsites], ln);
            e->nsites++;
            e->counts[i]++;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int wps_compile_one(const char *root, struct wps_env *e, int i,
                           char *out, size_t cap)
{
    static char *argv[WPS_ARGV];
    static char path[WPS_PATH];
    int k = 0, j, st = 0, rc;
    argv[k++] = e->cc;
    for (j = 0; j < e->nflags; j++)
        argv[k++] = e->flags[j];
    for (j = 0; j < e->nincs; j++)
        argv[k++] = e->incargs[j];
    if (ovf(snprintf(path, sizeof path, "%s%s%s", strcmp(root, ".") ? root : "",
                     strcmp(root, ".") ? "/" : "", e->srcs[i]),
            sizeof path))
        return wps_pathov();
    argv[k++] = path;
    argv[k] = NULL;
    rc = wps_spawn(argv, 0, out, cap, &st);
    (void)st;
    if (rc == 1) {
        fprintf(stderr, "%s: compiler '%s' disappeared mid-run\n", WPS_GATE,
                e->cc);
        return 2;
    }
    if (rc != 0)
        return 2; /* wps_spawn named the failure */
    return 0;
}

static int wps_scan(const char *root, struct wps_env *e, FILE *err)
{
    static char outbuf[WPS_OUTBUF];
    regex_t re;
    int i, r;
    if ((r = regcomp(&re, WPS_DIAG_RE, REG_EXTENDED)) != 0)
        return reg_fail(&re, r);
    for (i = 0; i < e->nsrcs; i++) {
        int rc = wps_compile_one(root, e, i, outbuf, sizeof outbuf);
        if (rc == 0)
            rc = wps_extract_sites(outbuf, &re, e, i, err);
        if (rc) {
            regfree(&re);
            return rc;
        }
    }
    regfree(&re);
    return 0;
}

/* ── baseline and verdicts ────────────────────────────────────────── */

static int wps_base_line(char *line, struct wps_base *b)
{
    char *sp;
    if (line[0] == '#' || line[0] == '\0')
        return 0;
    sp = strpbrk(line, " \t");
    if (!sp)
        return 0;
    if (b->n >= WPS_BASES) {
        fprintf(stderr, "%s: baseline rows exceed %d\n", WPS_GATE, WPS_BASES);
        return 2;
    }
    *sp = '\0';
    if (strlen(line) >= WPS_BPATH)
        return wps_fail("baseline path over %d bytes", WPS_BPATH - 1);
    strcpy(b->path[b->n], line);
    b->allowed[b->n] = atoi(sp + 1);
    b->n++;
    return 0;
}

static int wps_base_load(const char *root, struct wps_base *b)
{
    char path[WPS_PATH], line[WPS_LINE];
    FILE *f;
    int rc = 0;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, WPS_BASE), sizeof path))
        return wps_pathov();
    f = fopen(path, "r");
    if (!f)
        return -1;
    for (;;) {
        int g = wps_getline(f, line, sizeof line);
        if (g == 1)
            break;
        if (g) {
            rc = wps_lineerr(g, "baseline");
            break;
        }
        rc = wps_base_line(line, b);
        if (rc)
            break;
    }
    fclose(f);
    return rc;
}

static int wps_base_get(const struct wps_base *b, const char *p)
{
    int i;
    for (i = 0; i < b->n; i++)
        if (strcmp(b->path[i], p) == 0)
            return b->allowed[i];
    return 0;
}

static int wps_src_index(const struct wps_env *e, const char *p)
{
    int i;
    for (i = 0; i < e->nsrcs; i++)
        if (strcmp(e->srcs[i], p) == 0)
            return i;
    return -1;
}

static int wps_diff_rows(const struct wps_env *e, const struct wps_base *b,
                         char regs[][WPS_ROW], int *nregs,
                         char imps[][WPS_ROW], int *nimps)
{
    int i, q;
    *nregs = 0;
    *nimps = 0;
    for (i = 0; i < e->nsrcs; i++) {
        int allowed = wps_base_get(b, e->srcs[i]);
        if (e->counts[i] > allowed) {
            if (*nregs >= WPS_ROWS)
                return wps_fail("diff rows exceed %d", WPS_ROWS);
            q = snprintf(regs[(*nregs)++], WPS_ROW,
                         "  %s: %d site(s), baseline allows %d", e->srcs[i],
                         e->counts[i], allowed);
            if (ovf(q, WPS_ROW))
                return wps_fail("diff row over %d bytes", WPS_ROW);
        } else if (e->counts[i] < allowed) {
            if (*nimps >= WPS_ROWS)
                return wps_fail("diff rows exceed %d", WPS_ROWS);
            q = snprintf(imps[(*nimps)++], WPS_ROW,
                         "  %s: %d site(s) (baseline %d)", e->srcs[i],
                         e->counts[i], allowed);
            if (ovf(q, WPS_ROW))
                return wps_fail("diff row over %d bytes", WPS_ROW);
        }
    }
    for (i = 0; i < b->n; i++) {
        if (wps_src_index(e, b->path[i]) >= 0)
            continue;
        if (*nimps >= WPS_ROWS)
            return wps_fail("diff rows exceed %d", WPS_ROWS);
        q = snprintf(imps[(*nimps)++], WPS_ROW, "  %s: 0 site(s) (baseline %d)",
                     b->path[i], b->allowed[i]);
        if (ovf(q, WPS_ROW))
            return wps_fail("diff row over %d bytes", WPS_ROW);
    }
    return 0;
}

static int wps_join_flags(const struct wps_env *e, char *dst, size_t cap)
{
    size_t len = 0;
    int i, rc = wps_app(dst, cap, &len, "%s", e->cc);
    for (i = 0; !rc && i < e->nflags; i++)
        rc = wps_app(dst, cap, &len, " %s", e->flags[i]);
    return rc;
}

static int wps_repro(const struct wps_env *e, char *dst, size_t cap)
{
    size_t len;
    int i, rc = wps_join_flags(e, dst, cap);
    if (rc)
        return rc;
    len = strlen(dst);
    for (i = 0; i < e->nincs; i++) {
        rc = wps_app(dst, cap, &len, " %s", e->incargs[i]);
        if (rc)
            return rc;
    }
    return wps_app(dst, cap, &len, " <file.c>");
}

static void wps_report_regs(FILE *err, const struct wps_env *e,
                            char regs[][WPS_ROW], int nregs, const char *cc,
                            const char *repro)
{
    int i, j;
    fprintf(err,
            "\nFAIL: mingw diagnostic site(s) — this change does not cross-\n"
            "      compile cleanly for Windows under %s.\n\n",
            cc);
    for (i = 0; i < nregs; i++)
        fprintf(err, "%s\n", regs[i]);
    fprintf(err, "\n  Diagnostics:\n");
    for (i = 0; i < nregs; i++) {
        const char *f = regs[i] + 2;
        size_t fl = strcspn(f, ":");
        for (j = 0; j < e->nsites; j++)
            if (strncmp(e->sites[j], f, fl) == 0 && e->sites[j][fl] == ':')
                fprintf(err, "    %s\n", e->sites[j]);
    }
    fprintf(err, "\n  Reproduce one file:\n    %s\n", repro);
}

static void wps_report_imps(FILE *out, char imps[][WPS_ROW], int nimps)
{
    int i;
    fprintf(out, "  NOTE: mingw diagnostics went DOWN — tighten the ratchet:\n");
    for (i = 0; i < nimps; i++)
        fprintf(out, "%s\n", imps[i]);
    fprintf(out,
            "    ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint check-windows-platform-seam\n");
}

static int wps_ratchet(const char *root, struct wps_env *e, FILE *out,
                       FILE *err)
{
    static struct wps_base b;
    static char repro[WPS_TEXT];
    static char regs[WPS_ROWS][WPS_ROW], imps[WPS_ROWS][WPS_ROW];
    int rc, nregs = 0, nimps = 0;
    memset(&b, 0, sizeof b);
    rc = wps_base_load(root, &b);
    if (rc == -1) {
        fprintf(err,
                "%s: FATAL — baseline '%s' is missing.\n"
                "  Refusing to report 'clean' with nothing to ratchet against.\n"
                "  Regenerate: ZCL_LINT_MODE=UPDATE z23-lint %s\n",
                WPS_GATE, WPS_BASE, WPS_GATE);
        return 2;
    }
    if (rc)
        return rc;
    rc = wps_repro(e, repro, sizeof repro);
    if (rc)
        return rc;
    rc = wps_diff_rows(e, &b, regs, &nregs, imps, &nimps);
    if (rc) {
        fprintf(err, "%s: report rows exceed %d\n", WPS_GATE, WPS_ROWS);
        return 2;
    }
    if (nregs > 0) {
        wps_report_regs(err, e, regs, nregs, e->cc, repro);
        return 1;
    }
    if (nimps > 0)
        wps_report_imps(out, imps, nimps);
    fprintf(out,
            "  OK: %d platform-seam file(s) cross-compiled with %s"
            " (%d Makefile-exempt); %d known diagnostic site(s), no new ones\n",
            e->nsrcs, e->cc, e->nexempt, e->nsites);
    return 0;
}

/* ── UPDATE and --sites modes ─────────────────────────────────────── */

static int wps_update_hdr(char *text, size_t cap, size_t *len,
                          const struct wps_env *e, const char *ccver)
{
    static char joined[4096];
    int rc = wps_join_flags(e, joined, sizeof joined);
    if (rc)
        return rc;
    rc = wps_app(text, cap, len,
                 "# Windows platform-seam ratchet baseline — regenerate with:\n"
                 "#   ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint check-windows-platform-seam\n"
                 "#\n"
                 "# One '<path> <count>' line per platform/modules/platform/src/*.c file that\n"
                 "# still holds mingw diagnostic sites under\n"
                 "#   %s <lib/*/include -I flags>\n",
                 joined);
    if (!rc)
        rc = wps_app(text, cap, len,
                     "# A file absent from this list must produce ZERO diagnostics.\n"
                     "# Counts may only go DOWN. os_sandbox_linux.c and any other\n"
                     "# file the Makefile's own non-Linux LIB_SRCS filter drops are\n"
                     "# never listed here — they are exempt, not zero.\n"
                     "#\n"
                     "# Recorded from %d in-scope translation units with:\n"
                     "#   %s\n",
                     e->nsrcs, ccver);
    return rc;
}

static int wps_update(const char *root, struct wps_env *e, FILE *out)
{
    static char text[WPS_TEXT], ver[WPS_LINE];
    char path[WPS_PATH];
    size_t len = 0;
    int i, nz = 0, rc;
    wps_cc_ver(e->cc, ver, sizeof ver);
    rc = wps_update_hdr(text, sizeof text, &len, e, ver);
    if (rc)
        return rc;
    for (i = 0; i < e->nsrcs; i++) {
        if (e->counts[i] == 0)
            continue;
        nz++;
        rc = wps_app(text, sizeof text, &len, "%s %d\n", e->srcs[i],
                     e->counts[i]);
        if (rc)
            return rc;
    }
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, WPS_BASE), sizeof path))
        return wps_pathov();
    if (csr_write(path, text))
        return wps_fail("cannot write baseline file");
    fprintf(out, "  UPDATED: %s (%d file(s), %d site(s))\n", WPS_BASE, nz,
            e->nsites);
    return 0;
}

static int wps_sites_mode(const struct wps_env *e, FILE *out)
{
    int i;
    fprintf(out,
            "  %d diagnostic site(s) over %d in-scope file(s)"
            " (%d Makefile-exempt):\n",
            e->nsites, e->nsrcs, e->nexempt);
    for (i = 0; i < e->nsites; i++)
        fprintf(out, "    %s\n", e->sites[i]);
    return 0;
}

/* ── UNOBSERVED contract and --self-test probes ───────────────────── */

static int wps_tmpdir(char *out, size_t cap, const char *tag)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(out, cap, "%s/z23-lint-%s.XXXXXX", td, tag), cap))
        return wps_pathov();
    if (!mkdtemp(out)) {
        fprintf(stderr, "%s: FATAL — mktemp failed.\n", WPS_GATE);
        return 2;
    }
    return 0;
}

static int wps_probe(struct wps_env *e, const char *work, const char *name,
                     const char *text)
{
    static char *argv[WPS_ARGV];
    static char path[WPS_PATH];
    int k = 0, j, st = 0, rc;
    if (ovf(snprintf(path, sizeof path, "%s/%s", work, name), sizeof path))
        { wps_pathov(); return -2; }
    if (csr_write(path, text))
        { wps_fail("cannot write probe file"); return -2; }
    argv[k++] = e->cc;
    for (j = 0; j < e->nflags; j++)
        argv[k++] = e->flags[j];
    for (j = 0; j < e->nincs; j++)
        argv[k++] = e->incargs[j];
    argv[k++] = path;
    argv[k] = NULL;
    rc = wps_spawn(argv, 1, NULL, 0, &st);
    if (rc == 1)
        wps_fail("cannot run probe compiler %s", e->cc);
    if (rc)
        return -2; /* rc 2: wps_spawn named the failure */
    return st;
}

static int wps_selftest(struct wps_env *e, int avail, FILE *out, FILE *err)
{
    static const char probe[] =
        "#include <sys/resource.h> /* POSIX-only: does not exist under mingw */\n"
        "int zcl_gate_probe(void) { return (int)RLIMIT_NOFILE; }\n";
    static const char clean[] =
        "int zcl_gate_clean(int a);\n"
        "int zcl_gate_clean(int a) { return a + 1; }\n";
    char work[WPS_PATH];
    int st, rc;
    if (avail < 0)
        return 2;
    if (avail == 0) {
        if (strcmp(env_or("ZCL_REQUIRE_MINGW", ""), "1") == 0) {
            fprintf(err,
                    "  %s --self-test: FAIL — required compiler '%s' is unavailable.\n",
                    WPS_GATE, e->cc);
            return 2;
        }
        fprintf(out,
                "  %s --self-test: UNOBSERVED — '%s' is not installed;"
                " cannot prove the gate trips without the compiler it gates.\n",
                WPS_GATE, e->cc);
        return 0;
    }
    rc = wps_tmpdir(work, sizeof work, "win-seam-selftest");
    if (rc)
        return rc;
    st = wps_probe(e, work, "violating.c", probe);
    if (st == 0) {
        fprintf(out,
                "FAIL: --self-test — mingw ACCEPTED a TU that #includes a\n"
                "  POSIX-only header. The gate is hollow: it would report\n"
                "  'clean' on a real Windows-portability regression.\n");
        rap_rm_rf(work);
        return 1;
    }
    if (st < 0) {
        rap_rm_rf(work);
        return 2;
    }
    st = wps_probe(e, work, "clean.c", clean);
    if (st != 0) {
        fprintf(out,
                "FAIL: --self-test — mingw REJECTED a trivially clean TU.\n"
                "  The gate would false-fail every contributor.\n");
        rap_rm_rf(work);
        return st < 0 ? 2 : 1;
    }
    fprintf(out,
            "  OK: --self-test — flag set trips on a POSIX-only violation,"
            " passes clean code\n");
    rap_rm_rf(work);
    return 0;
}

static int wps_unobserved(struct wps_env *e, int avail, FILE *out, FILE *err)
{
    if (avail < 0)
        return 2;
    if (strcmp(env_or("ZCL_REQUIRE_MINGW", ""), "1") == 0) {
        fprintf(err,
                "  %s: FAIL — required compiler '%s' is unavailable;\n"
                "  acceptance cannot succeed after checking zero files.\n",
                WPS_GATE, e->cc);
        return 2;
    }
    fprintf(out,
            "  %s: UNOBSERVED — '%s' is not installed on this box.\n"
            "  0 of %d+ platform-seam files were checked. This is NOT a\n"
            "  pass: it is an unobserved leg. Install mingw-w64\n"
            "  (apt install gcc-mingw-w64-x86-64) or set ZCL_MINGW_CC=<path> to\n"
            "  actually run this gate.\n",
            WPS_GATE, e->cc, WPS_SRC_FLOOR);
    return 0;
}

/* ── orchestration ────────────────────────────────────────────────── */

static int wps_stage1_flags(const char *root, struct wps_env *e)
{
    static char defs[WPS_FLAGS][WPS_FLAG];
    char winnt[WPS_FLAG];
    int ndefs = 0, i, rc = wps_winnt(root, winnt, sizeof winnt);
    if (rc)
        return rc;
    rc = wps_platform(root, defs, WPS_FLAGS, &ndefs);
    if (rc)
        return rc;
    strcpy(e->flags[0], "-std=c2x");
    strcpy(e->flags[1], "-fsyntax-only");
    strcpy(e->flags[2], winnt);
    e->nflags = 3;
    for (i = 0; i < ndefs; i++) {
        if (e->nflags >= WPS_FLAGS) {
            fprintf(stderr, "%s: flag list exceeds %d\n", WPS_GATE, WPS_FLAGS);
            return 2;
        }
        strcpy(e->flags[e->nflags++], defs[i]);
    }
    return 0;
}

static int wps_stage2_sources(const char *root, struct wps_env *e, FILE *err)
{
    char msg[256];
    int rc = wps_exempt(root, e);
    if (rc)
        return rc;
    if (e->nexempt == 0) {
        fprintf(err,
                "  %s: FAIL — parsed ZERO Makefile-exempt seam files.\n"
                "      The host-OS guard around LIB_SRCS in 'Makefile' no longer\n"
                "      matches any opener this gate knows, so the build's own\n"
                "      platform decision could not be read. Refusing to grade the\n"
                "      seam against a guessed exemption set. Update the exempt\n"
                "      parser to track the guard's new shape — do NOT baseline the\n"
                "      files that suddenly appear.\n",
                WPS_GATE);
        return 1;
    }
    rc = wps_list_srcs(root, e);
    if (rc)
        return rc;
    if (ovf(snprintf(msg, sizeof msg,
                     "scanned '%s' minus %d Makefile-exempt file(s) — a "
                     "directory move or an exemption parse gone wrong would "
                     "empty this",
                     WPS_SEAM, e->nexempt),
            sizeof msg))
        return wps_fail("scan message over %d bytes", (int)sizeof msg);
    if (gate_require_scanned(e->nsrcs, WPS_SRC_FLOOR, WPS_GATE, msg))
        return 2;
    return 0;
}

static int wps_stage3(const char *root, struct wps_env *e, int mode, FILE *out,
                      FILE *err)
{
    int rc = wps_stage2_sources(root, e, err);
    if (rc)
        return rc;
    rc = wps_scan(root, e, err);
    if (rc)
        return rc;
    if (mode == WPS_MODE_SITES)
        return wps_sites_mode(e, out);
    if (mode == WPS_UPDATE)
        return wps_update(root, e, out);
    return wps_ratchet(root, e, out, err);
}

int wps_check_root(const char *root, FILE *out, FILE *err, int mode)
{
    static struct wps_env e;
    int rc, avail;
    memset(&e, 0, sizeof e);
    if (ovf(snprintf(e.cc, sizeof e.cc, "%s",
                     env_or("ZCL_MINGW_CC", WPS_CC_DEF)),
            sizeof e.cc))
        return wps_fail("ZCL_MINGW_CC over %d bytes", (int)sizeof e.cc);
    rc = wps_stage1_flags(root, &e);
    if (rc)
        return rc;
    fprintf(out,
            "══ LINT: Windows platform-seam cross-compile"
            " (mingw -fsyntax-only) ══\n");
    fflush(out);
    avail = wps_cc_ok(e.cc);
    if (mode != WPS_SELFTEST && avail <= 0)
        return wps_unobserved(&e, avail, out, err);
    rc = wps_collect_incs(root, &e);
    if (rc)
        return rc;
    if (gate_require_scanned(e.nincs, WPS_INC_FLOOR, WPS_GATE,
                             "module include roots are incomplete"))
        return 2;
    if (mode == WPS_SELFTEST)
        return wps_selftest(&e, avail, out, err);
    return wps_stage3(root, &e, mode, out, err);
}

int check_windows_platform_seam_run(int argc, char **argv)
{
    int mode = WPS_SCAN;
    if (argc >= 1) {
        if (strcmp(argv[0], "--self-test") == 0)
            mode = WPS_SELFTEST;
        else if (strcmp(argv[0], "--sites") == 0)
            mode = WPS_MODE_SITES;
    }
    if (mode == WPS_SCAN &&
        strcmp(env_or("ZCL_LINT_MODE", ""), "UPDATE") == 0)
        mode = WPS_UPDATE;
    return wps_check_root(".", stdout, stderr, mode);
}
