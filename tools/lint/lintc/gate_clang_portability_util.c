/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: low-level helpers for the check-clang-portability gate port:
 * an in-process SHA-256, spawn/which/version capture, Makefile variable
 * lists, include-root discovery, source collection, sorting. No heap.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <spawn.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "base/hex.h"
#include "zsha256/zsha256.h"
#include "gate_clang_portability_priv.h"

/* ── SHA-256 (the shared zsha256 package) ───────────────────────────── */

void cp_sha256_hex(const unsigned char hash[32], char out[CP_SHA])
{
    zcl_hex_encode(hash, 32, out);
}

int cp_sha256_data(const void *p, size_t n, char out[CP_SHA])
{
    zsha256_hex(p, n, out);
    return 0;
}

int cp_sha256_file(const char *path, char out[CP_SHA])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return errno == ENOENT ? 1 : -1;
    zsha256_ctx ctx;
    unsigned char buf[8192], h[ZSHA256_DIGEST_LEN];
    zsha256_init(&ctx);
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        zsha256_update(&ctx, buf, n);
    int bad = ferror(f);
    fclose(f);
    if (bad)
        return -1;
    zsha256_final(&ctx, h);
    cp_sha256_hex(h, out);
    return 0;
}

/* ── process spawn ───────────────────────────────────────────────────── */

/* Wait for pid and map the wait status to a shell-style exit code. */
static int cp_reap(pid_t pid, int *rc)
{
    int st;
    pid_t w;
    while ((w = waitpid(pid, &st, 0)) < 0 && errno == EINTR)
        ;
    if (w < 0)
        return -1;
    if (WIFEXITED(st))
        *rc = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        *rc = 128 + WTERMSIG(st);
    else
        *rc = 127;
    return 0;
}

static int cp_open_redirect(posix_spawn_file_actions_t *fa, const char *path,
                            int target)
{
    if (!path)
        return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    posix_spawn_file_actions_adddup2(fa, fd < 0 ? -1 : fd, target);
    return fd;
}

int cp_spawn(const char *file, char *const argv[], const char *so,
             const char *se, int *rc)
{
    extern char **environ;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    int sofd = cp_open_redirect(&fa, so, 1);
    int sefd = cp_open_redirect(&fa, se, 2);
    pid_t pid;
    int err = posix_spawnp(&pid, file, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (sofd >= 0)
        close(sofd);
    if (sefd >= 0)
        close(sefd);
    return err ? -1 : cp_reap(pid, rc);
}

int cp_which(const char *cmd)
{
    if (strchr(cmd, '/'))
        return access(cmd, X_OK) == 0;
    const char *path = getenv("PATH");
    if (!path)
        return 0;
    char buf[CP_PATH];
    const char *p = path;
    while (*p) {
        const char *e = strchr(p, ':');
        size_t d = e ? (size_t)(e - p) : strlen(p);
        if (d >= sizeof buf)
            d = sizeof buf - 1;
        memcpy(buf, p, d);
        buf[d] = '\0';
        if (ovf(snprintf(buf + strlen(buf), sizeof buf - strlen(buf), "/%s", cmd),
                sizeof buf))
            return 0;
        if (access(buf, X_OK) == 0)
            return 1;
        if (!e)
            break;
        p = e + 1;
    }
    return 0;
}

/* Run the compiler c->cc on `tail` (NULL-terminated), its own argv[0] first.
 * In the selftest's stub mode the "compiler" is this very binary, entered
 * through its gate: z23-lint check-clang-portability --stub-cc <tail>. */
int cp_cc_spawn(const struct cp_ctx *c, char *const tail[], const char *so,
                const char *se, int *rc)
{
    char *av[CP_MAXARGS + 8];
    int a = 0;
    av[a++] = (char *)c->cc;
    if (c->stub_cc) {
        av[a++] = (char *)"check-clang-portability";
        av[a++] = (char *)"--stub-cc";
    }
    for (int i = 0; tail[i]; i++) {
        if (a >= CP_MAXARGS + 7)
            return -1;
        av[a++] = tail[i];
    }
    av[a] = NULL;
    return cp_spawn(c->cc, av, so, se, rc);
}

int cp_version_line(const struct cp_ctx *c, const char *capture, char *out,
                    size_t cap)
{
    char *tail[2] = { (char *)"--version", NULL };
    int rc;
    out[0] = '\0';
    if (cp_cc_spawn(c, tail, capture, "/dev/null", &rc) != 0)
        return 0;
    if (cp_first_line(capture, out, cap) != 0)
        out[0] = '\0';
    return 0;
}

/* ── small text helpers ──────────────────────────────────────────────── */

void cp_key(const char *src, char *out, size_t cap)
{
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++)
        out[i] = isalnum((unsigned char)src[i]) ? src[i] : '_';
    out[i] = '\0';
}

int cp_first_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int ok = fgets(out, (int)cap, f) != NULL;
    fclose(f);
    if (!ok)
        return -1;
    char *nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    return 0;
}

static int cp_var_head(const char *line, const char *var)
{
    size_t v = strlen(var);
    if (strncmp(line, var, v) != 0)
        return 0;
    size_t i = v;
    while (line[i] == ' ' || line[i] == '\t')
        i++;
    if (line[i] == '+' || line[i] == ':')
        i++;
    return line[i] == '=' ? (int)i + 1 : 0;
}

/* Strip trailing whitespace and one continuation backslash; 1 if continued. */
static int cp_strip_cont(char *line)
{
    size_t len = strlen(line);
    while (len && (line[len - 1] == ' ' || line[len - 1] == '\t'))
        len--;
    int cont = len && line[len - 1] == '\\';
    if (cont)
        len--;
    line[len] = '\0';
    return cont;
}

/* Append the whitespace-separated words of line to out; -1 on overflow. */
static int cp_add_words(char *p, char out[][CP_PATH], int *n, int max)
{
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        char *tok = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (*p)
            *p++ = '\0';
        if (*tok && strchr(tok, '#'))
            *tok = '\0';
        if (!*tok || *n >= max)
            continue;
        if (ovf(snprintf(out[*n], CP_PATH, "%s", tok), CP_PATH))
            return -1;
        (*n)++;
    }
    return 0;
}

int cp_makefile_list(const char *mk, const char *var,
                     char out[][CP_PATH], int max)
{
    FILE *f = fopen(mk, "r");
    if (!f)
        return -1;
    char line[CP_LINE];
    int n = 0, inb = 0, bad = 0;
    while (!bad && fgets(line, sizeof line, f)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (!inb) {
            int off = cp_var_head(line, var);
            if (!off)
                continue;
            inb = 1;
            memmove(line, line + off, strlen(line + off) + 1);
        }
        int cont = cp_strip_cont(line);
        bad = cp_add_words(line, out, &n, max) < 0;
        if (!cont)
            break;
    }
    fclose(f);
    return bad ? -1 : n;
}


static int cp_walk_inc(const char *dir, char out[][CP_PATH], int max, int *n)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char sub[CP_PATH];
        if (ovf(snprintf(sub, sizeof sub, "%s/%s", dir, e->d_name), sizeof sub)) {
            closedir(d);
            return -1;
        }
        if (!lintc_is_dir(sub))
            continue;
        if (!strcmp(e->d_name, "include")) {
            if (*n >= max) {
                closedir(d);
                return -1;
            }
            if (ovf(snprintf(out[*n], CP_PATH, "%s", sub), CP_PATH)) {
                closedir(d);
                return -1;
            }
            (*n)++;
        } else if (cp_walk_inc(sub, out, max, n) < 0) {
            closedir(d);
            return -1;
        }
    }
    closedir(d);
    return 0;
}

static int cp_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

int cp_find_includes(const char *const roots[], int nroots,
                     char out[][CP_PATH], int max)
{
    int n = 0;
    for (int i = 0; i < nroots; i++)
        if (cp_walk_inc(roots[i], out, max, &n) < 0)
            return -1;
    if (n > 1)
        qsort(out, (size_t)n, CP_PATH, cp_cmp_str);
    return n;
}

int cp_collect_c(const char *dir, char arr[][CP_PATH], int max, int *n)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l < 2 || strcmp(e->d_name + l - 2, ".c") != 0)
            continue;
        if (*n >= max) {
            closedir(d);
            return -1;
        }
        if (ovf(snprintf(arr[*n], CP_PATH, "%s/%s", dir, e->d_name), CP_PATH)) {
            closedir(d);
            return -1;
        }
        (*n)++;
    }
    closedir(d);
    return 0;
}

void cp_sort_uniq(char *arr, size_t w, int *n)
{
    if (*n > 1)
        qsort(arr, (size_t)*n, w, cp_cmp_str);
    int u = 0;
    for (int i = 0; i < *n; i++)
        if (u == 0 || strcmp(arr + (size_t)(u - 1) * w, arr + (size_t)i * w) != 0)
            memcpy(arr + (size_t)u++ * w, arr + (size_t)i * w, w);
    *n = u;
}

int cp_mkdirs(const char *path)
{
    char buf[CP_PATH];
    if (ovf(snprintf(buf, sizeof buf, "%s", path), sizeof buf))
        return -1;
    for (char *p = buf + 1; *p; p++)
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
                *p = '/';
                return -1;
            }
            *p = '/';
        }
    return mkdir(buf, 0755) != 0 && errno != EEXIST ? -1 : 0;
}

int cp_regcomp(regex_t *re, const char *pat, int flags)
{
    int e = regcomp(re, pat, flags);
    if (e) {
        char msg[256];
        regerror(e, re, msg, sizeof msg);
        fprintf(stderr, "check-clang-portability: regcomp failed: %s\n", msg);
        return -1;
    }
    return 0;
}

int cp_file_eq(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) {
        if (fa)
            fclose(fa);
        if (fb)
            fclose(fb);
        return -1;
    }
    char ba[8192], bb[8192];
    int same = 1;
    while (same) {
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        if (na != nb || memcmp(ba, bb, na) != 0)
            same = 0;
        if (na < sizeof ba)
            break;
    }
    fclose(fa);
    fclose(fb);
    return same;
}

int cp_appendf(const char *path, const char *fmt, ...)
{
    FILE *f = fopen(path, "a");
    if (!f)
        return -1;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
    return 0;
}

int cp_touch(const char *path)
{
    FILE *f = fopen(path, "a");
    if (!f)
        return -1;
    fclose(f);
    return 0;
}

int cp_count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[CP_LINE];
    int n = 0;
    while (fgets(line, sizeof line, f))
        n++;
    fclose(f);
    return n;
}

/* A fresh scratch directory "<tmp>/<tag>.XXXXXX": $TMPDIR, else the repo's
 * own test-tmp/ (never the shared system temp directory, where an aborted
 * run would leave stale entries). 0 ok, 2 failure (reported). */
int cp_mkscratch(char *out, size_t cap, const char *tag)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    if (cp_mkdirs(td) != 0)
        return die("z23-lint: cannot create scratch parent %s\n", td);
    if (ovf(snprintf(out, cap, "%s/%s.XXXXXX", td, tag), cap))
        return 2;
    return mkdtemp(out) ? 0 : die("z23-lint: mkdtemp failed\n", "");
}
