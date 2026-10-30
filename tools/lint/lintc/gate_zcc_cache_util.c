/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: process and file helpers shared by the check-zcc-cache gate
 * sections (spawn with env/redirect control, content compare, copy, touch,
 * zcc log disposition reads, and the two fixture compile wrappers).
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_cache_priv.h"

struct zc_state zc;

enum { ZC_RING = 1024 };
static char zc_ring[ZC_RING][ZC_PATH];
static unsigned zc_ring_at;

static const char *zc_vfmt(const char *prefix, const char *fmt, va_list ap)
{
    char *b = zc_ring[zc_ring_at++ % ZC_RING];
    int n = 0;
    if (prefix) {
        n = snprintf(b, ZC_PATH, "%s/", prefix);
        if (ovf(n, ZC_PATH)) {
            zc.overflow = 1;
            return b;
        }
    }
    int m = vsnprintf(b + n, (size_t)(ZC_PATH - n), fmt, ap);
    if (ovf(m, (size_t)(ZC_PATH - n)))
        zc.overflow = 1;
    return b;
}

const char *zcf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const char *r = zc_vfmt(NULL, fmt, ap);
    va_end(ap);
    return r;
}

const char *zcw(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const char *r = zc_vfmt(zc.work, fmt, ap);
    va_end(ap);
    return r;
}

void zc_fail(const char *msg)
{
    fprintf(stderr, "check_zcc_cache: FAIL — %s\n", msg);
    zc.failures++;
}

int zc_want(int cond, const char *msg)
{
    if (!cond)
        zc_fail(msg);
    return cond;
}

static void zc_redirect(int target, const char *path, int flags)
{
    int fd = open(path, flags, 0644);
    if (fd < 0)
        _exit(126);
    dup2(fd, target);
    close(fd);
}

static void zc_child(const struct zc_cmd *c, const int p[2])
{
    if (c->cwd && chdir(c->cwd) != 0)
        _exit(126);
    for (const char *const *e = c->env; e && *e; e++) {
        if (strchr(*e, '='))
            putenv((char *)*e);
        else
            unsetenv(*e);
    }
    zc_redirect(0, c->inf ? c->inf : "/dev/null", O_RDONLY);
    if (c->out) {
        dup2(p[1], 1);
        close(p[0]);
        close(p[1]);
    } else if (c->outf) {
        zc_redirect(1, c->outf, O_WRONLY | O_CREAT | O_TRUNC);
    } else if (!c->keep_out) {
        zc_redirect(1, "/dev/null", O_WRONLY);
    }
    if (c->merge)
        dup2(1, 2);
    else if (c->errf)
        zc_redirect(2, c->errf, O_WRONLY | O_CREAT | O_TRUNC);
    execvp(c->argv[0], (char *const *)c->argv);
    _exit(127);
}

static pid_t zc_spawn(const struct zc_cmd *c, int *rd)
{
    int p[2] = { -1, -1 };
    if (c->out && pipe(p) != 0)
        return -1;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        if (c->out) {
            close(p[0]);
            close(p[1]);
        }
        return -1;
    }
    if (pid == 0)
        zc_child(c, p);
    if (c->out)
        close(p[1]);
    *rd = p[0];
    return pid;
}

pid_t zc_start(const struct zc_cmd *c)
{
    struct zc_cmd d = *c;
    int rd = -1;
    d.out = NULL;
    return zc_spawn(&d, &rd);
}

int zc_wait(pid_t pid)
{
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1;
}

static void zc_drain(int fd, char *out, size_t cap)
{
    size_t got = 0;
    char sink[512];
    for (;;) {
        char *dst = got + 1 < cap ? out + got : sink;
        size_t room = got + 1 < cap ? cap - 1 - got : sizeof sink;
        ssize_t n = read(fd, dst, room);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (got + 1 < cap)
            got += (size_t)n;
    }
    out[got] = '\0';
    close(fd);
}

int zc_run(const struct zc_cmd *c)
{
    int rd = -1;
    if (c->out && c->cap)
        c->out[0] = '\0'; /* readers must see "" when the spawn fails */
    pid_t pid = zc_spawn(c, &rd);
    if (pid < 0)
        return -1;
    if (c->out)
        zc_drain(rd, c->out, c->cap);
    return zc_wait(pid);
}

int zc_x(const char *const *argv, const char *const *env, const char *errf)
{
    struct zc_cmd c = { .argv = argv, .env = env, .errf = errf };
    return zc_run(&c);
}

int zc_line_with_prefix(const char *path, const char *prefix)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[ZC_LINE];
    size_t pl = strlen(prefix);
    int hit = 0;
    while (!hit && fgets(line, sizeof line, f))
        hit = strncmp(line, prefix, pl) == 0;
    fclose(f);
    return hit;
}

int zc_exists(const char *path)
{
    struct stat sb;
    return lstat(path, &sb) == 0;
}

int zc_nonempty(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_size > 0;
}

int zc_same(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int same = fa && fb;
    char ba[4096], bb[4096];
    while (same) {
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        same = na == nb && memcmp(ba, bb, na) == 0;
        if (na == 0 || nb == 0)
            break;
    }
    if (fa)
        fclose(fa);
    if (fb)
        fclose(fb);
    return same;
}

int zc_touch_ref(const char *ref, const char *dst)
{
    struct stat sb;
    if (stat(ref, &sb) != 0)
        return 1;
    struct timespec t[2] = { sb.st_atim, sb.st_mtim };
    return utimensat(AT_FDCWD, dst, t, 0) != 0;
}

int zc_touch_now(const char *path)
{
    return utimensat(AT_FDCWD, path, NULL, 0) != 0;
}

int zc_copy(const char *src, const char *dst, int keep_time)
{
    FILE *fa = fopen(src, "rb");
    if (!fa)
        return 1;
    struct stat old;
    int existed = stat(dst, &old) == 0;
    FILE *fb = fopen(dst, "wb");
    if (!fb) {
        fclose(fa);
        return 1;
    }
    char buf[4096];
    size_t n;
    int bad = 0;
    while ((n = fread(buf, 1, sizeof buf, fa)) > 0)
        bad |= fwrite(buf, 1, n, fb) != n;
    fclose(fa);
    bad |= fclose(fb) != 0;
    struct stat sb;
    if ((!existed || keep_time) && stat(src, &sb) == 0)
        bad |= chmod(dst, sb.st_mode & 07777) != 0;
    return bad || (keep_time && zc_touch_ref(src, dst));
}

int zc_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int n = 0, c;
    while ((c = fgetc(f)) != EOF)
        n += c == '\n';
    fclose(f);
    return n;
}

int zc_mkwork(const char *tmpl)
{
    char tmp[ZC_PATH];
    if (ovf(snprintf(tmp, sizeof tmp, "%s/%s", env_or("TMPDIR", "/tmp"), tmpl),
            sizeof tmp) ||
        !mkdtemp(tmp) || !realpath(tmp, zc.work))
        return 1;
    return 0;
}

int zc_put(const char *name, const char *text)
{
    return csr_write(zcw("%s", name), text) != 0;
}

int zc_sha(const char *path, char out[ZC_SHA])
{
    char buf[ZC_LINE];
    struct zc_cmd c = { .argv = ZC_ARGV("sha256sum"), .out = buf,
                        .cap = sizeof buf, .inf = path };
    if (zc_run(&c) != 0 || strlen(buf) < 64)
        return 0;
    memcpy(out, buf, 64);
    out[64] = '\0';
    return 1;
}

int zc_prog_out(const char *prog, char *out, size_t cap)
{
    struct zc_cmd c = { .argv = ZC_ARGV(prog), .out = out, .cap = cap };
    int rc = zc_run(&c);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return rc;
}

int zc_prog_is(const char *prog, const char *want)
{
    char out[ZC_LINE];
    zc_prog_out(prog, out, sizeof out);
    return strcmp(out, want) == 0;
}

int zc_which(const char *name, char *out, size_t cap)
{
    if (strchr(name, '/')) {
        if (access(name, X_OK) != 0)
            return 0;
        zc_str(out, cap, name);
        return 1;
    }
    const char *path = env_or("PATH", "/usr/bin:/bin");
    const char *p = path;
    while (*p || p == path) {
        const char *e = strchr(p, ':');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        const char *cand = zcf("%.*s/%s", n ? (int)n : 1, n ? p : ".", name);
        if (access(cand, X_OK) == 0) {
            zc_str(out, cap, cand);
            return 1;
        }
        if (!e)
            break;
        p = e + 1;
    }
    return 0;
}

int zc_sed_first(const char *src, const char *dst, const char *from,
                 const char *to)
{
    FILE *fa = fopen(src, "r"), *fb = fopen(dst, "w");
    int bad = !fa || !fb;
    static char line[65536];
    size_t fl = strlen(from);
    while (!bad && fgets(line, sizeof line, fa)) {
        char *at = strstr(line, from);
        if (at) {
            *at = '\0';
            bad = fprintf(fb, "%s%s%s", line, to, at + fl) < 0;
        } else {
            bad = fputs(line, fb) < 0;
        }
    }
    if (fa)
        fclose(fa);
    if (fb)
        bad |= fclose(fb) != 0;
    return bad;
}

static int zc_find_rec(const char *dir, const char *suffix, char *out,
                       size_t cap, int depth)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    size_t sl = strlen(suffix);
    int found = 0;
    while (!found && (e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        char p[ZC_PATH];
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, e->d_name), sizeof p))
            continue;
        struct stat sb;
        if (lstat(p, &sb) != 0)
            continue;
        size_t nl = strlen(e->d_name);
        if (S_ISREG(sb.st_mode) && nl >= sl &&
            strcmp(e->d_name + nl - sl, suffix) == 0)
            found = !ovf(snprintf(out, cap, "%s", p), cap);
        else if (S_ISDIR(sb.st_mode) && depth < 8)
            found = zc_find_rec(p, suffix, out, cap, depth + 1);
    }
    closedir(d);
    return found;
}

int zc_find_suffix(const char *dir, const char *suffix, char *out, size_t cap)
{
    return zc_find_rec(dir, suffix, out, cap, 0);
}

int zc_lookup_after(const char *log, int after, const char *reason)
{
    regex_t re;
    const char *pat = zcf("^LOOKUP[[:space:]]+reason=%s key=[0-9a-f]{64}[[:space:]]",
                          reason);
    if (regcomp(&re, pat, REG_EXTENDED | REG_NOSUB) != 0)
        return 0;
    FILE *f = fopen(log, "r");
    char line[ZC_LINE];
    int no = 0, hit = 0;
    while (f && !hit && fgets(line, sizeof line, f))
        hit = ++no > after && regexec(&re, line, 0, NULL, 0) == 0;
    if (f)
        fclose(f);
    regfree(&re);
    return hit;
}

/* First whitespace-delimited token of the last line of a log. */
static void zc_last_token(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    char line[ZC_LINE], last[ZC_LINE] = "";
    out[0] = '\0';
    if (!f)
        return;
    while (fgets(line, sizeof line, f))
        zc_str(last, sizeof last, line);
    fclose(f);
    const char *s = last + strspn(last, " \t");
    size_t n = strcspn(s, " \t\r\n");
    if (n >= cap)
        n = cap - 1;
    memcpy(out, s, n);
    out[n] = '\0';
}

int zc_disp_in(const char *log, const char *want, const char *msg)
{
    char tok[ZC_LINE];
    zc_last_token(log, tok, sizeof tok);
    return zc_want(strcmp(tok, want) == 0, msg);
}

int zc_disp_not_in(const char *log, const char *unwanted, const char *msg)
{
    char tok[ZC_LINE];
    zc_last_token(log, tok, sizeof tok);
    return zc_want(strcmp(tok, unwanted) != 0, msg);
}

int zc_disp(const char *want, const char *msg)
{
    return zc_disp_in(zc.log, want, msg);
}

static void zc_cat_stderr(const char *path)
{
    FILE *f = fopen(path, "r");
    int c;
    while (f && (c = fgetc(f)) != EOF)
        fputc(c, stderr);
    if (f)
        fclose(f);
}

int zc_build(const char *label, const char *const *env, char sha[ZC_SHA])
{
    const char *errf = zcw("stderr.%s", label);
    struct zc_cmd c = {
        .argv = ZC_ARGV(zc.zcc, "cc", "-std=c23", "-O1", "-Wall",
                        zcf("-I%s", zc.work), zcw("main.c"), "-o", zcw("prog")),
        .env = env, .errf = errf };
    if (zc_run(&c) != 0) {
        zc_fail(zcf("%s: the compile itself failed", label));
        zc_cat_stderr(errf);
        return 1;
    }
    if (!zc_sha(zcw("prog"), sha)) {
        zc_fail("could not hash the built program");
        return 1;
    }
    return 0;
}

int zc_stage_build(const char *tag, const char *const *env, char sha[ZC_SHA])
{
    const char *dir = zcw("stage.%s", tag);
    if (csr_mkdirs(dir) != 0)
        return 1;
    const char *obj = zcf("%s/main.o", dir);
    struct zc_cmd c = {
        .argv = ZC_ARGV(zc.zcc, "cc", "-std=c23", "-O1", "-Wall",
                        zcf("-I%s", zc.work), "-MD", "-MP", "-MF",
                        zcf("%s/main.d", dir), "-MT", zcw("final/main.o"),
                        "-c", zcw("main.c"), "-o", obj),
        .env = env, .errf = "/dev/null" };
    if (zc_run(&c) != 0)
        return 1;
    return zc_sha(obj, sha) ? 0 : 1;
}

const char *zc_zd(const char *name)
{
    return zcf("ZCC_DIR=%s/%s", zc.work, name);
}

void zc_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap) {
        zc.overflow = 1;
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void zc_append(char *dst, size_t cap, const char *sep, const char *s, size_t n)
{
    size_t used = strlen(dst), sl = used ? strlen(sep) : 0;
    if (used + sl + n + 1 > cap) {
        zc.overflow = 1;
        return;
    }
    memcpy(dst + used, sep, sl);
    memcpy(dst + used + sl, s, n);
    dst[used + sl + n] = '\0';
}

int zc_on(const char *sysname)
{
    struct utsname un;
    return uname(&un) == 0 && strcmp(un.sysname, sysname) == 0;
}
