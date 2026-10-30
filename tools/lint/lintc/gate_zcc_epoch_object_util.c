/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared helpers for the check-zcc-epoch-object gate port:
 * SHA-256 labels via zsha256, file text and
 * byte-compare helpers, log line counting and tail probes, grep probes,
 * fork+execvp spawning with argv arrays and optional stdout/stderr
 * redirection, bounded marker waits, and the epoch compile argv builders.
 * Every path lives in a fixed ZEO_PATH buffer; no heap anywhere.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "zsha256/zsha256.h"
#include "gate_zcc_epoch_object_priv.h"

static struct zeo *g_zeo_ctx;

void zeo_set_ctx(struct zeo *z) { g_zeo_ctx = z; }

void zeo_cleanup(struct zeo *z)
{
    if (!z)
        return;
    if (z->locked_compile > 0)
        kill(z->locked_compile, SIGKILL);
    if (z->lock_holder > 0)
        kill(z->lock_holder, SIGKILL);
    if (z->work[0])
        rap_rm_rf(z->work);
    z->work[0] = '\0';
}

[[noreturn]] void zeo_fail(const char *msg)
{
    fprintf(stderr, "check_zcc_epoch_object: FAIL: %s\n", msg);
    zeo_cleanup(g_zeo_ctx);
    exit(1);
}

[[noreturn]] void zeo_failf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("check_zcc_epoch_object: FAIL: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    zeo_cleanup(g_zeo_ctx);
    exit(1);
}

[[noreturn]] void zeo_bail(int code)
{
    zeo_cleanup(g_zeo_ctx);
    exit(code ? code : 1);
}

int zeo_join(char *dst, size_t cap, const char *a, const char *b)
{
    return ovf(snprintf(dst, cap, "%s/%s", a, b), cap) ? 2 : 0;
}

int zeo_dep_of(char *dst, size_t cap, const char *obj)
{
    size_t n = strlen(obj);
    if (n < 2 || n + 1 > cap || strcmp(obj + n - 2, ".o") != 0)
        return 2;
    memcpy(dst, obj, n);
    dst[n - 1] = 'd';
    dst[n] = '\0';
    return 0;
}

int zeo_gcno_of(char *dst, size_t cap, const char *obj)
{
    size_t n = strlen(obj);
    if (n < 3 || n + 9 > cap || strcmp(obj + n - 2, ".o") != 0)
        return 2;
    memcpy(dst, obj, n - 2);
    memcpy(dst + n - 2, ".gcno-path", 11);
    return 0;
}

int zeo_sha256_hex(const char *s, char out[ZEO_HASH])
{
    zsha256_hex(s, strlen(s), out);
    return 0;
}


int zeo_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    size_t n = strlen(text);
    int bad = fwrite(text, 1, n, f) != n;
    bad |= fclose(f) != 0;
    return bad ? -1 : 0;
}

int zeo_append_raw(const char *path, const char *data, size_t n)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0)
        return -1;
    ssize_t w = write(fd, data, n);
    int bad = close(fd) != 0 || (size_t)w != n;
    return bad ? -1 : 0;
}

int zeo_append_file(const char *path, const char *text)
{
    return zeo_append_raw(path, text, strlen(text));
}

int zeo_copy_file(const char *src, const char *dst)
{
    FILE *a = fopen(src, "r");
    if (!a)
        return -1;
    FILE *b = fopen(dst, "w");
    if (!b) {
        fclose(a);
        return -1;
    }
    char buf[4096];
    size_t r;
    int bad = 0;
    while (!bad && (r = fread(buf, 1, sizeof buf, a)) > 0)
        bad = fwrite(buf, 1, r, b) != r;
    bad |= ferror(a) != 0;
    bad |= fclose(a) != 0;
    bad |= fclose(b) != 0;
    return bad ? -1 : 0;
}

int zeo_files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "r");
    FILE *fb = fopen(b, "r");
    if (!fa || !fb) {
        if (fa)
            fclose(fa);
        if (fb)
            fclose(fb);
        return 0;
    }
    int ca, cb, same = 1;
    do {
        ca = getc(fa);
        cb = getc(fb);
        if (ca != cb) {
            same = 0;
            break;
        }
    } while (ca != EOF);
    fclose(fa);
    fclose(fb);
    return same;
}

int zeo_read_file(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    int bad = ferror(f) != 0 || fclose(f) != 0;
    if (bad)
        return -1;
    buf[n] = '\0';
    *len = n;
    return 0;
}

int zeo_read_first(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(buf, (int)cap, f)) {
        fclose(f);
        return -1;
    }
    buf[strcspn(buf, "\n")] = '\0';
    return fclose(f) != 0 ? -1 : 0;
}

int zeo_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

long zeo_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    return (long)st.st_size;
}

int zeo_nonempty(const char *path)
{
    return zeo_size(path) > 0;
}

int zeo_file_stamp(const char *path, char *out, size_t cap)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    if (ovf(snprintf(out, cap, "%lld:%lld:%lld:%lld:%lld",
                     (long long)st.st_dev, (long long)st.st_ino,
                     (long long)st.st_size, (long long)st.st_mtime,
                     (long long)st.st_ctime), cap))
        return 2;
    return 0;
}

long zeo_count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    long n = 0;
    int c;
    while ((c = getc(f)) != EOF)
        if (c == '\n')
            n++;
    fclose(f);
    return n;
}

static int zeo_line_first_is(const char *line, const char *w)
{
    size_t n = strlen(w);
    if (strncmp(line, w, n) != 0)
        return 0;
    char c = line[n];
    return c == ' ' || c == '\t' || c == '\0';
}

long zeo_count_first_field(const char *path, const char *word)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[ZEO_PATH];
    long n = 0;
    while (fgets(line, sizeof line, f))
        if (zeo_line_first_is(line, word))
            n++;
    fclose(f);
    return n;
}

long zeo_count_line_eq(const char *path, const char *token)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[512];
    long n = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, token) == 0)
            n++;
    }
    fclose(f);
    return n;
}

long zeo_outcome_count(const char *path)
{
    static const char *const w[4] = { "HIT", "MISS", "BYPASS", "UNKEY" };
    long n = 0;
    for (int i = 0; i < 4; i++)
        n += zeo_count_first_field(path, w[i]);
    return n;
}

int zeo_tail1(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long end = ftell(f);
    if (end < 0) {
        fclose(f);
        return -1;
    }
    if (end > 0) {
        if (fseek(f, end - 1, SEEK_SET) != 0) {
            fclose(f);
            return -1;
        }
        if (getc(f) == '\n')
            end--;
    }
    long pos = end;
    while (pos > 0) {
        if (fseek(f, pos - 1, SEEK_SET) != 0) {
            fclose(f);
            return -1;
        }
        if (getc(f) == '\n')
            break;
        pos--;
    }
    size_t len = (size_t)(end - pos);
    if (len + 1 > cap) {
        fclose(f);
        return 2;
    }
    if (fseek(f, pos, SEEK_SET) != 0 || fread(out, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    out[len] = '\0';
    fclose(f);
    return 0;
}

int zeo_first_tok_is(const char *line, const char *word)
{
    return zeo_line_first_is(line, word);
}

int zeo_grep_f(const char *needle, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[ZEO_PATH];
    int found = 0;
    while (!found && fgets(line, sizeof line, f))
        found = strstr(line, needle) != NULL;
    fclose(f);
    return found;
}

int zeo_grep_re(const char *pattern, const char *path)
{
    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0)
        return 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        regfree(&re);
        return 0;
    }
    char line[ZEO_PATH];
    int found = 0;
    while (!found && fgets(line, sizeof line, f))
        found = regexec(&re, line, 0, NULL, 0) == 0;
    fclose(f);
    regfree(&re);
    return found;
}

int zeo_head_to_stderr(const char *path, long lines)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[ZEO_PATH];
    for (long i = 0; i < lines && fgets(line, sizeof line, f); i++)
        fputs(line, stderr);
    fclose(f);
    return 0;
}

pid_t zeo_spawn(const char *path, char *argv[], const char *outf,
                const char *errf)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (outf) {
            int fd = open(outf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0 || dup2(fd, 1) < 0)
                _exit(127);
        }
        if (errf) {
            int fd = open(errf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0 || dup2(fd, 2) < 0)
                _exit(127);
        }
        execvp(path, argv);
        _exit(127);
    }
    return pid;
}

int zeo_wait(pid_t pid)
{
    int st = 0;
    if (waitpid(pid, &st, 0) != pid)
        return -1;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return -1;
}

int zeo_run(const char *path, char *argv[], const char *outf,
            const char *errf)
{
    pid_t pid = zeo_spawn(path, argv, outf, errf);
    if (pid < 0)
        return -1;
    return zeo_wait(pid);
}

int zeo_capture(const char *path, char *argv[], char *out, size_t cap)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], 1) < 0)
            _exit(127);
        close(fds[1]);
        execvp(path, argv);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    char tmp[512];
    ssize_t r;
    while (n + 1 < cap && (r = read(fds[0], tmp, sizeof tmp)) > 0) {
        size_t take = (size_t)r;
        if (take > cap - 1 - n)
            take = cap - 1 - n;
        memcpy(out + n, tmp, take);
        n += take;
    }
    out[n] = '\0';
    close(fds[0]);
    int code = zeo_wait(pid);
    while (n > 0 &&
           (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
        out[--n] = '\0';
    return code;
}

int zeo_alive(pid_t pid)
{
    return kill(pid, 0) == 0;
}

int zeo_wait_file(const char *path, pid_t pid)
{
    struct timespec ts = { 0, 10000000 };
    for (int attempt = 0; attempt < 60000; attempt++) {
        if (access(path, F_OK) == 0)
            return 0;
        if (!zeo_alive(pid))
            return 2;
        nanosleep(&ts, NULL);
    }
    return 1;
}

void zeo_wait_marker(const char *path, pid_t pid, const char *what)
{
    int st = zeo_wait_file(path, pid);
    if (st == 2)
        zeo_failf("%s exited before signalling", what);
    if (st != 0)
        zeo_failf("%s did not signal within the hung-process bound", what);
}

int zeo_wait_lock_waiter(const char *lock, pid_t pid)
{
    if (access("/proc/locks", R_OK) != 0) {
        struct timespec ts = { 0, 500000000 };
        nanosleep(&ts, NULL);
        return 0;
    }
    struct stat st;
    if (stat(lock, &st) != 0)
        zeo_fail("could not identify the admission lock");
    char pat[128];
    if (ovf(snprintf(pat, sizeof pat, "-> *FLOCK.*:%lld ",
                     (long long)st.st_ino), sizeof pat))
        return 2;
    struct timespec ts = { 0, 10000000 };
    for (int attempt = 0; attempt < 60000; attempt++) {
        if (zeo_grep_re(pat, "/proc/locks"))
            return 0;
        if (!zeo_alive(pid))
            zeo_fail("locked epoch compile ended without blocking on the "
                     "held admission lock");
        nanosleep(&ts, NULL);
    }
    zeo_fail("locked epoch compile did not block within the hung-process "
             "bound");
}

int zeo_dir_has_file(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    int found = 0;
    while (!found && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char p[ZEO_PATH];
        struct stat st;
        if (ovf(snprintf(p, sizeof p, "%s/%s", dir, e->d_name), sizeof p))
            continue;
        if (lstat(p, &st) != 0)
            continue;
        if (S_ISREG(st.st_mode))
            found = 1;
        else if (S_ISDIR(st.st_mode))
            found = zeo_dir_has_file(p);
    }
    closedir(d);
    return found;
}

int zeo_dir_has_entry_prefix(const char *dir, const char *prefix)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

int zeo_is_windows(void)
{
    struct utsname u;
    if (uname(&u) != 0)
        return 0;
    return strncmp(u.sysname, "MSYS", 4) == 0 ||
           strncmp(u.sysname, "MINGW", 5) == 0 ||
           strncmp(u.sysname, "CYGWIN", 6) == 0;
}

static int zeo_cygpath(const char *p, char *out, size_t cap)
{
    char *argv[4];
    argv[0] = (char *)"cygpath";
    argv[1] = (char *)"-w";
    argv[2] = (char *)p;
    argv[3] = NULL;
    return zeo_capture("cygpath", argv, out, cap) == 0 && out[0] ? 0 : -1;
}

int zeo_dir_link(const char *link, const char *target)
{
    if (!zeo_is_windows())
        return symlink(target, link) == 0 ? 0 : -1;
    char wl[ZEO_PATH], wt[ZEO_PATH];
    if (zeo_cygpath(link, wl, sizeof wl) != 0 ||
        zeo_cygpath(target, wt, sizeof wt) != 0)
        return -1;
    if (setenv("MSYS2_ARG_CONV_EXCL", "*", 1) != 0)
        return -1;
    char *argv[8];
    argv[0] = (char *)"cmd.exe";
    argv[1] = (char *)"/d";
    argv[2] = (char *)"/c";
    argv[3] = (char *)"mklink";
    argv[4] = (char *)"/J";
    argv[5] = wl;
    argv[6] = wt;
    argv[7] = NULL;
    int rc = zeo_run("cmd.exe", argv, "/dev/null", NULL);
    unsetenv("MSYS2_ARG_CONV_EXCL");
    return rc == 0 ? 0 : -1;
}

int zeo_dir_unlink(const char *link)
{
    return zeo_is_windows() ? rmdir(link) : unlink(link);
}

int zeo_which(const char *name, char *out, size_t cap)
{
    const char *path = env_or("PATH", "/usr/bin:/bin");
    const char *p = path;
    for (;;) {
        const char *colon = strchr(p, ':');
        size_t n = colon ? (size_t)(colon - p) : strlen(p);
        if (n == 0) {
            if (access(name, X_OK) == 0) {
                if (ovf(snprintf(out, cap, "%s", name), cap))
                    return 2;
                return 0;
            }
        } else if (n + strlen(name) + 2 < cap) {
            memcpy(out, p, n);
            out[n] = '/';
            strcpy(out + n + 1, name);
            if (access(out, X_OK) == 0)
                return 0;
        }
        if (!colon)
            return -1;
        p = colon + 1;
    }
}
