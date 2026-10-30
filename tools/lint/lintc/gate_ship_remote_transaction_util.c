/* Copyright 2026 Rhett Creiton - Apache License 2.0
 *
 * purpose: shared helpers for the check_ship_remote_transaction gate port.
 * Subprocess execution (fork + execvp, never system or popen), an internal
 * SHA-256 so no coreutils dependency exists, small-file IO with fixed
 * buffers, and the grep -n / grep -qx / grep -q equivalents the shell
 * original used. Ported from tools/lint/check_ship_remote_transaction.sh
 * (deleted). Every error path logs and fails closed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "base/hex.h"
#include "zsha256/zsha256.h"
#include "gate_ship_remote_transaction_priv.h"

/* ---- SHA-256 via the shared zsha256 package ---- */

int srt_sha256_file(const char *path, char out[SRT_SHA])
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", k_srt_gate, path);
        return -1;
    }
    zsha256_ctx ctx;
    static uint8_t buf[4096];
    size_t n;
    zsha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        zsha256_update(&ctx, buf, n);
    int bad = ferror(f);
    fclose(f);
    if (bad) {
        fprintf(stderr, "%s: cannot hash %s\n", k_srt_gate, path);
        return -1;
    }
    uint8_t d[ZSHA256_DIGEST_LEN];
    zsha256_final(&ctx, d);
    zcl_hex_encode(d, sizeof d, out);
    return 0;
}

/* ---- subprocess: fork + execvp, optional env and redirects ---- */

static void srt_child_redirect(const char *out_path, int merge_err)
{
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        _exit(126);
    dup2(fd, 1);
    if (merge_err)
        dup2(fd, 2);
    if (fd > 2)
        close(fd);
}

static int srt_wait_status(pid_t pid, int *rc)
{
    int st = 0;
    pid_t w;
    do w = waitpid(pid, &st, 0); while (w < 0 && errno == EINTR);
    if (w < 0)
        return -1;
    if (WIFEXITED(st))
        *rc = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        *rc = 128 + WTERMSIG(st);
    else
        *rc = 125;
    return 0;
}

int srt_run(char *const *argv, const char *home, const char *path_pre,
            const char *out_path, int merge_err, int *rc)
{
    static char pathenv[4096];
    if (path_pre) {
        const char *cur = getenv("PATH");
        if (ovf(snprintf(pathenv, sizeof pathenv, "%s:%s", path_pre,
                         cur ? cur : ""), sizeof pathenv))
            return -1;
    }
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (out_path)
            srt_child_redirect(out_path, merge_err);
        if (home)
            setenv("HOME", home, 1);
        if (path_pre)
            setenv("PATH", pathenv, 1);
        execvp(argv[0], argv);
        _exit(127);
    }
    return srt_wait_status(pid, rc);
}

static size_t srt_read_all(int fd, char *out, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(fd, out + n, cap - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    out[n] = '\0';
    return n;
}

static void srt_first_line_trim(char *out)
{
    char *nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    size_t a = 0, b = strlen(out);
    while (a < b && (out[a] == ' ' || out[a] == '\t'))
        a++;
    while (b > a && (out[b - 1] == ' ' || out[b - 1] == '\t'))
        b--;
    memmove(out, out + a, b - a);
    out[b - a] = '\0';
}

int srt_ps_comm(long pid, char *out, size_t cap)
{
    char pidstr[32];
    if (ovf(snprintf(pidstr, sizeof pidstr, "%ld", pid), sizeof pidstr))
        return -1;
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t f = fork();
    if (f < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (f == 0) {
        close(fds[0]);
        dup2(fds[1], 1);
        close(fds[1]);
        char *av[7] = { (char *)"ps", (char *)"-ww", (char *)"-o",
                        (char *)"comm=", (char *)"-p", pidstr, NULL };
        execvp("ps", av);
        _exit(127);
    }
    close(fds[1]);
    (void)srt_read_all(fds[0], out, cap);
    close(fds[0]);
    int rc;
    if (srt_wait_status(f, &rc) != 0)
        return -1;
    srt_first_line_trim(out);
    return out[0] ? 0 : -1;
}

int srt_live_exe_sha(long pid, char out[SRT_SHA])
{
    char p[64];
    if (ovf(snprintf(p, sizeof p, "/proc/%ld/exe", pid), sizeof p))
        return -1;
    if (access(p, R_OK) == 0)
        return srt_sha256_file(p, out);
    char comm[SRT_PATH];
    if (srt_ps_comm(pid, comm, sizeof comm) != 0)
        return -1;
    return srt_sha256_file(comm, out);
}

/* ---- file IO (fixed buffers, fail closed) ---- */

int srt_read_file(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", k_srt_gate, path);
        return -1;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    int bad = ferror(f);
    if (!bad && n == cap - 1 && fgetc(f) != EOF) {
        fprintf(stderr, "%s: %s exceeds %zu\n", k_srt_gate, path, cap - 1);
        bad = 1;
    }
    fclose(f);
    if (bad)
        return -1;
    buf[n] = '\0';
    *len = n;
    return 0;
}

int srt_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "%s: cannot write %s\n", k_srt_gate, path);
        return -1;
    }
    size_t n = strlen(text);
    int bad = fwrite(text, 1, n, f) != n;
    if (fclose(f) != 0)
        bad = 1;
    if (bad) {
        fprintf(stderr, "%s: write failed for %s\n", k_srt_gate, path);
        return -1;
    }
    return 0;
}

int srt_write_exec(const char *path, const char *text)
{
    if (srt_write_file(path, text))
        return -1;
    if (chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int srt_stream_copy(FILE *in, FILE *out)
{
    static char buf[1 << 16];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n)
            return -1;
    return ferror(in) ? -1 : 0;
}

int srt_copy_file(const char *src, const char *dst, int exec_bit)
{
    FILE *in = fopen(src, "rb");
    if (!in) {
        fprintf(stderr, "%s: cannot read %s\n", k_srt_gate, src);
        return -1;
    }
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        fprintf(stderr, "%s: cannot write %s\n", k_srt_gate, dst);
        return -1;
    }
    int bad = srt_stream_copy(in, out);
    fclose(in);
    if (fclose(out) != 0)
        bad = -1;
    if (bad) {
        fprintf(stderr, "%s: copy %s -> %s failed\n", k_srt_gate, src, dst);
        return -1;
    }
    if (exec_bit && chmod(dst, 0755) != 0)
        return -1;
    return 0;
}

int srt_append_file(const char *dst, const char *src)
{
    FILE *in = fopen(src, "rb");
    if (!in) {
        fprintf(stderr, "%s: cannot read %s\n", k_srt_gate, src);
        return -1;
    }
    FILE *out = fopen(dst, "ab");
    if (!out) {
        fclose(in);
        fprintf(stderr, "%s: cannot write %s\n", k_srt_gate, dst);
        return -1;
    }
    int bad = srt_stream_copy(in, out);
    fclose(in);
    if (fclose(out) != 0)
        bad = -1;
    if (bad) {
        fprintf(stderr, "%s: append %s -> %s failed\n", k_srt_gate, src, dst);
        return -1;
    }
    return 0;
}

int srt_mkdirp(const char *path)
{
    char p[SRT_PATH];
    if (ovf(snprintf(p, sizeof p, "%s", path), sizeof p))
        return -1;
    for (char *q = p + 1; *q; q++) {
        if (*q != '/')
            continue;
        *q = '\0';
        if (mkdir(p, 0777) != 0 && errno != EEXIST)
            return -1;
        *q = '/';
    }
    if (mkdir(p, 0777) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* ---- line iteration and the grep equivalents ---- */

int srt_each_line(const char *path, srt_line_fn fn, void *ctx)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot read %s\n", k_srt_gate, path);
        return -1;
    }
    char line[SRT_LINEBUF];
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        if (l + 1 == sizeof line && line[l - 1] != '\n' && !feof(f)) {
            fclose(f);
            fprintf(stderr, "%s: line of %s exceeds %d\n", k_srt_gate, path,
                    SRT_LINEBUF);
            return -1;
        }
        int r = fn(ctx, line, l);
        if (r) {
            fclose(f);
            return r;
        }
    }
    int bad = ferror(f);
    fclose(f);
    return bad ? -1 : 0;
}

struct srt_exact { const char *want; int found; };

static int srt_exact_cb(void *p, const char *line, size_t len)
{
    struct srt_exact *e = p;
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    char tmp[SRT_LINEBUF];
    if (n >= sizeof tmp)
        return -1;
    memcpy(tmp, line, n);
    tmp[n] = '\0';
    if (strcmp(tmp, e->want) == 0) {
        e->found = 1;
        return 1;
    }
    return 0;
}

int srt_file_has_exact_line(const char *path, const char *line)
{
    struct srt_exact e = { line, 0 };
    int r = srt_each_line(path, srt_exact_cb, &e);
    if (r == 1)
        return 1;
    if (r != 0)
        return -1;
    return 0;
}

struct srt_contains { const char *needle; int found; };

static int srt_contains_cb(void *p, const char *line, size_t len)
{
    struct srt_contains *c = p;
    if (memchr(line, '\n', len))
        len = (size_t)((const char *)memchr(line, '\n', len) - line);
    char tmp[SRT_LINEBUF];
    if (len >= sizeof tmp)
        return -1;
    memcpy(tmp, line, len);
    tmp[len] = '\0';
    if (strstr(tmp, c->needle)) {
        c->found = 1;
        return 1;
    }
    return 0;
}

int srt_file_contains(const char *path, const char *needle)
{
    struct srt_contains c = { needle, 0 };
    int r = srt_each_line(path, srt_contains_cb, &c);
    if (r == 1)
        return 1;
    if (r != 0)
        return -1;
    return 0;
}

struct srt_grep {
    const char *needle;
    int prefix;
    int last;
    long line;
    long hit;
    int found;
};

static int srt_grep_cb(void *p, const char *line, size_t len)
{
    struct srt_grep *g = p;
    if (memchr(line, '\n', len))
        len = (size_t)((const char *)memchr(line, '\n', len) - line);
    char tmp[SRT_LINEBUF];
    if (len >= sizeof tmp)
        return -1;
    memcpy(tmp, line, len);
    tmp[len] = '\0';
    g->line++;
    size_t nl = strlen(g->needle);
    int hit = g->prefix ? (strncmp(tmp, g->needle, nl) == 0)
                        : (strstr(tmp, g->needle) != NULL);
    if (hit) {
        g->found = 1;
        g->hit = g->line;
        if (!g->last)
            return 1;
    }
    return 0;
}

int srt_grep_lineno(const char *path, const char *needle, int prefix,
                    int last, long *lineno)
{
    struct srt_grep g = { needle, prefix, last, 0, 0, 0 };
    int r = srt_each_line(path, srt_grep_cb, &g);
    if (r < 0)
        return -1;
    if (!g.found)
        return 0;
    *lineno = g.hit;
    return 1;
}

size_t srt_count_lines(const char *buf, size_t len)
{
    size_t n = 0;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n')
            n++;
    return n;
}

int srt_read_pid(const char *pidfile, long *pid)
{
    char buf[64];
    size_t len;
    if (srt_read_file(pidfile, buf, sizeof buf, &len))
        return -1;
    char *end = NULL;
    long v = strtol(buf, &end, 10);
    if (end == buf || v <= 0)
        return -1;
    *pid = v;
    return 0;
}
