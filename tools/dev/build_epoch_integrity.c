/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run the two build-epoch compile probes behind a fail-open cache
 *          keyed on their inputs, the compiler identity, and make's version. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "build_epoch_integrity.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BEI_PATH 4096

static const char *const k_rels[] = {
    "tools/dev/build-epoch-selftest.sh",
    "tools/dev/build-epoch-key.sh",
    "tools/dev/publish_build_alias.c",
    "tools/dev/publish_build_alias.h",
    "tools/dev/build_epoch_lock_wait.c",
    "tools/dev/build_epoch_lock_wait.h",
    "tools/dev/compile-epoch-object.sh",
    "tools/dev/build-epoch-session.sh",
    "tools/dev/build-epoch-open-file-identity.sh",
    "tools/dev/process-start-token.sh",
    "tools/dev/source-identity.sh",
    "tools/dev/depfile_scope_launch.c",
    "tools/dev/depfile_scope_launch.h",
    "tools/dev/make_depfile_scope_selftest.c",
    "tools/dev/make_depfile_scope_process.h",
    "Makefile",
};

static int bei_reap(pid_t child)
{
    int status = 0;
    for (;;) {
        pid_t got = waitpid(child, &status, 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got != child)
            return 125;
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
    }
}

static int bei_join(char *out, size_t cap, const char *root, const char *rel)
{
    size_t nr;
    size_t nl;
    size_t need;
    if (root == NULL || rel == NULL || root[0] == '\0')
        return -1;
    nr = strlen(root);
    nl = strlen(rel);
    need = nr + nl + 2;
    if (need > cap)
        return -1;
    memcpy(out, root, nr);
    out[nr] = '/';
    memcpy(out + nr + 1, rel, nl);
    out[nr + nl + 1] = '\0';
    return 0;
}

static int bei_write_span(int fd, const char *text, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int bei_line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    if (cap < 2)
        return -1;
    while (n + 1 < cap) {
        unsigned char b = 0;
        ssize_t got = read(fd, &b, 1);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0 || b == '\n')
            break;
        out[n++] = (char)b;
    }
    out[n] = '\0';
    return n == 0 ? -1 : 0;
}

static int bei_hex64(const char *s)
{
    int i;
    if (s == NULL)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = s[i];
        int digit = c >= '0' && c <= '9';
        int lower = c >= 'a' && c <= 'f';
        if (c == '\0' || (!digit && !lower))
            return 0;
    }
    return s[64] == '\0';
}

static int bei_take_hex(const char *line, char hex[65])
{
    size_t n;
    if (line == NULL)
        return -1;
    n = strlen(line);
    if (n < 64)
        return -1;
    memcpy(hex, line, 64);
    hex[64] = '\0';
    return bei_hex64(hex) ? 0 : -1;
}

/* sha256sum reads the file on stdin so the digest line stays `hex  -`. */
static int bei_sha_file(const char *path, char hex[65])
{
    int in;
    int ends[2];
    pid_t child;
    char line[96];
    char *argv[] = {"sha256sum", NULL};
    int rc;
    in = open(path, O_RDONLY);
    if (in < 0)
        return -1;
    if (pipe(ends) != 0) {
        close(in);
        return -1;
    }
    child = fork();
    if (child == 0) {
        int in_ok = dup2(in, STDIN_FILENO);
        int out_ok = dup2(ends[1], STDOUT_FILENO);
        close(in);
        close(ends[0]);
        close(ends[1]);
        if (in_ok < 0 || out_ok < 0)
            _exit(127);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(in);
    close(ends[1]);
    if (child < 0) {
        close(ends[0]);
        return -1;
    }
    rc = bei_line(ends[0], line, sizeof line);
    close(ends[0]);
    if (bei_reap(child) != 0 || rc != 0)
        return -1;
    return bei_take_hex(line, hex);
}

static int bei_inherit(char *const argv[])
{
    pid_t child = fork();
    if (child < 0)
        return 127;
    if (child == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return bei_reap(child);
}

static void bei_drop(int fd)
{
    char buf[64];
    ssize_t n = 1;
    while (n > 0) {
        n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            n = 1;
    }
}

/* quiet_err sends the child's stderr to /dev/null. The first stdout line is
 * kept; the rest is discarded so the child can exit instead of dying on a
 * closed pipe. */
static int bei_first(char *const argv[], char *out, size_t cap, int quiet_err)
{
    int ends[2];
    pid_t child;
    int rc;
    if (pipe(ends) != 0)
        return -1;
    child = fork();
    if (child == 0) {
        int devnull = -1;
        if (quiet_err)
            devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        if (dup2(ends[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(ends[0]);
        close(ends[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(ends[1]);
    if (child < 0) {
        close(ends[0]);
        return -1;
    }
    rc = bei_line(ends[0], out, cap);
    bei_drop(ends[0]);
    close(ends[0]);
    if (bei_reap(child) != 0)
        return -1;
    return rc;
}

static const char *bei_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return fallback;
    return v;
}

static int bei_tmp(char *out, size_t cap, const char *tag)
{
    const char *tmp = bei_or("TMPDIR", "/tmp");
    int n = snprintf(out, cap, "%s/zcl-bei-%s.%ld", tmp, tag, (long)getpid());
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int bei_present(const char *repo)
{
    size_t i;
    for (i = 0; i < sizeof k_rels / sizeof k_rels[0]; i++) {
        char path[BEI_PATH];
        struct stat st;
        if (bei_join(path, sizeof path, repo, k_rels[i]) != 0)
            return 0;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            return 0;
    }
    return 1;
}

static int bei_manifest(const char *repo, const char *man)
{
    size_t i;
    int fd = open(man, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0)
        return -1;
    for (i = 0; i < sizeof k_rels / sizeof k_rels[0]; i++) {
        char path[BEI_PATH];
        char hex[65];
        char line[BEI_PATH + 96];
        int n;
        if (bei_join(path, sizeof path, repo, k_rels[i]) != 0 ||
            bei_sha_file(path, hex) != 0) {
            close(fd);
            return -1;
        }
        n = snprintf(line, sizeof line, "%zu:%s:%s\n", strlen(path), path, hex);
        if (n < 0 || (size_t)n >= sizeof line ||
            bei_write_span(fd, line, (size_t)n) != 0) {
            close(fd);
            return -1;
        }
    }
    if (close(fd) != 0)
        return -1;
    return 0;
}

static int bei_content(const char *repo, char hex[65])
{
    char man[BEI_PATH];
    int rc;
    if (bei_tmp(man, sizeof man, "manifest") != 0)
        return -1;
    if (bei_manifest(repo, man) != 0) {
        unlink(man);
        return -1;
    }
    rc = bei_sha_file(man, hex);
    unlink(man);
    return rc;
}

static int bei_compiler(const char *repo, const char *cc, const char *cxx, char hex[65])
{
    char tool[BEI_PATH];
    char line[128];
    char *argv[] = {tool, "compiler-id", (char *)cc, (char *)cxx, (char *)repo, NULL};
    if (bei_join(tool, sizeof tool, repo, "tools/dev/build-epoch-key.sh") != 0)
        return -1;
    if (bei_first(argv, line, sizeof line, 0) != 0)
        return -1;
    return bei_take_hex(line, hex);
}

static int bei_make_ver(char *out, size_t cap)
{
    char *argv[] = {"make", "--version", NULL};
    if (bei_first(argv, out, cap, 1) != 0)
        return -1;
    return out[0] == '\0' ? -1 : 0;
}

static int bei_format(char *key, size_t cap, const char *cc, const char *content,
                      const char *compiler, const char *make_ver)
{
    int n = snprintf(key, cap, "v2 cc=[%s] content=%s compiler=%s make=[%s]",
                     cc, content, compiler, make_ver);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int bei_key(const char *repo, char *key, size_t cap)
{
    char content[65];
    char compiler[65];
    char make_ver[256];
    const char *cc = bei_or("CC", "cc");
    const char *cxx = bei_or("CXX", "g++");
    if (!bei_present(repo))
        return -1;
    if (bei_content(repo, content) != 0 || !bei_hex64(content))
        return -1;
    if (bei_compiler(repo, cc, cxx, compiler) != 0)
        return -1;
    if (bei_make_ver(make_ver, sizeof make_ver) != 0)
        return -1;
    return bei_format(key, cap, cc, content, compiler, make_ver);
}

static int bei_read_key(const char *path, char *out, size_t cap)
{
    char buf[1024];
    int fd = open(path, O_RDONLY);
    int rc;
    size_t n;
    if (fd < 0)
        return -1;
    rc = bei_line(fd, buf, sizeof buf);
    close(fd);
    if (rc != 0)
        return -1;
    n = strlen(buf);
    if (n + 1 > cap)
        return -1;
    memcpy(out, buf, n + 1);
    return 0;
}

static void bei_cache_dir(const char *repo, char *out, size_t cap)
{
    const char *env = getenv("ZCL_BUILD_EPOCH_CACHE_DIR");
    if (env != NULL && env[0] != '\0') {
        int n = snprintf(out, cap, "%s", env);
        if (n < 0 || (size_t)n >= cap)
            out[0] = '\0';
        return;
    }
    if (bei_join(out, cap, repo, ".cache/build-epoch-integrity") != 0)
        out[0] = '\0';
}

static int bei_hit(const char *dir, const char *key)
{
    char file[BEI_PATH];
    char cached[1024];
    if (dir[0] == '\0' || bei_join(file, sizeof file, dir, "verdict.key") != 0)
        return 0;
    if (bei_read_key(file, cached, sizeof cached) != 0)
        return 0;
    if (strcmp(cached, key) != 0)
        return 0;
    printf("build-epoch-selftest: PASS (cached; identical inputs -- rm -rf %s to force a rerun)\n",
           dir);
    printf("make-depfile-scope-selftest: PASS (cached; identical inputs -- rm -rf %s to force a rerun)\n",
           dir);
    return 1;
}

static void bei_store(const char *dir, const char *key)
{
    char file[BEI_PATH];
    char tmp[BEI_PATH];
    char leaf[64];
    FILE *fp;
    int n;
    if (dir[0] == '\0')
        return;
    if (bei_inherit((char *[]){"mkdir", "-p", "--", (char *)dir, NULL}) != 0)
        return;
    if (bei_join(file, sizeof file, dir, "verdict.key") != 0)
        return;
    n = snprintf(leaf, sizeof leaf, ".verdict.%ld", (long)getpid());
    if (n < 0 || (size_t)n >= sizeof leaf)
        return;
    if (bei_join(tmp, sizeof tmp, dir, leaf) != 0)
        return;
    fp = fopen(tmp, "w");
    if (fp == NULL)
        return;
    if (fprintf(fp, "%s\n", key) < 0) {
        fclose(fp);
        unlink(tmp);
        return;
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return;
    }
    if (rename(tmp, file) != 0)
        unlink(tmp);
}

static int bei_spawn_log(const char *bin, const char *log, pid_t *child)
{
    *child = fork();
    if (*child < 0)
        return -1;
    if (*child == 0) {
        int fd = open(log, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        char *argv[] = {(char *)bin, NULL};
        if (fd < 0)
            _exit(127);
        if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
            _exit(127);
        close(fd);
        execvp(argv[0], argv);
        _exit(127);
    }
    return 0;
}

static int bei_cat(const char *path)
{
    char buf[512];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n == 0)
            break;
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 || bei_write_span(STDOUT_FILENO, buf, (size_t)n) != 0) {
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

static int bei_probes(const char *repo)
{
    char depfile[BEI_PATH];
    char selftest[BEI_PATH];
    char build_log[BEI_PATH];
    char dep_log[BEI_PATH];
    pid_t build_pid = -1;
    pid_t dep_pid = -1;
    int build_rc;
    int dep_rc;
    char *make_argv[] = {
        "make", "-C", (char *)repo, "--no-print-directory", depfile, NULL
    };
    if (bei_join(depfile, sizeof depfile, repo, "build/bin/depfile-scope-launch") != 0)
        return 1;
    if (bei_join(selftest, sizeof selftest, repo, "tools/dev/build-epoch-selftest.sh") != 0)
        return 1;
    if (bei_inherit(make_argv) != 0)
        return 1;
    if (bei_tmp(build_log, sizeof build_log, "build") != 0 ||
        bei_tmp(dep_log, sizeof dep_log, "depfile") != 0)
        return 1;
    if (bei_spawn_log(selftest, build_log, &build_pid) != 0) {
        unlink(build_log);
        return 1;
    }
    if (bei_spawn_log(depfile, dep_log, &dep_pid) != 0) {
        bei_reap(build_pid);
        unlink(build_log);
        unlink(dep_log);
        return 1;
    }
    build_rc = bei_reap(build_pid);
    dep_rc = bei_reap(dep_pid);
    bei_cat(build_log);
    bei_cat(dep_log);
    unlink(build_log);
    unlink(dep_log);
    return build_rc == 0 && dep_rc == 0 ? 0 : 1;
}

static int bei_go(const char *repo)
{
    char key[1024];
    char dir[BEI_PATH];
    int key_ok;
    if (repo == NULL || repo[0] == '\0') {
        fprintf(stderr, "build-epoch-integrity: repo is required\n");
        return 2;
    }
    key_ok = bei_key(repo, key, sizeof key) == 0;
    bei_cache_dir(repo, dir, sizeof dir);
    if (key_ok && bei_hit(dir, key))
        return 0;
    if (key_ok)
        fprintf(stderr,
                "check-build-epoch-integrity: cache MISS (first run or an input changed) -- running both probes\n");
    else
        fprintf(stderr,
                "check-build-epoch-integrity: cache key unavailable -- running both probes (fail open)\n");
    if (bei_probes(repo) != 0)
        return 1;
    if (key_ok)
        bei_store(dir, key);
    return 0;
}

#endif /* !_WIN32 */

int zcl_build_epoch_integrity(const char *repo)
{
#if defined(_WIN32)
    (void)repo;
    fprintf(stdout, "build-epoch-integrity: unavailable on Windows\n");
    return 2;
#else
    return bei_go(repo);
#endif
}
