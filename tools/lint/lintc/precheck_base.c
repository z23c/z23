/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: base-tree resolution, locking and result cache for
 * `z23-lint precheck` without --base (see precheck_base.h). Git runs through
 * fork/execvp with an argv array, never a shell.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "precheck_base.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PB_ARGV_MAX = 24, PB_NAME_MAX = 255 };

[[noreturn]] static void pb_exec(const char *const *argv, const int *p)
{
    int nul = open("/dev/null", O_RDWR);
    if (nul < 0 || dup2(p[1], STDOUT_FILENO) < 0 || dup2(nul, STDERR_FILENO) < 0
        || dup2(nul, STDIN_FILENO) < 0)
        _exit(126);
    close(p[0]);
    close(p[1]);
    execvp("git", (char *const *)argv);
    _exit(127);
}

static void pb_slurp(int fd, char *out, size_t cap)
{
    size_t used = 0;
    char junk[256];
    for (;;) {
        char *dst = out && used + 1 < cap ? out + used : junk;
        size_t room = out && used + 1 < cap ? cap - 1 - used : sizeof junk;
        ssize_t n = read(fd, dst, room);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (dst != junk)
            used += (size_t)n;
    }
    if (out && cap > 0) {
        while (used > 0 && isspace((unsigned char)out[used - 1]))
            used--;
        out[used] = '\0';
    }
}

int precheck_base_git(const char *dir, const char *const *args, char *out,
                      size_t cap)
{
    const char *argv[PB_ARGV_MAX];
    size_t n = 0;
    int p[2], st = 0;
    argv[n++] = "git";
    if (dir) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= PB_ARGV_MAX)
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    if (pipe(p) != 0)
        return -1;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0)
        pb_exec(argv, p);
    close(p[1]);
    pb_slurp(p[0], out, cap);
    close(p[0]);
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int pb_mkdirs(char *path)
{
    for (char *s = path + 1; *s; s++) {
        if (*s != '/')
            continue;
        *s = '\0';
        int rc = mkdir(path, 0755);
        *s = '/';
        if (rc != 0 && errno != EEXIST)
            return -1;
    }
    return mkdir(path, 0755) != 0 && errno != EEXIST ? -1 : 0;
}

static int pb_cache_dir(char *dst, size_t cap)
{
    const char *c = getenv("ZCL_PRECHECK_CACHE"), *h = getenv("HOME");
    int n;
    if (c && *c)
        n = snprintf(dst, cap, "%s", c);
    else if (h && *h)
        n = snprintf(dst, cap, "%s/.cache/development-scratch/z23/precheck", h);
    else
        return -1;
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}

static int pb_resolve_sha(struct precheck_base *b, char *why, size_t wcap)
{
    const char *tip_args[] = { "rev-parse", "--verify", "-q",
                               "refs/remotes/origin/main^{commit}", NULL };
    char tip[72];
    if (precheck_base_git(NULL, tip_args, tip, sizeof tip) != 0 || !*tip) {
        snprintf(why, wcap, "origin/main not found in the current tree");
        return 2;
    }
    const char *mb_args[] = { "merge-base", "HEAD", tip, NULL };
    if (precheck_base_git(NULL, mb_args, b->sha, sizeof b->sha) != 0
        || !*b->sha) {
        snprintf(why, wcap, "git merge-base HEAD origin/main failed");
        return 2;
    }
    return 0;
}

static int pb_lock(const char *cache)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/base.lock", cache) >= (int)sizeof path)
        return -1;
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    while (fd >= 0 && flock(fd, LOCK_EX) != 0) {
        if (errno == EINTR)
            continue;
        close(fd);
        return -1;
    }
    return fd;
}

/* Reuse the shared worktree when it exists, else add it from this tree. */
static int pb_ensure_tree(const struct precheck_base *b)
{
    char gitpath[PATH_MAX + 8];
    snprintf(gitpath, sizeof gitpath, "%s/.git", b->tree);
    if (access(gitpath, F_OK) == 0) {
        const char *co[] = { "checkout", "-q", "-f", "--detach", b->sha, NULL };
        return precheck_base_git(b->tree, co, NULL, 0) == 0 ? 0 : -1;
    }
    const char *add[] = { "worktree", "add", "-q", "--detach", b->tree, b->sha,
                          NULL };
    return precheck_base_git(NULL, add, NULL, 0) == 0 ? 0 : -1;
}

/* The base gates run in-process, so cached rcs are only valid for the lint
 * binary that produced them: key the cache on this binary's size and mtime. */
static const char *pb_binary_tag(char *out, size_t cap)
{
    struct stat st;
    const char *exe = (const char *)getauxval(AT_EXECFN);
    if (!exe || stat(exe, &st) != 0)
        snprintf(out, cap, "unknown-%ld", (long)getpid());
    else
        snprintf(out, cap, "%llx-%llx%llx", (unsigned long long)st.st_size,
                 (unsigned long long)st.st_mtim.tv_sec,
                 (unsigned long long)st.st_mtim.tv_nsec);
    return out;
}

int precheck_base_open(struct precheck_base *b, char *why, size_t wcap)
{
    char cache[PATH_MAX - 64], tag[48];
    memset(b, 0, sizeof *b);
    b->lock_fd = -1;
    if (pb_resolve_sha(b, why, wcap) != 0)
        return 2;
    if (pb_cache_dir(cache, sizeof cache) != 0 || pb_mkdirs(cache) != 0) {
        snprintf(why, wcap, "cannot create the precheck cache directory");
        return 2;
    }
    snprintf(b->tree, sizeof b->tree, "%s/base-tree", cache);
    snprintf(b->results, sizeof b->results, "%s/base-native-%s-%s.txt", cache,
             b->sha, pb_binary_tag(tag, sizeof tag));
    b->lock_fd = pb_lock(cache);
    if (b->lock_fd < 0) {
        snprintf(why, wcap, "cannot lock the precheck cache");
        return 2;
    }
    if (pb_ensure_tree(b) != 0) {
        precheck_base_close(b);
        snprintf(why, wcap, "cannot check out the base tree at %.12s", b->sha);
        return 2;
    }
    return 0;
}

void precheck_base_close(struct precheck_base *b)
{
    if (b->lock_fd >= 0)
        close(b->lock_fd);
    b->lock_fd = -1;
}

int precheck_base_lookup(const struct precheck_base *b, const char *name,
                         int *rc)
{
    FILE *f = fopen(b->results, "r");
    char line[PB_NAME_MAX + 32], key[PB_NAME_MAX + 1];
    int got, hit = 1;
    if (!f)
        return 1;
    while (hit && fgets(line, sizeof line, f)) {
        if (sscanf(line, "%255s %d", key, &got) == 2
            && strcmp(key, name) == 0) {
            *rc = got;
            hit = 0;
        }
    }
    fclose(f);
    return hit;
}

static int pb_copy_old(const struct precheck_base *b, FILE *out)
{
    FILE *in = fopen(b->results, "r");
    char buf[4096];
    size_t n;
    if (!in)
        return 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            return -1;
        }
    fclose(in);
    return 0;
}

int precheck_base_store(const struct precheck_base *b,
                        const char *const *names, const int *rcs, size_t n)
{
    char tmp[PATH_MAX + 32];
    int have;
    snprintf(tmp, sizeof tmp, "%s.tmp%ld", b->results, (long)getpid());
    FILE *f = fopen(tmp, "w");
    if (!f)
        return -1;
    int bad = pb_copy_old(b, f);
    for (size_t i = 0; i < n && !bad; i++) {
        if (precheck_base_lookup(b, names[i], &have) == 0)
            continue;
        bad = fprintf(f, "%s %d\n", names[i], rcs[i]) < 0;
    }
    bad |= fclose(f) != 0;
    if (!bad && rename(tmp, b->results) == 0)
        return 0;
    unlink(tmp);
    return -1;
}
