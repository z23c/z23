/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Armed-checkout hook refresh. It runs the existing installer only
 *          when this worktree already points core.hooksPath at build/githooks
 *          and the installed binary differs from the rebuilt one. */

#define _POSIX_C_SOURCE 200809L

#include "refresh_git_hooks.h"

#include "dev_script_dir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if !defined(_WIN32)
static const char *rgh_env(const char *key, const char *fallback)
{
    const char *value = getenv(key);
    if (value && value[0])
        return value;
    return fallback;
}

static void rgh_child_stdio(int write_fd, int merge_err)
{
    int devnull = -1;
    if (dup2(write_fd, STDOUT_FILENO) < 0)
        _exit(127);
    if (!merge_err)
        devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0)
        (void)dup2(devnull, STDERR_FILENO);
    else if (dup2(write_fd, STDERR_FILENO) < 0)
        _exit(127);
    if (devnull >= 0)
        close(devnull);
    close(write_fd);
}

static void rgh_read_fd(int fd, char *out, size_t cap)
{
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t step = read(fd, out + used, cap - 1 - used);
        if (step < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (step == 0)
            break;
        used += (size_t)step;
    }
    out[used] = '\0';
}

static int rgh_reap(pid_t pid, int *status)
{
    for (;;) {
        int wait_status = 0;
        pid_t got = waitpid(pid, &wait_status, 0);
        if (got == pid) {
            *status = WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : 1;
            return 0;
        }
        if (errno != EINTR)
            return -1;
    }
}

static int rgh_capture(char *const argv[], char *out, size_t cap, int merge_err,
                       int *status)
{
    int pipefd[2];
    pid_t pid;
    if (cap == 0 || pipe(pipefd) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        rgh_child_stdio(pipefd[1], merge_err);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    rgh_read_fd(pipefd[0], out, cap);
    close(pipefd[0]);
    return rgh_reap(pid, status);
}

static int rgh_git_text(const char *root, char *const tail[], char *out,
                        size_t cap)
{
    char *argv[8];
    int status = 1;
    int i;
    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = (char *)root;
    for (i = 0; tail[i] && i < 4; i++)
        argv[3 + i] = tail[i];
    argv[3 + i] = NULL;
    out[0] = '\0';
    if (rgh_capture(argv, out, cap, 0, &status) != 0)
        return -1;
    zcl_dev_chomp(out);
    return status;
}

static int rgh_files_same(const char *left, const char *right)
{
    FILE *a = fopen(left, "rb");
    FILE *b = fopen(right, "rb");
    int same = a && b;
    while (same) {
        unsigned char ba[4096], bb[4096];
        size_t na = fread(ba, 1, sizeof ba, a);
        size_t nb = fread(bb, 1, sizeof bb, b);
        if (na != nb || memcmp(ba, bb, na) != 0)
            same = 0;
        else if (na == 0)
            break;
    }
    if (a)
        fclose(a);
    if (b)
        fclose(b);
    return same;
}

static int rgh_armed(const char *root, const char *native, const char *installed)
{
    char text[256];
    char *rev[] = {"rev-parse", "--git-dir", NULL};
    char *ext[] = {"config", "--get", "extensions.worktreeConfig", NULL};
    char *hooks[] = {"config", "--worktree", "--get", "core.hooksPath", NULL};
    struct stat st;
    if (rgh_git_text(root, rev, text, sizeof text) != 0)
        return 0;
    if (rgh_git_text(root, ext, text, sizeof text) != 0 ||
        strcmp(text, "true") != 0)
        return 0;
    if (rgh_git_text(root, hooks, text, sizeof text) != 0 ||
        strcmp(text, "build/githooks") != 0)
        return 0;
    if (access(native, X_OK) != 0 || stat(installed, &st) != 0 ||
        !S_ISREG(st.st_mode))
        return 0;
    return !rgh_files_same(native, installed);
}

static int rgh_install(const char *source, const char *root, const char *native,
                       const char *installer)
{
    char out[8192];
    char *argv[2];
    int status = 1;
    argv[0] = (char *)installer;
    argv[1] = NULL;
    if (setenv("ZCL_GIT_HOOK_SOURCE_ROOT", source, 1) != 0 ||
        setenv("ZCL_GIT_HOOK_ROOT", root, 1) != 0 ||
        setenv("ZCL_GIT_HOOK_NATIVE_BIN", native, 1) != 0)
        return -1;
    if (rgh_capture(argv, out, sizeof out, 1, &status) != 0)
        return -1;
    if (status != 0) {
        fprintf(stderr,
                "refresh_git_hooks_if_armed: install failed (non-fatal):\n%s\n",
                out);
        return 0;
    }
    printf("refreshed installed git hooks (armed checkout, rebuilt hook binary)\n");
    return 0;
}

static int rgh_run(void)
{
    const char *source = rgh_env("ZCL_GIT_HOOK_SOURCE_ROOT", NULL);
    const char *root;
    const char *native;
    char native_buf[PATH_MAX];
    char installed[PATH_MAX];
    char installer[PATH_MAX];
    if (!source)
        return 2;
    root = rgh_env("ZCL_GIT_HOOK_ROOT", source);
    native = rgh_env("ZCL_GIT_HOOK_NATIVE_BIN", NULL);
    if (!native) {
        if (snprintf(native_buf, sizeof native_buf, "%s/build/bin/z23-git-hook",
                     root) >= (int)sizeof native_buf)
            return 2;
        native = native_buf;
    }
    if (snprintf(installed, sizeof installed, "%s/build/githooks/z23-git-hook",
                 root) >= (int)sizeof installed ||
        snprintf(installer, sizeof installer,
                 "%s/tools/scripts/install_git_hooks.sh", source) >=
            (int)sizeof installer)
        return 2;
    if (!rgh_armed(root, native, installed))
        return 0;
    (void)rgh_install(source, root, native, installer);
    return 0;
}
#endif

int zcl_refresh_git_hooks_if_armed(void)
{
#if defined(_WIN32)
    return 0;
#else
    return rgh_run();
#endif
}
