/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Report core.hooksPath and the armed pre-push hook. Read-only:
 *          writes nothing, installs nothing, never fails a build. */

#include "hooks_status.h"
#include "dev_script_dir.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int hs_which(char *out, size_t cap)
{
    const char *path = getenv("PATH");
    const char *cursor;
    if (path == NULL || path[0] == '\0')
        path = "/usr/bin:/bin";
    cursor = path;
    while (*cursor != '\0') {
        const char *stop = strchr(cursor, ':');
        size_t len = stop != NULL ? (size_t)(stop - cursor) : strlen(cursor);
        int wrote;
        if (len == 0)
            wrote = snprintf(out, cap, "git");
        else
            wrote = snprintf(out, cap, "%.*s/git", (int)len, cursor);
        if (wrote > 0 && (size_t)wrote < cap && access(out, X_OK) == 0)
            return 0;
        if (stop == NULL)
            break;
        cursor = stop + 1;
    }
    return -1;
}

static int hs_actions(posix_spawn_file_actions_t *act, int rd, int wr)
{
    int rc = posix_spawn_file_actions_init(act);
    if (rc != 0)
        return rc;
    rc = posix_spawn_file_actions_adddup2(act, wr, STDOUT_FILENO);
    if (rc == 0)
        rc = posix_spawn_file_actions_addopen(act, STDERR_FILENO, "/dev/null",
                                               O_WRONLY, 0);
    if (rc == 0)
        rc = posix_spawn_file_actions_addclose(act, rd);
    if (rc == 0)
        rc = posix_spawn_file_actions_addclose(act, wr);
    if (rc != 0)
        posix_spawn_file_actions_destroy(act);
    return rc;
}

static int hs_launch(const char *git, char *const argv[], int rd, int wr, pid_t *pid)
{
    posix_spawn_file_actions_t act;
    int rc = hs_actions(&act, rd, wr);
    if (rc != 0)
        return rc;
    rc = posix_spawn(pid, git, &act, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&act);
    return rc;
}

static void hs_slurp(int fd, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    while (n + 1 < cap) {
        ssize_t got = read(fd, out + n, cap - n - 1);
        if (got > 0) {
            n += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        break;
    }
    out[n] = '\0';
}

static void hs_wait(pid_t pid)
{
    int status = 0;
    pid_t got;
    got = waitpid(pid, &status, 0);
    while (got < 0 && errno == EINTR)
        got = waitpid(pid, &status, 0);
}

static void hs_strip(char *line)
{
    char *end = line + strlen(line);
    while (end > line && end[-1] == '\n')
        *--end = '\0';
    if (end > line && end[-1] == '\r')
        end[-1] = '\0';
}

static void hs_line(const char *root, int origin, char *out, size_t cap)
{
    char git[PATH_MAX];
    char *argv[8];
    int fds[2];
    pid_t pid = -1;
    int n = 0;
    out[0] = '\0';
    if (hs_which(git, sizeof git) != 0 || pipe(fds) != 0)
        return;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = (char *)root;
    argv[n++] = "config";
    if (origin)
        argv[n++] = "--show-origin";
    argv[n++] = "--get";
    argv[n++] = "core.hooksPath";
    argv[n] = NULL;
    if (hs_launch(git, argv, fds[0], fds[1], &pid) != 0) {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    close(fds[1]);
    hs_slurp(fds[0], out, cap);
    close(fds[0]);
    hs_wait(pid);
    hs_strip(out);
}

static void hs_origin_file(char *pair)
{
    char *tab = strchr(pair, '\t');
    size_t rest;
    if (tab != NULL)
        *tab = '\0';
    if (strncmp(pair, "file:", 5) != 0)
        return;
    rest = strlen(pair + 5);
    memmove(pair, pair + 5, rest + 1);
}

static int hs_ends(const char *text, const char *suffix)
{
    size_t n = strlen(text);
    size_t m = strlen(suffix);
    if (n < m)
        return 0;
    return memcmp(text + (n - m), suffix, m) == 0;
}

static int hs_join(char *dst, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(dst, cap, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static void hs_unset(void)
{
    printf("core.hooksPath: UNSET — no hook fires. `git push` runs no local CI at all.\n");
    printf("arm it:         make install-hooks   (writes THIS worktree's Git config)\n");
}

static int hs_resolved(const char *root, const char *hooks, char *resolved, size_t cap)
{
    int n;
    printf("core.hooksPath: %s\n", hooks);
    if (hooks[0] == '/') {
        n = snprintf(resolved, cap, "%s", hooks);
        if (n < 0 || (size_t)n >= cap)
            return -1;
        return 0;
    }
    n = snprintf(resolved, cap, "%s/%s", root, hooks);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    printf("                relative — Git resolves it against the top of the\n");
    printf("                worktree running the hook, so each worktree gets\n");
    printf("                its own: here, %s\n", resolved);
    return 0;
}

static void hs_where(const char *file)
{
    if (file[0] == '\0') {
        printf("set in:         (origin unknown to this git)\n");
        return;
    }
    printf("set in:         %s\n", file);
    if (hs_ends(file, "config.worktree")) {
        printf("                (this worktree's own scope — other worktrees unaffected)\n");
        return;
    }
    printf("                (shared repo scope — every worktree without its own\n");
    printf("                config.worktree inherits this; run make install-hooks\n");
    printf("                here to give this worktree its own)\n");
}

static void hs_missing(const char *path)
{
    printf("pre-push:       MISSING at %s despite hooksPath being set\n", path);
    printf("                re-arm: make install-hooks\n");
}

static void hs_link(const char *path)
{
    char target[PATH_MAX];
    ssize_t n = readlink(path, target, sizeof target - 1);
    if (n < 0) {
        target[0] = '?';
        target[1] = '\0';
    } else {
        target[n] = '\0';
    }
    printf("pre-push:       %s -> %s\n", path, target);
    if (strcmp(target, "z23-git-hook") == 0) {
        printf("runs:           the native receipt hook — admits one immutable\n");
        printf("                exact commit/base receipt (see tools/dev/z23_git_hook.c);\n");
        printf("                post-commit/post-merge/post-checkout schedule proof and return\n");
        return;
    }
    printf("runs:           unrecognized symlink target — inspect %s directly\n", path);
}

static void hs_plain(const char *path)
{
    if (hs_ends(path, ".exe")) {
        printf("pre-push:       %s (native Windows receipt hook)\n", path);
        printf("runs:           immutable exact commit/base receipt admission;\n");
        printf("                no shell, Make, compile, test, wait, or fetch\n");
        return;
    }
    printf("pre-push:       %s (unrecognized regular hook)\n", path);
    printf("runs:           inspect this file; re-arm with make install-hooks\n");
}

static void hs_bypass(void)
{
    printf("bypass one push:     git push --no-verify   (git itself then runs no hook;\n");
    printf("                     nothing in this tree reads a ZCL_SKIP_PREPUSH variable —\n");
    printf("                     measured 2026-09-19: the native hook refuses through it)\n");
    printf("full-suite/fuzz/coverage (not on this path): make install-quality-linger\n");
}

static void hs_hook(const char *resolved)
{
    char path[PATH_MAX];
    char exe[PATH_MAX];
    struct stat st;
    int present;
    int linked;
    if (hs_join(path, sizeof path, resolved, "pre-push") != 0)
        return;
    if (hs_join(exe, sizeof exe, resolved, "pre-push.exe") != 0)
        return;
    present = stat(path, &st) == 0;
    if (!present && stat(exe, &st) == 0) {
        memcpy(path, exe, sizeof path);
        present = 1;
    }
    linked = lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
    if (!present && !linked) {
        hs_missing(path);
        return;
    }
    if (linked)
        hs_link(path);
    else
        hs_plain(path);
    hs_bypass();
}

static void hs_report(const char *root)
{
    char hooks[PATH_MAX];
    char origin[PATH_MAX];
    char resolved[PATH_MAX];
    hs_line(root, 0, hooks, sizeof hooks);
    if (hooks[0] == '\0') {
        hs_unset();
        return;
    }
    hs_line(root, 1, origin, sizeof origin);
    hs_origin_file(origin);
    if (hs_resolved(root, hooks, resolved, sizeof resolved) != 0)
        return;
    hs_where(origin);
    printf("checkout:       %s\n", root);
    hs_hook(resolved);
}

static const char *hs_pick(const char *root, char *owned, size_t cap)
{
    const char *env;
    if (root != NULL && root[0] != '\0')
        return root;
    env = getenv("ZCL_HOOKS_STATUS_ROOT");
    if (env != NULL && env[0] != '\0')
        return env;
    if (zcl_dev_checkout_root(owned, cap) != 0)
        return NULL;
    return owned;
}
#endif

int zcl_hooks_status(const char *root)
{
#if defined(_WIN32)
    (void)root;
    puts("hooks-status: unavailable on Windows");
    return 0;
#else
    char owned[PATH_MAX];
    const char *use = hs_pick(root, owned, sizeof owned);
    if (use == NULL) {
        hs_unset();
        return 0;
    }
    hs_report(use);
    return 0;
#endif
}
