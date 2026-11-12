/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_refresh_git_hooks_if_armed. The installer is a stub in the
 * fixture source root; Git is the real git the refresher execs. */

#include "test/test_core.h"

#include "refresh_git_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int rgh_write(const char *path, const char *text, int mode)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(text, file) < 0 || fclose(file) != 0)
        return -1;
    return chmod(path, (mode_t)mode);
}

static int rgh_mkdir(const char *path)
{
    return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static int rgh_git(const char *root, const char *args)
{
    char cmd[1024];
    int n = snprintf(cmd, sizeof cmd, "git -C '%s' %s >/dev/null 2>&1", root,
                     args);
    if (n < 0 || n >= (int)sizeof cmd)
        return -1;
    return system(cmd) == 0 ? 0 : -1;
}

static int rgh_stub(const char *source, const char *marker, const char *fail,
                    const char *dest)
{
    char dir[512];
    char path[512];
    char body[1024];
    int n = snprintf(dir, sizeof dir, "%s/tools", source);
    if (n < 0 || n >= (int)sizeof dir || rgh_mkdir(dir) != 0)
        return -1;
    n = snprintf(dir, sizeof dir, "%s/tools/scripts", source);
    if (n < 0 || n >= (int)sizeof dir || rgh_mkdir(dir) != 0)
        return -1;
    n = snprintf(path, sizeof path, "%s/tools/scripts/install_git_hooks.sh",
                 source);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    n = snprintf(body, sizeof body,
                 "#!/bin/sh\n"
                 "printf '%%s\\n' \"$ZCL_GIT_HOOK_SOURCE_ROOT\" "
                 "\"$ZCL_GIT_HOOK_ROOT\" \"$ZCL_GIT_HOOK_NATIVE_BIN\" > '%s'\n"
                 "if [ -f '%s' ]; then echo stub-install-error >&2; exit 1; fi\n"
                 "mkdir -p \"$(dirname '%s')\"\n"
                 "cp \"$ZCL_GIT_HOOK_NATIVE_BIN\" '%s'\n"
                 "exit 0\n",
                 marker, fail, dest, dest);
    if (n < 0 || n >= (int)sizeof body)
        return -1;
    return rgh_write(path, body, 0755);
}

static int rgh_parents(const char *path)
{
    char buf[512];
    size_t i;
    size_t n = strlen(path);
    if (n >= sizeof buf)
        return -1;
    memcpy(buf, path, n + 1);
    for (i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (rgh_mkdir(buf) != 0)
            return -1;
        buf[i] = '/';
    }
    return 0;
}

static int rgh_file(const char *path, const char *text)
{
    if (rgh_parents(path) != 0)
        return -1;
    return rgh_write(path, text, 0755);
}

static int rgh_call(const char *source, const char *root, const char *native,
                    char *got, size_t cap)
{
    char log[512];
    int fd, saved_out, saved_err, rc, n;
    FILE *file;
    size_t used;
    n = snprintf(log, sizeof log, "%s/refresh.out", source);
    if (n < 0 || n >= (int)sizeof log)
        return -1;
    fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    if (fd < 0 || saved_out < 0 || saved_err < 0 ||
        dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
        if (fd >= 0)
            close(fd);
        if (saved_out >= 0)
            close(saved_out);
        if (saved_err >= 0)
            close(saved_err);
        return -1;
    }
    if (setenv("ZCL_GIT_HOOK_SOURCE_ROOT", source, 1) != 0 ||
        setenv("ZCL_GIT_HOOK_ROOT", root, 1) != 0 ||
        setenv("ZCL_GIT_HOOK_NATIVE_BIN", native, 1) != 0)
        rc = -1;
    else
        rc = zcl_refresh_git_hooks_if_armed();
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd);
    file = fopen(log, "r");
    if (!file)
        return -1;
    used = fread(got, 1, cap - 1, file);
    got[used] = '\0';
    fclose(file);
    return rc;
}

static void rgh_clear_env(void)
{
    unsetenv("ZCL_GIT_HOOK_SOURCE_ROOT");
    unsetenv("ZCL_GIT_HOOK_ROOT");
    unsetenv("ZCL_GIT_HOOK_NATIVE_BIN");
}

static int test_refresh_git_hooks_cases(const char *source, const char *root)
{
    int failures = 0;
    char marker[512];
    char fail[512];
    char native[512];
    char installed[512];
    char got[1024];
    TEST("refresh git hooks: leaves an unarmed checkout alone and refreshes a stale armed one") {
        int n = snprintf(marker, sizeof marker, "%s/marker", source);
        ASSERT(n > 0 && n < (int)sizeof marker);
        n = snprintf(fail, sizeof fail, "%s/fail", source);
        ASSERT(n > 0 && n < (int)sizeof fail);
        n = snprintf(native, sizeof native, "%s/build/bin/z23-git-hook", root);
        ASSERT(n > 0 && n < (int)sizeof native);
        n = snprintf(installed, sizeof installed,
                     "%s/build/githooks/z23-git-hook", root);
        ASSERT(n > 0 && n < (int)sizeof installed);
        ASSERT(rgh_stub(source, marker, fail, installed) == 0);
        ASSERT(rgh_file(native, "hook-bytes\n") == 0);
        ASSERT(rgh_file(installed, "hook-bytes\n") == 0);
        rgh_clear_env();
        ASSERT(zcl_refresh_git_hooks_if_armed() == 2);
        ASSERT(rgh_call(source, root, native, got, sizeof got) == 0);
        ASSERT(access(marker, F_OK) != 0);
        ASSERT(rgh_git(root, "init -q") == 0);
        ASSERT(rgh_call(source, root, native, got, sizeof got) == 0);
        ASSERT(access(marker, F_OK) != 0);
        ASSERT(rgh_git(root, "config extensions.worktreeConfig true") == 0);
        ASSERT(rgh_git(root, "config --worktree core.hooksPath elsewhere") == 0);
        ASSERT(rgh_call(source, root, native, got, sizeof got) == 0);
        ASSERT(access(marker, F_OK) != 0);
        ASSERT(rgh_git(root, "config --worktree core.hooksPath build/githooks") == 0);
        ASSERT(rgh_call(source, root, native, got, sizeof got) == 0);
        ASSERT(access(marker, F_OK) != 0);
        ASSERT(rgh_file(installed, "stale-bytes\n") == 0);
        ASSERT(rgh_call(source, root, native, got, sizeof got) == 0);
        ASSERT(strstr(got, "refreshed installed git hooks "
                           "(armed checkout, rebuilt hook binary)\n") != NULL);
        ASSERT(access(marker, F_OK) == 0);
        ASSERT(rgh_write(fail, "1\n", 0644) == 0);
        ASSERT(rgh_file(installed, "stale-again\n") == 0);
        ASSERT(rgh_call(source, root, native, got, sizeof got) == 0);
        ASSERT(strstr(got, "refresh_git_hooks_if_armed: install failed "
                           "(non-fatal):\n") != NULL);
        ASSERT(strstr(got, "stub-install-error\n") != NULL);
        PASS();
    } _test_next:;
    rgh_clear_env();
    return failures;
}

int test_refresh_git_hooks(void);
int test_refresh_git_hooks(void)
{
    char source[512];
    char root[512];
    int failures;
    test_make_tmpdir(source, sizeof source, "refresh_git_hooks", "source");
    test_make_tmpdir(root, sizeof root, "refresh_git_hooks", "root");
    failures = test_refresh_git_hooks_cases(source, root);
    (void)test_rm_rf_recursive(source);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_refresh_git_hooks: all passed\n");
    else
        printf("test_refresh_git_hooks: %d FAILED\n", failures);
    return failures;
}
