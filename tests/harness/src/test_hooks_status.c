/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_hooks_status against private git fixtures. */

#include "test/test_core.h"

#include "hooks_status.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_shared[] =
    "set in:         .git/config\n"
    "                (shared repo scope — every worktree without its own\n"
    "                config.worktree inherits this; run make install-hooks\n"
    "                here to give this worktree its own)\n";

static const char k_bypass[] =
    "bypass one push:     git push --no-verify   (git itself then runs no hook;\n"
    "                     nothing in this tree reads a ZCL_SKIP_PREPUSH variable —\n"
    "                     measured 2026-09-19: the native hook refuses through it)\n"
    "full-suite/fuzz/coverage (not on this path): make install-quality-linger\n";

static const char k_relative[] =
    "                relative — Git resolves it against the top of the\n"
    "                worktree running the hook, so each worktree gets\n"
    "                its own: here, %s/.githooks\n";

static int hs_sh(const char *cmd)
{
    int status = system(cmd);
    return status == 0 ? 0 : -1;
}

static int hs_init(const char *repo)
{
    char cmd[1600];
    int n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s' && git init -q -b main '%s' && "
                     "git -C '%s' config user.name hook-status-test && "
                     "git -C '%s' config user.email hook-status-test@example.invalid && "
                     "git -C '%s' config commit.gpgsign false",
                     repo, repo, repo, repo, repo);
    if (n < 0 || (size_t)n >= sizeof cmd)
        return -1;
    return hs_sh(cmd);
}

static int hs_capture(const char *root, const char *log, char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved = dup(STDOUT_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved < 0)
        goto fail;
    fflush(stdout);
    if (dup2(fd, STDOUT_FILENO) < 0)
        goto fail;
    *rc = zcl_hooks_status(root);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    close(fd);
    file = fopen(log, "r");
    if (file == NULL)
        return -1;
    used = fread(got, 1, cap - 1, file);
    fclose(file);
    if (used == cap - 1)
        return -1;
    got[used] = '\0';
    return 0;
fail:
    if (saved >= 0) {
        dup2(saved, STDOUT_FILENO);
        close(saved);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int test_hooks_unset(const char *dir)
{
    int failures = 0;
    TEST("hooks status: an unarmed repo and a non-repo both stay unset") {
        char repo[1024];
        char plain[1024];
        char log[1024];
        char got[2048];
        int rc = 1;
        const char *want =
            "core.hooksPath: UNSET — no hook fires. `git push` runs no local CI at all.\n"
            "arm it:         make install-hooks   (writes THIS worktree's Git config)\n";
        ASSERT(snprintf(repo, sizeof repo, "%s/unset", dir) > 0);
        ASSERT(snprintf(plain, sizeof plain, "%s/plain", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/unset.log", dir) > 0);
        ASSERT(hs_init(repo) == 0);
        ASSERT(mkdir(plain, 0700) == 0);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        /* The plain directory must stay a non-repo even when the scratch
         * tree sits inside a larger checkout (a proof worktree): without a
         * ceiling, Git discovery walks out of the fixture and legitimately
         * finds the enclosing repository. */
        ASSERT(setenv("GIT_CEILING_DIRECTORIES", dir, 1) == 0);
        ASSERT(hs_capture(plain, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        ASSERT(setenv("ZCL_HOOKS_STATUS_ROOT", repo, 1) == 0);
        ASSERT(hs_capture(NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        ASSERT(hs_capture("", log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    unsetenv("GIT_CEILING_DIRECTORIES");
    unsetenv("ZCL_HOOKS_STATUS_ROOT");
    return failures;
}

static int test_hooks_relative_missing(const char *dir)
{
    int failures = 0;
    TEST("hooks status: a relative hooksPath with no pre-push is missing") {
        char repo[1024];
        char log[1024];
        char got[4096];
        char want[4096];
        char cmd[1600];
        int rc = 1;
        int n;
        ASSERT(snprintf(repo, sizeof repo, "%s/rel", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/rel.log", dir) > 0);
        ASSERT(hs_init(repo) == 0);
        n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s/.githooks' && git -C '%s' config core.hooksPath .githooks",
                     repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof cmd);
        ASSERT(hs_sh(cmd) == 0);
        n = snprintf(want, sizeof want,
                     "core.hooksPath: .githooks\n"
                     "%s"
                     "%s"
                     "checkout:       %s\n"
                     "pre-push:       MISSING at %s/.githooks/pre-push despite hooksPath being set\n"
                     "                re-arm: make install-hooks\n",
                     (snprintf(got, sizeof got, k_relative, repo), got),
                     k_shared, repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        ASSERT(strstr(got, "bypass one push") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hooks_native_link(const char *dir)
{
    int failures = 0;
    TEST("hooks status: an absolute symlink to z23-git-hook names the native hook") {
        char repo[1024];
        char log[1024];
        char got[4096];
        char want[4096];
        char cmd[1800];
        char hook[1200];
        int rc = 1;
        int n;
        ASSERT(snprintf(repo, sizeof repo, "%s/abs", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/abs.log", dir) > 0);
        ASSERT(snprintf(hook, sizeof hook, "%s/hooks/pre-push", repo) > 0);
        ASSERT(hs_init(repo) == 0);
        n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s/hooks' && git -C '%s' config core.hooksPath '%s/hooks'",
                     repo, repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof cmd);
        ASSERT(hs_sh(cmd) == 0);
        ASSERT(symlink("z23-git-hook", hook) == 0);
        n = snprintf(want, sizeof want,
                     "core.hooksPath: %s/hooks\n"
                     "%s"
                     "checkout:       %s\n"
                     "pre-push:       %s/hooks/pre-push -> z23-git-hook\n"
                     "runs:           the native receipt hook — admits one immutable\n"
                     "                exact commit/base receipt (see tools/dev/z23_git_hook.c);\n"
                     "                post-commit/post-merge/post-checkout schedule proof and return\n"
                     "%s",
                     repo, k_shared, repo, repo, k_bypass);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hooks_worktree_file(const char *dir)
{
    int failures = 0;
    TEST("hooks status: a worktree config and a regular hook stay local") {
        char repo[1024];
        char log[1024];
        char got[4096];
        char want[4096];
        char cmd[1800];
        char hook[1200];
        FILE *file;
        int rc = 1;
        int n;
        ASSERT(snprintf(repo, sizeof repo, "%s/wt", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/wt.log", dir) > 0);
        ASSERT(snprintf(hook, sizeof hook, "%s/.githooks/pre-push", repo) > 0);
        ASSERT(hs_init(repo) == 0);
        n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s/.githooks' && "
                     "git -C '%s' config extensions.worktreeConfig true && "
                     "git -C '%s' config --worktree core.hooksPath .githooks",
                     repo, repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof cmd);
        ASSERT(hs_sh(cmd) == 0);
        file = fopen(hook, "w");
        ASSERT(file != NULL);
        ASSERT(fputs("hook\n", file) >= 0);
        ASSERT(fclose(file) == 0);
        n = snprintf(want, sizeof want,
                     "core.hooksPath: .githooks\n"
                     "%s"
                     "set in:         .git/config.worktree\n"
                     "                (this worktree's own scope — other worktrees unaffected)\n"
                     "checkout:       %s\n"
                     "pre-push:       %s/.githooks/pre-push (unrecognized regular hook)\n"
                     "runs:           inspect this file; re-arm with make install-hooks\n"
                     "%s",
                     (snprintf(got, sizeof got, k_relative, repo), got),
                     repo, repo, k_bypass);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hooks_windows_exe(const char *dir)
{
    int failures = 0;
    TEST("hooks status: a lone pre-push.exe is the Windows receipt hook") {
        char repo[1024];
        char log[1024];
        char got[4096];
        char want[4096];
        char cmd[1800];
        char hook[1200];
        FILE *file;
        int rc = 1;
        int n;
        ASSERT(snprintf(repo, sizeof repo, "%s/exe", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/exe.log", dir) > 0);
        ASSERT(snprintf(hook, sizeof hook, "%s/hooks/pre-push.exe", repo) > 0);
        ASSERT(hs_init(repo) == 0);
        n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s/hooks' && git -C '%s' config core.hooksPath '%s/hooks'",
                     repo, repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof cmd);
        ASSERT(hs_sh(cmd) == 0);
        file = fopen(hook, "w");
        ASSERT(file != NULL);
        ASSERT(fputs("exe\n", file) >= 0);
        ASSERT(fclose(file) == 0);
        n = snprintf(want, sizeof want,
                     "core.hooksPath: %s/hooks\n"
                     "%s"
                     "checkout:       %s\n"
                     "pre-push:       %s/hooks/pre-push.exe (native Windows receipt hook)\n"
                     "runs:           immutable exact commit/base receipt admission;\n"
                     "                no shell, Make, compile, test, wait, or fetch\n"
                     "%s",
                     repo, k_shared, repo, repo, k_bypass);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hooks_dangling(const char *dir)
{
    int failures = 0;
    TEST("hooks status: a dangling symlink is not a missing hook") {
        char repo[1024];
        char log[1024];
        char got[4096];
        char want[4096];
        char cmd[1800];
        char hook[1200];
        int rc = 1;
        int n;
        ASSERT(snprintf(repo, sizeof repo, "%s/dangle", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/dangle.log", dir) > 0);
        ASSERT(snprintf(hook, sizeof hook, "%s/hooks/pre-push", repo) > 0);
        ASSERT(hs_init(repo) == 0);
        n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s/hooks' && git -C '%s' config core.hooksPath '%s/hooks'",
                     repo, repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof cmd);
        ASSERT(hs_sh(cmd) == 0);
        ASSERT(symlink("missing-target", hook) == 0);
        n = snprintf(want, sizeof want,
                     "core.hooksPath: %s/hooks\n"
                     "%s"
                     "checkout:       %s\n"
                     "pre-push:       %s/hooks/pre-push -> missing-target\n"
                     "runs:           unrecognized symlink target — inspect %s/hooks/pre-push directly\n"
                     "%s",
                     repo, k_shared, repo, repo, repo, k_bypass);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_hooks_unknown_origin(const char *dir)
{
    int failures = 0;
    const char *old = getenv("PATH");
    char saved[8192];
    saved[0] = '\0';
    if (old != NULL && strlen(old) < sizeof saved)
        memcpy(saved, old, strlen(old) + 1);
    TEST("hooks status: a hooksPath with no origin file says so") {
        ASSERT(saved[0] != '\0');
        char bindir[1024];
        char repo[1024];
        char log[1024];
        char got[4096];
        char want[4096];
        char git[1200];
        FILE *file;
        int rc = 1;
        int n;
        ASSERT(snprintf(bindir, sizeof bindir, "%s/bin", dir) > 0);
        ASSERT(snprintf(repo, sizeof repo, "%s/origin", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/origin.log", dir) > 0);
        ASSERT(snprintf(git, sizeof git, "%s/git", bindir) > 0);
        ASSERT(mkdir(bindir, 0700) == 0);
        ASSERT(mkdir(repo, 0700) == 0);
        file = fopen(git, "w");
        ASSERT(file != NULL);
        ASSERT(fputs("#!/bin/sh\n"
                     "origin=0\n"
                     "get=0\n"
                     "for a in \"$@\"; do\n"
                     "  if [ \"$a\" = \"--show-origin\" ]; then origin=1; fi\n"
                     "  if [ \"$a\" = \"--get\" ]; then get=1; fi\n"
                     "done\n"
                     "if [ \"$origin\" -eq 1 ]; then exit 0; fi\n"
                     "if [ \"$get\" -eq 1 ]; then printf '%s\\n' .githooks; exit 0; fi\n"
                     "exit 0\n",
                     file) >= 0);
        ASSERT(fclose(file) == 0);
        ASSERT(chmod(git, 0700) == 0);
        ASSERT(setenv("PATH", bindir, 1) == 0);
        n = snprintf(want, sizeof want,
                     "core.hooksPath: .githooks\n"
                     "%s"
                     "set in:         (origin unknown to this git)\n"
                     "checkout:       %s\n"
                     "pre-push:       MISSING at %s/.githooks/pre-push despite hooksPath being set\n"
                     "                re-arm: make install-hooks\n",
                     (snprintf(got, sizeof got, k_relative, repo), got),
                     repo, repo);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        ASSERT(hs_capture(repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    if (saved[0] != '\0')
        setenv("PATH", saved, 1);
    return failures;
}

int test_hooks_status(void);
int test_hooks_status(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "hooks_status", "root");
    failures = test_hooks_unset(dir);
    failures += test_hooks_relative_missing(dir);
    failures += test_hooks_native_link(dir);
    failures += test_hooks_worktree_file(dir);
    failures += test_hooks_windows_exe(dir);
    failures += test_hooks_dangling(dir);
    failures += test_hooks_unknown_origin(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_hooks_status: all passed\n");
    else
        printf("test_hooks_status: %d FAILED\n", failures);
    return failures;
}
