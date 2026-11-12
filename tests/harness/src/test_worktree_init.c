/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_worktree_init against a private git worktree. */

#include "test/test_core.h"

#include "worktree_init.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const k_arcs[] = {
    "libsecp256k1.a", "libcrypto.a", "libssl.a", "libevent.a",
    "libevent_openssl.a", "libevent_pthreads.a", "libleveldb.a",
    "libsqlite3.a", "libz.a", "libtor_stub.a"
};

static int wti_sh(const char *cmd)
{
    return system(cmd) == 0 ? 0 : -1;
}

static int wti_capture(const char *root, const char *log, char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_worktree_init(root);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
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
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int wti_git(const char *repo)
{
    char cmd[1600];
    int n = snprintf(cmd, sizeof cmd,
                     "git init -q -b main '%s' && "
                     "git -C '%s' config user.name worktree-init-test && "
                     "git -C '%s' config user.email worktree-init-test@example.invalid && "
                     "git -C '%s' -c commit.gpgsign=false commit --allow-empty -q -m init",
                     repo, repo, repo, repo);
    if (n < 0 || (size_t)n >= sizeof cmd)
        return -1;
    return wti_sh(cmd);
}

static int wti_make(const char *dir)
{
    char path[1200];
    FILE *file;
    if (snprintf(path, sizeof path, "%s/bin", dir) >= (int)sizeof path)
        return -1;
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    if (snprintf(path, sizeof path, "%s/bin/make", dir) >= (int)sizeof path)
        return -1;
    file = fopen(path, "w");
    if (file == NULL)
        return -1;
    if (fputs("#!/bin/sh\n"
              "if [ \"$1\" = \"--no-print-directory\" ] && [ \"$2\" = \"install-hooks\" ]; then\n"
              "  git config extensions.worktreeConfig true\n"
              "  git config --worktree core.hooksPath build/githooks\n"
              "  exit 0\n"
              "fi\n"
              "echo unexpected make >&2\n"
              "exit 9\n",
              file) < 0) {
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0)
        return -1;
    return chmod(path, 0700);
}

static int wti_seed(const char *repo, int with_zlib)
{
    char cmd[2048];
    int n = snprintf(cmd, sizeof cmd,
                     "mkdir -p '%s/vendor/lib' '%s/vendor/include/openssl' && "
                     "printf 'z\\n' > '%s/vendor/include/zlib.h' && "
                     "printf 'c\\n' > '%s/vendor/include/zconf.h' && "
                     "printf 'o\\n' > '%s/vendor/include/openssl/rand.h'",
                     repo, repo, repo, repo, repo);
    size_t i;
    if (n < 0 || (size_t)n >= sizeof cmd)
        return -1;
    if (wti_sh(cmd) != 0)
        return -1;
    for (i = 0; i < sizeof k_arcs / sizeof k_arcs[0]; i++) {
        if (!with_zlib && strcmp(k_arcs[i], "libz.a") == 0)
            continue;
        n = snprintf(cmd, sizeof cmd, "printf '%s\\n' > '%s/vendor/lib/%s'",
                     k_arcs[i], repo, k_arcs[i]);
        if (n < 0 || (size_t)n >= sizeof cmd || wti_sh(cmd) != 0)
            return -1;
    }
    return 0;
}

static int wti_lane(const char *canon, const char *lane)
{
    char cmd[1600];
    int n = snprintf(cmd, sizeof cmd,
                     "git -C '%s' worktree add -q -b lane '%s'", canon, lane);
    if (n < 0 || (size_t)n >= sizeof cmd)
        return -1;
    return wti_sh(cmd);
}

static int test_worktree_missing_lib(const char *dir)
{
    int failures = 0;
    TEST("worktree init: a canonical checkout without vendor/lib is refused") {
        char canon[1024];
        char lane[1024];
        char log[1024];
        char got[4096];
        int rc = 0;
        ASSERT(snprintf(canon, sizeof canon, "%s/bare-canon", dir) > 0);
        ASSERT(snprintf(lane, sizeof lane, "%s/bare-lane", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/bare.log", dir) > 0);
        ASSERT(wti_git(canon) == 0);
        ASSERT(wti_lane(canon, lane) == 0);
        ASSERT(wti_capture(lane, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "[1/3] vendor/lib: FAIL -- canonical ") != NULL);
        ASSERT(strstr(got, "make vendor-ready") != NULL);
        ASSERT(strstr(got, "worktree-init: done") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_worktree_copy(const char *dir)
{
    int failures = 0;
    const char *old = getenv("PATH");
    char saved[8192];
    saved[0] = '\0';
    if (old != NULL && strlen(old) < sizeof saved)
        memcpy(saved, old, strlen(old) + 1);
    TEST("worktree init: archives copy once and a second run skips them") {
        char canon[1024];
        char lane[1024];
        char log[1024];
        char got[8192];
        char path[1200];
        char binpath[1200];
        int rc = 1;
        ASSERT(saved[0] != '\0');
        ASSERT(snprintf(canon, sizeof canon, "%s/copy-canon", dir) > 0);
        ASSERT(snprintf(lane, sizeof lane, "%s/copy-lane", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/copy.log", dir) > 0);
        ASSERT(snprintf(binpath, sizeof binpath, "%s/bin", dir) > 0);
        ASSERT(wti_git(canon) == 0);
        ASSERT(wti_seed(canon, 1) == 0);
        ASSERT(wti_lane(canon, lane) == 0);
        ASSERT(wti_make(dir) == 0);
        ASSERT(snprintf(path, sizeof path, "%s:%s", binpath, saved) < (int)sizeof path);
        ASSERT(setenv("PATH", path, 1) == 0);
        ASSERT(wti_capture(lane, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "[1/3] vendor/lib: copied from ") != NULL);
        ASSERT(strstr(got, "[1b/3] vendor/include: merged from ") != NULL);
        ASSERT(strstr(got, "armed at build/githooks") != NULL);
        ASSERT(strstr(got, "all 10 VENDOR_ARCHIVES present") != NULL);
        ASSERT(strstr(got, "== worktree-init: done ==") != NULL);
        ASSERT(snprintf(path, sizeof path, "%s/vendor/lib/libz.a", lane) > 0);
        ASSERT(access(path, R_OK) == 0);
        ASSERT(snprintf(path, sizeof path, "%s/vendor/include/zlib.h", lane) > 0);
        ASSERT(access(path, R_OK) == 0);
        ASSERT(wti_capture(lane, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "already identical to ") != NULL);
        ASSERT(strstr(got, "vendor/include: already identical -- skipped") != NULL);
        ASSERT(strstr(got, "already armed -- refreshed") != NULL);
        ASSERT(wti_capture(canon, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "vendor/lib: this IS the canonical checkout") != NULL);
        ASSERT(strstr(got, "vendor/include: this IS the canonical checkout") != NULL);
        PASS();
    } _test_next:;
    if (saved[0] != '\0')
        setenv("PATH", saved, 1);
    return failures;
}

static int test_worktree_gap(const char *dir)
{
    int failures = 0;
    const char *old = getenv("PATH");
    char saved[8192];
    saved[0] = '\0';
    if (old != NULL && strlen(old) < sizeof saved)
        memcpy(saved, old, strlen(old) + 1);
    TEST("worktree init: a missing archive fails the link check") {
        char canon[1024];
        char lane[1024];
        char log[1024];
        char got[8192];
        char path[1200];
        int rc = 0;
        ASSERT(saved[0] != '\0');
        ASSERT(snprintf(canon, sizeof canon, "%s/gap-canon", dir) > 0);
        ASSERT(snprintf(lane, sizeof lane, "%s/gap-lane", dir) > 0);
        ASSERT(snprintf(log, sizeof log, "%s/gap.log", dir) > 0);
        ASSERT(wti_git(canon) == 0);
        ASSERT(wti_seed(canon, 0) == 0);
        ASSERT(wti_lane(canon, lane) == 0);
        ASSERT(wti_make(dir) == 0);
        ASSERT(snprintf(path, sizeof path, "%s/bin:%s", dir, saved) < (int)sizeof path);
        ASSERT(setenv("PATH", path, 1) == 0);
        ASSERT(wti_capture(lane, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "missing: vendor/lib/libz.a") != NULL);
        ASSERT(strstr(got, "worktree-init: done") == NULL);
        PASS();
    } _test_next:;
    if (saved[0] != '\0')
        setenv("PATH", saved, 1);
    return failures;
}

int test_worktree_init(void);
int test_worktree_init(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "worktree_init", "root");
    failures = test_worktree_missing_lib(dir);
    failures += test_worktree_copy(dir);
    failures += test_worktree_gap(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_worktree_init: all passed\n");
    else
        printf("test_worktree_init: %d FAILED\n", failures);
    return failures;
}
