/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_build_epoch_integrity through a miss, a cache hit,
 *          a changed input, and a fail-open key. */

#include "test/test_core.h"
#include "test/host_tool_capture.h"

#include "build_epoch_integrity.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static int bei_put(const char *path, const char *text, int exec_bit)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(text, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    if (exec_bit && chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int bei_layout(const char *root)
{
    static const char *const dirs[] = {"tools", "tools/dev", "build", "build/bin"};
    size_t i;
    for (i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "%s/%s", root, dirs[i]) >= (int)sizeof path)
            return -1;
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return -1;
    }
    return 0;
}

static int bei_files(const char *root)
{
    size_t i;
    for (i = 0; i < sizeof k_rels / sizeof k_rels[0]; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "%s/%s", root, k_rels[i]) >= (int)sizeof path)
            return -1;
        if (bei_put(path, "# seed\n", 0) != 0)
            return -1;
    }
    return 0;
}

static int bei_stubs(const char *root, const char *marker, int fail)
{
    char path[PATH_MAX];
    char body[PATH_MAX];
    const char *key =
        "#!/bin/sh\n"
        "printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n'\n";
    if (snprintf(path, sizeof path, "%s/tools/dev/build-epoch-key.sh", root) >= (int)sizeof path)
        return -1;
    if (bei_put(path, key, 1) != 0)
        return -1;
    if (snprintf(body, sizeof body,
                 "#!/bin/sh\nprintf 'probe-build\\n'\nprintf 'b\\n' >> '%s.b'\nexit %d\n",
                 marker, fail) >= (int)sizeof body)
        return -1;
    if (snprintf(path, sizeof path, "%s/tools/dev/build-epoch-selftest.sh", root) >= (int)sizeof path)
        return -1;
    if (bei_put(path, body, 1) != 0)
        return -1;
    if (snprintf(body, sizeof body,
                 "#!/bin/sh\nprintf 'probe-depfile\\n'\nprintf 'd\\n' >> '%s.d'\nexit %d\n",
                 marker, fail) >= (int)sizeof body)
        return -1;
    if (snprintf(path, sizeof path, "%s/build/bin/depfile-scope-launch", root) >= (int)sizeof path)
        return -1;
    return bei_put(path, body, 1);
}

static int bei_is(const char *path, const char *want)
{
    char buf[32];
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return 0;
    n = fread(buf, 1, sizeof buf - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return strcmp(buf, want) == 0;
}

static int bei_capture(const char *scratch, const char *repo,
                       char *out, size_t out_cap, char *err, size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int saved_out = -1;
    int saved_err = -1;
    int fd_out = -1;
    int fd_err = -1;
    int rc;
    if (snprintf(out_path, sizeof out_path, "%s/stdout.txt", scratch) >= (int)sizeof out_path)
        return -1;
    if (snprintf(err_path, sizeof err_path, "%s/stderr.txt", scratch) >= (int)sizeof err_path)
        return -1;
    fflush(stdout);
    fflush(stderr);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (saved_out < 0 || saved_err < 0 || fd_out < 0 || fd_err < 0)
        goto fail;
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = zcl_build_epoch_integrity(repo);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    {
        FILE *fp = fopen(out_path, "r");
        size_t n;
        if (fp == NULL)
            return -1;
        n = fread(out, 1, out_cap - 1, fp);
        fclose(fp);
        out[n] = '\0';
        fp = fopen(err_path, "r");
        if (fp == NULL)
            return -1;
        n = fread(err, 1, err_cap - 1, fp);
        fclose(fp);
        err[n] = '\0';
    }
    return rc;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd_out >= 0)
        close(fd_out);
    if (fd_err >= 0)
        close(fd_err);
    return -1;
}

static int test_bei_usage(const char *root)
{
    int failures = 0;
    char out[64];
    char err[256];
    int rc;
    TEST("a missing checkout is refused") {
        rc = bei_capture(root, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, "build-epoch-integrity: repo is required\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_bei_hit(const char *root)
{
    int failures = 0;
    char repo[PATH_MAX];
    char marker[PATH_MAX];
    char verdict[PATH_MAX];
    char out[1024];
    char err[1024];
    char side[PATH_MAX];
    int rc;
    TEST("a second run with the same inputs skips the probes") {
        ASSERT(snprintf(repo, sizeof repo, "%s/hit", root) > 0);
        ASSERT(mkdir(repo, 0700) == 0);
        ASSERT(bei_layout(repo) == 0);
        ASSERT(bei_files(repo) == 0);
        ASSERT(snprintf(marker, sizeof marker, "%s/marker", repo) > 0);
        ASSERT(bei_stubs(repo, marker, 0) == 0);
        rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(err, "cache MISS") != NULL);
        ASSERT(strstr(out, "probe-build\n") != NULL);
        ASSERT(strstr(out, "probe-depfile\n") != NULL);
        ASSERT(strstr(out, "probe-build\n") < strstr(out, "probe-depfile\n"));
        ASSERT(snprintf(verdict, sizeof verdict,
                        "%s/.cache/build-epoch-integrity/verdict.key", repo) > 0);
        {
            struct stat st;
            ASSERT(stat(verdict, &st) == 0);
        }
        rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "build-epoch-selftest: PASS (cached;") != NULL);
        ASSERT(strstr(out, "make-depfile-scope-selftest: PASS (cached;") != NULL);
        ASSERT(strstr(out, repo) != NULL);
        ASSERT(strstr(out, "probe-build\n") == NULL);
        ASSERT(snprintf(side, sizeof side, "%s.b", marker) > 0);
        ASSERT(bei_is(side, "b\n"));
        ASSERT(snprintf(side, sizeof side, "%s.d", marker) > 0);
        ASSERT(bei_is(side, "d\n"));
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_bei_change(const char *root)
{
    int failures = 0;
    char repo[PATH_MAX];
    char marker[PATH_MAX];
    char make_path[PATH_MAX];
    char out[1024];
    char err[1024];
    int rc;
    TEST("a changed key input runs the probes again") {
        ASSERT(snprintf(repo, sizeof repo, "%s/change", root) > 0);
        ASSERT(mkdir(repo, 0700) == 0);
        ASSERT(bei_layout(repo) == 0);
        ASSERT(bei_files(repo) == 0);
        ASSERT(snprintf(marker, sizeof marker, "%s/marker", repo) > 0);
        ASSERT(bei_stubs(repo, marker, 0) == 0);
        rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(snprintf(make_path, sizeof make_path, "%s/Makefile", repo) > 0);
        ASSERT(bei_put(make_path, "# changed\n", 0) == 0);
        ASSERT(snprintf(make_path, sizeof make_path, "%s.b", marker) > 0);
        unlink(make_path);
        ASSERT(snprintf(make_path, sizeof make_path, "%s.d", marker) > 0);
        unlink(make_path);
        rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(err, "cache MISS") != NULL);
        ASSERT(strstr(out, "probe-build\n") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_bei_open(const char *root)
{
    int failures = 0;
    char repo[PATH_MAX];
    char marker[PATH_MAX];
    char key[PATH_MAX];
    char verdict[PATH_MAX];
    char out[1024];
    char err[1024];
    struct stat st;
    int rc;
    TEST("a bad compiler id does not trust a previous cache") {
        ASSERT(snprintf(repo, sizeof repo, "%s/open", root) > 0);
        ASSERT(mkdir(repo, 0700) == 0);
        ASSERT(bei_layout(repo) == 0);
        ASSERT(bei_files(repo) == 0);
        ASSERT(snprintf(marker, sizeof marker, "%s/marker", repo) > 0);
        ASSERT(bei_stubs(repo, marker, 0) == 0);
        rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(snprintf(key, sizeof key, "%s/tools/dev/build-epoch-key.sh", repo) > 0);
        ASSERT(bei_stubs(repo, marker, 1) == 0);
        ASSERT(bei_put(key, "#!/bin/sh\nprintf 'nope\\n'\n", 1) == 0);
        rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "cache key unavailable") != NULL);
        ASSERT(snprintf(verdict, sizeof verdict,
                        "%s/.cache/build-epoch-integrity/verdict.key", repo) > 0);
        ASSERT(stat(verdict, &st) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_bei_input_hash_failure(const char *root)
{
    int failures = 0;
    TEST("build-system-id refuses a failed input hash without emitting an identity") {
        char shim[PATH_MAX], hit[PATH_MAX], path_env[2 * PATH_MAX], out[128];
        const char *path = getenv("PATH");
        ASSERT(path != NULL);
        int n = snprintf(path_env, sizeof path_env, "PATH=%s:%s", root, path);
        ASSERT(n > 0 && (size_t)n < sizeof path_env);
        n = snprintf(shim, sizeof shim, "%s/sha256sum", root);
        ASSERT(n > 0 && (size_t)n < sizeof shim);
        n = snprintf(hit, sizeof hit, "%s.hit", shim);
        ASSERT(n > 0 && (size_t)n < sizeof hit);
        ASSERT_EQ(bei_put(shim, "#!/bin/sh\n"
            "if mkdir \"$0.hit\" 2>/dev/null; then exit 1; fi\n"
            "PATH=${PATH#*:}; export PATH\nexec sha256sum \"$@\"\n", 1), 0);
        const char *argv[] = {"env", path_env, "bash", "tools/dev/build-epoch-key.sh",
                              "build-system-id", NULL};
        ASSERT_EQ(test_host_tool_capture(argv, out, sizeof out, 30000), 2);
        ASSERT(access(hit, F_OK) == 0);
        ASSERT_STR_EQ(out, "");
        PASS();
    }
    _test_next:;
    return failures;
}

#if defined(__APPLE__)
static long bei_spawn_count(const char *path)
{
    FILE *fp = fopen(path, "r");
    long n;
    if (fp == NULL)
        return 0;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    n = ftell(fp);
    fclose(fp);
    return n < 0 ? 0 : n;
}

static int bei_arm_sha_trap(const char *root, char *repo, size_t repo_cap,
                            char *saved, size_t saved_cap)
{
    char marker[PATH_MAX];
    char shim[PATH_MAX];
    char path_env[PATH_MAX];
    const char *path = getenv("PATH");
    if (path == NULL || strlen(path) + 1 > saved_cap)
        return -1;
    memcpy(saved, path, strlen(path) + 1);
    if (snprintf(repo, repo_cap, "%s/nosha", root) >= (int)repo_cap)
        return -1;
    if (mkdir(repo, 0700) != 0 || bei_layout(repo) != 0 || bei_files(repo) != 0)
        return -1;
    if (snprintf(marker, sizeof marker, "%s/spawn", repo) >= (int)sizeof marker)
        return -1;
    if (bei_stubs(repo, marker, 0) != 0)
        return -1;
    if (snprintf(shim, sizeof shim, "%s/sha256sum", repo) >= (int)sizeof shim)
        return -1;
    if (bei_put(shim,
                "#!/bin/sh\nprintf x >> \"$ZCL_BEI_SPAWN\"\n"
                "PATH=${PATH#*:}\nexport PATH\nexec sha256sum \"$@\"\n",
                1) != 0)
        return -1;
    if (snprintf(path_env, sizeof path_env, "%s:%s", repo, saved) >= (int)sizeof path_env)
        return -1;
    if (setenv("ZCL_BEI_SPAWN", marker, 1) != 0 || setenv("PATH", path_env, 1) != 0)
        return -1;
    return 0;
}

/* The cache key must be hashed without launching sha256sum. */
static int test_bei_no_sha256sum(const char *root)
{
    char repo[PATH_MAX];
    char saved[PATH_MAX];
    char marker[PATH_MAX];
    char out[1024];
    char err[1024];
    long spawn;
    int rc;
    int miss;
    if (bei_arm_sha_trap(root, repo, sizeof repo, saved, sizeof saved) != 0)
        return 1;
    rc = bei_capture(root, repo, out, sizeof out, err, sizeof err);
    if (setenv("PATH", saved, 1) != 0)
        return 1;
    unsetenv("ZCL_BEI_SPAWN");
    if (snprintf(marker, sizeof marker, "%s/spawn", repo) >= (int)sizeof marker)
        return 1;
    spawn = bei_spawn_count(marker);
    miss = strstr(err, "cache MISS") != NULL;
    printf("epoch_hash: status=%d miss=%d spawn=%ld\n", rc, miss, spawn);
    if (rc != 0 || !miss || spawn != 0)
        return 1;
    return 0;
}
#else
static int test_bei_no_sha256sum(const char *root)
{
    (void)root;
    printf("epoch_hash: skip\n");
    return 0;
}
#endif

static int test_bei_key_stream(const char *root)
{
    static const char digest[] = "7d8ad353438cfe346217501b5f605281724d1b51746608e8f1f10ec5668427f5";
    static const char expected[] = "7d8ad353438cfe346217501b5f605281724d1b51746608e8f1f10ec5668427f5\n";
    static const char compiler[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char system_id[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    int failures = 0;
    TEST("key streams its exact v3 vector and refuses bad hashes") {
        char out[128], dir[PATH_MAX], shim[PATH_MAX], path_env[2 * PATH_MAX];
        const char *path = getenv("PATH");
        ASSERT(path != NULL);
        int n = snprintf(dir, sizeof dir, "%s/key-bin", root);
        ASSERT(n > 0 && (size_t)n < sizeof dir);
        ASSERT(mkdir(dir, 0700) == 0);
        n = snprintf(shim, sizeof shim, "%s/sha256sum", dir);
        ASSERT(n > 0 && (size_t)n < sizeof shim);
        n = snprintf(path_env, sizeof path_env, "PATH=%s:%s", dir, path);
        ASSERT(n > 0 && (size_t)n < sizeof path_env);
        const char *args[] = {"env", "TMPDIR=/dev/null", "bash", "tools/dev/build-epoch-key.sh",
                              "key", compiler, "vector", "-O2", "-pthread", system_id, NULL};
        /* Independent OpenSSL SHA-256 of the NUL-delimited v3 vector. */
        ASSERT_EQ(test_host_tool_capture(args, out, sizeof out, 30000), 0);
        ASSERT_STR_EQ(out, expected);
        const char *stub_args[] = {"env", path_env, "bash", "tools/dev/build-epoch-key.sh",
                                   "key", compiler, "vector", "-O2", "-pthread", system_id, NULL};
        char stub[256];
        n = snprintf(stub, sizeof stub, "#!/bin/sh\ncat >/dev/null || exit 1\nprintf '%%s *-\\n' '%s'\n", digest);
        ASSERT(n > 0 && (size_t)n < sizeof stub);
        ASSERT_EQ(bei_put(shim, stub, 1), 0);
        ASSERT_EQ(test_host_tool_capture(stub_args, out, sizeof out, 30000), 0);
        ASSERT_STR_EQ(out, expected);
        ASSERT_EQ(bei_put(shim, "#!/bin/sh\ncat >/dev/null || exit 1\nprintf '%064d  -\\n' 0\nexit 1\n", 1), 0);
        ASSERT_EQ(test_host_tool_capture(stub_args, out, sizeof out, 30000), 2);
        ASSERT_STR_EQ(out, "");
        ASSERT_EQ(bei_put(shim, "#!/bin/sh\ncat >/dev/null || exit 1\nprintf 'malformed\\n'\n", 1), 0);
        ASSERT_EQ(test_host_tool_capture(stub_args, out, sizeof out, 30000), 2);
        ASSERT_STR_EQ(out, "");
        PASS();
    }
    _test_next:;
    return failures;
}

int test_build_epoch_integrity(void);
int test_build_epoch_integrity(void)
{
    char root[PATH_MAX];
    int failures = 0;
    unsetenv("ZCL_BUILD_EPOCH_CACHE_DIR");
    test_make_tmpdir(root, sizeof root, "build_epoch_integrity", "root");
    failures += test_bei_usage(root);
    failures += test_bei_hit(root);
    failures += test_bei_change(root);
    failures += test_bei_open(root);
    failures += test_bei_input_hash_failure(root);
    failures += test_bei_no_sha256sum(root);
    failures += test_bei_key_stream(root);
    if (failures == 0)
        printf("test_build_epoch_integrity: all passed\n");
    else
        printf("test_build_epoch_integrity: %d FAILED\n", failures);
    return failures;
}
