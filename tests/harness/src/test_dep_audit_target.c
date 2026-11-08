/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Verify target-scoped dependency audit evidence and refusal. */
#include "test/test_core.h"
#include <stdio.h>
#ifndef _WIN32
#define main z23_test_dep_audit_entry
#include "../../../tools/dep_audit.c"
#undef main
#include <sys/wait.h>
#include <fcntl.h>

static bool dat_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    if (fclose(f) != 0) ok = false;
    return ok && chmod(path, mode) == 0;
}
static bool dat_dir(const char *path) { return mkdir(path, 0700) == 0; }
static bool dat_versions(const char *root, const char *target, bool valid)
{
    char p[PATH_MAX], lib[PATH_MAX], inc[PATH_MAX];
    int n = snprintf(lib, sizeof(lib), "%s/vendor/%slib", root, target);
    int m = snprintf(inc, sizeof(inc), "%s/vendor/%sinclude", root, target);
    if (n < 0 || m < 0 || (size_t)n >= sizeof(lib) || (size_t)m >= sizeof(inc) || !dat_dir(lib) || !dat_dir(inc)) return false;
#define DAT_FILE(dir, leaf, body) do { \
    int z = snprintf(p, sizeof(p), "%s/%s", dir, leaf); \
    if (z < 0 || (size_t)z >= sizeof(p) || !dat_write(p, body, 0600)) return false; \
} while (0)
    DAT_FILE(lib, "libcrypto.a", valid ? "OpenSSL 3.1.0\n" : "OpenSSL 1.0.0\n");
    DAT_FILE(lib, "libevent.a", "2.1.12-stable\n");
    DAT_FILE(lib, "libz.a", "deflate 1.3.1\n");
    DAT_FILE(inc, "sqlite3.h", "#define SQLITE_VERSION \"3.46.0\"\n");
#undef DAT_FILE
    return true;
}
static int dat_run(const char *root, const char *target, const char *archive)
{
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (chdir(root) != 0) _exit(90);
        if (target) { if (setenv("VENDOR_TARGET", target, 1)) _exit(91); }
        else if (unsetenv("VENDOR_TARGET")) _exit(91);
        if (archive) { if (setenv("NODE_SECP_ARCHIVE", archive, 1)) _exit(91); }
        else if (unsetenv("NODE_SECP_ARCHIVE")) _exit(91);
        int fd = open("audit-output", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) _exit(92);
        close(fd);
        char *argv[] = {"dep_audit", "--json", NULL};
        int result = z23_test_dep_audit_entry(2, argv);
        fflush(NULL);
        _exit(result);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
static bool dat_output_contains(const char *root, const char *text)
{
    char p[PATH_MAX];
    int n = snprintf(p, sizeof(p), "%s/audit-output", root);
    if (n < 0 || (size_t)n >= sizeof(p)) return false;
    size_t len = 0; unsigned char *bytes = read_regular(p, &len);
    bool ok = bytes && strstr((const char *)bytes, text);
    free(bytes);
    return ok;
}
static bool dat_fixture(const char *root)
{
    char p[PATH_MAX];
#define DAT_DIR(leaf) do { \
    int n = snprintf(p, sizeof(p), "%s/%s", root, leaf); \
    if (n < 0 || (size_t)n >= sizeof(p) || !dat_dir(p)) return false; \
} while (0)
    DAT_DIR("tools"); DAT_DIR("tools/scripts"); DAT_DIR("vendor"); DAT_DIR("vendor/cross");
    DAT_DIR("vendor/cross/aarch64-linux-android24");
    if (!dat_versions(root, "", true) || !dat_versions(root, "cross/aarch64-linux-android24/", true)) return false;
    DAT_DIR("vendor/lib/.provenance");
#undef DAT_DIR
    snprintf(p, sizeof(p), "%s/vendor/lib/.provenance/libleveldb.a.stamp", root);
    if (!dat_write(p, "version=1.23\n", 0600)) return false;
    snprintf(p, sizeof(p), "%s/tools/scripts/build_vendor.sh", root);
    return dat_write(p, "#!/bin/sh\ncase \"$VENDOR_TARGET:$2\" in\n"
        "  :|:libsecp256k1.a|aarch64-linux-android24:|aarch64-linux-android24:libsecp256k1-android.a) exit 0;;\n"
        "  *) exit 1;;\nesac\n", 0700);
}
int test_dep_audit_target(void)
{
    int failures = 0;
    char root[256], absolute[PATH_MAX];
    test_make_tmpdir(root, sizeof(root), "dep_audit", "target");
    if (!test_abs_path(root, absolute, sizeof(absolute))) return 1;
    bool ok = dat_fixture(absolute);
    TEST("dependency audit selects target evidence and fails closed") {
        ASSERT(ok);
        ASSERT(dat_run(absolute, NULL, NULL) == 0);
        ASSERT(dat_run(absolute, "aarch64-linux-android24", "libsecp256k1-android.a") == 0);
        ASSERT(dat_output_contains(absolute, "target archive provenance verified"));
        ASSERT(dat_output_contains(absolute, "not linked by cross node"));
        ASSERT(dat_run(absolute, "aarch64-linux-android24", NULL) == 1);
        ASSERT(dat_run(absolute, "../invalid", "libsecp256k1-android.a") == 1);
        ASSERT(dat_run(absolute, "aarch64-linux-android24", "../bad.a") == 1);
        ASSERT(dat_run(absolute, "aarch64-linux-android24", "libsecp256k1-darwin.a") == 1);
        ASSERT(dat_run(absolute, "aarch64-linux-android24", "libsecp256k1.a") == 1);
        char file[PATH_MAX];
        snprintf(file, sizeof(file), "%s/vendor/cross/aarch64-linux-android24/lib/libcrypto.a", absolute);
        ASSERT(dat_write(file, "OpenSSL 1.0.0\n", 0600));
        ASSERT(dat_run(absolute, "aarch64-linux-android24", "libsecp256k1-android.a") == 1);
        ASSERT(unlink(file) == 0);
        ASSERT(dat_run(absolute, "aarch64-linux-android24", "libsecp256k1-android.a") == 1);
        ASSERT(dat_run(absolute, NULL, NULL) == 0);
        PASS();
    } _test_next:;
    test_rm_rf(root);
    return failures;
}
#else
int test_dep_audit_target(void)
{
    printf("dep_audit_target: SKIP (Windows): fixture requires POSIX fork and executable scripts.\n");
    return 0;
}
#endif
