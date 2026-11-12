/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_seed_anchor_snapshot: skip, stage, same-size keep, and
 * copy/rename failures. */

#include "test/test_core.h"

#include "seed_anchor_snapshot.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int sa_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

static int sa_mkdir(const char *path)
{
    if (mkdir(path, 0700) == 0)
        return 0;
    return errno == EEXIST ? 0 : -1;
}

static int sa_write(const char *path, const char *bytes, size_t n)
{
    FILE *fp = fopen(path, "wb");
    size_t w;
    if (fp == NULL)
        return -1;
    w = fwrite(bytes, 1, n, fp);
    if (fclose(fp) != 0)
        return -1;
    return w == n ? 0 : -1;
}

static int sa_eq(const char *path, const char *bytes, size_t n)
{
    char buf[256];
    FILE *fp;
    size_t got;
    if (n >= sizeof buf)
        return 0;
    fp = fopen(path, "rb");
    if (fp == NULL)
        return 0;
    got = fread(buf, 1, sizeof buf, fp);
    fclose(fp);
    if (got != n)
        return 0;
    return memcmp(buf, bytes, n) == 0 ? 1 : 0;
}

static int sa_reg(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) ? 1 : 0;
}

static int sa_size(const char *path, unsigned long long *sz)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode) || st.st_size < 0)
        return 0;
    *sz = (unsigned long long)st.st_size;
    return 1;
}

static int sa_capture(const char *log, char *got, size_t cap, int *rc)
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
    *rc = zcl_seed_anchor_snapshot();
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
    got[used] = '\0';
    fclose(file);
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

static int sa_env_save(const char *key, char *buf, size_t cap)
{
    const char *v = getenv(key);
    int n;
    if (v == NULL)
        return 0;
    n = snprintf(buf, cap, "%s", v);
    if (!sa_fit(n, cap))
        return -1;
    return 1;
}

static void sa_env_restore(const char *key, int had, const char *buf)
{
    if (had == 0)
        unsetenv(key);
    else if (had > 0)
        setenv(key, buf, 1);
}

static int test_seed_anchor_absent(const char *dir)
{
    int failures = 0;
    TEST("seed anchor: missing datadir and missing source skip") {
        char dd[1024], src[1024], log[1024], got[2048], want[2048];
        int rc = 0;
        int n;
        n = snprintf(dd, sizeof dd, "%s/no-datadir", dir);
        ASSERT(sa_fit(n, sizeof dd));
        n = snprintf(src, sizeof src, "%s/no-source.snapshot", dir);
        ASSERT(sa_fit(n, sizeof src));
        n = snprintf(log, sizeof log, "%s/absent.log", dir);
        ASSERT(sa_fit(n, sizeof log));
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        ASSERT(setenv("ZCL_ANCHOR_SNAPSHOT_SRC", src, 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] datadir %s absent — skip "
                     "(fresh install mints in-fold)\n",
                     dd);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);

        n = snprintf(dd, sizeof dd, "%s/empty-datadir", dir);
        ASSERT(sa_fit(n, sizeof dd));
        ASSERT(sa_mkdir(dd) == 0);
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] no source snapshot at %s — skip "
                     "(self-mint will produce one on the anchor-crossing fold; "
                     "set ZCL_ANCHOR_SNAPSHOT_SRC to override)\n",
                     src);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);
        n = snprintf(dd, sizeof dd, "%s/empty-datadir/utxo-anchor.snapshot", dir);
        ASSERT(sa_fit(n, sizeof dd));
        ASSERT(sa_reg(dd) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_anchor_stage(const char *dir)
{
    int failures = 0;
    TEST("seed anchor: stage, keep same size, replace a different size") {
        char dd[1024], src[1024], dst[1024], log[1024];
        char got[2048], want[2048];
        int rc = 0;
        int n;
        n = snprintf(dd, sizeof dd, "%s/stage", dir);
        ASSERT(sa_fit(n, sizeof dd));
        n = snprintf(src, sizeof src, "%s/stage/source.snapshot", dir);
        ASSERT(sa_fit(n, sizeof src));
        n = snprintf(dst, sizeof dst, "%s/stage/utxo-anchor.snapshot", dir);
        ASSERT(sa_fit(n, sizeof dst));
        n = snprintf(log, sizeof log, "%s/stage.log", dir);
        ASSERT(sa_fit(n, sizeof log));
        ASSERT(sa_mkdir(dd) == 0);
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        ASSERT(setenv("ZCL_ANCHOR_SNAPSHOT_SRC", src, 1) == 0);
        ASSERT(sa_write(src, "anchor-v1", 9) == 0);

        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(sa_eq(dst, "anchor-v1", 9) == 1);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] staged %s -> %s (size 9). "
                     "The node SHA3-verifies it vs the compiled checkpoint "
                     "on boot before any trust.\n",
                     src, dst);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(sa_write(src, "ANCHOR-V1", 9) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(sa_eq(dst, "anchor-v1", 9) == 1);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] %s already present (size 9) — "
                     "not re-copying\n",
                     dst);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(sa_write(src, "anchor-v1-longer", 16) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(sa_eq(dst, "anchor-v1-longer", 16) == 1);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] staged %s -> %s (size 16). "
                     "The node SHA3-verifies it vs the compiled checkpoint "
                     "on boot before any trust.\n",
                     src, dst);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_anchor_zero(const char *dir)
{
    int failures = 0;
    TEST("seed anchor: a zero-size snapshot is copied again") {
        char dd[1024], src[1024], dst[1024], log[1024], got[2048], want[2048];
        int rc = 0;
        int n;
        n = snprintf(dd, sizeof dd, "%s/zero", dir);
        ASSERT(sa_fit(n, sizeof dd));
        n = snprintf(src, sizeof src, "%s/zero/source.snapshot", dir);
        ASSERT(sa_fit(n, sizeof src));
        n = snprintf(dst, sizeof dst, "%s/zero/utxo-anchor.snapshot", dir);
        ASSERT(sa_fit(n, sizeof dst));
        n = snprintf(log, sizeof log, "%s/zero.log", dir);
        ASSERT(sa_fit(n, sizeof log));
        ASSERT(sa_mkdir(dd) == 0);
        ASSERT(sa_write(src, "", 0) == 0);
        ASSERT(sa_write(dst, "", 0) == 0);
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        ASSERT(setenv("ZCL_ANCHOR_SNAPSHOT_SRC", src, 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(sa_eq(dst, "", 0) == 1);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] staged %s -> %s (size 0). "
                     "The node SHA3-verifies it vs the compiled checkpoint "
                     "on boot before any trust.\n",
                     src, dst);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_anchor_copy_fail(const char *dir)
{
    int failures = 0;
    TEST("seed anchor: copy failure leaves the datadir without a snapshot") {
        char dd[1024], src[1024], dst[1024], tmp[1024];
        char log[1024], got[2048], want[2048];
        int rc = 0;
        int n;
        n = snprintf(dd, sizeof dd, "%s/copy-fail", dir);
        ASSERT(sa_fit(n, sizeof dd));
        n = snprintf(src, sizeof src, "%s/copy-source.snapshot", dir);
        ASSERT(sa_fit(n, sizeof src));
        n = snprintf(dst, sizeof dst, "%s/copy-fail/utxo-anchor.snapshot", dir);
        ASSERT(sa_fit(n, sizeof dst));
        n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", dst, (long)getpid());
        ASSERT(sa_fit(n, sizeof tmp));
        n = snprintf(log, sizeof log, "%s/copy-fail.log", dir);
        ASSERT(sa_fit(n, sizeof log));
        ASSERT(sa_mkdir(dd) == 0);
        ASSERT(sa_mkdir(tmp) == 0);
        ASSERT(sa_write(src, "anchor-v1", 9) == 0);
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        ASSERT(setenv("ZCL_ANCHOR_SNAPSHOT_SRC", src, 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(sa_reg(dst) == 0);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] copy %s -> %s failed — "
                     "skip (non-fatal)\n",
                     src, tmp);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_anchor_rename_fail(const char *dir)
{
    int failures = 0;
    TEST("seed anchor: rename failure removes the temp sibling") {
        char dd[1024], src[1024], dst[1024], tmp[1024];
        char log[1024], got[2048], want[2048];
        int rc = 0;
        int n;
        n = snprintf(dd, sizeof dd, "%s/rename-fail", dir);
        ASSERT(sa_fit(n, sizeof dd));
        n = snprintf(src, sizeof src, "%s/rename-fail/source.snapshot", dir);
        ASSERT(sa_fit(n, sizeof src));
        n = snprintf(dst, sizeof dst, "%s/rename-fail/utxo-anchor.snapshot", dir);
        ASSERT(sa_fit(n, sizeof dst));
        n = snprintf(tmp, sizeof tmp, "%s.tmp.%ld", dst, (long)getpid());
        ASSERT(sa_fit(n, sizeof tmp));
        n = snprintf(log, sizeof log, "%s/rename-fail.log", dir);
        ASSERT(sa_fit(n, sizeof log));
        ASSERT(sa_mkdir(dd) == 0);
        ASSERT(sa_mkdir(dst) == 0);
        ASSERT(sa_write(src, "anchor-v1", 9) == 0);
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        ASSERT(setenv("ZCL_ANCHOR_SNAPSHOT_SRC", src, 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(sa_reg(tmp) == 0);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] rename %s -> %s failed — "
                     "skip (non-fatal)\n",
                     tmp, dst);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);
        PASS();
    } _test_next:;
    return failures;
}

static int test_seed_anchor_defaults(const char *dir)
{
    int failures = 0;
    TEST("seed anchor: HOME datadir, default source, and unset env") {
        char dd[1024], src[1024], def[64], log[1024], got[2048], want[2048];
        int rc = 0;
        int n;
        n = snprintf(log, sizeof log, "%s/defaults.log", dir);
        ASSERT(sa_fit(n, sizeof log));
        n = snprintf(src, sizeof src, "%s/unused.snapshot", dir);
        ASSERT(sa_fit(n, sizeof src));
        n = snprintf(def, sizeof def, "/%s/%s", "tmp", "anchor-ram.snapshot");
        ASSERT(sa_fit(n, sizeof def));
        ASSERT(setenv("HOME", dir, 1) == 0);
        unsetenv("ZCL_DATADIR");
        ASSERT(setenv("ZCL_ANCHOR_SNAPSHOT_SRC", src, 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        n = snprintf(want, sizeof want,
                     "[seed-anchor-snapshot] datadir %s/.zclassic-c23 absent — "
                     "skip (fresh install mints in-fold)\n",
                     dir);
        ASSERT(sa_fit(n, sizeof want));
        ASSERT_STR_EQ(got, want);

        ASSERT(setenv("ZCL_DATADIR", "", 1) == 0);
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, want);

        n = snprintf(dd, sizeof dd, "%s/default-src", dir);
        ASSERT(sa_fit(n, sizeof dd));
        ASSERT(sa_mkdir(dd) == 0);
        ASSERT(setenv("ZCL_DATADIR", dd, 1) == 0);
        unsetenv("ZCL_ANCHOR_SNAPSHOT_SRC");
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        if (sa_reg(def)) {
            unsigned long long src_sz = 0;
            unsigned long long dst_sz = 0;
            char dst[1024];
            ASSERT(sa_size(def, &src_sz) == 1);
            n = snprintf(dst, sizeof dst, "%s/utxo-anchor.snapshot", dd);
            ASSERT(sa_fit(n, sizeof dst));
            n = snprintf(want, sizeof want,
                         "[seed-anchor-snapshot] staged %s -> %s (size %llu). "
                         "The node SHA3-verifies it vs the compiled checkpoint "
                         "on boot before any trust.\n",
                         def, dst, src_sz);
            ASSERT(sa_fit(n, sizeof want));
            ASSERT_STR_EQ(got, want);
            ASSERT(sa_size(dst, &dst_sz) == 1);
            ASSERT(src_sz == dst_sz);
        } else {
            n = snprintf(want, sizeof want,
                         "[seed-anchor-snapshot] no source snapshot at %s — "
                         "skip (self-mint will produce one on the "
                         "anchor-crossing fold; set "
                         "ZCL_ANCHOR_SNAPSHOT_SRC to override)\n",
                         def);
            ASSERT(sa_fit(n, sizeof want));
            ASSERT_STR_EQ(got, want);
        }

        unsetenv("ZCL_DATADIR");
        unsetenv("HOME");
        ASSERT(sa_capture(log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got,
                      "seed-anchor-snapshot: ZCL_DATADIR and HOME are unset\n");
        PASS();
    } _test_next:;
    return failures;
}

int test_seed_anchor_snapshot(void);
int test_seed_anchor_snapshot(void)
{
    char dir[1024];
    char old_home[1024], old_dd[1024], old_src[1024];
    int had_home, had_dd, had_src;
    int failures = 0;
    had_home = sa_env_save("HOME", old_home, sizeof old_home);
    had_dd = sa_env_save("ZCL_DATADIR", old_dd, sizeof old_dd);
    had_src = sa_env_save("ZCL_ANCHOR_SNAPSHOT_SRC", old_src, sizeof old_src);
    test_make_tmpdir(dir, sizeof dir, "seed_anchor_snapshot", "root");
    if (had_home < 0 || had_dd < 0 || had_src < 0) {
        printf("test_seed_anchor_snapshot: env does not fit\n");
        failures = 1;
    } else {
        failures += test_seed_anchor_absent(dir);
        failures += test_seed_anchor_stage(dir);
        failures += test_seed_anchor_zero(dir);
        failures += test_seed_anchor_copy_fail(dir);
        failures += test_seed_anchor_rename_fail(dir);
        failures += test_seed_anchor_defaults(dir);
    }
    sa_env_restore("HOME", had_home, old_home);
    sa_env_restore("ZCL_DATADIR", had_dd, old_dd);
    sa_env_restore("ZCL_ANCHOR_SNAPSHOT_SRC", had_src, old_src);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_seed_anchor_snapshot: all passed\n");
    else
        printf("test_seed_anchor_snapshot: %d FAILED\n", failures);
    return failures;
}
