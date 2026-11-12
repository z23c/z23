/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_native_dev_loop_wait_selftest against the built dev binary. */

#include "test/test_core.h"

#include "native_dev_loop_wait_selftest.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int ndw_capture(const char *bin, const char *root, const char *log,
                       char *got, size_t cap, int *rc)
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
    *rc = zcl_native_dev_loop_wait_selftest(bin, root);
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

static int test_native_dev_loop_missing(const char *dir)
{
    int failures = 0;
    TEST("native dev loop wait: a missing dev binary is refused") {
        char log[1024];
        char got[2048];
        int rc = 0;
        ASSERT(snprintf(log, sizeof log, "%s/missing.log", dir) > 0);
        ASSERT(ndw_capture("build/bin/native-dev-loop-missing", ".", log, got,
                           sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(got, "native-dev-loop-wait-selftest: missing dev binary:") != NULL);
        ASSERT(strstr(got, "native-dev-loop-wait-selftest: PASS") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_dev_loop_live(const char *dir)
{
    int failures = 0;
    TEST("native dev loop wait: the dev binary returns the sealed verdict") {
        char log[1024];
        char got[4096];
        int rc = 1;
        ASSERT(access("build/bin/zclassic23-dev", X_OK) == 0);
        ASSERT(snprintf(log, sizeof log, "%s/live.log", dir) > 0);
        ASSERT(ndw_capture("build/bin/zclassic23-dev", ".", log, got, sizeof got,
                           &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(got, "native-dev-loop-wait-selftest: PASS\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_native_dev_loop_wait(void);
int test_native_dev_loop_wait(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "native_dev_loop_wait", "root");
    failures = test_native_dev_loop_missing(dir);
    failures += test_native_dev_loop_live(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_native_dev_loop_wait: all passed\n");
    else
        printf("test_native_dev_loop_wait: %d FAILED\n", failures);
    return failures;
}
