/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_zcode_async_proof_perf_selftest against the shipped report
 * script and against a stub that cannot account the synthetic logs. */

#include "test/test_core.h"

#include "zcode_async_proof_perf_selftest.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char k_pass[] =
    "proof-perf-report-selftest: PASS (boundary, missing, zero, retries, "
    "invalid, wide values, complete accounting)\n";

static int pp_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

static int pp_write(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    size_t n;
    size_t wrote;
    if (fp == NULL)
        return -1;
    n = strlen(text);
    wrote = fwrite(text, 1, n, fp);
    if (fclose(fp) != 0)
        return -1;
    return wrote == n ? 0 : -1;
}

static int pp_capture(const char *report, const char *log, char *got,
                      size_t cap, int *rc)
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
    *rc = zcl_zcode_async_proof_perf_selftest(report);
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

static int pp_save(const char *key, char *buf, size_t cap)
{
    const char *v = getenv(key);
    int n;
    if (v == NULL)
        return 0;
    n = snprintf(buf, cap, "%s", v);
    if (!pp_fit(n, cap))
        return -1;
    return 1;
}

static void pp_restore(const char *key, int had, const char *buf)
{
    if (had == 0)
        unsetenv(key);
    else if (had > 0)
        setenv(key, buf, 1);
}

static int test_perf_report_cases(const char *dir)
{
    int failures = 0;
    TEST("proof perf report: real script passes, a stub refuses") {
        char stub[1024];
        char log[1024];
        char got[4096];
        int rc = 0;
        int n;
        n = snprintf(stub, sizeof stub, "%s/stub.sh", dir);
        ASSERT(pp_fit(n, sizeof stub));
        n = snprintf(log, sizeof log, "%s/capture.log", dir);
        ASSERT(pp_fit(n, sizeof log));
        ASSERT(pp_write(stub, "exit 0\n") == 0);
        unsetenv("ZCL_PERF_REPORT_UNDER_TEST");

        ASSERT(pp_capture("tools/dev/zcode_async_proof_perf_report.sh", log,
                          got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_pass);

        ASSERT(setenv("ZCL_PERF_REPORT_UNDER_TEST", stub, 1) == 0);
        ASSERT(pp_capture("tools/dev/zcode_async_proof_perf_report.sh", log,
                          got, sizeof got, &rc) == 0);
        ASSERT(rc != 0);
        ASSERT(strstr(got, "proof-perf-report-selftest: PASS") == NULL);

        unsetenv("ZCL_PERF_REPORT_UNDER_TEST");
        ASSERT(pp_capture(stub, log, got, sizeof got, &rc) == 0);
        ASSERT(rc != 0);
        ASSERT(strstr(got, "proof-perf-report-selftest: PASS") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_async_proof_perf_selftest(void);
int test_zcode_async_proof_perf_selftest(void)
{
    char dir[1024];
    char old[1024];
    int had;
    int failures;
    had = pp_save("ZCL_PERF_REPORT_UNDER_TEST", old, sizeof old);
    test_make_tmpdir(dir, sizeof dir, "zcode_async_proof_perf", "root");
    if (had < 0) {
        printf("test_zcode_async_proof_perf_selftest: env does not fit\n");
        failures = 1;
    } else {
        failures = test_perf_report_cases(dir);
    }
    pp_restore("ZCL_PERF_REPORT_UNDER_TEST", had, old);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_zcode_async_proof_perf_selftest: all passed\n");
    else
        printf("test_zcode_async_proof_perf_selftest: %d FAILED\n", failures);
    return failures;
}
