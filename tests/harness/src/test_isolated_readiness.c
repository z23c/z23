/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_isolated_readiness_selftest against the real isolation
 * library and against a missing jsonq. */

#include "test/test_core.h"

#include "isolated_readiness_selftest.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char k_pass[] =
    "isolated-readiness selftest: PASS typed_rpc=true errors_refused=true "
    "portable_listener=true unobserved_refused=true dead_sink_refused=true\n";

static int rd_capture(const char *env, const char *jsonq, const char *log,
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
    *rc = zcl_isolated_readiness_selftest(env, jsonq);
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

static int test_isolated_readiness_cases(const char *dir)
{
    int failures = 0;
    TEST("isolated readiness: real library passes, missing jsonq refuses") {
        char log[1024];
        char got[4096];
        int rc = 0;
        int n = snprintf(log, sizeof log, "%s/capture.log", dir);
        ASSERT(n > 0 && (size_t)n < sizeof log);
        ASSERT(rd_capture("tools/scripts/isolated_node_env.sh",
                          "build/bin/jsonq", log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_pass);
        ASSERT(rd_capture("tools/scripts/isolated_node_env.sh",
                          "build/bin/jsonq-missing", log, got, sizeof got,
                          &rc) == 0);
        ASSERT(rc != 0);
        ASSERT(strstr(got, "readiness selftest requires make jsonq") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_isolated_readiness(void);
int test_isolated_readiness(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "isolated_readiness", "root");
    failures = test_isolated_readiness_cases(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_isolated_readiness: all passed\n");
    else
        printf("test_isolated_readiness: %d FAILED\n", failures);
    return failures;
}
