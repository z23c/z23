/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_sovereign_source_identity_selftest against the checkout's
 * source-identity.sh and against a script that is not that adapter. */

#include "test/test_core.h"

#include "sovereign_source_identity_selftest.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char k_ssi_pass[] =
    "sovereign-source-identity-selftest: PASS root="
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
    "git_contacted=false aba_refused=true\n";

static int ssi_capture(const char *script, const char *log, char *got,
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
    *rc = zcl_sovereign_source_identity_selftest(script);
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

static int test_sovereign_source_identity_cases(const char *dir)
{
    int failures = 0;
    TEST("sovereign source identity: real adapter and a non-adapter") {
        char log[1024];
        char got[1024];
        int rc = 0;
        int n = snprintf(log, sizeof log, "%s/capture.out", dir);
        ASSERT(n > 0);
        ASSERT(n < (int)sizeof log);
        ASSERT(ssi_capture("tools/dev/source-identity.sh", log, got, sizeof got,
                           &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_ssi_pass);
        ASSERT(ssi_capture("/bin/true", log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(got, "sovereign-source-identity-selftest: FAIL: "
                           "capture did not use ZVCS authority\n") == got);
        PASS();
    } _test_next:;
    return failures;
}

int test_sovereign_source_identity(void);
int test_sovereign_source_identity(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "sovereign_source_identity", "root");
    failures = test_sovereign_source_identity_cases(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_sovereign_source_identity: all passed\n");
    else
        printf("test_sovereign_source_identity: %d FAILED\n", failures);
    return failures;
}
