/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_fleet_source_status_selftest against the real classifier
 * library and against a missing library. */

#include "test/test_core.h"

#include "fleet_source_status_selftest.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fss_capture(const char *library, const char *log, char *got, size_t cap, int *rc)
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
    *rc = zcl_fleet_source_status_selftest(library);
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

static int fss_oks(const char *text)
{
    int n = 0;
    const char *p = text;
    while ((p = strstr(p, "  ok: ")) != NULL) {
        n++;
        p += 6;
    }
    return n;
}

static int test_fleet_source_missing(const char *dir)
{
    int failures = 0;
    TEST("fleet source status: a missing library is refused") {
        char log[1024];
        char got[2048];
        int rc = 0;
        ASSERT(snprintf(log, sizeof log, "%s/missing.log", dir) > 0);
        ASSERT(fss_capture("build/bin/fleet-source-missing.sh", log, got,
                           sizeof got, &rc) == 0);
        ASSERT(rc != 0);
        ASSERT(strstr(got, "check_fleet_source_status: FAIL") != NULL);
        ASSERT(strstr(got, "check_fleet_source_status: PASS") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_source_live(const char *dir)
{
    int failures = 0;
    TEST("fleet source status: the real classifier matches the fixture") {
        char log[1024];
        char got[4096];
        int rc = 1;
        ASSERT(access("tools/scripts/fleet_source_status.sh", R_OK) == 0);
        ASSERT(snprintf(log, sizeof log, "%s/live.log", dir) > 0);
        ASSERT(fss_capture("tools/scripts/fleet_source_status.sh", log, got,
                           sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(fss_oks(got) == 20);
        ASSERT(strstr(got, "  ok: utc_z_normalized\n") != NULL);
        ASSERT(strstr(got, "  ok: direct_git_behind\n") != NULL);
        ASSERT(strstr(got, "  ok: nonancestor_detail\n") != NULL);
        ASSERT(strstr(got, "  ok: prefloor_flag\n") != NULL);
        ASSERT(strstr(got, "check_fleet_source_status: PASS\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_source_status(void);
int test_fleet_source_status(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "fleet_source_status", "root");
    failures = test_fleet_source_missing(dir);
    failures += test_fleet_source_live(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_fleet_source_status: all passed\n");
    else
        printf("test_fleet_source_status: %d FAILED\n", failures);
    return failures;
}
