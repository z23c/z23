/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_checkout_lock_selftest against this checkout. */

#include "test/test_core.h"

#include "checkout_lock_selftest.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int cls_capture(const char *repo, char *out, size_t out_cap, char *err, size_t err_cap)
{
    char out_path[] = "cls-out";
    char err_path[] = "cls-err";
    int fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *fp;
    size_t n;
    int rc;
    if (fd_out < 0 || fd_err < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = zcl_checkout_lock_selftest(repo);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    fp = fopen(out_path, "r");
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
    unlink(out_path);
    unlink(err_path);
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

int test_checkout_lock_selftest(void);
int test_checkout_lock_selftest(void)
{
    char root[PATH_MAX];
    char out[1024];
    char err[2048];
    int failures = 0;
    int rc;
    TEST("the checkout lock selftest passes on this checkout") {
        ASSERT(getcwd(root, sizeof root) != NULL);
        rc = cls_capture(NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "repo is required") != NULL);
        rc = cls_capture(root, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out,
                      "checkout-lock-selftest: PASS uncontended=true watcher_defers=true "
                      "foreground_blocks=true nested_no_deadlock=true releases_on_failure=true "
                      "fast_ci_serialized=true build_and_run_serialized=true "
                      "inner_bypass_refused=true\n") == out);
        ASSERT_STR_EQ(err, "");
        PASS();
    }
    _test_next:;
    return failures;
}
