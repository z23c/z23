/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_repro_network_policy against fixture Makefiles and the
 *          checkout's repro-verify script. */

#include "test/test_core.h"

#include "repro_network_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char k_block[] =
    "ZCL_NETWORK_DENIED_BUILD_GOALS := ci-reproducible repro-verify\n"
    "ifneq ($(strip $(filter $(ZCL_NETWORK_DENIED_BUILD_GOALS),$(MAKECMDGOALS))),)\n"
    "override ZCL_VENDOR_OFFLINE := 1\n"
    "override ZCL_USE_CCACHE := 0\n"
    "export ZCL_VENDOR_OFFLINE\n"
    "export ZCL_USE_CCACHE\n"
    "endif\n";

static int rnp_put(const char *path, const char *text)
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
    return 0;
}

static int rnp_mkdir_at(const char *dir, const char *rel)
{
    char path[PATH_MAX];
    size_t n;
    size_t i;
    if (snprintf(path, sizeof path, "%s/%s", dir, rel) >= (int)sizeof path)
        return -1;
    n = strlen(path);
    for (i = 1; i < n; i++) {
        if (path[i] != '/')
            continue;
        path[i] = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return -1;
        path[i] = '/';
    }
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rnp_capture(const char *scratch, const char *repo, char *out, size_t out_cap,
                       char *err, size_t err_cap)
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
    rc = zcl_repro_network_policy(repo);
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

static int rnp_case(const char *root, const char *tag, const char *make, char *dir, size_t cap)
{
    char path[PATH_MAX];
    if (snprintf(dir, cap, "%s/%s", root, tag) >= (int)cap)
        return -1;
    if (mkdir(dir, 0700) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/Makefile", dir) >= (int)sizeof path)
        return -1;
    return rnp_put(path, make);
}

static int test_rnp_repo(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[512];
    char err2[512];
    int rc;
    TEST("a missing repo is refused") {
        ASSERT(rnp_case(root, "repo", "all:\n", dir, sizeof dir) == 0);
        rc = rnp_capture(dir, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(out, "");
        ASSERT_STR_EQ(err, "repro_network_policy_selftest: FAIL: repo is required\n");
        rc = rnp_capture(dir, "", out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_order(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char body[1024];
    char out[64];
    char err[512];
    char err2[512];
    int rc;
    TEST("policy order is refused when cache or the vendor barrier comes first") {
        ASSERT(snprintf(body, sizeof body, "ZCL_USE_CCACHE ?= 1\n%sVENDOR_BOOTSTRAP_MK := build/x\n",
                        k_block) > 0);
        ASSERT(rnp_case(root, "cache", body, dir, sizeof dir) == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err,
                      "repro_network_policy_selftest: FAIL: Make hermetic policy is defined "
                      "after compiler-cache selection\n");
        rc = rnp_capture(dir, dir, out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        ASSERT(snprintf(body, sizeof body,
                        "VENDOR_BOOTSTRAP_MK := build/x\n%sZCL_USE_CCACHE ?= 1\n", k_block) > 0);
        ASSERT(rnp_case(root, "barrier", body, dir, sizeof dir) == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err,
                      "repro_network_policy_selftest: FAIL: Make offline policy is defined "
                      "after the vendor parse barrier\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_caller(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char body[1024];
    char out[64];
    char err[512];
    int rc;
    TEST("a permissive caller value does not survive the parse barrier") {
        ASSERT(snprintf(body, sizeof body,
                        "%s"
                        "ZCL_USE_CCACHE ?= 1\n"
                        "VENDOR_BOOTSTRAP_MK := build/x\n",
                        "ZCL_NETWORK_DENIED_BUILD_GOALS := ci-reproducible repro-verify\n"
                        "ifneq ($(strip $(filter $(ZCL_NETWORK_DENIED_BUILD_GOALS),$(MAKECMDGOALS))),)\n"
                        "export ZCL_VENDOR_OFFLINE\n"
                        "export ZCL_USE_CCACHE\n"
                        "endif\n") > 0);
        ASSERT(rnp_case(root, "caller", body, dir, sizeof dir) == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "did not force offline/no-cache policy: 0 1") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_fixture(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char path[PATH_MAX];
    char body[1024];
    char out[64];
    char err[1024];
    int rc;
    TEST("a failing repro-verify is reported with its output") {
        ASSERT(snprintf(body, sizeof body, "%sZCL_USE_CCACHE ?= 1\nVENDOR_BOOTSTRAP_MK := build/x\n",
                        k_block) > 0);
        ASSERT(rnp_case(root, "fail", body, dir, sizeof dir) == 0);
        ASSERT(rnp_mkdir_at(dir, "tools/scripts") == 0);
        ASSERT(snprintf(path, sizeof path, "%s/tools/scripts/repro-verify.sh", dir) >= 0);
        ASSERT(rnp_put(path, "#!/bin/sh\nprintf 'fixture-blew-up\\n' >&2\nexit 9\n") == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "fixture-blew-up") != NULL);
        ASSERT(strstr(err, "repro-verify fixture failed") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_pass(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[4096];
    int rc;
    const char *pass =
        "repro_network_policy_selftest: PASS builds=2 make_parse_offline=true "
        "make_parse_cache=false host_cache=false\n";
    TEST("the checkout forces two hermetic repro-verify builds") {
        ASSERT(rnp_case(root, "pass", "all:\n", dir, sizeof dir) == 0);
        rc = rnp_capture(dir, ".", out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s out=%s", rc, err, out);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, pass);
        ASSERT_STR_EQ(err, "");
        rc = rnp_capture(dir, ".", out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, pass);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_repro_network_policy(void);
int test_repro_network_policy(void)
{
    char root[PATH_MAX];
    int failures = 0;
    test_make_tmpdir(root, sizeof root, "repro_network_policy", "root");
    failures += test_rnp_repo(root);
    failures += test_rnp_order(root);
    failures += test_rnp_caller(root);
    failures += test_rnp_fixture(root);
    failures += test_rnp_pass(root);
    if (failures == 0)
        printf("test_repro_network_policy: all passed\n");
    else
        printf("test_repro_network_policy: %d FAILED\n", failures);
    return failures;
}
