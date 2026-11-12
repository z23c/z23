/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_make_help against the checkout Makefile and a private one. */

#include "test/test_core.h"

#include "make_help.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int mh_capture(const char *repo, int argc, char **argv, char *out,
                      size_t out_cap, char *err, size_t err_cap, int *rc)
{
    char out_path[] = "mh-out";
    char err_path[] = "mh-err";
    int fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *fp;
    size_t n;
    if (fd_out < 0 || fd_err < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_make_help(repo, argc, argv);
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
    if (fd_out >= 0)
        close(fd_out);
    if (fd_err >= 0)
        close(fd_err);
    return -1;
}

static int mh_take_target(const char *line, char *out, size_t cap)
{
    const char *p;
    size_t n = 0;
    if (strncmp(line, "  make ", 7) != 0)
        return 0;
    p = line + 7;
    while (*p != '\0' && *p != ' ' && n + 1 < cap)
        out[n++] = *p++;
    out[n] = '\0';
    return n > 0;
}

static int mh_collect(const char *help, char names[][64], int cap)
{
    const char *p = help;
    int n = 0;
    while (*p != '\0' && n < cap) {
        char line[256];
        size_t i = 0;
        while (p[i] != '\0' && p[i] != '\n' && i + 1 < sizeof line) {
            line[i] = p[i];
            i++;
        }
        line[i] = '\0';
        if (mh_take_target(line, names[n], 64))
            n++;
        if (p[i] == '\n')
            i++;
        p += i;
    }
    return n;
}

static int mh_write_rules(const char *path, char names[][64], int n, int drop,
                          int phantom)
{
    FILE *fp = fopen(path, "w");
    int i;
    if (fp == NULL)
        return -1;
    fprintf(fp, ".PHONY: help-fixture\n");
    for (i = 0; i < n; i++) {
        if (i == drop)
            continue;
        fprintf(fp, "%s:\n\t@:\n", names[i]);
    }
    if (phantom)
        fprintf(fp, "zcl-target-that-cannot-exist:\n\t@:\n");
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int test_mh_repo(const char *repo)
{
    int failures = 0;
    char out[16384];
    char err[1024];
    char again_out[1024];
    char again_err[1024];
    char *argv[] = {"--self-test", NULL};
    int rc = -1;
    int rc2 = -1;
    TEST("checkout Makefile self-test and help") {
        ASSERT(mh_capture(repo, 1, argv, out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(err[0] == '\0');
        ASSERT(strstr(out, "make_help selftest: PASS \xe2\x80\x94 ") == out);
        ASSERT(strstr(out, " documented targets all exist\n") != NULL);
        ASSERT(mh_capture(repo, 1, argv, again_out, sizeof again_out, again_err,
                          sizeof again_err, &rc2) == 0);
        ASSERT_EQ(rc2, 0);
        ASSERT(strcmp(out, again_out) == 0);
        ASSERT(strcmp(err, again_err) == 0);
        ASSERT(mh_capture(repo, 0, NULL, out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "zclassic23 \xe2\x80\x94 one C23 binary:") == out);
        ASSERT(strstr(out, "First run, in this order\n") != NULL);
        ASSERT(strstr(out, "Inner loop \xe2\x80\x94 while you are editing\n") != NULL);
        ASSERT(strstr(out, "Gates \xe2\x80\x94 what a change must survive\n") != NULL);
        ASSERT(strstr(out, "Agent and operator surface\n") != NULL);
        ASSERT(strstr(out, "  make doctor") != NULL);
        ASSERT(strstr(out, "  make t-fast") != NULL);
        ASSERT(strstr(out, "  make timings") != NULL);
        ASSERT(strstr(out, "NOT MEASURED") != NULL);
        ASSERT(strstr(out, "The Makefile defines ") != NULL);
        ASSERT(strstr(out, " rule targets;") != NULL);
        ASSERT(strstr(out, "First run") < strstr(out, "Inner loop"));
        ASSERT(strstr(out, "Inner loop") < strstr(out, "Gates "));
        ASSERT(strstr(out, "Gates ") < strstr(out, "Agent and operator"));
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_mh_missing_repo(void)
{
    int failures = 0;
    char out1[64], out2[64], err1[128], err2[128];
    int rc1 = -1, rc2 = -1;
    TEST("a missing repo is a stable usage failure") {
        ASSERT(mh_capture(NULL, 0, NULL, out1, sizeof out1, err1, sizeof err1, &rc1) == 0);
        ASSERT(mh_capture("", 0, NULL, out2, sizeof out2, err2, sizeof err2, &rc2) == 0);
        ASSERT_EQ(rc1, 2);
        ASSERT_EQ(rc2, 2);
        ASSERT(strcmp(err1, err2) == 0);
        ASSERT(strstr(err1, "make_help: repo is required\n") == err1);
        ASSERT(out1[0] == '\0');
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_mh_fixture(const char *dir)
{
    int failures = 0;
    char help[16384];
    char err[4096];
    char pass1[256];
    char pass2[256];
    char names[40][64];
    char path[PATH_MAX];
    char *self[] = {"--self-test", NULL};
    char *other[] = {"foo", "--self-test", NULL};
    int n;
    int rc = -1;
    const char *hit;
    TEST("self-test fails closed on a private Makefile") {
        ASSERT(snprintf(path, sizeof path, "%s/Makefile", dir) > 0);
        ASSERT(mh_write_rules(path, names, 0, -1, 0) == 0);
        ASSERT(mh_capture(dir, 0, NULL, help, sizeof help, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        n = mh_collect(help, names, 40);
        ASSERT(n >= 20);
        ASSERT(mh_write_rules(path, names, n, -1, 0) == 0);
        ASSERT(mh_capture(dir, 1, self, pass1, sizeof pass1, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(err[0] == '\0');
        ASSERT(strstr(pass1, "make_help selftest: PASS \xe2\x80\x94 ") == pass1);
        ASSERT(mh_capture(dir, 1, self, pass2, sizeof pass2, err, sizeof err, &rc) == 0);
        ASSERT(strcmp(pass1, pass2) == 0);
        ASSERT(mh_write_rules(path, names, n, 0, 0) == 0);
        ASSERT(mh_capture(dir, 1, self, pass2, sizeof pass2, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "make_help selftest: FAIL \xe2\x80\x94 help names targets the Makefile does not define:\n") ==
               err);
        ASSERT(strstr(err, names[0]) != NULL);
        ASSERT(mh_write_rules(path, names, n, -1, 1) == 0);
        ASSERT(mh_capture(dir, 1, self, pass2, sizeof pass2, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "detector accepts a nonexistent target") != NULL);
        ASSERT(mh_capture(dir, 2, other, help, sizeof help, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(help, "zclassic23 \xe2\x80\x94 one C23 binary:") == help);
        hit = strstr(help, "The Makefile defines ");
        ASSERT(hit != NULL);
        ASSERT(strstr(hit, " rule targets;") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_make_help(void);
int test_make_help(void)
{
    char repo[PATH_MAX];
    char dir[PATH_MAX];
    int failures;
    if (getcwd(repo, sizeof repo) == NULL)
        return 1;
    test_make_tmpdir(dir, sizeof dir, "make_help", "root");
    failures = test_mh_missing_repo();
    failures += test_mh_repo(repo);
    failures += test_mh_fixture(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_make_help: all passed\n");
    else
        printf("test_make_help: %d FAILED\n", failures);
    return failures;
}
