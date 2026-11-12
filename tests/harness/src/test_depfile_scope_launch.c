/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_depfile_scope_launch. A stub make on PATH stands in for the
 * real build so the test observes the arguments and the private directory
 * without compiling the repository. */

#include "test/test_core.h"

#include "depfile_scope_launch.h"

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int dsl_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(text, file) < 0 || fclose(file) != 0)
        return -1;
    return chmod(path, 0755);
}

static int dsl_make_ok(const char *dir, const char *log_dir, const char *run_log)
{
    char path[512];
    char tool[512];
    char body[1024];
    char tool_body[512];
    int n = snprintf(path, sizeof path, "%s/make", dir);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    n = snprintf(tool, sizeof tool, "%s/tool.sh", dir);
    if (n < 0 || n >= (int)sizeof tool)
        return -1;
    n = snprintf(tool_body, sizeof tool_body,
                 "#!/bin/sh\n"
                 "printf '%%s\\n' \"$@\" > \"%s\"\n"
                 "exit 0\n",
                 run_log);
    if (n < 0 || n >= (int)sizeof tool_body || dsl_write(tool, tool_body) != 0)
        return -1;
    n = snprintf(body, sizeof body,
                 "#!/bin/sh\n"
                 "printf '%%s\\n' \"$@\" > \"%s/make.log\"\n"
                 "out=\n"
                 "for a in \"$@\"; do out=$a; done\n"
                 "mkdir -p \"$(dirname \"$out\")\"\n"
                 "cp \"%s\" \"$out\"\n"
                 "chmod +x \"$out\"\n"
                 "exit 0\n",
                 log_dir, tool);
    if (n < 0 || n >= (int)sizeof body)
        return -1;
    return dsl_write(path, body);
}

static int dsl_make_fail(const char *dir, const char *log_dir)
{
    char path[512];
    char body[512];
    int n = snprintf(path, sizeof path, "%s/make", dir);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    n = snprintf(body, sizeof body,
                 "#!/bin/sh\n"
                 "printf '%%s\\n' \"$@\" > \"%s/make.log\"\n"
                 "exit 3\n",
                 log_dir);
    if (n < 0 || n >= (int)sizeof body)
        return -1;
    return dsl_write(path, body);
}

static int dsl_make_sleep(const char *dir, const char *log_dir, const char *ready)
{
    char path[512];
    char body[512];
    int n = snprintf(path, sizeof path, "%s/make", dir);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    n = snprintf(body, sizeof body,
                 "#!/bin/sh\n"
                 "printf '%%s\\n' \"$@\" > \"%s/make.log\"\n"
                 "printf ready > \"%s\"\n"
                 "sleep 5\n"
                 "exit 0\n",
                 log_dir, ready);
    if (n < 0 || n >= (int)sizeof body)
        return -1;
    return dsl_write(path, body);
}

static int dsl_contains(const char *path, const char *needle)
{
    char buf[4096];
    FILE *file = fopen(path, "r");
    size_t n;
    if (!file)
        return 0;
    n = fread(buf, 1, sizeof buf - 1, file);
    fclose(file);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static int test_depfile_scope_success(const char *root, const char *bin_dir)
{
    int failures = 0;
    char path_env[1024];
    char make_log[512];
    char run_log[512];
    char saved_path[1024];
    const char *old_path = getenv("PATH");
    const char *old_tmp = getenv("TMPDIR");
    TEST("depfile scope launch: builds in a private directory and removes it") {
        int n;
        ASSERT(old_path != NULL);
        n = snprintf(saved_path, sizeof saved_path, "%s", old_path);
        ASSERT(n > 0 && n < (int)sizeof saved_path);
        n = snprintf(path_env, sizeof path_env, "%s:%s", bin_dir, old_path);
        ASSERT(n > 0 && n < (int)sizeof path_env);
        n = snprintf(make_log, sizeof make_log, "%s/make.log", root);
        ASSERT(n > 0 && n < (int)sizeof make_log);
        n = snprintf(run_log, sizeof run_log, "%s/run.log", root);
        ASSERT(n > 0 && n < (int)sizeof run_log);
        ASSERT(dsl_make_ok(bin_dir, root, run_log) == 0);
        ASSERT(setenv("PATH", path_env, 1) == 0);
        ASSERT(setenv("TMPDIR", root, 1) == 0);
        ASSERT(zcl_depfile_scope_launch(NULL) == 2);
        ASSERT(zcl_depfile_scope_launch("") == 2);
        ASSERT(zcl_depfile_scope_launch(root) == 0);
        ASSERT(dsl_contains(make_log, "-C\n"));
        ASSERT(dsl_contains(make_log, "--no-print-directory\n"));
        ASSERT(dsl_contains(make_log, "ZCL_STANDALONE_CLEAN=1\n"));
        ASSERT(dsl_contains(make_log, "BIN_DIR="));
        ASSERT(dsl_contains(make_log, "/make-depfile-scope-selftest\n"));
        ASSERT(dsl_contains(run_log, root));
        ASSERT(access(run_log, F_OK) == 0);
        PASS();
    } _test_next:;
    if (old_path)
        (void)setenv("PATH", saved_path, 1);
    if (old_tmp)
        (void)setenv("TMPDIR", old_tmp, 1);
    else
        unsetenv("TMPDIR");
    return failures;
}

static int test_depfile_scope_make_fails(const char *root, const char *bin_dir)
{
    int failures = 0;
    char path_env[1024];
    char saved_path[1024];
    const char *old_path = getenv("PATH");
    const char *old_tmp = getenv("TMPDIR");
    TEST("depfile scope launch: a failing make removes the private directory") {
        int n = old_path ? snprintf(saved_path, sizeof saved_path, "%s", old_path) : -1;
        ASSERT(n > 0 && n < (int)sizeof saved_path);
        n = snprintf(path_env, sizeof path_env, "%s:%s", bin_dir, old_path);
        ASSERT(n > 0 && n < (int)sizeof path_env);
        ASSERT(dsl_make_fail(bin_dir, root) == 0);
        ASSERT(setenv("PATH", path_env, 1) == 0);
        ASSERT(setenv("TMPDIR", root, 1) == 0);
        ASSERT(zcl_depfile_scope_launch(root) == 3);
        PASS();
    } _test_next:;
    if (old_path)
        (void)setenv("PATH", saved_path, 1);
    if (old_tmp)
        (void)setenv("TMPDIR", old_tmp, 1);
    else
        unsetenv("TMPDIR");
    return failures;
}

static int dsl_ready(pid_t pid, const char *path)
{
    for (;;) {
        int status = 0;
        if (access(path, F_OK) == 0)
            return 0;
        if (waitpid(pid, &status, WNOHANG) == pid)
            return -1;
    }
}

static int test_depfile_scope_signal(const char *root, const char *bin_dir)
{
    int failures = 0;
    char path_env[1024];
    char ready[512];
    char saved_path[1024];
    const char *old_path = getenv("PATH");
    const char *old_tmp = getenv("TMPDIR");
    pid_t pid = -1;
    int status = 0;
    TEST("depfile scope launch: a caught signal stops make and removes the directory") {
        int n = old_path ? snprintf(saved_path, sizeof saved_path, "%s", old_path) : -1;
        ASSERT(n > 0 && n < (int)sizeof saved_path);
        n = snprintf(path_env, sizeof path_env, "%s:%s", bin_dir, old_path);
        ASSERT(n > 0 && n < (int)sizeof path_env);
        n = snprintf(ready, sizeof ready, "%s/ready", root);
        ASSERT(n > 0 && n < (int)sizeof ready);
        ASSERT(dsl_make_sleep(bin_dir, root, ready) == 0);
        ASSERT(setenv("PATH", path_env, 1) == 0);
        ASSERT(setenv("TMPDIR", root, 1) == 0);
        pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            _exit(zcl_depfile_scope_launch(root));
        ASSERT(dsl_ready(pid, ready) == 0);
        ASSERT(kill(pid, SIGTERM) == 0);
        ASSERT(waitpid(pid, &status, 0) == pid);
        pid = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 1);
        PASS();
    } _test_next:;
    if (pid > 0) {
        kill(pid, SIGTERM);
        (void)waitpid(pid, &status, 0);
    }
    if (old_path)
        (void)setenv("PATH", saved_path, 1);
    if (old_tmp)
        (void)setenv("TMPDIR", old_tmp, 1);
    else
        unsetenv("TMPDIR");
    return failures;
}

static int dsl_work_gone(const char *root)
{
    char log[512];
    char line[PATH_MAX];
    FILE *file;
    int n = snprintf(log, sizeof log, "%s/make.log", root);
    char *bin;
    if (n < 0 || n >= (int)sizeof log)
        return 0;
    file = fopen(log, "r");
    if (!file)
        return 0;
    while (fgets(line, sizeof line, file)) {
        bin = strstr(line, "BIN_DIR=");
        if (!bin)
            continue;
        bin += strlen("BIN_DIR=");
        bin[strcspn(bin, "\n")] = '\0';
        fclose(file);
        if (strlen(bin) < 4)
            return 0;
        bin[strlen(bin) - 4] = '\0';
        return access(bin, F_OK) != 0;
    }
    fclose(file);
    return 0;
}

int test_depfile_scope_launch(void);
int test_depfile_scope_launch(void)
{
    char root[512];
    char bins[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "depfile_scope_launch", "root");
    test_make_tmpdir(bins, sizeof bins, "depfile_scope_launch", "bin");
    failures = test_depfile_scope_success(root, bins);
    if (failures == 0 && !dsl_work_gone(root))
        failures = 1;
    if (failures == 0)
        failures = test_depfile_scope_make_fails(root, bins);
    if (failures == 0 && !dsl_work_gone(root))
        failures = 1;
    if (failures == 0)
        failures = test_depfile_scope_signal(root, bins);
    if (failures == 0 && !dsl_work_gone(root))
        failures = 1;
    (void)test_rm_rf_recursive(root);
    (void)test_rm_rf_recursive(bins);
    if (failures == 0)
        printf("test_depfile_scope_launch: all passed\n");
    else
        printf("test_depfile_scope_launch: %d FAILED\n", failures);
    return failures;
}
