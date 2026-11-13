/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_depfile_scope_launch. A stub make on PATH stands in for the
 * real build so the test observes the arguments and the private directory
 * without compiling the repository. */

#include "test/test_core.h"

#include "depfile_scope_launch.h"

#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
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
                 "printf 'linker=%%s\\n' \"${ZCL_DEV_LINKER-<unset>}\" >> \"%s\"\n"
                 "exit 0\n",
                 run_log, run_log);
    if (n < 0 || n >= (int)sizeof tool_body || dsl_write(tool, tool_body) != 0)
        return -1;
    n = snprintf(body, sizeof body,
                 "#!/bin/sh\n"
                 "printf '%%s\\n' \"$@\" > \"%s/make.log\"\n"
                 "printf 'linker=%%s\\n' \"${ZCL_DEV_LINKER-<unset>}\" >> \"%s/make.log\"\n"
                 "out=\n"
                 "for a in \"$@\"; do out=$a; done\n"
                 "mkdir -p \"$(dirname \"$out\")\"\n"
                 "cp \"%s\" \"$out\"\n"
                 "chmod +x \"$out\"\n"
                 "exit 0\n",
                 log_dir, log_dir, tool);
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

static bool dsl_dir(const char *path)
{
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

static bool dsl_fake_selector(const char *root)
{
    char path[512], body[2048];
    if (snprintf(path, sizeof path, "%s/tools", root) >= (int)sizeof path || !dsl_dir(path)) return false;
    if (snprintf(path, sizeof path, "%s/tools/dev", root) >= (int)sizeof path || !dsl_dir(path)) return false;
    if (snprintf(path, sizeof path, "%s/tools/dev/dev-linker-select.sh", root) >= (int)sizeof path) return false;
    int n = snprintf(body, sizeof body,
        "#!/bin/sh\nprintf 'x\\n' >> '%s/selector.log'\n"
        "case \"$DSL_MODE\" in\n"
        "empty) exit 0;; fail) exit 7;; over) printf '%%0300d' 0; exit 0;;\n"
        "invalid) printf 'bad\\nflag'; exit 0;;\n"
        "garbage) printf '%%s' 'garbage'; exit 0;;\n"
        "badflag) printf '%%s' '-fuse-ld=invalid'; exit 0;;\n"
        "dollar) printf '%%s' '-fuse-ld=$BAD'; exit 0;;\n"
        "mold) printf '%%s' '-fuse-ld=mold'; exit 0;;\n"
        "gold) printf '%%s' '-fuse-ld=gold -Wl,--threads -Wl,--thread-count=9'; exit 0;;\n"
        "sleep) sleep 20 & sub=$!; printf '%%s' \"$$\" > '%s/selector-pid'; "
        "printf '%%s' \"$sub\" > '%s/descendant-pid'; printf ready > '%s/selector-ready'; wait \"$sub\";;\n"
        "*) printf '%%s' '-fuse-ld=lld';; esac\n", root, root, root, root);
    return n >= 0 && n < (int)sizeof body && dsl_write(path, body) == 0;
}

static int dsl_line_count(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : -1;
    int count = 0, c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') ++count;
    if (ferror(f)) count = -1;
    if (fclose(f) != 0) count = -1;
    return count;
}

static bool dsl_linker_env(const char *root, const char *bins, const char *mode)
{
    char path[1024];
    const char *oldpath = getenv("PATH");
    if (!oldpath || snprintf(path, sizeof path, "%s:%s", bins, oldpath) >= (int)sizeof path) return false;
    if (setenv("PATH", path, 1) || setenv("TMPDIR", root, 1) || setenv("DSL_MODE", mode, 1)) return false;
    const char *const controls[] = {"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEOVERRIDES", "MAKEFILES"};
    for (size_t i = 0; i < sizeof controls / sizeof controls[0]; ++i) if (unsetenv(controls[i])) return false;
    return true;
}

static bool dsl_linker_fixture_child(const char *root, const char *bins,
                                     const char *mode, const char *override,
                                     const char *makeflags, int runs,
                                     const char *wanted, int calls)
{
    char log[512], runlog[512], selector[512];
    if (snprintf(log, sizeof log, "%s/make.log", root) >= (int)sizeof log ||
        snprintf(runlog, sizeof runlog, "%s/run.log", root) >= (int)sizeof runlog ||
        snprintf(selector, sizeof selector, "%s/selector.log", root) >= (int)sizeof selector ||
        !dsl_linker_env(root, bins, mode)) return false;
    if ((override ? setenv("ZCL_DEV_LINKER", override, 1) : unsetenv("ZCL_DEV_LINKER")) != 0) return false;
    if (makeflags && setenv(makeflags, "-e", 1)) return false;
    (void)unlink(selector);
    for (int i = 0; i < runs; ++i) if (zcl_depfile_scope_launch(root) != 0) return false;
    return dsl_line_count(selector) == calls && dsl_contains(log, wanted) &&
        dsl_contains(runlog, wanted) && (override ? !strcmp(getenv("ZCL_DEV_LINKER"), override) :
        getenv("ZCL_DEV_LINKER") == NULL);
}

static bool dsl_linker_fixture(const char *root, const char *bins, const char *mode,
                               const char *override, const char *makeflags,
                               int runs, const char *wanted, int calls)
{
    pid_t child = fork();
    if (child == 0)
        _exit(dsl_linker_fixture_child(root, bins, mode, override, makeflags, runs, wanted, calls) ? 0 : 1);
    if (child < 0) return false;
    int status; pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    return got == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int test_depfile_scope_linker(const char *root, const char *bins)
{
    int failures = 0; char runlog[512];
    TEST("depfile scope launch: linker selection is invocation-local and optional") {
        ASSERT(snprintf(runlog, sizeof runlog, "%s/run.log", root) < (int)sizeof runlog);
        ASSERT(dsl_make_ok(bins, root, runlog) == 0 && dsl_fake_selector(root));
        ASSERT(dsl_linker_fixture(root, bins, "value", NULL, NULL, 2, "linker=-fuse-ld=lld\n", 2));
        ASSERT(dsl_linker_fixture(root, bins, "mold", NULL, NULL, 1, "linker=-fuse-ld=mold\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "gold", NULL, NULL, 1, "linker=-fuse-ld=gold -Wl,--threads -Wl,--thread-count=9\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "empty", NULL, NULL, 1, "linker=\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "value", "explicit", NULL, 1, "linker=explicit\n", 0));
        ASSERT(dsl_linker_fixture(root, bins, "value", "", NULL, 1, "linker=\n", 0));
        const char *const controls[] = {"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEOVERRIDES", "MAKEFILES"};
        for (size_t i = 0; i < sizeof controls / sizeof controls[0]; ++i)
            ASSERT(dsl_linker_fixture(root, bins, "value", NULL, controls[i], 1, "linker=<unset>\n", 0));
        ASSERT(dsl_linker_fixture(root, bins, "fail", NULL, NULL, 1, "linker=<unset>\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "over", NULL, NULL, 1, "linker=<unset>\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "invalid", NULL, NULL, 1, "linker=<unset>\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "garbage", NULL, NULL, 1, "linker=<unset>\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "badflag", NULL, NULL, 1, "linker=<unset>\n", 1));
        ASSERT(dsl_linker_fixture(root, bins, "dollar", NULL, NULL, 1, "linker=<unset>\n", 1));
        PASS();
    } _test_next:;
    return failures;
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

/* A killed orphan can remain a zombie until its new parent reaps it. */
static bool dsl_dead_or_zombie(int pid)
{
    if (kill(pid, 0) < 0 && errno == ESRCH) return true;
#if defined(__linux__)
    char path[64], state = 0;
    if (snprintf(path, sizeof path, "/proc/%d/stat", pid) >= (int)sizeof path) return false;
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT;
    int n = fscanf(f, "%*d %*s %c", &state);
    if (fclose(f) != 0) return false;
    return n == 1 && state == 'Z';
#else
    return false;
#endif
}

static bool dsl_wait_dead(int pid)
{
    for (int i = 0; i < 200; ++i) {
        if (dsl_dead_or_zombie(pid)) return true;
        (void)nanosleep(&(struct timespec){.tv_nsec = 10000000}, NULL); /* real-clock: observes orphaned OS process termination after SIGKILL; no injected clock controls kernel exit */
    }
    return false;
}

static int dsl_pid_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int pid = -1;
    int n = fscanf(f, "%d", &pid);
    if (fclose(f) != 0 || n != 1 || pid <= 1) return -1;
    return pid;
}

static int test_depfile_scope_selector_signal(const char *root, const char *bins)
{
    int failures = 0, status = 0, selector = -1, descendant = -1;
    char ready[512], pidpath[512], subpath[512], makelog[512];
    pid_t child = -1;
    TEST("depfile scope launch: interruption contains the selector") {
        ASSERT(snprintf(ready, sizeof ready, "%s/selector-ready", root) < (int)sizeof ready);
        ASSERT(snprintf(pidpath, sizeof pidpath, "%s/selector-pid", root) < (int)sizeof pidpath);
        ASSERT(snprintf(subpath, sizeof subpath, "%s/descendant-pid", root) < (int)sizeof subpath);
        ASSERT(snprintf(makelog, sizeof makelog, "%s/make.log", root) < (int)sizeof makelog);
        (void)unlink(ready); (void)unlink(pidpath); (void)unlink(subpath); (void)unlink(makelog);
        child = fork();
        ASSERT(child >= 0);
        if (!child) {
            if (!dsl_linker_env(root, bins, "sleep") || unsetenv("ZCL_DEV_LINKER")) _exit(125);
            _exit(zcl_depfile_scope_launch(root));
        }
        ASSERT(dsl_ready(child, ready) == 0);
        selector = dsl_pid_file(pidpath);
        descendant = dsl_pid_file(subpath);
        ASSERT(selector > 1 && descendant > 1);
        ASSERT(kill(child, SIGTERM) == 0);
        ASSERT(waitpid(child, &status, 0) == child);
        child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 1);
        ASSERT(kill(selector, 0) < 0 && errno == ESRCH);
        ASSERT(dsl_wait_dead(descendant));
        ASSERT(access(makelog, F_OK) < 0 && errno == ENOENT);
        PASS();
    } _test_next:;
    if (child > 0) { (void)kill(child, SIGTERM); (void)waitpid(child, &status, 0); }
    return failures;
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
        failures = test_depfile_scope_linker(root, bins);
    if (failures == 0 && !dsl_work_gone(root))
        failures = 1;
    if (failures == 0)
        failures = test_depfile_scope_selector_signal(root, bins);
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
