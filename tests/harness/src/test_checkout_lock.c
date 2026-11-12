/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_checkout_lock_run, the shipped checkout lock. A temporary
 * lock file is a real flock. The suite may itself be running with
 * ZCL_CHECKOUT_LOCK_HELD=1, so these cases clear that variable except
 * when the case is the already-held bypass.
 */

#include "test/test_core.h"

#include "checkout_lock.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_cl_saved_held[32];
static int g_cl_had_held;
static pid_t g_cl_holder = -1;

static void cl_env_clear(void)
{
    const char *cur = getenv("ZCL_CHECKOUT_LOCK_HELD");
    g_cl_had_held = cur && cur[0];
    g_cl_saved_held[0] = '\0';
    if (g_cl_had_held)
        (void)snprintf(g_cl_saved_held, sizeof g_cl_saved_held, "%s", cur);
    (void)unsetenv("ZCL_CHECKOUT_LOCK_HELD");
}

static void cl_env_restore(void)
{
    if (g_cl_had_held)
        (void)setenv("ZCL_CHECKOUT_LOCK_HELD", g_cl_saved_held, 1);
    else
        (void)unsetenv("ZCL_CHECKOUT_LOCK_HELD");
}

static void cl_holder_stop(void)
{
    if (g_cl_holder <= 0)
        return;
    (void)kill(g_cl_holder, SIGTERM);
    (void)waitpid(g_cl_holder, NULL, 0);
    g_cl_holder = -1;
    (void)alarm(0);
}

/* Child holds an exclusive flock and reports once it has it. */
static int cl_holder_start(const char *lock)
{
    int pipefd[2];
    char ready = 0;
    if (pipe(pipefd) != 0)
        return -1;
    g_cl_holder = fork();
    if (g_cl_holder < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return -1;
    }
    if (g_cl_holder == 0) {
        int fd;
        (void)close(pipefd[0]);
        fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0 || flock(fd, LOCK_EX) != 0)
            _exit(1);
        ready = 1;
        if (write(pipefd[1], &ready, 1) != 1)
            _exit(1);
        (void)close(pipefd[1]);
        for (;;)
            pause();
    }
    (void)close(pipefd[1]);
    if (read(pipefd[0], &ready, 1) != 1)
        ready = 0;
    (void)close(pipefd[0]);
    return ready == 1 ? 0 : -1;
}

static int cl_capture(const char *mode, const char *lock,
                      const char *const *argv, char *err, size_t cap)
{
    int pipefd[2];
    int saved;
    int rc;
    ssize_t n;
    if (pipe(pipefd) != 0)
        return -1;
    saved = dup(STDERR_FILENO);
    if (saved < 0 || dup2(pipefd[1], STDERR_FILENO) < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        if (saved >= 0)
            (void)close(saved);
        return -1;
    }
    rc = zcl_checkout_lock_run(mode, lock, argv, -1);
    (void)dup2(saved, STDERR_FILENO);
    (void)close(saved);
    (void)close(pipefd[1]);
    n = read(pipefd[0], err, cap - 1);
    (void)close(pipefd[0]);
    if (n < 0)
        n = 0;
    err[n] = '\0';
    if (err[0])
        (void)fputs(err, stderr);
    return rc;
}

static int test_checkout_lock_cases(const char *root)
{
    int failures = 0;
    char lock[512];
    char marker[512];
    const char *exit0[] = {"/bin/sh", "-c", "exit 0", NULL};
    const char *exit3[] = {"/bin/sh", "-c", "exit 3", NULL};
    (void)snprintf(lock, sizeof lock, "%s/checkout.lock", root);
    (void)snprintf(marker, sizeof marker, "%s/ran", root);
    cl_env_clear();
    TEST("checkout lock: status, defer, usage, and the held bypass") {
        char err_a[256], err_b[256];
        char touch[640];
        const char *touch_argv[4];
        int rc_a, rc_b;
        (void)snprintf(touch, sizeof touch, "touch '%s'", marker);
        touch_argv[0] = "/bin/sh";
        touch_argv[1] = "-c";
        touch_argv[2] = touch;
        touch_argv[3] = NULL;
        rc_a = zcl_checkout_lock_run("foreground", lock, exit0, -1);
        rc_b = zcl_checkout_lock_run("foreground", lock, exit0, -1);
        ASSERT(rc_a == 0);
        ASSERT(rc_b == rc_a);
        rc_a = zcl_checkout_lock_run("foreground", lock, exit3, -1);
        rc_b = zcl_checkout_lock_run("foreground", lock, exit3, -1);
        ASSERT(rc_a == 3);
        ASSERT(rc_b == rc_a);
        (void)unlink(marker);
        rc_a = zcl_checkout_lock_run("watcher", lock, touch_argv, -1);
        ASSERT(rc_a == 0);
        ASSERT(access(marker, F_OK) == 0);
        (void)unlink(marker);
        ASSERT(cl_holder_start(lock) == 0);
        (void)alarm(5);
        rc_a = cl_capture("watcher", lock, touch_argv, err_a, sizeof err_a);
        rc_b = cl_capture("watcher", lock, touch_argv, err_b, sizeof err_b);
        (void)alarm(0);
        ASSERT(rc_a == 99);
        ASSERT(rc_b == rc_a);
        ASSERT(strcmp(err_a, err_b) == 0);
        ASSERT(strstr(err_a, "deferred: foreground build holds the lock") !=
               NULL);
        ASSERT(access(marker, F_OK) != 0);
        (void)setenv("ZCL_CHECKOUT_LOCK_HELD", "1", 1);
        (void)alarm(5);
        rc_a = zcl_checkout_lock_run("foreground", lock, exit0, -1);
        rc_b = zcl_checkout_lock_run("foreground", lock, exit0, -1);
        (void)alarm(0);
        (void)unsetenv("ZCL_CHECKOUT_LOCK_HELD");
        ASSERT(rc_a == 0);
        ASSERT(rc_b == rc_a);
        cl_holder_stop();
        rc_a = cl_capture("sideways", lock, exit0, err_a, sizeof err_a);
        rc_b = cl_capture("sideways", lock, exit0, err_b, sizeof err_b);
        ASSERT(rc_a == 2);
        ASSERT(rc_b == rc_a);
        ASSERT(strcmp(err_a, err_b) == 0);
        ASSERT(strncmp(err_a, "checkout-lock:", 14) == 0);
        rc_a = cl_capture("foreground", lock, NULL, err_a, sizeof err_a);
        rc_b = cl_capture("foreground", lock, NULL, err_b, sizeof err_b);
        ASSERT(rc_a == 2);
        ASSERT(rc_b == rc_a);
        ASSERT(strcmp(err_a, err_b) == 0);
        ASSERT(strncmp(err_a, "checkout-lock:", 14) == 0);
        PASS();
    } _test_next:;
    cl_holder_stop();
    cl_env_restore();
    return failures;
}

int test_checkout_lock(void);
int test_checkout_lock(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "checkout_lock", "root");
    failures = test_checkout_lock_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_checkout_lock: all passed\n");
    else
        printf("test_checkout_lock: %d FAILED\n", failures);
    return failures;
}
