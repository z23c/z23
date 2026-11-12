/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_build_epoch_flock_bounded. A child that locks an inherited
 * descriptor and exits must leave the lock held for the parent. A second
 * open of the same file must not acquire it until the parent closes. */

#include "test/test_core.h"

#include "build_epoch_lock_wait.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_bel_saved[64];
static int g_bel_had;
static pid_t g_bel_holder = -1;

static void bel_holder_stop(void)
{
    if (g_bel_holder <= 0)
        return;
    (void)kill(g_bel_holder, SIGTERM);
    (void)waitpid(g_bel_holder, NULL, 0);
    g_bel_holder = -1;
}

static void bel_env_clear(void)
{
    const char *cur = getenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT");
    g_bel_had = cur != NULL;
    g_bel_saved[0] = '\0';
    if (cur)
        (void)snprintf(g_bel_saved, sizeof g_bel_saved, "%s", cur);
    (void)unsetenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT");
}

static void bel_env_restore(void)
{
    if (g_bel_had)
        (void)setenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT", g_bel_saved, 1);
    else
        (void)unsetenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT");
}

static int bel_capture(const char *tag, int fd, const char *lock,
                       const char *kind, char *err, size_t cap)
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
    rc = zcl_build_epoch_flock_bounded(tag, fd, lock, kind, -1);
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

/* 0 when a different open cannot take the lock. */
static int bel_other_blocked(const char *lock)
{
    pid_t pid = fork();
    int st = 0;
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open(lock, O_RDWR | O_CLOEXEC);
        int rc = fd < 0 ? 0 : flock(fd, LOCK_EX | LOCK_NB);
        _exit(rc == 0 ? 0 : 1);
    }
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    return WIFEXITED(st) && WEXITSTATUS(st) == 1;
}

static int test_build_epoch_lock_wait_cases(const char *root)
{
    int failures = 0;
    char lock[512];
    (void)snprintf(lock, sizeof lock, "%s/epoch.lock", root);
    bel_env_clear();
    TEST("epoch lock: held across return, timeout names the holder, "
         "invalid timeout is stable") {
        char err_a[1024], err_b[1024];
        char pid_text[32];
        int fd;
        int rc_a, rc_b;
        pid_t holder;
        fd = open(lock, O_RDWR | O_CREAT, 0600);
        ASSERT(fd >= 0);
        holder = fork();
        ASSERT(holder >= 0);
        if (holder == 0) {
            int rc = zcl_build_epoch_flock_bounded("child", fd, lock, "kind",
                                                   STDERR_FILENO);
            _exit(rc == 0 ? 0 : 2);
        }
        {
            int st = 0;
            ASSERT(waitpid(holder, &st, 0) > 0);
            ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
        }
        ASSERT(bel_other_blocked(lock) == 1);
        ASSERT(flock(fd, LOCK_UN) == 0);
        (void)close(fd);
        ASSERT(bel_other_blocked(lock) == 0);
        fd = open(lock, O_RDWR | O_CLOEXEC);
        ASSERT(fd >= 0);
        ASSERT(zcl_build_epoch_flock_bounded("live", fd, lock, "kind",
                                             STDERR_FILENO) == 0);
        ASSERT(bel_other_blocked(lock) == 1);
        (void)setenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT", "0", 1);
        rc_a = bel_capture("epoch", fd, lock, "kind", err_a, sizeof err_a);
        rc_b = bel_capture("epoch", fd, lock, "kind", err_b, sizeof err_b);
        ASSERT(rc_a == 1);
        ASSERT(rc_b == rc_a);
        ASSERT(strcmp(err_a, err_b) == 0);
        ASSERT(strstr(err_a,
                      "invalid ZCL_BUILD_EPOCH_LOCK_TIMEOUT=0 (must be a "
                      "positive integer number of seconds)") != NULL);
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
        {
            int readyfd[2];
            char ready = 0;
            ASSERT(pipe(readyfd) == 0);
            holder = fork();
            ASSERT(holder >= 0);
            if (holder == 0) {
                int held = open(lock, O_RDWR | O_CLOEXEC);
                (void)close(readyfd[0]);
                if (held < 0 || flock(held, LOCK_EX) != 0)
                    _exit(2);
                ready = 1;
                if (write(readyfd[1], &ready, 1) != 1)
                    _exit(2);
                for (;;)
                    pause();
            }
            g_bel_holder = holder;
            (void)close(readyfd[1]);
            ASSERT(read(readyfd[0], &ready, 1) == 1);
            (void)close(readyfd[0]);
        }
        (void)snprintf(pid_text, sizeof pid_text, "%ld", (long)holder);
        (void)setenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT", "1", 1);
        fd = open(lock, O_RDWR | O_CLOEXEC);
        ASSERT(fd >= 0);
        rc_a = bel_capture("epoch-wait", fd, lock, "epoch admission", err_a,
                           sizeof err_a);
        bel_holder_stop();
        (void)close(fd);
        ASSERT(rc_a == 1);
        ASSERT(strstr(err_a, "timed out after 1s waiting for exclusive "
                             "epoch admission lock ") != NULL);
        ASSERT(strstr(err_a, pid_text) != NULL);
        PASS();
    } _test_next:;
    bel_holder_stop();
    bel_env_restore();
    return failures;
}

int test_build_epoch_lock_wait(void);
int test_build_epoch_lock_wait(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "epoch_lock", "root");
    failures = test_build_epoch_lock_wait_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_build_epoch_lock_wait: all passed\n");
    else
        printf("test_build_epoch_lock_wait: %d FAILED\n", failures);
    return failures;
}
