/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: flock the checkout once so a foreground build and the watcher
 *          never run at the same time. Foreground waits. The watcher defers
 *          with exit 99. ZCL_CHECKOUT_LOCK_HELD=1 means this process already
 *          holds the lock and must not take it again. */

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#include "checkout_lock.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#endif

static const char k_prefix[] = "checkout-lock: ";
static const char k_usage[] =
    "usage: checkout-lock {foreground|watcher} LOCK_FILE -- CMD...";
static const char k_defer[] = "deferred: foreground build holds the lock";

#if !defined(_WIN32)

static void cl_write_all(int fd, const char *s, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, s, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        s += w;
        n -= (size_t)w;
    }
}

static void cl_line(int fd, const char *prefix, const char *text)
{
    if (fd < 0)
        fd = STDERR_FILENO;
    if (prefix)
        cl_write_all(fd, prefix, strlen(prefix));
    if (text)
        cl_write_all(fd, text, strlen(text));
    cl_write_all(fd, "\n", 1);
}

static int cl_already(void)
{
    const char *v = getenv("ZCL_CHECKOUT_LOCK_HELD");
    return v != NULL && strcmp(v, "1") == 0;
}

static int cl_mkdir_parent(const char *path)
{
    char buf[PATH_MAX];
    size_t n = strlen(path);
    char *slash;
    char *p;
    if (n == 0 || n >= sizeof buf)
        return -1;
    memcpy(buf, path, n + 1);
    slash = strrchr(buf, '/');
    if (!slash || slash == buf)
        return 0;
    *slash = '\0';
    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int cl_open_lock(const char *path, int err_fd)
{
    char buf[PATH_MAX + 64];
    int fd;
    if (cl_mkdir_parent(path) != 0) {
        (void)snprintf(buf, sizeof buf,
                       "cannot create lock directory for %s", path);
        cl_line(err_fd, k_prefix, buf);
        return -1;
    }
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        (void)snprintf(buf, sizeof buf, "cannot open %s", path);
        cl_line(err_fd, k_prefix, buf);
        return -1;
    }
    return fd;
}

static int cl_flock_wait(int fd)
{
    for (;;) {
        if (flock(fd, LOCK_EX) == 0)
            return 0;
        if (errno != EINTR)
            return -1;
    }
}

static int cl_mode_ok(const char *mode)
{
    return strcmp(mode, "foreground") == 0 || strcmp(mode, "watcher") == 0;
}

/* 0 when the flock is held. 99 when a watcher defers. 2 on failure. */
static int cl_take(const char *mode, const char *lock_file, int err_fd,
                   int *fd_out)
{
    int fd = cl_open_lock(lock_file, err_fd);
    if (fd < 0)
        return 2;
    if (strcmp(mode, "watcher") == 0 && flock(fd, LOCK_EX | LOCK_NB) != 0) {
        cl_line(err_fd, NULL, k_defer);
        (void)close(fd);
        return 99;
    }
    if (strcmp(mode, "watcher") != 0 && cl_flock_wait(fd) != 0) {
        char buf[PATH_MAX + 64];
        (void)snprintf(buf, sizeof buf, "could not acquire %s", lock_file);
        cl_line(err_fd, k_prefix, buf);
        (void)close(fd);
        return 2;
    }
    *fd_out = fd;
    return 0;
}

static int cl_publish(struct zcl_checkout_lock_hold *hold, int fd, int err_fd)
{
    const char *cur = getenv("ZCL_CHECKOUT_LOCK_HELD");
    if (cur) {
        hold->saved = strdup(cur);
        if (!hold->saved) {
            (void)flock(fd, LOCK_UN);
            (void)close(fd);
            cl_line(err_fd, k_prefix, "out of memory");
            return 2;
        }
    }
    if (setenv("ZCL_CHECKOUT_LOCK_HELD", "1", 1) != 0) {
        free(hold->saved);
        hold->saved = NULL;
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
        cl_line(err_fd, k_prefix, "could not export the held flag");
        return 2;
    }
    hold->fd = fd;
    hold->active = 1;
    return 0;
}

static int cl_wait(pid_t pid)
{
    for (;;) {
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) {
            if (errno == EINTR)
                continue;
            return 2;
        }
        if (WIFEXITED(st))
            return WEXITSTATUS(st);
        if (WIFSIGNALED(st))
            return 128 + WTERMSIG(st);
        return 2;
    }
}

static int cl_spawn(const char *const *argv, int err_fd)
{
    pid_t pid = 0;
    int rc = posix_spawnp(&pid, argv[0], NULL, NULL, (char *const *)argv,
                          environ);
    if (rc != 0) {
        cl_line(err_fd, k_prefix, "could not run command");
        return 127;
    }
    return cl_wait(pid);
}

#else

static void cl_line(int fd, const char *prefix, const char *text)
{
    (void)fd;
    if (prefix)
        fputs(prefix, stderr);
    if (text)
        fputs(text, stderr);
    fputc('\n', stderr);
}

#endif

int zcl_checkout_lock_enter(struct zcl_checkout_lock_hold *hold,
                            const char *mode, const char *lock_file,
                            int err_fd)
{
#if defined(_WIN32)
    (void)mode;
    (void)lock_file;
    if (hold)
        memset(hold, 0, sizeof(*hold));
    cl_line(err_fd, k_prefix, "not available on this host");
    return 2;
#else
    int fd = -1;
    int took;
    if (!hold)
        return 2;
    memset(hold, 0, sizeof(*hold));
    hold->fd = -1;
    if (!mode || !mode[0] || !lock_file || !lock_file[0]) {
        cl_line(err_fd, k_prefix, k_usage);
        return 2;
    }
    if (!cl_mode_ok(mode)) {
        char buf[160];
        (void)snprintf(buf, sizeof buf, "unknown mode: %s", mode);
        cl_line(err_fd, k_prefix, buf);
        return 2;
    }
    if (cl_already())
        return 0;
    took = cl_take(mode, lock_file, err_fd, &fd);
    if (took != 0)
        return took;
    return cl_publish(hold, fd, err_fd);
#endif
}

void zcl_checkout_lock_leave(struct zcl_checkout_lock_hold *hold)
{
    if (!hold || !hold->active)
        return;
#if !defined(_WIN32)
    if (hold->saved)
        (void)setenv("ZCL_CHECKOUT_LOCK_HELD", hold->saved, 1);
    else
        (void)unsetenv("ZCL_CHECKOUT_LOCK_HELD");
    (void)flock(hold->fd, LOCK_UN);
    (void)close(hold->fd);
#else
    (void)hold;
#endif
    free(hold->saved);
    hold->saved = NULL;
    hold->fd = -1;
    hold->active = 0;
}

int zcl_checkout_lock_run(const char *mode, const char *lock_file,
                          const char *const *argv, int err_fd)
{
    struct zcl_checkout_lock_hold hold;
    int st;
    int rc;
    if (!argv || !argv[0]) {
        cl_line(err_fd, k_prefix, k_usage);
        return 2;
    }
    st = zcl_checkout_lock_enter(&hold, mode, lock_file, err_fd);
    if (st != 0)
        return st;
#if defined(_WIN32)
    (void)mode;
    rc = 2;
#else
    rc = cl_spawn(argv, err_fd);
#endif
    zcl_checkout_lock_leave(&hold);
    return rc;
}
