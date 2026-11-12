/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One bounded flock for every compile-epoch waiter. A stuck holder
 *          turns the caller red with the lock path and the holder pid. */

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#include "build_epoch_lock_wait.h"

#include "platform/clock.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

static void bel_write(int fd, const char *text)
{
    size_t n;
    if (!text)
        return;
    n = strlen(text);
#if defined(_WIN32)
    (void)fd;
    (void)fwrite(text, 1, n, stderr);
#else
    if (fd < 0)
        fd = STDERR_FILENO;
    while (n > 0) {
        ssize_t w = write(fd, text, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        text += w;
        n -= (size_t)w;
    }
#endif
}

static void bel_line(int fd, const char *text)
{
    bel_write(fd, text);
    bel_write(fd, "\n");
}

/* Positive integer with no leading zero. Empty selects the default. */
static int bel_timeout(char *raw, size_t raw_cap)
{
    const char *env = getenv("ZCL_BUILD_EPOCH_LOCK_TIMEOUT");
    const char *p;
    if (!env || !env[0]) {
        (void)snprintf(raw, raw_cap, "%s", "120");
        return 120;
    }
    (void)snprintf(raw, raw_cap, "%s", env);
    if (env[0] < '1' || env[0] > '9')
        return -1;
    for (p = env + 1; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
    }
    return atoi(env);
}

#if !defined(_WIN32)

static int bel_same_file(const char *lock, const char *fd_path)
{
    struct stat a, b;
    if (stat(lock, &a) != 0 || stat(fd_path, &b) != 0)
        return 0;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int bel_pid_listed(const char *holders, const char *pid)
{
    char needle[32];
    if (strlen(pid) > 20)
        return 0;
    (void)snprintf(needle, sizeof needle, " %s ", pid);
    return strstr(holders, needle) != NULL;
}

static void bel_note_pid(char *holders, size_t cap, const char *pid)
{
    size_t n = strlen(holders);
    int wr;
    if (bel_pid_listed(holders, pid))
        return;
    wr = snprintf(holders + n, cap - n, "%s%s", n > 1 ? " " : "", pid);
    if (wr < 0 || (size_t)wr >= cap - n)
        holders[n] = '\0';
}

static void bel_scan_pid(const char *lock, const char *pid, char *holders,
                         size_t cap)
{
    char dirpath[PATH_MAX];
    char fdpath[PATH_MAX];
    char target[PATH_MAX];
    DIR *dir;
    struct dirent *ent;
    if (snprintf(dirpath, sizeof dirpath, "/proc/%s/fd", pid) >=
        (int)sizeof dirpath)
        return;
    dir = opendir(dirpath);
    if (!dir)
        return;
    while ((ent = readdir(dir)) != NULL) {
        ssize_t n;
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;
        if (snprintf(fdpath, sizeof fdpath, "%s/%s", dirpath, ent->d_name) >=
            (int)sizeof fdpath)
            continue;
        n = readlink(fdpath, target, sizeof target - 1);
        if (n < 0)
            continue;
        target[n] = '\0';
        if (strcmp(target, lock) != 0) {
            char deleted[PATH_MAX];
            (void)snprintf(deleted, sizeof deleted, "%s (deleted)", lock);
            if (strcmp(target, deleted) != 0)
                continue;
        }
        if (!bel_same_file(lock, fdpath))
            continue;
        bel_note_pid(holders, cap, pid);
        break;
    }
    closedir(dir);
}

static int bel_pid_name(const char *name, const char *self)
{
    const char *p;
    if (!name || name[0] < '1' || name[0] > '9')
        return 0;
    for (p = name + 1; *p; p++) {
        if (*p < '0' || *p > '9')
            return 0;
    }
    return strcmp(name, self) != 0;
}

static void bel_scan_proc(const char *lock, char *out, size_t cap)
{
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    char self[32];
    if (!proc)
        return;
    (void)snprintf(self, sizeof self, "%ld", (long)getpid());
    while ((ent = readdir(proc)) != NULL) {
        if (!bel_pid_name(ent->d_name, self))
            continue;
        bel_scan_pid(lock, ent->d_name, out, cap);
    }
    closedir(proc);
}

static void bel_holders(const char *lock, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s", " ");
    if (lock && lock[0] && access(lock, F_OK) == 0)
        bel_scan_proc(lock, out, cap);
    if (out[0] == ' ' && out[1] == '\0')
        (void)snprintf(out, cap, "%s",
                       "unknown (no matching open file descriptor found)");
    else if (out[0] == ' ')
        memmove(out, out + 1, strlen(out));
}

static int bel_wait(int fd, int seconds)
{
    int64_t start = clock_now_monotonic_ns();
    int64_t limit = (int64_t)seconds * INT64_C(1000000000);
    struct timespec pause;
    if (start < 0)
        return -1;
    pause.tv_sec = 0;
    pause.tv_nsec = 20000000L;
    for (;;) {
        int64_t now;
        if (flock(fd, LOCK_EX | LOCK_NB) == 0)
            return 0;
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR)
            return -1;
        now = clock_now_monotonic_ns();
        if (now < 0 || now - start >= limit)
            return -1;
        (void)nanosleep(&pause, NULL);
    }
}

#else

static void bel_holders(const char *lock, char *out, size_t cap)
{
    (void)lock;
    (void)snprintf(out, cap, "%s",
                   "unknown (no matching open file descriptor found)");
}

static int bel_wait(int fd, int seconds)
{
    (void)fd;
    (void)seconds;
    return -1;
}

#endif

int zcl_build_epoch_flock_bounded(const char *tag, int fd,
                                  const char *lock_file, const char *kind,
                                  int err_fd)
{
    char shown[64];
    char msg[1024];
    char holders[512];
    int seconds = bel_timeout(shown, sizeof shown);
    if (!tag)
        tag = "";
    if (!lock_file)
        lock_file = "";
    if (!kind)
        kind = "";
    if (seconds < 0) {
        (void)snprintf(msg, sizeof msg,
                       "%s: invalid ZCL_BUILD_EPOCH_LOCK_TIMEOUT=%s (must be "
                       "a positive integer number of seconds)",
                       tag, shown);
        bel_line(err_fd, msg);
        return 1;
    }
    if (bel_wait(fd, seconds) == 0)
        return 0;
    bel_holders(lock_file, holders, sizeof holders);
    (void)snprintf(msg, sizeof msg,
                   "%s: timed out after %ds waiting for exclusive %s lock %s "
                   "(held by pid(s): %s)",
                   tag, seconds, kind, lock_file, holders);
    bel_line(err_fd, msg);
    return 1;
}
