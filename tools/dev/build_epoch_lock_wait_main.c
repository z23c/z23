/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host tool the epoch shell drivers exec. The lock fd is inherited.
 *          Exit leaves it held on that open file description. */

#include "build_epoch_lock_wait.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#if defined(__linux__) || defined(__APPLE__)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>

/* A lease is removable only when its record is complete and kill reports
 * ESRCH. Every unreadable, malformed or otherwise uncertain entry protects
 * the generation. The caller holds the epoch GC lock. */
static bool lease_pid(const char *buf, ssize_t n, long *pid)
{
    char expected[32], *end;
    if (strncmp(buf, "pid=", 4) != 0) return false;
    errno = 0;
    *pid = strtol(buf + 4, &end, 10);
    if (errno || *pid <= 0 || *pid > INT_MAX || strncmp(end, "\nstart=", 7) != 0)
        return false;
    int len = snprintf(expected, sizeof(expected), "pid=%ld", *pid);
    if (len != end - buf || memcmp(expected, buf, (size_t)len) != 0) return false;
    const char *start = end + 7;
    size_t digits = strspn(start, "0123456789abcdef");
    return digits > 0 && digits <= 64 && start[digits] == '\n' &&
           start + digits + 1 == buf + n;
}

static int retire_dead_lease(int dirfd, const char *name)
{
    char buf[128];
    long pid;
    struct stat st;
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return 1; }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    int ok = n == st.st_size && n > 0 && n < (ssize_t)sizeof(buf) - 1;
    if (close(fd) != 0) ok = 0;
    if (!ok) return 1;
    buf[n] = '\0';
    if (!lease_pid(buf, n, &pid)) return 1;
    if (kill((pid_t)pid, 0) == 0 || errno != ESRCH) return 1;
    return unlinkat(dirfd, name, 0) == 0 ? 0 : 1;
}

static int retire_dead_leases(const char *path)
{
    int parent = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return 1;
    struct stat st;
    if (fstatat(parent, ".unverified", &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        close(parent); return 1;
    }
    int fd = openat(parent, ".leases", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved_errno = errno;
    if (close(parent) != 0) { if (fd >= 0) close(fd); return 1; }
    if (fd < 0) return saved_errno == ENOENT ? 0 : 1;
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return 1; }
    int unsafe = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (retire_dead_lease(fd, entry->d_name)) unsafe = 1;
        errno = 0;
    }
    if (errno) unsafe = 1;
    if (closedir(dir) != 0) unsafe = 1;
    return unsafe;
}
#else
static int retire_dead_leases(const char *path) { (void)path; return 1; }
#endif

int main(int argc, char **argv)
{
    char *end = NULL;
    long fd;
    if (argc == 3 && strcmp(argv[1], "retire-dead-leases") == 0)
        return retire_dead_leases(argv[2]);
    if (argc != 5) {
        fprintf(stderr,
                "build-epoch-lock-wait: usage: build-epoch-lock-wait "
                "TAG FD LOCK_FILE KIND\n");
        return 2;
    }
    fd = strtol(argv[2], &end, 10);
    if (!end || *end || fd < 0 || fd > 1023)
        return zcl_build_epoch_flock_bounded(argv[1], -1, argv[3], argv[4],
                                             STDERR_FILENO);
    return zcl_build_epoch_flock_bounded(argv[1], (int)fd, argv[3], argv[4],
                                         STDERR_FILENO);
}
