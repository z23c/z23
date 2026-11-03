/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_proc_foreign_writer — Linux procfs scan for another same-uid process
 * holding a database file open for writing (declared in platform/os_proc.h).
 * Read-only: it reads /proc/<pid>/{fd,fdinfo,comm} and never signals the
 * process or opens the target file. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "platform/os_proc.h"

#include <stdint.h>
#include <string.h>

#if defined(__linux__)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define WRITER_PATH_MAX        4096
#define WRITER_MAX_PIDS        8192
#define WRITER_MAX_FDS         4096
#define WRITER_FLAGS_LINE_MAX  256

/* Strict decimal parse of a /proc entry name; false for anything else. */
static bool writer_decimal(const char *s, uint64_t *out)
{
    if (!*s)
        return false;
    uint64_t value = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || value > UINT32_MAX)
            return false;
        value = value * 10u + (uint64_t)(*s - '0');
    }
    *out = value;
    return true;
}

/* "/proc/<pid>/<sub>" or "/proc/<pid>/<sub>/<name>" into `out`. */
static bool writer_proc_leaf(char *out, size_t size, uint64_t pid,
                             const char *sub, const char *name)
{
    int n = name
        ? snprintf(out, size, "/proc/%" PRIu64 "/%s/%s", pid, sub, name)
        : snprintf(out, size, "/proc/%" PRIu64 "/%s", pid, sub);
    return n > 0 && (size_t)n < size;
}

/* True when /proc/<pid>/fd/<name> links to exactly `path` or `wal`. */
static bool writer_fd_names(const char *path, const char *wal,
                            uint64_t pid, const char *name)
{
    char fd[128];
    char link[WRITER_PATH_MAX];
    if (!writer_proc_leaf(fd, sizeof fd, pid, "fd", name))
        return false;
    ssize_t n = readlink(fd, link, sizeof link - 1);
    if (n <= 0)
        return false;
    link[n] = '\0';
    return strcmp(link, path) == 0 || strcmp(link, wal) == 0;
}

/* True when /proc/<pid>/fdinfo/<name> reports write access in `flags:`
 * (octal open flags; O_ACCMODE is O_RDONLY for read-only openers). */
static bool writer_fd_writable(uint64_t pid, const char *name)
{
    char info[128];
    if (!writer_proc_leaf(info, sizeof info, pid, "fdinfo", name))
        return false;
    FILE *f = fopen(info, "r");
    if (!f)
        return false;
    char line[WRITER_FLAGS_LINE_MAX];
    bool writable = false;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "flags:", 6) != 0)
            continue;
        errno = 0;
        char *end = NULL;
        unsigned long flags = strtoul(line + 6, &end, 8);
        writable = errno == 0 && end != line + 6 &&
                   ((unsigned long)O_ACCMODE & flags) != (unsigned long)O_RDONLY;
        break;
    }
    fclose(f);
    return writable;
}

/* True when `pid` holds `path` or `wal` open with write access. */
static bool writer_pid_holds_writable(uint64_t pid, const char *path,
                                      const char *wal)
{
    char dir[128];
    if (!writer_proc_leaf(dir, sizeof dir, pid, "fd", NULL))
        return false;
    DIR *fds = opendir(dir);
    if (!fds)
        return false;
    bool hit = false;
    int seen = 0;
    struct dirent *entry;
    while (!hit && seen < WRITER_MAX_FDS && (entry = readdir(fds)) != NULL) {
        uint64_t fd_number = 0;
        if (!writer_decimal(entry->d_name, &fd_number))
            continue;
        seen++;
        hit = writer_fd_names(path, wal, pid, entry->d_name) &&
              writer_fd_writable(pid, entry->d_name);
    }
    closedir(fds);
    return hit;
}

/* Same-uid ownership of /proc/<pid> (the kernel owns it by effective uid). */
static bool writer_same_owner(uint64_t pid, uid_t uid)
{
    char dir[128];
    struct stat st;
    if (!writer_proc_leaf(dir, sizeof dir, pid, "", NULL))
        return false;
    return stat(dir, &st) == 0 && st.st_uid == uid;
}

static void writer_read_comm(uint64_t pid, char comm[OS_PROC_COMM_MAX])
{
    comm[0] = '\0';
    char path[128];
    if (!writer_proc_leaf(path, sizeof path, pid, "comm", NULL))
        return;
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    if (fgets(comm, OS_PROC_COMM_MAX, f))
        comm[strcspn(comm, "\n")] = '\0';
    fclose(f);
}

static enum os_proc_writer_result writer_scan_pids(
    const char *path, const char *wal, struct os_proc_foreign_writer *out)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return OS_PROC_WRITER_NONE;
    uid_t uid = geteuid();
    uint64_t self = os_proc_current_pid();
    enum os_proc_writer_result result = OS_PROC_WRITER_NONE;
    int scanned = 0;
    struct dirent *entry;
    while (result == OS_PROC_WRITER_NONE && scanned < WRITER_MAX_PIDS &&
           (entry = readdir(proc)) != NULL) {
        uint64_t pid = 0;
        if (!writer_decimal(entry->d_name, &pid) || pid == 0 || pid == self)
            continue;
        scanned++;
        if (!writer_same_owner(pid, uid) ||
            !writer_pid_holds_writable(pid, path, wal))
            continue;
        out->pid = pid;
        writer_read_comm(pid, out->comm);
        result = OS_PROC_WRITER_FOUND;
    }
    closedir(proc);
    return result;
}
#endif

enum os_proc_writer_result os_proc_foreign_writer_find(
    const char *path, struct os_proc_foreign_writer *out)
{
#if defined(__linux__)
    char wal[WRITER_PATH_MAX];
    if (!out || !path || path[0] != '/')
        return OS_PROC_WRITER_NONE;
    int n = snprintf(wal, sizeof wal, "%s-wal", path);
    if (n <= 0 || (size_t)n >= sizeof wal)
        return OS_PROC_WRITER_NONE;
    out->pid = 0;
    out->comm[0] = '\0';
    return writer_scan_pids(path, wal, out);
#else
    (void)path;
    (void)out;
    return OS_PROC_WRITER_UNSUPPORTED;
#endif
}
