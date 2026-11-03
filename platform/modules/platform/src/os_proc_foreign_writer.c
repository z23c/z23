/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_proc_foreign_writer — Linux procfs scan for another same-uid process
 * holding a database file open for writing (declared in platform/os_proc.h).
 * Read-only: it stats /proc/<pid>/fd/<n> and reads /proc/<pid>/{fdinfo,comm};
 * it never signals the process or opens the target file. Matching is by
 * device and inode, so symlinked datadirs and bind mounts match. Only the
 * database file and its -wal are targets; -shm is deliberately not one. */

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
#define WRITER_MAX_FDS         4096
#define WRITER_FLAGS_LINE_MAX  256
#define WRITER_TARGET_MAX      2

/* Identities of the files a holder must have open: the database and its WAL. */
struct writer_targets {
    size_t count;
    dev_t dev[WRITER_TARGET_MAX];
    ino_t ino[WRITER_TARGET_MAX];
};

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

static bool writer_stat_regular(const char *path, struct stat *st)
{
    return stat(path, st) == 0 && S_ISREG(st->st_mode);
}

/* Records the identity of `path`; false when it is not a regular file. */
static bool writer_add_target(struct writer_targets *t, const char *path)
{
    struct stat st;
    if (t->count >= WRITER_TARGET_MAX || !writer_stat_regular(path, &st))
        return false;
    t->dev[t->count] = st.st_dev;
    t->ino[t->count] = st.st_ino;
    t->count++;
    return true;
}

/* Stat the database once per scan. The database must exist; the WAL is
 * optional. stat() follows symlinks, so a symlinked datadir resolves to the
 * real inode. */
static bool writer_targets_read(const char *path,
                                struct writer_targets *t)
{
    char wal[WRITER_PATH_MAX];
    int n = snprintf(wal, sizeof wal, "%s-wal", path);
    if (n <= 0 || (size_t)n >= sizeof wal)
        return false;
    memset(t, 0, sizeof *t);
    if (!writer_add_target(t, path))
        return false;
    (void)writer_add_target(t, wal);
    return true;
}

/* True when /proc/<pid>/fd/<name> resolves to one of the target inodes. */
static bool writer_fd_is_target(uint64_t pid, const char *name,
                                const struct writer_targets *t)
{
    char fd[128];
    struct stat st;
    if (!writer_proc_leaf(fd, sizeof fd, pid, "fd", name) ||
        !writer_stat_regular(fd, &st))
        return false;
    for (size_t i = 0; i < t->count; i++) {
        if (st.st_dev == t->dev[i] && st.st_ino == t->ino[i])
            return true;
    }
    return false;
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

/* True when `pid` holds a target open with write access. */
static bool writer_pid_holds_writable(uint64_t pid,
                                      const struct writer_targets *t)
{
    char dir[128];
    if (!writer_proc_leaf(dir, sizeof dir, pid, "fd", NULL))
        return false;
    DIR *fds = opendir(dir);
    if (!fds)
        return false;
    bool hit = false;
    size_t seen = 0;
    struct dirent *entry;
    while (!hit && seen < WRITER_MAX_FDS && (entry = readdir(fds)) != NULL) {
        uint64_t fd_number = 0;
        if (!writer_decimal(entry->d_name, &fd_number))
            continue;
        seen++;
        hit = writer_fd_is_target(pid, entry->d_name, t) &&
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
    const struct writer_targets *t, size_t max_pids,
    struct os_proc_foreign_writer *out)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return OS_PROC_WRITER_NONE;
    uid_t uid = geteuid();
    uint64_t self = os_proc_current_pid();
    enum os_proc_writer_result result = OS_PROC_WRITER_NONE;
    size_t scanned = 0;
    struct dirent *entry;
    while (result == OS_PROC_WRITER_NONE && (entry = readdir(proc)) != NULL) {
        uint64_t pid = 0;
        if (!writer_decimal(entry->d_name, &pid) || pid == 0 || pid == self)
            continue;
        if (scanned >= max_pids) {
            result = OS_PROC_WRITER_INCOMPLETE;
            break;
        }
        scanned++;
        if (!writer_same_owner(pid, uid) ||
            !writer_pid_holds_writable(pid, t))
            continue;
        out->pid = pid;
        writer_read_comm(pid, out->comm);
        result = OS_PROC_WRITER_FOUND;
    }
    closedir(proc);
    return result;
}
#endif

enum os_proc_writer_result os_proc_foreign_writer_find_bounded(
    const char *path, struct os_proc_foreign_writer *out, size_t max_pids)
{
#if defined(__linux__)
    if (!out || !path || path[0] != '/')
        return OS_PROC_WRITER_NONE;
    out->pid = 0;
    out->comm[0] = '\0';
    struct writer_targets targets;
    if (!writer_targets_read(path, &targets))
        return OS_PROC_WRITER_NONE;
    return writer_scan_pids(&targets, max_pids, out);
#else
    (void)path;
    (void)out;
    (void)max_pids;
    return OS_PROC_WRITER_UNSUPPORTED;
#endif
}

enum os_proc_writer_result os_proc_foreign_writer_find(
    const char *path, struct os_proc_foreign_writer *out)
{
    return os_proc_foreign_writer_find_bounded(path, out,
                                               OS_PROC_WRITER_MAX_PIDS);
}
