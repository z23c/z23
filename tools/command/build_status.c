/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: report the running and queued build jobs of command/build_admit.h
 *          as JSON. Holders come from /proc/locks, which lists every flock
 *          with its owner and inode, so jobs started by the installed
 *          devbuild wrapper appear alongside native ones. The read takes no
 *          lock and changes nothing.
 */

#include "command/build_admit.h"

#ifndef _WIN32

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

enum { BS_LOCKS_MAX = 512, BS_TEXT_MAX = 240, BS_NAME_MAX = 64, BS_LIST_MAX = 256 };

struct bs_lock {
    int pid;
    unsigned dev_major, dev_minor;
    unsigned long inode;
    bool write;
};

static size_t bs_load_locks(struct bs_lock *locks, size_t max)
{
    char line[256];
    size_t n = 0;
    FILE *f = fopen("/proc/locks", "r");
    if (!f)
        return 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        char kind[16], mode[16];
        struct bs_lock l;
        if (sscanf(line, "%*d: %15s %*s %15s %d %x:%x:%lu", kind, mode,
                   &l.pid, &l.dev_major, &l.dev_minor, &l.inode) == 6 &&
            strcmp(kind, "FLOCK") == 0) {
            l.write = strcmp(mode, "WRITE") == 0;
            locks[n++] = l;
        }
    }
    fclose(f);
    return n;
}

static bool bs_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

/* The kernel reports a flock under the pid that first took it, and the
 * wrapper takes its locks through a short-lived flock(1) child. The open
 * file description that holds the lock lists it in /proc/<pid>/fdinfo, so
 * the process that still owns it can be found by inode. */
static bool bs_file_lists_lock(const char *path, unsigned long inode)
{
    char line[256];
    unsigned long ino;
    bool found = false;
    FILE *f = fopen(path, "r");
    while (f && !found && fgets(line, sizeof(line), f))
        found = sscanf(line, "lock:\t%*d: FLOCK ADVISORY %*s %*d %*x:%*x:%lu",
                       &ino) == 1 && ino == inode;
    if (f)
        fclose(f);
    return found;
}

static bool bs_process_owns(const char *pid, unsigned long inode)
{
    char dir[64], path[128];
    bool found = false;
    DIR *fds;
    (void)snprintf(dir, sizeof(dir), "/proc/%s/fdinfo", pid);
    fds = opendir(dir);
    for (struct dirent *e = fds ? readdir(fds) : NULL; e && !found;
         e = readdir(fds))
        found = e->d_name[0] != '.' &&
                snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) <
                    (int)sizeof(path) && bs_file_lists_lock(path, inode);
    if (fds)
        closedir(fds);
    return found;
}

static int bs_fdinfo_owner(unsigned long inode)
{
    DIR *proc = opendir("/proc");
    int owner = 0;
    for (struct dirent *p = proc ? readdir(proc) : NULL; p && !owner;
         p = readdir(proc))
        if (p->d_name[0] >= '1' && p->d_name[0] <= '9' &&
            bs_process_owns(p->d_name, inode))
            owner = atoi(p->d_name);
    if (proc)
        closedir(proc);
    return owner;
}

static bool bs_pid_visible(int pid)
{
    char path[64];
    struct stat sb;
    (void)snprintf(path, sizeof(path), "/proc/%d", pid);
    return pid > 0 && stat(path, &sb) == 0;
}

/* Holders of `path` in `locks`: pids written to `pids`, any WRITE flagged. */
static size_t bs_holders(const struct bs_lock *locks, size_t nlocks,
                         const char *path, int *pids, size_t max, bool *write)
{
    struct stat sb;
    size_t n = 0;
    *write = false;
    if (stat(path, &sb) != 0)
        return 0;
    for (size_t i = 0; i < nlocks; i++) {
        if (locks[i].inode != (unsigned long)sb.st_ino ||
            locks[i].dev_major != major(sb.st_dev) ||
            locks[i].dev_minor != minor(sb.st_dev))
            continue;
        if (n < max) {
            int owner = bs_pid_visible(locks[i].pid)
                            ? locks[i].pid : bs_fdinfo_owner(locks[i].inode);
            pids[n++] = owner ? owner : locks[i].pid;
        }
        *write = *write || locks[i].write;
    }
    return n;
}

static void bs_push_process(struct json_value *row, int pid)
{
    char path[64], text[BS_TEXT_MAX], cwd[BS_TEXT_MAX];
    ssize_t n = 0;
    FILE *f;
    (void)json_push_kv_int(row, "pid", pid);
    text[0] = cwd[0] = '\0';
    (void)snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = pid > 0 ? fopen(path, "r") : NULL;
    if (f) {
        n = (ssize_t)fread(text, 1, sizeof(text) - 1u, f);
        fclose(f);
    }
    for (ssize_t i = 0; i < n; i++)
        if (text[i] == '\0')
            text[i] = ' ';
    text[n > 0 ? n : 0] = '\0';
    (void)snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    n = pid > 0 ? readlink(path, cwd, sizeof(cwd) - 1u) : -1;
    cwd[n > 0 ? n : 0] = '\0';
    (void)json_push_kv_str(row, "cmd", text);
    (void)json_push_kv_str(row, "cwd", cwd);
}

static int bs_name_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static size_t bs_list(const char *dir, char (*names)[BS_NAME_MAX], size_t max)
{
    DIR *d = opendir(dir);
    size_t n = 0;
    if (!d)
        return 0;
    for (struct dirent *e = readdir(d); e && n < max; e = readdir(d))
        if (e->d_name[0] != '.' && strlen(e->d_name) < BS_NAME_MAX)
            memcpy(names[n++], e->d_name, strlen(e->d_name) + 1u);
    closedir(d);
    qsort(names, n, BS_NAME_MAX, bs_name_cmp);
    return n;
}

static void bs_push_lanes(struct json_value *out, const char *state_dir,
                          const struct bs_lock *locks, size_t nlocks)
{
    static const char *const name[BA_MAX_LANES] = {
        "z23.lock", "z23.lock.1", "z23.lock.2", "z23.lock.3"
    };
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (int i = 0; i < BA_MAX_LANES; i++) {
        char path[BA_PATH_MAX];
        int pids[8];
        bool write;
        size_t n = bs_join(path, sizeof(path), state_dir, name[i])
                       ? bs_holders(locks, nlocks, path, pids, 8, &write) : 0;
        for (size_t k = 0; k < n && write; k++) {
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_int(&row, "lane", i + 1);
            bs_push_process(&row, pids[k]);
            (void)json_push_back(&rows, &row);
            json_free(&row);
        }
    }
    (void)json_push_kv(out, "running", &rows);
    json_free(&rows);
}

/* Waiters of one directory in ticket order; entries nobody holds are stale
 * and skipped. A ticket name is <seconds><9-digit ns>-<pid>. */
static size_t bs_push_waiters(struct json_value *out, const char *key,
                              const char *dir, const struct bs_lock *locks,
                              size_t nlocks)
{
    char names[BS_LIST_MAX][BS_NAME_MAX];
    size_t n = bs_list(dir, names, BS_LIST_MAX), live = 0;
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < n; i++) {
        char path[BA_PATH_MAX];
        int pids[4];
        bool write;
        size_t digits = strcspn(names[i], "-");
        struct json_value row;
        if (!bs_join(path, sizeof(path), dir, names[i]) ||
            bs_holders(locks, nlocks, path, pids, 4, &write) == 0)
            continue;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_int(&row, "position", (int64_t)++live);
        (void)json_push_kv_str(&row, "ticket", names[i]);
        (void)json_push_kv_int(&row, "enqueued",
                               digits > 9 ? strtoll(names[i], NULL, 10) /
                                   1000000000LL : 0);
        bs_push_process(&row, pids[0]);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(out, key, &rows);
    json_free(&rows);
    return live;
}

bool ba_status(const char *state_dir, struct json_value *out)
{
    struct bs_lock locks[BS_LOCKS_MAX];
    size_t nlocks = bs_load_locks(locks, BS_LOCKS_MAX);
    char dir[BA_PATH_MAX], heavy[BA_PATH_MAX];
    int pids[4];
    bool exclusive = false;
    (void)json_push_kv_str(out, "state_dir", state_dir);
    bs_push_lanes(out, state_dir, locks, nlocks);
    if (!bs_join(dir, sizeof(dir), state_dir, "z23.fifo") ||
        !bs_join(heavy, sizeof(heavy), state_dir, "heavy.lock"))
        return false;
    (void)bs_push_waiters(out, "queued", dir, locks, nlocks);
    if (!bs_join(dir, sizeof(dir), state_dir, "z23.prio"))
        return false;
    (void)bs_push_waiters(out, "landing", dir, locks, nlocks);
    (void)bs_holders(locks, nlocks, heavy, pids, 4, &exclusive);
    (void)json_push_kv_bool(out, "exclusive_build", exclusive);
    return true;
}

#endif /* _WIN32 */
