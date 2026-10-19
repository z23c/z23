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

enum { BS_LOCKS_MAX = 512, BS_TEXT_MAX = 240 };

struct bs_lock {
    int pid;
    unsigned dev_major, dev_minor;
    unsigned long inode;
    bool write;
};

/* Every flock of the host, and for each one whose recorded pid has exited
 * the live process that still holds its open file description (0: none
 * found). The owners are looked up once per status call. */
struct bs_view {
    struct bs_lock locks[BS_LOCKS_MAX];
    int owner[BS_LOCKS_MAX];
    size_t count;
    bool scanned;
    uid_t uid;                       /* whose processes may be scanned */
};

static void bs_load_locks(struct bs_view *v)
{
    char line[256];
    FILE *f = fopen("/proc/locks", "r");
    memset(v->owner, 0, sizeof(v->owner));
    v->count = 0;
    v->scanned = false;
    while (f && v->count < BS_LOCKS_MAX && fgets(line, sizeof(line), f)) {
        char kind[16], mode[16];
        struct bs_lock l;
        if (sscanf(line, "%*d: %15s %*s %15s %d %x:%x:%lu", kind, mode,
                   &l.pid, &l.dev_major, &l.dev_minor, &l.inode) == 6 &&
            strcmp(kind, "FLOCK") == 0) {
            l.write = strcmp(mode, "WRITE") == 0;
            v->locks[v->count++] = l;
        }
    }
    if (f)
        fclose(f);
}

static bool bs_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

static bool bs_pid_visible(int pid)
{
    char path[64];
    struct stat sb;
    (void)snprintf(path, sizeof(path), "/proc/%d", pid);
    return pid > 0 && stat(path, &sb) == 0;
}

/* Record `pid` as the owner of one orphaned lock on this file, at most once
 * per process so descriptors duplicated by dup or fork count once. */
static void bs_claim(struct bs_view *v, unsigned maj, unsigned min,
                     unsigned long inode, int pid)
{
    size_t slot = v->count;
    for (size_t i = 0; i < v->count; i++) {
        if (v->locks[i].inode != inode || v->locks[i].dev_major != maj ||
            v->locks[i].dev_minor != min)
            continue;
        if (v->owner[i] == pid)
            return;
        if (v->owner[i] == 0 && slot == v->count &&
            !bs_pid_visible(v->locks[i].pid))
            slot = i;
    }
    if (slot < v->count)
        v->owner[slot] = pid;
}

/* The kernel reports a flock under the pid that first took it, and the
 * wrapper takes its locks through a short-lived flock(1) child. The open
 * file description that holds the lock lists it in /proc/<pid>/fdinfo, so
 * the process that still owns it is found by device and inode. */
static void bs_scan_file(struct bs_view *v, const char *path, int pid)
{
    char line[256];
    unsigned maj, min;
    unsigned long ino;
    FILE *f = fopen(path, "r");
    while (f && fgets(line, sizeof(line), f))
        if (sscanf(line, "lock:\t%*d: FLOCK ADVISORY %*s %*d %x:%x:%lu",
                   &maj, &min, &ino) == 3)
            bs_claim(v, maj, min, ino, pid);
    if (f)
        fclose(f);
}

static void bs_scan_process(struct bs_view *v, const char *name)
{
    char dir[64], path[128];
    DIR *fds;
    (void)snprintf(dir, sizeof(dir), "/proc/%s/fdinfo", name);
    fds = opendir(dir);
    for (struct dirent *e = fds ? readdir(fds) : NULL; e; e = readdir(fds))
        if (e->d_name[0] != '.' && bs_join(path, sizeof(path), dir, e->d_name))
            bs_scan_file(v, path, atoi(name));
    if (fds)
        closedir(fds);
}

/* Only processes of user `me` are read: the listing never looks into another
 * account's descriptors. */
static void bs_scan_owners(struct bs_view *v, uid_t me)
{
    DIR *proc = opendir("/proc");
    v->scanned = true;
    for (struct dirent *p = proc ? readdir(proc) : NULL; p; p = readdir(proc)) {
        char path[64];
        struct stat sb;
        if (p->d_name[0] < '1' || p->d_name[0] > '9' ||
            !bs_join(path, sizeof(path), "/proc", p->d_name) ||
            stat(path, &sb) != 0 || sb.st_uid != me)
            continue;
        bs_scan_process(v, p->d_name);
    }
    if (proc)
        closedir(proc);
}

/* Holders of `path`: pids written to `pids` (0 when the holder cannot be
 * named), any WRITE flagged. */
static size_t bs_holders(struct bs_view *v, const char *path, int *pids,
                         size_t max, bool *write)
{
    struct stat sb;
    size_t n = 0;
    *write = false;
    if (stat(path, &sb) != 0)
        return 0;
    for (size_t i = 0; i < v->count; i++) {
        if (v->locks[i].inode != (unsigned long)sb.st_ino ||
            v->locks[i].dev_major != major(sb.st_dev) ||
            v->locks[i].dev_minor != minor(sb.st_dev))
            continue;
        if (n < max) {
            if (!bs_pid_visible(v->locks[i].pid) && !v->scanned)
                bs_scan_owners(v, v->uid);
            pids[n++] = bs_pid_visible(v->locks[i].pid) ? v->locks[i].pid
                                                       : v->owner[i];
        }
        *write = *write || v->locks[i].write;
    }
    return n;
}

static void bs_push_process(struct json_value *row, int pid)
{
    char path[64], text[BS_TEXT_MAX], cwd[BS_TEXT_MAX];
    ssize_t n = 0;
    FILE *f;
    if (pid <= 0)
        return;
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

static void bs_push_lanes(struct json_value *out, const char *state_dir,
                          struct bs_view *view)
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
                       ? bs_holders(view, path, pids, 8, &write) : 0;
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
                              const char *dir, struct bs_view *view)
{
    char (*names)[BA_NAME_MAX];
    size_t n, live = 0;
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    if (!ba_list_names(dir, &names, &n))
        n = 0;
    for (size_t i = 0; i < n; i++) {
        char path[BA_PATH_MAX];
        int pids[4];
        bool write;
        size_t digits = strcspn(names[i], "-");
        struct json_value row;
        if (!bs_join(path, sizeof(path), dir, names[i]) ||
            bs_holders(view, path, pids, 4, &write) == 0)
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
    free(names);
    (void)json_push_kv(out, key, &rows);
    json_free(&rows);
    return live;
}

bool ba_status_as(const char *state_dir, uid_t uid, struct json_value *out)
{
    struct bs_view view;
    char dir[BA_PATH_MAX], heavy[BA_PATH_MAX];
    int pids[4];
    bool exclusive = false;
    (void)json_push_kv_str(out, "state_dir", state_dir);
    bs_load_locks(&view);
    view.uid = uid;
    bs_push_lanes(out, state_dir, &view);
    if (!bs_join(dir, sizeof(dir), state_dir, "z23.fifo") ||
        !bs_join(heavy, sizeof(heavy), state_dir, "heavy.lock"))
        return false;
    (void)bs_push_waiters(out, "queued", dir, &view);
    if (!bs_join(dir, sizeof(dir), state_dir, "z23.prio"))
        return false;
    (void)bs_push_waiters(out, "landing", dir, &view);
    (void)bs_holders(&view, heavy, pids, 4, &exclusive);
    (void)json_push_kv_bool(out, "exclusive_build", exclusive);
    return true;
}

bool ba_status(const char *state_dir, struct json_value *out)
{
    return ba_status_as(state_dir, geteuid(), out);
}

#endif /* _WIN32 */
