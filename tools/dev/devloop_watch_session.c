/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: resident-watcher launch identity and whole-session stop (POSIX). */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "devloop_watch_session.h"
#include "devloop.h"

#if !defined(_WIN32)
#include "platform/os_proc.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define SESSION_SCHEMA "zcl.dev_watch_session.v2"
#define SESSION_BOOT_MAX 64
#define SESSION_MEMBER_MAX 64
/* After the cooperative phase: session SIGTERM, then session SIGKILL. */
#define SESSION_TERM_TAIL_MS 2000
#define SESSION_KILL_TAIL_MS 1000
#define SESSION_DEFAULT_BUDGET_MS 10000
#define SESSION_POLL_MS 25

struct session_record {
    uint64_t born;
    char boot[SESSION_BOOT_MAX];
    unsigned long long exe_dev;
    unsigned long long exe_ino;
};

static bool session_dir(const char *root, char out[PATH_MAX])
{
    if (!root || !root[0])
        return false;
    int n = snprintf(out, PATH_MAX, "%s/%s", root,
                     ZCL_DEVLOOP_WATCH_SESSION_DIR_REL);
    return n > 0 && n < PATH_MAX;
}

static bool session_path(const char *root, int64_t pid, char out[PATH_MAX])
{
    char dir[PATH_MAX];
    if (pid <= 1 || pid > INT_MAX || !session_dir(root, dir))
        return false;
    int n = snprintf(out, PATH_MAX, "%s/%lld", dir, (long long)pid);
    return n > 0 && n < PATH_MAX;
}

static void session_forget(const char *root, int64_t pid)
{
    char path[PATH_MAX];
    if (session_path(root, pid, path))
        (void)unlink(path);
}

/* EPERM is another user's process: never one of ours. A zombie is dead. */
static bool leader_running(int64_t pid)
{
    if (kill((pid_t)pid, 0) != 0)
        return false;
#if defined(__linux__)
    char path[64], body[512];
    int n = snprintf(path, sizeof(path), "/proc/%lld/stat", (long long)pid);
    int fd = n > 0 && n < (int)sizeof(path)
        ? open(path, O_RDONLY | O_CLOEXEC) : -1;
    if (fd < 0)
        return false;
    ssize_t got = read(fd, body, sizeof(body) - 1);
    (void)close(fd);
    if (got <= 0)
        return false;
    body[got] = 0;
    const char *paren = strrchr(body, ')');
    return paren && paren[1] == ' ' && paren[2] != 'Z';
#else
    return true;
#endif
}

static bool session_running(int64_t pid)
{
    return zcl_devloop_process_session_members(pid, 0) > 0;
}

#if defined(__linux__)
static bool boot_id_read(char out[SESSION_BOOT_MAX])
{
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t got = read(fd, out, SESSION_BOOT_MAX - 1);
    (void)close(fd);
    if (got <= 0)
        return false;
    out[got] = 0;
    size_t len = strcspn(out, "\n");
    out[len] = 0;
    for (size_t i = 0; i < len; i++)
        if (!isxdigit((unsigned char)out[i]) && out[i] != '-')
            return false;
    return len >= 8;
}

static bool proc_link_stat(int64_t pid, const char *what, struct stat *st)
{
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%lld/%s", (long long)pid,
                     what);
    return n > 0 && n < (int)sizeof(path) && stat(path, st) == 0;
}

static bool image_name_is_dev(const char *base)
{
    static const char *const k_names[] = {"z23-dev", "zclassic23-dev",
                                          "z23.dev"};
    size_t base_len = strlen(base);
    for (size_t i = 0; i < sizeof(k_names) / sizeof(k_names[0]); i++) {
        size_t len = strlen(k_names[i]);
        if (base_len < len || strcmp(base + base_len - len, k_names[i]) != 0)
            continue;
        if (base_len == len || base[base_len - len - 1] == '-')
            return true;
    }
    return false;
}

/* The image `pid` runs (`exe`) is a dev binary: this process's own image,
 * or a file carrying a dev binary's name (a rebuilt one reads
 * "<path> (deleted)"). */
static bool self_image_is(const struct stat *exe)
{
    FILE *self_exe = os_proc_open_self_exe();
    if (!self_exe)
        return false;
    struct stat self;
    bool same = fstat(fileno(self_exe), &self) == 0 &&
                self.st_dev == exe->st_dev && self.st_ino == exe->st_ino;
    (void)fclose(self_exe);
    return same;
}

static bool pid_image_is_dev(int64_t pid, const struct stat *exe)
{
    if (self_image_is(exe))
        return true;
    char path[64], target[PATH_MAX];
    int n = snprintf(path, sizeof(path), "/proc/%lld/exe", (long long)pid);
    ssize_t got = n > 0 && n < (int)sizeof(path)
        ? readlink(path, target, sizeof(target) - 1) : -1;
    if (got <= 0)
        return false;
    target[got] = 0;
    static const char k_deleted[] = " (deleted)";
    size_t len = (size_t)got, dlen = sizeof(k_deleted) - 1;
    if (len >= dlen && strcmp(target + len - dlen, k_deleted) == 0)
        target[len - dlen] = 0;
    const char *base = strrchr(target, '/');
    return image_name_is_dev(base ? base + 1 : target);
}

static bool proc_cwd_is(int64_t pid, const struct stat *root_st)
{
    struct stat cwd;
    return proc_link_stat(pid, "cwd", &cwd) && cwd.st_dev == root_st->st_dev &&
           cwd.st_ino == root_st->st_ino;
}

enum proc_match {
    /* Runs the recorded image, and that image is a dev binary. */
    PROC_MATCH,
    /* Runs something else: proof against the record. */
    PROC_OTHER,
    /* No image to read: the process is exiting (its address space, and
     * with it /proc/<pid>/exe, goes before its open files and its pid), or
     * belongs to another user. Neither proof nor disproof. */
    PROC_UNREADABLE,
};

static enum proc_match proc_match_record(int64_t pid,
                                         const struct session_record *rec)
{
    struct stat exe;
    if (!proc_link_stat(pid, "exe", &exe))
        return PROC_UNREADABLE;
    if ((unsigned long long)exe.st_dev == rec->exe_dev &&
        (unsigned long long)exe.st_ino == rec->exe_ino &&
        pid_image_is_dev(pid, &exe))
        return PROC_MATCH;
    return proc_link_stat(pid, "exe", &exe) ? PROC_OTHER : PROC_UNREADABLE;
}

static bool session_prepare_dir(const char *root, char dir[PATH_MAX])
{
    char cache[PATH_MAX];
    if (!session_dir(root, dir))
        return false;
    int n = snprintf(cache, sizeof(cache), "%s/.cache", root);
    return n > 0 && n < (int)sizeof(cache) &&
           platform_private_directory_ensure(cache) &&
           platform_private_directory_ensure(dir);
}

static bool session_record(const char *root, int64_t pid)
{
    char dir[PATH_MAX], path[PATH_MAX], tmp[PATH_MAX], body[256];
    char boot[SESSION_BOOT_MAX];
    uint64_t born = 0;
    struct stat exe;
    if (!session_path(root, pid, path) || !session_prepare_dir(root, dir) ||
        !os_proc_pid_start_token((uint64_t)pid, &born) ||
        !boot_id_read(boot) || !proc_link_stat(pid, "exe", &exe))
        return false;
    int t = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int len = snprintf(body, sizeof(body), SESSION_SCHEMA " %lld %llu %s %llu %llu\n",
                       (long long)pid, (unsigned long long)born, boot,
                       (unsigned long long)exe.st_dev,
                       (unsigned long long)exe.st_ino);
    if (t <= 0 || t >= (int)sizeof(tmp) || len <= 0 ||
        len >= (int)sizeof(body))
        return false;
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0)
        return false;
    bool ok = write(fd, body, (size_t)len) == (ssize_t)len;
    ok = close(fd) == 0 && ok;
    if (ok && rename(tmp, path) == 0)
        return true;
    (void)unlink(tmp);
    return false;
}

/* Only this user may have written it, and no one else can rewrite it. */
static bool owner_only(const struct stat *st)
{
    return st->st_uid == geteuid() && (st->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool session_dir_trusted(const char *root)
{
    char dir[PATH_MAX];
    struct stat st;
    return session_dir(root, dir) && lstat(dir, &st) == 0 &&
           S_ISDIR(st.st_mode) && owner_only(&st);
}

static bool session_read(const char *root, int64_t pid,
                         struct session_record *rec)
{
    char path[PATH_MAX], body[256];
    struct stat st;
    if (!session_path(root, pid, path) || !session_dir_trusted(root))
        return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    bool trusted = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                   st.st_nlink == 1 && owner_only(&st);
    ssize_t got = trusted ? pread(fd, body, sizeof(body) - 1, 0) : -1;
    (void)close(fd);
    if (got <= 0)
        return false;
    body[got] = 0;
    long long recorded = 0;
    unsigned long long token = 0;
    int used = 0;
    if (sscanf(body, SESSION_SCHEMA " %lld %llu %63s %llu %llu%n", &recorded,
               &token, rec->boot, &rec->exe_dev, &rec->exe_ino, &used) != 5 ||
        recorded != pid || token == 0 || strcmp(body + used, "\n") != 0)
        return false;
    rec->born = token;
    return true;
}

/* The leader is dead or exiting. A member running anything but the
 * recorded dev image disproves the record (ABSENT) and an empty session is
 * GONE. The session is ORPHANED only when it could be listed whole and
 * every readable member runs that image, at least one from the checkout
 * root. A member with no image to read is exiting (or not this user's): it
 * neither proves nor disproves, so a session too large to list, or one no
 * readable rooted member vouches for, is UNPROVEN. */
static enum zcl_devloop_watch_session_state session_orphan_proof(
    int64_t pid, const struct session_record *rec, const struct stat *root_st)
{
    int64_t members[SESSION_MEMBER_MAX];
    bool complete = false;
    size_t count = zcl_devloop_process_session_list(pid, members,
                                                    SESSION_MEMBER_MAX,
                                                    &complete);
    if (complete && count == 0)
        return ZCL_DEVLOOP_WATCH_SESSION_GONE;
    size_t listed = count < SESSION_MEMBER_MAX ? count : SESSION_MEMBER_MAX;
    bool rooted = false;
    for (size_t i = 0; i < listed; i++) {
        enum proc_match match = proc_match_record(members[i], rec);
        if (match == PROC_OTHER)
            return ZCL_DEVLOOP_WATCH_SESSION_ABSENT;
        rooted = rooted ||
                 (match == PROC_MATCH && proc_cwd_is(members[i], root_st));
    }
    return complete && rooted ? ZCL_DEVLOOP_WATCH_SESSION_ORPHANED
                              : ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN;
}

static enum zcl_devloop_watch_session_state session_probe_proven(
    int64_t pid, const struct session_record *rec, const struct stat *root_st)
{
    uint64_t now = 0;
    if (leader_running(pid) && os_proc_pid_start_token((uint64_t)pid, &now)) {
        if (now != rec->born)
            return ZCL_DEVLOOP_WATCH_SESSION_ABSENT; /* a recycled pid */
        enum proc_match match = proc_match_record(pid, rec);
        if (match == PROC_OTHER)
            return ZCL_DEVLOOP_WATCH_SESSION_ABSENT;
        /* The recorded process itself, but not provably at the root. */
        if (match == PROC_MATCH)
            return proc_cwd_is(pid, root_st)
                ? ZCL_DEVLOOP_WATCH_SESSION_LIVE
                : ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN;
        /* The leader is exiting: what it leaves behind decides. */
    }
    /* A dead leader's pid is not reused while a member still references
     * its session id; the members themselves must still prove it. */
    return session_orphan_proof(pid, rec, root_st);
}

/* Only a disproven record is pruned: untrusted or malformed, written in
 * another boot, or disproven by the running processes. One that cannot be
 * decided right now (no boot id to compare) is kept as UNPROVEN. */
static enum zcl_devloop_watch_session_state session_probe(const char *root,
                                                          int64_t pid)
{
    char path[PATH_MAX], boot[SESSION_BOOT_MAX];
    struct session_record rec = {0};
    struct stat root_st;
    if (!session_path(root, pid, path) || access(path, F_OK) != 0 ||
        stat(root, &root_st) != 0)
        return ZCL_DEVLOOP_WATCH_SESSION_ABSENT;
    enum zcl_devloop_watch_session_state state =
        ZCL_DEVLOOP_WATCH_SESSION_ABSENT;
    if (session_read(root, pid, &rec)) {
        if (!boot_id_read(boot))
            return ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN;
        if (strcmp(boot, rec.boot) == 0)
            state = session_probe_proven(pid, &rec, &root_st);
    }
    if (state == ZCL_DEVLOOP_WATCH_SESSION_ABSENT)
        session_forget(root, pid);
    return state;
}

static void session_release(const char *root, int64_t pid)
{
    struct session_record rec = {0};
    uint64_t now = 0;
    if (session_read(root, pid, &rec) &&
        os_proc_pid_start_token((uint64_t)pid, &now) && now == rec.born)
        session_forget(root, pid);
}

static bool session_born_is(const char *root, int64_t pid, uint64_t born)
{
    struct session_record rec = {0};
    return session_read(root, pid, &rec) && rec.born == born;
}
#else /* POSIX without /proc: no launch identity is recorded. */
static bool session_record(const char *root, int64_t pid)
{
    (void)root;
    (void)pid;
    return false;
}

static enum zcl_devloop_watch_session_state session_probe(const char *root,
                                                          int64_t pid)
{
    (void)root;
    (void)pid;
    return ZCL_DEVLOOP_WATCH_SESSION_ABSENT;
}

static void session_release(const char *root, int64_t pid)
{
    (void)root;
    (void)pid;
}

static bool session_born_is(const char *root, int64_t pid, uint64_t born)
{
    (void)root;
    (void)pid;
    (void)born;
    return false;
}
#endif

static int64_t session_name_pid(const char *name)
{
    char *end = NULL;
    if (!name || name[0] < '1' || name[0] > '9')
        return 0;
    long long value = strtoll(name, &end, 10);
    return end && *end == 0 && value > 1 && value <= INT_MAX ? value : 0;
}

static int64_t session_retiring(const char *root, int64_t owner_pid)
{
    char dir[PATH_MAX];
    if (!session_dir(root, dir))
        return 0;
    DIR *listing = opendir(dir);
    if (!listing)
        return 0;
    int64_t found = 0;
    struct dirent *entry;
    while (found == 0 && (entry = readdir(listing)) != NULL) {
        int64_t pid = session_name_pid(entry->d_name);
        if (pid <= 1 || pid == owner_pid)
            continue;
        /* An UNPROVEN session may still be a watcher: it is kept and
         * counted, never forgotten. */
        enum zcl_devloop_watch_session_state state = session_probe(root, pid);
        if (state == ZCL_DEVLOOP_WATCH_SESSION_LIVE ||
            state == ZCL_DEVLOOP_WATCH_SESSION_ORPHANED ||
            state == ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN)
            found = pid;
        else
            session_forget(root, pid);
    }
    (void)closedir(listing);
    return found;
}

static int64_t session_admit(const char *root,
                             bool (*owner_active)(const char *root),
                             int64_t budget_ms)
{
    int64_t deadline = platform_time_monotonic_ms() + budget_ms;
    for (;;) {
        if (owner_active && owner_active(root))
            return 0;
        int64_t pending = session_retiring(root, 0);
        if (pending <= 1 || platform_time_monotonic_ms() >= deadline)
            return pending > 1 ? pending : 0;
        platform_sleep_ms(20);
    }
}

static bool lock_held(const char *lock)
{
    int fd = open(lock, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    bool held = flock(fd, LOCK_EX | LOCK_NB) != 0 &&
                (errno == EWOULDBLOCK || errno == EAGAIN);
    (void)close(fd);
    return held;
}

/* What one stop is allowed to touch: a recorded session, re-proven by its
 * record before each escalation. */
struct stop_target {
    const char *root;
    int64_t pid;
    bool group;
    const char *lock;
};

static bool target_still_ours(const struct stop_target *t)
{
    enum zcl_devloop_watch_session_state state =
        session_probe(t->root, t->pid);
    return state == ZCL_DEVLOOP_WATCH_SESSION_LIVE ||
           state == ZCL_DEVLOOP_WATCH_SESSION_ORPHANED;
}

/* Quiet means nothing of the session is left (just the leader when it does
 * not lead a group of its own) and, when it owned the checkout, the lock is
 * free again. */
static bool target_quiet(const struct stop_target *t)
{
    if (t->group ? session_running(t->pid) : leader_running(t->pid))
        return false;
    return !t->lock || !lock_held(t->lock);
}

/* In the SIGKILL tail every poll kills again, so a member forked while the
 * session was being killed does not survive it. */
static bool target_wait(const struct stop_target *t, int64_t budget_ms,
                        bool rekill)
{
    int64_t deadline = platform_time_monotonic_ms() + budget_ms;
    for (;;) {
        if (target_quiet(t))
            return true;
        if (platform_time_monotonic_ms() >= deadline)
            return false;
        platform_sleep_ms(SESSION_POLL_MS);
        if (rekill && target_still_ours(t))
            (void)zcl_devloop_process_session_members(t->pid, SIGKILL);
    }
}

/* Never signal the group or session the caller itself belongs to. */
static bool session_is_group(int64_t pid,
                             enum zcl_devloop_watch_session_state state)
{
    if (getpgrp() == (pid_t)pid || getsid(0) == (pid_t)pid)
        return false;
    return state == ZCL_DEVLOOP_WATCH_SESSION_ORPHANED ||
           getpgid((pid_t)pid) == (pid_t)pid;
}

/* Step 0 asks the live leader to stop: the watcher cancels and joins its
 * own proof worker. Step 1 signals the whole session (the only target once
 * the leader is gone), step 2 kills it. */
static enum zcl_devloop_watch_stop_result session_drain(
    const struct stop_target *t, int64_t budget_ms,
    struct zcl_devloop_watch_stop *io)
{
    static const int k_signal[] = {SIGTERM, SIGTERM, SIGKILL};
    static const int64_t k_tail_ms[] = {0, SESSION_TERM_TAIL_MS,
                                        SESSION_KILL_TAIL_MS};
    int first = leader_running(t->pid) ? 0 : 1;
    for (int step = first; step < 3; step++) {
        if (step > 0 && !t->group)
            break;
        if (step > 0 && !target_still_ours(t))
            return target_quiet(t) ? ZCL_DEVLOOP_WATCH_STOPPED
                                   : ZCL_DEVLOOP_WATCH_STOP_TIMEOUT;
        io->escalation = step;
        if (step == 0 && kill((pid_t)t->pid, k_signal[0]) != 0 &&
            errno != ESRCH)
            return ZCL_DEVLOOP_WATCH_STOP_SIGNAL_FAILED;
        if (step > 0)
            (void)zcl_devloop_process_session_members(t->pid, k_signal[step]);
        if (target_wait(t, step == first ? budget_ms : k_tail_ms[step],
                        step == 2))
            return ZCL_DEVLOOP_WATCH_STOPPED;
    }
    return ZCL_DEVLOOP_WATCH_STOP_TIMEOUT;
}

/* STOPPED when `requested` may be stopped, otherwise the refusal: only a
 * proven record authorizes a signal, and a caller that names a birth token
 * is refused a record carrying another one. */
static enum zcl_devloop_watch_stop_result stop_authorize(
    const char *root, int64_t requested, bool recorded,
    const struct zcl_devloop_watch_stop *io)
{
    if (!recorded)
        return io->owner_pid > 1 ? ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH
                                 : ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING;
    if (io->expect_born != 0 &&
        !session_born_is(root, requested, io->expect_born))
        return ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH;
    return ZCL_DEVLOOP_WATCH_STOPPED;
}

static size_t target_members_left(const struct stop_target *t)
{
    if (t->group)
        return zcl_devloop_process_session_members(t->pid, 0);
    return leader_running(t->pid) ? 1u : 0u;
}

static enum zcl_devloop_watch_stop_result session_stop(
    const char *root, int64_t requested, struct zcl_devloop_watch_stop *io)
{
    if (!io || requested <= 1)
        return ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH;
    io->retired = false;
    io->escalation = 0;
    io->members_left = 0;
    enum zcl_devloop_watch_session_state state = session_probe(root, requested);
    /* Recorded but neither proven nor disproven: keep it, signal nothing. */
    if (state == ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN)
        return ZCL_DEVLOOP_WATCH_STOP_UNPROVEN;
    if (state == ZCL_DEVLOOP_WATCH_SESSION_GONE)
        session_forget(root, requested);
    bool recorded = state == ZCL_DEVLOOP_WATCH_SESSION_LIVE ||
                    state == ZCL_DEVLOOP_WATCH_SESSION_ORPHANED;
    enum zcl_devloop_watch_stop_result result =
        stop_authorize(root, requested, recorded, io);
    if (result != ZCL_DEVLOOP_WATCH_STOPPED)
        return result;
    /* A recorded watcher that another watcher has since replaced is still
     * ours to stop; the current owner is never touched. */
    bool owner = io->owner_pid == requested;
    io->retired = !owner;
    char lock[PATH_MAX];
    struct stop_target target = {
        .root = root, .pid = requested,
        .group = session_is_group(requested, state),
        .lock = owner && zcl_devloop_watch_lock_path(root, lock, sizeof(lock))
            ? lock : NULL,
    };
    result = session_drain(&target,
                           io->budget_ms > 0 ? io->budget_ms
                                             : SESSION_DEFAULT_BUDGET_MS,
                           io);
    io->members_left = target_members_left(&target);
    if (result == ZCL_DEVLOOP_WATCH_STOPPED)
        session_forget(root, requested);
    return result;
}
#endif

/* One definition per entry point. The Windows arm refuses: the Windows
 * watcher store carries its own birth identity. */
bool zcl_devloop_watch_session_record(const char *root, int64_t pid)
{
#if defined(_WIN32)
    (void)root;
    (void)pid;
    return false;
#else
    return session_record(root, pid);
#endif
}

void zcl_devloop_watch_session_release(const char *root, int64_t pid)
{
#if defined(_WIN32)
    (void)root;
    (void)pid;
#else
    session_release(root, pid);
#endif
}

enum zcl_devloop_watch_session_state zcl_devloop_watch_session_probe(
    const char *root, int64_t pid)
{
#if defined(_WIN32)
    (void)root;
    (void)pid;
    return ZCL_DEVLOOP_WATCH_SESSION_ABSENT;
#else
    return session_probe(root, pid);
#endif
}

int64_t zcl_devloop_watch_session_retiring(const char *root,
                                           int64_t owner_pid)
{
#if defined(_WIN32)
    (void)root;
    (void)owner_pid;
    return 0;
#else
    return session_retiring(root, owner_pid);
#endif
}

int64_t zcl_devloop_watch_session_admit(const char *root,
                                        bool (*owner_active)(const char *root),
                                        int64_t budget_ms)
{
#if defined(_WIN32)
    (void)root;
    (void)owner_active;
    (void)budget_ms;
    return 0;
#else
    return session_admit(root, owner_active, budget_ms);
#endif
}

enum zcl_devloop_watch_stop_result zcl_devloop_watch_session_stop(
    const char *root, int64_t requested, struct zcl_devloop_watch_stop *io)
{
#if defined(_WIN32)
    (void)root;
    (void)requested;
    (void)io;
    return ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH;
#else
    return session_stop(root, requested, io);
#endif
}
