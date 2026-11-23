/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: tmpfs scratch root lifecycle for the test runner; see
 *          test/test_scratch_reap.h for the liveness proof.
 */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_scratch_reap.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum { TSR_MAX_DEPTH = 200, TSR_MAX_BUSY = 1 << 20 };

/* ---- descriptor-relative removal ------------------------------------ */

static int tsr_walk_entry(int parentfd, const char *name, dev_t dev, int depth,
                          bool apply, uint64_t *bytes);

/* Give the owner rwx on the directory that O_PATH fd names. */
static void tsr_make_writable_path(int pathfd, mode_t mode)
{
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", pathfd);
    (void)chmod(proc, (mode & 07777) | S_IRWXU);
}

static int tsr_same_dir(int fd, const struct stat *want)
{
    struct stat got;
    if (fstat(fd, &got) != 0) return -1;
    if (!S_ISDIR(got.st_mode) || got.st_ino != want->st_ino ||
        got.st_dev != want->st_dev) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

static int tsr_open_walk_dir(int parentfd, const char *name,
                             const struct stat *st, bool apply)
{
    const int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    int fd = openat(parentfd, name, flags);
    if (fd < 0 && errno == EACCES && apply) {
        int pathfd = openat(parentfd, name,
                            O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (pathfd < 0) return -1;
        if (tsr_same_dir(pathfd, st) == 0) tsr_make_writable_path(pathfd, st->st_mode);
        close(pathfd);
        fd = openat(parentfd, name, flags);
    }
    if (fd < 0) return -1;
    if (tsr_same_dir(fd, st) != 0) { close(fd); return -1; }
    if (apply && (st->st_mode & S_IRWXU) != S_IRWXU)
        (void)fchmod(fd, (st->st_mode & 07777) | S_IRWXU);
    return fd;
}

static int tsr_walk_children(int fd, dev_t dev, int depth, bool apply,
                             uint64_t *bytes)
{
    int dupfd = dup(fd);
    DIR *dir = dupfd >= 0 ? fdopendir(dupfd) : NULL;
    if (!dir) {
        if (dupfd >= 0) close(dupfd);
        return -1;
    }
    int rc = 0, saved = 0;
    for (struct dirent *e;;) {
        errno = 0;
        e = readdir(dir);
        if (!e) { if (errno) { rc = -1; saved = errno; } break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (tsr_walk_entry(fd, e->d_name, dev, depth, apply, bytes) != 0) {
            rc = -1;
            saved = errno;
        }
    }
    closedir(dir);
    if (rc != 0) errno = saved;
    return rc;
}

static int tsr_walk_dir(int parentfd, const char *name, const struct stat *st,
                        int depth, bool apply, uint64_t *bytes)
{
    int fd = tsr_open_walk_dir(parentfd, name, st, apply);
    if (fd < 0) return apply ? -1 : 0;   /* a dry run only measures */
    int rc = tsr_walk_children(fd, st->st_dev, depth + 1, apply, bytes);
    int saved = errno;
    close(fd);
    if (rc != 0) { errno = saved; return -1; }
    if (apply && unlinkat(parentfd, name, AT_REMOVEDIR) != 0 && errno != ENOENT)
        return -1;
    return 0;
}

static int tsr_walk_entry(int parentfd, const char *name, dev_t dev, int depth,
                          bool apply, uint64_t *bytes)
{
    struct stat st;
    if (fstatat(parentfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    if (st.st_blocks > 0) *bytes += (uint64_t)st.st_blocks * 512u;
    if (!S_ISDIR(st.st_mode)) {   /* files and symlinks: unlink, never follow */
        if (apply && unlinkat(parentfd, name, 0) != 0 && errno != ENOENT) return -1;
        return 0;
    }
    if (st.st_dev != dev) { errno = EXDEV; return -1; }   /* never leave the root's mount */
    if (depth >= TSR_MAX_DEPTH) { errno = ELOOP; return -1; }
    return tsr_walk_dir(parentfd, name, &st, depth, apply, bytes);
}

int tsr_remove_tree(int parentfd, const char *name, bool apply, uint64_t *bytes)
{
    struct stat st;
    uint64_t scratch = 0;
    if (!bytes) bytes = &scratch;
    if (fstatat(parentfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    return tsr_walk_entry(parentfd, name, st.st_dev, 0, apply, bytes);
}

/* ---- naming, lock, keep marker -------------------------------------- */

bool tsr_name_is_root(const char *name)
{
    if (strlen(name) != 15 || name[8] != '.') return false;
    for (int i = 0; i < 8; i++)
        if (!isxdigit((unsigned char)name[i]) || isupper((unsigned char)name[i]))
            return false;
    for (int i = 9; i < 15; i++)
        if (!isalnum((unsigned char)name[i])) return false;
    return true;
}

int tsr_lock_root(const char *root)
{
    int dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) return -1;
    int fd = openat(dirfd, TSR_LOCK_NAME,
                    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    close(dirfd);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) { close(fd); return -1; }
    return fd;
}

bool tsr_keep_mark(const char *root)
{
    int dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) return false;
    int fd = openat(dirfd, TSR_KEEP_NAME,
                    O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    close(dirfd);
    if (fd < 0) return false;
    return close(fd) == 0;
}

/* ---- who is inside a root ------------------------------------------- */

struct tsr_busy {
    char **path;
    size_t n, cap;
};

static void tsr_busy_free(struct tsr_busy *b)
{
    for (size_t i = 0; i < b->n; i++) free(b->path[i]);
    free(b->path);
    memset(b, 0, sizeof(*b));
}

static bool tsr_busy_add(struct tsr_busy *b, const char *target)
{
    if (target[0] != '/' || b->n >= TSR_MAX_BUSY) return true;
    if (b->n == b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 256;
        char **grown = realloc(b->path, cap * sizeof(*grown));
        if (!grown) return false;
        b->path = grown;
        b->cap = cap;
    }
    char *copy = strdup(target);
    if (!copy) return false;
    b->path[b->n++] = copy;
    return true;
}

static bool tsr_busy_link(struct tsr_busy *b, const char *link)
{
    char target[PATH_MAX];
    ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0) return true;   /* gone or unreadable: not provably inside */
    target[n] = '\0';
    return tsr_busy_add(b, target);
}

static bool tsr_busy_process(struct tsr_busy *b, const char *pid)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%s/cwd", pid);
    if (!tsr_busy_link(b, path)) return false;
    snprintf(path, sizeof(path), "/proc/%s/fd", pid);
    DIR *fds = opendir(path);
    if (!fds) return true;
    bool ok = true;
    for (struct dirent *e; ok && (e = readdir(fds)) != NULL;) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/%s/fd/%s", pid, e->d_name);
        ok = tsr_busy_link(b, path);
    }
    closedir(fds);
    return ok;
}

static bool tsr_busy_scan(struct tsr_busy *b)
{
    DIR *proc = opendir("/proc");
    if (!proc) return false;
    bool ok = true;
    for (struct dirent *e; ok && (e = readdir(proc)) != NULL;)
        if (isdigit((unsigned char)e->d_name[0])) ok = tsr_busy_process(b, e->d_name);
    closedir(proc);
    return ok;
}

static bool tsr_busy_under(const struct tsr_busy *b, const char *root)
{
    size_t len = strlen(root);
    for (size_t i = 0; i < b->n; i++)
        if (!strncmp(b->path[i], root, len) &&
            (b->path[i][len] == '\0' || b->path[i][len] == '/'))
            return true;
    return false;
}

/* ---- classification -------------------------------------------------- */

struct tsr_scan {
    int parentfd;
    const char *parent;   /* canonical */
    uid_t uid;
    int64_t now;
    bool apply;
    const struct tsr_busy *busy;
    struct tsr_report *report;
};

/* The proof: every lock this root can carry must be free. The locks stay
 * held (the caller closes *lockfd) so removal runs under them. */
static int tsr_prove_dead(int rootfd, int *lockfd, bool *has_lock)
{
    *lockfd = openat(rootfd, TSR_LOCK_NAME, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    *has_lock = *lockfd >= 0;
    if (flock(rootfd, LOCK_EX | LOCK_NB) != 0) return -1;   /* older runner */
    if (*has_lock && flock(*lockfd, LOCK_EX | LOCK_NB) != 0) return -1;
    return 0;
}

static bool tsr_keep_valid(int rootfd, int64_t now)
{
    struct stat ks;
    return fstatat(rootfd, TSR_KEEP_NAME, &ks, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(ks.st_mode) && now < (int64_t)ks.st_mtime + TSR_KEEP_SECONDS;
}

static void tsr_reap_dead(const struct tsr_scan *s, const char *name)
{
    uint64_t bytes = 0;
    int rc = tsr_remove_tree(s->parentfd, name, s->apply, &bytes);
    s->report->dead++;
    s->report->dead_bytes += bytes;
    if (!s->apply) return;
    if (rc == 0) { s->report->reaped++; s->report->reaped_bytes += bytes; }
    else s->report->failed++;
}

/* Returns the report bucket the root belongs to when it is not dead. */
static size_t *tsr_live_bucket(const struct tsr_scan *s, const char *name,
                               const struct stat *st, int rootfd, int *lockfd)
{
    struct tsr_report *r = s->report;
    bool has_lock = false;
    char full[PATH_MAX];
    if (tsr_keep_valid(rootfd, s->now)) return &r->kept;
    if (tsr_prove_dead(rootfd, lockfd, &has_lock) != 0) return &r->live;
    int64_t age = s->now - (int64_t)st->st_mtime;
    if (age < (has_lock ? TSR_GRACE_SECONDS : TSR_LEGACY_AGE_SECONDS))
        return &r->young;
    if (snprintf(full, sizeof(full), "%s/%s", s->parent, name) >= (int)sizeof(full) ||
        tsr_busy_under(s->busy, full))
        return &r->live;
    return NULL;
}

static void tsr_classify(const struct tsr_scan *s, const char *name)
{
    struct stat st;
    if (!tsr_name_is_root(name) ||
        fstatat(s->parentfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISDIR(st.st_mode) || st.st_uid != s->uid) {
        s->report->foreign++;
        return;
    }
    int rootfd = openat(s->parentfd, name,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootfd < 0) { s->report->foreign++; return; }
    int lockfd = -1;
    size_t *bucket = tsr_live_bucket(s, name, &st, rootfd, &lockfd);
    if (bucket) (*bucket)++;
    else tsr_reap_dead(s, name);
    if (lockfd >= 0) close(lockfd);
    close(rootfd);
}

static int tsr_open_parent(const char *parent, char *canonical, size_t cap)
{
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat ps;
    bool safe = fstat(fd, &ps) == 0 && ps.st_uid == geteuid() && !(ps.st_mode & 0022);
    if (!safe) errno = EPERM;
    else if (!realpath(parent, canonical)) safe = false;
    else if (strlen(canonical) >= cap) { errno = ENAMETOOLONG; safe = false; }
    if (!safe) { int saved = errno; close(fd); errno = saved; return -1; }
    return fd;
}

int tsr_reap_parent(const char *parent, uid_t uid, int64_t now, bool apply,
                    struct tsr_report *report)
{
    struct tsr_report none;
    char canonical[PATH_MAX];
    struct tsr_busy busy = {0};
    if (!report) report = &none;
    memset(report, 0, sizeof(*report));
    int pfd = tsr_open_parent(parent, canonical, sizeof(canonical));
    if (pfd < 0) return errno == ENOENT ? 0 : -1;
    int dupfd = dup(pfd);
    DIR *dir = dupfd >= 0 ? fdopendir(dupfd) : NULL;
    if (!dir || !tsr_busy_scan(&busy)) {
        if (dir) closedir(dir);
        else if (dupfd >= 0) close(dupfd);
        tsr_busy_free(&busy);
        close(pfd);
        return -1;
    }
    struct tsr_scan scan = {pfd, canonical, uid, now, apply, &busy, report};
    for (struct dirent *e; (e = readdir(dir)) != NULL;) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            tsr_classify(&scan, e->d_name);
    }
    closedir(dir);
    tsr_busy_free(&busy);
    close(pfd);
    return 0;
}

#else
typedef int tsr_not_linux;   /* the scratch roots exist only on Linux tmpfs */
#endif /* __linux__ */
