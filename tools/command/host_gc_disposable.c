/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the disposable-pool half of the host-GC sweep (declared in
 *          command/host_gc_priv.h). A disposable pool holds remote-gate lane
 *          copies: build outputs of commits that live elsewhere. This file
 *          owns what such a pool adds to host_gc_sweep.c:
 *
 *            - the sibling flock <copy>.lock a running gate holds, probed
 *              with a non-blocking flock and then HELD through the removal;
 *            - the sibling files <copy>.bundle, <copy>.prime.log and
 *              <copy>.lock, unlinked only when they are regular files
 *              (lstat, never through a symlink), the lock last;
 *            - the shape of an orphaned copy: a directory git no longer
 *              registers, whose .git file names a worktree administrative
 *              directory that is gone, with a sibling .lock;
 *            - the two inventory narrowing predicates: a process of another
 *              non-root uid cannot open files under a closed pool root.
 *
 * It never removes a directory and never follows a symlink: the recursive
 * delete stays in host_gc_sweep.c behind its two re-checks.
 */

#include "command/host_gc_priv.h"

#include "util/path_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/file.h>
#endif

enum { HG_SIB_CAP = HOST_GC_PATH_CAP + 16, HG_UID_FIELDS = 4 };

static bool hg_sibling_path(char *out, size_t cap, const char *wt,
                            const char *suffix)
{
    int n = snprintf(out, cap, "%s%s", wt, suffix);
    return n > 0 && (size_t)n < cap;
}

int hg_lock_acquire(const char *wt, int *fd)
{
#if defined(_WIN32)
    (void)wt;
    *fd = -1;
    return HG_LOCK_BUSY;
#else
    char lock[HG_SIB_CAP];
    struct stat st;
    int f;
    *fd = -1;
    if (!hg_sibling_path(lock, sizeof(lock), wt, ".lock"))
        return HG_LOCK_BUSY;
    f = open(lock, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (f < 0)
        return errno == ENOENT ? HG_LOCK_FREE : HG_LOCK_BUSY;
    if (fstat(f, &st) != 0 || !S_ISREG(st.st_mode) ||
        flock(f, LOCK_EX | LOCK_NB) != 0) {
        (void)close(f);
        return HG_LOCK_BUSY;
    }
    *fd = f;
    return HG_LOCK_FREE;
#endif
}

void hg_lock_release(int fd)
{
    if (fd >= 0)
        (void)close(fd);
}

/* Unlink `path` only when lstat says it is a regular file; returns the bytes
 * it held, 0 for anything else (a symlink is left exactly where it is). */
static uint64_t hg_unlink_regular(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (unlink(path) != 0)
        return 0;
    return (uint64_t)st.st_size;
}

uint64_t hg_remove_siblings(const char *wt)
{
    static const char *const suffix[] = { ".bundle", ".prime.log", ".lock" };
    uint64_t bytes = 0;
    char path[HG_SIB_CAP];
    for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++)
        if (hg_sibling_path(path, sizeof(path), wt, suffix[i]))
            bytes += hg_unlink_regular(path);
    return bytes;
}

static bool hg_regular_sibling(const char *dir, const char *suffix)
{
    char path[HG_SIB_CAP];
    struct stat st;
    return hg_sibling_path(path, sizeof(path), dir, suffix) &&
           lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* The gitdir a linked worktree's .git FILE names, or false when .git is not
 * a regular file or does not start with "gitdir: ". */
static bool hg_dotgit_target(const char *dir, char *out, size_t cap)
{
    char dotgit[HG_SIB_CAP], line[HOST_GC_PATH_CAP + 16];
    struct stat st;
    FILE *f;
    if (!hg_sibling_path(dotgit, sizeof(dotgit), dir, "/.git") ||
        lstat(dotgit, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    f = fopen(dotgit, "r");
    if (!f)
        return false;
    if (!fgets(line, (int)sizeof(line), f))
        line[0] = '\0';
    (void)fclose(f);
    hg_strip(line);
    return strncmp(line, "gitdir: ", 8) == 0 && hg_copy(out, cap, line + 8);
}

bool hg_orphan_shape(const char *dir)
{
    char target[HOST_GC_PATH_CAP];
    struct stat st;
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        !hg_regular_sibling(dir, ".lock") ||
        !hg_dotgit_target(dir, target, sizeof(target)))
        return false;
    if (!strstr(target, "/.git/worktrees/"))
        return false;
    return stat(target, &st) != 0 && errno == ENOENT;
}

/* ------------------------------------------------- inventory narrowing */

#if !defined(_WIN32)
static bool hg_id_is_ours_or_root(unsigned long id)
{
    return id == 0 || id == (unsigned long)geteuid() ||
           id == (unsigned long)getuid();
}
#endif

bool hg_proc_foreign(const char *procdir)
{
#if defined(_WIN32)
    (void)procdir;
    return false;
#else
    char file[HG_SIB_CAP], line[256];
    FILE *f;
    bool foreign = false;
    if (!hg_sibling_path(file, sizeof(file), procdir, "/status"))
        return false;
    f = fopen(file, "r");
    if (!f)
        return false;
    while (!foreign && fgets(line, (int)sizeof(line), f)) {
        char *p = line + 4, *end;
        int seen = 0;
        if (strncmp(line, "Uid:", 4) != 0)
            continue;
        for (; seen < HG_UID_FIELDS; seen++) {
            unsigned long id = strtoul(p, &end, 10);
            if (end == p || hg_id_is_ours_or_root(id))
                break;
            p = end;
        }
        foreign = seen == HG_UID_FIELDS;
        break;
    }
    (void)fclose(f);
    return foreign;
#endif
}

bool hg_pool_closed(const char *pool)
{
#if defined(_WIN32)
    (void)pool;
    return false;
#else
    char p[HOST_GC_PATH_CAP];
    char *slash;
    struct stat st;
    if (!hg_copy(p, sizeof(p), pool))
        return false;
    for (;;) {
        if (stat(p, &st) != 0)
            return false;
        if (S_ISDIR(st.st_mode) && (st.st_mode & 077) == 0 &&
            st.st_uid == geteuid())
            return true;
        slash = strrchr(p, '/');
        if (!slash || slash == p)
            return false;
        *slash = '\0';
    }
#endif
}
