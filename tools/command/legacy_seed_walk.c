/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Source tree enumeration for the legacy seed: only blocks/ and chainstate/,
 * every step O_NOFOLLOW, wallets and keys filtered out by name. */

#ifndef _WIN32

#define _GNU_SOURCE

#include "command/legacy_seed_priv.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const k_roots[] = { "blocks", "chainstate" };

static bool lseed_ci_contains(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++)
        if (strncasecmp(hay, needle, n) == 0)
            return true;
    return false;
}

bool lseed_is_secret(const char *name)
{
    size_t len = strlen(name);
    if (strncasecmp(name, "wallet", 6) == 0 || strncasecmp(name, "key", 3) == 0)
        return true;
    if (lseed_ci_contains(name, "privkey") || lseed_ci_contains(name, "private"))
        return true;
    return (len > 4 && (strcasecmp(name + len - 4, ".key") == 0 ||
                        strcasecmp(name + len - 4, ".pem") == 0)) ||
           (len > 7 && strcasecmp(name + len - 7, ".wallet") == 0);
}

/* One directory fd per path component, each O_DIRECTORY|O_NOFOLLOW, so a
 * subdirectory swapped for a symlink after the walk is refused instead of
 * followed. The last component is opened with O_NOFOLLOW too. */
int lseed_open_beneath(int rootfd, const char *rel, int flags, mode_t mode)
{
    char path[LSEED_PATH_MAX];
    char *part = path, *slash;
    int dir = dup(rootfd);
    if (dir < 0 || strlen(rel) >= sizeof(path) || rel[0] == '/') {
        if (dir >= 0)
            close(dir);
        return -1;
    }
    (void)snprintf(path, sizeof(path), "%s", rel);
    while (dir >= 0 && (slash = strchr(part, '/')) != NULL) {
        int next;
        *slash = '\0';
        next = (part[0] == '\0' || strcmp(part, "..") == 0)
                   ? -1
                   : openat(dir, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dir);
        dir = next;
        part = slash + 1;
    }
    if (dir < 0 || part[0] == '\0' || strcmp(part, "..") == 0) {
        if (dir >= 0)
            close(dir);
        return -1;
    }
    int fd = openat(dir, part, flags | O_NOFOLLOW | O_CLOEXEC, mode);
    close(dir);
    return fd;
}

/* Grow in 256-entry steps (a datadir holds thousands of files, not millions). */
static bool lseed_tree_push(struct lseed_tree *t, const struct lseed_ent *ent)
{
    size_t need = (t->n + 1 + 255) / 256 * 256;
    struct lseed_ent *grown = t->e;
    if (need > t->cap) {
        grown = zcl_realloc(t->e, need * sizeof(*grown), "lseed_tree");
        if (grown) {
            t->e = grown;
            t->cap = need;
        }
    }
    if (!grown)
        return false;
    memcpy(&t->e[t->n++], ent, sizeof(*ent));
    return true;
}

void lseed_tree_free(struct lseed_tree *tree)
{
    free(tree->e);
    memset(tree, 0, sizeof(*tree));
}

static enum lseed_refusal lseed_note_refuse(char *why, size_t cap, const char *what,
                                      const char *rel, enum lseed_refusal rc)
{
    (void)snprintf(why, cap, "%s: %s", what, rel);
    return rc;
}

static enum lseed_refusal lseed_take_entry(struct lseed_tree *t, int dirfd,
                                     const char *rel, const char *name,
                                     const struct stat *st, char *why,
                                     size_t cap)
{
    struct lseed_ent ent = { 0 };
    if (S_ISLNK(st->st_mode))
        return lseed_note_refuse(why, cap, "symlink in source tree", rel,
                           LSEED_SYMLINK_IN_TREE);
    if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode))
        return lseed_note_refuse(why, cap, "special file in source tree", rel,
                           LSEED_SPECIAL_FILE);
    (void)dirfd;
    if (!S_ISDIR(st->st_mode) && lseed_is_secret(name)) {
        t->excluded++;
        return LSEED_OK;
    }
    (void)snprintf(ent.rel, sizeof(ent.rel), "%s", rel);
    ent.size = S_ISREG(st->st_mode) ? (uint64_t)st->st_size : 0;
    ent.mtime_s = st->st_mtim.tv_sec;
    ent.mtime_ns = st->st_mtim.tv_nsec;
    ent.mode = st->st_mode & 0777;
    ent.dir = S_ISDIR(st->st_mode);
    t->bytes += ent.size;
    return lseed_tree_push(t, &ent) ? LSEED_OK
                              : lseed_note_refuse(why, cap, "out of memory", rel,
                                            LSEED_COPY_FAILED);
}

static enum lseed_refusal lseed_walk_dir(int dirfd, const char *rel,
                                   struct lseed_tree *t, char *why, size_t cap,
                                   int depth);

static enum lseed_refusal lseed_walk_one(int dirfd, const char *rel,
                                   const char *name, struct lseed_tree *t,
                                   char *why, size_t cap, int depth)
{
    struct stat st;
    char child[LSEED_PATH_MAX];
    if (snprintf(child, sizeof(child), "%s/%s", rel, name) >=
        (int)sizeof(child))
        return lseed_note_refuse(why, cap, "path too long", rel, LSEED_BAD_INPUT);
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return lseed_note_refuse(why, cap, "stat failed", child, LSEED_COPY_FAILED);
    enum lseed_refusal rc = lseed_take_entry(t, dirfd, child, name, &st, why, cap);
    if (rc != LSEED_OK || !S_ISDIR(st.st_mode))
        return rc;
    int sub = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sub < 0)
        return lseed_note_refuse(why, cap, "open dir failed", child,
                           LSEED_SYMLINK_IN_TREE);
    rc = lseed_walk_dir(sub, child, t, why, cap, depth + 1);
    close(sub);
    return rc;
}

static enum lseed_refusal lseed_walk_dir(int dirfd, const char *rel,
                                   struct lseed_tree *t, char *why, size_t cap,
                                   int depth)
{
    int dup_fd = dup(dirfd);
    DIR *d = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
    struct dirent *de;
    enum lseed_refusal rc = LSEED_OK;
    if (!d || depth > 8) {
        if (dup_fd >= 0 && !d)
            close(dup_fd);
        return lseed_note_refuse(why, cap, "cannot list", rel, LSEED_COPY_FAILED);
    }
    rewinddir(d);
    while (rc == LSEED_OK && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        rc = lseed_walk_one(dirfd, rel, de->d_name, t, why, cap, depth);
    }
    closedir(d);
    return rc;
}

static int lseed_cmp_ent(const void *a, const void *b)
{
    return strcmp(((const struct lseed_ent *)a)->rel,
                  ((const struct lseed_ent *)b)->rel);
}

/* blocks/blkNNNNN.dat or blocks/revNNNNN.dat -> NNNNN, else -1. */
static int64_t lseed_pair_number(const char *rel)
{
    char *end;
    if (strncmp(rel, "blocks/", 7) != 0)
        return -1;
    const char *name = rel + 7;
    if (strncmp(name, "blk", 3) != 0 && strncmp(name, "rev", 3) != 0)
        return -1;
    long n = strtol(name + 3, &end, 10);
    return (end != name + 3 && strcmp(end, ".dat") == 0 && n >= 0) ? n : -1;
}

static void lseed_mark_tail(struct lseed_tree *t)
{
    t->tail_pair = -1;
    for (size_t i = 0; i < t->n; i++) {
        int64_t n = t->e[i].dir ? -1 : lseed_pair_number(t->e[i].rel);
        if (n > t->tail_pair)
            t->tail_pair = n;
    }
    for (size_t i = 0; i < t->n; i++) {
        int64_t n = t->e[i].dir ? -1 : lseed_pair_number(t->e[i].rel);
        /* Everything that is not an immutable lower pair is the tail. */
        t->e[i].tail = !t->e[i].dir && (n < 0 || n == t->tail_pair);
    }
}

enum lseed_refusal lseed_walk(int rootfd, struct lseed_tree *tree, char *why,
                              size_t why_cap)
{
    memset(tree, 0, sizeof(*tree));
    for (size_t i = 0; i < sizeof(k_roots) / sizeof(k_roots[0]); i++) {
        struct stat st;
        if (fstatat(rootfd, k_roots[i], &st, AT_SYMLINK_NOFOLLOW) != 0) {
            lseed_tree_free(tree);
            return lseed_note_refuse(why, why_cap, "source lacks", k_roots[i],
                               LSEED_SOURCE_MISSING);
        }
        enum lseed_refusal rc = lseed_take_entry(tree, rootfd, k_roots[i], k_roots[i],
                                           &st, why, why_cap);
        int sub = rc == LSEED_OK && S_ISDIR(st.st_mode)
                      ? openat(rootfd, k_roots[i],
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                      : -1;
        if (rc == LSEED_OK && sub < 0)
            rc = lseed_note_refuse(why, why_cap, "not a directory", k_roots[i],
                             LSEED_SOURCE_MISSING);
        if (rc == LSEED_OK) {
            rc = lseed_walk_dir(sub, k_roots[i], tree, why, why_cap, 0);
            close(sub);
        }
        if (rc != LSEED_OK) {
            lseed_tree_free(tree);
            return rc;
        }
    }
    qsort(tree->e, tree->n, sizeof(*tree->e), lseed_cmp_ent);
    lseed_mark_tail(tree);
    return LSEED_OK;
}

bool lseed_want_stage(const struct lseed_ent *ent)
{
    return !ent->dir && !ent->tail;
}

bool lseed_want_all(const struct lseed_ent *ent)
{
    return !ent->dir;
}

#else

typedef int lseed_posix_only_unused; /* empty on Windows */

#endif /* _WIN32 */
