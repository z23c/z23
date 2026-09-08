/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the host-GC protection predicate and its bounded path plumbing.
 *          Split from host_gc_sweep.c so the question "what can this engine
 *          never touch?" is answered by one small file a reviewer can read
 *          end to end.
 *
 * NO DELETION SYSCALL APPEARS IN THIS FILE, and none appears in its sibling
 * either: the engine's only removal path is `git worktree remove` through
 * the spawn seam. Everything here reads.
 */

/* realpath() is declared by glibc only through the fortify inline unless a
 * feature-test macro asks for it; without this the file compiles at -O2 by
 * accident and is a hard C23 error at -O0. Must precede the first include. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "command/host_gc_priv.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { HG_DU_MAX_DEPTH = 24, HG_DU_MAX_ENTRIES = 4000000 };

bool hg_copy(char *dst, size_t cap, const char *src)
{
    size_t n;
    if (!dst || !cap || !src)
        return false;
    n = strlen(src);
    if (n + 1 > cap)
        return false;
    memcpy(dst, src, n + 1);
    return true;
}

bool hg_join(char *out, size_t cap, const char *a, const char *b)
{
    int n;
    if (!out || !a || !b)
        return false;
    n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

void hg_strip(char *s)
{
    size_t n;
    if (!s)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

bool hg_under(const char *dir, const char *path)
{
    size_t n;
    if (!dir || !path || !dir[0])
        return false;
    n = strlen(dir);
    if (strncmp(path, dir, n) != 0)
        return false;
    return path[n] == '\0' || path[n] == '/';
}

static uint64_t hg_walk(const char *path, int depth, long *budget)
{
    DIR *d;
    struct dirent *e;
    struct stat st;
    uint64_t total;

    if (*budget <= 0 || lstat(path, &st) != 0)
        return 0;
    (*budget)--;
    total = (uint64_t)st.st_size;
    if (!S_ISDIR(st.st_mode) || depth >= HG_DU_MAX_DEPTH)
        return total;
    d = opendir(path);
    if (!d)
        return total;
    while ((e = readdir(d)) != NULL && *budget > 0) {
        char child[HOST_GC_PATH_CAP * 2];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (hg_join(child, sizeof(child), path, e->d_name))
            total += hg_walk(child, depth + 1, budget);
    }
    (void)closedir(d);
    return total;
}

uint64_t hg_dir_bytes(const char *path)
{
    long budget = HG_DU_MAX_ENTRIES;
    return hg_walk(path, 0, &budget);
}

/* ----------------------------------------------------------- protection */

struct hg_protected_row {
    const char *rel;   /* relative to $HOME */
    bool star;         /* also match every sibling sharing this prefix */
};

/* The trees this engine refuses BY NAME, before it touches the filesystem.
 * `.zclassic` with star=true covers ~/.zclassic, ~/.zclassic-c23-devfleet,
 * ~/.zclassic-c23-backups and every other datadir sibling — the whole point
 * of a prefix row is that a datadir minted tomorrow is already covered. */
static const struct hg_protected_row k_hg_protected[] = {
    { ".zclassic", true },
    { "wallet_backups", false },
    { ".zcash-params", false },
    { ".ssh", false },
    { ".config/zclassic23", false },
    { "github/zclassic23", false },
    { ".local/state/zclassic23-quality", false },
};

/* Read-only view of k_hg_protected for callers (tests, chiefly) that must
 * exercise "every protected leaf is refused by name" without hand-copying
 * this table's entries — including the two live datadir names — into their
 * own source. */
size_t host_gc_protected_leaf_count(void)
{
    return sizeof(k_hg_protected) / sizeof(k_hg_protected[0]);
}

const char *host_gc_protected_leaf(size_t i)
{
    return i < host_gc_protected_leaf_count() ? k_hg_protected[i].rel : NULL;
}

static bool hg_protected_named(const char *home, const char *p,
                               char *reason, size_t cap)
{
    for (size_t i = 0; i < sizeof(k_hg_protected) / sizeof(k_hg_protected[0]);
         i++) {
        char full[HOST_GC_PATH_CAP];
        bool hit;
        if (!hg_join(full, sizeof(full), home, k_hg_protected[i].rel))
            continue;
        hit = k_hg_protected[i].star
                  ? strncmp(p, full, strlen(full)) == 0
                  : hg_under(full, p);
        if (hit) {
            (void)snprintf(reason, cap, "protected_tree:%s",
                           k_hg_protected[i].rel);
            return true;
        }
    }
    return false;
}

/* A directory that actually holds chain data is a datadir whatever it is
 * called. Names, not a size heuristic: node.db is the record layer's store
 * and blk*.dat are the block files. */
static bool hg_holds_chain_data(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    bool hit = false;
    if (!d)
        return false;
    while (!hit && (e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (strcmp(e->d_name, "node.db") == 0)
            hit = true;
        else if (n > 7 && strncmp(e->d_name, "blk", 3) == 0 &&
                 strcmp(e->d_name + n - 4, ".dat") == 0)
            hit = true;
    }
    (void)closedir(d);
    return hit;
}

/* Lexical normalisation: collapse "//", drop "." segments, and resolve ".."
 * against what has already been emitted. Done BEFORE any syscall so a
 * protected NAME is refused without the engine ever touching the tree it is
 * protecting. realpath() runs afterwards to catch a symlink that points
 * into a protected tree under an innocent name. */
static bool hg_norm_segment(char *out, size_t cap, size_t *o, const char *p,
                            size_t len)
{
    if (len == 1 && p[0] == '.')
        return true;
    if (len == 2 && p[0] == '.' && p[1] == '.') {
        while (*o > 1 && out[*o - 1] != '/')
            (*o)--;
        if (*o > 1)
            (*o)--;
        return true;
    }
    if (*o > 1) {
        if (*o + 1 >= cap)
            return false;
        out[(*o)++] = '/';
    }
    if (*o + len >= cap)
        return false;
    memcpy(out + *o, p, len);
    *o += len;
    return true;
}

static bool hg_norm(const char *path, char *out, size_t cap)
{
    size_t o = 1;
    const char *p = path;
    if (!path || path[0] != '/' || cap < 2)
        return false;
    out[0] = '/';
    while (*p) {
        size_t len = 0;
        while (*p == '/')
            p++;
        while (p[len] && p[len] != '/')
            len++;
        if (len == 0)
            break;
        if (!hg_norm_segment(out, cap, &o, p, len))
            return false;
        p += len;
    }
    out[o] = '\0';
    return true;
}

static bool hg_protected_core(const char *home, const char *repo,
                              const char *p, char *reason, size_t cap)
{
    if (strcmp(p, "/") == 0 || strcmp(p, home) == 0) {
        (void)snprintf(reason, cap, "protected_root");
        return true;
    }
    if (repo && repo[0] && hg_under(repo, p)) {
        (void)snprintf(reason, cap, "protected_checkout");
        return true;
    }
    return hg_protected_named(home, p, reason, cap);
}

bool host_gc_path_protected(const struct host_gc_request *req,
                            const char *repo, const char *path,
                            char *reason, size_t reason_cap)
{
    char norm[HOST_GC_PATH_CAP];
    char real[PATH_MAX];
    const char *home;

    if (!req || !reason || reason_cap == 0)
        return true;
    home = req->home[0] ? req->home : "/";
    if (!path || path[0] != '/') {
        (void)snprintf(reason, reason_cap, "not_absolute");
        return true;
    }
    if (!hg_norm(path, norm, sizeof(norm))) {
        (void)snprintf(reason, reason_cap, "path_too_long");
        return true;
    }
    if (hg_protected_core(home, repo, norm, reason, reason_cap))
        return true;
    if (realpath(norm, real) != NULL && strcmp(real, norm) != 0 &&
        hg_protected_core(home, repo, real, reason, reason_cap))
        return true;
    if (hg_holds_chain_data(norm)) {
        (void)snprintf(reason, reason_cap, "holds_chain_data");
        return true;
    }
    return false;
}
