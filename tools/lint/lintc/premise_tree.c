/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: premise path sets — the candidate generation walked and hashed
 * byte by byte, the base tree listed from a verified private Git store, and
 * one SHA3-256 path-set root over each path and file kind so an added,
 * removed, renamed or mode-changed path is part of every premise.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha3/sha3.h"

enum { PREMISE_FILE_MAX = 256 * 1024 * 1024, PREMISE_BLOB_TAG = 0x20 };

/* Directories no gate reads as source: VCS metadata, build output, test
 * scratch, agent scratch, and the two vendored trees the per-TU gates prune
 * from their include search. Pruned identically on both sides. */
static const char *const k_pruned[] = {
    ".git", "build", "test-tmp", ".claude", "vendor/tor", "vendor/raylib",
};

bool premise_path_pruned(const char *path)
{
    for (size_t i = 0; i < sizeof k_pruned / sizeof k_pruned[0]; i++) {
        size_t n = strlen(k_pruned[i]);
        if (strncmp(path, k_pruned[i], n) == 0
            && (path[n] == '\0' || path[n] == '/'))
            return true;
    }
    return false;
}

/* A path beginning with prefix lies under a pruned root when the prefix is
 * itself inside one, or when it is a leading piece of one. */
bool premise_prefix_reaches_pruned(const char *prefix)
{
    size_t k = strlen(prefix);
    for (size_t i = 0; i < sizeof k_pruned / sizeof k_pruned[0]; i++) {
        size_t n = strlen(k_pruned[i]);
        if (k <= n ? strncmp(k_pruned[i], prefix, k) == 0
                   : strncmp(prefix, k_pruned[i], n) == 0 && prefix[n] == '/')
            return true;
    }
    return false;
}

int premise_tree_add(struct premise_tree *t, const char *path, const char *oid,
                     bool symlink, bool executable)
{
    if (t->count == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 1024;
        struct premise_entry *grown = realloc(t->entries, cap * sizeof *grown); // raw-alloc-ok:lint-runtime
        if (!grown)
            return 2;
        t->entries = grown;
        t->cap = cap;
    }
    struct premise_entry *e = &t->entries[t->count];
    memset(e, 0, sizeof *e);
    e->path = strdup(path);
    if (!e->path)
        return 2;
    if (oid)
        snprintf(e->oid, sizeof e->oid, "%s", oid);
    e->symlink = symlink;
    e->executable = executable;
    t->count++;
    return 0;
}

static int entry_cmp(const void *a, const void *b)
{
    const struct premise_entry *x = a, *y = b;
    return strcmp(x->path, y->path);
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static const struct premise_tree *g_sort_tree;

static int by_base_cmp(const void *a, const void *b)
{
    const struct premise_entry *e = g_sort_tree->entries;
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    int c = strcmp(base_name(e[x].path), base_name(e[y].path));
    return c ? c : (x > y) - (x < y);
}

static void path_set_root(struct premise_tree *t)
{
    static const char domain[] = "zcl.lint.premise.path_set.v1";
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, (const unsigned char *)domain, sizeof domain);
    for (size_t i = 0; i < t->count; i++) {
        size_t n = strlen(t->entries[i].path) + 1;
        sha3_256_write(&h, (const unsigned char *)t->entries[i].path, n);
        /* Git grep skips symlinks and [ -e ] follows them. Executability
         * also changes whether a gate script can run. Git blob bytes alone
         * cannot distinguish any of these mode transitions. */
        unsigned char kind = t->entries[i].symlink ? 3
                             : t->entries[i].executable ? 2 : 1;
        sha3_256_write(&h, &kind, 1);
    }
    sha3_256_finalize(&h, t->path_set_root);
}

int premise_tree_finish(struct premise_tree *t)
{
    if (t->count > 1)
        qsort(t->entries, t->count, sizeof *t->entries, entry_cmp);
    for (size_t i = 1; i < t->count; i++)
        if (strcmp(t->entries[i - 1].path, t->entries[i].path) == 0)
            return 2;
    path_set_root(t);
    t->by_base = malloc((t->count ? t->count : 1) * sizeof *t->by_base); // raw-alloc-ok:lint-runtime
    if (!t->by_base)
        return 2;
    for (size_t i = 0; i < t->count; i++)
        t->by_base[i] = i;
    g_sort_tree = t;
    if (t->count > 1)
        qsort(t->by_base, t->count, sizeof *t->by_base, by_base_cmp);
    g_sort_tree = NULL;
    return 0;
}

struct premise_entry *premise_tree_find(const struct premise_tree *t,
                                        const char *path)
{
    struct premise_entry key = { .path = (char *)path };
    return bsearch(&key, t->entries, t->count, sizeof *t->entries, entry_cmp);
}

static int read_fd(int fd, uint8_t **bytes, size_t *len)
{
    size_t cap = 65536, used = 0;
    uint8_t *buf = malloc(cap); // raw-alloc-ok:lint-runtime
    if (!buf)
        return 2;
    for (;;) {
        if (used == cap) {
            uint8_t *grown = cap < PREMISE_FILE_MAX ? realloc(buf, cap * 2) : NULL; // raw-alloc-ok:lint-runtime
            if (!grown) {
                free(buf);
                return 2;
            }
            buf = grown;
            cap *= 2;
        }
        ssize_t n = read(fd, buf + used, cap - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            free(buf);
            return 2;
        }
        if (n == 0)
            break;
        used += (size_t)n;
    }
    *bytes = buf;
    *len = used;
    return 0;
}

static int read_candidate(const struct premise_tree *t,
                          const struct premise_entry *e, uint8_t **bytes,
                          size_t *len)
{
    char full[PREMISE_PATH_MAX * 2];
    int k = snprintf(full, sizeof full, "%s/%s", t->root, e->path);
    if (k < 0 || (size_t)k >= sizeof full)
        return 2;
    if (e->symlink) {
        uint8_t *buf = malloc(PREMISE_PATH_MAX); // raw-alloc-ok:lint-runtime
        ssize_t n = buf ? readlink(full, (char *)buf, PREMISE_PATH_MAX) : -1;
        if (n < 0 || n >= PREMISE_PATH_MAX) {
            free(buf);
            return 2;
        }
        *bytes = buf;
        *len = (size_t)n;
        return 0;
    }
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 2;
    int rc = read_fd(fd, bytes, len);
    close(fd);
    return rc;
}

int premise_tree_read(struct premise_tree *t, const char *path,
                      uint8_t **bytes, size_t *len, FILE *err)
{
    struct premise_entry *e = premise_tree_find(t, path);
    *bytes = NULL;
    *len = 0;
    if (!e)
        return 1;
    int rc = t->git ? premise_git_blob(t->git, e->oid, bytes, len)
                    : read_candidate(t, e, bytes, len);
    if (rc)
        fprintf(err, "premise: cannot read %s from the %s tree\n", path,
                t->git ? "verified base" : "candidate");
    return rc;
}

int premise_tree_hash(struct premise_tree *t, struct premise_entry *e,
                      FILE *err)
{
    if (e->hashed)
        return 0;
    uint8_t *bytes = NULL;
    size_t len = 0;
    int rc = premise_tree_read(t, e->path, &bytes, &len, err);
    if (rc)
        return rc;
    unsigned char tag = PREMISE_BLOB_TAG;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, &tag, 1);
    sha3_256_write(&h, bytes, len);
    sha3_256_finalize(&h, e->hash);
    free(bytes);
    e->hashed = true;
    e->present = true;
    return 0;
}

static int walk_dir(struct premise_tree *t, const char *rel, FILE *err);

static int walk_entry(struct premise_tree *t, const char *rel, FILE *err)
{
    char full[PREMISE_PATH_MAX * 2];
    struct stat st;
    int k = snprintf(full, sizeof full, "%s/%s", t->root, rel);
    if (k < 0 || (size_t)k >= sizeof full || lstat(full, &st) != 0) {
        fprintf(err, "premise: cannot stat candidate path %s\n", rel);
        return 2;
    }
    if (premise_path_pruned(rel))
        return 0;
    if (S_ISDIR(st.st_mode))
        return walk_dir(t, rel, err);
    if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
        bool executable = S_ISREG(st.st_mode) &&
            (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
        return premise_tree_add(t, rel, NULL, S_ISLNK(st.st_mode),
                                executable);
    }
    return 0;
}

static int walk_dir(struct premise_tree *t, const char *rel, FILE *err)
{
    char full[PREMISE_PATH_MAX * 2];
    int k = snprintf(full, sizeof full, "%s%s%s", t->root, rel[0] ? "/" : "",
                     rel);
    DIR *d = (k < 0 || (size_t)k >= sizeof full) ? NULL : opendir(full);
    if (!d) {
        fprintf(err, "premise: cannot list candidate directory %s\n",
                rel[0] ? rel : ".");
        return 2;
    }
    int rc = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[PREMISE_PATH_MAX];
        k = snprintf(child, sizeof child, "%s%s%s", rel, rel[0] ? "/" : "",
                     de->d_name);
        rc = (k < 0 || (size_t)k >= sizeof child) ? 2
                                                   : walk_entry(t, child, err);
    }
    closedir(d);
    return rc;
}

int premise_tree_walk(struct premise_tree *t, const char *root, FILE *err)
{
    int k = snprintf(t->root, sizeof t->root, "%s", root);
    if (k < 0 || (size_t)k >= sizeof t->root)
        return 2;
    int rc = walk_dir(t, "", err);
    if (rc == 0)
        rc = premise_tree_finish(t);
    return rc;
}

static void free_strings(char **v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(v[i]);
    free(v);
}

void premise_tree_free(struct premise_tree *t)
{
    for (size_t i = 0; i < t->count; i++) {
        free(t->entries[i].path);
        free(t->entries[i].deps);
        free_strings(t->entries[i].externals, t->entries[i].nexternals);
    }
    free(t->entries);
    free(t->by_base);
    if (t->git)
        premise_git_close(t->git);
    memset(t, 0, sizeof *t);
}
