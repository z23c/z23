/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File operations for data import/export.
 * Always byte-copy. Never hardlink or symlink.
 *
 * Thin wrappers over the single fd-based file-tree walker in
 * lib/util/src/file_tree_ops.c — this file holds no recursive copy/remove
 * logic of its own (os-substrate-plan §1: exactly one walker in the tree). */

#include "config/file_ops.h"
#include "util/file_tree_ops.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool file_ops_join(char *out, size_t cap, const char *dir,
                          const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

bool file_copy(const char *src, const char *dst)
{
    /* Preserve the historical contract: a regular file only. A directory (or
     * anything non-regular) returns false. lstat, not stat, so a symlink
     * source is refused rather than followed (matches this module's
     * "Never hardlink or symlink" doctrine and the O_NOFOLLOW walker). */
    struct stat st;
    if (lstat(src, &st) != 0 || !S_ISREG(st.st_mode))
        return false;

    struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
    return r.ok;
}

bool dir_copy(const char *src_dir, const char *dst_dir)
{
    /* One level deep, byte copy, skip LOCK — same semantics as before. The
     * recursive walker is deliberately NOT used here: dir_copy treats a
     * nested subdirectory as a failure (fails closed), whereas a tree copy
     * would descend it. Empty the destination via the shared rm -rf
     * primitive, then copy each regular file through file_copy (itself a
     * walker wrapper). */
    (void)zcl_tree_remove(dst_dir);
    if (mkdir(dst_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: mkdir(%s) failed: %s\n",
                dst_dir, strerror(errno));
        return false;
    }
    DIR *d = opendir(src_dir);
    if (!d) return false;
    struct dirent *ent;
    int copied = 0, failed = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strcmp(ent->d_name, "LOCK") == 0) continue;
        char s[1024], de[1024];
        if (!file_ops_join(s, sizeof(s), src_dir, ent->d_name) ||
            !file_ops_join(de, sizeof(de), dst_dir, ent->d_name)) {
            failed++;
            continue;
        }
        if (file_copy(s, de))
            copied++;
        else
            failed++;
    }
    closedir(d);
    printf(" %d files", copied);
    if (failed > 0)
        fprintf(stderr, "\nWarning: %d files failed to copy in %s\n",
                failed, dst_dir);
    return failed == 0;
}

int block_files_copy(const char *src_dir, const char *dst_dir)
{
    int count = 0;
    char src[1024], dst[1024];
    for (int i = 0; i < 9999; i++) {
        struct stat st;
        char name[32];
        snprintf(name, sizeof(name), "blk%05d.dat", i);
        if (!file_ops_join(src, sizeof(src), src_dir, name))
            return -1;
        if (stat(src, &st) != 0) break;
        if (!file_ops_join(dst, sizeof(dst), dst_dir, name))
            return -1;
        if (!file_copy(src, dst))
            return -1;
        count++;
        snprintf(name, sizeof(name), "rev%05d.dat", i);
        if (!file_ops_join(src, sizeof(src), src_dir, name))
            return -1;
        if (stat(src, &st) == 0) {
            if (!file_ops_join(dst, sizeof(dst), dst_dir, name))
                return -1;
            if (!file_copy(src, dst))
                return -1;
        }
    }
    return count;
}

void block_files_clean(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if ((strncmp(ent->d_name, "blk", 3) == 0 ||
             strncmp(ent->d_name, "rev", 3) == 0) &&
            strstr(ent->d_name, ".dat")) {
            char path[1024];
            if (file_ops_join(path, sizeof(path), dir, ent->d_name))
                unlink(path);
        }
    }
    closedir(d);
}

void dir_remove_tree(const char *dir)
{
    /* rm -rf semantics, best-effort (void return preserved). The one shared
     * walker handles symlinks-in-place and ENOENT-as-success. */
    (void)zcl_tree_remove(dir);
}
