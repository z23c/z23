/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File operations for data import/export.
 * Always byte-copy. Never hardlink or symlink.
 *
 * Thin wrappers over the single fd-based file-tree walker in
 * lib/util/src/file_tree_ops.c — this file holds no recursive copy/remove
 * logic of its own (os-substrate-plan §1: exactly one walker in the tree). */

#include "config/file_ops.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/file_tree_ops.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static _Atomic uint64_t g_file_copy_nonce;

static bool file_ops_join(char *out, size_t cap, const char *dir,
                          const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

bool file_copy(const char *src, const char *dst)
{
    struct platform_positioned_file input;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&input);
    if (!platform_positioned_file_open(&input, src) ||
        !platform_positioned_file_snapshot(&input, &before)) {
        platform_positioned_file_close(&input);
        return false;
    }
    char resolved[4096], parent[4096], staging_path[4096];
    if (!platform_private_path_resolve(dst, resolved, sizeof(resolved), parent,
                                       sizeof(parent))) {
        platform_positioned_file_close(&input);
        return false;
    }
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = false;
    for (unsigned attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_file_copy_nonce, 1, memory_order_relaxed);
        int n = snprintf(staging_path, sizeof(staging_path), "%s.tmp.%016llx",
                         resolved, (unsigned long long)nonce);
        if (n <= 0 || (size_t)n >= sizeof(staging_path))
            break;
        created = platform_private_file_create(staging_path, &staging);
    }
    uint8_t buffer[64 * 1024];
    uint64_t offset = 0;
    bool ok = created;
    while (ok && offset < before.size) {
        size_t want = before.size - offset < sizeof(buffer)
                          ? (size_t)(before.size - offset)
                          : sizeof(buffer);
        ok = platform_positioned_file_read(&input, buffer, want, offset) ==
                 (int64_t)want &&
             platform_private_file_write_at(&staging, buffer, want, offset);
        offset += ok ? want : 0;
    }
    ok = ok && platform_positioned_file_snapshot(&input, &after) &&
         before.size == after.size && before.volume == after.volume &&
         before.file_low == after.file_low &&
         before.file_high == after.file_high &&
         before.modified_seconds == after.modified_seconds &&
         before.modified_nanoseconds == after.modified_nanoseconds &&
         before.changed_seconds == after.changed_seconds &&
         before.changed_nanoseconds == after.changed_nanoseconds &&
         platform_private_file_flush(&staging) &&
         platform_private_file_replace(&staging, staging_path, resolved) &&
         platform_private_parent_flush(parent);
    platform_positioned_file_close(&input);
    platform_private_file_close(&staging);
    if (!ok && created)
        (void)platform_private_file_unlink_missing_ok(staging_path);
    return ok;
}

bool dir_copy(const char *src_dir, const char *dst_dir)
{
#ifdef _WIN32
    (void)src_dir;
    (void)dst_dir;
    /* Recursive replacement needs a retained-root immutable generation
     * transaction. Refuse before destination removal or creation. */
    return false;
#else
    /* One level deep, byte copy, skip LOCK — same semantics as before. The
     * recursive walker is deliberately NOT used here: dir_copy treats a
     * nested subdirectory as a failure (fails closed), whereas a tree copy
     * would descend it. Empty the destination via the shared rm -rf
     * primitive, then copy each regular file through file_copy (itself a
     * walker wrapper). */
    (void)zcl_tree_remove(dst_dir);
    if (!platform_private_directory_ensure(dst_dir)) {
        fprintf(stderr, "Warning: private directory refused: %s\n", dst_dir);
        return false;
    }
    struct platform_directory_list entries = {0};
    struct platform_directory_list directories = {0};
    if (!platform_directory_list_regular_sorted(src_dir, &entries) ||
        !platform_directory_list_real_sorted(src_dir, &directories)) {
        platform_directory_list_free(&entries);
        platform_directory_list_free(&directories);
        return false;
    }
    int copied = 0, failed = 0;
    if (directories.count > 0)
        failed += (int)directories.count;
    for (size_t i = 0; i < entries.count; i++) {
        const char *name = entries.entries[i].name;
        if (name[0] == '.' || strcmp(name, "LOCK") == 0) continue;
        char s[1024], de[1024];
        if (!file_ops_join(s, sizeof(s), src_dir, name) ||
            !file_ops_join(de, sizeof(de), dst_dir, name)) {
            failed++;
            continue;
        }
        if (file_copy(s, de))
            copied++;
        else
            failed++;
    }
    platform_directory_list_free(&entries);
    platform_directory_list_free(&directories);
    printf(" %d files", copied);
    if (failed > 0)
        fprintf(stderr, "\nWarning: %d files failed to copy in %s\n",
                failed, dst_dir);
    return failed == 0;
#endif
}

int block_files_copy(const char *src_dir, const char *dst_dir)
{
#ifdef _WIN32
    if (!src_dir || !src_dir[0] || !dst_dir || !dst_dir[0] ||
        !platform_private_directory_ensure(dst_dir))
        return -1;
#endif
    int count = 0;
    char src[1024], dst[1024];
    for (int i = 0; i < 9999; i++) {
        struct platform_positioned_file_snapshot st;
        char name[32];
        snprintf(name, sizeof(name), "blk%05d.dat", i);
        if (!file_ops_join(src, sizeof(src), src_dir, name))
            return -1;
        struct platform_positioned_file probe;
        platform_positioned_file_init(&probe);
        bool exists = platform_positioned_file_open(&probe, src) &&
                      platform_positioned_file_snapshot(&probe, &st);
        platform_positioned_file_close(&probe);
        if (!exists) {
            if (platform_private_path_absent(src)) break;
            return -1;
        }
        if (!file_ops_join(dst, sizeof(dst), dst_dir, name))
            return -1;
        if (!file_copy(src, dst))
            return -1;
        count++;
        snprintf(name, sizeof(name), "rev%05d.dat", i);
        if (!file_ops_join(src, sizeof(src), src_dir, name))
            return -1;
        platform_positioned_file_init(&probe);
        exists = platform_positioned_file_open(&probe, src) &&
                 platform_positioned_file_snapshot(&probe, &st);
        platform_positioned_file_close(&probe);
        if (!exists && !platform_private_path_absent(src))
            return -1;
        if (exists) {
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
#ifdef _WIN32
    (void)dir;
    return;
#else
    struct platform_directory_list entries = {0};
    if (!platform_directory_list_regular_sorted(dir, &entries)) return;
    for (size_t i = 0; i < entries.count; i++) {
        const char *name = entries.entries[i].name;
        if ((strncmp(name, "blk", 3) == 0 ||
             strncmp(name, "rev", 3) == 0) && strstr(name, ".dat")) {
            char path[1024];
            struct platform_private_file file;
            struct platform_private_file_identity identity;
            platform_private_file_init(&file);
            if (file_ops_join(path, sizeof(path), dir, name) &&
                platform_private_file_open_locked(path, &file) &&
                platform_private_file_identity(&file, &identity))
                (void)platform_private_file_retire_if_identity(
                    &file, path, &identity);
            platform_private_file_close(&file);
        }
    }
    platform_directory_list_free(&entries);
#endif
}

void dir_remove_tree(const char *dir)
{
#ifdef _WIN32
    (void)dir;
    return;
#else
    /* rm -rf semantics, best-effort (void return preserved). The one shared
     * walker handles symlinks-in-place and ENOENT-as-success. */
    (void)zcl_tree_remove(dir);
#endif
}
