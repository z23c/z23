/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File operations for data import/export.
 * Always byte-copy. Never hardlink or symlink.
 *
 * Thin wrappers over the single fd-based file-tree walker in
 * platform/modules/util/src/file_tree_ops.c — this file holds no recursive copy/remove
 * logic of its own (os-substrate-plan §1: exactly one walker in the tree). */

#include "config/file_ops.h"
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static _Atomic uint64_t g_file_copy_nonce;

/* Open src and capture the before-copy snapshot. Returns 0 on success; on
 * failure input is initialized and possibly open, and the caller closes
 * it. */
static int file_copy_open_and_snapshot(
    const char *src, struct platform_positioned_file *input,
    struct platform_positioned_file_snapshot *before)
{
    platform_positioned_file_init(input);
    if (!platform_positioned_file_open(input, src) ||
        !platform_positioned_file_snapshot(input, before))
        return -1;
    return 0;
}

/* Create the staging file beside the resolved destination under a fresh
 * nonce name, up to 64 attempts. Returns 0 when created, -1 otherwise. */
static int file_copy_create_staging(const char *resolved,
                                    struct platform_private_file *staging,
                                    char *staging_path,
                                    size_t staging_path_size)
{
    bool created = false;
    for (unsigned attempt = 0; attempt < 64 && !created; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_file_copy_nonce, 1, memory_order_relaxed);
        int n = snprintf(staging_path, staging_path_size, "%s.tmp.%016llx",
                         resolved, (unsigned long long)nonce);
        if (n <= 0 || (size_t)n >= staging_path_size)
            break;
        created = platform_private_file_create(staging_path, staging);
    }
    return created ? 0 : -1;
}

/* Byte-copy size bytes from input to staging at matching offsets. Returns
 * 0 when every chunk landed, -1 on a short read or failed write. */
static int file_copy_stream_bytes(struct platform_positioned_file *input,
                                  struct platform_private_file *staging,
                                  uint64_t size)
{
    uint8_t buffer[64 * 1024];
    uint64_t offset = 0;
    bool ok = true;
    while (ok && offset < size) {
        size_t want = size - offset < sizeof(buffer)
                          ? (size_t)(size - offset)
                          : sizeof(buffer);
        ok = platform_positioned_file_read(input, buffer, want, offset) ==
                 (int64_t)want &&
             platform_private_file_write_at(staging, buffer, want, offset);
        offset += ok ? want : 0;
    }
    return ok ? 0 : -1;
}

/* True when the after snapshot still describes the same source bytes the
 * before snapshot captured (nothing modified it while it was copied).
 * Re-reads the after snapshot from input: 0 when the bytes are unchanged,
 * -1 when the snapshot read fails or a field moved. */
static int file_copy_verify_source_unchanged(
    struct platform_positioned_file *input,
    const struct platform_positioned_file_snapshot *before)
{
    struct platform_positioned_file_snapshot after;
    if (!platform_positioned_file_snapshot(input, &after))
        return -1;
    if (before->size != after.size || before->volume != after.volume ||
        before->file_low != after.file_low ||
        before->file_high != after.file_high ||
        before->modified_seconds != after.modified_seconds ||
        before->modified_nanoseconds != after.modified_nanoseconds ||
        before->changed_seconds != after.changed_seconds ||
        before->changed_nanoseconds != after.changed_nanoseconds)
        return -1;
    return 0;
}

bool file_copy(const char *src, const char *dst)
{
    struct platform_positioned_file input;
    struct platform_positioned_file_snapshot before;
    if (file_copy_open_and_snapshot(src, &input, &before) != 0) {
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
    bool created =
        file_copy_create_staging(resolved, &staging, staging_path,
                                 sizeof(staging_path)) == 0;
    bool ok = created &&
              (file_copy_stream_bytes(&input, &staging, before.size) == 0);
    ok = ok && file_copy_verify_source_unchanged(&input, &before) == 0 &&
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
        if (!zcl_path_join(s, sizeof(s), src_dir, name) ||
            !zcl_path_join(de, sizeof(de), dst_dir, name)) {
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

/* What a blk/rev coordinate holds, as three outcomes rather than a bool.
 *
 * The block series is walked by probing consecutive names until one is not
 * there, so "nothing at this coordinate" is a normal end-of-series and must
 * never be confused with "something is there that this copier will not
 * touch". A single open()-succeeded bool collapses those: since
 * platform_positioned_file_open() started refusing every non-regular object
 * (S_ISREG check) and every symlink (O_NOFOLLOW), a directory or a symlink
 * planted at blk00000.dat read as end-of-series and the copy reported
 * success having silently skipped it — a snapshot import would land a
 * truncated block series and call it complete. platform_file_metadata_read()
 * already separates the two: MISSING is ENOENT, REFUSED is "exists but is
 * not a regular file we can read", which is a hard failure here. */
enum block_files_probe {
    BLOCK_FILES_PROBE_PRESENT = 0,
    BLOCK_FILES_PROBE_MISSING,
    BLOCK_FILES_PROBE_REFUSED,
};

static enum block_files_probe block_files_probe_coordinate(const char *path)
{
    struct platform_file_metadata metadata;
    switch (platform_file_metadata_read(path, &metadata)) {
    case PLATFORM_FILE_METADATA_OK:
        return BLOCK_FILES_PROBE_PRESENT;
    case PLATFORM_FILE_METADATA_MISSING:
        return BLOCK_FILES_PROBE_MISSING;
    default:
        return BLOCK_FILES_PROBE_REFUSED;
    }
}

/* Outcome of copying the members at one index of the block series: the blk
 * file (always probed; MISSING is the normal end of the series) and the rev
 * file (copied only when PRESENT). FAILED is the fail-closed result the
 * caller turns into its -1 return. */
enum block_files_pair_outcome {
    BLOCK_FILES_PAIR_COPIED = 0,
    BLOCK_FILES_PAIR_END,
    BLOCK_FILES_PAIR_FAILED,
};

static enum block_files_pair_outcome block_files_copy_pair(
    const char *src_dir, const char *dst_dir, int index)
{
    char src[1024], dst[1024], name[32];
    snprintf(name, sizeof(name), "blk%05d.dat", index);
    if (!zcl_path_join(src, sizeof(src), src_dir, name))
        return BLOCK_FILES_PAIR_FAILED;
    enum block_files_probe blk = block_files_probe_coordinate(src);
    if (blk == BLOCK_FILES_PROBE_REFUSED)
        return BLOCK_FILES_PAIR_FAILED;
    if (blk == BLOCK_FILES_PROBE_MISSING)
        return BLOCK_FILES_PAIR_END;
    if (!zcl_path_join(dst, sizeof(dst), dst_dir, name))
        return BLOCK_FILES_PAIR_FAILED;
    if (!file_copy(src, dst))
        return BLOCK_FILES_PAIR_FAILED;
    snprintf(name, sizeof(name), "rev%05d.dat", index);
    if (!zcl_path_join(src, sizeof(src), src_dir, name))
        return BLOCK_FILES_PAIR_FAILED;
    enum block_files_probe rev = block_files_probe_coordinate(src);
    if (rev == BLOCK_FILES_PROBE_REFUSED)
        return BLOCK_FILES_PAIR_FAILED;
    if (rev == BLOCK_FILES_PROBE_PRESENT) {
        if (!zcl_path_join(dst, sizeof(dst), dst_dir, name))
            return BLOCK_FILES_PAIR_FAILED;
        if (!file_copy(src, dst))
            return BLOCK_FILES_PAIR_FAILED;
    }
    return BLOCK_FILES_PAIR_COPIED;
}

int block_files_copy(const char *src_dir, const char *dst_dir)
{
#ifdef _WIN32
    if (!src_dir || !src_dir[0] || !dst_dir || !dst_dir[0] ||
        !platform_private_directory_ensure(dst_dir))
        return -1;
#endif
    int count = 0;
    for (int i = 0; i < 9999; i++) {
        enum block_files_pair_outcome outcome =
            block_files_copy_pair(src_dir, dst_dir, i);
        if (outcome == BLOCK_FILES_PAIR_FAILED)
            return -1;
        if (outcome == BLOCK_FILES_PAIR_END)
            break;
        count++;
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
            if (zcl_path_join(path, sizeof(path), dir, name) &&
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
