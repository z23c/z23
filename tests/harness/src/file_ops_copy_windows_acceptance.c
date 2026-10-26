/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves file_copy() produces a private, byte-identical, bounded
 * copy and refuses a directory destination, and that on Windows dir_copy()
 * refuses without creating the tree while block-file cleanup and tree removal
 * refuse rather than deleting blk*.dat.
 *
 * dir_copy(), block_files_clean() and dir_remove_tree() refuse in their
 * Windows arms before reaching the shared walker; the sentinel below proves it. */
#if defined(_WIN32)

#include "config/file_ops.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static const char payload[] = "stable-copy-payload";

/* Every path this program creates under the private data directory. */
struct copy_paths {
    char source[1024];
    char target[1024];
    char directory_target[1024];
    char refused_tree[1024];
    char block_marker[1024];
};

static bool create_private_datadir(char *datadir, size_t datadir_size)
{
    char temp[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    return n != 0 && n < sizeof(temp) &&
           snprintf(datadir, datadir_size, "%sz23-file-ops-copy-%lu", temp,
                    (unsigned long)GetCurrentProcessId()) > 0 &&
           platform_private_directory_ensure(datadir);
}

static bool build_copy_paths(const char *datadir, struct copy_paths *paths)
{
    return snprintf(paths->source, sizeof(paths->source), "%s/source.bin",
                    datadir) > 0 &&
           snprintf(paths->target, sizeof(paths->target), "%s/target.bin",
                    datadir) > 0 &&
           snprintf(paths->directory_target, sizeof(paths->directory_target),
                    "%s/directory", datadir) > 0 &&
           snprintf(paths->refused_tree, sizeof(paths->refused_tree),
                    "%s/refused-tree", datadir) > 0 &&
           snprintf(paths->block_marker, sizeof(paths->block_marker),
                    "%s/blk00000.dat", datadir) > 0;
}

static bool payload_file_written(const char *source,
                                 struct platform_private_file *file)
{
    return platform_private_file_create(source, file) &&
           platform_private_file_write_at(file, payload, sizeof(payload), 0) &&
           platform_private_file_flush(file);
}

static bool file_copy_refuses_directory_destination(
    const struct copy_paths *paths)
{
    return platform_private_directory_ensure(paths->directory_target) &&
           !file_copy(paths->source, paths->directory_target) &&
           file_copy(paths->source, paths->target);
}

static bool dir_copy_refuses_without_creating_tree(const char *datadir,
    const struct copy_paths *paths)
{
    return !dir_copy(datadir, paths->refused_tree) &&
           platform_private_path_absent(paths->refused_tree) &&
           file_copy(paths->source, paths->block_marker);
}

static bool block_marker_survived_cleanup(const char *block_marker)
{
    struct platform_positioned_file sentinel;
    platform_positioned_file_init(&sentinel);
    bool present = platform_positioned_file_open(&sentinel, block_marker);
    platform_positioned_file_close(&sentinel);
    return present;
}

static bool copied_target_is_private_and_identical(const char *target)
{
    struct platform_positioned_file copied;
    char actual[sizeof(payload)];
    platform_positioned_file_init(&copied);
    bool ok = platform_positioned_file_open(&copied, target) &&
              platform_positioned_file_is_private(&copied) &&
              platform_positioned_file_read(&copied, actual, sizeof(actual),
                                             0) == (int64_t)sizeof(actual) &&
              memcmp(actual, payload, sizeof(payload)) == 0;
    platform_positioned_file_close(&copied);
    return ok;
}

int main(void)
{
    char datadir[MAX_PATH];
    if (!create_private_datadir(datadir, sizeof(datadir)))
        return 2;
    struct copy_paths paths;
    if (!build_copy_paths(datadir, &paths))
        return 3;
    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!payload_file_written(paths.source, &file))
        return 4;
    platform_private_file_close(&file);
    if (!file_copy_refuses_directory_destination(&paths))
        return 5;
    if (!dir_copy_refuses_without_creating_tree(datadir, &paths))
        return 6;
    block_files_clean(datadir);
    dir_remove_tree(datadir);
    if (!block_marker_survived_cleanup(paths.block_marker))
        return 7;
    if (!copied_target_is_private_and_identical(paths.target))
        return 8;

    /* Best-effort cleanup: every assertion above is already decided, and the
     * Windows tree-removal path is the refusal this program just proved. */
    (void)DeleteFileA(paths.source);
    (void)DeleteFileA(paths.target);
    (void)DeleteFileA(paths.block_marker);
    (void)RemoveDirectoryA(paths.directory_target);
    (void)RemoveDirectoryA(datadir);
    puts("file_ops_copy_windows_acceptance: PASS");
    return 0;
}

#else
typedef int file_ops_copy_windows_acceptance_not_built;
#endif
