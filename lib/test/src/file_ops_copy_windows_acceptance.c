/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves file_copy() produces a private, byte-identical, bounded
 * copy and refuses a directory destination, and that on Windows dir_copy()
 * refuses without creating the tree while block-file cleanup and tree removal
 * refuse rather than deleting blk*.dat.
 *
 * Adopted from the `#ifdef _WIN32` arm of tools/tests/test_file_ops_copy.c.
 * The deleted tools/scripts/winacceptance.sh built that program natively, so
 * this arm was never read by a compiler; the catalog cross-links it for
 * Windows, which is the first time these lines are checked. The POSIX
 * assertions of the same program are now the `file_ops_copy` suite group in
 * lib/test/src/test_file_ops_copy.c, where they execute on every run.
 *
 * The standalone stubbed zcl_tree_remove() to a no-op so it could link. No
 * stub is needed here: dir_copy(), block_files_clean() and dir_remove_tree()
 * all refuse in their Windows arms before reaching the shared walker, which
 * is precisely what the sentinel below proves. */
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

int main(void)
{
    char temp[MAX_PATH], datadir[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    if (!n || n >= sizeof(temp) ||
        snprintf(datadir, sizeof(datadir), "%sz23-file-ops-copy-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0)
        return 2;
    if (!platform_private_directory_ensure(datadir))
        return 2;
    char source[1024], target[1024], directory_target[1024];
    char refused_tree[1024], block_marker[1024];
    if (snprintf(source, sizeof(source), "%s/source.bin", datadir) <= 0 ||
        snprintf(target, sizeof(target), "%s/target.bin", datadir) <= 0 ||
        snprintf(directory_target, sizeof(directory_target), "%s/directory",
                 datadir) <= 0 ||
        snprintf(refused_tree, sizeof(refused_tree), "%s/refused-tree",
                 datadir) <= 0 ||
        snprintf(block_marker, sizeof(block_marker), "%s/blk00000.dat",
                 datadir) <= 0)
        return 3;
    struct platform_private_file file;
    platform_private_file_init(&file);
    static const char payload[] = "stable-copy-payload";
    if (!platform_private_file_create(source, &file) ||
        !platform_private_file_write_at(&file, payload, sizeof(payload), 0) ||
        !platform_private_file_flush(&file))
        return 4;
    platform_private_file_close(&file);
    if (!platform_private_directory_ensure(directory_target) ||
        file_copy(source, directory_target) || !file_copy(source, target))
        return 5;
    if (dir_copy(datadir, refused_tree) ||
        !platform_private_path_absent(refused_tree) ||
        !file_copy(source, block_marker))
        return 6;
    block_files_clean(datadir);
    dir_remove_tree(datadir);
    struct platform_positioned_file sentinel;
    platform_positioned_file_init(&sentinel);
    bool sentinel_present =
        platform_positioned_file_open(&sentinel, block_marker);
    platform_positioned_file_close(&sentinel);
    if (!sentinel_present)
        return 7;
    struct platform_positioned_file copied;
    char actual[sizeof(payload)];
    platform_positioned_file_init(&copied);
    bool ok = platform_positioned_file_open(&copied, target) &&
              platform_positioned_file_is_private(&copied) &&
              platform_positioned_file_read(&copied, actual, sizeof(actual),
                                             0) == (int64_t)sizeof(actual) &&
              memcmp(actual, payload, sizeof(payload)) == 0;
    platform_positioned_file_close(&copied);
    if (!ok)
        return 8;

    /* Best-effort cleanup: every assertion above is already decided, and the
     * Windows tree-removal path is the refusal this program just proved. */
    (void)DeleteFileA(source);
    (void)DeleteFileA(target);
    (void)DeleteFileA(block_marker);
    (void)RemoveDirectoryA(directory_target);
    (void)RemoveDirectoryA(datadir);
    puts("file_ops_copy_windows_acceptance: PASS");
    return 0;
}

#else
typedef int file_ops_copy_windows_acceptance_not_built;
#endif
