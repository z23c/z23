/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "config/file_ops.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/file_tree_ops.h"

#include <stdio.h>
#include <string.h>

struct zcl_result zcl_tree_remove(const char *path)
{
    (void)path;
    return ZCL_OK;
}

int main(int argc, char **argv)
{
    if (argc != 2 || !platform_private_directory_ensure(argv[1]))
        return 2;
    char source[1024], target[1024], directory_target[1024];
    char refused_tree[1024], block_marker[1024];
    if (snprintf(source, sizeof(source), "%s/source.bin", argv[1]) <= 0 ||
        snprintf(target, sizeof(target), "%s/target.bin", argv[1]) <= 0 ||
        snprintf(directory_target, sizeof(directory_target), "%s/directory",
                 argv[1]) <= 0 ||
        snprintf(refused_tree, sizeof(refused_tree), "%s/refused-tree",
                 argv[1]) <= 0 ||
        snprintf(block_marker, sizeof(block_marker), "%s/blk00000.dat",
                 argv[1]) <= 0)
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
#ifdef _WIN32
    if (dir_copy(argv[1], refused_tree) ||
        !platform_private_path_absent(refused_tree) ||
        !file_copy(source, block_marker))
        return 6;
    block_files_clean(argv[1]);
    dir_remove_tree(argv[1]);
    struct platform_positioned_file sentinel;
    platform_positioned_file_init(&sentinel);
    bool sentinel_present =
        platform_positioned_file_open(&sentinel, block_marker);
    platform_positioned_file_close(&sentinel);
    if (!sentinel_present)
        return 7;
#endif
    struct platform_positioned_file copied;
    char actual[sizeof(payload)];
    platform_positioned_file_init(&copied);
    bool ok = platform_positioned_file_open(&copied, target) &&
              platform_positioned_file_is_private(&copied) &&
              platform_positioned_file_read(&copied, actual, sizeof(actual),
                                             0) == (int64_t)sizeof(actual) &&
              memcmp(actual, payload, sizeof(payload)) == 0;
    platform_positioned_file_close(&copied);
    return ok ? 0 : 8;
}
