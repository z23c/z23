/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_blocktree_cleanup.h"

#include "config/file_ops.h"

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static bool boot_blocktree_path(char *out, size_t out_n,
                                const char *datadir,
                                const char *suffix)
{
    if (!out || out_n == 0 || !datadir || !*datadir || !suffix || !*suffix)
        return false;

    int n = snprintf(out, out_n, "%s/%s", datadir, suffix);
    return n >= 0 && (size_t)n < out_n;
}

static bool boot_remove_lock_if_present(const char *path)
{
    if (!path || !*path || access(path, F_OK) != 0)
        return false;
    return unlink(path) == 0;
}

static bool boot_remove_stranded_scratch_dir(const char *path)
{
    if (!path || !*path)
        return false;

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;

    dir_remove_tree(path);
    bool removed = access(path, F_OK) != 0;
    printf("[boot] removed stranded scratch dir %s (rc=%d)\n",
           path, removed ? 0 : -1);
    return removed;
}

struct boot_blocktree_cleanup_result
boot_blocktree_cleanup_prepare(const char *datadir,
                               char *blocktree_path,
                               size_t blocktree_path_n)
{
    struct boot_blocktree_cleanup_result result = {0};
    if (blocktree_path && blocktree_path_n > 0)
        blocktree_path[0] = '\0';

    if (!datadir || !*datadir) {
        result.invalid_datadir = true;
        fprintf(stderr,
                "[boot] Cannot prepare block tree cleanup: invalid datadir\n");
        return result;
    }

    if (!boot_blocktree_path(blocktree_path, blocktree_path_n, datadir,
                             "blocks/index")) {
        result.truncated_path = true;
        if (blocktree_path && blocktree_path_n > 0)
            blocktree_path[0] = '\0';
        fprintf(stderr,
                "[boot] Cannot prepare block tree cleanup: datadir too long\n");
        return result;
    }
    result.blocktree_path_ready = true;

    char path[1100];
    if (!boot_blocktree_path(path, sizeof(path), datadir,
                             "blocks/index/LOCK")) {
        result.truncated_path = true;
        return result;
    }
    result.block_index_lock_removed = boot_remove_lock_if_present(path);

    if (!boot_blocktree_path(path, sizeof(path), datadir,
                             "chainstate_import_tmp")) {
        result.truncated_path = true;
        return result;
    }
    result.chainstate_import_tmp_removed =
        boot_remove_stranded_scratch_dir(path);

    if (!boot_blocktree_path(path, sizeof(path), datadir,
                             ".legacy_ldb_snap")) {
        result.truncated_path = true;
        return result;
    }
    result.legacy_ldb_snap_removed = boot_remove_stranded_scratch_dir(path);

    return result;
}
