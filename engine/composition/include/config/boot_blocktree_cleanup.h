/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_BOOT_BLOCKTREE_CLEANUP_H
#define ZCL_CONFIG_BOOT_BLOCKTREE_CLEANUP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Filesystem-only hygiene that runs before the LevelDB block index opens.
 * The result is for tests and diagnostics; boot only needs blocktree_path. */
struct boot_blocktree_cleanup_result {
    bool blocktree_path_ready;
    bool block_index_lock_removed;
    bool chainstate_import_tmp_removed;
    bool legacy_ldb_snap_removed;
    bool invalid_datadir;
    bool truncated_path;
};

struct boot_blocktree_cleanup_result
boot_blocktree_cleanup_prepare(const char *datadir,
                               char *blocktree_path,
                               size_t blocktree_path_n);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_BLOCKTREE_CLEANUP_H */
