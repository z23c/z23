/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * file_tree_ops — the single fd-based recursive file-tree walker.
 *
 * This is the one in-tree primitive that replaces every `system("cp -a …")`
 * / `system("rm -rf …")` shell-out in the node (see
 * docs/work/os-substrate-plan.md §1, Rung 0). Exactly one recursive walker
 * exists in the tree: this one. `engine/composition/src/file_ops.c` and every future
 * copy/remove path are thin wrappers over these functions rather than a
 * second parallel implementation.
 *
 * Doctrine:
 *   - O_NOFOLLOW everywhere: a symlink is NEVER followed during a copy or a
 *     remove. The ROOT src being a symlink is refused. A symlink ENTRY found
 *     inside a tree during copy is REFUSED (a hard error, not silently
 *     dereferenced or recreated); during remove it is unlinked in place.
 *   - Recursion is depth-bounded (ZCL_TREE_MAX_DEPTH) and returns a real
 *     error rather than overflowing the stack.
 *   - Every failure path returns a populated struct zcl_result carrying the
 *     exact offending path.
 */

#ifndef ZCL_UTIL_FILE_TREE_OPS_H
#define ZCL_UTIL_FILE_TREE_OPS_H

#include "util/result.h"

#include <stdbool.h>
#include <sys/types.h>   /* mode_t */

/* Maximum directory nesting depth a copy/remove will descend before it
 * refuses with an error rather than risk unbounded recursion. */
#define ZCL_TREE_MAX_DEPTH 64

/* ── zcl_tree_copy flags ─────────────────────────────────────────── */

/* Preserve st_mtim/st_atim on every copied file and directory (futimens),
 * matching `cp -a`'s timestamp preservation. Load-bearing for
 * engine/services/src/utxo_recovery_ldb_copy.c, which proves copy completeness
 * via an FNV-1a signature over (name, size, mtime_ns) of every entry — that
 * proof only holds if the copy preserves mtime exactly. */
#define ZCL_COPY_PRESERVE_TIMES  (1u << 0)

/* `cp -u` semantics: skip a destination file that already exists with an
 * mtime >= the source's (i.e. only copy when the source is newer or the
 * destination is absent). */
#define ZCL_COPY_UPDATE_ONLY     (1u << 1)

/* Per-entry filter. Called for every directory entry the walker visits with
 * the bare entry name (not a path), whether it is a directory, and the
 * caller-supplied context. Return true to include the entry, false to skip
 * it. A NULL filter accepts every entry. */
typedef bool (*zcl_tree_filter_fn)(const char *name, bool is_dir, void *ctx);

/* Recursively copy the tree rooted at `src` to `dst`.
 *
 *   - `src` a regular file  → `dst` is written as a single file (overwritten
 *     if present); the parent directory of `dst` must already exist.
 *   - `src` a directory     → `dst` is created (mkdir) and the tree is copied
 *     recursively; intermediate destination directories are created as the
 *     walk descends.
 *   - `src` a symlink       → REFUSED (never followed).
 *   - a symlink entry found inside the tree → REFUSED.
 *   - any other file type (fifo/socket/device) → REFUSED.
 *
 * Regular files are copied via a 256 KB read/write loop; the source mode is
 * preserved (fchmod). `flags` is a bitwise-OR of ZCL_COPY_*; `filter`/`fctx`
 * gate which entries are copied (NULL filter = all). Returns ZCL_OK or a
 * zcl_result naming the exact path that failed. */
struct zcl_result zcl_tree_copy(const char *src, const char *dst,
                                unsigned flags,
                                zcl_tree_filter_fn filter, void *fctx);

/* Recursively remove the tree at `path` (rm -rf semantics). A missing path
 * (ENOENT) is success. Symlinks are unlinked in place, never followed.
 * Returns ZCL_OK or a zcl_result naming the path that could not be removed. */
struct zcl_result zcl_tree_remove(const char *path);

/* Create `path` and any missing parent directories (mkdir -p semantics) with
 * mode `mode`. An already-existing directory is success. Returns ZCL_OK or a
 * zcl_result naming the component that failed. */
struct zcl_result zcl_mkdir_p(const char *path, mode_t mode);

#endif /* ZCL_UTIL_FILE_TREE_OPS_H */
