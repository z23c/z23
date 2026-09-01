/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_walk — private worktree traversal for contexts/commons/modules/vcs/. NOT a public header.
 *
 * Defines the tracked set (an ls-files-style recursive walk minus the ZVCS
 * ignore set), the ignore predicate, and per-file blob hashing. Shared by the
 * manifest builder and the index rebuild so the two agree byte-for-byte on
 * "what is tracked". */

#ifndef ZCL_VCS_WALK_H
#define ZCL_VCS_WALK_H

#include <stdbool.h>
#include <stdint.h>

/* True iff a repo-relative path is in the ZVCS ignore set:
 *   source-control/build roots plus checkout-local agent worktrees/caches;
 *   basename globs for databases, logs, test artifacts, and local tokens.
 * A directory whose name triggers a prefix rule is pruned (not descended). */
bool vcs_path_ignored(const char *relpath);

/* Per-tracked-file callback. relpath is repo-relative ('/'-separated). Return
 * false to abort the walk. */
typedef bool (*vcs_walk_cb)(const char *relpath, uint32_t mode, uint64_t size,
                            int64_t mtime_ns, int64_t ctime_ns, void *user);

/* Recursively walk the tracked set under repo_root, invoking cb per regular
 * file. Returns false on a hard error (unreadable root, cb abort). */
bool vcs_walk_tracked(const char *repo_root, vcs_walk_cb cb, void *user);

/* SHA3(0x20 || file content) of <repo_root>/<relpath>. Returns false on any
 * open/read error. */
bool vcs_blob_hash_file(const char *repo_root, const char *relpath,
                        uint8_t out[32]);

#endif /* ZCL_VCS_WALK_H */
