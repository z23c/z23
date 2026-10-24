/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: internal seam between the two host-GC translation units —
 *          host_gc_paths.c (bounded string plumbing, the protection
 *          predicate, apparent-size measurement) and host_gc_sweep.c
 *          (worktree enumeration, occupancy, classification, removal).
 *          Not a public surface: command/host_gc_sweep.h is.
 */

#ifndef ZCL_TOOLS_HOST_GC_PRIV_H
#define ZCL_TOOLS_HOST_GC_PRIV_H

#include "command/host_gc_sweep.h"

/* Bounded copy. It refuses rather than truncates: a truncated path is
 * a different path, and this engine hands paths to a removal command. */
bool hg_copy(char *dst, size_t cap, const char *src);

/* Trim trailing whitespace and line endings in place. */
void hg_strip(char *s);

/* True when `path` is `dir` itself or lives strictly under it. */
bool hg_under(const char *dir, const char *path);

/* Apparent size of a tree, symlinks counted as links and never followed.
 * Bounded by an entry budget so a pathological tree cannot make the sweep
 * unbounded; exhausting it reports what was measured so far. */
uint64_t hg_dir_bytes(const char *path);

/* Restore owner read/write/search on every directory of the tree at `path`.
 * A dead dev-proof generation routinely holds read-only test scratch, and a
 * single read-only directory is enough to make the whole generation
 * undeletable — which is how one survives a sweep that has already
 * unregistered it. Bounded and symlink-safe exactly like hg_dir_bytes: only
 * a real directory found by lstat() is ever chmod()ed, never a symlink. */
void hg_grant_write(const char *path);

/* ---- host_gc_disposable.c: disposable gate-copy pools ---- */

enum { HG_LOCK_FREE = 0, HG_LOCK_BUSY = 1 };

/* Probe (and keep) the sibling flock <wt>.lock with a non-blocking flock.
 * HG_LOCK_FREE: nobody holds it; *fd is the held descriptor, or -1 when the
 * file is absent. HG_LOCK_BUSY: another process holds it, or it could not be
 * opened or is not a regular file (fail closed). */
int hg_lock_acquire(const char *wt, int *fd);
void hg_lock_release(int fd);

/* Unlink <wt>.bundle, <wt>.prime.log and <wt>.lock, in that order, each only
 * when it is a regular file (lstat; a symlink is left alone). Returns bytes. */
uint64_t hg_remove_siblings(const char *wt);

/* True for a directory git does not register but that has the gate-copy
 * shape: a .git FILE naming a missing .../.git/worktrees/<n> and a sibling
 * regular <dir>.lock. */
bool hg_orphan_shape(const char *dir);

/* True when <procdir>/status names only uids that are neither root nor ours
 * (real, effective, saved, fs). Unreadable or malformed reads as false. */
bool hg_proc_foreign(const char *procdir);

/* True when `pool` or an ancestor is a directory of our uid closed to group
 * and other, so a process of another uid cannot open anything under it. */
bool hg_pool_closed(const char *pool);

#endif /* ZCL_TOOLS_HOST_GC_PRIV_H */
