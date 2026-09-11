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

/* Bounded copy/join. Both refuse rather than truncate: a truncated path is
 * a different path, and this engine hands paths to a removal command. */
bool hg_copy(char *dst, size_t cap, const char *src);
bool hg_join(char *out, size_t cap, const char *a, const char *b);

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

#endif /* ZCL_TOOLS_HOST_GC_PRIV_H */
