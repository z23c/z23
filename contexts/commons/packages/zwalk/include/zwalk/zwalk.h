/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded recursive directory traversal for C23 — deterministic
 *          order, explicit depth bound, fail-closed on filesystem errors.
 *
 * Design notes:
 *  - Deterministic order: entries within each directory are sorted by
 *    byte-wise name comparison before visiting (readdir order is
 *    unspecified), so a walk is reproducible across runs, filesystems,
 *    and machines. This is a feature: callers may diff walk output.
 *  - Symlinks are NEVER followed by default. Following links turns a tree
 *    walk into a graph walk: cycles, escaped subtrees, and surprising
 *    duplicate work. With follow_symlinks=false a symlink is reported
 *    once as ZWALK_SYMLINK and never descended. Opt in with
 *    follow_symlinks=true only with a modest max_depth — depth is the
 *    ONLY cycle guard, and a dangling link fails the walk.
 *  - Bounded: recursion is capped at max_depth (default
 *    ZWALK_DEFAULT_MAX_DEPTH), joined paths at PATH_MAX bytes, and
 *    directory fan-out at ZWALK_MAX_ENTRIES per directory.
 *  - Fail-closed: an unreadable directory, a failed stat, an over-long
 *    path, or a fan-out over the cap aborts the walk and returns false.
 *    The caller sees failure, never silent omission.
 *
 * Visit contract: the root itself is visited first at depth 0; children
 * at depth 1, up to max_depth. size is the byte size for ZWALK_FILE and
 * 0 for all other types. The callback returns ZWALK_GO to continue,
 * ZWALK_SKIP to not descend into this directory (no effect on other
 * types), or ZWALK_STOP to end the walk early — zwalk() then still
 * returns true. The path pointer is valid only during the callback.
 */
#ifndef ZWALK_H
#define ZWALK_H

#include <stdbool.h>
#include <stdint.h>

#define ZWALK_DEFAULT_MAX_DEPTH 32
#define ZWALK_MAX_ENTRIES (1u << 20) /* per directory */

typedef enum {
  ZWALK_FILE = 0,
  ZWALK_DIR,
  ZWALK_SYMLINK,
  ZWALK_OTHER /* fifo, socket, device, ... */
} zwalk_type;

typedef enum {
  ZWALK_GO = 0,
  ZWALK_SKIP,
  ZWALK_STOP
} zwalk_action;

typedef zwalk_action (*zwalk_visit_fn)(void *ctx, const char *path,
                                       zwalk_type type, int depth,
                                       uint64_t size);

struct zwalk_opts {
  int max_depth;        /* deepest level visited; 0 visits the root only */
  bool skip_hidden;     /* skip entries whose name starts with '.' */
  bool follow_symlinks; /* DANGER: see header notes; default false */
};

/* Walk root depth-first in sorted order, invoking visit per node.
 * NULL opts means { ZWALK_DEFAULT_MAX_DEPTH, false, false }.
 * Returns false (fail-closed) on NULL arguments, an empty root, a
 * negative max_depth, or any filesystem error; ZWALK_STOP is not an
 * error. The root may be a plain file, visited once at depth 0. */
bool zwalk(const char *root, const struct zwalk_opts *opts,
           zwalk_visit_fn visit, void *ctx);

#endif /* ZWALK_H */
