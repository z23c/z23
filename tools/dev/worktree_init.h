/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bootstrap one lane worktree from its canonical checkout. */

#ifndef ZCL_WORKTREE_INIT_H
#define ZCL_WORKTREE_INIT_H

/* Copy vendor archives and headers from the checkout that owns this
 * worktree's git common dir, arm this worktree's hooks, and require the
 * link prerequisites. 0 when the report ends with "done". 1 when a vendor
 * or prerequisite check fails. The make install-hooks status otherwise. */
int zcl_worktree_init(const char *worktree);

#endif
