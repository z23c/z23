/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Refresh installed git hooks when this worktree is already armed
 *          and the rebuilt hook binary differs. Never arms a checkout. */

#ifndef ZCL_REFRESH_GIT_HOOKS_H
#define ZCL_REFRESH_GIT_HOOKS_H

/* Reads ZCL_GIT_HOOK_SOURCE_ROOT, ZCL_GIT_HOOK_ROOT and
 * ZCL_GIT_HOOK_NATIVE_BIN. Returns 0 for every leave-alone and refresh
 * outcome, including a non-fatal installer failure. Returns 2 when the
 * source root is unset. */
int zcl_refresh_git_hooks_if_armed(void);

#endif
