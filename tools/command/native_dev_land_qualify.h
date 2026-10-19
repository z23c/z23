/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land qualify gates -- the pre-submit checks a lane runs in its
 *          own worktree (fetch, rebase, signed tip, regenerated files, full
 *          lint, affected test groups) before `dev land submit` queues it.
 *
 * Kept apart from native_dev_land.c, which owns the queue and its rows. This
 * file owns the gate sequence and its typed refusals; every child process
 * goes through the spawn seam with an explicit argument vector.
 */
#ifndef ZCL_NATIVE_DEV_LAND_QUALIFY_H
#define ZCL_NATIVE_DEV_LAND_QUALIFY_H

#include <stdbool.h>

enum zcl_land_qualify_code {
    ZCL_LAND_QUALIFY_OK = 0,
    ZCL_LAND_QUALIFY_DIRTY_TREE,
    ZCL_LAND_QUALIFY_FETCH_FAILED,
    ZCL_LAND_QUALIFY_REBASE_CONFLICT,
    ZCL_LAND_QUALIFY_UNSIGNED_TIP,
    ZCL_LAND_QUALIFY_STEP_FAILED,
    ZCL_LAND_QUALIFY_LINT_FAILED,
    ZCL_LAND_QUALIFY_GROUP_FAILED,
    ZCL_LAND_QUALIFY_TREE_CHANGED
};

struct zcl_land_qualify {
    enum zcl_land_qualify_code code;
    char name[128];    /* failing step or test group */
    char log[4096];    /* retained log of the failing command */
    char paths[1024];  /* space-separated paths a refusal names */
    char detail[256];  /* first failing line, when the log has one */
    char tip[41];      /* qualified tip, set on ZCL_LAND_QUALIFY_OK */
};

/* Run the gates in worktree `wt` and report the first refusal, or OK with the
 * tip that was qualified. The only history rewrite is folding regenerated
 * files into the tip (a signed amend) and rebasing onto origin/main when the
 * lane is behind it. `signing_exempt` skips the signature requirement and the
 * signing flag, and is meant for the landing fixtures that already gate
 * unsigned tips behind the proof stub. Returns true on OK. */
bool zcl_dev_land_qualify(const char *wt, bool signing_exempt,
                          struct zcl_land_qualify *out);

/* The registry spelling of a refusal: lint_failed, group_failed,
 * unsigned_tip, tree_changed and the rest. */
const char *zcl_dev_land_qualify_refusal(enum zcl_land_qualify_code code);

#endif
