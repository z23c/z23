/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared bounded structures and seams for the dev.fleet collector. */

#ifndef ZCL_NATIVE_DEV_FLEET_INTERNAL_H
#define ZCL_NATIVE_DEV_FLEET_INTERNAL_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>

#define ZCL_FLEET_PATH_MAX 4096
#define ZCL_FLEET_OID_MAX  65

struct zcl_fleet_worktree {
    bool present;
    char path[ZCL_FLEET_PATH_MAX];
    char head[ZCL_FLEET_OID_MAX];
    char branch[256];
};

int zcl_dev_fleet_git_capture(const char *cwd, const char *const args[],
                              char *out, size_t cap, bool *truncated);

bool zcl_dev_fleet_receipts_json(const struct zcl_fleet_worktree *worktree,
                                 struct json_value *lane,
                                 size_t *owner_red,
                                 char *why, size_t why_size);

#endif
