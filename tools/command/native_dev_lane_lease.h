/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * What `dev lane new` leaves in a fresh lane beyond the worktree itself:
 * a lease file, the per-worktree signing settings and a report of whether
 * the precheck lint binary is present (native_dev_lane_lease.c). */

#ifndef ZCL_NATIVE_DEV_LANE_LEASE_H
#define ZCL_NATIVE_DEV_LANE_LEASE_H

#include "json/json.h"

#include <stdbool.h>
#include <stdint.h>

#define ZCL_LANE_LEASE_FILE ".lane-lease.json"
#define ZCL_LANE_LEASE_TTL_S 21600

/* Write <lane>/.lane-lease.json once (an existing lease is kept), copy the
 * signing settings set in `root`'s effective git configuration into the
 * lane's per-worktree configuration, and append lease_path,
 * signing_configured and precheck_lint_present to `data`. Returns false only
 * when the lease cannot be written. */
bool zcl_dev_lane_lease_setup(const char *root, const char *lane,
                              struct json_value *data);

/* Lease body for tests and readers; false when `owner` is unusable. */
bool zcl_dev_lane_lease_body(const char *owner, int64_t now, char *out,
                             size_t cap);

#endif
