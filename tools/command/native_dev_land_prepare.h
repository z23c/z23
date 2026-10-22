/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land preparation of the landing worktree's make products --
 *          the restart plan and the sealed proof's checker binaries --
 *          right before proof admission.
 *
 * Split out of tools/command/native_dev_land.c (which is at its file-size
 * ceiling). native_dev_land.c owns the queue and rows; this file only asks
 * Make for products the proof reads. It rewrites no tracked file and makes
 * no commit: the queue lands the tip exactly as it was submitted.
 */
#ifndef ZCL_NATIVE_DEV_LAND_PREPARE_H
#define ZCL_NATIVE_DEV_LAND_PREPARE_H

#include <stddef.h>
#include <stdbool.h>

/* Prepare the native Make restart plan after all landing inputs are ready.
 * Re-run its FORCE target even when a plan exists: earlier preparation may
 * have changed source metadata. Uses the bounded real Make adapter; false
 * leaves a diagnostic and never accepts a stale file after Make failure. */
bool zcl_dev_land_restart_plan_prepare(const char *wt, char *why,
                                       size_t why_cap);

/* Ensure the sealed proof's generated-docs checker binaries
 * (build/bin/z23-lint, z23-fleet-observe, gen_capability_inventory) exist
 * in the landing worktree: the proof copies them out of this checkout
 * before any dimension builds inside its generation and refuses the proof
 * when one is absent. Runs make only when a member is missing; false
 * leaves a diagnostic naming the exact absent binary or the make
 * failure. */
bool zcl_dev_land_proof_tools_prepare(const char *wt, char *why,
                                      size_t why_cap);

#endif /* ZCL_NATIVE_DEV_LAND_PREPARE_H */
