/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private recheck surface shared by the confined worker and its
 * binding-currency/ZCODE-context verifier. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_WORKER_INTERNAL_H
#define ZCL_SERVICES_BUILD_FABRIC_WORKER_INTERNAL_H

#if !defined(_WIN32)

#include "models/build_fabric.h"
#include "util/result.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stdint.h>

/* The source tree named by `root_hex` is still exactly in the workspace CAS
 * and still hashes to its own name. */
bool bfw_input_root_current(const char *workspace, const char *root_hex);

/* This host's gcc capsule still roots to the toolchain the job was bound to. */
bool bfw_toolchain_current(const struct db_build_job *job);

/* The database still holds the exact job/action/lease binding this worker
 * captured, and both ids still re-derive from their stored roots. */
bool bfw_binding_current(
    struct node_db *ndb, const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, const char *lease_id);

/* Load the action's ZCODE task/candidate/proof-policy from the workspace CAS
 * and refuse unless every root, patch, toolchain, and source binding still
 * verifies. `*present` stays false for an action with no ZCODE context. */
struct zcl_result bfw_load_zcode_context(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, int64_t now,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy, bool *present);

#endif /* !_WIN32 */

#endif /* ZCL_SERVICES_BUILD_FABRIC_WORKER_INTERNAL_H */
