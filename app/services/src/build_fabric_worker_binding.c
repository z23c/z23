/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Recheck a leased build action's bound inputs — source CAS root,
 * toolchain capsule, database job/action/lease binding — and load its
 * verified ZCODE task/candidate/proof-policy context (E1 file-size split out
 * of build_fabric_worker.c). */

// one-result-type-ok:total-binding-currency-predicates — the three currency
// rechecks are TOTAL yes/no predicates over already-captured state ("is this
// binding still exactly what the lease captured?"); they own no fallible
// service surface. Only the ZCODE context load, which refuses with a named
// reason, returns struct zcl_result.

#include "services/build_fabric_worker.h"
#include "build_fabric_worker_internal.h"

#if !defined(_WIN32)

#include "base/hex.h"
#include "crypto/sha3.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_patch.h"

#include <stdlib.h>
#include <string.h>

bool bfw_input_root_current(const char *workspace,
                                   const char *root_hex)
{
    uint8_t root[32], checked[32], *bytes = NULL;
    size_t len = 0;
    bool loaded = zcl_hex_decode_lower(root_hex, root, 32) &&
        vcs_object_load_raw(workspace, root, &bytes, &len) == 0;
    if (loaded) sha3_256(bytes, len, checked);
    free(bytes);
    return loaded && memcmp(root, checked, 32) == 0;
}

bool bfw_toolchain_current(const struct db_build_job *job)
{
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t root[32]; char root_hex[65];
    if (!vcs_toolchain_capsule_v1_capture_gcc(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, root))
        return false;
    zcl_hex_encode(root, 32, root_hex);
    return strcmp(root_hex, job->toolchain_sha3) == 0;
}

bool bfw_binding_current(
    struct node_db *ndb, const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, const char *lease_id)
{
    struct db_build_job job;
    struct db_build_action action;
    char action_id[65], job_id[65];
    return db_build_action_find(ndb, expected_action->action_id, &action) &&
        db_build_job_find(ndb, expected_job->job_id, &job) &&
        strcmp(action.state, "VERIFYING") == 0 &&
        strcmp(action.lease_id, lease_id) == 0 &&
        build_fabric_action_id(&job, &action, action_id).ok &&
        strcmp(action_id, expected_action->action_id) == 0 &&
        build_fabric_job_id(&job, action_id, job_id).ok &&
        strcmp(job_id, expected_job->job_id) == 0 &&
        strcmp(action.task_root_sha3,
               expected_action->task_root_sha3) == 0 &&
        strcmp(action.candidate_root_sha3,
               expected_action->candidate_root_sha3) == 0 &&
        strcmp(action.proof_policy_root_sha3,
               expected_action->proof_policy_root_sha3) == 0 &&
           strcmp(action.context_root_sha3,
               expected_action->context_root_sha3) == 0;
}

struct zcl_result bfw_load_zcode_context(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, int64_t now,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy, bool *present)
{
    *present = false;
    if (!action->task_root_sha3[0]) return ZCL_OK;
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    if (!zcl_hex_decode_lower(action->task_root_sha3, task_root, 32) ||
        !zcl_hex_decode_lower(action->candidate_root_sha3,
                              candidate_root, 32) ||
        !zcl_hex_decode_lower(action->proof_policy_root_sha3,
                              policy_root, 32))
        return ZCL_ERR(-1, "zcode-context-roots-invalid");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(workspace, task_root, &wire, &wire_len) != 0 ||
        vcs_zcode_task_parse(wire, wire_len, task) != VCS_ZCODE_DEV_OK) {
        free(wire);
        return ZCL_ERR(-1, "zcode-task-cas-miss-or-corrupt");
    }
    free(wire); wire = NULL; wire_len = 0;
    uint8_t checked[32];
    if (vcs_zcode_task_root(task, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(checked, task_root, 32) != 0 ||
        vcs_zcode_task_validate_at(task, now) != VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "zcode-task-stale-or-expired");
    if (vcs_object_load_raw(workspace, candidate_root, &wire, &wire_len) != 0 ||
        vcs_zcode_candidate_parse(wire, wire_len, candidate) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return ZCL_ERR(-1, "zcode-candidate-cas-miss-or-corrupt");
    }
    free(wire); wire = NULL; wire_len = 0;
    if (vcs_zcode_candidate_root(candidate, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(checked, candidate_root, 32) != 0 ||
        vcs_zcode_candidate_validate_for_task(task, candidate, now) !=
            VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "zcode-candidate-stale");
    enum vcs_zcode_patch_result patch_verified = vcs_zcode_patch_verify_cas(
        workspace, task, candidate);
    if (patch_verified != VCS_ZCODE_PATCH_OK)
        return ZCL_ERR(-1, "zcode-patch-refused: %s",
                       vcs_zcode_patch_result_string(patch_verified));
    if (vcs_object_load_raw(workspace, policy_root, &wire, &wire_len) != 0 ||
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return ZCL_ERR(-1, "zcode-proof-policy-cas-miss-or-corrupt");
    }
    free(wire);
    if (vcs_zcode_proof_policy_root(policy, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(checked, policy_root, 32) != 0 ||
        memcmp(task->proof_policy_root, policy_root, 32) != 0)
        return ZCL_ERR(-1, "zcode-proof-policy-stale");
    char root_hex[65];
    zcl_hex_encode(task->toolchain_capsule_root, 32, root_hex);
    if (strcmp(root_hex, job->toolchain_sha3) != 0) {
        return ZCL_ERR(-1, "zcode-toolchain-stale");
    }
    zcl_hex_encode(candidate->candidate_source_root, 32, root_hex);
    if (strcmp(root_hex, job->source_cas_sha3) != 0)
        return ZCL_ERR(-1, "zcode-candidate-source-stale");
    *present = true;
    return ZCL_OK;
}

#endif /* !_WIN32 */
