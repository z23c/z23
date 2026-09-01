/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Publish fixed-action outputs and canonical signed work receipts. */

#include "services/build_fabric_worker_evidence.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_work_output.h"

#include <string.h>

struct zcl_result build_fabric_worker_canonical_receipt(
    const char *workspace, const struct db_build_action *action,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t output_root[32], int64_t started, int64_t finished,
    const uint8_t evidence_root[32],
    uint8_t work_kind, uint8_t status, int exit_status,
    const char *confinement,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    char out_hex[65])
{
    uint8_t confinement_root[32];
    sha3_256((const uint8_t *)confinement, strlen(confinement),
             confinement_root);
    if (!vcs_object_put_addressed(workspace, confinement_root,
                                  (const uint8_t *)confinement,
                                  strlen(confinement)))
        return ZCL_ERR(-1, "confinement-evidence-cas-store-failed");
    struct vcs_zcode_work_receipt_v1 receipt = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .work_kind = work_kind,
        .status = status,
        .exit_status = (uint32_t)exit_status,
        .started_unix = started,
        .finished_unix = finished,
    };
    if (!zcl_hex_decode_lower(action->task_root_sha3, receipt.task_root, 32) ||
        !zcl_hex_decode_lower(action->candidate_root_sha3,
                              receipt.candidate_root, 32) ||
        !zcl_hex_decode_lower(action->action_id, receipt.action_root, 32) ||
        !zcl_hex_decode_lower(action->input_root_sha3, receipt.input_root, 32) ||
        !zcl_hex_decode_lower(action->proof_policy_root_sha3,
                              receipt.proof_policy_root, 32) ||
        !zcl_hex_decode_lower(action->lease_id, receipt.lease_id, 32))
        return ZCL_ERR(-1, "canonical-receipt-roots-invalid");
    memcpy(receipt.output_root, output_root, 32);
    memcpy(receipt.toolchain_capsule_root, task->toolchain_capsule_root, 32);
    memcpy(receipt.evidence_root, evidence_root, 32);
    memcpy(receipt.confinement_root, confinement_root, 32);
    if (vcs_zcode_work_receipt_seal(&receipt, signer_secret, signer_pubkey) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_validate_for_candidate(
            task, candidate, &receipt, finished) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_verify(&receipt, signer_pubkey) !=
            VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "canonical-work-receipt-refused");
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES], root[32];
    if (vcs_zcode_work_receipt_serialize(&receipt, wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(&receipt, root) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(workspace, root, wire, sizeof(wire)))
        return ZCL_ERR(-1, "canonical-work-receipt-cas-store-failed");
    zcl_hex_encode(root, 32, out_hex);
    return ZCL_OK;
}

struct zcl_result build_fabric_worker_store_observation(
    const char *workspace,
    const struct vcs_build_execution_observation_v1 *observation,
    uint8_t observation_root[32])
{
    uint8_t wire[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES];
    if (!workspace || !observation || !observation_root ||
        !vcs_build_execution_observation_v1_root(
            observation, observation_root) ||
        !vcs_build_execution_observation_v1_serialize(observation, wire) ||
        !vcs_object_put_addressed(workspace, observation_root, wire,
                                  sizeof(wire)))
        return ZCL_ERR(-1, "physical-observation-cas-store-failed");
    return ZCL_OK;
}

struct zcl_result build_fabric_worker_store_artifact(
    const char *workspace, const char *action_id, const uint8_t *bytes,
    size_t len, uint8_t manifest_root[32])
{
    struct vcs_build_artifact_manifest_v1 manifest = {0};
    if (!zcl_hex_decode_lower(action_id, manifest.action_sha3, 32))
        return ZCL_ERR(-1, "action id is not canonical lowercase hex");
    manifest.total_bytes = len;
    manifest.chunk_bytes = VCS_BUILD_ARTIFACT_CHUNK_BYTES;
    manifest.chunk_count = (uint32_t)(
        (len + VCS_BUILD_ARTIFACT_CHUNK_BYTES - 1u) /
        VCS_BUILD_ARTIFACT_CHUNK_BYTES);
    for (uint32_t i = 0; i < manifest.chunk_count; i++) {
        size_t off = (size_t)i * VCS_BUILD_ARTIFACT_CHUNK_BYTES;
        size_t take = len - off;
        if (take > VCS_BUILD_ARTIFACT_CHUNK_BYTES)
            take = VCS_BUILD_ARTIFACT_CHUNK_BYTES;
        sha3_256(bytes + off, take, manifest.chunk_sha3[i]);
        if (!vcs_object_put_addressed(workspace, manifest.chunk_sha3[i],
                                      bytes + off, take))
            return ZCL_ERR(-1, "cannot persist build artifact chunk %u", i);
    }
    uint8_t wire[VCS_BUILD_ARTIFACT_WIRE_MAX];
    size_t wire_len = 0;
    if (!vcs_build_artifact_manifest_v1_root(&manifest, manifest_root) ||
        !vcs_build_artifact_manifest_v1_serialize(
            &manifest, wire, sizeof(wire), &wire_len) ||
        !vcs_object_put_addressed(workspace, manifest_root, wire, wire_len))
        return ZCL_ERR(-1, "cannot persist build artifact manifest");
    return ZCL_OK;
}

struct zcl_result build_fabric_worker_store_transferable_output(
    const char *workspace, const char *action_id, bool zcode_context,
    const uint8_t *bytes, size_t len, uint8_t output_root[32])
{
    struct vcs_package_store *store = zcode_context
        ? vcs_package_store_global() : NULL;
    if (!store)
        return build_fabric_worker_store_artifact(
            workspace, action_id, bytes, len, output_root);
    uint8_t action_root[32];
    if (!zcl_hex_decode_lower(action_id, action_root, 32))
        return ZCL_ERR(-1, "action-bound-output-package-failed: action-shape");
    enum vcs_zcode_work_output_result result = vcs_zcode_work_output_put(
        store, action_root, bytes, len, output_root);
    if (result != VCS_ZCODE_WORK_OUTPUT_OK)
        return ZCL_ERR(-1, "action-bound-output-package-failed: %s",
                       vcs_zcode_work_output_result_string(result));
    return ZCL_OK;
}
