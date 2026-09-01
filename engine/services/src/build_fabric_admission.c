/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-closed build receipt admission and clean-shadow comparison. */

#include "services/build_fabric_service.h"

#include "build_fabric_observation_internal.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "vcs/build_action.h"
#include "vcs/build_execution_observation.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool bfa_lower_hex_id(const char *value)
{
    uint8_t decoded[32];
    return value && zcl_hex_decode_lower(value, decoded, sizeof(decoded));
}

struct zcl_result build_fabric_receipt_quarantine(
    struct node_db *ndb, const struct db_build_receipt *receipt, int64_t now)
{
    if (!ndb || !ndb->open || !receipt ||
        strcmp(receipt->trust_state, "REMOTE_OBSERVED") != 0)
        return ZCL_ERR(-1, "worker result requires a quarantined observation");
    struct db_build_worker worker;
    struct db_build_action action;
    if (!db_build_worker_find(ndb, receipt->worker_id, &worker) ||
        !worker.approved || worker.revoked ||
        (worker.expires_at != 0 && now >= worker.expires_at) ||
        !db_build_action_find(ndb, receipt->action_id, &action) ||
        strcmp(action.state, "VERIFYING") != 0 ||
        strcmp(action.job_id, receipt->job_id) != 0 ||
        strcmp(action.action_id, receipt->action_sha3) != 0 ||
        strcmp(action.worker_id, receipt->worker_id) != 0 ||
        strcmp(action.lease_id, receipt->lease_id) != 0 ||
        action.lease_expires_at == 0 || now >= action.lease_expires_at)
        return ZCL_ERR(-1, "quarantined receipt authority is stale");
    if (strcmp(action.kind, VCS_BUILD_ACTION_KIND_V1) == 0 &&
        !bfa_lower_hex_id(receipt->observation_sha3))
        return ZCL_ERR(-1, "compile result lacks a physical observation");
    if (strcmp(action.kind, VCS_BUILD_ACTION_KIND_V1) != 0 &&
        receipt->observation_sha3[0])
        return ZCL_ERR(-1, "legacy action has an unexpected observation");
    char expected_id[65];
    uint8_t id[32], sig[64], pubkey[32];
    if (!build_fabric_receipt_id(receipt, expected_id).ok ||
        strcmp(expected_id, receipt->receipt_id) != 0 ||
        !zcl_hex_decode_lower(receipt->receipt_id, id, sizeof(id)) ||
        !zcl_hex_decode_lower(receipt->signature, sig, sizeof(sig)) ||
        !zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)) ||
        !ed25519_verify(sig, id, sizeof(id), pubkey))
        return ZCL_ERR(-1, "quarantined receipt signature is invalid");
    struct db_build_receipt prior;
    if (db_build_receipt_find(ndb, receipt->receipt_id, &prior))
        return strcmp(prior.observation_sha3, receipt->observation_sha3) == 0
            ? ZCL_OK
            : ZCL_ERR(-1, "receipt id collides with another observation");
    if (!db_build_receipt_save(ndb, receipt))
        return ZCL_ERR(-1, "quarantined receipt could not be persisted");
    return ZCL_OK;
}

struct zcl_result build_fabric_observation_verify(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action,
    const struct db_build_receipt *receipt)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    struct vcs_build_execution_observation_v1 observation;
    if (!workspace || !job || !action || !receipt ||
        !zcl_hex_decode_lower(
            receipt->observation_sha3, root, sizeof(root)) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
        return ZCL_ERR(-1, "physical observation is absent from CAS");
    bool parsed = vcs_build_execution_observation_v1_parse(
        wire, wire_len, &observation);
    free(wire);
    if (!parsed || !vcs_build_execution_observation_v1_root(
                       &observation, checked) ||
        memcmp(root, checked, sizeof(root)) != 0)
        return ZCL_ERR(-1, "physical observation is malformed or poisoned");
    uint8_t action_root[32], input_root[32], artifact_root[32];
    uint8_t toolchain_root[32], flags_root[32], environment_root[32];
    if (!zcl_hex_decode_lower(action->action_id, action_root, 32) ||
        !zcl_hex_decode_lower(action->input_root_sha3, input_root, 32) ||
        !zcl_hex_decode_lower(receipt->output_sha3, artifact_root, 32) ||
        !zcl_hex_decode_lower(job->toolchain_sha3, toolchain_root, 32) ||
        !zcl_hex_decode_lower(action->flags_sha3, flags_root, 32) ||
        !zcl_hex_decode_lower(action->environment_sha3,
                              environment_root, 32) ||
        memcmp(observation.action_root, action_root, 32) != 0 ||
        memcmp(observation.action_input_root, input_root, 32) != 0 ||
        memcmp(observation.artifact_root, artifact_root, 32) != 0 ||
        memcmp(observation.toolchain_root, toolchain_root, 32) != 0 ||
        memcmp(observation.flags_root, flags_root, 32) != 0 ||
        memcmp(observation.environment_root, environment_root, 32) != 0 ||
        observation.exit_status != receipt->exit_status)
        return ZCL_ERR(-1, "physical observation does not bind the action");
    return ZCL_OK;
}

struct zcl_result build_fabric_receipt_admit(
    struct node_db *ndb, const char *workspace, const char *receipt_id,
    int64_t now)
{
    struct db_build_receipt receipt;
    struct db_build_action action;
    struct db_build_job job;
    if (!ndb || !ndb->open || !bfa_lower_hex_id(receipt_id) ||
        !db_build_receipt_find(ndb, receipt_id, &receipt) ||
        strcmp(receipt.trust_state, "REMOTE_OBSERVED") != 0 ||
        !db_build_action_find(ndb, receipt.action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job))
        return ZCL_ERR(-1, "quarantined receipt is absent or not admissible");
    if (strcmp(action.kind, VCS_BUILD_ACTION_KIND_V1) == 0)
        ZCL_CHECK(build_fabric_observation_verify(
            workspace, &job, &action, &receipt));
    (void)snprintf(receipt.trust_state, sizeof(receipt.trust_state),
                   "LOCAL_ACCEPTED");
    return build_fabric_receipt_accept(ndb, &receipt, now);
}

static struct zcl_result bfa_observation_load(
    const char *workspace, const char *root_hex,
    struct vcs_build_execution_observation_v1 *out)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    if (!workspace || !out || !zcl_hex_decode_lower(root_hex, root, 32) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
        return ZCL_ERR(-1, "physical observation is absent from CAS");
    bool ok = vcs_build_execution_observation_v1_parse(
                  wire, wire_len, out) &&
              vcs_build_execution_observation_v1_root(out, checked) &&
              memcmp(root, checked, 32) == 0;
    free(wire);
    return ok ? ZCL_OK
              : ZCL_ERR(-1, "physical observation is malformed or poisoned");
}

static bool bfa_preserved_receipt_signature_valid(
    struct node_db *ndb, const char *workspace,
    const struct db_build_receipt *receipt)
{
    struct db_build_worker worker;
    char expected[65];
    uint8_t id[32], signature[64], pubkey[32];
    if (!ndb || !workspace || !receipt ||
        !db_build_worker_find(ndb, receipt->worker_id, &worker) ||
        !zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)))
        return false;
    if (strcmp(receipt->receipt_id, receipt->work_receipt_sha3) == 0) {
        uint8_t root[32], checked[32], *wire = NULL;
        size_t wire_len = 0;
        struct vcs_zcode_work_receipt_v1 work;
        bool valid = zcl_hex_decode_lower(receipt->receipt_id, root, 32) &&
            vcs_object_load_raw(workspace, root, &wire, &wire_len) == 0 &&
            vcs_zcode_work_receipt_parse(wire, wire_len, &work) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_id(&work, checked) == VCS_ZCODE_DEV_OK &&
            memcmp(root, checked, 32) == 0 &&
            vcs_zcode_work_receipt_verify(&work, pubkey) == VCS_ZCODE_DEV_OK;
        free(wire);
        return valid;
    }
    return
        build_fabric_receipt_id(receipt, expected).ok &&
        strcmp(expected, receipt->receipt_id) == 0 &&
        zcl_hex_decode_lower(receipt->receipt_id, id, sizeof(id)) &&
        zcl_hex_decode_lower(receipt->signature, signature,
                             sizeof(signature)) &&
        ed25519_verify(signature, id, sizeof(id), pubkey);
}

struct zcl_result build_fabric_clean_shadow_compare(
    struct node_db *ndb, const char *workspace,
    const char *primary_receipt_id, const char *shadow_receipt_id,
    struct build_fabric_shadow_match *out)
{
    if (out) memset(out, 0, sizeof(*out));
    struct db_build_receipt primary, shadow;
    if (!ndb || !ndb->open || !workspace || !out ||
        !bfa_lower_hex_id(primary_receipt_id) ||
        !bfa_lower_hex_id(shadow_receipt_id) ||
        strcmp(primary_receipt_id, shadow_receipt_id) == 0 ||
        !db_build_receipt_find(ndb, primary_receipt_id, &primary) ||
        !db_build_receipt_find(ndb, shadow_receipt_id, &shadow))
        return ZCL_ERR(-1, "clean shadow requires two preserved receipts");
    if (!bfa_preserved_receipt_signature_valid(ndb, workspace, &primary) ||
        !bfa_preserved_receipt_signature_valid(ndb, workspace, &shadow))
        return ZCL_ERR(-1, "clean shadow receipt signature is invalid");
    out->same_action = strcmp(primary.action_id, shadow.action_id) == 0;
    struct db_build_worker primary_worker, shadow_worker;
    out->distinct_signers =
        db_build_worker_find(ndb, primary.worker_id, &primary_worker) &&
        db_build_worker_find(ndb, shadow.worker_id, &shadow_worker) &&
        strcmp(primary_worker.signer_pubkey,
               shadow_worker.signer_pubkey) != 0;
    if (!out->same_action) {
        (void)snprintf(out->first_bad_invariant,
                       sizeof(out->first_bad_invariant),
                       "action-root-mismatch");
        return ZCL_ERR(-1, "%s", out->first_bad_invariant);
    }
    if (!out->distinct_signers) {
        (void)snprintf(out->first_bad_invariant,
                       sizeof(out->first_bad_invariant),
                       "shadow-signer-not-independent");
        return ZCL_ERR(-1, "%s", out->first_bad_invariant);
    }
    if (strcmp(primary.observation_sha3, shadow.observation_sha3) != 0) {
        (void)snprintf(out->first_bad_invariant,
                       sizeof(out->first_bad_invariant),
                       "physical-observation-root-mismatch");
        return ZCL_ERR(-1, "%s", out->first_bad_invariant);
    }
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, primary.action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job))
        return ZCL_ERR(-1, "clean shadow action authority is absent");
    struct zcl_result bound = build_fabric_observation_verify(
        workspace, &job, &action, &primary);
    if (!bound.ok) return bound;
    bound = build_fabric_observation_verify(
        workspace, &job, &action, &shadow);
    if (!bound.ok) return bound;
    struct vcs_build_execution_observation_v1 a, b;
    struct zcl_result loaded = bfa_observation_load(
        workspace, primary.observation_sha3, &a);
    if (!loaded.ok) return loaded;
    loaded = bfa_observation_load(workspace, shadow.observation_sha3, &b);
    if (!loaded.ok) return loaded;
    out->artifact_match = memcmp(a.artifact_root, b.artifact_root, 32) == 0;
    out->declared_reads_match =
        memcmp(a.declared_reads_root, b.declared_reads_root, 32) == 0;
    out->observed_reads_match =
        memcmp(a.observed_reads_root, b.observed_reads_root, 32) == 0;
    out->declared_writes_match =
        memcmp(a.declared_writes_root, b.declared_writes_root, 32) == 0;
    out->observed_writes_match =
        memcmp(a.observed_writes_root, b.observed_writes_root, 32) == 0;
    zcl_hex_encode(a.artifact_root, 32, out->artifact_root_sha3);
    const char *bad = !out->artifact_match ? "artifact-root-mismatch"
        : !out->declared_reads_match ? "declared-read-set-mismatch"
        : !out->observed_reads_match ? "observed-read-set-mismatch"
        : !out->declared_writes_match ? "declared-write-set-mismatch"
        : !out->observed_writes_match ? "observed-write-set-mismatch"
        : NULL;
    if (bad) {
        (void)snprintf(out->first_bad_invariant,
                       sizeof(out->first_bad_invariant), "%s", bad);
        return ZCL_ERR(-1, "%s", bad);
    }
    return ZCL_OK;
}
