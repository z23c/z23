/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable remote ZBuild evidence observation and trust evaluation. */

#include "services/build_fabric_service.h"

#include "build_fabric_observation_internal.h"

#include "base/hex.h"
#include "config/c23_commons_build_profile.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_build.h"
#include "vcs/package_store.h"
#include "vcs/proof_ticket.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_work_output.h"
#include "vcs/zcode_work_swarm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void bf_worker_id_from_pubkey(const uint8_t pubkey[32],
                                     char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool bf_remote_inputs_incomplete(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result, const char *receipt_id,
    int64_t now)
{
    return !ndb || !ndb->open || !workspace || !workspace[0] || !request ||
        !result || !receipt_id || now < 0;
}

static bool bf_remote_result_invalid(
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result, const uint8_t *signer)
{
    return !vcs_zcode_work_request_verify(request) ||
        !vcs_zcode_work_result_verify(request, result, signer);
}

static bool bf_remote_action_missing(
    struct node_db *ndb, const struct vcs_zcode_work_result_v1 *result,
    char action_id[65], struct db_build_action *action)
{
    zcl_hex_encode(result->action_root, 32, action_id);
    return !db_build_action_find(ndb, action_id, action) ||
        strcmp(action->task_root_sha3, "") == 0 ||
        strcmp(action->candidate_root_sha3, "") == 0;
}

static bool bf_remote_work_kind_conflicts(
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result,
    const struct db_build_action *action)
{
    uint8_t expected_kind = vcs_build_action_v1_work_kind(action->kind);
    return expected_kind == 0 || request->work_kind != expected_kind ||
        result->receipt.work_kind != expected_kind;
}

static bool bf_remote_roots_conflict(
    const struct db_build_action *action,
    const struct vcs_zcode_work_result_v1 *result)
{
    uint8_t expected[32];
    return !zcl_hex_decode_lower(action->task_root_sha3, expected, 32) ||
        memcmp(expected, result->task_root, 32) != 0 ||
        !zcl_hex_decode_lower(action->candidate_root_sha3, expected, 32) ||
        memcmp(expected, result->candidate_root, 32) != 0 ||
        !zcl_hex_decode_lower(action->input_root_sha3, expected, 32) ||
        memcmp(expected, result->receipt.input_root, 32) != 0 ||
        !zcl_hex_decode_lower(action->proof_policy_root_sha3, expected, 32) ||
        memcmp(expected, result->receipt.proof_policy_root, 32) != 0;
}

static bool bf_store_remote_receipt(
    const char *workspace, const struct vcs_zcode_work_receipt_v1 *receipt,
    uint8_t work_root[32])
{
    uint8_t work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    return vcs_zcode_work_receipt_serialize(receipt, work_wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(receipt, work_root) == VCS_ZCODE_DEV_OK &&
        vcs_object_store_init(workspace) &&
        vcs_object_put_addressed(workspace, work_root, work_wire,
                                 sizeof(work_wire));
}

static bool bf_remote_prior_matches(const struct db_build_receipt *prior,
                                    const char *action_id,
                                    const char *receipt_id)
{
    return strcmp(prior->action_id, action_id) == 0 &&
        strcmp(prior->work_receipt_sha3, receipt_id) == 0;
}

static bool bf_remote_worker_prepare(struct node_db *ndb,
                                     const uint8_t *signer,
                                     const char *action_kind, int64_t now,
                                     struct db_build_worker *worker,
                                     char worker_id[65])
{
    bf_worker_id_from_pubkey(signer, worker_id);
    if (db_build_worker_find(ndb, worker_id, worker)) {
        char signer_hex[65];
        zcl_hex_encode(signer, 32, signer_hex);
        if (strcmp(worker->signer_pubkey, signer_hex) != 0)
            return false;
        worker->last_seen_at = now;
    } else {
        memset(worker, 0, sizeof(*worker));
        (void)snprintf(worker->worker_id, sizeof(worker->worker_id), "%s",
                       worker_id);
        zcl_hex_encode(signer, 32, worker->signer_pubkey);
        (void)snprintf(worker->capabilities, sizeof(worker->capabilities),
                       "p2p-observed,%s", action_kind);
        worker->last_seen_at = now;
    }
    return true;
}

static bool bf_fill_remote_observation(
    const struct vcs_zcode_work_result_v1 *result,
    const struct db_build_action *action, const char *receipt_id,
    const char *action_id, const char *worker_id,
    struct db_build_receipt *observed)
{
    (void)snprintf(observed->receipt_id, sizeof(observed->receipt_id), "%s",
                   receipt_id);
    (void)snprintf(observed->action_id, sizeof(observed->action_id), "%s",
                   action_id);
    (void)snprintf(observed->job_id, sizeof(observed->job_id), "%s",
                   action->job_id);
    (void)snprintf(observed->worker_id, sizeof(observed->worker_id), "%s",
                   worker_id);
    zcl_hex_encode(result->receipt.lease_id, 32, observed->lease_id);
    (void)snprintf(observed->action_sha3, sizeof(observed->action_sha3),
                   "%s", action_id);
    zcl_hex_encode(result->output_root, 32, observed->output_sha3);
    if (strcmp(action->kind, VCS_BUILD_ACTION_KIND_V1) == 0) {
        if (memcmp(result->receipt.evidence_root,
                   (const uint8_t[32]){0}, 32) == 0)
            return false;
        zcl_hex_encode(result->receipt.evidence_root, 32,
                       observed->observation_sha3);
    }
    (void)snprintf(observed->work_receipt_sha3,
                   sizeof(observed->work_receipt_sha3), "%s", receipt_id);
    zcl_hex_encode(result->receipt.signature, 64, observed->signature);
    (void)snprintf(observed->confinement, sizeof(observed->confinement),
                   "p2p-untrusted;facts-in-work-receipt");
    (void)snprintf(observed->trust_state, sizeof(observed->trust_state),
                   "REMOTE_OBSERVED");
    observed->exit_status = result->receipt.exit_status;
    observed->created_at = result->receipt.finished_unix;
    return true;
}

static bool bf_save_remote_observation(
    struct node_db *ndb, const struct db_build_worker *worker,
    const struct db_build_receipt *observed)
{
    return db_build_worker_save(ndb, worker) &&
        db_build_receipt_save(ndb, observed) && node_db_commit(ndb);
}

struct zcl_result build_fabric_receipt_observe_remote(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result, int64_t now,
    char receipt_id[BUILD_FABRIC_ID_HEX + 1])
{
    if (receipt_id) receipt_id[0] = '\0';
    if (bf_remote_inputs_incomplete(ndb, workspace, request, result,
                                    receipt_id, now))
        return ZCL_ERR(-1, "remote receipt observation requires complete inputs");
    const uint8_t *signer = result->receipt.signer_pubkey;
    if (bf_remote_result_invalid(request, result, signer))
        return ZCL_ERR(-1, "remote result signature or request binding is invalid");
    char action_id[65];
    struct db_build_action action;
    if (bf_remote_action_missing(ndb, result, action_id, &action))
        return ZCL_ERR(-1, "remote result has no matching local ZBuild action");
    if (bf_remote_work_kind_conflicts(request, result, &action))
        return ZCL_ERR(-1, "remote receipt work kind conflicts with the fixed action");
    if (bf_remote_roots_conflict(&action, result))
        return ZCL_ERR(-1, "remote receipt conflicts with the local action");
    uint8_t work_root[32];
    if (!bf_store_remote_receipt(workspace, &result->receipt, work_root))
        return ZCL_ERR(-1, "remote canonical receipt could not enter CAS");
    zcl_hex_encode(work_root, 32, receipt_id);
    struct db_build_receipt prior;
    if (db_build_receipt_find(ndb, receipt_id, &prior)) {
        if (bf_remote_prior_matches(&prior, action_id, receipt_id))
            return ZCL_OK;
        return ZCL_ERR(-1, "remote receipt id collides with different evidence");
    }
    struct db_build_worker worker;
    char worker_id[65];
    if (!bf_remote_worker_prepare(ndb, signer, action.kind, now, &worker,
                                  worker_id))
        return ZCL_ERR(-1, "remote signer collides with a worker identity");
    struct db_build_receipt observed = {0};
    if (!bf_fill_remote_observation(result, &action, receipt_id, action_id,
                                    worker_id, &observed))
        return ZCL_ERR(-1,
                       "remote compile receipt lacks an observation root");
    if (!node_db_begin(ndb))
        return ZCL_ERR(-1, "cannot begin remote receipt observation");
    bool ok = bf_save_remote_observation(ndb, &worker, &observed);
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "remote receipt save and rollback failed");
        return ZCL_ERR(-1, "remote receipt observation could not persist");
    }
    return ZCL_OK;
}

struct bf_verified_receipt {
    struct db_build_receipt row;
    struct vcs_zcode_work_receipt_v1 receipt;
    uint8_t root[32];
    /* The verified result identity used for matching. Package actions use
     * the canonical package-build receipt id inside their action-bound
     * artifact manifest; other action kinds use the receipt output root. */
    uint8_t evidence_output[32];
    uint8_t work_kind;
    bool approved;
    bool local;
    bool shadow_checked;
    bool clean_shadow;
    bool review_approved;
    bool package_test_passed;
};

static int bf_root_compare(const void *left, const void *right)
{
    return memcmp(left, right, 32);
}

static bool bf_load_dev_object(const char *workspace, const char *root_hex,
                               uint8_t **wire, size_t *wire_len,
                               uint8_t root[32])
{
    return zcl_hex_decode_lower(root_hex, root, 32) &&
           vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

static struct zcl_result bf_receipt_load(const char *workspace,
    const char *root_hex, struct vcs_zcode_work_receipt_v1 *receipt,
    uint8_t root[32])
{
    uint8_t checked[32], *wire = NULL;
    size_t length = 0;
    if (!bf_load_dev_object(workspace, root_hex, &wire, &length, root))
        return ZCL_ERR(-1, "proof receipt CAS object is unavailable");
    bool intact = vcs_zcode_work_receipt_parse(wire, length, receipt) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(receipt, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    if (!intact)
        return ZCL_ERR(-1, "proof receipt CAS object is corrupt");
    return ZCL_OK;
}

static bool bf_receipt_trusted(const struct bf_verified_receipt *receipt)
{
    return receipt && (receipt->local || receipt->approved);
}

/* Inspect all eligible observations before selecting successes. A majority or
 * a local success cannot erase a contradictory observation for identical
 * inputs. Other actions and untrusted signers do not veto this action. */
static bool bf_observations_conflict(
    const struct bf_verified_receipt *valid, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!bf_receipt_trusted(&valid[i])) continue;
        for (size_t j = i + 1; j < count; j++) {
            if (!bf_receipt_trusted(&valid[j]) ||
                valid[i].work_kind != valid[j].work_kind ||
                memcmp(valid[i].receipt.action_root,
                       valid[j].receipt.action_root, 32) != 0 ||
                memcmp(valid[i].receipt.input_root,
                       valid[j].receipt.input_root, 32) != 0)
                continue;
            if (valid[i].receipt.status != valid[j].receipt.status ||
                (valid[i].receipt.status == VCS_ZCODE_WORK_PASS &&
                 valid[i].work_kind == VCS_ZCODE_WORK_BUILD &&
                 memcmp(valid[i].evidence_output,
                        valid[j].evidence_output, 32) != 0))
                return true;
        }
    }
    return false;
}

static size_t bf_successful_observations(
    struct bf_verified_receipt *valid, size_t count)
{
    size_t passes = 0;
    for (size_t i = 0; i < count; i++)
        if (valid[i].receipt.status == VCS_ZCODE_WORK_PASS)
            valid[passes++] = valid[i];
    return passes;
}

static bool bf_receipt_current(
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const struct db_build_receipt *row,
    const struct vcs_zcode_proof_policy_v1 *policy, int64_t now)
{
    return (receipt->status == VCS_ZCODE_WORK_PASS ||
            receipt->status == VCS_ZCODE_WORK_FAIL) &&
        receipt->exit_status == row->exit_status &&
        receipt->finished_unix <= now &&
        (policy->maximum_proof_age_seconds == 0 ||
         now - receipt->finished_unix <=
             (int64_t)policy->maximum_proof_age_seconds);
}

static bool bf_package_result_matches(
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const struct vcs_package_build_receipt *package)
{
    bool passed = vcs_package_build_installable(package);
    if (receipt->status == VCS_ZCODE_WORK_PASS) return passed;
    return receipt->status == VCS_ZCODE_WORK_FAIL && !passed &&
        receipt->exit_status == (package->test_exit_code != 0
            ? (int)package->test_exit_code : 1);
}

static bool bf_manifest_binds_receipt(
    const uint8_t *manifest_wire, size_t manifest_len,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    struct vcs_build_artifact_manifest_v1 *manifest)
{
    uint8_t checked[32];
    return vcs_build_artifact_manifest_v1_parse(
            manifest_wire, manifest_len, manifest) &&
        vcs_build_artifact_manifest_v1_root(manifest, checked) &&
        memcmp(checked, receipt->output_root, 32) == 0 &&
        memcmp(manifest->action_sha3, receipt->action_root, 32) == 0 &&
        manifest->total_bytes > 0 &&
        manifest->total_bytes <= VCS_PACKAGE_BUILD_MAX_WIRE_BYTES;
}

static bool bf_package_evidence_wire(
    const char *workspace, const struct vcs_zcode_work_receipt_v1 *receipt,
    uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    uint8_t *manifest_wire = NULL;
    size_t manifest_len = 0;
    if (vcs_object_load_raw_bounded(
            workspace, receipt->output_root, VCS_BUILD_ARTIFACT_WIRE_MAX,
            &manifest_wire, &manifest_len) == 0) {
        struct vcs_build_artifact_manifest_v1 manifest;
        bool manifest_ok = bf_manifest_binds_receipt(
                manifest_wire, manifest_len, receipt, &manifest);
        free(manifest_wire);
        if (!manifest_ok)
            LOG_FAIL("zcode.evidence", "artifact manifest does not bind receipt");
        size_t wire_len = (size_t)manifest.total_bytes;
        uint8_t *wire = zcl_malloc(wire_len, "build_fabric.package_evidence");
        if (!wire)
            LOG_FAIL("zcode.evidence", "artifact evidence allocation failed");
        size_t offset = 0;
        for (uint32_t i = 0; i < manifest.chunk_count; i++) {
            uint8_t *chunk = NULL;
            size_t chunk_len = 0;
            if (vcs_object_load_raw_bounded(
                    workspace, manifest.chunk_sha3[i],
                    VCS_BUILD_ARTIFACT_CHUNK_BYTES, &chunk, &chunk_len) != 0 ||
                !vcs_build_artifact_manifest_v1_verify_chunk(
                    &manifest, i, chunk, chunk_len) ||
                chunk_len > wire_len - offset) {
                free(chunk);
                free(wire);
                LOG_FAIL("zcode.evidence", "artifact chunk verification failed");
            }
            memcpy(wire + offset, chunk, chunk_len);
            offset += chunk_len;
            free(chunk);
        }
        if (offset != wire_len) {
            free(wire);
            LOG_FAIL("zcode.evidence", "artifact evidence length mismatch");
        }
        *out = wire;
        *out_len = wire_len;
        return true;
    }
    struct vcs_package_store *store = vcs_package_store_global();
    enum vcs_zcode_work_output_result loaded = store
        ? vcs_zcode_work_output_get(
              store, receipt->output_root, receipt->action_root, out, out_len)
        : VCS_ZCODE_WORK_OUTPUT_ABSENT;
    if (loaded != VCS_ZCODE_WORK_OUTPUT_OK ||
        *out_len > VCS_PACKAGE_BUILD_MAX_WIRE_BYTES) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        LOG_FAIL("zcode.evidence", "work output evidence is unavailable");
    }
    return true;
}

static struct zcl_result bf_package_evidence_check(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    bool *eligible, bool *test_passed, uint8_t evidence_output[32])
{
    *eligible = false;
    *test_passed = false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!bf_package_evidence_wire(workspace, receipt, &wire, &wire_len))
        return ZCL_ERR(-1, "proof package evidence is unavailable");
    struct vcs_package_build_receipt package;
    bool standard = policy->minimum_compile_receipts >= 2u ||
                    policy->minimum_test_receipts >= 2u;
    const char *expected_flags = standard
        ? ZCL_C23_COMMONS_BUILD_FLAGS_STANDARD_V2
        : ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2;
    bool ok = vcs_package_build_parse(wire, wire_len, &package) ==
            VCS_PACKAGE_BUILD_OK &&
        memcmp(package.package_root, candidate->candidate_source_root, 32) == 0 &&
        memcmp(package.recipe_root, task->acceptance_tests_root, 32) == 0 &&
        memcmp(package.lock_root, task->dependency_lock_root, 32) == 0 &&
        strcmp(package.flags, expected_flags) == 0 &&
        package.isolation == VCS_PACKAGE_BUILD_ISOLATION_FULL &&
        bf_package_result_matches(receipt, &package) &&
        vcs_package_build_id(&package, evidence_output) ==
            VCS_PACKAGE_BUILD_OK;
    free(wire);
    if (ok)
        *test_passed = package.result_class ==
                VCS_PACKAGE_BUILD_RESULT_TEST_PASS &&
            package.test_ran && package.test_exit_code == 0;
    *eligible = ok;
    return ZCL_OK;
}

static struct zcl_result bf_package_evidence_verify(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const char *action_kind, bool *eligible, bool *test_passed,
    uint8_t evidence_output[32])
{
    if (!*eligible || strcmp(action_kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) != 0)
        return ZCL_OK;
    return bf_package_evidence_check(workspace, task, candidate, policy,
        receipt, eligible, test_passed, evidence_output);
}

static bool bf_trusted_evidence_has_root(
    const struct bf_verified_receipt *valid, size_t valid_count,
    const uint8_t root[32])
{
    for (size_t i = 0; i < valid_count; i++)
        if (valid[i].work_kind != VCS_ZCODE_WORK_REVIEW &&
            bf_receipt_trusted(&valid[i]) &&
            memcmp(valid[i].root, root, 32) == 0)
            return true;
    return false;
}

static bool bf_review_approves_evidence(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct bf_verified_receipt *valid, size_t valid_count,
    size_t review_index, int64_t now)
{
    const struct bf_verified_receipt *entry = &valid[review_index];
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(workspace, entry->receipt.output_root,
                            &wire, &wire_len) != 0)
        return false;
    struct vcs_zcode_review_v1 review;
    bool ok = vcs_zcode_review_parse(wire, wire_len, &review) ==
                  VCS_ZCODE_DEV_OK &&
        vcs_zcode_review_validate_for_candidate(
            task, candidate, &review, now) == VCS_ZCODE_DEV_OK &&
        review.verdict == VCS_ZCODE_REVIEW_APPROVE &&
        memcmp(review.reviewer_pubkey, entry->receipt.signer_pubkey, 32) == 0;
    free(wire);
    if (!ok) return false;
    uint8_t proof_roots[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t proof_count = 0;
    wire = NULL; wire_len = 0;
    if (vcs_object_load_raw(workspace, review.proof_set_root,
                            &wire, &wire_len) != 0 ||
        vcs_zcode_proof_set_parse(
            wire, wire_len, proof_roots,
            VCS_ZCODE_PROOF_SET_MAX_RECEIPTS, &proof_count) !=
                VCS_ZCODE_DEV_OK) {
        free(wire);
        return false;
    }
    free(wire);
    for (size_t i = 0; i < proof_count; i++)
        if (!bf_trusted_evidence_has_root(
                valid, valid_count, proof_roots[i]))
            return false;
    return true;
}

static bool bf_has_local_match(
    const struct bf_verified_receipt *valid, size_t valid_count,
    size_t remote_index);

static bool bf_signer_listed(uint8_t signers[][32], size_t count,
                             const uint8_t pubkey[32])
{
    bool listed = false;
    for (size_t j = 0; j < count; j++)
        if (memcmp(signers[j], pubkey, 32) == 0)
            listed = true;
    return listed;
}

static size_t bf_count_kind(
    const struct bf_verified_receipt *valid, size_t valid_count,
    uint8_t work_kind, const uint8_t *required_output, bool independent)
{
    uint8_t signers[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t count = 0;
    for (size_t i = 0; i < valid_count; i++) {
        if (work_kind == VCS_ZCODE_WORK_BUILD &&
            valid[i].shadow_checked && !valid[i].clean_shadow)
            continue;
        bool trusted = bf_receipt_trusted(&valid[i]) ||
                       bf_has_local_match(valid, valid_count, i);
        if (valid[i].work_kind != work_kind ||
            !trusted ||
            (work_kind == VCS_ZCODE_WORK_REVIEW &&
             !valid[i].review_approved) ||
            (required_output && memcmp(valid[i].evidence_output,
                                       required_output, 32) != 0))
            continue;
        bool duplicate = independent &&
            bf_signer_listed(signers, count, valid[i].receipt.signer_pubkey);
        if (!duplicate) {
            memcpy(signers[count], valid[i].receipt.signer_pubkey, 32);
            count++;
        }
    }
    return count;
}

static size_t bf_count_approved_kind(
    const struct bf_verified_receipt *valid, size_t valid_count,
    uint8_t work_kind, const uint8_t *required_output, bool independent)
{
    uint8_t signers[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t count = 0;
    for (size_t i = 0; i < valid_count; i++) {
        if (work_kind == VCS_ZCODE_WORK_BUILD &&
            valid[i].shadow_checked && !valid[i].clean_shadow)
            continue;
        if (valid[i].work_kind != work_kind || !valid[i].approved ||
            (required_output && memcmp(valid[i].evidence_output,
                                       required_output, 32) != 0))
            continue;
        bool duplicate = false;
        if (independent)
            for (size_t j = 0; j < count; j++)
                if (memcmp(signers[j], valid[i].receipt.signer_pubkey,
                           32) == 0)
                    duplicate = true;
        if (!duplicate) {
            memcpy(signers[count], valid[i].receipt.signer_pubkey, 32);
            count++;
        }
    }
    return count;
}

static size_t bf_count_tests(const struct bf_verified_receipt *valid,
                             size_t valid_count, bool independent)
{
    uint8_t signers[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t count = 0;
    for (size_t i = 0; i < valid_count; i++) {
        bool is_test = valid[i].work_kind == VCS_ZCODE_WORK_TEST ||
                       valid[i].package_test_passed;
        bool trusted = bf_receipt_trusted(&valid[i]) ||
                       bf_has_local_match(valid, valid_count, i);
        if (!is_test || !trusted) continue;
        bool duplicate = false;
        if (independent)
            for (size_t j = 0; j < count; j++)
                if (memcmp(signers[j], valid[i].receipt.signer_pubkey,
                           32) == 0)
                    duplicate = true;
        if (!duplicate) {
            memcpy(signers[count], valid[i].receipt.signer_pubkey, 32);
            count++;
        }
    }
    return count;
}

static bool bf_has_local_match(
    const struct bf_verified_receipt *valid, size_t valid_count,
    size_t remote_index)
{
    if (valid[remote_index].work_kind == VCS_ZCODE_WORK_BUILD)
        return valid[remote_index].shadow_checked &&
               valid[remote_index].clean_shadow;
    for (size_t i = 0; i < valid_count; i++)
        if (valid[i].local &&
            valid[i].work_kind == valid[remote_index].work_kind &&
            memcmp(valid[i].evidence_output,
                   valid[remote_index].evidence_output, 32) == 0)
            return true;
    return false;
}

static struct zcl_result bf_candidate_receipts_read(struct node_db *ndb,
    const struct db_build_action *action, struct db_build_receipt *rows,
    int *count)
{
    *count = db_build_candidate_receipts(
        ndb, action->task_root_sha3, action->candidate_root_sha3,
        action->proof_policy_root_sha3, rows,
        VCS_ZCODE_PROOF_SET_MAX_RECEIPTS + 1u);
    if (*count < 0)
        return ZCL_ERR(-1, "proof receipt query could not be read completely");
    if (*count > (int)VCS_ZCODE_PROOF_SET_MAX_RECEIPTS)
        return ZCL_ERR(-1, "proof receipt set exceeds the bounded maximum");
    return ZCL_OK;
}

static struct zcl_result bf_observation_authority(struct node_db *ndb,
    const struct db_build_receipt *row,
    const struct vcs_zcode_work_receipt_v1 *receipt, int64_t now,
    bool *bound, bool *approved, bool *local)
{
    struct db_build_worker worker;
    char signer[65];
    zcl_hex_encode(receipt->signer_pubkey, 32, signer);
    if (!db_build_worker_find(ndb, row->worker_id, &worker))
        return ZCL_ERR(-1, "proof receipt worker is unavailable");
    *bound = strcmp(worker.signer_pubkey, signer) == 0;
    bool current = !worker.revoked &&
        (worker.expires_at == 0 || now < worker.expires_at);
    *approved = worker.approved && current;
    *local = current && strcmp(row->trust_state, "LOCAL_ACCEPTED") == 0;
    return ZCL_OK;
}

static struct zcl_result bf_compile_observation(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const struct db_build_receipt *row,
    const struct vcs_zcode_work_receipt_v1 *receipt, bool compile_action,
    bool *verified)
{
    if (!*verified || !compile_action) return ZCL_OK;
    uint8_t output[32], observation[32];
    *verified = zcl_hex_decode_lower(row->output_sha3, output, 32) &&
        zcl_hex_decode_lower(row->observation_sha3, observation, 32) &&
        memcmp(output, receipt->output_root, 32) == 0 &&
        memcmp(observation, receipt->evidence_root, 32) == 0;
    if (!*verified) return ZCL_OK;
    return build_fabric_observation_verify(workspace, job, action, row);
}

struct bf_eval_ctx {
    struct node_db *ndb;
    const char *workspace;
    const struct db_build_action *action;
    const struct vcs_zcode_task_v1 *task;
    const struct vcs_zcode_candidate_v1 *candidate;
    const struct vcs_zcode_proof_policy_v1 *policy;
    int64_t now;
    int64_t validation_now;
};

/* Selection consults the shadow/review flags after the durable fields are
 * populated. The snapshot starts zeroed so a receipt that has not gone
 * through either classifier cannot inherit indeterminate stack bits and
 * masquerade as a failed shadow or an approved review. */
struct bf_snapshot {
    struct bf_verified_receipt valid[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS];
    size_t count;
    bool have_selected;
    uint8_t selected_output[32];
};

static bool bf_eval_args_valid(struct node_db *ndb, const char *workspace,
    const char *action_id, const struct build_fabric_proof_evaluation *out,
    int64_t now)
{
    return ndb && ndb->open && workspace && workspace[0] && action_id &&
           out && now >= 0;
}

static struct zcl_result bf_eval_action_find(struct node_db *ndb,
    const char *action_id, struct db_build_action *action)
{
    if (!db_build_action_find(ndb, action_id, action) ||
        !action->task_root_sha3[0] || !action->candidate_root_sha3[0] ||
        !action->proof_policy_root_sha3[0])
        return ZCL_ERR(-1, "canonical ZCODE action not found");
    return ZCL_OK;
}

static struct zcl_result bf_load_task(const char *workspace,
    const char *root_hex, struct vcs_zcode_task_v1 *task)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32], checked_root[32];
    if (!bf_load_dev_object(workspace, root_hex, &wire, &wire_len, root) ||
        vcs_zcode_task_parse(wire, wire_len, task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, checked_root) != VCS_ZCODE_DEV_OK ||
        memcmp(root, checked_root, 32) != 0) {
        free(wire);
        return ZCL_ERR(-1, "task CAS object is absent or corrupt");
    }
    free(wire);
    return ZCL_OK;
}

static struct zcl_result bf_load_candidate(const char *workspace,
    const char *root_hex, struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32], checked_root[32];
    if (!bf_load_dev_object(workspace, root_hex, &wire, &wire_len, root) ||
        vcs_zcode_candidate_parse(wire, wire_len, candidate) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, checked_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(root, checked_root, 32) != 0) {
        free(wire);
        return ZCL_ERR(-1, "candidate CAS object is absent or corrupt");
    }
    free(wire);
    return ZCL_OK;
}

static struct zcl_result bf_load_policy(const char *workspace,
    const char *root_hex, struct vcs_zcode_proof_policy_v1 *policy)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32], checked_root[32];
    if (!bf_load_dev_object(workspace, root_hex, &wire, &wire_len, root) ||
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(policy, checked_root) !=
            VCS_ZCODE_DEV_OK ||
        memcmp(root, checked_root, 32) != 0) {
        free(wire);
        return ZCL_ERR(-1, "proof policy CAS object is absent or corrupt");
    }
    free(wire);
    return ZCL_OK;
}

static struct zcl_result bf_load_proof_inputs(const char *workspace,
    const struct db_build_action *action, struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy)
{
    struct zcl_result step =
        bf_load_task(workspace, action->task_root_sha3, task);
    if (!step.ok) return step;
    step = bf_load_candidate(workspace, action->candidate_root_sha3,
                             candidate);
    if (!step.ok) return step;
    return bf_load_policy(workspace, action->proof_policy_root_sha3, policy);
}

/* Reads the receipt row's own action and reports whether it belongs to the
 * evaluated candidate and names a known work kind. */
static struct zcl_result bf_row_action(const struct bf_eval_ctx *c,
    const struct db_build_receipt *row, struct db_build_action *receipt_action,
    uint8_t *expected_kind, bool *relevant)
{
    *relevant = false;
    if (!row->work_receipt_sha3[0])
        return ZCL_OK;
    if (!db_build_action_find(c->ndb, row->action_id, receipt_action))
        return ZCL_ERR(-1, "proof receipt action is unavailable");
    if (strcmp(receipt_action->task_root_sha3, c->action->task_root_sha3) != 0 ||
        strcmp(receipt_action->candidate_root_sha3,
               c->action->candidate_root_sha3) != 0 ||
        strcmp(receipt_action->proof_policy_root_sha3,
               c->action->proof_policy_root_sha3) != 0)
        return ZCL_OK;
    *expected_kind = vcs_build_action_v1_work_kind(receipt_action->kind);
    *relevant = *expected_kind != 0;
    return ZCL_OK;
}

static bool bf_receipt_verified(const struct bf_eval_ctx *c,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const struct db_build_action *receipt_action,
    const struct db_build_receipt *row, uint8_t expected_kind)
{
    uint8_t action_root[32], input_root[32];
    return vcs_zcode_work_receipt_verify(receipt, receipt->signer_pubkey) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_validate_for_candidate(
            c->task, c->candidate, receipt, c->validation_now) ==
            VCS_ZCODE_DEV_OK &&
        zcl_hex_decode_lower(receipt_action->action_id, action_root, 32) &&
        zcl_hex_decode_lower(receipt_action->input_root_sha3,
                             input_root, 32) &&
        memcmp(receipt->action_root, action_root, 32) == 0 &&
        memcmp(receipt->input_root, input_root, 32) == 0 &&
        receipt->work_kind == expected_kind &&
        bf_receipt_current(receipt, row, c->policy, c->now);
}

/* Verifies one receipt row. On acceptance with room left (slot != NULL) the
 * verified receipt is written to *slot and *accepted is set. */
static struct zcl_result bf_read_row(const struct bf_eval_ctx *c,
    const struct db_build_receipt *row, struct bf_verified_receipt *slot,
    bool *accepted)
{
    *accepted = false;
    struct db_build_action receipt_action;
    uint8_t expected_kind = 0;
    bool relevant = false;
    struct zcl_result found = bf_row_action(
        c, row, &receipt_action, &expected_kind, &relevant);
    if (!found.ok || !relevant) return found;
    struct db_build_job receipt_job;
    bool compile_action = strcmp(
        receipt_action.kind, VCS_BUILD_ACTION_KIND_V1) == 0;
    if (compile_action &&
        !db_build_job_find(c->ndb, receipt_action.job_id, &receipt_job))
        return ZCL_ERR(-1, "proof receipt job is unavailable");
    struct vcs_zcode_work_receipt_v1 receipt;
    uint8_t receipt_root[32];
    struct zcl_result loaded = bf_receipt_load(
        c->workspace, row->work_receipt_sha3, &receipt, receipt_root);
    if (!loaded.ok) return loaded;
    bool verified = bf_receipt_verified(
        c, &receipt, &receipt_action, row, expected_kind);
    if (!verified) return ZCL_OK;
    bool bound = false, approved = false, local = false;
    struct zcl_result authority = bf_observation_authority(
        c->ndb, row, &receipt, c->now, &bound, &approved, &local);
    if (!authority.ok) return authority;
    if (!bound) return ZCL_OK;
    struct zcl_result observation = bf_compile_observation(c->workspace,
        &receipt_job, &receipt_action, row, &receipt, compile_action,
        &verified);
    if (!observation.ok)
        return (approved || local) ? observation : ZCL_OK;
    bool package_test_passed = false;
    uint8_t evidence_output[32];
    memcpy(evidence_output, receipt.output_root, sizeof(evidence_output));
    struct zcl_result package_result = bf_package_evidence_verify(
        c->workspace, c->task, c->candidate, c->policy, &receipt,
        receipt_action.kind, &verified, &package_test_passed,
        evidence_output);
    if (!package_result.ok) return package_result;
    if (!verified || !slot) return ZCL_OK;
    slot->row = *row;
    slot->receipt = receipt;
    memcpy(slot->root, receipt_root, 32);
    memcpy(slot->evidence_output, evidence_output, 32);
    slot->work_kind = expected_kind;
    slot->approved = approved;
    slot->local = local;
    slot->package_test_passed = package_test_passed;
    *accepted = true;
    return ZCL_OK;
}

static struct zcl_result bf_collect_receipts(const struct bf_eval_ctx *c,
    const struct db_build_receipt *rows, int row_count,
    struct bf_snapshot *snap)
{
    for (int i = 0; i < row_count; i++) {
        bool accepted = false;
        struct bf_verified_receipt *slot =
            snap->count < VCS_ZCODE_PROOF_SET_MAX_RECEIPTS
                ? &snap->valid[snap->count] : NULL;
        struct zcl_result row = bf_read_row(c, &rows[i], slot, &accepted);
        if (!row.ok) return row;
        if (accepted) snap->count++;
    }
    return ZCL_OK;
}

static void bf_mark_reviews(const struct bf_eval_ctx *c,
    struct bf_snapshot *snap)
{
    for (size_t i = 0; i < snap->count; i++)
        if (snap->valid[i].work_kind == VCS_ZCODE_WORK_REVIEW &&
            bf_receipt_trusted(&snap->valid[i]))
            snap->valid[i].review_approved = bf_review_approves_evidence(
                c->workspace, c->task, c->candidate, snap->valid,
                snap->count, i, c->validation_now);
}

/* The build output a local build proves for this action wins; otherwise the
 * first approved build receipt names the output. */
static size_t bf_select_build(const struct bf_snapshot *snap,
                              const char *action_id)
{
    for (size_t i = 0; i < snap->count; i++)
        if (snap->valid[i].local &&
            snap->valid[i].work_kind == VCS_ZCODE_WORK_BUILD &&
            strcmp(snap->valid[i].row.action_id, action_id) == 0)
            return i;
    for (size_t i = 0; i < snap->count; i++)
        if (snap->valid[i].approved &&
            snap->valid[i].work_kind == VCS_ZCODE_WORK_BUILD)
            return i;
    return SIZE_MAX;
}

static size_t bf_count_distinct_approved(const struct bf_snapshot *snap)
{
    uint8_t distinct[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t distinct_count = 0;
    for (size_t i = 0; i < snap->count; i++) {
        if (!snap->valid[i].approved) continue;
        bool duplicate = false;
        for (size_t j = 0; j < distinct_count; j++)
            if (memcmp(distinct[j], snap->valid[i].receipt.signer_pubkey,
                       32) == 0)
                duplicate = true;
        if (!duplicate)
            memcpy(distinct[distinct_count++],
                   snap->valid[i].receipt.signer_pubkey, 32);
    }
    return distinct_count;
}

/* Finds the local build receipt and whether any remote build receipt carries
 * the selected output. */
static void bf_scan_selected_builds(const struct bf_snapshot *snap,
                                    size_t *local_build, bool *have_remote)
{
    *local_build = SIZE_MAX;
    *have_remote = false;
    if (!snap->have_selected) return;
    for (size_t i = 0; i < snap->count; i++) {
        if (snap->valid[i].work_kind != VCS_ZCODE_WORK_BUILD ||
            memcmp(snap->valid[i].evidence_output,
                   snap->selected_output, 32) != 0)
            continue;
        if (snap->valid[i].local)
            *local_build = i;
        else
            *have_remote = true;
    }
}

/* Compares each remote build receipt against the local build in a clean
 * shadow; true when at least one matches. */
static bool bf_shadow_compare_remotes(struct node_db *ndb,
    const char *workspace, struct bf_snapshot *snap, size_t local_build)
{
    bool reproduced = false;
    for (size_t i = 0; i < snap->count; i++) {
        struct bf_verified_receipt *remote = &snap->valid[i];
        if (remote->local || remote->work_kind != VCS_ZCODE_WORK_BUILD ||
            memcmp(remote->evidence_output, snap->selected_output, 32) != 0)
            continue;
        struct build_fabric_shadow_match shadow = {0};
        remote->shadow_checked = true;
        remote->clean_shadow = build_fabric_clean_shadow_compare(
            ndb, workspace, snap->valid[local_build].row.receipt_id,
            remote->row.receipt_id, &shadow).ok;
        if (remote->clean_shadow)
            reproduced = true;
    }
    return reproduced;
}

static bool bf_policy_satisfied(
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct build_fabric_proof_evaluation *out)
{
    bool local_required = (policy->required_proofs &
                           VCS_ZCODE_PROOF_LOCAL_REPRODUCTION) != 0;
    return (!(policy->required_proofs & VCS_ZCODE_PROOF_COMPILE) ||
            out->compile_satisfied) &&
        (!(policy->required_proofs & VCS_ZCODE_PROOF_TEST) ||
         out->test_satisfied) &&
        (!(policy->required_proofs & VCS_ZCODE_PROOF_FUZZ) ||
         out->fuzz_satisfied) &&
        (!(policy->required_proofs & VCS_ZCODE_PROOF_REVIEW) ||
         out->review_satisfied) &&
        (!local_required || out->local_reproduced) &&
        out->release_identity_satisfied;
}

static void bf_fill_counts(const struct vcs_zcode_proof_policy_v1 *policy,
    const struct bf_snapshot *snap,
    struct build_fabric_proof_evaluation *out)
{
    const struct bf_verified_receipt *valid = snap->valid;
    size_t valid_count = snap->count;
    bool independent =
        (policy->flags & VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS) != 0;
    out->compile_receipts = snap->have_selected
        ? bf_count_kind(valid, valid_count, VCS_ZCODE_WORK_BUILD,
                        snap->selected_output, independent)
        : 0;
    out->test_receipts = bf_count_tests(valid, valid_count, independent);
    out->fuzz_receipts = bf_count_kind(
        valid, valid_count, VCS_ZCODE_WORK_FUZZ, NULL, independent);
    out->review_receipts = bf_count_kind(
        valid, valid_count, VCS_ZCODE_WORK_REVIEW, NULL, independent);
    out->matching_receipts = out->compile_receipts;
    size_t compile_needed = policy->minimum_compile_receipts;
    if (policy->minimum_matching_receipts > compile_needed)
        compile_needed = policy->minimum_matching_receipts;
    size_t approved_compile_receipts = snap->have_selected
        ? bf_count_approved_kind(
            valid, valid_count, VCS_ZCODE_WORK_BUILD,
            snap->selected_output, independent)
        : 0;
    out->quorum_satisfied = approved_compile_receipts >= compile_needed;
    out->compile_satisfied = out->compile_receipts >= compile_needed &&
        (out->local_reproduced || out->quorum_satisfied);
    out->test_satisfied = out->test_receipts >= policy->minimum_test_receipts;
    out->fuzz_satisfied = out->fuzz_receipts >= policy->minimum_fuzz_receipts;
    out->review_satisfied =
        out->review_receipts >= policy->minimum_reviews;
    out->release_identity_satisfied =
        (policy->flags & VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY) == 0;
    out->policy_satisfied = bf_policy_satisfied(policy, out);
}

static void bf_fill_evaluation(struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_proof_policy_v1 *policy, struct bf_snapshot *snap,
    struct build_fabric_proof_evaluation *out)
{
    size_t local_build;
    bool have_remote;
    bf_scan_selected_builds(snap, &local_build, &have_remote);
    out->approved_distinct_signers = bf_count_distinct_approved(snap);
    out->local_reproduced = false;
    if (have_remote && local_build != SIZE_MAX)
        out->local_reproduced =
            bf_shadow_compare_remotes(ndb, workspace, snap, local_build);
    bf_fill_counts(policy, snap, out);
}

static bool bf_receipt_contributes(const struct bf_snapshot *snap, size_t i)
{
    const struct bf_verified_receipt *entry = &snap->valid[i];
    if (snap->have_selected && entry->work_kind == VCS_ZCODE_WORK_BUILD &&
        memcmp(entry->evidence_output, snap->selected_output, 32) == 0)
        return (!entry->shadow_checked || entry->clean_shadow) &&
               (bf_receipt_trusted(entry) ||
                bf_has_local_match(snap->valid, snap->count, i));
    if (entry->work_kind == VCS_ZCODE_WORK_TEST ||
        entry->work_kind == VCS_ZCODE_WORK_FUZZ)
        return bf_receipt_trusted(entry);
    if (entry->work_kind == VCS_ZCODE_WORK_REVIEW)
        return bf_receipt_trusted(entry) && entry->review_approved;
    return false;
}

/* Builds the canonical proof set from the contributing receipts. *have_proof
 * is false when no receipt contributes and no proof set exists. */
static struct zcl_result bf_publish_proof_set(const char *workspace,
    bool materialize, const struct bf_snapshot *snap,
    struct build_fabric_proof_evaluation *out, bool *have_proof)
{
    uint8_t proof_roots[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t proof_count = 0;
    *have_proof = false;
    if (snap->have_selected)
        zcl_hex_encode(snap->selected_output, 32, out->output_root_sha3);
    for (size_t i = 0; i < snap->count; i++)
        if (bf_receipt_contributes(snap, i))
            memcpy(proof_roots[proof_count++], snap->valid[i].root, 32);
    if (proof_count == 0) return ZCL_OK;
    qsort(proof_roots, proof_count, 32, bf_root_compare);
    uint8_t proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX], proof_root[32];
    size_t proof_len = 0;
    if (vcs_zcode_proof_set_serialize(
            (const uint8_t (*)[32])proof_roots, proof_count, proof_wire,
            sizeof(proof_wire), &proof_len) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])proof_roots, proof_count, proof_root) !=
            VCS_ZCODE_DEV_OK ||
        (materialize && !vcs_object_put_addressed(
                            workspace, proof_root, proof_wire, proof_len)))
        return ZCL_ERR(-1, "canonical proof set could not enter CAS");
    zcl_hex_encode(proof_root, 32, out->proof_set_root_sha3);
    *have_proof = true;
    return ZCL_OK;
}

static bool bf_class_quorum(const struct bf_snapshot *snap, size_t i,
    const struct build_fabric_proof_evaluation *out)
{
    const struct bf_verified_receipt *entry = &snap->valid[i];
    if (entry->work_kind == VCS_ZCODE_WORK_BUILD)
        return snap->have_selected && out->quorum_satisfied &&
            (!entry->shadow_checked || entry->clean_shadow) &&
            memcmp(entry->evidence_output, snap->selected_output, 32) == 0;
    if (entry->work_kind == VCS_ZCODE_WORK_TEST)
        return out->test_satisfied;
    if (entry->work_kind == VCS_ZCODE_WORK_FUZZ)
        return out->fuzz_satisfied;
    if (entry->work_kind == VCS_ZCODE_WORK_REVIEW)
        return out->review_satisfied && entry->review_approved;
    return false;
}

/* The trust state a remote-observed receipt is promoted to, or NULL to leave
 * it as observed. */
static const char *bf_promoted_trust_state(struct bf_snapshot *snap, size_t i,
    const struct build_fabric_proof_evaluation *out)
{
    if (bf_has_local_match(snap->valid, snap->count, i))
        return "LOCAL_REPRODUCED";
    if (bf_class_quorum(snap, i, out) && snap->valid[i].approved)
        return "QUORUM_MATCHED";
    return NULL;
}

static struct zcl_result bf_promote_receipts(struct node_db *ndb,
    struct bf_snapshot *snap, const struct build_fabric_proof_evaluation *out)
{
    if (!node_db_begin(ndb))
        return ZCL_ERR(-1, "cannot begin receipt trust promotion");
    bool saved = true;
    for (size_t i = 0; i < snap->count && saved; i++) {
        struct bf_verified_receipt *entry = &snap->valid[i];
        if (strcmp(entry->row.trust_state, "REMOTE_OBSERVED") != 0)
            continue;
        const char *state = bf_promoted_trust_state(snap, i, out);
        if (!state) continue;
        (void)snprintf(entry->row.trust_state,
                       sizeof(entry->row.trust_state), "%s", state);
        saved = db_build_receipt_save(ndb, &entry->row);
    }
    saved = saved && node_db_commit(ndb);
    if (!saved) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "trust promotion and rollback failed");
        return ZCL_ERR(-1, "receipt trust promotion could not persist");
    }
    return ZCL_OK;
}

static struct zcl_result bf_proof_evaluate(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, bool materialize, bool promote,
    struct build_fabric_proof_evaluation *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!bf_eval_args_valid(ndb, workspace, action_id, out, now))
        return ZCL_ERR(-1, "proof evaluation requires complete inputs");
    struct db_build_action action;
    struct zcl_result step = bf_eval_action_find(ndb, action_id, &action);
    if (!step.ok) return step;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    step = bf_load_proof_inputs(workspace, &action, &task, &candidate,
                                &policy);
    if (!step.ok) return step;
    struct db_build_receipt rows[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS + 1u];
    int row_count = 0;
    step = bf_candidate_receipts_read(ndb, &action, rows, &row_count);
    if (!step.ok) return step;
    struct bf_snapshot snap = {0};
    struct bf_eval_ctx ctx = {
        .ndb = ndb, .workspace = workspace, .action = &action,
        .task = &task, .candidate = &candidate, .policy = &policy,
        .now = now,
        .validation_now = now < task.expires_unix
            ? now : task.expires_unix - 1,
    };
    step = bf_collect_receipts(&ctx, rows, row_count, &snap);
    if (!step.ok) return step;
    if (bf_observations_conflict(snap.valid, snap.count))
        return ZCL_ERR(-1, VCS_PROOF_OBSERVATION_CONFLICT);
    /* Failed observations remain immutable in CAS and in the receipt ledger,
     * but cannot satisfy any positive proof dimension or be promoted. */
    snap.count = bf_successful_observations(snap.valid, snap.count);
    bf_mark_reviews(&ctx, &snap);
    out->valid_receipts = snap.count;
    size_t selected = bf_select_build(&snap, action_id);
    snap.have_selected = selected != SIZE_MAX;
    if (snap.have_selected)
        memcpy(snap.selected_output, snap.valid[selected].evidence_output,
               32);
    bf_fill_evaluation(ndb, workspace, &policy, &snap, out);
    bool have_proof = false;
    step = bf_publish_proof_set(workspace, materialize, &snap, out,
                                &have_proof);
    if (!step.ok || !have_proof || !promote) return step;
    return bf_promote_receipts(ndb, &snap, out);
}

struct zcl_result build_fabric_proof_evaluate(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out)
{
    return bf_proof_evaluate(
        ndb, workspace, action_id, now, true, true, out);
}

struct zcl_result build_fabric_proof_materialize(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out)
{
    return bf_proof_evaluate(
        ndb, workspace, action_id, now, true, false, out);
}

struct zcl_result build_fabric_proof_evaluate_readonly(
    struct node_db *ndb, const char *workspace, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out)
{
    return bf_proof_evaluate(
        ndb, workspace, action_id, now, false, false, out);
}
