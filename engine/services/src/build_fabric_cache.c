/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact, non-executing restoration of accepted ZCODE build outputs. */

#include "services/build_fabric_cache.h"

#include "build_fabric_observation_internal.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "crypto/sha3.h"
#include "platform/private_file.h"
#include "services/build_fabric_service.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs_object.h"
#include "vcs/vcs_manifest.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_work_output.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    BFC_PATH_CAP = 32768,
    BFC_RECEIPT_SCAN_CAP = 257,
};

const char *build_fabric_cache_disposition_string(
    enum build_fabric_cache_disposition disposition)
{
    switch (disposition) {
    case BUILD_FABRIC_CACHE_MISS: return "miss";
    case BUILD_FABRIC_CACHE_HIT: return "hit";
    case BUILD_FABRIC_CACHE_CORRUPT: return "corrupt";
    }
    return "corrupt";
}

static bool bfc_job_same(const struct db_build_job *a,
                         const struct db_build_job *b)
{
    return strcmp(a->job_id, b->job_id) == 0 &&
           strcmp(a->source_sha256, b->source_sha256) == 0 &&
           strcmp(a->source_cas_sha3, b->source_cas_sha3) == 0 &&
           strcmp(a->toolchain_sha3, b->toolchain_sha3) == 0 &&
           strcmp(a->profile, b->profile) == 0;
}

static bool bfc_action_same(const struct db_build_action *a,
                            const struct db_build_action *b)
{
    return strcmp(a->action_id, b->action_id) == 0 &&
           strcmp(a->job_id, b->job_id) == 0 && a->sequence == b->sequence &&
           strcmp(a->kind, b->kind) == 0 &&
           strcmp(a->input_root_sha3, b->input_root_sha3) == 0 &&
           strcmp(a->task_root_sha3, b->task_root_sha3) == 0 &&
           strcmp(a->candidate_root_sha3, b->candidate_root_sha3) == 0 &&
           strcmp(a->proof_policy_root_sha3,
                  b->proof_policy_root_sha3) == 0 &&
           strcmp(a->target, b->target) == 0 &&
           strcmp(a->flags_sha3, b->flags_sha3) == 0 &&
           strcmp(a->environment_sha3, b->environment_sha3) == 0 &&
           strcmp(a->virtual_workdir, b->virtual_workdir) == 0 &&
           strcmp(a->declared_outputs, b->declared_outputs) == 0 &&
           strcmp(a->resource_policy, b->resource_policy) == 0;
}

static bool bfc_plan_current(const struct db_build_job *job,
                             const struct db_build_action *action)
{
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    return build_fabric_action_id(job, action, action_id).ok &&
           strcmp(action_id, action->action_id) == 0 &&
           build_fabric_job_id(job, action_id, job_id).ok &&
           strcmp(job_id, job->job_id) == 0 &&
           strcmp(action->job_id, job_id) == 0;
}

static bool bfc_candidate_structure_valid(
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t task_root[32], const uint8_t candidate_root[32])
{
    uint8_t checked_task[32], checked_candidate[32];
    return vcs_zcode_task_validate(task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_validate(candidate) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, checked_task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(candidate, checked_candidate) ==
            VCS_ZCODE_DEV_OK &&
        memcmp(checked_task, task_root, 32) == 0 &&
        memcmp(checked_candidate, candidate_root, 32) == 0 &&
        memcmp(candidate->task_root, task_root, 32) == 0 &&
        memcmp(candidate->base_source_root, task->source_root, 32) == 0 &&
        candidate->created_unix < task->expires_unix;
}

static bool bfc_source_identity_valid(
    const char *workspace, const uint8_t source_root[32],
    const uint8_t expected_source_id[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw_bounded(
            workspace, source_root, VCS_SOURCE_BUNDLE_MAX_MANIFEST_BYTES,
            &wire, &wire_len) != 0)
        return false;
    struct vcs_manifest manifest;
    uint8_t checked_root[32], checked_id[32];
    bool ok = vcs_manifest_parse(wire, wire_len, &manifest);
    if (ok) {
        ok = vcs_manifest_tree_hash(&manifest, checked_root) &&
            memcmp(checked_root, source_root, 32) == 0;
        for (size_t i = 0; ok && i < manifest.count; i++) {
            uint8_t *blob = NULL;
            size_t blob_len = 0;
            ok = manifest.entries[i].size <= SIZE_MAX &&
                vcs_object_get(workspace, manifest.entries[i].blob,
                               VCS_TAG_BLOB, &blob, &blob_len) == 0 &&
                blob_len == (size_t)manifest.entries[i].size;
            free(blob);
        }
        vcs_manifest_free(&manifest);
    }
    vcs_source_manifest_id(wire, wire_len, checked_id);
    free(wire);
    return ok && memcmp(checked_id, expected_source_id, 32) == 0;
}

static bool bfc_input_current(const char *workspace,
                              const struct db_build_job *job,
                              const struct db_build_action *action)
{
    uint8_t root[32], source[32], source_id[32], task_root[32];
    uint8_t candidate_root[32], toolchain[32], policy[32];
    uint8_t *task_wire = NULL, *candidate_wire = NULL;
    size_t task_len = 0, candidate_len = 0;
    if (!zcl_hex_decode_lower(action->input_root_sha3, root, 32) ||
        !zcl_hex_decode_lower(job->source_sha256, source_id, 32) ||
        !zcl_hex_decode_lower(job->source_cas_sha3, source, 32) ||
        !zcl_hex_decode_lower(job->toolchain_sha3, toolchain, 32) ||
        !zcl_hex_decode_lower(action->task_root_sha3, task_root, 32) ||
        !zcl_hex_decode_lower(action->candidate_root_sha3,
                              candidate_root, 32) ||
        !zcl_hex_decode_lower(action->proof_policy_root_sha3, policy, 32) ||
        vcs_object_load_raw_bounded(workspace, task_root,
                                    VCS_ZCODE_TASK_WIRE_BYTES,
                                    &task_wire, &task_len) != 0 ||
        vcs_object_load_raw_bounded(workspace, candidate_root,
                                    VCS_ZCODE_CANDIDATE_WIRE_BYTES,
                                    &candidate_wire, &candidate_len) != 0) {
        free(candidate_wire); free(task_wire);
        return false;
    }
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    bool ok = vcs_zcode_task_parse(task_wire, task_len, &task) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_parse(candidate_wire, candidate_len, &candidate) ==
            VCS_ZCODE_DEV_OK &&
        bfc_candidate_structure_valid(
            &task, &candidate, task_root, candidate_root) &&
        memcmp(task.toolchain_capsule_root, toolchain, 32) == 0 &&
        memcmp(task.proof_policy_root, policy, 32) == 0 &&
        memcmp(candidate.candidate_source_root, source, 32) == 0 &&
        bfc_source_identity_valid(workspace, source, source_id) &&
        vcs_zcode_action_input_verify_cas(
            workspace, root, &task, &candidate, VCS_ZCODE_WORK_BUILD) ==
            VCS_ZCODE_ACTION_INPUT_OK;
    free(candidate_wire); free(task_wire);
    return ok;
}

static bool bfc_existing_destination_safe(const char *path)
{
    if (platform_private_path_absent(path)) return true;
    struct platform_private_file existing;
    platform_private_file_init(&existing);
    bool ok = platform_private_file_open_locked(path, &existing);
    platform_private_file_close(&existing);
    return ok;
}

static bool bfc_receipt_signature_valid(
    struct node_db *ndb, const struct db_build_receipt *receipt)
{
    struct db_build_worker worker;
    char expected[BUILD_FABRIC_ID_HEX + 1];
    uint8_t id[32], signature[64], pubkey[32];
    return db_build_worker_find(ndb, receipt->worker_id, &worker) &&
        build_fabric_receipt_id(receipt, expected).ok &&
        strcmp(expected, receipt->receipt_id) == 0 &&
        zcl_hex_decode_lower(receipt->receipt_id, id, sizeof(id)) &&
        zcl_hex_decode_lower(receipt->signature, signature,
                             sizeof(signature)) &&
        zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)) &&
        ed25519_verify(signature, id, sizeof(id), pubkey);
}

static bool bfc_receipt_matches(
    const struct db_build_receipt *receipt,
    const struct db_build_job *job, const struct db_build_action *action)
{
    return strcmp(receipt->trust_state, "LOCAL_ACCEPTED") == 0 &&
        receipt->exit_status == 0 &&
        strcmp(receipt->action_id, action->action_id) == 0 &&
        strcmp(receipt->action_sha3, action->action_id) == 0 &&
        strcmp(receipt->job_id, job->job_id) == 0 &&
        strcmp(receipt->output_sha3, action->output_root_sha3) == 0;
}

static bool bfc_has_one_accepted_receipt(
    struct node_db *ndb, const char *workspace,
    const struct db_build_job *job, const struct db_build_action *action,
    struct db_build_receipt *out)
{
    struct db_build_receipt *rows = zcl_malloc(
        BFC_RECEIPT_SCAN_CAP * sizeof(*rows), "build.cache.receipts");
    if (!rows) return false;
    int count = db_build_job_receipts(
        ndb, job->job_id, rows, BFC_RECEIPT_SCAN_CAP);
    const struct db_build_receipt *accepted = NULL;
    bool complete = count >= 0 && count < BFC_RECEIPT_SCAN_CAP;
    for (int i = 0; complete && i < count; i++) {
        if (strcmp(rows[i].action_id, action->action_id) != 0 ||
            strcmp(rows[i].trust_state, "LOCAL_ACCEPTED") != 0)
            continue;
        if (accepted || !bfc_receipt_matches(&rows[i], job, action)) {
            complete = false;
            break;
        }
        accepted = &rows[i];
    }
    bool valid = complete && accepted &&
        bfc_receipt_signature_valid(ndb, accepted) &&
        build_fabric_observation_verify(
            workspace, job, action, accepted).ok;
    if (valid && out) *out = *accepted;
    free(rows);
    return valid;
}

static bool bfc_file_matches(const char *path, const uint8_t *bytes, size_t len)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    uint64_t size = 0;
    uint8_t buffer[64u * 1024u];
    bool ok = platform_private_file_open_locked(path, &file) &&
              platform_private_file_size(&file, &size) && size == len;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    for (size_t off = 0; ok && off < len;) {
        size_t take = len - off;
        if (take > sizeof(buffer)) take = sizeof(buffer);
        ok = platform_private_file_read_at(&file, buffer, take, off);
        if (ok) sha3_256_write(&sha, buffer, take);
        off += take;
    }
    uint8_t actual[32], expected[32];
    if (ok) {
        sha3_256_finalize(&sha, actual);
        sha3_256(bytes, len, expected);
        ok = memcmp(actual, expected, 32) == 0;
    }
    platform_private_file_close(&file);
    return ok;
}

static bool bfc_publish(const char *destination, const uint8_t *bytes,
                        size_t len)
{
    char *resolved = zcl_malloc(BFC_PATH_CAP, "build.cache.destination");
    char *parent = zcl_malloc(BFC_PATH_CAP, "build.cache.parent");
    char *staging = zcl_malloc(BFC_PATH_CAP, "build.cache.staging");
    uint8_t nonce[16];
    bool ok = resolved && parent && staging &&
        platform_private_destination_resolve(
            destination, resolved, BFC_PATH_CAP, parent, BFC_PATH_CAP) &&
        bfc_existing_destination_safe(resolved) &&
        zcl_random_secret_bytes(nonce, sizeof(nonce), "build_cache_staging");
    char nonce_hex[33];
    if (ok) zcl_hex_encode(nonce, sizeof(nonce), nonce_hex);
    int n = ok ? snprintf(staging, BFC_PATH_CAP, "%s.z23-cache-%s.tmp",
                          resolved, nonce_hex) : -1;
    ok = ok && n > 0 && n < BFC_PATH_CAP;
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool created = ok && platform_private_file_create(staging, &file);
    bool replaced = created &&
        platform_private_file_write_at(&file, bytes, len, 0) &&
        platform_private_file_truncate(&file, len) &&
        platform_private_file_replace(&file, staging, resolved);
    ok = replaced && platform_private_parent_flush(parent) &&
         bfc_file_matches(resolved, bytes, len);
    if (created && !replaced) {
        if (!platform_private_file_retire(&file, staging))
            platform_private_file_close(&file);
    }
    free(staging); free(parent); free(resolved);
    return ok;
}

static struct zcl_result bfc_corrupt(
    struct build_fabric_cache_report *report, const char *detail)
{
    report->disposition = BUILD_FABRIC_CACHE_CORRUPT;
    return ZCL_ERR(-1, "exact build cache refused: %s", detail);
}

struct zcl_result build_fabric_cache_restore(
    struct node_db *ndb, const char *workspace,
    struct vcs_package_store *store, const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, const char *destination,
    struct build_fabric_cache_report *report)
{
    if (report) memset(report, 0, sizeof(*report));
    if (!ndb || !ndb->open || !workspace || !store || !expected_job ||
        !expected_action || !destination || !report)
        return ZCL_ERR(-1, "exact build cache requires plan, store, and output");
    report->disposition = BUILD_FABRIC_CACHE_MISS;
    if (strcmp(expected_action->kind, VCS_BUILD_ACTION_KIND_V1) != 0 ||
        !expected_action->task_root_sha3[0] ||
        !bfc_plan_current(expected_job, expected_action) ||
        !bfc_input_current(workspace, expected_job, expected_action))
        return bfc_corrupt(report, "current immutable plan is invalid");
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, expected_action->action_id, &action) ||
        !db_build_job_find(ndb, expected_job->job_id, &job))
        return ZCL_OK;
    if (!bfc_job_same(&job, expected_job) ||
        !bfc_action_same(&action, expected_action) ||
        !bfc_plan_current(&job, &action))
        return bfc_corrupt(report, "durable plan differs from requested plan");
    if (strcmp(action.state, "ACCEPTED") != 0 ||
        !action.output_root_sha3[0])
        return ZCL_OK;
    if (!bfc_has_one_accepted_receipt(ndb, workspace, &job, &action, NULL))
        return bfc_corrupt(report,
                           "accepted action lacks one canonical local receipt");
    uint8_t action_root[32], output_root[32], *bytes = NULL;
    size_t len = 0;
    if (!zcl_hex_decode_lower(action.action_id, action_root, 32) ||
        !zcl_hex_decode_lower(action.output_root_sha3, output_root, 32))
        return bfc_corrupt(report, "accepted action roots are malformed");
    enum vcs_zcode_work_output_result got = vcs_zcode_work_output_get(
        store, output_root, action_root, &bytes, &len);
    if (got == VCS_ZCODE_WORK_OUTPUT_ABSENT) return ZCL_OK;
    if (got != VCS_ZCODE_WORK_OUTPUT_OK)
        return bfc_corrupt(report,
                           vcs_zcode_work_output_result_string(got));
    bool published = bfc_existing_destination_safe(destination) &&
        bfc_file_matches(destination, bytes, len);
    if (!published) published = bfc_publish(destination, bytes, len);
    free(bytes);
    if (!published)
        return bfc_corrupt(report, "atomic output publication failed");
    report->disposition = BUILD_FABRIC_CACHE_HIT;
    report->restored_bytes = len;
    (void)snprintf(report->action_id, sizeof(report->action_id), "%s",
                   action.action_id);
    (void)snprintf(report->output_root_sha3,
                   sizeof(report->output_root_sha3), "%s",
                   action.output_root_sha3);
    return ZCL_OK;
}

struct bfc_replay_roots {
    uint8_t task[32], candidate[32], action[32], input[32], output[32];
    uint8_t policy[32], toolchain[32], observation[32], lease[32];
};

static bool bfc_replay_roots_decode(
    const struct db_build_job *job, const struct db_build_action *action,
    const struct db_build_receipt *accepted, struct bfc_replay_roots *roots)
{
    return zcl_hex_decode_lower(action->task_root_sha3, roots->task, 32) &&
        zcl_hex_decode_lower(action->candidate_root_sha3,
                             roots->candidate, 32) &&
        zcl_hex_decode_lower(action->action_id, roots->action, 32) &&
        zcl_hex_decode_lower(action->input_root_sha3, roots->input, 32) &&
        zcl_hex_decode_lower(action->output_root_sha3, roots->output, 32) &&
        zcl_hex_decode_lower(action->proof_policy_root_sha3,
                             roots->policy, 32) &&
        zcl_hex_decode_lower(job->toolchain_sha3, roots->toolchain, 32) &&
        zcl_hex_decode_lower(accepted->observation_sha3,
                             roots->observation, 32) &&
        zcl_hex_decode_lower(accepted->lease_id, roots->lease, 32);
}

static bool bfc_replay_receipt_binds(
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const struct db_build_receipt *accepted,
    const struct bfc_replay_roots *roots)
{
    return memcmp(receipt->task_root, roots->task, 32) == 0 &&
        memcmp(receipt->candidate_root, roots->candidate, 32) == 0 &&
        memcmp(receipt->action_root, roots->action, 32) == 0 &&
        memcmp(receipt->input_root, roots->input, 32) == 0 &&
        memcmp(receipt->output_root, roots->output, 32) == 0 &&
        memcmp(receipt->proof_policy_root, roots->policy, 32) == 0 &&
        memcmp(receipt->toolchain_capsule_root, roots->toolchain, 32) == 0 &&
        memcmp(receipt->evidence_root, roots->observation, 32) == 0 &&
        memcmp(receipt->lease_id, roots->lease, 32) == 0 &&
        receipt->work_kind == VCS_ZCODE_WORK_BUILD &&
        receipt->exit_status == accepted->exit_status &&
        receipt->status == VCS_ZCODE_WORK_PASS;
}

static bool bfc_replay_args_valid(
    struct node_db *ndb, const char *workspace,
    const struct vcs_package_store *store,
    const struct db_build_job *job, const struct db_build_action *action,
    int64_t now, const bool *hit,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const uint64_t *verified_output_bytes)
{
    return ndb && ndb->open && workspace && store && job && action &&
        now > 0 && hit && receipt && verified_output_bytes;
}

static struct zcl_result bfc_replay_record_current(
    struct node_db *ndb, const char *workspace,
    const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, int64_t now,
    struct db_build_job *job, struct db_build_action *action,
    struct db_build_receipt *accepted, bool *eligible)
{
    *eligible = false;
    if (!bfc_plan_current(expected_job, expected_action) ||
        !bfc_input_current(workspace, expected_job, expected_action))
        return ZCL_ERR(-1, "historical replay immutable input is invalid");
    if (!db_build_job_find(ndb, expected_job->job_id, job) ||
        !db_build_action_find(ndb, expected_action->action_id, action))
        return ZCL_OK;
    if (!bfc_job_same(job, expected_job) ||
        !bfc_action_same(action, expected_action) ||
        !bfc_plan_current(job, action))
        return ZCL_ERR(-1, "historical replay durable plan differs");
    if ((strcmp(action->state, "ACCEPTED") != 0 &&
         strcmp(action->state, "CACHE_HIT") != 0) ||
        !action->output_root_sha3[0])
        return ZCL_OK;
    if (!bfc_has_one_accepted_receipt(
            ndb, workspace, job, action, accepted))
        return ZCL_ERR(-1, "historical replay lacks one local receipt");
    struct build_fabric_proof_evaluation proof;
    struct zcl_result evaluated = build_fabric_proof_evaluate_readonly(
        ndb, workspace, action->action_id, now, &proof);
    if (!evaluated.ok) return evaluated;
    *eligible = proof.compile_satisfied &&
        strcmp(proof.output_root_sha3, action->output_root_sha3) == 0;
    return ZCL_OK;
}

static struct zcl_result bfc_replay_signed_receipt_load(
    struct node_db *ndb, const char *workspace,
    const struct db_build_receipt *accepted,
    const struct bfc_replay_roots *roots,
    struct vcs_zcode_work_receipt_v1 *receipt,
    struct db_build_worker *worker)
{
    uint8_t receipt_root[32], checked[32], signer[32], *wire = NULL;
    size_t wire_len = 0;
    if (!zcl_hex_decode_lower(accepted->work_receipt_sha3,
                              receipt_root, 32) ||
        vcs_object_load_raw_bounded(
            workspace, receipt_root, VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
            &wire, &wire_len) != 0) {
        free(wire);
        return ZCL_ERR(-1, "historical replay receipt CAS unavailable");
    }
    bool valid = wire_len == VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES &&
        vcs_zcode_work_receipt_parse(wire, wire_len, receipt) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_validate(receipt) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(receipt, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, receipt_root, 32) == 0 &&
        db_build_worker_find(ndb, accepted->worker_id, worker) &&
        zcl_hex_decode_lower(worker->signer_pubkey, signer, 32) &&
        vcs_zcode_work_receipt_verify(receipt, signer) == VCS_ZCODE_DEV_OK &&
        bfc_replay_receipt_binds(receipt, accepted, roots);
    free(wire);
    if (!valid) {
        memset(receipt, 0, sizeof(*receipt));
        return ZCL_ERR(-1, "historical replay receipt is invalid");
    }
    return ZCL_OK;
}

static bool bfc_replay_policy_load(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_proof_policy_v1 *policy)
{
    uint8_t checked[32], *wire = NULL;
    size_t wire_len = 0;
    bool valid = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(policy, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return valid;
}

static bool bfc_replay_candidate_valid(
    const char *workspace, const struct bfc_replay_roots *roots,
    const struct vcs_zcode_work_receipt_v1 *receipt, int64_t now)
{
    uint8_t *task_wire = NULL, *candidate_wire = NULL;
    size_t task_len = 0, candidate_len = 0;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    bool valid = vcs_object_load_raw_bounded(
            workspace, roots->task, VCS_ZCODE_TASK_WIRE_BYTES,
            &task_wire, &task_len) == 0 &&
        vcs_object_load_raw_bounded(
            workspace, roots->candidate, VCS_ZCODE_CANDIDATE_WIRE_BYTES,
            &candidate_wire, &candidate_len) == 0 &&
        vcs_zcode_task_parse(task_wire, task_len, &task) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_parse(candidate_wire, candidate_len,
                                  &candidate) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_validate_for_candidate(
            &task, &candidate, receipt,
            now < task.expires_unix ? now : task.expires_unix - 1) ==
            VCS_ZCODE_DEV_OK;
    free(task_wire);
    free(candidate_wire);
    return valid;
}

static struct zcl_result bfc_replay_receipt_current(
    const char *workspace, const struct bfc_replay_roots *roots,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const struct db_build_worker *worker, int64_t now, bool *eligible)
{
    *eligible = false;
    struct vcs_zcode_proof_policy_v1 policy;
    if (!bfc_replay_policy_load(workspace, roots->policy, &policy))
        return ZCL_ERR(-1, "historical replay policy is invalid");
    if (!bfc_replay_candidate_valid(workspace, roots, receipt, now))
        return ZCL_ERR(-1, "historical replay receipt candidate is invalid");
    /* A newer matching proof must never refresh this old physical run. */
    *eligible = !worker->revoked &&
        (worker->expires_at == 0 || now < worker->expires_at) &&
        receipt->finished_unix <= now &&
        (policy.maximum_proof_age_seconds == 0 ||
         receipt->finished_unix >=
             now - (int64_t)policy.maximum_proof_age_seconds);
    return ZCL_OK;
}

struct zcl_result build_fabric_cache_replay_receipt(
    struct node_db *ndb, const char *workspace,
    struct vcs_package_store *store, const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, int64_t now, bool *hit,
    struct vcs_zcode_work_receipt_v1 *receipt,
    uint64_t *verified_output_bytes)
{
    if (hit) *hit = false;
    if (receipt) memset(receipt, 0, sizeof(*receipt));
    if (verified_output_bytes) *verified_output_bytes = 0;
    if (!bfc_replay_args_valid(
            ndb, workspace, store, expected_job, expected_action, now,
            hit, receipt, verified_output_bytes))
        return ZCL_ERR(-1, "historical replay requires complete inputs");
    if (strcmp(expected_action->kind, VCS_BUILD_ACTION_KIND_V1) != 0)
        return ZCL_OK; /* independently executed obligations remain fresh */
    struct db_build_job job;
    struct db_build_action action;
    struct db_build_receipt accepted;
    bool eligible = false;
    struct zcl_result selected = bfc_replay_record_current(
        ndb, workspace, expected_job, expected_action, now,
        &job, &action, &accepted, &eligible);
    if (!selected.ok || !eligible) return selected;
    struct bfc_replay_roots roots;
    if (!bfc_replay_roots_decode(&job, &action, &accepted, &roots))
        return ZCL_ERR(-1, "historical replay roots are malformed");
    uint8_t *output = NULL;
    size_t output_len = 0;
    enum vcs_zcode_work_output_result got = vcs_zcode_work_output_get(
        store, roots.output, roots.action, &output, &output_len);
    free(output);
    if (got == VCS_ZCODE_WORK_OUTPUT_ABSENT) return ZCL_OK;
    if (got != VCS_ZCODE_WORK_OUTPUT_OK)
        return ZCL_ERR(-1, "historical replay output: %s",
                       vcs_zcode_work_output_result_string(got));
    struct db_build_worker worker;
    struct zcl_result loaded = bfc_replay_signed_receipt_load(
        ndb, workspace, &accepted, &roots, receipt, &worker);
    if (!loaded.ok) return loaded;
    struct zcl_result current = bfc_replay_receipt_current(
        workspace, &roots, receipt, &worker, now, &eligible);
    if (!current.ok || !eligible) {
        memset(receipt, 0, sizeof(*receipt));
        return current;
    }
    *verified_output_bytes = output_len;
    *hit = true;
    return ZCL_OK;
}
