/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared exact regression-action fixture for release fabric tests. */

#include "test/build_release_regression_fixture.h"

#include "test/accepted_work_fixture.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/build_release_regressions.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"

#include <stdio.h>
#include <string.h>

static void brf_job(struct db_build_job *row)
{
    memset(row, 0, sizeof(*row));
    memset(row->source_sha256, 'b', 64); row->source_sha256[64] = '\0';
    memset(row->source_cas_sha3, 'c', 64); row->source_cas_sha3[64] = '\0';
    memset(row->toolchain_sha3, 'd', 64); row->toolchain_sha3[64] = '\0';
    (void)snprintf(row->profile, sizeof(row->profile),
                   "secure-regressions-v1");
    (void)snprintf(row->state, sizeof(row->state), "PLANNED");
    row->created_at = 100;
    row->updated_at = 100;
}

static void brf_action(struct db_build_action *row)
{
    memset(row, 0, sizeof(*row));
    row->sequence = 0;
    (void)snprintf(row->kind, sizeof(row->kind), "%s",
                   VCS_BUILD_ACTION_KIND_TEST_V1);
    (void)snprintf(row->state, sizeof(row->state), "SNAPSHOTTED");
    (void)snprintf(row->target, sizeof(row->target), "%s",
                   VCS_BUILD_TARGET_V1);
    row->created_at = 101;
    row->updated_at = 101;
}

static void brf_worker_id(const uint8_t pubkey[32], char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, out);
}

static bool brf_canonicalize(struct db_build_job *job,
                             struct db_build_action *action)
{
    char action_id[65], job_id[65];
    if (!build_fabric_action_id(job, action, action_id).ok ||
        !build_fabric_job_id(job, action_id, job_id).ok)
        return false;
    (void)snprintf(action->action_id, sizeof(action->action_id), "%s",
                   action_id);
    (void)snprintf(job->job_id, sizeof(job->job_id), "%s", job_id);
    (void)snprintf(action->job_id, sizeof(action->job_id), "%s", job_id);
    return true;
}

/* Build the release test dependency through the same task/action/receipt/CAS
 * model used by real workers. The fixture bypasses process execution only so
 * this unit can exercise qualification policy deterministically; fixed worker
 * execution has a separate real-process test. */
bool test_build_release_regression_fixture(
    struct node_db *ndb, const char *dir,
    const struct db_build_job *candidate_job,
    const uint8_t test_input_root[32], int64_t now,
    uint8_t action_root_out[32], uint8_t proof_root_out[32],
    char receipt_id_out[65])
{
    struct test_accepted_work_fixture fixture;
    uint8_t candidate_source_root[32];
    if (!ndb || !dir || !candidate_job || !test_input_root || now <= 30 ||
        !action_root_out || !proof_root_out || !receipt_id_out ||
        !zcl_hex_decode_lower(candidate_job->source_cas_sha3,
                              candidate_source_root, 32) ||
        !test_accepted_work_fixture_create(
            dir, candidate_source_root, now, 51, &fixture))
        return false;

    struct vcs_zcode_proof_policy_v1 *policy = &fixture.accepted.policy;
    *policy = (struct vcs_zcode_proof_policy_v1) {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .required_proofs = VCS_ZCODE_PROOF_TEST,
        .minimum_test_receipts = 1,
        .minimum_matching_receipts = 1,
        .maximum_proof_age_seconds = 3600,
    };
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (vcs_zcode_proof_policy_serialize(policy, policy_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(
            policy, fixture.accepted.proof_policy_root) !=
            VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(
            dir, fixture.accepted.proof_policy_root, policy_wire,
            sizeof(policy_wire)))
        return false;

    struct vcs_zcode_task_v1 *task = &fixture.accepted.task;
    memcpy(task->proof_policy_root, fixture.accepted.proof_policy_root, 32);
    if (!vcs_build_release_regression_manifest_v1_store(
            dir, task->acceptance_tests_root) ||
        !zcl_hex_decode_lower(candidate_job->toolchain_sha3,
                              task->toolchain_capsule_root, 32))
        return false;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    if (vcs_zcode_task_serialize(task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, fixture.accepted.task_root) !=
            VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(
            dir, fixture.accepted.task_root, task_wire, sizeof(task_wire)))
        return false;

    struct vcs_zcode_candidate_v1 *candidate = &fixture.accepted.candidate;
    memcpy(candidate->task_root, fixture.accepted.task_root, 32);
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_serialize(candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, fixture.accepted.candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(
            dir, fixture.accepted.candidate_root, candidate_wire,
            sizeof(candidate_wire)))
        return false;

    struct db_build_job job;
    struct db_build_action action;
    brf_job(&job); brf_action(&action);
    (void)snprintf(job.source_sha256, sizeof(job.source_sha256), "%s",
                   candidate_job->source_sha256);
    (void)snprintf(job.source_cas_sha3, sizeof(job.source_cas_sha3), "%s",
                   candidate_job->source_cas_sha3);
    (void)snprintf(job.toolchain_sha3, sizeof(job.toolchain_sha3), "%s",
                   candidate_job->toolchain_sha3);
    zcl_hex_encode(test_input_root, 32, action.input_root_sha3);
    zcl_hex_encode(fixture.accepted.task_root, 32, action.task_root_sha3);
    zcl_hex_encode(fixture.accepted.candidate_root, 32,
                   action.candidate_root_sha3);
    zcl_hex_encode(fixture.accepted.proof_policy_root, 32,
                   action.proof_policy_root_sha3);
    uint8_t fixed_flags[32], fixed_environment[32];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            action.kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action.kind, fixed_environment))
        return false;
    zcl_hex_encode(fixed_flags, 32, action.flags_sha3);
    zcl_hex_encode(fixed_environment, 32, action.environment_sha3);
    (void)snprintf(action.virtual_workdir, sizeof(action.virtual_workdir),
                   "%s", VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1);
    (void)snprintf(action.declared_outputs, sizeof(action.declared_outputs),
                   "%s", VCS_BUILD_TEST_OUTPUT_V1);
    (void)snprintf(action.resource_policy, sizeof(action.resource_policy),
                   "%s", VCS_BUILD_TEST_RESOURCE_POLICY_V1);
    if (!brf_canonicalize(&job, &action) ||
        !build_fabric_plan(ndb, &job, &action).ok ||
        !zcl_hex_decode_lower(action.action_id, action_root_out, 32))
        return false;

    uint8_t seed[32], pubkey[32], secret[32];
    memset(seed, 52, sizeof(seed));
    ed25519_keypair(pubkey, secret, seed);
    struct db_build_worker worker = {0};
    brf_worker_id(pubkey, worker.worker_id);
    zcl_hex_encode(pubkey, 32, worker.signer_pubkey);
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities),
                   "linux,x86-64-v3,gcc,%s",
                   VCS_BUILD_ACTION_KIND_TEST_V1);
    worker.approved = 1;
    worker.approved_at = now - 30;
    worker.last_seen_at = now - 30;
    if (!build_fabric_worker_approve(ndb, &worker, now - 30).ok)
        return false;

    struct vcs_zcode_work_receipt_v1 work = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .work_kind = VCS_ZCODE_WORK_TEST,
        .status = VCS_ZCODE_WORK_PASS,
        .exit_status = 0,
        .started_unix = now - 20,
        .finished_unix = now - 10,
    };
    memcpy(work.task_root, fixture.accepted.task_root, 32);
    memcpy(work.candidate_root, fixture.accepted.candidate_root, 32);
    memcpy(work.action_root, action_root_out, 32);
    memcpy(work.input_root, test_input_root, 32);
    memcpy(work.proof_policy_root, fixture.accepted.proof_policy_root, 32);
    memcpy(work.toolchain_capsule_root, task->toolchain_capsule_root, 32);
    memset(work.output_root, 0xe1, 32);
    memset(work.lease_id, 0xe2, 32);
    memset(work.evidence_root, 0xe3, 32);
    memset(work.confinement_root, 0xe4, 32);
    uint8_t work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES], work_root[32];
    if (vcs_zcode_work_receipt_seal(&work, secret, pubkey) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_serialize(&work, work_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_work_receipt_id(&work, work_root) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(
            dir, work_root, work_wire, sizeof(work_wire)))
        return false;

    struct db_build_receipt row = {0};
    zcl_hex_encode(work_root, 32, row.receipt_id);
    (void)snprintf(row.action_id, sizeof(row.action_id), "%s",
                   action.action_id);
    (void)snprintf(row.job_id, sizeof(row.job_id), "%s", job.job_id);
    (void)snprintf(row.worker_id, sizeof(row.worker_id), "%s",
                   worker.worker_id);
    zcl_hex_encode(work.lease_id, 32, row.lease_id);
    (void)snprintf(row.action_sha3, sizeof(row.action_sha3), "%s",
                   action.action_id);
    zcl_hex_encode(work.output_root, 32, row.output_sha3);
    (void)snprintf(row.work_receipt_sha3, sizeof(row.work_receipt_sha3),
                   "%s", row.receipt_id);
    zcl_hex_encode(work.signature, 64, row.signature);
    (void)snprintf(row.confinement, sizeof(row.confinement),
                   "landlock=1,seccomp=1,network=0");
    (void)snprintf(row.trust_state, sizeof(row.trust_state),
                   "REMOTE_OBSERVED");
    row.created_at = work.finished_unix;
    if (!db_build_receipt_save(ndb, &row)) return false;

    (void)snprintf(action.state, sizeof(action.state), "ACCEPTED");
    (void)snprintf(action.outcome, sizeof(action.outcome), "ACCEPTED");
    (void)snprintf(action.output_root_sha3,
                   sizeof(action.output_root_sha3), "%s", row.output_sha3);
    action.finished_at = work.finished_unix;
    action.updated_at = work.finished_unix;
    if (!db_build_action_save(ndb, &action)) return false;

    uint8_t proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
    size_t proof_len = 0;
    if (vcs_zcode_proof_set_serialize(
            (const uint8_t (*)[32])&work_root, 1, proof_wire,
            sizeof(proof_wire), &proof_len) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])&work_root, 1, proof_root_out) !=
            VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(
            dir, proof_root_out, proof_wire, proof_len))
        return false;
    struct build_fabric_proof_evaluation inspected = {0};
    struct db_build_receipt unchanged;
    bool valid = build_fabric_proof_evaluate_readonly(
               ndb, dir, action.action_id, now, &inspected).ok &&
           inspected.policy_satisfied && inspected.test_satisfied &&
           inspected.test_receipts == 1 &&
           db_build_receipt_find(ndb, row.receipt_id, &unchanged) &&
           strcmp(unchanged.trust_state, "REMOTE_OBSERVED") == 0;
    if (valid)
        (void)snprintf(receipt_id_out, 65, "%s", row.receipt_id);
    return valid;
}
