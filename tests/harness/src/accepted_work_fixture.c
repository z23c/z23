/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/accepted_work_fixture.h"

#include "crypto/ed25519.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_task_authority.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fixture_root(uint8_t out[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
}

static bool fixture_put(const char *dir, const uint8_t root[32],
                        const uint8_t *wire, size_t len)
{
    return vcs_object_put_addressed(dir, root, wire, len);
}

static bool fixture_work_receipt(
    const char *dir, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const uint8_t policy_root[32], uint8_t kind, uint8_t seed_byte,
    int64_t now, uint8_t root_out[32])
{
    struct vcs_zcode_work_receipt_v1 receipt = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .work_kind = kind,
        .status = VCS_ZCODE_WORK_PASS,
        .started_unix = now - 20,
        .finished_unix = now - 10,
    };
    memcpy(receipt.task_root, task_root, 32);
    memcpy(receipt.candidate_root, candidate_root, 32);
    memcpy(receipt.proof_policy_root, policy_root, 32);
    memcpy(receipt.toolchain_capsule_root, task->toolchain_capsule_root, 32);
    fixture_root(receipt.action_root, (uint8_t)(seed_byte + 1));
    fixture_root(receipt.input_root, (uint8_t)(seed_byte + 2));
    fixture_root(receipt.output_root, 0xa0);
    fixture_root(receipt.lease_id, (uint8_t)(seed_byte + 3));
    fixture_root(receipt.evidence_root, (uint8_t)(seed_byte + 4));
    fixture_root(receipt.confinement_root, (uint8_t)(seed_byte + 5));
    uint8_t seed[32], secret[32], pubkey[32];
    fixture_root(seed, seed_byte);
    ed25519_keypair(pubkey, secret, seed);
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    bool ok = vcs_zcode_work_receipt_seal(&receipt, secret, pubkey) ==
                  VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_serialize(&receipt, wire) ==
                  VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(&receipt, root_out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_validate_for_candidate(
            task, candidate, &receipt, now) == VCS_ZCODE_DEV_OK &&
        fixture_put(dir, root_out, wire, sizeof(wire));
    memset(secret, 0, sizeof(secret));
    return ok;
}

static bool fixture_lane(
    const char *dir, struct vcs_zcode_lane_receipt_v1 *lane,
    const uint8_t secret[32], const uint8_t pubkey[32], uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_LANE_WIRE_BYTES];
    memset(lane->signature, 0, sizeof(lane->signature));
    return vcs_zcode_lane_receipt_seal(lane, secret, pubkey) ==
               VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_serialize(lane, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(lane, root) == VCS_ZCODE_DEV_OK &&
        fixture_put(dir, root, wire, sizeof(wire));
}

bool test_accepted_work_fixture_create(
    const char *dir, const uint8_t source_root[32], int64_t now,
    uint8_t signer_seed, struct test_accepted_work_fixture *fixture)
{
    if (!dir || !source_root || !fixture || now <= 0)
        return false;
    memset(fixture, 0, sizeof(*fixture));
    struct vcs_zcode_proof_policy_v1 *policy = &fixture->accepted.policy;
    *policy = (struct vcs_zcode_proof_policy_v1) {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .required_proofs = VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST,
        .minimum_compile_receipts = 1,
        .minimum_test_receipts = 1,
        .minimum_matching_receipts = 1,
        .maximum_proof_age_seconds = 3600,
    };
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (vcs_zcode_proof_policy_serialize(policy, policy_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(
            policy, fixture->accepted.proof_policy_root) !=
            VCS_ZCODE_DEV_OK ||
        !fixture_put(dir, fixture->accepted.proof_policy_root,
                     policy_wire, sizeof(policy_wire)))
        return false;

    struct vcs_zcode_task_v1 *task = &fixture->accepted.task;
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(task->source_root, source_root, 32);
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    lock.count = 1;
    memcpy(lock.nodes[0].root, source_root, 32);
    (void)snprintf(lock.nodes[0].name, sizeof(lock.nodes[0].name),
                   "test/source");
    (void)snprintf(lock.nodes[0].semver, sizeof(lock.nodes[0].semver),
                   "1.0.0");
    uint8_t *lock_wire = NULL, *recipe_wire = NULL;
    size_t lock_len = 0, recipe_len = 0;
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    enum vcs_package_recipe_error recipe_error = VCS_PACKAGE_RECIPE_OK;
    bool authority = vcs_package_lock_serialize(
            &lock, &lock_wire, &lock_len) == VCS_PACKAGE_DEPS_OK &&
        vcs_package_recipe_add_source(&recipe, "engine/entry/main.c", &recipe_error);
    vcs_package_recipe_set_test_limits(
        &recipe, 0, 60, UINT64_C(64) * 1024u * 1024u);
    authority = authority && vcs_package_recipe_serialize(
            &recipe, &recipe_wire, &recipe_len) == VCS_PACKAGE_RECIPE_OK &&
        vcs_zcode_task_authority_store(
            dir, lock_wire, lock_len, recipe_wire, recipe_len,
            task->dependency_lock_root, task->acceptance_tests_root) ==
            VCS_ZCODE_TASK_AUTHORITY_OK;
    free(recipe_wire);
    vcs_package_recipe_free(&recipe);
    free(lock_wire);
    if (!authority)
        return false;
    fixture_root(task->toolchain_capsule_root, 0x21);
    fixture_root(task->write_scope_root, 0x31);
    memcpy(task->proof_policy_root, fixture->accepted.proof_policy_root, 32);
    fixture_root(task->model_policy_root, 0x51);
    fixture_root(task->goal_root, signer_seed);
    task->capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task->max_changed_files = 8;
    task->max_patch_bytes = 1024 * 1024;
    task->max_context_bytes = 1024 * 1024;
    task->max_cpu_seconds = 60;
    task->max_memory_bytes = UINT64_C(256) * 1024 * 1024;
    task->max_output_bytes = UINT64_C(16) * 1024 * 1024;
    task->expires_unix = now + 3600;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    if (vcs_zcode_task_serialize(task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, fixture->accepted.task_root) !=
            VCS_ZCODE_DEV_OK ||
        !fixture_put(dir, fixture->accepted.task_root,
                     task_wire, sizeof(task_wire)))
        return false;

    uint8_t seed[32];
    fixture_root(seed, signer_seed);
    ed25519_keypair(fixture->signer_pubkey, fixture->signer_secret, seed);
    struct vcs_zcode_candidate_v1 *candidate = &fixture->accepted.candidate;
    candidate->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(candidate->task_root, fixture->accepted.task_root, 32);
    memcpy(candidate->base_source_root, source_root, 32);
    fixture_root(candidate->patch_root, 0x71);
    memcpy(candidate->candidate_source_root, source_root, 32);
    fixture_root(candidate->adapter_policy_root, 0x81);
    memcpy(candidate->author_pubkey, fixture->signer_pubkey, 32);
    candidate->sequence = 1;
    candidate->created_unix = now - 100;
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_serialize(candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, fixture->accepted.candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        !fixture_put(dir, fixture->accepted.candidate_root,
                     candidate_wire, sizeof(candidate_wire)))
        return false;

    uint8_t receipt_roots[2][32];
    if (!fixture_work_receipt(
            dir, task, candidate, fixture->accepted.task_root,
            fixture->accepted.candidate_root,
            fixture->accepted.proof_policy_root, VCS_ZCODE_WORK_BUILD,
            0x91, now, receipt_roots[0]) ||
        !fixture_work_receipt(
            dir, task, candidate, fixture->accepted.task_root,
            fixture->accepted.candidate_root,
            fixture->accepted.proof_policy_root, VCS_ZCODE_WORK_TEST,
            0xb1, now, receipt_roots[1]))
        return false;
    if (memcmp(receipt_roots[0], receipt_roots[1], 32) > 0) {
        uint8_t swap[32];
        memcpy(swap, receipt_roots[0], 32);
        memcpy(receipt_roots[0], receipt_roots[1], 32);
        memcpy(receipt_roots[1], swap, 32);
    }
    uint8_t proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
    size_t proof_len = 0;
    if (vcs_zcode_proof_set_serialize(
            (const uint8_t (*)[32])receipt_roots, 2, proof_wire,
            sizeof(proof_wire), &proof_len) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])receipt_roots, 2,
            fixture->accepted.proof_set_root) != VCS_ZCODE_DEV_OK ||
        !fixture_put(dir, fixture->accepted.proof_set_root,
                     proof_wire, proof_len))
        return false;

    struct vcs_zcode_lane_receipt_v1 lane = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .lane = VCS_ZCODE_LANE_FRONTIER,
        .created_unix = now - 50,
    };
    memcpy(lane.source_root, source_root, 32);
    memcpy(lane.task_root, fixture->accepted.task_root, 32);
    memcpy(lane.candidate_root, fixture->accepted.candidate_root, 32);
    memcpy(lane.proof_policy_root, fixture->accepted.proof_policy_root, 32);
    if (!fixture_lane(dir, &lane, fixture->signer_secret,
                      fixture->signer_pubkey,
                      fixture->accepted.frontier_root))
        return false;
    fixture->accepted.frontier = lane;
    lane.lane = VCS_ZCODE_LANE_CANDIDATE;
    lane.created_unix = now - 40;
    memcpy(lane.proof_set_root, fixture->accepted.proof_set_root, 32);
    memcpy(lane.prior_receipt_root, fixture->accepted.frontier_root, 32);
    if (!fixture_lane(dir, &lane, fixture->signer_secret,
                      fixture->signer_pubkey,
                      fixture->accepted.candidate_lane_root))
        return false;
    fixture->accepted.candidate_lane = lane;
    lane.lane = VCS_ZCODE_LANE_PROVEN;
    lane.created_unix = now - 30;
    memcpy(lane.prior_receipt_root,
           fixture->accepted.candidate_lane_root, 32);
    if (!fixture_lane(dir, &lane, fixture->signer_secret,
                      fixture->signer_pubkey,
                      fixture->accepted.accepted_work_root))
        return false;
    fixture->accepted.proven = lane;
    memcpy(fixture->accepted.expected_signer, fixture->signer_pubkey, 32);
    return true;
}
