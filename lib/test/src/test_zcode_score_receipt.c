/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove canonical evidence-derived ZC23 Score receipts. */

#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "core/uint256.h"
#include "vcs/package_manifest.h"
#include "vcs/package_build.h"
#include "vcs/blob_store.h"
#include "vcs/package_prepare.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_contributor_binding.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_continuity_policy.h"
#include "vcs/zcode_epoch_creation.h"
#include "vcs/zcode_patronage.h"
#include "vcs/zcode_patronage_funding.h"
#include "vcs/zcode_patronage_projection.h"
#include "vcs/zcode_patronage_settlement.h"
#include "vcs/zcode_reproduction_qualification.h"
#include "vcs/zcode_reproduction_request.h"
#include "vcs/zcode_score_receipt.h"
#include "vcs/zcode_shadow_policy.h"
#include "vcs/zcode_shadow_simulation.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

struct score_work_fixture {
    struct vcs_zcode_work_receipt_v1 receipt;
    uint8_t root[32];
};

struct score_package_fixture {
    const char *name;
    const char *dir;
    uint64_t sequence;
    const char *content;
    const char *release;
    const char *recipe;
    const char *lock;
    const char *capsule;
    const char *publisher;
    const char *signature;
};

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) \
    {name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature},
static const struct score_package_fixture score_packages[] = {
#include "../../../config/zcode_package_registry.def"
};
#undef ZCODE_PACKAGE

#if !defined(_WIN32)

static void score_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

struct score_transport_entry {
    uint8_t semantic_root[32];
    uint8_t transport_root[32];
};

static bool score_transport_export(
    struct vcs_package_store *store, const char *workspace,
    const uint8_t semantic_root[32], struct score_transport_entry *entry)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!store || !workspace || !semantic_root || !entry ||
        vcs_object_load_raw_bounded(
            workspace, semantic_root, VCS_BLOB_MAX_BYTES,
            &wire, &wire_len) != 0)
        return false;
    memcpy(entry->semantic_root, semantic_root, 32);
    bool ok = vcs_blob_put_to(store, wire, wire_len,
                              entry->transport_root) == VCS_BLOB_OK;
    free(wire);
    return ok;
}

static bool score_transport_import(
    struct vcs_package_store *source, struct vcs_package_store *destination,
    const char *workspace, const struct score_transport_entry *entry)
{
    uint8_t wire[VCS_BLOB_MAX_BYTES], observed[32];
    size_t wire_len = 0;
    if (!source || !destination || !workspace || !entry ||
        vcs_blob_get_from(source, entry->transport_root, wire, sizeof(wire),
                          &wire_len) != VCS_BLOB_OK ||
        vcs_blob_put_to(destination, wire, wire_len, observed) !=
            VCS_BLOB_OK ||
        memcmp(observed, entry->transport_root, 32) != 0)
        return false;
    return vcs_object_store_init(workspace) &&
        vcs_object_put_addressed(workspace, entry->semantic_root,
                                 wire, wire_len);
}

static bool score_transport_package(
    struct vcs_package_store *source, struct vcs_package_store *destination,
    const char *workspace, const uint8_t package_root[32],
    bool manifest_only)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t observed[32];
    struct vcs_package_manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    if (!source || !destination || !workspace || !package_root ||
        vcs_package_store_get_manifest_wire(
            source, package_root, &wire, &wire_len) !=
            VCS_PACKAGE_STORE_OK ||
        vcs_package_store_put_manifest(destination, wire, wire_len,
                                       observed) != VCS_PACKAGE_STORE_OK ||
        memcmp(observed, package_root, 32) != 0 ||
        !vcs_package_manifest_parse(wire, wire_len, &manifest) ||
        !vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(workspace, package_root,
                                  wire, wire_len)) {
        free(wire);
        vcs_package_manifest_free(&manifest);
        return false;
    }
    free(wire);
    if (manifest_only) {
        vcs_package_manifest_free(&manifest);
        return true;
    }
    for (size_t i = 0; i < manifest.count; i++) {
        const struct vcs_package_file *file = &manifest.files[i];
        for (uint32_t j = 0; j < file->chunk_count; j++) {
            uint8_t *chunk = NULL;
            size_t chunk_len = 0;
            if (vcs_package_store_get_chunk_at(
                    source, package_root, (uint32_t)i, j,
                    &chunk, &chunk_len) != VCS_PACKAGE_STORE_OK ||
                vcs_package_store_put_chunk(
                    destination, package_root, file->path, j,
                    chunk, chunk_len) != VCS_PACKAGE_STORE_OK) {
                free(chunk);
                vcs_package_manifest_free(&manifest);
                return false;
            }
            if (strcmp(file->path, "LICENSE") == 0 &&
                !vcs_object_put_addressed(
                    workspace, file->chunk_hashes + (size_t)j * 32u,
                    chunk, chunk_len)) {
                free(chunk);
                vcs_package_manifest_free(&manifest);
                return false;
            }
            free(chunk);
        }
    }
    vcs_package_manifest_free(&manifest);
    return true;
}

static int score_work_compare(const void *left, const void *right)
{
    const struct score_work_fixture *a = left, *b = right;
    return memcmp(a->root, b->root, 32);
}

static void score_policy(struct vcs_zcode_proof_policy_v1 *policy)
{
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = VCS_ZCODE_DEV_VERSION;
    policy->required_proofs = VCS_ZCODE_PROOF_COMPILE |
        VCS_ZCODE_PROOF_TEST | VCS_ZCODE_PROOF_FUZZ |
        VCS_ZCODE_PROOF_REVIEW | VCS_ZCODE_PROOF_LOCAL_REPRODUCTION;
    policy->minimum_compile_receipts = 1;
    policy->minimum_test_receipts = 1;
    policy->minimum_fuzz_receipts = 1;
    policy->minimum_reviews = 1;
    policy->minimum_matching_receipts = 1;
    policy->flags = VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS |
        VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY;
    policy->deterministic_fuzz_seeds = 1;
    policy->audit_basis_points = 100;
    policy->maximum_proof_age_seconds = 3600;
}

static bool score_fixture_for_roots(
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy,
    struct vcs_zcode_lane_receipt_v1 *lane,
    struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS],
    uint8_t lane_secret[32], uint8_t lane_pubkey[32],
    const uint8_t source_root[32], const uint8_t lock_root[32],
    const uint8_t capsule_root[32], const uint8_t author_pubkey[32])
{
    score_policy(policy);
    uint8_t policy_root[32], task_root[32], candidate_root[32];
    if (vcs_zcode_proof_policy_root(policy, policy_root) != VCS_ZCODE_DEV_OK)
        return false;
    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(task->source_root, source_root, 32);
    memcpy(task->dependency_lock_root, lock_root, 32);
    memcpy(task->toolchain_capsule_root, capsule_root, 32);
    score_fill(task->write_scope_root, 4);
    score_fill(task->acceptance_tests_root, 5);
    memcpy(task->proof_policy_root, policy_root, 32);
    score_fill(task->model_policy_root, 7);
    score_fill(task->goal_root, 8);
    task->capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task->max_changed_files = 8;
    task->max_patch_bytes = 4096;
    task->max_context_bytes = 4096;
    task->max_cpu_seconds = 60;
    task->max_memory_bytes = 1024 * 1024;
    task->max_output_bytes = 1024 * 1024;
    task->expires_unix = 5000;
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK)
        return false;
    memset(candidate, 0, sizeof(*candidate));
    candidate->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(candidate->task_root, task_root, 32);
    memcpy(candidate->base_source_root, task->source_root, 32);
    score_fill(candidate->patch_root, 9);
    memcpy(candidate->candidate_source_root, task->source_root, 32);
    score_fill(candidate->adapter_policy_root, 11);
    if (author_pubkey)
        memcpy(candidate->author_pubkey, author_pubkey, 32);
    else
        score_fill(candidate->author_pubkey, 12);
    candidate->sequence = 1;
    candidate->created_unix = 1000;
    if (vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK)
        return false;
    for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
        struct vcs_zcode_work_receipt_v1 *work = &works[i].receipt;
        memset(work, 0, sizeof(*work));
        work->schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(work->task_root, task_root, 32);
        memcpy(work->candidate_root, candidate_root, 32);
        vcs_zcode_score_action_root((enum vcs_zcode_score_unit)i,
                                    work->action_root);
        score_fill(work->input_root, (uint8_t)(20 + i));
        score_fill(work->output_root, (uint8_t)(30 + i));
        memcpy(work->proof_policy_root, policy_root, 32);
        memcpy(work->toolchain_capsule_root,
               task->toolchain_capsule_root, 32);
        score_fill(work->lease_id, (uint8_t)(40 + i));
        struct sha3_256_ctx evidence_sha;
        static const char evidence_domain[] =
            "zcl.zcode.selfhost_vertical_evidence.v1";
        sha3_256_init(&evidence_sha);
        sha3_256_write(&evidence_sha, (const uint8_t *)evidence_domain,
                       sizeof(evidence_domain));
        sha3_256_write(&evidence_sha, source_root, 32);
        sha3_256_write(&evidence_sha, work->action_root, 32);
        sha3_256_finalize(&evidence_sha, work->evidence_root);
        score_fill(work->confinement_root, (uint8_t)(60 + i));
        static const uint8_t kinds[VCS_ZCODE_SCORE_UNITS] = {
            VCS_ZCODE_WORK_REVIEW, VCS_ZCODE_WORK_TEST,
            VCS_ZCODE_WORK_REPRODUCE, VCS_ZCODE_WORK_BUILD,
            VCS_ZCODE_WORK_BUILD,
        };
        work->work_kind = kinds[i];
        work->status = VCS_ZCODE_WORK_PASS;
        work->started_unix = 1100 + (int64_t)i;
        work->finished_unix = 1200 + (int64_t)i;
        uint8_t seed[32], secret[32], pubkey[32];
        score_fill(seed, (uint8_t)(70 + i));
        ed25519_keypair(pubkey, secret, seed);
        if (vcs_zcode_work_receipt_seal(work, secret, pubkey) !=
                VCS_ZCODE_DEV_OK ||
            vcs_zcode_work_receipt_id(work, works[i].root) !=
                VCS_ZCODE_DEV_OK)
            return false;
    }
    qsort(works, VCS_ZCODE_SCORE_UNITS, sizeof(works[0]),
          score_work_compare);
    uint8_t proof_roots[VCS_ZCODE_SCORE_UNITS][32], proof_set_root[32];
    for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++)
        memcpy(proof_roots[i], works[i].root, 32);
    if (vcs_zcode_proof_set_root(proof_roots, VCS_ZCODE_SCORE_UNITS,
                                 proof_set_root) != VCS_ZCODE_DEV_OK)
        return false;
    memset(lane, 0, sizeof(*lane));
    lane->schema_version = VCS_ZCODE_DEV_VERSION;
    lane->lane = VCS_ZCODE_LANE_PROVEN;
    memcpy(lane->source_root, candidate->candidate_source_root, 32);
    memcpy(lane->task_root, task_root, 32);
    memcpy(lane->candidate_root, candidate_root, 32);
    memcpy(lane->proof_policy_root, policy_root, 32);
    memcpy(lane->proof_set_root, proof_set_root, 32);
    score_fill(lane->prior_receipt_root, 90);
    lane->created_unix = 1400;
    uint8_t lane_seed[32]; score_fill(lane_seed, 91);
    ed25519_keypair(lane_pubkey, lane_secret, lane_seed);
    return vcs_zcode_lane_receipt_seal(lane, lane_secret, lane_pubkey) ==
           VCS_ZCODE_DEV_OK;
}

static bool score_fixture(
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy,
    struct vcs_zcode_lane_receipt_v1 *lane,
    struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS],
    uint8_t lane_secret[32], uint8_t lane_pubkey[32])
{
    uint8_t source[32], lock[32], capsule[32];
    return zcl_hex_decode_lower(
               "ea54d7038792764c059a697792d46ee92fe75e29aa302d3c8db3a208a580876e",
               source, sizeof(source)) &&
        zcl_hex_decode_lower(
               "a32339729bd0a4e0cf723238faa4c1ad378d93f7de4bad84591781fc782d92a3",
               lock, sizeof(lock)) &&
        zcl_hex_decode_lower(
               "c0c3ec6514fd2a7ea242e087aff75b33fdc208a219c61855788509efef37b15d",
               capsule, sizeof(capsule)) &&
        score_fixture_for_roots(task, candidate, policy, lane, works,
                                lane_secret, lane_pubkey, source, lock,
                                capsule, NULL);
}

static int test_score_happy_path(void)
{
    int failures = 0;
    TEST("zcode score: fixed actions derive signed score with off-host credit withheld") {
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_proof_policy_v1 policy;
        struct vcs_zcode_lane_receipt_v1 lane;
        struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS];
        uint8_t secret[32], pubkey[32];
        ASSERT(score_fixture(&task, &candidate, &policy, &lane, works,
                             secret, pubkey));
        uint8_t proof_roots[VCS_ZCODE_SCORE_UNITS][32];
        struct vcs_zcode_work_receipt_v1 receipts[VCS_ZCODE_SCORE_UNITS];
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            memcpy(proof_roots[i], works[i].root, 32);
            receipts[i] = works[i].receipt;
        }
        uint8_t package[32], release[32], recipe[32];
        ASSERT(zcl_hex_decode_lower(
            "ea54d7038792764c059a697792d46ee92fe75e29aa302d3c8db3a208a580876e",
            package, 32));
        ASSERT(zcl_hex_decode_lower(
            "17f33b8f5be818a1a396d7c9bf04de1c11926af9e6d1118b313a9ac0a6335af8",
            release, 32));
        ASSERT(zcl_hex_decode_lower(
            "71280e02ba1ec0c8006b28a8c325657cc2d2f5547b70a19442d91411199f7b49",
            recipe, 32));
        struct vcs_zcode_score_plan_input input = {
            .task = &task, .candidate = &candidate,
            .proof_policy = &policy, .proven_lane = &lane,
            .proof_receipt_roots = proof_roots,
            .work_receipts = receipts,
            .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
            .package_root = package, .release_root = release,
            .recipe_root = recipe,
            .dependency_lock_root = task.dependency_lock_root,
            .api_capsule_root = task.toolchain_capsule_root,
        };
        struct vcs_zcode_score_receipt_v1 score, parsed;
        ASSERT_EQ(vcs_zcode_score_plan(&input, &score), VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(score.score, 4);
        ASSERT_EQ(score.awarded_mask, 0x1b);
        ASSERT(score.evidence_roots[2][0] != 0);
        ASSERT(!vcs_zcode_score_offhost_reproducer_approved(
            receipts[0].signer_pubkey));
        ASSERT_EQ(vcs_zcode_score_receipt_seal(&score, secret, pubkey),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_score_receipt_verify(&score),
                  VCS_ZCODE_SCORE_OK);
        uint8_t wire[VCS_ZCODE_SCORE_WIRE_BYTES], id[32], parsed_id[32];
        ASSERT_EQ(vcs_zcode_score_receipt_serialize(&score, wire),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_score_receipt_parse(wire, sizeof(wire), &parsed),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_score_receipt_id(&score, id),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_score_receipt_id(&parsed, parsed_id),
                  VCS_ZCODE_SCORE_OK);
        ASSERT(memcmp(id, parsed_id, 32) == 0);
        ASSERT_EQ(vcs_zcode_score_receipt_parse(wire, sizeof(wire) - 1,
                                                &parsed),
                  VCS_ZCODE_SCORE_SHAPE);
        wire[12] = 1;
        ASSERT_EQ(vcs_zcode_score_receipt_parse(wire, sizeof(wire), &parsed),
                  VCS_ZCODE_SCORE_SHAPE);
        wire[12] = 0;

        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace), "zcode_score", "cas");
        ASSERT(vcs_object_store_init(workspace));
        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
        uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
        uint8_t lane_wire[VCS_ZCODE_LANE_WIRE_BYTES];
        uint8_t proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX]; size_t proof_len = 0;
        ASSERT_EQ(vcs_zcode_task_serialize(&task, task_wire), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_candidate_serialize(&candidate, candidate_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_serialize(&policy, policy_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_serialize(&lane, lane_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_set_serialize(
                      proof_roots, VCS_ZCODE_SCORE_UNITS, proof_wire,
                      sizeof(proof_wire), &proof_len), VCS_ZCODE_DEV_OK);
        uint8_t task_root[32], candidate_root[32], policy_root[32];
        uint8_t proof_set_root[32], lane_root[32];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_candidate_root(&candidate, candidate_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_set_root(
                      proof_roots, VCS_ZCODE_SCORE_UNITS, proof_set_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_id(&lane, lane_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(workspace, task_root, task_wire,
                                         sizeof(task_wire)));
        ASSERT(vcs_object_put_addressed(workspace, candidate_root,
                                         candidate_wire,
                                         sizeof(candidate_wire)));
        ASSERT(vcs_object_put_addressed(workspace, policy_root, policy_wire,
                                         sizeof(policy_wire)));
        ASSERT(vcs_object_put_addressed(workspace, proof_set_root, proof_wire,
                                         proof_len));
        ASSERT(vcs_object_put_addressed(workspace, lane_root, lane_wire,
                                         sizeof(lane_wire)));
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            uint8_t work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
            ASSERT_EQ(vcs_zcode_work_receipt_serialize(
                          &receipts[i], work_wire), VCS_ZCODE_DEV_OK);
            ASSERT(vcs_object_put_addressed(workspace, proof_roots[i],
                                             work_wire, sizeof(work_wire)));
        }
        char task_hex[sizeof(task_wire) * 2u + 1u];
        char candidate_hex[sizeof(candidate_wire) * 2u + 1u];
        char policy_hex[sizeof(policy_wire) * 2u + 1u];
        char lane_hex[sizeof(lane_wire) * 2u + 1u];
        char proof_hex[VCS_ZCODE_PROOF_SET_WIRE_MAX * 2u + 1u];
        char package_hex[65], release_hex[65], recipe_hex[65];
        char lock_hex[65], capsule_hex[65], score_wire_hex[1185];
        zcl_hex_encode(task_wire, sizeof(task_wire), task_hex);
        zcl_hex_encode(candidate_wire, sizeof(candidate_wire), candidate_hex);
        zcl_hex_encode(policy_wire, sizeof(policy_wire), policy_hex);
        zcl_hex_encode(lane_wire, sizeof(lane_wire), lane_hex);
        zcl_hex_encode(proof_wire, proof_len, proof_hex);
        zcl_hex_encode(package, 32, package_hex);
        zcl_hex_encode(release, 32, release_hex);
        zcl_hex_encode(recipe, 32, recipe_hex);
        zcl_hex_encode(task.dependency_lock_root, 32, lock_hex);
        zcl_hex_encode(task.toolchain_capsule_root, 32, capsule_hex);
        zcl_hex_encode(wire, sizeof(wire), score_wire_hex);
        struct json_value plan_input;
        json_init(&plan_input); json_set_object(&plan_input);
#define SCORE_PLAN_STR(key, value) ASSERT(json_push_kv_str(&plan_input, key, value))
        SCORE_PLAN_STR("workspace", workspace);
        SCORE_PLAN_STR("task_hex", task_hex);
        SCORE_PLAN_STR("candidate_hex", candidate_hex);
        SCORE_PLAN_STR("proof_policy_hex", policy_hex);
        SCORE_PLAN_STR("proof_set_hex", proof_hex);
        SCORE_PLAN_STR("proven_lane_hex", lane_hex);
        SCORE_PLAN_STR("package_root", package_hex);
        SCORE_PLAN_STR("release_root", release_hex);
        SCORE_PLAN_STR("recipe_root", recipe_hex);
        SCORE_PLAN_STR("dependency_lock_root", lock_hex);
        SCORE_PLAN_STR("api_capsule_root", capsule_hex);
#undef SCORE_PLAN_STR
        struct zcl_command_request plan_request = { .input = &plan_input };
        struct zcl_command_reply plan_reply;
        zcl_command_reply_init(&plan_reply, "zcl.zcode_score_test.v1");
        zcl_native_handle_zcode_package_dev_score_plan(&plan_request,
                                                       &plan_reply);
        ASSERT_EQ(plan_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&plan_reply.data, "score")), 4);
        ASSERT(!json_get_bool(json_get(&plan_reply.data, "persisted")));
        zcl_command_reply_free(&plan_reply); json_free(&plan_input);

        struct json_value commit_input;
        json_init(&commit_input); json_set_object(&commit_input);
        ASSERT(json_push_kv_str(&commit_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&commit_input, "receipt_hex", score_wire_hex));
        struct zcl_command_request commit_request = { .input = &commit_input };
        struct zcl_command_reply commit_reply;
        zcl_command_reply_init(&commit_reply, "zcl.zcode_score_test.v1");
        zcl_native_handle_zcode_package_dev_score_commit(&commit_request,
                                                         &commit_reply);
        ASSERT_EQ(commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const char *stored_root = json_get_str(json_get(
            &commit_reply.data, "score_receipt_root"));
        ASSERT(stored_root != NULL);
        char stored_root_copy[65];
        (void)snprintf(stored_root_copy, sizeof(stored_root_copy), "%s",
                       stored_root);
        zcl_command_reply_free(&commit_reply); json_free(&commit_input);

        struct json_value show_input;
        json_init(&show_input); json_set_object(&show_input);
        ASSERT(json_push_kv_str(&show_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&show_input, "root", stored_root_copy));
        struct zcl_command_request show_request = { .input = &show_input };
        struct zcl_command_reply show_reply;
        zcl_command_reply_init(&show_reply, "zcl.zcode_score_test.v1");
        zcl_native_handle_zcode_package_dev_score_show(&show_request,
                                                       &show_reply);
        ASSERT_EQ(show_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&show_reply.data, "score")), 4);
        zcl_command_reply_free(&show_reply); json_free(&show_input);
        test_rm_rf(workspace);

        score.awarded_mask |= 1u << 2;
        score.score = 5;
        ASSERT_EQ(vcs_zcode_score_receipt_verify(&score),
                  VCS_ZCODE_SCORE_SHAPE);
        PASS();
    } _test_next:;
    return failures;
}

static bool score_store_vertical(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct vcs_zcode_lane_receipt_v1 *lane,
    const struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS],
    const struct vcs_zcode_score_receipt_v1 *score,
    uint8_t task_root[32], uint8_t candidate_root[32],
    uint8_t proof_set_root[32], uint8_t lane_root[32],
    uint8_t score_root[32])
{
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    uint8_t lane_wire[VCS_ZCODE_LANE_WIRE_BYTES];
    uint8_t proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
    uint8_t score_wire[VCS_ZCODE_SCORE_WIRE_BYTES];
    uint8_t policy_root[32], proof_roots[VCS_ZCODE_SCORE_UNITS][32];
    size_t proof_len = 0;
    for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++)
        memcpy(proof_roots[i], works[i].root, 32);
    if (vcs_zcode_task_serialize(task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_serialize(policy, policy_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_lane_receipt_serialize(lane, lane_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_serialize(
            proof_roots, VCS_ZCODE_SCORE_UNITS, proof_wire,
            sizeof(proof_wire), &proof_len) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_score_receipt_serialize(score, score_wire) !=
            VCS_ZCODE_SCORE_OK ||
        vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(policy, policy_root) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(proof_roots, VCS_ZCODE_SCORE_UNITS,
                                 proof_set_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_lane_receipt_id(lane, lane_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_score_receipt_id(score, score_root) !=
            VCS_ZCODE_SCORE_OK)
        return false;
    if (!vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(workspace, task_root, task_wire,
                                  sizeof(task_wire)) ||
        !vcs_object_put_addressed(workspace, candidate_root, candidate_wire,
                                  sizeof(candidate_wire)) ||
        !vcs_object_put_addressed(workspace, policy_root, policy_wire,
                                  sizeof(policy_wire)) ||
        !vcs_object_put_addressed(workspace, proof_set_root, proof_wire,
                                  proof_len) ||
        !vcs_object_put_addressed(workspace, lane_root, lane_wire,
                                  sizeof(lane_wire)) ||
        !vcs_object_put_addressed(workspace, score_root, score_wire,
                                  sizeof(score_wire)))
        return false;
    for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
        uint8_t work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        if (vcs_zcode_work_receipt_serialize(&works[i].receipt, work_wire) !=
                VCS_ZCODE_DEV_OK ||
            !vcs_object_put_addressed(workspace, works[i].root, work_wire,
                                      sizeof(work_wire)))
            return false;
    }
    return true;
}

static int test_score_package_verticals(void)
{
    int failures = 0;
    TEST("zcode score: SHA3, base, then codec complete hermetic PROVEN verticals") {
        static const size_t evidence_order[] = {1, 0, 2};
        static const char *const scratch_labels[] = {"sha3", "base", "codec"};
        ASSERT(sizeof(score_packages) / sizeof(score_packages[0]) >= 3);
        for (size_t order = 0;
             order < sizeof(evidence_order) / sizeof(evidence_order[0]);
             order++) {
            const struct score_package_fixture *package =
                &score_packages[evidence_order[order]];
            uint8_t content[32], release[32], recipe[32], lock[32], capsule[32];
            ASSERT(zcl_hex_decode_lower(package->content, content, 32));
            ASSERT(zcl_hex_decode_lower(package->release, release, 32));
            ASSERT(zcl_hex_decode_lower(package->recipe, recipe, 32));
            ASSERT(zcl_hex_decode_lower(package->lock, lock, 32));
            ASSERT(zcl_hex_decode_lower(package->capsule, capsule, 32));
            struct vcs_zcode_task_v1 task;
            struct vcs_zcode_candidate_v1 candidate;
            struct vcs_zcode_proof_policy_v1 policy;
            struct vcs_zcode_lane_receipt_v1 lane;
            struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS];
            uint8_t secret[32], pubkey[32];
            ASSERT(score_fixture_for_roots(
                &task, &candidate, &policy, &lane, works, secret, pubkey,
                content, lock, capsule, NULL));
            uint8_t proof_roots[VCS_ZCODE_SCORE_UNITS][32];
            struct vcs_zcode_work_receipt_v1
                receipts[VCS_ZCODE_SCORE_UNITS];
            for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
                memcpy(proof_roots[i], works[i].root, 32);
                receipts[i] = works[i].receipt;
            }
            struct vcs_zcode_score_plan_input input = {
                .task = &task, .candidate = &candidate,
                .proof_policy = &policy, .proven_lane = &lane,
                .proof_receipt_roots = proof_roots,
                .work_receipts = receipts,
                .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
                .package_root = content, .release_root = release,
                .recipe_root = recipe, .dependency_lock_root = lock,
                .api_capsule_root = capsule,
            };
            struct vcs_zcode_score_receipt_v1 score;
            ASSERT_EQ(vcs_zcode_score_plan(&input, &score),
                      VCS_ZCODE_SCORE_OK);
            ASSERT_EQ(score.awarded_mask, 0x1b);
            ASSERT_EQ(score.score, 4);
            ASSERT_EQ(vcs_zcode_score_receipt_seal(&score, secret, pubkey),
                      VCS_ZCODE_SCORE_OK);
            ASSERT_EQ(vcs_zcode_score_receipt_verify(&score),
                      VCS_ZCODE_SCORE_OK);
            char workspace[256];
            test_make_tmpdir(workspace, sizeof(workspace),
                             "zcode_selfhost_vertical",
                             scratch_labels[order]);
            uint8_t task_root[32], candidate_root[32], proof_set_root[32];
            uint8_t policy_root[32], lane_root[32], score_root[32];
            ASSERT(score_store_vertical(
                workspace, &task, &candidate, &policy, &lane, works,
                &score, task_root, candidate_root, proof_set_root,
                lane_root, score_root));
            ASSERT_EQ(vcs_zcode_score_receipt_verify_cas(workspace, &score),
                      VCS_ZCODE_SCORE_OK);
            struct vcs_zcode_score_receipt_v1 substituted_score = score;
            substituted_score.task_root[0] ^= 1u;
            ASSERT_EQ(vcs_zcode_score_receipt_verify_cas(
                          workspace, &substituted_score),
                      VCS_ZCODE_SCORE_SIGNATURE);
            ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                      VCS_ZCODE_DEV_OK);
            char task_hex[65], candidate_hex[65], policy_hex[65];
            char proof_hex[65];
            char lane_hex[65], score_hex[65];
            zcl_hex_encode(task_root, 32, task_hex);
            zcl_hex_encode(candidate_root, 32, candidate_hex);
            zcl_hex_encode(policy_root, 32, policy_hex);
            zcl_hex_encode(proof_set_root, 32, proof_hex);
            zcl_hex_encode(lane_root, 32, lane_hex);
            zcl_hex_encode(score_root, 32, score_hex);
            printf("zcode selfhost vertical: %s task=%s candidate=%s policy=%s proof_set=%s proven_lane=%s score_receipt=%s\n",
                   package->name, task_hex, candidate_hex, policy_hex,
                   proof_hex, lane_hex, score_hex);
            for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
                char evidence_hex[65], work_hex[65];
                zcl_hex_encode(score.evidence_roots[i], 32, evidence_hex);
                zcl_hex_encode(works[i].root, 32, work_hex);
                printf("zcode selfhost evidence: %s %s=%s work_receipt=%s awarded=%s\n",
                       package->name,
                       vcs_zcode_score_unit_name(
                           (enum vcs_zcode_score_unit)i),
                       evidence_hex, work_hex,
                           (score.awarded_mask & (UINT8_C(1) << i))
                           ? "true" : "false");
            }
            if (strcmp(package->name, "zclassic23/sha3") == 0) {
                struct json_value shadow_input;
                json_init(&shadow_input); json_set_object(&shadow_input);
                ASSERT(json_push_kv_str(&shadow_input, "workspace",
                                        workspace));
                ASSERT(json_push_kv_str(&shadow_input,
                                        "score_receipt_root", score_hex));
                struct zcl_command_request shadow_request = {
                    .input = &shadow_input,
                };
                struct zcl_command_reply shadow_reply;
                zcl_command_reply_init(&shadow_reply,
                                       "zcl.test.commons_shadow.v1");
                zcl_native_handle_zcode_commons_shadow_plan(
                    &shadow_request, &shadow_reply);
                ASSERT(shadow_reply.exit_code != ZCL_COMMAND_EXIT_OK);
                zcl_command_reply_free(&shadow_reply);
                json_free(&shadow_input);
            }
            test_rm_rf(workspace);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_score_rejections(void)
{
    int failures = 0;
    TEST("zcode score: stale bindings and duplicate registered actions fail closed") {
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_proof_policy_v1 policy;
        struct vcs_zcode_lane_receipt_v1 lane;
        struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS];
        uint8_t secret[32], pubkey[32];
        ASSERT(score_fixture(&task, &candidate, &policy, &lane, works,
                             secret, pubkey));
        uint8_t accepted_action[32], born_red_action[32];
        vcs_zcode_score_action_root(VCS_ZCODE_SCORE_ACCEPTED_EXTRACTION,
                                    accepted_action);
        vcs_zcode_score_action_root(VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST,
                                    born_red_action);
        size_t accepted = VCS_ZCODE_SCORE_UNITS;
        size_t born_red = VCS_ZCODE_SCORE_UNITS;
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            if (memcmp(works[i].receipt.action_root, accepted_action, 32) == 0)
                accepted = i;
            if (memcmp(works[i].receipt.action_root, born_red_action, 32) == 0)
                born_red = i;
        }
        ASSERT(accepted < VCS_ZCODE_SCORE_UNITS);
        ASSERT(born_red < VCS_ZCODE_SCORE_UNITS);
        memcpy(works[born_red].receipt.action_root, accepted_action, 32);
        works[born_red].receipt.work_kind = VCS_ZCODE_WORK_REVIEW;
        uint8_t seed[32], worker_secret[32], worker_pubkey[32];
        score_fill(seed, 110);
        ed25519_keypair(worker_pubkey, worker_secret, seed);
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
                      &works[born_red].receipt, worker_secret, worker_pubkey),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_id(
                      &works[born_red].receipt, works[born_red].root),
                  VCS_ZCODE_DEV_OK);
        qsort(works, VCS_ZCODE_SCORE_UNITS, sizeof(works[0]),
              score_work_compare);
        uint8_t roots[VCS_ZCODE_SCORE_UNITS][32];
        struct vcs_zcode_work_receipt_v1 receipts[VCS_ZCODE_SCORE_UNITS];
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            memcpy(roots[i], works[i].root, 32);
            receipts[i] = works[i].receipt;
        }
        ASSERT_EQ(vcs_zcode_proof_set_root(
                      roots, VCS_ZCODE_SCORE_UNITS, lane.proof_set_root),
                  VCS_ZCODE_DEV_OK);
        memset(lane.signature, 0, sizeof(lane.signature));
        ASSERT_EQ(vcs_zcode_lane_receipt_seal(
                      &lane, secret, pubkey), VCS_ZCODE_DEV_OK);
        uint8_t package[32], release[32], recipe[32];
        score_fill(package, 101); score_fill(release, 102);
        score_fill(recipe, 103);
        struct vcs_zcode_score_plan_input input = {
            .task = &task, .candidate = &candidate,
            .proof_policy = &policy, .proven_lane = &lane,
            .proof_receipt_roots = roots, .work_receipts = receipts,
            .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
            .package_root = package, .release_root = release,
            .recipe_root = recipe,
            .dependency_lock_root = task.dependency_lock_root,
            .api_capsule_root = task.toolchain_capsule_root,
        };
        struct vcs_zcode_score_receipt_v1 score;
        uint8_t stale[32]; score_fill(stale, 104);
        input.api_capsule_root = stale;
        ASSERT_EQ(vcs_zcode_score_plan(&input, &score),
                  VCS_ZCODE_SCORE_BINDING);
        input.api_capsule_root = task.toolchain_capsule_root;
        ASSERT_EQ(vcs_zcode_score_plan(&input, &score),
                  VCS_ZCODE_SCORE_DUPLICATE);
        PASS();
    } _test_next:;
    return failures;
}

struct creation_callback_fixture {
    bool anchor_active;
    bool duplicate;
    bool continuity_duplicate;
    uint64_t opening_height;
    uint8_t opening_hash[32];
    uint64_t maturity_height;
    uint8_t maturity_hash[32];
    uint64_t expected_award_atoms;
    uint64_t security_award_atoms;
    uint16_t last_award_category;
};

static bool creation_test_anchor(void *opaque, uint64_t height,
                                 const uint8_t hash[32])
{
    const struct creation_callback_fixture *fixture = opaque;
    return fixture && fixture->anchor_active &&
           ((height == fixture->opening_height &&
             memcmp(hash, fixture->opening_hash, 32) == 0) ||
            (height == fixture->maturity_height &&
             memcmp(hash, fixture->maturity_hash, 32) == 0));
}

static bool creation_test_continuity_duplicate(
    void *opaque, const uint8_t event_key[32],
    const uint8_t attribution_root[32])
{
    const struct creation_callback_fixture *fixture = opaque;
    (void)event_key;
    (void)attribution_root;
    return fixture && fixture->continuity_duplicate;
}

static bool creation_test_duplicate(void *opaque,
                                    const uint8_t candidate_root[32],
                                    const uint8_t attribution_root[32])
{
    const struct creation_callback_fixture *fixture = opaque;
    (void)candidate_root;
    (void)attribution_root;
    return fixture && fixture->duplicate;
}

static bool creation_test_award(
    void *opaque,
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint64_t *expected_atoms)
{
    struct creation_callback_fixture *fixture = opaque;
    if (expected_atoms) *expected_atoms = 0;
    if (!fixture || !attribution || !expected_atoms)
        return false;
    fixture->last_award_category = attribution->category;
    *expected_atoms =
        attribution->category == VCS_ZCODE_CREATION_SECURITY_FIX &&
                fixture->security_award_atoms != 0
            ? fixture->security_award_atoms
            : fixture->expected_award_atoms;
    return true;
}

static bool creation_test_keypair(uint8_t value, struct privkey *secret,
                                  struct pubkey *pubkey)
{
    memset(secret->vch, value, 32);
    secret->fValid = true;
    secret->fCompressed = true;
    return privkey_get_pubkey(secret, pubkey) &&
           pubkey->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool creation_test_release(struct vcs_package_release *release,
                                  const uint8_t package_root[32],
                                  const uint8_t recipe_root[32])
{
    struct privkey secret;
    struct pubkey pubkey;
    if (!creation_test_keypair(0x31, &secret, &pubkey))
        return false;
    memset(release, 0, sizeof(*release));
    release->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    (void)snprintf(release->name, sizeof(release->name), "commons/work");
    (void)snprintf(release->semver, sizeof(release->semver), "0.1.0");
    memcpy(release->package_root, package_root, 32);
    memcpy(release->publisher_pubkey, pubkey.vch, 33);
    release->publisher_sequence = 1;
    (void)snprintf(release->license, sizeof(release->license), "MIT");
    memcpy(release->recipe_root, recipe_root, 32);
    (void)snprintf(release->chain_id, sizeof(release->chain_id),
                   "zclassic-main");
    uint8_t id[32];
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (vcs_package_release_id(release, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    memcpy(hash.data, id, 32);
    if (!privkey_sign_compact(&secret, &hash, compact))
        return false;
    memcpy(release->signature, compact + 1, 64);
    return vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK;
}

static bool creation_test_child_release(
    struct vcs_package_release *release,
    const struct vcs_package_release *parent,
    const uint8_t parent_root[32], const uint8_t package_root[32],
    const uint8_t recipe_root[32])
{
    if (!release || !parent || !parent_root || !package_root || !recipe_root)
        return false;
    struct privkey secret;
    struct pubkey pubkey;
    if (!creation_test_keypair(0x31, &secret, &pubkey))
        return false;
    *release = *parent;
    (void)snprintf(release->semver, sizeof(release->semver), "0.1.1");
    memcpy(release->package_root, package_root, 32);
    release->has_parent = true;
    memcpy(release->parent_root, parent_root, 32);
    release->publisher_sequence = parent->publisher_sequence + 1;
    memcpy(release->recipe_root, recipe_root, 32);
    memset(release->signature, 0, sizeof(release->signature));
    uint8_t id[32];
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (vcs_package_release_id(release, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    memcpy(hash.data, id, 32);
    if (!privkey_sign_compact(&secret, &hash, compact))
        return false;
    memcpy(release->signature, compact + 1, 64);
    return vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK;
}

static bool creation_test_binding(
    struct vcs_zcode_contributor_binding_v1 *binding,
    const uint8_t network[32], uint8_t zid_pubkey[32],
    uint8_t zid_secret[32])
{
    uint8_t zid_seed[32], zcl_secret[32];
    memset(zid_seed, 0x41, sizeof(zid_seed));
    memset(zcl_secret, 0x42, sizeof(zcl_secret));
    ed25519_keypair(zid_pubkey, zid_secret, zid_seed);
    struct privkey secret;
    struct pubkey pubkey;
    if (!creation_test_keypair(0x42, &secret, &pubkey))
        return false;
    memset(binding, 0, sizeof(*binding));
    binding->schema_version = VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION;
    memcpy(binding->network_genesis_root, network, 32);
    memcpy(binding->zid_pubkey, zid_pubkey, 32);
    memcpy(binding->zcl_pubkey, pubkey.vch, 33);
    struct key_id key_id = pubkey_get_id(&pubkey);
    memcpy(binding->zcl_key_id, key_id.id.data, 20);
    binding->sequence = 1;
    binding->issued_unix = 100;
    binding->expires_unix = 1000000;
    binding->operation = VCS_ZCODE_BINDING_ACTIVE;
    return vcs_zcode_contributor_binding_seal(
               binding, zid_secret, zid_pubkey, zcl_secret) ==
           VCS_ZCODE_BINDING_OK;
}

static bool qualification_test_binding(
    struct vcs_zcode_contributor_binding_v1 *binding,
    const uint8_t network[32], uint8_t zid_value, uint8_t zcl_value,
    uint8_t zid_pubkey[32], uint8_t zid_secret[32])
{
    uint8_t zid_seed[32], zcl_secret[32];
    memset(zid_seed, zid_value, sizeof(zid_seed));
    memset(zcl_secret, zcl_value, sizeof(zcl_secret));
    ed25519_keypair(zid_pubkey, zid_secret, zid_seed);
    struct privkey secret;
    struct pubkey pubkey;
    if (!creation_test_keypair(zcl_value, &secret, &pubkey)) return false;
    memset(binding, 0, sizeof(*binding));
    binding->schema_version = VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION;
    memcpy(binding->network_genesis_root, network, 32);
    memcpy(binding->zid_pubkey, zid_pubkey, 32);
    memcpy(binding->zcl_pubkey, pubkey.vch, 33);
    struct key_id key_id = pubkey_get_id(&pubkey);
    memcpy(binding->zcl_key_id, key_id.id.data, 20);
    binding->sequence = 1;
    binding->issued_unix = 100;
    binding->expires_unix = 10000;
    binding->operation = VCS_ZCODE_BINDING_ACTIVE;
    return vcs_zcode_contributor_binding_seal(
               binding, zid_secret, zid_pubkey, zcl_secret) ==
           VCS_ZCODE_BINDING_OK;
}

static int test_patronage_intent_cross_validation(void)
{
    int failures = 0;
    TEST("ZC23 patronage intent: CAS authorities rederive or fail closed") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_patronage", "cas");
        ASSERT(vcs_object_store_init(workspace));
        uint8_t network[32], zid_pubkey[32], zid_secret[32];
        score_fill(network, 0xc1);
        struct vcs_zcode_contributor_binding_v1 binding;
        ASSERT(creation_test_binding(&binding, network, zid_pubkey,
                                     zid_secret));
        uint8_t binding_root[32];
        uint8_t binding_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_contributor_binding_root(&binding, binding_root),
                  VCS_ZCODE_BINDING_OK);
        ASSERT_EQ(vcs_zcode_contributor_binding_serialize(
                      &binding, binding_wire), VCS_ZCODE_BINDING_OK);
        ASSERT(vcs_object_put_addressed(workspace, binding_root,
                                        binding_wire, sizeof(binding_wire)));

        struct vcs_zcode_proof_policy_v1 policy;
        score_policy(&policy);
        uint8_t policy_root[32];
        uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_proof_policy_root(&policy, policy_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_serialize(&policy, policy_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(workspace, policy_root, policy_wire,
                                        sizeof(policy_wire)));

        struct vcs_zcode_task_v1 task;
        memset(&task, 0, sizeof(task));
        task.schema_version = VCS_ZCODE_DEV_VERSION;
        score_fill(task.source_root, 1);
        score_fill(task.dependency_lock_root, 2);
        score_fill(task.toolchain_capsule_root, 3);
        score_fill(task.write_scope_root, 4);
        score_fill(task.acceptance_tests_root, 5);
        memcpy(task.proof_policy_root, policy_root, 32);
        score_fill(task.model_policy_root, 6);
        score_fill(task.goal_root, 7);
        task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
        task.max_changed_files = 4;
        task.max_patch_bytes = 4096;
        task.max_context_bytes = 4096;
        task.max_cpu_seconds = 60;
        task.max_memory_bytes = 1024 * 1024;
        task.max_output_bytes = 1024 * 1024;
        task.expires_unix = 5000;
        uint8_t task_root[32], task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_task_serialize(&task, task_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(workspace, task_root, task_wire,
                                        sizeof(task_wire)));

        struct vcs_zcode_patronage_intent_v1 intent;
        memset(&intent, 0, sizeof(intent));
        intent.schema_version = VCS_ZCODE_PATRONAGE_INTENT_VERSION;
        intent.mode = VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION;
        intent.target_kind = VCS_ZCODE_PATRONAGE_TARGET_TASK;
        intent.settlement_trust_mode = VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER;
        intent.flags = VCS_ZCODE_PATRONAGE_NO_AUTHORITY |
                       VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
        memcpy(intent.network_genesis_root, network, 32);
        score_fill(intent.zc23_token_or_simulation_root, 8);
        memcpy(intent.patron_contributor_binding_root, binding_root, 32);
        memcpy(intent.patron_zid_pubkey, zid_pubkey, 32);
        memcpy(intent.target_root, task_root, 32);
        memcpy(intent.task_root, task_root, 32);
        memcpy(intent.proof_policy_root, policy_root, 32);
        memcpy(intent.intended_recipient_binding_root, binding_root, 32);
        intent.amount_atoms = 100000000;
        intent.created_unix = 1000;
        intent.expires_unix = 2000;
        intent.refund_height = 3000;
        intent.refund_unix = 2100;
        intent.sequence = 1;
        intent.maximum_zcl_fee_zat = 10000;
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(
                      &intent, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        struct vcs_zcode_patronage_validation_context context = {
            .workspace = workspace,
            .expected_network_genesis_root = network,
            .now_unix = 1500,
        };
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(&intent, &context),
                  VCS_ZCODE_PATRONAGE_OK);
        uint8_t offer_plan_wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
        char offer_plan_hex[sizeof(offer_plan_wire) * 2u + 1u];
        char network_hex[65];
        ASSERT_EQ(vcs_zcode_patronage_intent_serialize(
                      &intent, offer_plan_wire), VCS_ZCODE_PATRONAGE_OK);
        zcl_hex_encode(offer_plan_wire, sizeof(offer_plan_wire),
                       offer_plan_hex);
        zcl_hex_encode(network, sizeof(network), network_hex);
        struct json_value offer_input;
        json_init(&offer_input); json_set_object(&offer_input);
        ASSERT(json_push_kv_str(&offer_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&offer_input, "intent_hex",
                                offer_plan_hex));
        ASSERT(json_push_kv_str(&offer_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&offer_input, "now_unix", 1500));
        struct zcl_command_request offer_request = {.input = &offer_input};
        struct zcl_command_reply offer_reply;
        zcl_command_reply_init(&offer_reply, "zcl.test.patronage.v1");
        zcl_native_handle_zcode_patronage_offer_plan(
            &offer_request, &offer_reply);
        ASSERT_EQ(offer_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&offer_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&offer_reply.data, "funded")));
        zcl_command_reply_free(&offer_reply);
        json_free(&offer_input);

        intent.settlement_trust_mode =
            VCS_ZCODE_PATRONAGE_SIMULATED_FUNDING;
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(
                      &intent, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        uint8_t intent_root[32];
        uint8_t intent_wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_intent_root(&intent, intent_root),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_serialize(&intent, intent_wire),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_object_put_addressed(workspace, intent_root, intent_wire,
                                        sizeof(intent_wire)));
        char committed_intent_hex[sizeof(intent_wire) * 2u + 1u];
        char committed_intent_root_hex[65];
        zcl_hex_encode(intent_wire, sizeof(intent_wire), committed_intent_hex);
        zcl_hex_encode(intent_root, 32, committed_intent_root_hex);
        struct json_value commit_input;
        json_init(&commit_input); json_set_object(&commit_input);
        ASSERT(json_push_kv_str(&commit_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&commit_input, "intent_hex",
                                committed_intent_hex));
        ASSERT(json_push_kv_str(&commit_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&commit_input, "now_unix", 1500));
        struct zcl_command_request commit_request = {.input = &commit_input};
        struct zcl_command_reply commit_reply;
        zcl_command_reply_init(&commit_reply, "zcl.test.patronage.v1");
        zcl_native_handle_zcode_patronage_offer_commit(
            &commit_request, &commit_reply);
        ASSERT_EQ(commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&commit_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&commit_reply.data, "funded")));
        zcl_command_reply_free(&commit_reply);
        json_free(&commit_input);

        struct json_value show_input;
        json_init(&show_input); json_set_object(&show_input);
        ASSERT(json_push_kv_str(&show_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&show_input, "root",
                                committed_intent_root_hex));
        ASSERT(json_push_kv_str(&show_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&show_input, "now_unix", 1500));
        struct zcl_command_request show_request = {.input = &show_input};
        struct zcl_command_reply show_reply;
        zcl_command_reply_init(&show_reply, "zcl.test.patronage.v1");
        zcl_native_handle_zcode_patronage_show(&show_request, &show_reply);
        ASSERT_EQ(show_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&show_reply.data, "object")),
                      "patronage_intent");
        ASSERT(!json_get_bool(json_get(&show_reply.data, "implies_ownership")));
        zcl_command_reply_free(&show_reply);
        json_free(&show_input);
        struct vcs_zcode_patronage_funding_v1 funding;
        memset(&funding, 0, sizeof(funding));
        funding.schema_version = VCS_ZCODE_PATRONAGE_FUNDING_VERSION;
        funding.funding_kind =
            VCS_ZCODE_PATRONAGE_FUNDING_FULLY_SIMULATED;
        funding.flags = VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS |
                        VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES;
        memcpy(funding.network_genesis_root, network, 32);
        memcpy(funding.patronage_intent_root, intent_root, 32);
        memcpy(funding.funder_contributor_binding_root, binding_root, 32);
        memcpy(funding.funder_zid_pubkey, zid_pubkey, 32);
        funding.amount_atoms = intent.amount_atoms;
        funding.created_unix = 1600;
        funding.sequence = 1;
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, funding.amount_atoms,
                      funding.simulation_plan_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(
                      &funding, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        uint8_t funding_wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
        struct vcs_zcode_patronage_funding_v1 parsed_funding, zero_funding;
        memset(&zero_funding, 0, sizeof(zero_funding));
        ASSERT_EQ(vcs_zcode_patronage_funding_serialize(
                      &funding, funding_wire),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                      funding_wire, sizeof(funding_wire), &parsed_funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify(&parsed_funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        for (size_t cut = 0; cut < sizeof(funding_wire); cut++) {
            ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                          funding_wire, cut, &parsed_funding),
                      VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE);
            ASSERT(memcmp(&parsed_funding, &zero_funding,
                          sizeof(parsed_funding)) == 0);
        }
        ASSERT_EQ(vcs_zcode_patronage_funding_parse(
                      funding_wire, sizeof(funding_wire) - 1,
                      &parsed_funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_WIRE_SIZE);
        ASSERT(memcmp(&parsed_funding, &zero_funding,
                      sizeof(parsed_funding)) == 0);
        context.now_unix = 1700;
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(
                      &funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        uint8_t committed_funding_root[32];
        char committed_funding_hex[sizeof(funding_wire) * 2u + 1u];
        char committed_funding_root_hex[65];
        ASSERT_EQ(vcs_zcode_patronage_funding_root(
                      &funding, committed_funding_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        zcl_hex_encode(funding_wire, sizeof(funding_wire),
                       committed_funding_hex);
        zcl_hex_encode(committed_funding_root, 32,
                       committed_funding_root_hex);
        struct json_value fund_input;
        json_init(&fund_input); json_set_object(&fund_input);
        ASSERT(json_push_kv_str(&fund_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&fund_input, "funding_hex",
                                committed_funding_hex));
        ASSERT(json_push_kv_str(&fund_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&fund_input, "now_unix", 1700));
        struct zcl_command_request fund_request = {.input = &fund_input};
        struct zcl_command_reply fund_plan_reply, fund_commit_reply;
        zcl_command_reply_init(&fund_plan_reply, "zcl.test.patronage.v1");
        zcl_native_handle_zcode_patronage_fund_plan(
            &fund_request, &fund_plan_reply);
        ASSERT_EQ(fund_plan_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&fund_plan_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&fund_plan_reply.data, "funded")));
        ASSERT(json_get_bool(json_get(&fund_plan_reply.data,
                                      "simulation_funded")));
        zcl_command_reply_free(&fund_plan_reply);
        zcl_command_reply_init(&fund_commit_reply, "zcl.test.patronage.v1");
        zcl_native_handle_zcode_patronage_fund_commit(
            &fund_request, &fund_commit_reply);
        ASSERT_EQ(fund_commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&fund_commit_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&fund_commit_reply.data,
                                       "moves_live_funds")));
        zcl_command_reply_free(&fund_commit_reply);
        json_free(&fund_input);

        json_init(&show_input); json_set_object(&show_input);
        ASSERT(json_push_kv_str(&show_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&show_input, "root",
                                committed_funding_root_hex));
        ASSERT(json_push_kv_str(&show_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&show_input, "now_unix", 1700));
        show_request.input = &show_input;
        zcl_command_reply_init(&show_reply, "zcl.test.patronage.v1");
        zcl_native_handle_zcode_patronage_show(&show_request, &show_reply);
        ASSERT_EQ(show_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&show_reply.data, "object")),
                      "patronage_funding");
        ASSERT(!json_get_bool(json_get(&show_reply.data, "funded")));
        zcl_command_reply_free(&show_reply);
        json_free(&show_input);
        funding.flags &= (uint8_t)
            ~VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS;
        ASSERT_EQ(vcs_zcode_patronage_funding_validate(&funding),
                  VCS_ZCODE_PATRONAGE_FUNDING_SHAPE);
        funding.flags |= VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS;
        funding.amount_atoms++;
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, funding.amount_atoms,
                      funding.simulation_plan_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(
                      &funding, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_verify_cas(
                      &funding, &context),
                  VCS_ZCODE_PATRONAGE_FUNDING_AMOUNT);
        funding.amount_atoms--;

        struct vcs_zcode_patronage_intent_v1 gift = intent;
        gift.mode = VCS_ZCODE_PATRONAGE_DIRECT_GIFT;
        gift.target_kind = VCS_ZCODE_PATRONAGE_TARGET_CONTRIBUTOR;
        memcpy(gift.target_root, binding_root, 32);
        memset(gift.task_root, 0, 32);
        memset(gift.proof_policy_root, 0, 32);
        gift.refund_height = 0;
        gift.refund_unix = 0;
        gift.sequence = 2;
        gift.amount_atoms = UINT64_C(50000000);
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(
                      &gift, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        uint8_t gift_root[32];
        ASSERT_EQ(vcs_zcode_patronage_intent_root(&gift, gift_root),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_serialize(&gift, intent_wire),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_object_put_addressed(workspace, gift_root, intent_wire,
                                        sizeof(intent_wire)));

        struct vcs_zcode_patronage_funding_v1 gift_funding;
        memset(&gift_funding, 0, sizeof(gift_funding));
        gift_funding.schema_version = VCS_ZCODE_PATRONAGE_FUNDING_VERSION;
        gift_funding.funding_kind =
            VCS_ZCODE_PATRONAGE_FUNDING_FULLY_SIMULATED;
        gift_funding.flags = VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS |
                             VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES;
        memcpy(gift_funding.network_genesis_root, network, 32);
        memcpy(gift_funding.patronage_intent_root, gift_root, 32);
        memcpy(gift_funding.funder_contributor_binding_root,
               binding_root, 32);
        memcpy(gift_funding.funder_zid_pubkey, zid_pubkey, 32);
        gift_funding.amount_atoms = gift.amount_atoms;
        gift_funding.created_unix = 1600;
        gift_funding.sequence = 2;
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      gift_root, gift.amount_atoms,
                      gift_funding.simulation_plan_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(
                      &gift_funding, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        uint8_t gift_funding_root[32];
        ASSERT_EQ(vcs_zcode_patronage_funding_root(
                      &gift_funding, gift_funding_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_serialize(
                      &gift_funding, funding_wire),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT(vcs_object_put_addressed(workspace, gift_funding_root,
                                        funding_wire,
                                        sizeof(funding_wire)));

        struct vcs_zcode_patronage_settlement_v1 gift_settlement;
        memset(&gift_settlement, 0, sizeof(gift_settlement));
        gift_settlement.schema_version =
            VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION;
        gift_settlement.action = VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED;
        gift_settlement.flags =
            VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY |
            VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS |
            VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES;
        memcpy(gift_settlement.network_genesis_root, network, 32);
        memcpy(gift_settlement.patronage_intent_root, gift_root, 32);
        memcpy(gift_settlement.patronage_funding_root,
               gift_funding_root, 32);
        memcpy(gift_settlement.recipient_contributor_binding_root,
               binding_root, 32);
        memcpy(gift_settlement.settler_zid_pubkey, zid_pubkey, 32);
        gift_settlement.amount_atoms = gift.amount_atoms;
        gift_settlement.created_unix = 1700;
        gift_settlement.observed_height = 1;
        gift_settlement.observed_mtp = 1500;
        gift_settlement.sequence = 1;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &gift_settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        struct vcs_zcode_patronage_settlement_validation_context
            gift_context = {
                .patronage = &context,
                .active_height = 1,
                .active_mtp = 1700,
                .now_unix = 1700,
            };
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &gift_settlement, &gift_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        memcpy(gift_settlement.patronage_funding_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &gift_settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &gift_settlement, &gift_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_FUNDING);
        memcpy(gift_settlement.patronage_funding_root,
               gift_funding_root, 32);
        gift_settlement.action = VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &gift_settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &gift_settlement, &gift_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT);

        uint8_t other_network[32]; score_fill(other_network, 0xc2);
        context.expected_network_genesis_root = other_network;
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(&intent, &context),
                  VCS_ZCODE_PATRONAGE_NETWORK);
        context.expected_network_genesis_root = network;
        memcpy(intent.task_root, policy_root, 32);
        memcpy(intent.target_root, policy_root, 32);
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(
                      &intent, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_verify_cas(&intent, &context),
                  VCS_ZCODE_PATRONAGE_TASK);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int test_creation_attribution_cross_validation(void)
{
    int failures = 0;
    TEST("ZC23 creation attribution: CAS authorities rederive or fail closed") {
        static const uint8_t license_bytes[] =
            "MIT License\n\nPermission is hereby granted, free of charge.\n";
        uint8_t license_chunk[32], package_root[32], license_root[32];
        ASSERT(vcs_package_chunk_hash(license_bytes,
                                      sizeof(license_bytes) - 1,
                                      license_chunk));
        struct vcs_package_manifest manifest;
        vcs_package_manifest_init(&manifest);
        ASSERT(vcs_package_manifest_add(
            &manifest, "LICENSE", VCS_PACKAGE_MODE_FILE,
            sizeof(license_bytes) - 1, license_chunk, 1));
        ASSERT(vcs_package_manifest_root(&manifest, package_root));
        ASSERT(vcs_package_file_hash(&manifest.files[0], license_root));
        uint8_t *manifest_wire = NULL; size_t manifest_wire_len = 0;
        ASSERT(vcs_package_manifest_serialize(
            &manifest, &manifest_wire, &manifest_wire_len));

        uint8_t network[32], policy_authority[32], recipe[32], lock[32];
        char network_hex[65];
        uint8_t capsule[32], zid_pubkey[32], zid_secret[32];
        score_fill(network, 0xa1); score_fill(policy_authority, 0xa2);
        zcl_hex_encode(network, sizeof(network), network_hex);
        score_fill(recipe, 0xa3); score_fill(lock, 0xa4);
        score_fill(capsule, 0xa5);
        struct vcs_zcode_contributor_binding_v1 binding;
        ASSERT(creation_test_binding(&binding, network, zid_pubkey,
                                     zid_secret));
        uint8_t binding_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
        uint8_t binding_root[32];
        ASSERT_EQ(vcs_zcode_contributor_binding_serialize(
                      &binding, binding_wire), VCS_ZCODE_BINDING_OK);
        ASSERT_EQ(vcs_zcode_contributor_binding_root(
                      &binding, binding_root), VCS_ZCODE_BINDING_OK);

        struct vcs_package_release parent_release, release;
        ASSERT(creation_test_release(&parent_release, package_root, recipe));
        uint8_t *parent_release_wire = NULL;
        size_t parent_release_wire_len = 0;
        uint8_t parent_release_root[32];
        ASSERT_EQ(vcs_package_release_serialize(
                      &parent_release, &parent_release_wire,
                      &parent_release_wire_len), VCS_PACKAGE_RELEASE_OK);
        ASSERT_EQ(vcs_package_release_id(
                      &parent_release, parent_release_root),
                  VCS_PACKAGE_RELEASE_OK);
        ASSERT(creation_test_child_release(
            &release, &parent_release, parent_release_root,
            package_root, recipe));
        uint8_t *release_wire = NULL; size_t release_wire_len = 0;
        uint8_t release_root[32];
        ASSERT_EQ(vcs_package_release_serialize(
                      &release, &release_wire, &release_wire_len),
                  VCS_PACKAGE_RELEASE_OK);
        ASSERT_EQ(vcs_package_release_id(&release, release_root),
                  VCS_PACKAGE_RELEASE_OK);

        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_proof_policy_v1 proof_policy;
        struct vcs_zcode_lane_receipt_v1 lane;
        struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS];
        uint8_t lane_secret[32], lane_pubkey[32];
        ASSERT(score_fixture_for_roots(
            &task, &candidate, &proof_policy, &lane, works,
            lane_secret, lane_pubkey, package_root, lock, capsule,
            zid_pubkey));
        uint8_t proof_roots[VCS_ZCODE_SCORE_UNITS][32];
        struct vcs_zcode_work_receipt_v1 receipts[VCS_ZCODE_SCORE_UNITS];
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            memcpy(proof_roots[i], works[i].root, 32);
            receipts[i] = works[i].receipt;
        }
        struct vcs_zcode_score_plan_input score_input = {
            .task = &task, .candidate = &candidate,
            .proof_policy = &proof_policy, .proven_lane = &lane,
            .proof_receipt_roots = proof_roots,
            .work_receipts = receipts,
            .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
            .package_root = package_root, .release_root = release_root,
            .recipe_root = recipe, .dependency_lock_root = lock,
            .api_capsule_root = capsule,
        };
        struct vcs_zcode_score_receipt_v1 score;
        ASSERT_EQ(vcs_zcode_score_plan(&score_input, &score),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_score_receipt_seal(
                      &score, lane_secret, lane_pubkey), VCS_ZCODE_SCORE_OK);

        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_creation", "cross");
        uint8_t task_root[32], candidate_root[32], proof_set_root[32];
        uint8_t lane_root[32], score_root[32], proof_policy_root[32];
        ASSERT(score_store_vertical(
            workspace, &task, &candidate, &proof_policy, &lane, works,
            &score, task_root, candidate_root, proof_set_root,
            lane_root, score_root));
        ASSERT_EQ(vcs_zcode_proof_policy_root(
                      &proof_policy, proof_policy_root), VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(workspace, package_root,
                                         manifest_wire,
                                         manifest_wire_len));
        ASSERT(vcs_object_put_addressed(workspace, license_chunk,
                                         license_bytes,
                                         sizeof(license_bytes) - 1));
        ASSERT(vcs_object_put_addressed(workspace, release_root,
                                         release_wire, release_wire_len));
        ASSERT(vcs_object_put_addressed(
            workspace, parent_release_root, parent_release_wire,
            parent_release_wire_len));
        ASSERT(vcs_object_put_addressed(workspace, binding_root,
                                         binding_wire,
                                         sizeof(binding_wire)));

        struct vcs_zcode_creation_attribution_v1 attribution;
        memset(&attribution, 0, sizeof(attribution));
        attribution.schema_version =
            VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
        attribution.category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
        attribution.epoch = 3;
        attribution.award_atoms = UINT64_C(250000000);
        attribution.challenge_opening_height = 100;
        score_fill(attribution.challenge_opening_hash, 0xb1);
        attribution.challenge_opening_mtp = 1000;
        attribution.challenge_maturity_height = 8164;
        attribution.challenge_maturity_mtp = 605800;
        attribution.created_unix = 605801;
        memcpy(attribution.network_genesis_root, network, 32);
        memcpy(attribution.zc23_policy_root, policy_authority, 32);
        memcpy(attribution.contributor_binding_root, binding_root, 32);
        memcpy(attribution.task_root, task_root, 32);
        memcpy(attribution.candidate_root, candidate_root, 32);
        memcpy(attribution.proof_policy_root, proof_policy_root, 32);
        memcpy(attribution.proof_set_root, proof_set_root, 32);
        memcpy(attribution.proven_lane_root, lane_root, 32);
        memcpy(attribution.score_receipt_root, score_root, 32);
        memcpy(attribution.package_root, package_root, 32);
        memcpy(attribution.release_root, release_root, 32);
        memcpy(attribution.license_evidence_root, license_root, 32);
        attribution.lineage_kind = VCS_ZCODE_CREATION_LINEAGE_RELEASE;
        memcpy(attribution.lineage_root, parent_release_root, 32);

        struct creation_callback_fixture callbacks = {
            .anchor_active = true, .duplicate = false,
            .opening_height = attribution.challenge_opening_height,
            .maturity_height = attribution.challenge_maturity_height,
            .expected_award_atoms = attribution.award_atoms,
        };
        memcpy(callbacks.opening_hash, attribution.challenge_opening_hash,
               32);
        memcpy(callbacks.maturity_hash, attribution.challenge_opening_hash,
               32);
        struct vcs_zcode_creation_validation_context context = {
            .workspace = workspace,
            .expected_network_genesis_root = network,
            .expected_zc23_policy_root = policy_authority,
            .expected_epoch = attribution.epoch,
            .expected_award_atoms = attribution.award_atoms,
            .active_height = 9000,
            .active_mtp = 700000,
            .now_unix = 700000,
            .anchor_is_active = creation_test_anchor,
            .contribution_is_duplicate = creation_test_duplicate,
            .callback_opaque = &callbacks,
        };
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &attribution, &context), VCS_ZCODE_CREATION_OK);

        /* Historical authorship is evaluated at the candidate event.  A
         * binding that was valid then remains valid after its later expiry;
         * current payout authority is a separate adapter decision. */
        struct vcs_zcode_contributor_binding_v1 historical_binding = binding;
        historical_binding.expires_unix = 2000;
        ASSERT_EQ(vcs_zcode_contributor_binding_seal(
                      &historical_binding, zid_secret, zid_pubkey,
                      (const uint8_t[32]){
                          0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                          0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                          0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                          0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}),
                  VCS_ZCODE_BINDING_OK);
        uint8_t historical_binding_root[32];
        uint8_t historical_binding_wire[
            VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_contributor_binding_root(
                      &historical_binding, historical_binding_root),
                  VCS_ZCODE_BINDING_OK);
        ASSERT_EQ(vcs_zcode_contributor_binding_serialize(
                      &historical_binding, historical_binding_wire),
                  VCS_ZCODE_BINDING_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, historical_binding_root, historical_binding_wire,
            sizeof(historical_binding_wire)));
        struct vcs_zcode_creation_attribution_v1 historical = attribution;
        memcpy(historical.contributor_binding_root,
               historical_binding_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &historical, &context), VCS_ZCODE_CREATION_OK);

        /* A PUBLIC_SOURCE lineage root is authority, not a narrative hint.
         * The signed direct parent above succeeds; claiming the current
         * release itself or an unrelated CAS object must fail closed. */
        struct vcs_zcode_creation_attribution_v1 bad_lineage = attribution;
        memcpy(bad_lineage.lineage_root, release_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &bad_lineage, &context), VCS_ZCODE_CREATION_RELEASE);
        memcpy(bad_lineage.lineage_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &bad_lineage, &context), VCS_ZCODE_CREATION_RELEASE);

        /* A predecessor-attribution lineage reloads and re-verifies the
         * complete prior vertical, then proves that its signed release is
         * the direct parent of this release. */
        struct vcs_zcode_task_v1 prior_task;
        struct vcs_zcode_candidate_v1 prior_candidate;
        struct vcs_zcode_proof_policy_v1 prior_policy;
        struct vcs_zcode_lane_receipt_v1 prior_lane;
        struct score_work_fixture prior_works[VCS_ZCODE_SCORE_UNITS];
        uint8_t prior_lane_secret[32], prior_lane_pubkey[32];
        uint8_t prior_capsule[32];
        score_fill(prior_capsule, 0xa6);
        ASSERT(score_fixture_for_roots(
            &prior_task, &prior_candidate, &prior_policy, &prior_lane,
            prior_works, prior_lane_secret, prior_lane_pubkey,
            package_root, lock, prior_capsule, zid_pubkey));
        uint8_t prior_proof_roots[VCS_ZCODE_SCORE_UNITS][32];
        struct vcs_zcode_work_receipt_v1
            prior_receipts[VCS_ZCODE_SCORE_UNITS];
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            memcpy(prior_proof_roots[i], prior_works[i].root, 32);
            prior_receipts[i] = prior_works[i].receipt;
        }
        struct vcs_zcode_score_plan_input prior_score_input = {
            .task = &prior_task, .candidate = &prior_candidate,
            .proof_policy = &prior_policy, .proven_lane = &prior_lane,
            .proof_receipt_roots = prior_proof_roots,
            .work_receipts = prior_receipts,
            .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
            .package_root = package_root,
            .release_root = parent_release_root,
            .recipe_root = recipe, .dependency_lock_root = lock,
            .api_capsule_root = prior_capsule,
        };
        struct vcs_zcode_score_receipt_v1 prior_score;
        ASSERT_EQ(vcs_zcode_score_plan(&prior_score_input, &prior_score),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_score_receipt_seal(
                      &prior_score, prior_lane_secret, prior_lane_pubkey),
                  VCS_ZCODE_SCORE_OK);
        uint8_t prior_task_root[32], prior_candidate_root[32];
        uint8_t prior_proof_set_root[32], prior_lane_root[32];
        uint8_t prior_score_root[32], prior_policy_root[32];
        ASSERT(score_store_vertical(
            workspace, &prior_task, &prior_candidate, &prior_policy,
            &prior_lane, prior_works, &prior_score, prior_task_root,
            prior_candidate_root, prior_proof_set_root, prior_lane_root,
            prior_score_root));
        ASSERT_EQ(vcs_zcode_proof_policy_root(
                      &prior_policy, prior_policy_root), VCS_ZCODE_DEV_OK);
        struct vcs_zcode_creation_attribution_v1 prior_attribution =
            attribution;
        prior_attribution.epoch = 2;
        prior_attribution.created_unix = attribution.created_unix - 1;
        memcpy(prior_attribution.task_root, prior_task_root, 32);
        memcpy(prior_attribution.candidate_root, prior_candidate_root, 32);
        memcpy(prior_attribution.proof_policy_root, prior_policy_root, 32);
        memcpy(prior_attribution.proof_set_root, prior_proof_set_root, 32);
        memcpy(prior_attribution.proven_lane_root, prior_lane_root, 32);
        memcpy(prior_attribution.score_receipt_root, prior_score_root, 32);
        memcpy(prior_attribution.release_root, parent_release_root, 32);
        prior_attribution.lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
        memset(prior_attribution.lineage_root, 0, 32);
        uint8_t prior_attribution_wire[
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        uint8_t prior_attribution_root[32];
        ASSERT_EQ(vcs_zcode_creation_attribution_serialize(
                      &prior_attribution, prior_attribution_wire),
                  VCS_ZCODE_CREATION_OK);
        ASSERT_EQ(vcs_zcode_creation_attribution_root(
                      &prior_attribution, prior_attribution_root),
                  VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, prior_attribution_root, prior_attribution_wire,
            sizeof(prior_attribution_wire)));
        struct vcs_zcode_creation_attribution_v1 predecessor_lineage =
            attribution;
        predecessor_lineage.lineage_kind =
            VCS_ZCODE_CREATION_LINEAGE_PREDECESSOR_ATTRIBUTION;
        memcpy(predecessor_lineage.lineage_root,
               prior_attribution_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &predecessor_lineage, &context),
                  VCS_ZCODE_CREATION_OK);
        predecessor_lineage.lineage_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &predecessor_lineage, &context),
                  VCS_ZCODE_CREATION_LINEAGE);

        uint8_t attribution_wire[
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        uint8_t attribution_root[32];
        ASSERT_EQ(vcs_zcode_creation_attribution_serialize(
                      &attribution, attribution_wire),
                  VCS_ZCODE_CREATION_OK);
        ASSERT_EQ(vcs_zcode_creation_attribution_root(
                      &attribution, attribution_root),
                  VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, attribution_root, attribution_wire,
            sizeof(attribution_wire)));
        struct vcs_zcode_epoch_creation_set_v1 epoch_set;
        vcs_zcode_epoch_creation_init(&epoch_set);
        epoch_set.schema_version = VCS_ZCODE_EPOCH_CREATION_VERSION;
        epoch_set.epoch = attribution.epoch;
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(
                      epoch_set.epoch, &epoch_set.emission_cap_atoms),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        epoch_set.actual_mint_atoms = attribution.award_atoms;
        epoch_set.unissued_atoms = epoch_set.emission_cap_atoms -
                                   epoch_set.actual_mint_atoms;
        memcpy(epoch_set.network_genesis_root, network, 32);
        memcpy(epoch_set.zc23_policy_root, policy_authority, 32);
        score_fill(epoch_set.previous_epoch_creation_root, 0xc1);
        score_fill(epoch_set.committee_evidence_snapshot_root, 0xc2);
        epoch_set.opening_height = attribution.challenge_opening_height;
        memcpy(epoch_set.opening_hash,
               attribution.challenge_opening_hash, 32);
        epoch_set.opening_mtp = attribution.challenge_opening_mtp;
        epoch_set.maturity_height = attribution.challenge_maturity_height;
        score_fill(epoch_set.maturity_hash, 0xc3);
        epoch_set.maturity_mtp = attribution.challenge_maturity_mtp;
        epoch_set.attribution_roots = &attribution_root;
        epoch_set.attribution_count = 1;
        callbacks.maturity_height = epoch_set.maturity_height;
        memcpy(callbacks.maturity_hash, epoch_set.maturity_hash, 32);
        struct vcs_zcode_epoch_creation_validation_context epoch_context = {
            .workspace = workspace,
            .expected_network_genesis_root = network,
            .expected_zc23_policy_root = policy_authority,
            .expected_previous_epoch_creation_root =
                epoch_set.previous_epoch_creation_root,
            .observed_actual_mint_atoms = epoch_set.actual_mint_atoms,
            .active_height = 9000,
            .active_mtp = 700000,
            .now_unix = 700000,
            .anchor_is_active = creation_test_anchor,
            .contribution_is_duplicate = creation_test_duplicate,
            .award_atoms_for_creation = creation_test_award,
            .callback_opaque = &callbacks,
        };
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(
                      &epoch_set, &epoch_context),
                  VCS_ZCODE_EPOCH_CREATION_OK);

        struct vcs_zcode_patronage_intent_v1 intent;
        memset(&intent, 0, sizeof(intent));
        intent.schema_version = VCS_ZCODE_PATRONAGE_INTENT_VERSION;
        intent.mode = VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION;
        intent.target_kind = VCS_ZCODE_PATRONAGE_TARGET_TASK;
        intent.settlement_trust_mode =
            VCS_ZCODE_PATRONAGE_SIMULATED_FUNDING;
        intent.flags = VCS_ZCODE_PATRONAGE_NO_AUTHORITY |
                       VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
        memcpy(intent.network_genesis_root, network, 32);
        score_fill(intent.zc23_token_or_simulation_root, 0xd1);
        memcpy(intent.patron_contributor_binding_root, binding_root, 32);
        memcpy(intent.patron_zid_pubkey, zid_pubkey, 32);
        memcpy(intent.target_root, task_root, 32);
        memcpy(intent.task_root, task_root, 32);
        memcpy(intent.proof_policy_root, proof_policy_root, 32);
        memcpy(intent.intended_recipient_binding_root, binding_root, 32);
        intent.amount_atoms = UINT64_C(100000000);
        intent.created_unix = 1000;
        intent.expires_unix = 800000;
        intent.refund_height = 10000;
        intent.refund_unix = 800100;
        intent.sequence = 1;
        intent.maximum_zcl_fee_zat = 10000;
        ASSERT_EQ(vcs_zcode_patronage_intent_seal(
                      &intent, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_OK);
        uint8_t intent_root[32];
        uint8_t intent_wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_intent_root(&intent, intent_root),
                  VCS_ZCODE_PATRONAGE_OK);
        ASSERT_EQ(vcs_zcode_patronage_intent_serialize(
                      &intent, intent_wire), VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_object_put_addressed(workspace, intent_root, intent_wire,
                                        sizeof(intent_wire)));

        struct vcs_zcode_patronage_funding_v1 funding;
        memset(&funding, 0, sizeof(funding));
        funding.schema_version = VCS_ZCODE_PATRONAGE_FUNDING_VERSION;
        funding.funding_kind =
            VCS_ZCODE_PATRONAGE_FUNDING_FULLY_SIMULATED;
        funding.flags = VCS_ZCODE_PATRONAGE_FUNDING_NO_LIVE_FUNDS |
                        VCS_ZCODE_PATRONAGE_FUNDING_NO_TRANSACTION_BYTES;
        memcpy(funding.network_genesis_root, network, 32);
        memcpy(funding.patronage_intent_root, intent_root, 32);
        memcpy(funding.funder_contributor_binding_root, binding_root, 32);
        memcpy(funding.funder_zid_pubkey, zid_pubkey, 32);
        funding.amount_atoms = intent.amount_atoms;
        funding.created_unix = 1100;
        funding.sequence = 1;
        ASSERT_EQ(vcs_zcode_patronage_simulation_plan_root(
                      intent_root, funding.amount_atoms,
                      funding.simulation_plan_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_seal(
                      &funding, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        uint8_t funding_root[32];
        uint8_t funding_wire[VCS_ZCODE_PATRONAGE_FUNDING_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_patronage_funding_root(&funding, funding_root),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT_EQ(vcs_zcode_patronage_funding_serialize(
                      &funding, funding_wire),
                  VCS_ZCODE_PATRONAGE_FUNDING_OK);
        ASSERT(vcs_object_put_addressed(workspace, funding_root, funding_wire,
                                        sizeof(funding_wire)));

        struct vcs_zcode_patronage_settlement_v1 settlement;
        memset(&settlement, 0, sizeof(settlement));
        settlement.schema_version =
            VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION;
        settlement.action = VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED;
        settlement.flags = VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY |
            VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS |
            VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES;
        memcpy(settlement.network_genesis_root, network, 32);
        memcpy(settlement.patronage_intent_root, intent_root, 32);
        memcpy(settlement.patronage_funding_root, funding_root, 32);
        memcpy(settlement.creation_attribution_root, attribution_root, 32);
        memcpy(settlement.task_root, task_root, 32);
        memcpy(settlement.candidate_root, candidate_root, 32);
        memcpy(settlement.proof_policy_root, proof_policy_root, 32);
        memcpy(settlement.proof_set_root, proof_set_root, 32);
        memcpy(settlement.proven_lane_root, lane_root, 32);
        memcpy(settlement.score_receipt_root, score_root, 32);
        memcpy(settlement.recipient_contributor_binding_root,
               binding_root, 32);
        memcpy(settlement.settler_zid_pubkey, zid_pubkey, 32);
        settlement.amount_atoms = intent.amount_atoms;
        settlement.created_unix = 700000;
        settlement.observed_height = 9000;
        settlement.observed_mtp = 700000;
        settlement.sequence = 1;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        struct vcs_zcode_patronage_validation_context patronage_context = {
            .workspace = workspace,
            .expected_network_genesis_root = network,
            .now_unix = 700000,
        };
        struct vcs_zcode_continuity_policy_v1 continuity;
        memset(&continuity, 0, sizeof(continuity));
        continuity.schema_version = VCS_ZCODE_CONTINUITY_POLICY_VERSION;
        continuity.event_mask = VCS_ZCODE_CONTINUITY_BORN_RED_FIX |
            VCS_ZCODE_CONTINUITY_SECURITY_FIX |
            VCS_ZCODE_CONTINUITY_INDEPENDENT_REPRODUCTION |
            VCS_ZCODE_CONTINUITY_COMPATIBILITY |
            VCS_ZCODE_CONTINUITY_PRESERVATION;
        continuity.flags = VCS_ZCODE_CONTINUITY_NO_AUTHORITY |
                           VCS_ZCODE_CONTINUITY_SIMULATION_ONLY;
        memcpy(continuity.network_genesis_root, network, 32);
        score_fill(continuity.zc23_token_or_simulation_root, 0xe1);
        memcpy(continuity.patron_contributor_binding_root, binding_root, 32);
        memcpy(continuity.patron_zid_pubkey, zid_pubkey, 32);
        memcpy(continuity.package_root, package_root, 32);
        memcpy(continuity.current_release_root, release_root, 32);
        score_fill(continuity.from_capsule_root, 0xe2);
        memcpy(continuity.to_capsule_root, capsule, 32);
        memcpy(continuity.proof_policy_root, proof_policy_root, 32);
        continuity.maximum_cycles = 3;
        continuity.per_cycle_cap_atoms = UINT64_C(250000000);
        continuity.total_cap_atoms = UINT64_C(750000000);
        continuity.created_unix = 1000;
        continuity.expires_unix = 800000;
        continuity.sequence = 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(
                      &continuity, &patronage_context),
                  VCS_ZCODE_CONTINUITY_OK);
        struct vcs_zcode_creation_attribution_v1 continuity_attribution =
            attribution;
        continuity_attribution.category = VCS_ZCODE_CREATION_COMPATIBILITY;
        continuity_attribution.lineage_kind =
            VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY;
        uint8_t continuity_policy_root[32], continuity_event_key[32];
        ASSERT_EQ(vcs_zcode_continuity_policy_root(
                      &continuity, continuity_policy_root),
                  VCS_ZCODE_CONTINUITY_OK);
        memcpy(continuity_attribution.lineage_root,
               continuity_policy_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &continuity_attribution, &continuity, &task, &score,
                      continuity_event_key),
                  VCS_ZCODE_CONTINUITY_OK);
        char continuity_event_key_hex[65];
        zcl_hex_encode(continuity_event_key, 32, continuity_event_key_hex);
        ASSERT_STR_EQ(continuity_event_key_hex,
            "aa520e9943150bf70bdda88fe56f94bdc276eebc6ee90a0f14b93678add2e50c");
        uint8_t continuity_wire[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES];
        uint8_t continuity_root[32];
        char continuity_hex[sizeof(continuity_wire) * 2u + 1u];
        char continuity_root_hex[65];
        ASSERT_EQ(vcs_zcode_continuity_policy_serialize(
                      &continuity, continuity_wire),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_root(
                      &continuity, continuity_root),
                  VCS_ZCODE_CONTINUITY_OK);
        zcl_hex_encode(continuity_wire, sizeof(continuity_wire),
                       continuity_hex);
        zcl_hex_encode(continuity_root, sizeof(continuity_root),
                       continuity_root_hex);
        struct json_value continuity_input;
        json_init(&continuity_input); json_set_object(&continuity_input);
        ASSERT(json_push_kv_str(&continuity_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&continuity_input, "policy_hex",
                                continuity_hex));
        ASSERT(json_push_kv_str(&continuity_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&continuity_input, "now_unix", 700000));
        struct zcl_command_request continuity_request = {
            .input = &continuity_input,
        };
        struct zcl_command_reply continuity_reply;
        zcl_command_reply_init(&continuity_reply,
                               "zcl.test.continuity.v1");
        zcl_native_handle_zcode_continuity_plan(
            &continuity_request, &continuity_reply);
        ASSERT_EQ(continuity_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&continuity_reply.data, "persisted")));
        ASSERT(json_get_bool(json_get(&continuity_reply.data,
                                      "simulation_only")));
        ASSERT(json_get_bool(json_get(&continuity_reply.data,
                                      "no_authority")));
        ASSERT(!json_get_bool(json_get(&continuity_reply.data, "funded")));
        ASSERT(!json_get_bool(json_get(&continuity_reply.data,
                                       "guaranteed_income")));
        zcl_command_reply_free(&continuity_reply);

        ASSERT(json_push_kv_bool(&continuity_input, "unknown", true));
        zcl_command_reply_init(&continuity_reply,
                               "zcl.test.continuity.v1");
        zcl_native_handle_zcode_continuity_plan(
            &continuity_request, &continuity_reply);
        ASSERT_EQ(continuity_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        zcl_command_reply_free(&continuity_reply);
        json_free(&continuity_input);

        json_init(&continuity_input); json_set_object(&continuity_input);
        ASSERT(json_push_kv_str(&continuity_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&continuity_input, "policy_hex",
                                continuity_hex));
        ASSERT(json_push_kv_str(&continuity_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&continuity_input, "now_unix", 700000));
        continuity_request.input = &continuity_input;
        zcl_command_reply_init(&continuity_reply,
                               "zcl.test.continuity.v1");
        zcl_native_handle_zcode_continuity_commit(
            &continuity_request, &continuity_reply);
        ASSERT_EQ(continuity_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&continuity_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&continuity_reply.data,
                                       "moves_live_funds")));
        zcl_command_reply_free(&continuity_reply);
        json_free(&continuity_input);

        struct json_value continuity_status_input;
        json_init(&continuity_status_input);
        json_set_object(&continuity_status_input);
        ASSERT(json_push_kv_str(&continuity_status_input, "workspace",
                                workspace));
        ASSERT(json_push_kv_str(&continuity_status_input, "root",
                                continuity_root_hex));
        ASSERT(json_push_kv_str(&continuity_status_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&continuity_status_input, "now_unix",
                                700000));
        struct zcl_command_request continuity_status_request = {
            .input = &continuity_status_input,
        };
        zcl_command_reply_init(&continuity_reply,
                               "zcl.test.continuity.v1");
        zcl_native_handle_zcode_continuity_status(
            &continuity_status_request, &continuity_reply);
        ASSERT_EQ(continuity_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&continuity_reply.data, "object")),
                      "continuity_policy");
        ASSERT_STR_EQ(json_get_str(json_get(&continuity_reply.data,
                                            "continuity_policy_root")),
                      continuity_root_hex);
        ASSERT_EQ(json_get_int(json_get(&continuity_reply.data,
                                        "maximum_cycles")), 3);
        ASSERT(!json_get_bool(json_get(&continuity_reply.data, "funded")));
        zcl_command_reply_free(&continuity_reply);
        json_free(&continuity_status_input);

        struct json_value patronage_list_input;
        json_init(&patronage_list_input);
        json_set_object(&patronage_list_input);
        ASSERT(json_push_kv_str(&patronage_list_input, "workspace",
                                workspace));
        ASSERT(json_push_kv_str(&patronage_list_input,
                                "expected_network_genesis_root",
                                network_hex));
        ASSERT(json_push_kv_int(&patronage_list_input, "now_unix", 700000));
        struct zcl_command_request patronage_list_request = {
            .input = &patronage_list_input,
        };
        zcl_command_reply_init(&continuity_reply,
                               "zcl.test.patronage_list.v1");
        zcl_native_handle_zcode_patronage_list(
            &patronage_list_request, &continuity_reply);
        ASSERT_EQ(continuity_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&continuity_reply.data, "count")), 3);
        ASSERT_EQ(json_get_int(json_get(&continuity_reply.data,
                                        "offer_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&continuity_reply.data,
                                        "simulated_funding_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&continuity_reply.data,
                                        "continuity_policy_count")), 1);
        ASSERT(!json_get_bool(json_get(&continuity_reply.data, "funded")));
        ASSERT(!json_get_bool(json_get(&continuity_reply.data, "persisted")));
        zcl_command_reply_free(&continuity_reply);
        json_free(&patronage_list_input);
        struct vcs_zcode_patronage_projection *first_patronage =
            vcs_zcode_patronage_projection_build(&patronage_context);
        struct vcs_zcode_patronage_projection *second_patronage =
            vcs_zcode_patronage_projection_build(&patronage_context);
        uint8_t first_patronage_root[32], second_patronage_root[32];
        ASSERT(first_patronage && second_patronage);
        ASSERT(vcs_zcode_patronage_projection_root(
            first_patronage, first_patronage_root));
        ASSERT(vcs_zcode_patronage_projection_root(
            second_patronage, second_patronage_root));
        ASSERT(memcmp(first_patronage_root, second_patronage_root, 32) == 0);
        vcs_zcode_patronage_projection_free(second_patronage);
        vcs_zcode_patronage_projection_free(first_patronage);

        context.continuity_is_duplicate =
            creation_test_continuity_duplicate;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &continuity_attribution, &context),
                  VCS_ZCODE_CREATION_OK);
        context.continuity_is_duplicate = NULL;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &continuity_attribution, &context),
                  VCS_ZCODE_CREATION_CONTINUITY);
        context.continuity_is_duplicate =
            creation_test_continuity_duplicate;
        callbacks.continuity_duplicate = true;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &continuity_attribution, &context),
                  VCS_ZCODE_CREATION_DUPLICATE);
        callbacks.continuity_duplicate = false;

        struct vcs_zcode_creation_attribution_v1 born_red_attribution =
            continuity_attribution;
        struct vcs_zcode_creation_attribution_v1 security_attribution =
            continuity_attribution;
        born_red_attribution.category = VCS_ZCODE_CREATION_BORN_RED_FIX;
        security_attribution.category = VCS_ZCODE_CREATION_SECURITY_FIX;
        uint8_t born_red_event_key[32], security_event_key[32];
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &born_red_attribution, &continuity, &task, &score,
                      born_red_event_key),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &security_attribution, &continuity, &task, &score,
                      security_event_key),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(born_red_event_key, security_event_key, 32) == 0);

        /* Creation is useful without a patron.  The signed release lineage
         * and registered score evidence must be sufficient to identify and
         * deduplicate a born-red/security repair. */
        struct vcs_zcode_creation_attribution_v1 neutral_born_red =
            born_red_attribution;
        neutral_born_red.lineage_kind = VCS_ZCODE_CREATION_LINEAGE_RELEASE;
        memcpy(neutral_born_red.lineage_root, parent_release_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &neutral_born_red, &context),
                  VCS_ZCODE_CREATION_OK);
        struct vcs_zcode_creation_attribution_v1 neutral_security =
            neutral_born_red;
        neutral_security.category = VCS_ZCODE_CREATION_SECURITY_FIX;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &neutral_security, &context),
                  VCS_ZCODE_CREATION_OK);
        uint8_t neutral_policy_key[32], neutral_release_key[32];
        uint8_t neutral_security_key[32];
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &born_red_attribution, &task, &score,
                      neutral_policy_key), VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &neutral_born_red, &task, &score,
                      neutral_release_key), VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &neutral_security, &task, &score,
                      neutral_security_key), VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(neutral_policy_key, neutral_release_key, 32) == 0);
        ASSERT(memcmp(neutral_release_key, neutral_security_key, 32) == 0);
        char neutral_event_key_hex[65];
        zcl_hex_encode(neutral_release_key, 32, neutral_event_key_hex);
        ASSERT_STR_EQ(neutral_event_key_hex,
            "7bae4e36261433d84647745417142e33a3e424720d978c0abf685ed9397e1c65");

        uint8_t neutral_security_wire[
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        uint8_t neutral_security_root[32];
        ASSERT_EQ(vcs_zcode_creation_attribution_serialize(
                      &neutral_security, neutral_security_wire),
                  VCS_ZCODE_CREATION_OK);
        ASSERT_EQ(vcs_zcode_creation_attribution_root(
                      &neutral_security, neutral_security_root),
                  VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, neutral_security_root, neutral_security_wire,
            sizeof(neutral_security_wire)));
        epoch_set.attribution_roots = &neutral_security_root;
        epoch_context.continuity_is_duplicate =
            creation_test_continuity_duplicate;
        callbacks.security_award_atoms = attribution.award_atoms + 1;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(
                      &epoch_set, &epoch_context),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT_EQ(callbacks.last_award_category,
                  VCS_ZCODE_CREATION_BORN_RED_FIX);
        callbacks.security_award_atoms = 0;
        epoch_context.continuity_is_duplicate = NULL;
        epoch_set.attribution_roots = &attribution_root;

        /* SECURITY_FIX v1 has no structured security-finding authority.  It
         * therefore consumes exactly the ordinary born-red policy class;
         * the caller-selected label cannot open a separate issuance class. */
        struct vcs_zcode_continuity_policy_v1 born_red_only = continuity;
        born_red_only.event_mask &=
            (uint16_t)~VCS_ZCODE_CONTINUITY_SECURITY_FIX;
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &born_red_only, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        uint8_t born_red_only_root[32];
        ASSERT_EQ(vcs_zcode_continuity_policy_root(
                      &born_red_only, born_red_only_root),
                  VCS_ZCODE_CONTINUITY_OK);
        struct vcs_zcode_creation_attribution_v1 labeled_security =
            security_attribution;
        memcpy(labeled_security.lineage_root, born_red_only_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &labeled_security, &born_red_only, &task, &score,
                      security_event_key),
                  VCS_ZCODE_CONTINUITY_OK);

        struct vcs_zcode_continuity_policy_v1 mismatched_continuity =
            continuity;
        score_fill(mismatched_continuity.to_capsule_root, 0xe3);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &mismatched_continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_root(
                      &mismatched_continuity,
                      continuity_attribution.lineage_root),
                  VCS_ZCODE_CONTINUITY_OK);
        uint8_t zero_event_key[32];
        memset(zero_event_key, 0, sizeof(zero_event_key));
        memset(continuity_event_key, 0xa5, sizeof(continuity_event_key));
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &continuity_attribution, &mismatched_continuity,
                      &task, &score, continuity_event_key),
                  VCS_ZCODE_CONTINUITY_TRANSITION);
        ASSERT(memcmp(continuity_event_key, zero_event_key,
                      sizeof(zero_event_key)) == 0);

        memcpy(continuity.patron_contributor_binding_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(
                      &continuity, &patronage_context),
                  VCS_ZCODE_CONTINUITY_CONTRIBUTOR);
        memcpy(continuity.patron_contributor_binding_root, binding_root, 32);
        memcpy(continuity.package_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(
                      &continuity, &patronage_context),
                  VCS_ZCODE_CONTINUITY_PACKAGE);
        memcpy(continuity.package_root, package_root, 32);
        memcpy(continuity.current_release_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(
                      &continuity, &patronage_context),
                  VCS_ZCODE_CONTINUITY_RELEASE);
        memcpy(continuity.current_release_root, release_root, 32);
        memcpy(continuity.proof_policy_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(
                      &continuity, &patronage_context),
                  VCS_ZCODE_CONTINUITY_PROOF_POLICY);
        memcpy(continuity.proof_policy_root, proof_policy_root, 32);
        score_fill(continuity.network_genesis_root, 0xe4);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &continuity, zid_secret, zid_pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(
                      &continuity, &patronage_context),
                  VCS_ZCODE_CONTINUITY_NETWORK);
        memcpy(continuity.network_genesis_root, network, 32);
        struct vcs_zcode_patronage_settlement_validation_context
            settlement_context = {
                .patronage = &patronage_context,
                .creation = &context,
                .active_height = 9000,
                .active_mtp = 700000,
                .now_unix = 700000,
            };
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);

        memcpy(settlement.task_root, candidate_root, 32);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE);
        memcpy(settlement.task_root, task_root, 32);
        callbacks.anchor_active = false;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE);
        callbacks.anchor_active = true;
        settlement.observed_height =
            attribution.challenge_maturity_height - 1;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_EVIDENCE);

        settlement.action = VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED;
        memset(settlement.creation_attribution_root, 0, 32);
        memset(settlement.task_root, 0, 32);
        memset(settlement.candidate_root, 0, 32);
        memset(settlement.proof_policy_root, 0, 32);
        memset(settlement.proof_set_root, 0, 32);
        memset(settlement.proven_lane_root, 0, 32);
        memset(settlement.score_receipt_root, 0, 32);
        settlement.created_unix = intent.expires_unix - 1;
        settlement.observed_height = intent.refund_height - 1;
        settlement.observed_mtp = intent.expires_unix - 1;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_TIME);
        settlement.created_unix = intent.refund_unix;
        settlement.observed_height = intent.refund_height;
        settlement.observed_mtp = intent.refund_unix;
        settlement_context.active_height = intent.refund_height;
        settlement_context.active_mtp = intent.refund_unix;
        settlement_context.now_unix = intent.refund_unix;
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        memcpy(settlement.recipient_contributor_binding_root,
               task_root, 32);
        ASSERT_EQ(vcs_zcode_patronage_settlement_seal(
                      &settlement, zid_secret, zid_pubkey),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT_EQ(vcs_zcode_patronage_settlement_verify_cas(
                      &settlement, &settlement_context),
                  VCS_ZCODE_PATRONAGE_SETTLEMENT_INTENT);

        epoch_set.actual_mint_atoms--;
        epoch_set.unissued_atoms++;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(
                      &epoch_set, &epoch_context),
                  VCS_ZCODE_EPOCH_CREATION_MINT);
        epoch_set.actual_mint_atoms += 2;
        epoch_set.unissued_atoms -= 2;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(
                      &epoch_set, &epoch_context),
                  VCS_ZCODE_EPOCH_CREATION_MINT);
        epoch_context.observed_actual_mint_atoms =
            epoch_set.actual_mint_atoms;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(
                      &epoch_set, &epoch_context),
                  VCS_ZCODE_EPOCH_CREATION_SUM);
        epoch_set.actual_mint_atoms = attribution.award_atoms;
        epoch_set.unissued_atoms = epoch_set.emission_cap_atoms -
                                   epoch_set.actual_mint_atoms;
        epoch_context.observed_actual_mint_atoms =
            epoch_set.actual_mint_atoms;

        context.active_height = attribution.challenge_maturity_height - 1;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &attribution, &context), VCS_ZCODE_CREATION_IMMATURE);
        context.active_height = 9000;
        callbacks.anchor_active = false;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &attribution, &context), VCS_ZCODE_CREATION_REORG);
        callbacks.anchor_active = true; callbacks.duplicate = true;
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &attribution, &context), VCS_ZCODE_CREATION_DUPLICATE);
        callbacks.duplicate = false;

        struct vcs_zcode_creation_attribution_v1 substituted = attribution;
        score_fill(substituted.license_evidence_root, 0xb2);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &substituted, &context), VCS_ZCODE_CREATION_LICENSE);
        substituted = attribution;
        memcpy(substituted.proven_lane_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &substituted, &context), VCS_ZCODE_CREATION_LANE);
        substituted = attribution;
        memcpy(substituted.release_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &substituted, &context), VCS_ZCODE_CREATION_RELEASE);
        substituted = attribution;
        memcpy(substituted.contributor_binding_root, task_root, 32);
        ASSERT_EQ(vcs_zcode_creation_attribution_verify_cas(
                      &substituted, &context),
                  VCS_ZCODE_CREATION_CONTRIBUTOR);

        free(parent_release_wire); free(release_wire); free(manifest_wire);
        vcs_package_manifest_free(&manifest);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reproduction_qualification(void)
{
    int failures = 0;
    TEST("zcode reproduction qualification: CAS policy, identity and exact outputs gate readiness") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_reproduction", "qualification_scratch");
        ASSERT(vcs_object_store_init(workspace));

        uint8_t release_root[32];
        uint8_t package[32], recipe[32], lock[32], capsule[32], network[32];
        ASSERT(zcl_hex_decode_lower(score_packages[0].content, package, 32));
        ASSERT(zcl_hex_decode_lower(score_packages[0].release,
                                    release_root, 32));
        ASSERT(zcl_hex_decode_lower(score_packages[0].recipe, recipe, 32));
        ASSERT(zcl_hex_decode_lower(score_packages[0].lock, lock, 32));
        ASSERT(zcl_hex_decode_lower(score_packages[0].capsule, capsule, 32));
        score_fill(network, 0xa5);

        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_proof_policy_v1 proof_policy;
        struct vcs_zcode_lane_receipt_v1 lane;
        struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS];
        uint8_t lane_secret[32], lane_pubkey[32];
        struct vcs_zcode_contributor_binding_v1 requester_binding;
        struct vcs_zcode_contributor_binding_v1 reproducer_binding;
        uint8_t requester_pubkey[32], requester_secret[32];
        uint8_t reproducer_pubkey[32], reproducer_secret[32];
        ASSERT(qualification_test_binding(
            &requester_binding, network, 0xb1, 0xb2,
            requester_pubkey, requester_secret));
        ASSERT(qualification_test_binding(
            &reproducer_binding, network, 0xc1, 0xc2,
            reproducer_pubkey, reproducer_secret));
        ASSERT(score_fixture_for_roots(
            &task, &candidate, &proof_policy, &lane, works,
            lane_secret, lane_pubkey, package, lock, capsule,
            requester_pubkey));
        uint8_t requester_binding_root[32], reproducer_binding_root[32];
        ASSERT_EQ(vcs_zcode_contributor_binding_root(
                      &requester_binding, requester_binding_root),
                  VCS_ZCODE_BINDING_OK);
        ASSERT_EQ(vcs_zcode_contributor_binding_root(
                      &reproducer_binding, reproducer_binding_root),
                  VCS_ZCODE_BINDING_OK);

        struct vcs_package_build_receipt reference, rebuild;
        vcs_package_build_receipt_init(&reference);
        memcpy(reference.package_root, package, 32);
        memcpy(reference.recipe_root, recipe, 32);
        memcpy(reference.lock_root, lock, 32);
        (void)snprintf(reference.compiler_id, sizeof(reference.compiler_id),
                       "gcc");
        (void)snprintf(reference.compiler_version,
                       sizeof(reference.compiler_version), "15.1");
        (void)snprintf(reference.flags, sizeof(reference.flags), "-std=c23");
        reference.result_class = VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
        reference.isolation = VCS_PACKAGE_BUILD_ISOLATION_FULL;
        reference.test_ran = true;
        uint8_t output_sha3[32]; score_fill(output_sha3, 0xd1);
        ASSERT_EQ(vcs_package_build_add_output(
                      &reference, "lib/libsha3.a", output_sha3, 1234),
                  VCS_PACKAGE_BUILD_OK);
        rebuild = reference;
        (void)snprintf(rebuild.compiler_id, sizeof(rebuild.compiler_id),
                       "clang");
        (void)snprintf(rebuild.compiler_version,
                       sizeof(rebuild.compiler_version), "20.0");
        uint8_t reference_root[32], rebuild_root[32];
        ASSERT_EQ(vcs_package_build_id(&reference, reference_root),
                  VCS_PACKAGE_BUILD_OK);
        ASSERT_EQ(vcs_package_build_id(&rebuild, rebuild_root),
                  VCS_PACKAGE_BUILD_OK);
        ASSERT(memcmp(reference_root, rebuild_root, 32) != 0);

        struct vcs_build_artifact_manifest_v1 manifest;
        memset(&manifest, 0, sizeof(manifest));
        vcs_zcode_score_action_root(
            VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION,
            manifest.action_sha3);
        manifest.total_bytes = 1;
        manifest.chunk_bytes = 1;
        manifest.chunk_count = 1;
        score_fill(manifest.chunk_sha3[0], 0xd2);
        uint8_t manifest_root[32];
        ASSERT(vcs_build_artifact_manifest_v1_root(&manifest, manifest_root));

        struct vcs_zcode_approved_reproducer_set_v1 approved;
        vcs_zcode_approved_reproducer_set_init(&approved);
        approved.sequence = 1;
        memcpy(approved.network_genesis_root, network, 32);
        struct vcs_zcode_approved_reproducer_entry_v1 entry;
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.signer_pubkey, reproducer_pubkey, 32);
        memcpy(entry.contributor_binding_root, reproducer_binding_root, 32);
        score_fill(entry.operator_group_root, 0xd3);
        memcpy(entry.action_root, manifest.action_sha3, 32);
        entry.valid_from_epoch = 0;
        entry.valid_through_epoch = 8;
        entry.valid_from_unix = 1000;
        entry.valid_through_unix = 9000;
        ASSERT_EQ(vcs_zcode_approved_reproducer_set_add(&approved, &entry),
                  VCS_ZCODE_SHADOW_OK);
        uint8_t approved_root[32], covenant[32];
        score_fill(covenant, 0xd4);
        ASSERT_EQ(vcs_zcode_approved_reproducer_set_root(
                      &approved, approved_root), VCS_ZCODE_SHADOW_OK);
        struct vcs_zcode_policy_candidate_v1 policy;
        vcs_zcode_policy_candidate_init(
            &policy, network, approved_root, covenant);
        uint8_t policy_root[32];
        ASSERT_EQ(vcs_zcode_policy_candidate_root(&policy, policy_root),
                  VCS_ZCODE_SHADOW_OK);

        uint8_t task_root[32], candidate_root[32], proof_policy_root[32];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_candidate_root(&candidate, candidate_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_root(
                      &proof_policy, proof_policy_root), VCS_ZCODE_DEV_OK);
        struct vcs_zcode_reproduction_request_v1 request;
        vcs_zcode_reproduction_request_init(&request);
        memcpy(request.network_genesis_root, network, 32);
        memcpy(request.zc23_policy_root, policy_root, 32);
        memcpy(request.task_root, task_root, 32);
        memcpy(request.candidate_root, candidate_root, 32);
        memcpy(request.package_root, package, 32);
        memcpy(request.release_root, release_root, 32);
        memcpy(request.recipe_root, recipe, 32);
        memcpy(request.dependency_lock_root, lock, 32);
        memcpy(request.toolchain_capsule_root, capsule, 32);
        memcpy(request.reference_build_root, reference_root, 32);
        memcpy(request.output_manifest_root, manifest_root, 32);
        memcpy(request.action_root, manifest.action_sha3, 32);
        score_fill(request.challenge_nonce, 0xd5);
        memcpy(request.requester_contributor_binding_root,
               requester_binding_root, 32);
        request.created_unix = 1000;
        request.expires_unix = 605800;
        request.max_cpu_seconds = 60;
        request.max_processes = 4;
        request.max_memory_bytes = 1024 * 1024;
        request.max_output_bytes = 1024 * 1024;
        uint8_t request_root[32];
        ASSERT_EQ(vcs_zcode_reproduction_request_root(
                      &request, request_root), VCS_ZCODE_REPRODUCTION_OK);

        size_t reproduce_index = VCS_ZCODE_SCORE_UNITS;
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++)
            if (works[i].receipt.work_kind == VCS_ZCODE_WORK_REPRODUCE)
                reproduce_index = i;
        ASSERT(reproduce_index < VCS_ZCODE_SCORE_UNITS);

        uint8_t proof_roots[VCS_ZCODE_SCORE_UNITS][32];
        struct vcs_zcode_work_receipt_v1 receipts[VCS_ZCODE_SCORE_UNITS];
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++) {
            memcpy(proof_roots[i], works[i].root, 32);
            receipts[i] = works[i].receipt;
        }
        ASSERT_EQ(vcs_zcode_proof_set_root(
                      proof_roots, VCS_ZCODE_SCORE_UNITS,
                      lane.proof_set_root), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_lane_receipt_seal(
                      &lane, lane_secret, lane_pubkey), VCS_ZCODE_DEV_OK);
        struct vcs_zcode_score_plan_input score_input = {
            .task = &task, .candidate = &candidate,
            .proof_policy = &proof_policy, .proven_lane = &lane,
            .proof_receipt_roots = proof_roots,
            .work_receipts = receipts,
            .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
            .package_root = package, .release_root = release_root,
            .recipe_root = recipe, .dependency_lock_root = lock,
            .api_capsule_root = capsule,
        };
        struct vcs_zcode_score_receipt_v1 score;
        ASSERT_EQ(vcs_zcode_score_plan(&score_input, &score),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(score.awarded_mask, 0x1b);
        ASSERT_EQ(vcs_zcode_score_receipt_seal(
                      &score, lane_secret, lane_pubkey), VCS_ZCODE_SCORE_OK);
        uint8_t score_proof_set_root[32], lane_root[32], score_root[32];
        ASSERT(score_store_vertical(
            workspace, &task, &candidate, &proof_policy, &lane, works,
            &score, task_root, candidate_root, score_proof_set_root,
            lane_root, score_root));

        /* Score v1 remains the historical 4/5 vertical.  The independently
         * signed reproduction result lives in its own policy-bound proof set
         * so the reproducer never needs the requester's lane-signing key. */
        struct vcs_zcode_work_receipt_v1 reproduction_work =
            works[reproduce_index].receipt;
        memcpy(reproduction_work.input_root, request_root, 32);
        memcpy(reproduction_work.output_root, rebuild_root, 32);
        memcpy(reproduction_work.evidence_root, manifest_root, 32);
        reproduction_work.started_unix = 1200;
        reproduction_work.finished_unix = 1300;
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
                      &reproduction_work, reproducer_secret,
                      reproducer_pubkey), VCS_ZCODE_DEV_OK);
        uint8_t reproduction_work_root[32];
        ASSERT_EQ(vcs_zcode_work_receipt_id(
                      &reproduction_work, reproduction_work_root),
                  VCS_ZCODE_DEV_OK);
        uint8_t reproduction_work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(
                      &reproduction_work, reproduction_work_wire),
                  VCS_ZCODE_DEV_OK);
        uint8_t reproduction_proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
        uint8_t reproduction_proof_set_root[32];
        size_t reproduction_proof_len = 0;
        ASSERT_EQ(vcs_zcode_proof_set_serialize(
                      &reproduction_work_root, 1, reproduction_proof_wire,
                      sizeof(reproduction_proof_wire),
                      &reproduction_proof_len), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_set_root(
                      &reproduction_work_root, 1,
                      reproduction_proof_set_root), VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, reproduction_work_root, reproduction_work_wire,
            sizeof(reproduction_work_wire)));
        ASSERT(vcs_object_put_addressed(
            workspace, reproduction_proof_set_root,
            reproduction_proof_wire, reproduction_proof_len));

        uint8_t approved_wire[
            VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES];
        uint8_t policy_wire[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES];
        uint8_t request_wire[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES];
        uint8_t manifest_wire[VCS_BUILD_ARTIFACT_WIRE_MAX];
        uint8_t requester_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
        uint8_t reproducer_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
        size_t approved_len = 0, manifest_len = 0;
        uint8_t *reference_wire = NULL, *rebuild_wire = NULL;
        size_t reference_len = 0, rebuild_len = 0;
        ASSERT_EQ(vcs_zcode_approved_reproducer_set_serialize(
                      &approved, approved_wire, sizeof(approved_wire),
                      &approved_len), VCS_ZCODE_SHADOW_OK);
        ASSERT_EQ(vcs_zcode_policy_candidate_serialize(&policy, policy_wire),
                  VCS_ZCODE_SHADOW_OK);
        ASSERT_EQ(vcs_zcode_reproduction_request_serialize(
                      &request, request_wire), VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(vcs_build_artifact_manifest_v1_serialize(
            &manifest, manifest_wire, sizeof(manifest_wire), &manifest_len));
        ASSERT_EQ(vcs_zcode_contributor_binding_serialize(
                      &requester_binding, requester_wire),
                  VCS_ZCODE_BINDING_OK);
        ASSERT_EQ(vcs_zcode_contributor_binding_serialize(
                      &reproducer_binding, reproducer_wire),
                  VCS_ZCODE_BINDING_OK);
        ASSERT_EQ(vcs_package_build_serialize(
                      &reference, &reference_wire, &reference_len),
                  VCS_PACKAGE_BUILD_OK);
        ASSERT_EQ(vcs_package_build_serialize(
                      &rebuild, &rebuild_wire, &rebuild_len),
                  VCS_PACKAGE_BUILD_OK);
        ASSERT(vcs_object_put_addressed(workspace, approved_root,
                                         approved_wire, approved_len));
        ASSERT(vcs_object_put_addressed(workspace, policy_root, policy_wire,
                                         sizeof(policy_wire)));
        ASSERT(vcs_object_put_addressed(workspace, request_root, request_wire,
                                         sizeof(request_wire)));
        ASSERT(vcs_object_put_addressed(workspace, reference_root,
                                         reference_wire, reference_len));
        ASSERT(vcs_object_put_addressed(workspace, manifest_root,
                                         manifest_wire, manifest_len));
        ASSERT(vcs_object_put_addressed(workspace, requester_binding_root,
                                         requester_wire,
                                         sizeof(requester_wire)));

        struct vcs_zcode_reproduction_qualification_report report;
        ASSERT_EQ(vcs_zcode_reproduction_qualify_cas(
                      workspace, score_root, policy_root, request_root,
                      reproduction_proof_set_root, 4, 1400, &report),
                  VCS_ZCODE_QUALIFICATION_OUTPUT_MISMATCH);
        ASSERT(vcs_object_put_addressed(workspace, rebuild_root,
                                         rebuild_wire, rebuild_len));
        ASSERT_EQ(vcs_zcode_reproduction_qualify_cas(
                      workspace, score_root, policy_root, request_root,
                      reproduction_proof_set_root, 4, 1400, &report),
                  VCS_ZCODE_QUALIFICATION_SIGNER_NOT_APPROVED);
        ASSERT(vcs_object_put_addressed(workspace, reproducer_binding_root,
                                         reproducer_wire,
                                         sizeof(reproducer_wire)));
        ASSERT_EQ(vcs_zcode_reproduction_qualify_cas(
                      workspace, score_root, policy_root, request_root,
                      reproduction_proof_set_root, 9, 1400, &report),
                  VCS_ZCODE_QUALIFICATION_APPROVAL_NOT_VALID);
        ASSERT_EQ(vcs_zcode_reproduction_qualify_cas(
                      workspace, score_root, policy_root, request_root,
                      reproduction_proof_set_root, 4, 1400, &report),
                  VCS_ZCODE_QUALIFICATION_READY);
        ASSERT(report.exact_reproduction_match);
        ASSERT(report.distinct_signer);
        ASSERT(report.signer_policy_approved);
        ASSERT(!report.remote_transport_used);
        ASSERT(!report.physical_independence_proven);
        ASSERT(!report.identity_linkage_complete);
        ASSERT_EQ(report.reproduce_rule, VCS_REPRODUCE_MATCH);

        /* The shadow planner must reload the real frozen package manifest,
         * signed release and LICENSE bytes rather than trusting Score roots. */
        struct vcs_package_prepare_options package_options = {
            .dir = score_packages[0].dir,
            .publisher_sequence = score_packages[0].sequence,
            .reward_address = "",
            .chain_id = "zclassic-main",
        };
        ASSERT(zcl_hex_decode_lower(
            score_packages[0].publisher, package_options.publisher_pubkey,
            sizeof(package_options.publisher_pubkey)));
        struct vcs_package_prepared prepared;
        char prepare_detail[256];
        ASSERT_EQ(vcs_package_prepare(
                      &package_options, &prepared, prepare_detail,
                      sizeof(prepare_detail)), VCS_PACKAGE_PREPARE_OK);
        ASSERT(memcmp(prepared.package_root, package, 32) == 0);
        ASSERT(zcl_hex_decode_lower(
            score_packages[0].signature, prepared.release.signature,
            sizeof(prepared.release.signature)));
        ASSERT_EQ(vcs_package_release_verify(&prepared.release),
                  VCS_PACKAGE_RELEASE_OK);
        uint8_t prepared_release_root[32];
        ASSERT_EQ(vcs_package_release_id(
                      &prepared.release, prepared_release_root),
                  VCS_PACKAGE_RELEASE_OK);
        ASSERT(memcmp(prepared_release_root, release_root, 32) == 0);
        uint8_t *package_release_wire = NULL;
        size_t package_release_wire_len = 0;
        ASSERT_EQ(vcs_package_release_serialize(
                      &prepared.release, &package_release_wire,
                      &package_release_wire_len), VCS_PACKAGE_RELEASE_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, package, prepared.manifest_wire,
            prepared.manifest_wire_len));
        ASSERT(vcs_object_put_addressed(
            workspace, release_root, package_release_wire,
            package_release_wire_len));
        ASSERT(vcs_object_put_addressed(
            workspace, recipe, prepared.recipe_wire,
            prepared.recipe_wire_len));
        ASSERT(vcs_object_put_addressed(
            workspace, lock, prepared.lock_wire, prepared.lock_wire_len));
        ASSERT(vcs_object_put_addressed(
            workspace, capsule, prepared.capsule_wire,
            prepared.capsule_wire_len));
        const struct vcs_package_file *license_file = NULL;
        for (size_t i = 0; i < prepared.manifest.count; i++)
            if (strcmp(prepared.manifest.files[i].path, "LICENSE") == 0)
                license_file = &prepared.manifest.files[i];
        ASSERT(license_file != NULL);
        uint8_t chunk[VCS_PACKAGE_CHUNK_BYTES];
        for (uint32_t i = 0; i < license_file->chunk_count; i++) {
            size_t chunk_len = 0;
            enum vcs_package_publish_rule rule;
            ASSERT(vcs_package_publish_read_chunk(
                score_packages[0].dir, license_file, i, chunk,
                &chunk_len, &rule));
            ASSERT(vcs_object_put_addressed(
                workspace, license_file->chunk_hashes + (size_t)i * 32u,
                chunk, chunk_len));
        }

        /* O5 three-party acceptance.  Every semantic object rides as an
         * existing one-chunk content.v2 blob, while the real package uses
         * its ordinary multi-chunk package-store coordinates.  Child B and
         * child C are separate processes with separate CAS and package
         * stores; no process calls a new transport or trusts copied JSON. */
        char transport_a[256], transport_b[256], transport_c[256];
        char workspace_b[256], workspace_c[256];
        test_make_tmpdir(transport_a, sizeof(transport_a),
                         "zcode_reproduction", "requester_transport");
        test_make_tmpdir(transport_b, sizeof(transport_b),
                         "zcode_reproduction", "reproducer_transport");
        test_make_tmpdir(transport_c, sizeof(transport_c),
                         "zcode_reproduction", "observer_transport");
        test_make_tmpdir(workspace_b, sizeof(workspace_b),
                         "zcode_reproduction", "reproducer_scratch");
        test_make_tmpdir(workspace_c, sizeof(workspace_c),
                         "zcode_reproduction", "observer_scratch");
        uint64_t transport_quota = UINT64_C(256) * 1024u * 1024u;
        struct vcs_package_store *requester_store =
            vcs_package_store_open(transport_a, transport_quota);
        ASSERT(requester_store != NULL);
        uint8_t admitted_package[32];
        ASSERT_EQ(vcs_package_store_put_manifest(
                      requester_store, prepared.manifest_wire,
                      prepared.manifest_wire_len, admitted_package),
                  VCS_PACKAGE_STORE_OK);
        ASSERT(memcmp(admitted_package, package, 32) == 0);
        for (size_t i = 0; i < prepared.manifest.count; i++) {
            const struct vcs_package_file *file = &prepared.manifest.files[i];
            for (uint32_t j = 0; j < file->chunk_count; j++) {
                size_t chunk_len = 0;
                enum vcs_package_publish_rule rule;
                ASSERT(vcs_package_publish_read_chunk(
                    score_packages[0].dir, file, j, chunk,
                    &chunk_len, &rule));
                ASSERT_EQ(vcs_package_store_put_chunk(
                              requester_store, package, file->path, j,
                              chunk, chunk_len), VCS_PACKAGE_STORE_OK);
            }
        }
        ASSERT(vcs_package_store_verify_possession(
            requester_store, package, false));

        struct score_transport_entry request_entries[32];
        size_t request_entry_count = 0;
#define SCORE_EXPORT_ROOT(root_) do {                                      \
    ASSERT(request_entry_count <                                           \
           sizeof(request_entries) / sizeof(request_entries[0]));          \
    ASSERT(score_transport_export(                                         \
        requester_store, workspace, (root_),                               \
        &request_entries[request_entry_count++]));                          \
} while (0)
        SCORE_EXPORT_ROOT(approved_root);
        SCORE_EXPORT_ROOT(policy_root);
        SCORE_EXPORT_ROOT(request_root);
        SCORE_EXPORT_ROOT(reference_root);
        SCORE_EXPORT_ROOT(manifest_root);
        SCORE_EXPORT_ROOT(requester_binding_root);
        SCORE_EXPORT_ROOT(task_root);
        SCORE_EXPORT_ROOT(candidate_root);
        SCORE_EXPORT_ROOT(proof_policy_root);
        SCORE_EXPORT_ROOT(score_proof_set_root);
        SCORE_EXPORT_ROOT(lane_root);
        SCORE_EXPORT_ROOT(score_root);
        SCORE_EXPORT_ROOT(release_root);
        SCORE_EXPORT_ROOT(recipe);
        SCORE_EXPORT_ROOT(lock);
        SCORE_EXPORT_ROOT(capsule);
        for (size_t i = 0; i < VCS_ZCODE_SCORE_UNITS; i++)
            SCORE_EXPORT_ROOT(works[i].root);
#undef SCORE_EXPORT_ROOT
        vcs_package_store_close(requester_store);

        struct score_transport_entry result_entries[4];
        const uint8_t *result_semantic_roots[4] = {
            rebuild_root, reproducer_binding_root,
            reproduction_work_root, reproduction_proof_set_root,
        };
        const uint8_t *result_wires[4] = {
            rebuild_wire, reproducer_wire,
            reproduction_work_wire, reproduction_proof_wire,
        };
        const size_t result_wire_lens[4] = {
            rebuild_len, sizeof(reproducer_wire),
            sizeof(reproduction_work_wire), reproduction_proof_len,
        };
        for (size_t i = 0; i < 4; i++) {
            memcpy(result_entries[i].semantic_root,
                   result_semantic_roots[i], 32);
            ASSERT_EQ(vcs_blob_root_of(
                          result_wires[i], result_wire_lens[i],
                          result_entries[i].transport_root), VCS_BLOB_OK);
        }

        pid_t reproducer_pid = fork();
        ASSERT(reproducer_pid >= 0);
        if (reproducer_pid == 0) {
            bool ok = true;
            struct vcs_package_store *source =
                vcs_package_store_open(transport_a, transport_quota);
            struct vcs_package_store *destination =
                vcs_package_store_open(transport_b, transport_quota);
            ok = source && destination;
            if (ok) {
                struct score_transport_entry corrupt = request_entries[0];
                corrupt.transport_root[0] ^= 1u;
                ok = !score_transport_import(
                    source, destination, workspace_b, &corrupt);
            }
            if (ok && request_entry_count > 0)
                ok = !vcs_object_has(
                    workspace_b,
                    request_entries[request_entry_count - 1].semantic_root);
            for (size_t i = 0; ok && i < request_entry_count; i++)
                ok = score_transport_import(
                    source, destination, workspace_b, &request_entries[i]);
            if (ok)
                ok = score_transport_package(
                    source, destination, workspace_b, package, true);
            struct vcs_package_store_status package_status;
            if (ok)
                ok = vcs_package_store_package_status(
                         destination, package, &package_status) &&
                     !package_status.complete;
            if (ok)
                ok = score_transport_package(
                    source, destination, workspace_b, package, false);

            struct vcs_zcode_work_receipt_v1 signed_result =
                reproduction_work;
            if (ok)
                ok = vcs_zcode_work_receipt_seal(
                         &signed_result, reproducer_secret,
                         reproducer_pubkey) == VCS_ZCODE_DEV_OK;
            uint8_t signed_root[32], signed_wire[
                VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
            if (ok)
                ok = vcs_zcode_work_receipt_id(
                         &signed_result, signed_root) == VCS_ZCODE_DEV_OK &&
                     memcmp(signed_root, reproduction_work_root, 32) == 0 &&
                     vcs_zcode_work_receipt_serialize(
                         &signed_result, signed_wire) == VCS_ZCODE_DEV_OK &&
                     memcmp(signed_wire, reproduction_work_wire,
                            sizeof(signed_wire)) == 0;
            for (size_t i = 0; ok && i < 4; i++) {
                ok = vcs_object_put_addressed(
                         workspace_b, result_semantic_roots[i],
                         result_wires[i], result_wire_lens[i]) &&
                     score_transport_export(
                         destination, workspace_b,
                         result_semantic_roots[i], &result_entries[i]);
            }
            vcs_package_store_close(destination);
            vcs_package_store_close(source);
            _exit(ok ? 0 : 31);
        }
        int reproducer_status = 0;
        ASSERT(waitpid(reproducer_pid, &reproducer_status, 0) ==
               reproducer_pid);
        ASSERT(WIFEXITED(reproducer_status));
        ASSERT_EQ(WEXITSTATUS(reproducer_status), 0);

        /* A cold reopen proves that B's transport/package state, including
         * the resumed package after its deliberate missing-chunk phase,
         * is durable rather than inherited process memory. */
        struct vcs_package_store *restarted_reproducer =
            vcs_package_store_open(transport_b, transport_quota);
        ASSERT(restarted_reproducer != NULL);
        ASSERT(vcs_package_store_verify_possession(
            restarted_reproducer, package, false));
        vcs_package_store_close(restarted_reproducer);

        pid_t observer_pid = fork();
        ASSERT(observer_pid >= 0);
        if (observer_pid == 0) {
            bool ok = true;
            struct vcs_package_store *source =
                vcs_package_store_open(transport_b, transport_quota);
            struct vcs_package_store *destination =
                vcs_package_store_open(transport_c, transport_quota);
            ok = source && destination;
            for (size_t i = 0; ok && i < request_entry_count; i++)
                ok = score_transport_import(
                    source, destination, workspace_c, &request_entries[i]);
            for (size_t i = 0; ok && i < 4; i++)
                ok = score_transport_import(
                    source, destination, workspace_c, &result_entries[i]);
            if (ok)
                ok = score_transport_package(
                    source, destination, workspace_c, package, false);
            struct vcs_zcode_reproduction_qualification_report observed;
            if (ok)
                ok = vcs_zcode_reproduction_qualify_cas(
                         workspace_c, score_root, policy_root, request_root,
                         reproduction_proof_set_root, 0, 605800,
                         &observed) == VCS_ZCODE_QUALIFICATION_READY &&
                     observed.exact_reproduction_match &&
                     observed.distinct_signer &&
                     observed.signer_policy_approved &&
                     !observed.remote_transport_used &&
                     !observed.physical_independence_proven;
            struct vcs_zcode_shadow_attribution_input observed_input = {
                .workspace = workspace_c,
                .score_receipt_root = score_root,
                .policy_candidate_root = policy_root,
                .reproduction_request_root = request_root,
                .reproduction_proof_set_root = reproduction_proof_set_root,
                .contributor_binding_root = requester_binding_root,
                .epoch = 0,
                .now_unix = 605800,
            };
            struct vcs_zcode_shadow_attribution_plan observed_attribution;
            if (ok)
                ok = vcs_zcode_shadow_attribution_plan_cas(
                         &observed_input, &observed_attribution) ==
                     VCS_ZCODE_SHADOW_SIMULATION_OK;
            uint8_t observed_wire[
                VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
            if (ok)
                ok = vcs_zcode_creation_attribution_serialize(
                         &observed_attribution.attribution, observed_wire) ==
                         VCS_ZCODE_CREATION_OK &&
                     vcs_object_put_addressed(
                         workspace_c, observed_attribution.attribution_root,
                         observed_wire, sizeof(observed_wire));
            struct vcs_zcode_shadow_epoch_input observed_epoch_input = {
                .workspace = workspace_c,
                .policy_candidate_root = policy_root,
                .attribution_root = observed_attribution.attribution_root,
                .fixture_branch_root =
                    observed_attribution.fixture_branch_root,
                .previous_epoch_creation_root = (const uint8_t[32]){0},
                .now_unix = 605800,
            };
            struct vcs_zcode_shadow_epoch_plan observed_epoch;
            if (ok)
                ok = vcs_zcode_shadow_epoch_plan_cas(
                         &observed_epoch_input, &observed_epoch) ==
                     VCS_ZCODE_SHADOW_SIMULATION_OK;
            uint8_t *epoch_wire = NULL;
            size_t epoch_wire_len = 0;
            if (ok)
                ok = vcs_zcode_epoch_creation_serialize(
                         &observed_epoch.epoch, &epoch_wire,
                         &epoch_wire_len) == VCS_ZCODE_EPOCH_CREATION_OK &&
                     vcs_object_put_addressed(
                         workspace_c, observed_epoch.epoch_root,
                         epoch_wire, epoch_wire_len);
            free(epoch_wire);
            vcs_zcode_shadow_epoch_plan_free(&observed_epoch);
            struct vcs_zcode_commons_projection *first = ok
                ? vcs_zcode_commons_projection_build(workspace_c) : NULL;
            struct vcs_zcode_commons_projection *second = ok
                ? vcs_zcode_commons_projection_build(workspace_c) : NULL;
            uint8_t first_root[32], second_root[32];
            ok = ok && first && second &&
                vcs_zcode_commons_projection_root(first, first_root) &&
                vcs_zcode_commons_projection_root(second, second_root) &&
                memcmp(first_root, second_root, 32) == 0;
            vcs_zcode_commons_projection_free(second);
            vcs_zcode_commons_projection_free(first);
            vcs_package_store_close(destination);
            vcs_package_store_close(source);
            _exit(ok ? 0 : 32);
        }
        int observer_status = 0;
        ASSERT(waitpid(observer_pid, &observer_status, 0) == observer_pid);
        ASSERT(WIFEXITED(observer_status));
        ASSERT_EQ(WEXITSTATUS(observer_status), 0);
        struct vcs_zcode_commons_projection *observer_projection =
            vcs_zcode_commons_projection_build(workspace_c);
        ASSERT(observer_projection != NULL);
        ASSERT_EQ(vcs_zcode_commons_projection_creation_count(
                      observer_projection), 1);
        ASSERT_EQ(vcs_zcode_commons_projection_epoch_count(
                      observer_projection), 1);
        vcs_zcode_commons_projection_free(observer_projection);
        printf("zcode reproduction acceptance: distinct_signer_simulation=true approved_fixture_policy=true actual_off_host_credit=false requester_pid=%ld reproducer_pid=%ld observer_pid=%ld\n",
               (long)getpid(), (long)reproducer_pid, (long)observer_pid);

        struct vcs_zcode_shadow_attribution_input attribution_input = {
            .workspace = workspace,
            .score_receipt_root = score_root,
            .policy_candidate_root = policy_root,
            .reproduction_request_root = request_root,
            .reproduction_proof_set_root = reproduction_proof_set_root,
            .contributor_binding_root = requester_binding_root,
            .epoch = 0,
            .now_unix = 605800,
        };
        struct vcs_zcode_shadow_attribution_plan attribution_plan;
        struct vcs_zcode_shadow_attribution_plan repeated_attribution;
        ASSERT_EQ(vcs_zcode_shadow_attribution_plan_cas(
                      &attribution_input, &attribution_plan),
                  VCS_ZCODE_SHADOW_SIMULATION_OK);
        ASSERT_EQ(vcs_zcode_shadow_attribution_plan_cas(
                      &attribution_input, &repeated_attribution),
                  VCS_ZCODE_SHADOW_SIMULATION_OK);
        ASSERT(memcmp(attribution_plan.attribution_root,
                      repeated_attribution.attribution_root, 32) == 0);
        ASSERT_EQ(attribution_plan.attribution.award_atoms,
                  VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS);
        ASSERT(!attribution_plan.qualification.physical_independence_proven);
        uint8_t shadow_attribution_wire[
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_creation_attribution_serialize(
                      &attribution_plan.attribution,
                      shadow_attribution_wire), VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, attribution_plan.attribution_root,
            shadow_attribution_wire, sizeof(shadow_attribution_wire)));

        struct vcs_zcode_shadow_epoch_input epoch_input = {
            .workspace = workspace,
            .policy_candidate_root = policy_root,
            .attribution_root = attribution_plan.attribution_root,
            .fixture_branch_root = attribution_plan.fixture_branch_root,
            .previous_epoch_creation_root = (const uint8_t[32]){0},
            .now_unix = 605800,
        };
        struct vcs_zcode_shadow_epoch_plan shadow_epoch;
        ASSERT_EQ(vcs_zcode_shadow_epoch_plan_cas(
                      &epoch_input, &shadow_epoch),
                  VCS_ZCODE_SHADOW_SIMULATION_OK);
        ASSERT_EQ(shadow_epoch.epoch.actual_mint_atoms,
                  attribution_plan.attribution.award_atoms);
        ASSERT_EQ(shadow_epoch.epoch.unissued_atoms,
                  shadow_epoch.epoch.emission_cap_atoms -
                  shadow_epoch.epoch.actual_mint_atoms);

        uint8_t reorg_branch[32];
        memcpy(reorg_branch, attribution_plan.fixture_branch_root, 32);
        reorg_branch[0] ^= 1u;
        epoch_input.fixture_branch_root = reorg_branch;
        struct vcs_zcode_shadow_epoch_plan rejected_epoch;
        ASSERT_EQ(vcs_zcode_shadow_epoch_plan_cas(
                      &epoch_input, &rejected_epoch),
                  VCS_ZCODE_SHADOW_SIMULATION_ANCHOR);
        epoch_input.fixture_branch_root = attribution_plan.fixture_branch_root;
        uint8_t false_predecessor[32]; score_fill(false_predecessor, 0xf1);
        epoch_input.previous_epoch_creation_root = false_predecessor;
        ASSERT_EQ(vcs_zcode_shadow_epoch_plan_cas(
                      &epoch_input, &rejected_epoch),
                  VCS_ZCODE_SHADOW_SIMULATION_PREDECESSOR);
        epoch_input.previous_epoch_creation_root = (const uint8_t[32]){0};

        shadow_epoch.epoch.actual_mint_atoms--;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&shadow_epoch.epoch),
                  VCS_ZCODE_EPOCH_CREATION_SUM);
        shadow_epoch.epoch.actual_mint_atoms++;

        uint8_t substituted_policy[32];
        memcpy(substituted_policy, policy_root, 32);
        substituted_policy[0] ^= 1u;
        attribution_input.policy_candidate_root = substituted_policy;
        ASSERT_EQ(vcs_zcode_shadow_attribution_plan_cas(
                      &attribution_input, &repeated_attribution),
                  VCS_ZCODE_SHADOW_SIMULATION_QUALIFICATION);
        attribution_input.policy_candidate_root = policy_root;
        attribution_input.epoch = 1;
        ASSERT_EQ(vcs_zcode_shadow_attribution_plan_cas(
                      &attribution_input, &repeated_attribution),
                  VCS_ZCODE_SHADOW_SIMULATION_DUPLICATE);
        attribution_input.epoch = 0;

        vcs_zcode_shadow_epoch_plan_free(&shadow_epoch);
        free(package_release_wire);
        vcs_package_prepared_free(&prepared);

        struct vcs_zcode_work_receipt_v1 conflict =
            reproduction_work;
        score_fill(conflict.output_root, 0xe1);
        score_fill(conflict.lease_id, 0xe2);
        uint8_t conflict_seed[32], conflict_secret[32], conflict_pubkey[32];
        score_fill(conflict_seed, 0xe3);
        ed25519_keypair(conflict_pubkey, conflict_secret, conflict_seed);
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
                      &conflict, conflict_secret, conflict_pubkey),
                  VCS_ZCODE_DEV_OK);
        uint8_t conflict_root[32], conflict_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_work_receipt_id(&conflict, conflict_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&conflict, conflict_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(workspace, conflict_root,
                                         conflict_wire,
                                         sizeof(conflict_wire)));
        uint8_t contradictory_roots[2][32];
        memcpy(contradictory_roots[0], reproduction_work_root, 32);
        memcpy(contradictory_roots[1], conflict_root, 32);
        if (memcmp(contradictory_roots[0], contradictory_roots[1], 32) > 0) {
            uint8_t swap[32];
            memcpy(swap, contradictory_roots[0], 32);
            memcpy(contradictory_roots[0], contradictory_roots[1], 32);
            memcpy(contradictory_roots[1], swap, 32);
        }
        uint8_t contradictory_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
        uint8_t contradictory_root[32];
        size_t contradictory_len = 0;
        ASSERT_EQ(vcs_zcode_proof_set_serialize(
                      contradictory_roots, 2, contradictory_wire,
                      sizeof(contradictory_wire), &contradictory_len),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_set_root(
                      contradictory_roots, 2, contradictory_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(workspace, contradictory_root,
                                         contradictory_wire,
                                         contradictory_len));
        ASSERT_EQ(vcs_zcode_reproduction_qualify_cas(
                      workspace, score_root, policy_root, request_root,
                      contradictory_root, 4, 1400, &report),
                  VCS_ZCODE_QUALIFICATION_CONTRADICTION);

        char score_hex[65], policy_hex[65], request_hex[65];
        zcl_hex_encode(score_root, 32, score_hex);
        zcl_hex_encode(policy_root, 32, policy_hex);
        zcl_hex_encode(request_root, 32, request_hex);
        struct json_value command_input;
        json_init(&command_input); json_set_object(&command_input);
        ASSERT(json_push_kv_str(&command_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&command_input, "score_receipt_root",
                                score_hex));
        ASSERT(json_push_kv_str(&command_input, "policy_candidate_root",
                                policy_hex));
        ASSERT(json_push_kv_str(&command_input, "reproduction_request_root",
                                request_hex));
        char proof_set_hex[65];
        zcl_hex_encode(reproduction_proof_set_root, 32, proof_set_hex);
        ASSERT(json_push_kv_str(&command_input,
                                "reproduction_proof_set_root",
                                proof_set_hex));
        ASSERT(json_push_kv_int(&command_input, "epoch", 4));
        ASSERT(json_push_kv_int(&command_input, "now_unix", 1400));
        struct zcl_command_request command_request = {.input = &command_input};
        struct zcl_command_reply command_reply;
        zcl_command_reply_init(&command_reply, "zcl.test.shadow.v1");
        zcl_native_handle_zcode_commons_shadow_plan(
            &command_request, &command_reply);
        ASSERT_EQ(command_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
            &command_reply.data, "shadow_status")),
            "ready_for_shadow_attribution");
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "physical_independence_proven")));
        ASSERT_EQ(json_get_int(json_get(
            &command_reply.data, "shadow_award_atoms")), 0);
        zcl_command_reply_free(&command_reply);
        json_free(&command_input);

        char contributor_hex[65], attribution_hex[65], branch_hex[65];
        char zero_hex[65]; memset(zero_hex, '0', 64); zero_hex[64] = '\0';
        zcl_hex_encode(requester_binding_root, 32, contributor_hex);
        zcl_hex_encode(attribution_plan.attribution_root, 32,
                       attribution_hex);
        zcl_hex_encode(attribution_plan.fixture_branch_root, 32, branch_hex);
        json_init(&command_input); json_set_object(&command_input);
        ASSERT(json_push_kv_str(&command_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&command_input, "score_receipt_root",
                                score_hex));
        ASSERT(json_push_kv_str(&command_input, "policy_candidate_root",
                                policy_hex));
        ASSERT(json_push_kv_str(&command_input, "reproduction_request_root",
                                request_hex));
        ASSERT(json_push_kv_str(&command_input,
                                "reproduction_proof_set_root",
                                proof_set_hex));
        ASSERT(json_push_kv_str(&command_input, "contributor_binding_root",
                                contributor_hex));
        ASSERT(json_push_kv_int(&command_input, "epoch", 0));
        ASSERT(json_push_kv_int(&command_input, "now_unix", 605800));
        command_request.input = &command_input;
        zcl_command_reply_init(&command_reply,
                               "zcl.test.shadow_attribution.v1");
        zcl_native_handle_zcode_commons_shadow_attribution_commit(
            &command_request, &command_reply);
        ASSERT_EQ(command_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&command_reply.data, "simulated")));
        ASSERT(json_get_bool(json_get(&command_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&command_reply.data, "token_exists")));
        ASSERT(!json_get_bool(json_get(&command_reply.data, "funds_moved")));
        ASSERT(!json_get_bool(json_get(&command_reply.data, "custody_used")));
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "genesis_gate_satisfied")));
        ASSERT_STR_EQ(json_get_str(json_get(
            &command_reply.data, "creation_attribution_root")),
            attribution_hex);
        zcl_command_reply_free(&command_reply);
        json_free(&command_input);

        json_init(&command_input); json_set_object(&command_input);
        ASSERT(json_push_kv_str(&command_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&command_input, "policy_candidate_root",
                                policy_hex));
        ASSERT(json_push_kv_str(&command_input, "attribution_root",
                                attribution_hex));
        ASSERT(json_push_kv_str(&command_input, "fixture_branch_root",
                                branch_hex));
        ASSERT(json_push_kv_str(&command_input,
                                "previous_epoch_creation_root", zero_hex));
        ASSERT(json_push_kv_int(&command_input, "now_unix", 605800));
        command_request.input = &command_input;
        zcl_command_reply_init(&command_reply,
                               "zcl.test.shadow_epoch.v1");
        zcl_native_handle_zcode_commons_shadow_epoch_commit(
            &command_request, &command_reply);
        ASSERT_EQ(command_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&command_reply.data, "persisted")));
        ASSERT(json_get_bool(json_get(
            &command_reply.data, "exact_attribution_sum")));
        ASSERT_EQ(json_get_int(json_get(
            &command_reply.data, "actual_mint_atoms")),
            VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS);
        ASSERT(!json_get_bool(json_get(&command_reply.data, "token_exists")));
        zcl_command_reply_free(&command_reply);
        json_free(&command_input);

        json_init(&command_input); json_set_object(&command_input);
        ASSERT(json_push_kv_str(&command_input, "workspace", workspace));
        command_request.input = &command_input;
        zcl_command_reply_init(&command_reply,
                               "zcl.test.shadow_verify.v1");
        zcl_native_handle_zcode_commons_shadow_verify(
            &command_request, &command_reply);
        ASSERT_EQ(command_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&command_reply.data, "simulated")));
        ASSERT(!json_get_bool(json_get(&command_reply.data, "token_exists")));
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "genesis_gate_satisfied")));
        zcl_command_reply_free(&command_reply);
        json_free(&command_input);

        free(rebuild_wire); free(reference_wire);
        test_rm_rf(workspace_c);
        test_rm_rf(workspace_b);
        test_rm_rf(transport_c);
        test_rm_rf(transport_b);
        test_rm_rf(transport_a);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static bool shadow_protocol_package_vertical(
    const char *workspace, const struct score_package_fixture *package,
    const struct vcs_zcode_policy_candidate_v1 *shadow_policy,
    const uint8_t policy_root[32], const uint8_t branch_root[32],
    uint64_t epoch, uint8_t identity_value, uint8_t attribution_root[32])
{
    uint8_t content[32], release_root[32], recipe[32], lock[32], capsule[32];
    if (!workspace || !package || !shadow_policy || !policy_root ||
        !branch_root || !attribution_root ||
        !zcl_hex_decode_lower(package->content, content, 32) ||
        !zcl_hex_decode_lower(package->release, release_root, 32) ||
        !zcl_hex_decode_lower(package->recipe, recipe, 32) ||
        !zcl_hex_decode_lower(package->lock, lock, 32) ||
        !zcl_hex_decode_lower(package->capsule, capsule, 32))
        return false;

    struct vcs_package_prepare_options options = {
        .dir = package->dir,
        .publisher_sequence = package->sequence,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    if (!zcl_hex_decode_lower(package->publisher, options.publisher_pubkey,
                              sizeof(options.publisher_pubkey)))
        return false;
    struct vcs_package_prepared prepared;
    char detail[256];
    if (vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) !=
            VCS_PACKAGE_PREPARE_OK ||
        !zcl_hex_decode_lower(package->signature, prepared.release.signature,
                              sizeof(prepared.release.signature)) ||
        vcs_package_release_verify(&prepared.release) !=
            VCS_PACKAGE_RELEASE_OK ||
        prepared.release.has_parent ||
        memcmp(prepared.package_root, content, 32) != 0) {
        vcs_package_prepared_free(&prepared);
        return false;
    }
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    uint8_t observed_release[32];
    bool ok = vcs_package_release_id(
                  &prepared.release, observed_release) ==
                  VCS_PACKAGE_RELEASE_OK &&
        memcmp(observed_release, release_root, 32) == 0 &&
        vcs_package_release_serialize(
            &prepared.release, &release_wire, &release_wire_len) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_object_put_addressed(workspace, content, prepared.manifest_wire,
                                 prepared.manifest_wire_len) &&
        vcs_object_put_addressed(workspace, release_root, release_wire,
                                 release_wire_len) &&
        vcs_object_put_addressed(workspace, recipe, prepared.recipe_wire,
                                 prepared.recipe_wire_len) &&
        vcs_object_put_addressed(workspace, lock, prepared.lock_wire,
                                 prepared.lock_wire_len) &&
        vcs_object_put_addressed(workspace, capsule, prepared.capsule_wire,
                                 prepared.capsule_wire_len);
    free(release_wire);

    const struct vcs_package_file *license_file = NULL;
    for (size_t i = 0; ok && i < prepared.manifest.count; i++)
        if (strcmp(prepared.manifest.files[i].path, "LICENSE") == 0)
            license_file = &prepared.manifest.files[i];
    uint8_t license_root[32];
    ok = ok && license_file &&
        vcs_package_file_hash(license_file, license_root);
    uint8_t chunk[VCS_PACKAGE_CHUNK_BYTES];
    for (uint32_t i = 0; ok && i < license_file->chunk_count; i++) {
        size_t chunk_len = 0;
        enum vcs_package_publish_rule rule;
        ok = vcs_package_publish_read_chunk(
                 package->dir, license_file, i, chunk, &chunk_len, &rule) &&
            vcs_object_put_addressed(
                workspace, license_file->chunk_hashes + (size_t)i * 32u,
                chunk, chunk_len);
    }
    if (!ok) {
        vcs_package_prepared_free(&prepared);
        return false;
    }

    uint8_t zid_pubkey[32], zid_secret[32];
    struct vcs_zcode_contributor_binding_v1 binding;
    if (!qualification_test_binding(
            &binding, shadow_policy->network_genesis_root,
            identity_value, (uint8_t)(identity_value + 1u),
            zid_pubkey, zid_secret)) {
        vcs_package_prepared_free(&prepared);
        return false;
    }
    uint8_t binding_root[32];
    uint8_t binding_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    ok = vcs_zcode_contributor_binding_root(
             &binding, binding_root) == VCS_ZCODE_BINDING_OK &&
        vcs_zcode_contributor_binding_serialize(
            &binding, binding_wire) == VCS_ZCODE_BINDING_OK &&
        vcs_object_put_addressed(workspace, binding_root, binding_wire,
                                 sizeof(binding_wire));

    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 proof_policy;
    struct vcs_zcode_lane_receipt_v1 lane;
    struct score_work_fixture works[VCS_ZCODE_SCORE_UNITS];
    uint8_t lane_secret[32], lane_pubkey[32];
    ok = ok && score_fixture_for_roots(
        &task, &candidate, &proof_policy, &lane, works,
        lane_secret, lane_pubkey, content, lock, capsule, zid_pubkey);
    uint8_t proof_roots[VCS_ZCODE_SCORE_UNITS][32];
    struct vcs_zcode_work_receipt_v1 receipts[VCS_ZCODE_SCORE_UNITS];
    for (size_t i = 0; ok && i < VCS_ZCODE_SCORE_UNITS; i++) {
        memcpy(proof_roots[i], works[i].root, 32);
        receipts[i] = works[i].receipt;
    }
    struct vcs_zcode_score_plan_input score_input = {
        .task = &task, .candidate = &candidate,
        .proof_policy = &proof_policy, .proven_lane = &lane,
        .proof_receipt_roots = proof_roots,
        .work_receipts = receipts,
        .work_receipt_count = VCS_ZCODE_SCORE_UNITS,
        .package_root = content, .release_root = release_root,
        .recipe_root = recipe, .dependency_lock_root = lock,
        .api_capsule_root = capsule,
    };
    struct vcs_zcode_score_receipt_v1 score;
    ok = ok && vcs_zcode_score_plan(&score_input, &score) ==
                   VCS_ZCODE_SCORE_OK &&
        vcs_zcode_score_receipt_seal(&score, lane_secret, lane_pubkey) ==
            VCS_ZCODE_SCORE_OK;
    uint8_t task_root[32], candidate_root[32], proof_set_root[32];
    uint8_t lane_root[32], score_root[32], proof_policy_root[32];
    ok = ok && score_store_vertical(
        workspace, &task, &candidate, &proof_policy, &lane, works,
        &score, task_root, candidate_root, proof_set_root,
        lane_root, score_root) &&
        vcs_zcode_proof_policy_root(
            &proof_policy, proof_policy_root) == VCS_ZCODE_DEV_OK;

    struct vcs_zcode_creation_attribution_v1 attribution;
    memset(&attribution, 0, sizeof(attribution));
    attribution.schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    attribution.category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
    attribution.epoch = epoch;
    ok = ok && vcs_zcode_policy_candidate_award_atoms(
        shadow_policy, attribution.category, &attribution.award_atoms) ==
        VCS_ZCODE_SHADOW_OK;
    uint64_t stride = VCS_ZC23_CHALLENGE_BLOCKS * 2u;
    attribution.challenge_opening_height = epoch * stride;
    attribution.challenge_maturity_height =
        attribution.challenge_opening_height + VCS_ZC23_CHALLENGE_BLOCKS;
    attribution.challenge_opening_mtp = 1000 + (int64_t)epoch;
    attribution.challenge_maturity_mtp =
        attribution.challenge_opening_mtp + VCS_ZC23_CHALLENGE_SECONDS;
    attribution.created_unix = attribution.challenge_maturity_mtp;
    ok = ok && vcs_zcode_shadow_fixture_anchor_root(
        policy_root, branch_root, epoch, 1,
        attribution.challenge_opening_hash);
    memcpy(attribution.network_genesis_root,
           shadow_policy->network_genesis_root, 32);
    memcpy(attribution.zc23_policy_root, policy_root, 32);
    memcpy(attribution.contributor_binding_root, binding_root, 32);
    memcpy(attribution.task_root, task_root, 32);
    memcpy(attribution.candidate_root, candidate_root, 32);
    memcpy(attribution.proof_policy_root, proof_policy_root, 32);
    memcpy(attribution.proof_set_root, proof_set_root, 32);
    memcpy(attribution.proven_lane_root, lane_root, 32);
    memcpy(attribution.score_receipt_root, score_root, 32);
    memcpy(attribution.package_root, content, 32);
    memcpy(attribution.release_root, release_root, 32);
    memcpy(attribution.license_evidence_root, license_root, 32);
    attribution.lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
    uint8_t attribution_wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
    ok = ok && vcs_zcode_creation_attribution_serialize(
                   &attribution, attribution_wire) == VCS_ZCODE_CREATION_OK &&
        vcs_zcode_creation_attribution_root(
            &attribution, attribution_root) == VCS_ZCODE_CREATION_OK &&
        vcs_object_put_addressed(workspace, attribution_root,
                                 attribution_wire,
                                 sizeof(attribution_wire));
    vcs_package_prepared_free(&prepared);
    return ok;
}

static bool shadow_protocol_epoch_store(
    const char *workspace,
    const struct vcs_zcode_policy_candidate_v1 *policy,
    const uint8_t policy_root[32], const uint8_t branch_root[32],
    const uint8_t previous_root[32], const uint8_t *attribution_root,
    uint64_t epoch, uint8_t out_root[32])
{
    struct vcs_zcode_epoch_creation_set_v1 set;
    vcs_zcode_epoch_creation_init(&set);
    set.schema_version = VCS_ZCODE_EPOCH_CREATION_VERSION;
    set.epoch = epoch;
    bool ok = vcs_zc23_policy_epoch_cap_atoms(
                  epoch, &set.emission_cap_atoms) ==
                  VCS_ZCODE_EPOCH_CREATION_OK;
    if (attribution_root) {
        set.actual_mint_atoms = VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS;
        set.attribution_roots = zcl_malloc(
            sizeof(*set.attribution_roots), "shadow_protocol_epoch_root");
        ok = ok && set.attribution_roots != NULL;
        if (set.attribution_roots) {
            memcpy(set.attribution_roots[0], attribution_root, 32);
            set.attribution_count = 1;
        }
    }
    set.unissued_atoms = set.emission_cap_atoms - set.actual_mint_atoms;
    memcpy(set.network_genesis_root, policy->network_genesis_root, 32);
    memcpy(set.zc23_policy_root, policy_root, 32);
    memcpy(set.previous_epoch_creation_root, previous_root, 32);
    memcpy(set.committee_evidence_snapshot_root, branch_root, 32);
    set.opening_height = epoch * VCS_ZC23_CHALLENGE_BLOCKS * 2u;
    set.maturity_height = set.opening_height + VCS_ZC23_CHALLENGE_BLOCKS;
    set.opening_mtp = 1000 + (int64_t)epoch;
    set.maturity_mtp = set.opening_mtp + VCS_ZC23_CHALLENGE_SECONDS;
    ok = ok && vcs_zcode_shadow_fixture_anchor_root(
        policy_root, branch_root, epoch, 1, set.opening_hash) &&
        vcs_zcode_shadow_fixture_anchor_root(
            policy_root, branch_root, epoch, 2, set.maturity_hash);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ok = ok && vcs_zcode_epoch_creation_root(&set, out_root) ==
                   VCS_ZCODE_EPOCH_CREATION_OK &&
        vcs_zcode_epoch_creation_serialize(
            &set, &wire, &wire_len) == VCS_ZCODE_EPOCH_CREATION_OK &&
        vcs_object_put_addressed(workspace, out_root, wire, wire_len);
    free(wire);
    vcs_zcode_epoch_creation_free(&set);
    return ok;
}

static int test_shadow_protocol_contract(void)
{
    int failures = 0;
    TEST("ZC23 shadow protocol: four-epoch verifier fails closed") {
        struct vcs_zcode_shadow_protocol_report report;
        ASSERT_EQ(vcs_zcode_shadow_protocol_verify_cas(NULL, &report),
                  VCS_ZCODE_SHADOW_SIMULATION_NULL);
        ASSERT_EQ(report.epoch_count, 0);

        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_shadow_protocol", "four_epochs");
        ASSERT(vcs_object_store_init(workspace));
        uint8_t network[32], approved_root[32], covenant[32], policy_root[32];
        score_fill(network, 0xa5); score_fill(approved_root, 0xa6);
        score_fill(covenant, 0xa7);
        struct vcs_zcode_policy_candidate_v1 policy;
        vcs_zcode_policy_candidate_init(
            &policy, network, approved_root, covenant);
        uint8_t policy_wire[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_policy_candidate_root(&policy, policy_root),
                  VCS_ZCODE_SHADOW_OK);
        ASSERT_EQ(vcs_zcode_policy_candidate_serialize(&policy, policy_wire),
                  VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_object_put_addressed(workspace, policy_root, policy_wire,
                                        sizeof(policy_wire)));

        uint8_t branches[4][32], replacement_branches[4][32];
        uint8_t attribution_roots[3][32];
        for (size_t i = 0; i < 4; i++) {
            score_fill(branches[i], (uint8_t)(0xd0 + i));
            memcpy(replacement_branches[i], branches[i], 32);
        }
        score_fill(replacement_branches[2], 0xe2);
        score_fill(replacement_branches[3], 0xe3);
        static const size_t package_order[3] = {0, 1, 2};
        for (size_t i = 0; i < 3; i++)
            ASSERT(shadow_protocol_package_vertical(
                workspace, &score_packages[package_order[i]], &policy,
                policy_root, branches[i], i, (uint8_t)(0xb0 + i * 2u),
                attribution_roots[i]));

        uint8_t roots[4][32], zero[32] = {0};
        for (size_t i = 0; i < 4; i++) {
            const uint8_t *previous = i == 0 ? zero : roots[i - 1];
            ASSERT(shadow_protocol_epoch_store(
                workspace, &policy, policy_root, branches[i], previous,
                i < 3 ? attribution_roots[i] : NULL, i, roots[i]));
            struct vcs_zcode_commons_projection *first =
                vcs_zcode_commons_projection_build(workspace);
            struct vcs_zcode_commons_projection *second =
                vcs_zcode_commons_projection_build(workspace);
            uint8_t first_root[32], second_root[32];
            ASSERT(first && second);
            ASSERT(vcs_zcode_commons_projection_root(first, first_root));
            ASSERT(vcs_zcode_commons_projection_root(second, second_root));
            ASSERT(memcmp(first_root, second_root, 32) == 0);
            vcs_zcode_commons_projection_free(second);
            vcs_zcode_commons_projection_free(first);
        }
        struct vcs_zcode_shadow_protocol_input input = {
            .workspace = workspace,
            .policy_candidate_root = policy_root,
            .epoch_roots = roots,
            .fixture_branch_roots = branches,
            .now_unix = 700000,
        };
        enum vcs_zcode_shadow_simulation_error protocol_error =
            vcs_zcode_shadow_protocol_verify_cas(&input, &report);
        if (protocol_error != VCS_ZCODE_SHADOW_SIMULATION_OK)
            printf("shadow protocol first verify: %s\n",
                   vcs_zcode_shadow_simulation_error_string(protocol_error));
        ASSERT_EQ(protocol_error, VCS_ZCODE_SHADOW_SIMULATION_OK);
        ASSERT_EQ(report.epoch_count, 4);
        ASSERT_EQ(report.cumulative_issue_atoms,
                  UINT64_C(300000000));
        ASSERT_EQ(report.cumulative_attributed_atoms,
                  report.cumulative_issue_atoms);
        ASSERT(report.cumulative_equality);
        ASSERT(!report.real_genesis_gate_satisfied);
        ASSERT_EQ(report.epochs[3].creations, 0);
        ASSERT_EQ(report.epochs[3].simulated_issue_atoms, 0);
        uint8_t original_projection_root[32];
        memcpy(original_projection_root, report.active_projection_root, 32);
        struct vcs_zcode_shadow_protocol_report repeated;
        ASSERT_EQ(vcs_zcode_shadow_protocol_verify_cas(&input, &repeated),
                  VCS_ZCODE_SHADOW_SIMULATION_OK);
        ASSERT(memcmp(original_projection_root,
                      repeated.active_projection_root, 32) == 0);

        uint8_t *duplicate_wire = NULL;
        size_t duplicate_wire_len = 0;
        struct vcs_zcode_creation_attribution_v1 duplicate_attribution;
        ASSERT_EQ(vcs_object_load_raw_bounded(
                      workspace, attribution_roots[0],
                      VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES,
                      &duplicate_wire, &duplicate_wire_len), 0);
        ASSERT_EQ(vcs_zcode_creation_attribution_parse(
                      duplicate_wire, duplicate_wire_len,
                      &duplicate_attribution), VCS_ZCODE_CREATION_OK);
        free(duplicate_wire); duplicate_wire = NULL;
        duplicate_attribution.epoch = 1;
        duplicate_attribution.challenge_opening_height =
            VCS_ZC23_CHALLENGE_BLOCKS * 2u;
        duplicate_attribution.challenge_maturity_height =
            duplicate_attribution.challenge_opening_height +
            VCS_ZC23_CHALLENGE_BLOCKS;
        duplicate_attribution.challenge_opening_mtp = 1001;
        duplicate_attribution.challenge_maturity_mtp =
            1001 + VCS_ZC23_CHALLENGE_SECONDS;
        duplicate_attribution.created_unix =
            duplicate_attribution.challenge_maturity_mtp;
        ASSERT(vcs_zcode_shadow_fixture_anchor_root(
            policy_root, branches[1], 1, 1,
            duplicate_attribution.challenge_opening_hash));
        uint8_t duplicate_attribution_root[32];
        uint8_t duplicate_attribution_bytes[
            VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_creation_attribution_root(
                      &duplicate_attribution,
                      duplicate_attribution_root),
                  VCS_ZCODE_CREATION_OK);
        ASSERT_EQ(vcs_zcode_creation_attribution_serialize(
                      &duplicate_attribution,
                      duplicate_attribution_bytes),
                  VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
            workspace, duplicate_attribution_root,
            duplicate_attribution_bytes,
            sizeof(duplicate_attribution_bytes)));
        uint8_t duplicate_epoch_root[32];
        ASSERT(shadow_protocol_epoch_store(
            workspace, &policy, policy_root, branches[1], roots[0],
            duplicate_attribution_root, 1, duplicate_epoch_root));
        uint8_t duplicate_roots[4][32];
        memcpy(duplicate_roots, roots, sizeof(duplicate_roots));
        memcpy(duplicate_roots[1], duplicate_epoch_root, 32);
        input.epoch_roots = duplicate_roots;
        protocol_error = vcs_zcode_shadow_protocol_verify_cas(
            &input, &repeated);
        ASSERT_EQ(protocol_error, VCS_ZCODE_SHADOW_SIMULATION_DUPLICATE);
        ASSERT_EQ(repeated.epoch_count, 0);
        input.epoch_roots = roots;

        input.fixture_branch_roots = replacement_branches;
        ASSERT_EQ(vcs_zcode_shadow_protocol_verify_cas(&input, &repeated),
                  VCS_ZCODE_SHADOW_SIMULATION_ANCHOR);
        ASSERT_EQ(repeated.epoch_count, 0);

        uint8_t replacement_attributions[2][32];
        for (size_t i = 2; i < 4; i++) {
            if (i < 3)
                ASSERT(shadow_protocol_package_vertical(
                    workspace, &score_packages[package_order[i]], &policy,
                    policy_root, replacement_branches[i], i,
                    (uint8_t)(0xb0 + i * 2u),
                    replacement_attributions[i - 2]));
        }
        uint8_t replacement_roots[4][32];
        memcpy(replacement_roots[0], roots[0], 32);
        memcpy(replacement_roots[1], roots[1], 32);
        ASSERT(shadow_protocol_epoch_store(
            workspace, &policy, policy_root, replacement_branches[2],
            replacement_roots[1], replacement_attributions[0], 2,
            replacement_roots[2]));
        ASSERT(shadow_protocol_epoch_store(
            workspace, &policy, policy_root, replacement_branches[3],
            replacement_roots[2], NULL, 3, replacement_roots[3]));
        input.epoch_roots = replacement_roots;
        ASSERT_EQ(vcs_zcode_shadow_protocol_verify_cas(&input, &repeated),
                  VCS_ZCODE_SHADOW_SIMULATION_OK);
        ASSERT(repeated.cumulative_equality);
        ASSERT_EQ(repeated.cumulative_issue_atoms,
                  report.cumulative_issue_atoms);
        ASSERT(memcmp(original_projection_root,
                      repeated.active_projection_root, 32) != 0);

        char policy_hex[65], epoch_hex[4][65], branch_hex[4][65];
        zcl_hex_encode(policy_root, 32, policy_hex);
        for (size_t i = 0; i < 4; i++) {
            zcl_hex_encode(replacement_roots[i], 32, epoch_hex[i]);
            zcl_hex_encode(replacement_branches[i], 32, branch_hex[i]);
        }
        struct json_value command_input;
        json_init(&command_input); json_set_object(&command_input);
        ASSERT(json_push_kv_str(&command_input, "workspace", workspace));
        ASSERT(json_push_kv_str(&command_input, "policy_candidate_root",
                                policy_hex));
        static const char *const epoch_keys[4] = {
            "epoch_0_root", "epoch_1_root", "epoch_2_root", "epoch_3_root",
        };
        static const char *const branch_keys[4] = {
            "branch_0_root", "branch_1_root", "branch_2_root", "branch_3_root",
        };
        for (size_t i = 0; i < 4; i++) {
            ASSERT(json_push_kv_str(&command_input, epoch_keys[i],
                                    epoch_hex[i]));
            ASSERT(json_push_kv_str(&command_input, branch_keys[i],
                                    branch_hex[i]));
        }
        ASSERT(json_push_kv_int(&command_input, "now_unix", 700000));
        struct zcl_command_request command_request = {
            .input = &command_input,
        };
        struct zcl_command_reply command_reply;
        zcl_command_reply_init(&command_reply,
                               "zcl.test.shadow_protocol.v1");
        zcl_native_handle_zcode_commons_shadow_protocol_verify(
            &command_request, &command_reply);
        ASSERT_EQ(command_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const struct json_value *epochs_json = json_get(
            &command_reply.data, "epochs");
        ASSERT(epochs_json && epochs_json->type == JSON_ARR);
        ASSERT_EQ(epochs_json->num_children, 4);
        ASSERT_EQ(json_get_int(json_get(
            &command_reply.data, "cumulative_issue_atoms")),
            UINT64_C(300000000));
        ASSERT_EQ(json_get_int(json_get(
            &command_reply.data, "cumulative_attributed_atoms")),
            UINT64_C(300000000));
        ASSERT(json_get_bool(json_get(
            &command_reply.data, "cumulative_equality")));
        ASSERT(json_get_bool(json_get(
            &command_reply.data, "protocol_shadow_simulations")));
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "owner_required_green_shadow_epochs")));
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "genesis_gate_satisfied")));
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "token_exists")));
        ASSERT(!json_get_bool(json_get(
            &command_reply.data, "funds_moved")));
        zcl_command_reply_free(&command_reply);
        json_free(&command_input);

        uint8_t mixed_roots[4][32];
        memcpy(mixed_roots, replacement_roots, sizeof(mixed_roots));
        memcpy(mixed_roots[2], roots[2], 32);
        input.epoch_roots = mixed_roots;
        ASSERT_EQ(vcs_zcode_shadow_protocol_verify_cas(&input, &repeated),
                  VCS_ZCODE_SHADOW_SIMULATION_ANCHOR);
        input.epoch_roots = replacement_roots;
        input.fixture_branch_roots = branches;
        ASSERT_EQ(vcs_zcode_shadow_protocol_verify_cas(&input, &repeated),
                  VCS_ZCODE_SHADOW_SIMULATION_ANCHOR);

        printf("zcode shadow protocol simulations: epoch0=%s epoch1=%s epoch2=%s epoch3=%s cumulative_issue=%llu cumulative_attributed=%llu real_genesis_gate_satisfied=false\n",
               epoch_hex[0], epoch_hex[1], epoch_hex[2], epoch_hex[3],
               (unsigned long long)report.cumulative_issue_atoms,
               (unsigned long long)report.cumulative_attributed_atoms);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcode_score_receipt_platform_arm(void)
{
    int failures = test_score_happy_path();
    printf("=== zcode_score_receipt: %d failures ===\n", failures);
    return failures;
}

int test_zcode_score_receipt_packages(void)
{
    return test_score_package_verticals();
}

int test_zcode_score_receipt_rejections(void)
{
    return test_score_rejections();
}

int test_zcode_score_receipt_creation(void)
{
    return test_creation_attribution_cross_validation();
}

int test_zcode_score_receipt_patronage(void)
{
    return test_patronage_intent_cross_validation();
}

int test_zcode_score_receipt_reproduction(void)
{
    return test_reproduction_qualification();
}

int test_zcode_score_receipt_shadow(void)
{
    return test_shadow_protocol_contract();
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked score-receipt child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_zcode_score_receipt_platform_arm(void)
{
    printf("zcode_score_receipt: SKIP (Windows): forked score-receipt child lane\n");
    return 0;
}

#define ZCL_SCORE_RECEIPT_WIN_SKIP(entry) \
int entry(void) \
{ \
    printf(#entry ": SKIP (Windows): forked score-receipt child lane\n"); \
    return 0; \
}

ZCL_SCORE_RECEIPT_WIN_SKIP(test_zcode_score_receipt_packages)
ZCL_SCORE_RECEIPT_WIN_SKIP(test_zcode_score_receipt_rejections)
ZCL_SCORE_RECEIPT_WIN_SKIP(test_zcode_score_receipt_creation)
ZCL_SCORE_RECEIPT_WIN_SKIP(test_zcode_score_receipt_patronage)
ZCL_SCORE_RECEIPT_WIN_SKIP(test_zcode_score_receipt_reproduction)
ZCL_SCORE_RECEIPT_WIN_SKIP(test_zcode_score_receipt_shadow)

#undef ZCL_SCORE_RECEIPT_WIN_SKIP
#endif

int test_zcode_score_receipt(void)
{
    return test_zcode_score_receipt_platform_arm();
}
