/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KATs and adversarial economics/moderation tests for the Living
 * Commons family. */
#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "crypto/ed25519.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "services/zcode_c23_corpus_service.h"
#include "services/zcode_c23_economics_service.h"
#include "services/zcode_moderation_view_service.h"
#include "vcs/zcode_c23_corpus.h"
#include "vcs/zcode_commons.h"

#include <string.h>

static const char policy_root_kat[] =
    "8fc1df9547d1842004e86c1a06714829965693c031f8e3a16dd2fe38ee6f6ad9";
static const char family_root_kat[] =
    "460d650c5be714f27dde287c368eafb781467026a1c06a8215fbe17dc610ea86";
static const char receipt_root_kat[] =
    "8397de3e2a67dadd9e49fa1d9e2593ad72f01632a4c0cbab2370bff25c470cb9";
static const char asset_root_kat[] =
    "696e2ec2105c03754627c18991ed351b134ffe9942795e4626410e6c43f3ee61";
static const char workspace_root_kat[] =
    "3053aad90f975aa7d6548784bc80d90f9b51364afec4c5593a44e2d019ee4128";
static const char workspace_unsigned_root_kat[] =
    "657c51479ea5b6f95fb34b7659b570cb65a2509d3f87289541f6d893bd565acc";
static const char source_assignment_root_kat[] =
    "3c6d904fd178e8e888fc3479ff087f4e2a579412185232aa3feecb9d99d95be7";
static const char c23_corpus_rules_root_kat[] =
    "ae0c059c8c925464a7d9376b17687b207027833f5337dc49944bcd1b55d3be23";

static bool cv2_candidate_render_status(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    struct zcode_c23_corpus_status_result_v1 *out)
{
    if (!zcode_c23_corpus_service_builtin()->render_status(checkpoint, out))
        return false;
    (void)snprintf(out->blocker, sizeof(out->blocker),
                   "candidate corpus service generation is active");
    return true;
}

static bool cv2_candidate_render_economics_status(
    struct zcode_c23_economics_status_result_v1 *out)
{
    if (!zcode_c23_economics_service_builtin()->render_status(out))
        return false;
    (void)snprintf(out->category_order, sizeof(out->category_order),
                   "candidate economics service generation is active");
    return true;
}

static bool cv2_candidate_render_backlog_status(
    const struct zcode_c23_backlog_status_input_v1 *input,
    struct zcode_c23_backlog_status_result_v1 *out)
{
    if (!zcode_c23_economics_service_builtin()->render_backlog_status(
            input, out))
        return false;
    if (!input->projection_ready)
        (void)snprintf(out->reason, sizeof(out->reason),
                       "candidate backlog generation is active");
    return true;
}

static enum vcs_zcode_c23_error cv2_candidate_checkpoint_accept_all(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint)
{
    (void)checkpoint;
    return VCS_ZCODE_C23_OK;
}

static enum vcs_zcode_c23_error cv2_candidate_checkpoint_selective(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint)
{
    enum vcs_zcode_c23_error error =
        zcode_c23_corpus_service_builtin()->checkpoint_validate(checkpoint);
    return error == VCS_ZCODE_C23_OK && checkpoint->cutoff_height == 100
        ? VCS_ZCODE_C23_PROOF : error;
}

static enum vcs_zcode_c23_error cv2_candidate_shard_accept_all(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard)
{
    (void)shard;
    return VCS_ZCODE_C23_OK;
}

static enum vcs_zcode_c23_error cv2_candidate_shard_selective(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard)
{
    enum vcs_zcode_c23_error error =
        zcode_c23_corpus_service_builtin()->shard_validate(shard);
    return error == VCS_ZCODE_C23_OK &&
                   shard->entries[0].release_sequence == 700
        ? VCS_ZCODE_C23_PROOF : error;
}

static enum vcs_zcode_c23_error cv2_candidate_shard_page_accept_all(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    const struct vcs_zcode_c23_page_cursor_v1 *cursor, size_t page_size,
    size_t *first_index, size_t *item_count,
    struct vcs_zcode_c23_page_cursor_v1 *next_cursor, bool *has_more)
{
    (void)shard; (void)cursor; (void)page_size;
    if (first_index) *first_index = 0;
    if (item_count) *item_count = 1;
    if (next_cursor) memset(next_cursor, 0, sizeof(*next_cursor));
    if (has_more) *has_more = false;
    return VCS_ZCODE_C23_OK;
}

static enum vcs_zcode_c23_error cv2_candidate_shard_page_selective(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    const struct vcs_zcode_c23_page_cursor_v1 *cursor, size_t page_size,
    size_t *first_index, size_t *item_count,
    struct vcs_zcode_c23_page_cursor_v1 *next_cursor, bool *has_more)
{
    enum vcs_zcode_c23_error error =
        zcode_c23_corpus_service_builtin()->shard_page(
            shard, cursor, page_size, first_index, item_count, next_cursor,
            has_more);
    return error == VCS_ZCODE_C23_OK && page_size == 2
        ? VCS_ZCODE_C23_PROOF : error;
}

static enum vcs_zcode_c23_error cv2_candidate_productivity_accept_all(
    const struct vcs_zcode_productivity_receipt_v1 *receipt)
{
    (void)receipt;
    return VCS_ZCODE_C23_OK;
}

static enum vcs_zcode_c23_error cv2_candidate_productivity_selective(
    const struct vcs_zcode_productivity_receipt_v1 *receipt)
{
    enum vcs_zcode_c23_error error =
        zcode_c23_corpus_service_builtin()->productivity_validate(receipt);
    return error == VCS_ZCODE_C23_OK && receipt->completed_height == 700
        ? VCS_ZCODE_C23_PROOF : error;
}

static void cv2_fill(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static bool cv2_policy(struct vcs_zcode_policy_candidate_v2 *policy,
                       struct vcs_zcode_family_policy_v1 *family)
{
    uint8_t family_root[32];
    vcs_zcode_family_policy_v1_default(family);
    if (vcs_zcode_family_policy_v1_root(family, family_root) !=
        VCS_ZCODE_COMMONS_OK)
        return false;
    uint8_t network[32], qualification[32], backlog[32];
    cv2_fill(network, 0x21); cv2_fill(qualification, 0x22);
    cv2_fill(backlog, 0x23);
    vcs_zcode_policy_candidate_v2_init(policy, network, family_root,
                                       qualification, backlog);
    return vcs_zcode_policy_candidate_v2_validate(policy) ==
           VCS_ZCODE_COMMONS_OK;
}

static int test_v2_policy_kats(void)
{
    int failures = 0;
    TEST("v2 economics and immutable family-c23.v1 policy have frozen roots") {
        struct vcs_zcode_policy_candidate_v2 policy;
        struct vcs_zcode_family_policy_v1 family;
        ASSERT(cv2_policy(&policy, &family));
        uint8_t policy_root[32], family_root[32], expected[32];
        ASSERT_EQ(vcs_zcode_policy_candidate_v2_root(&policy, policy_root),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(vcs_zcode_family_policy_v1_root(&family, family_root),
                  VCS_ZCODE_COMMONS_OK);
        char phex[65], fhex[65];
        zcl_hex_encode(policy_root, 32, phex);
        zcl_hex_encode(family_root, 32, fhex);
        printf("policy_candidate.v2 policy=%s family-c23.v1=%s\n", phex, fhex);
        ASSERT(zcl_hex_decode(policy_root_kat, expected, 32));
        ASSERT(memcmp(policy_root, expected, 32) == 0);
        ASSERT(zcl_hex_decode(family_root_kat, expected, 32));
        ASSERT(memcmp(family_root, expected, 32) == 0);
        ASSERT_EQ(policy.award_atoms[VCS_ZCODE_CREATION_V2_MODULE_PUBLICATION],
                  UINT64_C(100000000));
        ASSERT_EQ(policy.award_atoms[VCS_ZCODE_CREATION_V2_DEFECT_REPAIR],
                  UINT64_C(50000000));
        ASSERT_EQ(policy.award_atoms[VCS_ZCODE_CREATION_V2_SECURITY_FINDING],
                  UINT64_C(50000000));
        ASSERT_EQ(policy.award_atoms[VCS_ZCODE_CREATION_V2_PRESERVATION],
                  UINT64_C(12500000));
        struct vcs_zcode_policy_candidate_v2 changed = policy;
        changed.award_atoms[0]--;
        ASSERT_EQ(vcs_zcode_policy_candidate_v2_validate(&changed),
                  VCS_ZCODE_COMMONS_AMOUNT);
        struct vcs_zcode_family_policy_v1 weakened = family;
        weakened.excluded_reason_mask &= ~VCS_ZCODE_FAMILY_TARGETED_HATE;
        ASSERT_EQ(vcs_zcode_family_policy_v1_validate(&weakened),
                  VCS_ZCODE_COMMONS_POLICY);
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_truthful_activation_status(void)
{
    int failures = 0;
    TEST("Family policy selection is not reported as effective enforcement") {
        char backlog_workspace[256];
        test_make_tmpdir(backlog_workspace, sizeof(backlog_workspace),
                         "zcode_commons", "backlog");
        zcl_hotswap_service_reset();
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.moderation_status.v1");
        zcl_native_handle_zcode_moderation_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "policy_selected_as_default")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "enforcement_complete")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "effective_default")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "default_public_view")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "view_service_id")),
                      ZCODE_MODERATION_VIEW_SERVICE_ID);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                       "view_service_generation")), 0);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "policy_root")),
                      family_root_kat);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "policy_summary")),
                      "enforcement remains resident and incomplete") != NULL);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "official_surface_policy")),
                      "legacy_v1_unchanged") == 0);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "admission_readiness")),
                      "blocked:projection_missing");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "zcode moderation service status");
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.moderation_service_status.v1");
        zcl_native_handle_zcode_moderation_service_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "projection_ready")));
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                        "registered_service_count")), 0);
        ASSERT(!json_get_bool(json_get(&reply.data, "roster_finalized")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "classification_enabled")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "advertisement_enabled")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "bootstrap_label")),
                      "unavailable:no_signed_service_roster");
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_status.v1");
        zcl_native_handle_zcode_commons_corpus_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "projection_ready")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "admitted_total_loc")),
                  0);
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "global_completeness_claimed")));
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "service_id")),
                      ZCODE_C23_CORPUS_SERVICE_ID) == 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")),
                  0);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "blocker")),
                      "checkpoint_missing: commit a verified corpus "
                      "checkpoint projection");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "progress_stage")),
                      "checkpoint_missing");
        ASSERT(strstr(json_get_str(json_get(&reply.data, "next_command")),
                      ZCODE_C23_CORPUS_KAT_FINGERPRINT) != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "root",
                         ZCODE_C23_CORPUS_KAT_FINGERPRINT);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_show.v1");
        zcl_native_handle_zcode_commons_corpus_show(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "found")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "root")),
                      ZCODE_C23_CORPUS_KAT_FINGERPRINT);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "kind")),
                      "c23_corpus_rules.v1");
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "global_completeness_claimed")));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "root",
            "0000000000000000000000000000000000000000000000000000000000000000");
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_show.v1");
        zcl_native_handle_zcode_commons_corpus_show(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "found")));
        ASSERT(json_get(&reply.data, "blocker") != NULL);
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "global_completeness_claimed")));
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcode_c23_corpus_service_v1 candidate_vtable =
            *zcode_c23_corpus_service_builtin();
        candidate_vtable.render_status = cv2_candidate_render_status;
        struct zcl_hotswap_service_candidate candidate = {
            .service_id = ZCODE_C23_CORPUS_SERVICE_ID,
            .source_tu = "contexts/commons/services/src/zcode_c23_corpus_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(candidate_vtable),
            .abi_fingerprint = ZCODE_C23_CORPUS_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_C23_CORPUS_KAT_FINGERPRINT,
            .vtable = &candidate_vtable,
        };
        struct zcl_hotswap_service_report service_report = {0};
        struct zcode_c23_corpus_service_v1 weak_checkpoint_vtable =
            candidate_vtable;
        weak_checkpoint_vtable.checkpoint_validate =
            cv2_candidate_checkpoint_accept_all;
        candidate.vtable = &weak_checkpoint_vtable;
        ASSERT(!zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &service_report));
        ASSERT_STR_EQ(service_report.stage, "kat");
        ASSERT(strstr(service_report.error, "checkpoint") != NULL);
        candidate.vtable = &candidate_vtable;
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &service_report));
        ASSERT(service_report.probed);

        json_init(&input);
        json_set_object(&input);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_status.v1");
        zcl_native_handle_zcode_commons_corpus_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")),
                  1);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "blocker")),
                      "candidate corpus service generation is active") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        json_init(&input);
        json_set_object(&input);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.economics_status.v2");
        zcl_native_handle_zcode_commons_economics_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "service_id")),
                      ZCODE_C23_ECONOMICS_SERVICE_ID);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "service_generation")),
                  0);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "category_order")),
                      "zero_root=0;else_first=(root[0]+1)%8;then=cyclic");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "concentration_cap")),
            "per-recipient cap=min(epoch_capacity,max(1 ZC23,floor(epoch_capacity/100)))");
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "workspace", backlog_workspace);
        json_push_kv_int(&input, "cutoff_height", 1);
        json_push_kv_int(&input, "cutoff_mtp", 1);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.commons_backlog.v1");
        zcl_native_handle_zcode_commons_backlog(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "projection_ready")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "claim_count")), 0);
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "unused_capacity_expires")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "queue_order")),
            "strict-oldest-first:maturity_height,maturity_mtp,claim_root");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "backlog_readiness")),
                      "blocked:claim_projection_missing");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "zcode commons claim plan");
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcode_c23_economics_service_v1 economics_candidate =
            *zcode_c23_economics_service_builtin();
        economics_candidate.render_status =
            cv2_candidate_render_economics_status;
        economics_candidate.render_backlog_status =
            cv2_candidate_render_backlog_status;
        struct zcl_hotswap_service_candidate economics_descriptor = {
            .service_id = ZCODE_C23_ECONOMICS_SERVICE_ID,
            .source_tu = "contexts/commons/services/src/zcode_c23_economics_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(economics_candidate),
            .abi_fingerprint = ZCODE_C23_ECONOMICS_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_C23_ECONOMICS_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_C23_ECONOMICS_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_C23_ECONOMICS_KAT_FINGERPRINT,
            .vtable = &economics_candidate,
        };
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_economics_service_contract(),
            &economics_descriptor, true, &service_report));
        json_init(&input);
        json_set_object(&input);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.economics_status.v2");
        zcl_native_handle_zcode_commons_economics_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "category_order")),
                      "candidate economics service generation is active");
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "workspace", backlog_workspace);
        json_push_kv_int(&input, "cutoff_height", 1);
        json_push_kv_int(&input, "cutoff_mtp", 1);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.commons_backlog.v1");
        zcl_native_handle_zcode_commons_backlog(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "blocker")),
                      "candidate backlog generation is active");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        json_init(&input);
        json_set_object(&input);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.impact_share.v1");
        zcl_native_handle_zcode_commons_impact_share(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "shareable")));
        ASSERT(json_get(&reply.data, "slogan") == NULL);
        ASSERT(!json_get_bool(json_get(&reply.data, "slogan_emitted")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "impact_readiness")),
                      "blocked:proven_work_missing");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "zcode guide");
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_rm_rf(backlog_workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_c23_corpus_objects(void)
{
    int failures = 0;
    TEST("source assignments and c23 rules have canonical fail-closed wires") {
        {
        struct vcs_zcode_source_assignment_v1 assignment = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .source_kind = VCS_ZCODE_SOURCE_CANONICAL_IMPORT,
            .sequence = 7,
            .assigned_height = 9000,
            .assigned_mtp = 8000,
        };
        cv2_fill(assignment.source_root, 0x11);
        cv2_fill(assignment.author_binding_root, 0x12);
        cv2_fill(assignment.upstream_source_root, 0x13);
        cv2_fill(assignment.upstream_author_root, 0x14);
        cv2_fill(assignment.license_root, 0x15);
        cv2_fill(assignment.assignment_evidence_root, 0x16);
        uint8_t seed[32]; cv2_fill(seed, 0x17);
        ASSERT_EQ(vcs_zcode_source_assignment_v1_sign(&assignment, seed),
                  VCS_ZCODE_C23_OK);
        uint8_t wire[VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_source_assignment_v1_encode(
                      &assignment, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(wire_len, VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES);
        struct vcs_zcode_source_assignment_v1 decoded;
        ASSERT_EQ(vcs_zcode_source_assignment_v1_decode(
                      &decoded, wire, wire_len), VCS_ZCODE_C23_OK);
        ASSERT(memcmp(&assignment, &decoded, sizeof(assignment)) == 0);
        uint8_t first_root[32], second_root[32];
        ASSERT_EQ(vcs_zcode_source_assignment_v1_root(
                      &assignment, first_root), VCS_ZCODE_C23_OK);
        ASSERT_EQ(vcs_zcode_source_assignment_v1_root(
                      &decoded, second_root), VCS_ZCODE_C23_OK);
        ASSERT(memcmp(first_root, second_root, 32) == 0);
        char assignment_hex[65];
        zcl_hex_encode(first_root, 32, assignment_hex);
        printf("source_assignment.v1=%s\n", assignment_hex);
        uint8_t expected[32];
        ASSERT(zcl_hex_decode(source_assignment_root_kat, expected, 32));
        ASSERT(memcmp(first_root, expected, 32) == 0);
        wire[40] ^= 1u;
        ASSERT_EQ(vcs_zcode_source_assignment_v1_decode(
                      &decoded, wire, wire_len), VCS_ZCODE_C23_SIGNATURE);
        ASSERT(vcs_zcode_source_kind_counts_v1(
            VCS_ZCODE_SOURCE_HUMAN_AUTHORED));
        ASSERT(vcs_zcode_source_kind_counts_v1(
            VCS_ZCODE_SOURCE_AI_AUTHORED));
        ASSERT(vcs_zcode_source_kind_counts_v1(
            VCS_ZCODE_SOURCE_CANONICAL_IMPORT));
        ASSERT(!vcs_zcode_source_kind_counts_v1(
            VCS_ZCODE_SOURCE_MECHANICAL_GENERATION));
        ASSERT(!vcs_zcode_source_kind_counts_v1(
            VCS_ZCODE_SOURCE_VENDOR_MATERIAL));
        }
        {
        struct vcs_zcode_c23_corpus_rules_v1 rules;
        vcs_zcode_c23_corpus_rules_v1_default(&rules);
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_validate(&rules),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(rules.overlap_threshold_bps, 8000);
        ASSERT_EQ(rules.shard_entry_max, 4096);
        ASSERT_EQ(rules.checkpoint_shard_max, 4096);
        ASSERT_EQ(rules.page_max, 256);
        ASSERT_EQ(rules.publication_batch_max, 256);
        ASSERT_EQ(rules.durable_ack_count, 5);
        ASSERT_EQ(rules.durable_operator_group_count, 3);
        ASSERT_EQ(rules.first_milestone_loc, UINT64_C(50000000));
        ASSERT_EQ(rules.second_milestone_loc, UINT64_C(100000000));
        uint8_t wire[VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_encode(
                      &rules, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(wire_len, VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES);
        struct vcs_zcode_c23_corpus_rules_v1 decoded;
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_decode(
                      &decoded, wire, wire_len), VCS_ZCODE_C23_OK);
        ASSERT(memcmp(&rules, &decoded, sizeof(rules)) == 0);
        uint8_t root[32], expected[32];
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_root(&rules, root),
                  VCS_ZCODE_C23_OK);
        char hex[65]; zcl_hex_encode(root, 32, hex);
        printf("c23_corpus_rules.v1=%s\n", hex);
        ASSERT(zcl_hex_decode(c23_corpus_rules_root_kat, expected, 32));
        ASSERT(memcmp(root, expected, 32) == 0);
        rules.page_max++;
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_validate(&rules),
                  VCS_ZCODE_C23_POLICY);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_c23_checkpoint_verify_command(void)
{
    int failures = 0;
    TEST("corpus checkpoint verify accepts one signed bounded wire and hard-fails tampering") {
        struct vcs_zcode_c23_checkpoint_shard_v1 binding = {
            .entry_count = 1,
            .production_loc = 12,
            .test_loc = 3,
            .durable_loc = 15,
            .physical_lines = 18,
            .unique_semantic_units = 9,
        };
        cv2_fill(binding.shard_root, 0x31);
        cv2_fill(binding.first_lineage_root, 0x32);
        cv2_fill(binding.last_lineage_root, 0x33);

        struct vcs_zcode_c23_corpus_rules_v1 rules;
        uint8_t rules_root[32];
        vcs_zcode_c23_corpus_rules_v1_default(&rules);
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_root(&rules, rules_root),
                  VCS_ZCODE_C23_OK);
        struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .milestone = VCS_ZCODE_C23_MILESTONE_NONE,
            .sequence = 1,
            .cutoff_height = 100,
            .cutoff_mtp = 200,
            .total_entries = binding.entry_count,
            .production_loc = binding.production_loc,
            .test_loc = binding.test_loc,
            .durable_loc = binding.durable_loc,
            .physical_lines = binding.physical_lines,
            .unique_semantic_units = binding.unique_semantic_units,
            .shards = &binding,
            .shard_count = 1,
        };
        memcpy(checkpoint.rules_root, rules_root, 32);
        cv2_fill(checkpoint.family_policy_root, 0x41);
        cv2_fill(checkpoint.moderation_set_root, 0x42);
        cv2_fill(checkpoint.replication_evidence_root, 0x43);
        uint8_t seed[32];
        cv2_fill(seed, 0x51);
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_sign(&checkpoint, seed),
                  VCS_ZCODE_C23_OK);

        struct zcode_c23_corpus_status_result_v1 status;
        ASSERT(zcode_c23_corpus_service_builtin()->render_status(
            &checkpoint, &status));
        ASSERT(status.projection_ready);
        ASSERT_EQ(status.admitted_total_loc, 15);
        ASSERT(strstr(status.blocker, "50000000") != NULL);

        uint8_t wire[VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES +
                     VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_checkpoint_v1_encode(
                      &checkpoint, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        char wire_hex[sizeof(wire) * 2u + 1u];
        zcl_hex_encode(wire, wire_len, wire_hex);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "checkpoint", wire_hex);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.corpus_checkpoint_verify.v1");
        zcl_native_handle_zcode_commons_corpus_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "kind")),
                      "c23_corpus_checkpoint.v1");
        ASSERT(json_get_bool(json_get(&reply.data, "verified")));
        ASSERT(json_get_bool(json_get(&reply.data, "simulation_only")));
        ASSERT(json_get_bool(json_get(&reply.data, "not_owner_approved")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "global_completeness_claimed")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "shard_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total_loc")), 15);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "inline_shard_limit")),
                  54);
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                            "checkpoint_root"))) == 64);
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcode_c23_corpus_service_v1 selective_vtable =
            *zcode_c23_corpus_service_builtin();
        selective_vtable.checkpoint_validate =
            cv2_candidate_checkpoint_selective;
        struct zcl_hotswap_service_candidate selective_candidate = {
            .service_id = ZCODE_C23_CORPUS_SERVICE_ID,
            .source_tu = "contexts/commons/services/src/zcode_c23_corpus_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(selective_vtable),
            .abi_fingerprint = ZCODE_C23_CORPUS_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_C23_CORPUS_KAT_FINGERPRINT,
            .vtable = &selective_vtable,
        };
        struct zcl_hotswap_service_report selective_report = {0};
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(),
            &selective_candidate, true, &selective_report));
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "checkpoint", wire_hex);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_checkpoint_verify.v1");
        zcl_native_handle_zcode_commons_corpus_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CORPUS_CHECKPOINT_INVALID");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        wire[wire_len - 1u] ^= 1u;
        zcl_hex_encode(wire, wire_len, wire_hex);
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "checkpoint", wire_hex);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_checkpoint_verify.v1");
        zcl_native_handle_zcode_commons_corpus_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CORPUS_CHECKPOINT_INVALID");
        ASSERT(!json_get_bool(json_get(&reply.data, "verified")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_c23_shard_verify_command(void)
{
    int failures = 0;
    TEST("corpus shard verify uses the pure service and reports bounded counts") {
        struct vcs_zcode_c23_corpus_entry_v1 entry = {
            .release_sequence = 700,
            .production_loc = 12,
            .test_loc = 3,
            .physical_lines = 18,
            .unique_semantic_units = 9,
            .evidence_mask = VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK,
            .flags = VCS_ZCODE_C23_ENTRY_COUNTED |
                     VCS_ZCODE_C23_ENTRY_DURABLE,
        };
        cv2_fill(entry.semantic_lineage_root, 0x21);
        cv2_fill(entry.release_root, 0x22);
        cv2_fill(entry.passport_root, 0x23);
        cv2_fill(entry.proof_root, 0x24);
        cv2_fill(entry.source_assignment_root, 0x25);
        cv2_fill(entry.admission_root, 0x26);
        cv2_fill(entry.possession_root, 0x27);

        struct vcs_zcode_c23_corpus_rules_v1 rules;
        struct vcs_zcode_c23_corpus_shard_v1 shard = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .entries = &entry,
            .entry_count = 1,
        };
        vcs_zcode_c23_corpus_rules_v1_default(&rules);
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_root(&rules,
                                                     shard.rules_root),
                  VCS_ZCODE_C23_OK);
        cv2_fill(shard.family_policy_root, 0x31);
        cv2_fill(shard.moderation_set_root, 0x32);

        uint8_t wire[VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES +
                     VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_encode(
                      &shard, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        char wire_hex[sizeof(wire) * 2u + 1u];
        zcl_hex_encode(wire, wire_len, wire_hex);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_verify.v1");
        zcl_native_handle_zcode_commons_corpus_shard_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "kind")),
                      "c23_corpus_shard.v1");
        ASSERT(json_get_bool(json_get(&reply.data, "verified")));
        ASSERT(json_get_bool(json_get(&reply.data, "simulation_only")));
        ASSERT(json_get_bool(json_get(&reply.data, "not_owner_approved")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "global_completeness_claimed")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "entry_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "counted_entries")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "durable_entries")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total_loc")), 15);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "durably_hosted_loc")),
                  15);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "inline_entry_limit")),
                  28);
        ASSERT(strlen(json_get_str(json_get(&reply.data, "shard_root"))) ==
               64);
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcode_c23_corpus_service_v1 weak_vtable =
            *zcode_c23_corpus_service_builtin();
        weak_vtable.shard_validate = cv2_candidate_shard_accept_all;
        struct zcl_hotswap_service_candidate candidate = {
            .service_id = ZCODE_C23_CORPUS_SERVICE_ID,
            .source_tu = "contexts/commons/services/src/zcode_c23_corpus_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(weak_vtable),
            .abi_fingerprint = ZCODE_C23_CORPUS_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_C23_CORPUS_KAT_FINGERPRINT,
            .vtable = &weak_vtable,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(!zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &report));
        ASSERT_STR_EQ(report.stage, "kat");
        ASSERT(strstr(report.error, "shard") != NULL);

        struct zcode_c23_corpus_service_v1 selective_vtable =
            *zcode_c23_corpus_service_builtin();
        selective_vtable.shard_validate = cv2_candidate_shard_selective;
        candidate.vtable = &selective_vtable;
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &report));
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_verify.v1");
        zcl_native_handle_zcode_commons_corpus_shard_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CORPUS_SHARD_INVALID");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        wire[VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES + 276u] = 0;
        zcl_hex_encode(wire, wire_len, wire_hex);
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_verify.v1");
        zcl_native_handle_zcode_commons_corpus_shard_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CORPUS_SHARD_INVALID");
        ASSERT(!json_get_bool(json_get(&reply.data, "verified")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_c23_shard_page_command(void)
{
    int failures = 0;
    TEST("corpus shard pages bind cursors to exact roots through the pure service") {
        struct vcs_zcode_c23_corpus_entry_v1 entries[3];
        memset(entries, 0, sizeof(entries));
        for (size_t i = 0; i < 3; i++) {
            entries[i].release_sequence = 800 + i;
            entries[i].production_loc = 10 + i;
            entries[i].test_loc = 1;
            entries[i].physical_lines = 15 + i;
            entries[i].unique_semantic_units = 8 + i;
            entries[i].evidence_mask = VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK;
            entries[i].flags = VCS_ZCODE_C23_ENTRY_COUNTED |
                               VCS_ZCODE_C23_ENTRY_DURABLE;
            cv2_fill(entries[i].semantic_lineage_root, (uint8_t)(0x21 + i));
            cv2_fill(entries[i].release_root, (uint8_t)(0x31 + i));
            cv2_fill(entries[i].passport_root, (uint8_t)(0x41 + i));
            cv2_fill(entries[i].proof_root, (uint8_t)(0x51 + i));
            cv2_fill(entries[i].source_assignment_root,
                     (uint8_t)(0x61 + i));
            cv2_fill(entries[i].admission_root, (uint8_t)(0x71 + i));
            cv2_fill(entries[i].possession_root, (uint8_t)(0x81 + i));
        }
        struct vcs_zcode_c23_corpus_rules_v1 rules;
        struct vcs_zcode_c23_corpus_shard_v1 shard = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .entries = entries,
            .entry_count = 3,
        };
        vcs_zcode_c23_corpus_rules_v1_default(&rules);
        ASSERT_EQ(vcs_zcode_c23_corpus_rules_v1_root(&rules,
                                                     shard.rules_root),
                  VCS_ZCODE_C23_OK);
        cv2_fill(shard.family_policy_root, 0x91);
        cv2_fill(shard.moderation_set_root, 0x92);

        uint8_t wire[VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES +
                     3u * VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_c23_corpus_shard_v1_encode(
                      &shard, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        char wire_hex[sizeof(wire) * 2u + 1u];
        zcl_hex_encode(wire, wire_len, wire_hex);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        json_push_kv_int(&input, "limit", 2);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_page.v1");
        zcl_native_handle_zcode_commons_corpus_shard_page(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "kind")),
                      "c23_corpus_shard.page.v1");
        ASSERT(json_get_bool(json_get(&reply.data, "verified")));
        ASSERT(json_get_bool(json_get(&reply.data, "has_more")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "first_index")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "item_count")), 2);
        const struct json_value *page_entries = json_get(&reply.data,
                                                         "entries");
        ASSERT(page_entries && page_entries->type == JSON_ARR);
        ASSERT_EQ(page_entries->num_children, 2);
        ASSERT_EQ(json_get_int(json_get(&page_entries->children[0],
                                        "release_sequence")), 800);
        const char *cursor_value = json_get_str(json_get(&reply.data,
                                                         "next_cursor"));
        ASSERT(cursor_value && strlen(cursor_value) == 68);
        char cursor[69];
        (void)snprintf(cursor, sizeof(cursor), "%s", cursor_value);
        const char *root = json_get_str(json_get(&reply.data, "shard_root"));
        ASSERT(root && memcmp(cursor, root, 64) == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcode_c23_corpus_service_v1 weak_vtable =
            *zcode_c23_corpus_service_builtin();
        weak_vtable.shard_page = cv2_candidate_shard_page_accept_all;
        struct zcl_hotswap_service_candidate candidate = {
            .service_id = ZCODE_C23_CORPUS_SERVICE_ID,
            .source_tu = "contexts/commons/services/src/zcode_c23_corpus_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(weak_vtable),
            .abi_fingerprint = ZCODE_C23_CORPUS_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_C23_CORPUS_KAT_FINGERPRINT,
            .vtable = &weak_vtable,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(!zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &report));
        ASSERT_STR_EQ(report.stage, "kat");
        ASSERT(strstr(report.error, "cursor") != NULL);

        struct zcode_c23_corpus_service_v1 selective_vtable =
            *zcode_c23_corpus_service_builtin();
        selective_vtable.shard_page = cv2_candidate_shard_page_selective;
        candidate.vtable = &selective_vtable;
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &report));
        json_init(&input); json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        json_push_kv_int(&input, "limit", 2);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_page.v1");
        zcl_native_handle_zcode_commons_corpus_shard_page(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CORPUS_SHARD_INVALID");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        json_init(&input); json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        json_push_kv_str(&input, "cursor", cursor);
        json_push_kv_int(&input, "limit", 2);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_page.v1");
        zcl_native_handle_zcode_commons_corpus_shard_page(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "has_more")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "first_index")), 2);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "item_count")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_cursor")), "");
        page_entries = json_get(&reply.data, "entries");
        ASSERT(page_entries && page_entries->num_children == 1);
        ASSERT_EQ(json_get_int(json_get(&page_entries->children[0],
                                        "release_sequence")), 802);
        zcl_command_reply_free(&reply);
        json_free(&input);

        cursor[0] = cursor[0] == '0' ? '1' : '0';
        json_init(&input); json_set_object(&input);
        json_push_kv_str(&input, "shard", wire_hex);
        json_push_kv_str(&input, "cursor", cursor);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.corpus_shard_page.v1");
        zcl_native_handle_zcode_commons_corpus_shard_page(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CORPUS_SHARD_CURSOR_INVALID");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_productivity_verify_command(void)
{
    int failures = 0;
    TEST("productivity verify checks signed structure but cannot authorize sharing") {
        struct vcs_zcode_productivity_receipt_v1 receipt = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .evidence_mask = VCS_ZCODE_PRODUCTIVITY_REQUIRED_MASK,
            .completed_height = 700,
            .completed_mtp = 800,
        };
        cv2_fill(receipt.work_root, 0x71);
        cv2_fill(receipt.acceptance_root, 0x72);
        cv2_fill(receipt.release_root, 0x73);
        cv2_fill(receipt.admission_root, 0x74);
        cv2_fill(receipt.package_root, 0x75);
        cv2_fill(receipt.checkpoint_root, 0x76);
        uint8_t seed[32];
        cv2_fill(seed, 0x77);
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_sign(&receipt, seed),
                  VCS_ZCODE_C23_OK);

        uint8_t wire[VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_productivity_receipt_v1_encode(
                      &receipt, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_C23_OK);
        ASSERT_EQ(wire_len, sizeof(wire));
        char wire_hex[sizeof(wire) * 2u + 1u];
        zcl_hex_encode(wire, wire_len, wire_hex);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "receipt", wire_hex);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.productivity_verify.v1");
        zcl_native_handle_zcode_commons_impact_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "kind")),
                      "productivity_receipt.v1");
        ASSERT(json_get_bool(json_get(&reply.data, "structurally_verified")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "external_chain_proof_present")));
        ASSERT(!json_get_bool(json_get(&reply.data, "shareable")));
        ASSERT(!json_get_bool(json_get(&reply.data, "slogan_emitted")));
        ASSERT(json_get(&reply.data, "slogan") == NULL);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "completed_height")),
                  700);
        ASSERT(strlen(json_get_str(json_get(&reply.data, "receipt_root"))) ==
               64);
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct zcode_c23_corpus_service_v1 weak_vtable =
            *zcode_c23_corpus_service_builtin();
        weak_vtable.productivity_validate =
            cv2_candidate_productivity_accept_all;
        struct zcl_hotswap_service_candidate candidate = {
            .service_id = ZCODE_C23_CORPUS_SERVICE_ID,
            .source_tu = "contexts/commons/services/src/zcode_c23_corpus_service.c",
            .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
            .vtable_size = sizeof(weak_vtable),
            .abi_fingerprint = ZCODE_C23_CORPUS_ABI_FINGERPRINT,
            .schema_fingerprint = ZCODE_C23_CORPUS_SCHEMA_FINGERPRINT,
            .wire_fingerprint = ZCODE_C23_CORPUS_WIRE_FINGERPRINT,
            .kat_fingerprint = ZCODE_C23_CORPUS_KAT_FINGERPRINT,
            .vtable = &weak_vtable,
        };
        struct zcl_hotswap_service_report report = {0};
        ASSERT(!zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &report));
        ASSERT_STR_EQ(report.stage, "kat");
        ASSERT(strstr(report.error, "productivity") != NULL);

        struct zcode_c23_corpus_service_v1 selective_vtable =
            *zcode_c23_corpus_service_builtin();
        selective_vtable.productivity_validate =
            cv2_candidate_productivity_selective;
        candidate.vtable = &selective_vtable;
        ASSERT(zcl_hotswap_service_publish(
            zcl_native_zcode_corpus_service_contract(), &candidate, true,
            &report));
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "receipt", wire_hex);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.productivity_verify.v1");
        zcl_native_handle_zcode_commons_impact_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "PRODUCTIVITY_RECEIPT_INVALID");
        zcl_command_reply_free(&reply);
        json_free(&input);
        zcl_hotswap_service_reset();

        wire[wire_len - 1u] ^= 1u;
        zcl_hex_encode(wire, wire_len, wire_hex);
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "receipt", wire_hex);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.productivity_verify.v1");
        zcl_native_handle_zcode_commons_impact_verify(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "PRODUCTIVITY_RECEIPT_INVALID");
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "structurally_verified")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static void cv2_claim(struct vcs_zcode_creation_claim_v2 *claim,
                      uint8_t id, uint16_t category)
{
    memset(claim, 0, sizeof(*claim));
    claim->schema_version = VCS_ZCODE_CREATION_CLAIM_V2_VERSION;
    claim->flags = VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS;
    claim->category = category;
    cv2_fill(claim->claim_root, id);
    cv2_fill(claim->recipient_binding_root, (uint8_t)(0x20u + id));
    cv2_fill(claim->workspace_lineage_root, (uint8_t)(0x40u + id));
    cv2_fill(claim->semantic_lineage_root, (uint8_t)(0x60u + id));
    cv2_fill(claim->evidence_root, (uint8_t)(0x80u + id));
    cv2_fill(claim->commons_admission_root, (uint8_t)(0xa0u + id));
    claim->maturity_height = 1000u + id;
    claim->maturity_mtp = 2000 + id;
}

static int test_v2_epoch_selection(void)
{
    int failures = 0;
    TEST("epoch selection is input-order invariant, cyclic, whole-claim and capped") {
        struct vcs_zcode_policy_candidate_v2 policy;
        struct vcs_zcode_family_policy_v1 family;
        ASSERT(cv2_policy(&policy, &family));
        struct vcs_zcode_creation_claim_v2 claims[10];
        const uint16_t categories[10] = {
            0, 1, 2, 3, 4, 5, 6, 7, 0, 1,
        };
        for (size_t i = 0; i < 10; i++)
            cv2_claim(&claims[i], (uint8_t)(i + 1u), categories[i]);
        /* A second claim for the same recipient must defer once its sum would
         * cross the one-token per-recipient cap. */
        memcpy(claims[8].recipient_binding_root,
               claims[0].recipient_binding_root, 32);
        /* A later duplicate semantic lineage is invalid, never another mint. */
        memcpy(claims[9].semantic_lineage_root,
               claims[1].semantic_lineage_root, 32);
        struct vcs_zcode_epoch_selection_v2 input = {
            .epoch = 7,
            .cutoff_height = 2000,
            .cutoff_mtp = 4000,
            .epoch_capacity_atoms = UINT64_C(300000000),
            .claims = claims,
            .claim_count = 10,
        };
        struct vcs_zcode_epoch_selection_result_v2 result;
        ASSERT_EQ(vcs_zcode_epoch_select_v2(&input, &policy, &result),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(result.first_category, 0);
        ASSERT_EQ(result.recipient_cap_atoms, UINT64_C(100000000));
        ASSERT(result.selected_atoms <= input.epoch_capacity_atoms);
        ASSERT_EQ(result.selected_atoms + result.expired_capacity_atoms,
                  input.epoch_capacity_atoms);
        ASSERT(result.deferred_count >= 1);
        ASSERT(result.invalid_count >= 1);
        ASSERT(result.selected_count > 0);

        struct vcs_zcode_creation_claim_v2 reversed[10];
        for (size_t i = 0; i < 10; i++) reversed[i] = claims[9u - i];
        input.claims = reversed;
        struct vcs_zcode_epoch_selection_result_v2 repeated;
        ASSERT_EQ(vcs_zcode_epoch_select_v2(&input, &policy, &repeated),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT(memcmp(result.epoch_creation_root,
                      repeated.epoch_creation_root, 32) == 0);
        ASSERT_EQ(result.selected_atoms, repeated.selected_atoms);
        ASSERT_EQ(result.deferred_count, repeated.deferred_count);
        ASSERT_EQ(result.invalid_count, repeated.invalid_count);

        input.claims = claims;
        cv2_fill(input.previous_epoch_root, 2);
        ASSERT_EQ(vcs_zcode_epoch_select_v2(&input, &policy, &repeated),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(repeated.first_category, 3);
        ASSERT(memcmp(result.epoch_creation_root,
                      repeated.epoch_creation_root, 32) != 0);

        claims[2].flags |= VCS_ZCODE_CLAIM_V2_REORGED;
        memset(input.previous_epoch_root, 0, 32);
        ASSERT_EQ(vcs_zcode_epoch_select_v2(&input, &policy, &repeated),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT(repeated.invalid_count > result.invalid_count);
        PASS();
    } _test_next:;
    return failures;
}

static int test_v2_workspace_objects(void)
{
    int failures = 0;
    TEST("workspace, asset, passport, quality, mission and split objects fail closed") {
        struct vcs_zcode_typed_asset_manifest_v1 asset = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
            .kind = VCS_ZCODE_ASSET_IMAGE,
            .license = VCS_ZCODE_ASSET_LICENSE_CC_BY_4_0,
            .byte_count = 12345,
        };
        cv2_fill(asset.format_root, 0x11);
        cv2_fill(asset.content_root, 0x12);
        cv2_fill(asset.attribution_root, 0x13);
        cv2_fill(asset.collection_root, 0x14);
        cv2_fill(asset.signer_root, 0x15);
        cv2_fill(asset.signature, 0x16);
        ASSERT_EQ(vcs_zcode_typed_asset_manifest_v1_validate(&asset),
                  VCS_ZCODE_COMMONS_OK);
        uint8_t asset_root[32], workspace_root[32], expected[32];
        ASSERT_EQ(vcs_zcode_typed_asset_manifest_v1_root(&asset, asset_root),
                  VCS_ZCODE_COMMONS_OK);
        struct vcs_zcode_typed_asset_manifest_v1 bad_asset = asset;
        memset(bad_asset.attribution_root, 0, 32);
        ASSERT_EQ(vcs_zcode_typed_asset_manifest_v1_validate(&bad_asset),
                  VCS_ZCODE_COMMONS_POLICY);
        bad_asset = asset; bad_asset.license = 3; /* NC/ND/SA are unrepresentable. */
        ASSERT_EQ(vcs_zcode_typed_asset_manifest_v1_validate(&bad_asset),
                  VCS_ZCODE_COMMONS_ENUM);

        struct vcs_zcode_quality_profile_v1 quality = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
            .field = VCS_ZCODE_QUALITY_CRYPTOGRAPHY,
            .required_check_mask = VCS_ZCODE_QUALITY_UNIVERSAL_MASK |
                                   (UINT64_C(1) << 10),
        };
        cv2_fill(quality.universal_profile_root, 0x21);
        cv2_fill(quality.additive_rules_root, 0x22);
        ASSERT_EQ(vcs_zcode_quality_profile_v1_validate(&quality),
                  VCS_ZCODE_COMMONS_OK);
        quality.required_check_mask = UINT64_C(1) << 10;
        ASSERT_EQ(vcs_zcode_quality_profile_v1_validate(&quality),
                  VCS_ZCODE_COMMONS_POLICY);

        struct vcs_zcode_module_passport_v1 passport = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
        };
        uint8_t *passport_roots[] = {
            passport.stable_api_root, passport.recipe_root,
            passport.toolchain_root, passport.tests_root,
            passport.license_root, passport.semantic_fingerprint_root,
            passport.workspace_lineage_root, passport.source_assignment_root,
            passport.quality_profiles_root, passport.signer_root,
        };
        for (size_t i = 0; i < 10; i++)
            cv2_fill(passport_roots[i], (uint8_t)(0x30u + i));
        cv2_fill(passport.signature, 0x3f);
        ASSERT_EQ(vcs_zcode_module_passport_v1_validate(&passport),
                  VCS_ZCODE_COMMONS_OK);
        uint8_t passport_seed[32], passport_secret[32], passport_wire[
            VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES];
        uint8_t passport_payload[
            VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES];
        cv2_fill(passport_seed, 0x40);
        memset(passport.signature, 0, sizeof(passport.signature));
        ed25519_keypair(passport.signer_root, passport_secret, passport_seed);
        size_t passport_payload_len = 0;
        ASSERT_EQ(vcs_zcode_module_passport_v1_signing_payload(
                      &passport, passport_payload, sizeof(passport_payload),
                      &passport_payload_len), VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(passport_payload_len,
                  VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES);
        ASSERT(memcmp(passport_payload,
                      VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_DOMAIN,
                      sizeof(VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_DOMAIN) - 1u)
               == 0);
        size_t refused_payload_len = 99;
        ASSERT_EQ(vcs_zcode_module_passport_v1_signing_payload(
                      &passport, passport_payload,
                      sizeof(passport_payload) - 1u, &refused_payload_len),
                  VCS_ZCODE_COMMONS_SIZE);
        ASSERT_EQ(refused_payload_len, 0u);
        ed25519_sign(passport.signature, passport_payload,
                     passport_payload_len, passport_secret,
                     passport.signer_root);
        ASSERT_EQ(vcs_zcode_module_passport_v1_verify(&passport),
                  VCS_ZCODE_COMMONS_OK);
        size_t passport_wire_len = 0;
        ASSERT_EQ(vcs_zcode_module_passport_v1_encode(
                      &passport, passport_wire, sizeof(passport_wire),
                      &passport_wire_len), VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(passport_wire_len,
                  VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES);
        char passport_hex[VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES * 2u + 1u];
        zcl_hex_encode(passport_wire, passport_wire_len, passport_hex);

        static const char *passport_root_keys[] = {
            "stable_api_root", "recipe_root", "toolchain_root", "tests_root",
            "license_root", "semantic_fingerprint_root",
            "workspace_lineage_root", "source_assignment_root",
            "quality_profiles_root", "signer_pubkey",
        };
        struct json_value passport_plan_input;
        json_init(&passport_plan_input);
        json_set_object(&passport_plan_input);
        for (size_t i = 0; i < 10; i++) {
            char root_hex[65];
            zcl_hex_encode(passport_roots[i], 32, root_hex);
            ASSERT(json_push_kv_str(&passport_plan_input,
                                    passport_root_keys[i], root_hex));
        }
        struct zcl_command_request passport_plan_request = {
            .input = &passport_plan_input,
        };
        struct zcl_command_reply passport_plan_reply;
        zcl_command_reply_init(&passport_plan_reply,
                               "zcl.zcode_passport_plan.v1");
        zcl_native_handle_zcode_passport_plan(&passport_plan_request,
                                              &passport_plan_reply);
        ASSERT_EQ(passport_plan_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_plan_reply.data,
                                      "ready_to_sign")));
        ASSERT(json_get(&passport_plan_reply.data, "private_key") == NULL);
        ASSERT(json_get(&passport_plan_reply.data, "signer_seed") == NULL);
        const char *planned_payload = json_get_str(json_get(
            &passport_plan_reply.data, "signing_payload"));
        char expected_payload_hex[
            VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES * 2u + 1u];
        zcl_hex_encode(passport_payload, passport_payload_len,
                       expected_payload_hex);
        ASSERT_STR_EQ(planned_payload, expected_payload_hex);
        zcl_command_reply_free(&passport_plan_reply);

        char passport_signature_hex[129];
        zcl_hex_encode(passport.signature, sizeof(passport.signature),
                       passport_signature_hex);
        ASSERT(json_push_kv_str(&passport_plan_input, "signature",
                                passport_signature_hex));
        struct zcl_command_reply passport_commit_reply;
        zcl_command_reply_init(&passport_commit_reply,
                               "zcl.zcode_passport_commit.v1");
        zcl_native_handle_zcode_passport_commit(&passport_plan_request,
                                                &passport_commit_reply);
        ASSERT_EQ(passport_commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_commit_reply.data,
                                      "verified")));
        ASSERT_STR_EQ(json_get_str(json_get(&passport_commit_reply.data,
                                            "passport")), passport_hex);
        ASSERT(!json_get_bool(json_get(&passport_commit_reply.data,
                                       "persisted")));
        ASSERT(!json_get_bool(json_get(&passport_commit_reply.data,
                                       "published")));
        zcl_command_reply_free(&passport_commit_reply);
        json_free(&passport_plan_input);

        struct json_value passport_input;
        json_init(&passport_input);
        json_set_object(&passport_input);
        ASSERT(json_push_kv_str(&passport_input, "passport", passport_hex));
        struct zcl_command_request passport_request = {
            .input = &passport_input,
        };
        struct zcl_command_reply passport_reply;
        zcl_command_reply_init(&passport_reply, "zcl.zcode_passport_verify.v1");
        zcl_native_handle_zcode_passport_verify(&passport_request,
                                                &passport_reply);
        ASSERT_EQ(passport_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&passport_reply.data, "verified")));
        ASSERT_STR_EQ(json_get_str(json_get(&passport_reply.data, "kind")),
                      "module_passport.v1");
        zcl_command_reply_free(&passport_reply);
        json_free(&passport_input);

        uint8_t workspace_release_root[32], workspace_binding_root[32];
        cv2_fill(workspace_release_root, 0x45);
        struct vcs_zcode_workspace_entry_v1 passport_entry = {
            .sequence = 1,
        };
        memcpy(passport_entry.module_release_root, workspace_release_root, 32);
        ASSERT_EQ(vcs_zcode_module_passport_v1_root(
                      &passport, passport_entry.module_passport_root),
                  VCS_ZCODE_COMMONS_OK);
        memcpy(passport_entry.semantic_fingerprint_root,
               passport.semantic_fingerprint_root, 32);
        memcpy(passport_entry.source_assignment_root,
               passport.source_assignment_root, 32);
        ASSERT_EQ(vcs_zcode_workspace_entry_v1_validate(&passport_entry),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(vcs_zcode_workspace_entry_v1_root(
                      &passport_entry, workspace_binding_root),
                  VCS_ZCODE_COMMONS_OK);

        char workspace_release_hex[65], workspace_binding_hex[65];
        zcl_hex_encode(workspace_release_root, 32, workspace_release_hex);
        zcl_hex_encode(workspace_binding_root, 32, workspace_binding_hex);
        struct json_value workspace_plan_input;
        json_init(&workspace_plan_input);
        json_set_object(&workspace_plan_input);
        ASSERT(json_push_kv_str(&workspace_plan_input, "passport",
                                passport_hex));
        ASSERT(json_push_kv_str(&workspace_plan_input, "module_release_root",
                                workspace_release_hex));
        ASSERT(json_push_kv_int(&workspace_plan_input, "sequence", 1));
        struct zcl_command_request workspace_request = {
            .input = &workspace_plan_input,
        };
        struct zcl_command_reply workspace_reply;
        zcl_command_reply_init(&workspace_reply,
                               "zcl.zcode_workspace_plan.v1");
        zcl_native_handle_zcode_workspace_plan(&workspace_request,
                                               &workspace_reply);
        ASSERT_EQ(workspace_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&workspace_reply.data,
                                      "verified_passport")));
        ASSERT_STR_EQ(json_get_str(json_get(&workspace_reply.data,
                                            "binding_root")),
                      workspace_binding_hex);
        zcl_command_reply_free(&workspace_reply);

        ASSERT(json_push_kv_str(&workspace_plan_input, "binding_root",
                                workspace_binding_hex));
        zcl_command_reply_init(&workspace_reply,
                               "zcl.zcode_workspace_verify.v1");
        zcl_native_handle_zcode_workspace_verify(&workspace_request,
                                                 &workspace_reply);
        ASSERT_EQ(workspace_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&workspace_reply.data,
                                      "binding_verified")));
        ASSERT_STR_EQ(json_get_str(json_get(&workspace_reply.data,
                                            "module_passport_root")),
                      json_get_str(json_get(&workspace_reply.data,
                                            "passport_root")));
        zcl_command_reply_free(&workspace_reply);

        struct json_value bad_workspace_input;
        json_init(&bad_workspace_input);
        json_set_object(&bad_workspace_input);
        ASSERT(json_push_kv_str(&bad_workspace_input, "passport",
                                passport_hex));
        ASSERT(json_push_kv_str(&bad_workspace_input, "module_release_root",
                                workspace_release_hex));
        ASSERT(json_push_kv_int(&bad_workspace_input, "sequence", 1));
        ASSERT(json_push_kv_str(&bad_workspace_input, "binding_root",
            "0000000000000000000000000000000000000000000000000000000000000000"));
        struct zcl_command_request bad_workspace_request = {
            .input = &bad_workspace_input,
        };
        zcl_command_reply_init(&workspace_reply,
                               "zcl.zcode_workspace_verify.v1");
        zcl_native_handle_zcode_workspace_verify(&bad_workspace_request,
                                                 &workspace_reply);
        ASSERT_EQ(workspace_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(workspace_reply.error.code,
                      "WORKSPACE_BINDING_ROOT_MISMATCH");
        zcl_command_reply_free(&workspace_reply);
        json_free(&bad_workspace_input);

        json_init(&bad_workspace_input);
        json_set_object(&bad_workspace_input);
        ASSERT(json_push_kv_str(&bad_workspace_input, "passport",
                                passport_hex));
        ASSERT(json_push_kv_str(&bad_workspace_input, "module_release_root",
                                workspace_release_hex));
        ASSERT(json_push_kv_int(&bad_workspace_input, "sequence", 2));
        zcl_command_reply_init(&workspace_reply,
                               "zcl.zcode_workspace_plan.v1");
        zcl_native_handle_zcode_workspace_plan(&bad_workspace_request,
                                               &workspace_reply);
        ASSERT_EQ(workspace_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(workspace_reply.error.code,
                      "WORKSPACE_PREDECESSOR_REQUIRED");
        zcl_command_reply_free(&workspace_reply);
        json_free(&bad_workspace_input);
        json_free(&workspace_plan_input);

        uint8_t manifest_seed[32], manifest_secret[32], manifest_pubkey[32];
        memset(manifest_seed, 0xb4, sizeof(manifest_seed));
        ed25519_keypair(manifest_pubkey, manifest_secret, manifest_seed);
        char manifest_pubkey_hex[65];
        zcl_hex_encode(manifest_pubkey, sizeof(manifest_pubkey),
                       manifest_pubkey_hex);
        struct json_value manifest_plan_input;
        json_init(&manifest_plan_input);
        json_set_object(&manifest_plan_input);
        ASSERT(json_push_kv_str(&manifest_plan_input, "passport",
                                passport_hex));
        ASSERT(json_push_kv_str(&manifest_plan_input, "module_release_root",
                                workspace_release_hex));
        ASSERT(json_push_kv_int(&manifest_plan_input, "sequence", 1));
        ASSERT(json_push_kv_int(&manifest_plan_input, "workspace_sequence", 1));
        ASSERT(json_push_kv_str(&manifest_plan_input, "signer_root",
                                manifest_pubkey_hex));
        struct zcl_command_request manifest_request = {
            .input = &manifest_plan_input,
        };
        struct zcl_command_reply manifest_reply;
        zcl_command_reply_init(&manifest_reply,
                               "zcl.zcode_workspace_manifest_plan.v1");
        zcl_native_handle_zcode_workspace_manifest_plan(&manifest_request,
                                                        &manifest_reply);
        ASSERT_EQ(manifest_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const char *manifest_payload_hex = json_get_str(json_get(
            &manifest_reply.data, "signing_payload"));
        ASSERT(manifest_payload_hex);
        uint8_t manifest_payload[
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES];
        ASSERT(zcl_hex_decode_lower(manifest_payload_hex, manifest_payload,
                                    sizeof(manifest_payload)));
        uint8_t manifest_signature[64];
        ed25519_sign(manifest_signature, manifest_payload,
                     sizeof(manifest_payload), manifest_secret,
                     manifest_pubkey);
        zcl_command_reply_free(&manifest_reply);
        char manifest_signature_hex[129];
        zcl_hex_encode(manifest_signature, sizeof(manifest_signature),
                       manifest_signature_hex);
        ASSERT(json_push_kv_str(&manifest_plan_input, "signature",
                                manifest_signature_hex));
        zcl_command_reply_init(&manifest_reply,
                               "zcl.zcode_workspace_manifest_commit.v1");
        zcl_native_handle_zcode_workspace_manifest_commit(&manifest_request,
                                                          &manifest_reply);
        ASSERT_EQ(manifest_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&manifest_reply.data, "verified")));
        ASSERT_EQ(json_get_int(json_get(&manifest_reply.data, "entry_count")),
                  1);
        ASSERT(!json_get_bool(json_get(&manifest_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&manifest_reply.data, "published")));
        ASSERT(json_get_str(json_get(&manifest_reply.data, "manifest_root")));
        zcl_command_reply_free(&manifest_reply);
        manifest_signature[0] ^= 1u;
        zcl_hex_encode(manifest_signature, sizeof(manifest_signature),
                       manifest_signature_hex);
        for (size_t i = 0; i < manifest_plan_input.num_children; i++)
            if (strcmp(manifest_plan_input.keys[i], "signature") == 0)
                json_set_str(&manifest_plan_input.children[i],
                             manifest_signature_hex);
        zcl_command_reply_init(&manifest_reply,
                               "zcl.zcode_workspace_manifest_commit.v1");
        zcl_native_handle_zcode_workspace_manifest_commit(&manifest_request,
                                                          &manifest_reply);
        ASSERT_EQ(manifest_reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(manifest_reply.error.code,
                      "WORKSPACE_MANIFEST_SIGNATURE_INVALID");
        zcl_command_reply_free(&manifest_reply);
        json_free(&manifest_plan_input);

        struct vcs_zcode_module_passport_v1 passport_decoded;
        ASSERT_EQ(vcs_zcode_module_passport_v1_decode(
                      &passport_decoded, passport_wire, passport_wire_len),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT(memcmp(&passport, &passport_decoded, sizeof(passport)) == 0);
        ASSERT_EQ(vcs_zcode_module_passport_v1_decode(
                      &passport_decoded, passport_wire,
                      passport_wire_len - 1u), VCS_ZCODE_COMMONS_SIZE);
        passport_wire[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_module_passport_v1_decode(
                      &passport_decoded, passport_wire, passport_wire_len),
                  VCS_ZCODE_COMMONS_MAGIC);
        passport_wire[0] ^= 1u;
        passport_wire[40] ^= 1u;
        ASSERT_EQ(vcs_zcode_module_passport_v1_decode(
                      &passport_decoded, passport_wire, passport_wire_len),
                  VCS_ZCODE_COMMONS_SIGNATURE);
        struct vcs_zcode_module_passport_v1 empty_passport = {0};
        ASSERT(memcmp(&passport_decoded, &empty_passport,
                      sizeof(passport_decoded)) == 0);
        memset(passport.tests_root, 0, 32);
        ASSERT_EQ(vcs_zcode_module_passport_v1_validate(&passport),
                  VCS_ZCODE_COMMONS_ROOT);

        struct vcs_zcode_workspace_entry_v1 entries[3] = {0};
        for (size_t i = 0; i < 3; i++) {
            cv2_fill(entries[i].module_release_root, (uint8_t)(1u + i));
            cv2_fill(entries[i].module_passport_root, (uint8_t)(0x41u + i));
            cv2_fill(entries[i].semantic_fingerprint_root,
                     (uint8_t)(0x51u + i));
            cv2_fill(entries[i].source_assignment_root,
                     (uint8_t)(0x61u + i));
            if (i > 0)
                cv2_fill(entries[i].predecessor_release_root,
                         (uint8_t)i);
            entries[i].sequence = i + 1u;
        }
        struct vcs_zcode_workspace_edge_v1 edges[2] = {
            {.from_entry = 0, .to_entry = 1},
            {.from_entry = 1, .to_entry = 2},
        };
        uint8_t asset_roots[1][32]; memcpy(asset_roots[0], asset_root, 32);
        struct vcs_zcode_workspace_manifest_v1 workspace = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
            .sequence = 1,
            .entries = entries,
            .entry_count = 3,
            .edges = edges,
            .edge_count = 2,
            .typed_asset_roots = asset_roots,
            .typed_asset_count = 1,
        };
        cv2_fill(workspace.signer_root, 0x71);
        cv2_fill(workspace.signature, 0x72);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_validate(&workspace),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_root(
                      &workspace, workspace_root), VCS_ZCODE_COMMONS_OK);
        char ahex[65], whex[65];
        zcl_hex_encode(asset_root, 32, ahex);
        zcl_hex_encode(workspace_root, 32, whex);
        printf("typed_asset_manifest.v1=%s workspace_manifest.v1=%s\n",
               ahex, whex);
        ASSERT(zcl_hex_decode(asset_root_kat, expected, 32));
        ASSERT(memcmp(asset_root, expected, 32) == 0);
        ASSERT(zcl_hex_decode(workspace_root_kat, expected, 32));
        ASSERT(memcmp(workspace_root, expected, 32) == 0);

        struct vcs_zcode_workspace_manifest_v1 signed_workspace = workspace;
        uint8_t workspace_seed[32], workspace_secret[32];
        memset(workspace_seed, 0xa7, sizeof(workspace_seed));
        ed25519_keypair(signed_workspace.signer_root, workspace_secret,
                        workspace_seed);
        memset(signed_workspace.signature, 0,
               sizeof(signed_workspace.signature));
        uint8_t workspace_unsigned_root[32];
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_unsigned_root(
                      &signed_workspace, workspace_unsigned_root),
                  VCS_ZCODE_COMMONS_OK);
        uint8_t workspace_payload[
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES];
        size_t workspace_payload_len = 0;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_signing_payload(
                      &signed_workspace, workspace_payload,
                      sizeof(workspace_payload), &workspace_payload_len),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(workspace_payload_len, sizeof(workspace_payload));
        ASSERT(memcmp(workspace_payload + workspace_payload_len - 32u,
                      workspace_unsigned_root, 32) == 0);
        char workspace_unsigned_hex[65];
        zcl_hex_encode(workspace_unsigned_root, 32, workspace_unsigned_hex);
        printf(" workspace_manifest.v1.unsigned=%s\n",
               workspace_unsigned_hex);
        ASSERT(zcl_hex_decode(workspace_unsigned_root_kat, expected, 32));
        ASSERT(memcmp(workspace_unsigned_root, expected, 32) == 0);
        ed25519_sign(signed_workspace.signature, workspace_payload,
                     workspace_payload_len, workspace_secret,
                     signed_workspace.signer_root);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_verify(&signed_workspace),
                  VCS_ZCODE_COMMONS_OK);
        size_t workspace_wire_size = 0, workspace_wire_len = 0;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_wire_size(
                      &signed_workspace, &workspace_wire_size),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(workspace_wire_size,
                  VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES +
                  3u * VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES +
                  2u * VCS_ZCODE_WORKSPACE_MANIFEST_V1_EDGE_WIRE_BYTES +
                  VCS_ZCODE_WORKSPACE_MANIFEST_V1_ASSET_WIRE_BYTES);
        uint8_t *workspace_wire = zcl_malloc(
            workspace_wire_size, "test_workspace_manifest_wire");
        ASSERT(workspace_wire != NULL);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_encode(
                      &signed_workspace, workspace_wire,
                      workspace_wire_size, &workspace_wire_len),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(workspace_wire_len, workspace_wire_size);
        ASSERT(memcmp(workspace_wire, "ZCWM1\0\0\0", 8) == 0);
        struct vcs_zcode_workspace_manifest_v1_decoded decoded_workspace = {0};
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_decode(
                      &decoded_workspace, workspace_wire,
                      workspace_wire_len), VCS_ZCODE_COMMONS_OK);
        uint8_t signed_workspace_root[32], decoded_workspace_root[32];
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_root(
                      &signed_workspace, signed_workspace_root),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_root(
                      &decoded_workspace.manifest, decoded_workspace_root),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT(memcmp(signed_workspace_root, decoded_workspace_root, 32) == 0);
        uint8_t *workspace_reencoded = zcl_malloc(
            workspace_wire_size, "test_workspace_manifest_reencode");
        ASSERT(workspace_reencoded != NULL);
        size_t workspace_reencoded_len = 0;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_encode(
                      &decoded_workspace.manifest, workspace_reencoded,
                      workspace_wire_size, &workspace_reencoded_len),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(workspace_reencoded_len, workspace_wire_len);
        ASSERT(memcmp(workspace_reencoded, workspace_wire,
                      workspace_wire_len) == 0);
        vcs_zcode_workspace_manifest_v1_decoded_free(&decoded_workspace);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_decode(
                      &decoded_workspace, workspace_wire,
                      workspace_wire_len - 1u), VCS_ZCODE_COMMONS_SIZE);
        workspace_wire[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_decode(
                      &decoded_workspace, workspace_wire,
                      workspace_wire_len), VCS_ZCODE_COMMONS_MAGIC);
        workspace_wire[0] ^= 1u;
        workspace_wire[100] ^= 1u;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_decode(
                      &decoded_workspace, workspace_wire,
                      workspace_wire_len), VCS_ZCODE_COMMONS_SIGNATURE);
        workspace_wire[100] ^= 1u;
        free(workspace_reencoded);
        free(workspace_wire);
        signed_workspace.signature[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_verify(&signed_workspace),
                  VCS_ZCODE_COMMONS_SIGNATURE);
        signed_workspace.signature[0] ^= 1u;
        entries[0].sequence++;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_verify(&signed_workspace),
                  VCS_ZCODE_COMMONS_SIGNATURE);
        entries[0].sequence--;

        struct vcs_zcode_workspace_edge_v1 cycle[2] = {
            {.from_entry = 0, .to_entry = 1},
            {.from_entry = 1, .to_entry = 0},
        };
        workspace.edges = cycle;
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_validate(&workspace),
                  VCS_ZCODE_COMMONS_POLICY);
        workspace.edges = edges;
        memcpy(entries[2].semantic_fingerprint_root,
               entries[0].semantic_fingerprint_root, 32);
        ASSERT_EQ(vcs_zcode_workspace_manifest_v1_validate(&workspace),
                  VCS_ZCODE_COMMONS_DUPLICATE);

        struct vcs_zcode_mission_v1 mission = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
            .created_height = 100,
            .created_mtp = 200,
        };
        cv2_fill(mission.publisher_binding_root, 0x81);
        cv2_fill(mission.subject_tags_root, 0x82);
        cv2_fill(mission.goal_text_root, 0x83);
        cv2_fill(mission.signature, 0x84);
        ASSERT_EQ(vcs_zcode_mission_v1_validate(&mission),
                  VCS_ZCODE_COMMONS_OK);

        struct vcs_zcode_contribution_split_v1 split = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
            .total_award_atoms = UINT64_C(100000000),
            .entry_count = 2,
        };
        cv2_fill(split.claim_root, 0x91);
        cv2_fill(split.entries[0].recipient_binding_root, 0x92);
        cv2_fill(split.entries[1].recipient_binding_root, 0x93);
        cv2_fill(split.entries[0].signature, 0x94);
        cv2_fill(split.entries[1].signature, 0x95);
        split.entries[0].award_atoms = UINT64_C(40000000);
        split.entries[1].award_atoms = UINT64_C(60000000);
        ASSERT_EQ(vcs_zcode_contribution_split_v1_validate(&split),
                  VCS_ZCODE_COMMONS_OK);
        split.entries[1].award_atoms--;
        ASSERT_EQ(vcs_zcode_contribution_split_v1_validate(&split),
                  VCS_ZCODE_COMMONS_AMOUNT);
        PASS();
    } _test_next:;
    return failures;
}

static struct vcs_zcode_moderation_coverage_v1 complete_coverage(void)
{
    return (struct vcs_zcode_moderation_coverage_v1){
        .required_mask = VCS_ZCODE_COVERAGE_REQUIRED_MASK,
        .completed_mask = VCS_ZCODE_COVERAGE_REQUIRED_MASK,
        .object_count = 17,
        .inspected_count = 17,
        .declared_bytes = 4096,
        .inspected_bytes = 4096,
    };
}

static int test_v2_coverage_and_receipt(void)
{
    int failures = 0;
    TEST("coverage is closed-world and receipts expose coordinates, not content") {
        struct vcs_zcode_moderation_coverage_v1 coverage =
            complete_coverage();
        ASSERT_EQ(vcs_zcode_moderation_coverage_vote_v1(
                      &coverage, VCS_ZCODE_AUDIENCE_GENERAL,
                      VCS_ZCODE_BEHAVIOR_BENIGN),
                  VCS_ZCODE_MODERATION_VOTE_PASS);
        ASSERT_EQ(vcs_zcode_moderation_coverage_vote_v1(
                      &coverage, VCS_ZCODE_AUDIENCE_CONTEXTUAL_SCIENCE,
                      VCS_ZCODE_BEHAVIOR_DUAL_USE),
                  VCS_ZCODE_MODERATION_VOTE_PASS);
        ASSERT_EQ(vcs_zcode_moderation_coverage_vote_v1(
                      &coverage, VCS_ZCODE_AUDIENCE_MATURE,
                      VCS_ZCODE_BEHAVIOR_BENIGN),
                  VCS_ZCODE_MODERATION_VOTE_BLOCK);
        coverage.failure_mask = VCS_ZCODE_COVERAGE_ENCRYPTED;
        ASSERT_EQ(vcs_zcode_moderation_coverage_vote_v1(
                      &coverage, VCS_ZCODE_AUDIENCE_GENERAL,
                      VCS_ZCODE_BEHAVIOR_BENIGN),
                  VCS_ZCODE_MODERATION_VOTE_UNKNOWN);
        coverage = complete_coverage(); coverage.inspected_count--;
        ASSERT_EQ(vcs_zcode_moderation_coverage_vote_v1(
                      &coverage, VCS_ZCODE_AUDIENCE_GENERAL,
                      VCS_ZCODE_BEHAVIOR_BENIGN),
                  VCS_ZCODE_MODERATION_VOTE_UNKNOWN);

        struct vcs_zcode_classification_receipt_v1 receipt = {0};
        receipt.schema_version = 1;
        receipt.flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
        cv2_fill(receipt.request_root, 0x31);
        cv2_fill(receipt.content_root, 0x32);
        cv2_fill(receipt.policy_root, 0x33);
        cv2_fill(receipt.classifier_manifest_root, 0x34);
        cv2_fill(receipt.operator_group_root, 0x35);
        cv2_fill(receipt.model_family_root, 0x36);
        receipt.coverage = complete_coverage();
        receipt.audience = VCS_ZCODE_AUDIENCE_CONTEXTUAL_SCIENCE;
        receipt.behavior = VCS_ZCODE_BEHAVIOR_DUAL_USE;
        receipt.reason_code_mask = 1;
        receipt.completed_height = 9000;
        receipt.completed_mtp = 8000;
        cv2_fill(receipt.signature, 0x37);
        ASSERT_EQ(vcs_zcode_classification_receipt_v1_validate(&receipt),
                  VCS_ZCODE_COMMONS_OK);
        uint8_t root[32], expected[32];
        ASSERT_EQ(vcs_zcode_classification_receipt_v1_root(&receipt, root),
                  VCS_ZCODE_COMMONS_OK);
        char hex[65]; zcl_hex_encode(root, 32, hex);
        printf("classification_receipt.v1=%s\n", hex);
        ASSERT(zcl_hex_decode(receipt_root_kat, expected, 32));
        ASSERT(memcmp(root, expected, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static void cv2_services(struct vcs_zcode_moderation_service_v1 *services,
                         size_t count)
{
    memset(services, 0, count * sizeof(*services));
    for (size_t i = 0; i < count; i++) {
        cv2_fill(services[i].zid_root, (uint8_t)(0x10u + i));
        cv2_fill(services[i].operator_group_root, (uint8_t)(0x30u + i));
        cv2_fill(services[i].model_family_root,
                 (uint8_t)(0x50u + (i % 4u)));
        services[i].eligible = true;
    }
}

static int test_v2_panels(void)
{
    int failures = 0;
    TEST("future-hash panels are one-operator-one-vote with exact ratchets") {
        struct vcs_zcode_moderation_service_v1 services[16];
        cv2_services(services, 16);
        /* A second ZID in group zero cannot manufacture another vote. */
        memcpy(services[15].operator_group_root,
               services[0].operator_group_root, 32);
        uint8_t future_hash[32]; cv2_fill(future_hash, 0x71);
        const size_t roster_sizes[] = {1, 2, 3, 5, 7, 16};
        const size_t expected_seats[] = {1, 2, 3, 5, 7, 7};
        const size_t expected_quorum[] = {1, 2, 2, 4, 5, 5};
        for (size_t i = 0; i < 6; i++) {
            struct vcs_zcode_classification_panel_v1 panel;
            ASSERT_EQ(vcs_zcode_classification_panel_v1_select(
                          services, roster_sizes[i], future_hash, false,
                          &panel), VCS_ZCODE_COMMONS_OK);
            ASSERT_EQ(panel.selected_count, expected_seats[i]);
            ASSERT_EQ(panel.required_votes, expected_quorum[i]);
            if (roster_sizes[i] >= 3)
                ASSERT(panel.distinct_model_families >= 3);
        }
        struct vcs_zcode_classification_panel_v1 panel;
        ASSERT_EQ(vcs_zcode_classification_panel_v1_select(
                      services, 16, future_hash, false, &panel),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(panel.eligible_operator_groups, 15);
        enum vcs_zcode_moderation_vote_v1 votes[7] = {
            VCS_ZCODE_MODERATION_VOTE_PASS,
            VCS_ZCODE_MODERATION_VOTE_PASS,
            VCS_ZCODE_MODERATION_VOTE_PASS,
            VCS_ZCODE_MODERATION_VOTE_PASS,
            VCS_ZCODE_MODERATION_VOTE_PASS,
            VCS_ZCODE_MODERATION_VOTE_BLOCK,
            VCS_ZCODE_MODERATION_VOTE_UNKNOWN,
        };
        ASSERT_EQ(vcs_zcode_classification_panel_v1_decide(
                      &panel, votes, 7),
                  VCS_ZCODE_ADMISSION_RESILIENT_PASS);
        for (size_t i = 0; i < 5; i++)
            votes[i] = VCS_ZCODE_MODERATION_VOTE_BLOCK;
        ASSERT_EQ(vcs_zcode_classification_panel_v1_decide(
                      &panel, votes, 7), VCS_ZCODE_ADMISSION_RESTRICTED);
        ASSERT(vcs_zcode_commons_admission_is_default_visible_v1(
            VCS_ZCODE_ADMISSION_SELF_SCREENED, true, true));
        ASSERT(!vcs_zcode_commons_admission_is_issuance_eligible_v1(
            VCS_ZCODE_ADMISSION_SELF_SCREENED,
            VCS_ZCODE_MODERATION_TIER_SELF_SCREENED, true));
        ASSERT(vcs_zcode_commons_admission_is_issuance_eligible_v1(
            VCS_ZCODE_ADMISSION_RESILIENT_PASS,
            VCS_ZCODE_MODERATION_TIER_RESILIENT_PASS, true));
        ASSERT(!vcs_zcode_commons_admission_is_default_visible_v1(
            VCS_ZCODE_ADMISSION_RESILIENT_PASS, false, true));

        ASSERT_EQ(vcs_zcode_classification_panel_v1_select(
                      services, 10, future_hash, true, &panel),
                  VCS_ZCODE_COMMONS_QUORUM);
        ASSERT_EQ(vcs_zcode_classification_panel_v1_select(
                      services, 12, future_hash, true, &panel),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(panel.selected_count, 11);
        ASSERT_EQ(panel.required_votes, 8);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_commons(void)
{
    int failures = test_v2_policy_kats() +
                   test_v2_truthful_activation_status() +
                   test_v2_c23_corpus_objects() +
                   test_v2_c23_checkpoint_verify_command() +
                   test_v2_c23_shard_verify_command() +
                   test_v2_c23_shard_page_command() +
                   test_v2_productivity_verify_command() +
                   test_v2_epoch_selection() +
                   test_v2_workspace_objects() +
                   test_v2_coverage_and_receipt() + test_v2_panels();
    TEST("Commons authorities fail closed and remain simulation-only") {
        uint8_t root[32];
        struct vcs_zcode_epoch_selection_result_v2 result;
        ASSERT_EQ(vcs_zcode_policy_candidate_v2_root(NULL, root),
                  VCS_ZCODE_COMMONS_NULL);
        ASSERT_EQ(vcs_zcode_epoch_select_v2(NULL, NULL, &result),
                  VCS_ZCODE_COMMONS_NULL);
        ASSERT(!vcs_zcode_commons_admission_is_default_visible_v1(
            VCS_ZCODE_ADMISSION_UNKNOWN, true, true));
        PASS();
    } _test_next:;
    printf("=== zcode_commons: %d failures ===\n", failures);
    return failures;
}
