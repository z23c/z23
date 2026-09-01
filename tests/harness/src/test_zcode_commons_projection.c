/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove ZC23 epoch creation-set accounting and byte-identical
 * rebuild-from-CAS of the Living Commons projection. */
#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_claim_epoch.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_creation_claim.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_epoch_creation.h"

#include <string.h>

static void commons_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* A valid standalone attribution: exact challenge timing, policy-epoch 1. */
static void commons_attribution_fixture(
    struct vcs_zcode_creation_attribution_v1 *a, uint8_t fill_base,
    uint64_t award_atoms)
{
    memset(a, 0, sizeof(*a));
    a->schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    a->category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
    a->lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
    a->epoch = 1;
    a->award_atoms = award_atoms;
    a->challenge_opening_height = 100;
    commons_fill(a->challenge_opening_hash, fill_base);
    a->challenge_opening_mtp = 1000;
    a->challenge_maturity_height = 8164;
    a->challenge_maturity_mtp = 605800;
    a->created_unix = 605801;
    commons_fill(a->network_genesis_root, (uint8_t)(fill_base + 1));
    commons_fill(a->zc23_policy_root, (uint8_t)(fill_base + 2));
    commons_fill(a->contributor_binding_root, (uint8_t)(fill_base + 3));
    commons_fill(a->task_root, (uint8_t)(fill_base + 4));
    commons_fill(a->candidate_root, (uint8_t)(fill_base + 5));
    commons_fill(a->proof_policy_root, (uint8_t)(fill_base + 6));
    commons_fill(a->proof_set_root, (uint8_t)(fill_base + 7));
    commons_fill(a->proven_lane_root, (uint8_t)(fill_base + 8));
    commons_fill(a->score_receipt_root, (uint8_t)(fill_base + 9));
    commons_fill(a->package_root, (uint8_t)(fill_base + 10));
    commons_fill(a->release_root, (uint8_t)(fill_base + 11));
    commons_fill(a->license_evidence_root, (uint8_t)(fill_base + 12));
}

static void commons_epoch_fixture(
    struct vcs_zcode_epoch_creation_set_v1 *set, uint64_t epoch,
    uint8_t previous_fill, uint8_t roots[][32], size_t count, uint64_t mint)
{
    vcs_zcode_epoch_creation_init(set);
    set->schema_version = VCS_ZCODE_EPOCH_CREATION_VERSION;
    set->epoch = epoch;
    set->emission_cap_atoms = UINT64_C(5000000000000); /* era-0 cap */
    set->actual_mint_atoms = mint;
    set->unissued_atoms = set->emission_cap_atoms - mint;
    commons_fill(set->network_genesis_root, 21);
    commons_fill(set->zc23_policy_root, 22);
    commons_fill(set->previous_epoch_creation_root, previous_fill);
    commons_fill(set->committee_evidence_snapshot_root, 24);
    set->opening_height = 100;
    commons_fill(set->opening_hash, 25);
    set->opening_mtp = 1000;
    set->maturity_height = 8164;
    commons_fill(set->maturity_hash, 26);
    set->maturity_mtp = 605800;
    set->attribution_roots = roots;
    set->attribution_count = count;
}

static bool commons_store_attribution(
    const char *workspace,
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint8_t root_out[32])
{
    uint8_t wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
    if (vcs_zcode_creation_attribution_serialize(attribution, wire) !=
            VCS_ZCODE_CREATION_OK ||
        vcs_zcode_creation_attribution_root(attribution, root_out) !=
            VCS_ZCODE_CREATION_OK)
        return false;
    return vcs_object_put_addressed(workspace, root_out, wire, sizeof(wire));
}

static bool commons_store_epoch(
    const char *workspace, struct vcs_zcode_epoch_creation_set_v1 *set,
    uint8_t root_out[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_zcode_epoch_creation_serialize(set, &wire, &wire_len) !=
            VCS_ZCODE_EPOCH_CREATION_OK ||
        vcs_zcode_epoch_creation_root(set, root_out) !=
            VCS_ZCODE_EPOCH_CREATION_OK) {
        free(wire);
        return false;
    }
    bool stored = vcs_object_put_addressed(workspace, root_out, wire,
                                           wire_len);
    free(wire);
    return stored;
}

static void commons_claim_fixture(
    struct vcs_zcode_creation_claim_wire_v2 *claim, uint8_t value,
    uint64_t maturity_height, int64_t maturity_mtp, uint16_t flags)
{
    uint8_t seed[32];
    memset(claim, 0, sizeof(*claim));
    memset(seed, (uint8_t)(value + 31u), sizeof(seed));
    claim->schema_version = VCS_ZCODE_CREATION_CLAIM_V2_VERSION;
    claim->flags = flags;
    claim->category = value % VCS_ZCODE_COMMONS_CATEGORY_COUNT;
    commons_fill(claim->recipient_binding_root, value);
    commons_fill(claim->workspace_lineage_root, (uint8_t)(value + 1u));
    commons_fill(claim->semantic_lineage_root, (uint8_t)(value + 2u));
    commons_fill(claim->evidence_root, (uint8_t)(value + 3u));
    commons_fill(claim->commons_admission_root, (uint8_t)(value + 4u));
    claim->maturity_height = maturity_height;
    claim->maturity_mtp = maturity_mtp;
    (void)vcs_zcode_creation_claim_wire_v2_sign(claim, seed);
}

static bool commons_store_claim(
    const char *workspace,
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    uint8_t root_out[32])
{
    uint8_t wire[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES];
    size_t wire_len = 0;
    return vcs_zcode_creation_claim_wire_v2_encode(
               claim, wire, sizeof(wire), &wire_len) ==
               VCS_ZCODE_CREATION_CLAIM_OK &&
           vcs_zcode_creation_claim_wire_v2_root(claim, root_out) ==
               VCS_ZCODE_CREATION_CLAIM_OK &&
           vcs_object_put_addressed(workspace, root_out, wire, wire_len);
}

static int creation_claim_object_test(void)
{
    int failures = 0;
    TEST("signed creation claim has canonical bytes and fails closed") {
        struct vcs_zcode_creation_claim_wire_v2 claim;
        commons_claim_fixture(&claim, 9, 1234, 5678,
                              VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS);
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_validate(&claim),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        uint8_t first[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES];
        size_t first_len = 0, second_len = 0;
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_encode(
                      &claim, first, sizeof(first), &first_len),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        ASSERT_EQ(first_len, VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES);
        struct vcs_zcode_creation_claim_wire_v2 parsed;
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_decode(
                      &parsed, first, first_len),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_encode(
                      &parsed, second, sizeof(second), &second_len),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        ASSERT(first_len == second_len &&
               memcmp(first, second, first_len) == 0);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_root(&claim, root_a),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_root(&parsed, root_b),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) == 0);
        uint8_t expected_root[32];
        char claim_root_hex[65];
        zcl_hex_encode(root_a, sizeof(root_a), claim_root_hex);
        printf("creation_claim.v2=%s\n", claim_root_hex);
        ASSERT(zcl_hex_decode(VCS_ZCODE_CREATION_CLAIM_KAT_ROOT,
                              expected_root, sizeof(expected_root)));
        ASSERT(memcmp(root_a, expected_root, sizeof(root_a)) == 0);
        for (size_t cut = 0; cut < first_len; cut++)
            ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_decode(
                          &parsed, first, cut),
                      VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE);
        first[first_len - 1u] ^= 1u;
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_decode(
                      &parsed, first, first_len),
                  VCS_ZCODE_CREATION_CLAIM_SIGNATURE);
        struct vcs_zcode_creation_claim_wire_v2 zero = {0};
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int claim_epoch_object_test(void)
{
    int failures = 0;
    TEST("signed-claim epoch proposal has canonical fail-closed bytes") {
        struct vcs_zcode_creation_claim_wire_v2 wires[2];
        struct vcs_zcode_creation_claim_v2 claims[2];
        uint8_t claim_roots[2][32];
        for (size_t i = 0; i < 2; i++) {
            commons_claim_fixture(&wires[i], (uint8_t)(9u + i),
                                  (uint64_t)(100u + i), 1000 + (int64_t)i,
                                  VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS);
            ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_root(
                          &wires[i], claim_roots[i]),
                      VCS_ZCODE_CREATION_CLAIM_OK);
            vcs_zcode_creation_claim_wire_v2_selection(
                &wires[i], claim_roots[i], &claims[i]);
        }
        uint8_t policy_inputs[4][32];
        for (size_t i = 0; i < 4; i++)
            commons_fill(policy_inputs[i], (uint8_t)(0xd0u + i));
        struct vcs_zcode_policy_candidate_v2 policy;
        vcs_zcode_policy_candidate_v2_init(
            &policy, policy_inputs[0], policy_inputs[1], policy_inputs[2],
            policy_inputs[3]);
        uint8_t projection_root[32];
        commons_fill(projection_root, 0xe1);
        struct vcs_zcode_epoch_selection_v2 input = {
            .epoch = 1,
            .cutoff_height = 500,
            .cutoff_mtp = 5000,
            .epoch_capacity_atoms = 1000000000,
            .claims = claims,
            .claim_count = 2,
        };
        struct vcs_zcode_epoch_selection_result_v2 result;
        ASSERT_EQ(vcs_zcode_epoch_select_v2(&input, &policy, &result),
                  VCS_ZCODE_COMMONS_OK);
        ASSERT_EQ(result.selected_count, 2);
        uint8_t policy_root[32];
        ASSERT_EQ(vcs_zcode_policy_candidate_v2_root(&policy, policy_root),
                  VCS_ZCODE_COMMONS_OK);
        struct vcs_zcode_claim_epoch_proposal_v2 proposal;
        ASSERT_EQ(vcs_zcode_claim_epoch_from_selection(
                      &input, policy_root, projection_root, &result, &proposal),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        ASSERT_EQ(vcs_zcode_claim_epoch_validate(&proposal),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        uint8_t *wire = NULL, *second = NULL;
        size_t wire_len = 0, second_len = 0;
        ASSERT_EQ(vcs_zcode_claim_epoch_encode(&proposal, &wire, &wire_len),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        ASSERT_EQ(wire_len, VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES + 64u);
        struct vcs_zcode_claim_epoch_proposal_v2 parsed, zero;
        vcs_zcode_claim_epoch_init(&zero);
        for (size_t cut = 0; cut < wire_len; cut++) {
            ASSERT(vcs_zcode_claim_epoch_decode(&parsed, wire, cut) !=
                   VCS_ZCODE_CLAIM_EPOCH_OK);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT_EQ(vcs_zcode_claim_epoch_decode(&parsed, wire, wire_len),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        ASSERT_EQ(vcs_zcode_claim_epoch_encode(&parsed, &second, &second_len),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        ASSERT(second_len == wire_len && memcmp(second, wire, wire_len) == 0);
        uint8_t root_a[32], root_b[32]; char root_hex[65];
        ASSERT_EQ(vcs_zcode_claim_epoch_root(&proposal, root_a),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        ASSERT_EQ(vcs_zcode_claim_epoch_root(&parsed, root_b),
                  VCS_ZCODE_CLAIM_EPOCH_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        zcl_hex_encode(root_a, sizeof(root_a), root_hex);
        printf("claim_epoch_proposal.v2=%s\n", root_hex);
        uint8_t kat_root[32];
        ASSERT(zcl_hex_decode_lower(VCS_ZCODE_CLAIM_EPOCH_KAT_ROOT,
                                    kat_root, sizeof(kat_root)));
        ASSERT(memcmp(root_a, kat_root, sizeof(root_a)) == 0);

        wire[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_claim_epoch_decode(&zero, wire, wire_len),
                  VCS_ZCODE_CLAIM_EPOCH_MAGIC);
        wire[0] ^= 1u;
        wire[93] = 1u;
        ASSERT_EQ(vcs_zcode_claim_epoch_decode(&zero, wire, wire_len),
                  VCS_ZCODE_CLAIM_EPOCH_RESERVED);
        wire[93] = 0;
        struct vcs_zcode_claim_epoch_proposal_v2 mutated = proposal;
        memcpy(mutated.selected_claim_roots[1],
               mutated.selected_claim_roots[0], 32);
        ASSERT_EQ(vcs_zcode_claim_epoch_validate(&mutated),
                  VCS_ZCODE_CLAIM_EPOCH_DUPLICATE);
        memcpy(mutated.selected_claim_roots[1], claim_roots[1], 32);
        mutated.invalid_count++;
        ASSERT_EQ(vcs_zcode_claim_epoch_validate(&mutated),
                  VCS_ZCODE_CLAIM_EPOCH_COUNT);
        free(second);
        free(wire);
        vcs_zcode_claim_epoch_free(&parsed);
        vcs_zcode_claim_epoch_free(&proposal);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_claim_projection_test(void)
{
    int failures = 0;
    TEST("signed claim projection rebuilds, orders and filters by cutoff") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_commons_claim_projection", "valid");
        ASSERT(vcs_object_store_init(workspace));
        struct vcs_zcode_creation_claim_wire_v2 mature, future, retracted;
        commons_claim_fixture(&future, 12, 300, 3000,
                              VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS);
        commons_claim_fixture(&mature, 11, 100, 1000,
                              VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS);
        commons_claim_fixture(&retracted, 13, 200, 2000,
                              VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS |
                              VCS_ZCODE_CLAIM_V2_RETRACTED);
        uint8_t command_wire[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES];
        size_t command_wire_len = 0;
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_encode(
                      &mature, command_wire, sizeof(command_wire),
                      &command_wire_len),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        char command_hex[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES * 2u + 1u];
        zcl_hex_encode(command_wire, command_wire_len, command_hex);
        struct json_value claim_input;
        json_init(&claim_input);
        json_set_object(&claim_input);
        json_push_kv_str(&claim_input, "workspace", workspace);
        json_push_kv_str(&claim_input, "claim", command_hex);
        const struct zcl_command_spec *claim_plan_spec =
            zcl_command_registry_find(zcl_command_catalog(),
                                      "zcode.commons.claim.plan", NULL);
        char claim_why[160] = {0};
        ASSERT(claim_plan_spec);
        ASSERT(zcl_command_registry_input_validate(
            claim_plan_spec, &claim_input, claim_why, sizeof(claim_why)));
        struct zcl_command_request claim_request = {.input = &claim_input};
        struct zcl_command_reply claim_reply;
        zcl_command_reply_init(&claim_reply, "zcl.test.commons_claim.v2");
        zcl_native_handle_zcode_commons_claim_plan(
            &claim_request, &claim_reply);
        ASSERT_EQ(claim_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&claim_reply.data, "persisted")));
        ASSERT(json_get_bool(json_get(&claim_reply.data,
                                      "signature_verified")));
        ASSERT_STR_EQ(json_get_str(json_get(&claim_reply.data,
                                            "next_command")),
                      "zcode commons claim commit");
        const char *planned_root =
            json_get_str(json_get(&claim_reply.data, "claim_root"));
        ASSERT(planned_root && strlen(planned_root) == 64);
        char planned_root_copy[65];
        memcpy(planned_root_copy, planned_root, sizeof(planned_root_copy));
        zcl_command_reply_free(&claim_reply);

        zcl_command_reply_init(&claim_reply, "zcl.test.commons_claim.v2");
        zcl_native_handle_zcode_commons_claim_commit(
            &claim_request, &claim_reply);
        ASSERT_EQ(claim_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&claim_reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&claim_reply.data,
                                       "issuance_enabled")));
        ASSERT_STR_EQ(json_get_str(json_get(&claim_reply.data,
                                            "next_command")),
                      "zcode commons backlog");
        zcl_command_reply_free(&claim_reply);
        json_free(&claim_input);

        json_init(&claim_input);
        json_set_object(&claim_input);
        json_push_kv_str(&claim_input, "workspace", workspace);
        json_push_kv_str(&claim_input, "root", planned_root_copy);
        claim_request.input = &claim_input;
        zcl_command_reply_init(&claim_reply, "zcl.test.commons_claim.v2");
        zcl_native_handle_zcode_commons_claim_show(
            &claim_request, &claim_reply);
        ASSERT_EQ(claim_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&claim_reply.data, "persisted")));
        ASSERT(json_get_bool(json_get(&claim_reply.data,
                                      "selection_flags_eligible")));
        ASSERT_STR_EQ(json_get_str(json_get(&claim_reply.data, "claim_root")),
                      planned_root_copy);
        zcl_command_reply_free(&claim_reply);
        json_free(&claim_input);
        uint8_t roots[3][32];
        ASSERT(commons_store_claim(workspace, &future, roots[0]));
        ASSERT(commons_store_claim(workspace, &mature, roots[1]));
        ASSERT(commons_store_claim(workspace, &retracted, roots[2]));

        struct vcs_zcode_commons_projection *first =
            vcs_zcode_commons_projection_build(workspace);
        ASSERT(first);
        ASSERT(vcs_zcode_commons_claim_projection_ready(first));
        ASSERT_EQ(vcs_zcode_commons_projection_claim_count(first), 3);
        ASSERT_EQ(vcs_zcode_commons_projection_eligible_claim_count(
                      first, 250, 2500), 1);
        ASSERT_EQ(vcs_zcode_commons_projection_claim_at(first, 0)
                      ->maturity_height, 100);
        ASSERT_EQ(vcs_zcode_commons_projection_claim_at(first, 1)
                      ->maturity_height, 200);
        ASSERT_EQ(vcs_zcode_commons_projection_claim_at(first, 2)
                      ->maturity_height, 300);
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        json_push_kv_str(&input, "workspace", workspace);
        json_push_kv_int(&input, "cutoff_height", 250);
        json_push_kv_int(&input, "cutoff_mtp", 2500);
        const struct zcl_command_spec *backlog_spec =
            zcl_command_registry_find(zcl_command_catalog(),
                                      "zcode.commons.backlog", NULL);
        char input_why[160] = {0};
        ASSERT(backlog_spec);
        ASSERT(zcl_command_registry_input_validate(
            backlog_spec, &input, input_why, sizeof(input_why)));
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.commons_backlog.v2");
        zcl_native_handle_zcode_commons_backlog(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "projection_ready")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "claim_count")), 3);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                        "eligible_claim_count")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "backlog_readiness")),
                      "ready:epoch_plan");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "zcode commons schedule claim plan");
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT(!json_get_bool(json_get(&reply.data, "funds_moved")));
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* The next action consumes these exact signed claims through the pure
         * v2 selector. It remains a plan: no CAS object or wallet state is
         * written, and future/retracted claims are named as invalid. */
        char root_hex[5][65];
        uint8_t policy_inputs[4][32];
        memset(root_hex[0], '0', 64); root_hex[0][64] = 0;
        for (size_t i = 0; i < 4; i++) {
            commons_fill(policy_inputs[i], (uint8_t)(0x70u + i));
            zcl_hex_encode(policy_inputs[i], 32, root_hex[i + 1u]);
        }
        json_init(&input); json_set_object(&input);
        json_push_kv_str(&input, "workspace", workspace);
        json_push_kv_int(&input, "epoch", 1);
        json_push_kv_int(&input, "cutoff_height", 250);
        json_push_kv_int(&input, "cutoff_mtp", 2500);
        json_push_kv_int(&input, "epoch_capacity_atoms", 1000000000);
        json_push_kv_str(&input, "previous_epoch_root", root_hex[0]);
        json_push_kv_str(&input, "network_genesis_root", root_hex[1]);
        json_push_kv_str(&input, "moderation_policy_root", root_hex[2]);
        json_push_kv_str(&input, "qualification_predicates_root",
                         root_hex[3]);
        json_push_kv_str(&input, "backlog_algorithm_root", root_hex[4]);
        const struct zcl_command_spec *epoch_plan_spec =
            zcl_command_registry_find(
                zcl_command_catalog(),
                "zcode.commons.schedule.claim.plan", NULL);
        memset(input_why, 0, sizeof(input_why));
        ASSERT(epoch_plan_spec);
        ASSERT(zcl_command_registry_input_validate(
            epoch_plan_spec, &input, input_why, sizeof(input_why)));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch.v2");
        zcl_native_handle_zcode_commons_schedule_claim_plan(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "pure_calculation")));
        ASSERT(json_get_bool(json_get(&reply.data, "simulation_only")));
        ASSERT(!json_get_bool(json_get(&reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT(!json_get_bool(json_get(&reply.data, "wallet_used")));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "claim_count")), 3);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "selected_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "invalid_count")), 2);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "selected_atoms")),
                  25000000);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                        "expired_capacity_atoms")),
                  975000000);
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "selected_claims_complete")));
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                            "epoch_selection_root"))) == 64);
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                        "claim_epoch_proposal_root"))) == 64);
        char epoch_proposal_root_hex[65];
        memcpy(epoch_proposal_root_hex,
               json_get_str(json_get(&reply.data,
                                     "claim_epoch_proposal_root")),
               sizeof(epoch_proposal_root_hex));
        ASSERT_EQ(json_get_int(json_get(
                      &reply.data, "claim_epoch_proposal_bytes")),
                  VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES + 32);
        const struct json_value *selected =
            json_get(&reply.data, "selected_claims");
        ASSERT(selected && selected->type == JSON_ARR &&
               selected->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(selected, 0),
                                            "claim_root")),
                      planned_root_copy);
        zcl_command_reply_free(&reply);

        const struct zcl_command_spec *epoch_commit_spec =
            zcl_command_registry_find(
                zcl_command_catalog(),
                "zcode.commons.schedule.claim.commit", NULL);
        ASSERT(epoch_commit_spec);
        ASSERT(zcl_command_registry_input_validate(
            epoch_commit_spec, &input, input_why, sizeof(input_why)));
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch.v2");
        zcl_native_handle_zcode_commons_schedule_claim_commit(
            &request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "claim_epoch_proposal_root")),
                      epoch_proposal_root_hex);
        uint8_t epoch_proposal_root[32];
        ASSERT(zcl_hex_decode_lower(epoch_proposal_root_hex,
                                    epoch_proposal_root, 32));
        ASSERT(vcs_object_has(workspace, epoch_proposal_root));
        zcl_command_reply_free(&reply);

        struct json_value show_input;
        json_init(&show_input); json_set_object(&show_input);
        json_push_kv_str(&show_input, "workspace", workspace);
        json_push_kv_str(&show_input, "root", epoch_proposal_root_hex);
        const struct zcl_command_spec *epoch_show_spec =
            zcl_command_registry_find(
                zcl_command_catalog(),
                "zcode.commons.schedule.claim.show", NULL);
        ASSERT(epoch_show_spec);
        ASSERT(zcl_command_registry_input_validate(
            epoch_show_spec, &show_input, input_why, sizeof(input_why)));
        request.input = &show_input;
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch_show.v2");
        zcl_native_handle_zcode_commons_schedule_claim_show(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "pure_calculation")));
        ASSERT(json_get_bool(json_get(&reply.data, "canonical_proposal")));
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "current_selection_verified")));
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "verification_state")),
                      "canonical:selection_not_reconstructed");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "zcode commons schedule claim verify");
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "claim_epoch_proposal_root")),
                      epoch_proposal_root_hex);
        zcl_command_reply_free(&reply);
        json_free(&show_input);

        /* Verification reloads the committed bytes and reproduces every
         * projection, policy and selection binding from current CAS state. */
        struct json_value verify_input;
        json_init(&verify_input); json_set_object(&verify_input);
        json_push_kv_str(&verify_input, "workspace", workspace);
        json_push_kv_str(&verify_input, "proposal_root",
                         epoch_proposal_root_hex);
        json_push_kv_str(&verify_input, "network_genesis_root", root_hex[1]);
        json_push_kv_str(&verify_input, "moderation_policy_root", root_hex[2]);
        json_push_kv_str(&verify_input, "qualification_predicates_root",
                         root_hex[3]);
        json_push_kv_str(&verify_input, "backlog_algorithm_root", root_hex[4]);
        const struct zcl_command_spec *epoch_verify_spec =
            zcl_command_registry_find(
                zcl_command_catalog(),
                "zcode.commons.schedule.claim.verify", NULL);
        ASSERT(epoch_verify_spec);
        ASSERT(zcl_command_registry_input_validate(
            epoch_verify_spec, &verify_input, input_why, sizeof(input_why)));
        request.input = &verify_input;
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch_verify.v2");
        zcl_native_handle_zcode_commons_schedule_claim_verify(
            &request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "verified")));
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "current_selection_verified")));
        ASSERT(json_get_bool(json_get(&reply.data, "canonical_proposal")));
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data,
                                            "verification_state")),
                      "verified:current_selection");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "next_command")),
                      "zcode commons backlog");
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "restart_reconstructed")));
        ASSERT(json_get_bool(json_get(&reply.data, "bounded_load")));
        ASSERT(!json_get_bool(json_get(&reply.data, "issuance_enabled")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &reply.data, "claim_epoch_proposal_root")),
                      epoch_proposal_root_hex);
        zcl_command_reply_free(&reply);

        json_set_str((struct json_value *)json_get(
                         &verify_input, "moderation_policy_root"),
                     root_hex[1]);
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch_verify.v2");
        zcl_native_handle_zcode_commons_schedule_claim_verify(
            &request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CLAIM_EPOCH_POLICY_MISMATCH");
        ASSERT_STR_EQ(reply.error.evidence,
                      "zcode.commons.schedule.claim.verify");
        zcl_command_reply_free(&reply);
        json_free(&verify_input);

        /* A commit refusal identifies the action the agent actually ran. */
        request.input = &input;
        json_set_str((struct json_value *)json_get(&input, "workspace"),
                     "/var/lib/zclassic23");
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch.v2");
        zcl_native_handle_zcode_commons_schedule_claim_commit(
            &request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "UNSAFE_PROPOSE_WORKSPACE");
        ASSERT_STR_EQ(reply.error.evidence,
                      "zcode.commons.schedule.claim.commit");
        zcl_command_reply_free(&reply);
        json_free(&input);
        uint8_t first_root[32], rebuilt_root[32];
        ASSERT(vcs_zcode_commons_claim_projection_root(first, first_root));
        vcs_zcode_commons_projection_free(first);

        struct vcs_zcode_commons_projection *rebuilt =
            vcs_zcode_commons_projection_build(workspace);
        ASSERT(rebuilt);
        ASSERT(vcs_zcode_commons_claim_projection_root(rebuilt,
                                                       rebuilt_root));
        ASSERT(memcmp(first_root, rebuilt_root, sizeof(first_root)) == 0);
        vcs_zcode_commons_projection_free(rebuilt);

        /* A newly admitted signed claim changes the projection root, so the
         * old proposal becomes explicitly stale instead of false-passing. */
        struct vcs_zcode_creation_claim_wire_v2 added;
        uint8_t added_root[32];
        commons_claim_fixture(&added, 14, 150, 1500,
                              VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS);
        ASSERT(commons_store_claim(workspace, &added, added_root));
        json_init(&verify_input); json_set_object(&verify_input);
        json_push_kv_str(&verify_input, "workspace", workspace);
        json_push_kv_str(&verify_input, "proposal_root",
                         epoch_proposal_root_hex);
        json_push_kv_str(&verify_input, "network_genesis_root", root_hex[1]);
        json_push_kv_str(&verify_input, "moderation_policy_root", root_hex[2]);
        json_push_kv_str(&verify_input, "qualification_predicates_root",
                         root_hex[3]);
        json_push_kv_str(&verify_input, "backlog_algorithm_root", root_hex[4]);
        request.input = &verify_input;
        zcl_command_reply_init(&reply, "zcl.test.commons_claim_epoch_verify.v2");
        zcl_native_handle_zcode_commons_schedule_claim_verify(
            &request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "CLAIM_EPOCH_PROJECTION_STALE");
        zcl_command_reply_free(&reply);
        json_free(&verify_input);
        test_rm_rf(workspace);

        char corrupt_workspace[256];
        test_make_tmpdir(corrupt_workspace, sizeof(corrupt_workspace),
                         "zcode_commons_claim_projection", "corrupt");
        ASSERT(vcs_object_store_init(corrupt_workspace));
        uint8_t wire[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_encode(
                      &mature, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        uint8_t address[32];
        ASSERT_EQ(vcs_zcode_creation_claim_wire_v2_root(&mature, address),
                  VCS_ZCODE_CREATION_CLAIM_OK);
        wire[wire_len - 1u] ^= 1u;
        ASSERT(vcs_object_put_addressed(corrupt_workspace, address, wire,
                                        wire_len));
        rebuilt = vcs_zcode_commons_projection_build(corrupt_workspace);
        ASSERT(rebuilt);
        ASSERT(!vcs_zcode_commons_claim_projection_ready(rebuilt));
        ASSERT_EQ(vcs_zcode_commons_projection_claim_count(rebuilt), 0);
        uint8_t failure_root[32]; const char *failure_reason = NULL;
        ASSERT(vcs_zcode_commons_projection_first_failure(
            rebuilt, failure_root, &failure_reason));
        ASSERT(memcmp(failure_root, address, sizeof(address)) == 0);
        ASSERT_STR_EQ(failure_reason, "claim-root-wire-or-signature");
        vcs_zcode_commons_projection_free(rebuilt);
        test_rm_rf(corrupt_workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int epoch_creation_accounting_test(void)
{
    int failures = 0;
    TEST("ZC23 epoch creation: accounting invariants and wire round-trip") {
        uint8_t roots[2][32];
        commons_fill(roots[0], 27);
        commons_fill(roots[1], 28);
        struct vcs_zcode_epoch_creation_set_v1 set;
        commons_epoch_fixture(&set, 1, 23, roots, 2, UINT64_C(375000000));
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&set),
                  VCS_ZCODE_EPOCH_CREATION_OK);

        struct vcs_zcode_epoch_creation_set_v1 mutated = set;
        memset(mutated.previous_epoch_creation_root, 0, 32);
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_PREDECESSOR);
        mutated = set;
        mutated.epoch = 0; /* epoch 0 must not carry a predecessor */
        mutated.emission_cap_atoms = VCS_ZC23_INITIAL_SUPPLY_ATOMS;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_PREDECESSOR);
        mutated = set;
        mutated.emission_cap_atoms++;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_CAP);
        mutated = set;
        mutated.unissued_atoms++;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_SUM);
        mutated = set;
        mutated.actual_mint_atoms = 0; /* mint of zero means no attributions */
        mutated.unissued_atoms = mutated.emission_cap_atoms;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_SUM);
        mutated = set;
        mutated.attribution_count = VCS_ZCODE_EPOCH_CREATION_MAX_ATTRIBUTIONS + 1;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_ORDER);
        uint8_t swapped[2][32];
        memcpy(swapped[0], roots[1], 32);
        memcpy(swapped[1], roots[0], 32);
        mutated = set;
        mutated.attribution_roots = swapped;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_ORDER);
        uint8_t with_zero[2][32];
        memset(with_zero[0], 0, 32);
        memcpy(with_zero[1], roots[1], 32);
        mutated = set;
        mutated.attribution_roots = with_zero;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_ORDER);
        mutated = set;
        mutated.attribution_count = 1;
        mutated.attribution_roots = NULL;
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_ORDER);
        mutated = set;
        mutated.maturity_height = 8163; /* below opening + challenge blocks */
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_TIME);
        mutated = set;
        mutated.maturity_mtp = 605799; /* below opening mtp + challenge secs */
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_TIME);
        mutated = set;
        mutated.opening_height = UINT64_MAX; /* checked-add must fire */
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&mutated),
                  VCS_ZCODE_EPOCH_CREATION_OVERFLOW);

        /* The frozen whole-token era curve. */
        uint64_t atoms = UINT64_MAX;
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(0, &atoms),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(atoms == VCS_ZC23_INITIAL_SUPPLY_ATOMS);
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(208, &atoms),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(atoms == UINT64_C(5000000000000));
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(209, &atoms),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(atoms == UINT64_C(2500000000000));
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(3328, &atoms),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(atoms == VCS_ZC23_ATOMS_PER_TOKEN);
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(3329, &atoms),
                  VCS_ZCODE_EPOCH_CREATION_OK && atoms == 0);
        ASSERT_EQ(vcs_zc23_policy_epoch_cap_atoms(1, NULL),
                  VCS_ZCODE_EPOCH_CREATION_NULL);

        /* Two-attribution wire: round-trip is byte-exact, truncation fails. */
        uint8_t *wire = NULL, *second = NULL;
        size_t wire_len = 0, second_len = 0;
        ASSERT_EQ(vcs_zcode_epoch_creation_serialize(&set, &wire, &wire_len),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(wire_len == VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES + 64u);
        struct vcs_zcode_epoch_creation_set_v1 parsed, zero;
        vcs_zcode_epoch_creation_init(&zero);
        ASSERT_EQ(vcs_zcode_epoch_creation_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        vcs_zcode_epoch_creation_free(&parsed);
        for (size_t cut = 0; cut < wire_len; cut++) {
            ASSERT(vcs_zcode_epoch_creation_parse(wire, cut, &parsed) !=
                   VCS_ZCODE_EPOCH_CREATION_OK);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT_EQ(vcs_zcode_epoch_creation_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT_EQ(vcs_zcode_epoch_creation_serialize(&parsed, &second,
                                                     &second_len),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(second_len == wire_len && memcmp(wire, second, wire_len) == 0);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_epoch_creation_root(&set, root_a),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT_EQ(vcs_zcode_epoch_creation_root(&parsed, root_b),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        wire[0] ^= 1;
        ASSERT_EQ(vcs_zcode_epoch_creation_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_CREATION_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        wire[0] ^= 1;
        wire[10] = 1; /* reserved u16 must stay zero */
        ASSERT_EQ(vcs_zcode_epoch_creation_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_CREATION_RESERVED);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        free(second);
        free(wire);
        vcs_zcode_epoch_creation_free(&parsed);
        PASS();
    } _test_next:;
    return failures;
}

struct epoch_callback_fixture {
    bool anchor_active;
    uint64_t opening_height;
    uint8_t opening_hash[32];
    uint64_t maturity_height;
    uint8_t maturity_hash[32];
    uint64_t award_atoms;
};

static bool epoch_test_anchor(void *opaque, uint64_t height,
                              const uint8_t hash[32])
{
    const struct epoch_callback_fixture *fixture = opaque;
    return fixture && fixture->anchor_active &&
           ((height == fixture->opening_height &&
             memcmp(hash, fixture->opening_hash, 32) == 0) ||
            (height == fixture->maturity_height &&
             memcmp(hash, fixture->maturity_hash, 32) == 0));
}

static bool epoch_test_duplicate(void *opaque,
                                 const uint8_t candidate_root[32],
                                 const uint8_t attribution_root[32])
{
    (void)opaque;
    (void)candidate_root;
    (void)attribution_root;
    return false;
}

static bool epoch_test_award(
    void *opaque, const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint64_t *expected_atoms)
{
    const struct epoch_callback_fixture *fixture = opaque;
    (void)attribution;
    if (!fixture || !expected_atoms)
        return false;
    *expected_atoms = fixture->award_atoms;
    return true;
}

static int epoch_creation_verify_failclosed_test(void)
{
    int failures = 0;
    TEST("ZC23 epoch creation: CAS verification fails closed rung by rung") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_epoch_verify", "empty");
        ASSERT(vcs_object_store_init(workspace));

        uint8_t roots[1][32];
        commons_fill(roots[0], 27);
        struct vcs_zcode_epoch_creation_set_v1 set;
        commons_epoch_fixture(&set, 1, 23, roots, 1, UINT64_C(125000000));
        ASSERT_EQ(vcs_zcode_epoch_creation_validate(&set),
                  VCS_ZCODE_EPOCH_CREATION_OK);

        struct epoch_callback_fixture callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.anchor_active = true;
        callbacks.opening_height = set.opening_height;
        memcpy(callbacks.opening_hash, set.opening_hash, 32);
        callbacks.maturity_height = set.maturity_height;
        memcpy(callbacks.maturity_hash, set.maturity_hash, 32);
        callbacks.award_atoms = set.actual_mint_atoms;

        struct vcs_zcode_epoch_creation_validation_context context = {
            .workspace = workspace,
            .expected_network_genesis_root = set.network_genesis_root,
            .expected_zc23_policy_root = set.zc23_policy_root,
            .expected_previous_epoch_creation_root =
                set.previous_epoch_creation_root,
            .observed_actual_mint_atoms = set.actual_mint_atoms,
            .active_height = set.maturity_height,
            .active_mtp = set.maturity_mtp,
            .now_unix = 605801,
            .anchor_is_active = epoch_test_anchor,
            .contribution_is_duplicate = epoch_test_duplicate,
            .award_atoms_for_creation = epoch_test_award,
            .callback_opaque = &callbacks,
        };
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, NULL),
                  VCS_ZCODE_EPOCH_CREATION_CONTEXT);
        context.now_unix = 0;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_CONTEXT);
        context.now_unix = 605801;
        context.anchor_is_active = NULL;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_CONTEXT);
        context.anchor_is_active = epoch_test_anchor;
        context.contribution_is_duplicate = NULL;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_CONTEXT);
        context.contribution_is_duplicate = epoch_test_duplicate;
        context.award_atoms_for_creation = NULL;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_CONTEXT);
        context.award_atoms_for_creation = epoch_test_award;

        uint8_t zero_root[32] = {0};
        context.expected_previous_epoch_creation_root = zero_root;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_PREDECESSOR);
        context.expected_previous_epoch_creation_root =
            set.previous_epoch_creation_root;
        context.observed_actual_mint_atoms = 1;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_MINT);
        context.observed_actual_mint_atoms = set.actual_mint_atoms;
        context.active_height = set.maturity_height - 1;
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_IMMATURE);
        context.active_height = set.maturity_height;
        callbacks.anchor_active = false; /* anchor reorged off the chain */
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_REORG);
        callbacks.anchor_active = true;

        /* Context and chain facts pass; the attribution object is absent. */
        ASSERT_EQ(vcs_zcode_epoch_creation_verify_cas(&set, &context),
                  VCS_ZCODE_EPOCH_CREATION_CAS);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_rebuild_identity_test(void)
{
    int failures = 0;
    TEST("ZC23 commons projection: rebuild from CAS is byte-identical") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_commons_rebuild", "populated");
        ASSERT(vcs_object_store_init(workspace));

        struct vcs_zcode_creation_attribution_v1 first_attribution,
            second_attribution;
        commons_attribution_fixture(&first_attribution, 27,
                                    UINT64_C(125000000));
        commons_attribution_fixture(&second_attribution, 41,
                                    UINT64_C(250000000));
        uint8_t first_root[32], second_root[32];
        ASSERT(commons_store_attribution(workspace, &first_attribution,
                                         first_root));
        ASSERT(commons_store_attribution(workspace, &second_attribution,
                                         second_root));
        ASSERT(memcmp(first_root, second_root, 32) != 0);

        uint8_t ordered[2][32];
        if (memcmp(first_root, second_root, 32) < 0) {
            memcpy(ordered[0], first_root, 32);
            memcpy(ordered[1], second_root, 32);
        } else {
            memcpy(ordered[0], second_root, 32);
            memcpy(ordered[1], first_root, 32);
        }
        struct vcs_zcode_epoch_creation_set_v1 set;
        commons_epoch_fixture(&set, 1, 23, ordered, 2, UINT64_C(375000000));
        uint8_t epoch_root[32];
        ASSERT(commons_store_epoch(workspace, &set, epoch_root));

        struct vcs_zcode_commons_projection *first =
            vcs_zcode_commons_projection_build(workspace);
        struct vcs_zcode_commons_projection *second =
            vcs_zcode_commons_projection_build(workspace);
        ASSERT(first && second);
        ASSERT(vcs_zcode_commons_projection_status(first) ==
               VCS_ZCODE_COMMONS_PARTIAL);
        ASSERT(vcs_zcode_commons_projection_creation_count(first) == 2);
        ASSERT(vcs_zcode_commons_projection_epoch_count(first) == 1);
        ASSERT(vcs_zcode_commons_projection_attributed_atoms(first) ==
               UINT64_C(375000000));
        ASSERT(vcs_zcode_commons_projection_minted_atoms(first) ==
               UINT64_C(375000000));
        ASSERT(vcs_zcode_commons_projection_unissued_atoms(first) ==
               UINT64_C(5000000000000) - UINT64_C(375000000));
        const struct vcs_zcode_commons_creation_entry *creation_first =
            vcs_zcode_commons_projection_creation_at(first, 0);
        const struct vcs_zcode_commons_creation_entry *creation_second =
            vcs_zcode_commons_projection_creation_at(first, 1);
        const struct vcs_zcode_commons_epoch_entry *epoch =
            vcs_zcode_commons_projection_epoch_at(first, 0);
        ASSERT(creation_first && creation_second && epoch);
        ASSERT(vcs_zcode_commons_projection_creation_at(first, 2) == NULL);
        ASSERT(vcs_zcode_commons_projection_epoch_at(first, 1) == NULL);
        ASSERT(memcmp(creation_first->root, ordered[0], 32) == 0);
        ASSERT(memcmp(creation_second->root, ordered[1], 32) == 0);
        ASSERT(creation_first->epoch == 1 &&
               creation_second->epoch == 1);
        ASSERT(creation_first->category == VCS_ZCODE_CREATION_PUBLIC_SOURCE);
        ASSERT(creation_first->award_atoms +
                   creation_second->award_atoms ==
               UINT64_C(375000000));
        ASSERT(memcmp(epoch->root, epoch_root, 32) == 0);
        ASSERT(epoch->epoch == 1);
        ASSERT(epoch->cap_atoms == UINT64_C(5000000000000));
        ASSERT(epoch->minted_atoms == UINT64_C(375000000));
        ASSERT(epoch->unissued_atoms ==
               UINT64_C(5000000000000) - UINT64_C(375000000));
        ASSERT(epoch->attribution_count == 2);
        ASSERT(memcmp(epoch->previous_root,
                      set.previous_epoch_creation_root, 32) == 0);
        uint8_t failure_root[32];
        const char *failure_reason = NULL;
        ASSERT(!vcs_zcode_commons_projection_first_failure(
                   first, failure_root, &failure_reason));
        uint8_t first_projection_root[32], second_projection_root[32];
        ASSERT(vcs_zcode_commons_projection_root(
                   first, first_projection_root));
        ASSERT(vcs_zcode_commons_projection_root(
                   second, second_projection_root));
        ASSERT(memcmp(first_projection_root, second_projection_root,
                      32) == 0);
        vcs_zcode_commons_projection_free(second);
        vcs_zcode_commons_projection_free(first);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_accounting_failures_test(void)
{
    int failures = 0;
    TEST("ZC23 commons projection: broken accounting is a named failure") {
        uint8_t failure_root[32];
        const char *failure_reason = NULL;

        /* Two epoch sets referencing the same attribution: the duplicate is
         * flagged, never double-counted silently. */
        char duplicate_workspace[256];
        test_make_tmpdir(duplicate_workspace, sizeof(duplicate_workspace),
                         "zcode_commons_failure", "duplicate");
        ASSERT(vcs_object_store_init(duplicate_workspace));
        struct vcs_zcode_creation_attribution_v1 attribution;
        commons_attribution_fixture(&attribution, 27, UINT64_C(125000000));
        uint8_t attribution_root[32];
        ASSERT(commons_store_attribution(duplicate_workspace, &attribution,
                                         attribution_root));
        uint8_t one_root[1][32];
        memcpy(one_root[0], attribution_root, 32);
        struct vcs_zcode_epoch_creation_set_v1 first_set, second_set;
        commons_epoch_fixture(&first_set, 1, 23, one_root, 1,
                              UINT64_C(125000000));
        commons_epoch_fixture(&second_set, 1, 29, one_root, 1,
                              UINT64_C(125000000));
        uint8_t first_epoch_root[32], second_epoch_root[32];
        ASSERT(commons_store_epoch(duplicate_workspace, &first_set,
                                   first_epoch_root));
        ASSERT(commons_store_epoch(duplicate_workspace, &second_set,
                                   second_epoch_root));
        ASSERT(memcmp(first_epoch_root, second_epoch_root, 32) != 0);
        struct vcs_zcode_commons_projection *projection =
            vcs_zcode_commons_projection_build(duplicate_workspace);
        ASSERT(projection);
        ASSERT(vcs_zcode_commons_projection_status(projection) ==
               VCS_ZCODE_COMMONS_PARTIAL);
        ASSERT(vcs_zcode_commons_projection_creation_count(projection) == 1);
        ASSERT(vcs_zcode_commons_projection_epoch_count(projection) == 2);
        ASSERT(vcs_zcode_commons_projection_first_failure(
                   projection, failure_root, &failure_reason));
        ASSERT(memcmp(failure_root, attribution_root, 32) == 0);
        ASSERT_STR_EQ(failure_reason, "duplicate-attribution");
        vcs_zcode_commons_projection_free(projection);
        test_rm_rf(duplicate_workspace);

        /* An epoch set referencing an attribution the CAS does not hold. */
        char missing_workspace[256];
        test_make_tmpdir(missing_workspace, sizeof(missing_workspace),
                         "zcode_commons_failure", "missing");
        ASSERT(vcs_object_store_init(missing_workspace));
        uint8_t absent[1][32];
        commons_fill(absent[0], 99);
        struct vcs_zcode_epoch_creation_set_v1 missing_set;
        commons_epoch_fixture(&missing_set, 1, 23, absent, 1,
                              UINT64_C(125000000));
        uint8_t missing_epoch_root[32];
        ASSERT(commons_store_epoch(missing_workspace, &missing_set,
                                   missing_epoch_root));
        projection = vcs_zcode_commons_projection_build(missing_workspace);
        ASSERT(projection);
        ASSERT(vcs_zcode_commons_projection_creation_count(projection) == 0);
        ASSERT(vcs_zcode_commons_projection_epoch_count(projection) == 1);
        ASSERT(vcs_zcode_commons_projection_attributed_atoms(projection) == 0);
        ASSERT(vcs_zcode_commons_projection_minted_atoms(projection) ==
               UINT64_C(125000000));
        ASSERT(vcs_zcode_commons_projection_first_failure(
                   projection, failure_root, &failure_reason));
        bool absent_is_lower =
            memcmp(absent[0], missing_epoch_root, 32) < 0;
        ASSERT(memcmp(failure_root,
                      absent_is_lower ? absent[0] : missing_epoch_root,
                      32) == 0);
        ASSERT_STR_EQ(failure_reason,
                      absent_is_lower ? "missing-attribution"
                                      : "epoch-attribution-mismatch");
        vcs_zcode_commons_projection_free(projection);
        test_rm_rf(missing_workspace);

        /* Minted atoms that do not equal the referenced awards. */
        char sum_workspace[256];
        test_make_tmpdir(sum_workspace, sizeof(sum_workspace),
                         "zcode_commons_failure", "sum");
        ASSERT(vcs_object_store_init(sum_workspace));
        ASSERT(commons_store_attribution(sum_workspace, &attribution,
                                         attribution_root));
        memcpy(one_root[0], attribution_root, 32);
        struct vcs_zcode_epoch_creation_set_v1 sum_set;
        commons_epoch_fixture(&sum_set, 1, 23, one_root, 1,
                              UINT64_C(125000001));
        uint8_t sum_epoch_root[32];
        ASSERT(commons_store_epoch(sum_workspace, &sum_set, sum_epoch_root));
        projection = vcs_zcode_commons_projection_build(sum_workspace);
        ASSERT(projection);
        ASSERT(vcs_zcode_commons_projection_first_failure(
                   projection, failure_root, &failure_reason));
        ASSERT(memcmp(failure_root, sum_epoch_root, 32) == 0);
        ASSERT_STR_EQ(failure_reason, "epoch-sum-mismatch");
        vcs_zcode_commons_projection_free(projection);
        test_rm_rf(sum_workspace);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_commons_projection(void)
{
    return creation_claim_object_test() +
           claim_epoch_object_test() +
           commons_claim_projection_test() +
           epoch_creation_accounting_test() +
           epoch_creation_verify_failclosed_test() +
           commons_rebuild_identity_test() +
           commons_accounting_failures_test();
}
