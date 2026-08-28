/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical ZC23 creation-attribution and policy arithmetic proofs. */
#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_continuity_policy.h"
#include "vcs/zcode_epoch_creation.h"
#include "vcs/zcode_patronage.h"
#include "vcs/zcode_patronage_settlement.h"
#include "vcs/vcs_object.h"

#include <string.h>
#include <sys/stat.h>

static void creation_fill_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void creation_fixture(struct vcs_zcode_creation_attribution_v1 *a)
{
    memset(a, 0, sizeof(*a));
    a->schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    a->category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
    a->lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
    a->epoch = 7;
    a->award_atoms = UINT64_C(125000000);
    a->challenge_opening_height = 100;
    creation_fill_root(a->challenge_opening_hash, 1);
    a->challenge_opening_mtp = 1000;
    a->challenge_maturity_height = 8164;
    a->challenge_maturity_mtp = 605800;
    a->created_unix = 605801;
    creation_fill_root(a->network_genesis_root, 2);
    creation_fill_root(a->zc23_policy_root, 3);
    creation_fill_root(a->contributor_binding_root, 4);
    creation_fill_root(a->task_root, 5);
    creation_fill_root(a->candidate_root, 6);
    creation_fill_root(a->proof_policy_root, 7);
    creation_fill_root(a->proof_set_root, 8);
    creation_fill_root(a->proven_lane_root, 9);
    creation_fill_root(a->score_receipt_root, 10);
    creation_fill_root(a->package_root, 11);
    creation_fill_root(a->release_root, 12);
    creation_fill_root(a->license_evidence_root, 13);
}

static int creation_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 creation attribution: exact canonical wire and root") {
        struct vcs_zcode_creation_attribution_v1 a, parsed;
        uint8_t first[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        uint8_t root_a[32], root_b[32];
        creation_fixture(&a);
        ASSERT(vcs_zcode_creation_attribution_serialize(&a, first) ==
               VCS_ZCODE_CREATION_OK);
        static const uint8_t wire_prefix_kat[32] = {
            0x5a, 0x43, 0x43, 0x52, 0x45, 0x41, 0x0d, 0x0a,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x59, 0x73, 0x07, 0x00, 0x00, 0x00, 0x00,
        };
        ASSERT(memcmp(first, wire_prefix_kat, sizeof(wire_prefix_kat)) == 0);
        ASSERT(vcs_zcode_creation_attribution_parse(first, sizeof(first),
                                                    &parsed) ==
               VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_zcode_creation_attribution_serialize(&parsed, second) ==
               VCS_ZCODE_CREATION_OK);
        ASSERT(memcmp(first, second, sizeof(first)) == 0);
        ASSERT(vcs_zcode_creation_attribution_root(&a, root_a) ==
               VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_zcode_creation_attribution_root(&parsed, root_b) ==
               VCS_ZCODE_CREATION_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        static const uint8_t root_kat[32] = {
            0x1b, 0x33, 0xb0, 0x17, 0x2b, 0xc7, 0xe9, 0x91,
            0xd2, 0xa1, 0x1a, 0x3e, 0x9f, 0x2d, 0xd3, 0x37,
            0x7e, 0x25, 0xbc, 0x51, 0xd0, 0x78, 0x38, 0x81,
            0x59, 0x0c, 0xd1, 0x88, 0xd8, 0xb4, 0xc6, 0x89,
        };
        ASSERT(memcmp(root_a, root_kat, sizeof(root_kat)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int creation_rejection_test(void)
{
    int failures = 0;
    TEST("ZC23 creation attribution: malformed and noncanonical inputs fail closed") {
        struct vcs_zcode_creation_attribution_v1 a, parsed, zero;
        uint8_t wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES + 1];
        creation_fixture(&a);
        memset(&zero, 0, sizeof(zero));
        ASSERT(vcs_zcode_creation_attribution_serialize(&a, wire) ==
               VCS_ZCODE_CREATION_OK);
        for (size_t cut = 0;
             cut < VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES; cut++) {
            ASSERT(vcs_zcode_creation_attribution_parse(
                       wire, cut, &parsed) ==
                   VCS_ZCODE_CREATION_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT(vcs_zcode_creation_attribution_parse(wire, sizeof(wire) - 2,
                                                    &parsed) ==
               VCS_ZCODE_CREATION_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES] = 0;
        ASSERT(vcs_zcode_creation_attribution_parse(wire, sizeof(wire),
                                                    &parsed) ==
               VCS_ZCODE_CREATION_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT(vcs_zcode_creation_attribution_serialize(&a, wire) ==
               VCS_ZCODE_CREATION_OK);
        wire[0] ^= 1;
        ASSERT(vcs_zcode_creation_attribution_parse(
                   wire, VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES, &parsed) ==
               VCS_ZCODE_CREATION_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        creation_fixture(&a); a.category = 99;
        ASSERT(vcs_zcode_creation_attribution_validate(&a) ==
               VCS_ZCODE_CREATION_CATEGORY);
        creation_fixture(&a); a.award_atoms = 0;
        ASSERT(vcs_zcode_creation_attribution_validate(&a) ==
               VCS_ZCODE_CREATION_AMOUNT);
        creation_fixture(&a); memset(a.release_root, 0, 32);
        ASSERT(vcs_zcode_creation_attribution_validate(&a) ==
               VCS_ZCODE_CREATION_ROOT);
        creation_fixture(&a); a.lineage_kind =
            VCS_ZCODE_CREATION_LINEAGE_RELEASE;
        ASSERT(vcs_zcode_creation_attribution_validate(&a) ==
               VCS_ZCODE_CREATION_LINEAGE);
        creation_fixture(&a); a.lineage_kind =
            VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY;
        creation_fill_root(a.lineage_root, 91);
        ASSERT(vcs_zcode_creation_attribution_validate(&a) ==
               VCS_ZCODE_CREATION_LINEAGE);
        creation_fixture(&a); a.category = VCS_ZCODE_CREATION_COMPATIBILITY;
        ASSERT(vcs_zcode_creation_attribution_validate(&a) ==
               VCS_ZCODE_CREATION_LINEAGE);
        PASS();
    } _test_next:;
    return failures;
}

static int creation_arithmetic_test(void)
{
    int failures = 0;
    TEST("ZC23 creation attribution: eight-decimal emission preserves exact cap") {
        uint64_t atoms = UINT64_MAX;
        ASSERT(VCS_ZC23_DECIMALS == 8);
        ASSERT(vcs_zc23_epoch_cap_atoms(0, &atoms) == VCS_ZCODE_CREATION_OK);
        ASSERT(atoms == UINT64_C(5000000000000));
        ASSERT(vcs_zc23_epoch_cap_atoms(15, &atoms) ==
               VCS_ZCODE_CREATION_OK);
        ASSERT(atoms == VCS_ZC23_ATOMS_PER_TOKEN);
        ASSERT(vcs_zc23_epoch_cap_atoms(16, &atoms) ==
               VCS_ZCODE_CREATION_OK && atoms == 0);
        ASSERT(vcs_zc23_max_supply_atoms(&atoms) == VCS_ZCODE_CREATION_OK);
        ASSERT(atoms == VCS_ZC23_MAX_SUPPLY_ATOMS);
        ASSERT(atoms / VCS_ZC23_ATOMS_PER_TOKEN == UINT64_C(20798753));
        ASSERT(vcs_zc23_max_supply_atoms(NULL) == VCS_ZCODE_CREATION_NULL);
        PASS();
    } _test_next:;
    return failures;
}

static void epoch_creation_fixture(
    struct vcs_zcode_epoch_creation_set_v1 *set,
    uint8_t roots[1][32])
{
    vcs_zcode_epoch_creation_init(set);
    set->schema_version = VCS_ZCODE_EPOCH_CREATION_VERSION;
    set->epoch = 1;
    set->emission_cap_atoms = UINT64_C(5000000000000);
    set->actual_mint_atoms = UINT64_C(125000000);
    set->unissued_atoms = set->emission_cap_atoms - set->actual_mint_atoms;
    creation_fill_root(set->network_genesis_root, 21);
    creation_fill_root(set->zc23_policy_root, 22);
    creation_fill_root(set->previous_epoch_creation_root, 23);
    creation_fill_root(set->committee_evidence_snapshot_root, 24);
    set->opening_height = 100;
    creation_fill_root(set->opening_hash, 25);
    set->opening_mtp = 1000;
    set->maturity_height = 8164;
    creation_fill_root(set->maturity_hash, 26);
    set->maturity_mtp = 605800;
    creation_fill_root(roots[0], 27);
    set->attribution_roots = roots;
    set->attribution_count = 1;
}

static int epoch_creation_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 epoch creation: ordered exact accounting wire") {
        struct vcs_zcode_epoch_creation_set_v1 set, parsed;
        uint8_t roots[1][32];
        epoch_creation_fixture(&set, roots);
        uint8_t *wire = NULL, *second = NULL;
        size_t wire_len = 0, second_len = 0;
        ASSERT(vcs_zcode_epoch_creation_serialize(
                   &set, &wire, &wire_len) == VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(wire_len == VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES + 32u);
        ASSERT(vcs_zcode_epoch_creation_parse(wire, wire_len, &parsed) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        vcs_zcode_epoch_creation_free(&parsed);
        for (size_t cut = 0; cut < wire_len; cut++) {
            ASSERT(vcs_zcode_epoch_creation_parse(wire, cut, &parsed) !=
                   VCS_ZCODE_EPOCH_CREATION_OK);
            vcs_zcode_epoch_creation_free(&parsed);
        }
        ASSERT(vcs_zcode_epoch_creation_parse(wire, wire_len, &parsed) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(vcs_zcode_epoch_creation_serialize(
                   &parsed, &second, &second_len) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(wire_len == second_len &&
               memcmp(wire, second, wire_len) == 0);
        uint8_t first_root[32], second_root[32];
        ASSERT(vcs_zcode_epoch_creation_root(&set, first_root) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(vcs_zcode_epoch_creation_root(&parsed, second_root) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(memcmp(first_root, second_root, 32) == 0);
        static const uint8_t root_kat[32] = {
            0x6d, 0x44, 0x46, 0x74, 0x2c, 0x94, 0xf6, 0x01,
            0xe1, 0x32, 0xc2, 0x1f, 0x35, 0x58, 0xf7, 0xab,
            0x77, 0x4d, 0x8d, 0x1d, 0xda, 0x35, 0xe1, 0xde,
            0xb3, 0x60, 0x3b, 0x16, 0xaf, 0xb4, 0x9f, 0x9a,
        };
        ASSERT(memcmp(first_root, root_kat, sizeof(root_kat)) == 0);
        free(second); free(wire);
        vcs_zcode_epoch_creation_free(&parsed);
        PASS();
    } _test_next:;

    return failures;
}

static int epoch_creation_accounting_test(void)
{
    int failures = 0;
    TEST("ZC23 epoch creation: no carry-forward and exact whole-token tail") {
        uint64_t atoms = UINT64_MAX;
        ASSERT(vcs_zc23_policy_epoch_cap_atoms(0, &atoms) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(atoms == VCS_ZC23_INITIAL_SUPPLY_ATOMS);
        ASSERT(vcs_zc23_policy_epoch_cap_atoms(1, &atoms) ==
               VCS_ZCODE_EPOCH_CREATION_OK &&
               atoms == UINT64_C(5000000000000));
        ASSERT(vcs_zc23_policy_epoch_cap_atoms(208, &atoms) ==
               VCS_ZCODE_EPOCH_CREATION_OK &&
               atoms == UINT64_C(5000000000000));
        ASSERT(vcs_zc23_policy_epoch_cap_atoms(209, &atoms) ==
               VCS_ZCODE_EPOCH_CREATION_OK &&
               atoms == UINT64_C(2500000000000));
        ASSERT(vcs_zc23_policy_epoch_cap_atoms(3328, &atoms) ==
               VCS_ZCODE_EPOCH_CREATION_OK &&
               atoms == VCS_ZC23_ATOMS_PER_TOKEN);
        ASSERT(vcs_zc23_policy_epoch_cap_atoms(3329, &atoms) ==
               VCS_ZCODE_EPOCH_CREATION_OK && atoms == 0);

        struct vcs_zcode_epoch_creation_set_v1 set;
        uint8_t roots[2][32];
        epoch_creation_fixture(&set, roots);
        memcpy(roots[1], roots[0], 32);
        set.attribution_count = 2;
        ASSERT(vcs_zcode_epoch_creation_validate(&set) ==
               VCS_ZCODE_EPOCH_CREATION_ORDER);
        set.attribution_count = 1;
        set.actual_mint_atoms++;
        ASSERT(vcs_zcode_epoch_creation_validate(&set) ==
               VCS_ZCODE_EPOCH_CREATION_SUM);
        set.actual_mint_atoms--;
        set.unissued_atoms++;
        ASSERT(vcs_zcode_epoch_creation_validate(&set) ==
               VCS_ZCODE_EPOCH_CREATION_SUM);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_projection_test(void)
{
    int failures = 0;
    TEST("ZC23 commons projection: absent workspace is non-creating and deterministic") {
        char workspace[256];
        test_fmt_tmpdir(workspace, sizeof(workspace),
                        "zcode_commons", "absent");
        test_rm_rf(workspace);
        ASSERT(access(workspace, F_OK) != 0);
        struct vcs_zcode_commons_projection *first =
            vcs_zcode_commons_projection_build(workspace);
        struct vcs_zcode_commons_projection *second =
            vcs_zcode_commons_projection_build(workspace);
        ASSERT(first && second);
        ASSERT(access(workspace, F_OK) != 0);
        ASSERT(vcs_zcode_commons_projection_status(first) ==
               VCS_ZCODE_COMMONS_UNKNOWN);
        ASSERT(vcs_zcode_commons_projection_creation_count(first) == 0);
        ASSERT(vcs_zcode_commons_projection_epoch_count(first) == 0);
        uint8_t first_root[32], second_root[32];
        ASSERT(vcs_zcode_commons_projection_root(first, first_root));
        ASSERT(vcs_zcode_commons_projection_root(second, second_root));
        ASSERT(memcmp(first_root, second_root, 32) == 0);
        vcs_zcode_commons_projection_free(second);
        vcs_zcode_commons_projection_free(first);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_projection_rebuild_test(void)
{
    int failures = 0;
    TEST("ZC23 commons projection: canonical CAS rebuild preserves exact totals") {
        char workspace[256];
        test_fmt_tmpdir(workspace, sizeof(workspace),
                        "zcode_commons", "populated");
        test_rm_rf(workspace);
        ASSERT(mkdir(workspace, 0700) == 0);
        ASSERT(vcs_object_store_init(workspace));

        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t creation_wire[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES];
        uint8_t creation_root[32];
        creation_fixture(&attribution);
        attribution.epoch = 1;
        ASSERT(vcs_zcode_creation_attribution_serialize(
                   &attribution, creation_wire) == VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_zcode_creation_attribution_root(
                   &attribution, creation_root) == VCS_ZCODE_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
                   workspace, creation_root, creation_wire,
                   sizeof(creation_wire)));

        struct vcs_zcode_epoch_creation_set_v1 epoch;
        uint8_t attribution_roots[1][32];
        epoch_creation_fixture(&epoch, attribution_roots);
        memcpy(attribution_roots[0], creation_root, 32);
        uint8_t *epoch_wire = NULL;
        size_t epoch_wire_len = 0;
        uint8_t epoch_root[32];
        ASSERT(vcs_zcode_epoch_creation_serialize(
                   &epoch, &epoch_wire, &epoch_wire_len) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(vcs_zcode_epoch_creation_root(&epoch, epoch_root) ==
               VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(vcs_object_put_addressed(
                   workspace, epoch_root, epoch_wire, epoch_wire_len));

        struct vcs_zcode_commons_projection *first =
            vcs_zcode_commons_projection_build(workspace);
        struct vcs_zcode_commons_projection *second =
            vcs_zcode_commons_projection_build(workspace);
        ASSERT(first && second);
        ASSERT(vcs_zcode_commons_projection_status(first) ==
               VCS_ZCODE_COMMONS_PARTIAL);
        ASSERT(vcs_zcode_commons_projection_creation_count(first) == 1);
        ASSERT(vcs_zcode_commons_projection_epoch_count(first) == 1);
        ASSERT(vcs_zcode_commons_projection_attributed_atoms(first) ==
               attribution.award_atoms);
        ASSERT(vcs_zcode_commons_projection_minted_atoms(first) ==
               epoch.actual_mint_atoms);
        ASSERT(vcs_zcode_commons_projection_unissued_atoms(first) ==
               epoch.unissued_atoms);
        const struct vcs_zcode_commons_creation_entry *creation =
            vcs_zcode_commons_projection_creation_at(first, 0);
        const struct vcs_zcode_commons_epoch_entry *epoch_entry =
            vcs_zcode_commons_projection_epoch_at(first, 0);
        ASSERT(creation && epoch_entry);
        ASSERT(memcmp(creation->root, creation_root, 32) == 0);
        ASSERT(memcmp(epoch_entry->root, epoch_root, 32) == 0);
        uint8_t first_root[32], second_root[32];
        ASSERT(vcs_zcode_commons_projection_root(first, first_root));
        ASSERT(vcs_zcode_commons_projection_root(second, second_root));
        ASSERT(memcmp(first_root, second_root, 32) == 0);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.commons.v1");
        zcl_native_handle_zcode_commons_status(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_int(json_get(&reply.data, "attributed_atoms")) ==
               (int64_t)attribution.award_atoms);
        ASSERT(json_get_int(json_get(&reply.data, "parsed_mint_atoms")) ==
               (int64_t)epoch.actual_mint_atoms);
        ASSERT(json_get_bool(json_get(&reply.data, "structural_integrity")));
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_int(&input, "epoch", 1));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.commons.v1");
        zcl_native_handle_zcode_commons_epoch(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_int(json_get(&reply.data, "minted_atoms")) ==
               (int64_t)epoch.actual_mint_atoms);
        zcl_command_reply_free(&reply); json_free(&input);

        char creation_hex[65], package_hex[65];
        zcl_hex_encode(creation_root, 32, creation_hex);
        zcl_hex_encode(attribution.package_root, 32, package_hex);
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "root", creation_hex));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.commons.v1");
        zcl_native_handle_zcode_commons_creation_show(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "category")),
                      "public_source") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "package_root", package_hex));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.test.commons.v1");
        zcl_native_handle_zcode_commons_lineage(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_int(json_get(&reply.data, "count")) == 1);
        ASSERT(!json_get_bool(json_get(&reply.data,
                                      "implies_package_ownership")));
        zcl_command_reply_free(&reply); json_free(&input);

        vcs_zcode_commons_projection_free(second);
        vcs_zcode_commons_projection_free(first);
        free(epoch_wire);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_command_noncreating_test(void)
{
    int failures = 0;
    TEST("ZC23 commons commands: absent workspace stays absent") {
        char workspace[256];
        test_fmt_tmpdir(workspace, sizeof(workspace),
                        "zcode_commons_command", "absent");
        test_rm_rf(workspace);
        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply status, rebuild, verify;
        zcl_command_reply_init(&status, "zcl.test.commons.v1");
        zcl_command_reply_init(&rebuild, "zcl.test.commons.v1");
        zcl_command_reply_init(&verify, "zcl.test.commons.v1");
        zcl_native_handle_zcode_commons_status(&request, &status);
        zcl_native_handle_zcode_commons_rebuild(&request, &rebuild);
        zcl_native_handle_zcode_commons_verify(&request, &verify);
        ASSERT(status.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(rebuild.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(verify.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(access(workspace, F_OK) != 0);
        ASSERT(strcmp(json_get_str(json_get(&status.data,
                                           "verification_status")),
                      "unknown") == 0);
        ASSERT(!json_get_bool(json_get(&rebuild.data, "persisted")));
        zcl_command_reply_free(&verify);
        zcl_command_reply_free(&rebuild);
        zcl_command_reply_free(&status);
        json_free(&input);

        char missing_score_root[65];
        memset(missing_score_root, '2', sizeof(missing_score_root) - 1u);
        missing_score_root[sizeof(missing_score_root) - 1u] = '\0';
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "score_receipt_root",
                                missing_score_root));
        request.input = &input;
        zcl_command_reply_init(&status, "zcl.test.commons_shadow.v1");
        zcl_native_handle_zcode_commons_shadow_plan(&request, &status);
        ASSERT(status.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT(access(workspace, F_OK) != 0);
        zcl_command_reply_free(&status);
        json_free(&input);

        char policy_hex[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES * 2u + 1u];
        char zero_root[65];
        memset(policy_hex, '0', sizeof(policy_hex) - 1u);
        policy_hex[sizeof(policy_hex) - 1u] = '\0';
        memset(zero_root, '0', sizeof(zero_root) - 1u);
        zero_root[sizeof(zero_root) - 1u] = '\0';
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "policy_hex", policy_hex));
        ASSERT(json_push_kv_str(&input, "expected_network_genesis_root",
                                zero_root));
        ASSERT(json_push_kv_int(&input, "now_unix", 1));
        request.input = &input;
        zcl_command_reply_init(&status, "zcl.test.continuity.v1");
        zcl_native_handle_zcode_continuity_plan(&request, &status);
        ASSERT(status.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT(access(workspace, F_OK) != 0);
        zcl_command_reply_free(&status);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "root", zero_root));
        ASSERT(json_push_kv_str(&input, "expected_network_genesis_root",
                                zero_root));
        ASSERT(json_push_kv_int(&input, "now_unix", 1));
        request.input = &input;
        zcl_command_reply_init(&status, "zcl.test.continuity.v1");
        zcl_native_handle_zcode_continuity_status(&request, &status);
        ASSERT(status.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT(access(workspace, F_OK) != 0);
        zcl_command_reply_free(&status);
        json_free(&input);

        char nonzero_root[65];
        memset(nonzero_root, '1', sizeof(nonzero_root) - 1u);
        nonzero_root[sizeof(nonzero_root) - 1u] = '\0';
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "expected_network_genesis_root",
                                nonzero_root));
        ASSERT(json_push_kv_int(&input, "now_unix", 1));
        request.input = &input;
        zcl_command_reply_init(&status, "zcl.test.patronage_list.v1");
        zcl_native_handle_zcode_patronage_list(&request, &status);
        ASSERT(status.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_int(json_get(&status.data, "count")) == 0);
        ASSERT(!json_get_bool(json_get(&status.data, "persisted")));
        ASSERT(access(workspace, F_OK) != 0);
        zcl_command_reply_free(&status);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_mission_api_test(void)
{
    int failures = 0;
    TEST("ZCODE guide has one root-free reuse-first front door") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.zcode_guide.v1");
        zcl_native_handle_zcode_guide(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "mission")),
            "Tell Z23 what you want C23 software on this device to "
            "do.") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "next_action")),
                      "Describe the behavior you want.") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "start_command")),
                      "z23 zcode work start . \"<desired behavior>\"") == 0);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "journey")),
                      "reuse C23 -> create only missing code") != NULL);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "continue_rule")),
                      "Follow the next_safe_command returned by each work "
                      "step.") == 0);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "proof_view")),
                      "details=true") != NULL);
        ASSERT(json_get(&reply.data, "find_work") == NULL);
        ASSERT(json_get(&reply.data, "create_work") == NULL);
        ASSERT(json_get(&reply.data, "improve_work") == NULL);
        ASSERT(json_get(&reply.data, "token_required") == NULL);
        ASSERT(json_get(&reply.data, "task_root") == NULL);
        ASSERT(json_get(&reply.data, "package_root") == NULL);
        ASSERT(json_get(&reply.data, "receipt_root") == NULL);
        zcl_command_reply_free(&reply); json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int commons_workspace_safety_test(void)
{
    int failures = 0;
    TEST("ZCODE commons rejects implicit, root, traversal and live workspaces") {
        static const char *const unsafe[] = {
            "", ".", "./", "..", "/", "./../test-tmp/escape",
            "./test-tmp/scratch/../escape", "~/.zcla" "ssic-c23",
            ".zcla" "ssic-c23", "/var/lib/.zcla" "ssic-c23",
            ".\\test-tmp\\scratch\\..\\escape",
            "C:\\canonical\\scratch\\..\\escape",
            ".\\test-tmp\\scratch\\"
        };
        for (size_t i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
            ASSERT(!zcl_native_zcode_workspace_is_explicit_scratch(unsafe[i]));
            struct json_value input;
            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "workspace", unsafe[i]));
            struct zcl_command_request request = {.input = &input};
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.test.commons_workspace.v1");
            zcl_native_handle_zcode_commons_status(&request, &reply);
            ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
            zcl_command_reply_free(&reply); json_free(&input);
        }
        ASSERT(zcl_native_zcode_workspace_is_explicit_scratch(
            "./test-tmp/zcode-explicit-scratch"));
        ASSERT(zcl_native_zcode_workspace_is_explicit_scratch(
            "/tmp/zclassic23-zcode-scratch"));
#if defined(_WIN32)
        ASSERT(zcl_native_zcode_workspace_is_explicit_scratch(
            "C:\\test-tmp\\zcode-explicit-scratch"));
#endif
        PASS();
    } _test_next:;
    return failures;
}

static int patronage_intent_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage: signed offers are simulation-only and non-authoritative") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 42, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_patronage_intent_v1 intent;
        memset(&intent, 0, sizeof(intent));
        intent.schema_version = VCS_ZCODE_PATRONAGE_INTENT_VERSION;
        intent.mode = VCS_ZCODE_PATRONAGE_EXACT_TASK_COMMISSION;
        intent.target_kind = VCS_ZCODE_PATRONAGE_TARGET_TASK;
        intent.settlement_trust_mode = VCS_ZCODE_PATRONAGE_UNFUNDED_OFFER;
        intent.flags = VCS_ZCODE_PATRONAGE_NO_AUTHORITY |
                       VCS_ZCODE_PATRONAGE_SIMULATION_ONLY;
        creation_fill_root(intent.network_genesis_root, 31);
        creation_fill_root(intent.zc23_token_or_simulation_root, 32);
        creation_fill_root(intent.patron_contributor_binding_root, 33);
        memcpy(intent.patron_zid_pubkey, pubkey, 32);
        creation_fill_root(intent.target_root, 34);
        memcpy(intent.task_root, intent.target_root, 32);
        creation_fill_root(intent.proof_policy_root, 35);
        creation_fill_root(intent.intended_recipient_binding_root, 36);
        intent.amount_atoms = 100000000;
        intent.created_unix = 1000;
        intent.expires_unix = 2000;
        intent.refund_height = 3000;
        intent.refund_unix = 2100;
        intent.sequence = 1;
        intent.maximum_zcl_fee_zat = 10000;
        ASSERT(vcs_zcode_patronage_intent_seal(&intent, secret, pubkey) ==
               VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_zcode_patronage_intent_verify(&intent, 1500) ==
               VCS_ZCODE_PATRONAGE_OK);
        uint8_t wire[VCS_ZCODE_PATRONAGE_INTENT_WIRE_BYTES];
        struct vcs_zcode_patronage_intent_v1 parsed, zero;
        memset(&zero, 0, sizeof(zero));
        ASSERT(vcs_zcode_patronage_intent_serialize(&intent, wire) ==
               VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_zcode_patronage_intent_parse(wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_zcode_patronage_intent_verify(&parsed, 1500) ==
               VCS_ZCODE_PATRONAGE_OK);
        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT(vcs_zcode_patronage_intent_parse(
                       wire, cut, &parsed) ==
                   VCS_ZCODE_PATRONAGE_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        wire[sizeof(wire) - 1] ^= 1;
        ASSERT(vcs_zcode_patronage_intent_parse(wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_PATRONAGE_OK);
        ASSERT(vcs_zcode_patronage_intent_verify(&parsed, 1500) ==
               VCS_ZCODE_PATRONAGE_SIGNATURE);
        ASSERT(vcs_zcode_patronage_intent_parse(wire, sizeof(wire) - 1,
                                                &parsed) ==
               VCS_ZCODE_PATRONAGE_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        intent.flags &= (uint8_t)~VCS_ZCODE_PATRONAGE_NO_AUTHORITY;
        ASSERT(vcs_zcode_patronage_intent_validate(&intent) ==
               VCS_ZCODE_PATRONAGE_FLAGS);
        PASS();
    } _test_next:;
    return failures;
}

static int patronage_settlement_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 patronage settlement: simulation wire cannot imply live funds") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 51, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_patronage_settlement_v1 settlement;
        memset(&settlement, 0, sizeof(settlement));
        settlement.schema_version = VCS_ZCODE_PATRONAGE_SETTLEMENT_VERSION;
        settlement.action = VCS_ZCODE_PATRONAGE_SIMULATED_SETTLED;
        settlement.flags = VCS_ZCODE_PATRONAGE_SETTLEMENT_SIMULATION_ONLY |
            VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS |
            VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_TRANSACTION_BYTES;
        uint8_t *roots[] = {
            settlement.network_genesis_root,
            settlement.patronage_intent_root,
            settlement.patronage_funding_root,
            settlement.creation_attribution_root, settlement.task_root,
            settlement.candidate_root, settlement.proof_policy_root,
            settlement.proof_set_root, settlement.proven_lane_root,
            settlement.score_receipt_root,
            settlement.recipient_contributor_binding_root,
        };
        for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
            creation_fill_root(roots[i], (uint8_t)(60 + i));
        memcpy(settlement.settler_zid_pubkey, pubkey, 32);
        settlement.amount_atoms = 200000000;
        settlement.created_unix = 2000;
        settlement.observed_height = 9000;
        settlement.observed_mtp = 3000;
        settlement.sequence = 1;
        ASSERT(vcs_zcode_patronage_settlement_seal(
                   &settlement, secret, pubkey) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT(vcs_zcode_patronage_settlement_verify(&settlement) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        ASSERT(vcs_zcode_patronage_settlement_verify_cas(
                   &settlement, NULL) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_CONTEXT);
        uint8_t wire[VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_BYTES];
        struct vcs_zcode_patronage_settlement_v1 parsed, zero;
        memset(&zero, 0, sizeof(zero));
        ASSERT(vcs_zcode_patronage_settlement_serialize(
                   &settlement, wire) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        const uint8_t prefix[] = {
            'Z','C','P','S','E','T','\r','\n', 1,0,1,7, 0,0,0,0,
            60,60,60,60,60,60,60,60,
        };
        ASSERT(memcmp(wire, prefix, sizeof(prefix)) == 0);
        ASSERT(vcs_zcode_patronage_settlement_parse(
                   wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_OK);
        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT(vcs_zcode_patronage_settlement_parse(
                       wire, cut, &parsed) ==
                   VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT(vcs_zcode_patronage_settlement_parse(
                   wire, sizeof(wire) - 1, &parsed) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        settlement.flags &= (uint8_t)
            ~VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS;
        ASSERT(vcs_zcode_patronage_settlement_validate(&settlement) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE);
        settlement.flags |= VCS_ZCODE_PATRONAGE_SETTLEMENT_NO_LIVE_FUNDS;
        settlement.signature[63] ^= 1;
        ASSERT(vcs_zcode_patronage_settlement_verify(&settlement) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_SIGNATURE);
        settlement.signature[63] ^= 1;
        settlement.action = VCS_ZCODE_PATRONAGE_SIMULATED_REFUNDED;
        ASSERT(vcs_zcode_patronage_settlement_validate(&settlement) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE);
        memset(settlement.creation_attribution_root, 0, 32);
        ASSERT(vcs_zcode_patronage_settlement_validate(&settlement) ==
               VCS_ZCODE_PATRONAGE_SETTLEMENT_SHAPE);
        PASS();
    } _test_next:;
    return failures;
}

static int continuity_policy_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 continuity policy: exact bounded simulation wire rejects churn-shaped policy") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 64, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_continuity_policy_v1 policy;
        memset(&policy, 0, sizeof(policy));
        policy.schema_version = VCS_ZCODE_CONTINUITY_POLICY_VERSION;
        policy.event_mask = VCS_ZCODE_CONTINUITY_BORN_RED_FIX |
            VCS_ZCODE_CONTINUITY_SECURITY_FIX |
            VCS_ZCODE_CONTINUITY_INDEPENDENT_REPRODUCTION |
            VCS_ZCODE_CONTINUITY_COMPATIBILITY |
            VCS_ZCODE_CONTINUITY_PRESERVATION;
        policy.flags = VCS_ZCODE_CONTINUITY_NO_AUTHORITY |
                       VCS_ZCODE_CONTINUITY_SIMULATION_ONLY;
        uint8_t *roots[] = {
            policy.network_genesis_root,
            policy.zc23_token_or_simulation_root,
            policy.patron_contributor_binding_root,
            policy.package_root, policy.current_release_root,
            policy.from_capsule_root, policy.to_capsule_root,
            policy.proof_policy_root,
        };
        for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
            creation_fill_root(roots[i], (uint8_t)(81 + i));
        memcpy(policy.patron_zid_pubkey, pubkey, 32);
        policy.maximum_cycles = 3;
        policy.per_cycle_cap_atoms = UINT64_C(100000000);
        policy.total_cap_atoms = UINT64_C(300000000);
        policy.created_unix = 1000;
        policy.expires_unix = 2000;
        policy.sequence = 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &policy, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&policy, 1500),
                  VCS_ZCODE_CONTINUITY_OK);

        uint8_t first[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES];
        uint8_t root_a[32], root_b[32];
        struct vcs_zcode_continuity_policy_v1 parsed, zero;
        memset(&zero, 0, sizeof(zero));
        ASSERT_EQ(vcs_zcode_continuity_policy_serialize(&policy, first),
                  VCS_ZCODE_CONTINUITY_OK);
        static const uint8_t prefix_kat[] = {
            'Z','C','C','O','N','T','\r','\n', 1,0, 31,0, 3,0,0,0,
            81,81,81,81,81,81,81,81,
        };
        ASSERT(memcmp(first, prefix_kat, sizeof(prefix_kat)) == 0);
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      first, sizeof(first), &parsed),
                  VCS_ZCODE_CONTINUITY_OK);
        for (size_t cut = 0; cut < sizeof(first); cut++) {
            ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                          first, cut, &parsed),
                      VCS_ZCODE_CONTINUITY_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      first, sizeof(first), &parsed),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_serialize(&parsed, second),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(first, second, sizeof(first)) == 0);
        ASSERT_EQ(vcs_zcode_continuity_policy_root(&policy, root_a),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_root(&parsed, root_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(root_a, root_b, sizeof(root_a)) == 0);
        static const uint8_t root_kat[32] = {
            0x4b, 0x24, 0x7c, 0xbe, 0x21, 0x6e, 0x2e, 0x2e,
            0xf3, 0xd7, 0x6c, 0x2e, 0xac, 0x4b, 0xb5, 0xd3,
            0xaa, 0x1e, 0x57, 0x9f, 0xd4, 0x02, 0x10, 0xe0,
            0xd9, 0x76, 0x82, 0x5d, 0x7c, 0x3d, 0x92, 0xcd,
        };
        ASSERT(memcmp(root_a, root_kat, sizeof(root_kat)) == 0);
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      first, sizeof(first) - 1, &parsed),
                  VCS_ZCODE_CONTINUITY_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        uint8_t malformed[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES + 1];
        memcpy(malformed, first, sizeof(first));
        malformed[sizeof(first)] = 0;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(malformed), &parsed),
                  VCS_ZCODE_CONTINUITY_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        malformed[0] ^= 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(first), &parsed),
                  VCS_ZCODE_CONTINUITY_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, first, sizeof(first));
        malformed[8] = 2;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(first), &parsed),
                  VCS_ZCODE_CONTINUITY_VERSION);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, first, sizeof(first));
        malformed[13] = 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(first), &parsed),
                  VCS_ZCODE_CONTINUITY_FLAGS);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, first, sizeof(first));
        malformed[sizeof(first) - 1] ^= 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(first), &parsed),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&parsed, 1500),
                  VCS_ZCODE_CONTINUITY_SIGNATURE);

        policy.event_mask |= UINT16_C(0x8000);
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_EVENT_MASK);
        policy.event_mask &= UINT16_C(0x7fff);
        memcpy(policy.to_capsule_root, policy.from_capsule_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_TRANSITION);
        creation_fill_root(policy.to_capsule_root, 87);
        policy.total_cap_atoms++;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_CAP);
        policy.total_cap_atoms--;
        policy.maximum_cycles = UINT32_MAX;
        policy.per_cycle_cap_atoms = UINT64_MAX;
        policy.total_cap_atoms = UINT64_MAX;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_CAP);
        policy.maximum_cycles = 3;
        policy.per_cycle_cap_atoms = UINT64_C(100000000);
        policy.total_cap_atoms = UINT64_C(300000000);
        policy.flags &= (uint8_t)~VCS_ZCODE_CONTINUITY_NO_AUTHORITY;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_FLAGS);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_creation_attribution(void)
{
    return creation_codec_test() + creation_rejection_test() +
           creation_arithmetic_test() + epoch_creation_codec_test() +
           epoch_creation_accounting_test() + commons_projection_test() +
           commons_projection_rebuild_test() +
           commons_command_noncreating_test() + commons_mission_api_test() +
           commons_workspace_safety_test() + patronage_intent_test() +
           patronage_settlement_codec_test() + continuity_policy_codec_test();
}
