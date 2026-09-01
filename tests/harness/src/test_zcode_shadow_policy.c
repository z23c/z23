/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: simulation-only ZC23 policy and approved-reproducer-set proofs. */
#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "json/json.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_score_receipt.h"
#include "vcs/zcode_reproduction_request.h"
#include "vcs/zcode_shadow_policy.h"

#include <string.h>

static void shadow_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void shadow_entry(struct vcs_zcode_approved_reproducer_entry_v1 *entry,
                         uint8_t signer)
{
    memset(entry, 0, sizeof(*entry));
    shadow_fill(entry->signer_pubkey, signer);
    shadow_fill(entry->contributor_binding_root, (uint8_t)(signer + 1u));
    shadow_fill(entry->operator_group_root, (uint8_t)(signer + 2u));
    vcs_zcode_score_action_root(VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION,
                                entry->action_root);
    entry->valid_from_epoch = 2;
    entry->valid_through_epoch = 8;
    entry->valid_from_unix = 1000;
    entry->valid_through_unix = 9000;
}

static bool shadow_set(struct vcs_zcode_approved_reproducer_set_v1 *set)
{
    struct vcs_zcode_approved_reproducer_entry_v1 high, low;
    vcs_zcode_approved_reproducer_set_init(set);
    shadow_fill(set->network_genesis_root, 11);
    set->sequence = 1;
    shadow_entry(&high, 40);
    shadow_entry(&low, 20);
    return vcs_zcode_approved_reproducer_set_add(set, &high) ==
               VCS_ZCODE_SHADOW_OK &&
           vcs_zcode_approved_reproducer_set_add(set, &low) ==
               VCS_ZCODE_SHADOW_OK;
}

static bool shadow_policy(struct vcs_zcode_policy_candidate_v1 *policy,
                          const struct vcs_zcode_approved_reproducer_set_v1 *set)
{
    uint8_t set_root[32], network[32], covenant[32];
    shadow_fill(network, 11);
    shadow_fill(covenant, 12);
    if (vcs_zcode_approved_reproducer_set_root(set, set_root) !=
        VCS_ZCODE_SHADOW_OK)
        return false;
    vcs_zcode_policy_candidate_init(policy, network, set_root, covenant);
    return true;
}

static int shadow_set_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 approved reproducer set: canonical order, exact wire and root") {
        struct vcs_zcode_approved_reproducer_set_v1 set, parsed, zero;
        uint8_t wire[VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES];
        uint8_t root_a[32], root_b[32];
        size_t wire_len = 0, second_len = 0;
        ASSERT(shadow_set(&set));
        ASSERT(set.entry_count == 2);
        ASSERT(set.entries[0].signer_pubkey[0] == 20);
        ASSERT(vcs_zcode_approved_reproducer_set_serialize(
                   &set, wire, sizeof(wire), &wire_len) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(wire_len == VCS_ZCODE_APPROVED_REPRODUCER_SET_HEADER_BYTES +
                           2u * VCS_ZCODE_APPROVED_REPRODUCER_ENTRY_BYTES);
        ASSERT(vcs_zcode_approved_reproducer_set_parse(
                   wire, wire_len, &parsed) == VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_approved_reproducer_set_serialize(
                   &parsed, second, sizeof(second), &second_len) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(second_len == wire_len && memcmp(wire, second, wire_len) == 0);
        ASSERT(vcs_zcode_approved_reproducer_set_root(&set, root_a) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_approved_reproducer_set_root(&parsed, root_b) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        static const uint8_t root_kat[32] = {
            0x37, 0xf5, 0x3a, 0x1b, 0xa3, 0x1d, 0x9f, 0xd5,
            0x97, 0xfb, 0x57, 0x6d, 0xa9, 0x41, 0x57, 0x3f,
            0x11, 0x9f, 0x5c, 0x2c, 0x53, 0xb7, 0x12, 0xa5,
            0xae, 0xa3, 0x65, 0xc6, 0xba, 0x33, 0x3c, 0xf1,
        };
        ASSERT(memcmp(root_a, root_kat, sizeof(root_kat)) == 0);

        memset(&zero, 0, sizeof(zero));
        for (size_t cut = 0; cut < wire_len; cut++) {
            ASSERT(vcs_zcode_approved_reproducer_set_parse(
                       wire, cut, &parsed) != VCS_ZCODE_SHADOW_OK);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        wire[wire_len] = 0;
        ASSERT(vcs_zcode_approved_reproducer_set_parse(
                   wire, wire_len + 1u, &parsed) != VCS_ZCODE_SHADOW_OK);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT(vcs_zcode_approved_reproducer_set_serialize(
                   &set, wire, sizeof(wire), &wire_len) ==
               VCS_ZCODE_SHADOW_OK);
        wire[0] ^= 1u;
        ASSERT(vcs_zcode_approved_reproducer_set_parse(
                   wire, wire_len, &parsed) == VCS_ZCODE_SHADOW_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT(vcs_zcode_approved_reproducer_set_serialize(
                   &set, wire, sizeof(wire), &wire_len) ==
               VCS_ZCODE_SHADOW_OK);
        wire[8] = 2;
        ASSERT(vcs_zcode_approved_reproducer_set_parse(
                   wire, wire_len, &parsed) == VCS_ZCODE_SHADOW_VERSION);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT(vcs_zcode_approved_reproducer_set_serialize(
                   &set, wire, sizeof(wire), &wire_len) ==
               VCS_ZCODE_SHADOW_OK);
        wire[12] = 1;
        ASSERT(vcs_zcode_approved_reproducer_set_parse(
                   wire, wire_len, &parsed) == VCS_ZCODE_SHADOW_RESERVED);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int shadow_set_rejection_test(void)
{
    int failures = 0;
    TEST("ZC23 approved reproducer set: duplicates, stale grants and actions fail closed") {
        struct vcs_zcode_approved_reproducer_set_v1 set, other;
        struct vcs_zcode_approved_reproducer_entry_v1 entry, found;
        ASSERT(shadow_set(&set));
        entry = set.entries[0];
        shadow_fill(entry.operator_group_root, 99);
        ASSERT(vcs_zcode_approved_reproducer_set_add(&set, &entry) ==
               VCS_ZCODE_SHADOW_DUPLICATE);
        shadow_entry(&entry, 60);
        memset(entry.action_root, 0, 32);
        ASSERT(vcs_zcode_approved_reproducer_set_add(&set, &entry) ==
               VCS_ZCODE_SHADOW_ACTION);
        shadow_entry(&entry, 60);
        entry.valid_from_epoch = entry.valid_through_epoch + 1u;
        ASSERT(vcs_zcode_approved_reproducer_set_add(&set, &entry) ==
               VCS_ZCODE_SHADOW_TIME);

        ASSERT(vcs_zcode_approved_reproducer_set_find(
                   &set, set.entries[0].signer_pubkey,
                   set.entries[0].action_root, 4, 4000, &found) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_approved_reproducer_set_find(
                   &set, set.entries[0].signer_pubkey,
                   set.entries[0].action_root, 9, 4000, &found) ==
               VCS_ZCODE_SHADOW_EPOCH);
        ASSERT(vcs_zcode_approved_reproducer_set_find(
                   &set, set.entries[0].signer_pubkey,
                   set.entries[0].action_root, 4, 999, &found) ==
               VCS_ZCODE_SHADOW_TIME);
        uint8_t wrong_action[32]; shadow_fill(wrong_action, 77);
        ASSERT(vcs_zcode_approved_reproducer_set_find(
                   &set, set.entries[0].signer_pubkey, wrong_action,
                   4, 4000, &found) == VCS_ZCODE_SHADOW_ACTION);

        other = set;
        other.flags &= (uint16_t)~VCS_ZCODE_SHADOW_NOT_OWNER_APPROVED;
        ASSERT(vcs_zcode_approved_reproducer_set_validate(&other) ==
               VCS_ZCODE_SHADOW_FLAGS);
        ASSERT(!vcs_zcode_score_offhost_reproducer_approved(
            set.entries[0].signer_pubkey));
        PASS();
    } _test_next:;
    return failures;
}

static int shadow_policy_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 policy candidate: fixed simulation covenant and award table") {
        struct vcs_zcode_approved_reproducer_set_v1 set, wrong_set;
        struct vcs_zcode_policy_candidate_v1 policy, parsed, zero, changed;
        uint8_t wire[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES];
        uint8_t wire2[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES];
        uint8_t root_a[32], root_b[32];
        uint64_t award = UINT64_MAX;
        ASSERT(shadow_set(&set));
        memset(&policy, 0, sizeof(policy));
        ASSERT(shadow_policy(&policy, &set));
        ASSERT(vcs_zcode_policy_candidate_validate(&policy) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_policy_candidate_validate_set(&policy, &set) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_policy_candidate_serialize(&policy, wire) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_policy_candidate_parse(wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_policy_candidate_serialize(&parsed, wire2) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(memcmp(wire, wire2, sizeof(wire)) == 0);
        ASSERT(vcs_zcode_policy_candidate_root(&policy, root_a) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_policy_candidate_root(&parsed, root_b) ==
               VCS_ZCODE_SHADOW_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        static const uint8_t root_kat[32] = {
            0xe6, 0x0c, 0xca, 0xb1, 0x2c, 0x6e, 0xbe, 0x6f,
            0xc5, 0x90, 0x8e, 0x39, 0x7b, 0x09, 0xb1, 0x84,
            0x7f, 0x44, 0x08, 0x84, 0x77, 0x78, 0xf3, 0xf4,
            0x22, 0xaf, 0x5e, 0x77, 0x76, 0xce, 0xdf, 0x77,
        };
        ASSERT(memcmp(root_a, root_kat, sizeof(root_kat)) == 0);
        ASSERT(vcs_zcode_policy_candidate_award_atoms(
                   &policy, VCS_ZCODE_CREATION_PUBLIC_SOURCE, &award) ==
               VCS_ZCODE_SHADOW_OK &&
               award == VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS);
        ASSERT(vcs_zcode_policy_candidate_award_atoms(
                   &policy, VCS_ZCODE_CREATION_SECURITY_FIX, &award) ==
               VCS_ZCODE_SHADOW_OK &&
               award == VCS_ZC23_SHADOW_BORN_RED_ATOMS);

        changed = policy;
        changed.flags &= (uint16_t)~VCS_ZCODE_SHADOW_SIMULATION_ONLY;
        ASSERT(vcs_zcode_policy_candidate_validate(&changed) ==
               VCS_ZCODE_SHADOW_FLAGS);
        changed = policy;
        changed.award_atoms[VCS_ZCODE_CREATION_PUBLIC_SOURCE - 1u]++;
        ASSERT(vcs_zcode_policy_candidate_validate(&changed) ==
               VCS_ZCODE_SHADOW_AMOUNT);
        wrong_set = set;
        shadow_fill(wrong_set.network_genesis_root, 91);
        ASSERT(vcs_zcode_policy_candidate_validate_set(&policy, &wrong_set) ==
               VCS_ZCODE_SHADOW_NETWORK);
        wrong_set = set;
        wrong_set.entries[0].operator_group_root[0] ^= 1u;
        ASSERT(vcs_zcode_policy_candidate_validate_set(&policy, &wrong_set) ==
               VCS_ZCODE_SHADOW_POLICY);

        memset(&zero, 0, sizeof(zero));
        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT(vcs_zcode_policy_candidate_parse(wire, cut, &parsed) !=
                   VCS_ZCODE_SHADOW_OK);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT(vcs_zcode_policy_candidate_parse(wire, sizeof(wire) - 1u,
                                                &parsed) !=
               VCS_ZCODE_SHADOW_OK);
        ASSERT(vcs_zcode_policy_candidate_serialize(&policy, wire) ==
               VCS_ZCODE_SHADOW_OK);
        wire[0] ^= 1u;
        ASSERT(vcs_zcode_policy_candidate_parse(wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_SHADOW_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT(vcs_zcode_policy_candidate_serialize(&policy, wire) ==
               VCS_ZCODE_SHADOW_OK);
        wire[8] = 2;
        ASSERT(vcs_zcode_policy_candidate_parse(wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_SHADOW_VERSION);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        ASSERT(vcs_zcode_policy_candidate_serialize(&policy, wire) ==
               VCS_ZCODE_SHADOW_OK);
        wire[224] = 1;
        ASSERT(vcs_zcode_policy_candidate_parse(wire, sizeof(wire), &parsed) ==
               VCS_ZCODE_SHADOW_RESERVED);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static void reproduction_request_fixture(
    struct vcs_zcode_reproduction_request_v1 *request)
{
    vcs_zcode_reproduction_request_init(request);
    uint8_t value = 1;
    shadow_fill(request->network_genesis_root, value++);
    shadow_fill(request->zc23_policy_root, value++);
    shadow_fill(request->task_root, value++);
    shadow_fill(request->candidate_root, value++);
    shadow_fill(request->package_root, value++);
    shadow_fill(request->release_root, value++);
    shadow_fill(request->recipe_root, value++);
    shadow_fill(request->dependency_lock_root, value++);
    shadow_fill(request->toolchain_capsule_root, value++);
    shadow_fill(request->reference_build_root, value++);
    shadow_fill(request->output_manifest_root, value++);
    vcs_zcode_score_action_root(VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION,
                                request->action_root);
    shadow_fill(request->challenge_nonce, value++);
    shadow_fill(request->requester_contributor_binding_root, value++);
    request->created_unix = 1000;
    request->expires_unix = 4600;
    request->max_cpu_seconds = 600;
    request->max_processes = 8;
    request->max_memory_bytes = UINT64_C(1073741824);
    request->max_output_bytes = UINT64_C(67108864);
}

static int reproduction_request_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 reproduction request: portable exact wire fails closed") {
        struct vcs_zcode_reproduction_request_v1 request, parsed, zero;
        uint8_t wire[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES];
        uint8_t root_a[32], root_b[32];
        reproduction_request_fixture(&request);
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(vcs_zcode_reproduction_request_serialize(&request, wire) ==
               VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(vcs_zcode_reproduction_request_parse(wire, sizeof(wire),
                                                    &parsed) ==
               VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(vcs_zcode_reproduction_request_serialize(&parsed, second) ==
               VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(memcmp(wire, second, sizeof(wire)) == 0);
        ASSERT(vcs_zcode_reproduction_request_root(&request, root_a) ==
               VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(vcs_zcode_reproduction_request_root(&parsed, root_b) ==
               VCS_ZCODE_REPRODUCTION_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        static const uint8_t root_kat[32] = {
            0x84, 0x8a, 0xf5, 0xd5, 0xf2, 0x9c, 0x50, 0x59,
            0x18, 0x40, 0x3a, 0x2d, 0xaf, 0x61, 0xfa, 0x86,
            0x4b, 0xbe, 0x36, 0x78, 0x7b, 0x39, 0x48, 0xd0,
            0xbb, 0xa7, 0xe5, 0xbe, 0x05, 0x92, 0xea, 0xbb,
        };
        ASSERT(memcmp(root_a, root_kat, sizeof(root_kat)) == 0);

        memset(&zero, 0, sizeof(zero));
        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT(vcs_zcode_reproduction_request_parse(wire, cut, &parsed) !=
                   VCS_ZCODE_REPRODUCTION_OK);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        uint8_t malformed[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES + 1u];
        memcpy(malformed, wire, sizeof(wire)); malformed[sizeof(wire)] = 0;
        ASSERT(vcs_zcode_reproduction_request_parse(
                   malformed, sizeof(malformed), &parsed) ==
               VCS_ZCODE_REPRODUCTION_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire)); malformed[0] ^= 1u;
        ASSERT(vcs_zcode_reproduction_request_parse(
                   malformed, sizeof(wire), &parsed) ==
               VCS_ZCODE_REPRODUCTION_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire)); malformed[13] = 1u;
        ASSERT(vcs_zcode_reproduction_request_parse(
                   malformed, sizeof(wire), &parsed) ==
               VCS_ZCODE_REPRODUCTION_RESERVED);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        request.flags &= (uint16_t)~VCS_ZCODE_REPRODUCTION_SIMULATION_ONLY;
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_FLAGS);
        reproduction_request_fixture(&request);
        memset(request.challenge_nonce, 0, 32);
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_ROOT);
        reproduction_request_fixture(&request);
        request.action_root[0] ^= 1u;
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_ACTION);
        reproduction_request_fixture(&request);
        request.confinement = 1;
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_CONFINEMENT);
        reproduction_request_fixture(&request);
        request.max_memory_bytes = UINT64_MAX;
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_BUDGET);
        reproduction_request_fixture(&request);
        request.expires_unix = request.created_unix;
        ASSERT(vcs_zcode_reproduction_request_validate(&request) ==
               VCS_ZCODE_REPRODUCTION_TIME);
        PASS();
    } _test_next:;
    return failures;
}

static int reproduction_request_command_test(void)
{
    int failures = 0;
    TEST("ZC23 reproduction challenge: plan is noncreating and commit is idempotent") {
        struct vcs_zcode_reproduction_request_v1 request;
        uint8_t wire[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES];
        char hex[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES * 2u + 1u];
        char workspace[256];
        reproduction_request_fixture(&request);
        ASSERT(vcs_zcode_reproduction_request_serialize(&request, wire) ==
               VCS_ZCODE_REPRODUCTION_OK);
        zcl_hex_encode(wire, sizeof(wire), hex);
        test_fmt_tmpdir(workspace, sizeof(workspace), "zcode_reproduction",
                        "scratch");
        test_rm_rf(workspace);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", workspace));
        ASSERT(json_push_kv_str(&input, "request_hex", hex));
        ASSERT(json_push_kv_int(&input, "now_unix", 1200));
        struct zcl_command_request command = {.input = &input};
        struct zcl_command_reply plan, commit, repeated;
        zcl_command_reply_init(&plan, "zcl.test.reproduction.v1");
        zcl_native_handle_zcode_reproduction_challenge_plan(&command, &plan);
        ASSERT(plan.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&plan.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&plan.data, "token_exists")));
        ASSERT(access(workspace, F_OK) != 0);

        zcl_command_reply_init(&commit, "zcl.test.reproduction.v1");
        zcl_native_handle_zcode_reproduction_challenge_commit(
            &command, &commit);
        ASSERT(commit.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&commit.data, "persisted")));
        ASSERT(!json_get_bool(json_get(&commit.data, "funds_moved")));
        ASSERT(!json_get_bool(json_get(&commit.data, "custody_used")));
        ASSERT(access(workspace, F_OK) == 0);
        zcl_command_reply_init(&repeated, "zcl.test.reproduction.v1");
        zcl_native_handle_zcode_reproduction_challenge_commit(
            &command, &repeated);
        ASSERT(repeated.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&commit.data,
                                            "reproduction_request_root")),
                      json_get_str(json_get(&repeated.data,
                                            "reproduction_request_root"))) == 0);

        zcl_command_reply_free(&repeated);
        zcl_command_reply_free(&commit);
        zcl_command_reply_free(&plan);
        json_free(&input);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_shadow_policy(void)
{
    int failures = 0;
    failures += shadow_set_codec_test();
    failures += shadow_set_rejection_test();
    failures += shadow_policy_codec_test();
    failures += reproduction_request_codec_test();
    failures += reproduction_request_command_test();
    return failures;
}
