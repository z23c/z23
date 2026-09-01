/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the ZC23 continuity policy codec and the unique
 * continuity-event key derivation fail closed on every non-canonical input. */
#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_continuity_policy.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_score_receipt.h"

#include <string.h>

static void continuity_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void continuity_policy_fixture(
    struct vcs_zcode_continuity_policy_v1 *policy,
    const uint8_t patron_pubkey[32])
{
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = VCS_ZCODE_CONTINUITY_POLICY_VERSION;
    policy->event_mask = VCS_ZCODE_CONTINUITY_ALLOWED_EVENT_MASK;
    policy->flags = VCS_ZCODE_CONTINUITY_NO_AUTHORITY |
                    VCS_ZCODE_CONTINUITY_SIMULATION_ONLY;
    continuity_fill(policy->network_genesis_root, 91);
    continuity_fill(policy->zc23_token_or_simulation_root, 92);
    continuity_fill(policy->patron_contributor_binding_root, 93);
    memcpy(policy->patron_zid_pubkey, patron_pubkey, 32);
    continuity_fill(policy->package_root, 95);
    continuity_fill(policy->current_release_root, 96);
    continuity_fill(policy->from_capsule_root, 97);
    continuity_fill(policy->to_capsule_root, 98);
    continuity_fill(policy->proof_policy_root, 99);
    policy->maximum_cycles = 3;
    policy->per_cycle_cap_atoms = UINT64_C(100000000);
    policy->total_cap_atoms = UINT64_C(300000000);
    policy->created_unix = 1000;
    policy->expires_unix = 700000;
    policy->sequence = 1;
}

/* Attribution bound to the policy: challenge timing is exact, lineage is the
 * policy root, and package/release/proof-policy roots mirror the policy. */
static void continuity_attribution_fixture(
    struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_continuity_policy_v1 *policy,
    const uint8_t policy_root[32], uint16_t category)
{
    memset(a, 0, sizeof(*a));
    a->schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    a->category = category;
    a->lineage_kind = VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY;
    a->epoch = 7;
    a->award_atoms = UINT64_C(100000000);
    a->challenge_opening_height = 100;
    continuity_fill(a->challenge_opening_hash, 1);
    a->challenge_opening_mtp = 1000;
    a->challenge_maturity_height = 8164;
    a->challenge_maturity_mtp = 605800;
    a->created_unix = 605801;
    memcpy(a->network_genesis_root, policy->network_genesis_root, 32);
    memcpy(a->zc23_policy_root, policy->zc23_token_or_simulation_root, 32);
    continuity_fill(a->contributor_binding_root, 4);
    continuity_fill(a->task_root, 5);
    continuity_fill(a->candidate_root, 6);
    memcpy(a->proof_policy_root, policy->proof_policy_root, 32);
    continuity_fill(a->proof_set_root, 8);
    continuity_fill(a->proven_lane_root, 9);
    continuity_fill(a->score_receipt_root, 10);
    memcpy(a->package_root, policy->package_root, 32);
    memcpy(a->release_root, policy->current_release_root, 32);
    continuity_fill(a->license_evidence_root, 13);
    memcpy(a->lineage_root, policy_root, 32);
}

static bool continuity_score_fixture(
    struct vcs_zcode_score_receipt_v1 *score,
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    enum vcs_zcode_score_unit unit, uint8_t evidence_fill)
{
    memset(score, 0, sizeof(*score));
    score->schema_version = VCS_ZCODE_SCORE_VERSION;
    score->awarded_mask = (uint8_t)(UINT8_C(1) << unit);
    score->score = 1;
    memcpy(score->task_root, attribution->task_root, 32);
    memcpy(score->candidate_root, attribution->candidate_root, 32);
    memcpy(score->proof_policy_root, attribution->proof_policy_root, 32);
    memcpy(score->proof_set_root, attribution->proof_set_root, 32);
    memcpy(score->proven_lane_root, attribution->proven_lane_root, 32);
    memcpy(score->package_root, attribution->package_root, 32);
    memcpy(score->release_root, attribution->release_root, 32);
    continuity_fill(score->recipe_root, 51);
    continuity_fill(score->dependency_lock_root, 52);
    continuity_fill(score->api_capsule_root, 53);
    continuity_fill(score->evidence_roots[unit], evidence_fill);
    uint8_t seed[32], secret[32], pubkey[32];
    memset(seed, 0x61, sizeof(seed));
    zcl_ed25519_keypair(pubkey, secret, seed);
    memcpy(score->lane_signer, pubkey, 32);
    return vcs_zcode_score_receipt_seal(score, secret, pubkey) ==
           VCS_ZCODE_SCORE_OK;
}

static int continuity_policy_codec_test(void)
{
    int failures = 0;
    TEST("ZC23 continuity policy: canonical wire round-trip and rejection") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 64, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_continuity_policy_v1 policy, parsed, zero;
        memset(&zero, 0, sizeof(zero));
        continuity_policy_fixture(&policy, pubkey);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(&policy, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&policy, 999),
                  VCS_ZCODE_CONTINUITY_TIME);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&policy, 1000),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&policy, 699999),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&policy, 700000),
                  VCS_ZCODE_CONTINUITY_TIME);

        uint8_t wire[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES];
        uint8_t second[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_continuity_policy_serialize(&policy, wire),
                  VCS_ZCODE_CONTINUITY_OK);
        static const uint8_t prefix_kat[24] = {
            'Z','C','C','O','N','T','\r','\n',
            0x01, 0x00, 0x1f, 0x00, 0x03, 0x00, 0x00, 0x00,
            91, 91, 91, 91, 91, 91, 91, 91,
        };
        ASSERT(memcmp(wire, prefix_kat, sizeof(prefix_kat)) == 0);
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(wire, sizeof(wire),
                                                    &parsed),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_serialize(&parsed, second),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(wire, second, sizeof(wire)) == 0);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_continuity_policy_root(&policy, root_a),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_root(&parsed, root_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);

        for (size_t cut = 0; cut < sizeof(wire); cut++) {
            ASSERT_EQ(vcs_zcode_continuity_policy_parse(wire, cut, &parsed),
                      VCS_ZCODE_CONTINUITY_WIRE_SIZE);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        uint8_t malformed[VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES + 1];
        memcpy(malformed, wire, sizeof(wire));
        malformed[sizeof(wire)] = 0;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(malformed), &parsed),
                  VCS_ZCODE_CONTINUITY_WIRE_SIZE);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        malformed[0] ^= 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_CONTINUITY_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[8] = 2; /* unknown schema version */
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_CONTINUITY_VERSION);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[13] = 1; /* reserved byte must stay zero */
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_CONTINUITY_FLAGS);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        memcpy(malformed, wire, sizeof(wire));
        malformed[sizeof(wire) - 1] ^= 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_parse(
                      malformed, sizeof(wire), &parsed),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_verify(&parsed, 1500),
                  VCS_ZCODE_CONTINUITY_SIGNATURE);

        /* Field validation: closed event mask, simulation flags, roots,
         * transition, caps, time order, and sequence all fail closed. */
        continuity_policy_fixture(&policy, pubkey);
        policy.event_mask = 0;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_EVENT_MASK);
        continuity_policy_fixture(&policy, pubkey);
        policy.event_mask |= UINT16_C(0x8000);
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_EVENT_MASK);
        continuity_policy_fixture(&policy, pubkey);
        policy.flags &= (uint8_t)~VCS_ZCODE_CONTINUITY_NO_AUTHORITY;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_FLAGS);
        continuity_policy_fixture(&policy, pubkey);
        memset(policy.package_root, 0, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_ROOT);
        continuity_policy_fixture(&policy, pubkey);
        memcpy(policy.to_capsule_root, policy.from_capsule_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_TRANSITION);
        continuity_policy_fixture(&policy, pubkey);
        policy.total_cap_atoms = policy.per_cycle_cap_atoms - 1;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_CAP);
        continuity_policy_fixture(&policy, pubkey);
        policy.maximum_cycles = 0;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_CAP);
        continuity_policy_fixture(&policy, pubkey);
        policy.expires_unix = policy.created_unix;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_TIME);
        continuity_policy_fixture(&policy, pubkey);
        policy.sequence = 0;
        ASSERT_EQ(vcs_zcode_continuity_policy_validate(&policy),
                  VCS_ZCODE_CONTINUITY_SEQUENCE);
        PASS();
    } _test_next:;
    return failures;
}

static int continuity_verify_cas_test(void)
{
    int failures = 0;
    TEST("ZC23 continuity policy: CAS authority fails closed without evidence") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 64, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_continuity_policy_v1 policy;
        continuity_policy_fixture(&policy, pubkey);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(&policy, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);

        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_continuity", "empty");
        ASSERT(vcs_object_store_init(workspace));
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(&policy, NULL),
                  VCS_ZCODE_CONTINUITY_TIME);
        struct vcs_zcode_patronage_validation_context context = {
            .workspace = NULL,
            .expected_network_genesis_root = policy.network_genesis_root,
            .now_unix = 1500,
        };
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(&policy, &context),
                  VCS_ZCODE_CONTINUITY_CONTEXT);
        uint8_t other_network[32];
        continuity_fill(other_network, 0xc2);
        context.workspace = workspace;
        context.expected_network_genesis_root = other_network;
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(&policy, &context),
                  VCS_ZCODE_CONTINUITY_NETWORK);
        context.expected_network_genesis_root = policy.network_genesis_root;
        ASSERT_EQ(vcs_zcode_continuity_policy_verify_cas(&policy, &context),
                  VCS_ZCODE_CONTINUITY_CONTRIBUTOR);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int continuity_event_key_test(void)
{
    int failures = 0;
    TEST("ZC23 continuity event: unique key derivation fails closed") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 64, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_continuity_policy_v1 policy;
        continuity_policy_fixture(&policy, pubkey);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(&policy, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        uint8_t policy_root[32];
        ASSERT_EQ(vcs_zcode_continuity_policy_root(&policy, policy_root),
                  VCS_ZCODE_CONTINUITY_OK);

        struct vcs_zcode_creation_attribution_v1 attribution;
        continuity_attribution_fixture(&attribution, &policy, policy_root,
                                       VCS_ZCODE_CREATION_SECURITY_FIX);
        ASSERT_EQ(vcs_zcode_creation_attribution_validate(&attribution),
                  VCS_ZCODE_CREATION_OK);
        struct vcs_zcode_task_v1 task;
        memset(&task, 0, sizeof(task));
        memcpy(task.proof_policy_root, policy.proof_policy_root, 32);
        memcpy(task.toolchain_capsule_root, policy.to_capsule_root, 32);
        struct vcs_zcode_score_receipt_v1 score;
        ASSERT(continuity_score_fixture(
                   &score, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));

        uint8_t key_a[32], key_b[32];
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &score, key_a),
                  VCS_ZCODE_CONTINUITY_OK);
        uint8_t zero_root[32] = {0};
        ASSERT(memcmp(key_a, zero_root, 32) != 0);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) == 0);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      NULL, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_NULL);
        ASSERT(memcmp(key_b, zero_root, 32) == 0);

        /* Every authority mismatch has its own typed rejection. */
        struct vcs_zcode_creation_attribution_v1 mutated = attribution;
        mutated.category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
        mutated.lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
        memset(mutated.lineage_root, 0, 32);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &mutated, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_EVENT_MASK);
        mutated = attribution;
        continuity_fill(mutated.lineage_root, 77);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &mutated, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_ROOT);
        mutated = attribution;
        continuity_fill(mutated.package_root, 78);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &mutated, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_PACKAGE);
        mutated = attribution;
        mutated.award_atoms = UINT64_C(200000000); /* above per-cycle cap */
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &mutated, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_CAP);

        struct vcs_zcode_continuity_policy_v1 policy_mutated = policy;
        policy_mutated.expires_unix = 2000; /* expired at attribution time */
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy_mutated, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_SIGNATURE);
        /* The two defect-fix classes share the born-red mask bit: clearing
         * only the security bit leaves the class open; clearing the born-red
         * bit closes it. */
        policy_mutated = policy;
        policy_mutated.event_mask &=
            (uint16_t)~VCS_ZCODE_CONTINUITY_SECURITY_FIX;
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &policy_mutated, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        uint8_t mutated_root[32];
        ASSERT_EQ(vcs_zcode_continuity_policy_root(
                      &policy_mutated, mutated_root),
                  VCS_ZCODE_CONTINUITY_OK);
        mutated = attribution;
        memcpy(mutated.lineage_root, mutated_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &mutated, &policy_mutated, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        policy_mutated = policy;
        policy_mutated.event_mask &=
            (uint16_t)~VCS_ZCODE_CONTINUITY_BORN_RED_FIX;
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(
                      &policy_mutated, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT_EQ(vcs_zcode_continuity_policy_root(
                      &policy_mutated, mutated_root),
                  VCS_ZCODE_CONTINUITY_OK);
        mutated = attribution;
        memcpy(mutated.lineage_root, mutated_root, 32);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &mutated, &policy_mutated, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_EVENT_MASK);

        struct vcs_zcode_task_v1 task_mutated = task;
        continuity_fill(task_mutated.proof_policy_root, 79);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task_mutated, &score, key_b),
                  VCS_ZCODE_CONTINUITY_PROOF_POLICY);
        task_mutated = task;
        continuity_fill(task_mutated.toolchain_capsule_root, 80);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task_mutated, &score, key_b),
                  VCS_ZCODE_CONTINUITY_TRANSITION);

        struct vcs_zcode_score_receipt_v1 score_mutated;
        ASSERT(continuity_score_fixture(
                   &score_mutated, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));
        score_mutated.awarded_mask = 0;
        score_mutated.score = 0;
        uint8_t lane_seed[32], lane_secret[32], lane_pubkey[32];
        memset(lane_seed, 0x61, sizeof(lane_seed));
        zcl_ed25519_keypair(lane_pubkey, lane_secret, lane_seed);
        ASSERT_EQ(vcs_zcode_score_receipt_seal(
                      &score_mutated, lane_secret, lane_pubkey),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &score_mutated, key_b),
                  VCS_ZCODE_CONTINUITY_CAS);
        ASSERT(continuity_score_fixture(
                   &score_mutated, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));
        score_mutated.signature[63] ^= 1;
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &score_mutated, key_b),
                  VCS_ZCODE_CONTINUITY_CAS);
        ASSERT(continuity_score_fixture(
                   &score_mutated, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));
        continuity_fill(score_mutated.task_root, 81);
        ASSERT_EQ(vcs_zcode_score_receipt_seal(
                      &score_mutated, lane_secret, lane_pubkey),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &score_mutated, key_b),
                  VCS_ZCODE_CONTINUITY_CAS);

        /* Score receipts structurally cannot award independent reproduction,
         * so that event class fails closed even when the policy allows it. */
        struct vcs_zcode_creation_attribution_v1 reproduction = attribution;
        reproduction.category = VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION;
        struct vcs_zcode_score_receipt_v1 reproduction_score;
        ASSERT(continuity_score_fixture(
                   &reproduction_score, &reproduction,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 55));
        reproduction_score.awarded_mask =
            (uint8_t)(UINT8_C(1) << VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION);
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &reproduction, &policy, &task, &reproduction_score,
                      key_b),
                  VCS_ZCODE_CONTINUITY_CAS);

        /* Uniqueness: distinct subjects give distinct keys; the two
         * defect-fix classes deliberately share one key space; a different
         * event class gives a different key. */
        struct vcs_zcode_score_receipt_v1 other_evidence;
        ASSERT(continuity_score_fixture(
                   &other_evidence, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 90));
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &other_evidence, key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) != 0);
        struct vcs_zcode_creation_attribution_v1 born_red = attribution;
        born_red.category = VCS_ZCODE_CREATION_BORN_RED_FIX;
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &born_red, &policy, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) == 0);
        struct vcs_zcode_creation_attribution_v1 compatibility = attribution;
        compatibility.category = VCS_ZCODE_CREATION_COMPATIBILITY;
        struct vcs_zcode_score_receipt_v1 compatibility_score;
        ASSERT(continuity_score_fixture(
                   &compatibility_score, &compatibility,
                   VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE, 56));
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &compatibility, &policy, &task, &compatibility_score,
                      key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int continuity_creation_event_key_test(void)
{
    int failures = 0;
    TEST("ZC23 creation event key: policy-free derivation fails closed") {
        uint8_t seed[32], secret[32], pubkey[32];
        memset(seed, 64, sizeof(seed));
        zcl_ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_continuity_policy_v1 policy;
        continuity_policy_fixture(&policy, pubkey);
        ASSERT_EQ(vcs_zcode_continuity_policy_seal(&policy, secret, pubkey),
                  VCS_ZCODE_CONTINUITY_OK);
        uint8_t policy_root[32];
        ASSERT_EQ(vcs_zcode_continuity_policy_root(&policy, policy_root),
                  VCS_ZCODE_CONTINUITY_OK);

        struct vcs_zcode_creation_attribution_v1 attribution;
        continuity_attribution_fixture(&attribution, &policy, policy_root,
                                       VCS_ZCODE_CREATION_SECURITY_FIX);
        struct vcs_zcode_task_v1 task;
        memset(&task, 0, sizeof(task));
        memcpy(task.proof_policy_root, policy.proof_policy_root, 32);
        memcpy(task.toolchain_capsule_root, policy.to_capsule_root, 32);
        struct vcs_zcode_score_receipt_v1 score;
        ASSERT(continuity_score_fixture(
                   &score, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));

        uint8_t key_a[32], key_b[32], zero_root[32] = {0};
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &attribution, &task, &score, key_a),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, zero_root, 32) != 0);
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &attribution, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) == 0);
        ASSERT_EQ(vcs_zcode_creation_event_key(NULL, &task, &score, key_b),
                  VCS_ZCODE_CONTINUITY_NULL);
        ASSERT(memcmp(key_b, zero_root, 32) == 0);

        /* The policy-free key is a different commitment from the
         * policy-bound continuity event key over the same evidence. */
        uint8_t policy_key[32];
        ASSERT_EQ(vcs_zcode_continuity_event_key(
                      &attribution, &policy, &task, &score, policy_key),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, policy_key, 32) != 0);

        struct vcs_zcode_creation_attribution_v1 mutated = attribution;
        mutated.category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
        mutated.lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
        memset(mutated.lineage_root, 0, 32);
        ASSERT_EQ(vcs_zcode_creation_event_key(&mutated, &task, &score,
                                               key_b),
                  VCS_ZCODE_CONTINUITY_EVENT_MASK);

        struct vcs_zcode_task_v1 task_mutated = task;
        continuity_fill(task_mutated.proof_policy_root, 79);
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &attribution, &task_mutated, &score, key_b),
                  VCS_ZCODE_CONTINUITY_CAS);
        struct vcs_zcode_score_receipt_v1 score_mutated;
        ASSERT(continuity_score_fixture(
                   &score_mutated, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));
        score_mutated.signature[63] ^= 1;
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &attribution, &task, &score_mutated, key_b),
                  VCS_ZCODE_CONTINUITY_CAS);
        ASSERT(continuity_score_fixture(
                   &score_mutated, &attribution,
                   VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST, 54));
        score_mutated.awarded_mask = 0;
        score_mutated.score = 0;
        uint8_t lane_seed[32], lane_secret[32], lane_pubkey[32];
        memset(lane_seed, 0x61, sizeof(lane_seed));
        zcl_ed25519_keypair(lane_pubkey, lane_secret, lane_seed);
        ASSERT_EQ(vcs_zcode_score_receipt_seal(
                      &score_mutated, lane_secret, lane_pubkey),
                  VCS_ZCODE_SCORE_OK);
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &attribution, &task, &score_mutated, key_b),
                  VCS_ZCODE_CONTINUITY_CAS);

        /* Same event class and evidence give the same key for both defect
         * categories; a different class gives a different key. */
        struct vcs_zcode_creation_attribution_v1 born_red = attribution;
        born_red.category = VCS_ZCODE_CREATION_BORN_RED_FIX;
        ASSERT_EQ(vcs_zcode_creation_event_key(&born_red, &task, &score,
                                               key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) == 0);
        struct vcs_zcode_creation_attribution_v1 compatibility = attribution;
        compatibility.category = VCS_ZCODE_CREATION_COMPATIBILITY;
        struct vcs_zcode_score_receipt_v1 compatibility_score;
        ASSERT(continuity_score_fixture(
                   &compatibility_score, &compatibility,
                   VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE, 56));
        ASSERT_EQ(vcs_zcode_creation_event_key(
                      &compatibility, &task, &compatibility_score, key_b),
                  VCS_ZCODE_CONTINUITY_OK);
        ASSERT(memcmp(key_a, key_b, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_continuity(void)
{
    return continuity_policy_codec_test() + continuity_verify_cas_test() +
           continuity_event_key_test() + continuity_creation_event_key_test();
}
