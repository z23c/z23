/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the owner-decided Proof-of-Participation emission schedule:
 * budget arithmetic, class split weights, preservation skip, predecessor
 * bootstrap, plan-is-non-mutating and commit idempotency. */
#include "test/test_core.h"

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_epoch_creation.h"
#include "vcs/zcode_epoch_schedule.h"

#include <string.h>

#define SCHEDULE_BOOTSTRAP_HEX \
    "0000000000000000000000000000000000000000000000000000000000000000"

static void schedule_fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

/* A valid standalone attribution (exact challenge timing) whose class and
 * contributor are chosen by the caller. */
static void schedule_attribution_fixture(
    struct vcs_zcode_creation_attribution_v1 *a, uint16_t category,
    uint8_t fill_base, uint8_t contributor_fill, uint64_t epoch,
    uint64_t award_atoms)
{
    memset(a, 0, sizeof(*a));
    a->schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    a->category = category;
    /* Only public-source creations may stand lineage-free. */
    if (category == VCS_ZCODE_CREATION_PUBLIC_SOURCE) {
        a->lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
    } else {
        a->lineage_kind = VCS_ZCODE_CREATION_LINEAGE_PREDECESSOR_ATTRIBUTION;
        schedule_fill(a->lineage_root, (uint8_t)(fill_base + 13));
    }
    a->epoch = epoch;
    a->award_atoms = award_atoms;
    a->challenge_opening_height = 100;
    schedule_fill(a->challenge_opening_hash, fill_base);
    a->challenge_opening_mtp = 1000;
    a->challenge_maturity_height = 8164;
    a->challenge_maturity_mtp = 605800;
    a->created_unix = 605801;
    schedule_fill(a->network_genesis_root, (uint8_t)(fill_base + 1));
    schedule_fill(a->zc23_policy_root, (uint8_t)(fill_base + 2));
    schedule_fill(a->contributor_binding_root, contributor_fill);
    schedule_fill(a->task_root, (uint8_t)(fill_base + 4));
    schedule_fill(a->candidate_root, (uint8_t)(fill_base + 5));
    schedule_fill(a->proof_policy_root, (uint8_t)(fill_base + 6));
    schedule_fill(a->proof_set_root, (uint8_t)(fill_base + 7));
    schedule_fill(a->proven_lane_root, (uint8_t)(fill_base + 8));
    schedule_fill(a->score_receipt_root, (uint8_t)(fill_base + 9));
    schedule_fill(a->package_root, (uint8_t)(fill_base + 10));
    schedule_fill(a->release_root, (uint8_t)(fill_base + 11));
    schedule_fill(a->license_evidence_root, (uint8_t)(fill_base + 12));
}

static bool schedule_store_attribution(
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

static bool schedule_store_proposal(
    const char *workspace,
    struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    uint8_t root_out[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_zcode_epoch_schedule_serialize(proposal, &wire, &wire_len) !=
            VCS_ZCODE_EPOCH_SCHEDULE_OK ||
        vcs_zcode_epoch_schedule_root(proposal, root_out) !=
            VCS_ZCODE_EPOCH_SCHEDULE_OK) {
        free(wire);
        return false;
    }
    bool stored = vcs_object_put_addressed(workspace, root_out, wire,
                                           wire_len);
    free(wire);
    return stored;
}

static bool schedule_proposal_present(const char *workspace,
                                      const uint8_t root[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool present = vcs_object_load_raw_bounded(
        workspace, root, VCS_ZCODE_EPOCH_SCHEDULE_MAX_WIRE_BYTES, &wire,
        &wire_len) == 0;
    free(wire);
    return present;
}

static void schedule_proposal_fixture(
    struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    struct vcs_zcode_epoch_schedule_allocation *allocations, size_t count)
{
    vcs_zcode_epoch_schedule_proposal_init(proposal);
    proposal->schema_version = VCS_ZCODE_EPOCH_SCHEDULE_VERSION;
    proposal->epoch = 1;
    proposal->already_emitted_atoms = 0;
    proposal->budget_atoms =
        VCS_ZC23_SCHEDULE_CAP_ATOMS / VCS_ZC23_SCHEDULE_TOTAL_EPOCHS;
    proposal->evidence_count = 2;
    proposal->eligible_count = 2;
    proposal->preservation_skipped = 0;
    proposal->allocations = allocations;
    proposal->allocation_count = count;
    for (size_t i = 0; i < count; i++) {
        schedule_fill(allocations[i].contributor_binding_root,
                      (uint8_t)(31 + i));
        allocations[i].schedule_class =
            VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION;
        allocations[i].award_atoms = 100 + i;
    }
    if (count != 0) {
        proposal->proposed_mint_atoms = 0;
        for (size_t i = 0; i < count; i++)
            proposal->proposed_mint_atoms += allocations[i].award_atoms;
    }
    proposal->unissued_atoms =
        proposal->budget_atoms - proposal->proposed_mint_atoms;
}

static int schedule_budget_and_weights_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule: budget formula, cap enforcement, class weights") {
        uint64_t atoms = UINT64_MAX;
        ASSERT_EQ(vcs_zc23_schedule_epoch_budget_atoms(0, &atoms),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(atoms == UINT64_C(2019230769230)); /* cap / 1040, floored */
        ASSERT_EQ(vcs_zc23_schedule_epoch_budget_atoms(
                      UINT64_C(375000000), &atoms),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(atoms == UINT64_C(2019230408653));
        ASSERT_EQ(vcs_zc23_schedule_epoch_budget_atoms(
                      VCS_ZC23_SCHEDULE_CAP_ATOMS - 100, &atoms),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK && atoms == 0);
        ASSERT_EQ(vcs_zc23_schedule_epoch_budget_atoms(
                      VCS_ZC23_SCHEDULE_CAP_ATOMS, &atoms),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK && atoms == 0);
        ASSERT_EQ(vcs_zc23_schedule_epoch_budget_atoms(
                      VCS_ZC23_SCHEDULE_CAP_ATOMS + 1, &atoms),
                  VCS_ZCODE_EPOCH_SCHEDULE_CAP);
        ASSERT(atoms == 0);
        ASSERT_EQ(vcs_zc23_schedule_epoch_budget_atoms(0, NULL),
                  VCS_ZCODE_EPOCH_SCHEDULE_NULL);

        uint64_t weight = 0;
        ASSERT(vcs_zcode_epoch_schedule_class_weight(
                   VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION, &weight) &&
               weight == 100);
        ASSERT(vcs_zcode_epoch_schedule_class_weight(
                   VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION, &weight) &&
               weight == 40);
        ASSERT(vcs_zcode_epoch_schedule_class_weight(
                   VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR, &weight) &&
               weight == 20);
        ASSERT(vcs_zcode_epoch_schedule_class_weight(
                   VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION, &weight) &&
               weight == 5);
        ASSERT(!vcs_zcode_epoch_schedule_class_weight(0, &weight));
        ASSERT(!vcs_zcode_epoch_schedule_class_weight(
                   VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION, NULL));
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(
                   VCS_ZCODE_CREATION_PUBLIC_SOURCE) ==
               VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION);
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(
                   VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION) ==
               VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION);
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(
                   VCS_ZCODE_CREATION_BORN_RED_FIX) ==
               VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR);
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(
                   VCS_ZCODE_CREATION_SECURITY_FIX) ==
               VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR);
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(
                   VCS_ZCODE_CREATION_COMPATIBILITY) ==
               VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR);
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(
                   VCS_ZCODE_CREATION_PRESERVATION) ==
               VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION);
        ASSERT(vcs_zcode_epoch_schedule_class_for_category(99) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int schedule_validate_and_wire_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule proposal: validation invariants and wire round-trip") {
        struct vcs_zcode_epoch_schedule_allocation rows[2];
        struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
        schedule_proposal_fixture(&proposal, rows, 2);
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);

        struct vcs_zcode_epoch_schedule_proposal_v1 mutated = proposal;
        mutated.schema_version = 2;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_SCHEMA);
        mutated = proposal;
        mutated.epoch = 0;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_EPOCH);
        mutated = proposal; /* epoch 1 must not carry a predecessor */
        schedule_fill(mutated.previous_proposal_root, 7);
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR);
        mutated = proposal; /* later epochs must carry one */
        mutated.epoch = 2;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR);
        mutated = proposal;
        mutated.budget_atoms++;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_CAP);
        mutated = proposal; /* mint may never push emission over the cap */
        mutated.already_emitted_atoms = VCS_ZC23_SCHEDULE_CAP_ATOMS;
        mutated.budget_atoms = 0;
        mutated.unissued_atoms = 0;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_CAP);
        mutated = proposal;
        mutated.unissued_atoms++;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_SUM);
        mutated = proposal;
        mutated.evidence_count = 3;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_SUM);
        mutated = proposal; /* zero mint means zero allocations */
        mutated.proposed_mint_atoms = 0;
        mutated.unissued_atoms = mutated.budget_atoms;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_SUM);
        mutated = proposal;
        mutated.allocations = NULL;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_ORDER);
        struct vcs_zcode_epoch_schedule_allocation swapped[2];
        swapped[0] = rows[1];
        swapped[1] = rows[0];
        mutated = proposal;
        mutated.allocations = swapped;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_ORDER);
        struct vcs_zcode_epoch_schedule_allocation preserved[2];
        preserved[0] = rows[0];
        preserved[1] = rows[1];
        preserved[0].schedule_class =
            VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION;
        mutated = proposal;
        mutated.allocations = preserved;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_CLASS);
        preserved[0] = rows[0];
        preserved[0].award_atoms = 0;
        mutated = proposal;
        mutated.allocations = preserved;
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&mutated),
                  VCS_ZCODE_EPOCH_SCHEDULE_ORDER);

        /* Wire: round-trip is byte-exact, truncation fails closed. */
        uint8_t *wire = NULL, *second = NULL;
        size_t wire_len = 0, second_len = 0;
        ASSERT_EQ(vcs_zcode_epoch_schedule_serialize(&proposal, &wire,
                                                     &wire_len),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(wire_len == VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES +
                               2u * VCS_ZCODE_EPOCH_SCHEDULE_ALLOCATION_BYTES);
        struct vcs_zcode_epoch_schedule_proposal_v1 parsed, zero;
        vcs_zcode_epoch_schedule_proposal_init(&zero);
        ASSERT_EQ(vcs_zcode_epoch_schedule_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        vcs_zcode_epoch_schedule_proposal_free(&parsed);
        for (size_t cut = 0; cut < wire_len; cut++) {
            ASSERT(vcs_zcode_epoch_schedule_parse(wire, cut, &parsed) !=
                   VCS_ZCODE_EPOCH_SCHEDULE_OK);
            ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        }
        ASSERT_EQ(vcs_zcode_epoch_schedule_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT_EQ(vcs_zcode_epoch_schedule_serialize(&parsed, &second,
                                                     &second_len),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(second_len == wire_len && memcmp(wire, second, wire_len) == 0);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_epoch_schedule_root(&proposal, root_a),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT_EQ(vcs_zcode_epoch_schedule_root(&parsed, root_b),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        wire[0] ^= 1;
        ASSERT_EQ(vcs_zcode_epoch_schedule_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_SCHEDULE_MAGIC);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        wire[0] ^= 1;
        wire[10] = 1; /* reserved u16 must stay zero */
        ASSERT_EQ(vcs_zcode_epoch_schedule_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_SCHEDULE_RESERVED);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        wire[10] = 0;
        wire[VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES + 34] = 1; /* row u16 */
        ASSERT_EQ(vcs_zcode_epoch_schedule_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_SCHEDULE_RESERVED);
        ASSERT(memcmp(&parsed, &zero, sizeof(parsed)) == 0);
        free(second);
        free(wire);
        vcs_zcode_epoch_schedule_proposal_free(&parsed);
        PASS();
    } _test_next:;
    return failures;
}

static int schedule_propose_split_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule proposer: pro-rata class split from the evidence graph") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_schedule_split", "populated");
        ASSERT(vcs_object_store_init(workspace));

        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t root[32];
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 27, 91, 1,
            UINT64_C(125000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 41, 92, 1,
            UINT64_C(250000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION, 55, 93, 1,
            UINT64_C(60000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_BORN_RED_FIX, 69, 94, 1,
            UINT64_C(30000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PRESERVATION, 83, 95, 1,
            UINT64_C(5000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));
        /* Evidence from another epoch is not this epoch's budget. */
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 97, 96, 2,
            UINT64_C(125000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));

        uint8_t zero_root[32] = {0};
        struct vcs_zcode_epoch_schedule_input input = {
            .workspace = workspace,
            .epoch = 1,
            .previous_proposal_root = zero_root,
        };
        struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        const uint64_t budget = UINT64_C(2019230769230);
        ASSERT(proposal.epoch == 1);
        ASSERT(proposal.already_emitted_atoms == 0);
        ASSERT(proposal.budget_atoms == budget);
        ASSERT(proposal.evidence_count == 5);
        ASSERT(proposal.eligible_count == 4);
        ASSERT(proposal.preservation_skipped == 1);
        ASSERT(proposal.allocation_count == 4);
        /* Exact pro-rata shares: total weight 260, floor dust unissued. */
        uint64_t expected[4];
        for (size_t i = 0; i < proposal.allocation_count; i++) {
            const struct vcs_zcode_epoch_schedule_allocation *allocation =
                &proposal.allocations[i];
            uint64_t weight = 0;
            ASSERT(vcs_zcode_epoch_schedule_class_weight(
                       allocation->schedule_class, &weight));
            expected[i] = budget * weight / 260;
            ASSERT(allocation->award_atoms == expected[i]);
        }
        ASSERT(proposal.proposed_mint_atoms ==
               2 * (budget * 100 / 260) + budget * 40 / 260 +
                   budget * 20 / 260);
        ASSERT(proposal.unissued_atoms ==
               budget - proposal.proposed_mint_atoms);
        ASSERT(proposal.unissued_atoms == 3);
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        /* The plan path writes nothing: the proposal is absent from CAS. */
        uint8_t proposal_root[32];
        ASSERT_EQ(vcs_zcode_epoch_schedule_root(&proposal, proposal_root),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(!schedule_proposal_present(workspace, proposal_root));
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int schedule_propose_grouping_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule proposer: one contributor, repeated evidence, one row") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_schedule_grouping", "populated");
        ASSERT(vcs_object_store_init(workspace));

        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t root[32];
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 27, 91, 1,
            UINT64_C(125000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 41, 91, 1,
            UINT64_C(250000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));

        uint8_t zero_root[32] = {0};
        struct vcs_zcode_epoch_schedule_input input = {
            .workspace = workspace,
            .epoch = 1,
            .previous_proposal_root = zero_root,
        };
        struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(proposal.eligible_count == 2);
        ASSERT(proposal.allocation_count == 1);
        ASSERT(proposal.allocations[0].award_atoms == proposal.budget_atoms);
        ASSERT(proposal.proposed_mint_atoms == proposal.budget_atoms);
        ASSERT(proposal.unissued_atoms == 0);
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int schedule_preservation_skip_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule proposer: preservation-only epoch emits nothing") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_schedule_preservation", "populated");
        ASSERT(vcs_object_store_init(workspace));

        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t root[32];
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PRESERVATION, 83, 95, 1,
            UINT64_C(5000000));
        ASSERT(schedule_store_attribution(workspace, &attribution, root));

        uint8_t zero_root[32] = {0};
        struct vcs_zcode_epoch_schedule_input input = {
            .workspace = workspace,
            .epoch = 1,
            .previous_proposal_root = zero_root,
        };
        struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(proposal.evidence_count == 1);
        ASSERT(proposal.eligible_count == 0);
        ASSERT(proposal.preservation_skipped == 1);
        ASSERT(proposal.allocation_count == 0);
        ASSERT(proposal.proposed_mint_atoms == 0);
        /* Non-issuance is not redistribution: the budget stays pooled. */
        ASSERT(proposal.unissued_atoms == proposal.budget_atoms);
        ASSERT_EQ(vcs_zcode_epoch_schedule_validate(&proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_epoch_schedule_serialize(&proposal, &wire,
                                                     &wire_len),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(wire_len == VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES);
        struct vcs_zcode_epoch_schedule_proposal_v1 parsed;
        ASSERT_EQ(vcs_zcode_epoch_schedule_parse(wire, wire_len, &parsed),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(parsed.unissued_atoms == proposal.budget_atoms);
        free(wire);
        vcs_zcode_epoch_schedule_proposal_free(&parsed);
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int schedule_predecessor_chain_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule proposer: bootstrap and predecessor lineage") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_schedule_chain", "populated");
        ASSERT(vcs_object_store_init(workspace));

        uint8_t zero_root[32] = {0}, nonroot[32];
        schedule_fill(nonroot, 7);
        struct vcs_zcode_epoch_schedule_input input = {
            .workspace = workspace,
            .epoch = 1,
            .previous_proposal_root = nonroot,
        };
        struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR);
        input.epoch = 2;
        input.previous_proposal_root = zero_root;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR);

        /* Bootstrap: epoch 1 with a zero predecessor, then epoch 2 on it. */
        input.epoch = 1;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(proposal.proposed_mint_atoms == 0);
        uint8_t first_root[32];
        ASSERT(schedule_store_proposal(workspace, &proposal, first_root));
        vcs_zcode_epoch_schedule_proposal_free(&proposal);

        input.epoch = 2;
        input.previous_proposal_root = first_root;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        vcs_zcode_epoch_schedule_proposal_free(&proposal);

        /* A predecessor that is not epoch - 1 is refused. */
        input.epoch = 3;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR);
        /* An unknown predecessor root is refused, never assumed. */
        input.epoch = 2;
        input.previous_proposal_root = nonroot;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static int schedule_already_emitted_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule proposer: already_emitted tapers the budget") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_schedule_emitted", "populated");
        ASSERT(vcs_object_store_init(workspace));

        /* Old-curve epoch accounting is the already_emitted input. */
        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t attribution_root[32];
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 27, 91, 1,
            UINT64_C(125000000));
        ASSERT(schedule_store_attribution(workspace, &attribution,
                                          attribution_root));
        struct vcs_zcode_epoch_creation_set_v1 set;
        vcs_zcode_epoch_creation_init(&set);
        set.schema_version = VCS_ZCODE_EPOCH_CREATION_VERSION;
        set.epoch = 1;
        set.emission_cap_atoms = UINT64_C(5000000000000);
        set.actual_mint_atoms = UINT64_C(375000000);
        set.unissued_atoms = set.emission_cap_atoms - set.actual_mint_atoms;
        schedule_fill(set.network_genesis_root, 21);
        schedule_fill(set.zc23_policy_root, 22);
        schedule_fill(set.previous_epoch_creation_root, 23);
        schedule_fill(set.committee_evidence_snapshot_root, 24);
        set.opening_height = 100;
        schedule_fill(set.opening_hash, 25);
        set.opening_mtp = 1000;
        set.maturity_height = 8164;
        schedule_fill(set.maturity_hash, 26);
        set.maturity_mtp = 605800;
        uint8_t (*roots)[32] =
            zcl_malloc(sizeof(*roots), "test_epoch_schedule_roots");
        ASSERT(roots != NULL);
        memcpy(roots[0], attribution_root, 32);
        set.attribution_roots = roots;
        set.attribution_count = 1;
        uint8_t *epoch_wire = NULL;
        size_t epoch_wire_len = 0;
        uint8_t epoch_root[32];
        ASSERT_EQ(vcs_zcode_epoch_creation_serialize(&set, &epoch_wire,
                                                     &epoch_wire_len),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT_EQ(vcs_zcode_epoch_creation_root(&set, epoch_root),
                  VCS_ZCODE_EPOCH_CREATION_OK);
        ASSERT(vcs_object_put_addressed(workspace, epoch_root, epoch_wire,
                                        epoch_wire_len));
        free(epoch_wire);
        vcs_zcode_epoch_creation_free(&set);

        uint8_t zero_root[32] = {0};
        struct vcs_zcode_epoch_schedule_input input = {
            .workspace = workspace,
            .epoch = 1,
            .previous_proposal_root = zero_root,
        };
        struct vcs_zcode_epoch_schedule_proposal_v1 proposal;
        ASSERT_EQ(vcs_zcode_epoch_schedule_propose_cas(&input, &proposal),
                  VCS_ZCODE_EPOCH_SCHEDULE_OK);
        ASSERT(proposal.already_emitted_atoms == UINT64_C(375000000));
        ASSERT(proposal.budget_atoms == UINT64_C(2019230408653));
        vcs_zcode_epoch_schedule_proposal_free(&proposal);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

static void schedule_call(void (*fn)(const struct zcl_command_request *,
                                     struct zcl_command_reply *),
                          const char *path, struct json_value *input,
                          struct zcl_command_reply *reply)
{
    struct zcl_command_spec spec = { .path = path };
    struct zcl_command_request request = { .spec = &spec, .input = input };
    zcl_command_reply_init(reply, "zcl.zcode_commons_schedule_propose.v1");
    fn(&request, reply);
}

static void schedule_input_open(struct json_value *input,
                                const char *workspace, int64_t epoch,
                                const char *previous_hex)
{
    json_init(input);
    json_set_object(input);
    (void)json_push_kv_str(input, "workspace", workspace);
    (void)json_push_kv_int(input, "epoch", epoch);
    (void)json_push_kv_str(input, "previous_proposal_root", previous_hex);
}

static int schedule_command_plan_commit_test(void)
{
    int failures = 0;
    TEST("ZC23 schedule commands: plan previews, commit persists idempotently") {
        char workspace[256];
        test_make_tmpdir(workspace, sizeof(workspace),
                         "zcode_schedule_command", "populated");
        ASSERT(vcs_object_store_init(workspace));
        struct vcs_zcode_creation_attribution_v1 attribution;
        uint8_t attribution_root[32];
        schedule_attribution_fixture(&attribution,
            VCS_ZCODE_CREATION_PUBLIC_SOURCE, 27, 91, 1,
            UINT64_C(125000000));
        ASSERT(schedule_store_attribution(workspace, &attribution,
                                          attribution_root));

        struct json_value input;
        struct zcl_command_reply reply;
        schedule_input_open(&input, workspace, 1, SCHEDULE_BOOTSTRAP_HEX);
        schedule_call(zcl_native_handle_zcode_commons_schedule_propose_plan,
                      "zcode.commons.schedule.propose.plan", &input, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "service_id")),
                      "zcode.c23.economics.v1");
        ASSERT(json_get_int(json_get(&reply.data, "service_generation")) ==
               0);
        ASSERT(json_get_bool(json_get(&reply.data, "pure_calculation")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "mint_authority")),
                      "simulation_only;no_issuance_authority");
        ASSERT(json_get_bool(json_get(&reply.data, "simulated")));
        ASSERT(!json_get_bool(json_get(&reply.data, "persisted")));
        ASSERT(json_get_bool(json_get(&reply.data, "schedule_proposal")));
        ASSERT(!json_get_bool(json_get(&reply.data, "mint")));
        ASSERT(!json_get_bool(json_get(&reply.data, "token_exists")));
        ASSERT(!json_get_bool(json_get(&reply.data, "funds_moved")));
        ASSERT(json_get_int(json_get(&reply.data, "budget_atoms")) ==
               (int64_t)UINT64_C(2019230769230));
        ASSERT(json_get_int(json_get(&reply.data, "proposed_mint_atoms")) ==
               (int64_t)UINT64_C(2019230769230));
        ASSERT(json_get_int(json_get(&reply.data, "preservation_skipped")) ==
               0);
        const char *root_hex =
            json_get_str(json_get(&reply.data, "schedule_proposal_root"));
        ASSERT(root_hex && strlen(root_hex) == 64);
        char root_hex_copy[65];
        snprintf(root_hex_copy, sizeof(root_hex_copy), "%s", root_hex);
        uint8_t proposal_root[32];
        ASSERT(zcl_hex_decode_lower(root_hex_copy, proposal_root, 32));
        /* Plan is non-mutating: the proposal never entered the CAS. */
        ASSERT(!schedule_proposal_present(workspace, proposal_root));
        zcl_command_reply_free(&reply);
        json_free(&input);

        schedule_input_open(&input, workspace, 1, SCHEDULE_BOOTSTRAP_HEX);
        schedule_call(zcl_native_handle_zcode_commons_schedule_propose_commit,
                      "zcode.commons.schedule.propose.commit", &input, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "persisted")));
        const char *commit_hex =
            json_get_str(json_get(&reply.data, "schedule_proposal_root"));
        ASSERT(commit_hex && strcmp(commit_hex, root_hex_copy) == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        ASSERT(schedule_proposal_present(workspace, proposal_root));

        /* Commit is root-addressed: repeating it stores the same object. */
        schedule_input_open(&input, workspace, 1, SCHEDULE_BOOTSTRAP_HEX);
        schedule_call(zcl_native_handle_zcode_commons_schedule_propose_commit,
                      "zcode.commons.schedule.propose.commit", &input, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* Closed input and the scratch-workspace gate both fail closed. */
        schedule_input_open(&input, workspace, 0, SCHEDULE_BOOTSTRAP_HEX);
        schedule_call(zcl_native_handle_zcode_commons_schedule_propose_plan,
                      "zcode.commons.schedule.propose.plan", &input, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "BAD_PROPOSE_INPUT");
        zcl_command_reply_free(&reply);
        json_free(&input);
        schedule_input_open(&input, "/var/lib/zclassic23", 1,
                            SCHEDULE_BOOTSTRAP_HEX);
        schedule_call(zcl_native_handle_zcode_commons_schedule_propose_plan,
                      "zcode.commons.schedule.propose.plan", &input, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "UNSAFE_PROPOSE_WORKSPACE");
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_rm_rf(workspace);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_epoch_schedule(void)
{
    return schedule_budget_and_weights_test() +
           schedule_validate_and_wire_test() +
           schedule_propose_split_test() +
           schedule_propose_grouping_test() +
           schedule_preservation_skip_test() +
           schedule_predecessor_chain_test() +
           schedule_already_emitted_test() +
           schedule_command_plan_commit_test();
}
