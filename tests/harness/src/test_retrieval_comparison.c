/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove retrieval comparison is exact, bounded observation only. */
#include "retrieval/retrieval_comparison.h"

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RC_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                     \
        printf("  retrieval_comparison: %s... OK\n", (name_));           \
    } else {                                                               \
        printf("  retrieval_comparison: %s... FAIL\n", (name_));         \
        failures++;                                                        \
    }                                                                      \
} while (0)

struct rc_fixture {
    struct zcl_retrieval_comparison_policy_v1 policy;
    struct zcl_retrieval_experiment_eval_result_v1 parent;
    struct zcl_retrieval_experiment_eval_result_v1 child;
    struct zcl_retrieval_comparison_arm_binding parent_binding;
    struct zcl_retrieval_comparison_arm_binding child_binding;
};

static void rc_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static bool rc_refresh_result(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    struct zcl_retrieval_comparison_arm_binding *binding)
{
    return zcl_retrieval_experiment_eval_result_root(
        result, binding->result_root) == ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rc_refresh(struct rc_fixture *fixture)
{
    return rc_refresh_result(&fixture->parent, &fixture->parent_binding) &&
           rc_refresh_result(&fixture->child, &fixture->child_binding);
}

static bool rc_fixture_init(struct rc_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->policy.schema_version =
        ZCL_RETRIEVAL_COMPARISON_POLICY_VERSION;
    fixture->policy.metric = ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP;
    fixture->policy.direction =
        ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST;
    fixture->policy.required_guards = ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL;
    fixture->policy.threshold_bp = 100u;
    fixture->policy.expected_tasks = 2u;
    rc_root(fixture->policy.evaluation_input_root, 0x11u);
    rc_root(fixture->policy.evaluator_root, 0x12u);

    fixture->parent.schema_version = ZCL_RETRIEVAL_EVAL_RESULT_VERSION;
    fixture->parent.flags = ZCL_RETRIEVAL_EVAL_RESULT_FLAGS_ALL;
    fixture->parent.tasks = 2u;
    fixture->parent.recall_at_5_bp = 5000u;
    fixture->parent.recall_at_20_bp = 6000u;
    fixture->parent.mrr_bp = 4000u;
    fixture->parent.wrong_scope_at_5_bp = 2500u;
    fixture->parent.unique_files_at_5 = 4u;
    fixture->parent.wrong_scope_files_at_5 = 1u;
    fixture->parent.changed_positions_at_5 = 2u;
    fixture->parent.context_bytes_at_5 = 100u;
    rc_root(fixture->parent.subject_root, 0x21u);
    rc_root(fixture->parent.proposal_input_root, 0x22u);
    memcpy(fixture->parent.evaluation_input_root,
           fixture->policy.evaluation_input_root, 32u);
    memcpy(fixture->parent.evaluator_root, fixture->policy.evaluator_root, 32u);

    fixture->child = fixture->parent;
    fixture->child.recall_at_5_bp = 5100u;
    fixture->child.recall_at_20_bp = 5900u;
    fixture->child.mrr_bp = 4200u;
    fixture->child.wrong_scope_at_5_bp = 2000u;
    fixture->child.unique_files_at_5 = 5u;
    fixture->child.changed_positions_at_5 = 3u;
    rc_root(fixture->child.subject_root, 0x31u);
    rc_root(fixture->child.proposal_input_root, 0x32u);

    memcpy(fixture->parent_binding.subject_root,
           fixture->parent.subject_root, 32u);
    memcpy(fixture->parent_binding.proposal_input_root,
           fixture->parent.proposal_input_root, 32u);
    memcpy(fixture->child_binding.subject_root,
           fixture->child.subject_root, 32u);
    memcpy(fixture->child_binding.proposal_input_root,
           fixture->child.proposal_input_root, 32u);
    return zcl_retrieval_comparison_policy_validate(&fixture->policy) ==
               ZCL_RETRIEVAL_COMPARISON_OK &&
           zcl_retrieval_experiment_eval_result_validate(&fixture->parent) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK &&
           zcl_retrieval_experiment_eval_result_validate(&fixture->child) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK && rc_refresh(fixture);
}

static enum zcl_retrieval_comparison_error rc_observe_expected(
    const struct rc_fixture *fixture,
    const uint8_t expected_policy_root[32],
    struct zcl_retrieval_comparison_report *report)
{
    return zcl_retrieval_comparison_observe(
        &fixture->policy, expected_policy_root, &fixture->parent,
        &fixture->parent_binding, &fixture->child, &fixture->child_binding,
        report);
}

static enum zcl_retrieval_comparison_error rc_observe(
    const struct rc_fixture *fixture,
    struct zcl_retrieval_comparison_report *report)
{
    uint8_t policy_root[32];
    enum zcl_retrieval_comparison_error error =
        zcl_retrieval_comparison_policy_root(&fixture->policy, policy_root);
    return error == ZCL_RETRIEVAL_COMPARISON_OK
        ? rc_observe_expected(fixture, policy_root, report) : error;
}

static bool rc_set_recall_5(struct rc_fixture *fixture,
                            uint32_t parent, uint32_t child)
{
    fixture->parent.recall_at_5_bp = parent;
    fixture->child.recall_at_5_bp = child;
    return rc_refresh(fixture);
}

static bool rc_expect_status(uint8_t direction, uint16_t threshold,
                             uint32_t parent, uint32_t child,
                             enum zcl_retrieval_comparison_status status,
                             int32_t delta)
{
    struct rc_fixture fixture;
    struct zcl_retrieval_comparison_report report;
    if (!rc_fixture_init(&fixture)) return false;
    fixture.policy.direction = direction;
    fixture.policy.threshold_bp = threshold;
    if (!rc_set_recall_5(&fixture, parent, child)) return false;
    return rc_observe(&fixture, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
           report.status == status && report.direction == direction &&
           report.metric == ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP &&
           report.directional_delta_bp == delta &&
           report.missing_arms == 0 && report.failed_guards == 0;
}

static int case_policy_kat(void)
{
    int failures = 0;
    struct rc_fixture fixture;
    const uint8_t expected_root[32] = {
        0xda, 0xbb, 0x18, 0x18, 0xa8, 0x48, 0x9d, 0xa2,
        0xcb, 0xbf, 0x6a, 0x05, 0x6d, 0x8d, 0x67, 0xb3,
        0x0d, 0x39, 0x30, 0x8c, 0x43, 0x40, 0x98, 0x1e,
        0x82, 0x34, 0x1a, 0x62, 0x5a, 0x53, 0x3e, 0xab,
    };
    uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES];
    uint8_t roundtrip[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES];
    uint8_t first_root[32], second_root[32];
    struct zcl_retrieval_comparison_policy_v1 parsed;
    bool initialized = rc_fixture_init(&fixture);
    bool exact = initialized &&
        zcl_retrieval_comparison_policy_serialize(&fixture.policy, wire) ==
            ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_parse(wire, sizeof(wire), &parsed) ==
            ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_serialize(&parsed, roundtrip) ==
            ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_root(&fixture.policy, first_root) ==
            ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_root(&parsed, second_root) ==
            ZCL_RETRIEVAL_COMPARISON_OK;
    RC_CHECK("policy wire and root known-answer vector",
             exact && memcmp(wire, "ZCRCMP1\n", 8u) == 0 &&
             wire[10] == ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP &&
             wire[11] == ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST &&
             wire[12] == (uint8_t)ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL &&
             wire[16] == 100u && wire[20] == 2u &&
             memcmp(wire, roundtrip, sizeof(wire)) == 0 &&
             memcmp(first_root, expected_root, 32u) == 0 &&
             memcmp(first_root, second_root, 32u) == 0);

    bool mutations = exact;
    for (unsigned int mutation = 0; mutation < 7u && mutations; mutation++) {
        struct zcl_retrieval_comparison_policy_v1 changed = fixture.policy;
        switch (mutation) {
        case 0: changed.metric = ZCL_RETRIEVAL_COMPARISON_MRR_BP; break;
        case 1:
            changed.direction = ZCL_RETRIEVAL_COMPARISON_LOWER_BY_AT_LEAST;
            break;
        case 2:
            changed.required_guards &= (uint16_t)~
                ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED;
            break;
        case 3: changed.threshold_bp++; break;
        case 4: changed.expected_tasks++; break;
        case 5: changed.evaluation_input_root[0] ^= 1u; break;
        default: changed.evaluator_root[0] ^= 1u; break;
        }
        uint8_t changed_root[32];
        mutations = zcl_retrieval_comparison_policy_root(
                        &changed, changed_root) ==
                        ZCL_RETRIEVAL_COMPARISON_OK &&
                    memcmp(first_root, changed_root, 32u) != 0;
    }
    RC_CHECK("every active policy field changes the root", mutations);
    return failures;
}

static int case_threshold_directions(void)
{
    int failures = 0;
    RC_CHECK("higher gain accepts exact threshold and plus one",
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
                              100u, 5000u, 5100u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, 100) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
                              100u, 5000u, 5101u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, 101));
    RC_CHECK("higher gain rejects threshold minus one",
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
                              100u, 5000u, 5099u,
                              ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED, 99));
    RC_CHECK("lower gain boundary is oriented parent minus child",
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_LOWER_BY_AT_LEAST,
                              100u, 5000u, 4900u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, 100) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_LOWER_BY_AT_LEAST,
                              100u, 5000u, 4901u,
                              ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED, 99) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_LOWER_BY_AT_LEAST,
                              100u, 5000u, 4899u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, 101));
    RC_CHECK("not-lower boundary accepts negative threshold only",
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_NOT_LOWER_BY_MORE_THAN,
                              100u, 5000u, 4900u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, -100) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_NOT_LOWER_BY_MORE_THAN,
                              100u, 5000u, 4899u,
                              ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED, -101) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_NOT_LOWER_BY_MORE_THAN,
                              100u, 5000u, 4901u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, -99));
    RC_CHECK("not-higher boundary accepts negative threshold only",
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN,
                              100u, 5000u, 5100u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, -100) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN,
                              100u, 5000u, 5101u,
                              ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED, -101) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN,
                              100u, 5000u, 5099u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, -99));
    RC_CHECK("zero threshold is an active exact boundary",
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
                              0u, 5000u, 5000u,
                              ZCL_RETRIEVAL_COMPARISON_SATISFIED, 0) &&
             rc_expect_status(ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
                              0u, 5000u, 4999u,
                              ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED, -1));
    return failures;
}

static int case_incomplete_and_guards(void)
{
    int failures = 0;
    struct rc_fixture fixture;
    struct zcl_retrieval_comparison_report report;
    bool initialized = rc_fixture_init(&fixture);
    fixture.parent.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE;
    fixture.parent.recall_at_5_bp = 0;
    RC_CHECK("required metric unavailable is incomplete",
             initialized && rc_refresh(&fixture) &&
             rc_observe(&fixture, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
             report.status == ZCL_RETRIEVAL_COMPARISON_INCOMPLETE &&
             report.missing_arms ==
                 ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING &&
             report.directional_delta_bp == 0);

    initialized = rc_fixture_init(&fixture);
    fixture.child.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED;
    RC_CHECK("absent required child guard is not satisfied",
             initialized && rc_refresh(&fixture) &&
             rc_observe(&fixture, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
             report.status == ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED &&
             report.failed_guards ==
                 ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED &&
             report.directional_delta_bp == 0);

    initialized = rc_fixture_init(&fixture);
    fixture.parent.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE;
    fixture.parent.recall_at_5_bp = 0;
    fixture.child.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED;
    RC_CHECK("failed guard takes precedence over missing required metric",
             initialized && rc_refresh(&fixture) &&
             rc_observe(&fixture, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
             report.status == ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED &&
             report.missing_arms ==
                 ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING &&
             report.failed_guards ==
                 ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED &&
             report.directional_delta_bp == 0);

    initialized = rc_fixture_init(&fixture);
    fixture.parent.flags &=
        (uint16_t)~ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE;
    fixture.child.flags &=
        (uint16_t)~ZCL_RETRIEVAL_EVAL_RESULT_MRR_AVAILABLE;
    fixture.parent.mrr_bp = 0;
    fixture.child.mrr_bp = 0;
    RC_CHECK("unselected unavailable metric is ignored",
             initialized && rc_refresh(&fixture) &&
             rc_observe(&fixture, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
             report.status == ZCL_RETRIEVAL_COMPARISON_SATISFIED &&
             report.missing_arms == 0 && report.failed_guards == 0 &&
             report.directional_delta_bp == 100);
    RC_CHECK("satisfied is a closed observational verdict only",
             report.status >= ZCL_RETRIEVAL_COMPARISON_SATISFIED &&
             report.status <= ZCL_RETRIEVAL_COMPARISON_INCOMPLETE &&
             report.metric == fixture.policy.metric &&
             report.direction == fixture.policy.direction);
    return failures;
}

static bool rc_binding_refusal_is_atomic(const struct rc_fixture *fixture)
{
    struct zcl_retrieval_comparison_report report;
    struct zcl_retrieval_comparison_report before;
    memset(&report, 0xa5, sizeof(report));
    before = report;
    return rc_observe(fixture, &report) ==
               ZCL_RETRIEVAL_COMPARISON_BINDING &&
           memcmp(&report, &before, sizeof(report)) == 0;
}

static bool rc_policy_refusal_is_atomic(
    const struct rc_fixture *fixture, const uint8_t expected_policy_root[32])
{
    struct zcl_retrieval_comparison_report report;
    struct zcl_retrieval_comparison_report before;
    memset(&report, 0xa5, sizeof(report));
    before = report;
    return rc_observe_expected(fixture, expected_policy_root, &report) ==
               ZCL_RETRIEVAL_COMPARISON_BINDING &&
           memcmp(&report, &before, sizeof(report)) == 0;
}

static int case_binding_refusals(void)
{
    int failures = 0;
    struct rc_fixture baseline, changed;
    bool initialized = rc_fixture_init(&baseline);

    changed = baseline;
    changed.child.tasks = 1u;
    RC_CHECK("task-count mismatch hard-refuses atomically",
             initialized && rc_refresh_result(
                 &changed.child, &changed.child_binding) &&
             rc_binding_refusal_is_atomic(&changed));

    changed = baseline;
    changed.child.evaluation_input_root[0] ^= 1u;
    RC_CHECK("evaluation-root mismatch hard-refuses atomically",
             rc_refresh_result(&changed.child, &changed.child_binding) &&
             rc_binding_refusal_is_atomic(&changed));

    changed = baseline;
    changed.child.evaluator_root[0] ^= 1u;
    RC_CHECK("evaluator-root mismatch hard-refuses atomically",
             rc_refresh_result(&changed.child, &changed.child_binding) &&
             rc_binding_refusal_is_atomic(&changed));

    changed = baseline;
    changed.child_binding.subject_root[0] ^= 1u;
    RC_CHECK("subject-root mismatch hard-refuses atomically",
             rc_binding_refusal_is_atomic(&changed));

    changed = baseline;
    changed.child_binding.proposal_input_root[0] ^= 1u;
    RC_CHECK("proposal-root mismatch hard-refuses atomically",
             rc_binding_refusal_is_atomic(&changed));

    changed = baseline;
    changed.child_binding.result_root[0] ^= 1u;
    RC_CHECK("result-root mismatch hard-refuses atomically",
             rc_binding_refusal_is_atomic(&changed));

    uint8_t preregistered_policy_root[32];
    bool rooted = zcl_retrieval_comparison_policy_root(
        &baseline.policy, preregistered_policy_root) ==
        ZCL_RETRIEVAL_COMPARISON_OK;
    changed = baseline;
    changed.policy.threshold_bp++;
    RC_CHECK("post-hoc policy substitution hard-refuses atomically",
             rooted && rc_policy_refusal_is_atomic(
                 &changed, preregistered_policy_root));
    return failures;
}

int test_retrieval_comparison(void)
{
    int failures = 0;
    failures += case_policy_kat();
    failures += case_threshold_directions();
    failures += case_incomplete_and_guards();
    failures += case_binding_refusals();
    printf("retrieval_comparison: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
