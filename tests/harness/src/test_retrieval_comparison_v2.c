/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove workload-preregistered retrieval comparison v2 bindings. */
#include "retrieval/retrieval_comparison.h"

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define R2_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                     \
        printf("  retrieval_comparison_v2: %s... OK\n", (name_));       \
    } else {                                                               \
        printf("  retrieval_comparison_v2: %s... FAIL\n", (name_));     \
        failures++;                                                        \
    }                                                                      \
} while (0)

struct r2_fixture {
    struct zcl_retrieval_comparison_policy_v2 policy;
    struct zcl_retrieval_paired_evaluation_report_v1 paired;
    struct zcl_retrieval_experiment_eval_result_v1 parent, child;
    struct zcl_retrieval_comparison_arm_binding parent_binding, child_binding;
    uint8_t policy_root[32];
};

static void r2_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static bool r2_zero(const void *value, size_t size)
{
    const uint8_t *bytes = value;
    uint8_t aggregate = 0;
    for (size_t i = 0; i < size; i++) aggregate |= bytes[i];
    return aggregate == 0;
}

static void r2_metrics(struct zcl_retrieval_eval_metrics *metrics,
                       uint32_t recall5, uint32_t recall20, uint32_t mrr,
                       uint64_t unique, uint64_t wrong, uint64_t context)
{
    *metrics = (struct zcl_retrieval_eval_metrics){
        .tasks = 2u,
        .recall_at_5_bp = recall5,
        .recall_at_20_bp = recall20,
        .mrr_bp = mrr,
        .recall_at_5_available = true,
        .recall_at_20_available = true,
        .mrr_available = true,
        .unique_files_at_5 = unique,
        .context_bytes_at_5 = context,
        .approximate_tokens_at_5 = (context + 3u) / 4u,
        .wrong_scope_files_at_5 = wrong,
        .wrong_scope_at_5_bp = (uint32_t)(wrong * 10000u / unique),
        .wrong_scope_at_5_available = true,
    };
}

static void r2_result(
    struct zcl_retrieval_experiment_eval_result_v1 *result,
    const struct zcl_retrieval_eval_metrics *metrics, uint8_t subject,
    uint8_t proposal, const uint8_t pair_root[32], const uint8_t evaluator[32])
{
    memset(result, 0, sizeof(*result));
    result->schema_version = ZCL_RETRIEVAL_EVAL_RESULT_VERSION;
    result->flags = ZCL_RETRIEVAL_EVAL_RESULT_FLAGS_ALL;
    result->tasks = metrics->tasks;
    result->recall_at_5_bp = metrics->recall_at_5_bp;
    result->recall_at_20_bp = metrics->recall_at_20_bp;
    result->mrr_bp = metrics->mrr_bp;
    result->wrong_scope_at_5_bp = metrics->wrong_scope_at_5_bp;
    result->unique_files_at_5 = (uint32_t)metrics->unique_files_at_5;
    result->wrong_scope_files_at_5 =
        (uint32_t)metrics->wrong_scope_files_at_5;
    result->changed_positions_at_5 = 2u;
    result->context_bytes_at_5 = metrics->context_bytes_at_5;
    r2_root(result->subject_root, subject);
    r2_root(result->proposal_input_root, proposal);
    memcpy(result->evaluation_input_root, pair_root, 32u);
    memcpy(result->evaluator_root, evaluator, 32u);
}

static bool r2_refresh_result(
    const struct zcl_retrieval_experiment_eval_result_v1 *result,
    struct zcl_retrieval_comparison_arm_binding *binding)
{
    memcpy(binding->subject_root, result->subject_root, 32u);
    memcpy(binding->proposal_input_root, result->proposal_input_root, 32u);
    return zcl_retrieval_experiment_eval_result_root(
               result, binding->result_root) == ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool r2_refresh(struct r2_fixture *fixture)
{
    return zcl_retrieval_comparison_policy_v2_root(
               &fixture->policy, fixture->policy_root) ==
               ZCL_RETRIEVAL_COMPARISON_OK &&
           r2_refresh_result(&fixture->parent, &fixture->parent_binding) &&
           r2_refresh_result(&fixture->child, &fixture->child_binding);
}

static bool r2_fixture_init(struct r2_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->policy.schema_version =
        ZCL_RETRIEVAL_COMPARISON_POLICY_V2_VERSION;
    fixture->policy.metric = ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP;
    fixture->policy.direction =
        ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST;
    fixture->policy.required_guards = ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL;
    fixture->policy.evaluation_kind =
        ZCL_RETRIEVAL_COMPARISON_DERIVED_PROFILE_PAIRED_V1;
    fixture->policy.threshold_bp = 100u;
    fixture->policy.expected_tasks = 2u;
    r2_root(fixture->policy.workload_root, 0x11u);
    r2_root(fixture->policy.evaluator_root, 0x12u);

    fixture->paired.schema_version =
        ZCL_RETRIEVAL_PAIRED_EVALUATION_VERSION;
    fixture->paired.task_count = 2u;
    r2_metrics(&fixture->paired.parent_metrics,
               5000u, 6000u, 4000u, 4u, 1u, 100u);
    r2_metrics(&fixture->paired.child_metrics,
               5100u, 5900u, 4200u, 5u, 1u, 100u);
    r2_root(fixture->paired.expected_task_root, 0x13u);
    r2_root(fixture->paired.source_root, 0x14u);
    r2_root(fixture->paired.retrieval_projection_root, 0x15u);
    memcpy(fixture->paired.workload_root,
           fixture->policy.workload_root, 32u);
    r2_root(fixture->paired.parent_arm_root, 0x16u);
    r2_root(fixture->paired.child_arm_root, 0x17u);
    if (zcl_retrieval_paired_evaluation_input_root(
            fixture->paired.workload_root,
            fixture->paired.parent_arm_root,
            fixture->paired.child_arm_root,
            fixture->paired.evaluation_input_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;

    r2_result(&fixture->parent, &fixture->paired.parent_metrics,
              0x21u, 0x22u, fixture->paired.evaluation_input_root,
              fixture->policy.evaluator_root);
    r2_result(&fixture->child, &fixture->paired.child_metrics,
              0x31u, 0x32u, fixture->paired.evaluation_input_root,
              fixture->policy.evaluator_root);
    return r2_refresh(fixture);
}

static enum zcl_retrieval_comparison_error r2_observe_inputs(
    const struct r2_fixture *fixture,
    const uint8_t expected_pair[32],
    const struct zcl_retrieval_experiment_eval_result_v1 *parent,
    const struct zcl_retrieval_comparison_arm_binding *parent_binding,
    const struct zcl_retrieval_experiment_eval_result_v1 *child,
    const struct zcl_retrieval_comparison_arm_binding *child_binding,
    struct zcl_retrieval_comparison_report_v2 *report)
{
    return zcl_retrieval_comparison_observe_v2(
        &fixture->policy, fixture->policy_root, &fixture->paired, expected_pair,
        parent, parent_binding, child, child_binding, report);
}

static enum zcl_retrieval_comparison_error r2_observe(
    const struct r2_fixture *fixture,
    struct zcl_retrieval_comparison_report_v2 *report)
{
    return r2_observe_inputs(
        fixture, fixture->paired.evaluation_input_root,
        &fixture->parent, &fixture->parent_binding,
        &fixture->child, &fixture->child_binding, report);
}

static bool r2_refuses(const struct r2_fixture *fixture,
                       enum zcl_retrieval_comparison_error expected)
{
    struct zcl_retrieval_comparison_report_v2 report, before;
    memset(&report, 0xa5, sizeof(report));
    before = report;
    return r2_observe(fixture, &report) == expected &&
        memcmp(&report, &before, sizeof(report)) == 0;
}

static void r2_print_root(const uint8_t root[32])
{
    printf("  retrieval_comparison_v2: actual root=");
    for (size_t i = 0; i < 32u; i++) printf("%02x", root[i]);
    putchar('\n');
}

static int case_v2_policy_kat(void)
{
    int failures = 0;
    struct r2_fixture fixture;
    uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES], roundtrip[88];
    uint8_t expected_wire[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES] = {
        'Z','C','R','C','M','P','2','\n', 2u,0u, 1u,1u, 0x70u,0u,
        1u,0u, 100u,0u, 0u,0u, 2u,0u,0u,0u,
    };
    memset(expected_wire + 24u, 0x11, 32u);
    memset(expected_wire + 56u, 0x12, 32u);
    const uint8_t expected_root[32] = {
        0xde,0x7b,0x22,0xf5,0x82,0x10,0x7b,0x74,
        0xd6,0xc0,0x2f,0x46,0x33,0x2d,0x7b,0x4c,
        0x39,0xb0,0xf3,0x36,0x3b,0xe2,0x7c,0x86,
        0x07,0x70,0xb2,0xc9,0xc0,0x57,0x8c,0x6a,
    };
    struct zcl_retrieval_comparison_policy_v2 parsed;
    uint8_t parsed_root[32];
    bool exact = r2_fixture_init(&fixture) &&
        zcl_retrieval_comparison_policy_v2_serialize(
            &fixture.policy, wire) == ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_v2_parse(
            wire, sizeof(wire), &parsed) == ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_v2_serialize(
            &parsed, roundtrip) == ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_v2_root(
            &parsed, parsed_root) == ZCL_RETRIEVAL_COMPARISON_OK;
    bool kat = exact && memcmp(wire, expected_wire, sizeof(wire)) == 0 &&
        memcmp(wire, roundtrip, sizeof(wire)) == 0 &&
        memcmp(fixture.policy_root, parsed_root, 32u) == 0 &&
        memcmp(fixture.policy_root, expected_root, 32u) == 0;
    if (exact && !kat) r2_print_root(fixture.policy_root);
    R2_CHECK("v2 policy wire and root known-answer vector", kat);

    bool mutations = exact;
    for (size_t mutation = 0; mutation < 7u && mutations; mutation++) {
        struct zcl_retrieval_comparison_policy_v2 changed = fixture.policy;
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
        case 5: changed.workload_root[0] ^= 1u; break;
        default: changed.evaluator_root[0] ^= 1u; break;
        }
        uint8_t changed_root[32];
        mutations = zcl_retrieval_comparison_policy_v2_root(
                        &changed, changed_root) ==
                        ZCL_RETRIEVAL_COMPARISON_OK &&
                    memcmp(changed_root, fixture.policy_root, 32u) != 0;
    }
    R2_CHECK("every variable v2 policy field changes the root", mutations);
    return failures;
}

static bool r2_v2_parse_error(const uint8_t *wire, size_t size,
                              enum zcl_retrieval_comparison_error expected)
{
    struct zcl_retrieval_comparison_policy_v2 out;
    memset(&out, 0xa5, sizeof(out));
    return zcl_retrieval_comparison_policy_v2_parse(wire, size, &out) ==
            expected && r2_zero(&out, sizeof(out));
}

static int case_wire_refusals_and_v1(void)
{
    int failures = 0;
    struct r2_fixture fixture;
    struct zcl_retrieval_comparison_policy_v1 v1 = {
        .schema_version = ZCL_RETRIEVAL_COMPARISON_POLICY_VERSION,
        .metric = ZCL_RETRIEVAL_COMPARISON_RECALL_AT_5_BP,
        .direction = ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
        .required_guards = ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL,
        .threshold_bp = 100u, .expected_tasks = 2u,
    };
    r2_root(v1.evaluation_input_root, 0x11u);
    r2_root(v1.evaluator_root, 0x12u);
    uint8_t v1_wire[ZCL_RETRIEVAL_COMPARISON_POLICY_WIRE_BYTES];
    uint8_t v2_wire[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES];
    uint8_t v1_root[32];
    const uint8_t raw_v1_root[32] = {
        0xda,0xbb,0x18,0x18,0xa8,0x48,0x9d,0xa2,
        0xcb,0xbf,0x6a,0x05,0x6d,0x8d,0x67,0xb3,
        0x0d,0x39,0x30,0x8c,0x43,0x40,0x98,0x1e,
        0x82,0x34,0x1a,0x62,0x5a,0x53,0x3e,0xab,
    };
    bool ready = r2_fixture_init(&fixture) &&
        zcl_retrieval_comparison_policy_serialize(&v1, v1_wire) ==
            ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_root(&v1, v1_root) ==
            ZCL_RETRIEVAL_COMPARISON_OK &&
        zcl_retrieval_comparison_policy_v2_serialize(
            &fixture.policy, v2_wire) == ZCL_RETRIEVAL_COMPARISON_OK;
    struct zcl_retrieval_comparison_policy_v1 parsed_v1;
    memset(&parsed_v1, 0xa5, sizeof(parsed_v1));
    bool cross = ready &&
        r2_v2_parse_error(v1_wire, sizeof(v1_wire),
                          ZCL_RETRIEVAL_COMPARISON_WIRE) &&
        zcl_retrieval_comparison_policy_parse(
            v2_wire, sizeof(v2_wire), &parsed_v1) ==
            ZCL_RETRIEVAL_COMPARISON_WIRE &&
        r2_zero(&parsed_v1, sizeof(parsed_v1));
    R2_CHECK("v1 and v2 wires cross-refuse and raw v1 stays pinned",
             cross && memcmp(v1_wire, "ZCRCMP1\n", 8u) == 0 &&
             memcmp(v1_root, raw_v1_root, 32u) == 0);

    uint8_t changed[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES];
    memcpy(changed, v2_wire, sizeof(changed)); changed[0] ^= 1u;
    bool magic = r2_v2_parse_error(
        changed, sizeof(changed), ZCL_RETRIEVAL_COMPARISON_WIRE);
    memcpy(changed, v2_wire, sizeof(changed)); changed[8] = 1u;
    bool version = r2_v2_parse_error(
        changed, sizeof(changed), ZCL_RETRIEVAL_COMPARISON_VERSION);
    bool size = r2_v2_parse_error(
        v2_wire, sizeof(v2_wire) - 1u, ZCL_RETRIEVAL_COMPARISON_WIRE);
    memcpy(changed, v2_wire, sizeof(changed)); changed[18] = 1u;
    bool reserved = r2_v2_parse_error(
        changed, sizeof(changed), ZCL_RETRIEVAL_COMPARISON_RESERVED);
    memcpy(changed, v2_wire, sizeof(changed)); changed[14] = 2u;
    bool kind = r2_v2_parse_error(
        changed, sizeof(changed), ZCL_RETRIEVAL_COMPARISON_PARAMETER);
    R2_CHECK("v2 magic version size reserved and kind refuse exactly",
             magic && version && size && reserved && kind);

    struct zcl_retrieval_comparison_policy_v2 invalid = fixture.policy;
    memset(invalid.workload_root, 0, 32u);
    bool zero_workload = zcl_retrieval_comparison_policy_v2_validate(
        &invalid) == ZCL_RETRIEVAL_COMPARISON_ROOT;
    invalid = fixture.policy; memset(invalid.evaluator_root, 0, 32u);
    bool zero_evaluator = zcl_retrieval_comparison_policy_v2_validate(
        &invalid) == ZCL_RETRIEVAL_COMPARISON_ROOT;
    invalid = fixture.policy; invalid.schema_version++;
    bool object_version = zcl_retrieval_comparison_policy_v2_validate(
        &invalid) == ZCL_RETRIEVAL_COMPARISON_VERSION;
    invalid = fixture.policy; invalid.reserved_threshold = 1u;
    bool object_reserved = zcl_retrieval_comparison_policy_v2_validate(
        &invalid) == ZCL_RETRIEVAL_COMPARISON_RESERVED;
    invalid = fixture.policy; invalid.evaluation_kind++;
    bool object_kind = zcl_retrieval_comparison_policy_v2_validate(
        &invalid) == ZCL_RETRIEVAL_COMPARISON_PARAMETER;
    R2_CHECK("v2 invariant fields and zero roots refuse exactly",
             zero_workload && zero_evaluator && object_version &&
             object_reserved && object_kind);

    union r2_codec_alias {
        struct zcl_retrieval_comparison_policy_v2 policy;
        uint8_t wire[ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES];
    } alias, before;
    alias.policy = fixture.policy; before = alias;
    bool serialize_alias = zcl_retrieval_comparison_policy_v2_serialize(
        &alias.policy, alias.wire) == ZCL_RETRIEVAL_COMPARISON_ALIAS &&
        memcmp(&alias, &before, sizeof(alias)) == 0;
    memcpy(alias.wire, v2_wire, sizeof(alias.wire)); before = alias;
    bool parse_alias = zcl_retrieval_comparison_policy_v2_parse(
        alias.wire, sizeof(alias.wire), &alias.policy) ==
            ZCL_RETRIEVAL_COMPARISON_ALIAS &&
        memcmp(&alias, &before, sizeof(alias)) == 0;
    alias.policy = fixture.policy; before = alias;
    bool root_alias = zcl_retrieval_comparison_policy_v2_root(
        &alias.policy, alias.wire) == ZCL_RETRIEVAL_COMPARISON_ALIAS &&
        memcmp(&alias, &before, sizeof(alias)) == 0;
    R2_CHECK("v2 codec aliases refuse atomically",
             serialize_alias && parse_alias && root_alias);
    return failures;
}

static int case_observer_positive_and_bindings(void)
{
    int failures = 0;
    struct r2_fixture fixture, changed;
    struct zcl_retrieval_comparison_report_v2 report;
    bool initialized = r2_fixture_init(&fixture);
    const uint8_t pair_kat[32] = {
        0x43,0x2f,0x40,0xb7,0xeb,0x01,0x34,0xad,
        0x2d,0x0b,0xb0,0x2d,0xa5,0x70,0xfd,0x1e,
        0x99,0x5b,0x06,0x22,0x62,0xcb,0xbb,0x61,
        0xf1,0xfe,0xd8,0x99,0xf8,0xc2,0xad,0x40,
    };
    uint8_t pair[32], swapped[32];
    bool pair_helper = initialized &&
        zcl_retrieval_paired_evaluation_input_root(
            fixture.paired.workload_root, fixture.paired.parent_arm_root,
            fixture.paired.child_arm_root, pair) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_paired_evaluation_input_root(
            fixture.paired.workload_root, fixture.paired.child_arm_root,
            fixture.paired.parent_arm_root, swapped) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        memcmp(pair, pair_kat, 32u) == 0 &&
        memcmp(pair, fixture.paired.evaluation_input_root, 32u) == 0 &&
        memcmp(pair, swapped, 32u) != 0;
    uint8_t zero[32] = {0}, unchanged[32], before_root[32];
    memset(unchanged, 0xa5, sizeof(unchanged));
    memcpy(before_root, unchanged, sizeof(before_root));
    bool zero_refusal = zcl_retrieval_paired_evaluation_input_root(
            zero, fixture.paired.parent_arm_root,
            fixture.paired.child_arm_root, unchanged) ==
            ZCL_RETRIEVAL_EXPERIMENT_BINDING &&
        memcmp(unchanged, before_root, 32u) == 0;
    memcpy(unchanged, fixture.paired.workload_root, 32u);
    memcpy(before_root, unchanged, sizeof(before_root));
    bool alias_refusal = zcl_retrieval_paired_evaluation_input_root(
            unchanged, fixture.paired.parent_arm_root,
            fixture.paired.child_arm_root, unchanged) ==
            ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
        memcmp(unchanged, before_root, 32u) == 0;
    R2_CHECK("canonical ordered pair helper KAT and refusals",
             pair_helper && zero_refusal && alias_refusal);
    bool observed = initialized && r2_observe(&fixture, &report) ==
        ZCL_RETRIEVAL_COMPARISON_OK;
    R2_CHECK("v2 exact threshold observes the bound pair only",
             observed && report.observation.status ==
                 ZCL_RETRIEVAL_COMPARISON_SATISFIED &&
             report.observation.directional_delta_bp == 100 &&
             memcmp(report.observation.policy_root,
                    fixture.policy_root, 32u) == 0 &&
             memcmp(report.workload_root,
                    fixture.paired.workload_root, 32u) == 0 &&
             memcmp(report.evaluation_input_root,
                    fixture.paired.evaluation_input_root, 32u) == 0);

    bool bindings = initialized;
    for (size_t mutation = 0; mutation < 7u && bindings; mutation++) {
        changed = fixture;
        switch (mutation) {
        case 0:
            changed.policy.workload_root[0] ^= 1u;
            bindings = zcl_retrieval_comparison_policy_v2_root(
                &changed.policy, changed.policy_root) ==
                ZCL_RETRIEVAL_COMPARISON_OK;
            break;
        case 1: changed.paired.task_count++; break;
        case 2:
            changed.child.evaluation_input_root[0] ^= 1u;
            bindings = r2_refresh_result(
                &changed.child, &changed.child_binding);
            break;
        case 3:
            changed.child.evaluator_root[0] ^= 1u;
            bindings = r2_refresh_result(
                &changed.child, &changed.child_binding);
            break;
        case 4: changed.child_binding.result_root[0] ^= 1u; break;
        case 5: changed.child_binding.subject_root[0] ^= 1u; break;
        default: changed.child_binding.proposal_input_root[0] ^= 1u; break;
        }
        bindings = bindings && r2_refuses(
            &changed, ZCL_RETRIEVAL_COMPARISON_BINDING);
    }
    R2_CHECK("workload task pair evaluator result subject proposal bind",
             bindings);

    uint8_t wrong_runtime_pair[32];
    memcpy(wrong_runtime_pair, fixture.paired.evaluation_input_root, 32u);
    wrong_runtime_pair[0] ^= 1u;
    struct zcl_retrieval_comparison_report_v2 report_before;
    memset(&report, 0xa5, sizeof(report)); report_before = report;
    bool runtime_pair = r2_observe_inputs(
        &fixture, wrong_runtime_pair, &fixture.parent,
        &fixture.parent_binding, &fixture.child, &fixture.child_binding,
        &report) == ZCL_RETRIEVAL_COMPARISON_BINDING &&
        memcmp(&report, &report_before, sizeof(report)) == 0;
    R2_CHECK("runtime pair identity mismatch refuses atomically", runtime_pair);

    changed = fixture;
    uint8_t swap_root[32];
    memcpy(swap_root, changed.paired.parent_arm_root, 32u);
    memcpy(changed.paired.parent_arm_root,
           changed.paired.child_arm_root, 32u);
    memcpy(changed.paired.child_arm_root, swap_root, 32u);
    bool swapped_pair = r2_refuses(
        &changed, ZCL_RETRIEVAL_COMPARISON_RESULT);
    struct zcl_retrieval_comparison_report_v2 before;
    memset(&report, 0xa5, sizeof(report)); before = report;
    bool swapped_results = r2_observe_inputs(
        &fixture, fixture.paired.evaluation_input_root,
        &fixture.child, &fixture.child_binding,
        &fixture.parent, &fixture.parent_binding, &report) ==
            ZCL_RETRIEVAL_COMPARISON_BINDING &&
        memcmp(&report, &before, sizeof(report)) == 0;
    R2_CHECK("swapped arms and results cannot reuse the ordered pair",
             swapped_pair && swapped_results);

    union r2_observer_alias {
        struct zcl_retrieval_comparison_policy_v2 policy;
        struct zcl_retrieval_comparison_report_v2 report;
    } alias, alias_before;
    memset(&alias, 0, sizeof(alias)); alias.policy = fixture.policy;
    alias_before = alias;
    bool observer_alias = zcl_retrieval_comparison_observe_v2(
        &alias.policy, fixture.policy_root, &fixture.paired,
        fixture.paired.evaluation_input_root, &fixture.parent,
        &fixture.parent_binding, &fixture.child, &fixture.child_binding,
        &alias.report) == ZCL_RETRIEVAL_COMPARISON_ALIAS &&
        memcmp(&alias, &alias_before, sizeof(alias)) == 0;
    R2_CHECK("v2 observer alias refuses atomically", observer_alias);
    return failures;
}

static int case_metric_binding_and_precedence(void)
{
    int failures = 0;
    struct r2_fixture fixture, changed;
    bool initialized = r2_fixture_init(&fixture), metrics = initialized;
    for (size_t mutation = 0; mutation < 13u && metrics; mutation++) {
        changed = fixture;
        struct zcl_retrieval_eval_metrics *m = &changed.paired.parent_metrics;
        switch (mutation) {
        case 0: m->tasks++; break;
        case 1: m->recall_at_5_bp++; break;
        case 2: m->recall_at_20_bp++; break;
        case 3: m->mrr_bp++; break;
        case 4: m->wrong_scope_at_5_bp++; break;
        case 5: m->recall_at_5_available = false; break;
        case 6: m->recall_at_20_available = false; break;
        case 7: m->mrr_available = false; break;
        case 8: m->wrong_scope_at_5_available = false; break;
        case 9: m->unique_files_at_5++; break;
        case 10: m->wrong_scope_files_at_5++; break;
        case 11: m->context_bytes_at_5++; break;
        default: m->approximate_tokens_at_5++; break;
        }
        metrics = r2_refuses(&changed, ZCL_RETRIEVAL_COMPARISON_BINDING);
    }
    changed = fixture; changed.paired.child_metrics.recall_at_5_bp++;
    metrics = metrics && r2_refuses(
        &changed, ZCL_RETRIEVAL_COMPARISON_BINDING);
    R2_CHECK("every paired metric availability count and context is exact",
             metrics);

    changed = fixture;
    changed.parent.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_RECALL_5_AVAILABLE;
    changed.parent.recall_at_5_bp = 0u;
    changed.paired.parent_metrics.recall_at_5_available = false;
    changed.paired.parent_metrics.recall_at_5_bp = 0u;
    struct zcl_retrieval_comparison_report_v2 report;
    bool incomplete = r2_refresh_result(
            &changed.parent, &changed.parent_binding) &&
        r2_observe(&changed, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
        report.observation.status == ZCL_RETRIEVAL_COMPARISON_INCOMPLETE &&
        report.observation.missing_arms ==
            ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING;
    R2_CHECK("missing selected paired metric is incomplete", incomplete);

    changed.child.flags &= (uint16_t)~
        ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED;
    bool precedence = r2_refresh_result(
            &changed.child, &changed.child_binding) &&
        r2_observe(&changed, &report) == ZCL_RETRIEVAL_COMPARISON_OK &&
        report.observation.status ==
            ZCL_RETRIEVAL_COMPARISON_NOT_SATISFIED &&
        report.observation.missing_arms ==
            ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING &&
        report.observation.failed_guards ==
            ZCL_RETRIEVAL_EVAL_RESULT_TOP20_PRESERVED;
    R2_CHECK("failed guard precedes missing selected metric", precedence);
    return failures;
}

int test_retrieval_comparison_v2(void)
{
    int failures = 0;
    failures += case_v2_policy_kat();
    failures += case_wire_refusals_and_v1();
    failures += case_observer_positive_and_bindings();
    failures += case_metric_binding_and_precedence();
    printf("retrieval_comparison_v2: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
