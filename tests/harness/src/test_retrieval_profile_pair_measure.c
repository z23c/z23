/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: derived-only retrieval profile-pair measurement integration tests. */
#include "services/zcode_retrieval_profile_pair_measure_service.h"

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RPM_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                       \
        printf("  retrieval_profile_pair_measure: %s... OK\n", (name_)); \
    } else {                                                                \
        printf("  retrieval_profile_pair_measure: %s... FAIL\n", (name_)); \
        failures++;                                                         \
    }                                                                       \
} while (0)

struct rpm_fixture {
    struct zcl_retrieval_profile_v1 parent_profile, child_profile;
    struct zcl_retrieval_feature_snapshot_v1 snapshot;
    struct zcl_retrieval_feature_row_v1 rows[5];
    struct vcs_zcode_heuristic_v1 parent_heuristic, child_heuristic;
    struct zcl_retrieval_comparison_policy_v2 policy;
    const char *relevant[1];
    uint8_t task_root[32], source_root[32], snapshot_source_root[32];
    uint8_t projection_root[32], study_root[32], evaluator_root[32];
    uint8_t policy_root[32], parent_heuristic_root[32];
};

static void rpm_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static bool rpm_profile_projection(
    const struct zcl_retrieval_profile_v1 *profile,
    const struct rpm_fixture *fixture,
    struct zcl_retrieval_profile_report *report)
{
    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    return zcl_retrieval_profile_project(
        profile, &fixture->snapshot, fixture->rows, indices,
        ZCL_RETRIEVAL_EVAL_RANK_MAX, report) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static void rpm_heuristic_common(
    struct vcs_zcode_heuristic_v1 *heuristic,
    const struct rpm_fixture *fixture, const uint8_t snapshot_root[32])
{
    vcs_zcode_heuristic_init(heuristic);
    heuristic->evaluator_count = 1u;
    memcpy(heuristic->task_root, fixture->task_root, 32u);
    memcpy(heuristic->source_root, fixture->source_root, 32u);
    rpm_root(heuristic->agent_context_root, 0x31u);
    rpm_root(heuristic->ontology_context_root, 0x32u);
    rpm_root(heuristic->applicability_root, 0x33u);
    memcpy(heuristic->observed_features_root, snapshot_root, 32u);
    memcpy(heuristic->study_root, fixture->study_root, 32u);
    memcpy(heuristic->preregistration_root, fixture->policy_root, 32u);
    rpm_root(heuristic->provenance_root, 0x34u);
    memcpy(heuristic->evaluator_roots[0], fixture->evaluator_root, 32u);
    heuristic->requested_cpu_seconds = 30u;
    heuristic->requested_processes = 1u;
    heuristic->requested_memory_bytes = 1024u * 1024u;
    heuristic->requested_context_bytes = 4096u;
    heuristic->requested_output_bytes = 4096u;
}

static bool rpm_proposal_root(
    const struct rpm_fixture *fixture, const uint8_t profile_root[32],
    const uint8_t snapshot_root[32], const uint8_t candidate_root[32],
    uint8_t out[32])
{
    return zcl_retrieval_profile_proposal_input_root(
        fixture->source_root, fixture->snapshot.source_root,
        fixture->snapshot.codeindex_root, "pair_measure",
        "find the exact target", fixture->snapshot.baseline_ranking_root,
        profile_root, snapshot_root, candidate_root, fixture->study_root,
        fixture->policy_root, fixture->evaluator_root, out);
}

static bool rpm_fixture_init(struct rpm_fixture *fixture, uint8_t metric)
{
    memset(fixture, 0, sizeof(*fixture));
    rpm_root(fixture->task_root, 0x11u);
    rpm_root(fixture->source_root, 0x12u);
    rpm_root(fixture->snapshot_source_root, 0x13u);
    rpm_root(fixture->projection_root, 0x14u);
    rpm_root(fixture->study_root, 0x15u);
    rpm_root(fixture->evaluator_root, 0x16u);
    fixture->relevant[0] = "src/target.c";

    zcl_retrieval_profile_init(&fixture->parent_profile);
    fixture->parent_profile.feature_mask = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    fixture->parent_profile.weight_bp[
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES] = 100u;
    fixture->parent_profile.rerank_window = 5u;
    fixture->parent_profile.top_k = ZCL_RETRIEVAL_EXPERIMENT_TOP;
    fixture->parent_profile.context_byte_scale = 1u;
    fixture->child_profile = fixture->parent_profile;
    fixture->child_profile.context_byte_scale = 1000u;

    const char *paths[5] = {
        "src/target.c", "src/a.c", "src/b.c", "src/c.c", "src/d.c"};
    const uint64_t bytes[5] = {500u, 100u, 200u, 300u, 400u};
    for (size_t i = 0; i < 5u; i++) {
        fixture->rows[i] = (struct zcl_retrieval_feature_row_v1){
            .path = paths[i],
            .context_bytes = bytes[i],
            .original_bm25_rank = (uint16_t)(i + 1u),
            .observed_features = ZCL_RETRIEVAL_FEATURE_BIT(
                ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES),
        };
    }
    fixture->snapshot.schema_version = ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION;
    fixture->snapshot.row_count = 5u;
    fixture->snapshot.ranking_complete = true;
    fixture->snapshot.available_features = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    memcpy(fixture->snapshot.source_root,
           fixture->snapshot_source_root, 32u);
    memcpy(fixture->snapshot.codeindex_root, fixture->projection_root, 32u);
    if (zcl_retrieval_query_root(
            "find the exact target", fixture->snapshot.query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;
    rpm_root(fixture->snapshot.extractor_root, 0x17u);
    struct zcl_retrieval_ranked_file baseline[5];
    for (size_t i = 0; i < 5u; i++)
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = fixture->rows[i].path,
            .context_bytes = fixture->rows[i].context_bytes,
            .in_scope = false,
            .in_scope_available = false,
        };
    if (!zcl_retrieval_ranked_files_root(
            baseline, 5u, true, fixture->snapshot.baseline_ranking_root))
        return false;

    struct zcl_retrieval_evaluation_workload_task_v1 workload = {
        .task_id = "pair_measure",
        .query = "find the exact target",
        .relevant_paths = fixture->relevant,
        .relevant_count = 1u,
    };
    uint8_t workload_root[32];
    if (zcl_retrieval_evaluation_workload_root(
            &workload, 1u, fixture->task_root, fixture->source_root,
            fixture->projection_root, workload_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;
    fixture->policy = (struct zcl_retrieval_comparison_policy_v2){
        .schema_version = ZCL_RETRIEVAL_COMPARISON_POLICY_V2_VERSION,
        .metric = metric,
        .direction = metric == ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP
            ? ZCL_RETRIEVAL_COMPARISON_NOT_HIGHER_BY_MORE_THAN
            : ZCL_RETRIEVAL_COMPARISON_HIGHER_BY_AT_LEAST,
        .required_guards = ZCL_RETRIEVAL_COMPARISON_GUARDS_ALL,
        .evaluation_kind =
            ZCL_RETRIEVAL_COMPARISON_DERIVED_PROFILE_PAIRED_V1,
        .threshold_bp = metric == ZCL_RETRIEVAL_COMPARISON_MRR_BP ? 100u : 0u,
        .expected_tasks = 1u,
    };
    memcpy(fixture->policy.workload_root, workload_root, 32u);
    memcpy(fixture->policy.evaluator_root, fixture->evaluator_root, 32u);
    if (zcl_retrieval_comparison_policy_v2_root(
            &fixture->policy, fixture->policy_root) !=
            ZCL_RETRIEVAL_COMPARISON_OK)
        return false;

    struct zcl_retrieval_profile_report parent_projection, child_projection;
    uint8_t parent_profile_root[32], child_profile_root[32], snapshot_root[32];
    if (!rpm_profile_projection(
            &fixture->parent_profile, fixture, &parent_projection) ||
        !rpm_profile_projection(
            &fixture->child_profile, fixture, &child_projection) ||
        zcl_retrieval_profile_root(
            &fixture->parent_profile, parent_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_root(
            &fixture->child_profile, child_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_feature_snapshot_root(
            &fixture->snapshot, fixture->rows, snapshot_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;

    rpm_heuristic_common(&fixture->parent_heuristic, fixture, snapshot_root);
    memcpy(fixture->parent_heuristic.proposed_rule_root,
           parent_profile_root, 32u);
    memcpy(fixture->parent_heuristic.expected_effect_root,
           parent_projection.candidate_ranking_root, 32u);
    if (!rpm_proposal_root(
            fixture, parent_profile_root, snapshot_root,
            parent_projection.candidate_ranking_root,
            fixture->parent_heuristic.proposal_input_root) ||
        vcs_zcode_heuristic_root(
            &fixture->parent_heuristic,
            fixture->parent_heuristic_root) != VCS_ZCODE_ATTENTION_OK)
        return false;

    fixture->child_heuristic = fixture->parent_heuristic;
    fixture->child_heuristic.derivation = VCS_ZCODE_HEURISTIC_SPECIALIZE;
    fixture->child_heuristic.parent_count = 1u;
    memcpy(fixture->child_heuristic.parent_roots[0],
           fixture->parent_heuristic_root, 32u);
    memcpy(fixture->child_heuristic.proposed_rule_root,
           child_profile_root, 32u);
    memcpy(fixture->child_heuristic.expected_effect_root,
           child_projection.candidate_ranking_root, 32u);
    rpm_root(fixture->child_heuristic.provenance_root, 0x35u);
    if (!rpm_proposal_root(
            fixture, child_profile_root, snapshot_root,
            child_projection.candidate_ranking_root,
            fixture->child_heuristic.proposal_input_root))
        return false;
    return vcs_zcode_heuristic_validate_derivation(
        &fixture->child_heuristic, &fixture->parent_heuristic, 1u) ==
        VCS_ZCODE_ATTENTION_OK;
}

static struct zcode_retrieval_profile_pair_measure_request rpm_request(
    const struct rpm_fixture *fixture)
{
    struct zcode_retrieval_profile_pair_measure_request request = {
        .parent_profile = &fixture->parent_profile,
        .child_profile = &fixture->child_profile,
        .feature_snapshot = &fixture->snapshot,
        .feature_rows = fixture->rows,
        .parent_heuristic = &fixture->parent_heuristic,
        .child_heuristic = &fixture->child_heuristic,
        .policy = &fixture->policy,
        .task_id = "pair_measure",
        .query = "find the exact target",
        .relevant_paths = fixture->relevant,
        .relevant_count = 1u,
    };
    memcpy(request.expected_task_root, fixture->task_root, 32u);
    memcpy(request.expected_source_root, fixture->source_root, 32u);
    memcpy(request.expected_snapshot_source_root,
           fixture->snapshot_source_root, 32u);
    memcpy(request.expected_retrieval_projection_root,
           fixture->projection_root, 32u);
    memcpy(request.expected_study_root, fixture->study_root, 32u);
    memcpy(request.expected_policy_root, fixture->policy_root, 32u);
    memcpy(request.expected_evaluator_root, fixture->evaluator_root, 32u);
    return request;
}

static bool rpm_refused_unchanged(
    const struct zcode_retrieval_profile_pair_measure_request *request,
    enum zcode_retrieval_profile_pair_measure_error expected)
{
    struct zcode_retrieval_profile_pair_measure_report report, before;
    memset(&report, 0xa5, sizeof(report));
    before = report;
    return zcode_retrieval_profile_pair_measure(request, &report) == expected &&
        memcmp(&report, &before, sizeof(report)) == 0;
}

static int case_positive_and_deterministic(void)
{
    int failures = 0;
    struct rpm_fixture fixture;
    bool ready = rpm_fixture_init(
        &fixture, ZCL_RETRIEVAL_COMPARISON_MRR_BP);
    struct zcode_retrieval_profile_pair_measure_request request =
        rpm_request(&fixture);
    struct zcode_retrieval_profile_pair_measure_report first, repeated;
    bool measured = ready && zcode_retrieval_profile_pair_measure(
            &request, &first) == ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK &&
        zcode_retrieval_profile_pair_measure(
            &request, &repeated) == ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK;
    RPM_CHECK("derived pair satisfies exact MRR policy",
              measured && first.comparison.observation.status ==
                  ZCL_RETRIEVAL_COMPARISON_SATISFIED &&
              first.parent_result.mrr_bp == 2000u &&
              first.child_result.mrr_bp == 10000u &&
              first.comparison.observation.directional_delta_bp == 8000);
    RPM_CHECK("all derived identities are deterministic",
              measured && memcmp(first.parent_result_root,
                                 repeated.parent_result_root, 32u) == 0 &&
              memcmp(first.child_result_root,
                     repeated.child_result_root, 32u) == 0 &&
              memcmp(first.paired_evaluation.evaluation_input_root,
                     repeated.paired_evaluation.evaluation_input_root,
                     32u) == 0 &&
              memcmp(first.comparison.workload_root,
                     repeated.comparison.workload_root, 32u) == 0);
    RPM_CHECK("workload policy is shared before child specialization",
              ready && memcmp(fixture.parent_heuristic.preregistration_root,
                              fixture.policy_root, 32u) == 0 &&
              memcmp(fixture.child_heuristic.preregistration_root,
                     fixture.policy_root, 32u) == 0 &&
              memcmp(fixture.child_heuristic.parent_roots[0],
                     fixture.parent_heuristic_root, 32u) == 0 &&
              memcmp(first.comparison.observation.policy_root,
                     fixture.policy_root, 32u) == 0);
    RPM_CHECK("scope remains unavailable rather than false evidence",
              measured &&
              (first.parent_result.flags &
               ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE) == 0 &&
              (first.child_result.flags &
               ZCL_RETRIEVAL_EVAL_RESULT_WRONG_SCOPE_AVAILABLE) == 0);
    return failures;
}

static int case_exact_refusals(void)
{
    int failures = 0;
    struct rpm_fixture fixture, changed;
    bool ready = rpm_fixture_init(
        &fixture, ZCL_RETRIEVAL_COMPARISON_MRR_BP);
    struct zcode_retrieval_profile_pair_measure_request request;

    request = rpm_request(&fixture);
    request.expected_source_root[0] ^= 1u;
    RPM_CHECK("stale source generation refuses atomically",
              ready && rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING));

    const char *different_relevant[1] = {"src/a.c"};
    request = rpm_request(&fixture);
    request.relevant_paths = different_relevant;
    RPM_CHECK("changed frozen workload refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING));

    request = rpm_request(&fixture);
    request.query = "find a different target";
    RPM_CHECK("query substitution refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT));

    changed = fixture;
    changed.policy.threshold_bp++;
    request = rpm_request(&changed);
    RPM_CHECK("post-preregistration policy mutation refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_POLICY));

    request = rpm_request(&fixture);
    request.expected_evaluator_root[0] ^= 1u;
    RPM_CHECK("evaluator substitution refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_POLICY));

    changed = fixture;
    changed.child_heuristic.parent_roots[0][0] ^= 1u;
    request = rpm_request(&changed);
    RPM_CHECK("wrong immediate lineage refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_LINEAGE));

    changed = fixture;
    changed.child_profile.context_byte_scale = 500u;
    request = rpm_request(&changed);
    RPM_CHECK("profile substitution refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_BINDING));

    changed = fixture;
    changed.rows[0].context_bytes++;
    request = rpm_request(&changed);
    RPM_CHECK("snapshot row mutation refuses atomically",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_SNAPSHOT));

    changed = fixture;
    changed.child_profile.top_k = 4u;
    request = rpm_request(&changed);
    RPM_CHECK("non-top-five profile refuses before projection",
              rpm_refused_unchanged(
                  &request, ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_PARAMETER));
    return failures;
}

static int case_incomplete_and_aliases(void)
{
    int failures = 0;
    struct rpm_fixture fixture;
    bool ready = rpm_fixture_init(
        &fixture, ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP);
    struct zcode_retrieval_profile_pair_measure_request request =
        rpm_request(&fixture);
    struct zcode_retrieval_profile_pair_measure_report report;
    RPM_CHECK("wrong-scope policy yields typed incomplete observation",
              ready && zcode_retrieval_profile_pair_measure(
                  &request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_OK &&
              report.comparison.observation.status ==
                  ZCL_RETRIEVAL_COMPARISON_INCOMPLETE &&
              report.comparison.observation.missing_arms ==
                  (ZCL_RETRIEVAL_COMPARISON_PARENT_METRIC_MISSING |
                   ZCL_RETRIEVAL_COMPARISON_CHILD_METRIC_MISSING));

    union rpm_direct_alias {
        struct rpm_fixture fixture;
        struct zcode_retrieval_profile_pair_measure_report report;
    } direct, before;
    ready = rpm_fixture_init(
        &direct.fixture, ZCL_RETRIEVAL_COMPARISON_MRR_BP);
    request = rpm_request(&direct.fixture);
    before = direct;
    RPM_CHECK("direct output/input alias refuses unchanged",
              ready && zcode_retrieval_profile_pair_measure(
                  &request, &direct.report) ==
                  ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS &&
              memcmp(&direct, &before, sizeof(direct)) == 0);

    union rpm_reachable_alias {
        struct zcode_retrieval_profile_pair_measure_report report;
        char text[sizeof(struct zcode_retrieval_profile_pair_measure_report)];
    } reachable, reachable_before;
    memset(&reachable, 0xa5, sizeof(reachable));
    ready = rpm_fixture_init(
        &fixture, ZCL_RETRIEVAL_COMPARISON_MRR_BP);
    request = rpm_request(&fixture);
    const char *reachable_relevant[1] = {reachable.text};
    request.relevant_paths = reachable_relevant;
    reachable_before = reachable;
    RPM_CHECK("reachable relevance alias refuses unchanged",
              ready && zcode_retrieval_profile_pair_measure(
                  &request, &reachable.report) ==
                  ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS &&
              memcmp(&reachable, &reachable_before, sizeof(reachable)) == 0);

    union rpm_pointer_table_alias {
        struct zcode_retrieval_profile_pair_measure_report report;
        const char *paths[1];
    } pointer_table, pointer_table_before;
    memset(&pointer_table, 0xa5, sizeof(pointer_table));
    request = rpm_request(&fixture);
    request.relevant_paths = pointer_table.paths;
    pointer_table_before = pointer_table;
    RPM_CHECK("overlaid relevance pointer table refuses before dereference",
              zcode_retrieval_profile_pair_measure(
                  &request, &pointer_table.report) ==
                  ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS &&
              memcmp(&pointer_table, &pointer_table_before,
                     sizeof(pointer_table)) == 0);

    union rpm_feature_rows_alias {
        struct zcode_retrieval_profile_pair_measure_report report;
        struct zcl_retrieval_feature_row_v1 rows[5u];
    } feature_rows, feature_rows_before;
    memset(&feature_rows, 0xa5, sizeof(feature_rows));
    request = rpm_request(&fixture);
    request.feature_rows = feature_rows.rows;
    feature_rows_before = feature_rows;
    RPM_CHECK("overlaid feature rows refuse before path dereference",
              zcode_retrieval_profile_pair_measure(
                  &request, &feature_rows.report) ==
                  ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS &&
              memcmp(&feature_rows, &feature_rows_before,
                     sizeof(feature_rows)) == 0);

    struct zcl_retrieval_feature_row_v1 nested_rows[5u];
    memcpy(nested_rows, fixture.rows, sizeof(nested_rows));
    memset(&reachable, 0xa5, sizeof(reachable));
    nested_rows[0].path = reachable.text;
    request = rpm_request(&fixture);
    request.feature_rows = nested_rows;
    reachable_before = reachable;
    RPM_CHECK("nested row path alias refuses before non-NUL scan",
              zcode_retrieval_profile_pair_measure(
                  &request, &reachable.report) ==
                  ZCODE_RETRIEVAL_PROFILE_PAIR_MEASURE_ALIAS &&
              memcmp(&reachable, &reachable_before, sizeof(reachable)) == 0);
    return failures;
}

int test_retrieval_profile_pair_measure(void)
{
    int failures = 0;
    failures += case_positive_and_deterministic();
    failures += case_exact_refusals();
    failures += case_incomplete_and_aliases();
    printf("retrieval_profile_pair_measure: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
