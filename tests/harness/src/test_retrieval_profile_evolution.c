/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: adversarial checks for one-field retrieval specialization. */
#include "test/test_core.h"

#include "services/zcode_retrieval_profile_evolution_service.h"

#include <stdio.h>
#include <string.h>

#define RPE_CHECK(name_, expression_) do {                              \
    if (expression_) {                                                  \
        printf("  retrieval_profile_evolution: %s... OK\n", (name_)); \
    } else {                                                            \
        printf("  retrieval_profile_evolution: %s... FAIL\n", (name_)); \
        failures++;                                                     \
    }                                                                   \
} while (0)

struct rpe_fixture {
    struct zcl_retrieval_profile_v1 parent_profile;
    struct zcl_retrieval_feature_snapshot_v1 snapshot;
    struct zcl_retrieval_feature_row_v1 rows[3];
    struct vcs_zcode_heuristic_v1 parent_heuristic;
    uint8_t expected_task_root[32];
    uint8_t expected_source_root[32];
    uint8_t candidate_provenance_root[32];
};

static void rpe_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static struct zcode_retrieval_profile_evolution_request rpe_request(
    const struct rpe_fixture *fixture, uint64_t scale)
{
    struct zcode_retrieval_profile_evolution_request request = {
        .parent_profile = &fixture->parent_profile,
        .candidate_context_byte_scale = scale,
        .feature_snapshot = &fixture->snapshot,
        .feature_rows = fixture->rows,
        .parent_heuristic = &fixture->parent_heuristic,
        .task_id = "context-scale-specialization",
        .query = "rank bounded context files",
    };
    memcpy(request.expected_task_root, fixture->expected_task_root, 32u);
    memcpy(request.expected_source_root, fixture->expected_source_root, 32u);
    memcpy(request.expected_snapshot_source_root,
           fixture->snapshot.source_root, 32u);
    memcpy(request.expected_retrieval_projection_root,
           fixture->snapshot.codeindex_root, 32u);
    memcpy(request.proposal_evaluator_root,
           fixture->parent_heuristic.evaluator_roots[0], 32u);
    memcpy(request.candidate_provenance_root,
           fixture->candidate_provenance_root, 32u);
    return request;
}

static bool rpe_fixture_init(struct rpe_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    zcl_retrieval_profile_init(&fixture->parent_profile);
    fixture->parent_profile.feature_mask = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    fixture->parent_profile.weight_bp[ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES] =
        100u;
    fixture->parent_profile.rerank_window = 3u;
    fixture->parent_profile.top_k = 3u;
    fixture->parent_profile.context_byte_scale = 1u;

    fixture->rows[0] = (struct zcl_retrieval_feature_row_v1){
        .path = "cognition/a.c", .context_bytes = 300u,
        .original_bm25_rank = 1u,
        .observed_features = ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES),
    };
    fixture->rows[1] = (struct zcl_retrieval_feature_row_v1){
        .path = "cognition/b.c", .context_bytes = 100u,
        .original_bm25_rank = 2u,
        .observed_features = ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES),
    };
    fixture->rows[2] = (struct zcl_retrieval_feature_row_v1){
        .path = "cognition/c.c", .context_bytes = 200u,
        .original_bm25_rank = 3u,
        .observed_features = ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES),
    };
    fixture->snapshot.schema_version =
        ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION;
    fixture->snapshot.row_count = 3u;
    fixture->snapshot.ranking_complete = true;
    fixture->snapshot.available_features = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    rpe_root(fixture->snapshot.source_root, 1u);
    rpe_root(fixture->snapshot.codeindex_root, 2u);
    if (zcl_retrieval_query_root(
            "rank bounded context files", fixture->snapshot.query_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;
    rpe_root(fixture->snapshot.extractor_root, 4u);
    const struct zcl_retrieval_ranked_file baseline[3] = {
        {"cognition/a.c", 300u, false, false},
        {"cognition/b.c", 100u, false, false},
        {"cognition/c.c", 200u, false, false},
    };
    if (!zcl_retrieval_ranked_files_root(
            baseline, 3u, true,
            fixture->snapshot.baseline_ranking_root))
        return false;

    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_profile_report parent_projection;
    uint8_t parent_profile_root[32], feature_snapshot_root[32];
    if (zcl_retrieval_profile_project(
            &fixture->parent_profile, &fixture->snapshot, fixture->rows,
            indices, ZCL_RETRIEVAL_EVAL_RANK_MAX, &parent_projection) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_profile_root(
            &fixture->parent_profile, parent_profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_feature_snapshot_root(
            &fixture->snapshot, fixture->rows, feature_snapshot_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK)
        return false;

    vcs_zcode_heuristic_init(&fixture->parent_heuristic);
    fixture->parent_heuristic.evaluator_count = 1u;
    rpe_root(fixture->expected_task_root, 10u);
    rpe_root(fixture->expected_source_root, 11u);
    memcpy(fixture->parent_heuristic.task_root,
           fixture->expected_task_root, 32u);
    memcpy(fixture->parent_heuristic.source_root,
           fixture->expected_source_root, 32u);
    rpe_root(fixture->parent_heuristic.agent_context_root, 12u);
    rpe_root(fixture->parent_heuristic.ontology_context_root, 13u);
    rpe_root(fixture->parent_heuristic.applicability_root, 14u);
    memcpy(fixture->parent_heuristic.observed_features_root,
           feature_snapshot_root, 32u);
    memcpy(fixture->parent_heuristic.proposed_rule_root,
           parent_profile_root, 32u);
    memcpy(fixture->parent_heuristic.expected_effect_root,
           parent_projection.candidate_ranking_root, 32u);
    rpe_root(fixture->parent_heuristic.study_root, 16u);
    rpe_root(fixture->parent_heuristic.preregistration_root, 17u);
    rpe_root(fixture->parent_heuristic.provenance_root, 18u);
    rpe_root(fixture->parent_heuristic.evaluator_roots[0], 19u);
    if (!zcl_retrieval_profile_proposal_input_root(
            fixture->expected_source_root, fixture->snapshot.source_root,
            fixture->snapshot.codeindex_root,
            "context-scale-specialization", "rank bounded context files",
            fixture->snapshot.baseline_ranking_root, parent_profile_root,
            feature_snapshot_root,
            parent_projection.candidate_ranking_root,
            fixture->parent_heuristic.study_root,
            fixture->parent_heuristic.preregistration_root,
            fixture->parent_heuristic.evaluator_roots[0],
            fixture->parent_heuristic.proposal_input_root))
        return false;
    fixture->parent_heuristic.requested_cpu_seconds = 30u;
    fixture->parent_heuristic.requested_processes = 1u;
    fixture->parent_heuristic.requested_memory_bytes = 1024u * 1024u;
    fixture->parent_heuristic.requested_context_bytes = 4096u;
    fixture->parent_heuristic.requested_output_bytes = 4096u;
    rpe_root(fixture->candidate_provenance_root, 20u);
    return vcs_zcode_heuristic_validate(&fixture->parent_heuristic) ==
        VCS_ZCODE_ATTENTION_OK;
}

static int case_exact_specialization(void)
{
    int failures = 0;
    struct rpe_fixture fixture;
    bool ready = rpe_fixture_init(&fixture);
    struct zcode_retrieval_profile_evolution_request request =
        rpe_request(&fixture, 1000u);
    struct zcode_retrieval_profile_evolution_report report = {0};
    enum zcode_retrieval_profile_evolution_error error = ready
        ? zcode_retrieval_profile_evolution_propose(&request, &report)
        : ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL;
    RPE_CHECK("one context-scale proposal succeeds",
              ready && error == ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK);

    struct zcl_retrieval_profile_v1 reconstructed = report.candidate_profile;
    reconstructed.context_byte_scale =
        fixture.parent_profile.context_byte_scale;
    RPE_CHECK("candidate changes exactly one profile field",
              report.candidate_profile.context_byte_scale == 1000u &&
              memcmp(&reconstructed, &fixture.parent_profile,
                     sizeof(reconstructed)) == 0);
    RPE_CHECK("same snapshot produces a changed ranking",
              memcmp(report.parent_projection.feature_snapshot_root,
                     report.candidate_projection.feature_snapshot_root,
                     32u) == 0 &&
              memcmp(report.parent_projection.candidate_ranking_root,
                     report.candidate_projection.candidate_ranking_root,
                     32u) != 0);
    RPE_CHECK("child binds exact parent lineage",
              report.candidate_heuristic.derivation ==
                  VCS_ZCODE_HEURISTIC_SPECIALIZE &&
              report.candidate_heuristic.parent_count == 1u &&
              memcmp(report.candidate_heuristic.parent_roots[0],
                     report.parent_heuristic_root, 32u) == 0 &&
              vcs_zcode_heuristic_validate_derivation(
                  &report.candidate_heuristic,
                  &fixture.parent_heuristic, 1u) ==
                  VCS_ZCODE_ATTENTION_OK);
    RPE_CHECK("child binds profile snapshot effect and proposal",
              memcmp(report.candidate_heuristic.proposed_rule_root,
                     report.candidate_profile_root, 32u) == 0 &&
              memcmp(report.candidate_heuristic.observed_features_root,
                     report.feature_snapshot_root, 32u) == 0 &&
              memcmp(report.candidate_heuristic.expected_effect_root,
                     report.candidate_projection.candidate_ranking_root,
                     32u) == 0 &&
              memcmp(report.candidate_heuristic.proposal_input_root,
                     report.proposal_input_root, 32u) == 0);
    uint8_t canonical_proposal[32];
    bool canonical = zcl_retrieval_profile_proposal_input_root(
        request.expected_source_root, fixture.snapshot.source_root,
        fixture.snapshot.codeindex_root, request.task_id, request.query,
        fixture.snapshot.baseline_ranking_root,
        report.candidate_profile_root, report.feature_snapshot_root,
        report.candidate_projection.candidate_ranking_root,
        fixture.parent_heuristic.study_root,
        fixture.parent_heuristic.preregistration_root,
        request.proposal_evaluator_root, canonical_proposal);
    RPE_CHECK("child reuses canonical profile proposal identity",
              canonical && memcmp(canonical_proposal,
                                  report.proposal_input_root, 32u) == 0);
    RPE_CHECK("science evaluator applicability and budgets stay frozen",
              memcmp(report.candidate_heuristic.study_root,
                     fixture.parent_heuristic.study_root, 32u) == 0 &&
              memcmp(report.candidate_heuristic.preregistration_root,
                     fixture.parent_heuristic.preregistration_root, 32u) == 0 &&
              memcmp(report.candidate_heuristic.evaluator_roots,
                     fixture.parent_heuristic.evaluator_roots,
                     sizeof(report.candidate_heuristic.evaluator_roots)) == 0 &&
              memcmp(report.candidate_heuristic.applicability_root,
                     fixture.parent_heuristic.applicability_root, 32u) == 0 &&
              report.candidate_heuristic.requested_context_bytes ==
                  fixture.parent_heuristic.requested_context_bytes);
    RPE_CHECK("quality stays unknown and attention stays incomplete",
              report.evaluation_status == ZCL_ONTOLOGY_UNKNOWN &&
              report.attention_status == ZCL_ONTOLOGY_INCOMPLETE &&
              report.missing_attention_metrics ==
                  VCS_ZCODE_ATTENTION_METRIC_REQUIRED);
    return failures;
}

static int case_refusals_are_atomic(void)
{
    int failures = 0;
    struct rpe_fixture fixture;
    bool ready = rpe_fixture_init(&fixture);
    struct zcode_retrieval_profile_evolution_request request =
        rpe_request(&fixture, 1000u);
    struct zcode_retrieval_profile_evolution_report sentinel;
    memset(&sentinel, 0xa5, sizeof(sentinel));
    struct zcode_retrieval_profile_evolution_report unchanged = sentinel;

    request.candidate_context_byte_scale = 2u;
    RPE_CHECK("different parameter with unchanged ranking is no effect",
              ready && zcode_retrieval_profile_evolution_propose(
                  &request, &sentinel) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_NO_EFFECT &&
              memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    request = rpe_request(&fixture, fixture.parent_profile.context_byte_scale);
    RPE_CHECK("identical parameter is not an experiment",
              zcode_retrieval_profile_evolution_propose(&request, &sentinel) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_PARAMETER &&
              memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    request = rpe_request(&fixture, 1000u);
    memcpy(request.expected_source_root,
           fixture.snapshot.source_root, 32u);
    RPE_CHECK("stale source generation is refused",
              zcode_retrieval_profile_evolution_propose(&request, &sentinel) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING &&
              memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    request = rpe_request(&fixture, 1000u);
    request.query = "";
    RPE_CHECK("empty proposal identity is refused",
              zcode_retrieval_profile_evolution_propose(&request, &sentinel) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_PARAMETER &&
              memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    request = rpe_request(&fixture, 1000u);
    request.query = "different query bytes";
    RPE_CHECK("query substitution is refused",
              zcode_retrieval_profile_evolution_propose(&request, &sentinel) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING &&
              memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    request = rpe_request(&fixture, 1000u);
    request.proposal_evaluator_root[0] ^= 1u;
    RPE_CHECK("proposal evaluator substitution is refused",
              zcode_retrieval_profile_evolution_propose(&request, &sentinel) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING &&
              memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);

    union {
        struct zcode_retrieval_profile_evolution_report report;
        struct rpe_fixture fixture;
    } aliased;
    ready = rpe_fixture_init(&aliased.fixture);
    request = rpe_request(&aliased.fixture, 1000u);
    RPE_CHECK("output/input alias is refused without mutation",
              ready && zcode_retrieval_profile_evolution_propose(
                  &request, &aliased.report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_ALIAS);
    return failures;
}

static int case_binding_mutations(void)
{
    int failures = 0;
    struct rpe_fixture fixture;
    bool ready = rpe_fixture_init(&fixture);
    struct zcode_retrieval_profile_evolution_report report;
    struct zcode_retrieval_profile_evolution_request request;

#define MUTATION_REFUSED(label_, field_) do {                            \
    struct rpe_fixture changed = fixture;                                \
    changed.parent_heuristic.field_[0] ^= 1u;                            \
    request = rpe_request(&changed, 1000u);                              \
    RPE_CHECK((label_), ready &&                                         \
        zcode_retrieval_profile_evolution_propose(&request, &report) ==  \
            ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING);                  \
} while (0)
    MUTATION_REFUSED("wrong parent profile root is refused",
                     proposed_rule_root);
    MUTATION_REFUSED("wrong parent snapshot root is refused",
                     observed_features_root);
    MUTATION_REFUSED("wrong parent ranking root is refused",
                     expected_effect_root);
#undef MUTATION_REFUSED

    struct rpe_fixture malformed_no_effect = fixture;
    malformed_no_effect.parent_heuristic.proposed_rule_root[0] ^= 1u;
    request = rpe_request(&malformed_no_effect, 2u);
    RPE_CHECK("invalid binding is never masked as no effect",
              zcode_retrieval_profile_evolution_propose(&request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING);

    struct rpe_fixture stale_snapshot = fixture;
    stale_snapshot.snapshot.source_root[0] ^= 1u;
    request = rpe_request(&stale_snapshot, 1000u);
    RPE_CHECK("cross-generation snapshot replay is refused",
              zcode_retrieval_profile_evolution_propose(&request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING);

    struct rpe_fixture coherent_stale = fixture;
    coherent_stale.snapshot.source_root[0] ^= 1u;
    uint8_t stale_snapshot_root[32];
    bool stale_rooted = zcl_retrieval_feature_snapshot_root(
        &coherent_stale.snapshot, coherent_stale.rows,
        stale_snapshot_root) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    if (stale_rooted)
        memcpy(coherent_stale.parent_heuristic.observed_features_root,
               stale_snapshot_root, 32u);
    request = rpe_request(&coherent_stale, 1000u);
    memcpy(request.expected_snapshot_source_root,
           fixture.snapshot.source_root, 32u);
    RPE_CHECK("coherent stale snapshot still misses expected generation",
              stale_rooted && zcode_retrieval_profile_evolution_propose(
                  &request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING);

    struct rpe_fixture incomplete = fixture;
    incomplete.snapshot.available_features = 0u;
    for (size_t i = 0; i < incomplete.snapshot.row_count; i++)
        incomplete.rows[i].observed_features = 0u;
    request = rpe_request(&incomplete, 1000u);
    RPE_CHECK("missing feature evidence remains incomplete",
              zcode_retrieval_profile_evolution_propose(&request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_INCOMPLETE);

    struct rpe_fixture null_path = fixture;
    null_path.rows[1].path = NULL;
    request = rpe_request(&null_path, 1000u);
    RPE_CHECK("null feature path fails closed without a crash",
              zcode_retrieval_profile_evolution_propose(&request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_RETRIEVAL);

    struct zcode_retrieval_profile_evolution_report first;
    request = rpe_request(&fixture, 1000u);
    bool proposed = zcode_retrieval_profile_evolution_propose(
        &request, &first) == ZCODE_RETRIEVAL_PROFILE_EVOLUTION_OK;
    struct rpe_fixture swapped = fixture;
    swapped.parent_profile = first.candidate_profile;
    request = rpe_request(&swapped, 1u);
    RPE_CHECK("parent and candidate profile swap is refused",
              proposed && zcode_retrieval_profile_evolution_propose(
                  &request, &report) ==
                  ZCODE_RETRIEVAL_PROFILE_EVOLUTION_BINDING);
    return failures;
}

int test_retrieval_profile_evolution(void)
{
    int failures = 0;
    failures += case_exact_specialization();
    failures += case_refusals_are_atomic();
    failures += case_binding_mutations();
    printf("retrieval_profile_evolution: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
