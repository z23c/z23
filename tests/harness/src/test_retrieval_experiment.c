/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "retrieval/retrieval_experiment.h"

#include <stdio.h>
#include <string.h>

#define RX_CHECK(name, expression)                                      \
    do {                                                                \
        const bool rx_ok_ = (expression);                               \
        printf("retrieval_experiment: %s %s\n",                        \
               rx_ok_ ? "OK  " : "FAIL", (name));                     \
        if (!rx_ok_) failures++;                                        \
    } while (0)

static void rx_rows(struct zcl_retrieval_ranked_file *rows,
                    char paths[][8], size_t count)
{
    for (size_t i = 0; i < count; i++) {
        (void)snprintf(paths[i], 8u, "f%02zu.c", i);
        rows[i].path = paths[i];
        rows[i].context_bytes = 100u;
        rows[i].in_scope = (i & 1u) != 0;
        rows[i].in_scope_available = true;
    }
}

static bool same_order(const struct zcl_retrieval_ranked_file *left,
                       const struct zcl_retrieval_ranked_file *right,
                       size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(left[i].path, right[i].path) != 0) return false;
    return true;
}

static int case_projection(void)
{
    int failures = 0;
    char paths[20][8];
    struct zcl_retrieval_ranked_file bm25[20], parent[20], out[20];
    rx_rows(bm25, paths, 20u);
    const size_t order[20] = {
        5, 6, 0, 1, 2, 3, 4, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    };
    for (size_t i = 0; i < 20u; i++) parent[i] = bm25[order[i]];
    struct zcl_retrieval_experiment_report report;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_project(
            bm25, 20u, true, parent, 20u, true, 3u, out, 20u, &report);
    RX_CHECK("prefix-three projection succeeds",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK);
    RX_CHECK("BM25 prefix is exact",
             strcmp(out[0].path, "f00.c") == 0 &&
             strcmp(out[1].path, "f01.c") == 0 &&
             strcmp(out[2].path, "f02.c") == 0);
    RX_CHECK("graph order fills only remaining slots",
             strcmp(out[3].path, "f05.c") == 0 &&
             strcmp(out[4].path, "f06.c") == 0);
    RX_CHECK("byte ceiling is preserved",
             report.bm25_context_bytes_at_5 == 500u &&
             report.candidate_context_bytes_at_5 == 500u);
    RX_CHECK("scope labels are not propagated", !out[0].in_scope_available &&
             !out[1].in_scope_available && !out[2].in_scope_available);

    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, true, 0u, out, 20u, &report);
    RX_CHECK("zero prefix is the unchanged parent",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             same_order(out, parent, 20u) && !report.used_bm25_fallback);
    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, true, 5u, out, 20u, &report);
    RX_CHECK("five prefix restores the exact BM25 top five",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             same_order(out, bm25, 5u));
    return failures;
}

static int case_guard_and_refusals(void)
{
    int failures = 0;
    char paths[20][8];
    struct zcl_retrieval_ranked_file bm25[20], parent[20], out[20];
    rx_rows(bm25, paths, 20u);
    const size_t order[20] = {
        5, 0, 1, 2, 3, 4, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    };
    for (size_t i = 0; i < 20u; i++) parent[i] = bm25[order[i]];
    parent[0].context_bytes = 300u;
    bm25[5].context_bytes = 300u;
    struct zcl_retrieval_experiment_report report;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_project(
            bm25, 20u, true, parent, 20u, true, 1u, out, 20u, &report);
    RX_CHECK("greedy byte dead-end falls back deterministically",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             report.used_bm25_fallback && same_order(out, bm25, 20u));

    parent[0].context_bytes++;
    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, true, 1u, out, 20u, &report);
    RX_CHECK("path/context mutation is refused",
             error == ZCL_RETRIEVAL_EXPERIMENT_BINDING);
    parent[0].context_bytes--;
    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, false, 1u, out, 20u, &report);
    RX_CHECK("ranking completeness mutation is refused",
             error == ZCL_RETRIEVAL_EXPERIMENT_SHAPE);
    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, true, 6u, out, 20u, &report);
    RX_CHECK("a second heuristic parameter cannot be smuggled in",
             error == ZCL_RETRIEVAL_EXPERIMENT_PARAMETER);

    rx_rows(bm25, paths, 20u);
    for (size_t i = 0; i < 20u; i++) parent[i] = bm25[i];
    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, true, 3u, bm25, 20u, &report);
    RX_CHECK("exact output/input alias is refused",
             error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS);
    error = zcl_retrieval_experiment_project(
        bm25, 20u, true, parent, 20u, true, 3u, parent + 1u, 20u,
        &report);
    RX_CHECK("partial output/input alias is refused",
             error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS);

    char paths21[21][8];
    struct zcl_retrieval_ranked_file bm25_21[21], parent_21[21], out_21[21];
    rx_rows(bm25_21, paths21, 21u);
    for (size_t i = 0; i < 21u; i++) parent_21[i] = bm25_21[i];
    struct zcl_retrieval_ranked_file swap = parent_21[19];
    parent_21[19] = parent_21[20];
    parent_21[20] = swap;
    error = zcl_retrieval_experiment_project(
        bm25_21, 21u, true, parent_21, 21u, true, 3u, out_21, 21u,
        &report);
    RX_CHECK("top-20 membership mismatch is refused",
             error == ZCL_RETRIEVAL_EXPERIMENT_BINDING);
    return failures;
}

static int case_roots_exclude_gold(void)
{
    int failures = 0;
    uint8_t source[32] = {1}, codeindex[32] = {2}, bm25[32] = {3};
    uint8_t parent[32] = {4}, study[32] = {5}, prereg[32] = {6};
    uint8_t evaluator[32] = {7}, first[32], second[32], changed[32];
    const char *reviewed_gold_before = "lib/a.c";
    const char *reviewed_gold_after = "lib/b.c";
    bool ok = zcl_retrieval_experiment_proposal_input_root(
        source, codeindex, "task", "query", bm25, parent, 3u, study,
        prereg, evaluator, first);
    /* Gold is intentionally not an argument to the proposal-root API. */
    (void)reviewed_gold_before;
    ok = ok && zcl_retrieval_experiment_proposal_input_root(
        source, codeindex, "task", "query", bm25, parent, 3u, study,
        prereg, evaluator, second);
    (void)reviewed_gold_after;
    RX_CHECK("gold mutation has no proposal-input channel",
             ok && memcmp(first, second, 32u) == 0);
    ok = zcl_retrieval_experiment_proposal_input_root(
        source, codeindex, "task", "query", bm25, parent, 4u, study,
        prereg, evaluator, changed);
    RX_CHECK("the sole scalar parameter is root-bound",
             ok && memcmp(first, changed, 32u) != 0);
    codeindex[0]++;
    ok = zcl_retrieval_experiment_proposal_input_root(
        source, codeindex, "task", "query", bm25, parent, 3u, study,
        prereg, evaluator, changed);
    RX_CHECK("retrieval projection root is proposal-bound",
             ok && memcmp(first, changed, 32u) != 0);
    codeindex[0]--;
    study[0]++;
    ok = zcl_retrieval_experiment_proposal_input_root(
        source, codeindex, "task", "query", bm25, parent, 3u, study,
        prereg, evaluator, changed);
    RX_CHECK("science roots are proposal-bound",
             ok && memcmp(first, changed, 32u) != 0);
    study[0]--;

    uint8_t zero[32] = {0};
    memset(changed, 0xa5, sizeof(changed));
    RX_CHECK("zero evidence root is refused without a false root",
             !zcl_retrieval_experiment_proposal_input_root(
                 zero, codeindex, "task", "query", bm25, parent, 3u,
                 study, prereg, evaluator, changed) &&
             changed[0] == 0xa5);
    char overlong_task[130];
    memset(overlong_task, 't', sizeof(overlong_task));
    overlong_task[sizeof(overlong_task) - 1u] = '\0';
    RX_CHECK("overlong task identity is refused",
             !zcl_retrieval_experiment_proposal_input_root(
                 source, codeindex, overlong_task, "query", bm25, parent,
                 3u, study, prereg, evaluator, changed));

    memcpy(changed, source, sizeof(changed));
    ok = zcl_retrieval_experiment_proposal_input_root(
        changed, codeindex, "task", "query", bm25, parent, 3u, study,
        prereg, evaluator, changed);
    RX_CHECK("proposal root supports exact in-place source output",
             ok && memcmp(changed, first, 32u) == 0);
    return failures;
}

static int case_post_proposal_evaluation(void)
{
    int failures = 0;
    char paths[6][8];
    struct zcl_retrieval_ranked_file bm25[6], parent[6];
    rx_rows(bm25, paths, 6u);
    const size_t order[6] = {5, 0, 1, 2, 3, 4};
    for (size_t i = 0; i < 6u; i++) parent[i] = bm25[order[i]];
    bm25[5].context_bytes = 50u;
    parent[0].context_bytes = 50u;
    const char *relevant[] = {"f05.c"};
    struct zcl_retrieval_experiment_eval_task task = {
        .task_id = "task",
        .query = "find f05",
        .relevant_paths = relevant,
        .relevant_count = 1u,
        .bm25 = bm25,
        .bm25_count = 6u,
        .bm25_complete = true,
        .parent = parent,
        .parent_count = 6u,
        .parent_complete = true,
    };
    struct zcl_retrieval_experiment_eval_report report;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_experiment_evaluate(&task, 1u, 0u, &report);
    RX_CHECK("post-proposal gold evaluates the unchanged parent",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             report.metrics.recall_at_5_available &&
             report.metrics.recall_at_5_bp == 10000u &&
             !report.metrics.wrong_scope_at_5_available &&
             report.context_ceiling_preserved);
    error = zcl_retrieval_experiment_evaluate(&task, 1u, 5u, &report);
    RX_CHECK("prefix-five evaluation restores the BM25 observation",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             report.metrics.recall_at_5_available &&
             report.metrics.recall_at_5_bp == 0u);
    const char *bad_relevant[] = {"f05.c", "f05.c"};
    task.relevant_paths = bad_relevant;
    task.relevant_count = 2u;
    memset(&report, 0xa5, sizeof(report));
    error = zcl_retrieval_experiment_evaluate(&task, 1u, 0u, &report);
    RX_CHECK("malformed independent gold is refused without stale metrics",
             error == ZCL_RETRIEVAL_EXPERIMENT_EVALUATION &&
             report.metrics.tasks == 0u &&
             !report.top20_membership_preserved);
    error = zcl_retrieval_experiment_evaluate(&task, 1u, 6u, &report);
    RX_CHECK("evaluation cannot widen the registered parameter range",
             error == ZCL_RETRIEVAL_EXPERIMENT_PARAMETER);
    task.relevant_paths = relevant;
    task.relevant_count =
        ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX + 1u;
    error = zcl_retrieval_experiment_evaluate(&task, 1u, 0u, &report);
    RX_CHECK("direct callers cannot create unbounded relevance work",
             error == ZCL_RETRIEVAL_EXPERIMENT_SHAPE);
    task.relevant_count = 1u;
    union {
        struct zcl_retrieval_experiment_eval_task task;
        struct zcl_retrieval_experiment_eval_report report;
    } alias = {.task = task};
    error = zcl_retrieval_experiment_evaluate(
        &alias.task, 1u, 0u, &alias.report);
    RX_CHECK("evaluation report cannot overwrite its task input",
             error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS);
    zcl_alloc_fault_fail_next("retrieval experiment candidates");
    memset(&report, 0xa5, sizeof(report));
    error = zcl_retrieval_experiment_evaluate(&task, 1u, 0u, &report);
    RX_CHECK("candidate allocation failure is observed and clears output",
             error == ZCL_RETRIEVAL_EXPERIMENT_ALLOCATION &&
             report.metrics.tasks == 0u &&
             !report.context_ceiling_preserved);
    zcl_alloc_fault_clear();
    return failures;
}

static void rx_tag_root(uint8_t root[32], uint8_t tag)
{
    memset(root, tag, 32u);
}

static void rx_profile_fixture(struct zcl_retrieval_profile_v1 *profile)
{
    zcl_retrieval_profile_init(profile);
    profile->feature_mask =
        ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY) |
        ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY) |
        ZCL_RETRIEVAL_FEATURE_BIT(ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    profile->weight_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 100u;
    profile->weight_bp[ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY] = 100u;
    profile->weight_bp[ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES] = 1u;
    profile->identifier_df_max = 16u;
    profile->graph_depth = 1u;
    profile->rerank_window = 4u;
    profile->top_k = 2u;
    profile->context_byte_scale = 100u;
}

static bool rx_feature_fixture(
    struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    struct zcl_retrieval_feature_row_v1 rows[4])
{
    static const char *const paths[] = {
        "lib/a.c", "lib/b.c", "lib/c.c", "lib/d.c",
    };
    const uint16_t available =
        ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY) |
        ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY) |
        ZCL_RETRIEVAL_FEATURE_BIT(ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    memset(snapshot, 0, sizeof(*snapshot));
    memset(rows, 0, 4u * sizeof(*rows));
    snapshot->schema_version = ZCL_RETRIEVAL_FEATURE_SNAPSHOT_VERSION;
    snapshot->row_count = 4u;
    snapshot->ranking_complete = true;
    snapshot->available_features = available;
    snapshot->identifier_df_max = 16u;
    snapshot->graph_depth = 1u;
    rx_tag_root(snapshot->source_root, 1u);
    rx_tag_root(snapshot->codeindex_root, 2u);
    rx_tag_root(snapshot->query_root, 3u);
    rx_tag_root(snapshot->extractor_root, 4u);
    struct zcl_retrieval_ranked_file baseline[4];
    for (size_t i = 0; i < 4u; i++) {
        rows[i].path = paths[i];
        rows[i].context_bytes = 100u;
        rows[i].original_bm25_rank = (uint16_t)i + 1u;
        rows[i].observed_features = available;
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = paths[i], .context_bytes = 100u,
        };
    }
    rows[0].feature_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 1000u;
    rows[1].feature_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 9000u;
    rows[2].feature_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 8000u;
    rows[3].feature_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 500u;
    rows[2].feature_bp[ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY] = 500u;
    return zcl_retrieval_ranked_files_root(
        baseline, 4u, true, snapshot->baseline_ranking_root);
}

static bool rx_rebind_baseline(
    struct zcl_retrieval_feature_snapshot_v1 *snapshot,
    const struct zcl_retrieval_feature_row_v1 rows[4])
{
    struct zcl_retrieval_ranked_file baseline[4];
    for (size_t i = 0; i < 4u; i++)
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = rows[i].path,
            .context_bytes = rows[i].context_bytes,
        };
    return zcl_retrieval_ranked_files_root(
        baseline, 4u, snapshot->ranking_complete,
        snapshot->baseline_ranking_root);
}

static int case_integer_profile_identity(void)
{
    int failures = 0;
    static const uint8_t expected_root[32] = {
        0x2d, 0x62, 0xcc, 0x11, 0x71, 0xe1, 0x75, 0xcd,
        0xf6, 0x29, 0x16, 0x01, 0xf7, 0x49, 0x35, 0xd0,
        0x8c, 0x69, 0x9d, 0xcc, 0x01, 0xf2, 0xaa, 0xfa,
        0xc0, 0x19, 0xba, 0xaa, 0xc0, 0x0a, 0x48, 0x3f,
    };
    struct zcl_retrieval_profile_v1 profile, parsed;
    rx_profile_fixture(&profile);
    uint8_t wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES];
    uint8_t root[32], changed[32];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_serialize(&profile, wire);
    RX_CHECK("integer profile has exact fixed wire",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             memcmp(wire, "ZCRPRO1\n", 8u) == 0 &&
             wire[8] == 1u && wire[9] == 0u &&
             wire[43] == 4u && wire[44] == 2u &&
             zcl_retrieval_profile_parse(wire, sizeof(wire), &parsed) ==
                 ZCL_RETRIEVAL_EXPERIMENT_OK &&
             memcmp(&profile, &parsed, sizeof(profile)) == 0);
    bool rooted = zcl_retrieval_profile_root(&profile, root) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("profile root matches fixed canonical SHA3 vector",
             rooted && memcmp(root, expected_root, sizeof(root)) == 0);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY]++;
    rooted = rooted && zcl_retrieval_profile_root(&profile, changed) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("active weight changes canonical profile root",
             rooted && memcmp(root, changed, 32u) != 0);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY]--;
    profile.identifier_df_max++;
    rooted = zcl_retrieval_profile_root(&profile, changed) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("rarity scope is root-bound",
             rooted && memcmp(root, changed, 32u) != 0);
    profile.identifier_df_max--;
    profile.graph_depth++;
    rooted = zcl_retrieval_profile_root(&profile, changed) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("graph depth is root-bound",
             rooted && memcmp(root, changed, 32u) != 0);
    profile.graph_depth--;
    profile.context_byte_scale++;
    rooted = zcl_retrieval_profile_root(&profile, changed) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("context scale is root-bound",
             rooted && memcmp(root, changed, 32u) != 0);
    profile.context_byte_scale--;
    profile.reserved = 1u;
    RX_CHECK("reserved profile state is refused",
             zcl_retrieval_profile_validate(&profile) ==
                 ZCL_RETRIEVAL_EXPERIMENT_RESERVED);
    profile.reserved = 0u;
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 1u;
    RX_CHECK("inactive nonzero weight is refused",
             zcl_retrieval_profile_validate(&profile) ==
                 ZCL_RETRIEVAL_EXPERIMENT_PARAMETER);
    wire[0] ^= 1u;
    memset(&parsed, 0xa5, sizeof(parsed));
    RX_CHECK("bad profile magic clears parsed output",
             zcl_retrieval_profile_parse(wire, sizeof(wire), &parsed) ==
                 ZCL_RETRIEVAL_EXPERIMENT_WIRE_SIZE &&
             parsed.schema_version == 0u);
    return failures;
}

static int case_feature_snapshot_and_projection(void)
{
    int failures = 0;
    static const uint8_t expected_root[32] = {
        0x68, 0x99, 0x7d, 0x7d, 0x83, 0xdd, 0x00, 0x45,
        0x75, 0x55, 0xd4, 0x12, 0x9a, 0xe7, 0xfd, 0xd2,
        0x63, 0x0f, 0x8f, 0x43, 0x98, 0x65, 0xde, 0x78,
        0x5c, 0x6e, 0x7f, 0xfb, 0x33, 0x7b, 0x24, 0xba,
    };
    struct zcl_retrieval_profile_v1 profile;
    struct zcl_retrieval_feature_snapshot_v1 snapshot;
    struct zcl_retrieval_feature_row_v1 rows[4];
    bool fixture = rx_feature_fixture(&snapshot, rows);
    rx_profile_fixture(&profile);
    uint8_t root[32], changed[32];
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_feature_snapshot_root(&snapshot, rows, root);
    RX_CHECK("snapshot root matches fixed canonical SHA3 vector",
             fixture && error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             memcmp(root, expected_root, sizeof(root)) == 0);
    rows[2].feature_bp[ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY]++;
    bool rerooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, changed) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("feature observation changes snapshot root",
             fixture && error == ZCL_RETRIEVAL_EXPERIMENT_OK && rerooted &&
             memcmp(root, changed, 32u) != 0);
    rows[2].feature_bp[ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY]--;
    size_t indices[4] = {99u, 99u, 99u, 99u};
    struct zcl_retrieval_profile_report report;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("integer profile deterministically reranks the bounded window",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             indices[0] == 1u && indices[1] == 2u &&
             report.changed_positions_at_top == 2u &&
             report.baseline_context_bytes_at_top == 200u &&
             report.candidate_context_bytes_at_top == 200u &&
             report.retained_set_preserved &&
             !report.used_baseline_fallback);

    const uint16_t package = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PACKAGE_OWNERSHIP);
    profile.feature_mask |= package;
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PACKAGE_OWNERSHIP] = 7u;
    snapshot.available_features |= package;
    for (size_t i = 0; i < 4u; i++) rows[i].observed_features |= package;
    rows[3].feature_bp[ZCL_RETRIEVAL_FEATURE_PACKAGE_OWNERSHIP] = 10000u;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("benefit after context penalty uses checked signed arithmetic",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK && indices[0] == 1u);
    profile.feature_mask &= (uint16_t)~package;
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PACKAGE_OWNERSHIP] = 0u;
    snapshot.available_features &= (uint16_t)~package;
    for (size_t i = 0; i < 4u; i++) {
        rows[i].observed_features &= (uint16_t)~package;
        rows[i].feature_bp[ZCL_RETRIEVAL_FEATURE_PACKAGE_OWNERSHIP] = 0u;
    }

    struct zcl_retrieval_profile_report sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    report = sentinel;
    size_t untouched[4] = {91u, 92u, 93u, 94u};
    const uint16_t graph = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY);
    for (size_t i = 0; i < 4u; i++) {
        rows[i].observed_features &= (uint16_t)~graph;
        rows[i].feature_bp[ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY] = 0;
    }
    snapshot.available_features &= (uint16_t)~graph;
    snapshot.saturated_features = graph;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, untouched, 4u, &report);
    RX_CHECK("saturated required evidence is incomplete and atomic",
             error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE &&
             untouched[0] == 91u &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    (void)rx_feature_fixture(&snapshot, rows);
    rows[2].context_bytes = 150u;
    rows[3].context_bytes = 150u;
    (void)rx_rebind_baseline(&snapshot, rows);
    rows[2].feature_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 10000u;
    rows[3].feature_bp[ZCL_RETRIEVAL_FEATURE_IDENTIFIER_RARITY] = 9000u;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("byte-ceiling dead end falls back to exact baseline",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             report.used_baseline_fallback &&
             indices[0] == 0u && indices[1] == 1u);
    rows[0].path = "../escape.c";
    RX_CHECK("noncanonical feature path is refused",
             zcl_retrieval_feature_snapshot_root(&snapshot, rows, changed) ==
                 ZCL_RETRIEVAL_EXPERIMENT_BINDING);
    return failures;
}

static int case_feature_refusals_and_aliases(void)
{
    int failures = 0;
    struct zcl_retrieval_profile_v1 profile;
    struct zcl_retrieval_feature_snapshot_v1 snapshot;
    struct zcl_retrieval_feature_row_v1 rows[4];
    rx_profile_fixture(&profile);
    bool fixture = rx_feature_fixture(&snapshot, rows);
    uint8_t root[32], changed[32];
    bool rooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, root) == ZCL_RETRIEVAL_EXPERIMENT_OK;

    snapshot.identifier_df_max++;
    bool rerooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, changed) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    size_t indices[4] = {81u, 82u, 83u, 84u};
    struct zcl_retrieval_profile_report report, sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    report = sentinel;
    enum zcl_retrieval_experiment_error error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("rarity extraction scope is rooted and must match profile",
             fixture && rooted && rerooted &&
             memcmp(root, changed, sizeof(root)) != 0 &&
             error == ZCL_RETRIEVAL_EXPERIMENT_BINDING &&
             indices[0] == 81u &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    snapshot.identifier_df_max--;
    snapshot.graph_depth++;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("graph extraction scope must match profile",
             error == ZCL_RETRIEVAL_EXPERIMENT_BINDING &&
             indices[0] == 81u &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    (void)rx_feature_fixture(&snapshot, rows);
    rows[2].original_bm25_rank++;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("declared rank must equal exact baseline row order",
             error == ZCL_RETRIEVAL_EXPERIMENT_BINDING &&
             indices[0] == 81u &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    (void)rx_feature_fixture(&snapshot, rows);
    bool complete_rooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, root) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    snapshot.ranking_complete = false;
    bool rebound = rx_rebind_baseline(&snapshot, rows);
    bool incomplete_rooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, changed) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("ranking truth state changes snapshot identity",
             complete_rooted && rebound && incomplete_rooted &&
             memcmp(root, changed, sizeof(root)) != 0);

    (void)rx_feature_fixture(&snapshot, rows);
    const uint16_t graph = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY);
    snapshot.available_features &= (uint16_t)~graph;
    snapshot.graph_depth = 0u;
    for (size_t i = 0; i < 4u; i++) {
        rows[i].observed_features &= (uint16_t)~graph;
        rows[i].feature_bp[ZCL_RETRIEVAL_FEATURE_GRAPH_PROXIMITY] = 0u;
    }
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    bool missing_rooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, root) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    RX_CHECK("missing required evidence remains incomplete and atomic",
             missing_rooted && error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE &&
             indices[0] == 81u &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);
    snapshot.saturated_features = graph;
    snapshot.graph_depth = 1u;
    bool saturated_rooted = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, changed) == ZCL_RETRIEVAL_EXPERIMENT_OK;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report);
    RX_CHECK("missing and saturated evidence have distinct identities",
             saturated_rooted && error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE &&
             memcmp(root, changed, sizeof(root)) != 0 &&
             indices[0] == 81u &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    (void)rx_feature_fixture(&snapshot, rows);
    rows[1].path = rows[0].path;
    RX_CHECK("duplicate snapshot paths are refused",
             zcl_retrieval_feature_snapshot_root(
                 &snapshot, rows, changed) ==
                 ZCL_RETRIEVAL_EXPERIMENT_BINDING);
    (void)rx_feature_fixture(&snapshot, rows);
    snapshot.baseline_ranking_root[0] ^= 1u;
    RX_CHECK("baseline root mismatch is refused",
             zcl_retrieval_feature_snapshot_root(
                 &snapshot, rows, changed) ==
                 ZCL_RETRIEVAL_EXPERIMENT_BINDING);

    union {
        max_align_t align;
        char path[64];
        size_t indices[8];
    } index_alias;
    (void)rx_feature_fixture(&snapshot, rows);
    (void)snprintf(index_alias.path, sizeof(index_alias.path), "lib/a.c");
    rows[0].path = index_alias.path;
    rebound = rx_rebind_baseline(&snapshot, rows);
    report = sentinel;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, index_alias.indices, 4u, &report);
    RX_CHECK("index output cannot overwrite indirect path storage",
             rebound && error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
             strcmp(index_alias.path, "lib/a.c") == 0 &&
             memcmp(&report, &sentinel, sizeof(report)) == 0);

    union {
        max_align_t align;
        char path[256];
        struct zcl_retrieval_profile_report report;
    } report_alias;
    (void)rx_feature_fixture(&snapshot, rows);
    (void)snprintf(report_alias.path, sizeof(report_alias.path), "lib/a.c");
    rows[0].path = report_alias.path;
    rebound = rx_rebind_baseline(&snapshot, rows);
    indices[0] = 81u;
    error = zcl_retrieval_profile_project(
        &profile, &snapshot, rows, indices, 4u, &report_alias.report);
    RX_CHECK("report output cannot overwrite indirect path storage",
             rebound && error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
             strcmp(report_alias.path, "lib/a.c") == 0 &&
             indices[0] == 81u);

    union {
        max_align_t align;
        char path[64];
        uint8_t root[32];
    } root_alias;
    (void)rx_feature_fixture(&snapshot, rows);
    (void)snprintf(root_alias.path, sizeof(root_alias.path), "lib/a.c");
    rows[0].path = root_alias.path;
    rebound = rx_rebind_baseline(&snapshot, rows);
    error = zcl_retrieval_feature_snapshot_root(
        &snapshot, rows, root_alias.root);
    RX_CHECK("snapshot root cannot overwrite indirect path storage",
             rebound && error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
             strcmp(root_alias.path, "lib/a.c") == 0);
    return failures;
}

static int case_context_snapshot_and_profile_proposal(void)
{
    int failures = 0;
    uint8_t roots[10][32];
    for (size_t i = 0; i < 10u; i++) rx_tag_root(roots[i], (uint8_t)i + 1u);
    char paths[2][8];
    struct zcl_retrieval_ranked_file baseline[2];
    rx_rows(baseline, paths, 2u);
    struct zcl_retrieval_feature_snapshot_v1 snapshot, sentinel;
    struct zcl_retrieval_feature_row_v1 rows[2], rows_sentinel[2];
    memset(&sentinel, 0xa5, sizeof(sentinel));
    memset(rows_sentinel, 0x5a, sizeof(rows_sentinel));
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_context_feature_snapshot(
            roots[1], roots[2], "query", baseline, 2u, true,
            &snapshot, rows, 2u);
    RX_CHECK("context extractor seals only exact context-byte observations",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             snapshot.available_features == ZCL_RETRIEVAL_FEATURE_BIT(
                 ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES) &&
             rows[0].context_bytes == baseline[0].context_bytes &&
             rows[0].observed_features == snapshot.available_features);

    snapshot = sentinel;
    memcpy(rows, rows_sentinel, sizeof(rows));
    error = zcl_retrieval_context_feature_snapshot(
        roots[1], roots[2], "query", baseline, 2u, true,
        &snapshot, rows, 1u);
    RX_CHECK("context extractor capacity refusal is atomic",
             error == ZCL_RETRIEVAL_EXPERIMENT_CAPACITY &&
             memcmp(&snapshot, &sentinel, sizeof(snapshot)) == 0 &&
             memcmp(rows, rows_sentinel, sizeof(rows)) == 0);

    union {
        max_align_t align;
        char path[128];
        struct zcl_retrieval_feature_row_v1 rows[2];
    } alias;
    (void)snprintf(alias.path, sizeof(alias.path), "lib/a.c");
    baseline[0].path = alias.path;
    snapshot = sentinel;
    error = zcl_retrieval_context_feature_snapshot(
        roots[1], roots[2], "query", baseline, 2u, true,
        &snapshot, alias.rows, 2u);
    RX_CHECK("context extractor cannot overwrite indirect path storage",
             error == ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
             strcmp(alias.path, "lib/a.c") == 0 &&
             memcmp(&snapshot, &sentinel, sizeof(snapshot)) == 0);

    uint8_t first[32], changed[32];
    bool ok = zcl_retrieval_profile_proposal_input_root(
        roots[0], roots[1], roots[2], "task", "query", roots[3], roots[4],
        roots[5], roots[6], roots[7], roots[8], roots[9], first);
    bool all_bound = ok;
    for (size_t i = 0; i < 10u; i++) {
        roots[i][0] ^= 0x80u;
        all_bound = all_bound && zcl_retrieval_profile_proposal_input_root(
            roots[0], roots[1], roots[2], "task", "query", roots[3],
            roots[4], roots[5], roots[6], roots[7], roots[8], roots[9],
            changed) && memcmp(first, changed, 32u) != 0;
        roots[i][0] ^= 0x80u;
    }
    RX_CHECK("profile proposal binds every supplied evidence root", all_bound);
    ok = zcl_retrieval_profile_proposal_input_root(
        roots[0], roots[1], roots[2], "task-2", "query", roots[3], roots[4],
        roots[5], roots[6], roots[7], roots[8], roots[9], changed);
    RX_CHECK("profile proposal binds task identity",
             ok && memcmp(first, changed, 32u) != 0);
    memset(changed, 0xa5, sizeof(changed));
    memset(roots[0], 0, sizeof(roots[0]));
    RX_CHECK("profile proposal refuses zero roots atomically",
             !zcl_retrieval_profile_proposal_input_root(
                 roots[0], roots[1], roots[2], "task", "query", roots[3],
                 roots[4], roots[5], roots[6], roots[7], roots[8], roots[9],
                 changed) && changed[0] == 0xa5);
    return failures;
}

static int case_frozen_profile_replay(void)
{
    int failures = 0;
    char paths[6][8];
    struct zcl_retrieval_ranked_file baseline[6];
    rx_rows(baseline, paths, 6u);
    const uint64_t bytes[6] = {30u, 40u, 50u, 60u, 70u, 5u};
    for (size_t i = 0; i < 6u; i++) baseline[i].context_bytes = bytes[i];
    struct zcl_retrieval_profile_v1 profile;
    zcl_retrieval_profile_init(&profile);
    profile.feature_mask = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES] = 1u;
    profile.rerank_window = 6u;
    profile.top_k = 5u;
    profile.context_byte_scale = 1u;
    struct zcl_retrieval_profile_replay_task_v1 task = {
        .task_id = "task",
        .query = "find smallest context",
        .baseline = baseline,
        .baseline_count = 6u,
        .baseline_complete = true,
    };
    struct zcl_retrieval_profile_replay_candidate_v1 first, second;
    struct zcl_retrieval_profile_replay_report_v1 report, repeated;
    enum zcl_retrieval_experiment_error error =
        zcl_retrieval_profile_replay_project(
            &profile, &task, 1u, &first, 1u, &report);
    RX_CHECK("frozen replay reranks only the sealed BM25 rows",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             report.schema_version == ZCL_RETRIEVAL_PROFILE_REPLAY_VERSION &&
             report.task_count == 1u &&
             strcmp(first.ranked[0].path, "f05.c") == 0 &&
             report.changed_positions_at_5 == 5u &&
             report.fallback_tasks == 0u &&
             report.top20_membership_preserved &&
             report.full_retained_set_preserved &&
             report.context_ceiling_preserved);
    RX_CHECK("frozen replay erases proposer scope labels",
             !first.ranked[0].in_scope_available &&
             !first.ranked[1].in_scope_available);
    error = zcl_retrieval_profile_replay_project(
        &profile, &task, 1u, &second, 1u, &repeated);
    RX_CHECK("frozen replay roots and ranking are deterministic",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             memcmp(report.replay_hypothesis_root,
                    repeated.replay_hypothesis_root, 32u) == 0 &&
             memcmp(report.candidate_batch_root,
                    repeated.candidate_batch_root, 32u) == 0 &&
             same_order(first.ranked, second.ranked, 6u));

    uint8_t original_hypothesis[32];
    memcpy(original_hypothesis, report.replay_hypothesis_root, 32u);
    baseline[5].context_bytes++;
    error = zcl_retrieval_profile_replay_project(
        &profile, &task, 1u, &second, 1u, &repeated);
    RX_CHECK("baseline evidence mutation moves replay hypothesis",
             error == ZCL_RETRIEVAL_EXPERIMENT_OK &&
             memcmp(original_hypothesis,
                    repeated.replay_hypothesis_root, 32u) != 0);
    baseline[5].context_bytes--;

    struct zcl_retrieval_profile_replay_candidate_v1 candidate_sentinel;
    struct zcl_retrieval_profile_replay_report_v1 report_sentinel;
    memset(&candidate_sentinel, 0xa5, sizeof(candidate_sentinel));
    memset(&report_sentinel, 0x5a, sizeof(report_sentinel));
    first = candidate_sentinel;
    report = report_sentinel;
    profile.top_k = 4u;
    error = zcl_retrieval_profile_replay_project(
        &profile, &task, 1u, &first, 1u, &report);
    RX_CHECK("fixed at-five evidence refuses another top-k atomically",
             error == ZCL_RETRIEVAL_EXPERIMENT_PARAMETER &&
             memcmp(&first, &candidate_sentinel, sizeof(first)) == 0 &&
             memcmp(&report, &report_sentinel, sizeof(report)) == 0);
    profile.top_k = 5u;
    profile.feature_mask |= ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PATH);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 1u;
    error = zcl_retrieval_profile_replay_project(
        &profile, &task, 1u, &first, 1u, &report);
    RX_CHECK("unavailable frozen feature evidence refuses atomically",
             error == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE &&
             memcmp(&first, &candidate_sentinel, sizeof(first)) == 0 &&
             memcmp(&report, &report_sentinel, sizeof(report)) == 0);
    profile.feature_mask &= (uint16_t)~ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PATH);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 0u;
    task.baseline_count = 4u;
    error = zcl_retrieval_profile_replay_project(
        &profile, &task, 1u, &first, 1u, &report);
    RX_CHECK("fewer than five replay rows cannot claim at-five evidence",
             error == ZCL_RETRIEVAL_EXPERIMENT_SHAPE &&
             memcmp(&first, &candidate_sentinel, sizeof(first)) == 0 &&
             memcmp(&report, &report_sentinel, sizeof(report)) == 0);
    task.baseline_count = 6u;
    task.task_id = "_hidden";
    error = zcl_retrieval_profile_replay_project(
        &profile, &task, 1u, &first, 1u, &report);
    RX_CHECK("noncanonical replay task identity is refused atomically",
             error == ZCL_RETRIEVAL_EXPERIMENT_SHAPE &&
             memcmp(&first, &candidate_sentinel, sizeof(first)) == 0 &&
             memcmp(&report, &report_sentinel, sizeof(report)) == 0);

    struct zcl_retrieval_profile_replay_task_v1 pair[2] = {task, task};
    pair[0].task_id = "first";
    pair[1].task_id = "_late_invalid";
    struct zcl_retrieval_profile_replay_candidate_v1 pair_candidates[2];
    struct zcl_retrieval_profile_replay_candidate_v1 pair_sentinel[2];
    memset(pair_sentinel, 0x3c, sizeof(pair_sentinel));
    memcpy(pair_candidates, pair_sentinel, sizeof(pair_candidates));
    report = report_sentinel;
    error = zcl_retrieval_profile_replay_project(
        &profile, pair, 2u, pair_candidates, 2u, &report);
    RX_CHECK("late second-task refusal preserves every output atomically",
             error == ZCL_RETRIEVAL_EXPERIMENT_SHAPE &&
             memcmp(pair_candidates, pair_sentinel,
                    sizeof(pair_candidates)) == 0 &&
             memcmp(&report, &report_sentinel, sizeof(report)) == 0);
    return failures;
}

int test_retrieval_experiment(void)
{
    int failures = 0;
    failures += case_projection();
    failures += case_guard_and_refusals();
    failures += case_roots_exclude_gold();
    failures += case_post_proposal_evaluation();
    failures += case_integer_profile_identity();
    failures += case_feature_snapshot_and_projection();
    failures += case_feature_refusals_and_aliases();
    failures += case_context_snapshot_and_profile_proposal();
    failures += case_frozen_profile_replay();
    return failures;
}
