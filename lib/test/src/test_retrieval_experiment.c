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

int test_retrieval_experiment(void)
{
    int failures = 0;
    failures += case_projection();
    failures += case_guard_and_refusals();
    failures += case_roots_exclude_gold();
    failures += case_post_proposal_evaluation();
    return failures;
}
