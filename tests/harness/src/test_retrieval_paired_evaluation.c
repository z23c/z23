/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: adversarial proof for exact paired retrieval evaluation inputs. */
#include "retrieval/retrieval_evaluation_batch.h"

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PE_CHECK(name_, expression_) do {                                  \
    if (expression_) {                                                     \
        printf("  retrieval_paired_evaluation: %s... OK\n", (name_));   \
    } else {                                                               \
        printf("  retrieval_paired_evaluation: %s... FAIL\n", (name_)); \
        failures++;                                                        \
    }                                                                      \
} while (0)

enum pe_changed_root {
    PE_WORKLOAD = 1u << 0,
    PE_PARENT = 1u << 1,
    PE_CHILD = 1u << 2,
    PE_PAIR = 1u << 3,
    PE_ALL = PE_WORKLOAD | PE_PARENT | PE_CHILD | PE_PAIR,
};

struct pe_fixture {
    uint8_t task_root[32], source_root[32], projection_root[32];
    const char *alpha_relevant[2];
    const char *beta_relevant[1];
    struct zcl_retrieval_ranked_file parent[2][3];
    struct zcl_retrieval_ranked_file child[2][3];
    struct zcl_retrieval_paired_evaluation_task_v1 tasks[2];
};

static void pe_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32u);
}

static void pe_fixture_init(struct pe_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    pe_root(fixture->task_root, 0x11u);
    pe_root(fixture->source_root, 0x22u);
    pe_root(fixture->projection_root, 0x33u);
    fixture->alpha_relevant[0] = "src/a.c";
    fixture->alpha_relevant[1] = "src/shared.c";
    fixture->beta_relevant[0] = "src/c.c";
    fixture->parent[0][0] = (struct zcl_retrieval_ranked_file){
        "src/a.c", 100u, true, true};
    fixture->parent[0][1] = (struct zcl_retrieval_ranked_file){
        "src/b.c", 200u, false, true};
    fixture->parent[0][2] = (struct zcl_retrieval_ranked_file){
        "src/shared.c", 300u, false, false};
    fixture->child[0][0] = fixture->parent[0][1];
    fixture->child[0][1] = fixture->parent[0][0];
    fixture->child[0][2] = fixture->parent[0][2];
    fixture->parent[1][0] = (struct zcl_retrieval_ranked_file){
        "src/d.c", 400u, false, true};
    fixture->parent[1][1] = (struct zcl_retrieval_ranked_file){
        "src/e.c", 500u, false, true};
    fixture->parent[1][2] = (struct zcl_retrieval_ranked_file){
        "src/c.c", 600u, true, true};
    fixture->child[1][0] = fixture->parent[1][2];
    fixture->child[1][1] = fixture->parent[1][0];
    fixture->child[1][2] = fixture->parent[1][1];
    fixture->tasks[0] = (struct zcl_retrieval_paired_evaluation_task_v1){
        .task_id = "alpha", .query = "find alpha implementation",
        .relevant_paths = fixture->alpha_relevant, .relevant_count = 2u,
        .parent_ranked = fixture->parent[0], .parent_count = 3u,
        .parent_complete = true,
        .child_ranked = fixture->child[0], .child_count = 3u,
        .child_complete = true,
    };
    fixture->tasks[1] = (struct zcl_retrieval_paired_evaluation_task_v1){
        .task_id = "beta", .query = "find beta implementation",
        .relevant_paths = fixture->beta_relevant, .relevant_count = 1u,
        .parent_ranked = fixture->parent[1], .parent_count = 3u,
        .parent_complete = true,
        .child_ranked = fixture->child[1], .child_count = 3u,
        .child_complete = true,
    };
}

static enum zcl_retrieval_experiment_error pe_evaluate(
    const struct pe_fixture *fixture,
    const struct zcl_retrieval_paired_evaluation_task_v1 *tasks,
    size_t task_count,
    struct zcl_retrieval_paired_evaluation_report_v1 *report)
{
    return zcl_retrieval_paired_evaluate(
        tasks, task_count, fixture->task_root, fixture->source_root,
        fixture->projection_root, report);
}

static void pe_workload_tasks(
    const struct pe_fixture *fixture,
    struct zcl_retrieval_evaluation_workload_task_v1 tasks[2])
{
    for (size_t i = 0; i < 2u; i++)
        tasks[i] = (struct zcl_retrieval_evaluation_workload_task_v1){
            .task_id = fixture->tasks[i].task_id,
            .query = fixture->tasks[i].query,
            .relevant_paths = fixture->tasks[i].relevant_paths,
            .relevant_count = fixture->tasks[i].relevant_count,
        };
}

static enum zcl_retrieval_experiment_error pe_workload_root(
    const struct pe_fixture *fixture,
    const struct zcl_retrieval_evaluation_workload_task_v1 *tasks,
    size_t task_count, uint8_t out[32])
{
    return zcl_retrieval_evaluation_workload_root(
        tasks, task_count, fixture->task_root, fixture->source_root,
        fixture->projection_root, out);
}

static bool pe_workload_refused(
    const struct zcl_retrieval_evaluation_workload_task_v1 *tasks,
    size_t task_count, const uint8_t task_root[32],
    const uint8_t source_root[32], const uint8_t projection_root[32])
{
    uint8_t out[32], before[32];
    memset(out, 0xa5, sizeof(out));
    memcpy(before, out, sizeof(before));
    return zcl_retrieval_evaluation_workload_root(
               tasks, task_count, task_root, source_root, projection_root,
               out) != ZCL_RETRIEVAL_EXPERIMENT_OK &&
           memcmp(out, before, sizeof(out)) == 0;
}

static bool pe_metrics_equal(const struct zcl_retrieval_eval_metrics *left,
                             const struct zcl_retrieval_eval_metrics *right)
{
    return left->tasks == right->tasks &&
        left->recall_at_5_bp == right->recall_at_5_bp &&
        left->recall_at_20_bp == right->recall_at_20_bp &&
        left->mrr_bp == right->mrr_bp &&
        left->recall_at_5_available == right->recall_at_5_available &&
        left->recall_at_20_available == right->recall_at_20_available &&
        left->mrr_available == right->mrr_available &&
        left->unique_files_at_5 == right->unique_files_at_5 &&
        left->context_bytes_at_5 == right->context_bytes_at_5 &&
        left->approximate_tokens_at_5 == right->approximate_tokens_at_5 &&
        left->wrong_scope_files_at_5 == right->wrong_scope_files_at_5 &&
        left->wrong_scope_at_5_bp == right->wrong_scope_at_5_bp &&
        left->wrong_scope_at_5_available == right->wrong_scope_at_5_available;
}

static bool pe_reports_equal(
    const struct zcl_retrieval_paired_evaluation_report_v1 *left,
    const struct zcl_retrieval_paired_evaluation_report_v1 *right)
{
    return left->schema_version == right->schema_version &&
        left->task_count == right->task_count &&
        pe_metrics_equal(&left->parent_metrics, &right->parent_metrics) &&
        pe_metrics_equal(&left->child_metrics, &right->child_metrics) &&
        memcmp(left->expected_task_root, right->expected_task_root, 32u) == 0 &&
        memcmp(left->source_root, right->source_root, 32u) == 0 &&
        memcmp(left->retrieval_projection_root,
               right->retrieval_projection_root, 32u) == 0 &&
        memcmp(left->workload_root, right->workload_root, 32u) == 0 &&
        memcmp(left->parent_arm_root, right->parent_arm_root, 32u) == 0 &&
        memcmp(left->child_arm_root, right->child_arm_root, 32u) == 0 &&
        memcmp(left->evaluation_input_root,
               right->evaluation_input_root, 32u) == 0;
}

static bool pe_direct_metrics(
    const struct zcl_retrieval_paired_evaluation_task_v1 tasks[2],
    struct zcl_retrieval_eval_metrics *parent,
    struct zcl_retrieval_eval_metrics *child)
{
    struct zcl_retrieval_gold_task parent_tasks[2], child_tasks[2];
    for (size_t i = 0; i < 2u; i++) {
        parent_tasks[i] = (struct zcl_retrieval_gold_task){
            .task_id = tasks[i].task_id, .query = tasks[i].query,
            .relevant_paths = tasks[i].relevant_paths,
            .relevant_count = tasks[i].relevant_count,
            .ranked = tasks[i].parent_ranked,
            .ranked_count = tasks[i].parent_count,
            .ranking_complete = tasks[i].parent_complete,
        };
        child_tasks[i] = (struct zcl_retrieval_gold_task){
            .task_id = tasks[i].task_id, .query = tasks[i].query,
            .relevant_paths = tasks[i].relevant_paths,
            .relevant_count = tasks[i].relevant_count,
            .ranked = tasks[i].child_ranked,
            .ranked_count = tasks[i].child_count,
            .ranking_complete = tasks[i].child_complete,
        };
    }
    return zcl_retrieval_evaluate(parent_tasks, 2u, parent) &&
           zcl_retrieval_evaluate(child_tasks, 2u, child);
}

static bool pe_roots_changed(
    const struct zcl_retrieval_paired_evaluation_report_v1 *baseline,
    const struct zcl_retrieval_paired_evaluation_report_v1 *changed,
    unsigned int expected)
{
    const uint8_t *left[] = {
        baseline->workload_root, baseline->parent_arm_root,
        baseline->child_arm_root, baseline->evaluation_input_root,
    };
    const uint8_t *right[] = {
        changed->workload_root, changed->parent_arm_root,
        changed->child_arm_root, changed->evaluation_input_root,
    };
    for (size_t i = 0; i < 4u; i++)
        if ((memcmp(left[i], right[i], 32u) != 0) !=
            ((expected & (1u << i)) != 0))
            return false;
    return true;
}

static bool pe_evaluate_changed(
    const struct pe_fixture *fixture,
    const struct zcl_retrieval_paired_evaluation_task_v1 tasks[2],
    const struct zcl_retrieval_paired_evaluation_report_v1 *baseline,
    unsigned int expected)
{
    struct zcl_retrieval_paired_evaluation_report_v1 report;
    return pe_evaluate(fixture, tasks, 2u, &report) ==
               ZCL_RETRIEVAL_EXPERIMENT_OK &&
           pe_roots_changed(baseline, &report, expected);
}

static void pe_print_root(const char *name, const uint8_t root[32])
{
    printf("  retrieval_paired_evaluation: actual %s=", name);
    for (size_t i = 0; i < 32u; i++) printf("%02x", root[i]);
    putchar('\n');
}

static int case_kat_and_metrics(void)
{
    int failures = 0;
    struct pe_fixture fixture;
    pe_fixture_init(&fixture);
    struct zcl_retrieval_paired_evaluation_report_v1 first, repeated;
    struct zcl_retrieval_eval_metrics parent, child;
    bool evaluated = pe_evaluate(&fixture, fixture.tasks, 2u, &first) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        pe_evaluate(&fixture, fixture.tasks, 2u, &repeated) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK;
    PE_CHECK("repeat preserves every field and root",
             evaluated && pe_reports_equal(&first, &repeated));
    PE_CHECK("metrics equal the maintained evaluator",
             evaluated && pe_direct_metrics(fixture.tasks, &parent, &child) &&
             pe_metrics_equal(&first.parent_metrics, &parent) &&
             pe_metrics_equal(&first.child_metrics, &child));
    const uint8_t expected_workload[32] = {
        0xbc, 0xb4, 0x79, 0xe1, 0x80, 0x2d, 0xa3, 0x4b,
        0x61, 0x05, 0x5e, 0x5c, 0x32, 0xd3, 0xb2, 0x1a,
        0xf0, 0xa5, 0x7f, 0x0f, 0xff, 0xf2, 0x8b, 0x42,
        0xb6, 0x72, 0xdd, 0xa7, 0x22, 0xbb, 0xa5, 0xbd,
    };
    const uint8_t expected_parent[32] = {
        0x3f, 0x29, 0xdc, 0xbe, 0xf6, 0x6a, 0xdc, 0x59,
        0x72, 0x64, 0xf3, 0x5e, 0x51, 0x2a, 0xe9, 0x9b,
        0x0b, 0xf4, 0x60, 0x35, 0xed, 0x1b, 0x47, 0x2f,
        0x26, 0x24, 0x3c, 0xc8, 0xc0, 0x4e, 0x9a, 0x9c,
    };
    const uint8_t expected_child[32] = {
        0x22, 0x42, 0x41, 0xa2, 0x74, 0xfc, 0x84, 0x1f,
        0xa3, 0x10, 0x9a, 0x8d, 0x83, 0x94, 0xfa, 0xba,
        0xe1, 0x03, 0x0d, 0x0f, 0x8b, 0xbc, 0x42, 0xca,
        0x80, 0x11, 0xd7, 0x9a, 0xd9, 0xd7, 0xe8, 0x6c,
    };
    const uint8_t expected_pair[32] = {
        0x17, 0x50, 0x25, 0x31, 0xdd, 0xa0, 0x9b, 0xc4,
        0x33, 0x53, 0x42, 0x2d, 0x6e, 0x8e, 0xfa, 0x59,
        0x3b, 0x8c, 0x75, 0x7e, 0x01, 0xa6, 0x23, 0x1e,
        0x02, 0x4c, 0x8b, 0xaa, 0xc3, 0x84, 0xb2, 0xf3,
    };
    bool kat = evaluated &&
        memcmp(first.workload_root, expected_workload, 32u) == 0 &&
        memcmp(first.parent_arm_root, expected_parent, 32u) == 0 &&
        memcmp(first.child_arm_root, expected_child, 32u) == 0 &&
        memcmp(first.evaluation_input_root, expected_pair, 32u) == 0;
    if (!kat && evaluated) {
        pe_print_root("workload", first.workload_root);
        pe_print_root("parent", first.parent_arm_root);
        pe_print_root("child", first.child_arm_root);
        pe_print_root("pair", first.evaluation_input_root);
    }
    PE_CHECK("canonical root known-answer vector", kat);
    return failures;
}

static int case_workload_mutations(void)
{
    int failures = 0;
    struct pe_fixture base, changed;
    pe_fixture_init(&base);
    struct zcl_retrieval_paired_evaluation_report_v1 baseline;
    bool ready = pe_evaluate(&base, base.tasks, 2u, &baseline) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    struct zcl_retrieval_paired_evaluation_task_v1 tasks[2];
    memcpy(tasks, base.tasks, sizeof(tasks));
    tasks[0].task_id = "alpha-v2";
    bool task_id = pe_evaluate_changed(&base, tasks, &baseline, PE_ALL);
    memcpy(tasks, base.tasks, sizeof(tasks));
    tasks[0].query = "find alpha implementation exactly";
    bool query = pe_evaluate_changed(&base, tasks, &baseline, PE_ALL);
    const char *changed_relevance[2] = {"src/a.c", "src/new.c"};
    memcpy(tasks, base.tasks, sizeof(tasks));
    tasks[0].relevant_paths = changed_relevance;
    bool relevance = pe_evaluate_changed(&base, tasks, &baseline, PE_ALL);
    const char *reordered_relevance[2] = {"src/shared.c", "src/a.c"};
    memcpy(tasks, base.tasks, sizeof(tasks));
    tasks[0].relevant_paths = reordered_relevance;
    bool relevance_order = pe_evaluate_changed(&base, tasks, &baseline, PE_ALL);
    tasks[0] = base.tasks[1];
    tasks[1] = base.tasks[0];
    bool task_order = pe_evaluate_changed(&base, tasks, &baseline, PE_ALL);
    PE_CHECK("task query relevance and caller order bind every root",
             ready && task_id && query && relevance && relevance_order &&
             task_order);

    changed = base;
    changed.task_root[0] ^= 1u;
    bool task_root = pe_evaluate_changed(
        &changed, changed.tasks, &baseline, PE_ALL);
    changed = base;
    changed.source_root[0] ^= 1u;
    bool source_root = pe_evaluate_changed(
        &changed, changed.tasks, &baseline, PE_ALL);
    changed = base;
    changed.projection_root[0] ^= 1u;
    bool projection_root = pe_evaluate_changed(
        &changed, changed.tasks, &baseline, PE_ALL);
    PE_CHECK("task source and projection roots bind the workload and pair",
             task_root && source_root && projection_root);
    changed = base;
    changed.source_root[0] ^= 1u;
    changed.projection_root[0] ^= 1u;
    struct zcl_retrieval_paired_evaluation_report_v1 stale;
    PE_CHECK("same rows at a stale generation change identity not metrics",
             pe_evaluate(&changed, changed.tasks, 2u, &stale) ==
                 ZCL_RETRIEVAL_EXPERIMENT_OK &&
             pe_roots_changed(&baseline, &stale, PE_ALL) &&
             pe_metrics_equal(&baseline.parent_metrics,
                              &stale.parent_metrics) &&
             pe_metrics_equal(&baseline.child_metrics, &stale.child_metrics));
    return failures;
}

static int case_root_only_workload(void)
{
    int failures = 0;
    struct pe_fixture fixture, changed;
    pe_fixture_init(&fixture);
    struct zcl_retrieval_evaluation_workload_task_v1 base[2], tasks[2];
    pe_workload_tasks(&fixture, base);
    uint8_t root[32], repeated[32];
    struct zcl_retrieval_paired_evaluation_report_v1 paired;
    const uint8_t kat[32] = {
        0xbc, 0xb4, 0x79, 0xe1, 0x80, 0x2d, 0xa3, 0x4b,
        0x61, 0x05, 0x5e, 0x5c, 0x32, 0xd3, 0xb2, 0x1a,
        0xf0, 0xa5, 0x7f, 0x0f, 0xff, 0xf2, 0x8b, 0x42,
        0xb6, 0x72, 0xdd, 0xa7, 0x22, 0xbb, 0xa5, 0xbd,
    };
    bool ready = pe_workload_root(&fixture, base, 2u, root) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        pe_workload_root(&fixture, base, 2u, repeated) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        pe_evaluate(&fixture, fixture.tasks, 2u, &paired) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK;
    PE_CHECK("root-only workload matches KAT and paired evaluation",
             ready && memcmp(root, kat, 32u) == 0 &&
             memcmp(root, repeated, 32u) == 0 &&
             memcmp(root, paired.workload_root, 32u) == 0);

#define PE_WORKLOAD_MUTATION(name_, mutation_) do {                         \
    memcpy(tasks, base, sizeof(tasks));                                     \
    mutation_;                                                              \
    uint8_t mutated[32];                                                    \
    bool changed_root = pe_workload_root(&fixture, tasks, 2u, mutated) ==   \
            ZCL_RETRIEVAL_EXPERIMENT_OK &&                                 \
        memcmp(root, mutated, 32u) != 0;                                    \
    PE_CHECK((name_), ready && changed_root);                               \
} while (0)
    PE_WORKLOAD_MUTATION("root-only task id binds", tasks[0].task_id = "a2");
    PE_WORKLOAD_MUTATION("root-only query binds", tasks[0].query = "q2");
    const char *other_relevance[2] = {"src/a.c", "src/new.c"};
    PE_WORKLOAD_MUTATION("root-only relevance binds",
                         tasks[0].relevant_paths = other_relevance);
    const char *reordered[2] = {"src/shared.c", "src/a.c"};
    PE_WORKLOAD_MUTATION("root-only relevance order binds",
                         tasks[0].relevant_paths = reordered);
    PE_WORKLOAD_MUTATION("root-only task order binds",
                         tasks[0] = base[1]; tasks[1] = base[0]);
#undef PE_WORKLOAD_MUTATION

    bool external_roots = true;
    for (size_t which = 0; which < 3u; which++) {
        changed = fixture;
        uint8_t *roots[] = {
            changed.task_root, changed.source_root, changed.projection_root};
        roots[which][0] ^= 1u;
        uint8_t mutated[32];
        external_roots = external_roots &&
            pe_workload_root(&changed, base, 2u, mutated) ==
                ZCL_RETRIEVAL_EXPERIMENT_OK &&
            memcmp(root, mutated, 32u) != 0;
    }
    PE_CHECK("root-only task source and projection roots bind",
             ready && external_roots);

    memcpy(tasks, base, sizeof(tasks));
    tasks[1].task_id = tasks[0].task_id;
    bool duplicate_task = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    const char *duplicate_relevance[2] = {"src/a.c", "src/a.c"};
    memcpy(tasks, base, sizeof(tasks));
    tasks[0].relevant_paths = duplicate_relevance;
    bool duplicate_relevant = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    PE_CHECK("root-only duplicates refuse atomically",
             duplicate_task && duplicate_relevant);

    memcpy(tasks, base, sizeof(tasks));
    tasks[0].relevant_count = 0u;
    bool empty_relevance = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    memcpy(tasks, base, sizeof(tasks)); tasks[0].task_id = "";
    bool empty_id = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    memcpy(tasks, base, sizeof(tasks)); tasks[0].query = "";
    bool empty_query = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    bool empty_batch = pe_workload_refused(
        base, 0u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    PE_CHECK("root-only empty fields and batch refuse atomically",
             empty_relevance && empty_id && empty_query && empty_batch);

    memcpy(tasks, base, sizeof(tasks));
    tasks[0].relevant_count = ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX + 1u;
    bool relevance_limit = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    bool task_limit = pe_workload_refused(
        base, ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX + 1u, fixture.task_root,
        fixture.source_root, fixture.projection_root);
    char long_query[ZCL_RETRIEVAL_PAIRED_EVALUATION_QUERY_MAX + 2u];
    memset(long_query, 'q', sizeof(long_query));
    long_query[sizeof(long_query) - 1u] = 0;
    memcpy(tasks, base, sizeof(tasks)); tasks[0].query = long_query;
    bool query_limit = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    char long_id[ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX + 2u];
    memset(long_id, 'i', sizeof(long_id));
    long_id[sizeof(long_id) - 1u] = 0;
    memcpy(tasks, base, sizeof(tasks)); tasks[0].task_id = long_id;
    bool id_limit = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    char long_path[ZCL_RETRIEVAL_PAIRED_EVALUATION_PATH_MAX + 2u];
    memset(long_path, 'p', sizeof(long_path));
    long_path[sizeof(long_path) - 1u] = 0;
    const char *long_relevance[2] = {long_path, "src/shared.c"};
    memcpy(tasks, base, sizeof(tasks));
    tasks[0].relevant_paths = long_relevance;
    bool path_limit = pe_workload_refused(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    PE_CHECK("root-only count and text limits refuse atomically",
             relevance_limit && task_limit && query_limit && id_limit &&
             path_limit);

    uint8_t zero[32] = {0};
    bool zero_task = pe_workload_refused(
        base, 2u, zero, fixture.source_root, fixture.projection_root);
    bool zero_source = pe_workload_refused(
        base, 2u, fixture.task_root, zero, fixture.projection_root);
    bool zero_projection = pe_workload_refused(
        base, 2u, fixture.task_root, fixture.source_root, zero);
    PE_CHECK("root-only zero roots refuse atomically",
             zero_task && zero_source && zero_projection);

    union pe_workload_direct_alias {
        uint8_t out[32];
        struct zcl_retrieval_evaluation_workload_task_v1 task;
    } direct, direct_before;
    direct.task = base[0]; direct_before = direct;
    bool direct_alias = zcl_retrieval_evaluation_workload_root(
        &direct.task, 1u, fixture.task_root, fixture.source_root,
        fixture.projection_root, direct.out) == ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
        memcmp(&direct, &direct_before, sizeof(direct)) == 0;
    union pe_workload_reachable_alias { uint8_t out[32]; char text[32]; }
        reachable, reachable_before;
    memset(&reachable, 0, sizeof(reachable));
    memcpy(reachable.text, "reachable-workload", 19u);
    memcpy(tasks, base, sizeof(tasks)); tasks[0].task_id = reachable.text;
    reachable_before = reachable;
    bool reachable_alias = zcl_retrieval_evaluation_workload_root(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root, reachable.out) ==
            ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
        memcmp(&reachable, &reachable_before, sizeof(reachable)) == 0;
    PE_CHECK("root-only direct and reachable aliases refuse atomically",
             direct_alias && reachable_alias);
    return failures;
}

static int case_arm_mutations(void)
{
    int failures = 0;
    struct pe_fixture fixture;
    pe_fixture_init(&fixture);
    struct zcl_retrieval_paired_evaluation_report_v1 baseline, changed;
    bool ready = pe_evaluate(&fixture, fixture.tasks, 2u, &baseline) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    struct zcl_retrieval_paired_evaluation_task_v1 tasks[2];
    struct zcl_retrieval_ranked_file rows[3];
#define PE_ARM_MUTATION(member_, rows_member_, count_member_, complete_member_, \
                        expected_) do {                                      \
    memcpy(tasks, fixture.tasks, sizeof(tasks));                             \
    memcpy(rows, fixture.member_[0], sizeof(rows));                          \
    tasks[0].rows_member_ = rows;                                            \
    rows[0].path = "src/changed.c";                                         \
    bool path = pe_evaluate_changed(&fixture, tasks, &baseline, expected_);  \
    memcpy(rows, fixture.member_[0], sizeof(rows));                          \
    struct zcl_retrieval_ranked_file swap = rows[0];                         \
    rows[0] = rows[1]; rows[1] = swap;                                       \
    bool order = pe_evaluate_changed(&fixture, tasks, &baseline, expected_); \
    memcpy(rows, fixture.member_[0], sizeof(rows));                          \
    rows[0].context_bytes++;                                                 \
    bool context = pe_evaluate_changed(                                      \
        &fixture, tasks, &baseline, expected_);                              \
    memcpy(rows, fixture.member_[0], sizeof(rows));                          \
    tasks[0].complete_member_ = false;                                       \
    bool complete = pe_evaluate_changed(                                     \
        &fixture, tasks, &baseline, expected_);                              \
    tasks[0].complete_member_ = true;                                        \
    rows[2].in_scope_available = true;                                       \
    bool available = pe_evaluate_changed(                                    \
        &fixture, tasks, &baseline, expected_);                              \
    memcpy(rows, fixture.member_[0], sizeof(rows));                          \
    rows[1].in_scope = !rows[1].in_scope;                                    \
    bool scope = pe_evaluate_changed(&fixture, tasks, &baseline, expected_); \
    PE_CHECK(#member_ " path/order/context/completeness/scope bind its arm", \
             ready && path && order && context && complete && available &&   \
             scope);                                                         \
} while (0)
    PE_ARM_MUTATION(parent, parent_ranked, parent_count, parent_complete,
                    PE_PARENT | PE_PAIR);
    PE_ARM_MUTATION(child, child_ranked, child_count, child_complete,
                    PE_CHILD | PE_PAIR);
#undef PE_ARM_MUTATION

    memcpy(tasks, fixture.tasks, sizeof(tasks));
    for (size_t i = 0; i < 2u; i++) {
        tasks[i].parent_ranked = fixture.tasks[i].child_ranked;
        tasks[i].parent_count = fixture.tasks[i].child_count;
        tasks[i].parent_complete = fixture.tasks[i].child_complete;
        tasks[i].child_ranked = fixture.tasks[i].parent_ranked;
        tasks[i].child_count = fixture.tasks[i].parent_count;
        tasks[i].child_complete = fixture.tasks[i].parent_complete;
    }
    bool swapped = pe_evaluate(&fixture, tasks, 2u, &changed) ==
        ZCL_RETRIEVAL_EXPERIMENT_OK;
    PE_CHECK("swapping arms swaps arm roots and changes the pair",
             swapped && memcmp(changed.workload_root,
                               baseline.workload_root, 32u) == 0 &&
             memcmp(changed.parent_arm_root,
                    baseline.child_arm_root, 32u) == 0 &&
             memcmp(changed.child_arm_root,
                    baseline.parent_arm_root, 32u) == 0 &&
             memcmp(changed.evaluation_input_root,
                    baseline.evaluation_input_root, 32u) != 0);
    return failures;
}

static bool pe_refused_unchanged(
    const struct pe_fixture *fixture,
    const struct zcl_retrieval_paired_evaluation_task_v1 *tasks,
    size_t task_count, const uint8_t task_root[32],
    const uint8_t source_root[32], const uint8_t projection_root[32])
{
    struct zcl_retrieval_paired_evaluation_report_v1 report, before;
    memset(&report, 0xa5, sizeof(report));
    before = report;
    return zcl_retrieval_paired_evaluate(
               tasks, task_count, task_root, source_root, projection_root,
               &report) != ZCL_RETRIEVAL_EXPERIMENT_OK &&
           memcmp(&report, &before, sizeof(report)) == 0 && fixture != NULL;
}

static int case_malformed_refusals(void)
{
    int failures = 0;
    struct pe_fixture fixture;
    pe_fixture_init(&fixture);
    struct zcl_retrieval_paired_evaluation_task_v1 tasks[2];
    struct zcl_retrieval_ranked_file rows[3];
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[1].task_id = tasks[0].task_id;
    bool duplicate_task = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    const char *duplicate_relevance[2] = {"src/a.c", "src/a.c"};
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[0].relevant_paths = duplicate_relevance;
    bool duplicate_gold = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    memcpy(rows, fixture.parent[0], sizeof(rows));
    rows[1].path = rows[0].path;
    tasks[0].parent_ranked = rows;
    bool duplicate_parent = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    memcpy(rows, fixture.child[0], sizeof(rows));
    rows[1].path = rows[0].path;
    tasks[0].child_ranked = rows;
    bool duplicate_child = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    PE_CHECK("duplicate task relevance and ranked paths refuse atomically",
             duplicate_task && duplicate_gold && duplicate_parent &&
             duplicate_child);

    memcpy(tasks, fixture.tasks, sizeof(tasks));
    memcpy(rows, fixture.parent[0], sizeof(rows));
    rows[2].in_scope = true;
    tasks[0].parent_ranked = rows;
    PE_CHECK("unavailable true scope is noncanonical and atomic",
             pe_refused_unchanged(
                 &fixture, tasks, 2u, fixture.task_root,
                 fixture.source_root, fixture.projection_root));

    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[0].relevant_count = 0;
    bool empty_relevance = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[0].task_id = "";
    bool empty_id = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    bool empty_batch = pe_refused_unchanged(
        &fixture, fixture.tasks, 0u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    PE_CHECK("empty batch relevance and identity refuse atomically",
             empty_relevance && empty_id && empty_batch);

    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[0].relevant_count = ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX + 1u;
    bool relevance_limit = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[0].parent_count = ZCL_RETRIEVAL_EVAL_RANK_MAX + 1u;
    bool rank_limit = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    bool task_limit = pe_refused_unchanged(
        &fixture, fixture.tasks, ZCL_RETRIEVAL_EXPERIMENT_TASK_MAX + 1u,
        fixture.task_root, fixture.source_root, fixture.projection_root);
    char long_id[ZCL_RETRIEVAL_PAIRED_EVALUATION_TASK_ID_MAX + 2u];
    memset(long_id, 'i', sizeof(long_id)); long_id[sizeof(long_id) - 1u] = 0;
    memcpy(tasks, fixture.tasks, sizeof(tasks)); tasks[0].task_id = long_id;
    bool id_limit = pe_refused_unchanged(
        &fixture, tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root);
    PE_CHECK("count and text limits refuse before traversal atomically",
             relevance_limit && rank_limit && task_limit && id_limit);

    uint8_t zero[32] = {0};
    bool zero_task = pe_refused_unchanged(
        &fixture, fixture.tasks, 2u, zero, fixture.source_root,
        fixture.projection_root);
    bool zero_source = pe_refused_unchanged(
        &fixture, fixture.tasks, 2u, fixture.task_root, zero,
        fixture.projection_root);
    bool zero_projection = pe_refused_unchanged(
        &fixture, fixture.tasks, 2u, fixture.task_root,
        fixture.source_root, zero);
    PE_CHECK("every required external root refuses zero atomically",
             zero_task && zero_source && zero_projection);
    return failures;
}

static int case_alias_refusals(void)
{
    int failures = 0;
    struct pe_fixture fixture;
    pe_fixture_init(&fixture);
    union pe_direct_alias {
        struct zcl_retrieval_paired_evaluation_report_v1 report;
        struct zcl_retrieval_paired_evaluation_task_v1 tasks[2];
    } direct, direct_before;
    direct.tasks[0] = fixture.tasks[0];
    direct.tasks[1] = fixture.tasks[1];
    direct_before = direct;
    bool direct_alias = zcl_retrieval_paired_evaluate(
        direct.tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root, &direct.report) ==
            ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
        memcmp(&direct, &direct_before, sizeof(direct)) == 0;

    union pe_reachable_alias {
        struct zcl_retrieval_paired_evaluation_report_v1 report;
        char task_id[sizeof(struct zcl_retrieval_paired_evaluation_report_v1)];
    } reachable, reachable_before;
    memset(&reachable, 0, sizeof(reachable));
    memcpy(reachable.task_id, "reachable-alias", 16u);
    struct zcl_retrieval_paired_evaluation_task_v1 tasks[2];
    memcpy(tasks, fixture.tasks, sizeof(tasks));
    tasks[0].task_id = reachable.task_id;
    reachable_before = reachable;
    bool reachable_alias = zcl_retrieval_paired_evaluate(
        tasks, 2u, fixture.task_root, fixture.source_root,
        fixture.projection_root, &reachable.report) ==
            ZCL_RETRIEVAL_EXPERIMENT_ALIAS &&
        memcmp(&reachable, &reachable_before, sizeof(reachable)) == 0;
    PE_CHECK("direct and reachable input aliases refuse without mutation",
             direct_alias && reachable_alias);
    return failures;
}

int test_retrieval_paired_evaluation(void)
{
    int failures = 0;
    failures += case_kat_and_metrics();
    failures += case_workload_mutations();
    failures += case_root_only_workload();
    failures += case_arm_mutations();
    failures += case_malformed_refusals();
    failures += case_alias_refusals();
    printf("retrieval_paired_evaluation: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 1 ? "" : "s");
    return failures;
}
