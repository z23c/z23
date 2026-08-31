/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Truthful file-level metrics for reviewed retrieval task corpora. */

#include <retrieval/retrieval.h>

#include <limits.h>
#include <string.h>

static bool add_u64(uint64_t *sum, uint64_t value)
{
    if (!sum || UINT64_MAX - *sum < value) return false;
    *sum += value;
    return true;
}

static bool task_valid(const struct zcl_retrieval_gold_task *task)
{
    if (!task || !task->task_id || !task->task_id[0] || !task->query ||
        !task->query[0] || !task->relevant_paths || task->relevant_count == 0 ||
        !task->ranked || task->ranked_count > ZCL_RETRIEVAL_EVAL_RANK_MAX)
        return false;
    for (size_t i = 0; i < task->relevant_count; i++) {
        if (!task->relevant_paths[i] || !task->relevant_paths[i][0])
            return false;
        for (size_t prior = 0; prior < i; prior++)
            if (strcmp(task->relevant_paths[i],
                       task->relevant_paths[prior]) == 0)
                return false;
    }
    for (size_t i = 0; i < task->ranked_count; i++)
        if (!task->ranked[i].path || !task->ranked[i].path[0])
            return false;
    return true;
}

static bool path_relevant(const struct zcl_retrieval_gold_task *task,
                          const char *path)
{
    for (size_t i = 0; i < task->relevant_count; i++)
        if (strcmp(task->relevant_paths[i], path) == 0) return true;
    return false;
}

static bool ranked_duplicate(const struct zcl_retrieval_gold_task *task,
                             size_t index)
{
    for (size_t prior = 0; prior < index; prior++)
        if (strcmp(task->ranked[prior].path,
                   task->ranked[index].path) == 0)
            return true;
    return false;
}

bool zcl_retrieval_evaluate(
    const struct zcl_retrieval_gold_task *tasks, size_t task_count,
    struct zcl_retrieval_eval_metrics *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!tasks || task_count == 0 || task_count > UINT32_MAX) return false;
    uint64_t recall5_sum = 0, recall20_sum = 0, rr_sum = 0;
    bool r5_available = true, r20_available = true, mrr_available = true;
    for (size_t t = 0; t < task_count; t++) {
        const struct zcl_retrieval_gold_task *task = &tasks[t];
        if (!task_valid(task)) return false;
        for (size_t prior = 0; prior < t; prior++)
            if (strcmp(task->task_id, tasks[prior].task_id) == 0)
                return false;
        size_t unique_rank = 0, relevant5 = 0, relevant20 = 0;
        size_t first_relevant = 0;
        for (size_t i = 0; i < task->ranked_count; i++) {
            if (ranked_duplicate(task, i)) continue;
            unique_rank++;
            bool relevant = path_relevant(task, task->ranked[i].path);
            if (relevant && first_relevant == 0) first_relevant = unique_rank;
            if (relevant && unique_rank <= 5) relevant5++;
            if (relevant && unique_rank <= 20) relevant20++;
            if (unique_rank <= 5) {
                if (!add_u64(&out->unique_files_at_5, 1) ||
                    !add_u64(&out->context_bytes_at_5,
                             task->ranked[i].context_bytes))
                    return false;
                if (!task->ranked[i].in_scope &&
                    !add_u64(&out->wrong_scope_files_at_5, 1))
                    return false;
            }
        }
        bool task_r5 = task->ranking_complete || unique_rank >= 5 ||
            relevant5 == task->relevant_count;
        bool task_r20 = task->ranking_complete || unique_rank >= 20 ||
            relevant20 == task->relevant_count;
        bool task_mrr = first_relevant != 0 || task->ranking_complete;
        r5_available = r5_available && task_r5;
        r20_available = r20_available && task_r20;
        mrr_available = mrr_available && task_mrr;
        if (task_r5)
            recall5_sum += (uint64_t)relevant5 *
                ZCL_RETRIEVAL_EVAL_BASIS_POINTS / task->relevant_count;
        if (task_r20)
            recall20_sum += (uint64_t)relevant20 *
                ZCL_RETRIEVAL_EVAL_BASIS_POINTS / task->relevant_count;
        if (task_mrr && first_relevant != 0)
            rr_sum += ZCL_RETRIEVAL_EVAL_BASIS_POINTS / first_relevant;
    }
    out->tasks = (uint32_t)task_count;
    out->recall_at_5_available = r5_available;
    out->recall_at_20_available = r20_available;
    out->mrr_available = mrr_available;
    if (r5_available) out->recall_at_5_bp = (uint32_t)(recall5_sum / task_count);
    if (r20_available)
        out->recall_at_20_bp = (uint32_t)(recall20_sum / task_count);
    if (mrr_available) out->mrr_bp = (uint32_t)(rr_sum / task_count);
    if (out->context_bytes_at_5 > UINT64_MAX - 3u) return false;
    out->approximate_tokens_at_5 = (out->context_bytes_at_5 + 3u) / 4u;
    if (out->unique_files_at_5 != 0)
        out->wrong_scope_at_5_bp = (uint32_t)(
            out->wrong_scope_files_at_5 *
            ZCL_RETRIEVAL_EVAL_BASIS_POINTS / out->unique_files_at_5);
    return true;
}
