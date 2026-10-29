/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: experiment-event statistics and export, split from fleet_ledger.c
 * so that file stays under the size cap. */

#include "fleet_ledger_experiment.h"

#include <string.h>

static bool experiment_task_equal(const struct fleet_experiment_event *a,
                                  const struct fleet_experiment_event *b)
{
    return a->task_class == b->task_class && a->model == b->model &&
           a->note_len == b->note_len &&
           memcmp(a->note, b->note, a->note_len) == 0;
}

static struct zcl_fleet_experiment_group *exp_group(
    struct zcl_fleet_experiment_group *out, size_t cap, size_t *count,
    uint8_t task_class, uint8_t model)
{
    for (size_t i = 0; i < *count; i++)
        if (out[i].task_class == task_class && out[i].model == model)
            return &out[i];
    if (*count >= cap)
        return NULL;
    struct zcl_fleet_experiment_group *g = &out[(*count)++];
    memset(g, 0, sizeof(*g));
    g->task_class = task_class;
    g->model = model;
    return g;
}

static int64_t median_i64(int64_t *v, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        int64_t t = v[i];
        size_t j = i;
        while (j > 0 && v[j - 1] > t) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = t;
    }
    return v[(n - 1) / 2];
}

static bool experiment_has_predict(const struct fleet_experiment_event *ev, uint32_t n,
                                   const struct fleet_experiment_event *e)
{
    for (uint32_t j = 0; j < n; j++) {
        const struct fleet_experiment_event *p = &ev[j];
        if (p->phase == ZCL_FLEET_EXPERIMENT_PREDICT &&
            experiment_task_equal(p, e))
            return true;
    }
    return false;
}

/* Tally one event into its group; returns 1 when a result had no predict. */
static uint64_t experiment_tally_event(const struct fleet_experiment_event *ev, uint32_t n,
                                       struct zcl_fleet_experiment_group *g,
                                       const struct fleet_experiment_event *e)
{
    if (e->phase == ZCL_FLEET_EXPERIMENT_PREDICT) {
        g->predicts++;
        return 0;
    }
    if (e->phase != ZCL_FLEET_EXPERIMENT_RESULT)
        return 0;
    g->results++;
    if (e->outcome == 1) /* LAND */
        g->lands++;
    if (experiment_has_predict(ev, n, e))
        return 0;
    g->unpredicted++;
    return 1;
}

struct experiment_samples {
    int64_t walls[FLEET_EXPERIMENT_EVENTS_MAX];
    int64_t tokens[FLEET_EXPERIMENT_EVENTS_MAX];
    size_t nw, nt;
    int64_t pred_sum, act_sum;
    bool have_ratio;
};

static void experiment_sample_result(const struct fleet_experiment_event *ev, uint32_t n,
                                     struct experiment_samples *s,
                                     const struct fleet_experiment_event *e)
{
    if (e->have_wall && s->nw < FLEET_EXPERIMENT_EVENTS_MAX)
        s->walls[s->nw++] = e->wall_s;
    if (e->have_tokens && s->nt < FLEET_EXPERIMENT_EVENTS_MAX)
        s->tokens[s->nt++] = e->tokens;
    for (uint32_t j = 0; j < n; j++) {
        const struct fleet_experiment_event *p = &ev[j];
        if (p->phase != ZCL_FLEET_EXPERIMENT_PREDICT ||
            !experiment_task_equal(p, e) || !p->have_tokens ||
            !e->have_tokens)
            continue;
        s->pred_sum += p->tokens;
        s->act_sum += e->tokens;
        s->have_ratio = true;
        break;
    }
}

static void experiment_group_summarize(const struct fleet_experiment_event *ev, uint32_t n,
                                       struct zcl_fleet_experiment_group *g)
{
    struct experiment_samples s;
    memset(&s, 0, sizeof s);
    for (uint32_t i = 0; i < n; i++) {
        const struct fleet_experiment_event *e = &ev[i];
        if (e->task_class != g->task_class || e->model != g->model)
            continue;
        if (e->phase != ZCL_FLEET_EXPERIMENT_RESULT)
            continue;
        experiment_sample_result(ev, n, &s, e);
    }
    if (s.nw > 0) {
        g->median_wall_s = median_i64(s.walls, s.nw);
        g->have_median_wall = 1;
    }
    if (s.nt > 0) {
        g->median_tokens = median_i64(s.tokens, s.nt);
        g->have_median_tokens = 1;
    }
    if (s.have_ratio && s.act_sum > 0) {
        g->pred_actual_bp = (s.pred_sum * 10000) / s.act_sum;
        g->have_pred_actual = 1;
    }
}

static void experiment_groups_sort(struct zcl_fleet_experiment_group *out,
                                   size_t count)
{
    for (size_t i = 1; i < count; i++) {
        struct zcl_fleet_experiment_group t = out[i];
        size_t j = i;
        while (j > 0 &&
               (out[j - 1].task_class > t.task_class ||
                (out[j - 1].task_class == t.task_class &&
                 out[j - 1].model > t.model))) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = t;
    }
}

/* Copy one retained event into the export shape. A free function rather
 * than inline in the walk below, so the walk's own decision count stays
 * about which rows match rather than about how a row is copied. */
static void experiment_row_fill(struct zcl_fleet_experiment_row *out,
                                const struct fleet_experiment_event *e)
{
    memset(out, 0, sizeof(*out));
    out->ts_unix = e->ts_unix;
    memcpy(out->box_id, e->box_id, ZCL_FLEET_ID_BYTES);
    out->phase = e->phase;
    memcpy(out->task_id, e->note, e->note_len);
    out->task_class = e->task_class;
    memcpy(out->story, e->story, e->story_len);
    out->have_executor = e->have_executor ? 1 : 0;
    out->executor = e->executor;
    out->have_harness = e->have_harness ? 1 : 0;
    out->harness = e->harness;
    out->model = e->model;
    out->have_effort = e->have_effort ? 1 : 0;
    out->effort = e->effort;
    out->have_tokens_in = e->have_tokens_in ? 1 : 0;
    out->tokens_in = e->tokens_in;
    out->have_tokens_out = e->have_tokens_out ? 1 : 0;
    out->tokens_out = e->tokens_out;
    out->have_tokens_cache = e->have_tokens_cache ? 1 : 0;
    out->tokens_cache = e->tokens_cache;
    out->have_tokens_reasoning = e->have_tokens_reasoning ? 1 : 0;
    out->tokens_reasoning = e->tokens_reasoning;
    out->have_tool_uses = e->have_tool_uses ? 1 : 0;
    out->tool_uses = e->tool_uses;
    out->have_turns = e->have_turns ? 1 : 0;
    out->turns = e->turns;
    out->have_wall_s = e->have_wall ? 1 : 0;
    out->wall_s = e->wall_s;
    out->have_outcome = e->phase == ZCL_FLEET_EXPERIMENT_RESULT ? 1 : 0;
    out->outcome = e->outcome;
    out->have_lines_added = e->have_lines_added ? 1 : 0;
    out->lines_added = e->lines_added;
    out->have_lines_removed = e->have_lines_removed ? 1 : 0;
    out->lines_removed = e->lines_removed;
    out->have_defects = e->have_defects ? 1 : 0;
    out->defects = e->defects;
}

enum zcl_fleet_status fleet_experiment_groups(
    const struct fleet_experiment_event *ev, uint32_t n,
    struct zcl_fleet_experiment_group *out, size_t cap, size_t *count,
    uint64_t *unmatched)
{
    enum zcl_fleet_status status = ZCL_FLEET_OK;

    for (uint32_t i = 0; i < n; i++) {
        const struct fleet_experiment_event *e = &ev[i];
        struct zcl_fleet_experiment_group *g =
            exp_group(out, cap, count, e->task_class, e->model);
        if (!g) {
            status = ZCL_FLEET_FULL;
            break;
        }
        *unmatched += experiment_tally_event(ev, n, g, e);
    }

    for (size_t gi = 0; gi < *count && status == ZCL_FLEET_OK; gi++)
        experiment_group_summarize(ev, n, &out[gi]);

    /* Stable order: task_class then model, so a fixture has one answer. */
    experiment_groups_sort(out, *count);
    return status;
}

enum zcl_fleet_status fleet_experiment_rows(
    const struct fleet_experiment_event *ev, uint32_t n, int64_t since_unix,
    const uint8_t box_id[ZCL_FLEET_ID_BYTES], bool have_box,
    struct zcl_fleet_experiment_row *out, size_t cap, size_t *count)
{
    enum zcl_fleet_status status = ZCL_FLEET_OK;
    for (uint32_t i = 0; i < n; i++) {
        const struct fleet_experiment_event *e = &ev[i];
        if (e->ts_unix < since_unix)
            continue;
        if (have_box && memcmp(e->box_id, box_id, ZCL_FLEET_ID_BYTES) != 0)
            continue;
        if (*count >= cap) {
            status = ZCL_FLEET_FULL;
            break;
        }
        experiment_row_fill(&out[(*count)++], e);
    }
    return status;
}
