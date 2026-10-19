/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.goals` leaf: the live report card of the fleet goals
 *          G1-G13, the public-node criteria C1-C8 and the development
 *          milestones D1-D8, one graded row each.
 *
 * WHAT IT DECIDES. Nothing. It grades the closed catalog in
 * engine/composition/goals.def against probes this tree can run now. A row
 * whose probe is missing is unmeasured with the reason; no gate reads this
 * leaf. */

#include "native_fleet_goals.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

static const char *goals_input_str(const struct zcl_command_request *request,
                                   const char *key)
{
    const struct json_value *in = request ? request->input : NULL;
    const char *text = in ? json_get_str(json_get(in, key)) : NULL;
    return text && text[0] ? text : NULL;
}

static void goals_row_json(const struct zcl_goal_row *row,
                           const struct zcl_goal_result *res,
                           struct json_value *out)
{
    json_set_object(out);
    (void)json_push_kv_str(out, "id", row->id);
    (void)json_push_kv_str(out, "title", row->title);
    (void)json_push_kv_str(out, "grade", zcl_goal_grade_name(res->grade));
    (void)json_push_kv_str(out, "bar", row->bar);
    (void)json_push_kv_str(out, "evidence", res->evidence);
    (void)json_push_kv_str(out, "next", res->next);
}

void zcl_goals_tally(const struct json_value *rows, int64_t counts[4])
{
    for (int g = 0; g < 4; g++)
        counts[g] = 0;
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const char *grade =
            json_get_str(json_get(&rows->children[i], "grade"));
        for (int g = 0; g < 4; g++)
            if (strcmp(grade, zcl_goal_grade_name((enum zcl_goal_grade)g)) ==
                0)
                counts[g]++;
    }
}

static void goals_summary_json(const struct json_value *rows,
                               struct json_value *out)
{
    int64_t counts[4];
    zcl_goals_tally(rows, counts);
    json_set_object(out);
    for (int g = 0; g < 4; g++)
        (void)json_push_kv_int(out, zcl_goal_grade_name((enum zcl_goal_grade)g),
                               counts[g]);
}

void zcl_native_handle_fleet_goals(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct zcl_goals_options options;
    const struct zcl_goal_row *catalog;
    struct json_value rows, summary;
    static char text[ZCL_GOALS_TEXT_MAX];
    size_t n;

    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_GOALS_SCHEMA);
    memset(&options, 0, sizeof(options));
    options.repo = goals_input_str(request, "repo");
    options.outcomes = goals_input_str(request, "outcomes");
    options.bash_allowlist = goals_input_str(request, "bash_allowlist");
    options.claims = goals_input_str(request, "claims");

    n = zcl_goals_catalog(&catalog);
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < n; i++) {
        struct zcl_goal_result res = zcl_goals_measure(&options, catalog[i].id);
        struct json_value row;
        json_init(&row);
        goals_row_json(&catalog[i], &res, &row);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    json_init(&summary);
    goals_summary_json(&rows, &summary);
    (void)zcl_goals_render_text(&rows, text, sizeof(text));

    (void)json_push_kv_str(&reply->data, "schema", ZCL_GOALS_SCHEMA);
    (void)json_push_kv(&reply->data, "goals", &rows);
    (void)json_push_kv(&reply->data, "summary", &summary);
    (void)json_push_kv_str(&reply->data, "text", text);
    json_free(&summary);
    json_free(&rows);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── plain-text render ────────────────────────────────────────────────── */

size_t zcl_goals_render_text(const struct json_value *rows, char *out,
                             size_t cap)
{
    size_t at = 0;
    if (!rows || !out || cap == 0)
        return 0;
    out[0] = '\0';
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        int w = snprintf(out + at, cap - at,
                         "%-4s %-10s %s\n     %s\n     next: %s\n",
                         json_get_str(json_get(row, "id")),
                         json_get_str(json_get(row, "grade")),
                         json_get_str(json_get(row, "title")),
                         json_get_str(json_get(row, "evidence")),
                         json_get_str(json_get(row, "next")));
        if (w < 0 || (size_t)w >= cap - at) {
            at = cap - 1;
            break;
        }
        at += (size_t)w;
    }
    return at;
}
