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

static bool goals_row_json(const struct zcl_goal_row *row,
                           const struct zcl_goal_result *res,
                           struct json_value *out)
{
    json_set_object(out);
    return json_push_kv_str(out, "id", row->id) &&
           json_push_kv_str(out, "title", row->title) &&
           json_push_kv_str(out, "grade", zcl_goal_grade_name(res->grade)) &&
           json_push_kv_str(out, "bar", row->bar) &&
           json_push_kv_str(out, "evidence", res->evidence) &&
           json_push_kv_str(out, "next", res->next);
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

static bool goals_summary_json(const struct json_value *rows,
                               struct json_value *out)
{
    int64_t counts[4];
    bool ok = true;
    zcl_goals_tally(rows, counts);
    json_set_object(out);
    for (int g = 0; g < 4; g++)
        ok = json_push_kv_int(out, zcl_goal_grade_name((enum zcl_goal_grade)g),
                              counts[g]) && ok;
    return ok;
}

static bool goals_rows(const struct zcl_goals_options *options,
                       struct json_value *rows)
{
    const struct zcl_goal_row *catalog;
    size_t n = zcl_goals_catalog(&catalog);
    json_set_array(rows);
    for (size_t i = 0; i < n; i++) {
        struct zcl_goal_result res = zcl_goals_measure(options, catalog[i].id);
        struct json_value row;
        bool ok;
        json_init(&row);
        ok = goals_row_json(&catalog[i], &res, &row) &&
             json_push_back(rows, &row);
        json_free(&row);
        if (!ok)
            return false;
    }
    return true;
}

static void goals_fail(struct zcl_command_reply *reply, const char *what)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INTERNAL, "GOALS_REPLY_FAILED",
                           "render", false, false, what, "");
}

void zcl_native_handle_fleet_goals(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct zcl_goals_options options;
    struct json_value rows, summary;
    static char text[ZCL_GOALS_TEXT_MAX];
    bool ok;

    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_GOALS_SCHEMA);
    memset(&options, 0, sizeof(options));
    options.repo = goals_input_str(request, "repo");
    options.outcomes = goals_input_str(request, "outcomes");
    options.bash_allowlist = goals_input_str(request, "bash_allowlist");
    options.claims = goals_input_str(request, "claims");

    json_init(&rows);
    json_init(&summary);
    ok = goals_rows(&options, &rows) && goals_summary_json(&rows, &summary);
    (void)zcl_goals_render_text(&rows, text, sizeof(text));
    ok = ok && json_push_kv_str(&reply->data, "schema", ZCL_GOALS_SCHEMA) &&
         json_push_kv(&reply->data, "goals", &rows) &&
         json_push_kv(&reply->data, "summary", &summary) &&
         json_push_kv_str(&reply->data, "text", text);
    json_free(&summary);
    json_free(&rows);
    if (!ok) {
        goals_fail(reply, "the report card could not be assembled");
        return;
    }
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
            static const char mark[] = "[truncated]\n";
            at = cap > sizeof(mark) ? cap - sizeof(mark) : 0;
            (void)snprintf(out + at, cap - at, "%s", mark);
            return cap - 1;
        }
        at += (size_t)w;
    }
    return at;
}
