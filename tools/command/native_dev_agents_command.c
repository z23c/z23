/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `z23-dev fleet agents` leaf — one command that answers what
 *          every AI agent on this box is doing and how each has graded out.
 *
 * WHY IT EXISTS. Several AI executors work this repository at the same time,
 * in their own worktrees, under their own harnesses. Until now, asking "who
 * is working, on what, and are they any good?" meant a dozen shell reads over
 * worktrees, /proc, systemd and a tab-separated ledger, and the answer went
 * stale before it was finished. One call answers it, in a fixed shape, at a
 * fixed cost.
 *
 * WHAT IT DECIDES. Nothing. Every number here is a report: a running process
 * is evidence of activity, never of a result, and a letter grade is a summary
 * of past rows, never a permission. No gate reads this leaf.
 *
 * WHAT IT REACHES. This box only: four workspace directories, /proc, the
 * systemd user units named z23-*, and one local ledger file. It never
 * fetches, never dials a peer, never opens a datadir, and writes nothing.
 * Other hosts are reported as not collected rather than guessed at.
 *
 * Bound by engine/composition/commands/agents.def.
 */

#include "command/native_dev_agents.h"

#include "json/json.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AG_LEAF "dev.fleet.agents"
/* Widest window a caller may ask for: one year of hours. Past that the
 * ledger's own age is the bound, and `since=0` already means "everything". */
#define AG_MAX_SINCE_HOURS 8760
#define AG_DEFAULT_SINCE_HOURS 168

static const char *ag_input_str(const struct zcl_command_request *request,
                                const char *key)
{
    const char *v;
    if (!request || !request->input) return NULL;
    v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

static void ag_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence,
                      const char *next_action)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "collect", false,
                           false, message, evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action);
    reply->error.human_action_required = true;
}

/* `since` is a window in HOURS, and 0 means the whole ledger. It arrives as
 * an integer from the typed CLI and as a string from a hand-written input
 * object; both are read, and anything outside the range is refused rather
 * than clamped, because a silently narrowed window reports a grade the
 * caller did not ask for. */
static bool ag_read_since(const struct zcl_command_request *request,
                          int64_t *hours)
{
    const struct json_value *v;
    const char *text;
    long long parsed;
    if (!request || !request->input) return true;
    v = json_get(request->input, "since");
    if (!v) return true;
    text = json_get_str(v);
    parsed = v->type == JSON_INT ? (long long)json_get_int(v)
                                 : atoll(text ? text : "-1");
    if (parsed < 0 || parsed > AG_MAX_SINCE_HOURS) return false;
    *hours = parsed;
    return true;
}

/* The three groupings. An unknown one is named back to the caller rather
 * than quietly answered as the default. */
static bool ag_read_group_by(const struct zcl_command_request *request,
                             const char **group_by)
{
    const struct json_value *v;
    const char *by;
    if (!request || !request->input) return true;
    v = json_get(request->input, "by");
    if (!v || v->type != JSON_STR) return true;
    by = json_get_str(v);
    if (strcmp(by, "executor") != 0 && strcmp(by, "lane") != 0 &&
        strcmp(by, "class") != 0)
        return false;
    *group_by = by;
    return true;
}

static bool ag_read_flag(const struct zcl_command_request *request,
                         const char *key, bool fallback)
{
    const struct json_value *v;
    if (!request || !request->input) return fallback;
    v = json_get(request->input, key);
    return v && v->type == JSON_BOOL ? json_get_bool(v) : fallback;
}

/* The OTHER HOSTS section: the plain "not collected" stub by default, or
 * the board merge when the caller asked `--fleet`. Split out of the leaf's
 * dispatch so that branch does not grow the handler's own complexity. */
static void ag_other_hosts(bool fleet, const struct json_value *running,
                           const struct json_value *grades, int64_t now,
                           struct json_value *others)
{
    json_init(others);
    if (fleet) {
        zcl_agents_do_fleet_merge(running, grades, now, others);
        return;
    }
    json_set_object(others);
    (void)json_push_kv_str(others, "state", "not_collected");
    (void)json_push_kv_str(others, "note", ZCL_AGENTS_OTHER_HOSTS_NOTE);
}

void zcl_native_handle_dev_agents(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    struct zcl_agents_options options;
    struct json_value running, grades, others;
    char why[512] = "";
    char text[ZCL_AGENTS_TEXT_MAX];

    if (!reply) return;

    memset(&options, 0, sizeof(options));
    options.since_hours = AG_DEFAULT_SINCE_HOURS;
    /* The one reading of a real clock in this command, taken through the
     * injectable platform clock so a test can decide `now` and grade the
     * same fixture to the same numbers forever. */
    options.now_unix = clock_now_wall_ms() / 1000;

    if (!ag_read_since(request, &options.since_hours)) {
        ag_refuse(reply, "SINCE_OUT_OF_RANGE",
                  "since is a number of hours between 0 and 8760; 0 means the "
                  "whole ledger",
                  "input.since is outside the accepted range",
                  "rerun with --since=<hours> in 0..8760");
        return;
    }
    if (!ag_read_group_by(request, &options.group_by)) {
        ag_refuse(reply, "UNKNOWN_GROUPING", "by is executor, lane, or class",
                  "input.by is not one of the three groupings",
                  "rerun with --by=executor, --by=lane or --by=class");
        return;
    }
    options.collect_units = ag_read_flag(request, "include_units", true);
    options.root = ag_input_str(request, "root");
    options.ledger = ag_input_str(request, "ledger");
    bool publish = ag_read_flag(request, "publish", false);
    bool fleet = ag_read_flag(request, "fleet", false);

    json_init(&grades);
    if (!zcl_agents_grades_json(&options, &grades, why, sizeof(why))) {
        json_free(&grades);
        ag_refuse(reply, "NO_LEDGER", why,
                  "the delegation ledger is the only source of a grade",
                  "record one delegation, or pass --ledger=<path> to read "
                  "another machine's exported ledger");
        return;
    }

    json_init(&running);
    zcl_agents_running_json(&options, &running);

    if (publish) {
        zcl_agents_do_publish(&options, &running, &grades, reply);
        json_free(&running);
        json_free(&grades);
        return;
    }

    ag_other_hosts(fleet, &running, &grades, options.now_unix, &others);

    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", ZCL_AGENTS_SCHEMA);
    (void)json_push_kv_int(&reply->data, "now_unix", options.now_unix);
    (void)json_push_kv(&reply->data, "running", &running);
    (void)json_push_kv(&reply->data, "grades", &grades);
    (void)json_push_kv(&reply->data, "other_hosts", &others);

    /* The plain-English rendering is built from the object above and pushed
     * back into it, so the text and the JSON are the same measurement. */
    (void)zcl_agents_render_text(&reply->data, text, sizeof(text));
    (void)json_push_kv_str(&reply->data, "text", text);

    json_free(&running);
    json_free(&grades);
    json_free(&others);
}
