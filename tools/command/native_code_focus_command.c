/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Native handler for `code focus` — where a specialist works next.
 *
 * Answers from recorded evidence only. `--list` / no specialist renders the
 * X-macro catalog. An unknown name is a typed refusal. Ranking is delegated
 * to cognition/modules/codeindex; this file supplies the impact-rule router
 * and renders JSON plus `lines` like the sibling `code` leaves. */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_focus.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_TAG "native.code.focus"

static const char *focus_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

static void focus_push_obj(struct json_value *arr, struct json_value *obj)
{
    (void)json_push_back(arr, obj);
    json_free(obj);
}

static void focus_push_str(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

static size_t focus_route(const char *path,
                          char (*out)[SPECIALIST_GROUP_MAX], size_t cap,
                          void *user)
{
    (void)user;
    struct agent_impact_acc acc = {0};
    bool crisk = false;
    (void)zcl_native_code_route_for_path(path, &acc, &crisk);
    if (acc.shared_rule_hits == 0 && !crisk)
        return 0;
    size_t n = 0;
    if (crisk && n < cap)
        (void)snprintf(out[n++], SPECIALIST_GROUP_MAX, "%s",
                       "consensus_parity");
    for (size_t i = 0; i < acc.groups_len && n < cap; i++) {
        bool dup = false;
        for (size_t j = 0; j < n; j++) {
            if (strcmp(out[j], acc.groups[i]) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup)
            (void)snprintf(out[n++], SPECIALIST_GROUP_MAX, "%s",
                           acc.groups[i]);
    }
    return n;
}

static void focus_render_list(struct zcl_command_reply *reply)
{
    size_t n = 0;
    const struct specialist *rows = specialist_table(&n);
    struct json_value arr, lines;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&lines);
    json_set_array(&lines);
    for (size_t i = 0; i < n; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "name", rows[i].name);
        (void)json_push_kv_str(&o, "territories", rows[i].territories);
        (void)json_push_kv_str(&o, "gates", rows[i].gates);
        (void)json_push_kv_str(&o, "test_groups", rows[i].test_groups);
        (void)json_push_kv_str(&o, "fact_kinds", rows[i].fact_kinds);
        focus_push_obj(&arr, &o);
        focus_push_str(&lines, rows[i].name);
    }
    (void)json_push_kv_str(&reply->data, "scope", "list");
    (void)json_push_kv(&reply->data, "specialists", &arr);
    (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)n);
    char summary[160];
    (void)snprintf(summary, sizeof summary,
                   "%zu specialists; run `code focus <name>` for a ranked file list",
                   n);
    (void)json_push_kv_str(&reply->data, "summary", summary);
    json_free(&arr);
    json_free(&lines);
}

void zcl_native_handle_code_focus(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input || request->input->type != JSON_OBJ) {
        LOG_ERROR(CF_TAG, "BAD_CODE_FOCUS_INPUT: input must be one object");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "BAD_CODE_FOCUS_INPUT", "validate", false,
                               false, "code focus input must be one JSON object",
                               "code.focus");
        return;
    }

    bool list = json_get_bool_or(request->input, "list", false);
    const char *name = json_get_str(json_get(request->input, "specialist"));
    if (name && !name[0])
        name = NULL;
    if (list || !name) {
        focus_render_list(reply);
        return;
    }

    const struct specialist *spec = specialist_find(name);
    if (!spec) {
        LOG_ERROR(CF_TAG, "UNKNOWN_SPECIALIST: %s", name);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "UNKNOWN_SPECIALIST", "validate", false, false,
                               "no specialist with that name; run code focus --list",
                               name);
        return;
    }

    const char *root = focus_source_root(request);
    struct codeindex *ci = codeindex_open_source_view(root);
    if (!ci) {
        LOG_ERROR(CF_TAG, "CODEINDEX_OPEN: %s", root);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index",
                               root);
        return;
    }

    struct specialist_focus_evidence ev;
    specialist_focus_evidence_clear(&ev);
    bool loaded = specialist_focus_load_failed_groups(root, &ev) &&
                  specialist_focus_load_notes(root, &ev) &&
                  specialist_focus_load_issues(root, &ev) &&
                  specialist_focus_load_churn(root, &ev);
    if (!loaded) {
        codeindex_close(ci);
        LOG_ERROR(CF_TAG, "FOCUS_EVIDENCE: could not read recorded evidence");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FOCUS_EVIDENCE",
                               "dispatch", true, false,
                               "recorded focus evidence was unreadable",
                               root);
        return;
    }

    struct specialist_focus_hit hits[SPECIALIST_FOCUS_HIT_CAP];
    bool truncated = false;
    int n = specialist_focus_rank(ci, spec, &ev, focus_route, NULL, hits,
                                  SPECIALIST_FOCUS_HIT_CAP, &truncated);
    codeindex_close(ci);
    if (n < 0) {
        LOG_ERROR(CF_TAG, "FOCUS_RANK: ranking failed for %s", name);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FOCUS_RANK",
                               "dispatch", true, false,
                               "could not rank the specialist territory",
                               name);
        return;
    }

    struct json_value files, lines;
    json_init(&files);
    json_set_array(&files);
    json_init(&lines);
    json_set_array(&lines);
    for (int i = 0; i < n; i++) {
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "path", hits[i].path);
        (void)json_push_kv_int(&o, "score", hits[i].score);
        (void)json_push_kv_str(&o, "reason", hits[i].reason);
        focus_push_obj(&files, &o);
        char line[640];
        (void)snprintf(line, sizeof line, "%d  %s  %s", hits[i].score,
                       hits[i].path, hits[i].reason);
        focus_push_str(&lines, line);
    }
    (void)json_push_kv_str(&reply->data, "scope", "focus");
    (void)json_push_kv_str(&reply->data, "specialist", spec->name);
    (void)json_push_kv(&reply->data, "files", &files);
    (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv_int(&reply->data, "count", n);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);
    char summary[200];
    (void)snprintf(summary, sizeof summary,
                   "%s: %d file%s ranked from recorded evidence%s",
                   spec->name, n, n == 1 ? "" : "s",
                   truncated ? " (truncated)" : "");
    (void)json_push_kv_str(&reply->data, "summary", summary);
    json_free(&files);
    json_free(&lines);
}
