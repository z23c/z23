/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.triggers.list` and `fleet.triggers.check` handlers —
 * CLI glue over the registry (native_fleet_triggers_catalog.c) and the
 * run-once evaluator (native_fleet_triggers_eval.c). */

#include "command/native_fleet_triggers.h"

#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <string.h>

static void trg_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "input", false,
                           false, message, evidence);
}

void zcl_native_handle_fleet_triggers_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_triggers_list.v1");

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    char text[8192];
    size_t tlen = 0;
    text[0] = 0;

    size_t count = zcl_trigger_count();
    for (size_t i = 0; i < count; i++) {
        const struct zcl_trigger_row *t = zcl_trigger_at(i);
        if (!t)
            continue;
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "id", t->id);
        (void)json_push_kv_str(&row, "source", t->source_name);
        (void)json_push_kv_str(&row, "field", t->field);
        (void)json_push_kv_str(&row, "op", t->op_name);
        (void)json_push_kv_str(&row, "value", t->value);
        (void)json_push_kv_str(&row, "action", t->action_name);
        (void)json_push_kv_str(&row, "why", t->why);
        (void)json_push_back(&rows, &row);
        json_free(&row);

        int wrote = snprintf(text + tlen, sizeof text - tlen,
                             "%-28s %-18s %-10s %-9s %-10s %-7s %s\n", t->id,
                             t->source_name, t->field, t->op_name, t->value,
                             t->action_name, t->why);
        if (wrote > 0 && (size_t)wrote < sizeof text - tlen)
            tlen += (size_t)wrote;
    }

    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet_triggers_list.v1");
    (void)json_push_kv_int(&reply->data, "count", (int64_t)count);
    (void)json_push_kv(&reply->data, "triggers", &rows);
    (void)json_push_kv_str(&reply->data, "text", text);
    json_free(&rows);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* --since=<seconds>: a non-negative integer, defaulting to 0 (no filter).
 * --dry-run: a bare flag, defaulting to false. */
static bool trg_read_since(const struct json_value *input, int64_t *out,
                           struct zcl_command_reply *reply)
{
    *out = 0;
    if (!input)
        return true;
    const struct json_value *v = json_get(input, "since");
    if (!v)
        return true;
    if (v->type != JSON_INT || json_get_int(v) < 0) {
        trg_refuse(reply, "SINCE_INVALID",
                  "--since must be a non-negative integer number of seconds",
                  "input.since");
        return false;
    }
    *out = json_get_int(v);
    return true;
}

static bool trg_read_dry_run(const struct json_value *input)
{
    if (!input)
        return false;
    const struct json_value *v = json_get(input, "dry-run");
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

void zcl_native_handle_fleet_triggers_check(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_triggers_check.v1");

    int64_t since_s = 0;
    if (!trg_read_since(request ? request->input : NULL, &since_s, reply))
        return;
    bool dry_run = trg_read_dry_run(request ? request->input : NULL);

    struct json_value fired_ids;
    json_init(&fired_ids);
    json_set_array(&fired_ids);

    uint64_t checked = 0, fired = 0;
    char why[256] = "";
    if (!zcl_trigger_check_run(dry_run, since_s, &checked, &fired, &fired_ids,
                              why, sizeof why)) {
        json_free(&fired_ids);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                              ZCL_COMMAND_EXIT_INTERNAL, "CHECK_FAILED",
                              "execute", true, false,
                              why[0] ? why : "trigger check did not complete",
                              "fleet.triggers.check");
        return;
    }

    char text[128];
    (void)snprintf(text, sizeof text, "checked %llu rows, fired %llu\n",
                  (unsigned long long)checked, (unsigned long long)fired);

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.fleet_triggers_check.v1");
    (void)json_push_kv_int(&reply->data, "checked", (int64_t)checked);
    (void)json_push_kv_int(&reply->data, "fired", (int64_t)fired);
    (void)json_push_kv_int(&reply->data, "since", since_s);
    (void)json_push_kv_bool(&reply->data, "dry_run", dry_run);
    (void)json_push_kv(&reply->data, "fired_ids", &fired_ids);
    (void)json_push_kv_str(&reply->data, "text", text);
    json_free(&fired_ids);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
