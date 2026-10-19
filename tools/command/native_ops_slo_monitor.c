/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ops.host.slo.probe / page / judge: the node SLO monitors as native leaves.
 * They replace the node_slo_probe, slo_page_if_stalled and slo_hold_judge
 * shell instruments the standing timers used to run, keep the ledger paths
 * and row formats those wrote, and never act on a node: they dial its RPC
 * port as any outside client would and record what came back. */

#include "command/native_command.h"
#include "command/slo_monitor_io.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/slo_monitor.h"

#include <stdio.h>
#include <string.h>

static void push_strings(struct json_value *obj, const char *key,
                         const char *rows, size_t stride, size_t n)
{
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n; i++) {
        json_init(&item);
        json_set_str(&item, rows + i * stride);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv(obj, key, &arr);
    json_free(&arr);
}

static void push_opt(struct json_value *obj, const char *key,
                     struct slo_opt value)
{
    struct json_value v;
    json_init(&v);
    if (value.has)
        json_set_int(&v, value.v);
    else
        json_set_null(&v);
    (void)json_push_kv(obj, key, &v);
    json_free(&v);
}

static void fail(struct zcl_command_reply *reply,
                 enum zcl_command_exit exit_code, const char *code,
                 const char *phase, const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, exit_code == ZCL_COMMAND_EXIT_FAILED, false,
                           message, evidence);
}

void zcl_native_handle_ops_host_slo_probe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct slo_probe_config cfg;
    struct slo_probe_result res;
    if (!reply)
        return;
    if (!slo_io_probe_config(&cfg)) {
        fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "SLO_NO_HOME", "resolve",
             "HOME is not set, so the instance table cannot be resolved",
             "HOME");
        return;
    }
    bool ok = slo_probe_collect(&cfg, slo_io_probe(), &res);
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "ledger", res.ledger);
    (void)json_push_kv_int(&reply->data, "samples", (int64_t)res.samples);
    push_opt(&reply->data, "oracle_height", res.oracle_height);
    push_opt(&reply->data, "max_height", res.max_height);
    (void)json_push_kv_bool(&reply->data, "any_unreachable",
                            res.any_unreachable);
    (void)json_push_kv_bool(&reply->data, "any_blind", res.any_blind);
    push_strings(&reply->data, "notes", res.notes[0], SLO_NOTE_LEN,
                 res.nnotes);
    if (!ok) {
        fail(reply, ZCL_COMMAND_EXIT_FAILED, "SLO_LEDGER_WRITE", "append",
             "the probe cycle could not append to its ledger", res.ledger);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void push_conditions(struct json_value *obj,
                            const struct slo_page_eval *eval)
{
    struct json_value arr, row;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < eval->ncond; i++) {
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "condition", eval->cond[i].id);
        (void)json_push_kv_str(&row, "detail", eval->cond[i].detail);
        push_opt(&row, "served_height", eval->cond[i].served);
        push_opt(&row, "oracle_height", eval->cond[i].oracle);
        push_opt(&row, "gap_vs_oracle", eval->cond[i].gap);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(obj, "active", &arr);
    json_free(&arr);
}

static void page_failure(struct zcl_command_reply *reply,
                         const struct slo_page_eval *eval)
{
    char ids[128] = "";
    struct slo_text t;
    slo_text_init(&t, ids, sizeof(ids));
    for (size_t i = 0; i < eval->ncond; i++)
        slo_text_addf(&t, "%s%s", i ? "," : "", eval->cond[i].id);
    char message[192];
    snprintf(message, sizeof(message), "page conditions active: %s", ids);
    fail(reply, ZCL_COMMAND_EXIT_FAILED, "SLO_PAGE_ACTIVE", "evaluate",
         message, eval->summary);
}

void zcl_native_handle_ops_host_slo_page(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct slo_probe_config probe;
    struct slo_page_config cfg;
    struct slo_page_eval eval;
    struct slo_page_outcome out;
    char ledger[SLO_PATH_MAX];
    if (!reply)
        return;
    slo_io_page_config(&cfg);
    if (!slo_io_probe_config(&probe) ||
        !slo_monitor_file("uptime-ledger.jsonl", ledger, sizeof(ledger)) ||
        !slo_page_evaluate(ledger, &cfg, &eval) ||
        !slo_page_announce(&cfg, slo_io_page(&probe.inst[0]), &eval, &out)) {
        fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "SLO_PAGE_UNAVAILABLE",
             "evaluate", "the pager could not read or record its ledgers",
             ledger);
        return;
    }
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "summary", eval.summary);
    (void)json_push_kv_int(&reply->data, "announced", (int64_t)out.announced);
    (void)json_push_kv_int(&reply->data, "deduped", (int64_t)out.deduped);
    push_conditions(&reply->data, &eval);
    push_strings(&reply->data, "notes", out.notes[0], SLO_NOTE_LEN,
                 out.nnotes);
    if (eval.ncond > 0) {
        page_failure(reply, &eval);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static bool judge_input(const struct zcl_command_request *request,
                        struct slo_hold_config *cfg, bool *record,
                        struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    const struct json_value *inst = json_get(in, "instance");
    const struct json_value *hours = json_get(in, "window_hours");
    const struct json_value *gap = json_get(in, "gap_budget");
    const struct json_value *rec = json_get(in, "record");
    *record = rec && rec->type == JSON_BOOL && json_get_bool(rec);
    if (inst && inst->type == JSON_STR)
        snprintf(cfg->instance, sizeof(cfg->instance), "%s",
                 json_get_str(inst));
    if (hours && hours->type == JSON_INT)
        cfg->window_hours = json_get_int(hours);
    if (gap && gap->type == JSON_INT)
        cfg->gap_budget = json_get_int(gap);
    if (slo_hold_instance_known(cfg->instance) && cfg->window_hours > 0)
        return true;
    fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_HOLD_INPUT", "validate",
         "instance must be canonical, soak or dev and window_hours must be "
         "a positive integer", cfg->instance);
    return false;
}

static void push_report(struct json_value *obj,
                        const struct slo_hold_config *cfg,
                        const struct slo_hold_report *rep)
{
    json_set_object(obj);
    (void)json_push_kv_str(obj, "instance", cfg->instance);
    (void)json_push_kv_int(obj, "window_hours", cfg->window_hours);
    (void)json_push_kv_int(obj, "gap_budget", cfg->gap_budget);
    (void)json_push_kv_str(obj, "verdict", rep->verdict);
    (void)json_push_kv_str(obj, "reason", rep->reason);
    (void)json_push_kv_int(obj, "judge_rc", rep->rc);
    push_strings(obj, "criteria", rep->lines[0], SLO_HOLD_LINE_LEN,
                 rep->nlines);
}

void zcl_native_handle_ops_host_slo_judge(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct slo_hold_config cfg;
    struct slo_hold_report rep;
    char ledger[SLO_PATH_MAX], pages[SLO_PATH_MAX];
    bool record = false;
    if (!reply)
        return;
    slo_io_hold_config(&cfg);
    if (!judge_input(request, &cfg, &record, reply))
        return;
    if (!slo_monitor_file("uptime-ledger.jsonl", ledger, sizeof(ledger)) ||
        !slo_io_pages_path(pages, sizeof(pages)) ||
        !slo_hold_judge(ledger, pages, &cfg, &rep)) {
        fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "SLO_HOLD_UNAVAILABLE", "read",
             "the hold judge could not read its ledgers", ledger);
        return;
    }
    push_report(&reply->data, &cfg, &rep);
    if (record && !slo_hold_record(&cfg, &rep)) {
        fail(reply, ZCL_COMMAND_EXIT_FAILED, "SLO_HOLD_RECORD", "append",
             "the verdict could not be appended to hold-ledger.jsonl", ledger);
        return;
    }
    if (!record && !rep.proven) {
        fail(reply, ZCL_COMMAND_EXIT_FAILED, "HOLD_NOT_PROVEN", "judge",
             "the hold bar is not proven", rep.lines[rep.nlines - 1]);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
