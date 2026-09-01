/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unified AI/operator liveness contract. This composes existing C-owned
 * contracts instead of re-implementing lane, quality, or supervisor logic. */

#include "controllers/agent_background_quality.h"
#include "controllers/agent_controller.h"
#include "controllers/agent_first_call.h"
#include "controllers/strong_params.h"

#include "json/json.h"
#include "rpc/server.h"
#include "util/clientversion.h"
#include "util/supervisor.h"

#include <stdint.h>
#include <string.h>

struct agent_liveness_supervisor_counts {
    int64_t child_count;
    int64_t stale_child_count;
    int64_t stall_fires_total;
    int64_t restart_count_total;
};

enum agent_liveness_detail_mode { AGENT_LIVENESS_DETAIL_BRIEF = 0,
                                  AGENT_LIVENESS_DETAIL_FULL = 1 };

static void agent_liveness_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void agent_liveness_copy_key(struct json_value *dst,
                                    const struct json_value *src,
                                    const char *key)
{
    const struct json_value *v = src ? json_get(src, key) : NULL;
    if (v)
        json_push_kv(dst, key, v);
}

static void agent_liveness_copy_keys(struct json_value *dst,
                                     const struct json_value *src,
                                     const char *const *keys,
                                     size_t key_count)
{
    for (size_t i = 0; i < key_count; i++)
        agent_liveness_copy_key(dst, src, keys[i]);
}

static const char *agent_liveness_detail_mode_name(enum agent_liveness_detail_mode mode)
{
    return mode == AGENT_LIVENESS_DETAIL_FULL ? "full" : "brief";
}

static bool agent_liveness_mode_is_brief(const char *mode)
{
    return !mode || !mode[0] || strcmp(mode, "default") == 0 ||
           strcmp(mode, "brief") == 0 || strcmp(mode, "compact") == 0 ||
           strcmp(mode, "summary") == 0;
}

static bool agent_liveness_mode_is_full(const char *mode)
{
    return mode &&
           (strcmp(mode, "full") == 0 || strcmp(mode, "detailed") == 0);
}

static bool agent_liveness_parse_detail_mode(
    const struct json_value *params, struct json_value *result,
    enum agent_liveness_detail_mode *mode)
{
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    const char *raw = rpc_permit_str(&p, 0, "mode", "brief");
    if (rpc_params_invalid(&p)) {
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.agent_liveness.v2");
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", p.error);
        json_push_kv_str(result, "allowed_modes",
                         "full,brief,compact,summary");
        return false;
    }
    if (agent_liveness_mode_is_brief(raw)) {
        *mode = AGENT_LIVENESS_DETAIL_BRIEF;
        return true;
    }
    if (agent_liveness_mode_is_full(raw)) {
        *mode = AGENT_LIVENESS_DETAIL_FULL;
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.agent_liveness.v2");
    json_push_kv_str(result, "status", "error");
    json_push_kv_str(result, "error", "invalid_agentliveness_mode");
    json_push_kv_str(result, "mode", raw ? raw : "");
    json_push_kv_str(result, "allowed_modes",
                     "full,brief,compact,summary");
    return false;
}

static void agent_liveness_count_children(
    const struct json_value *children,
    struct agent_liveness_supervisor_counts *counts)
{
    if (!children || children->type != JSON_ARR || !counts)
        return;
    for (size_t i = 0; i < json_size(children); i++) {
        const struct json_value *child = json_at(children, i);
        int64_t deadline_secs =
            json_get_int(json_get(child, "deadline_secs"));
        int64_t age_us =
            json_get_int(json_get(child, "last_tick_age_us"));
        int64_t stall_fires =
            json_get_int(json_get(child, "stall_fires"));
        int64_t restarts =
            json_get_int(json_get(child, "restart_count"));

        counts->child_count++;
        counts->stall_fires_total += stall_fires;
        counts->restart_count_total += restarts;
        if (deadline_secs > 0 && age_us > deadline_secs * 1000000LL)
            counts->stale_child_count++;
    }
}

static struct agent_liveness_supervisor_counts
agent_liveness_supervisor_counts(const struct json_value *supervisor)
{
    struct agent_liveness_supervisor_counts counts = {0};
    const struct json_value *domains = json_get(supervisor, "domains");
    const struct json_value *orphans = json_get(supervisor, "root_orphans");

    if (domains && domains->type == JSON_ARR) {
        for (size_t i = 0; i < json_size(domains); i++) {
            const struct json_value *domain = json_at(domains, i);
            agent_liveness_count_children(json_get(domain, "children"),
                                          &counts);
        }
    }
    agent_liveness_count_children(orphans, &counts);
    return counts;
}

static void agent_liveness_push_omissions(struct json_value *out)
{
    struct json_value omitted;
    json_init(&omitted);
    json_set_array(&omitted);
    agent_liveness_push_str(&omitted, "runtime_availability.methods");
    agent_liveness_push_str(&omitted, "background_quality_status.lanes");
    agent_liveness_push_str(&omitted, "supervisor_state.domains");
    agent_liveness_push_str(&omitted, "supervisor_state.root_orphans");
    json_push_kv(out, "omitted_sections", &omitted);
    json_free(&omitted);
}

static void agent_liveness_push_availability_compact(
    struct json_value *out, const struct json_value *full)
{
    static const char *const keys[] = {
        "schema", "schema_version", "source_identity_authority",
        "producer_source_id_sha256", "producer_build_commit",
        "operator_lane_name", "operator_lane_source",
        "operator_lane_declared", "operator_lane_inferred",
        "producer_datadir", "producer_rpcport", "availability_scope",
        "probe_source", "probe_status", "target_rpc_attempted",
        "target_rpc_reachable", "target_datadir", "target_rpcport",
        "target_source_id_sha256", "target_build_commit",
        "producer_target_source_relation",
        "producer_target_build_relation",
        "producer_target_build_relation_authority",
        "supported_count", "unsupported_count", "error_count",
        "unknown_count", "safe_next_action",
    };
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    agent_liveness_copy_keys(&obj, full, keys, sizeof(keys) / sizeof(keys[0]));
    json_push_kv_str(&obj, "object_completeness", "compact");
    json_push_kv_str(&obj, "full_detail_command",
                     "z23 agentliveness full");
    json_push_kv(out, "runtime_availability", &obj);
    json_free(&obj);
}

static void agent_liveness_push_quality_compact(
    struct json_value *out, const struct json_value *full)
{
    static const char *const keys[] = {
        "schema", "api_version", "status", "native_status_reader",
        "requires_python", "status_command", "state_path_valid",
        "pre_push_blocks_on_long_lanes", "lanes_configured",
        "status_files_present", "status_files_valid", "passed_count",
        "skipped_count", "running_count", "failed_count",
        "current_commit_count", "stale_commit_count",
        "unknown_commit_count", "summary", "agent_next_action",
    };
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    agent_liveness_copy_keys(&obj, full, keys, sizeof(keys) / sizeof(keys[0]));
    json_push_kv_str(&obj, "object_completeness", "compact");
    json_push_kv_str(&obj, "full_detail_command",
                     "z23 agentliveness full");
    json_push_kv(out, "background_quality_status", &obj);
    json_free(&obj);
}

static void agent_liveness_push_supervisor_compact(
    struct json_value *out, const struct json_value *full,
    const struct agent_liveness_supervisor_counts *counts)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "object_completeness", "compact");
    agent_liveness_copy_key(&obj, full, "running");
    agent_liveness_copy_key(&obj, full, "thread_alive");
    agent_liveness_copy_key(&obj, full, "tick_ms");
    agent_liveness_copy_key(&obj, full, "child_count");
    json_push_kv_int(&obj, "observed_child_count",
                     counts ? counts->child_count : 0);
    json_push_kv_int(&obj, "stale_child_count",
                     counts ? counts->stale_child_count : 0);
    json_push_kv_int(&obj, "stall_fires_total",
                     counts ? counts->stall_fires_total : 0);
    json_push_kv_int(&obj, "restart_count_total",
                     counts ? counts->restart_count_total : 0);
    json_push_kv_str(&obj, "full_detail_command",
                     "z23 agentliveness full");
    json_push_kv(out, "supervisor_state", &obj);
    json_free(&obj);
}

static void agent_liveness_push_drilldowns(struct json_value *out,
                                           bool attention_needed)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    agent_push_contract_native_command_json(&arr, "agent");
    agent_push_contract_native_command_json(&arr, "agentlanes");
    agent_liveness_push_str(&arr, "z23 dumpstate supervisor");
    agent_push_contract_native_command_json(&arr, "agentbuild");
    agent_liveness_push_str(&arr, "make quality-linger-status");
    if (attention_needed) {
        agent_liveness_push_str(&arr,
            "z23 getnodelog 'stall|stale|fail|restart|quality'");
    }
    json_push_kv(out, "recommended_drilldowns", &arr);
    json_free(&arr);
}

static void agent_liveness_push_summary(struct json_value *out,
                                        const struct json_value *lane,
                                        const struct json_value *runtime,
                                        const struct json_value *availability,
                                        const struct json_value *quality,
                                        const struct json_value *supervisor)
{
    struct agent_liveness_supervisor_counts sup =
        agent_liveness_supervisor_counts(supervisor);
    bool supervisor_running = json_get_bool(json_get(supervisor, "running"));
    bool supervisor_thread_alive =
        json_get_bool(json_get(supervisor, "thread_alive"));
    bool rpc_running = json_get_bool(json_get(runtime, "rpc_running"));
    bool https_running = json_get_bool(json_get(runtime, "https_running"));
    bool fs_running = json_get_bool(json_get(runtime, "fs_running"));
    int64_t quality_failed =
        json_get_int(json_get(quality, "failed_count"));
    int64_t quality_running =
        json_get_int(json_get(quality, "running_count"));
    int64_t quality_valid =
        json_get_int(json_get(quality, "status_files_valid"));
    int64_t quality_configured =
        json_get_int(json_get(quality, "lanes_configured"));
    const char *quality_summary =
        json_get_str(json_get(quality, "summary"));
    const char *lane_name =
        json_get_str(json_get(lane, "lane"));
    bool in_process_runtime_active =
        supervisor_running || supervisor_thread_alive ||
        rpc_running || https_running || fs_running;
    bool target_rpc_attempted =
        json_get_bool(json_get(availability, "target_rpc_attempted"));
    bool target_rpc_reachable =
        json_get_bool(json_get(availability, "target_rpc_reachable"));
    const char *availability_scope =
        json_get_str(json_get(availability, "availability_scope"));
    bool attention_needed = quality_failed > 0 ||
                            sup.stale_child_count > 0 ||
                            sup.stall_fires_total > 0 ||
                            (supervisor_running && !supervisor_thread_alive);
    bool effective_runtime_reachable =
        in_process_runtime_active || target_rpc_reachable;
    const char *effective_runtime_scope =
        in_process_runtime_active ? "producer_runtime" :
        (target_rpc_reachable ? "target_rpc_probe" : "none");
    const char *producer_runtime_state =
        in_process_runtime_active ? "active" : "inactive_or_static_probe";
    const char *target_runtime_state =
        target_rpc_attempted ? (target_rpc_reachable ? "reachable"
                                                     : "unreachable")
                             : "not_probed";
    const char *overall = attention_needed ? "attention_needed" :
        (in_process_runtime_active ? "active" :
         (target_rpc_reachable ? "target_runtime_reachable"
                               : "static_or_offline_context"));
    const char *next_action = attention_needed
        ? "inspect_agent_liveness_drilldowns"
        : (in_process_runtime_active ? "monitor_liveness_and_quality_lanes"
          : (target_rpc_reachable
                 ? "monitor_target_runtime"
                 : "probe_target_runtime_or_start_dev_lane"));

    struct json_value summary;
    json_init(&summary);
    json_set_object(&summary);
    json_push_kv_str(&summary, "lane", lane_name);
    json_push_kv_bool(&summary, "runtime_active", in_process_runtime_active);
    json_push_kv_bool(&summary, "in_process_runtime_active",
                      in_process_runtime_active);
    json_push_kv_bool(&summary, "producer_runtime_active",
                      in_process_runtime_active);
    json_push_kv_str(&summary, "producer_runtime_state",
                     producer_runtime_state);
    json_push_kv_bool(&summary, "target_rpc_attempted",
                      target_rpc_attempted);
    json_push_kv_bool(&summary, "target_runtime_reachable",
                      target_rpc_reachable);
    json_push_kv_str(&summary, "target_runtime_state",
                     target_runtime_state);
    json_push_kv_bool(&summary, "effective_runtime_reachable",
                      effective_runtime_reachable);
    json_push_kv_str(&summary, "effective_runtime_scope",
                     effective_runtime_scope);
    json_push_kv_str(&summary, "runtime_observation_scope",
                     availability_scope && availability_scope[0]
                         ? availability_scope : "producer_runtime");
    json_push_kv_bool(&summary, "attention_needed", attention_needed);
    json_push_kv_bool(&summary, "rpc_running", rpc_running);
    json_push_kv_bool(&summary, "https_running", https_running);
    json_push_kv_bool(&summary, "fs_running", fs_running);
    json_push_kv_bool(&summary, "supervisor_running", supervisor_running);
    json_push_kv_bool(&summary, "supervisor_thread_alive",
                      supervisor_thread_alive);
    json_push_kv_int(&summary, "supervisor_child_count", sup.child_count);
    json_push_kv_int(&summary, "supervisor_stale_child_count",
                     sup.stale_child_count);
    json_push_kv_int(&summary, "supervisor_stall_fires_total",
                     sup.stall_fires_total);
    json_push_kv_int(&summary, "supervisor_restart_count_total",
                     sup.restart_count_total);
    json_push_kv_str(&summary, "background_quality_summary",
                     quality_summary);
    json_push_kv_int(&summary, "background_quality_lanes_configured",
                     quality_configured);
    json_push_kv_int(&summary, "background_quality_status_files_valid",
                     quality_valid);
    json_push_kv_int(&summary, "background_quality_running_count",
                     quality_running);
    json_push_kv_int(&summary, "background_quality_failed_count",
                     quality_failed);
    json_push_kv_str(&summary, "overall_liveness", overall);
    json_push_kv_str(&summary, "agent_next_action", next_action);
    json_push_kv(out, "liveness_summary", &summary);
    json_free(&summary);

    json_push_kv_str(out, "overall_liveness", overall);
    json_push_kv_str(out, "agent_next_action", next_action);
    agent_liveness_push_drilldowns(out, attention_needed);
}

bool rpc_agent_liveness(const struct json_value *params, bool help,
                        struct json_value *result)
{
    RPC_HELP(help, result,
        "agentliveness [full|brief]\n"
        "\nReturn one AI/operator liveness contract that composes lane identity,\n"
        "runtime listeners, supervisor children, and background quality lanes.\n"
        "Default brief mode keeps bounded summary/count fields; full mode embeds\n"
        "availability methods, supervisor domains, and quality lane details.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_liveness.v2\", "
        "\"liveness_summary\":{...} }\n");

    int64_t first_call_started_us = agent_first_call_start_us();
    bool quality_skipped_for_budget = false;
    enum agent_liveness_detail_mode detail_mode =
        AGENT_LIVENESS_DETAIL_BRIEF;
    if (!agent_liveness_parse_detail_mode(params, result, &detail_mode))
        return true;
    bool brief_mode = detail_mode == AGENT_LIVENESS_DETAIL_BRIEF;
    struct json_value fragments, supervisor_state, quality_status;
    struct agent_liveness_supervisor_counts supervisor_counts;
    json_set_object(result);
    json_init(&fragments);
    json_set_object(&fragments);
    agent_push_contract_identity_fields_json(result, "agentliveness");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "detail_mode",
                     agent_liveness_detail_mode_name(detail_mode));
    json_push_kv_bool(result, "embedded_drilldowns", !brief_mode);
    json_push_kv_str(result, "semantics",
                     "read-only composition of current_runtime_lane, runtime_services, supervisor_state, and background_quality_status");
    json_push_kv_str(result, "full_mode_command",
                     "z23 agentliveness full");
    json_push_kv_str(result, "full_mode_params", "{\"mode\":\"full\"}");

    agent_push_operator_lane_json(&fragments, "current_runtime_lane");
    agent_push_runtime_services_json(&fragments, "runtime_services");
    agent_push_runtime_availability_json(&fragments, "runtime_availability");

    json_init(&supervisor_state);
    if (!supervisor_dump_state_json(&supervisor_state, NULL)) {
        json_free(&supervisor_state);
        json_set_object(&supervisor_state);
        json_push_kv_str(&supervisor_state, "status", "unavailable");
    }

    json_init(&quality_status);
    if (agent_first_call_budget_exceeded(
            first_call_started_us,
            ZCL_AGENT_FIRST_CALL_BUDGET_LIVENESS_MS)) {
        quality_skipped_for_budget = true;
        json_set_object(&quality_status);
        json_push_kv_str(&quality_status, "schema",
                         "zcl.background_quality_runtime.v1");
        json_push_kv_str(&quality_status, "status", "skipped");
        json_push_kv_str(&quality_status, "summary",
                         "background_quality_skipped_due_to_first_call_budget");
        json_push_kv_int(&quality_status, "lanes_configured", 0);
        json_push_kv_int(&quality_status, "status_files_valid", 0);
        json_push_kv_int(&quality_status, "running_count", 0);
        json_push_kv_int(&quality_status, "failed_count", 0);
        json_push_kv_bool(&quality_status, "partial_result", true);
        json_push_kv_str(&quality_status, "partial_reason",
                         "first_call_budget_exhausted_before_quality_scan");
    } else {
        agent_build_background_quality_status(&quality_status);
    }
    json_push_kv(&fragments, "supervisor_state", &supervisor_state);
    json_push_kv(&fragments, "background_quality_status", &quality_status);

    supervisor_counts = agent_liveness_supervisor_counts(&supervisor_state);
    json_push_kv(result, "current_runtime_lane",
                 json_get(&fragments, "current_runtime_lane"));
    json_push_kv(result, "runtime_services",
                 json_get(&fragments, "runtime_services"));
    if (brief_mode) {
        agent_liveness_push_availability_compact(
            result, json_get(&fragments, "runtime_availability"));
        agent_liveness_push_supervisor_compact(
            result, &supervisor_state, &supervisor_counts);
        agent_liveness_push_quality_compact(result, &quality_status);
        agent_liveness_push_omissions(result);
    } else {
        json_push_kv(result, "runtime_availability",
                     json_get(&fragments, "runtime_availability"));
        json_push_kv(result, "supervisor_state", &supervisor_state);
        json_push_kv(result, "background_quality_status", &quality_status);
    }
    agent_liveness_push_summary(
        result,
        json_get(&fragments, "current_runtime_lane"),
        json_get(&fragments, "runtime_services"),
        json_get(&fragments, "runtime_availability"),
        &quality_status,
        &supervisor_state);

    agent_push_first_call_simple_json(
        result, "first_call", "agentliveness",
        brief_mode ? "runtime_supervisor_quality_status_brief"
                   : "runtime_supervisor_quality_status_full",
        ZCL_AGENT_FIRST_CALL_BUDGET_LIVENESS_MS, first_call_started_us,
        brief_mode || quality_skipped_for_budget,
        brief_mode ? "brief_mode_omits_embedded_drilldowns" :
        quality_skipped_for_budget
            ? "first_call_budget_exhausted_before_quality_scan" : "",
        brief_mode ? "z23 agentliveness full" : "");

    json_free(&quality_status);
    json_free(&supervisor_state);
    json_free(&fragments);
    return true;
}
