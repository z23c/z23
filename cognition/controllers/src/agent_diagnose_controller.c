/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded diagnosis contract for AI/operator first calls. This composes
 * already-bounded C-owned views and marks skipped lower-priority sections
 * explicitly instead of blocking on a heavy drill-down. */

#include "controllers/agent_controller.h"
#include "controllers/agent_first_call.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/event_healthcheck_controller.h"
#include "controllers/event_timeline_controller.h"
#include "controllers/strong_params.h"

#include "event_agent_summary.h"

#include "json/json.h"
#include "net/peer_lifecycle.h"
#include "rpc/server.h"
#include "util/clientversion.h"

#include <stdint.h>
#include <string.h>

enum diagnose_detail_mode {
    DIAGNOSE_DETAIL_FULL = 0,
    DIAGNOSE_DETAIL_BRIEF = 1,
};

static void diagnose_push_str(struct json_value *arr, const char *s)
{
    struct json_value v = {0};
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void diagnose_push_finding(struct json_value *arr,
                                  const char *name,
                                  const char *severity,
                                  const char *detail,
                                  const char *next_action)
{
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "name", name ? name : "");
    json_push_kv_str(&obj, "severity", severity ? severity : "info");
    json_push_kv_str(&obj, "detail", detail ? detail : "");
    json_push_kv_str(&obj, "next_action", next_action ? next_action : "");
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void diagnose_push_skipped(struct json_value *out, const char *key,
                                  const char *reason)
{
    struct json_value skipped = {0};
    json_set_object(&skipped);
    json_push_kv_str(&skipped, "status", "skipped");
    json_push_kv_bool(&skipped, "partial_result", true);
    json_push_kv_str(&skipped, "partial_reason", reason ? reason : "");
    json_push_kv(out, key, &skipped);
    json_free(&skipped);
}

static const char *diagnose_detail_mode_name(enum diagnose_detail_mode mode)
{
    return mode == DIAGNOSE_DETAIL_BRIEF ? "brief" : "full";
}

static bool diagnose_detail_mode_is_brief(const char *mode)
{
    return !mode || !mode[0] || strcmp(mode, "default") == 0 ||
           strcmp(mode, "brief") == 0 || strcmp(mode, "compact") == 0 ||
           strcmp(mode, "summary") == 0;
}

static bool diagnose_detail_mode_is_full(const char *mode)
{
    return mode && (strcmp(mode, "full") == 0 || strcmp(mode, "detailed") == 0);
}

static bool diagnose_parse_detail_mode(const struct json_value *params,
                                       struct json_value *result,
                                       enum diagnose_detail_mode *mode)
{
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 1);
    const char *raw = rpc_permit_str(&p, 0, "mode", "brief");
    if (rpc_params_invalid(&p)) {
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.agent_diagnose.v2");
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "error", p.error);
        json_push_kv_str(result, "allowed_modes",
                         "full,brief,compact,summary");
        return false;
    }
    if (diagnose_detail_mode_is_brief(raw)) {
        *mode = DIAGNOSE_DETAIL_BRIEF;
        return true;
    }
    if (diagnose_detail_mode_is_full(raw)) {
        *mode = DIAGNOSE_DETAIL_FULL;
        return true;
    }

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.agent_diagnose.v2");
    json_push_kv_str(result, "status", "error");
    json_push_kv_str(result, "error", "invalid_agentdiagnose_mode");
    json_push_kv_str(result, "mode", raw ? raw : "");
    json_push_kv_str(result, "allowed_modes",
                     "full,brief,compact,summary");
    return false;
}

static void diagnose_push_brief_omissions(struct json_value *out)
{
    struct json_value omitted = {0};
    json_set_array(&omitted);
    diagnose_push_str(&omitted, "agent");
    diagnose_push_str(&omitted, "healthcheck");
    diagnose_push_str(&omitted, "peer_incidents");
    diagnose_push_str(&omitted, "mirror");
    diagnose_push_str(&omitted, "timeline");
    json_push_kv(out, "omitted_sections", &omitted);
    json_free(&omitted);
}

static void diagnose_timeline_params(struct json_value *params)
{
    struct json_value category = {0};
    struct json_value count = {0};

    json_set_array(params);
    json_set_str(&category, "all");
    json_push_back(params, &category);
    json_free(&category);
    json_set_int(&count, 12);
    json_push_back(params, &count);
    json_free(&count);
}

static bool diagnose_agent_chain_ready(const struct json_value *agent)
{
    const struct json_value *readiness = agent ? json_get(agent, "readiness")
                                               : NULL;
    if (readiness)
        return json_get_bool(json_get(readiness, "chain_serving_ready"));
    return agent && json_get_bool(json_get(agent, "chain_serving_ready"));
}

static bool diagnose_agent_normal_lookahead(const struct json_value *agent)
{
    const struct json_value *height_contract =
        agent ? json_get(agent, "height_contract") : NULL;
    return height_contract &&
           json_get_bool(json_get(height_contract, "normal_lookahead"));
}

static bool diagnose_peer_incident_material(const struct json_value *incident)
{
    if (!incident || incident->type != JSON_OBJ)
        return false;
    if (json_get_int(json_get(incident, "duplicate_host_entries")) > 1)
        return true;
    if (json_get_int(json_get(incident, "reconnects")) > 0)
        return true;
    if (json_get_int(json_get(incident, "timeout")) > 0)
        return true;
    if (json_get_int(json_get(incident, "rejected")) > 0)
        return true;
    if (json_get_int(json_get(incident, "pre_handshake_disconnects")) > 1)
        return true;
    return false;
}

static int64_t diagnose_peer_material_incidents(const struct json_value *peers)
{
    const struct json_value *top =
        peers ? json_get(peers, "top_incidents") : NULL;
    if (!top || top->type != JSON_ARR)
        return 0;
    int64_t material = 0;
    for (size_t i = 0; i < json_size(top); i++) {
        if (diagnose_peer_incident_material(json_at(top, i)))
            material++;
    }
    return material;
}

static bool diagnose_peer_group_material(const struct json_value *group)
{
    if (!group || group->type != JSON_OBJ)
        return false;
    if (json_get_int(json_get(group, "entries")) > 1)
        return true;
    if (json_get_int(json_get(group, "reconnects")) > 0)
        return true;
    if (json_get_int(json_get(group, "timeout")) > 0)
        return true;
    if (json_get_int(json_get(group, "rejected")) > 0)
        return true;
    if (json_get_int(json_get(group, "pre_handshake_disconnects")) > 1)
        return true;
    return false;
}

static int64_t diagnose_peer_material_groups(const struct json_value *peers)
{
    const struct json_value *groups =
        peers ? json_get(peers, "duplicate_host_groups") : NULL;
    if (!groups || groups->type != JSON_ARR)
        return 0;
    int64_t material = 0;
    for (size_t i = 0; i < json_size(groups); i++) {
        if (diagnose_peer_group_material(json_at(groups, i)))
            material++;
    }
    return material;
}

static const struct json_value *diagnose_peer_primary_host(
    const struct json_value *peers)
{
    const struct json_value *primary =
        peers ? json_get(peers, "primary_host_issue") : NULL;
    return primary && primary->type == JSON_OBJ ? primary : NULL;
}

static const char *diagnose_peer_host_str(const struct json_value *primary,
                                          const char *key)
{
    return primary ? json_get_str(json_get(primary, key)) : "";
}

static int64_t diagnose_peer_host_int(const struct json_value *primary,
                                      const char *key)
{
    return primary ? json_get_int(json_get(primary, key)) : 0;
}

static bool diagnose_peer_host_bool(const struct json_value *primary,
                                    const char *key)
{
    return primary && json_get_bool(json_get(primary, key));
}

static bool diagnose_peer_host_action_is_specific(const char *action)
{
    return action && action[0] &&
           strcmp(action, "monitor_peer_lifecycle") != 0;
}

static void diagnose_push_primary_host_issue(struct json_value *out,
                                             const struct json_value *primary)
{
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.peer_primary_host_issue.v1");
    json_push_kv_str(&obj, "status",
                     diagnose_peer_host_str(primary, "status"));
    json_push_kv_str(&obj, "host",
                     diagnose_peer_host_str(primary, "host"));
    json_push_kv_str(&obj, "issue_class",
                     diagnose_peer_host_str(primary, "issue_class"));
    json_push_kv_str(&obj, "next_action",
                     diagnose_peer_host_str(primary, "next_action"));
    json_push_kv_str(&obj, "direction",
                     diagnose_peer_host_str(primary, "direction"));
    json_push_kv_bool(&obj, "mixed_direction",
                      diagnose_peer_host_bool(primary, "mixed_direction"));
    json_push_kv_str(&obj, "current_open_direction",
                     diagnose_peer_host_str(primary,
                                            "current_open_direction"));
    json_push_kv_bool(&obj, "current_open_mixed_direction",
                      diagnose_peer_host_bool(primary,
                                             "current_open_mixed_direction"));
    json_push_kv_str(&obj, "current_handshaked_direction",
                     diagnose_peer_host_str(
                         primary, "current_handshaked_direction"));
    json_push_kv_bool(
        &obj, "current_handshaked_mixed_direction",
        diagnose_peer_host_bool(primary,
                                "current_handshaked_mixed_direction"));
    json_push_kv_int(&obj, "incident_score",
                     diagnose_peer_host_int(primary, "incident_score"));
    json_push_kv_int(&obj, "entries",
                     diagnose_peer_host_int(primary, "entries"));
    json_push_kv_int(&obj, "open_connections",
                     diagnose_peer_host_int(primary, "open_connections"));
    json_push_kv_int(&obj, "current_open_inbound_connections",
                     diagnose_peer_host_int(
                         primary, "current_open_inbound_connections"));
    json_push_kv_int(&obj, "current_open_outbound_connections",
                     diagnose_peer_host_int(
                         primary, "current_open_outbound_connections"));
    json_push_kv_int(&obj, "current_open_unknown_connections",
                     diagnose_peer_host_int(
                         primary, "current_open_unknown_connections"));
    json_push_kv_int(&obj, "handshaked_open_connections",
                     diagnose_peer_host_int(primary,
                                           "handshaked_open_connections"));
    json_push_kv_int(&obj, "current_handshaked_inbound_connections",
                     diagnose_peer_host_int(
                         primary, "current_handshaked_inbound_connections"));
    json_push_kv_int(&obj, "current_handshaked_outbound_connections",
                     diagnose_peer_host_int(
                         primary, "current_handshaked_outbound_connections"));
    json_push_kv_int(&obj, "current_handshaked_unknown_connections",
                     diagnose_peer_host_int(
                         primary,
                         "current_handshaked_unknown_connections"));
    json_push_kv_int(&obj, "handshaked_network_connections",
                     diagnose_peer_host_int(primary,
                                           "handshaked_network_connections"));
    json_push_kv_int(&obj, "handshaked_advertised_height_connections",
                     diagnose_peer_host_int(
                         primary, "handshaked_advertised_height_connections"));
    json_push_kv_int(&obj, "handshaked_zclassic23_connections",
                     diagnose_peer_host_int(
                         primary, "handshaked_zclassic23_connections"));
    json_push_kv_int(&obj, "bootstrap_useful_connections",
                     diagnose_peer_host_int(primary,
                                           "bootstrap_useful_connections"));
    json_push_kv_int(&obj, "fast_sync_useful_connections",
                     diagnose_peer_host_int(primary,
                                           "fast_sync_useful_connections"));
    json_push_kv_bool(&obj, "duplicate_current_connections",
                      diagnose_peer_host_bool(primary,
                                             "duplicate_current_connections"));
    json_push_kv_bool(&obj, "duplicate_handshaked_connections",
                      diagnose_peer_host_bool(
                          primary, "duplicate_handshaked_connections"));
    json_push_kv_str(&obj, "bootstrap_readiness",
                     diagnose_peer_host_str(primary, "bootstrap_readiness"));
    json_push_kv_str(&obj, "fast_sync_readiness",
                     diagnose_peer_host_str(primary, "fast_sync_readiness"));
    json_push_kv_int(&obj, "timeout",
                     diagnose_peer_host_int(primary, "timeout"));
    json_push_kv_int(&obj, "reconnects",
                     diagnose_peer_host_int(primary, "reconnects"));
    json_push_kv_int(&obj, "rejected",
                     diagnose_peer_host_int(primary, "rejected"));
    json_push_kv_int(&obj, "pre_handshake_disconnects",
                     diagnose_peer_host_int(primary,
                                           "pre_handshake_disconnects"));
    json_push_kv(out, "peer_primary_host_issue", &obj);
    json_free(&obj);
}

static void diagnose_push_primary_host_issue_compact(
    struct json_value *out, const struct json_value *primary)
{
    static const char *str_fields[] = { "status", "host", "issue_class",
        "next_action", "direction", "bootstrap_readiness",
        "fast_sync_readiness" };
    static const char *int_fields[] = { "incident_score", "entries",
        "open_connections", "handshaked_open_connections", "timeout",
        "reconnects", "rejected", "pre_handshake_disconnects" };
    static const char *bool_fields[] = { "mixed_direction",
        "duplicate_current_connections", "duplicate_handshaked_connections" };
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.peer_primary_host_issue.v1");
    json_push_kv_str(&obj, "object_completeness", "compact");
    for (size_t i = 0; i < sizeof(str_fields) / sizeof(str_fields[0]); i++)
        json_push_kv_str(&obj, str_fields[i],
                         diagnose_peer_host_str(primary, str_fields[i]));
    for (size_t i = 0; i < sizeof(int_fields) / sizeof(int_fields[0]); i++)
        json_push_kv_int(&obj, int_fields[i],
                         diagnose_peer_host_int(primary, int_fields[i]));
    for (size_t i = 0; i < sizeof(bool_fields) / sizeof(bool_fields[0]); i++)
        json_push_kv_bool(&obj, bool_fields[i],
                          diagnose_peer_host_bool(primary, bool_fields[i]));
    json_push_kv_str(&obj, "full_detail_command", "z23 peerincidents");
    json_push_kv(out, "peer_primary_host_issue", &obj);
    json_free(&obj);
}

static const char *diagnose_peer_detail(int64_t peer_count,
                                        int64_t peer_incidents,
                                        int64_t material_signals,
                                        bool bootstrap_blocker,
                                        bool fast_sync_blocker)
{
    if (peer_count <= 0)
        return "no connected peers";
    if (bootstrap_blocker)
        return "peer lifecycle has no currently bootstrap-useful peer";
    if (material_signals > 0)
        return "peer lifecycle has material reconnect, duplicate, timeout, or reject incidents";
    if (fast_sync_blocker)
        return "peer lifecycle has bootstrap peers but no zclassic23 fast-sync peer";
    if (peer_incidents > 0)
        return "minor peer lifecycle incidents only; no duplicate or reconnect storm";
    return "peer lifecycle has no scored incidents";
}

static const char *diagnose_peer_next_action(int64_t peer_count,
                                             int64_t peer_incidents,
                                             int64_t material_signals,
                                             bool bootstrap_blocker,
                                             bool fast_sync_blocker)
{
    if (peer_count <= 0)
        return "inspect peer lifecycle and bootstrap status";
    if (bootstrap_blocker)
        return "inspect_peer_lifecycle_bootstrap_readiness";
    if (material_signals > 0)
        return "z23 peerincidents";
    if (fast_sync_blocker)
        return "prefer_zclassic23_fast_sync_peer";
    if (peer_incidents > 0)
        return "monitor peer lifecycle incidents";
    return "monitor getnetworkinfo peer_lifecycle";
}

static bool diagnose_mirror_status_unhealthy(const char *status)
{
    return status && status[0] && strcmp(status, "healthy") != 0 &&
           strcmp(status, "ok") != 0;
}

static const char *diagnose_mirror_next_action(bool mirror_present,
                                               bool mirror_attention,
                                               bool mirror_info)
{
    if (mirror_attention)
        return "inspect_mirror_status";
    if (mirror_info)
        return "monitor advisory mirror status";
    if (!mirror_present)
        return "mirror status skipped or unavailable";
    return "mirror is advisory only";
}

static const char *diagnose_next_action(bool operator_needed,
                                        bool agent_healthy,
                                        bool chain_attention,
                                        int64_t peer_count,
                                        bool peer_attention,
                                        bool peer_bootstrap_blocker,
                                        bool mirror_attention,
                                        const char *peer_host_action)
{
    if (operator_needed)
        return "inspect_condition_engine_and_operator_latch";
    if (!agent_healthy || chain_attention)
        return "inspect_agent_healthcheck_and_chain_timeline";
    if (peer_count <= 0)
        return "inspect_peer_lifecycle_incidents_and_bootstrapstatus";
    if (peer_attention && peer_bootstrap_blocker)
        return "inspect_peer_lifecycle_bootstrap_readiness";
    if (peer_attention && diagnose_peer_host_action_is_specific(
                              peer_host_action))
        return peer_host_action;
    if (peer_attention)
        return "inspect_peer_lifecycle_incidents";
    if (mirror_attention)
        return "inspect_mirror_status";
    return "monitor_agent_and_liveness";
}

bool rpc_agent_diagnose(const struct json_value *params, bool help,
                        struct json_value *result)
{
    RPC_HELP(help, result,
        "agentdiagnose [full|brief]\n"
        "\nReturn a bounded no-jq diagnosis packet for AI/operators. It "
        "composes cheap status, peer incident, mirror, and drill-down "
        "pointers without requiring a client-side pipeline. The default "
        "brief mode keeps only stable decision fields and findings; full "
        "mode adds healthcheck, peer, mirror, and timeline drill-downs.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_diagnose.v2\", "
        "\"verdict\":\"healthy|attention_needed\", "
        "\"findings\":[...] }\n");

    int64_t started_us = agent_first_call_start_us();
    enum diagnose_detail_mode detail_mode = DIAGNOSE_DETAIL_FULL;
    if (!diagnose_parse_detail_mode(params, result, &detail_mode))
        return true;
    bool brief_mode = detail_mode == DIAGNOSE_DETAIL_BRIEF;
    struct json_value empty_params = {0};
    struct json_value agent = {0};
    struct json_value health = {0};
    struct json_value peers = {0};
    struct json_value mirror = {0};
    struct json_value timeline_params = {0};
    struct json_value timeline = {0};
    struct json_value findings = {0};
    struct json_value commands = {0};
    bool partial = false;
    bool mirror_present = false;
    bool timeline_present = false;

    json_set_object(result);
    agent_push_contract_identity_fields_json(result, "agentdiagnose");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_bool(result, "no_jq_required", true);
    json_push_kv_str(result, "detail_mode",
                     diagnose_detail_mode_name(detail_mode));
    json_push_kv_bool(result, "embedded_drilldowns", !brief_mode);
    json_set_array(&empty_params);

    bool agent_ok = rpc_agent_summary(&empty_params, false, &agent);
    bool health_ok = false;
    if (brief_mode) {
        partial = true;
    } else if (agent_first_call_budget_exceeded(
            started_us, ZCL_AGENT_FIRST_CALL_BUDGET_DIAGNOSE_MS)) {
        partial = true;
        diagnose_push_skipped(result, "healthcheck",
                              "first_call_budget_exhausted_before_healthcheck");
        health_ok = false;
    } else {
        health_ok = rpc_healthcheck(&empty_params, false, &health);
    }

    peer_lifecycle_incidents_json(&peers);
    agent_push_contract_identity_fields_json(&peers, "peerincidents");

    if (agent_first_call_budget_exceeded(
            started_us, ZCL_AGENT_FIRST_CALL_BUDGET_DIAGNOSE_MS)) {
        partial = true;
    } else {
        mirror_present =
            diag_rpc_getmirrorstatus(&empty_params, false, &mirror);
    }

    if (agent_first_call_budget_exceeded(
            started_us, ZCL_AGENT_FIRST_CALL_BUDGET_DIAGNOSE_MS)) {
        partial = true;
    } else if (!brief_mode) {
        diagnose_timeline_params(&timeline_params);
        timeline_present = rpc_timeline(&timeline_params, false, &timeline);
    } else {
        partial = true;
    }

    bool agent_healthy = agent_ok && json_get_bool(json_get(&agent, "healthy"));
    bool serving = agent_ok && json_get_bool(json_get(&agent, "serving"));
    bool operator_needed =
        agent_ok && json_get_bool(json_get(&agent, "operator_needed"));
    bool chain_serving_ready = agent_ok && diagnose_agent_chain_ready(&agent);
    bool normal_lookahead = agent_ok && diagnose_agent_normal_lookahead(&agent);
    const char *readiness_status =
        agent_ok ? json_get_str(json_get(&agent, "readiness_status")) : "";
    const struct json_value *height_contract =
        agent_ok ? json_get(&agent, "height_contract") : NULL;
    const char *height_contract_status =
        height_contract ? json_get_str(json_get(height_contract, "status"))
                        : "";
    int64_t gap = agent_ok ? json_get_int(json_get(&agent, "gap")) : -1;
    const struct json_value *agent_peers =
        agent_ok ? json_get(&agent, "peers") : NULL;
    int64_t peer_count =
        agent_peers ? json_get_int(json_get(agent_peers, "total")) : -1;
    int64_t peer_incidents =
        json_get_int(json_get(&peers, "incident_count"));
    int64_t duplicate_groups =
        json_get_int(json_get(&peers, "duplicate_host_group_count"));
    int64_t host_incident_count =
        json_get_int(json_get(&peers, "host_incident_count"));
    int64_t host_count_returned =
        json_get_int(json_get(&peers, "host_count_returned"));
    const struct json_value *primary_host =
        diagnose_peer_primary_host(&peers);
    const char *primary_host_name =
        diagnose_peer_host_str(primary_host, "host");
    const char *primary_host_issue_class =
        diagnose_peer_host_str(primary_host, "issue_class");
    const char *primary_host_next_action =
        diagnose_peer_host_str(primary_host, "next_action");
    const char *primary_host_direction =
        diagnose_peer_host_str(primary_host, "direction");
    const char *primary_host_bootstrap_readiness =
        diagnose_peer_host_str(primary_host, "bootstrap_readiness");
    const char *primary_host_fast_sync_readiness =
        diagnose_peer_host_str(primary_host, "fast_sync_readiness");
    const char *peer_bootstrap_readiness =
        json_get_str(json_get(&peers, "bootstrap_readiness"));
    const char *peer_fast_sync_readiness =
        json_get_str(json_get(&peers, "fast_sync_readiness"));
    bool peer_bootstrap_blocker =
        json_get_bool(json_get(&peers, "bootstrap_blocked"));
    bool peer_fast_sync_blocker =
        json_get_bool(json_get(&peers, "fast_sync_blocked"));
    int64_t material_peer_incidents =
        diagnose_peer_material_incidents(&peers);
    int64_t material_peer_groups =
        diagnose_peer_material_groups(&peers);
    int64_t informational_peer_incidents =
        peer_incidents > material_peer_incidents
            ? peer_incidents - material_peer_incidents : 0;
    bool peer_attention =
        peer_count <= 0 || peer_bootstrap_blocker ||
        material_peer_incidents > 0 ||
        material_peer_groups > 0 || duplicate_groups > 0;
    const char *peer_severity =
        peer_attention ? "attention" :
        (peer_fast_sync_blocker || peer_incidents > 0 ? "info" : "ok");
    int64_t material_peer_signals =
        material_peer_incidents + material_peer_groups;
    const struct json_value *mirror_contract =
        mirror_present ? json_get(&mirror, "mirror_contract") : NULL;
    const char *mirror_status =
        mirror_contract ? json_get_str(json_get(mirror_contract, "status"))
                        : "";
    const struct json_value *mirror_operator_required_j =
        mirror_contract ? json_get(mirror_contract,
                                   "operator_action_required") : NULL;
    bool mirror_operator_action_required =
        mirror_operator_required_j &&
        json_get_bool(mirror_operator_required_j);
    bool mirror_advisory_only =
        mirror_contract &&
        json_get_bool(json_get(mirror_contract, "advisory_only"));
    bool mirror_status_unhealthy =
        diagnose_mirror_status_unhealthy(mirror_status);
    bool mirror_attention =
        mirror_operator_required_j ? mirror_operator_action_required :
        (mirror_present && mirror_status_unhealthy);
    bool mirror_info =
        mirror_present && !mirror_attention && mirror_status_unhealthy;
    const char *mirror_severity =
        mirror_attention ? "attention" : (mirror_info ? "info" : "ok");

    json_push_kv_bool(result, "healthy", agent_healthy);
    json_push_kv_bool(result, "serving", serving);
    json_push_kv_bool(result, "operator_needed", operator_needed);
    json_push_kv_bool(result, "chain_serving_ready", chain_serving_ready);
    json_push_kv_bool(result, "normal_lookahead", normal_lookahead);
    json_push_kv_str(result, "chain_readiness_status", readiness_status);
    json_push_kv_str(result, "height_contract_status", height_contract_status);
    json_push_kv_int(result, "gap", gap);
    json_push_kv_int(result, "peer_count", peer_count);
    json_push_kv_int(result, "peer_incident_count", peer_incidents);
    json_push_kv_int(result, "duplicate_host_group_count", duplicate_groups);
    json_push_kv_int(result, "peer_host_incident_count",
                     host_incident_count);
    json_push_kv_int(result, "peer_host_count_returned",
                     host_count_returned);
    json_push_kv_str(result, "peer_primary_host", primary_host_name);
    json_push_kv_str(result, "peer_primary_host_issue_class",
                     primary_host_issue_class);
    json_push_kv_str(result, "peer_primary_host_next_action",
                     primary_host_next_action);
    json_push_kv_str(result, "peer_primary_host_direction",
                     primary_host_direction);
    json_push_kv_bool(result, "peer_primary_host_mixed_direction",
                      diagnose_peer_host_bool(primary_host,
                                             "mixed_direction"));
    json_push_kv_str(result, "peer_primary_host_bootstrap_readiness",
                     primary_host_bootstrap_readiness);
    json_push_kv_str(result, "peer_primary_host_fast_sync_readiness",
                     primary_host_fast_sync_readiness);
    json_push_kv_str(result, "peer_bootstrap_readiness",
                     peer_bootstrap_readiness);
    json_push_kv_str(result, "peer_fast_sync_readiness",
                     peer_fast_sync_readiness);
    json_push_kv_bool(result, "peer_bootstrap_blocker",
                      peer_bootstrap_blocker);
    json_push_kv_bool(result, "peer_fast_sync_blocker",
                      peer_fast_sync_blocker);
    json_push_kv_int(result, "peer_primary_host_incident_score",
                     diagnose_peer_host_int(primary_host, "incident_score"));
    json_push_kv_str(result, "peer_incident_severity", peer_severity);
    json_push_kv_bool(result, "peer_stability_blocker", peer_attention);
    json_push_kv_int(result, "peer_material_incident_count",
                     material_peer_incidents);
    json_push_kv_int(result, "peer_material_group_count",
                     material_peer_groups);
    json_push_kv_int(result, "peer_informational_incident_count",
                     informational_peer_incidents);
    json_push_kv_str(result, "peer_incident_summary",
                     diagnose_peer_detail(peer_count, peer_incidents,
                                          material_peer_signals,
                                          peer_bootstrap_blocker,
                                          peer_fast_sync_blocker));
    json_push_kv_str(result, "mirror_status", mirror_status);
    json_push_kv_str(result, "mirror_severity", mirror_severity);
    json_push_kv_bool(result, "mirror_advisory_only", mirror_advisory_only);
    json_push_kv_bool(result, "mirror_operator_action_required",
                      mirror_operator_action_required);
    json_push_kv_bool(result, "partial_result", partial);

    bool chain_attention = !chain_serving_ready;
    const char *next_action =
        diagnose_next_action(operator_needed, agent_healthy, chain_attention,
                             peer_count, peer_attention,
                             peer_bootstrap_blocker, mirror_attention,
                             primary_host_next_action);
    bool attention = operator_needed || !agent_healthy || chain_attention ||
                     peer_attention || mirror_attention;
    json_push_kv_str(result, "verdict",
                     attention ? "attention_needed" : "healthy");
    json_push_kv_str(result, "safe_next_action", next_action);

    json_set_array(&findings);
    diagnose_push_finding(&findings, "chain_serving",
                          agent_healthy && serving && !chain_attention
                              ? "ok" : "attention",
                          agent_ok ? json_get_str(json_get(&agent, "summary"))
                                   : "agent status unavailable",
                          chain_attention
                              ? "inspect sync timeline and reducer frontier"
                              : "continue monitoring H* and peer target");
    diagnose_push_finding(&findings, "peer_lifecycle",
                          peer_severity,
                          diagnose_peer_detail(peer_count, peer_incidents,
                                               material_peer_signals,
                                               peer_bootstrap_blocker,
                                               peer_fast_sync_blocker),
                          peer_attention &&
                                  diagnose_peer_host_action_is_specific(
                                      primary_host_next_action)
                              ? primary_host_next_action
                              : diagnose_peer_next_action(
                                    peer_count, peer_incidents,
                                    material_peer_signals,
                                    peer_bootstrap_blocker,
                                    peer_fast_sync_blocker));
    diagnose_push_finding(&findings, "mirror",
                          mirror_severity,
                          mirror_present ? mirror_status
                                         : "mirror status skipped or unavailable",
                          diagnose_mirror_next_action(mirror_present,
                                                      mirror_attention,
                                                      mirror_info));
    json_push_kv(result, "findings", &findings);
    json_free(&findings);

    json_set_array(&commands);
    agent_push_contract_native_command_json(&commands, "agent");
    agent_push_contract_native_command_json(&commands, "agentliveness");
    agent_push_contract_native_command_json(&commands, "peerincidents");
    agent_push_contract_native_command_json(&commands, "timeline");
    diagnose_push_str(&commands, "z23 healthcheck full");
    json_push_kv(result, "recommended_commands", &commands);
    json_free(&commands);

    if (brief_mode)
        diagnose_push_primary_host_issue_compact(result, primary_host);
    else
        diagnose_push_primary_host_issue(result, primary_host);

    if (brief_mode) {
        diagnose_push_brief_omissions(result);
        json_push_kv_str(result, "full_diagnose_command",
                         "z23 agentdiagnose full");
    } else if (agent_ok) {
        json_push_kv(result, "agent", &agent);
    } else {
        diagnose_push_skipped(result, "agent", "agent_status_unavailable");
    }
    if (!brief_mode && health_ok)
        json_push_kv(result, "healthcheck", &health);
    if (!brief_mode && mirror_present)
        json_push_kv(result, "mirror", &mirror);
    else if (!brief_mode && !json_get(result, "mirror"))
        diagnose_push_skipped(result, "mirror",
                              "first_call_budget_exhausted_before_mirror");
    if (!brief_mode)
        json_push_kv(result, "peer_incidents", &peers);
    if (!brief_mode && timeline_present)
        json_push_kv(result, "timeline", &timeline);
    else if (!brief_mode)
        diagnose_push_skipped(result, "timeline",
                              "first_call_budget_exhausted_before_timeline");

    agent_push_first_call_simple_json(
        result, "first_call", "agentdiagnose",
        brief_mode ? "bounded_status_peer_mirror_brief"
                   : "bounded_status_health_peer_mirror_timeline",
        ZCL_AGENT_FIRST_CALL_BUDGET_DIAGNOSE_MS, started_us, true,
        brief_mode ? "brief_mode_omits_embedded_drilldowns" :
        partial ? "lower_priority_sections_skipped_by_budget"
                : "bounded_diagnosis_not_full_forensics",
        brief_mode ? "z23 agentdiagnose full"
                   : "z23 healthcheck full");

    json_free(&timeline);
    json_free(&timeline_params);
    json_free(&mirror);
    json_free(&peers);
    json_free(&health);
    json_free(&agent);
    json_free(&empty_params);
    return true;
}
