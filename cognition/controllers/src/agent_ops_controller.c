/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Compact no-jq operator surface for AI agents. This is intentionally
 * opinionated: it returns the common answers directly instead of forcing the
 * caller to filter larger discovery payloads. */

#include "controllers/agent_controller.h"
#include "controllers/agent_background_quality.h"
#include "controllers/strong_params.h"

#include "json/json.h"
#include "rpc/server.h"
#include "util/clientversion.h"

static void agent_ops_push_quality_summary(struct json_value *out)
{
    struct json_value q;
    json_init(&q);
    agent_build_background_quality_status(&q);
    json_push_kv_str(out, "background_quality_schema",
                     json_get_str(json_get(&q, "schema")));
    json_push_kv_str(out, "background_quality_summary",
                     json_get_str(json_get(&q, "summary")));
    json_push_kv_int(out, "background_quality_lanes_configured",
                     json_get_int(json_get(&q, "lanes_configured")));
    json_push_kv_int(out, "background_quality_status_files_present",
                     json_get_int(json_get(&q, "status_files_present")));
    json_push_kv_int(out, "background_quality_status_files_valid",
                     json_get_int(json_get(&q, "status_files_valid")));
    json_push_kv_str(out, "background_quality_next_action",
                     json_get_str(json_get(&q, "agent_next_action")));
    json_free(&q);
}

bool rpc_agent_ops(const struct json_value *params, bool help,
                   struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "agentops\n"
        "\nReturn the compact no-jq AI/operator command center contract:\n"
        "direct fields, drill-down commands, and the top next architecture\n"
        "work items.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_ops.v2\", \"no_jq_required\":true, "
        "\"top_next_work\":[...] }\n");

    struct json_value commands, api_rules, review, gaps, workflow, ux, work;
    json_set_object(result);
    agent_push_contract_identity_fields_json(result, "agentops");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_bool(result, "no_jq_required", true);
    json_push_kv_str(result, "purpose",
                     "one compact agent-ready view of API shape, service architecture, and next work");
    json_push_kv_str(result, "preferred_transport", "native_cli");
    json_push_kv_str(result, "api_style",
                     "one compact first call, then registry-owned primitive drilldowns");
    json_push_kv_str(result, "dry_source",
                     "agent_contracts.def + agent_contract_registry.c");
    agent_push_contract_field_surface_json(result, "agentops.first_call");
    json_push_kv_str(result, "refold_plain_english",
                     "Rebuild the UTXO/trust anchor from zclassic23's own verified block history, then cut over so the node no longer depends on a borrowed snapshot seed.");

    agent_push_operator_lane_json(result, "current_runtime_lane");
    agent_push_runtime_build_json(result, "runtime_build");
    agent_push_runtime_availability_json(result, "runtime_availability");
    agent_ops_push_quality_summary(result);

    json_init(&api_rules);
    json_set_array(&api_rules);
    agent_push_contract_ops_surface_json(&api_rules, "direct");
    json_push_kv(result, "direct_commands", &api_rules);
    json_free(&api_rules);

    json_init(&commands);
    json_set_array(&commands);
    agent_push_contract_ops_surface_json(&commands, "drilldown");
    json_push_kv(result, "drilldowns", &commands);
    json_free(&commands);

    json_init(&review);
    json_set_object(&review);
    agent_push_contract_review_surface_json(&review,
                                            "agentops.architecture_review");
    json_push_kv(result, "architecture_review", &review);
    json_free(&review);

    json_init(&ux);
    json_set_object(&ux);
    json_push_kv_str(&ux, "start_here",
                     "z23 status; then z23 agentops");
    json_push_kv_str(&ux, "change_router",
                     "z23 agentimpact <files...>");
    json_push_kv_str(&ux, "preferred_drilldowns",
                     "z23 dumpstate, getnodelog, dbquery, timeline");
    json_push_kv_str(&ux, "add_new_api_rule",
                     "try registry-owned primitives first; add bespoke tools only when a repeated decision needs a stable field");
    json_push_kv(result, "api_ux", &ux);
    json_free(&ux);

    json_init(&gaps);
    json_set_array(&gaps);
    agent_push_contract_work_surface_json(&gaps, "agentops.api_gaps");
    json_push_kv(result, "api_gaps", &gaps);
    json_free(&gaps);

    json_init(&workflow);
    json_set_array(&workflow);
    agent_push_contract_work_surface_json(&workflow, "agentops.workflow");
    json_push_kv(result, "workflow", &workflow);
    json_free(&workflow);

    json_init(&work);
    json_set_array(&work);
    agent_push_contract_work_surface_json(&work, "agentops.top_next_work");
    json_push_kv(result, "top_next_work", &work);
    json_free(&work);
    return true;
}
