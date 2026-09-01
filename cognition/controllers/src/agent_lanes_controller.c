/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native lane topology contract for AI/operator automation. This describes
 * where fresh binaries may be exercised without consuming the canonical node
 * or the soak evidence lane. */

#include "controllers/agent_controller.h"
#include "controllers/strong_params.h"

#include "json/json.h"
#include "rpc/server.h"
#include "util/clientversion.h"

#include <stdint.h>

static void agent_lanes_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void agent_lanes_push_external_command(struct json_value *arr,
                                              const char *name,
                                              const char *native,
                                              const char *purpose)
{
    if (!arr)
        return;

    struct json_value cmd;
    json_init(&cmd);
    json_set_object(&cmd);
    json_push_kv_str(&cmd, "name", name);
    json_push_kv_str(&cmd, "native", native);
    json_push_kv_str(&cmd, "purpose", purpose);
    json_push_back(arr, &cmd);
    json_free(&cmd);
}

static void agent_push_lane_topology(struct json_value *arr,
                                     const struct agent_operator_lane_topology
                                         *topology)
{
    struct json_value obj;
    json_init(&obj);
    agent_fill_operator_lane_topology_json(&obj, topology);
    json_push_back(arr, &obj);
    json_free(&obj);
}

bool rpc_agent_lanes(const struct json_value *params, bool help,
                     struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "agentlanes\n"
        "\nReturn the native lane topology contract for long-running canonical,\n"
        "soak-evidence, and restartable development nodes.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_lanes.v2\", "
        "\"lanes\":[...], \"current_runtime_lane\":{...} }\n");

    struct json_value lanes, rules, commands;
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.agent_lanes.v2");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "summary",
                     "Keep canonical running; deploy fresh binaries to dev; preserve soak evidence unless the operator explicitly rebaselines it.");
    json_push_kv_str(result, "default_deploy_target", "dev");
    json_push_kv_str(result, "canonical_lane", "canonical");
    json_push_kv_str(result, "soak_lane", "soak");
    json_push_kv_str(result, "development_lane", "dev");
    json_push_kv_str(result, "source",
                     "native_c_agent_controller_lane_topology");
    agent_push_operator_lane_json(result, "current_runtime_lane");
    agent_push_runtime_services_json(result, "current_runtime_services");
    agent_push_runtime_availability_json(result,
                                         "current_runtime_availability");

    json_init(&lanes);
    json_set_array(&lanes);
    for (size_t i = 0; i < agent_operator_lane_topology_count(); i++)
        agent_push_lane_topology(&lanes,
                                 agent_operator_lane_topology_at(i));
    json_push_kv(result, "lanes", &lanes);
    json_free(&lanes);

    json_init(&rules);
    json_set_array(&rules);
    agent_lanes_push_str(&rules,
        "never deploy or restart canonical from automation without an operator-approved window");
    agent_lanes_push_str(&rules,
        "never consume the soak lane for frequent development restarts");
    agent_lanes_push_str(&rules,
        "fresh binaries and risky probes go to the dev lane first");
    agent_lanes_push_str(&rules,
        "copy/live surgery must be proven on an isolated copy before touching a live datadir");
    agent_lanes_push_str(&rules,
        "automation must read zcl.operator_deployment_safety.v1 before deploy or restart");
    json_push_kv(result, "automation_rules", &rules);
    json_free(&rules);

    json_init(&commands);
    json_set_array(&commands);
    agent_push_contract_command_json(&commands, "status", "agent",
                                     "current node status");
    agent_push_contract_command_json(&commands, "lane_topology",
                                     "agentlanes",
                                     "all operator lanes and safety contracts");
    agent_push_contract_command_json(&commands, "deploy_guard",
                                     "agentdeployguard",
                                     "current-lane deploy/restart allow/refuse");
    agent_lanes_push_external_command(
        &commands, "lane_health", "tools/scripts/lane_health.sh --json",
        "external systemd/RPC readiness probe for all lanes");
    json_push_kv(result, "commands", &commands);
    json_free(&commands);
    return true;
}
