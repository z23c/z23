/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"

#include "json/json.h"

struct agent_contract_schema_surface {
    int rank;
    const char *schema;
    const char *producer;
    const char *purpose;
};

static const struct agent_contract_schema_surface g_agent_schema_surfaces[] = {
    { 1, "zcl.first_call_contract.v1",
      "nested in zcl.public_status.v3, zcl.healthcheck.v1, zcl.agent_liveness.v2, and zcl.agent_diagnose.v2",
      "first-call boundedness, elapsed time, partial-result, and budget semantics" },
    { 2, "zcl.agent_readiness.v1",
      "nested in zcl.public_status.v3 readiness",
      "separates chain-serving readiness from index projection freshness" },
    { 3, "zcl.height_contract.v1",
      "nested in zcl.public_status.v3 height_contract",
      "names served H*, active lookahead, header, peer, and target heights" },
    { 4, "zcl.operator_latch.v2",
      "nested in zcl.public_status.v3 operator_latch",
      "names EV_OPERATOR_NEEDED latch detail, age, and whether operator action is still required" },
    { 5, "zcl.condition_engine_summary.v2",
      "nested in zcl.public_status.v3 conditions",
      "cheap active/unresolved condition counts with drill-down routes" },
    { 6, "zcl.runtime_build.v2",
      "nested in zcl.public_status.v3 runtime_build",
      "running-vs-deploy-expected build freshness for stale-runtime detection" },
    { 7, "zcl.agent_runtime_availability.v3",
      "nested in zcl.agent_interface.v2 and zcl.agent_ops.v2",
      "producer-vs-target first-call method availability and method-not-found guardrail" },
    { 8, "zcl.background_quality_runtime.v1",
      "nested in zcl.agent_build.v2 background_quality_status",
      "native status-file reader for background tests/fuzz/coverage verdicts" },
    { 9, "zcl.agent_runtime_services.v1",
      "nested in zcl.agent_lanes.v2",
      "configured boot ports plus observed in-process listener state" },
    { 10, "zcl.agent_capability.v2",
      "nested in zcl.agent_interface.v2 capabilities[]",
      "one machine-readable agent operation and its transports" },
    { 11, "zcl.agent_machine_contract.v2",
      "nested in zcl.agent_interface.v2 machine_contract",
      "JSON/schema/version compatibility requirements for agents" },
    { 12, "zcl.agent_runtime_identity.v1",
      "nested in zcl.agent_interface.v2 runtime_identity",
      "running binary identity for the interface contract producer" },
    { 13, "zcl.operator_summary.v3",
      "nested in z23 operatorsnapshot and exposed by the native summary command",
      "native target-owned operator verdict projection" },
    { 14, "zcl.operator_lane.v1",
      "z23 agent / GET /api/v1/agent",
      "declared or exact-topology-inferred canonical/soak/dev lane and restart policy" },
    { 15, "zcl.operator_deployment_safety.v1",
      "nested in zcl.operator_lane.v1",
      "machine-readable deploy/restart safety contract" },
    { 16, "zcl.node_resources.v1",
      "nested in zcl.public_status.v3 resources",
      "cheap process RSS, uptime, and memory-pressure telemetry" },
    { 17, "zcl.restart_watchdog.v1",
      "nested in zcl.public_status.v3 restart_watchdog",
      "chain tip watchdog restart budget and last autonomous recycle reason" },
    { 18, "zcl.security_posture.v1",
      "nested in zcl.public_status.v3 security_posture",
      "bounded bootstrap trust and shielded-nullifier history completeness posture" },
    { 19, "zcl.service_catalog.v2",
      "z23 servicecatalog / GET /api/v1/service-catalog",
      "UX-oriented sovereign service catalog with transport, CRUD, verification, and trust boundaries" },
    { 20, "zcl.service_contract.v2",
      "z23 servicecatalog <name> / GET /api/v1/service-catalog/{service}",
      "one sovereign service contract with CRUD surface, transports, verification, trust, and privacy model" },
    { 21, "zcl.service_operations.index.v2",
      "z23 serviceoperations / GET /api/v1/service-operations",
      "operation-level catalog with CRUD action, write safety, callable surfaces, and preferred interface facets" },
    { 22, "zcl.service_operation.v2",
      "z23 serviceoperations <operation_id> / GET /api/v1/service-operations/{operation_id}",
      "one stable service.operation contract with input/output, authority, effect, and safety metadata" },
    { 23, "zcl.agent_dev_status.v2",
      "z23 agentdevstatus",
      "read-only worker-lane contract, staged binary, linger service, RPC/recovery, deploy state, and next-action status" },
    { 24, "zcl.mvp_operator_proofs.v1",
      "nested in zcl.milestone_status.v2",
      "MVP criterion proof commands, local dependencies, CI regression floors, and pending blockers" },
    { 25, "zcl.operator_proof_bundle.v2",
      "z23 proofbundle",
      "one read-only evidence artifact tying live status, MVP proofs, sovereign anchor status, refold readiness, lanes, and dev status together" },
    { 26, "zcl.operator_snapshot.v3",
      "z23 operatorsnapshot",
      "single-target bounded component snapshots, capture coherence, typed evidence, invariants, and native summary" },
    { 27, "zcl.blocker_registry_summary.v1",
      "nested in zcl.public_status.v3 blocker_registry",
      "typed-blocker-registry active count and dominant head, from the same authority as dumpstate blocker, so status surfaces cannot name disjoint blockers" },
};

static const size_t g_agent_schema_surface_count =
    sizeof(g_agent_schema_surfaces) / sizeof(g_agent_schema_surfaces[0]);

size_t agent_contract_schema_surface_count(void)
{
    return g_agent_schema_surface_count;
}

static void agent_push_schema_surface_entry_json(
    struct json_value *arr, const struct agent_contract_schema_surface *entry)
{
    if (!arr || !entry)
        return;

    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", entry->schema);
    json_push_kv_str(&obj, "producer", entry->producer);
    json_push_kv_str(&obj, "purpose", entry->purpose);
    json_push_back(arr, &obj);
    json_free(&obj);
}

size_t agent_push_contract_schema_surface_json(struct json_value *arr)
{
    if (!arr)
        return 0;

    int max_rank = 0;
    for (size_t i = 0; i < g_agent_schema_surface_count; i++) {
        if (g_agent_schema_surfaces[i].rank > max_rank)
            max_rank = g_agent_schema_surfaces[i].rank;
    }

    size_t emitted = 0;
    for (int rank = 1; rank <= max_rank; rank++) {
        for (size_t i = 0; i < g_agent_schema_surface_count; i++) {
            const struct agent_contract_schema_surface *entry =
                &g_agent_schema_surfaces[i];
            if (entry->rank == rank) {
                agent_push_schema_surface_entry_json(arr, entry);
                emitted++;
            }
        }
    }
    return emitted;
}
