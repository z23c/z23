/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent code-map cases: the code map document and the changed-file to focused-test impact mapping.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_agent_codemap(void)
{
    int failures = 0;

    printf("api: native RPC returns agent code map... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool ok = rpc_table_execute(&tbl, "agentmap", &params, &result);
        const struct json_value *commands = json_get(&result, "commands");
        const struct json_value *telemetry =
            json_get(&result, "telemetry_drilldowns");
        const struct json_value *subsystems = json_get(&result, "subsystems");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_map.v3") == 0;
        ok = ok &&
            agent_contract_command_surface_count("agentmap.commands.core") ==
                14;
        ok = ok &&
            agent_contract_command_surface_count(
                "agentmap.commands.drilldown") == 6;
        ok = ok &&
            agent_contract_command_surface_count("agentmap.telemetry") == 12;
        ok = ok &&
            agent_contract_command_surface_count("missing.surface") == 0;
        ok = ok && commands && commands->type == JSON_ARR;
        ok = ok && find_object_with_str(commands, "method", "agentmap") != NULL;
        ok = ok &&
            find_object_with_str(commands, "method", "agentdeployguard") != NULL;
        ok = ok && find_object_with_str(commands, "name", "impact") != NULL;
        ok = ok && find_object_with_str(commands, "name", "build") != NULL;
        const struct json_value *map_dev_status =
            find_object_with_str(commands, "name", "dev_status");
        ok = ok && map_dev_status &&
            strcmp(json_get_str(json_get(map_dev_status, "native")),
                   "z23 agentdevstatus") == 0;
        const struct json_value *map_proof_bundle =
            find_object_with_str(commands, "name", "proof_bundle");
        ok = ok && map_proof_bundle &&
            strcmp(json_get_str(json_get(map_proof_bundle, "native")),
                   "z23 proofbundle [anchor_datadir]") == 0;
        ok = ok && find_object_with_str(commands, "method", "healthcheck")
                         != NULL;
        ok = ok && find_object_with_str(commands, "method", "statecatalog")
                         != NULL;
        ok = ok && find_object_with_str(commands, "method", "peerincidents")
                         != NULL;
        const struct json_value *map_compact_status =
            find_object_with_str(commands, "name", "compact_status");
        ok = ok && map_compact_status &&
            strcmp(json_get_str(json_get(map_compact_status, "native")),
                   "z23 status") == 0;
        const struct json_value *map_full_compatibility =
            find_object_with_str(commands, "name",
                                 "full_compatibility_status");
        ok = ok && map_full_compatibility &&
            strcmp(json_get_str(json_get(map_full_compatibility, "native")),
                   "z23 agent") == 0;
        const struct json_value *map_background_quality =
            find_object_with_str(commands, "name", "background_quality");
        ok = ok && map_background_quality &&
            strcmp(json_get_str(json_get(map_background_quality, "native")),
                   "make quality-linger-status") == 0;
        const struct json_value *map_state =
            find_object_with_str(commands, "method", "dumpstate");
        const struct json_value *map_log =
            find_object_with_str(commands, "method", "getnodelog");
        ok = ok && map_state &&
            strcmp(json_get_str(json_get(map_state, "native")),
                   "z23 dumpstate <subsystem> [key]") == 0;
        ok = ok && map_log &&
            strcmp(json_get_str(json_get(map_log, "native")),
                   "z23 getnodelog <pattern>") == 0;
        ok = ok && telemetry && telemetry->type == JSON_ARR;
        const struct json_value *map_peer_incidents =
            find_object_with_str(telemetry, "method", "peerincidents");
        ok = ok && map_peer_incidents &&
            strcmp(json_get_str(json_get(map_peer_incidents, "native")),
                   "z23 peerincidents") == 0;
        const struct json_value *map_telemetry_status =
            find_object_with_str(telemetry, "name", "compact_status");
        ok = ok && map_telemetry_status &&
            strcmp(json_get_str(json_get(map_telemetry_status, "native")),
                   "z23 status") == 0;
        const struct json_value *map_full_status =
            find_object_with_str(telemetry, "name", "full_status");
        ok = ok && map_full_status &&
            strcmp(json_get_str(json_get(map_full_status, "native")),
                   "z23 healthcheck") == 0;
        ok = ok &&
            find_object_with_str(telemetry, "name", "node_log") != NULL;
        ok = ok &&
            find_object_with_str(telemetry, "method", "anchorstatus") != NULL;
        const struct json_value *map_proof_telemetry =
            find_object_with_str(telemetry, "method", "proofbundle");
        ok = ok && map_proof_telemetry &&
            strcmp(json_get_str(json_get(map_proof_telemetry, "schema")),
                   "zcl.operator_proof_bundle.v2") == 0;
        const struct json_value *map_db =
            find_object_with_str(telemetry, "method", "dbquery");
        ok = ok && map_db &&
            strcmp(json_get_str(json_get(map_db, "schema")),
                   "zcl.sql_result.v1") == 0;
        ok = ok && map_db &&
            strcmp(json_get_str(json_get(map_db, "native")),
                   "z23 dbquery <SELECT>") == 0;
        const struct json_value *map_events =
            find_object_with_str(telemetry, "method", "eventlog");
        ok = ok && map_events &&
            strcmp(json_get_str(json_get(map_events, "schema")),
                   "zcl.event_log.v1") == 0;
        ok = ok && map_events &&
            strcmp(json_get_str(json_get(map_events, "native")),
                   "z23 eventlog <count>") == 0;
        const struct json_value *map_quality_lanes =
            find_object_with_str(telemetry, "name", "quality_lanes");
        ok = ok && map_quality_lanes &&
            strcmp(json_get_str(json_get(map_quality_lanes, "native")),
                   "make quality-linger-status") == 0;
        ok = ok && subsystems && subsystems->type == JSON_ARR;
        ok = ok && find_object_with_str(subsystems, "name", "fast_ci") != NULL;
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC maps changed files to tests... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        const char *files[] = {
            "cognition/controllers/src/agent_controller.c",
            "cognition/controllers/src/agent_lanes_controller.c",
            "engine/controllers/src/event_healthcheck_controller.c",
            "engine/controllers/include/controllers/event_healthcheck_controller.h",
            "engine/controllers/src/diagnostics_native_handlers.c",
            "docs/AGENT_API.md",
        };
        for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
            struct json_value v;
            json_init(&v);
            json_set_str(&v, files[i]);
            json_push_back(&params, &v);
            json_free(&v);
        }

        struct json_value result;
        json_init(&result);

        bool ok = rpc_table_execute(&tbl, "agentimpact", &params, &result);
        const struct json_value *groups =
            json_get(&result, "relevant_test_groups");
        const struct json_value *commands =
            json_get(&result, "recommended_commands");
        const struct json_value *out_files = json_get(&result, "files");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_impact.v2") == 0;
        ok = ok && json_get_int(json_get(&result, "files_count")) == 6;
        ok = ok && json_get_bool(json_get(&result, "code_changed"));
        ok = ok && !json_get_bool(json_get(&result, "docs_only"));
        ok = ok && json_get_bool(json_get(&result, "agent_api_changed"));
        ok = ok && strcmp(json_get_str(json_get(&result, "mapping_source")),
                          "cognition/controllers/include/controllers/agent_impact_rules.def") == 0;
        ok = ok && json_get_int(json_get(&result, "shared_rule_count")) > 0;
        ok = ok && json_get_int(json_get(&result, "shared_rule_hits")) >= 6;
        ok = ok && json_get_int(json_get(
                     &result, "relevant_test_groups_count")) >= 3;
        ok = ok && out_files && json_size(out_files) == 6;
        ok = ok && json_array_has_str(groups, "syncdiag_rpc");
        ok = ok && json_array_has_str(groups, "command_registry_catalog");
        ok = ok && json_array_has_str(groups, "make_lint_gates");
        ok = ok && json_array_has_substr(commands,
                                         "ZCL_FAST_TESTS=syncdiag_rpc");
        ok = ok && json_array_has_substr(commands, "make fast-ci");

        if (ok) {
            printf("OK\n");
        } else {
            char dbg[4096];
            json_write(&result, dbg, sizeof(dbg));
            printf("FAIL result=%s\n", dbg);
            failures++;
        }

        json_free(&params);
        json_free(&result);
    }

    /* A change to a *_native_handlers.c file classifies into the
     * command-registry catalog test group. */
    printf("api: native RPC maps a native-handlers file change to "
           "command_registry_catalog... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value v;
        json_init(&v);
        json_set_str(&v, "engine/controllers/src/chain_native_handlers.c");
        json_push_back(&params, &v);
        json_free(&v);

        struct json_value result;
        json_init(&result);

        bool ok = rpc_table_execute(&tbl, "agentimpact", &params, &result);
        const struct json_value *groups =
            json_get(&result, "relevant_test_groups");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(&result, "code_changed"));
        ok = ok && json_array_has_str(groups, "command_registry_catalog");
        ok = ok && json_array_has_str(groups, "syncdiag_rpc");
        ok = ok && json_array_has_str(groups, "make_lint_gates");

        if (ok) {
            printf("OK\n");
        } else {
            char dbg[4096];
            json_write(&result, dbg, sizeof(dbg));
            printf("FAIL result=%s\n", dbg);
            failures++;
        }

        json_free(&params);
        json_free(&result);
    }


    return failures;
}
