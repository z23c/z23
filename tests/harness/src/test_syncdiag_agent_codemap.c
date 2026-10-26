/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent code-map cases: the code map document and the changed-file to focused-test impact mapping.
 */

#include "test/syncdiag_rpc_fixture.h"

/* Every classification category, plus inputs where two conditions can
 * both match and the earlier one must win. */
enum { F_CODE = 1, F_API = 2, F_CONSENSUS = 4 };

static const struct agent_impact_case {
    const char *path, *subsystem, *risk, *docs;
    int flags;
} agent_impact_cases[] = {
    { "", "general", "invalid", "docs/agent/AGENT_API.md", 0 },
    { "docs/README.md", "documentation", "docs_only",
      "docs/README.md", 0 },
    { "docs/dev/fast-path.md", "documentation", "docs_only",
      "docs/dev/fast-path.md", 0 },
    { "Makefile", "fast_ci_and_gates", "normal",
      "docs/dev/fast-path.md", F_CODE },
    { "tools/agent_fast_ci.sh", "fast_ci_and_gates", "normal",
      "docs/dev/fast-path.md", F_CODE },
    { "Makefile.extra", "general", "normal",
      "docs/dev/CODEBASE_MAP.md", 0 },
    { "tools/githooks", "general", "normal",
      "docs/dev/CODEBASE_MAP.md", F_CODE },
    { "cognition/controllers/src/agent_controller.c",
      "native_agent_api", "operator_api", "docs/agent/AGENT_API.md",
      F_CODE | F_API },
    { "engine/controllers/include/controllers/diagnostics_internal.h",
      "native_agent_api", "operator_api", "docs/agent/AGENT_API.md",
      F_CODE | F_API },
    { "engine/services/src/operator_snapshot_service.c",
      "native_agent_api", "operator_api", "docs/agent/AGENT_API.md",
      F_CODE | F_API },
    { "engine/services/src/operator_snapshot_service.cc",
      "service_layer", "operator_liveness", "docs/dev/CODEBASE_MAP.md",
      F_CODE },
    { "engine/controllers/src/event_controller.c",
      "native_status_api", "operator_api", "docs/agent/AGENT_API.md",
      F_CODE | F_API },
    { "engine/controllers/src/health_controller.c",
      "native_status_api", "operator_api", "docs/agent/AGENT_API.md",
      F_CODE | F_API },
    { "engine/controllers/include/controllers/health_controller.h",
      "native_status_api", "operator_api", "docs/agent/AGENT_API.md",
      F_CODE | F_API },
    { "engine/entry/main.c", "native_cli_api", "operator_api",
      "docs/agent/AGENT_API.md", F_CODE | F_API },
    { "engine/controllers/src/api_controller.c", "rest_agent_api",
      "operator_api", "docs/dev/CODEBASE_MAP.md", F_CODE | F_API },
    { "engine/controllers/src/api_controller_routes.c",
      "rest_agent_api", "operator_api", "docs/dev/CODEBASE_MAP.md",
      F_CODE | F_API },
    { "engine/services/src/node_health_service.c", "node_health",
      "operator_health", "docs/RUNBOOK.md", F_CODE },
    { "engine/services/include/services/node_health_service.h",
      "node_health", "operator_health", "docs/RUNBOOK.md", F_CODE },
    { "engine/services/include/services/node_health_service_x.h",
      "node_health", "operator_health", "docs/RUNBOOK.md", F_CODE },
    { "core/consensus/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/params/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/chainparams/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/modules/chain/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/modules/validation/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/modules/script/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/modules/primitives/x.c", "consensus_or_validation",
      "consensus_parity", "docs/CONSENSUS_PARITY_DOCTRINE.md",
      F_CODE | F_CONSENSUS },
    { "core/modules/chain", "general", "normal",
      "docs/dev/CODEBASE_MAP.md", 0 },
    { "engine/jobs/x.c", "reducer_stage", "reducer_liveness",
      "docs/node/HOW_THE_NODE_WORKS.md", F_CODE },
    { "engine/services/x.c", "service_layer", "operator_liveness",
      "docs/dev/CODEBASE_MAP.md", F_CODE },
    { "tests/harness/include/test/x.h", "test_harness", "normal",
      "docs/dev/fast-path.md", F_CODE },
    { "app/x.c", "code", "normal", "docs/dev/CODEBASE_MAP.md", F_CODE },
    { "lib/x.c", "code", "normal", "docs/dev/CODEBASE_MAP.md", F_CODE },
    { "config/x.c", "code", "normal", "docs/dev/CODEBASE_MAP.md",
      F_CODE },
    { "src/x.c", "code", "normal", "docs/dev/CODEBASE_MAP.md", F_CODE },
    { "zzz/unclassified.txt", "general", "normal",
      "docs/dev/CODEBASE_MAP.md", 0 },
};

static bool agent_impact_case_matches(size_t i)
{
    struct json_value params, v, result;
    json_init(&params);
    json_set_array(&params);
    json_init(&v);
    json_set_str(&v, agent_impact_cases[i].path);
    json_push_back(&params, &v);
    json_free(&v);
    json_init(&result);

    bool ok = rpc_agent_impact(&params, false, &result);
    const struct json_value *files = json_get(&result, "files");
    const struct json_value *e = files ? json_at(files, 0) : NULL;
    ok = ok && e && json_size(files) == 1;
    ok = ok && strcmp(json_get_str(json_get(e, "subsystem")),
                      agent_impact_cases[i].subsystem) == 0;
    ok = ok && strcmp(json_get_str(json_get(e, "risk")),
                      agent_impact_cases[i].risk) == 0;
    ok = ok && strcmp(json_get_str(json_get(e, "docs")),
                      agent_impact_cases[i].docs) == 0;
    ok = ok && json_get_bool(json_get(&result, "agent_api_changed")) ==
        !!(agent_impact_cases[i].flags & F_API);
    ok = ok && json_get_bool(json_get(&result, "consensus_risk")) ==
        !!(agent_impact_cases[i].flags & F_CONSENSUS);
    ok = ok && json_get_bool(json_get(&result, "code_changed")) ==
        !!(agent_impact_cases[i].flags & F_CODE);
    json_free(&params);
    json_free(&result);
    return ok;
}

static int agent_impact_classification_cases(void)
{
    printf("api: agentimpact classifies each path category and overlap... ");
    bool ok = true;
    for (size_t i = 0; i < sizeof(agent_impact_cases) /
                           sizeof(agent_impact_cases[0]); i++) {
        if (!agent_impact_case_matches(i)) {
            printf("\n  FAIL path=\"%s\"", agent_impact_cases[i].path);
            ok = false;
        }
    }
    printf("%s\n", ok ? "OK" : "\nFAIL");
    return ok ? 0 : 1;
}

static void agent_codemap_prepare_rpc(struct rpc_table *tbl)
{
    rpc_table_init(tbl);
    register_event_rpc_commands(tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
}

static void agent_codemap_push_paths(struct json_value *params,
                                    const char **paths, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        struct json_value v;
        json_init(&v);
        json_set_str(&v, paths[i]);
        json_push_back(params, &v);
        json_free(&v);
    }
}

static void agent_codemap_begin_impact(struct rpc_table *tbl,
                                      struct json_value *params,
                                      struct json_value *result,
                                      const char **files, size_t n)
{
    agent_codemap_prepare_rpc(tbl);
    json_init(params);
    json_set_array(params);
    agent_codemap_push_paths(params, files, n);
    json_init(result);
}

static bool agent_codemap_is_json_arr(bool ok, const struct json_value *v)
{
    return ok && v && v->type == JSON_ARR;
}

static bool agent_codemap_map_contract_ok(bool ok,
                                         const struct json_value *result)
{
    static const struct {
        const char *name;
        size_t count;
    } rows[] = {
        { "agentmap.commands.core", 14 },
        { "agentmap.commands.drilldown", 6 },
        { "agentmap.telemetry", 12 },
        { "missing.surface", 0 },
    };
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.agent_map.v3") == 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        ok = ok &&
            agent_contract_command_surface_count(rows[i].name) == rows[i].count;
    return ok;
}

/* Rows stay in the original check order. find_always calls
 * find_object_with_str even after ok is false; otherwise that find sits
 * inside the ok && chain. A null field is an existence check. field2, when
 * set, is a second compare against the same object. */
static const struct agent_codemap_field_row {
    const char *key;
    const char *value;
    const char *field;
    const char *expect;
    const char *field2;
    const char *expect2;
    bool find_always;
} agent_codemap_command_rows[] = {
    { "method", "agentmap", NULL, NULL, NULL, NULL, false },
    { "method", "agentdeployguard", NULL, NULL, NULL, NULL, false },
    { "name", "impact", NULL, NULL, NULL, NULL, false },
    { "name", "build", NULL, NULL, NULL, NULL, false },
    { "name", "dev_status", "native", "z23 agentdevstatus", NULL, NULL, true },
    { "name", "proof_bundle", "native", "z23 proofbundle [anchor_datadir]",
      NULL, NULL, true },
    { "method", "healthcheck", NULL, NULL, NULL, NULL, false },
    { "method", "statecatalog", NULL, NULL, NULL, NULL, false },
    { "method", "peerincidents", NULL, NULL, NULL, NULL, false },
    { "name", "compact_status", "native", "z23 status", NULL, NULL, true },
    { "name", "full_compatibility_status", "native", "z23 agent",
      NULL, NULL, true },
    { "name", "background_quality", "native", "make quality-linger-status",
      NULL, NULL, true },
    { "method", "dumpstate", "native", "z23 dumpstate <subsystem> [key]",
      NULL, NULL, true },
    { "method", "getnodelog", "native", "z23 getnodelog <pattern>",
      NULL, NULL, true },
};

static const struct agent_codemap_field_row agent_codemap_telemetry_rows[] = {
    { "method", "peerincidents", "native", "z23 peerincidents", NULL, NULL,
      true },
    { "name", "compact_status", "native", "z23 status", NULL, NULL, true },
    { "name", "full_status", "native", "z23 healthcheck", NULL, NULL, true },
    { "name", "node_log", NULL, NULL, NULL, NULL, false },
    { "method", "anchorstatus", NULL, NULL, NULL, NULL, false },
    { "method", "proofbundle", "schema", "zcl.operator_proof_bundle.v2",
      NULL, NULL, true },
    { "method", "dbquery", "schema", "zcl.sql_result.v1",
      "native", "z23 dbquery <SELECT>", true },
    { "method", "eventlog", "schema", "zcl.event_log.v1",
      "native", "z23 eventlog <count>", true },
    { "name", "quality_lanes", "native", "make quality-linger-status",
      NULL, NULL, true },
};

static const struct agent_codemap_field_row agent_codemap_subsystem_rows[] = {
    { "name", "fast_ci", NULL, NULL, NULL, NULL, false },
};

static bool agent_codemap_field_rows_ok(bool ok, const struct json_value *arr,
                                        const struct agent_codemap_field_row *rows,
                                        size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const struct json_value *obj = NULL;
        if (rows[i].find_always || ok)
            obj = find_object_with_str(arr, rows[i].key, rows[i].value);
        ok = ok && obj && (rows[i].field == NULL ||
            strcmp(json_get_str(json_get(obj, rows[i].field)),
                   rows[i].expect) == 0);
        if (rows[i].field2 != NULL)
            ok = ok && obj &&
                strcmp(json_get_str(json_get(obj, rows[i].field2)),
                       rows[i].expect2) == 0;
    }
    return ok;
}

static bool agent_codemap_map_ok(void)
{
    struct rpc_table tbl;
    agent_codemap_prepare_rpc(&tbl);

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
    ok = agent_codemap_map_contract_ok(ok, &result);
    ok = agent_codemap_is_json_arr(ok, commands);
    ok = agent_codemap_field_rows_ok(ok, commands, agent_codemap_command_rows,
                                    sizeof(agent_codemap_command_rows) /
                                        sizeof(agent_codemap_command_rows[0]));
    ok = agent_codemap_is_json_arr(ok, telemetry);
    ok = agent_codemap_field_rows_ok(ok, telemetry,
                                    agent_codemap_telemetry_rows,
                                    sizeof(agent_codemap_telemetry_rows) /
                                        sizeof(agent_codemap_telemetry_rows[0]));
    ok = agent_codemap_is_json_arr(ok, subsystems);
    ok = agent_codemap_field_rows_ok(ok, subsystems,
                                    agent_codemap_subsystem_rows,
                                    sizeof(agent_codemap_subsystem_rows) /
                                        sizeof(agent_codemap_subsystem_rows[0]));
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool agent_codemap_impact_scalars_ok(bool ok,
                                           const struct json_value *result)
{
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.agent_impact.v2") == 0;
    ok = ok && json_get_int(json_get(result, "files_count")) == 6;
    ok = ok && json_get_bool(json_get(result, "code_changed"));
    ok = ok && !json_get_bool(json_get(result, "docs_only"));
    ok = ok && json_get_bool(json_get(result, "agent_api_changed"));
    ok = ok && strcmp(json_get_str(json_get(result, "mapping_source")),
                      "cognition/controllers/include/controllers/agent_impact_rules.def") == 0;
    ok = ok && json_get_int(json_get(result, "shared_rule_count")) > 0;
    return ok;
}

static bool agent_codemap_needles_ok(bool ok, const struct json_value *arr,
                                    bool (*has)(const struct json_value *,
                                                const char *),
                                    const char **needles, size_t n)
{
    for (size_t i = 0; i < n; i++)
        ok = ok && has(arr, needles[i]);
    return ok;
}

static bool agent_codemap_impact_detail_ok(bool ok,
                                          const struct json_value *result)
{
    const struct json_value *groups =
        json_get(result, "relevant_test_groups");
    const struct json_value *commands =
        json_get(result, "recommended_commands");
    const struct json_value *out_files = json_get(result, "files");
    static const char *group_needles[] = {
        "syncdiag_rpc",
        "command_registry_catalog",
        "make_lint_gates",
    };
    static const char *command_needles[] = {
        "ZCL_FAST_TESTS=syncdiag_rpc",
        "make fast-ci",
    };
    ok = agent_codemap_impact_scalars_ok(ok, result);
    ok = ok && json_get_int(json_get(result, "shared_rule_hits")) >= 6;
    ok = ok && json_get_int(json_get(result,
                                    "relevant_test_groups_count")) >= 3;
    ok = ok && out_files && json_size(out_files) == 6;
    ok = agent_codemap_needles_ok(ok, groups, json_array_has_str,
                                 group_needles,
                                 sizeof(group_needles) /
                                     sizeof(group_needles[0]));
    ok = agent_codemap_needles_ok(ok, commands, json_array_has_substr,
                                 command_needles,
                                 sizeof(command_needles) /
                                     sizeof(command_needles[0]));
    return ok;
}

static bool agent_codemap_native_handlers_match(bool ok,
                                               const struct json_value *result)
{
    const struct json_value *groups =
        json_get(result, "relevant_test_groups");
    static const char *needles[] = {
        "command_registry_catalog",
        "syncdiag_rpc",
        "make_lint_gates",
    };
    ok = ok && result->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(result, "code_changed"));
    return agent_codemap_needles_ok(ok, groups, json_array_has_str, needles,
                                   sizeof(needles) / sizeof(needles[0]));
}

int syncdiag_cases_agent_codemap(void)
{
    int failures = 0;

    printf("api: native RPC returns agent code map... ");
    if (agent_codemap_map_ok())
        printf("OK\n");
    else    { printf("FAIL\n"); failures++; }

    printf("api: native RPC maps changed files to tests... ");
    {
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;
        static const char *files[] = {
            "cognition/controllers/src/agent_controller.c",
            "cognition/controllers/src/agent_lanes_controller.c",
            "engine/controllers/src/event_healthcheck_controller.c",
            "engine/controllers/include/controllers/event_healthcheck_controller.h",
            "engine/controllers/src/diagnostics_native_handlers.c",
            "docs/agent/AGENT_API.md",
        };
        agent_codemap_begin_impact(&tbl, &params, &result, files,
                                  sizeof(files) / sizeof(files[0]));
        bool ok = rpc_table_execute(&tbl, "agentimpact", &params, &result);
        ok = agent_codemap_impact_detail_ok(ok, &result);
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
        struct json_value params;
        struct json_value result;
        static const char *files[] = {
            "engine/controllers/src/chain_native_handlers.c",
        };
        agent_codemap_begin_impact(&tbl, &params, &result, files,
                                  sizeof(files) / sizeof(files[0]));
        bool ok = rpc_table_execute(&tbl, "agentimpact", &params, &result);
        ok = agent_codemap_native_handlers_match(ok, &result);
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

    failures += agent_impact_classification_cases();

    return failures;
}
