/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The native agent API surface contract: the typed command registry is the
 * only agent interface, every documented leaf resolves, the discovery and
 * schema surfaces stay in step with the handlers, and the docs that describe
 * them stay accurate.
 *
 * One long check that asserts on the TEXT of the registry sources, the
 * controllers behind them, and docs/AGENT_API.md, so a leaf that is renamed,
 * dropped, or left undocumented fails here. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; native
 * Windows has no fork/exec/waitpid, so on _WIN32 every check compiles out and
 * the registered group entry points (test_make_lint_gates.c) report a loud
 * skip instead. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

int t_native_agent_api_contract(void)
{
    int failures = 0;
    char *main_buf = NULL;
    char *event_buf = NULL;
    char *agent_summary_buf = NULL;
    char *agent_summary_json_buf = NULL;
    char *agent_operator_buf = NULL;
    char *agent_ctrl_buf = NULL;
    char *agent_capability_registry_buf = NULL;
    char *agent_registry_buf = NULL;
    char *agent_review_registry_buf = NULL;
    char *agent_schema_registry_buf = NULL;
    char *agent_contracts_buf = NULL;
    char *agent_contracts_def_buf = NULL;
    char *agent_bg_quality_buf = NULL;
    char *agent_first_call_buf = NULL;
    char *agent_lanes_buf = NULL;
    char *agent_lane_runtime_buf = NULL;
    char *agent_liveness_buf = NULL;
    char *agent_diagnose_buf = NULL;
    char *event_timeline_buf = NULL;
    char *agent_anchor_status_buf = NULL;
    char *agent_iface_buf = NULL;
    char *agent_ops_buf = NULL;
    char *agent_runtime_buf = NULL;
    char *agent_readiness_buf = NULL;
    char *diag_ctrl_buf = NULL;
    char *diag_reg_buf = NULL;
    char *diag_manifest_buf = NULL;
    char *diag_catalog_buf = NULL;
    char *api_buf = NULL;
    char *api_status_buf = NULL;
    char *agent_doc_buf = NULL;
    TEST("zclassic23 binary exposes native API and agent commands") {
        char main_path[PATH_MAX];
        char event_path[PATH_MAX];
        char agent_summary_path[PATH_MAX];
        char agent_summary_json_path[PATH_MAX];
        char agent_operator_path[PATH_MAX];
        char agent_ctrl_path[PATH_MAX];
        char agent_capability_registry_path[PATH_MAX];
        char agent_registry_path[PATH_MAX];
        char agent_review_registry_path[PATH_MAX];
        char agent_schema_registry_path[PATH_MAX];
        char agent_contracts_path[PATH_MAX];
        char agent_contracts_def_path[PATH_MAX];
        char agent_bg_quality_path[PATH_MAX];
        char agent_first_call_path[PATH_MAX];
        char agent_lanes_path[PATH_MAX];
        char agent_lane_runtime_path[PATH_MAX];
        char agent_liveness_path[PATH_MAX];
        char agent_diagnose_path[PATH_MAX];
        char event_timeline_path[PATH_MAX];
        char agent_anchor_status_path[PATH_MAX];
        char agent_iface_path[PATH_MAX];
        char agent_ops_path[PATH_MAX];
        char agent_runtime_path[PATH_MAX];
        char agent_readiness_path[PATH_MAX];
        char diag_ctrl_path[PATH_MAX];
        char diag_reg_path[PATH_MAX];
        char diag_manifest_path[PATH_MAX];
        char diag_catalog_path[PATH_MAX];
        char api_path[PATH_MAX];
        char api_status_path[PATH_MAX];
        char agent_doc_path[PATH_MAX];
        ASSERT(repo_path(main_path, sizeof(main_path), "engine/entry/main.c") == 0);
        ASSERT(repo_path(event_path, sizeof(event_path),
                         "engine/controllers/src/event_controller.c") == 0);
        ASSERT(repo_path(agent_summary_path, sizeof(agent_summary_path),
                         "cognition/controllers/src/event_agent_summary.c") == 0);
        ASSERT(repo_path(agent_summary_json_path,
                         sizeof(agent_summary_json_path),
                         "cognition/controllers/src/event_agent_summary_json.c")
               == 0);
        ASSERT(repo_path(agent_operator_path, sizeof(agent_operator_path),
                         "cognition/controllers/src/agent_operator_contracts.c")
               == 0);
        ASSERT(repo_path(agent_ctrl_path, sizeof(agent_ctrl_path),
                         "cognition/controllers/src/agent_controller.c") == 0);
        ASSERT(repo_path(agent_capability_registry_path,
                         sizeof(agent_capability_registry_path),
                         "cognition/controllers/src/agent_contract_capability_registry.c")
               == 0);
        ASSERT(repo_path(agent_registry_path, sizeof(agent_registry_path),
                         "cognition/controllers/src/agent_contract_registry.c")
               == 0);
        ASSERT(repo_path(agent_review_registry_path,
                         sizeof(agent_review_registry_path),
                         "cognition/controllers/src/agent_contract_review_registry.c")
               == 0);
        ASSERT(repo_path(agent_schema_registry_path,
                         sizeof(agent_schema_registry_path),
                         "cognition/controllers/src/agent_contract_schema_registry.c")
               == 0);
        ASSERT(repo_path(agent_contracts_path, sizeof(agent_contracts_path),
                         "cognition/controllers/src/agent_contracts_controller.c")
               == 0);
        ASSERT(repo_path(agent_contracts_def_path,
                         sizeof(agent_contracts_def_path),
                         "cognition/controllers/include/controllers/agent_contracts.def")
               == 0);
        ASSERT(repo_path(agent_bg_quality_path,
                         sizeof(agent_bg_quality_path),
                         "cognition/controllers/src/agent_background_quality.c")
               == 0);
        ASSERT(repo_path(agent_first_call_path,
                         sizeof(agent_first_call_path),
                         "cognition/controllers/src/agent_first_call.c")
               == 0);
        ASSERT(repo_path(agent_lanes_path, sizeof(agent_lanes_path),
                         "cognition/controllers/src/agent_lanes_controller.c") == 0);
        ASSERT(repo_path(agent_lane_runtime_path,
                         sizeof(agent_lane_runtime_path),
                         "cognition/controllers/src/agent_lane_runtime.c") == 0);
        ASSERT(repo_path(agent_liveness_path, sizeof(agent_liveness_path),
                         "cognition/controllers/src/agent_liveness_controller.c")
               == 0);
        ASSERT(repo_path(agent_diagnose_path, sizeof(agent_diagnose_path),
                         "cognition/controllers/src/agent_diagnose_controller.c")
               == 0);
        ASSERT(repo_path(event_timeline_path, sizeof(event_timeline_path),
                         "engine/controllers/src/event_timeline_controller.c")
               == 0);
        ASSERT(repo_path(agent_anchor_status_path,
                         sizeof(agent_anchor_status_path),
                         "cognition/controllers/src/agent_anchor_status_controller.c")
               == 0);
        ASSERT(repo_path(agent_iface_path, sizeof(agent_iface_path),
                         "cognition/controllers/src/agent_interface_controller.c")
               == 0);
        ASSERT(repo_path(agent_ops_path, sizeof(agent_ops_path),
                         "cognition/controllers/src/agent_ops_controller.c") == 0);
        ASSERT(repo_path(agent_runtime_path, sizeof(agent_runtime_path),
                         "cognition/controllers/src/agent_runtime_controller.c") == 0);
        ASSERT(repo_path(agent_readiness_path, sizeof(agent_readiness_path),
                         "cognition/controllers/src/event_agent_readiness.c") == 0);
        ASSERT(repo_path(diag_ctrl_path, sizeof(diag_ctrl_path),
                         "engine/controllers/src/diagnostics_controller.c") == 0);
        ASSERT(repo_path(diag_reg_path, sizeof(diag_reg_path),
                         "engine/controllers/src/diagnostics_registry.c") == 0);
        ASSERT(repo_path(
                   diag_manifest_path, sizeof(diag_manifest_path),
                   "engine/controllers/include/controllers/diagnostics_dumpers.def")
               == 0);
        ASSERT(repo_path(diag_catalog_path, sizeof(diag_catalog_path),
                         "engine/controllers/src/diagnostics_catalog_controller.c")
               == 0);
        ASSERT(repo_path(api_path, sizeof(api_path),
                         "cognition/controllers/src/api_controller_agent_index.c")
               == 0);
        ASSERT(repo_path(api_status_path, sizeof(api_status_path),
                         "engine/controllers/src/api_controller_status.c") == 0);
        ASSERT(repo_path(agent_doc_path, sizeof(agent_doc_path),
                         "docs/AGENT_API.md") == 0);
        ASSERT(read_entire_file(main_path, &main_buf) == 0);
        /* P1 split (pure code motion): the CLI client + run-and-exit modes
         * moved from engine/entry/main.c to engine/entry/main_cli_modes.c, and the flag ladder +
         * usage text to engine/composition/src/args.c. This "node entry point exposes the
         * agent surface" contract now spans all three node-entry/args sources,
         * so concatenate them into main_buf — the assertions below assert the
         * combined surface, exactly as they did when it all lived in main.c. */
        {
            char main_cli_modes_path[PATH_MAX];
            char args_path[PATH_MAX];
            char *main_cli_modes_buf = NULL;
            char *args_buf = NULL;
            ASSERT(repo_path(main_cli_modes_path, sizeof(main_cli_modes_path),
                             "engine/entry/main_cli_modes.c") == 0);
            ASSERT(repo_path(args_path, sizeof(args_path),
                             "engine/composition/src/args.c") == 0);
            ASSERT(read_entire_file(main_cli_modes_path, &main_cli_modes_buf)
                   == 0);
            ASSERT(read_entire_file(args_path, &args_buf) == 0);
            size_t combined_len = strlen(main_buf) + strlen(main_cli_modes_buf)
                                + strlen(args_buf) + 1;
            char *combined = malloc(combined_len);
            ASSERT(combined != NULL);
            snprintf(combined, combined_len, "%s%s%s", main_buf,
                     main_cli_modes_buf, args_buf);
            free(main_buf);
            free(main_cli_modes_buf);
            free(args_buf);
            main_buf = combined;
        }
        ASSERT(read_entire_file(event_path, &event_buf) == 0);
        ASSERT(read_entire_file(agent_summary_path, &agent_summary_buf) == 0);
        ASSERT(read_entire_file(agent_summary_json_path,
                                &agent_summary_json_buf) == 0);
        ASSERT(read_entire_file(agent_operator_path, &agent_operator_buf)
               == 0);
        ASSERT(read_entire_file(agent_ctrl_path, &agent_ctrl_buf) == 0);
        ASSERT(read_entire_file(agent_capability_registry_path,
                                &agent_capability_registry_buf) == 0);
        ASSERT(read_entire_file(agent_registry_path, &agent_registry_buf) == 0);
        ASSERT(read_entire_file(agent_review_registry_path,
                                &agent_review_registry_buf) == 0);
        ASSERT(read_entire_file(agent_schema_registry_path,
                                &agent_schema_registry_buf) == 0);
        ASSERT(read_entire_file(agent_contracts_path,
                                &agent_contracts_buf) == 0);
        ASSERT(read_entire_file(agent_contracts_def_path,
                                &agent_contracts_def_buf) == 0);
        ASSERT(read_entire_file(agent_bg_quality_path,
                                &agent_bg_quality_buf) == 0);
        ASSERT(read_entire_file(agent_first_call_path,
                                &agent_first_call_buf) == 0);
        ASSERT(read_entire_file(agent_lanes_path, &agent_lanes_buf) == 0);
        ASSERT(read_entire_file(agent_lane_runtime_path,
                                &agent_lane_runtime_buf) == 0);
        ASSERT(read_entire_file(agent_liveness_path,
                                &agent_liveness_buf) == 0);
        ASSERT(read_entire_file(agent_diagnose_path,
                                &agent_diagnose_buf) == 0);
        ASSERT(read_entire_file(event_timeline_path,
                                &event_timeline_buf) == 0);
        ASSERT(read_entire_file(agent_anchor_status_path,
                                &agent_anchor_status_buf) == 0);
        ASSERT(read_entire_file(agent_iface_path, &agent_iface_buf) == 0);
        ASSERT(read_entire_file(agent_ops_path, &agent_ops_buf) == 0);
        ASSERT(read_entire_file(agent_runtime_path, &agent_runtime_buf) == 0);
        ASSERT(read_entire_file(agent_readiness_path,
                                &agent_readiness_buf) == 0);
        ASSERT(read_entire_file(diag_ctrl_path, &diag_ctrl_buf) == 0);
        ASSERT(read_entire_file(diag_reg_path, &diag_reg_buf) == 0);
        ASSERT(read_entire_file(diag_manifest_path, &diag_manifest_buf) == 0);
        /* The DIAG_* rows moved out of diagnostics_dumpers.def into eight
         * per-domain files; the .def itself is now a pure aggregator holding
         * only #includes. The contract asserted below is about the ROW SET,
         * not about which file a row sits in, so resolve the aggregator's
         * include list and concatenate — the same set the preprocessor sees.
         *
         * The list is PARSED rather than hardcoded because naming the eight
         * files here would let a ninth domain escape every assertion below
         * without anyone noticing. The >= 8 floor is the anti-hollowness
         * guard: without it, an include pattern that stopped matching would
         * leave diag_manifest_buf holding nothing but comments, and every
         * strstr() below would fail with a message blaming the wrong thing. */
        {
            static const char inc_needle[] =
                "#include \"controllers/diagnostics_dumpers_";
            char diag_dir[PATH_MAX];
            snprintf(diag_dir, sizeof diag_dir, "%s", diag_manifest_path);
            char *slash = strrchr(diag_dir, '/');
            ASSERT(slash != NULL);
            *slash = '\0';

            char *combined = strdup(diag_manifest_buf);
            ASSERT(combined != NULL);
            size_t combined_len = strlen(combined);
            int domain_files = 0;

            for (const char *p = strstr(diag_manifest_buf, inc_needle); p;
                 p = strstr(p + 1, inc_needle)) {
                const char *name = p + sizeof(inc_needle) - 1;
                const char *end = strchr(name, '"');
                ASSERT(end != NULL);
                char rel[PATH_MAX];
                int n = snprintf(rel, sizeof rel,
                                 "%s/diagnostics_dumpers_%.*s", diag_dir,
                                 (int)(end - name), name);
                ASSERT(n > 0 && (size_t)n < sizeof rel);

                if (access(rel, R_OK) != 0) {
                    const char *authority =
                        strncmp(name, "wallet.def", (size_t)(end - name)) == 0
                            ? "contexts/wallet"
                            : "contexts/commons";
                    n = snprintf(rel, sizeof rel,
                                 "%s/%s/controllers/include/controllers/"
                                 "diagnostics_dumpers_%.*s",
                                 repo_root(), authority,
                                 (int)(end - name), name);
                    ASSERT(n > 0 && (size_t)n < sizeof rel);
                }

                char *part = NULL;
                ASSERT(read_entire_file(rel, &part) == 0);
                size_t part_len = strlen(part);
                char *grown = realloc(combined, combined_len + part_len + 1);
                ASSERT(grown != NULL);
                combined = grown;
                memcpy(combined + combined_len, part, part_len + 1);
                combined_len += part_len;
                free(part);
                domain_files++;
            }
            ASSERT(domain_files >= 8);
            free(diag_manifest_buf);
            diag_manifest_buf = combined;
        }
        ASSERT(read_entire_file(diag_catalog_path, &diag_catalog_buf) == 0);
        ASSERT(read_entire_file(api_path, &api_buf) == 0);
        ASSERT(read_entire_file(api_status_path, &api_status_buf) == 0);
        ASSERT(read_entire_file(agent_doc_path, &agent_doc_buf) == 0);
        ASSERT(strstr(main_buf,
                      "Agent/operator API commands (from agent_contracts.def)")
               != NULL);
        ASSERT(strstr(main_buf, "agent_print_native_usage(stdout, prog)")
               != NULL);
        ASSERT(strstr(main_buf, "AI-coder code/docs/test map") == NULL);
        ASSERT(strstr(main_buf, "Compact no-jq AI/operator command center")
               == NULL);
        ASSERT(strstr(main_buf, "-operator-lane=<name>") != NULL);
        ASSERT(strstr(main_buf, "ZCL_OPERATOR_LANE") != NULL);
        ASSERT(strstr(main_buf, "strncmp(argv[i], \"-operator-lane=\", 15)")
               != NULL);
        ASSERT(strstr(main_buf, "app_operator_lane_parse") != NULL);
        ASSERT(strstr(main_buf, "app_operator_lane_name(operator_lane)")
               != NULL);
        ASSERT(strstr(main_buf, "rpc_agent_set_boot_context") != NULL);
        ASSERT(strstr(main_buf, "cli_probe_static_agent_target") != NULL);
        ASSERT(strstr(main_buf, "agent_runtime_probe_method_name") != NULL);
        ASSERT(strstr(main_buf, "RPC_METHOD_NOT_FOUND") != NULL);
        ASSERT(strstr(main_buf, "cli_agent_contract_method") != NULL);
        ASSERT(strstr(main_buf,
                      "cli_print_contract_method_skew_diagnostic") != NULL);
        ASSERT(strstr(main_buf, "zcl.cli_rpc_diagnostic.v1") != NULL);
        ASSERT(strstr(main_buf,
                      "target_runtime_method_not_found") != NULL);
        ASSERT(strstr(main_buf,
                      "target_runtime_version_skew_or_contract_not_deployed")
               != NULL);
        ASSERT(strstr(main_buf, "cli_service_exec_arg") != NULL);
        ASSERT(strstr(main_buf, "systemctl --user show zclassic23") != NULL);
        ASSERT(strstr(main_buf, "cli_p2p_port") != NULL);
        ASSERT(strstr(main_buf, "cli_service_exec_arg(\"port\"") != NULL);
        ASSERT(strstr(main_buf,
                      "datadir, cli_port, cli_p2p_port") != NULL);
        ASSERT(strstr(main_buf, "cli_cookie_exists") != NULL);
        ASSERT(strstr(main_buf, "cannot accidentally query") != NULL);
        ASSERT(strstr(main_buf, "params_storage") != NULL);
        ASSERT(strstr(main_buf, "strcmp(method, \"--agent\")") != NULL);
        ASSERT(strstr(main_buf, "strcmp(method, \"--status\")") != NULL);
        ASSERT(strstr(main_buf, "cli_runtime_rpc_method") == NULL);
        ASSERT(strstr(main_buf, "zcl_native_command_is_root(method)") != NULL);
        ASSERT(strstr(main_buf, "zcl_native_command_main(method") != NULL);
        ASSERT(strstr(main_buf, "strcmp(argv[i], \"--agent\")") != NULL);
        ASSERT(strstr(main_buf, "strcmp(argv[i], \"--status\")") != NULL);
        ASSERT(strstr(main_buf, "cli_static_agent_method") != NULL);
        ASSERT(strstr(main_buf, "struct cli_static_agent_route") != NULL);
        ASSERT(strstr(main_buf, "g_cli_static_agent_routes") != NULL);
        ASSERT(strstr(main_buf, "cli_static_agent_lookup") != NULL);
        ASSERT(strstr(main_buf, "agent_contract_lookup(route->method)")
               != NULL);
        ASSERT(strstr(main_buf, "cli_run_static_agent_method") != NULL);
        ASSERT(strstr(main_buf, "cli_static_agent_result_exit_code") != NULL);
        ASSERT(strstr(main_buf, "json_get(result, \"exit_code\")") != NULL);
        ASSERT(strstr(main_buf, "code < 0 || code > 125") != NULL);
        ASSERT(strstr(main_buf, "\"agentmap\", rpc_agent_map") != NULL);
        ASSERT(strstr(main_buf, "\"agentlanes\", rpc_agent_lanes") != NULL);
        ASSERT(strstr(main_buf, "\"agentliveness\", rpc_agent_liveness")
               != NULL);
        ASSERT(strstr(main_buf, "\"agentimpact\", rpc_agent_impact") != NULL);
        ASSERT(strstr(main_buf, "\"agentcontracts\", rpc_agent_contracts")
               != NULL);
        ASSERT(strstr(main_buf, "\"agentbuild\", rpc_agent_build") != NULL);
        ASSERT(strstr(main_buf, "\"agentdevstatus\", rpc_agent_dev_status")
               != NULL);
        ASSERT(strstr(main_buf, "\"anchorstatus\", rpc_agent_anchor_status")
               != NULL);
        ASSERT(strstr(main_buf, "\"appprotocols\", rpc_app_protocols")
               != NULL);
        ASSERT(strstr(main_buf, "\"servicecatalog\", rpc_service_catalog")
               != NULL);
        ASSERT(strstr(main_buf, "\"agentinterface\", rpc_agent_interface")
               != NULL);
        ASSERT(strstr(main_buf, "\"agentops\", rpc_agent_ops") != NULL);
        ASSERT(strstr(main_buf, "\"statecatalog\", diag_rpc_statecatalog")
               != NULL);
        ASSERT(strstr(main_buf, "strcmp(method, \"agentdeployguard\")")
               != NULL);
        ASSERT(strstr(main_buf,
                      "\"agentdeployguard\", rpc_agent_deploy_guard")
               != NULL);
        ASSERT(strstr(main_buf, "route->handler(&params, false, &result)")
               != NULL);
        char *static_agent_dispatch =
            strstr(main_buf, "if (cli_static_agent_method(method))");
        char *cookie_read = static_agent_dispatch
            ? strstr(static_agent_dispatch, "if (!cli_read_cookie(datadir))")
            : NULL;
        ASSERT(static_agent_dispatch != NULL);
        ASSERT(cookie_read != NULL);
        ASSERT(static_agent_dispatch < cookie_read);
        ASSERT(strstr(event_buf, "{ \"control\", \"api\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"apiindex\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"appprotocols\"")
               != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"protocols\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"servicecatalog\"")
               != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"service_catalog\"")
               != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agent\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"status\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentops\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentdiagnose\"")
               != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"timeline\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentmap\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentlanes\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentliveness\"")
               != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentimpact\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentcontracts\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentbuild\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"anchorstatus\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentinterface\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"agentdeployguard\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"summary\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"milestone\"") != NULL);
        ASSERT(strstr(event_buf, "{ \"control\", \"refold\"") != NULL);
        ASSERT(strstr(diag_ctrl_buf, "{ \"control\", \"statecatalog\"")
               != NULL);
        ASSERT(strstr(diag_reg_buf, "diagnostics_dumper_count") != NULL);
        ASSERT(strstr(diag_reg_buf, "diagnostics_dumper_at") != NULL);
        ASSERT(strstr(diag_reg_buf,
                      "#include \"controllers/diagnostics_dumpers.def\"")
               != NULL);
        ASSERT(strstr(diag_manifest_buf, "DIAG_ENTRY(\"supervisor\"")
               != NULL);
        ASSERT(strstr(diag_manifest_buf, "DIAG_PROJECTION(") != NULL);
        ASSERT(strstr(diag_catalog_buf, "zcl.state_catalog.v2") != NULL);
        ASSERT(strstr(diag_catalog_buf, "diagnostics_catalog_push_entry")
               != NULL);
        ASSERT(strstr(diag_catalog_buf, "e->cost") != NULL);
        ASSERT(strstr(diag_catalog_buf, "e->owner_file") != NULL);
        ASSERT(strstr(diag_catalog_buf, "\"owner_file\"") != NULL);
        ASSERT(strstr(diag_catalog_buf, "\"safety_level\"") != NULL);
        ASSERT(strstr(diag_catalog_buf, "\"accepted_keys\"") != NULL);
        ASSERT(strstr(diag_catalog_buf, "\"tests\"") != NULL);
        ASSERT(strstr(diag_catalog_buf, "\"drilldowns\"") != NULL);
        ASSERT(strstr(agent_summary_buf, "api_version\", \"v1\"") != NULL);
        ASSERT(strstr(event_buf, "#include \"event_agent_summary.h\"") != NULL);
        ASSERT(strstr(event_buf, "rpc_agent_summary") != NULL);
        ASSERT(strstr(agent_summary_buf, "zcl.public_status.v3") != NULL);
        ASSERT(strstr(agent_summary_buf, "agent_push_first_call_simple_json")
               != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "ZCL_AGENT_FIRST_CALL_BUDGET_AGENT_MS") != NULL);
        ASSERT(strstr(agent_first_call_buf,
                      "zcl.first_call_contract.v1") != NULL);
        ASSERT(strstr(agent_first_call_buf, "\"result_completeness\"")
               != NULL);
        ASSERT(strstr(agent_first_call_buf,
                      "platform_time_monotonic_us") != NULL);
        ASSERT(strstr(agent_first_call_buf, "\"budget_ms\"") != NULL);
        ASSERT(strstr(agent_first_call_buf, "\"elapsed_ms\"") != NULL);
        ASSERT(strstr(agent_first_call_buf, "\"budget_exceeded\"")
               != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "agent_operator_latch_suppressed_by_mirror") != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "agent_push_operator_latch_contract_json") != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "agent_push_condition_summary_contract_json") != NULL);
        ASSERT(strstr(agent_operator_buf, "zcl.operator_latch.v2") != NULL);
        ASSERT(strstr(agent_operator_buf,
                      "zcl.condition_engine_summary.v2") != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "legacy_mirror_sync_push_status_contract_json")
               != NULL);
        ASSERT(strstr(agent_operator_buf,
                      "suppressed_by_mirror_contract") != NULL);
        /* Conditions are captured in one registry pass (operator-snapshot
         * refactor) — the summary reads condition_engine_get_summary, not
         * the per-count getters. */
        ASSERT(strstr(agent_summary_buf,
                      "condition_engine_get_summary") != NULL);
        ASSERT(strstr(agent_summary_buf, "agent_fast_collect") != NULL);
        ASSERT(strstr(agent_summary_buf, "agent_summary_push_detail_json")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "dl_get_stats") != NULL);
        ASSERT(strstr(agent_summary_buf, "dl_get_diagnostics") != NULL);
        ASSERT(strstr(agent_summary_buf, "dl_get_throughput") != NULL);
        ASSERT(strstr(agent_summary_buf, "assign_attempts") != NULL);
        ASSERT(strstr(agent_summary_buf, "message_send_calls") != NULL);
        ASSERT(strstr(agent_summary_buf, "connman_get_message_cycle_stats")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "dl_assign_result_name") == NULL);
        ASSERT(strstr(agent_summary_json_buf, "dl_assign_result_name")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "sync_monitor_tip_advance_age")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "AGENT_CATCHUP_STALL_SECS")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "AGENT_DISPATCH_IDLE_SECS")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "catchup_stalled") != NULL);
        ASSERT(strstr(agent_summary_buf, "download_dispatch_idle")
               != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "block_source_policy_get_cached_status") != NULL);
        ASSERT(strstr(agent_summary_buf, "block_source_policy_get_status")
               == NULL);
        ASSERT(strstr(agent_summary_buf, "api_served_tip_height()") == NULL);
        ASSERT(strstr(agent_summary_buf, "node_db_sync_get_job_status")
               != NULL);
        ASSERT(strstr(agent_summary_json_buf, "\"indexer\"") != NULL);
        ASSERT(strstr(agent_summary_buf, "agent_push_readiness_contract_json")
               != NULL);
        ASSERT(strstr(api_status_buf, "agent_push_readiness_contract_json")
               != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "agent_push_security_posture_snapshot_json") != NULL);
        ASSERT(strstr(api_status_buf, "agent_push_security_posture_json")
               != NULL);
        ASSERT(strstr(agent_readiness_buf, "agent_push_readiness_json")
               != NULL);
        ASSERT(strstr(agent_readiness_buf, "agent_push_readiness_fields_json")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "agent_push_height_contract_fields_json")
               != NULL);
        ASSERT(strstr(api_status_buf, "agent_push_height_contract_fields_json")
               != NULL);
        ASSERT(strstr(agent_readiness_buf, "zcl.agent_readiness.v1") != NULL);
        ASSERT(strstr(agent_schema_registry_buf, "zcl.security_posture.v1")
               != NULL);
        ASSERT(strstr(agent_readiness_buf, "chain_serving_ready") != NULL);
        ASSERT(strstr(agent_readiness_buf, "index_projection_ready") != NULL);
        ASSERT(strstr(agent_readiness_buf, "agent_work_ready") != NULL);
        ASSERT(strstr(agent_readiness_buf, "readiness_status") != NULL);
        ASSERT(strstr(agent_readiness_buf, "readiness_next_action") != NULL);
        ASSERT(strstr(agent_readiness_buf, "serving_projection_deferred")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "projection_lag") != NULL);
        ASSERT(strstr(agent_summary_buf, "projection_deferred") != NULL);
        ASSERT(strstr(agent_summary_buf, "projection_catchup_active")
               != NULL);
        ASSERT(strstr(agent_summary_buf, "node_health_collect(") == NULL);
        ASSERT(strstr(agent_ctrl_buf, "zcl.agent_map.v3") != NULL);
        ASSERT(strstr(agent_lanes_buf, "zcl.agent_lanes.v2") != NULL);
        ASSERT(strstr(agent_liveness_buf, "zcl.agent_liveness.v2") != NULL);
        ASSERT(strstr(agent_liveness_buf, "agent_push_first_call_simple_json")
               != NULL);
        ASSERT(strstr(agent_liveness_buf,
                      "ZCL_AGENT_FIRST_CALL_BUDGET_LIVENESS_MS") != NULL);
        ASSERT(strstr(agent_liveness_buf,
                      "background_quality_skipped_due_to_first_call_budget")
               != NULL);
        ASSERT(strstr(agent_liveness_buf, "supervisor_dump_state_json")
               != NULL);
        ASSERT(strstr(agent_liveness_buf,
                      "agent_build_background_quality_status") != NULL);
        ASSERT(strstr(agent_liveness_buf, "effective_runtime_reachable")
               != NULL);
        ASSERT(strstr(agent_liveness_buf, "effective_runtime_scope")
               != NULL);
        ASSERT(strstr(agent_diagnose_buf, "zcl.agent_diagnose.v2")
               != NULL);
        ASSERT(strstr(agent_diagnose_buf,
                      "ZCL_AGENT_FIRST_CALL_BUDGET_DIAGNOSE_MS") != NULL);
        ASSERT(strstr(agent_diagnose_buf, "peer_lifecycle_incidents_json")
               != NULL);
        ASSERT(strstr(agent_diagnose_buf, "rpc_healthcheck") != NULL);
        ASSERT(strstr(agent_diagnose_buf, "rpc_timeline") != NULL);
        ASSERT(strstr(agent_diagnose_buf, "diag_rpc_getmirrorstatus")
               != NULL);
        ASSERT(strstr(event_timeline_buf,
                      "#include \"controllers/agent_controller.h\"") != NULL);
        ASSERT(strstr(agent_diagnose_buf,
                      "agent_push_contract_native_command_json(&commands, "
                      "\"agent\")")
               != NULL);
        ASSERT(strstr(agent_diagnose_buf,
                      "agent_push_contract_native_command_json(&commands, "
                      "\"agentliveness\")")
               != NULL);
        ASSERT(strstr(agent_diagnose_buf,
                      "agent_push_contract_native_command_json(&commands, "
                      "\"timeline\")")
               != NULL);
        ASSERT(strstr(agent_anchor_status_buf,
                      "zcl.anchor_mint_status.v1") != NULL);
        /* A4: the anchor-status controller resolves the kernel store via the
         * flip-aware helper (consensus.db, legacy progress.kv fallback) rather
         * than hardcoding the store filename. */
        ASSERT(strstr(agent_anchor_status_buf,
                      "consensus_db_kernel_store_path") != NULL);
        ASSERT(strstr(agent_anchor_status_buf,
                      "validated_backlog_blocks") != NULL);
        ASSERT(strstr(agent_anchor_status_buf,
                      "stale_header_rows_above_anchor") != NULL);
        ASSERT(strstr(agent_anchor_status_buf,
                      "agent_next_action") != NULL);
        ASSERT(strstr(agent_anchor_status_buf,
                      "inspect_utxo_apply_idle_reason_before_waiting_more")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf, "zcl.agent_impact.v2") != NULL);
        ASSERT(strstr(agent_ctrl_buf,
                      "cognition/controllers/src/agent_anchor_status_controller.c")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "anchorstatus") != NULL);
        ASSERT(strstr(agent_contracts_buf, "zcl.agent_contracts.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "AGENT_CONTRACT") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.public_status.v3")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "runtime_status_alias")
               == NULL);
        ASSERT(strstr(agent_contracts_def_buf, "AGENT_CONTRACT(\"status\"")
               == NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.agent_interface.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.agent_ops.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.agent_diagnose.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 agentdiagnose")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.agent_liveness.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 agentliveness")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.agent_dev_status.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 agentdevstatus")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.timeline.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 timeline")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.state_catalog.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 statecatalog")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.agent_deploy_guard.v1")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "zcl.anchor_mint_status.v1") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "zcl.operator_proof_bundle.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 proofbundle")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf, "zcl.agent_build.v2") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "dev_node_binary") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make agent-loop") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "ZCL_AGENT_LOOP_BIN=1 make agent-loop")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf,
                      "ZCL_AGENT_LOOP_DEPLOY=dev make agent-loop refuses") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make agent-deploy-fast") != NULL);
        /* The self-documentation names native dev-lane workflows. */
        ASSERT(strstr(agent_ctrl_buf, "make agent-dev-status") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make agent-doctor") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "z23 agentdevstatus") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make agent-stage-dev") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make dev-bin") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "build/bin/z23-dev") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "ZCL_DEV_HOT_OPT=-O2") != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.background_quality_runtime.v1") != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.agent_dev_status.v2") != NULL);
        ASSERT(strstr(agent_schema_registry_buf, "zcl.first_call_contract.v1")
               != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.agent_readiness.v1") != NULL);
        ASSERT(strstr(agent_schema_registry_buf, "zcl.height_contract.v1")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.mirror_status.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "ops_surface") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "ops_rank") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "ops_name") != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.operator_latch.v2") != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.condition_engine_summary.v2") != NULL);
        ASSERT(strstr(agent_contracts_buf,
                      "contracts_push_agent_registry_schemas") != NULL);
        ASSERT(strstr(agent_contracts_buf,
                      "agent_push_contract_schema_surface_json") != NULL);
        ASSERT(strstr(agent_schema_registry_buf, "g_agent_schema_surfaces")
               != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "agent_contract_schema_surface_count") != NULL);
        ASSERT(strstr(agent_contracts_buf,
                      "agent_push_contract_summary_json") != NULL);
        ASSERT(strstr(agent_contracts_buf, "agent_contract_count()")
               != NULL);
        ASSERT(strstr(agent_contracts_buf, "agent_contract_at(i)")
               != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.agent_runtime_availability.v3") != NULL);
        ASSERT(strstr(agent_registry_buf, "schema_surface_count") != NULL);
        ASSERT(strstr(agent_registry_buf, "schema_registry_source") != NULL);
        ASSERT(strstr(agent_ops_buf, "zcl.agent_ops.v2") != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_field_surface_json(result, \"agentops.first_call\")")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_ops_surface_json(&api_rules, \"direct\")")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_ops_surface_json(&commands, \"drilldown\")")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_contract_lookup(") == NULL);
        ASSERT(strstr(agent_ops_buf, "anchor_status_command") == NULL);
        ASSERT(strstr(agent_contracts_def_buf, "anchor_mint_status") != NULL);
        ASSERT(strstr(agent_ops_buf, "refold_plain_english") != NULL);
        ASSERT(strstr(agent_ops_buf, "diagnostics_drilldown_command")
               == NULL);
        ASSERT(strstr(agent_ops_buf, "no_jq_required") != NULL);
        ASSERT(strstr(agent_ops_buf, "diagnose_command") == NULL);
        ASSERT(strstr(agent_ops_buf, "deploy_guard_command") == NULL);
        ASSERT(strstr(agent_ops_buf, "agentdiagnose") == NULL);
        ASSERT(strstr(agent_ops_buf, "top_next_work") != NULL);
        ASSERT(strstr(agent_ops_buf, "api_gaps") != NULL);
        ASSERT(strstr(agent_ops_buf, "api_ux") != NULL);
        ASSERT(strstr(agent_ops_buf, "agentops.workflow") != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_work_surface_json(&gaps")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_work_surface_json(&workflow")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_work_surface_json(&work")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "agent_push_contract_review_surface_json(&review")
               != NULL);
        ASSERT(strstr(agent_ops_buf, "main_dry_problem") == NULL);
        ASSERT(strstr(agent_review_registry_buf,
                      "agentops.architecture_review") != NULL);
        ASSERT(strstr(agent_review_registry_buf,
                      "g_agent_review_surfaces") != NULL);
        ASSERT(strstr(agent_review_registry_buf,
                      "agent_contract_review_surface_count") != NULL);
        ASSERT(strstr(agent_review_registry_buf,
                      "agent_push_contract_review_surface_json") != NULL);
        ASSERT(strstr(agent_review_registry_buf, "main_dry_problem")
               != NULL);
        ASSERT(strstr(agent_ops_buf, "agentops.api_gaps") != NULL);
        ASSERT(strstr(agent_ops_buf, "agentops.top_next_work") != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "finish_self_verified_utxo_anchor_rebuild") == NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.agent_runtime_identity.v1")
               != NULL);
        ASSERT(strstr(agent_contracts_buf, "No Python is required") != NULL);
        ASSERT(strstr(agent_iface_buf, "build_commit") != NULL);
        ASSERT(strstr(agent_iface_buf, "runtime_identity") != NULL);
        ASSERT(strstr(agent_iface_buf, "runtime_availability") != NULL);
        ASSERT(strstr(agent_iface_buf, "preferred_transport") != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "agent_push_contract_capabilities_json(&capabilities)")
               != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "agent_push_contract_capability_json(") != NULL);
        ASSERT(strstr(agent_capability_registry_buf,
                      "agent_contract_count()") != NULL);
        ASSERT(strstr(agent_capability_registry_buf,
                      "agent_contract_at(i)") != NULL);
        ASSERT(strstr(agent_capability_registry_buf,
                      "registry_alias") != NULL);
        ASSERT(strstr(agent_capability_registry_buf,
                      "canonical_capability") != NULL);
        ASSERT(strstr(agent_capability_registry_buf,
                      "contract_source") != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "agent_push_contract_native_field_json(&loop")
               != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "\"preferred_transport\", \"native_cli\"")
               != NULL);
        ASSERT(strstr(agent_ops_buf,
                      "\"preferred_transport\", \"native_cli\"")
               != NULL);
        ASSERT(strstr(agent_iface_buf, "must_live_in_c") != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "cognition/controllers/src/agent_interface_controller.c")
               != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "do not require Python to parse agent API JSON")
               != NULL);
        ASSERT(strstr(agent_schema_registry_buf, "zcl.operator_lane.v1")
               != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.operator_deployment_safety.v1") != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.agent_runtime_services.v1") != NULL);
        ASSERT(strstr(agent_schema_registry_buf,
                      "zcl.mvp_operator_proofs.v1") != NULL);
        ASSERT(strstr(agent_lanes_buf, "agent_push_lane_topology") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "agent_push_runtime_services_json") != NULL);
        ASSERT(strstr(agent_lanes_buf, "default_deploy_target") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "agent_operator_lane_topology_count") != NULL);
        ASSERT(strstr(agent_runtime_buf,
                      "zcl.agent_runtime_services.v1") != NULL);
        ASSERT(strstr(agent_runtime_buf,
                      "zcl.agent_runtime_availability.v3") != NULL);
        ASSERT(strstr(agent_runtime_buf, "controllers/agent_contracts.def")
               != NULL);
        ASSERT(strstr(agent_runtime_buf, "agent_contract_count()") != NULL);
        ASSERT(strstr(agent_runtime_buf, "agent_contract_at(i)") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "static const struct agent_contract g_agent_contracts")
               != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "g_agent_command_surfaces") != NULL);
        ASSERT(strstr(agent_registry_buf, "g_agent_field_surfaces")
               != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_contract_field_surface_count") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_push_contract_field_surface_json") != NULL);
        ASSERT(strstr(agent_registry_buf, "agentops.first_call") != NULL);
        ASSERT(strstr(agent_registry_buf, "agentops.workflow") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "drill_down_only_when_needed") != NULL);
        ASSERT(strstr(agent_registry_buf, "anchor_status_command") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "diagnostics_drilldown_command") != NULL);
        ASSERT(strstr(agent_registry_buf, "deploy_guard_command") != NULL);
        ASSERT(strstr(agent_registry_buf, "diagnose_command") != NULL);
        ASSERT(strstr(agent_registry_buf, "agentdiagnose") != NULL);
        ASSERT(strstr(agent_registry_buf, "DIRECT_COMMAND") != NULL);
        ASSERT(strstr(agent_registry_buf, "native_override") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_contract_command_surface_count") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_push_contract_command_surface_json") != NULL);
        ASSERT(strstr(agent_registry_buf, "g_agent_work_surfaces") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_contract_work_surface_count") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_push_contract_work_surface_json") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "native_declared_count") != NULL);
        ASSERT(strstr(agent_registry_buf, "rest_declared_count") != NULL);
        ASSERT(strstr(agent_registry_buf, "field_surface_count") != NULL);
        ASSERT(strstr(agent_registry_buf, "review_surface_count") != NULL);
        ASSERT(strstr(agent_registry_buf, "review_registry_source") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_contract_review_surface_total_count") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agentmap.commands.core") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agentmap.commands.drilldown") != NULL);
        ASSERT(strstr(agent_registry_buf, "agentmap.telemetry") != NULL);
        ASSERT(strstr(agent_registry_buf, "\"node_db\", \"dbquery\"")
               != NULL);
        ASSERT(strstr(agent_registry_buf, "\"events\", \"eventlog\"")
               != NULL);
        ASSERT(strstr(agent_registry_buf, "\"compact_status\"") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "\"full_compatibility_status\"") != NULL);
        ASSERT(strstr(agent_registry_buf, "\"full_status\"") != NULL);
        ASSERT(strstr(agent_registry_buf, "\"quality_lanes\"") != NULL);
        ASSERT(strstr(agent_registry_buf, "z23 status") != NULL);
        ASSERT(strstr(agent_registry_buf, "make quality-linger-status")
               != NULL);
        ASSERT(strstr(agent_registry_buf, "agent_contract_probe_params_json")
               != NULL);
        ASSERT(strstr(agent_registry_buf, "sqlite_master") != NULL);
        ASSERT(strstr(agent_registry_buf, "strcmp(method, \"eventlog\")")
               != NULL);
        ASSERT(strstr(agent_registry_buf, "agentops.api_gaps") != NULL);
        ASSERT(strstr(agent_registry_buf, "agentops.top_next_work") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "finish_self_verified_utxo_anchor_rebuild") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "harden_peer_bootstrap_lifecycle") != NULL);
        ASSERT(strstr(agent_registry_buf, "promote_mvp_operator_proofs")
               != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "shrink_boot_refold_supervised_units") != NULL);
        ASSERT(strstr(agent_registry_buf, "dry_agent_contract_registry")
               == NULL);
        ASSERT(strstr(agent_registry_buf, "agent_contract_lookup") != NULL);
        ASSERT(strstr(agent_registry_buf, "agent_print_native_usage") != NULL);
        ASSERT(strstr(agent_registry_buf, "agent_native_usage_tail") != NULL);
        ASSERT(strstr(agent_registry_buf, "native_command[prefix_len]")
               != NULL);
        ASSERT(strstr(agent_registry_buf, "c->native_command") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_push_contract_command_json") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_push_contract_native_field_json") != NULL);
        ASSERT(strstr(agent_registry_buf,
                      "agent_push_contract_native_command_json") != NULL);
        ASSERT(strstr(agent_runtime_buf,
                      "unsupported_method_not_found") != NULL);
        ASSERT(strstr(agent_runtime_buf,
                      "target_runtime_support") != NULL);
        ASSERT(strstr(agent_runtime_buf,
                      "agent_runtime_probe_method_count") != NULL);
        ASSERT(strstr(agent_runtime_buf, "rpc_running") != NULL);
        ASSERT(strstr(agent_runtime_buf, "https_bound_port") != NULL);
        ASSERT(strstr(agent_runtime_buf, "fs_bound_port") != NULL);
        ASSERT(strstr(agent_schema_registry_buf, "zcl.node_resources.v1")
               != NULL);
        ASSERT(strstr(agent_contracts_buf,
                      "Automation must read deployment_safety") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf, "zcl.operator_lane.v1")
               != NULL);
        ASSERT(strstr(agent_lane_runtime_buf,
                      "zcl.operator_deployment_safety.v1") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf,
                      "agent_fill_operator_lane_contract_json") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf,
                      "agent_operator_lane_topology_lookup") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf, "zcl23-dev") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "agent_push_contract_command_json(&commands, "
                      "\"status\", \"agent\"") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "agent_push_contract_command_json(&commands, "
                      "\"lane_topology\"") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "\"agentlanes\"") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "agent_push_contract_command_json(&commands, "
                      "\"deploy_guard\"") != NULL);
        ASSERT(strstr(agent_lanes_buf,
                      "\"agentdeployguard\"") != NULL);
        ASSERT(strstr(agent_lanes_buf, "z23 agent\",") == NULL);
        ASSERT(strstr(agent_lanes_buf, "agent_lanes_push_external_command")
               != NULL);
        ASSERT(strstr(agent_iface_buf, "~/.zclassic-c23-dev") == NULL);
        ASSERT(strstr(agent_iface_buf, "agent_deploy_action_target_lane")
               != NULL);
        ASSERT(strstr(agent_iface_buf,
                      "agent_fill_known_operator_lane_contract_json")
               != NULL);
        ASSERT(strstr(agent_runtime_buf,
                      "agent_push_operator_lane_fields_json") != NULL);
        ASSERT(strstr(agent_summary_buf,
                      "agent_push_operator_lane_fields_json") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf, "restart_policy") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf, "safety_contract") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf, "automation_restart_ok")
               != NULL);
        ASSERT(strstr(agent_lane_runtime_buf, "automation_deploy_ok")
               != NULL);
        ASSERT(strstr(agent_lane_runtime_buf,
                      "requires_operator_confirmation") != NULL);
        ASSERT(strstr(agent_lane_runtime_buf,
                      "safe_default_action") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make ci-reproducible") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "ZCL_FAST_CACHE") != NULL);
        ASSERT(strstr(agent_ctrl_buf, ".cache/zcl-agent-fast-ci") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "agent_impact_rules.def") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "shared_rule_hits") != NULL);
        ASSERT(strstr(agent_ctrl_buf,
                      "agent_push_contract_command_surface_json(&commands")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf, "agentmap.commands.core") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "agentmap.commands.drilldown") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "agentmap.telemetry") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "agent_push_command(") == NULL);
        ASSERT(strstr(agent_ctrl_buf, "command_center") == NULL);
        ASSERT(strstr(agent_ctrl_buf, "full_status") == NULL);
        ASSERT(strstr(agent_ctrl_buf, "telemetry_drilldowns") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "z23 healthcheck") == NULL);
        ASSERT(strstr(agent_ctrl_buf, "z23 dbquery <select>") == NULL);
        ASSERT(strstr(agent_ctrl_buf, "z23 eventlog <count>")
               == NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.sql_result.v1") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 dbquery <SELECT>")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.event_log.v1") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "z23 eventlog <count>") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "background_quality_lanes") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "background_quality_status") != NULL);
        ASSERT(strstr(agent_bg_quality_buf, "native_status_reader") != NULL);
        ASSERT(strstr(agent_bg_quality_buf, "requires_python") != NULL);
        ASSERT(strstr(agent_bg_quality_buf, "ZCL_QUALITY_STATE_DIR") != NULL);
        ASSERT(strstr(agent_bg_quality_buf,
                      "agent_quality_read_json_file") != NULL);
        ASSERT(strstr(agent_bg_quality_buf,
                      "commit_matches_expected") != NULL);
        ASSERT(strstr(agent_bg_quality_buf,
                      "background_quality_stale") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "make quality-linger-status") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "zclassic23-fuzz.timer") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "zclassic23-coverage.timer") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "zclassic23-test-suite.timer") != NULL);
        ASSERT(strstr(agent_ctrl_buf, "native pre-push checks ancestry")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf, "cognition/controllers/src/agent_controller.c")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf,
                      "cognition/controllers/src/agent_background_quality.c")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf,
                      "cognition/controllers/src/agent_lanes_controller.c")
               != NULL);
        ASSERT(strstr(agent_ctrl_buf,
                      "cognition/controllers/src/agent_liveness_controller.c")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"api_command\",") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"app_protocols_command\",") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "zcl.application_protocols.index.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"service_catalog_command\",") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "zcl.service_catalog.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"first_command\",") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"ops_command\",") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"mirror_command\",") != NULL);
        ASSERT(strstr(agent_registry_buf, "api_cli_field") != NULL);
        ASSERT(strstr(api_buf,
                      "agent_push_contract_api_cli_fields_json(cli)")
               != NULL);
        ASSERT(strstr(api_buf,
                      "agent_push_contract_native_field_json(cli,")
               == NULL);
        ASSERT(strstr(api_buf,
                      "json_push_kv_str(cli, \"milestone_command\"")
               == NULL);
        ASSERT(strstr(api_buf,
                      "json_push_kv_str(cli, \"refold_command\"")
               == NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "\"drilldown_command\",") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.healthcheck.v1") != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "zcl.milestone_status.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "zcl.refold_status.v2")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf,
                      "zcl.operator_proof_bundle.v2") != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 milestone")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 refold")
               != NULL);
        ASSERT(strstr(agent_contracts_def_buf, "z23 proofbundle")
               != NULL);
        ASSERT(strstr(api_buf, "\"compat_command\"") == NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentbuild") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 anchorstatus") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.anchor_mint_status.v1") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 proofbundle") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.operator_proof_bundle.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 appprotocols") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "zcl.application_protocols.index.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 servicecatalog") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.service_catalog.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.service_contract.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentlanes") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_lanes.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentliveness") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_liveness.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "agent_contracts.def") != NULL);
        ASSERT(strstr(agent_doc_buf, "g_cli_static_agent_routes") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "agent_push_contract_command_json()` for "
                      "registry-owned commands")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "probe_params_json") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "tools/scripts/lane_health.sh --json")
               != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "Do not add a second\nallowlist") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 getmirrorstatus") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_runtime_services.v1")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "configured boot intent") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_readiness.v1") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.height_contract.v1") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.mirror_status.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.operator_latch.v2") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "zcl.condition_engine_summary.v2") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "suppressed_by_mirror_contract") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "z23 dumpstate condition_engine") != NULL);
        ASSERT(strstr(agent_doc_buf, "chain_serving_ready") != NULL);
        ASSERT(strstr(agent_doc_buf, "index_projection_ready") != NULL);
        ASSERT(strstr(agent_doc_buf, "readiness_status") != NULL);
        ASSERT(strstr(agent_doc_buf, "readiness_next_action") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentinterface") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 status") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "operator-gated real-money first check") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentops") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_ops.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentdiagnose") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_diagnose.v2") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "zcl.agent_runtime_availability.v3") != NULL);
        ASSERT(strstr(agent_doc_buf, "effective_runtime_reachable") != NULL);
        ASSERT(strstr(agent_doc_buf, "effective_runtime_scope") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "`build/bin/zclassic-cli` as\n"
                      "a z23 status oracle") != NULL);
        ASSERT(strstr(agent_doc_buf, "`build/bin/zcl-rpc getblockcount`")
               != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "`build/bin/zclassic-cli -rpcport=18232 getblockcount`")
               != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "false \"z23 is behind\"\n"
                      "diagnosis") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "unsupported_method_not_found") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 statecatalog") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.state_catalog.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 timeline") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.timeline.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "no_jq_required=true") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentdeployguard") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "z23 agentdeployguard deploy-dev")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "process exit status") != NULL);
        ASSERT(strstr(agent_doc_buf, "JSON `exit_code`") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "Scripts therefore do not need\n`jq`") != NULL);
        ASSERT(strstr(agent_doc_buf, "make check-agent-cli") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "hermetic executable regression") != NULL);
        ASSERT(strstr(agent_doc_buf, "target_lane_name=\"dev\"") != NULL);
        ASSERT(strstr(agent_doc_buf, "target_lane_name=\"canonical\"")
               != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "z23 agentdeployguard -operator-lane=dev deploy")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "No Python is required") != NULL);
        ASSERT(strstr(agent_doc_buf, "docs/AGENT_ARCHITECTURE.md") != NULL);
        /* The doc leads with native no-build probes. */
        ASSERT(strstr(agent_doc_buf, "prefer native commands like "
                                     "`z23 status`") != NULL);
        ASSERT(strstr(agent_doc_buf, "make agent-dev-status") != NULL);
        ASSERT(strstr(agent_doc_buf, "make agent-doctor") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 agentdevstatus") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_dev_status.v2") != NULL);
        ASSERT(strstr(agent_doc_buf, "deploy_blocker") != NULL);
        ASSERT(strstr(agent_doc_buf, "auto_reindex_stale_candidate")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "make agent-stage-dev") != NULL);
        /* The doc teaches native command examples. */
        ASSERT(strstr(agent_doc_buf, "build/bin/z23 status")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "build/bin/z23 discover help")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "make agent-loop") != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_AGENT_LOOP_BIN=1") != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_AGENT_LOOP_DEPLOY=stage|dev") != NULL);
        ASSERT(strstr(agent_doc_buf, "make build-only") != NULL);
        ASSERT(strstr(agent_doc_buf, "make fast-rebuild") != NULL);
        ASSERT(strstr(agent_doc_buf, "make dev-bin") != NULL);
        ASSERT(strstr(agent_doc_buf, "build/bin/z23-dev") != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_DEV_HOT_OPT=-O2") != NULL);
        ASSERT(strstr(agent_doc_buf, "make t-fast ONLY=<group>") != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_FAST_CACHE=0") != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_FAST_CACHE_RESET=1") != NULL);
        ASSERT(strstr(agent_doc_buf, "make ci-reproducible") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "zcl.operator_deployment_safety.v1") != NULL);
        ASSERT(strstr(agent_doc_buf, "automation_restart_ok") != NULL);
        ASSERT(strstr(agent_doc_buf, "automation_deploy_ok") != NULL);
        ASSERT(strstr(agent_doc_buf, "operator_lane_name") != NULL);
        ASSERT(strstr(agent_doc_buf, "preferred_deploy_target") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "Runtime generation publication is Phase-0 contained")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.agent_dev_deploy.v1") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "requires_operator_confirmation") != NULL);
        ASSERT(strstr(agent_doc_buf, "safe_default_action") != NULL);
        ASSERT(strstr(agent_doc_buf, "tools/deploy_guard.sh canonical-deploy")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_DEPLOY_ALLOW_CANONICAL=1")
               != NULL);
        ASSERT(strstr(agent_doc_buf, "make deploy-dev") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 dumpstate") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 getnodelog") != NULL);
        ASSERT(strstr(agent_doc_buf, "z23 dbquery") != NULL);
        ASSERT(strstr(agent_doc_buf, "make pre-push-ci") != NULL);
        ASSERT(strstr(agent_doc_buf, "ZCL_FAST_LIVE=0") != NULL);
        ASSERT(strstr(agent_doc_buf, "make install-quality-linger") != NULL);
        ASSERT(strstr(agent_doc_buf, "make quality-linger-status") != NULL);
        ASSERT(strstr(agent_doc_buf, "background_quality_status") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "zcl.background_quality_runtime.v1") != NULL);
        ASSERT(strstr(agent_doc_buf, "zcl.background_quality_lane.v1") != NULL);
        ASSERT(strstr(agent_doc_buf, "source_id_freshness") != NULL);
        ASSERT(strstr(agent_doc_buf, "background_quality_stale") != NULL);
        ASSERT(strstr(agent_doc_buf,
                      "Keep operator logic in typed native `z23` commands")
               != NULL);
        PASS();
    } _test_next:;
    free(main_buf);
    free(event_buf);
    free(agent_summary_buf);
    free(agent_summary_json_buf);
    free(agent_operator_buf);
    free(agent_ctrl_buf);
    free(agent_capability_registry_buf);
    free(agent_registry_buf);
    free(agent_review_registry_buf);
    free(agent_schema_registry_buf);
    free(agent_contracts_buf);
    free(agent_contracts_def_buf);
    free(agent_bg_quality_buf);
    free(agent_first_call_buf);
    free(agent_lanes_buf);
    free(agent_lane_runtime_buf);
    free(agent_liveness_buf);
    free(agent_diagnose_buf);
    free(event_timeline_buf);
    free(agent_anchor_status_buf);
    free(agent_iface_buf);
    free(agent_ops_buf);
    free(agent_runtime_buf);
    free(agent_readiness_buf);
    free(diag_ctrl_buf);
    free(diag_reg_buf);
    free(diag_manifest_buf);
    free(diag_catalog_buf);
    free(api_buf);
    free(api_status_buf);
    free(agent_doc_buf);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_api_unit;

#endif /* ZCL_TESTING */
