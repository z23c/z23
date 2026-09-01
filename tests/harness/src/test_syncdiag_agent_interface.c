/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentinterface and agentdeployguard cases: the probed runtime
 * interface document (resources, restart watchdog) and the deploy
 * guard verdict for each lane and action.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_agent_interface(void)
{
    int failures = 0;

    printf("api: native RPC returns agent interface and deploy guard... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        register_diagnostics_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        bool ok = true;

        struct json_value interface;
        json_init(&interface);
        agent_runtime_availability_begin_probe("test_target_rpc",
                                               "/tmp/zcl-canonical",
                                               18232, "ok");
        agent_runtime_availability_set_target_source_id_sha256(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        agent_runtime_availability_set_target_build_commit("oldbuild");
        agent_runtime_availability_record_method("agent", "supported", 0, "");
        agent_runtime_availability_record_method(
            "agentops", "unsupported_method_not_found",
            RPC_METHOD_NOT_FOUND, "Method not found");
        ok = ok && rpc_table_execute(&tbl, "agentinterface",
                                     &params, &interface);
        const struct json_value *interface_transports =
            json_get(&interface, "transports");
        const struct json_value *must_live_in_c =
            json_get(&interface, "must_live_in_c");
        const struct json_value *avoid = json_get(&interface, "avoid");
        const struct json_value *capabilities =
            json_get(&interface, "capabilities");
        const struct json_value *full_compatibility_status =
            find_object_with_str(capabilities, "name",
                                 "full_compatibility_status");
        const struct json_value *runtime_status =
            find_object_with_str(capabilities, "name", "runtime_status");
        const struct json_value *runtime_status_alias =
            find_object_with_str(capabilities, "name", "runtime_status_alias");
        const struct json_value *mirror_status =
            find_object_with_str(capabilities, "name", "mirror_status");
        const struct json_value *lane_topology =
            find_object_with_str(capabilities, "name", "lane_topology");
        const struct json_value *unified_liveness =
            find_object_with_str(capabilities, "name", "unified_liveness");
        const struct json_value *deploy_cap =
            find_object_with_str(capabilities, "name", "deploy_guard");
        const struct json_value *state_catalog_cap =
            find_object_with_str(capabilities, "name", "state_catalog");
        const struct json_value *timeline_cap =
            find_object_with_str(capabilities, "name", "semantic_timeline");
        const struct json_value *app_protocols_cap =
            find_object_with_str(capabilities, "name",
                                 "application_protocol_catalog");
        const struct json_value *service_catalog_cap =
            find_object_with_str(capabilities, "name",
                                 "sovereign_service_catalog");
        const struct json_value *subsystem_state_cap =
            find_object_with_str(capabilities, "name", "subsystem_state");
        const struct json_value *semantic_state_cap =
            find_object_with_str(capabilities, "name", "semantic_state");
        const struct json_value *node_log_cap =
            find_object_with_str(capabilities, "name", "node_log_search");
        const struct json_value *bounded_logs_cap =
            find_object_with_str(capabilities, "name", "bounded_logs");
        const struct json_value *sql_cap =
            find_object_with_str(capabilities, "name", "sql_inspection");
        const struct json_value *select_sql_cap =
            find_object_with_str(capabilities, "name", "select_sql");
        const struct json_value *machine =
            json_get(&interface, "machine_contract");
        const struct json_value *runtime =
            json_get(&interface, "runtime_identity");
        const struct json_value *development_loop =
            json_get(&interface, "development_loop");
        const struct json_value *visual_instruments =
            json_get(&interface, "native_visual_instruments");
        const struct json_value *visual_loop =
            json_get(&interface, "native_visual_loop");
        const struct json_value *visual_qr =
            find_object_with_str(visual_instruments, "name", "qr");
        const struct json_value *visual_status =
            find_object_with_str(visual_instruments, "name", "node_status");
        const struct json_value *visual_diff =
            find_object_with_str(visual_instruments, "name", "code_change");
        const struct json_value *visual_progress =
            find_object_with_str(visual_instruments, "name",
                                 "reproduction_progress");
        const struct json_value *visual_confirmation =
            find_object_with_str(visual_instruments, "name",
                                 "publication_confirmation");
        const struct json_value *visual_corpus =
            find_object_with_str(visual_instruments, "name",
                                 "corpus_status");
        const struct json_value *visual_publication =
            find_object_with_str(visual_instruments, "name",
                                 "publication_status");
        const struct json_value *visual_bounded =
            find_object_with_str(visual_instruments, "name",
                                 "bounded_display");
        const struct json_value *visual_release_confirmation =
            find_object_with_str(visual_instruments, "name",
                                 "release_confirmation");
        const struct json_value *availability =
            json_get(&interface, "runtime_availability");
        const struct json_value *availability_methods =
            availability ? json_get(availability, "methods") : NULL;
        const struct json_value *agent_method =
            find_object_with_str(availability_methods, "method", "agent");
        const struct json_value *agentops_method =
            find_object_with_str(availability_methods, "method", "agentops");
        ok = ok && interface.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&interface, "schema")),
                          "zcl.agent_interface.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&interface, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(&interface,
                                                "preferred_transport")),
                          "native_cli") == 0;
        ok = ok && strcmp(json_get_str(json_get(&interface,
                                                "capabilities_schema")),
                          "zcl.agent_capability.v2") == 0;
        ok = ok && interface_transports &&
            json_size(interface_transports) == 2;
        ok = ok && json_array_has_substr(must_live_in_c,
                                         "deploy/restart safety decisions");
        ok = ok && json_array_has_substr(avoid,
                                         "do not require Python");
        ok = ok && capabilities && json_size(capabilities) >= 8;
        ok = ok && app_protocols_cap &&
            strcmp(json_get_str(json_get(app_protocols_cap, "schema")),
                   "zcl.application_protocols.index.v2") == 0;
        ok = ok && service_catalog_cap &&
            strcmp(json_get_str(json_get(service_catalog_cap, "schema")),
                   "zcl.service_catalog.v2") == 0;
        ok = ok && lane_topology &&
            strcmp(json_get_str(json_get(lane_topology, "schema")),
                   "zcl.agent_lanes.v2") == 0;
        ok = ok && unified_liveness &&
            strcmp(json_get_str(json_get(unified_liveness, "schema")),
                   "zcl.agent_liveness.v2") == 0;
        ok = ok && full_compatibility_status &&
            strcmp(json_get_str(json_get(full_compatibility_status, "schema")),
                   "zcl.public_status.v3") == 0;
        ok = ok && runtime_status == NULL;
        ok = ok && runtime_status_alias == NULL;
        ok = ok && mirror_status &&
            strcmp(json_get_str(json_get(mirror_status, "schema")),
                   "zcl.mirror_status.v2") == 0;
        ok = ok && mirror_status &&
            strcmp(json_get_str(json_get(mirror_status, "native")),
                   "z23 getmirrorstatus") == 0;
        ok = ok && deploy_cap &&
            strcmp(json_get_str(json_get(deploy_cap, "schema")),
                   "zcl.agent_deploy_guard.v1") == 0;
        ok = ok && state_catalog_cap &&
            strcmp(json_get_str(json_get(state_catalog_cap, "schema")),
                   "zcl.state_catalog.v2") == 0;
        ok = ok && timeline_cap &&
            strcmp(json_get_str(json_get(timeline_cap, "schema")),
                   "zcl.timeline.v2") == 0;
        ok = ok && subsystem_state_cap &&
            strcmp(json_get_str(json_get(subsystem_state_cap, "method")),
                   "dumpstate") == 0;
        ok = ok && subsystem_state_cap &&
            strcmp(json_get_str(json_get(subsystem_state_cap,
                                         "contract_source")),
                   "agent_contracts.def") == 0;
        ok = ok && !json_get_bool(json_get(subsystem_state_cap,
                                           "registry_alias"));
        ok = ok && semantic_state_cap &&
            strcmp(json_get_str(json_get(semantic_state_cap, "method")),
                   "dumpstate") == 0;
        ok = ok && semantic_state_cap &&
            strcmp(json_get_str(json_get(semantic_state_cap, "schema")),
                   json_get_str(json_get(subsystem_state_cap, "schema"))) == 0;
        ok = ok && semantic_state_cap &&
            json_get_bool(json_get(semantic_state_cap, "registry_alias"));
        ok = ok && semantic_state_cap &&
            strcmp(json_get_str(json_get(semantic_state_cap,
                                         "canonical_capability")),
                   "subsystem_state") == 0;
        ok = ok && node_log_cap &&
            strcmp(json_get_str(json_get(node_log_cap, "method")),
                   "getnodelog") == 0;
        ok = ok && bounded_logs_cap &&
            strcmp(json_get_str(json_get(bounded_logs_cap, "method")),
                   "getnodelog") == 0;
        ok = ok && bounded_logs_cap &&
            json_get_bool(json_get(bounded_logs_cap, "registry_alias"));
        ok = ok && sql_cap &&
            strcmp(json_get_str(json_get(sql_cap, "method")),
                   "dbquery") == 0;
        ok = ok && select_sql_cap &&
            strcmp(json_get_str(json_get(select_sql_cap, "method")),
                   "dbquery") == 0;
        ok = ok && select_sql_cap &&
            json_get_bool(json_get(select_sql_cap, "registry_alias"));
        ok = ok && development_loop &&
            strcmp(json_get_str(json_get(development_loop, "status")),
                   "z23 status") == 0;
        ok = ok && development_loop &&
            strcmp(json_get_str(json_get(development_loop,
                                         "full_compatibility_status")),
                   "z23 agent") == 0;
        ok = ok && development_loop &&
            strcmp(json_get_str(json_get(development_loop,
                                         "subsystem_state")),
                   "z23 dumpstate <subsystem> [key]") == 0;
        ok = ok && development_loop &&
            strcmp(json_get_str(json_get(development_loop, "logs")),
                   "z23 getnodelog <pattern>") == 0;
        ok = ok && development_loop &&
            strcmp(json_get_str(json_get(development_loop, "database")),
                   "z23 dbquery <SELECT>") == 0;
        ok = ok && visual_instruments &&
            json_size(visual_instruments) == 9;
        ok = ok && visual_qr &&
            strcmp(json_get_str(json_get(visual_qr, "native")),
                   "z23 app qr show 'zclassic:t1...?amount=0.01'") == 0;
        ok = ok && visual_qr &&
            strcmp(json_get_str(json_get(visual_qr, "path")),
                   "app.qr.show") == 0;
        ok = ok && visual_qr &&
            strcmp(json_get_str(json_get(visual_qr, "input_schema")),
                   "zcl.app_qr_show.input.v1") == 0;
        ok = ok && visual_qr &&
            strstr(json_get_str(json_get(visual_qr, "input_keys")),
                   "output") != NULL;
        ok = ok && visual_status &&
            strcmp(json_get_str(json_get(visual_status, "native")),
                   "z23 app presentation status") == 0;
        ok = ok && visual_diff &&
            strstr(json_get_str(json_get(visual_diff, "native")),
                   "app presentation code-change") != NULL;
        ok = ok && visual_progress &&
            strstr(json_get_str(json_get(visual_progress, "native")),
                   "app presentation reproduction") != NULL;
        ok = ok && visual_confirmation &&
            strstr(json_get_str(json_get(visual_confirmation, "native")),
                   "app presentation publication-confirm") != NULL;
        ok = ok && visual_corpus &&
            strcmp(json_get_str(json_get(visual_corpus, "native")),
                   "z23 app presentation corpus") == 0;
        ok = ok && visual_publication &&
            strstr(json_get_str(json_get(visual_publication, "native")),
                   "app presentation publication-status") != NULL;
        ok = ok && visual_bounded &&
            strstr(json_get_str(json_get(visual_bounded, "native")),
                   "app presentation show") != NULL;
        ok = ok && visual_bounded &&
            strcmp(json_get_str(json_get(visual_bounded, "input_schema")),
                   "zcl.app_presentation_show.input.v1") == 0;
        ok = ok && visual_bounded &&
            strcmp(json_get_str(json_get(visual_bounded, "discover_input")),
                   "z23 discover schema app.presentation.show") == 0;
        ok = ok && visual_release_confirmation &&
            strstr(json_get_str(json_get(visual_release_confirmation,
                                         "native")),
                   "app presentation release-confirm") != NULL;
        ok = ok && visual_loop &&
            strcmp(json_get_str(json_get(visual_loop, "schema")),
                   "zcl.agent_visual_loop.v1") == 0;
        ok = ok && visual_loop &&
            strcmp(json_get_str(json_get(visual_loop, "default_channel")),
                   "ai_conversation") == 0;
        ok = ok && visual_loop &&
            !json_get_bool(json_get(visual_loop, "unsolicited_windows"));
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "query_rule")),
                   "answer ordinary questions directly") != NULL;
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "visual_trigger")),
                   "explicitly asks") != NULL;
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "media_rule")),
                   "QR, image, movie, and NFT media") != NULL;
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "media_rule")),
                   "never improvise a browser") != NULL;
        ok = ok && visual_loop &&
            strcmp(json_get_str(json_get(visual_loop,
                                         "input_discovery")),
                   "z23 discover schema <leaf>") == 0;
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "text_companion")),
                   "output=text") != NULL;
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "selection_rule")),
                   "typed instrument for node-owned facts") != NULL;
        ok = ok && visual_loop &&
            !json_get_bool(json_get(visual_loop, "browser_required"));
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop, "authority_rule")),
                   "visual host owns none") != NULL;
        ok = ok && visual_loop &&
            strstr(json_get_str(json_get(visual_loop,
                                         "generic_model_policy")),
                   "only for inert agent-supplied visuals") != NULL;
        ok = ok && machine &&
            strcmp(json_get_str(json_get(machine, "schema")),
                   "zcl.agent_machine_contract.v2") == 0;
        ok = ok && machine &&
            strcmp(json_get_str(json_get(machine, "payload")),
                   "json_object") == 0;
        ok = ok && json_get_bool(json_get(machine, "schema_required"));
        ok = ok && json_get_bool(json_get(machine,
                                          "transport_equivalent_payloads"));
        ok = ok && json_get_bool(json_get(machine, "no_python_required"));
        ok = ok && json_get_bool(
            json_get(machine, "typed_native_commands_required"));
        ok = ok && runtime &&
            strcmp(json_get_str(json_get(runtime, "schema")),
                   "zcl.agent_runtime_identity.v1") == 0;
        ok = ok && runtime &&
            strcmp(json_get_str(json_get(runtime, "build_commit")),
                   zcl_build_commit()) == 0;
        ok = ok && runtime &&
            strcmp(json_get_str(json_get(runtime, "binary")),
                   "zclassic23") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(availability, "schema")),
                   "zcl.agent_runtime_availability.v3") == 0;
        ok = ok && availability &&
            json_get_int(json_get(availability, "schema_version")) == 3;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(availability,
                                         "availability_scope")),
                   "target_rpc_probe") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(availability, "probe_status")),
                   "ok") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(availability,
                                         "target_source_id_sha256")),
                   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(availability,
                                         "target_build_commit")),
                   "oldbuild") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(
                       availability, "producer_target_source_relation")),
                   "different") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(
                       availability, "producer_target_build_relation")),
                   "unknown") == 0;
        ok = ok && availability &&
            strcmp(json_get_str(json_get(
                       availability,
                       "producer_target_build_relation_authority")),
                   "unavailable_artifact_and_build_epoch_identity") == 0;
        ok = ok && availability &&
            json_get_int(json_get(availability, "unsupported_count")) >= 1;
        ok = ok && availability &&
            strstr(json_get_str(json_get(availability,
                                         "safe_next_action")),
                   "do not call unsupported methods") != NULL;
        ok = ok && agent_method &&
            strcmp(json_get_str(json_get(agent_method,
                                         "target_runtime_support")),
                   "supported") == 0;
        ok = ok && json_get_bool(json_get(agent_method,
                                          "safe_to_call_target"));
        ok = ok && agentops_method &&
            strcmp(json_get_str(json_get(agentops_method,
                                         "target_runtime_support")),
                   "unsupported_method_not_found") == 0;
        ok = ok && agentops_method &&
            !json_get_bool(json_get(agentops_method,
                                    "target_runtime_supports"));
        ok = ok && agentops_method &&
            !json_get_bool(json_get(agentops_method,
                                    "safe_to_call_target"));
        ok = ok && agentops_method &&
            json_get_int(json_get(agentops_method,
                                  "rpc_error_code")) ==
            RPC_METHOD_NOT_FOUND;

        struct json_value probed_ops;
        json_init(&probed_ops);
        ok = ok && rpc_table_execute(&tbl, "agentops", &params,
                                     &probed_ops);
        const struct json_value *probed_ops_availability =
            json_get(&probed_ops, "runtime_availability");
        const struct json_value *probed_ops_methods =
            probed_ops_availability
                ? json_get(probed_ops_availability, "methods") : NULL;
        const struct json_value *probed_ops_method =
            find_object_with_str(probed_ops_methods, "method", "agentops");
        ok = ok && probed_ops_availability &&
            strcmp(json_get_str(json_get(probed_ops_availability,
                                         "availability_scope")),
                   "target_rpc_probe") == 0;
        ok = ok && probed_ops_method &&
            strcmp(json_get_str(json_get(probed_ops_method,
                                         "target_runtime_support")),
                   "unsupported_method_not_found") == 0;
        json_free(&probed_ops);
        agent_runtime_availability_reset();

        struct agent_resource_snapshot fixed_resources = {
            .rss_mb = 5000,
            .rss_warn_threshold_mb = 4096,
            .rss_warning = true,
            .cgroup_memory_available = false,
            .cgroup_memory_current_mb = -1,
            .cgroup_memory_high_mb = -1,
            .cgroup_memory_max_mb = -1,
            .cgroup_memory_high_pct = -1,
            .cgroup_memory_max_pct = -1,
            .cgroup_memory_stat_available = false,
            .cgroup_memory_anon_mb = -1,
            .cgroup_memory_file_mb = -1,
            .cgroup_memory_kernel_mb = -1,
            .cgroup_memory_inactive_file_mb = -1,
            .cgroup_memory_slab_reclaimable_mb = -1,
            .cgroup_memory_reclaimable_mb = -1,
            .cgroup_memory_working_set_mb = -1,
            .cgroup_memory_working_set_high_pct = -1,
            .cgroup_memory_working_set_max_pct = -1,
            .cgroup_memory_reclaimable_dominant = false,
            .cgroup_memory_watch = false,
            .cgroup_memory_warning = false,
            .uptime_seconds = 123,
        };
        struct json_value resources_body;
        json_init(&resources_body);
        json_set_object(&resources_body);
        agent_push_resources_json(&resources_body, "resources",
                                  &fixed_resources);
        const struct json_value *fixed =
            json_get(&resources_body, "resources");
        ok = ok && fixed && fixed->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(fixed, "schema")),
                          "zcl.node_resources.v1") == 0;
        ok = ok && json_get_int(json_get(fixed, "schema_version")) == 1;
        ok = ok && json_get_int(json_get(fixed, "rss_mb")) == 5000;
        ok = ok && json_get_bool(json_get(fixed, "rss_warning"));
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure")),
                          "warn") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure_detail")),
                          "rss_over_threshold") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "pressure_basis")),
                          "rss") == 0;
        json_free(&resources_body);

        struct agent_resource_snapshot cgroup_resources = {
            .rss_mb = 9000,
            .rss_warn_threshold_mb = 4096,
            .rss_warning = true,
            .cgroup_memory_available = true,
            .cgroup_memory_current_mb = 9000,
            .cgroup_memory_high_mb = 12000,
            .cgroup_memory_max_mb = 16000,
            .cgroup_memory_high_pct = 75,
            .cgroup_memory_max_pct = 56,
            .cgroup_memory_stat_available = true,
            .cgroup_memory_anon_mb = 3000,
            .cgroup_memory_file_mb = 5000,
            .cgroup_memory_kernel_mb = 200,
            .cgroup_memory_inactive_file_mb = 4500,
            .cgroup_memory_slab_reclaimable_mb = 200,
            .cgroup_memory_reclaimable_mb = 4700,
            .cgroup_memory_working_set_mb = 4300,
            .cgroup_memory_working_set_high_pct = 35,
            .cgroup_memory_working_set_max_pct = 26,
            .cgroup_memory_reclaimable_dominant = true,
            .cgroup_memory_watch = false,
            .cgroup_memory_warning = false,
            .uptime_seconds = 456,
        };
        json_init(&resources_body);
        json_set_object(&resources_body);
        agent_push_resources_json(&resources_body, "resources",
                                  &cgroup_resources);
        fixed = json_get(&resources_body, "resources");
        ok = ok && fixed && fixed->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(fixed,
                                          "cgroup_memory_available"));
        ok = ok && json_get_int(json_get(fixed,
                                         "cgroup_memory_current_mb")) == 9000;
        ok = ok && json_get_bool(json_get(fixed,
                                          "cgroup_memory_stat_available"));
        ok = ok && json_get_int(json_get(fixed,
                                         "cgroup_memory_working_set_mb")) ==
            4300;
        ok = ok && json_get_bool(json_get(fixed,
            "cgroup_memory_reclaimable_dominant"));
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure")),
                          "ok") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure_detail")),
                          "within_limits") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "pressure_basis")),
                          "cgroup_high") == 0;
        json_free(&resources_body);

        cgroup_resources.cgroup_memory_current_mb = 10320;
        cgroup_resources.cgroup_memory_high_pct = 86;
        cgroup_resources.cgroup_memory_max_pct = 64;
        cgroup_resources.cgroup_memory_working_set_mb = 4300;
        cgroup_resources.cgroup_memory_working_set_high_pct = 35;
        cgroup_resources.cgroup_memory_working_set_max_pct = 26;
        cgroup_resources.cgroup_memory_reclaimable_dominant = true;
        cgroup_resources.cgroup_memory_watch = true;
        cgroup_resources.cgroup_memory_warning = false;
        json_init(&resources_body);
        json_set_object(&resources_body);
        agent_push_resources_json(&resources_body, "resources",
                                  &cgroup_resources);
        fixed = json_get(&resources_body, "resources");
        ok = ok && fixed && fixed->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(fixed,
                                          "cgroup_memory_watch"));
        ok = ok && !json_get_bool(json_get(fixed,
                                           "cgroup_memory_warning"));
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure")),
                          "watch") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure_detail")),
                          "cgroup_cache_watch") == 0;
        json_free(&resources_body);

        cgroup_resources.cgroup_memory_current_mb = 11520;
        cgroup_resources.cgroup_memory_high_pct = 96;
        cgroup_resources.cgroup_memory_max_pct = 72;
        cgroup_resources.cgroup_memory_working_set_mb = 4800;
        cgroup_resources.cgroup_memory_working_set_high_pct = 40;
        cgroup_resources.cgroup_memory_working_set_max_pct = 30;
        cgroup_resources.cgroup_memory_reclaimable_dominant = true;
        cgroup_resources.cgroup_memory_watch = true;
        cgroup_resources.cgroup_memory_warning = false;
        json_init(&resources_body);
        json_set_object(&resources_body);
        agent_push_resources_json(&resources_body, "resources",
                                  &cgroup_resources);
        fixed = json_get(&resources_body, "resources");
        ok = ok && fixed && fixed->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(fixed,
                                          "cgroup_memory_watch"));
        ok = ok && !json_get_bool(json_get(fixed,
                                           "cgroup_memory_warning"));
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure")),
                          "watch") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure_detail")),
                          "cgroup_reclaimable_cache_high") == 0;
        json_free(&resources_body);

        cgroup_resources.cgroup_memory_current_mb = 11400;
        cgroup_resources.cgroup_memory_high_pct = 95;
        cgroup_resources.cgroup_memory_max_pct = 71;
        cgroup_resources.cgroup_memory_working_set_mb = 10320;
        cgroup_resources.cgroup_memory_working_set_high_pct = 86;
        cgroup_resources.cgroup_memory_working_set_max_pct = 64;
        cgroup_resources.cgroup_memory_reclaimable_dominant = false;
        cgroup_resources.cgroup_memory_watch = true;
        cgroup_resources.cgroup_memory_warning = true;
        json_init(&resources_body);
        json_set_object(&resources_body);
        agent_push_resources_json(&resources_body, "resources",
                                  &cgroup_resources);
        fixed = json_get(&resources_body, "resources");
        ok = ok && fixed && fixed->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(fixed,
                                          "cgroup_memory_warning"));
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure")),
                          "warn") == 0;
        ok = ok && strcmp(json_get_str(json_get(fixed,
                                                "memory_pressure_detail")),
                          "cgroup_working_set_high") == 0;
        json_free(&resources_body);

        struct agent_restart_watchdog_snapshot wd = {
            .registered = true,
            .highest_tip = 3171111,
            .last_advance_unix = 1783268402,
            .age_secs = 45,
            .escalation_level = 0,
            .fires_mirror = 2,
            .fires_restart = 0,
            .fires_operator_needed = 0,
            .threshold_restart_secs = 1200,
            .persisted_stuck_height = 3171109,
            .no_progress_restarts = 1,
            .max_restarts = 3,
            .operator_needed = false,
        };
        struct json_value watchdog_body;
        json_init(&watchdog_body);
        json_set_object(&watchdog_body);
        agent_push_restart_watchdog_json(&watchdog_body,
                                         "restart_watchdog", &wd);
        const struct json_value *wd_json =
            json_get(&watchdog_body, "restart_watchdog");
        ok = ok && wd_json && wd_json->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(wd_json, "schema")),
                          "zcl.restart_watchdog.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(wd_json, "status")),
                          "restart_budget_burning") == 0;
        ok = ok && json_get_bool(json_get(wd_json,
                                          "last_restart_autonomous"));
        ok = ok && strcmp(json_get_str(json_get(wd_json,
                                                "last_restart_reason")),
                          "no_progress_tip_stall") == 0;
        ok = ok && json_get_int(json_get(wd_json,
                                         "persisted_stuck_height")) ==
            3171109;
        ok = ok && json_get_int(json_get(wd_json,
                                         "no_progress_restarts")) == 1;
        ok = ok && json_get_int(json_get(wd_json,
                                         "restarts_remaining")) == 2;
        ok = ok && strcmp(json_get_str(json_get(wd_json, "deep_state")),
                          "z23 dumpstate chain_tip_watchdog") == 0;
        json_free(&watchdog_body);

        wd.no_progress_restarts = 3;
        wd.fires_restart = 3;
        wd.operator_needed = false;
        json_init(&watchdog_body);
        json_set_object(&watchdog_body);
        agent_push_restart_watchdog_json(&watchdog_body,
                                         "restart_watchdog", &wd);
        wd_json = json_get(&watchdog_body, "restart_watchdog");
        ok = ok && wd_json && wd_json->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(wd_json, "status")),
                          "restart_budget_exhausted") == 0;
        ok = ok && json_get_bool(json_get(wd_json,
                                          "restart_budget_exhausted"));
        ok = ok && json_get_int(json_get(wd_json,
                                         "restarts_remaining")) == 0;
        json_free(&watchdog_body);

        rpc_agent_set_boot_context("canonical", "full",
                                   "/tmp/zcl-agent-canonical",
                                   18232, 8033, 8443, 18033);
        struct json_value guard;
        json_init(&guard);
        struct json_value guard_params;
        json_init(&guard_params);
        json_set_array(&guard_params);
        struct json_value action;
        json_init(&action);
        json_set_str(&action, "canonical-deploy");
        json_push_back(&guard_params, &action);
        json_free(&action);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &guard_params, &guard);
        ok = ok && guard.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&guard, "schema")),
                          "zcl.agent_deploy_guard.v1") == 0;
        ok = ok && !json_get_bool(json_get(&guard, "allowed"));
        ok = ok && strcmp(json_get_str(json_get(&guard, "decision")),
                          "refuse") == 0;
        ok = ok && strcmp(json_get_str(json_get(&guard, "reason")),
                          "operator_confirmation_required") == 0;
        ok = ok && json_get_int(json_get(&guard, "exit_code")) == 1;
        ok = ok && strcmp(json_get_str(json_get(&guard,
                                                "operator_lane_name")),
                          "canonical") == 0;
        ok = ok && !json_get_bool(json_get(&guard,
                                           "automation_restart_ok"));
        ok = ok && !json_get_bool(json_get(&guard,
                                           "automation_deploy_ok"));
        ok = ok && json_get_bool(json_get(&guard,
                                          "requires_operator_confirmation"));
        ok = ok && strcmp(json_get_str(json_get(&guard,
                                                "preferred_deploy_target")),
                          "dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(&guard,
                                                "safe_default_action")),
                          "observe_only_or_use_dev_lane") == 0;
        ok = ok && strcmp(json_get_str(json_get(&guard, "action_scope")),
                          "explicit_target_lane") == 0;
        ok = ok && strcmp(json_get_str(json_get(&guard,
                                                "current_lane_name")),
                          "canonical") == 0;
        ok = ok && strcmp(json_get_str(json_get(&guard,
                                                "target_lane_name")),
                          "canonical") == 0;
        const struct json_value *canonical_target =
            json_get(&guard, "target_lane");
        ok = ok && canonical_target &&
            canonical_target->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(canonical_target, "lane")),
                          "canonical") == 0;
        ok = ok && json_get_int(json_get(canonical_target,
                                         "https_port")) == 8443;

        const char *old_home_env = getenv("HOME");
        char old_home_buf[4096];
        bool old_home_set = old_home_env != NULL;
        if (old_home_set)
            snprintf(old_home_buf, sizeof(old_home_buf), "%s",
                     old_home_env);
        ok = ok && setenv("HOME", "/tmp/zcl-agent-home", 1) == 0;
        rpc_agent_set_boot_context("unknown", "full",
                                   "/tmp/zcl-agent-home/.zclassic-c23",
                                   18232, 8033, 8443, 18034);
        struct json_value inferred_guard_params;
        json_init(&inferred_guard_params);
        json_set_array(&inferred_guard_params);
        json_init(&action);
        json_set_str(&action, "deploy");
        json_push_back(&inferred_guard_params, &action);
        json_free(&action);
        struct json_value inferred_guard;
        json_init(&inferred_guard);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &inferred_guard_params,
                                     &inferred_guard);
        const struct json_value *inferred_lane =
            json_get(&inferred_guard, "operator_lane");
        ok = ok && inferred_lane && inferred_lane->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(inferred_lane, "lane")),
                          "canonical") == 0;
        ok = ok && strcmp(json_get_str(json_get(inferred_lane,
                                                "lane_source")),
                          "inferred_exact_topology") == 0;
        ok = ok && !json_get_bool(json_get(inferred_lane,
                                           "lane_declared"));
        ok = ok && json_get_bool(json_get(inferred_lane,
                                          "lane_inferred"));
        ok = ok && strcmp(json_get_str(json_get(&inferred_guard,
                                                "current_lane_name")),
                          "canonical") == 0;
        ok = ok && strcmp(json_get_str(json_get(&inferred_guard,
                                                "operator_lane_name")),
                          "canonical") == 0;
        ok = ok && strcmp(json_get_str(json_get(&inferred_guard,
                                                "guard_env")),
                          "ZCL_DEPLOY_ALLOW_CANONICAL") == 0;
        ok = ok && !json_get_bool(json_get(&inferred_guard, "allowed"));
        ok = ok && strcmp(json_get_str(json_get(&inferred_guard,
                                                "reason")),
                          "operator_confirmation_required") == 0;
        json_free(&inferred_guard_params);
        json_free(&inferred_guard);
        if (old_home_set)
            setenv("HOME", old_home_buf, 1);
        else
            unsetenv("HOME");

        struct json_value guard_object_params;
        json_init(&guard_object_params);
        json_set_object(&guard_object_params);
        json_push_kv_str(&guard_object_params, "action",
                         "canonical-restart");
        struct json_value guard_object;
        json_init(&guard_object);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &guard_object_params, &guard_object);
        ok = ok && strcmp(json_get_str(json_get(&guard_object, "action")),
                          "canonical-restart") == 0;
        ok = ok && !json_get_bool(json_get(&guard_object, "allowed"));

        const char *guard_old_home_env = getenv("HOME");
        char guard_old_home_buf[4096];
        bool guard_old_home_set = guard_old_home_env != NULL;
        if (guard_old_home_set)
            snprintf(guard_old_home_buf, sizeof(guard_old_home_buf), "%s",
                     guard_old_home_env);
        char guard_home[512];
        test_make_tmpdir(guard_home, sizeof(guard_home), "syncdiag",
                         "deploy_guard_home");
        char guard_devdir[768];
        int guard_devdir_len = snprintf(guard_devdir, sizeof(guard_devdir),
                                        "%s/.zclassic-c23-dev",
                                        guard_home);
        ok = ok && guard_devdir_len > 0 &&
            (size_t)guard_devdir_len < sizeof(guard_devdir);
        ok = ok && mkdir(guard_devdir, 0755) == 0;
        ok = ok && setenv("HOME", guard_home, 1) == 0;

        struct json_value dev_guard_params;
        json_init(&dev_guard_params);
        json_set_array(&dev_guard_params);
        json_init(&action);
        json_set_str(&action, "deploy-dev");
        json_push_back(&dev_guard_params, &action);
        json_free(&action);
        struct json_value dev_guard;
        json_init(&dev_guard);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &dev_guard_params, &dev_guard);
        ok = ok && strcmp(json_get_str(json_get(&dev_guard, "action")),
                          "deploy-dev") == 0;
        ok = ok && json_get_bool(json_get(&dev_guard, "allowed"));
        ok = ok && strcmp(json_get_str(json_get(&dev_guard, "decision")),
                          "allow") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard, "reason")),
                          "deployment_safety_allows_action") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard, "action_scope")),
                          "explicit_target_lane") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard,
                                                "current_lane_name")),
                          "canonical") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard,
                                                "operator_lane_name")),
                          "dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard, "lane")),
                          "dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard,
                                                "target_lane_name")),
                          "dev") == 0;
        const struct json_value *dev_target =
            json_get(&dev_guard, "target_lane");
        ok = ok && dev_target && dev_target->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(dev_target, "development"));
        ok = ok && json_get_bool(json_get(dev_target,
                                          "automation_deploy_ok"));
        ok = ok && !json_get_bool(json_get(dev_target,
                                           "requires_operator_confirmation"));
        ok = ok && !json_get_bool(json_get(&dev_guard,
                                           "recovery_deploy_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&dev_guard,
                                                "recovery_status")),
                          "clean") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard,
                                                "explicit_recovery_env")),
                          "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY") == 0;
        const struct json_value *dev_recovery =
            json_get(dev_target, "recovery_state");
        ok = ok && dev_recovery && dev_recovery->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(dev_recovery, "schema")),
                          "zcl.operator_lane_recovery.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev_recovery, "status")),
                          "clean") == 0;
        ok = ok && !json_get_bool(json_get(dev_recovery,
                                           "deploy_blocker"));
        ok = ok && strcmp(json_get_str(json_get(dev_recovery,
                                                "explicit_recovery_env")),
                          "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_guard,
                                                "safe_default_action")),
                          "deploy_dev_lane") == 0;

        ok = ok && boot_auto_reindex_request(guard_devdir, 3172354) == 1;
        struct json_value pending_guard;
        json_init(&pending_guard);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &dev_guard_params, &pending_guard);
        ok = ok && strcmp(json_get_str(json_get(&pending_guard, "action")),
                          "deploy-dev") == 0;
        ok = ok && !json_get_bool(json_get(&pending_guard, "allowed"));
        ok = ok && strcmp(json_get_str(json_get(&pending_guard,
                                                "decision")),
                          "refuse") == 0;
        ok = ok && strcmp(json_get_str(json_get(&pending_guard,
                                                "reason")),
                          "pending_auto_reindex_requires_explicit_recovery_boot")
            == 0;
        ok = ok && json_get_bool(json_get(&pending_guard,
                                          "recovery_deploy_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&pending_guard,
                                                "recovery_status")),
                          "pending_auto_reindex") == 0;
        ok = ok && strcmp(json_get_str(json_get(&pending_guard,
                                                "explicit_recovery_env")),
                          "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY") == 0;
        ok = ok && json_get_int(json_get(&pending_guard, "exit_code")) == 1;
        const struct json_value *pending_target =
            json_get(&pending_guard, "target_lane");
        const struct json_value *pending_recovery =
            pending_target ? json_get(pending_target, "recovery_state") : NULL;
        ok = ok && pending_recovery && pending_recovery->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(pending_recovery, "status")),
                          "pending_auto_reindex") == 0;
        ok = ok && json_get_bool(json_get(pending_recovery,
                                          "auto_reindex_marker_present"));
        ok = ok && json_get_bool(json_get(pending_recovery,
                                          "auto_reindex_status_well_formed"));
        ok = ok && json_get_bool(json_get(pending_recovery,
                                          "auto_reindex_pending"));
        ok = ok && !json_get_bool(json_get(pending_recovery,
                                           "auto_reindex_terminal"));
        ok = ok && json_get_bool(json_get(pending_recovery,
                                          "deploy_blocker"));
        ok = ok && json_get_int(json_get(pending_recovery,
                                         "auto_reindex_anchor")) == 3172354;
        ok = ok && json_get_int(json_get(pending_recovery,
                                         "auto_reindex_count")) == 1;
        ok = ok && strcmp(json_get_str(json_get(pending_recovery,
                                                "deploy_blocker_reason")),
                          "pending_auto_reindex_requires_explicit_recovery_boot")
            == 0;

        ok = ok && boot_auto_reindex_mark_terminal(guard_devdir, 3172354);
        struct json_value terminal_guard;
        json_init(&terminal_guard);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &dev_guard_params, &terminal_guard);
        ok = ok && json_get_bool(json_get(&terminal_guard, "allowed"));
        ok = ok && strcmp(json_get_str(json_get(&terminal_guard,
                                                "decision")),
                          "allow") == 0;
        ok = ok && !json_get_bool(json_get(&terminal_guard,
                                           "recovery_deploy_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&terminal_guard,
                                                "recovery_status")),
                          "terminal_auto_reindex") == 0;
        const struct json_value *terminal_target =
            json_get(&terminal_guard, "target_lane");
        const struct json_value *terminal_recovery =
            terminal_target ? json_get(terminal_target,
                                       "recovery_state") : NULL;
        ok = ok && terminal_recovery && terminal_recovery->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(terminal_recovery, "status")),
                          "terminal_auto_reindex") == 0;
        ok = ok && !json_get_bool(json_get(terminal_recovery,
                                           "auto_reindex_pending"));
        ok = ok && json_get_bool(json_get(terminal_recovery,
                                          "auto_reindex_terminal"));
        ok = ok && !json_get_bool(json_get(terminal_recovery,
                                           "deploy_blocker"));
        ok = ok && json_get_int(json_get(terminal_recovery,
                                         "auto_reindex_count")) ==
            BOOT_AUTO_REINDEX_TERMINAL;

        if (guard_old_home_set)
            setenv("HOME", guard_old_home_buf, 1);
        else
            unsetenv("HOME");
        test_cleanup_tmpdir(guard_home);

        rpc_agent_set_boot_context("dev", "full",
                                   "/tmp/zcl-agent-dev",
                                   18252, 8053, 0, 18034);
        struct json_value canonical_from_dev_params;
        json_init(&canonical_from_dev_params);
        json_set_array(&canonical_from_dev_params);
        json_init(&action);
        json_set_str(&action, "canonical-deploy");
        json_push_back(&canonical_from_dev_params, &action);
        json_free(&action);
        struct json_value canonical_from_dev;
        json_init(&canonical_from_dev);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &canonical_from_dev_params,
                                     &canonical_from_dev);
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "action")),
                          "canonical-deploy") == 0;
        ok = ok && !json_get_bool(json_get(&canonical_from_dev,
                                           "allowed"));
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "decision")),
                          "refuse") == 0;
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "reason")),
                          "operator_confirmation_required") == 0;
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "action_scope")),
                          "explicit_target_lane") == 0;
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "current_lane_name")),
                          "dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "target_lane_name")),
                          "canonical") == 0;
        ok = ok && strcmp(json_get_str(json_get(&canonical_from_dev,
                                                "operator_lane_name")),
                          "canonical") == 0;
        ok = ok && !json_get_bool(json_get(&canonical_from_dev,
                                           "automation_deploy_ok"));
        ok = ok && json_get_bool(json_get(&canonical_from_dev,
                                          "requires_operator_confirmation"));


        json_free(&params);
        json_free(&interface);
        json_free(&guard_params);
        json_free(&guard);
        json_free(&guard_object_params);
        json_free(&guard_object);
        json_free(&dev_guard_params);
        json_free(&dev_guard);
        json_free(&pending_guard);
        json_free(&terminal_guard);
        json_free(&canonical_from_dev_params);
        json_free(&canonical_from_dev);
        rpc_agent_set_boot_context(NULL, NULL, NULL, 0, 0, 0, 0);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    return failures;
}
