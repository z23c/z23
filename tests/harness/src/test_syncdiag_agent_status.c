/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent status cases: the health blocking reason, answering from the operator snapshot while node.db is busy, the status alias, and operator-snapshot coherence and edge-state classification.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_agent_status(void)
{
    int failures = 0;

    printf("api: native RPC agent names health blocking reason... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        blocker_module_shutdown();
        bool blocker_ready = blocker_module_init();
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        event_log_init();
        alerts_init();
        alerts_reset();
        const char *long_blocker =
            "check=window.consistency I4.3 utxo_apply log hole: contiguous "
            "ok=1 prefix h=3056758 but cursor=3171120 first_hole_h=3056759 "
            "repair_owner=reducer_frontier_reconcile_light";
        event_emitf(EV_OPERATOR_NEEDED, 0, "%s", long_blocker);
        char expected_source_id[65] = {0};
        const char *running_source_id = zcl_build_source_id_sha256();
        bool expected_source_fixture_ok =
            running_source_id && strlen(running_source_id) == 64;
        if (expected_source_fixture_ok) {
            snprintf(expected_source_id, sizeof(expected_source_id), "%s",
                     running_source_id);
            expected_source_id[0] =
                expected_source_id[0] == '0' ? '1' : '0';
        }
        setenv("ZCL_AGENT_EXPECT_BUILD_COMMIT", "expected-agent-test", 1);
        setenv("ZCL_AGENT_EXPECT_SOURCE_ID", expected_source_id, 1);
        setenv("ZCL_AGENT_EXPECT_BUILD_SOURCE", "unit-test", 1);
        rpc_agent_set_boot_context("dev", "full", "/tmp/zcl-agent-dev",
                                   18252, 8053, 8443, 18034);

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "agent", &params, &result);
        bool ok = blocker_ready && expected_source_fixture_ok && executed &&
            result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.public_status.v3") == 0;
        const struct json_value *first_call =
            json_get(&result, "first_call");
        ok = ok && first_call && first_call->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(first_call, "schema")),
                          "zcl.first_call_contract.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call, "api")),
                          "agent") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call, "source")),
                          "cached_fast_fields") == 0;
        ok = ok && !json_get_bool(json_get(first_call, "partial_result"));
        ok = ok && json_get_int(json_get(first_call, "budget_ms")) == 250;
        ok = ok && json_get(first_call, "elapsed_ms") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "source_id_sha256")),
                          zcl_build_source_id_sha256()) == 0;
        const struct json_value *runtime_build =
            json_get(&result, "runtime_build");
        ok = ok && runtime_build && runtime_build->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(runtime_build, "schema")),
                          "zcl.runtime_build.v2") == 0;
        ok = ok && json_get_int(json_get(runtime_build,
                                         "schema_version")) == 2;
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "running_build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "expected_build_commit")),
                          "expected-agent-test") == 0;
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "freshness_authority")),
                          "source_id_sha256") == 0;
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "running_source_id_sha256")),
                          zcl_build_source_id_sha256()) == 0;
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "expected_source_id_sha256")),
                          expected_source_id) == 0;
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "expected_source")),
                          "unit-test") == 0;
        ok = ok && json_get_bool(json_get(runtime_build,
                                          "expected_present"));
        ok = ok && !json_get_bool(json_get(runtime_build,
                                           "matches_expected"));
        ok = ok && json_get_bool(json_get(runtime_build, "stale"));
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "freshness")),
                          "stale") == 0;
        ok = ok && !json_get_bool(json_get(runtime_build,
                                            "dirty_build_known"));
        ok = ok && strcmp(json_get_str(json_get(runtime_build,
                                                "dirty_build_state")),
                          "unknown") == 0;
        ok = ok && json_get(runtime_build, "semantics") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "blocked") == 0;
        ok = ok && !json_get_bool(json_get(&result, "serving"));
        ok = ok && !json_get_bool(json_get(&result, "healthy"));
        ok = ok && !json_get_bool(json_get(&result, "serving"));
        ok = ok && json_get_bool(json_get(&result, "operator_needed"));
        const char *primary =
            json_get_str(json_get(&result, "primary_blocker"));
        ok = ok && primary &&
             strstr(primary, "operator_needed:check=window.consistency") != NULL;
        ok = ok && primary &&
             strstr(primary, "first_hole_h=3056759") != NULL;
        ok = ok && primary &&
             strstr(primary, "reducer_frontier_reconcile_light") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "summary")),
                          "node has an active health blocker") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "next")),
                          "z23 healthcheck") == 0;
        const struct json_value *readiness = json_get(&result, "readiness");
        ok = ok && readiness && readiness->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(readiness, "schema")),
                          "zcl.agent_readiness.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(readiness, "status")),
                          "not_serving") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "readiness_status")),
                          "not_serving") == 0;
        ok = ok && !json_get_bool(json_get(readiness,
                                           "chain_serving_ready"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "chain_serving_ready"));
        ok = ok && !json_get_bool(json_get(readiness,
                                           "index_projection_ready"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "index_projection_ready"));
        ok = ok && !json_get_bool(json_get(readiness,
                                           "agent_work_ready"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "agent_work_ready"));
        ok = ok && json_get_bool(json_get(readiness,
                                          "operator_action_required"));
        ok = ok && json_get_bool(json_get(&result,
                                          "operator_action_required"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "readiness_next_action")),
                          "operator_intervention_required") == 0;
        const struct json_value *operator_latch =
            json_get(&result, "operator_latch");
        ok = ok && operator_latch && operator_latch->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(operator_latch, "schema")),
                          "zcl.operator_latch.v2") == 0;
        ok = ok && json_get_int(json_get(operator_latch,
                                         "schema_version")) == 2;
        ok = ok && json_get_bool(json_get(operator_latch, "active"));
        ok = ok && json_get_bool(json_get(operator_latch,
                                          "operator_action_required"));
        ok = ok && !json_get_bool(json_get(operator_latch,
                                           "recovered_this_call"));
        ok = ok && !json_get_bool(json_get(operator_latch,
                                           "suppressed_by_mirror_contract"));
        ok = ok && json_get(operator_latch, "since_unix") != NULL;
        ok = ok && strstr(json_get_str(json_get(operator_latch, "detail")),
                          "window.consistency") != NULL;
        ok = ok && strcmp(json_get_str(json_get(operator_latch,
                                                "native_state_command")),
                          "z23 dumpstate condition_engine") == 0;
        const struct json_value *condition_summary =
            json_get(&result, "conditions");
        ok = ok && condition_summary && condition_summary->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(condition_summary,
                                                "schema")),
                          "zcl.condition_engine_summary.v2") == 0;
        ok = ok && json_get(condition_summary, "active_count") != NULL;
        ok = ok && json_get(condition_summary, "unresolved_count") != NULL;
        ok = ok && strcmp(json_get_str(json_get(condition_summary,
                                                "native_state_command")),
                          "z23 dumpstate condition_engine") == 0;
        const struct json_value *mirror_contract =
            json_get(&result, "mirror_contract");
        ok = ok && mirror_contract && mirror_contract->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(mirror_contract,
                                                "schema")),
                          "zcl.mirror_status.v2") == 0;
        ok = ok && json_get_bool(json_get(mirror_contract,
                                          "advisory_only"));
        ok = ok && json_get(mirror_contract,
                            "operator_action_required") != NULL;
        const struct json_value *reducer = json_get(&result, "reducer");
        ok = ok && reducer && reducer->type == JSON_OBJ;
        ok = ok && json_get(reducer, "log_head") != NULL;
        ok = ok && json_get(reducer, "log_head_gap") != NULL;
        ok = ok && json_get(reducer, "tip_advance_age_seconds") != NULL;
        ok = ok && json_get(reducer, "validation_pack_ok") != NULL;
        ok = ok && json_get(reducer, "validation_pack_detail") != NULL;
        const struct json_value *health = json_get(&result, "health");
        ok = ok && health && health->type == JSON_OBJ;
        ok = ok && json_get(health, "warning_count") != NULL;
        ok = ok && json_get(health, "warning_reasons") != NULL;
        ok = ok && json_get(health, "last_error_age_seconds") != NULL;
        ok = ok && json_get(health, "last_error_type") != NULL;
        ok = ok && json_get(health, "blocking_reason") != NULL;
        ok = ok && json_get_bool(json_get(health,
                                          "operator_latch_active"));
        ok = ok && json_get_bool(json_get(health,
                                          "operator_action_required"));
        ok = ok && json_get(health,
                            "operator_latch_detail") != NULL;
        ok = ok && json_get(health,
                            "operator_latch_since_unix") != NULL;
        ok = ok && json_get(health,
                            "active_condition_count") != NULL;
        ok = ok && json_get(health,
                            "unresolved_condition_count") != NULL;
        const struct json_value *resources = json_get(&result, "resources");
        ok = ok && resources && resources->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(resources, "schema")),
                          "zcl.node_resources.v1") == 0;
        ok = ok && json_get(resources, "rss_mb") != NULL;
        ok = ok && json_get(resources, "rss_warn_threshold_mb") != NULL;
        ok = ok && json_get(resources, "rss_warning") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_available") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_current_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_high_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_max_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_stat_available") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_anon_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_file_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_kernel_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_reclaimable_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_working_set_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_watch") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_warning") != NULL;
        ok = ok && json_get(resources, "memory_pressure") != NULL;
        ok = ok && json_get(resources, "memory_pressure_detail") != NULL;
        ok = ok && json_get(resources, "pressure_basis") != NULL;
        ok = ok && json_get(resources, "uptime_seconds") != NULL;
        const struct json_value *restart_watchdog =
            json_get(&result, "restart_watchdog");
        ok = ok && restart_watchdog && restart_watchdog->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(restart_watchdog, "schema")),
                          "zcl.restart_watchdog.v1") == 0;
        ok = ok && json_get(restart_watchdog, "status") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "last_restart_autonomous") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "last_restart_reason") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "no_progress_restarts") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "restarts_remaining") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "deep_state") != NULL;
        const struct json_value *security =
            json_get(&result, "security_posture");
        ok = ok && security && security->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(security, "schema")),
                          "zcl.security_posture.v1") == 0;
        ok = ok && json_get(security, "bootstrap_model") != NULL;
        ok = ok && json_get(security,
                            "full_history_validation_state") != NULL;
        ok = ok && json_get(security,
                            "anchor_history_state") != NULL;
        ok = ok && json_get(security,
                            "nullifier_history_state") != NULL;
        ok = ok && readiness && readiness->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(readiness, "schema")),
                          "zcl.agent_readiness.v1") == 0;
        ok = ok && json_get(readiness, "status") != NULL;
        ok = ok && json_get(&result, "readiness_status") != NULL;
        ok = ok && json_get(readiness, "chain_serving_ready") != NULL;
        ok = ok && json_get(&result, "chain_serving_ready") != NULL;
        ok = ok && json_get(readiness, "index_projection_ready") != NULL;
        ok = ok && json_get(&result, "index_projection_ready") != NULL;
        ok = ok && json_get(readiness, "agent_work_ready") != NULL;
        ok = ok && json_get(&result, "agent_work_ready") != NULL;
        ok = ok && json_get(readiness, "operator_action_required") != NULL;
        ok = ok && json_get(&result, "operator_action_required") != NULL;
        ok = ok && json_get(readiness, "next_action") != NULL;
        ok = ok && json_get(&result, "readiness_next_action") != NULL;
        ok = ok && json_get(readiness, "semantics") != NULL;
        const struct json_value *download = json_get(&result, "download");
        ok = ok && download && download->type == JSON_OBJ;
        ok = ok && json_get(download, "requested") != NULL;
        ok = ok && json_get(download, "received") != NULL;
        ok = ok && json_get(download, "timed_out") != NULL;
        ok = ok && json_get(download, "in_flight") != NULL;
        ok = ok && json_get(download, "queued") != NULL;
        ok = ok && json_get(download, "queue_peer_avoid_count") != NULL;
        ok = ok && json_get(download,
                            "queue_peer_avoid_max_seconds") != NULL;
        ok = ok && json_get(download, "bytes_received") != NULL;
        ok = ok && json_get(download, "mbps_avg") != NULL;
        const struct json_value *indexer = json_get(&result, "indexer");
        ok = ok && indexer && indexer->type == JSON_OBJ;
        ok = ok && json_get(indexer, "height") != NULL;
        ok = ok && json_get(indexer, "lag") != NULL;
        ok = ok && json_get(indexer, "projection_height") != NULL;
        ok = ok && json_get(indexer, "projection_lag") != NULL;
        ok = ok && json_get(indexer, "projection_deferred") != NULL;
        ok = ok && json_get(indexer, "projection_state") != NULL;
        ok = ok && json_get(indexer, "catchup_active") != NULL;
        ok = ok && json_get(indexer, "catchup_height") != NULL;
        ok = ok && json_get(indexer, "catchup_target_height") != NULL;
        ok = ok && json_get(indexer,
                            "catchup_progress_age_seconds") != NULL;
        ok = ok && json_get(indexer, "catchup_uptime_seconds") != NULL;
        const struct json_value *lane =
            json_get(&result, "operator_lane");
        ok = ok && lane && lane->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(lane, "schema")),
                          "zcl.operator_lane.v1") == 0;
        ok = ok && json_get_int(json_get(lane, "schema_version")) == 1;
        ok = ok && strcmp(json_get_str(json_get(lane, "lane")),
                          "dev") == 0;
        ok = ok && json_get_bool(json_get(lane, "development"));
        ok = ok && !json_get_bool(json_get(lane, "canonical"));
        ok = ok && strcmp(json_get_str(json_get(lane,
                                                "restart_policy")),
                          "frequent_deploy_ok") == 0;
        ok = ok && json_get_bool(json_get(lane,
                                          "automation_restart_ok"));
        ok = ok && json_get_bool(json_get(lane,
                                          "automation_deploy_ok"));
        ok = ok && !json_get_bool(json_get(lane,
                                           "requires_operator_confirmation"));
        const struct json_value *safety =
            json_get(lane, "deployment_safety");
        ok = ok && safety && safety->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(safety, "schema")),
                          "zcl.operator_deployment_safety.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(safety,
                                                "preferred_deploy_target")),
                          "dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(safety,
                                                "safe_default_action")),
                          "deploy_dev_lane") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "operator_lane_name")),
                          "dev") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "automation_restart_ok"));
        ok = ok && json_get_bool(json_get(&result,
                                          "automation_deploy_ok"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "requires_operator_confirmation"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "preferred_deploy_target")),
                          "dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_default_action")),
                          "deploy_dev_lane") == 0;

        json_free(&params);
        json_free(&result);
        unsetenv("ZCL_AGENT_EXPECT_BUILD_COMMIT");
        unsetenv("ZCL_AGENT_EXPECT_SOURCE_ID");
        unsetenv("ZCL_AGENT_EXPECT_BUILD_SOURCE");
        rpc_agent_set_boot_context(NULL, NULL, NULL, 0, 0, 0, 0);
        alerts_shutdown();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: agent status answers from snapshot while node.db is busy... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        node_db_long_op_test_clear();

        /* 1. A live call while the connection is idle publishes the in-memory
         *    posture snapshot and is labelled source=live. */
        struct json_value p0, live;
        json_init(&p0);
        json_set_array(&p0);
        json_init(&live);
        bool exec_live = rpc_table_execute(&tbl, "agent", &p0, &live);
        bool ok = exec_live && live.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&live, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&live, "source")),
                          "live") == 0;
        ok = ok && json_get(&live, "db_maintenance") == NULL;
        json_free(&p0);
        json_free(&live);

        /* 2. Hold the shared node.db connection busy with a long maintenance op
         *    (the ~11-minute quick_check that once made status go dark). */
        node_db_long_op_test_set("quick_check", 647514);
        const char *busy_op = NULL;
        int64_t busy_elapsed = 0;
        ok = ok && node_db_long_op_active(&busy_op, &busy_elapsed);
        ok = ok && busy_op && strcmp(busy_op, "quick_check") == 0;
        ok = ok && busy_elapsed >= 647514;

        /* 3. The status call must still answer promptly, from the snapshot,
         *    naming the maintenance op — never hang on the busy connection. */
        struct json_value p1, busy;
        json_init(&p1);
        json_set_array(&p1);
        json_init(&busy);
        int64_t t0 = platform_time_monotonic_ms();
        bool exec_busy = rpc_table_execute(&tbl, "agent", &p1, &busy);
        int64_t answer_ms = platform_time_monotonic_ms() - t0;
        ok = ok && exec_busy && busy.type == JSON_OBJ;
        ok = ok && answer_ms < 2000;   /* bounded: proves it did not block */
        ok = ok && strcmp(json_get_str(json_get(&busy, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&busy, "source")),
                          "snapshot") == 0;
        ok = ok && json_get(&busy, "age_ms") != NULL &&
             json_get_int(json_get(&busy, "age_ms")) >= 0;
        const struct json_value *maint = json_get(&busy, "db_maintenance");
        ok = ok && maint && maint->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(maint, "op")),
                          "quick_check") == 0;
        ok = ok && json_get_int(json_get(maint, "elapsed_ms")) >= 647514;
        json_free(&p1);
        json_free(&busy);

        /* 4. Once maintenance clears, status returns to live source. */
        node_db_long_op_test_clear();
        ok = ok && !node_db_long_op_active(NULL, NULL);
        struct json_value p2, after;
        json_init(&p2);
        json_set_array(&p2);
        json_init(&after);
        bool exec_after = rpc_table_execute(&tbl, "agent", &p2, &after);
        ok = ok && exec_after && after.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&after, "source")),
                          "live") == 0;
        ok = ok && json_get(&after, "db_maintenance") == NULL;
        json_free(&p2);
        json_free(&after);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: mirror cached snapshot avoids live height refresh... ");
    {
        legacy_mirror_sync_reset_for_test();
        struct legacy_mirror_sync_stats seeded = {0};
        seeded.enabled = true;
        seeded.running = true;
        seeded.reachable = true;
        seeded.legacy_height = 100;
        seeded.legacy_headers = 100;
        seeded.local_height = 99;
        seeded.best_header_height = 100;
        seeded.target_height = 100;
        snprintf(seeded.zclassic23_hash, sizeof(seeded.zclassic23_hash),
                 "%s", "cached-local-hash");
        snprintf(seeded.zclassicd_hash, sizeof(seeded.zclassicd_hash),
                 "%s", "cached-legacy-hash");
        legacy_mirror_sync_test_set_stats(&seeded, NULL);

        struct legacy_mirror_sync_stats snap = {0};
        legacy_mirror_sync_stats_cached_snapshot(&snap);

        bool ok = snap.enabled && snap.running && snap.reachable;
        ok = ok && snap.local_height == 99;
        ok = ok && snap.best_header_height == 100;
        ok = ok && snap.lag_known;
        ok = ok && snap.lag == 1;
        ok = ok && strcmp(snap.zclassic23_hash,
                          "cached-local-hash") == 0;
        ok = ok && strcmp(snap.zclassicd_hash,
                          "cached-legacy-hash") == 0;

        legacy_mirror_sync_reset_for_test();
        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC status aliases bounded agent status... ");
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

        bool ok = rpc_table_execute(&tbl, "status", &params, &result);
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "api_version")),
                          "v1") == 0;
        const struct json_value *first_call = json_get(&result, "first_call");
        ok = ok && first_call && first_call->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(first_call, "schema")),
                          "zcl.first_call_contract.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call, "api")),
                          "agent") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call,
                                                "budget_semantics")),
                          "first-call path must use cached/bounded sources "
                          "and return valid JSON") == 0;
        const struct json_value *security =
            json_get(&result, "security_posture");
        ok = ok && security && security->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(security, "schema")),
                          "zcl.security_posture.v1") == 0;
        ok = ok && json_get(security, "bootstrap_model") != NULL;
        ok = ok && json_get(security,
                            "full_history_validation_state") != NULL;
        ok = ok && json_get(security,
                            "snapshot_full_validation_complete") != NULL;
        ok = ok && json_get(security,
                            "anchor_history_complete") != NULL;
        ok = ok && json_get(security,
                            "anchor_history_state") != NULL;
        ok = ok && json_get(security,
                            "nullifier_history_complete") != NULL;
        ok = ok && json_get(security,
                            "nullifier_activation_cursor") != NULL;
        ok = ok && strstr(json_get_str(json_get(security, "semantics")),
                          "public serving and healthy fail closed") != NULL;

        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native operator snapshot is coherent, authoritative, and pure... ");
    {
        char authority_dir[256];
        struct connman cm;
        struct node_signals sigs;
        struct main_state ms;
        struct block_index tip;
        struct uint256 tip_hash;
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;
        const int served_height = 100;

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&tip_hash, 0, sizeof(tip_hash));
        progress_store_close();
        test_make_tmpdir(authority_dir, sizeof(authority_dir),
                         "syncdiag", "operator_authority");
        bool ok = progress_store_open(authority_dir);
        ok = ok && connman_init(&cm, chain_params_get(), &sigs);
        main_state_init(&ms);
        block_index_init(&tip);
        syncdiag_set_hash(&tip_hash, 0x91);
        tip.phashBlock = &tip_hash;
        tip.nHeight = served_height;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        arith_uint256_set_u64(&tip.nChainWork, 100);
        ok = ok && block_map_insert(&ms.map_block_index, tip.phashBlock,
                                    &tip);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &tip;
        csr_init(csr_instance(), &ms.map_block_index, &ms.chain_active,
                 &ms.pindex_best_header, NULL, NULL, NULL);
        ok = ok && syncdiag_seed_durable_tip_authority(
            served_height, tip_hash.data);

        struct p2p_node *peer =
            syncdiag_add_peer(&cm, 91, false, PEER_HANDSHAKE_COMPLETE);
        ok = ok && peer != NULL;
        if (peer)
            peer->starting_height = 2000000000;

        struct download_manager *dm = msg_get_download_mgr();
        dl_drain_for_backpressure(dm);
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();
        rpc_net_set_connman(&cm);
        sync_monitor_set_context(&cm, dm, &ms);
        reducer_frontier_provable_tip_set(served_height);
        sync_set_state(SYNC_FINDING_PEERS, "operator snapshot baseline");
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "operator snapshot baseline");
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "operator snapshot baseline");
        sync_set_state(SYNC_AT_TIP, "operator snapshot baseline");

        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        event_log_init();
        alerts_init();
        alerts_reset();
        blocker_module_shutdown();
        ok = ok && blocker_module_init();

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "operatorsnapshot",
                                     &params, &result);
        const struct json_value *capture = json_get(&result, "capture");
        const struct json_value *chain = json_get(&result, "chain");
        const struct json_value *header =
            chain ? json_get(chain, "validated_header") : NULL;
        const struct json_value *peers = json_get(&result, "peers");
        const struct json_value *blockers = json_get(&result, "blockers");
        const struct json_value *summary = json_get(&result, "summary");
        const struct json_value *invariants = json_get(&result, "invariants");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.operator_snapshot.v3") == 0;
        ok = ok && json_get_int(json_get(&result, "schema_version")) == 3;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "execution_locus")),
                          "target_node") == 0;
        const char *snapshot_source_id = json_get_str(json_get(
            &result, "source_id_sha256"));
        ok = ok && snapshot_source_id && strlen(snapshot_source_id) == 64;
        ok = ok && strcmp(snapshot_source_id,
                          zcl_build_source_id_sha256()) == 0;
        ok = ok && capture && capture->type == JSON_OBJ;
        ok = ok && !json_get_bool(json_get(capture,
                                           "globally_linearizable"));
        ok = ok && json_get_bool(json_get(capture,
                                           "critical_frontier_stable"));
        ok = ok && json_get_bool(json_get(capture,
                                           "verdict_inputs_complete"));
        ok = ok && !json_get_bool(json_get(capture, "partial"));
        ok = ok && json_get_int(json_get(capture, "duration_us")) >= 0;
        ok = ok && header && header->type == JSON_OBJ;
        ok = ok && json_get_int(json_get(header, "height")) == served_height;
        ok = ok && json_get_str(json_get(header, "hash"))[0] != '\0';
        ok = ok && json_get_str(json_get(header, "chain_work"))[0] != '\0';
        ok = ok && peers && peers->type == JSON_OBJ;
        ok = ok && json_get_int(json_get(peers,
                                         "advertised_max_height")) ==
                       2000000000;
        ok = ok && strcmp(json_get_str(json_get(peers,
                                                "peer_height_trust")),
                          "untrusted_peer_advertisement") == 0;
        ok = ok && blockers && blockers->type == JSON_OBJ;
        ok = ok && json_get_int(json_get(blockers, "active_count")) == 0;
        ok = ok && json_get(blockers, "generation") != NULL;
        ok = ok && summary && summary->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(summary,
                                                "source_id_sha256")),
                          snapshot_source_id) == 0;
        ok = ok && json_get_int(json_get(summary, "target_height")) ==
                       served_height;
        ok = ok && json_get_int(json_get(summary, "gap")) == 0;
        ok = ok && strcmp(json_get_str(json_get(summary, "status")),
                          "healthy") == 0;
        ok = ok && invariants && invariants->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(
                              json_get(invariants, "frontier_order"),
                              "status")), "pass") == 0;
        struct agent_peer_snapshot live_peer_snapshot;
        struct agent_peer_snapshot cached_peer_snapshot;
        agent_peer_snapshot_collect(&live_peer_snapshot, &cm);
        struct syncdiag_peer_lock_hold hold = { .connman = &cm };
        pthread_t hold_thread;
        bool hold_started = pthread_create(&hold_thread, NULL,
                                           syncdiag_hold_peer_lock,
                                           &hold) == 0;
        for (int wait = 0; hold_started && !atomic_load(&hold.ready) &&
             wait < 1000; wait++)
            platform_sleep_ms(1);
        memset(&cached_peer_snapshot, 0, sizeof(cached_peer_snapshot));
        if (hold_started && atomic_load(&hold.ready))
            agent_peer_snapshot_collect(&cached_peer_snapshot, &cm);
        atomic_store(&hold.release, true);
        if (hold_started)
            pthread_join(hold_thread, NULL);
        bool cache_ok = hold_started && atomic_load(&hold.ready) &&
            live_peer_snapshot.available &&
            cached_peer_snapshot.available && cached_peer_snapshot.stale &&
            cached_peer_snapshot.generation == live_peer_snapshot.generation &&
            cached_peer_snapshot.peer_count == live_peer_snapshot.peer_count &&
            cached_peer_snapshot.inbound_count ==
                live_peer_snapshot.inbound_count &&
            cached_peer_snapshot.outbound_count ==
                live_peer_snapshot.outbound_count &&
            cached_peer_snapshot.ready_count == live_peer_snapshot.ready_count &&
            cached_peer_snapshot.peer_best_height ==
                live_peer_snapshot.peer_best_height;
        if (!cache_ok) {
            printf(" peer-cache mismatch live(gen=%llu stale=%d n=%zu) "
                   "cached(gen=%llu stale=%d n=%zu)",
                   (unsigned long long)live_peer_snapshot.generation,
                   live_peer_snapshot.stale,
                   live_peer_snapshot.peer_count,
                   (unsigned long long)cached_peer_snapshot.generation,
                   cached_peer_snapshot.stale,
                   cached_peer_snapshot.peer_count);
        }
        ok = ok && cache_ok;
        json_free(&result);

        /* Explicit negative: all chain/peer/download inputs remain healthy,
         * but a review-required security posture must suppress both healthy
         * and serving and name the causal posture. */
        agent_security_posture_test_override_review_required(1);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "operatorsnapshot",
                                     &params, &result);
        const struct json_value *security =
            json_get(&result, "security_posture");
        summary = json_get(&result, "summary");
        ok = ok && !json_get_bool(json_get(&result, "healthy"));
        ok = ok && !json_get_bool(json_get(&result, "serving"));
        ok = ok && !json_get_bool(json_get(&result, "verdict_complete"));
        ok = ok && json_get_bool(json_get(
            &result, "security_review_required"));
        ok = ok && !json_get_bool(json_get(
            &result, "security_posture_ok"));
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "operator_needed") == 0;
        ok = ok && strcmp(json_get_str(json_get(
            &result, "primary_blocker")), "review_required_test") == 0;
        ok = ok && security && json_get_bool(json_get(
            security, "review_required"));
        ok = ok && summary && !json_get_bool(json_get(summary, "serving"));
        json_free(&result);
        agent_security_posture_test_override_review_required(0);

        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=operator_snapshot_purity attempts=9");

        struct blocker_record downstream;
        struct blocker_record nullifier_gap;
        struct blocker_record anchor_gap;
        ok = ok && blocker_init(
            &downstream, "script_validate.prevout_unresolved",
            "script_validate", BLOCKER_PERMANENT,
            "downstream symptom");
        ok = ok && blocker_set(&downstream) == 0;
        ok = ok && blocker_init(
            &nullifier_gap, "utxo_apply.nullifier_backfill_gap",
            "utxo_apply", BLOCKER_PERMANENT,
            "historical nullifier state is incomplete");
        ok = ok && blocker_set(&nullifier_gap) == 0;
        ok = ok && blocker_init(
            &anchor_gap, "utxo_apply.anchor_backfill_gap",
            "utxo_apply", BLOCKER_PERMANENT,
            "historical anchor state is incomplete");
        ok = ok && blocker_set(&anchor_gap) == 0;

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agent", &params, &result);
        const struct json_value *health = json_get(&result, "health");
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "blocked") == 0;
        ok = ok && strcmp(json_get_str(json_get(
                          &result, "primary_blocker")),
                          "utxo_apply.anchor_backfill_gap") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "next")),
                          "z23 dumpstate blocker") == 0;
        ok = ok && health &&
             json_get_bool(json_get(health, "hard_typed_blocker"));
        ok = ok && health && strcmp(json_get_str(json_get(
                          health, "dominant_typed_blocker")),
                          "utxo_apply.anchor_backfill_gap") == 0;
        json_free(&result);

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "operatorsnapshot",
                                     &params, &result);
        char latch_detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN] = {0};
        ok = ok && alerts_operator_needed(latch_detail,
                                          sizeof(latch_detail), NULL);
        ok = ok && strstr(latch_detail, "operator_snapshot_purity") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "operator_needed") == 0;
        ok = ok && strcmp(json_get_str(json_get(
                          &result, "primary_blocker")),
                          "utxo_apply.anchor_backfill_gap") == 0;
        blockers = json_get(&result, "blockers");
        ok = ok && blockers && strcmp(json_get_str(json_get(
                          json_get(blockers, "dominant"), "id")),
                          "utxo_apply.anchor_backfill_gap") == 0;
        json_free(&result);

        blocker_clear("script_validate.prevout_unresolved");
        blocker_clear("utxo_apply.nullifier_backfill_gap");
        blocker_clear("utxo_apply.anchor_backfill_gap");
        alerts_operator_needed_clear();
        struct blocker_record resource;
        ok = ok && blocker_init(&resource, "test.operator.disk_full",
                                "operator_snapshot", BLOCKER_RESOURCE,
                                "test resource blocker");
        ok = ok && blocker_set(&resource) == 0;
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "operatorsnapshot",
                                     &params, &result);
        blockers = json_get(&result, "blockers");
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "operator_needed") == 0;
        ok = ok && json_get_int(json_get(blockers, "active_count")) == 1;
        ok = ok && json_get_int(json_get(blockers, "resource_count")) == 1;
        ok = ok && strcmp(json_get_str(json_get(
                              json_get(blockers, "dominant"), "id")),
                          "test.operator.disk_full") == 0;

        json_free(&result);
        json_free(&params);
        blocker_clear("test.operator.disk_full");
        blocker_module_shutdown();
        alerts_shutdown();
        dl_drain_for_backpressure(dm);
        sync_monitor_set_context(NULL, NULL, NULL);
        rpc_net_set_connman(NULL);
        reducer_frontier_provable_tip_reset();
        sync_set_state(SYNC_IDLE, "operator snapshot cleanup");
        csr_free(csr_instance());
        main_state_free(&ms);
        connman_free(&cm);
        progress_store_close();
        test_cleanup_tmpdir(authority_dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: operator snapshot classifier fails closed on edge states... ");
    {
        struct operator_capture capture;
        memset(&capture, 0, sizeof(capture));
        capture.critical_frontier_stable = true;
        capture.chain.context_known = true;
        capture.chain.hstar_published = true;
        capture.chain.served.height_known = true;
        capture.chain.served.binding_known = true;
        capture.chain.served.height = 100;
        snprintf(capture.chain.served.hash,
                 sizeof(capture.chain.served.hash), "served-hash");
        snprintf(capture.chain.served.chain_work,
                 sizeof(capture.chain.served.chain_work), "served-work");
        capture.chain.indexed = capture.chain.served;
        capture.chain.header = capture.chain.served;
        capture.chain.authority_pair_known = true;
        capture.chain.durable_authority_known = true;
        capture.chain.authority_matches_served = true;
        capture.chain.ancestry_known = true;
        capture.chain.served_ancestor_indexed = true;
        capture.chain.indexed_ancestor_header = true;
        capture.chain.work_known = true;
        capture.chain.work_monotone = true;
        capture.chain.validity_known = true;
        capture.chain.validity_sufficient = true;
        capture.chain.failure_free = true;
        capture.peers.available = true;
        capture.peers.direction_known = true;
        capture.peers.ready_known = true;
        capture.peers.peer_count = 1;
        capture.peers.outbound_count = 1;
        capture.peers.ready_count = 1;
        capture.download_known = true;
        capture.sync_state_known = true;
        capture.sync_state = SYNC_AT_TIP;

        struct operator_verdict verdict =
            operator_snapshot_classify(&capture);
        bool ok = verdict.healthy && verdict.complete &&
                  strcmp(verdict.status, "healthy") == 0;

        capture.mirror.enabled = true;
        capture.mirror.reachable = true;
        capture.mirror.lag_known = true;
        capture.mirror.local_height = 100;
        capture.mirror.legacy_height = 100;
        capture.mirror.tip_hashes_agree = false;
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy && !verdict.complete &&
             strcmp(verdict.status, "degraded") == 0 &&
             strcmp(verdict.primary,
                    "mirror_same_height_hash_unavailable_or_mismatch") == 0;
        snprintf(capture.mirror.zclassic23_hash,
                 sizeof(capture.mirror.zclassic23_hash), "%064x", 1);
        snprintf(capture.mirror.zclassicd_hash,
                 sizeof(capture.mirror.zclassicd_hash), "%064x", 2);
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy &&
             strcmp(verdict.primary,
                    "mirror_same_height_hash_unavailable_or_mismatch") == 0;
        capture.mirror.tip_hashes_agree = true;
        verdict = operator_snapshot_classify(&capture);
        ok = ok && verdict.healthy && verdict.complete;
        capture.mirror.enabled = false;

        capture.peers.peer_count = 0;
        capture.peers.outbound_count = 0;
        capture.peers.ready_count = 0;
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy &&
             strcmp(verdict.status, "blocked") == 0 &&
             strcmp(verdict.primary, "no_peers") == 0;

        capture.peers.peer_count = 1;
        capture.peers.outbound_count = 1;
        capture.peers.ready_count = 1;
        capture.sync_state = SYNC_BLOCKS_DOWNLOAD;
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy &&
             strcmp(verdict.status, "degraded") == 0 &&
             strcmp(verdict.primary, "sync_not_at_tip") == 0;

        capture.sync_state = SYNC_AT_TIP;
        capture.chain.served.height = 101;
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy && !verdict.frontier_order_ok &&
             strcmp(verdict.primary, "chain_evidence_inconsistent") == 0;

        capture.chain.served.height = 100;
        capture.peers.stale = true;
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy && !verdict.complete &&
             strcmp(verdict.primary, "peer_state_unavailable") == 0;

        capture.peers.stale = false;
        capture.security_review_required = true;
        snprintf(capture.security_posture_status,
                 sizeof(capture.security_posture_status),
                 "review_required_test");
        snprintf(capture.security_posture_next_action,
                 sizeof(capture.security_posture_next_action),
                 "test_review");
        verdict = operator_snapshot_classify(&capture);
        ok = ok && !verdict.healthy && !verdict.serving &&
             !verdict.complete && verdict.operator_needed &&
             strcmp(verdict.status, "operator_needed") == 0 &&
             strcmp(verdict.primary, "review_required_test") == 0;

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }


    return failures;
}
