/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentops sibling: agentbuild (loop, incremental-compile, indexing,
 * benchmark, cache, immutable-history, command catalog, and
 * background-quality sections) and its deferred-collector follow-up,
 * agentdevstatus, and the agentliveness rollup in brief, full, and
 * probed detail modes. Each scenario builds its params off the shared
 * struct sd_agent_ops_ctx (and, for agentbuild and its deferred
 * follow-up, the shared on-disk struct sd_quality_fixture), calls the
 * RPC through the shared table, asserts on the result, and frees what
 * it owns; the assertion helpers above each scenario are private to
 * that scenario and add no file-scope mutable state of their own.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_agent_ops_priv.h"

static bool sd_build_contract_and_loop_gates(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *loop =
        json_get(build, "recommended_loop");
    ok = ok && build->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(build, "schema")),
                      "zcl.agent_build.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(build, "build_commit")),
                      zcl_build_commit()) == 0;
    ok = ok && loop && strcmp(json_get_str(json_get(loop, "schema")),
                              "zcl.agent_build_loop.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop, "default_edit_gate")),
                      "make agent-loop") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "default_underlying_gate")),
                      "make fast-ci") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "read_only_fast_plan")),
                      "make agent-plan") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop, "doctor")),
                      "make agent-doctor") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "dev_lane_status")),
                      "make agent-dev-status") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "native_dev_lane_status")),
                      "z23 agentdevstatus") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "stage_dev_binary_no_restart")),
                      "contained: make agent-stage-dev refuses") == 0;
    return ok;
}

static bool sd_build_loop_compile_rules(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *loop =
        json_get(build, "recommended_loop");
    const struct json_value *incremental =
        json_get(build, "incremental_compile");
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "optional_dev_stage_no_restart")),
                      "contained: ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop refuses") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "direct_changed_compile")),
                      "make fast-changed-compile") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "fast_no_link_compile")),
                      "make fast-compile") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "fast_ci_compile_default")),
                      "ZCL_FAST_COMPILE=changed -> source-wide make fast-compile in an exact compile epoch") == 0;
    ok = ok && strstr(json_get_str(json_get(loop, "rule")),
                      "classification hints only") != NULL;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "immutable_history_canaries")),
                      "make immutable-history-canaries") == 0;
    ok = ok && strcmp(json_get_str(json_get(loop,
                       "pre_push_compile_default")),
                      "none; native pre-push never compiles") == 0;
    ok = ok && incremental && json_get_bool(json_get(incremental,
                                                     "header_depfiles"));
    ok = ok && strcmp(json_get_str(json_get(incremental,
                                            "changed_compile_check")),
                      "make fast-changed-compile") == 0;
    ok = ok && strstr(json_get_str(json_get(incremental, "behavior")),
                      "build/dev-obj/epochs/<compile_epoch>") != NULL;
    ok = ok && strstr(json_get_str(json_get(incremental,
                                            "changed_compile_fallbacks")),
                      "path hints never reduce") != NULL;
    return ok;
}

static bool sd_build_dev_binary_and_indexing(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *incremental =
        json_get(build, "incremental_compile");
    const struct json_value *dev_binary =
        json_get(build, "dev_node_binary");
    const struct json_value *indexing = json_get(build, "indexing");
    ok = ok && strcmp(json_get_str(json_get(incremental,
                                            "fast_compile_check")),
                      "make fast-compile") == 0;
    ok = ok && strcmp(json_get_str(json_get(incremental,
                                            "dev_binary_command")),
                      "make fast-rebuild") == 0;
    ok = ok && dev_binary && json_get_bool(json_get(dev_binary,
                                                    "enabled"));
    ok = ok && strcmp(json_get_str(json_get(dev_binary, "binary")),
                      "build/bin/z23-dev") == 0;
    ok = ok && indexing &&
        strcmp(json_get_str(json_get(indexing, "schema")),
               "zcl.agent_index_runtime.v1") == 0;
    ok = ok && indexing &&
        json_get(indexing, "collector_complete") != NULL;
    ok = ok && indexing &&
        json_get(indexing, "collector_deferred") != NULL;
    return ok;
}

static bool sd_build_indexing_freshness(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *indexing = json_get(build, "indexing");
    const struct json_value *dev_loop_benchmark =
        json_get(build, "dev_loop_benchmark");
    bool indexing_complete = indexing &&
        json_get_bool(json_get(indexing, "collector_complete"));
    ok = ok && indexing &&
        json_get_bool(json_get(indexing, "collector_deferred")) ==
            !indexing_complete;
    ok = ok && indexing &&
        strcmp(json_get_str(json_get(indexing, "command")),
               "make agent-index") == 0;
    ok = ok && indexing &&
        (!indexing_complete ||
         strcmp(json_get_str(json_get(indexing, "generator")),
                "tools/dev/generate-compdb.sh") == 0);
    ok = ok && indexing && json_get(indexing, "freshness") != NULL;
    ok = ok && indexing && json_get(indexing, "clangd_optional") != NULL;
    ok = ok && dev_loop_benchmark &&
        strcmp(json_get_str(json_get(dev_loop_benchmark, "schema")),
               "zcl.dev_loop_bench.v1") == 0;
    return ok;
}

static bool sd_build_dev_loop_benchmark(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *dev_loop_benchmark =
        json_get(build, "dev_loop_benchmark");
    const struct json_value *commands = json_get(build, "commands");
    bool benchmark_complete = dev_loop_benchmark &&
        json_get_bool(json_get(dev_loop_benchmark,
                                "collector_complete"));
    ok = ok && dev_loop_benchmark &&
        json_get(dev_loop_benchmark, "collector_complete") != NULL;
    ok = ok && dev_loop_benchmark &&
        json_get(dev_loop_benchmark, "collector_deferred") != NULL;
    ok = ok && dev_loop_benchmark &&
        json_get_bool(json_get(dev_loop_benchmark,
                               "collector_deferred")) ==
            !benchmark_complete;
    ok = ok && dev_loop_benchmark &&
        (benchmark_complete
            ? json_get(dev_loop_benchmark, "slo") != NULL
            : (strcmp(json_get_str(json_get(dev_loop_benchmark,
                                            "status")),
                      "unavailable") == 0 &&
               json_get(dev_loop_benchmark, "slo") == NULL &&
               json_get(dev_loop_benchmark, "collector_blocker") !=
                   NULL));
    ok = ok && find_object_with_str(commands, "name", "agent_index") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                     "dev_loop_benchmark") != NULL;
    return ok;
}

static bool sd_build_dev_binary_and_cache(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *dev_binary =
        json_get(build, "dev_node_binary");
    const struct json_value *cache = json_get(build, "cache");
    const struct json_value *history =
        json_get(build, "immutable_history_canaries");
    ok = ok && strcmp(json_get_str(json_get(dev_binary,
                                            "native_status_command")),
                      "z23 agentdevstatus") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_binary,
                                            "agent_loop_stage_no_restart")),
                      "contained: ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop refuses") == 0;
    ok = ok && !json_get_bool(json_get(dev_binary,
                                       "release_or_deploy_artifact"));
    ok = ok && strstr(json_get_str(json_get(dev_binary,
                                            "hot_path_buckets")),
                      "core/modules/crypto") != NULL;
    ok = ok && cache && strstr(json_get_str(json_get(cache,
                                                     "auto_select_order")),
                               "sccache cc") != NULL;
    ok = ok && strcmp(json_get_str(json_get(cache, "plan_command")),
                      "make agent-plan") == 0;
    ok = ok && strcmp(json_get_str(json_get(cache, "plan_schema")),
                      "zcl.agent_fast_plan.v1") == 0;
    ok = ok && strstr(json_get_str(json_get(cache,
                                            "makefile_auto_wrapper")),
                      "sccache cc") != NULL;
    ok = ok && find_object_with_str(json_get(cache, "knobs"), "name",
                                    "ZCL_FAST_CHANGED_FILES_ONLY") != NULL;
    ok = ok && history && history->type == JSON_OBJ;
    return ok;
}

static bool sd_build_immutable_history_canaries(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *history =
        json_get(build, "immutable_history_canaries");
    const struct json_value *commands = json_get(build, "commands");
    ok = ok && strcmp(json_get_str(json_get(history, "schema")),
                      "zcl.immutable_history_canaries.v1") == 0;
    ok = ok && json_get_bool(json_get(history, "enabled"));
    ok = ok && strcmp(json_get_str(json_get(history, "fast_command")),
                      "make immutable-history-canaries") == 0;
    ok = ok && strstr(json_get_str(json_get(history, "fast_groups")),
                      "domain_consensus_tx_structural") != NULL;
    ok = ok && strstr(json_get_str(json_get(history, "fast_groups")),
                      "consensus_parity") != NULL;
    ok = ok && strstr(json_get_str(json_get(history,
                                            "pinned_fixture")),
                      "h=478544") != NULL;
    ok = ok && strstr(json_get_str(json_get(history,
                                            "pinned_fixture")),
                      "size=125811") != NULL;
    ok = ok && strstr(json_get_str(json_get(history, "provenance")),
                      "fixture_tx_oversize_478544.c") != NULL;
    ok = ok && strcmp(json_get_str(json_get(history,
                                            "full_replay_anchor")),
                      "make replay-canary-anchor") == 0;
    ok = ok && strcmp(json_get_str(json_get(history,
                                            "full_replay_genesis")),
                      "make replay-canary-genesis") == 0;
    ok = ok && strstr(json_get_str(json_get(history,
                                            "tightening_rule")),
                      "real-chain replay") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "agent_plan") != NULL;
    return ok;
}

static bool sd_build_command_catalog(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *commands = json_get(build, "commands");
    ok = ok && find_object_with_str(commands, "name",
                                    "fast_changed_compile") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "agent_loop") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "agent_doctor") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "agent_dev_status_native") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "agent_clear_stale_dev_reindex") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "fast_dev_deploy") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "fast_compile") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "compile_check") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "fast_rebuild") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "dev_node_binary") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "immutable_history_canaries") != NULL;
    ok = ok && find_object_with_str(commands, "name",
                                    "byte_identity") != NULL;
    return ok;
}

static bool sd_build_reproducible_and_quality_status(const struct json_value *build,
                           const char *quality_root)
{
    bool ok = true;
    const struct json_value *repro =
        json_get(build, "reproducible_release");
    const struct json_value *quality_status =
        json_get(build, "background_quality_status");
    ok = ok && repro && strcmp(json_get_str(json_get(repro, "command")),
                               "make ci-reproducible") == 0;
    ok = ok && strcmp(json_get_str(json_get(repro, "portable_isa")),
                      "x86-64-v3") == 0;
    ok = ok && quality_status && quality_status->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(quality_status, "schema")),
                      "zcl.background_quality_runtime.v1") == 0;
    ok = ok && json_get_bool(json_get(quality_status,
                                      "native_status_reader"));
    ok = ok && !json_get_bool(json_get(quality_status,
                                       "requires_python"));
    ok = ok && strcmp(json_get_str(json_get(quality_status,
                                            "state_dir")),
                      quality_root ? quality_root : "") == 0;
    ok = ok && strcmp(json_get_str(json_get(quality_status,
                                            "summary")),
                      "background_quality_stale") == 0;
    ok = ok && strcmp(json_get_str(json_get(quality_status,
                                            "agent_next_action")),
                      "restart_or_wait_for_current_source_quality_lanes")
        == 0;
    ok = ok && strcmp(json_get_str(json_get(quality_status,
                                            "freshness_authority")),
                      "source_id_sha256") == 0;
    return ok;
}

static bool sd_build_quality_status_lanes_summary(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *quality_status =
        json_get(build, "background_quality_status");
    const struct json_value *quality_lanes =
        quality_status ? json_get(quality_status, "lanes") : NULL;
    const struct json_value *fuzz_lane =
        find_object_with_str(quality_lanes, "lane", "fuzz");
    ok = ok && json_get_int(json_get(quality_status,
                                     "status_files_present")) == 1;
    ok = ok && json_get_int(json_get(quality_status,
                                     "status_files_valid")) == 1;
    ok = ok && json_get_int(json_get(quality_status,
                                     "passed_count")) == 1;
    ok = ok && json_get_int(json_get(quality_status,
                                     "current_commit_count")) == 0;
    ok = ok && json_get_int(json_get(quality_status,
                                     "stale_commit_count")) == 1;
    ok = ok && json_get_int(json_get(quality_status,
                                     "unknown_commit_count")) == 0;
    ok = ok && quality_lanes && quality_lanes->type == JSON_ARR &&
        json_size(quality_lanes) == 3;
    ok = ok && fuzz_lane &&
        json_get_bool(json_get(fuzz_lane, "status_file_present"));
    return ok;
}

static bool sd_build_quality_status_fuzz_lane(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *quality_status =
        json_get(build, "background_quality_status");
    const struct json_value *quality_lanes =
        quality_status ? json_get(quality_status, "lanes") : NULL;
    const struct json_value *fuzz_lane =
        find_object_with_str(quality_lanes, "lane", "fuzz");
    const struct json_value *latest_fuzz =
        fuzz_lane ? json_get(fuzz_lane, "latest") : NULL;
    ok = ok && fuzz_lane &&
        json_get_bool(json_get(fuzz_lane, "latest_json_valid"));
    ok = ok && fuzz_lane &&
        strcmp(json_get_str(json_get(fuzz_lane, "latest_status")),
               "passed") == 0;
    ok = ok && latest_fuzz && latest_fuzz->type == JSON_OBJ;
    ok = ok && latest_fuzz &&
        strcmp(json_get_str(json_get(latest_fuzz, "commit")),
               zcl_build_commit()) == 0;
    ok = ok && fuzz_lane &&
        strcmp(json_get_str(json_get(fuzz_lane, "latest_commit")),
               zcl_build_commit()) == 0;
    ok = ok && fuzz_lane &&
        strcmp(json_get_str(json_get(fuzz_lane, "expected_commit")),
               zcl_build_commit()) == 0;
    return ok;
}

static bool sd_build_quality_status_fuzz_stale(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *quality_status =
        json_get(build, "background_quality_status");
    const struct json_value *quality_lanes =
        quality_status ? json_get(quality_status, "lanes") : NULL;
    const struct json_value *fuzz_lane =
        find_object_with_str(quality_lanes, "lane", "fuzz");
    const struct json_value *coverage_lane =
        find_object_with_str(quality_lanes, "lane", "coverage");
    ok = ok && fuzz_lane &&
        json_get_bool(json_get(fuzz_lane, "commit_present"));
    ok = ok && fuzz_lane &&
        !json_get_bool(json_get(fuzz_lane, "commit_matches_expected"));
    ok = ok && fuzz_lane &&
        !json_get_bool(json_get(fuzz_lane,
                                "source_id_matches_expected"));
    ok = ok && fuzz_lane &&
        strcmp(json_get_str(json_get(fuzz_lane,
                                     "source_id_freshness")),
               "stale") == 0;
    ok = ok && fuzz_lane &&
        strcmp(json_get_str(json_get(fuzz_lane, "commit_freshness")),
               "stale") == 0;
    ok = ok && coverage_lane &&
        !json_get_bool(json_get(coverage_lane, "status_file_present"));
    return ok;
}

static bool sd_build_quality_status_coverage_no_verdict(const struct json_value *build)
{
    bool ok = true;
    const struct json_value *quality_status =
        json_get(build, "background_quality_status");
    const struct json_value *quality_lanes =
        quality_status ? json_get(quality_status, "lanes") : NULL;
    const struct json_value *coverage_lane =
        find_object_with_str(quality_lanes, "lane", "coverage");
    ok = ok && coverage_lane &&
        strcmp(json_get_str(json_get(coverage_lane, "commit_freshness")),
               "no_verdict") == 0;
    return ok;
}

static bool sd_build_deferred_index_unavailable(bool moved_outside_repo,
                                    bool deferred_read, bool restored_cwd,
                                    const struct json_value *deferred_index)
{
    bool ok = true;
    ok = ok && moved_outside_repo && deferred_read && restored_cwd;
    ok = ok && deferred_index &&
        !json_get_bool(json_get(deferred_index, "collector_complete"));
    ok = ok && deferred_index &&
        json_get_bool(json_get(deferred_index, "collector_deferred"));
    ok = ok && deferred_index &&
        strcmp(json_get_str(json_get(deferred_index, "status")),
               "unavailable") == 0;
    return ok;
}

static bool sd_build_deferred_benchmark_unavailable(const struct json_value *deferred_benchmark)
{
    bool ok = true;
    ok = ok && deferred_benchmark &&
        !json_get_bool(json_get(deferred_benchmark,
                                "collector_complete"));
    ok = ok && deferred_benchmark &&
        json_get_bool(json_get(deferred_benchmark,
                               "collector_deferred"));
    ok = ok && deferred_benchmark &&
        strcmp(json_get_str(json_get(deferred_benchmark, "status")),
               "unavailable") == 0;
    ok = ok && deferred_benchmark &&
        json_get(deferred_benchmark, "slo") == NULL;
    return ok;
}
static bool sd_devstatus_contract_and_worker_lane(const struct json_value *dev_status)
{
    bool ok = true;
    const struct json_value *dev_worker =
        json_get(dev_status, "worker_lane");
    ok = ok && dev_status->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(dev_status, "schema")),
                      "zcl.agent_dev_status.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_status, "status")),
                      "ok") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_status,
                                            "native_command")),
                      "z23 agentdevstatus") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_status,
                                            "next_action")),
                      "unit-test") == 0;
    ok = ok && dev_worker && dev_worker->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(dev_worker, "role")),
                      "worker") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                            "mutation_policy")),
                      "noncanonical_dev_only") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                            "canonical_guard")),
                      "never_touches_live_or_soak") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                            "stage_command")),
                      "make agent-stage-dev") == 0;
    ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                            "recover_command")),
                      "make agent-dev-recover") == 0;
    return ok;
}

static bool sd_liveness_brief_contract(const struct json_value *liveness)
{
    bool ok = true;
    const struct json_value *live_first_call =
        json_get(liveness, "first_call");
    ok = ok && liveness->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(liveness, "schema")),
                      "zcl.agent_liveness.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(liveness, "method")),
                      "agentliveness") == 0;
    ok = ok && strcmp(json_get_str(json_get(liveness,
                                            "native_command")),
                      "z23 agentliveness") == 0;
    ok = ok && strcmp(json_get_str(json_get(liveness,
                                            "contract_source")),
                      "agent_contracts.def") == 0;
    ok = ok && strcmp(json_get_str(json_get(liveness, "detail_mode")),
                      "brief") == 0;
    ok = ok && !json_get_bool(json_get(liveness,
                                       "embedded_drilldowns"));
    ok = ok && strcmp(json_get_str(json_get(liveness,
                                            "full_mode_command")),
                      "z23 agentliveness full") == 0;
    ok = ok && live_first_call && live_first_call->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(live_first_call, "schema")),
                      "zcl.first_call_contract.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(live_first_call, "api")),
                      "agentliveness") == 0;
    return ok;
}

static bool sd_liveness_brief_first_call(const struct json_value *liveness)
{
    bool ok = true;
    const struct json_value *live_first_call =
        json_get(liveness, "first_call");
    const struct json_value *live_omitted =
        json_get(liveness, "omitted_sections");
    ok = ok && strcmp(json_get_str(json_get(live_first_call,
                                            "result_completeness")),
                      "bounded") == 0;
    ok = ok && strcmp(json_get_str(json_get(live_first_call, "source")),
                      "runtime_supervisor_quality_status_brief") == 0;
    ok = ok && json_get_bool(json_get(live_first_call,
                                      "partial_result"));
    ok = ok && strcmp(json_get_str(json_get(live_first_call,
                                            "partial_reason")),
                      "brief_mode_omits_embedded_drilldowns") == 0;
    ok = ok && strcmp(json_get_str(json_get(live_first_call,
                                            "full_mode_command")),
                      "z23 agentliveness full") == 0;
    ok = ok && json_get_int(json_get(live_first_call,
                                     "budget_ms")) == 750;
    ok = ok && json_get(live_first_call, "elapsed_ms") != NULL;
    ok = ok && json_get(live_first_call, "budget_exceeded") != NULL;
    ok = ok && live_omitted &&
        json_array_has_str(live_omitted, "runtime_availability.methods");
    ok = ok && live_omitted &&
        json_array_has_str(live_omitted, "background_quality_status.lanes");
    return ok;
}

static bool sd_liveness_brief_summary_and_runtime_services(const struct json_value *liveness)
{
    bool ok = true;
    const struct json_value *live_summary =
        json_get(liveness, "liveness_summary");
    const struct json_value *live_runtime =
        json_get(liveness, "runtime_services");
    const struct json_value *live_availability =
        json_get(liveness, "runtime_availability");
    const struct json_value *live_omitted =
        json_get(liveness, "omitted_sections");
    ok = ok && live_omitted &&
        json_array_has_str(live_omitted, "supervisor_state.domains");
    ok = ok && strcmp(json_get_str(json_get(liveness,
                                            "overall_liveness")),
                      "static_or_offline_context") == 0;
    ok = ok && live_summary &&
        strcmp(json_get_str(json_get(live_summary,
                                     "background_quality_summary")),
               "background_quality_stale") == 0;
    ok = ok && live_summary &&
        json_get_int(json_get(live_summary,
                              "background_quality_status_files_valid")) == 1;
    ok = ok && live_runtime &&
        strcmp(json_get_str(json_get(live_runtime, "schema")),
               "zcl.agent_runtime_services.v1") == 0;
    ok = ok && live_availability &&
        strcmp(json_get_str(json_get(live_availability, "schema")),
               "zcl.agent_runtime_availability.v3") == 0;
    return ok;
}

static bool sd_liveness_brief_runtime_availability_detail(const struct json_value *liveness)
{
    bool ok = true;
    const struct json_value *live_summary =
        json_get(liveness, "liveness_summary");
    const struct json_value *live_availability =
        json_get(liveness, "runtime_availability");
    ok = ok && live_availability &&
        strcmp(json_get_str(json_get(live_availability,
                                     "object_completeness")),
               "compact") == 0;
    ok = ok && live_availability &&
        json_get(live_availability, "methods") == NULL;
    ok = ok && live_availability &&
        !json_get_bool(json_get(live_availability,
                                "target_rpc_attempted"));
    ok = ok && live_summary &&
        !json_get_bool(json_get(live_summary,
                                "target_runtime_reachable"));
    ok = ok && live_summary &&
        !json_get_bool(json_get(live_summary,
                                "effective_runtime_reachable"));
    ok = ok && live_summary &&
        strcmp(json_get_str(json_get(live_summary,
                                     "producer_runtime_state")),
               "inactive_or_static_probe") == 0;
    return ok;
}

static bool sd_liveness_brief_quality_status(const struct json_value *liveness)
{
    bool ok = true;
    const struct json_value *live_summary =
        json_get(liveness, "liveness_summary");
    const struct json_value *live_quality =
        json_get(liveness, "background_quality_status");
    ok = ok && live_summary &&
        strcmp(json_get_str(json_get(live_summary,
                                     "target_runtime_state")),
               "not_probed") == 0;
    ok = ok && live_summary &&
        strcmp(json_get_str(json_get(live_summary,
                                     "effective_runtime_scope")),
               "none") == 0;
    ok = ok && live_summary &&
        strcmp(json_get_str(json_get(live_summary,
                                     "runtime_observation_scope")),
               "producer_runtime") == 0;
    ok = ok && live_quality &&
        strcmp(json_get_str(json_get(live_quality, "schema")),
               "zcl.background_quality_runtime.v1") == 0;
    ok = ok && live_quality &&
        strcmp(json_get_str(json_get(live_quality,
                                     "object_completeness")),
               "compact") == 0;
    ok = ok && live_quality &&
        json_get(live_quality, "lanes") == NULL;
    return ok;
}

static bool sd_liveness_brief_supervisor_state(const struct json_value *liveness)
{
    bool ok = true;
    const struct json_value *live_supervisor =
        json_get(liveness, "supervisor_state");
    const struct json_value *live_drilldowns =
        json_get(liveness, "recommended_drilldowns");
    ok = ok && live_supervisor &&
        json_get(live_supervisor, "running") != NULL;
    ok = ok && live_supervisor &&
        strcmp(json_get_str(json_get(live_supervisor,
                                     "object_completeness")),
               "compact") == 0;
    ok = ok && live_supervisor &&
        json_get(live_supervisor, "domains") == NULL;
    ok = ok && live_drilldowns &&
        json_array_has_substr(live_drilldowns,
                              "z23 dumpstate supervisor");
    return ok;
}

static bool sd_liveness_full_embedded_sections(const struct json_value *liveness_full)
{
    bool ok = true;
    const struct json_value *full_availability =
        json_get(liveness_full, "runtime_availability");
    const struct json_value *full_quality =
        json_get(liveness_full, "background_quality_status");
    const struct json_value *full_supervisor =
        json_get(liveness_full, "supervisor_state");
    const struct json_value *full_first_call =
        json_get(liveness_full, "first_call");
    ok = ok && strcmp(json_get_str(json_get(liveness_full,
                                            "detail_mode")),
                      "full") == 0;
    ok = ok && json_get_bool(json_get(liveness_full,
                                      "embedded_drilldowns"));
    ok = ok && json_get(liveness_full, "omitted_sections") == NULL;
    ok = ok && full_availability &&
        json_get(full_availability, "methods") != NULL;
    ok = ok && full_quality && json_get(full_quality, "lanes") != NULL;
    ok = ok && full_supervisor &&
        json_get(full_supervisor, "domains") != NULL;
    ok = ok && full_first_call &&
        strcmp(json_get_str(json_get(full_first_call, "source")),
               "runtime_supervisor_quality_status_full") == 0;
    return ok;
}

static bool sd_liveness_probed_summary(const struct json_value *probed_liveness)
{
    bool ok = true;
    const struct json_value *probed_summary =
        json_get(probed_liveness, "liveness_summary");
    ok = ok && strcmp(json_get_str(json_get(probed_liveness,
                                            "overall_liveness")),
                      "target_runtime_reachable") == 0;
    ok = ok && probed_summary &&
        json_get_bool(json_get(probed_summary,
                               "target_runtime_reachable"));
    ok = ok && probed_summary &&
        json_get_bool(json_get(probed_summary,
                               "effective_runtime_reachable"));
    ok = ok && probed_summary &&
        strcmp(json_get_str(json_get(probed_summary,
                                     "producer_runtime_state")),
               "inactive_or_static_probe") == 0;
    ok = ok && probed_summary &&
        strcmp(json_get_str(json_get(probed_summary,
                                     "target_runtime_state")),
               "reachable") == 0;
    ok = ok && probed_summary &&
        strcmp(json_get_str(json_get(probed_summary,
                                     "effective_runtime_scope")),
               "target_rpc_probe") == 0;
    return ok;
}

static bool sd_liveness_probed_availability_and_next_action(const struct json_value *probed_liveness)
{
    bool ok = true;
    const struct json_value *probed_summary =
        json_get(probed_liveness, "liveness_summary");
    const struct json_value *probed_availability =
        json_get(probed_liveness, "runtime_availability");
    ok = ok && probed_summary &&
        strcmp(json_get_str(json_get(probed_summary,
                                     "runtime_observation_scope")),
               "target_rpc_probe") == 0;
    ok = ok && probed_availability &&
        json_get_bool(json_get(probed_availability,
                               "target_rpc_reachable"));
    ok = ok && strcmp(json_get_str(json_get(probed_liveness,
                                            "agent_next_action")),
                      "monitor_target_runtime") == 0;
    return ok;
}

/* case: agentops top-level fields, direct_commands, workflow, gaps, and
 * architecture_review. */

/* case: agentbuild's loop, incremental-compile, indexing, benchmark,
 * cache, immutable-history, command, and background-quality sections,
 * read against the on-disk quality fixture. */
bool sd_build_scenario(struct sd_agent_ops_ctx *ctx,
                              const struct sd_quality_fixture *fx)
{
    struct json_value build;
    json_init(&build);
    bool ok = rpc_table_execute(&ctx->tbl, "agentbuild", &ctx->params,
                                &build);
    ok = sd_build_contract_and_loop_gates(&build) && ok;
    ok = sd_build_loop_compile_rules(&build) && ok;
    ok = sd_build_dev_binary_and_indexing(&build) && ok;
    ok = sd_build_indexing_freshness(&build) && ok;
    ok = sd_build_dev_loop_benchmark(&build) && ok;
    ok = sd_build_dev_binary_and_cache(&build) && ok;
    ok = sd_build_immutable_history_canaries(&build) && ok;
    ok = sd_build_command_catalog(&build) && ok;
    ok = sd_build_reproducible_and_quality_status(&build, fx->root) && ok;
    ok = sd_build_quality_status_lanes_summary(&build) && ok;
    ok = sd_build_quality_status_fuzz_lane(&build) && ok;
    ok = sd_build_quality_status_fuzz_stale(&build) && ok;
    ok = sd_build_quality_status_coverage_no_verdict(&build) && ok;
    json_free(&build);
    return ok;
}

/* case: agentbuild's indexing and dev_loop_benchmark collectors report
 * the deferred/unavailable state outside the repository checkout. */
bool sd_build_deferred_scenario(struct sd_agent_ops_ctx *ctx,
                                       const struct sd_quality_fixture *fx)
{
    char saved_cwd[4096];
    bool moved_outside_repo = fx->root &&
        getcwd(saved_cwd, sizeof(saved_cwd)) != NULL &&
        chdir(fx->root) == 0;
    struct json_value deferred_build;
    json_init(&deferred_build);
    bool deferred_read = moved_outside_repo &&
        rpc_table_execute(&ctx->tbl, "agentbuild", &ctx->params,
                          &deferred_build);
    bool restored_cwd = !moved_outside_repo || chdir(saved_cwd) == 0;
    const struct json_value *deferred_index =
        json_get(&deferred_build, "indexing");
    const struct json_value *deferred_benchmark =
        json_get(&deferred_build, "dev_loop_benchmark");
    bool ok = sd_build_deferred_index_unavailable(moved_outside_repo, deferred_read,
                                      restored_cwd, deferred_index);
    ok = sd_build_deferred_benchmark_unavailable(deferred_benchmark) && ok;
    json_free(&deferred_build);
    return ok;
}

/* case: agentdevstatus reflects a mocked dev-status-cmd worker_lane and
 * next_action payload. */
bool sd_devstatus_scenario(struct sd_agent_ops_ctx *ctx)
{
    const char *old_dev_status_cmd = getenv("ZCL_AGENT_DEV_STATUS_CMD");
    char old_dev_status_cmd_buf[4096];
    bool old_dev_status_cmd_set = old_dev_status_cmd != NULL;
    bool old_dev_status_cmd_saved = true;
    if (old_dev_status_cmd_set) {
        int n = snprintf(old_dev_status_cmd_buf,
                         sizeof(old_dev_status_cmd_buf), "%s",
                         old_dev_status_cmd);
        old_dev_status_cmd_saved = n >= 0 &&
            (size_t)n < sizeof(old_dev_status_cmd_buf);
    }
    bool ok = old_dev_status_cmd_saved;
    ok = ok && set_dev_status_cmd_json(
        "{\"schema\":\"zcl.agent_dev_status.v2\","
        "\"worker_lane\":{\"name\":\"dev\",\"role\":\"worker\","
        "\"mutation_policy\":\"noncanonical_dev_only\","
        "\"canonical_guard\":\"never_touches_live_or_soak\","
        "\"stage_command\":\"make agent-stage-dev\","
        "\"recover_command\":\"make agent-dev-recover\"},"
        "\"next_action\":\"unit-test\","
        "\"service\":{\"active_state\":\"active\"},"
        "\"rpc\":{\"status\":\"ok\"}}");
    struct json_value dev_status;
    json_init(&dev_status);
    ok = rpc_table_execute(&ctx->tbl, "agentdevstatus", &ctx->params,
                           &dev_status) && ok;
    if (old_dev_status_cmd_set)
        setenv("ZCL_AGENT_DEV_STATUS_CMD",
               old_dev_status_cmd_buf, 1);
    else
        unsetenv("ZCL_AGENT_DEV_STATUS_CMD");
    ok = sd_devstatus_contract_and_worker_lane(&dev_status) && ok;
    json_free(&dev_status);
    return ok;
}

/* case: agentliveness in brief mode — compact runtime_availability and
 * background_quality_status, first_call, and omitted_sections. */
bool sd_liveness_brief_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value liveness;
    json_init(&liveness);
    bool ok = rpc_table_execute(&ctx->tbl, "agentliveness", &ctx->params,
                                &liveness);
    ok = sd_liveness_brief_contract(&liveness) && ok;
    ok = sd_liveness_brief_first_call(&liveness) && ok;
    ok = sd_liveness_brief_summary_and_runtime_services(&liveness) && ok;
    ok = sd_liveness_brief_runtime_availability_detail(&liveness) && ok;
    ok = sd_liveness_brief_quality_status(&liveness) && ok;
    ok = sd_liveness_brief_supervisor_state(&liveness) && ok;
    json_free(&liveness);
    return ok;
}

/* case: agentliveness in full mode embeds the methods, lanes, and
 * domains sections that brief mode omits. */
bool sd_liveness_full_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value liveness_full_params, full_mode, liveness_full;
    json_init(&liveness_full_params);
    json_set_array(&liveness_full_params);
    json_init(&full_mode);
    json_set_str(&full_mode, "full");
    json_push_back(&liveness_full_params, &full_mode);
    json_free(&full_mode);
    json_init(&liveness_full);
    bool ok = rpc_table_execute(&ctx->tbl, "agentliveness",
                                &liveness_full_params, &liveness_full);
    ok = sd_liveness_full_embedded_sections(&liveness_full) && ok;
    json_free(&liveness_full);
    json_free(&liveness_full_params);
    return ok;
}

/* case: agentliveness reports target_runtime_reachable once a target RPC
 * probe has been recorded. */
bool sd_liveness_probed_scenario(struct sd_agent_ops_ctx *ctx)
{
    agent_runtime_availability_begin_probe("test_target_rpc",
                                           "/tmp/zcl-canonical",
                                           18232, "ok");
    agent_runtime_availability_record_method("agent", "supported", 0, "");
    struct json_value probed_liveness;
    json_init(&probed_liveness);
    bool ok = rpc_table_execute(&ctx->tbl, "agentliveness", &ctx->params,
                                &probed_liveness);
    ok = sd_liveness_probed_summary(&probed_liveness) && ok;
    ok = sd_liveness_probed_availability_and_next_action(&probed_liveness) && ok;
    json_free(&probed_liveness);
    agent_runtime_availability_reset();
    return ok;
}
