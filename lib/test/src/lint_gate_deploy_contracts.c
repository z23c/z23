/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Content contracts for the deployment surface: `make deploy` binds its proof
 * to the binary it publishes, the dev-lane deploy and recovery-apply entry
 * points stay contained and refuse, and tools/agent_fast_ci.sh keeps its
 * changed-file to focused-test mapping, its gate order, and its refusal
 * behavior.
 *
 * These assert on the TEXT of the Makefile and the deploy scripts, so a rule
 * that is deleted or reworded fails here instead of shipping. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#ifdef ZCL_TESTING

#include "lint_gate_selftests.h"

int t_canonical_deploy_proof_binding_contract(void)
{
    int failures = 0;
    char *make_buf = NULL;
    char *verify_buf = NULL;
    TEST("canonical deploy freezes one source/artifact/process proof") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "Makefile") == 0);
        ASSERT(read_entire_file(path, &make_buf) == 0);

        const char *deploy_recipe = strstr(make_buf, "\ndeploy: vendor-ready");
        const char *seed_target = deploy_recipe
            ? strstr(deploy_recipe, "\nseed-anchor-snapshot:") : NULL;
        ASSERT(deploy_recipe != NULL);
        ASSERT(seed_target != NULL);
        const char *pinned_build = strstr(
            deploy_recipe,
            "$(MAKE) BUILD_SOURCE_RECORD=\"$(BUILD_SOURCE_RECORD)\" zclassic23");
        const char *frozen_candidate = pinned_build
            ? strstr(pinned_build, "candidate=\"$$(mktemp") : NULL;
        const char *agentbuild = frozen_candidate
            ? strstr(frozen_candidate,
                     "candidate_agentbuild=\"$$(timeout 30 \"$$candidate\" agentbuild")
            : NULL;
        const char *source_compare = agentbuild
            ? strstr(agentbuild,
                     "[ \"$$candidate_source_id\" = \"$(BUILD_SOURCE_ID)\" ]")
            : NULL;
        const char *record_verify = source_compare
            ? strstr(source_compare, "tools/dev/source-identity.sh verify-record")
            : NULL;
        const char *service_preserve = record_verify
            ? strstr(record_verify,
                     "deploy: preserving existing canonical service unit")
            : NULL;
        const char *launcher_guard = service_preserve
            ? strstr(service_preserve,
                     "service_path\" = \"$(CURDIR)/deploy/zclassic23-launch.sh")
            : NULL;
        const char *binary_target = launcher_guard
            ? strstr(launcher_guard,
                     "n == 2")
            : NULL;
        const char *candidate_install = record_verify
            ? strstr(record_verify,
                     "install -m 755 \"$$candidate\" \"$$SERVICE_BIN\"")
            : NULL;
        const char *restart = candidate_install
            ? strstr(candidate_install, "systemctl --user restart zclassic23")
            : NULL;
        const char *stage_bind = restart
            ? strstr(restart,
                     "ZCL_DEPLOY_STAGE=\"$(DEPLOY_VERIFY_STAGE)\"")
            : NULL;
        const char *proof = stage_bind
            ? strstr(stage_bind, "./tools/deploy_verify.sh") : NULL;
        ASSERT(pinned_build != NULL && pinned_build < seed_target);
        ASSERT(frozen_candidate != NULL && frozen_candidate < seed_target);
        ASSERT(agentbuild != NULL && agentbuild < seed_target);
        ASSERT(source_compare != NULL && source_compare < seed_target);
        ASSERT(record_verify != NULL && record_verify < seed_target);
        ASSERT(service_preserve != NULL && service_preserve < seed_target);
        ASSERT(launcher_guard != NULL && launcher_guard < seed_target);
        ASSERT(binary_target != NULL && binary_target < seed_target);
        ASSERT(strstr(binary_target,
                      "[ \"$$SERVICE_BIN\" = \"$(CURDIR)/build/bin/zclassic23\" ]")
               != NULL);
        ASSERT(candidate_install != NULL && candidate_install < seed_target);
        ASSERT(restart != NULL && restart < seed_target);
        ASSERT(stage_bind != NULL && stage_bind < seed_target);
        ASSERT(proof != NULL && proof < seed_target);
        ASSERT(strstr(deploy_recipe,
                      "DEPLOY_VERIFY_STAGE must be stable or challenger")
               != NULL);
        ASSERT(strstr(deploy_recipe, "rollback_armed=1") != NULL);
        const char *prior_capture = strstr(
            deploy_recipe,
            "install -m 755 \"/proc/$$mainpid/exe\" \"$$prior_tmp\"");
        const char *forced_relink = strstr(deploy_recipe,
                                           "rm -f $(ZCLASSIC23_BIN)");
        ASSERT(prior_capture != NULL);
        ASSERT(forced_relink != NULL);
        ASSERT(prior_capture < forced_relink);
        ASSERT(strstr(deploy_recipe,
                      "[ \"$$running_sha256\" = \"$$prior_sha256\" ]")
               != NULL);
        ASSERT(strstr(deploy_recipe,
                      "install -m 755 \"$$prior_snapshot\" \"$$rollback_bin\"")
               != NULL);
        ASSERT(strstr(deploy_recipe, "ZCL_DEPLOY_STAGE=rollback") != NULL);
        ASSERT(strstr(deploy_recipe, "deploy: ROLLED_BACK") != NULL);
        ASSERT(strstr(deploy_recipe,
                      "deploy: CRITICAL — rollback verification failed")
               != NULL);
        const char *nested_after_freeze = strstr(frozen_candidate, "$(MAKE)");
        ASSERT(nested_after_freeze == NULL || nested_after_freeze >= seed_target);
        ASSERT(strstr(candidate_install,
                      "[ \"$$installed_sha256\" = \"$$artifact_sha256\" ]")
               != NULL);

        ASSERT(repo_path(path, sizeof(path), "tools/deploy_verify.sh") == 0);
        ASSERT(read_entire_file(path, &verify_buf) == 0);
        ASSERT(strstr(verify_buf, "SERVICE_MAIN_PID") != NULL);
        ASSERT(strstr(verify_buf, "/proc/$SERVICE_MAIN_PID/cmdline") != NULL);
        ASSERT(strstr(verify_buf, "exec_argv_values_from_text") != NULL);
        ASSERT(strstr(verify_buf, "SERVICE_NODE_ARG") != NULL);
        ASSERT(strstr(verify_buf,
                      "SERVICE_NODE_EXE\" = \"$SERVICE_EXE") != NULL);
        ASSERT(strstr(verify_buf, "SERVICE_START_TICKS") != NULL);
        ASSERT(strstr(verify_buf, "service_pid_is_stable") != NULL);
        ASSERT(strstr(verify_buf, "mainpid_owns_rpc_listener") != NULL);
        ASSERT(strstr(verify_buf, "RPC_CONNECT=\"127.0.0.1\"") != NULL);
        ASSERT(strstr(verify_buf,
                      "out=$(rpc_call dumpstate \"\\\"$component\\\"\" \"\\\"$key\\\"\"")
               != NULL);
        ASSERT(strstr(verify_buf,
                      "out=$(rpc_call dumpstate \"$component\" \"$key\"")
               != NULL);
        ASSERT(strstr(verify_buf,
                      "unset ZCL_DATADIR ZCL_RPCPORT ZCL_RPCCONNECT") != NULL);
        ASSERT(strstr(verify_buf, "${ZCL_DATADIR:-") == NULL);
        ASSERT(strstr(verify_buf, "${ZCL_RPCPORT:-") == NULL);
        ASSERT(strstr(verify_buf, "${ZCL_RPCCONNECT:-") == NULL);
        ASSERT(strstr(verify_buf, "ZCL_DEPLOY_VERIFY_SELFTEST") != NULL);
        ASSERT(strstr(verify_buf, "ZCL_DEPLOY_STAGE") != NULL);
        ASSERT(strstr(verify_buf, "CHALLENGER_ACTIVE (unqualified)") != NULL);
        ASSERT(run_gate_script_with_env("tools/deploy_verify.sh",
                                        "ZCL_DEPLOY_VERIFY_SELFTEST", "1") == 0);
        PASS();
    } _test_next:;
    free(make_buf);
    free(verify_buf);
    return failures;
}

int t_dev_lane_deploy_contract(void)
{
    int failures = 0;
    char *script = NULL;
    char *guard = NULL;
    char *lane_health = NULL;
    char *lane_recover = NULL;
    char *agent_status = NULL;
    char *clear_script = NULL;
    char *agent_doctor = NULL;
    char *handoff = NULL;
    char *makefile = NULL;
    char *live_unit = NULL;
    char *soak_unit = NULL;
    char *dev_unit = NULL;
    char *standby_unit = NULL;
    char *boot_index = NULL;
    char *coldstart = NULL;
    char *coldstart_tip = NULL;
    TEST("dev lane deploy self-cleans stale reindex override") {
        char script_path[PATH_MAX];
        char guard_path[PATH_MAX];
        char lane_health_path[PATH_MAX];
        char lane_recover_path[PATH_MAX];
        char agent_status_path[PATH_MAX];
        char clear_script_path[PATH_MAX];
        char agent_doctor_path[PATH_MAX];
        char handoff_path[PATH_MAX];
        char makefile_path[PATH_MAX];
        char live_unit_path[PATH_MAX];
        char soak_unit_path[PATH_MAX];
        char dev_unit_path[PATH_MAX];
        char standby_unit_path[PATH_MAX];
        char boot_index_path[PATH_MAX];
        char coldstart_path[PATH_MAX];
        char coldstart_tip_path[PATH_MAX];
        ASSERT(repo_path(script_path, sizeof(script_path),
                         "tools/dev/deploy-dev-lane.sh") == 0);
        ASSERT(repo_path(guard_path, sizeof(guard_path),
                         "tools/deploy_guard.sh") == 0);
        ASSERT(repo_path(lane_health_path, sizeof(lane_health_path),
                         "tools/scripts/lane_health.sh") == 0);
        ASSERT(repo_path(lane_recover_path, sizeof(lane_recover_path),
                         "tools/scripts/lane_recover.sh") == 0);
        ASSERT(repo_path(agent_status_path, sizeof(agent_status_path),
                         "tools/dev/agent-dev-status.sh") == 0);
        ASSERT(repo_path(clear_script_path, sizeof(clear_script_path),
                         "tools/dev/agent-clear-stale-reindex.sh") == 0);
        ASSERT(repo_path(agent_doctor_path, sizeof(agent_doctor_path),
                         "tools/dev/agent-doctor.sh") == 0);
        ASSERT(repo_path(handoff_path, sizeof(handoff_path),
                         "docs/HANDOFF.md") == 0);
        ASSERT(repo_path(makefile_path, sizeof(makefile_path),
                         "Makefile") == 0);
        ASSERT(repo_path(live_unit_path, sizeof(live_unit_path),
                         "deploy/zclassic23.service") == 0);
        ASSERT(repo_path(soak_unit_path, sizeof(soak_unit_path),
                         "deploy/examples/zclassic23-soak-node.service") == 0);
        ASSERT(repo_path(dev_unit_path, sizeof(dev_unit_path),
                         "deploy/zcl23-dev.service") == 0);
        ASSERT(repo_path(standby_unit_path, sizeof(standby_unit_path),
                         "deploy/zclassic23-standby.service") == 0);
        ASSERT(repo_path(boot_index_path, sizeof(boot_index_path),
                         "config/src/boot_index.c") == 0);
        ASSERT(repo_path(coldstart_path, sizeof(coldstart_path),
                         "tools/scripts/cold_start_test.sh") == 0);
        ASSERT(repo_path(coldstart_tip_path, sizeof(coldstart_tip_path),
                         "tools/scripts/cold_start_to_tip_probe.sh") == 0);
        ASSERT(read_entire_file(script_path, &script) == 0);
        ASSERT(read_entire_file(guard_path, &guard) == 0);
        ASSERT(read_entire_file(lane_health_path, &lane_health) == 0);
        ASSERT(read_entire_file(lane_recover_path, &lane_recover) == 0);
        ASSERT(read_entire_file(agent_status_path, &agent_status) == 0);
        ASSERT(read_entire_file(clear_script_path, &clear_script) == 0);
        ASSERT(read_entire_file(agent_doctor_path, &agent_doctor) == 0);
        ASSERT(read_entire_file(handoff_path, &handoff) == 0);
        ASSERT(read_entire_file(makefile_path, &makefile) == 0);
        ASSERT(read_entire_file(live_unit_path, &live_unit) == 0);
        ASSERT(read_entire_file(soak_unit_path, &soak_unit) == 0);
        ASSERT(read_entire_file(dev_unit_path, &dev_unit) == 0);
        ASSERT(read_entire_file(standby_unit_path, &standby_unit) == 0);
        ASSERT(read_entire_file(boot_index_path, &boot_index) == 0);
        ASSERT(read_entire_file(coldstart_path, &coldstart) == 0);
        ASSERT(read_entire_file(coldstart_tip_path, &coldstart_tip) == 0);

        ASSERT(strstr(script, "STALE_REINDEX_DROPIN=") != NULL);
        ASSERT(strstr(script, "zcl23-dev.service.d/reindex.conf") != NULL);
        ASSERT(strstr(script, "ZCL_DEV_ALLOW_REINDEX_DROPIN") != NULL);
        ASSERT(strstr(script, "removing stale reindex drop-in") != NULL);
        ASSERT(strstr(script, "rm -f \"$STALE_REINDEX_DROPIN\"") != NULL);
        ASSERT(strstr(script, "STALE_OOM_BUDGET_DROPIN=") != NULL);
        ASSERT(strstr(script, "zcl23-dev.service.d/zz-oom-budget.conf") != NULL);
        ASSERT(strstr(script, "ZCL_DEV_ALLOW_OOM_BUDGET_DROPIN") != NULL);
        ASSERT(strstr(script, "removing stale memory-budget drop-in") != NULL);
        ASSERT(strstr(script, "deploy/zcl23-dev.service owns the dev lane memory budget") != NULL);
        ASSERT(strstr(script, "rm -f \"$STALE_OOM_BUDGET_DROPIN\"") != NULL);
        ASSERT(strstr(script, "AUTO_REINDEX_SENTINEL=") != NULL);
        ASSERT(strstr(script, "auto_reindex_request") != NULL);
        ASSERT(strstr(script, "auto_reindex_status") != NULL);
        ASSERT(strstr(script, "guard_pending_auto_reindex") != NULL);
        ASSERT(strstr(script, "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY") != NULL);
        ASSERT(strstr(script, "unreadable auto-reindex marker") != NULL);
        ASSERT(strstr(script, "ignoring malformed auto-reindex marker") != NULL);
        ASSERT(strstr(script, "pending crash-only auto-reindex request")
               != NULL);
        ASSERT(strstr(script, "refusing to start or hot-swap the dev lane")
               != NULL);
        ASSERT(strstr(script, "pre_rpc_boot_diagnostic") != NULL);
        ASSERT(strstr(script, "pre-RPC recovery: reindex-chainstate")
               != NULL);
        ASSERT(strstr(script, "boot diagnostic: $diag") != NULL);
        ASSERT(strstr(script, "DEPLOY_STATE=") != NULL);
        ASSERT(strstr(script, "agent-deploy.json") != NULL);
        ASSERT(strstr(script, "write_deploy_state") != NULL);
        ASSERT(strstr(script, "zcl.agent_dev_deploy.v1") != NULL);
        ASSERT(strstr(script, "\"verify_status\"") != NULL);
        ASSERT(strstr(script, "\"auto_reindex_pending\"") != NULL);
        ASSERT(strstr(script, "deploy state: $DEPLOY_STATE") != NULL);
        ASSERT(strstr(script, "BUILD_ID_DROPIN=") != NULL);
        ASSERT(strstr(script, "zcl23-dev.service.d/90-build-identity.conf") != NULL);
        ASSERT(strstr(script, "ZCL_AGENT_EXPECT_BUILD_COMMIT") != NULL);
        ASSERT(strstr(script, "ZCL_AGENT_EXPECT_BUILD_SOURCE=deploy-dev") != NULL);
        ASSERT(strstr(script, "ZCL_DEV_DEPLOY_BUILD") != NULL);
        ASSERT(strstr(script, "make fast-rebuild") != NULL);
        ASSERT(strstr(script, "build/bin/z23-dev") != NULL);
        ASSERT(strstr(script, "case \"$DEV_DEPLOY_BUILD\"") != NULL);
        ASSERT(strstr(script, "strict)") != NULL);
        ASSERT(strstr(script,
                      "\"$CANDIDATE_BIN\" --importblockindex \"$LEGACY_SRC\"")
               != NULL);
        ASSERT(strstr(script,
                      "\"$CANDIDATE_BIN\" -datadir=\"$DEV_DATADIR\" --importblockindex")
               == NULL);
        ASSERT(strstr(script, "\"$DEV_DATADIR/node.db\"") != NULL);
        ASSERT(strstr(makefile, "deploy-dev-fast agent-deploy-fast") != NULL);
        ASSERT(strstr(script, "probe_agent_contract") != NULL);
        ASSERT(strstr(script, "ZCL_DEV_AGENT_TIMEOUT") != NULL);
        ASSERT(strstr(script, "agent_work_ready") != NULL);
        ASSERT(strstr(script, "chain_serving_ready") != NULL);
        ASSERT(strstr(script, "AGENT READY") != NULL);
        ASSERT(strstr(script, "BLOCKED: agent status=") != NULL);
        ASSERT(strstr(script, "SYNC OK") != NULL);
        ASSERT(strstr(script, "HEALTHY:") == NULL);
        ASSERT(strstr(agent_status, "\"deploy_blocker\"") != NULL);
        ASSERT(strstr(agent_status, "\"worker_lane\"") != NULL);
        ASSERT(strstr(agent_status, "\"role\":\"worker\"") != NULL);
        ASSERT(strstr(agent_status, "noncanonical_dev_only") != NULL);
        ASSERT(strstr(agent_status, "never_touches_live_or_soak") != NULL);
        ASSERT(strstr(agent_status, "\"runtime_publication\":false") != NULL);
        ASSERT(strstr(agent_status, "publication_blocker") != NULL);
        ASSERT(strstr(agent_status, "source identity is not activation authority")
               != NULL);
        ASSERT(strstr(agent_status, "make agent-dev-recover") != NULL);
        ASSERT(strstr(agent_status,
                      "pending_auto_reindex_requires_explicit_recovery_boot")
               != NULL);
        ASSERT(strstr(agent_status,
                      "auto_reindex_stale_candidate") != NULL);
        ASSERT(strstr(agent_status,
                      "make agent-clear-stale-dev-reindex") != NULL);
        ASSERT(strstr(agent_status,
                      "recovery_apply_authority") != NULL);
        ASSERT(strstr(agent_status,
                      "contained; no environment override") != NULL);
        ASSERT(strstr(clear_script, "zcl.agent_dev_reindex_clear.v1") != NULL);
        ASSERT(strstr(clear_script, "stale_marker_proven") != NULL);
        ASSERT(strstr(clear_script, "marker_anchor_above_served_height")
               != NULL);
        ASSERT(strstr(clear_script, "mv \"$MARKER\" \"$archive\"") != NULL);
        ASSERT(strstr(clear_script, "systemctl --user show") != NULL);
        ASSERT(strstr(clear_script, "getblockcount") != NULL);
        ASSERT(strstr(clear_script, "python") == NULL);
        ASSERT(strstr(agent_doctor, "deploy_blocker=") != NULL);
        ASSERT(strstr(makefile, "agent-clear-stale-dev-reindex:") != NULL);
        ASSERT(strstr(makefile,
                      "tools/dev/agent-clear-stale-reindex.sh") != NULL);
        ASSERT(strstr(script, "systemctl --user daemon-reload") != NULL);
        ASSERT(strstr(makefile,
                      "./tools/deploy_guard.sh canonical-deploy") != NULL);
        ASSERT(strstr(makefile,
                      "zclassic23.service.d/90-build-identity.conf") != NULL);
        ASSERT(strstr(makefile,
                      "ZCL_AGENT_EXPECT_BUILD_SOURCE=make-deploy") != NULL);
        ASSERT(strstr(makefile,
                      "bash tools/scripts/cold_start_test.sh; rc=$$?")
               != NULL);
        ASSERT(strstr(makefile,
                      "$(MAKE) --no-print-directory ci-coldstart; rc=$$?")
               == NULL);
        ASSERT(strstr(makefile,
                      "GNU make returns 2 for a failed recipe") != NULL);
        ASSERT(strstr(coldstart, "SRC_BUNDLE_SNAP_CANDIDATES") != NULL);
        ASSERT(strstr(coldstart, "-load-snapshot-at-own-height") != NULL);
        ASSERT(strstr(coldstart, "grep -m1 -F -- \"$BUNDLE_SUCCESS_PATTERN\"")
               != NULL);
        ASSERT(strstr(coldstart, "fast_rebuild_authority_ready") != NULL);
        ASSERT(strstr(coldstart, "consensus_snapshot.db above the compiled checkpoint")
               != NULL);
        ASSERT(strstr(coldstart, "python") == NULL);
        ASSERT(strstr(coldstart_tip, "BUNDLE_SNAP_CANDIDATES") != NULL);
        ASSERT(strstr(coldstart_tip, "CONSENSUS_BUNDLE_CANDIDATES") != NULL);
        ASSERT(strstr(coldstart_tip, "127.0.0.1:8033") != NULL);
        ASSERT(strstr(coldstart_tip, "-load-snapshot-at-own-height") != NULL);
        ASSERT(strstr(coldstart_tip, "BUNDLE_SUCCESS_PATTERN") != NULL);
        ASSERT(strstr(coldstart_tip, "consensus-state-bundle") != NULL);
        ASSERT(strstr(coldstart_tip, "zclassic23-bundle-bootstrap.sh") != NULL);
        ASSERT(strstr(coldstart_tip, "self_respawn_") != NULL);
        ASSERT(strstr(coldstart_tip, "--selftest") != NULL);
        ASSERT(strstr(coldstart_tip, "ZCL_C3_FILE_PEER") != NULL);
        ASSERT(strstr(coldstart_tip, "-fileservice") != NULL);
        ASSERT(strstr(coldstart_tip, "zcl.c3_probe_artifact.v2") != NULL);
        ASSERT(strstr(coldstart_tip, "proof.json") != NULL);
        ASSERT(strstr(coldstart_tip, "\"seed_authority_loaded\"") != NULL);
        ASSERT(strstr(coldstart_tip, "\"reached_at_tip\"") != NULL);
        ASSERT(strstr(coldstart_tip,
                      "write_artifact \"skip\" 2 \"$*\"") != NULL);
        ASSERT(strstr(coldstart_tip,
                      "seed authority loaded but forward-sync did not complete")
               != NULL);
        ASSERT(strstr(coldstart_tip, "python") == NULL);
        ASSERT(strstr(makefile, "mvp-coldstart-to-tip-local:") != NULL);
        ASSERT(strstr(makefile, "tools/scripts/cold_start_to_tip_probe.sh")
               != NULL);
        ASSERT(strstr(makefile,
                      "cold_start_to_tip_probe.sh --selftest") != NULL);
        ASSERT(strstr(makefile, "lane-recover:") != NULL);
        ASSERT(strstr(makefile, "tools/scripts/lane_recover.sh") != NULL);
        ASSERT(strstr(guard, "ZCL_DEPLOY_ALLOW_CANONICAL") != NULL);
        ASSERT(strstr(guard, "zcl.agent_deploy_guard.v1") != NULL);
        ASSERT(strstr(guard, "agentdeployguard") != NULL);
        ASSERT(strstr(guard, "ZCL_DEPLOY_GUARD_NATIVE_JSON") != NULL);
        ASSERT(strstr(guard,
                      "ZCL_DEPLOY_GUARD_RPC_TOOL=/nonexistent-zclassic23")
               != NULL);
        ASSERT(strstr(guard, "python") == NULL);
        ASSERT(strstr(guard, "systemctl --user show") != NULL);
        ASSERT(strstr(guard, "-operator-lane") != NULL);
        ASSERT(strstr(guard, "native agentdeployguard blocks") != NULL);
        ASSERT(strstr(guard, "allowed") != NULL);
        ASSERT(strstr(guard, "deploy-dev") != NULL);
        ASSERT(strstr(guard, "restart-dev") != NULL);
        ASSERT(run_gate_script_with_env("tools/deploy_guard.sh",
                                        "ZCL_DEPLOY_GUARD_SELFTEST",
                                        "1") == 0);
        ASSERT(strstr(lane_recover, "zcl.lane_recovery_plan.v1") != NULL);
        ASSERT(strstr(lane_recover, "ZCL_LANE_RECOVERY_SELFTEST") != NULL);
        ASSERT(strstr(lane_recover, "canonical/live/main recovery is not supported")
               != NULL);
        ASSERT(strstr(lane_recover, "copy_seed_install_loader_restart") != NULL);
        ASSERT(strstr(lane_recover, "install_loader_dropin_restart") != NULL);
        ASSERT(strstr(lane_recover, "import_headers_install_loader_restart")
               != NULL);
        ASSERT(strstr(lane_recover, "ZCL_LANE_RECOVERY_IMPORT_HEADERS")
               != NULL);
        ASSERT(strstr(lane_recover,
                      "ZCL_LANE_RECOVERY_ALLOW_STALE_HEADER_IMPORT")
               != NULL);
        ASSERT(strstr(lane_recover,
                      "header_import_skipped_snapshot_not_newer")
               != NULL);
        ASSERT(strstr(lane_recover, "runtime_recovery_contained") != NULL);
        ASSERT(strstr(lane_recover, "\"runtime_publication\":false")
               != NULL);
        ASSERT(strstr(lane_recover, "\"mutation_contained\":true")
               != NULL);
        ASSERT(strstr(lane_recover, "\"apply_authority\":\"none\"")
               != NULL);
        ASSERT(strstr(lane_recover, "refuse_public_apply") != NULL);
        ASSERT(strstr(lane_recover, "selftest_apply_refused") != NULL);
        ASSERT(strstr(lane_recover, "ZCL_LANE_RECOVERY_IMPORT_TIMEOUT")
               == NULL);
        ASSERT(strstr(lane_recover, "--importblockindex") == NULL);
        ASSERT(strstr(lane_recover, "ZCL_LANE_SNAPSHOT_LOADER_FLAG") == NULL);
        ASSERT(strstr(lane_recover, "systemctl") == NULL);
        ASSERT(strstr(lane_recover, "ZCL_LANE_RECOVERY_SEED_SOURCE") != NULL);
        ASSERT(strstr(lane_recover, "ZCL_LANE_RECOVERY_LEGACY_SRC") == NULL);
        ASSERT(strstr(lane_recover, "python") == NULL);
        ASSERT(run_gate_script_with_env("tools/scripts/lane_recover.sh",
                                        "ZCL_LANE_RECOVERY_SELFTEST",
                                        "1") == 0);
        ASSERT(strstr(live_unit, "-operator-lane=canonical") != NULL);
        ASSERT(strstr(live_unit, "TimeoutStartSec=14400") != NULL);
        ASSERT(strstr(live_unit,
                      "Environment=\"ZCL_EXTERNALIP_FLAG=\"") != NULL);
        ASSERT(strstr(live_unit,
                      "Environment=\"ZCL_ADDNODE_FLAGS=\"") != NULL);
        const char *bundle_default =
            strstr(live_unit,
                   "Environment=\"ZCL_CHECKPOINT_BUNDLE_SOURCE=\"");
        const char *operator_env =
            strstr(live_unit,
                   "EnvironmentFile=-%h/.config/zclassic23/env");
        ASSERT(bundle_default != NULL);
        ASSERT(operator_env != NULL);
        ASSERT(bundle_default != NULL && operator_env != NULL
               && bundle_default < operator_env);
        ASSERT(strstr(soak_unit, "-operator-lane=soak") != NULL);
        ASSERT(strstr(dev_unit, "-operator-lane=dev") != NULL);
        ASSERT(strstr(soak_unit, "$ZCL_LANE_SNAPSHOT_LOADER_FLAG") != NULL);
        ASSERT(strstr(dev_unit, "$ZCL_LANE_SNAPSHOT_LOADER_FLAG") != NULL);
        ASSERT(strstr(boot_index,
                      "boot_promote_tip_preserving_header_via_csr") != NULL);
        ASSERT(strstr(boot_index, "\"utxo_chain_mismatch\"") != NULL);
        ASSERT(strstr(handoff, "Public daily-driver node") != NULL);
        ASSERT(strstr(handoff, "Isolated build/test lane")
               != NULL);
        ASSERT(strstr(handoff, "Long-uptime / weekly evidence lane") != NULL);
        ASSERT(strstr(handoff, "zcl.operator_lane.v1") != NULL);
        ASSERT(strstr(handoff, "Phase-0 contained") != NULL);
        ASSERT(strstr(lane_health, "report_lane live zclassic23") != NULL);
        ASSERT(strstr(lane_health, "report_lane soak zclassic23-soak") != NULL);
        ASSERT(strstr(lane_health, "report_lane dev zcl23-dev") != NULL);
        ASSERT(strstr(lane_health, "forced_reindex_flag_present") != NULL);
        ASSERT(strstr(lane_health, "dev_booting_rpc_down") != NULL);
        ASSERT(strstr(lane_health, "ZCL_LANE_LAG_WARN") != NULL);
        ASSERT(strstr(lane_health, "ZCL_LANE_AGENT_TIMEOUT") != NULL);
        ASSERT(strstr(lane_health, "rpc_call_timeout") != NULL);
        ASSERT(strstr(lane_health, "ZCL_SOAK_LAG_WARN") != NULL);
        ASSERT(strstr(lane_health, "tip_lag_to_live") != NULL);
        ASSERT(strstr(lane_health, "getblockchaininfo") != NULL);
        ASSERT(strstr(lane_health, "chain_headers") != NULL);
        ASSERT(strstr(lane_health, "initialblockdownload") != NULL);
        ASSERT(strstr(lane_health, "lag_to_live_") != NULL);
        ASSERT(strstr(lane_health, "dumpstate reducer_frontier") != NULL);
        ASSERT(strstr(lane_health, "dumpstate condition_engine") != NULL);
        ASSERT(strstr(lane_health,
                      "dumpstate chain_advance_coordinator") != NULL);
        ASSERT(strstr(lane_health, "ZCL_LANE_HEALTH_SELFTEST") != NULL);
        ASSERT(strstr(lane_health, "json_first_bool_field") != NULL);
        ASSERT(strstr(lane_health, "agent_build_commit") != NULL);
        ASSERT(strstr(lane_health, "agent_rpc_state") != NULL);
        ASSERT(strstr(lane_health, "agent_timeout") != NULL);
        ASSERT(strstr(lane_health, "inspect_agent_timeout") != NULL);
        ASSERT(strstr(lane_health, "agent_contract_trusted") != NULL);
        ASSERT(strstr(lane_health, "agent_operator_needed") != NULL);
        ASSERT(strstr(lane_health, "agent_primary_blocker") != NULL);
        ASSERT(strstr(lane_health, "agent_validation_pack_ok") != NULL);
        ASSERT(strstr(lane_health, "agent_blocked") != NULL);
        ASSERT(strstr(lane_health, "inspect_agent_primary_blocker") != NULL);
        ASSERT(strstr(lane_health, "condition_operator_needed") != NULL);
        ASSERT(strstr(lane_health, "inspect_condition_engine") != NULL);
        ASSERT(run_gate_script_with_env("tools/scripts/lane_health.sh",
                                        "ZCL_LANE_HEALTH_SELFTEST",
                                        "1") == 0);
        ASSERT(strstr(lane_health, "chain_advance_current_json") != NULL);
        ASSERT(strstr(lane_health, "\\\"last_decision\\\"") != NULL);
        ASSERT(strstr(lane_health, "reducer_hstar") != NULL);
        ASSERT(strstr(lane_health, "reducer_pending_stage") != NULL);
        ASSERT(strstr(lane_health, "reducer_pending_detail") != NULL);
        ASSERT(strstr(lane_health, "projection_height") != NULL);
        ASSERT(strstr(lane_health, "projection_lag") != NULL);
        ASSERT(strstr(lane_health, "projection_deferred") != NULL);
        ASSERT(strstr(lane_health, "inspect_chain_advance_coordinator")
               != NULL);
        ASSERT(strstr(lane_health, "condition_active_count") != NULL);
        ASSERT(strstr(lane_health, "condition_operator_needed_count") != NULL);
        ASSERT(strstr(lane_health, "no_peers") != NULL);
        ASSERT(strstr(lane_health, "memory_pressure") != NULL);
        ASSERT(strstr(lane_health, "bootstrapstatus") != NULL);
        ASSERT(strstr(lane_health, "snapshot_seed_height") != NULL);
        ASSERT(strstr(lane_health, "snapshot_loader_configured") != NULL);
        ASSERT(strstr(lane_health, "snapshot_loader_path") != NULL);
        ASSERT(strstr(lane_health, "recovery_hint") != NULL);
        ASSERT(strstr(lane_health, "restart_with_load_snapshot_at_own_height")
               != NULL);
        ASSERT(strstr(lane_health, "install_tip_seed_snapshot") != NULL);
        ASSERT(strstr(lane_health, "inspect_reducer_frontier") != NULL);
        ASSERT(strstr(lane_health, "role_ready") != NULL);
        ASSERT(strstr(lane_health, "role_reason") != NULL);
        ASSERT(strstr(lane_health, "canonical_ready") != NULL);
        ASSERT(strstr(lane_health, "soak_evidence_ready") != NULL);
        ASSERT(strstr(lane_health, "dev_lane_ready") != NULL);
        ASSERT(strstr(lane_health, "soak_eligible") != NULL);
        ASSERT(strstr(lane_health, "soak_reason") != NULL);
        ASSERT(strstr(lane_health, "live_reference_missing") != NULL);
        ASSERT(strstr(lane_health, "REDUNDANCY canonical=") != NULL);
        ASSERT(strstr(lane_health, "--strict") != NULL);
        ASSERT(strstr(makefile, "lane-health:") != NULL);
        ASSERT(strstr(makefile, "tools/scripts/lane_health.sh") != NULL);
        ASSERT(strstr(handoff, "make lane-health") != NULL);
        ASSERT(strstr(handoff, "make lane-recover") != NULL);
        ASSERT(strstr(handoff, "read-only three-lane status check") != NULL);
        ASSERT(strstr(handoff, "lag from the live lane") != NULL);
        ASSERT(strstr(handoff, "memory pressure") != NULL);
        ASSERT(strstr(handoff, "bootstrapstatus.snapshot_loader") != NULL);
        ASSERT(strstr(handoff, "snapshot seed height") != NULL);
        ASSERT(strstr(handoff, "recovery_hint") != NULL);
        ASSERT(strstr(handoff, "role readiness") != NULL);
        ASSERT(strstr(handoff, "soak-evidence") != NULL);
        ASSERT(strstr(handoff, "soak_eligible=false") != NULL);
        ASSERT(strstr(standby_unit, "Environment=STANDBY_FSPORT=18054")
               != NULL);
        ASSERT(strstr(standby_unit, "Environment=STANDBY_HTTPSPORT=18443")
               != NULL);
        ASSERT(strstr(standby_unit, "-fsport=${STANDBY_FSPORT}") != NULL);
        ASSERT(strstr(standby_unit, "-httpsport=${STANDBY_HTTPSPORT}")
               != NULL);
        PASS();
    } _test_next:;
    free(script);
    free(guard);
    free(lane_health);
    free(lane_recover);
    free(agent_status);
    free(clear_script);
    free(agent_doctor);
    free(handoff);
    free(makefile);
    free(live_unit);
    free(soak_unit);
    free(dev_unit);
    free(standby_unit);
    free(boot_index);
    free(coldstart);
    free(coldstart_tip);
    return failures;
}

int t_agent_fast_ci_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    char *rules = NULL;
    char *main_src = NULL;
    char *arch_doc = NULL;
    TEST("agent fast CI stays cache-aware and native-service first") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "Makefile") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "fast-ci agent-fast-ci dev-ci") != NULL);
        ASSERT(strstr(buf, "t-fast") != NULL);
        ASSERT(strstr(buf, "test_parallel_fast") != NULL);
        ASSERT(strstr(buf, "fast-compile dev-build-only") != NULL);
        ASSERT(strstr(buf, "fast-changed-compile") != NULL);
        ASSERT(strstr(buf, "dev-bin z23-dev zclassic23-dev") != NULL);
        ASSERT(strstr(buf,
                      "fast-rebuild rebuild-fast dev-rebuild "
                      "hot-rebuild super-rebuild") != NULL);
        ASSERT(strstr(buf, "agent-loop agent-dev-loop") != NULL);
        ASSERT(strstr(buf, "ZCL_AGENT_LOOP_BIN") != NULL);
        ASSERT(strstr(buf, "ZCL_AGENT_LOOP_DEPLOY") != NULL);
        ASSERT(strstr(buf, "ZCL_AGENT_LOOP_DEPLOY=stage") != NULL);
        ASSERT(strstr(buf, "$(MAKE) agent-stage-dev") != NULL);
        ASSERT(strstr(buf, "$(MAKE) agent-deploy-fast") != NULL);
        ASSERT(strstr(buf, "tools/agent_fast_ci.sh rebuild-dev") != NULL);
        ASSERT(strstr(buf, "ZCLASSIC23_DEV_BIN") != NULL);
        ASSERT(strstr(buf, "DEV_OBJ_DIR") != NULL);
        ASSERT(strstr(buf, "DEV_CFLAGS") != NULL);
        ASSERT(strstr(buf, "DEV_HOT_CFLAGS") != NULL);
        ASSERT(strstr(buf, "DEV_LDFLAGS") != NULL);
        ASSERT(strstr(buf, "ZCL_DEV_LINKER") != NULL);
        ASSERT(strstr(buf, "command -v sccache") != NULL);
        ASSERT(strstr(buf, "DEV_OBJ_COMPLETE") != NULL);
        ASSERT(strstr(buf, ".complete") != NULL);
        ASSERT(strstr(buf, "DEV_COMPILE_EPOCH") != NULL);
        ASSERT(strstr(buf, "BUILD_MUTATION") != NULL);
        ASSERT(strstr(buf, "BUILD_COMPILER_ID") != NULL);
        ASSERT(strstr(buf, "compile-epoch-object.sh") != NULL);
        ASSERT(strstr(buf, "publish-build-alias.sh") != NULL);
        ASSERT(strstr(buf, "build-epoch-selftest.sh") != NULL);
        ASSERT(strstr(buf, "check-build-epoch-integrity") != NULL);
        ASSERT(strstr(buf, "COV_CFLAGS = $(filter-out -flto -flto=%")
               != NULL);
        ASSERT(strstr(buf, "coverage-locked: coverage-clean") == NULL);
        ASSERT(strstr(buf,
                      "coverage-locked:\n\t@test \"$(ZCL_COVERAGE_LOCKED)\" = 1")
               != NULL);
        ASSERT(strstr(buf,
                      "test-zcl-cov-locked:\n\t@test \"$(ZCL_COVERAGE_LOCKED)\" = 1")
               != NULL);
        ASSERT(strstr(buf, "not for release/deploy") != NULL);
        ASSERT(strstr(buf, "tools/agent_fast_ci.sh") != NULL);
        ASSERT(strstr(buf, "tools/deploy_guard.sh") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_TESTS") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_LIVE=0") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE=0") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE_RESET=1") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_FILE") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_ONLY") != NULL);
        ASSERT(strstr(buf, "pre-push-ci") != NULL);
        ASSERT(strstr(buf, "agent-plan") != NULL);
        ASSERT(strstr(buf, "tools/agent_fast_ci.sh plan-json") != NULL);
        ASSERT(strstr(buf,
                      "immutable-history-canaries historical-canaries")
               != NULL);
        ASSERT(strstr(buf, "domain_consensus_tx_structural") != NULL);
        ASSERT(strstr(buf, "consensus_parity") != NULL);
        ASSERT(strstr(buf, "replay-canary-anchor") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_LIVE=0 ZCL_FAST_COMPILE=strict")
               != NULL);
        ASSERT(strstr(buf, "tools/agent_fast_ci.sh pre-push") != NULL);
        ASSERT(strstr(buf,
                      "ZCL_FAST_LIVE=0 ZCL_FAST_COMPILE=strict $(MAKE) fast-ci")
               == NULL);
        ASSERT(strstr(buf, "check-agent-cli: zclassic23") != NULL);
        ASSERT(strstr(buf,
                      "tools/scripts/check_agentdeployguard_cli_exit.sh")
               != NULL);
        ASSERT(strstr(buf, "install-quality-linger") != NULL);
        ASSERT(strstr(buf, "quality-linger-status") != NULL);
        ASSERT(strstr(buf, "tools/scripts/background_quality_lane.sh") != NULL);
        ASSERT(strstr(buf, "background-tests") != NULL);
        ASSERT(strstr(buf, "zclassic23-test-suite.timer") != NULL);
        ASSERT(strstr(buf, "agent-dev-status") != NULL);
        ASSERT(strstr(buf, "agent-doctor") != NULL);
        ASSERT(strstr(buf, "tools/dev/agent-dev-status.sh") != NULL);
        ASSERT(strstr(buf, "tools/dev/agent-doctor.sh") != NULL);
        ASSERT(strstr(buf, "stage-dev-bin agent-stage-dev") != NULL);
        ASSERT(strstr(buf, "agent-stage-dev: REFUSING") != NULL);
        ASSERT(strstr(buf, "agent-deploy-fast: REFUSING") != NULL);
        ASSERT(strstr(buf,
                      "runtime publication is contained pending transactional")
               != NULL);
        ASSERT(strstr(buf, "ZCL_DEV_USE_PREBUILT=1") == NULL);
        ASSERT(strstr(buf, "deploy-dev-lane.sh --stage") == NULL);
        ASSERT(strstr(buf, "mktemp \"$(ZCL_AGENT_DEV_BIN).next.XXXXXX\"")
               == NULL);
        ASSERT(strstr(buf, "ZCL_AGENT_BIN") != NULL);
        ASSERT(strstr(buf, "ZCL_AGENT_DEV_BIN") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "tools/dev/agent-doctor.sh") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "zcl.agent_doctor.v1") != NULL);
        ASSERT(strstr(buf, "latest_test_artifact_mtime") != NULL);
        ASSERT(strstr(buf, "build/bin/test_parallel_fast") != NULL);
        ASSERT(strstr(buf, "build/bin/test_parallel") != NULL);
        ASSERT(strstr(buf, "build/bin/test_zcl") != NULL);
        ASSERT(strstr(buf, "latest_failure_log") != NULL);
        ASSERT(strstr(buf, "cutoff_mtime") != NULL);
        free(buf);
        buf = NULL;

        /* src/main.c delegates typed commands to the native registry. */
        ASSERT(repo_path(path, sizeof(path), "src/main.c") == 0);
        ASSERT(read_entire_file(path, &main_src) == 0);
        ASSERT(strstr(main_src, "node_rpc_client_init") == NULL);

        ASSERT(repo_path(path, sizeof(path),
                         "docs/AGENT_ARCHITECTURE.md") == 0);
        ASSERT(read_entire_file(path, &arch_doc) == 0);
        ASSERT(strstr(arch_doc, "REST resource first") != NULL);
        ASSERT(strstr(arch_doc, "ActiveRecord lifecycle") != NULL);
        ASSERT(strstr(arch_doc, "validates_*") != NULL);
        ASSERT(strstr(arch_doc, "Make relationships explicit C APIs")
               != NULL);
        ASSERT(strstr(arch_doc, "database_schema.c") != NULL);
        ASSERT(strstr(arch_doc, "api_controller_routes.c") != NULL);
        /* The doc leads with the native typed command registry. */
        ASSERT(strstr(arch_doc, "Terminal agents should prefer native "
                                "commands") != NULL);
        ASSERT(strstr(arch_doc, "`z23 status`") != NULL);
        ASSERT(strstr(arch_doc, "z23 dumpstate <subsystem>")
               != NULL);
        ASSERT(strstr(arch_doc, "z23 discover help") != NULL);
        ASSERT(strstr(arch_doc, "z23-dev status") != NULL);
        ASSERT(strstr(arch_doc, "make agent-dev-status") != NULL);

        ASSERT(repo_path(path, sizeof(path), "tools/agent_fast_ci.sh") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "zcl.agent_fast_ci.v1") != NULL);
        ASSERT(strstr(buf, "zcl.agent_fast_plan.v1") != NULL);
        ASSERT(strstr(buf, "zcl.agent_changed_compile_plan.v2") != NULL);
        ASSERT(strstr(buf, "zcl.agent_fast_ci.cache.v4") != NULL);
        ASSERT(strstr(buf, "emit_plan_json") != NULL);
        ASSERT(strstr(buf, "recommended_command") != NULL);
        ASSERT(strstr(buf, "native_shortcuts") != NULL);
        ASSERT(strstr(buf, "z23 <leaf> [--input=json]") != NULL);
        ASSERT(strstr(buf, "z23-dev <leaf> [--input=json]") != NULL);
        ASSERT(strstr(buf, "green_input_cache") != NULL);
        ASSERT(strstr(buf, "sccache cc") != NULL);
        ASSERT(strstr(buf, "ccache cc") != NULL);
        ASSERT(strstr(buf, "git diff --check") != NULL);
        ASSERT(strstr(buf, "make_fast watcher-safety-gates") != NULL);
        ASSERT(strstr(buf, "git ls-files --others --exclude-standard")
               != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_FILE") != NULL);
        ASSERT(strstr(buf, "hints must not fragment identical evidence")
               != NULL);
        ASSERT(strstr(buf, "printf 'fast_changed_files_file") == NULL);
        ASSERT(strstr(buf, "fast_changed_files_only()") != NULL);
        ASSERT(strstr(buf, "validate_changed_files_only") != NULL);
        ASSERT(strstr(buf, "impact_rules_file") != NULL);
        ASSERT(strstr(buf, "bash -n \"$script\"") != NULL);
        ASSERT(strstr(buf, "tools/deploy_guard.sh") != NULL);
        ASSERT(strstr(buf, "tools/dev/deploy-dev-lane.sh") != NULL);
        ASSERT(strstr(buf, "tools/dev/agent-dev-status.sh") != NULL);
        ASSERT(strstr(buf,
                      "tools/scripts/check_agentdeployguard_cli_exit.sh")
               != NULL);
        ASSERT(strstr(buf, "make_fast lint-fast") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_COMPILE") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_ONLY") != NULL);
        ASSERT(strstr(buf, "FAST_COMPILE=\"${ZCL_FAST_COMPILE:-changed}\"")
               != NULL);
        ASSERT(strstr(buf, "compile_changed_gate") != NULL);
        ASSERT(strstr(buf, "compute_changed_compile_plan") != NULL);
        ASSERT(strstr(buf, "is_graph_wide_compile_change") != NULL);
        ASSERT(strstr(buf, "is_direct_dependency_compile_change") == NULL);
        ASSERT(strstr(buf, "dev_depfiles_available") == NULL);
        ASSERT(strstr(buf, "add_dependent_dev_objects") == NULL);
        ASSERT(strstr(buf, "full_source_inventory") != NULL);
        ASSERT(strstr(buf, "proof_scope") != NULL);
        ASSERT(strstr(buf, "is_node_c_source") != NULL);
        ASSERT(strstr(buf, "classification_only") != NULL);
        ASSERT(strstr(buf, "fast-changed-compile: source-wide fast-compile")
               != NULL);
        ASSERT(strstr(buf, "path lists are classification hints only") != NULL);
        ASSERT(strstr(buf, "run_compile_gate") != NULL);
        ASSERT(strstr(buf, "changed|changed-dev|auto") != NULL);
        ASSERT(strstr(buf, "target=\"fast-compile\"") != NULL);
        ASSERT(strstr(buf, "target=\"build-only\"") != NULL);
        ASSERT(strstr(buf, "make_fast \"$target\"") != NULL);
        ASSERT(strstr(buf, "fast_compile") != NULL);
        ASSERT(strstr(buf, "UNMAPPED_CODE_CHANGES") != NULL);
        ASSERT(strstr(buf, "classification hints without focused mappings")
               != NULL);
        ASSERT(strstr(buf, "source-wide proof scope is unchanged") != NULL);
        ASSERT(strstr(buf, "fail_on_unmapped_code_changes") == NULL);
        ASSERT(strstr(buf, "IMPACT_RULES_FILE") != NULL);
        ASSERT(strstr(buf, "agent_impact_rules.def") != NULL);
        ASSERT(strstr(buf, "match_shared_impact_rules") != NULL);
        ASSERT(strstr(buf, "target=\"test-parallel-fast-active\"") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_STRICT_TESTS") != NULL);
        ASSERT(strstr(buf, "make_fast \"$target\"") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_JOBS") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_NODE_BIN:-build/bin/z23}") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_DEV_NODE_BIN:-build/bin/z23-dev}") != NULL);
        ASSERT(strstr(buf, "run_dev_rebuild") != NULL);
        ASSERT(strstr(buf, "dev-bin link target=$DEV_NODE_BIN") != NULL);
        ASSERT(strstr(buf,
                      "rebuild-dev|dev-rebuild|fast-rebuild|hot-rebuild")
               != NULL);
        ASSERT(strstr(buf, "zcl.public_status.v3") != NULL);
        ASSERT(strstr(buf, ".status == \"healthy\"") != NULL);
        ASSERT(strstr(buf, ".healthy == true") != NULL);
        ASSERT(strstr(buf, "((.gap // 0) <= 1)") == NULL);
        ASSERT(strstr(buf, "agent probe summary") != NULL);
        ASSERT(strstr(buf, "healthcheck") != NULL);
        ASSERT(strstr(buf, ".checks.has_peers == true") != NULL);
        ASSERT(strstr(buf, "health probe summary") != NULL);
        ASSERT(strstr(buf, "native service binary") != NULL);
        ASSERT(strstr(buf, "run make build-only or set ZCL_FAST_LIVE=0")
               != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_TESTS") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_COMPILE") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_LIVE") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE_RESET") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE_DIR") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_ONLY") != NULL);
        ASSERT(strstr(buf, "fast result cache hit") != NULL);
        ASSERT(strstr(buf,
                      "skipping previously proven source-wide lint/compile/test scope")
               != NULL);
        ASSERT(strstr(buf, "record_fast_cache_pass") != NULL);
        ASSERT(strstr(buf, "not full release CI") != NULL);
        ASSERT(strstr(buf, "make pre-push-ci") != NULL);
        ASSERT(strstr(buf, "pre-push)") != NULL);
        ASSERT(strstr(buf, "pre-push focused groups=") != NULL);
        ASSERT(strstr(buf, "run_mapped_focused_tests") != NULL);
        ASSERT(strstr(buf, "make install-quality-linger") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "app/controllers/include/controllers/agent_impact_rules.def") == 0);
        ASSERT(read_entire_file(path, &rules) == 0);
        ASSERT(strstr(rules, "AGENT_IMPACT_RULE") != NULL);
        ASSERT(strstr(rules, "node_health_service") != NULL);
        /* The command-registry catalog owns native handler coverage. */
        ASSERT(strstr(rules, "command_registry_catalog") != NULL);
        ASSERT(strstr(rules, "src/main.c") != NULL);
        ASSERT(strstr(rules, "app/controllers/src/agent_controller.c") != NULL);
        ASSERT(strstr(rules, "app/controllers/src/agent_contract_registry.c")
               != NULL);
        ASSERT(strstr(rules,
                      "app/controllers/src/agent_contracts_controller.c")
               != NULL);
        ASSERT(strstr(rules, "app/controllers/src/agent_interface_controller.c")
               != NULL);
        ASSERT(strstr(rules, "app/controllers/src/agent_runtime_controller.c")
               != NULL);
        ASSERT(strstr(rules,
                      "app/controllers/src/event_timeline_controller.c")
               != NULL);
        ASSERT(strstr(rules, "app/controllers/src/diagnostics_*.c")
               != NULL);
        ASSERT(strstr(rules,
                      "app/controllers/include/controllers/diagnostics_*.h")
               != NULL);
        ASSERT(strstr(rules, "app/controllers/src/api_controller*.c") != NULL);
        ASSERT(strstr(rules, "app/controllers/src/api_controller_internal.h")
               != NULL);
        ASSERT(strstr(rules, "lib/event/src/event.c") != NULL);
        ASSERT(strstr(rules, "lib/event/include/event/event.h") != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_event.c") != NULL);
        ASSERT(strstr(rules, "\"event make_lint_gates\"") != NULL);
        ASSERT(strstr(rules, "app/controllers/src/blockchain_controller*.c")
               != NULL);
        ASSERT(strstr(rules, "app/controllers/include/controllers/blockchain_controller.h")
               != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_rpc_safety.c") != NULL);
        ASSERT(strstr(rules, "rpc_safety") != NULL);
        ASSERT(strstr(rules, "app/models/src/*.c") != NULL);
        ASSERT(strstr(rules, "app/models/include/models/*.h") != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_models*.c") != NULL);
        ASSERT(strstr(rules, "\"models make_lint_gates\"") != NULL);
        ASSERT(strstr(rules, "core/consensus/*") != NULL);
        ASSERT(strstr(rules, "core/params/*") != NULL);
        ASSERT(strstr(rules,
                      "\"consensus_parity domain_consensus_tx_structural chain\"")
               != NULL);
        ASSERT(strstr(rules, "lib/net/src/connman.c") != NULL);
        ASSERT(strstr(rules, "docs/AGENT_API.md") != NULL);
        ASSERT(strstr(rules, "deploy/*.service") != NULL);
        ASSERT(strstr(rules, "lib/net/include/net/msg_internal.h") != NULL);
        ASSERT(strstr(rules, "lib/net/include/net/port_policy.h") != NULL);
        ASSERT(strstr(rules, "README.md") != NULL);
        ASSERT(strstr(rules, ".github/CONTRIBUTING.md") != NULL);
        ASSERT(strstr(rules, "docs/BUILD.md") != NULL);
        ASSERT(strstr(rules, "docs/GETTING_STARTED.md") != NULL);
        ASSERT(strstr(rules, "app/controllers/include/controllers/network_controller.h")
               != NULL);
        ASSERT(strstr(rules, "app/jobs/src/tip_finalize_stage*.c") != NULL);
        ASSERT(strstr(rules, "app/jobs/include/jobs/tip_finalize_stage.h")
               != NULL);
        ASSERT(strstr(rules, "app/jobs/include/jobs/reducer_frontier.h")
               != NULL);
        ASSERT(strstr(rules, "tip_finalize_stage") != NULL);
        ASSERT(strstr(rules, "reducer_frontier") != NULL);
        ASSERT(strstr(rules, "app/jobs/src/validate_headers_stage.c")
               != NULL);
        ASSERT(strstr(rules, "app/jobs/include/jobs/validate_headers_stage.h")
               != NULL);
        ASSERT(strstr(rules, "app/conditions/src/block_failed_mask_at_tip.c")
               != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_utxo_activation_paused.c")
               != NULL);
        ASSERT(strstr(rules, "utxo_activation_paused") != NULL);
        ASSERT(strstr(rules, "condition_engine") != NULL);
        ASSERT(strstr(rules, "app/conditions/src/download_queue_starved.c")
               != NULL);
        ASSERT(strstr(rules, "app/conditions/src/local_header_refill_needed.c")
               != NULL);
        ASSERT(strstr(rules, "app/conditions/src/tip_wedged_resnapshot.c")
               != NULL);
        ASSERT(strstr(rules, "app/conditions/src/tip_stall_oracle_rebuild.c")
               != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_sync_watchdog_conditions.c")
               != NULL);
        ASSERT(strstr(rules,
                      "lib/test/src/test_tip_stall_oracle_rebuild_condition.c")
               != NULL);
        ASSERT(strstr(rules, "sync_watchdog_conditions") != NULL);
        ASSERT(strstr(rules, "tip_stall_oracle_rebuild_condition") != NULL);
        ASSERT(strstr(rules, "app/conditions/src/stale_validate_headers_repair.c")
               != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_stale_validate_headers_repair_condition.c")
               != NULL);
        ASSERT(strstr(rules, "validate_headers_stage") != NULL);
        ASSERT(strstr(rules, "stale_validate_headers_repair_condition")
               != NULL);
        ASSERT(strstr(rules, "app/conditions/src/chain_integrity_failed.c")
               != NULL);
        ASSERT(strstr(rules, "app/services/include/services/chain_restore_integrity.h")
               != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_chain_integrity_failed_condition.c")
               != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_service_state.c") != NULL);
        ASSERT(strstr(rules, "chain_integrity_failed_condition") != NULL);
        ASSERT(strstr(rules, "service_state") != NULL);
        ASSERT(strstr(rules, "config/src/boot_services.c") != NULL);
        ASSERT(strstr(rules, "config/src/boot.c") != NULL);
        ASSERT(strstr(rules, "config/src/boot_index.c") != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_load_verify_boot.c") != NULL);
        ASSERT(strstr(rules, "config/include/config/boot_internal.h") != NULL);
        ASSERT(strstr(rules, "boot_refold_window_extend") != NULL);
        ASSERT(strstr(rules, "chain_state_repo") != NULL);
        ASSERT(strstr(rules, "load_verify_boot") != NULL);
        ASSERT(strstr(rules, "config/src/app_context.c") != NULL);
        ASSERT(strstr(rules, "config/include/config/boot.h") != NULL);
        ASSERT(strstr(rules, "app_context") != NULL);
        ASSERT(strstr(rules, "models") != NULL);
        ASSERT(strstr(rules, "lib/test/src/test_syncdiag_rpc.c") != NULL);
        free(rules);
        rules = NULL;

        ASSERT(repo_path(path, sizeof(path), "docs/work/fast-path.md") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "`make fast-ci`") != NULL);
        ASSERT(strstr(buf, "`make t-fast ONLY=<group>`") != NULL);
        ASSERT(strstr(buf, "`make fast-changed-compile`") != NULL);
        ASSERT(strstr(buf, "`make fast-compile`") != NULL);
        ASSERT(strstr(buf, "`make dev-bin`") != NULL);
        ASSERT(strstr(buf, "`make ci-reproducible`") != NULL);
        ASSERT(strstr(buf, "build/bin/test-fast/epochs/") != NULL);
        ASSERT(strstr(buf, "build/bin/z23-dev") != NULL);
        ASSERT(strstr(buf, "classification hints only") != NULL);
        ASSERT(strstr(buf, "build/dev-obj/epochs/") != NULL);
        ASSERT(strstr(buf, "ZCL_DEV_OPT=-Og") != NULL);
        ASSERT(strstr(buf, "ZCL_DEV_HOT_OPT=-O2") != NULL);
        ASSERT(strstr(buf, "ZCL_DEV_LINKER") != NULL);
        ASSERT(strstr(buf, "not a deploy or release artifact") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CC") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_COMPILE=strict") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_COMPILE=changed") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_ONLY=1") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_TESTS") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_STRICT_TESTS=1") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_JOBS") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_LIVE=0") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE=0") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE_RESET=1") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CACHE_DIR") != NULL);
        ASSERT(strstr(buf, ".cache/zcl-agent-fast-ci") != NULL);
        ASSERT(strstr(buf, "fast result cache hit") != NULL);
        ASSERT(strstr(buf, "build/bin/z23 agent") != NULL);
        ASSERT(strstr(buf, "There is no external shell-wrapper fallback")
               != NULL);
        ASSERT(strstr(buf, "z23 agentbuild") != NULL);
        ASSERT(strstr(buf, "`make immutable-history-canaries`") != NULL);
        ASSERT(strstr(buf, "h=478544") != NULL);
        ASSERT(strstr(buf, "replay-canary-anchor") != NULL);
        /* The native command registry is the sole agent interface. */
        ASSERT(strstr(buf,
                      "Do not add Python, shell, or helper-binary")
               != NULL);
        ASSERT(strstr(buf, "origin/main..HEAD") != NULL);
        ASSERT(strstr(buf, "cached focused fast-ci") != NULL);
        ASSERT(strstr(buf, "live node condition remains") != NULL);
        ASSERT(strstr(buf, "zclassic23-fuzz.timer") != NULL);
        ASSERT(strstr(buf, "zclassic23-coverage.timer") != NULL);
        ASSERT(strstr(buf, "zclassic23-test-suite.timer") != NULL);
        ASSERT(strstr(buf, "zcl.background_quality_status.v1") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "README.md") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "docs/GETTING_STARTED.md") != NULL);
        ASSERT(strstr(buf, "Public start here") != NULL);
        ASSERT(strstr(buf, "make dev-bin") != NULL);
        ASSERT(strstr(buf, "registered parallel groups") != NULL);
        ASSERT(strstr(buf, "build/bin/z23 core sync diagnose")
               != NULL);
        ASSERT(strstr(buf, "| jq") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "docs/GETTING_STARTED.md") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "generic, fresh-machine setup guide")
               != NULL);
        ASSERT(strstr(buf, "make vendor") != NULL);
        ASSERT(strstr(buf, "make -j\"$(nproc)\"") != NULL);
        ASSERT(strstr(buf, "make fast-rebuild") != NULL);
        ASSERT(strstr(buf, "make t-fast ONLY=<group>") != NULL);
        ASSERT(strstr(buf, "build/bin/z23 status")
               != NULL);
        ASSERT(strstr(buf, "build/bin/z23 discover help")
               != NULL);
        ASSERT(strstr(buf, "dumpstate reducer_frontier") != NULL);
        ASSERT(strstr(buf, "docs/BOOTSTRAPPING.md") != NULL);
        ASSERT(strstr(buf, "core sync diagnose") != NULL);
        ASSERT(strstr(buf, "docs/HANDOFF.md") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), ".github/CONTRIBUTING.md") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "make vendor") != NULL);
        ASSERT(strstr(buf, "make build-only") != NULL);
        ASSERT(strstr(buf, "make dev-bin") != NULL);
        ASSERT(strstr(buf, "make t-fast ONLY=<group>") != NULL);
        ASSERT(strstr(buf, "make fast-ci") != NULL);
        ASSERT(strstr(buf, "fresh clone will not link") == NULL);
        ASSERT(strstr(buf, "make vendor` automation is on the roadmap")
               == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "tools/githooks/pre-push") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "Fast local edit-loop before commit:  make fast-ci")
               != NULL);
        ASSERT(strstr(buf, "files being pushed to origin/main") != NULL);
        ASSERT(strstr(buf, "refs/heads/main") != NULL);
        ASSERT(strstr(buf, "ZCL_FAST_CHANGED_FILES_FILE") != NULL);
        ASSERT(strstr(buf, "git diff --name-only \"$rsha\" \"$lsha\"")
               != NULL);
        ASSERT(strstr(buf, "git rev-parse --local-env-vars") != NULL);
        ASSERT(strstr(buf, "unset \"$name\"") != NULL);
        ASSERT(strstr(buf, "make install-quality-linger") != NULL);
        ASSERT(run_gate_script("tools/dev/build-epoch-selftest.sh", NULL)
               == 0);
        PASS();
    } _test_next:;
    free(buf);
    free(rules);
    free(main_src);
    free(arch_doc);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_dep_unit;

#endif /* ZCL_TESTING */
