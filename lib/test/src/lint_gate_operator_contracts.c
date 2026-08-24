/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Content contracts for the operator-facing surface: the canonical operator
 * diagnostics stay wired, the native operator docs describe the commands that
 * actually exist, the remote node-update path keeps its guards, the MVP
 * reporters resolve against the live service RPC rather than a hand-pinned
 * value, and the soak assertion requires a known mirror lag.
 *
 * These assert on the TEXT of the tools and docs behind those surfaces. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#ifdef ZCL_TESTING

#include "lint_gate_selftests.h"

int t_canonical_operator_diagnostics_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("canonical runbook and deploy diagnostics remain fail-closed") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "docs/RUNBOOK.md") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "sources[].selectable=false") != NULL);
        ASSERT(strstr(buf, "selection_blocker") != NULL);
        ASSERT(strstr(buf, "initialized=true") != NULL);
        ASSERT(strstr(buf, "has_connman=true") != NULL);
        ASSERT(strstr(buf, "has_main_state=true") != NULL);
        ASSERT(strstr(buf, "has_node_db=true") != NULL);
        ASSERT(strstr(buf, "blockers_total") != NULL);
        ASSERT(strstr(buf, "stalls_total") != NULL);
        ASSERT(strstr(buf, "unsafe_overrides_total") != NULL);
        ASSERT(strstr(buf, "last_override_safe") != NULL);
        ASSERT(strstr(buf, "last_override_scope") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "tools/deploy_verify.sh") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "canonical diagnostics ready") != NULL);
        ASSERT(strstr(buf, "chain_advance_coordinator") != NULL);
        ASSERT(strstr(buf, "local_consensus_validation") != NULL);
        ASSERT(strstr(buf, "ZCL_DATADIR=$RPC_DATADIR") != NULL);
        ASSERT(strstr(buf, "ZCL_RPCPORT=$RPCPORT") != NULL);
        ASSERT(strstr(buf, "\"$SERVICE_EXE\" core node bootstatus") != NULL);
        ASSERT(strstr(buf, "NODE_LOG") == NULL);
        ASSERT(strstr(buf, "pre_rpc_boot_diagnostic") == NULL);
        ASSERT(strstr(buf, "tail -n 500") == NULL);
        ASSERT(strstr(buf, "${ZCL_DEPLOY_NODE_LOG") == NULL);
        ASSERT(strstr(buf, "ZCL_DEPLOY_EXPECT_SOURCE_ID") != NULL);
        ASSERT(strstr(buf, "ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256") != NULL);
        ASSERT(strstr(buf, "/proc/$SERVICE_MAIN_PID/exe") != NULL);
        ASSERT(strstr(buf, "norm_commit") == NULL);
        ASSERT(strstr(buf, "typed boot status") != NULL);
        ASSERT(strstr(buf, "zclassic-cli|zcl-rpc") != NULL);
        ASSERT(strstr(buf, "json_rpc_result") != NULL);
        ASSERT(strstr(buf, "extract_health_height") != NULL);
        ASSERT(strstr(buf, "log_head|projection_height|local_height") != NULL);
        ASSERT(strstr(buf, "handshaked_connections") != NULL);
        ASSERT(strstr(buf, "legacy_compatible_peers") != NULL);
        ASSERT(strstr(buf, "legacy_magicbean_peers") != NULL);
        ASSERT(strstr(buf, "peer_lifecycle") != NULL);
        ASSERT(strstr(buf, "legacy_mirror") != NULL);
        ASSERT(strstr(buf, "blockers_total") != NULL);
        ASSERT(strstr(buf, "stalls_total") != NULL);
        ASSERT(strstr(buf, "unsafe_overrides_total") != NULL);
        ASSERT(strstr(buf, "unsafe_overrides_total 0") != NULL);
        ASSERT(strstr(buf, "last_override_safe") != NULL);
        ASSERT(strstr(buf, "last_override_scope") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_native_operator_docs_contract(void)
{
    int failures = 0;
    char *readme = NULL;
    char *getting_started = NULL;
    char *build_doc = NULL;
    TEST("operator entry docs teach only native agent commands") {
        char path[PATH_MAX];

        ASSERT(repo_path(path, sizeof(path), "README.md") == 0);
        ASSERT(read_entire_file(path, &readme) == 0);
        ASSERT(strstr(readme, "build/bin/z23 status") != NULL);
        ASSERT(strstr(readme, "core sync diagnose") != NULL);
        ASSERT(strstr(readme, "ops logs") != NULL);
        ASSERT(strstr(readme, "native command registry") != NULL);

        ASSERT(repo_path(path, sizeof(path), "docs/GETTING_STARTED.md") == 0);
        ASSERT(read_entire_file(path, &getting_started) == 0);
        ASSERT(strstr(getting_started, "native command registry") != NULL);
        ASSERT(strstr(getting_started, "discover help") != NULL);

        ASSERT(repo_path(path, sizeof(path), "docs/BUILD.md") == 0);
        ASSERT(read_entire_file(path, &build_doc) == 0);
        ASSERT(strstr(build_doc, "z23 ops selftest") != NULL);
        ASSERT(strstr(build_doc, "z23 dumpstate hotswap") != NULL);
        PASS();
    } _test_next:;
    free(readme);
    free(getting_started);
    free(build_doc);
    return failures;
}

int t_remote_node_update_contract(void)
{
    int failures = 0;
    char *script = NULL;
    char *makefile = NULL;
    char *agent = NULL;
    char *doc = NULL;
    char *fast_ci = NULL;
    char *service = NULL;
    char *timer = NULL;
    TEST("remote node update is main-only and guarded") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "tools/scripts/remote_node_update.sh") == 0);
        ASSERT(read_entire_file(path, &script) == 0);
        ASSERT(strstr(script, "zcl.remote_node_update.v1") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_DRY_RUN") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_BRANCH") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_MAIN_REF") != NULL);
        ASSERT(strstr(script, "only origin/main may be used") != NULL);
        ASSERT(strstr(script, "git ls-remote --exit-code origin refs/heads/main")
               != NULL);
        ASSERT(strstr(script, "git fetch") == NULL);
        ASSERT(strstr(script, "git merge --") == NULL);
        ASSERT(strstr(script, "remote checkout must be $expect_branch")
               != NULL);
        ASSERT(strstr(script, "remote planning branch must be main") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_ALLOW_DIRTY") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_INSTALL_BIN") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_INSTALL_ARTIFACT") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_RESTART") != NULL);
        ASSERT(strstr(script, "ZCL_REMOTE_JSON") != NULL);
        ASSERT(strstr(script, "ZCL_DEPLOY_ALLOW_CANONICAL=1") != NULL);
        ASSERT(strstr(script, "--json") != NULL);
        ASSERT(strstr(script, "--selftest") != NULL);
        ASSERT(strstr(script, "json_escape") != NULL);
        ASSERT(strstr(script, "emit_json_summary") != NULL);
        ASSERT(strstr(script, "runtime_publication_contained") != NULL);
        ASSERT(strstr(script, "runtime_publication\":false") != NULL);
        ASSERT(strstr(script, "mutation_contained\":true") != NULL);
        ASSERT(strstr(script, "refuse_public_mutation_request") != NULL);
        ASSERT(strstr(script, "selftest_refusal") != NULL);
        ASSERT(strstr(script, "SSH before refusing mutation") != NULL);
        ASSERT(strstr(script, "\\\"plan\\\"") != NULL);
        ASSERT(strstr(script, "\\\"safe_next_action\\\"") != NULL);
        ASSERT(strstr(script, "printf '%s\\n' \"$json\"") != NULL);
        ASSERT(strstr(script, "make fast-rebuild") == NULL);
        ASSERT(strstr(script, "make zclassic23") == NULL);
        ASSERT(strstr(script, "systemctl --user restart") == NULL);
        ASSERT(strstr(script, "install -m") == NULL);
        ASSERT(strstr(script, "No Python or jq is required") != NULL);
        ASSERT(strstr(script, "python") == NULL);
        free(script);
        script = NULL;

        ASSERT(repo_path(path, sizeof(path), "Makefile") == 0);
        ASSERT(read_entire_file(path, &makefile) == 0);
        ASSERT(strstr(makefile, "remote-node-plan:") != NULL);
        ASSERT(strstr(makefile, "remote-node-plan-json:") != NULL);
        ASSERT(strstr(makefile, "remote-node-update remote-node-update-json:")
               != NULL);
        ASSERT(strstr(makefile, "remote apply/install/restart is contained")
               != NULL);
        ASSERT(strstr(makefile, "ZCL_REMOTE_JSON=1") != NULL);
        ASSERT(strstr(makefile, "tools/scripts/remote_node_update.sh")
               != NULL);
        ASSERT(strstr(makefile, "CXX_STDLIB_LDFLAGS") != NULL);
        ASSERT(strstr(makefile, "$(CXX) -print-file-name=libstdc++.a")
               != NULL);
        ASSERT(strstr(makefile, "install-remote-status-linger:") != NULL);
        ASSERT(strstr(makefile, "remote-status:") != NULL);
        ASSERT(strstr(makefile, "install-self-update-linger:") != NULL);
        ASSERT(strstr(makefile, "self-update/build publication is contained")
               != NULL);
        ASSERT(strstr(makefile, "install-remote-test-node-linger:") != NULL);
        ASSERT(strstr(makefile, "remote-test-node-status:") != NULL);
        ASSERT(strstr(makefile, "zclassic23-remote-test-node.service") != NULL);
        ASSERT(strstr(makefile, "zclassic23-remote-test.env.example") != NULL);
        ASSERT(strstr(makefile, "zclassic23-remote-status.timer") != NULL);
        ASSERT(strstr(makefile,
                      "systemctl --user enable --now zclassic23-remote-status.timer")
               != NULL);
        free(makefile);
        makefile = NULL;

        ASSERT(repo_path(path, sizeof(path), "tools/scripts/build_vendor.sh")
               == 0);
        ASSERT(read_entire_file(path, &script) == 0);
        ASSERT(strstr(script, "VENDOR_LOCK_DIR") != NULL);
        ASSERT(strstr(script, "acquire_vendor_lock") != NULL);
        ASSERT(strstr(script, "release_vendor_lock") != NULL);
        ASSERT(strstr(script, "timed out waiting for vendor build lock")
               != NULL);
        ASSERT(strstr(script, "build_leveldb_direct") != NULL);
        ASSERT(strstr(script, "leveldb_cxx_compiler") != NULL);
        ASSERT(strstr(script, "LEVELDB_PLATFORM_POSIX=1") != NULL);
        ASSERT(strstr(script, "#define HAVE_SNAPPY 0") != NULL);
        free(script);
        script = NULL;

        ASSERT(repo_path(path, sizeof(path), "tools/agent_fast_ci.sh") == 0);
        ASSERT(read_entire_file(path, &fast_ci) == 0);
        ASSERT(strstr(fast_ci, "tools/scripts/remote_node_update.sh")
               != NULL);
        ASSERT(strstr(fast_ci, "tools/scripts/lane_recover.sh") != NULL);
        ASSERT(strstr(fast_ci,
                      "tools/scripts/check_stable_publish_containment.sh")
               != NULL);
        ASSERT(strstr(fast_ci,
                      "deploy/examples/zclassic23-remote-test-node.service")
               != NULL);
        ASSERT(strstr(fast_ci,
                      "deploy/examples/zclassic23-remote-test.env.example")
               != NULL);
        ASSERT(strstr(fast_ci,
                      "deploy/examples/zclassic23-self-update.service")
               != NULL);
        ASSERT(strstr(fast_ci,
                      "deploy/examples/zclassic23-self-update.timer")
               != NULL);
        free(fast_ci);
        fast_ci = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "app/controllers/src/agent_controller.c") == 0);
        ASSERT(read_entire_file(path, &agent) == 0);
        ASSERT(strstr(agent, "remote_node_update") != NULL);
        ASSERT(strstr(agent, "zcl.remote_node_update.v1") != NULL);
        ASSERT(strstr(agent, "make remote-node-plan") != NULL);
        ASSERT(strstr(agent, "json_plan_command") != NULL);
        ASSERT(strstr(agent, "json_summary") != NULL);
        ASSERT(strstr(agent, "no_fetch") != NULL);
        ASSERT(strstr(agent, "runtime_publication") != NULL);
        ASSERT(strstr(agent, "install_restart_contained") != NULL);
        free(agent);
        agent = NULL;

        ASSERT(repo_path(path, sizeof(path), "docs/AGENT_API.md") == 0);
        ASSERT(read_entire_file(path, &doc) == 0);
        ASSERT(strstr(doc, "## Remote Node Planning") != NULL);
        ASSERT(strstr(doc, "zcl.remote_node_update.v1") != NULL);
        ASSERT(strstr(doc, "make remote-node-plan") != NULL);
        ASSERT(strstr(doc, "make remote-node-plan-json") != NULL);
        ASSERT(strstr(doc, "ZCL_REMOTE_JSON=1") != NULL);
        ASSERT(strstr(doc, "git ls-remote") != NULL);
        ASSERT(strstr(doc, "runtime_publication_contained") != NULL);
        ASSERT(strstr(doc, "before SSH, fetch, merge, build") != NULL);
        ASSERT(strstr(doc, "never fetches or changes") != NULL);
        ASSERT(strstr(doc, "make install-remote-status-linger") != NULL);
        ASSERT(strstr(doc, "make remote-status") != NULL);
        ASSERT(strstr(doc, "make install-self-update-linger") != NULL);
        ASSERT(strstr(doc, "make install-remote-test-node-linger") != NULL);
        ASSERT(strstr(doc, "make remote-test-node-status") != NULL);
        ASSERT(strstr(doc, "MemoryHigh=24G") != NULL);
        ASSERT(strstr(doc, "MemoryMax=32G") != NULL);
        ASSERT(strstr(doc, "ZCL_LANE_SNAPSHOT_LOADER_FLAG=-load-snapshot-at-own-height")
               != NULL);
        ASSERT(strstr(doc, "systemd memory-budget lint") != NULL);
        ASSERT(strstr(doc,
                      "deploy/examples/zclassic23-self-update.timer")
               != NULL);
        free(doc);
        doc = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "deploy/examples/zclassic23-remote-test-node.service")
               == 0);
        ASSERT(read_entire_file(path, &service) == 0);
        ASSERT(strstr(service, "EnvironmentFile=-%h/.config/zclassic23/remote-test.env")
               != NULL);
        ASSERT(strstr(service, "-datadir=%h/.zclassic23-test") != NULL);
        ASSERT(strstr(service, "-port=18033") != NULL);
        ASSERT(strstr(service, "-rpcport=18233") != NULL);
        ASSERT(strstr(service, "MemoryHigh=24G") != NULL);
        ASSERT(strstr(service, "MemoryMax=32G") != NULL);
        ASSERT(strstr(service, "\nMemoryMax=32G\n") == NULL);
        ASSERT(strstr(service, "$ZCL_LANE_SNAPSHOT_LOADER_FLAG") != NULL);
        ASSERT(strstr(service, "CPUWeight=30") != NULL);
        ASSERT(strstr(service, "IOWeight=30") != NULL);
        ASSERT(strstr(service, "StandardOutput=append:%h/.zclassic23-test/node.log")
               != NULL);
        free(service);
        service = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "deploy/examples/zclassic23-remote-test.env.example")
               == 0);
        ASSERT(read_entire_file(path, &service) == 0);
        ASSERT(strstr(service, "ZCL_TEST_EXTERNALIP_FLAG=-externalip=")
               != NULL);
        ASSERT(strstr(service, "ZCL_TEST_ADDNODE_FLAGS=-addnode=")
               != NULL);
        ASSERT(strstr(service,
                      "ZCL_LANE_SNAPSHOT_LOADER_FLAG=-load-snapshot-at-own-height")
               != NULL);
        free(service);
        service = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "deploy/examples/zclassic23-self-update.service")
               == 0);
        ASSERT(read_entire_file(path, &service) == 0);
        ASSERT(strstr(service,
                      "Documentation=file:%h/github/zclassic23/docs/AGENT_API.md")
               != NULL);
        ASSERT(strstr(service, "remote_node_update.sh self") != NULL);
        ASSERT(strstr(service, "ZCL_REMOTE_BUILD=none") != NULL);
        ASSERT(strstr(service, "ZCL_REMOTE_DRY_RUN=1") != NULL);
        ASSERT(strstr(service, "ZCL_REMOTE_RESTART=0") != NULL);
        ASSERT(strstr(service, "MemoryHigh=8G") != NULL);
        ASSERT(strstr(service, "IOSchedulingClass=idle") != NULL);
        free(service);
        service = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "deploy/examples/zclassic23-self-update.timer")
               == 0);
        ASSERT(read_entire_file(path, &timer) == 0);
        ASSERT(strstr(timer, "OnCalendar=daily") != NULL);
        ASSERT(strstr(timer, "RandomizedDelaySec=1h") != NULL);
        PASS();
    } _test_next:;
    free(script);
    free(makefile);
    free(agent);
    free(doc);
    free(fast_ci);
    free(service);
    free(timer);
    return failures;
}

int t_mvp_reporters_resolve_live_service_rpc_contract(void)
{
    int failures = 0;
    char *scoreboard = NULL;
    char *gate = NULL;
    char *evidence = NULL;
    TEST("MVP reporters resolve the live service datadir and RPC port") {
        char scoreboard_path[PATH_MAX];
        char gate_path[PATH_MAX];
        char evidence_path[PATH_MAX];
        ASSERT(repo_path(scoreboard_path, sizeof(scoreboard_path),
                         "tools/scripts/mvp_scoreboard.sh") == 0);
        ASSERT(repo_path(gate_path, sizeof(gate_path), "tools/mvp_gate.sh") == 0);
        ASSERT(repo_path(evidence_path, sizeof(evidence_path),
                         "tools/scripts/soak_evidence.sh") == 0);
        ASSERT(read_entire_file(scoreboard_path, &scoreboard) == 0);
        ASSERT(read_entire_file(gate_path, &gate) == 0);
        ASSERT(read_entire_file(evidence_path, &evidence) == 0);

        ASSERT(strstr(scoreboard, "ZCL_NODE_UNIT=\"${ZCL_NODE_UNIT:-zclassic23}\"")
               != NULL);
        ASSERT(strstr(scoreboard, "systemd_exec_arg()") != NULL);
        ASSERT(strstr(scoreboard,
                      "systemctl --user show \"$ZCL_NODE_UNIT\" -p ExecStart --value")
               != NULL);
        ASSERT(strstr(scoreboard, "SERVICE_DATADIR=\"$(systemd_exec_arg datadir || true)\"")
               != NULL);
        ASSERT(strstr(scoreboard, "SERVICE_RPCPORT=\"$(systemd_exec_arg rpcport || true)\"")
               != NULL);
        ASSERT(strstr(scoreboard, "ZCL_DATADIR=$LIVE_DATADIR") != NULL);
        ASSERT(strstr(scoreboard, "ZCL_RPCPORT=$LIVE_RPCPORT") != NULL);
        ASSERT(strstr(scoreboard, "TIP_GAP_OK") != NULL);
        ASSERT(strstr(scoreboard, "LIVE_GAP=$(( LIVE_HEADERS - LIVE_HEIGHT ))")
               != NULL);
        ASSERT(strstr(scoreboard, "ZCL_C3_STOPWATCH_HISTORY") != NULL);
        ASSERT(strstr(scoreboard, "stopwatch_evidence_judge.sh") != NULL);
        ASSERT(strstr(scoreboard, "[ \"$c3_judge_rc\" -eq 0 ]") != NULL);
        ASSERT(strstr(scoreboard,
                      "VERDICT[3]=\"PASS\"; FULL_PASS[3]=1") != NULL);
        ASSERT(strstr(scoreboard,
                      "NOT_MET) VERDICT[6]=\"BLOCKED\"")
               != NULL);
        ASSERT(strstr(scoreboard,
                      "clean 168h evidence is not established yet")
               != NULL);
        ASSERT(strstr(scoreboard, "rpc_live operatorsnapshot") != NULL);
        ASSERT(strstr(scoreboard, "LIVE_SECURITY_OK") != NULL);
        ASSERT(strstr(scoreboard,
                      "[ \"$LIVE_SECURITY_OK\" != \"1\" ]") != NULL);
        ASSERT(strstr(scoreboard,
                      "security posture review-free + soak-evidence") != NULL);

        ASSERT(strstr(gate, "ZCL_NODE_UNIT=\"${ZCL_NODE_UNIT:-$ZCL_SOAK_UNIT}\"")
               != NULL);
        ASSERT(strstr(gate, "systemd_exec_arg()") != NULL);
        ASSERT(strstr(gate,
                      "systemctl --user show \"$ZCL_NODE_UNIT\" -p ExecStart --value")
               != NULL);
        ASSERT(strstr(gate, "SERVICE_DATADIR=\"$(systemd_exec_arg datadir || true)\"")
               != NULL);
        ASSERT(strstr(gate, "SERVICE_RPCPORT=\"$(systemd_exec_arg rpcport || true)\"")
               != NULL);
        ASSERT(strstr(gate, "ZCL_DATADIR=\"$LIVE_DATADIR\" ZCL_RPCPORT=\"$LIVE_RPCPORT\"")
               != NULL);
        ASSERT(strstr(gate, "ZD_DATADIR=\"${ZD_DATADIR:-$HOME/.zclassic}\"")
               != NULL);
        ASSERT(strstr(gate, "ZCL_DATADIR=\"$ZD_DATADIR\" ZCL_RPCPORT=\"$ZD_RPCPORT\"")
               != NULL);
        ASSERT(strstr(gate,
                      "absence of a listed z-addr is\n"
                      "# BLOCKED to the owner/test proof")
               != NULL);
        ASSERT(strstr(gate,
                      "z_gettotalbalance answers but no sapling z-addr is listed")
               != NULL);
        ASSERT(strstr(gate, "z_gettotalbalance did not answer") != NULL);
        ASSERT(strstr(gate, "\"datadir\":\"%s\"") != NULL);
        ASSERT(strstr(gate, "\"rpcport\":%s") != NULL);
        ASSERT(strstr(gate, "SECURITY_SNAPSHOT=\"$(rpc operatorsnapshot)\"")
               != NULL);
        ASSERT(strstr(gate, "SECURITY_POSTURE_OK") != NULL);
        ASSERT(strstr(gate,
                      "elif [[ \"$SECURITY_POSTURE_OK\" != 1 ]]") != NULL);

        ASSERT(strstr(evidence, "ZCL_SOAK_SECURITY_CMD") != NULL);
        ASSERT(strstr(evidence, "security_review_required") != NULL);
        ASSERT(strstr(evidence, "window_eligible") != NULL);
        ASSERT(strstr(evidence,
                      "security_review_required_in_%d_of_%d_samples")
               != NULL);
        ASSERT(strstr(evidence,
                      "security_posture_unknown_in_%d_of_%d_samples")
               != NULL);
        ASSERT(strstr(evidence,
                      "security_posture_gap_in_%d_of_%d_samples")
               != NULL);
        PASS();
    } _test_next:;
    free(scoreboard);
    free(gate);
    free(evidence);
    return failures;
}

int t_soak_assert_requires_known_mirror_lag(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("soak assert treats unknown mirror lag as a deviation") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "tools/scripts/soak_assert.sh") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mirror_lag_known") != NULL);
        ASSERT(strstr(buf, "lag_known=$(json_bool \"$sync_detail\" mirror_lag_known") != NULL);
        ASSERT(strstr(buf, "fail=\"mirror_lag_unknown\"") != NULL);
        ASSERT(strstr(buf, "lag_known=$lag_known") != NULL);
        ASSERT(strstr(buf, "elif [ \"$lag_known\" != \"true\" ]; then")
               != NULL);
        ASSERT(strstr(buf, "elif [ \"$lag\" -gt \"$LAG_BREACH_BLOCKS\" ]; then")
               != NULL);
        ASSERT(strstr(buf, "mirror_lag is known and <=") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_ops_unit;

#endif /* ZCL_TESTING */
