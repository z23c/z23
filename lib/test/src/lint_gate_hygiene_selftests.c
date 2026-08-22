/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-tests for the repository-hygiene gates: the tracked git hooks are
 * installed and a no-op hook is rejected, the systemd memory budget holds, the
 * quality-job guard and the hermetic import-copy-prove / fresh-boot-weld
 * selftests run, the Makefile ignores ephemeral lint fixture sources, the
 * deprecated tools/z surface stays absent, production comments name a purpose
 * rather than a refactor scaffold label, contract headers carry no dev-history
 * phrasing, and HANDOFF.md carries no uncited victory claim. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#ifdef ZCL_TESTING

#include "lint_gate_selftests.h"

int run_git_hooks_gate_with_path(const char *hooks_path)
{
    return run_gate_script_with_env(GIT_HOOKS_SCRIPT_REL,
                                    "ZCL_GIT_HOOKS_PATH_FOR_TEST",
                                    hooks_path);
}

int run_git_hooks_gate_with_file(const char *hook_path)
{
    return run_gate_script_with_env2(
        GIT_HOOKS_SCRIPT_REL,
        "ZCL_GIT_HOOKS_PATH_FOR_TEST", "tools/githooks",
        "ZCL_GIT_HOOK_FILE_FOR_TEST", hook_path);
}

int run_git_hooks_gate_with_precommit_file(const char *hook_path)
{
    return run_gate_script_with_env2(
        GIT_HOOKS_SCRIPT_REL,
        "ZCL_GIT_HOOKS_PATH_FOR_TEST", "tools/githooks",
        "ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST", hook_path);
}

int t_git_hooks_gate_enforces_tracked_pre_push(void)
{
    int failures = 0;
    TEST("[lint-gate] local pre-push hook gate enforces tools/githooks") {
        ASSERT(run_git_hooks_gate_with_path(".git/hooks") != 0);
        ASSERT(run_git_hooks_gate_with_path("tools/githooks") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_git_hooks_gate_rejects_noop_pre_push(void)
{
    int failures = 0;
    char hook_path[PATH_MAX], fixture_path[PATH_MAX];
    char *orig = NULL;
    int resolved = repo_path(hook_path, sizeof(hook_path),
                             GIT_HOOKS_PRE_PUSH_REL);
    int fixture_resolved = repo_path_pid(fixture_path, sizeof(fixture_path),
                                         GIT_HOOKS_PRE_PUSH_FIXTURE_REL, "");
    int read_ok = (resolved == 0 && fixture_resolved == 0 &&
                   read_entire_file(hook_path, &orig) == 0);
    int planted_good = 0;
    int original_rc = -1;
    int wrote_noop = 0;
    int noop_rc = -1;

    if (read_ok) {
        (void)unlink(fixture_path);
        planted_good = (write_file(fixture_path, orig) == 0 &&
                        chmod(fixture_path, 0755) == 0);
        if (planted_good)
            original_rc = run_git_hooks_gate_with_file(fixture_path);
        wrote_noop = (write_file(fixture_path,
                      "#!/usr/bin/env bash\n"
                      "# fixture: no local CI gate\n"
                      "exit 0\n") == 0 &&
                      chmod(fixture_path, 0755) == 0);
        if (wrote_noop)
            noop_rc = run_git_hooks_gate_with_file(fixture_path);
        (void)unlink(fixture_path);
    }

    TEST("[lint-gate] local pre-push hook gate rejects no-op hook body") {
        ASSERT(read_ok);
        ASSERT(planted_good);
        ASSERT(original_rc == 0);
        ASSERT(wrote_noop);
        ASSERT(noop_rc != 0);
        PASS();
    } _test_next:;

    free(orig);
    return failures;
}

int t_git_hooks_gate_rejects_noop_pre_commit(void)
{
    int failures = 0;
    char hook_path[PATH_MAX], fixture_path[PATH_MAX];
    char *orig = NULL;
    int resolved = repo_path(hook_path, sizeof(hook_path),
                             GIT_HOOKS_PRECOMMIT_REL);
    int fixture_resolved = repo_path_pid(fixture_path, sizeof(fixture_path),
                                         GIT_HOOKS_PRECOMMIT_FIXTURE_REL, "");
    int read_ok = (resolved == 0 && fixture_resolved == 0 &&
                   read_entire_file(hook_path, &orig) == 0);
    int planted_good = 0;
    int original_rc = -1;
    int wrote_noop = 0;
    int noop_rc = -1;

    if (read_ok) {
        (void)unlink(fixture_path);
        planted_good = (write_file(fixture_path, orig) == 0 &&
                        chmod(fixture_path, 0755) == 0);
        if (planted_good)
            original_rc = run_git_hooks_gate_with_precommit_file(fixture_path);
        wrote_noop = (write_file(fixture_path,
                      "#!/usr/bin/env bash\n"
                      "# fixture: no main-checkout lane guard\n"
                      "exit 0\n") == 0 &&
                      chmod(fixture_path, 0755) == 0);
        if (wrote_noop)
            noop_rc = run_git_hooks_gate_with_precommit_file(fixture_path);
        (void)unlink(fixture_path);
    }

    TEST("[lint-gate] local pre-commit hook gate rejects no-op hook body") {
        ASSERT(read_ok);
        ASSERT(planted_good);
        ASSERT(original_rc == 0);
        ASSERT(wrote_noop);
        ASSERT(noop_rc != 0);
        PASS();
    } _test_next:;

    free(orig);
    return failures;
}

/* P1-3 — systemd memory budget: the live repo units must fit under the host
 * budget, and the script's parser self-test covers over-budget, infinity,
 * invalid-size, absent-cap, and drop-in override behavior.
 *
 * The baseline run checks the REAL committed deploy service units against
 * a REAL host's memory — that is the whole point of this gate (see
 * check_systemd_memory_budget.sh's own header). Left to its default, the
 * script reads /proc/meminfo of whatever machine happens to run this test,
 * which is only meaningful when that machine's RAM matches the actual
 * deploy target. That coincidentally holds on the maintainer's dev host
 * (maintainer-host-class hardware — see docs/HANDOFF.md), so it passed there
 * silently, but a hosted CI runner's RAM (a few GB) is nowhere near the
 * ~93 GiB deploy target, so the SAME finite MemoryMax sum that legitimately
 * fits the real host reads as over-budget there — not a real regression,
 * just this test reading the wrong machine's memory. .github/workflows/
 * build.yml's lint job already pins ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES
 * to the real deploy target for exactly this reason (see that job's own
 * comment); pin the SAME value here so this test verifies the same real
 * invariant identically on every host, never the ambient host's own RAM. */
/* The maintainer host, ~93 GiB — keep numerically identical to build.yml's
 * ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES. */
#define ZCL_TEST_DEPLOY_TARGET_MEMTOTAL_BYTES "100300546048"
int t_systemd_memory_budget(void)
{
    int failures = 0;
    int base_env_rc = setenv("ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES",
                             ZCL_TEST_DEPLOY_TARGET_MEMTOTAL_BYTES, 1);
    int baseline_rc = base_env_rc == 0
        ? run_gate_script(SYSMEM_SCRIPT_REL, NULL) : -1;
    (void)unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES");
    int env_rc = setenv("ZCL_SYSTEMD_MEMORY_BUDGET_SELFTEST", "1", 1);
    int selftest_rc = env_rc == 0 ? run_gate_script(SYSMEM_SCRIPT_REL, NULL) : -1;
    (void)unsetenv("ZCL_SYSTEMD_MEMORY_BUDGET_SELFTEST");
    TEST("[lint-gate] P1-3 systemd memory budget: baseline and selftest pass") {
        ASSERT(base_env_rc == 0);
        ASSERT(baseline_rc == 0);
        ASSERT(env_rc == 0);
        ASSERT(selftest_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Unattended quality lanes must yield to every active mint service and bound
 * their dated logs without touching status, artifacts, or symlinks.  The
 * standalone test replaces systemctl/logger and the lane bodies with hermetic
 * fixtures, so it is safe inside the ordinary parallel test group. */
int t_quality_job_guard(void)
{
    int failures = 0;
    TEST("[tooling] quality jobs yield to mint and retain bounded logs") {
        ASSERT(run_gate_script(QUALITY_GUARD_TEST_REL, NULL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* tools/scripts/import-copy-prove-selftest.sh — hermetic proof that the ONE
 * canonical copy-prove driver (tools/scripts/import-copy-prove.sh) computes
 * the mode-appropriate gate set and overall verdict correctly, in BOTH
 * --mode=import and --mode=bundle, using faked $NODE_BIN/$RPC_BIN fixture
 * scripts under a throwaway mktemp sandbox: no real node binary, no real
 * zclassicd, no real chainstate/bundle, no network ports. It does not (and
 * cannot) prove anything about the real importer/installer — only that the
 * driver gates correctly the moment a real cure runs. See the script's own
 * header for the full rationale. Bounded at 180s (see
 * run_gate_script_timeout). */
int t_import_copy_prove_selftest(void)
{
    int failures = 0;
    TEST("[tooling] import-copy-prove driver gates import+bundle modes "
         "correctly (hermetic)") {
        ASSERT(run_gate_script_timeout(IMPORT_COPY_PROVE_SELFTEST_REL,
                                       IMPORT_COPY_PROVE_SELFTEST_TIMEOUT_SECS)
               == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* tools/scripts/fresh-boot-weld-prove-selftest.sh — hermetic proof that the
 * zero-flag cold-boot weld copy-prove driver
 * (tools/scripts/fresh-boot-weld-prove.sh) classifies every boot outcome
 * (install+climb, tamper-refused, chain-binding-blocked, installed-but-frozen,
 * RPC-never-answers, a denylisted work dir) into the correct verdict and exit
 * code, using a faked $ZCL_NODE_BIN fixture script: no real node binary, no
 * real chain state, no live checkpoint bundle. Mirrors
 * t_import_copy_prove_selftest's run_gate_script_timeout convention. */
int t_fresh_boot_weld_prove_selftest(void)
{
    int failures = 0;
    TEST("[tooling] fresh-boot-weld-prove driver gates the zero-flag weld "
         "boot outcomes correctly (hermetic)") {
        ASSERT(run_gate_script_timeout(FRESH_BOOT_WELD_PROVE_SELFTEST_REL,
                                       FRESH_BOOT_WELD_PROVE_SELFTEST_TIMEOUT_SECS)
               == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Return 0 when no tracked, active file refers to the retired tools/z path,
 * 1 when git grep finds a reference, and -1 on a harness error. Dated work
 * archives are evidence, not an active operator surface; this test source is
 * excluded because it owns the tombstone assertion and search pattern. */
int tracked_active_tree_has_no_tools_z_reference(void)
{
    const char *root = repo_root();
    if (!root)
        return -1;

    pid_t pid = fork_with_retry();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (chdir(root) != 0)
            _exit(125);
        execlp("git", "git", "grep", "-n", "-E",
               "(^|[^[:alnum:]_-])tools/z([^[:alnum:]_.-]|$)", "--", ".",
               ":!docs/work/archive/**",
               ":!lib/test/src/lint_gate_hygiene_selftests.c", (char *)NULL);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    if (!WIFEXITED(status))
        return -1;
    int rc = WEXITSTATUS(status);
    if (rc == 1) /* git grep: no matches */
        return 0;
    if (rc == 0) /* a match was printed */
        return 1;
    return -1;
}

int t_deprecated_tools_z_is_absent(void)
{
    int failures = 0;
    TEST("deprecated tools/z control plane is absent") {
        char path[PATH_MAX];
        struct stat st;

        ASSERT(repo_path(path, sizeof(path), "tools/z") == 0);
        errno = 0;
        ASSERT(lstat(path, &st) == -1);
        ASSERT(errno == ENOENT);
        ASSERT(tracked_active_tree_has_no_tools_z_reference() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_make_ignores_ephemeral_lint_fixture_sources(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("Makefile source globs ignore ephemeral lint fixture sources") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "Makefile") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "ZCL_EPHEMERAL_SOURCE_PATTERNS") == NULL);
        ASSERT(strstr(buf, "%/_%fixture%.c") == NULL);
        ASSERT(strstr(buf, "zcl_ephemeral_sources") != NULL);
        ASSERT(strstr(buf, "$(findstring /_,$(s))") != NULL);
        ASSERT(strstr(buf, "zcl_filter_ephemeral_sources") != NULL);
        ASSERT(count_occurrences(buf,
                   "$(call zcl_filter_ephemeral_sources,") >= 8);
        ASSERT(strstr(buf,
               "APP_SRCS = $(call zcl_filter_ephemeral_sources") != NULL);
        ASSERT(strstr(buf,
               "CONFIG_SRCS = $(call zcl_filter_ephemeral_sources") != NULL);
        ASSERT(strstr(buf,
               "LIB_SRCS = $(call zcl_filter_ephemeral_sources") != NULL);
        ASSERT(strstr(buf,
               "DOMAIN_SRCS = $(call zcl_filter_ephemeral_sources") != NULL);
        ASSERT(strstr(buf,
               "APPLICATION_SRCS = $(call zcl_filter_ephemeral_sources")
               != NULL);
        ASSERT(strstr(buf,
               "ADAPTERS_SRCS = $(call zcl_filter_ephemeral_sources")
               != NULL);
        /* The shared RPC transport builds under APP_SRCS. */
        ASSERT(strstr(buf,
               "TEST_SRCS = $(call zcl_filter_ephemeral_sources") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_production_comments_do_not_carry_refactor_scaffold_labels(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("production comments name purpose, not refactor scaffold labels") {
        const char *files[] = {
            "config/src/boot_services.c",
            "config/src/boot_flyclient.c",
            "config/src/boot_background_workers.c",
            "config/src/boot_msg_callbacks.c",
            "config/src/boot.c",
            "lib/storage/include/storage/utxo_reimport_flag.h",
            "lib/validation/include/validation/process_block.h",
            "lib/validation/src/process_block_core.c",
            "lib/net/src/connman.c",
            "app/jobs/include/jobs/header_probe_poll.h",
            "app/services/include/services/block_source_policy.h",
            "app/services/src/block_source_policy_runtime.c",
            "app/services/src/block_source_policy_status.c",
            "app/services/src/block_source_policy_persist.c",
            "app/services/src/block_source_policy_decisions.c",
            "app/services/src/chain_restore_executor.c",
            "app/services/src/chain_restore_repair.c",
            "lib/storage/src/utxo_reimport_flag.c",
            "app/services/src/utxo_recovery_restore.c",
            "lib/util/include/util/stage.h",
            "lib/storage/include/storage/progress_store.h",
            "app/supervisors/include/supervisors/staged_sync_supervisor.h",
            "app/jobs/include/jobs/utxo_apply_delta.h",
            "app/jobs/include/jobs/header_admit_stage.h",
            "app/jobs/include/jobs/validate_headers_stage.h",
            "app/jobs/include/jobs/body_fetch_stage.h",
            "app/jobs/src/utxo_apply_delta.c",
            "app/jobs/src/utxo_apply_delta_reorg.c",
            "app/jobs/src/utxo_apply_stage.c",
            "app/jobs/include/jobs/block_header_emit.h",
            "app/jobs/include/jobs/body_persist_stage.h",
            "app/jobs/include/jobs/script_validate_stage.h",
            "app/jobs/include/jobs/proof_validate_stage.h",
            "app/jobs/include/jobs/utxo_apply_stage.h",
            "app/jobs/include/jobs/tip_finalize_stage.h",
            "app/jobs/include/jobs/job.h",
            "app/jobs/include/jobs/stage_helpers.h",
            "app/jobs/README.md",
            "app/jobs/src/body_persist_stage.c",
            "app/jobs/src/script_validate_stage.c",
            "app/jobs/src/proof_validate_stage.c",
            "app/jobs/src/tip_finalize_stage.c",
            "app/jobs/src/header_admit_stage.c",
            "app/jobs/src/stage_repair_reducer_frontier_refill.c",
            "app/jobs/src/stage_repair_reducer_frontier_refill_scan.c",
            "app/jobs/src/tip_finalize_post_step.h",
            "app/jobs/src/validate_headers_internal.h",
            "app/jobs/src/validate_headers_report.c",
            "app/jobs/src/validate_headers_validator.c",
            "app/controllers/src/wallet_controller_history.c",
            "app/controllers/src/transaction_controller_sign.c",
            "app/controllers/src/wallet_controller_keys.c",
            "app/controllers/src/repair_controller_utxo.c",
            "app/controllers/src/wallet_controller_multisig.c",
            "app/controllers/src/store_controller_schema.c",
            "app/controllers/src/wallet_shielded_send.c",
            "app/controllers/src/wallet_shielded_keys.c",
            "app/controllers/src/wallet_shielded_send_shielded.c",
            "app/controllers/src/wallet_shielded_controller.c",
            "app/controllers/src/wallet_rescan_controller_coins.c",
            "app/controllers/src/wallet_rescan_controller_witness.c",
            "app/controllers/src/wallet_view_emit.c",
            "app/controllers/src/wallet_view_sync.c",
            "app/controllers/src/sync_controller_import.c",
            "app/controllers/src/sync_controller_catchup.c",
            "app/controllers/src/sync_controller_catchup_jobs.c",
            "app/controllers/include/controllers/diagnostics_controller.h",
            "app/controllers/src/api_controller_node.c",
            "app/controllers/src/blockchain_controller_chain.c",
            "app/controllers/src/explorer_controller_block.c",
            "app/controllers/src/explorer_controller_pages.c",
            "app/controllers/src/explorer_controller_dashboard.c",
            "app/controllers/src/explorer_controller_address.c",
            "app/controllers/src/wallet_view_helpers.c",
            "app/controllers/src/sync_controller_blocks.c",
            "app/controllers/src/sync_controller_writers.c",
            "app/views/include/views/explorer_stats_view.h",
            "app/views/include/views/explorer_block_view.h",
            "app/views/include/views/explorer_pages_view.h",
            "app/views/include/views/explorer_dashboard_view.h",
            "app/views/include/views/store_internal.h",
            "app/views/include/views/explorer_address_view.h",
            "app/views/include/views/explorer_pages_loading_view.h",
            "app/views/include/views/explorer_tx_view.h",
            "app/views/include/views/wallet_gui_internal.h",
            "app/views/src/store_view.c",
            "app/views/src/explorer_factoids_view.c",
            "app/views/src/explorer_stats_view.c",
            "app/views/src/explorer_factoids_history.c",
            "app/views/src/explorer_factoids_chaindata.c",
            "app/views/include/views/explorer_factoids_view.h",
            "app/views/src/explorer_pages_hodl.c",
            "app/views/src/explorer_block_view.c",
            "app/views/src/explorer_stats_gather.c",
            "app/views/src/explorer_stats_sections.c",
            "app/views/src/explorer_pages_loading_view.c",
            "app/views/src/explorer_address_view.c",
            "app/views/src/explorer_pages_view.c",
            "app/views/src/explorer_dashboard_view.c",
            "app/views/src/wallet_gui_bot.c",
            "app/views/src/wallet_gui.c",
            "app/views/include/views/explorer_main_view.h",
            "app/views/src/explorer_main_view.c",
            "app/views/src/explorer_tx_view.c",
            "app/views/include/views/wallet_view_coins_view.h",
            "app/views/src/wallet_view_coins_view.c",
            "app/views/include/views/wallet_view_dashboard_view.h",
            "app/views/src/wallet_view_dashboard_view.c",
            "app/views/include/views/wallet_view_history_view.h",
            "app/views/src/wallet_view_history_view.c",
            "app/views/include/views/wallet_view_node_view.h",
            "app/views/src/wallet_view_node_view.c",
            "app/views/include/views/wallet_view_shield_view.h",
            "app/views/src/wallet_view_shield_view.c",
            "app/services/src/block_source_policy_internal.h",
            "app/controllers/include/controllers/diagnostics_internal.h",
            "app/controllers/src/diagnostics_controller.c",
            "app/services/src/block_index_loader_rebuild.c",
            "app/services/src/utxo_recovery_service.c",
            "app/services/src/chain_evidence_reconstruct.c",
            "app/services/src/bg_validation_scripts.c",
            "app/services/include/services/block_index_loader.h",
            "app/services/include/services/utxo_recovery_service.h",
            "app/services/src/bg_validation_proofs.c",
            "app/services/src/bg_validation_internal.h",
            "app/services/src/block_index_loader.c",
            "app/services/src/chain_evidence_persistence_service.c",
            "app/services/src/consensus_reject_index.c",
            "app/services/include/services/chain_state_validator.h",
            "app/services/src/chain_state_validator.c",
            "app/services/src/utxo_recovery_backfill.c",
            "app/services/src/snapshot_sync_service.c",
            "app/services/src/snapshot_sync_internal.h",
            "app/services/src/snapshot_offer.c",
            "app/services/src/snapshot_fetch.c",
            "app/services/src/snapshot_verify.c",
            "app/services/src/snapshot_apply.c",
            "app/services/include/services/chain_activation_service.h",
            "app/services/src/chain_activation_service.c",
            "app/supervisors/include/supervisors/chain_supervisor.h",
            "app/models/include/models/database_internal.h",
            "app/models/include/models/wallet_tx_internal.h",
            "app/models/include/models/header_admit_log.h",
            "app/models/src/database_modes.c",
            "app/models/src/database_migrate.c",
            "app/models/src/sapling_note.c",
            "app/models/src/wallet_tx_reads.c",
            "app/controllers/src/hodl_controller.c",
            "app/controllers/src/mining_controller.c",
            "app/controllers/src/repair_controller_rebuild.c",
            "app/supervisors/src/net_supervisor.c",
            "app/supervisors/src/staged_sync_supervisor.c",
            "app/supervisors/src/chain_supervisor.c",
            "config/src/boot_snapshot_import.c",
            "config/src/boot_index.c",
            "tools/sim/chaos.c",
            "lib/crypto_registry/include/crypto_registry/crypto_registry.h",
            "lib/crypto_registry/src/crypto_registry.c",
            "lib/platform/include/platform/clock.h",
            "lib/platform/include/platform/rng.h",
            "lib/platform/include/platform/time_compat.h",
            "lib/platform/src/clock.c",
            "lib/platform/src/rng.c",
            "lib/storage/include/storage/projection_util.h",
            "lib/storage/include/storage/event_log.h",
            "lib/storage/include/storage/event_log_payloads.h",
            "lib/storage/include/storage/block_index_projection.h",
            "lib/storage/include/storage/sha3_sidecar_io.h",
            "lib/storage/src/event_log.c",
            "lib/storage/src/mempool_projection.c",
            "lib/storage/src/peers_projection.c",
            "lib/storage/src/wallet_projection.c",
            "lib/storage/src/znam_projection.c",
            "app/controllers/src/diagnostics_registry.c",
            "lib/validation/include/validation/accept_block_header.h",
            "lib/validation/include/validation/process_block_invalidate.h",
            "lib/validation/include/validation/process_block_revalidate.h",
            "lib/validation/src/accept_block_header.c",
            "lib/validation/src/process_block.c",
            "lib/validation/src/process_block_crash_hooks.c",
            "lib/validation/src/process_block_failed_child.c",
            "lib/validation/src/process_block_flush_policy.c",
            "lib/validation/src/process_block_invalidate.c",
            "lib/validation/src/process_block_internal.h",
            "lib/validation/src/process_block_revalidate.c",
            "lib/validation/src/process_block_self_heal.c",
        };
        const char *stale[] = {
            "Phase 3 dissolve",
            "dissolve PR",
            "PR-",
            "B3:",
            "B3/",
            "B2:",
            "B5:",
            "B5 reorg",
            "B5 ordering",
            "C3 split",
            "D5",
            "F-1",
            "docs/dissolve",
            "dissolved chain_advance_coordinator",
            "Re-homed verbatim",
            "verbatim",
            "Behavior-preserving",
            "code motion",
            "Pure code-motion",
            "pure code move",
            "Pure code motion",
            "file-size ceiling E1",
            "until Phase 3",
            "Phase 3 unblocks",
            "Phase 3: release refs",
            "Split out of",
            "Split into",
            "split out of",
            "specific split",
            "split files",
            "behavior byte-identical",
            "byte-identical",
            "behavior unchanged",
            "byte-identically",
            "pre-split monolith",
            "extracted from",
            "checklist item",
            "checklist D5",
            "moved out of",
            "move, not a redesign",
            "not a redesign",
            "prior controller implementation",
            "prior inline",
            "No behavior change vs the original",
            "Behavior is byte-identical",
            "Extracted from",
            "extracted verbatim",
            "pure refactor",
            "pure code motion",
            "Pure code motion",
            "single-engine replacement",
            "single-engine",
            "Single-engine",
            "single engine",
            "copy-pasted",
            "Compatibility shim",
            "legacy controller includes",
            "lifted verbatim",
            "Moved verbatim",
            "byte-for-byte",
            "skeleton",
            "idle in this PR",
            "Later Phase",
            "Phase 5a",
            "Phase 6a",
            "Phase 6c",
            "Phase 4",
            "Phase 7a",
            "Wave F-5",
            "Wave T",
            "Wave M",
            "Wave-M",
            "Wave S",
            "Wave-S",
            "WS-6.4",
            "S-2",
            "S-3",
            "S-4",
            "S-5",
            "S-6",
            "S-7",
            "S-8",
            "S-9",
            "Back-compat",
            "Precedent:",
            "gate E1",
            "file-size ceiling",
            "Phase C",
            "boot decomposition Phase",
            "for file size",
        };

        for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
            char path[PATH_MAX];
            ASSERT(repo_path(path, sizeof(path), files[i]) == 0);
            ASSERT(read_entire_file(path, &buf) == 0);
            for (size_t j = 0; j < sizeof(stale) / sizeof(stale[0]); j++) {
                if (strstr(buf, stale[j])) {
                    fprintf(stderr, "stale scaffold label %s still present in %s\n",
                            stale[j], files[i]);
                    ASSERT(strstr(buf, stale[j]) == NULL);
                }
            }
            free(buf);
            buf = NULL;
        }
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

/* check-no-dev-history-in-contracts — rejects dev-history phrasing ("STEP-0
 * STATUS", "stub bodies"/"stub body", "lane <N><letter>", "future slice")
 * from production contract surfaces (any *.h under an include/ dir, any
 * *.def table). Proof:
 * (1) the clean tree passes; (2) a fixture named with the *_test.* allowlist
 * suffix is IGNORED even though it lives under a real include/ dir and
 * carries every banned phrase; (3) the SAME violating content under a
 * non-allowlisted fixture name trips the gate; (4) removing it recovers
 * green; (5) the gate is actually wired into the Makefile LINT_GATES list
 * and documented in DEFENSIVE_CODING.md's canonical block. */
int t_no_dev_history_in_contracts(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;

    unlink_rel(NO_DEV_HISTORY_FIXTURE_DST);
    unlink_rel(NO_DEV_HISTORY_ALLOWLIST_FIXTURE_DST);

    int baseline_rc = run_gate_script(NO_DEV_HISTORY_SCRIPT_REL, NULL);

    const char *violating_body =
        "#ifndef ZCL_DEV_HISTORY_LINT_FIXTURE_TMP_H\n"
        "#define ZCL_DEV_HISTORY_LINT_FIXTURE_TMP_H\n"
        "/* STEP-0 STATUS: contract + stub bodies; lane 2A lands the real\n"
        " * thing. Also a stub body and a future slice. */\n"
        "#endif\n";

    int allow_planted =
        (repo_path(path, sizeof(path), NO_DEV_HISTORY_ALLOWLIST_FIXTURE_DST) == 0 &&
         write_file(path, violating_body) == 0) ? 0 : -1;
    int allow_rc =
        allow_planted == 0 ? run_gate_script(NO_DEV_HISTORY_SCRIPT_REL, NULL) : -1;
    unlink_rel(NO_DEV_HISTORY_ALLOWLIST_FIXTURE_DST);

    int planted =
        (repo_path(path, sizeof(path), NO_DEV_HISTORY_FIXTURE_DST) == 0 &&
         write_file(path, violating_body) == 0) ? 0 : -1;
    int trip_rc =
        planted == 0 ? run_gate_script(NO_DEV_HISTORY_SCRIPT_REL, NULL) : -1;
    unlink_rel(NO_DEV_HISTORY_FIXTURE_DST);
    int recover_rc = run_gate_script(NO_DEV_HISTORY_SCRIPT_REL, NULL);

    int makefile_wired = 0;
    if (repo_path(path, sizeof(path), "Makefile") == 0 &&
        read_entire_file(path, &makefile_buf) == 0) {
        makefile_wired =
            strstr(makefile_buf, "check-no-dev-history-in-contracts:") != NULL &&
            strstr(makefile_buf, "check-no-dev-history-in-contracts \\") != NULL;
    }
    int doc_wired = 0;
    if (repo_path(path, sizeof(path), "docs/DEFENSIVE_CODING.md") == 0 &&
        read_entire_file(path, &doc_buf) == 0) {
        doc_wired = strstr(doc_buf, "check-no-dev-history-in-contracts") != NULL;
    }

    TEST("[lint-gate] check-no-dev-history-in-contracts: clean, allowlists "
         "*_test.* fixture, trips real fixture, recovers, wired") {
        ASSERT(baseline_rc == 0);
        ASSERT(allow_planted == 0);
        ASSERT(allow_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        ASSERT(makefile_wired);
        ASSERT(doc_wired);
        PASS();
    } _test_next:;
    free(makefile_buf);
    free(doc_buf);
    return failures;
}

/* check-no-uncited-victory — the one live-state page (docs/HANDOFF.md) may not
 * carry a victory phrase ("at tip", "cured", "wedge closed", ...) without a
 * machine-checkable citation token in the SAME paragraph. Exists because the
 * repo shipped 9+ false "cured / at tip" claims in six weeks (~103 wedge-FIXED
 * -> re-wedge cycles). Proof:
 * (1) the clean tree passes (the real HANDOFF.md is citation-clean);
 * (2) a planted fixture doc with an UNCITED victory paragraph trips the gate —
 *     scanned via the ZCL_LINT_MODE doc-override run_gate_script supports;
 * (3) a planted fixture doc whose victory paragraph carries a citation token
 *     (VERDICT=PASS / gap_vs_oracle) passes;
 * (4) removing the fixtures recovers green;
 * (5) the gate is wired into the Makefile LINT_GATES list and documented in
 *     DEFENSIVE_CODING.md's canonical block. */
int t_no_uncited_victory(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;

    unlink_rel(NO_UNCITED_VICTORY_FIXTURE_REL);
    unlink_rel(NO_UNCITED_VICTORY_CITED_FIXTURE_REL);

    int baseline_rc = run_gate_script(NO_UNCITED_VICTORY_SCRIPT_REL, NULL);

    /* Uncited victory: >= 10 lines (clears the hollow-gate floor) with a
     * victory paragraph that carries no citation token. */
    const char *uncited_body =
        "# fixture handoff\n"
        "\n"
        "The node is at tip and fully synced now, all good.\n"
        "No citation token appears in this paragraph, on purpose.\n"
        "\n"
        "Pad line one to clear the hollow-gate line floor.\n"
        "Pad line two to clear the hollow-gate line floor.\n"
        "Pad line three to clear the hollow-gate line floor.\n"
        "Pad line four to clear the hollow-gate line floor.\n"
        "Pad line five to clear the hollow-gate line floor.\n"
        "Pad line six to clear the hollow-gate line floor.\n";

    int uncited_planted =
        (repo_path(path, sizeof(path), NO_UNCITED_VICTORY_FIXTURE_REL) == 0 &&
         write_file(path, uncited_body) == 0) ? 0 : -1;
    int trip_rc =
        uncited_planted == 0
            ? run_gate_script(NO_UNCITED_VICTORY_SCRIPT_REL,
                              NO_UNCITED_VICTORY_FIXTURE_REL)
            : -1;
    unlink_rel(NO_UNCITED_VICTORY_FIXTURE_REL);

    /* Cited victory: same victory phrase, but the paragraph carries citation
     * tokens, so the gate must pass. */
    const char *cited_body =
        "# fixture handoff\n"
        "\n"
        "The soak run reached tip and held at tip: VERDICT=PASS,\n"
        "gap_vs_oracle=0. This paragraph carries a citation token.\n"
        "\n"
        "Pad line one to clear the hollow-gate line floor.\n"
        "Pad line two to clear the hollow-gate line floor.\n"
        "Pad line three to clear the hollow-gate line floor.\n"
        "Pad line four to clear the hollow-gate line floor.\n"
        "Pad line five to clear the hollow-gate line floor.\n"
        "Pad line six to clear the hollow-gate line floor.\n";

    int cited_planted =
        (repo_path(path, sizeof(path),
                   NO_UNCITED_VICTORY_CITED_FIXTURE_REL) == 0 &&
         write_file(path, cited_body) == 0) ? 0 : -1;
    int cited_rc =
        cited_planted == 0
            ? run_gate_script(NO_UNCITED_VICTORY_SCRIPT_REL,
                              NO_UNCITED_VICTORY_CITED_FIXTURE_REL)
            : -1;
    unlink_rel(NO_UNCITED_VICTORY_CITED_FIXTURE_REL);

    int recover_rc = run_gate_script(NO_UNCITED_VICTORY_SCRIPT_REL, NULL);

    int makefile_wired = 0;
    if (repo_path(path, sizeof(path), "Makefile") == 0 &&
        read_entire_file(path, &makefile_buf) == 0) {
        makefile_wired =
            strstr(makefile_buf, "check-no-uncited-victory:") != NULL &&
            strstr(makefile_buf, "check-no-uncited-victory \\") != NULL;
    }
    int doc_wired = 0;
    if (repo_path(path, sizeof(path), "docs/DEFENSIVE_CODING.md") == 0 &&
        read_entire_file(path, &doc_buf) == 0) {
        doc_wired = strstr(doc_buf, "check-no-uncited-victory") != NULL;
    }

    TEST("[lint-gate] check-no-uncited-victory: clean HANDOFF passes, uncited "
         "victory fixture trips, cited fixture passes, recovers, wired") {
        ASSERT(baseline_rc == 0);
        ASSERT(uncited_planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(cited_planted == 0);
        ASSERT(cited_rc == 0);
        ASSERT(recover_rc == 0);
        ASSERT(makefile_wired);
        ASSERT(doc_wired);
        PASS();
    } _test_next:;
    free(makefile_buf);
    free(doc_buf);
    return failures;
}

/* check-no-stray-root-files — the repository root is a curated list: git's
 * tracked top-level entries plus a short allowlist of generated/local ones
 * (build/, vendor/, test-tmp/, compile_commands.json, tool caches). Proof:
 * (1) the clean tree passes; (2) a planted stray root file trips the gate —
 *     it is gitignored (*.db), which is exactly the class that used to sit
 *     in the root forever because `git status` never objected;
 * (3) removing it recovers green; (4) the gate is wired into the Makefile
 *     LINT_GATES list and documented in DEFENSIVE_CODING.md's canonical
 *     block. Runs on the real worktree (it reads git ls-files). */
#define ROOT_STRAY_SCRIPT_REL  "tools/lint/check_no_stray_root_files.sh"
#define ROOT_STRAY_FIXTURE_REL "zcl_root_stray_lint_fixture.db"

int t_no_stray_root_files(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;

    unlink_rel(ROOT_STRAY_FIXTURE_REL);
    int baseline_rc = run_gate_script(ROOT_STRAY_SCRIPT_REL, NULL);

    int planted =
        (repo_path(path, sizeof(path), ROOT_STRAY_FIXTURE_REL) == 0 &&
         write_file(path, "stray root debris\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(ROOT_STRAY_SCRIPT_REL, NULL) : -1;
    unlink_rel(ROOT_STRAY_FIXTURE_REL);
    int recover_rc = run_gate_script(ROOT_STRAY_SCRIPT_REL, NULL);

    int makefile_wired = 0;
    if (repo_path(path, sizeof(path), "Makefile") == 0 &&
        read_entire_file(path, &makefile_buf) == 0) {
        makefile_wired =
            strstr(makefile_buf, "check-no-stray-root-files:") != NULL &&
            strstr(makefile_buf, "check-no-stray-root-files \\") != NULL;
    }
    int doc_wired = 0;
    if (repo_path(path, sizeof(path), "docs/DEFENSIVE_CODING.md") == 0 &&
        read_entire_file(path, &doc_buf) == 0) {
        doc_wired = strstr(doc_buf, "check-no-stray-root-files") != NULL;
    }

    TEST("[lint-gate] check-no-stray-root-files: clean root passes, planted "
         "gitignored stray trips, recovers, wired") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        ASSERT(makefile_wired);
        ASSERT(doc_wired);
        PASS();
    } _test_next:;
    free(makefile_buf);
    free(doc_buf);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_hyg_unit;

#endif /* ZCL_TESTING */
