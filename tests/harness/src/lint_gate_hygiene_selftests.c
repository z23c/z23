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

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; on
 * _WIN32 every check compiles out and the group entry points report a skip. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

int run_git_hooks_gate_with_path(const char *hooks_path)
{
    return run_gate_script_with_env(GIT_HOOKS_SCRIPT_REL,
                                    "ZCL_GIT_HOOKS_PATH_FOR_TEST",
                                    hooks_path);
}

/* Like run_git_hooks_gate_with_path, but also points ZCL_GIT_HOOK_ROOT at a
 * private fixture root so the verdict never depends on this checkout's own
 * installed hooks. */
int run_git_hooks_gate_with_path_root(const char *hooks_path, const char *root)
{
    return run_gate_script_with_env2(GIT_HOOKS_SCRIPT_REL,
                                     "ZCL_GIT_HOOKS_PATH_FOR_TEST", hooks_path,
                                     "ZCL_GIT_HOOK_ROOT", root);
}

int run_git_hooks_gate_with_file(const char *hook_path, const char *root)
{
    return run_gate_script_with_env3(
        GIT_HOOKS_SCRIPT_REL,
        "ZCL_GIT_HOOKS_PATH_FOR_TEST", "build/githooks",
        "ZCL_GIT_HOOK_FILE_FOR_TEST", hook_path,
        "ZCL_GIT_HOOK_ROOT", root);
}

int run_git_hooks_gate_with_precommit_file(const char *hook_path,
                                           const char *root)
{
    return run_gate_script_with_env3(
        GIT_HOOKS_SCRIPT_REL,
        "ZCL_GIT_HOOKS_PATH_FOR_TEST", "build/githooks",
        "ZCL_GIT_HOOK_PRECOMMIT_FILE_FOR_TEST", hook_path,
        "ZCL_GIT_HOOK_ROOT", root);
}

/* hermetic git-hooks-installed fixture: check_git_hooks_installed.sh
 * compares against ZCL_GIT_HOOK_ROOT, so a private installed-hooks tree is
 * built under test-tmp/ with tools/scripts/install_git_hooks.sh. */
#define GIT_HOOKS_FIXTURE_ROOT_PREFIX "test-tmp/_git_hooks_fixture_root_tmp"
#define INSTALL_GIT_HOOKS_SCRIPT_REL "tools/scripts/install_git_hooks.sh"

static int run_git_init(const char *dir)
{
    pid_t pid = fork_with_retry();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execlp("git", "git", "init", "-q", dir, (char *)NULL);
        _exit(127);
    }
    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    if (WIFEXITED(rc))
        return WEXITSTATUS(rc);
    return -1;
}

/* Runs the real install recipe (mirrors `make install-hooks`) with the
 * checkout-writing seams pointed at the fixture root. */
static int run_install_git_hooks(const char *source_root, const char *root,
                                 const char *native_bin)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), INSTALL_GIT_HOOKS_SCRIPT_REL) != 0)
        return -1;

    pid_t pid = fork_with_retry();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        (void)setenv("ZCL_GIT_HOOK_SOURCE_ROOT", source_root, 1);
        (void)setenv("ZCL_GIT_HOOK_ROOT", root, 1);
        (void)setenv("ZCL_GIT_HOOK_NATIVE_BIN", native_bin, 1);
        (void)setenv("ZCL_GIT_HOOK_HOST", "posix", 1);
        execl(script, script, (char *)NULL);
        _exit(127);
    }
    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    if (WIFEXITED(rc))
        return WEXITSTATUS(rc);
    return -1;
}

/* Builds the fixture root and returns 0 on success, filling `fixture_root`
 * with its absolute path. Caller must teardown_git_hooks_fixture() it. */
static int build_git_hooks_fixture(char *fixture_root, size_t cap)
{
    char dir[PATH_MAX], native_bin[PATH_MAX], real_bin[PATH_MAX];
    const char *root_repo;

    if (repo_path_pid(fixture_root, cap, GIT_HOOKS_FIXTURE_ROOT_PREFIX, "")
        != 0)
        return -1;
    (void)test_rm_rf_recursive(fixture_root);
    if (mkdir(fixture_root, 0755) != 0)
        return -1;
    /* install_git_hooks.sh refuses a non-worktree ROOT and scopes
     * core.hooksPath --worktree to this private repo only. */
    if (run_git_init(fixture_root) != 0)
        return -1;
    if (snprintf(dir, sizeof(dir), "%s/build", fixture_root) >= (int)sizeof(dir)
        || mkdir(dir, 0755) != 0)
        return -1;
    if (snprintf(dir, sizeof(dir), "%s/build/bin", fixture_root)
            >= (int)sizeof(dir)
        || mkdir(dir, 0755) != 0)
        return -1;
    if (repo_path(real_bin, sizeof(real_bin), "build/bin/z23-git-hook") != 0)
        return -1;
    if (snprintf(native_bin, sizeof(native_bin), "%s/build/bin/z23-git-hook",
                fixture_root) >= (int)sizeof(native_bin))
        return -1;
    if (copy_file(real_bin, native_bin) != 0)
        return -1;
    if (chmod(native_bin, 0755) != 0)
        return -1;
    root_repo = repo_root();
    if (!root_repo)
        return -1;
    if (run_install_git_hooks(root_repo, fixture_root, native_bin) != 0)
        return -1;
    return 0;
}

static void teardown_git_hooks_fixture(const char *fixture_root)
{
    if (fixture_root && fixture_root[0])
        (void)test_rm_rf_recursive(fixture_root);
}

int t_git_hooks_gate_enforces_tracked_pre_push(void)
{
    int failures = 0;
    char fixture_root[PATH_MAX];
    int fixture_ok = build_git_hooks_fixture(fixture_root,
                                             sizeof(fixture_root)) == 0;
    TEST("[lint-gate] local pre-push hook gate enforces native worktree hooks") {
        ASSERT(run_git_hooks_gate_with_path(".git/hooks") != 0);
        ASSERT(fixture_ok);
        ASSERT(run_git_hooks_gate_with_path_root("build/githooks",
                                                 fixture_root) == 0);
        PASS();
    } _test_next:;
    if (fixture_ok)
        teardown_git_hooks_fixture(fixture_root);
    return failures;
}

int t_git_hooks_gate_rejects_noop_pre_push(void)
{
    int failures = 0;
    char hook_path[PATH_MAX], fixture_path[PATH_MAX], fixture_root[PATH_MAX];
    char *orig = NULL;
    int resolved = repo_path(hook_path, sizeof(hook_path),
                             GIT_HOOKS_PRE_PUSH_REL);
    int fixture_resolved = repo_path_pid(fixture_path, sizeof(fixture_path),
                                         GIT_HOOKS_PRE_PUSH_FIXTURE_REL, "");
    int fixture_ok = build_git_hooks_fixture(fixture_root,
                                             sizeof(fixture_root)) == 0;
    int read_ok = (resolved == 0 && fixture_resolved == 0 && fixture_ok &&
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
            original_rc = run_git_hooks_gate_with_file(fixture_path,
                                                       fixture_root);
        wrote_noop = (write_file(fixture_path,
                      "#!/usr/bin/env bash\n"
                      "# fixture: no local CI gate\n"
                      "exit 0\n") == 0 &&
                      chmod(fixture_path, 0755) == 0);
        if (wrote_noop)
            noop_rc = run_git_hooks_gate_with_file(fixture_path,
                                                    fixture_root);
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
    if (fixture_ok)
        teardown_git_hooks_fixture(fixture_root);
    return failures;
}

int t_git_hooks_gate_rejects_noop_pre_commit(void)
{
    int failures = 0;
    char hook_path[PATH_MAX], fixture_path[PATH_MAX], fixture_root[PATH_MAX];
    char *orig = NULL;
    int resolved = repo_path(hook_path, sizeof(hook_path),
                             GIT_HOOKS_PRECOMMIT_REL);
    int fixture_resolved = repo_path_pid(fixture_path, sizeof(fixture_path),
                                         GIT_HOOKS_PRECOMMIT_FIXTURE_REL, "");
    int fixture_ok = build_git_hooks_fixture(fixture_root,
                                             sizeof(fixture_root)) == 0;
    int read_ok = (resolved == 0 && fixture_resolved == 0 && fixture_ok &&
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
            original_rc = run_git_hooks_gate_with_precommit_file(
                fixture_path, fixture_root);
        wrote_noop = (write_file(fixture_path,
                      "#!/usr/bin/env bash\n"
                      "# fixture: no main-checkout lane guard\n"
                      "exit 0\n") == 0 &&
                      chmod(fixture_path, 0755) == 0);
        if (wrote_noop)
            noop_rc = run_git_hooks_gate_with_precommit_file(fixture_path,
                                                             fixture_root);
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
    if (fixture_ok)
        teardown_git_hooks_fixture(fixture_root);
    return failures;
}

/* Systemd memory budget: the live repo units must fit under the host budget;
 * the script parser self-test covers over-budget, infinity, invalid-size,
 * absent-cap, and drop-in override behavior. The baseline run pins
 * ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES (as build.yml does) so the
 * verdict is independent of host RAM. */
/* ~93 GiB; keep identical to build.yml's ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES. */
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

/* Unattended quality lanes yield to every active mint service and bound
 * their dated logs without touching status, artifacts, or symlinks. The
 * standalone test uses hermetic systemctl/logger/lane fixtures. */
int t_quality_job_guard(void)
{
    int failures = 0;
    TEST("[tooling] quality jobs yield to mint and retain bounded logs") {
        ASSERT(run_gate_script(QUALITY_GUARD_TEST_REL, NULL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* tools/scripts/import-copy-prove-selftest.sh: hermetic proof that the
 * copy-prove driver computes the mode-appropriate gate set and verdict in
 * --mode=import and --mode=bundle with faked node/RPC fixtures. Watched for
 * progress, not runtime (run_gate_script_watched). */
int t_import_copy_prove_selftest(void)
{
    int failures = 0;
    TEST("[tooling] import-copy-prove driver gates import+bundle modes "
         "correctly (hermetic)") {
        int rc = run_gate_script_watched(IMPORT_COPY_PROVE_SELFTEST_REL,
                                         GATE_SELFTEST_MAX_SILENT_SECS,
                                         GATE_SELFTEST_SILENCE_DERIVATION);
        /* Two assertions on purpose: the first names a HANG, the second a
         * LOGIC failure. */
        ASSERT(rc != GATE_SCRIPT_WEDGED);
        ASSERT(rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* tools/scripts/fresh-boot-weld-prove-selftest.sh: hermetic proof that the
 * cold-boot weld driver classifies every boot outcome into the correct
 * verdict and exit code, using a faked $ZCL_NODE_BIN. The fixture advances
 * one height per sample and the driver takes its minimum samples before its
 * deadline, so the result is load-independent. */
int t_fresh_boot_weld_prove_selftest(void)
{
    int failures = 0;
    TEST("[tooling] fresh-boot-weld-prove driver gates the zero-flag weld "
         "boot outcomes correctly (hermetic)") {
        int rc = run_gate_script_watched(FRESH_BOOT_WELD_PROVE_SELFTEST_REL,
                                         GATE_SELFTEST_MAX_SILENT_SECS,
                                         GATE_SELFTEST_SILENCE_DERIVATION);
        ASSERT(rc != GATE_SCRIPT_WEDGED);  /* a hang — diagnosed on stderr */
        ASSERT(rc == 0);                   /* a logic verdict */
        PASS();
    } _test_next:;
    return failures;
}

/* Return 0 when no tracked, active file refers to the retired tools/z path,
 * 1 when git grep finds one, -1 on a harness error. Work archives and this
 * test source (which owns the tombstone pattern) are excluded. */
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
               ":!tests/harness/src/lint_gate_hygiene_selftests.c", (char *)NULL);
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
            "engine/composition/src/boot_services.c",
            "engine/composition/src/boot_flyclient.c",
            "engine/composition/src/boot_background_workers.c",
            "engine/composition/src/boot_msg_callbacks.c",
            "engine/composition/src/boot.c",
            "engine/modules/storage/include/storage/utxo_reimport_flag.h",
            "core/modules/validation/include/validation/process_block.h",
            "core/modules/validation/src/process_block_core.c",
            "core/modules/net/src/connman.c",
            "engine/jobs/include/jobs/header_probe_poll.h",
            "engine/services/include/services/block_source_policy.h",
            "engine/services/src/block_source_policy_runtime.c",
            "engine/services/src/block_source_policy_status.c",
            "engine/services/src/block_source_policy_persist.c",
            "engine/services/src/block_source_policy_decisions.c",
            "engine/services/src/chain_restore_executor.c",
            "engine/services/src/chain_restore_repair.c",
            "engine/modules/storage/src/utxo_reimport_flag.c",
            "engine/services/src/utxo_recovery_restore.c",
            "platform/modules/util/include/util/stage.h",
            "engine/modules/storage/include/storage/progress_store.h",
            "engine/supervisors/include/supervisors/staged_sync_supervisor.h",
            "engine/jobs/include/jobs/utxo_apply_delta.h",
            "engine/jobs/include/jobs/header_admit_stage.h",
            "engine/jobs/include/jobs/validate_headers_stage.h",
            "engine/jobs/include/jobs/body_fetch_stage.h",
            "engine/jobs/src/utxo_apply_delta.c",
            "engine/jobs/src/utxo_apply_delta_reorg.c",
            "engine/jobs/src/utxo_apply_stage.c",
            "engine/jobs/include/jobs/block_header_emit.h",
            "engine/jobs/include/jobs/body_persist_stage.h",
            "engine/jobs/include/jobs/script_validate_stage.h",
            "engine/jobs/include/jobs/proof_validate_stage.h",
            "engine/jobs/include/jobs/utxo_apply_stage.h",
            "engine/jobs/include/jobs/tip_finalize_stage.h",
            "engine/jobs/include/jobs/job.h",
            "engine/jobs/include/jobs/stage_helpers.h",
            "engine/jobs/README.md",
            "engine/jobs/src/body_persist_stage.c",
            "engine/jobs/src/script_validate_stage.c",
            "engine/jobs/src/proof_validate_stage.c",
            "engine/jobs/src/tip_finalize_stage.c",
            "engine/jobs/src/header_admit_stage.c",
            "engine/reducer/jobs/src/stage_repair_reducer_frontier_refill.c",
            "engine/reducer/jobs/src/stage_repair_reducer_frontier_refill_scan.c",
            "engine/jobs/src/tip_finalize_post_step.h",
            "engine/jobs/src/validate_headers_internal.h",
            "engine/jobs/src/validate_headers_report.c",
            "engine/jobs/src/validate_headers_validator.c",
            "contexts/wallet/controllers/src/wallet_controller_history.c",
            "engine/controllers/src/transaction_controller_sign.c",
            "contexts/wallet/controllers/src/wallet_controller_keys.c",
            "engine/controllers/src/repair_controller_utxo.c",
            "contexts/wallet/controllers/src/wallet_controller_multisig.c",
            "engine/controllers/src/store_controller_schema.c",
            "contexts/wallet/controllers/src/wallet_shielded_send.c",
            "contexts/wallet/controllers/src/wallet_shielded_keys.c",
            "contexts/wallet/controllers/src/wallet_shielded_send_shielded.c",
            "contexts/wallet/controllers/src/wallet_shielded_controller.c",
            "contexts/wallet/controllers/src/wallet_rescan_controller_coins.c",
            "contexts/wallet/controllers/src/wallet_rescan_controller_witness.c",
            "contexts/wallet/controllers/src/wallet_view_emit.c",
            "contexts/wallet/controllers/src/wallet_view_sync.c",
            "engine/controllers/src/sync_controller_import.c",
            "engine/controllers/src/sync_controller_catchup.c",
            "engine/controllers/src/sync_controller_catchup_jobs.c",
            "engine/controllers/include/controllers/diagnostics_controller.h",
            "engine/controllers/src/api_controller_node.c",
            "engine/controllers/src/blockchain_controller_chain.c",
            "contexts/explorer/controllers/src/explorer_controller_block.c",
            "contexts/explorer/controllers/src/explorer_controller_pages.c",
            "contexts/explorer/controllers/src/explorer_controller_dashboard.c",
            "contexts/explorer/controllers/src/explorer_controller_address.c",
            "contexts/wallet/controllers/src/wallet_view_helpers.c",
            "engine/controllers/src/sync_controller_blocks.c",
            "engine/controllers/src/sync_controller_writers.c",
            "contexts/explorer/views/include/views/explorer_stats_view.h",
            "contexts/explorer/views/include/views/explorer_block_view.h",
            "contexts/explorer/views/include/views/explorer_pages_view.h",
            "contexts/explorer/views/include/views/explorer_dashboard_view.h",
            "contexts/explorer/views/include/views/store_internal.h",
            "contexts/explorer/views/include/views/explorer_address_view.h",
            "contexts/explorer/views/include/views/explorer_pages_loading_view.h",
            "contexts/explorer/views/include/views/explorer_tx_view.h",
            "contexts/wallet/views/include/views/wallet_gui_internal.h",
            "contexts/explorer/views/src/store_view.c",
            "contexts/explorer/views/src/explorer_factoids_view.c",
            "contexts/explorer/views/src/explorer_stats_view.c",
            "contexts/explorer/views/src/explorer_factoids_history.c",
            "contexts/explorer/views/src/explorer_factoids_chaindata.c",
            "contexts/explorer/views/include/views/explorer_factoids_view.h",
            "contexts/explorer/views/src/explorer_pages_hodl.c",
            "contexts/explorer/views/src/explorer_block_view.c",
            "contexts/explorer/views/src/explorer_stats_gather.c",
            "contexts/explorer/views/src/explorer_stats_sections.c",
            "contexts/explorer/views/src/explorer_pages_loading_view.c",
            "contexts/explorer/views/src/explorer_address_view.c",
            "contexts/explorer/views/src/explorer_pages_view.c",
            "contexts/explorer/views/src/explorer_dashboard_view.c",
            "contexts/wallet/views/src/wallet_gui_bot.c",
            "contexts/wallet/views/src/wallet_gui.c",
            "contexts/explorer/views/include/views/explorer_main_view.h",
            "contexts/explorer/views/src/explorer_main_view.c",
            "contexts/explorer/views/src/explorer_tx_view.c",
            "contexts/wallet/views/include/views/wallet_view_coins_view.h",
            "contexts/wallet/views/src/wallet_view_coins_view.c",
            "contexts/wallet/views/include/views/wallet_view_dashboard_view.h",
            "contexts/wallet/views/src/wallet_view_dashboard_view.c",
            "contexts/wallet/views/include/views/wallet_view_history_view.h",
            "contexts/wallet/views/src/wallet_view_history_view.c",
            "contexts/wallet/views/include/views/wallet_view_node_view.h",
            "contexts/wallet/views/src/wallet_view_node_view.c",
            "contexts/wallet/views/include/views/wallet_view_shield_view.h",
            "contexts/wallet/views/src/wallet_view_shield_view.c",
            "engine/services/src/block_source_policy_internal.h",
            "engine/controllers/include/controllers/diagnostics_internal.h",
            "engine/controllers/src/diagnostics_controller.c",
            "engine/services/src/block_index_loader_rebuild.c",
            "engine/services/src/utxo_recovery_service.c",
            "engine/services/src/chain_evidence_reconstruct.c",
            "engine/services/src/bg_validation_scripts.c",
            "engine/services/include/services/block_index_loader.h",
            "engine/services/include/services/utxo_recovery_service.h",
            "engine/services/src/bg_validation_proofs.c",
            "engine/services/src/bg_validation_internal.h",
            "engine/services/src/block_index_loader.c",
            "engine/services/src/chain_evidence_persistence_service.c",
            "engine/services/src/consensus_reject_index.c",
            "engine/services/include/services/chain_state_validator.h",
            "engine/services/src/chain_state_validator.c",
            "engine/services/src/utxo_recovery_backfill.c",
            "engine/services/src/snapshot_sync_service.c",
            "engine/services/src/snapshot_sync_internal.h",
            "engine/services/src/snapshot_offer.c",
            "engine/services/src/snapshot_fetch.c",
            "engine/services/src/snapshot_verify.c",
            "engine/services/src/snapshot_apply.c",
            "engine/services/include/services/chain_activation_service.h",
            "engine/services/src/chain_activation_service.c",
            "engine/supervisors/include/supervisors/chain_supervisor.h",
            "engine/models/include/models/database_internal.h",
            "contexts/wallet/models/include/models/wallet_tx_internal.h",
            "engine/models/include/models/header_admit_log.h",
            "engine/models/src/database_modes.c",
            "engine/models/src/database_migrate.c",
            "engine/models/src/sapling_note.c",
            "contexts/wallet/models/src/wallet_tx_reads.c",
            "engine/controllers/src/hodl_controller.c",
            "engine/controllers/src/mining_controller.c",
            "engine/controllers/src/repair_controller_rebuild.c",
            "engine/supervisors/src/net_supervisor.c",
            "engine/supervisors/src/staged_sync_supervisor.c",
            "engine/supervisors/src/chain_supervisor.c",
            "engine/composition/src/boot_snapshot_import.c",
            "engine/composition/src/boot_index.c",
            "tools/sim/chaos.c",
            "core/modules/crypto_registry/include/crypto_registry/crypto_registry.h",
            "core/modules/crypto_registry/src/crypto_registry.c",
            "platform/modules/platform/include/platform/clock.h",
            "platform/modules/platform/include/platform/rng.h",
            "platform/modules/platform/include/platform/time_compat.h",
            "platform/modules/platform/src/clock.c",
            "platform/modules/platform/src/rng.c",
            "engine/modules/storage/include/storage/projection_util.h",
            "engine/modules/storage/include/storage/event_log.h",
            "engine/modules/storage/include/storage/event_log_payloads.h",
            "engine/modules/storage/include/storage/block_index_projection.h",
            "engine/modules/storage/include/storage/sha3_sidecar_io.h",
            "engine/modules/storage/src/event_log.c",
            "engine/modules/storage/src/mempool_projection.c",
            "engine/modules/storage/src/peers_projection.c",
            "engine/modules/storage/src/wallet_projection.c",
            "engine/modules/storage/src/znam_projection.c",
            "engine/controllers/src/diagnostics_registry.c",
            "core/modules/validation/include/validation/accept_block_header.h",
            "core/modules/validation/include/validation/process_block_invalidate.h",
            "core/modules/validation/include/validation/process_block_revalidate.h",
            "core/modules/validation/src/accept_block_header.c",
            "core/modules/validation/src/process_block.c",
            "core/modules/validation/src/process_block_crash_hooks.c",
            "core/modules/validation/src/process_block_failed_child.c",
            "core/modules/validation/src/process_block_flush_policy.c",
            "core/modules/validation/src/process_block_invalidate.c",
            "core/modules/validation/src/process_block_internal.h",
            "core/modules/validation/src/process_block_revalidate.c",
            "core/modules/validation/src/process_block_self_heal.c",
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

/* check-no-dev-history-in-contracts - rejects dev-history phrasing ("STEP-0
 * STATUS", "stub bodies", "lane <N><letter>", "future slice") from
 * production contract surfaces (*.h under include/, *.def). Proof:
 * (1) the clean tree passes; (2) a fixture with the *_test.* allowlist
 * suffix is ignored despite banned phrases; (3) the same content under a
 * non-allowlisted name trips the gate; (4) removing it recovers green;
 * (5) the gate is in LINT_GATES and DEFENSIVE_CODING.md's canonical block. */
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

/* check-no-uncited-victory - docs/HANDOFF.md may not carry a victory phrase
 * ("at tip", "cured", "wedge closed", ...) without a machine-checkable
 * citation token in the same paragraph. Proof:
 * (1) the clean tree passes;
 * (2) a fixture doc with an uncited victory paragraph trips the gate
 *     (via the ZCL_LINT_MODE doc-override);
 * (3) one carrying a citation token (VERDICT=PASS / gap_vs_oracle) passes;
 * (4) removing the fixtures recovers green;
 * (5) the gate is in LINT_GATES and DEFENSIVE_CODING.md's canonical block. */
/* check-no-invented-node-credentials - production frontends and repair
 * paths read node RPC credentials from conf/cookie/boot configuration and
 * refuse by name when none exist. Proof is source-level; the wallet-view
 * helper keeps its positive refusal marker pinned below. The
 * env-overridable default in tools/harvest_checkpoints.sh stays (shell
 * tooling over operator-supplied credentials). */
int t_wallet_view_never_invents_rpc_credentials(void)
{
    static const char *const guarded[] = {
        "contexts/wallet/controllers/src/wallet_view_helpers.c",
        "engine/controllers/src/api_controller.c",
        "contexts/explorer/controllers/src/explorer_controller.c",
        "engine/entry/main_cli_modes.c",
        "engine/controllers/src/repair_controller_utxo.c",
    };
    int failures = 0;
    char path[PATH_MAX];

    /* One TEST per function: ASSERT expands to a literal `_test_next` label. */
    TEST("[lint-gate] no invented node credentials remain in guarded files") {
        for (size_t i = 0; i < sizeof(guarded) / sizeof(guarded[0]); i++) {
            char *buf = NULL;
            int have_source =
                repo_path(path, sizeof(path), guarded[i]) == 0 &&
                read_entire_file(path, &buf) == 0;
            if (!have_source || !buf)
                fprintf(stderr,
                        "[lint-gate] %s unreadable\n", guarded[i]);
            ASSERT(have_source);
            ASSERT(buf);
            if (strstr(buf, "zcluser:zclpass")) {
                fprintf(stderr,
                        "[lint-gate] invented credential pair still "
                        "present in %s\n",
                        guarded[i]);
                ASSERT(strstr(buf, "zcluser:zclpass") == NULL);
            }
            free(buf);
        }

        /* Positive pin: the wallet view keeps its named refusal. */
        char *wbuf = NULL;
        int wallet_readable =
            repo_path(path, sizeof(path),
                      "contexts/wallet/controllers/src/wallet_view_helpers.c") == 0 &&
            read_entire_file(path, &wbuf) == 0;
        ASSERT(wallet_readable && wbuf);
        ASSERT(strstr(wbuf, "no RPC credentials found") != NULL);
        free(wbuf);
        PASS();
    } _test_next:;
    return failures;
}

int t_no_uncited_victory(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;

    unlink_rel(NO_UNCITED_VICTORY_FIXTURE_REL);
    unlink_rel(NO_UNCITED_VICTORY_CITED_FIXTURE_REL);

    int baseline_rc = run_gate_script(NO_UNCITED_VICTORY_SCRIPT_REL, NULL);

    /* Uncited victory: >= 10 lines (clears the hollow-gate floor), no citation token. */
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

    /* Cited victory: the paragraph carries citation tokens, so the gate passes. */
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

/* check-no-stray-root-files - the repository root is a curated list: git's
 * tracked top-level entries plus a short allowlist of generated/local ones
 * (build/, vendor/, test-tmp/, compile_commands.json, tool caches). Proof:
 * (1) the clean tree passes; (2) its test-only override classifies Makefile
 * as a stray, without writing into the live source root; (3) removing the
 * override recovers green; (4) the gate is in LINT_GATES and
 * DEFENSIVE_CODING.md's canonical block. Runs on the real worktree. */
#define ROOT_STRAY_SCRIPT_REL  "tools/lint/check_no_stray_root_files.sh"

/* Evidence for a failed run_gate_script(ROOT_STRAY_SCRIPT_REL, ...) call:
 * reads back the gate's redirected output (bounded) and lists the root
 * directory now, so a transient stray is named. Read-only. */
#define ROOT_STRAY_CAPTURE_MAX (8 * 1024)

static void print_root_stray_gate_capture(void)
{
    char out_path[PATH_MAX];
    if (lint_gate_out_path(out_path, sizeof(out_path)) != 0) {
        fprintf(stderr,
                "[lint-gate] (capture unavailable: could not resolve gate "
                "output path)\n");
        return;
    }
    char *buf = NULL;
    if (read_entire_file(out_path, &buf) != 0 || !buf) {
        fprintf(stderr, "[lint-gate] (capture unavailable: could not read %s)\n",
                out_path);
        free(buf);
        return;
    }
    size_t len = strlen(buf);
    if (len > ROOT_STRAY_CAPTURE_MAX) {
        fprintf(stderr, "%.*s\n[lint-gate] (output truncated at %d bytes)\n",
                ROOT_STRAY_CAPTURE_MAX, buf, ROOT_STRAY_CAPTURE_MAX);
    } else {
        fprintf(stderr, "%s", buf);
        if (len == 0 || buf[len - 1] != '\n')
            fprintf(stderr, "\n");
    }
    free(buf);
}

static void print_root_listing_now(void)
{
    struct dirent **names = NULL;
    int nd = scandir(".", &names, NULL, alphasort);
    if (nd < 0) {
        fprintf(stderr,
                "[lint-gate] root listing at failure: (scandir failed: %s)\n",
                strerror(errno));
        return;
    }
    fprintf(stderr, "[lint-gate] root listing at failure:\n");
    for (int i = 0; i < nd; i++) {
        if (strcmp(names[i]->d_name, ".") != 0 &&
            strcmp(names[i]->d_name, "..") != 0)
            fprintf(stderr, "  %s\n", names[i]->d_name);
        free(names[i]);
    }
    free(names);
}

/* Compile the real selftest against fixed environment slots. Retired slots
 * remain readable, but restoration from one is rejected deterministically. */
static int clock_env_script(const char *cpath, const char *script, const char *binary)
{
    FILE *f = fopen(script, "w");
    if (!f) return -1;
#if defined(__APPLE__)
    const char *linker = "-Wl,-dead_strip";
#else
    const char *linker = "-Wl,--gc-sections";
#endif
    int err = fprintf(f, "#!/bin/sh\nset -eu\n"
        "cc -std=c23 -ffunction-sections -fdata-sections %s "
        "-Dgetenv=clock_env_get -Dsetenv=clock_env_set -Dunsetenv=clock_env_unset "
        "-Itools/lint/lintc -Iplatform/modules/base/include "
        "'%s' tools/lint/lintc/gate_tree_walk.c tools/lint/lintc/lib.c "
        "-o '%s' >/dev/null 2>&1\nexec '%s' >/dev/null 2>&1\n",
        linker, cpath, binary, binary) < 0;
    if (fclose(f)) err = 1;
    if (err || chmod(script, 0700)) return -1;
    return run_gate_script_watched(script, 30, "clock environment witness");
}

static int clock_env_witness(void)
{
    static const char source[] =
        "#define _POSIX_C_SOURCE 200809L\n"
        "#include <stdlib.h>\n#include <string.h>\n#include <stdio.h>\n"
        "#include \"lintc.h\"\n"
        "static char slots[8][8193]; static int used, active=-1, rejected;\n"
        "char *clock_env_get(const char *n) { return !strcmp(n,\"ZCL_LINT_MODE\")"
        " && active>=0 ? slots[active] : NULL; }\n"
        "int clock_env_set(const char *n,const char *v,int overwrite) {\n"
        " if(strcmp(n,\"ZCL_LINT_MODE\")) return -1;\n"
        " for(int i=0;i<used;i++) if(v==slots[i] && i!=active)"
        " { rejected++; return -1; }\n"
        " if(active>=0 && !overwrite) return 0;\n"
        " if(used==8 || strlen(v)>=sizeof slots[0]) return -1;\n"
        " memcpy(slots[used],v,strlen(v)+1); active=used++; return 0; }\n"
        "int clock_env_unset(const char *n) { if(strcmp(n,\"ZCL_LINT_MODE\"))"
        " return -1; active=-1; return 0; }\n"
        "static int check(const char *v,int expected) {\n"
        " used=0; active=-1; rejected=0;\n"
        " if(v && clock_env_set(\"ZCL_LINT_MODE\",v,1)) return 1;\n"
        " int before=used, rc=check_no_raw_clock_outside_platform_selftest();\n"
        " const char *got=clock_env_get(\"ZCL_LINT_MODE\");\n"
        " if(rc!=expected || rejected || (v ? !got || strcmp(v,got) : got!=NULL))"
        " { fprintf(stderr,\"clock environment restoration failed rc=%d rejected=%d\\n\","
        "rc,rejected); return 1; }\n"
        " return expected && used!=before; }\n"
        "int main(void) {\n"
        " if(clock_env_set(\"ZCL_LINT_MODE\",\"FAIL\",1)) return 10;\n"
        " const char *borrowed=clock_env_get(\"ZCL_LINT_MODE\");\n"
        " if(clock_env_set(\"ZCL_LINT_MODE\",\"WARN\",1) ||"
        " clock_env_set(\"ZCL_LINT_MODE\",borrowed,1)!=-1 || rejected!=1) return 11;\n"
        " if(check(\"FAIL\",0) || check(NULL,0) || check(\"\",0)) return 12;\n"
        " char big[8193]; memset(big,'x',8192); big[8192]=0;\n"
        " return check(big,2) ? 13 : 0; }\n";
    char dir[] = "test-tmp/_clock_env_fixtureXXXXXX";
    char cpath[PATH_MAX], script[PATH_MAX], binary[PATH_MAX];
    if (!mkdtemp(dir)) return -1;
    int rc = -1;
    if (snprintf(cpath, sizeof cpath, "%s/witness.c", dir) >= (int)sizeof cpath
        || snprintf(script, sizeof script, "%s/run.sh", dir) >= (int)sizeof script
        || snprintf(binary, sizeof binary, "%s/witness", dir) >= (int)sizeof binary) {
        (void)rmdir(dir);
        return -1;
    }
    FILE *f = fopen(cpath, "w");
    if (f) {
        int err = fputs(source, f) == EOF;
        if (fclose(f)) err = 1;
        if (!err) rc = clock_env_script(cpath, script, binary);
    }
    if (unlink(binary) && errno != ENOENT) rc = -1;
    if (unlink(script) && errno != ENOENT) rc = -1;
    if (unlink(cpath) && errno != ENOENT) rc = -1;
    if (rmdir(dir)) rc = -1;
    return rc;
}

int t_no_stray_root_files(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;

    int clock_env_rc = clock_env_witness();
    int baseline_rc = run_gate_script(ROOT_STRAY_SCRIPT_REL, NULL);
    if (baseline_rc != 0) {
        fprintf(stderr,
                "[lint-gate] check-no-stray-root-files baseline rc=%d; gate "
                "output follows\n", baseline_rc);
        print_root_stray_gate_capture();
        print_root_listing_now();
    }
    int trip_rc = run_gate_script_with_env(
        ROOT_STRAY_SCRIPT_REL, "ZCL_ROOT_STRAY_EXTRA_FOR_TEST", "Makefile");
    int recover_rc = run_gate_script(ROOT_STRAY_SCRIPT_REL, NULL);
    if (recover_rc != 0) {
        fprintf(stderr,
                "[lint-gate] check-no-stray-root-files recover rc=%d; gate "
                "output follows\n", recover_rc);
        print_root_stray_gate_capture();
        print_root_listing_now();
    }

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

    TEST("[lint-gate] check-no-stray-root-files: clean root passes, isolated "
         "classification trips, recovers, wired") {
        ASSERT(clock_env_rc == 0);
        ASSERT(baseline_rc == 0);
        ASSERT(trip_rc == 1);
        ASSERT(recover_rc == 0);
        ASSERT(makefile_wired);
        ASSERT(doc_wired);
        PASS();
    } _test_next:;
    free(makefile_buf);
    free(doc_buf);
    return failures;
}

/* check-lint-gate-wiring - the umbrella's two files must agree: a gate is
 * a Makefile target + LINT_GATES line and a gate_command() case in
 * tools/lint/run_lint.sh. Proof:
 * (1) the real tree passes;
 * (2) the gate's --selftest passes (plants a listed-but-unwired gate, a
 *     wired-but-unlisted one, a listed name with no Make target, a missing
 *     script, an unreadable LINT_GATES; each is rejected and named, plus a
 *     positive control);
 * (3) a tree with no run_lint.sh FAILS rather than reporting clean;
 * (4) the gate is itself in LINT_GATES, run_lint.sh's case table, and
 *     DEFENSIVE_CODING.md's canonical block. */
/* ── check-doc-inline-paths, C port: the native gate on two generated
 * fixtures. A clean tree must PASS (exit 0); one seeded dead path must
 * FAIL (exit 1) and name the doc line it sits on. A fixture has no .git,
 * so the gate walks it. ─────────────────────────────────────────────── */

enum { DIP_LIB_DIRS = 24, DIP_FILES = 120, DIP_REFS = 210 };
/* "# Index" is line 1, the DIP_REFS references follow, the seed comes next. */
#define DIP_SEED_LINE (1 + DIP_REFS + 1)

static int dip_fixture_files(const char *root)
{
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s/lib", root) >= (int)sizeof p || mkdir(p, 0755) != 0)
        return 1;
    for (int k = 0; k < DIP_LIB_DIRS; k++) {
        if (snprintf(p, sizeof p, "%s/lib/m%d", root, k) >= (int)sizeof p
            || mkdir(p, 0755) != 0)
            return 1;
    }
    for (int j = 0; j < DIP_FILES; j++) {
        FILE *f = NULL;
        if (snprintf(p, sizeof p, "%s/lib/m%d/f%d.c", root, j % DIP_LIB_DIRS, j) >= (int)sizeof p)
            return 1;
        f = fopen(p, "w");
        if (!f || fputs("int x;\n", f) < 0 || fclose(f) != 0)
            return 1;
    }
    return 0;
}

static int dip_fixture_doc(const char *root, int seeded)
{
    char p[PATH_MAX];
    if (snprintf(p, sizeof p, "%s/docs", root) >= (int)sizeof p || mkdir(p, 0755) != 0)
        return 1;
    if (snprintf(p, sizeof p, "%s/docs/index.md", root) >= (int)sizeof p)
        return 1;
    FILE *f = fopen(p, "w");
    if (!f || fprintf(f, "# Index\n") < 0)
        return 1;
    for (int i = 0; i < DIP_REFS; i++) {
        int j = i % DIP_FILES;
        if (fprintf(f, "`lib/m%d/f%d.c`\n", j % DIP_LIB_DIRS, j) < 0) {
            fclose(f);
            return 1;
        }
    }
    if (seeded && fprintf(f, "Old flow: `lib/gone/missing.c`\n") < 0) {
        fclose(f);
        return 1;
    }
    return fclose(f) == 0 ? 0 : 1;
}

static int dip_run(const char *exe, const char *root, const char *out, int *rc_out)
{
    pid_t pid = fork_with_retry();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        int fd = open(out, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0 || chdir(root) != 0)
            _exit(127);
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        close(fd);
        execl(exe, "z23-lint", "check-doc-inline-paths", (char *)NULL);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR)
            return 1;
    }
    if (!WIFEXITED(st))
        return 1;
    *rc_out = WEXITSTATUS(st);
    return 0;
}

static int dip_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return 0;
}

static void dip_cleanup(const char *root)
{
    char p[PATH_MAX];
    for (int j = 0; j < DIP_FILES; j++) {
        if (snprintf(p, sizeof p, "%s/lib/m%d/f%d.c", root, j % DIP_LIB_DIRS, j) < (int)sizeof p)
            unlink(p);
    }
    for (int k = 0; k < DIP_LIB_DIRS; k++) {
        if (snprintf(p, sizeof p, "%s/lib/m%d", root, k) < (int)sizeof p)
            rmdir(p);
    }
    if (snprintf(p, sizeof p, "%s/lib", root) < (int)sizeof p)
        rmdir(p);
    if (snprintf(p, sizeof p, "%s/docs/index.md", root) < (int)sizeof p)
        unlink(p);
    if (snprintf(p, sizeof p, "%s/docs", root) < (int)sizeof p)
        rmdir(p);
    rmdir(root);
}

struct dip_roots {
    char tmpl[PATH_MAX], clean[PATH_MAX], seeded[PATH_MAX];
    char clean_out[PATH_MAX], seeded_out[PATH_MAX];
};

static int dip_join(char *out, size_t cap, const char *dir, const char *leaf)
{
    return snprintf(out, cap, "%s/%s", dir, leaf) >= (int)cap;
}

static int dip_roots_make(struct dip_roots *R, const char *base)
{
    if (snprintf(R->tmpl, sizeof R->tmpl, "%s/doc-inline-paths-XXXXXX", base) >= (int)sizeof R->tmpl
        || mkdtemp(R->tmpl) == NULL)
        return 1;
    if (dip_join(R->clean, sizeof R->clean, R->tmpl, "clean")
        || dip_join(R->seeded, sizeof R->seeded, R->tmpl, "seeded")
        || dip_join(R->clean_out, sizeof R->clean_out, R->tmpl, "clean.out")
        || dip_join(R->seeded_out, sizeof R->seeded_out, R->tmpl, "seeded.out")
        || mkdir(R->clean, 0755) != 0 || mkdir(R->seeded, 0755) != 0)
        return 1;
    return 0;
}

static int dip_build(const struct dip_roots *R)
{
    return dip_fixture_files(R->clean) || dip_fixture_doc(R->clean, 0)
        || dip_fixture_files(R->seeded) || dip_fixture_doc(R->seeded, 1);
}

static int dip_expect_clean(const char *exe, const char *root, const char *out,
                            char *text, size_t cap)
{
    int rc = -1;
    if (dip_run(exe, root, out, &rc) || rc != 0 || dip_slurp(out, text, cap)
        || !strstr(text, "check_doc_inline_paths: PASS (1 docs scanned, 0 baselined, 0 new)")) {
        fprintf(stderr, "[lint-gate] check-doc-inline-paths: clean fixture must PASS, got rc=%d\n%s",
                rc, text);
        return 1;
    }
    return 0;
}

static int dip_expect_seeded(const char *exe, const char *root, const char *out,
                             char *text, size_t cap)
{
    char want[PATH_MAX];
    int rc = -1;
    if (snprintf(want, sizeof want, "docs/index.md:%d -> lib/gone/missing.c", DIP_SEED_LINE)
        >= (int)sizeof want)
        return 1;
    if (dip_run(exe, root, out, &rc) || rc != 1 || dip_slurp(out, text, cap)
        || !strstr(text, "FAIL") || !strstr(text, want)) {
        fprintf(stderr, "[lint-gate] check-doc-inline-paths: seeded fixture must FAIL naming line %d, got rc=%d\n%s",
                DIP_SEED_LINE, rc, text);
        return 1;
    }
    return 0;
}

static void dip_remove_all(const struct dip_roots *R)
{
    dip_cleanup(R->clean);
    dip_cleanup(R->seeded);
    unlink(R->clean_out);
    unlink(R->seeded_out);
    rmdir(R->tmpl);
}

static int t_doc_inline_paths_c_gate(void)
{
    static char text[16384];
    char exe[PATH_MAX], base[PATH_MAX];
    struct dip_roots R;
    if (repo_path(exe, sizeof exe, "build/bin/z23-lint") != 0
        || repo_path(base, sizeof base, "test-tmp") != 0)
        return 1;
    (void)mkdir(base, 0755);
    if (dip_roots_make(&R, base))
        return 1;
    int fails = dip_build(&R);
    if (!fails) {
        text[0] = '\0';
        fails += dip_expect_clean(exe, R.clean, R.clean_out, text, sizeof text);
        text[0] = '\0';
        fails += dip_expect_seeded(exe, R.seeded, R.seeded_out, text, sizeof text);
    }
    dip_remove_all(&R);
    return fails;
}
int t_lint_gate_wiring_gate(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;
    char *driver_buf = NULL;

    int baseline_rc = run_gate_script(LINT_GATE_WIRING_SCRIPT_REL, NULL);
    int selftest_rc = run_gate_script_selftest(LINT_GATE_WIRING_SCRIPT_REL);

    /* An empty directory has neither Makefile nor driver: an error, never
     * "clean". Uses mkdtemp, not repo_path("test-tmp/..."), so the pooled
     * REALROOT lane never writes into a worktree another gate scans. */
    char empty_dir[PATH_MAX];
    const char *tmp_root = getenv("TMPDIR");
    if (tmp_root == NULL || tmp_root[0] == '\0') {
        tmp_root = "/tmp";
    }
    int empty_ready = -1;
    if ((size_t)snprintf(empty_dir, sizeof(empty_dir),
                         "%s/_lint_gate_wiring_empty_XXXXXX",
                         tmp_root) < sizeof(empty_dir) &&
        mkdtemp(empty_dir) != NULL) {
        empty_ready = 0;
    }
    int no_tree_rc =
        empty_ready == 0
            ? run_gate_script_with_env(LINT_GATE_WIRING_SCRIPT_REL,
                                       "ZCL_GATE_WIRING_ROOT", empty_dir)
            : -1;
    if (empty_ready == 0) {
        (void)rmdir(empty_dir);
    }

    int makefile_wired = 0;
    if (repo_path(path, sizeof(path), "Makefile") == 0 &&
        read_entire_file(path, &makefile_buf) == 0) {
        makefile_wired =
            strstr(makefile_buf, "check-lint-gate-wiring:") != NULL &&
            strstr(makefile_buf, "check-lint-gate-wiring \\") != NULL;
    }
    int driver_wired = 0;
    if (repo_path(path, sizeof(path), "tools/lint/run_lint.sh") == 0 &&
        read_entire_file(path, &driver_buf) == 0) {
        driver_wired = strstr(driver_buf, "check-lint-gate-wiring)") != NULL;
    }
    int doc_wired = 0;
    if (repo_path(path, sizeof(path), "docs/DEFENSIVE_CODING.md") == 0 &&
        read_entire_file(path, &doc_buf) == 0) {
        doc_wired = strstr(doc_buf, "check-lint-gate-wiring") != NULL;
    }

    TEST("[lint-gate] check-lint-gate-wiring: real umbrella is fully wired, "
         "selftest proves each desync class trips, missing tree fails closed, "
         "gate is itself in LINT_GATES + the case table + the doc block") {
        ASSERT(baseline_rc == 0);
        ASSERT(selftest_rc == 0);
        ASSERT(empty_ready == 0);
        ASSERT(no_tree_rc != 0);
        ASSERT(makefile_wired);
        ASSERT(driver_wired);
        ASSERT(doc_wired);
        PASS();
    } _test_next:;
    failures += t_doc_inline_paths_c_gate();
    free(makefile_buf);
    free(driver_buf);
    free(doc_buf);
    return failures;
}

/* All three lint umbrellas execute the same run_lint.sh gate catalog, so
 * their built tools form one shared prerequisite set. Grade the real
 * Makefile and two in-memory mutations for helper-membership and exact
 * target-set. */
static const char *make_logical_line_end(const char *start)
{
    const char *line = start;
    for (;;) {
        const char *newline = strchr(line, '\n');
        if (!newline || newline == line || newline[-1] != '\\') return newline;
        line = newline + 1;
    }
}

static bool range_contains(const char *start, const char *end,
                           const char *needle)
{
    const char *found = strstr(start, needle);
    return found != NULL && (end == NULL || found < end);
}

static bool lint_built_prereqs_contract(const char *makefile)
{
    if (!makefile) return false;
    const char *assignment = strstr(makefile, "\nLINT_BUILT_PREREQS =");
    if (!assignment) return false;
    assignment++;
    const char *assignment_end = make_logical_line_end(assignment);
    if (!range_contains(assignment, assignment_end, "$(EQUIHASH_FACT_TOOL)"))
        return false;
    if (!range_contains(assignment, assignment_end, "$(GIT_HOOK_BIN)"))
        return false;

    const char *targets =
        strstr(makefile, "\nlint lint-cached lint-cold-audit:");
    if (!targets) return false;
    targets++;
    const char *targets_end = make_logical_line_end(targets);
    return range_contains(targets, targets_end, "$(LINT_BUILT_PREREQS)");
}

int t_lint_explicit_gates_run_once(void)
{
    int failures = 0;
    char fixture[PATH_MAX] = {0};
    bool created = test_mkdtemp(fixture, sizeof(fixture), "lint_explicit") != NULL;
    TEST("[lint-gate] fast generated gates and explicit goals execute and propagate failures") {
        ASSERT(created);
        ASSERT(run_gate_script_arg("tools/scripts/test_lint_explicit_gates.sh",
                                  NULL, fixture) == 0);
        PASS();
    } _test_next:;
    if (created && test_rm_rf_recursive(fixture) != 0) {
        fprintf(stderr, "lint dispatch: fixture cleanup failed: %s\n", fixture);
        failures++;
    }
    return failures;
}

int t_lint_umbrellas_share_built_prereqs(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile = NULL;
    int read_ok = repo_path(path, sizeof(path), "Makefile") == 0 &&
                  read_entire_file(path, &makefile) == 0;
    int baseline_ok = read_ok && lint_built_prereqs_contract(makefile);

    char *missing_helper = read_ok ? strdup(makefile) : NULL;
    char *assignment = missing_helper
        ? strstr(missing_helper, "\nLINT_BUILT_PREREQS =") : NULL;
    char *helper = assignment
        ? strstr(assignment, "$(EQUIHASH_FACT_TOOL)") : NULL;
    if (helper) helper[0] = '!';
    int helper_mutation_trips = helper != NULL &&
        !lint_built_prereqs_contract(missing_helper);

    char *missing_git_hook = read_ok ? strdup(makefile) : NULL;
    char *git_hook_assignment = missing_git_hook
        ? strstr(missing_git_hook, "\nLINT_BUILT_PREREQS =") : NULL;
    char *git_hook_helper = git_hook_assignment
        ? strstr(git_hook_assignment, "$(GIT_HOOK_BIN)") : NULL;
    if (git_hook_helper) git_hook_helper[0] = '!';
    int git_hook_mutation_trips = git_hook_helper != NULL &&
        !lint_built_prereqs_contract(missing_git_hook);

    char *missing_target = read_ok ? strdup(makefile) : NULL;
    char *targets = missing_target
        ? strstr(missing_target, "\nlint lint-cached lint-cold-audit:") : NULL;
    char *cold = targets ? strstr(targets, "lint-cold-audit") : NULL;
    if (cold) cold[0] = 'L';
    int target_mutation_trips = cold != NULL &&
        !lint_built_prereqs_contract(missing_target);

    TEST("[lint-gate] lint umbrellas share every built prerequisite; helper "
         "and target-removal mutations trip") {
        ASSERT(read_ok);
        ASSERT(baseline_ok);
        ASSERT(helper_mutation_trips);
        ASSERT(git_hook_mutation_trips);
        ASSERT(target_mutation_trips);
        PASS();
    } _test_next:;
    free(makefile);
    free(missing_helper);
    free(missing_git_hook);
    free(missing_target);
    return failures;
}

/* A cold generation links its own build/bin/z23-lint in the pre-fork step
 * (tools/dev/dev_proof.c: proof_prefork_argv), before either proof dimension
 * starts, because lint-gate shims exec that binary. Scan the real source for
 * both halves: the make target that builds it and the helper-root hash that
 * binds it into the receipt's helper digest. */
static bool dev_proof_prerequisite_argv_has_lint(const char *source)
{
    if (!source) return false;
    const char *block = strstr(source,
                               "static const char *const proof_prefork_helpers[] = {");
    if (!block) return false;
    const char *end = strstr(block, "};");
    return range_contains(block, end, "\"build/bin/z23-lint\"");
}

static bool dev_proof_helper_root_hashes_lint(const char *source)
{
    if (!source) return false;
    const char *block = strstr(source, "hash_begin(&helpers, "
                                        "\"zcl.dev_proof_test_helpers.v1\");");
    if (!block) return false;
    const char *end = strstr(block, "sha3_256_finalize(&helpers, helper_root);");
    return range_contains(block, end, "lint_tool_root");
}

int t_dev_proof_helpers_include_lint_tool(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *source = NULL;
    int read_ok = repo_path(path, sizeof(path), "tools/dev/dev_proof.c") == 0 &&
                  read_entire_file(path, &source) == 0;
    int prereq_ok = read_ok && dev_proof_prerequisite_argv_has_lint(source);
    int hash_ok = read_ok && dev_proof_helper_root_hashes_lint(source);

    char *missing_prereq = read_ok ? strdup(source) : NULL;
    /* "build/bin/z23-lint" names the pre-fork target and the docs-fresh
     * prebuild: blank every occurrence, as in the hash loop below. */
    int prereq_hit_count = 0;
    char *cursor = missing_prereq;
    while (cursor && (cursor = strstr(cursor, "\"build/bin/z23-lint\""))) {
        cursor[0] = '!';
        prereq_hit_count++;
        cursor++;
    }
    int prereq_mutation_trips = prereq_hit_count > 0 &&
        !dev_proof_prerequisite_argv_has_lint(missing_prereq);

    char *missing_hash = read_ok ? strdup(source) : NULL;
    char *hash_block = missing_hash
        ? strstr(missing_hash, "hash_begin(&helpers, "
                               "\"zcl.dev_proof_test_helpers.v1\");") : NULL;
    char *hash_end = hash_block
        ? strstr(hash_block, "sha3_256_finalize(&helpers, helper_root);")
        : NULL;
    /* "lint_tool_root" appears twice on the write line: blank every
     * occurrence so the sizeof() copy alone cannot satisfy the scan. */
    int hash_hit_count = 0;
    if (hash_block) {
        char *cursor = hash_block;
        for (;;) {
            char *hit = strstr(cursor, "lint_tool_root");
            if (!hit || (hash_end && hit >= hash_end)) break;
            hit[0] = '!';
            hash_hit_count++;
            cursor = hit + 1;
        }
    }
    int hash_mutation_trips = hash_hit_count > 0 &&
        !dev_proof_helper_root_hashes_lint(missing_hash);

    TEST("[lint-gate] a proof generation builds build/bin/z23-lint as a "
         "pre-fork target and folds it into helper_root; "
         "removal mutations of either half trip") {
        ASSERT(read_ok);
        ASSERT(prereq_ok);
        ASSERT(hash_ok);
        ASSERT(prereq_mutation_trips);
        ASSERT(hash_mutation_trips);
        PASS();
    } _test_next:;
    free(source);
    free(missing_prereq);
    free(missing_hash);
    return failures;
}

/* Order is the invariant: both proof dimensions share one generation
 * worktree, so everything shared is admitted and built before either child
 * forks (a post-fork relink can expose a half-written build/bin/z23-lint).
 * Pin the sequence in the real source: inputs admitted, one pre-fork make,
 * helper digest, then the first dimension_start(); and pin it twice: inside
 * the pre-fork step and in the step that calls it before the forking step. */
static bool dev_proof_prefork_precedes_the_fork(const char *source)
{
    if (!source) return false;
    const char *body = strstr(source, "static bool dp_worker_prefork(");
    if (!body) return false;
    const char *inputs = strstr(body, "proof_generation_inputs_prepare(");
    const char *build = strstr(body, "proof_prefork_build(");
    const char *hash = strstr(body, "test_helpers_hash(");
    const char *fork = strstr(body, "dimension_start(");
    if (!inputs || !build || !hash || !fork) return false;
    if (!(inputs < build && build < hash && hash < fork)) return false;
    const char *dims = strstr(source, "static bool dp_worker_dimensions(");
    if (!dims) return false;
    const char *call_prefork = strstr(dims, "dp_worker_prefork(");
    const char *call_run = strstr(dims, "dp_worker_dimensions_run(");
    return call_prefork && call_run && call_prefork < call_run;
}

int t_dev_proof_prefork_runs_before_the_dimensions(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *source = NULL;
    int read_ok = repo_path(path, sizeof(path), "tools/dev/dev_proof.c") == 0 &&
                  read_entire_file(path, &source) == 0;
    int order_ok = read_ok && dev_proof_prefork_precedes_the_fork(source);

    /* Mutation: blank the pre-fork build call so nothing builds the shared set. */
    char *moved = read_ok ? strdup(source) : NULL;
    char *build_hit = moved ? strstr(moved, "proof_prefork_build(") : NULL;
    if (build_hit) {
        /* Blank every call so the declaration alone cannot satisfy it. */
        char *cursor = moved;
        for (;;) {
            char *hit = strstr(cursor, "proof_prefork_build(");
            if (!hit) break;
            hit[0] = '!';
            cursor = hit + 1;
        }
    }
    int mutation_trips = build_hit != NULL &&
        !dev_proof_prefork_precedes_the_fork(moved);

    TEST("[lint-gate] the proof admits and builds every shared target before "
         "it forks its dimensions; deleting the pre-fork build trips") {
        ASSERT(read_ok);
        ASSERT(order_ok);
        ASSERT(mutation_trips);
        PASS();
    } _test_next:;
    free(source);
    free(moved);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_hyg_unit;

#endif /* ZCL_TESTING */
