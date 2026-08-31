/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `make_lint_gates` self-test family: it runs the self-test of every lint
 * gate.
 *
 * Problem: a lint gate is the only thing stopping a whole class of bug from
 * coming back — `check-raw-sqlite`, for one, is all that stops new raw
 * `sqlite3_step` calls from reintroducing a UTXO-wipe. If someone loosens a
 * gate's pattern ("oh, it's annoying on this PR, let me add another
 * exemption"), the gate silently stops catching violations. Every check in
 * this family prevents that, in the same shape:
 *
 *   1. Copy a known-bad fixture into the scanned tree under a unique temp name
 *      so the gate's scan actually sees it.
 *   2. Run the gate.
 *   3. Assert exit code != 0 (the gate caught the fixture).
 *   4. Remove the temp file and rerun to confirm the gate passes again.
 *
 * The checks themselves live in the sibling lint_gate_*.c files, grouped by
 * the gate family they guard; lint_gate_selftests.h is the map and the shared
 * surface. This file owns the entry table (g_lint_gate_entries — the ONE list
 * of every check and the lane it belongs to), the partition that hands each
 * entry to exactly one registered test group, and the per-lane runners.
 *
 * ── Why this is split across several registered groups ────────────────────
 * Every check either plants a fixture into a scanned tree or execs a gate
 * script, so historically the whole family ran as ONE group, and that group
 * was marked exclusive (run_group_exclusive in test_parallel.c) because its
 * fixtures were planted into the LIVE source tree where another group's scan
 * could readdir them mid-unlink. Exclusive means the parallel pool is EMPTY
 * while it runs: measured on a 32-worker box this one group was ~95s of a
 * ~130s suite, with 31 workers idle for all of it.
 *
 * The fix is the lane split below. Each entry declares what it actually needs:
 *
 *   LINT_LANE_SANDBOX    plants fixtures, but runs entirely inside a private
 *                        reflink-or-copy clone of the worktree, so neither
 *                        bytes nor metadata change in the live tree. Pool-eligible;
 *                        spread over LINT_GATE_SHARD_COUNT shard groups.
 *   LINT_LANE_REALROOT   needs the real .git (git grep / git ls-files /
 *                        .git/hooks) or is hermetic (its own mktemp sandbox),
 *                        but never mutates a tracked path. Pool-eligible.
 *   LINT_LANE_EXCLUSIVE  genuinely plants into the REAL worktree. Only two
 *                        checks qualify. This lane keeps the historic group
 *                        name `make_lint_gates` and stays the exclusive
 *                        pre-pass — which also guarantees the tree is quiet
 *                        while the shards build their sandboxes.
 *
 * The group name `make_lint_gates` is deliberately KEPT and the shards are
 * named `make_lint_gates_shard_NN`, because --only is a substring match
 * (test_parallel.c) — so `make t ONLY=make_lint_gates` still runs the whole
 * family, and the agent_impact_rules.def rows plus agent_controller.c that
 * name `make_lint_gates` keep resolving with no edit.
 *
 * Gated by `ZCL_TESTING` so the shell-out + make invocation only fires when
 * the suite is built by `make test`; standalone compilations of test_zcl
 * without the macro silently turn this into a no-op pass. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include <string.h>

/* How many pool-eligible shard groups the sandbox lane is spread over. Each
 * one is a registered catalog row (see LINT_SHARD_LIST below) and builds its
 * own sandbox, so this is also the number of concurrent private clones. */
#define LINT_GATE_SHARD_COUNT 8
#define LINT_SHARD_LIST(X) \
    X(01, 0) X(02, 1) X(03, 2) X(04, 3) \
    X(05, 4) X(06, 5) X(07, 6) X(08, 7)

/* Which of this family's registered group names must run alone.
 *
 * The scheduler (test_parallel.c) asks this file rather than pattern-matching
 * the name itself, so the policy lives next to the table that makes it true.
 * The match is EXACT on purpose: a prefix or substring test here would mark
 * every shard exclusive too, silently re-serialising the whole split and
 * handing back every second it bought. test_make_lint_gates_partition asserts
 * this predicate in both directions so that regression cannot land quietly.
 *
 * Defined outside ZCL_TESTING: the scheduler links against it either way. */
bool lint_gates_group_is_exclusive(const char *group_name)
{
    if (!group_name) return false;
    if (strncmp(group_name, "test_", 5) == 0) group_name += 5;
    return strcmp(group_name, "make_lint_gates") == 0;
}

/* The eight private-sandbox shards are safe to run together, but each copies
 * and scans a source tree. Two concurrent 16-worker suites repeatedly starved
 * a different shard past the unchanged 300 s group timeout. Keep this family
 * in one bounded, parallel quiet phase before unrelated suite work. */
bool lint_gates_group_requires_quiet_pool(const char *group_name)
{
    if (!group_name) return false;
    if (strncmp(group_name, "test_", 5) == 0) group_name += 5;
#define LINT_QUIET_MATCH(tag, idx) \
    if (strcmp(group_name, "make_lint_gates_shard_" #tag) == 0) return true;
    LINT_SHARD_LIST(LINT_QUIET_MATCH)
#undef LINT_QUIET_MATCH
    return false;
}

#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"

/* Per-process sandbox-root override. A shard group chdir()s into its own
 * private sandbox and calls repo_root_set_override() with that path; from
 * then on every repo_path()/run_gate_script()/fixture-plant in that process
 * resolves INTO the sandbox (fixtures planted there, and the sandbox's own
 * copy of the gate script is exec'd, so `dirname $0/../..` roots the scan at
 * the sandbox). That is what makes the shards safe to run concurrently with
 * each other and with the rest of the pool. Checked BEFORE the cache so it
 * wins over an already-cached real-root value. */
static char g_repo_root_override[PATH_MAX];
static int g_repo_root_override_set = 0;

void repo_root_set_override(const char *path)
{
    if (!path) { g_repo_root_override_set = 0; return; }
    snprintf(g_repo_root_override, sizeof(g_repo_root_override), "%s", path);
    g_repo_root_override_set = 1;
}

const char *repo_root(void)
{
    static char root[PATH_MAX];
    static int cached = 0;

    if (g_repo_root_override_set)
        return g_repo_root_override[0] ? g_repo_root_override : NULL;

    if (cached) return root[0] ? root : NULL;

    char exe[PATH_MAX];
    /* One exe-path shim for both hosts: /proc/self/exe on Linux,
     * _NSGetExecutablePath on Darwin (platform/os_proc.h). */
    if (!os_proc_exe_path(exe, sizeof(exe))) {
        cached = 1;
        root[0] = '\0';
        return NULL;
    }

    /* The binary lives at <root>/build/bin/<name>; walk UP from the exe
     * until a directory holding both the Makefile and the raw-sqlite
     * fixture appears. A single dirname() here once left root at
     * build/bin, the entry stat failed, and the WHOLE suite silently
     * no-op-SKIPped (PASS in 1s) — every source-text gate in this file
     * was dead. Bounded walk so a stray Makefile high in the tree can't
     * send the shell-outs somewhere surprising. */
    for (int depth = 0; depth < 6; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';

        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/Makefile", exe)
                >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(probe, sizeof(probe), "%s/%s", exe, FIXTURE_SRC_REL)
                >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;

        if (snprintf(root, sizeof(root), "%s", exe) >= (int)sizeof(root))
            break;
        cached = 1;
        return root;
    }

    cached = 1;
    root[0] = '\0';
    return NULL;
}

int repo_path(char *out, size_t outsz, const char *rel)
{
    const char *root = repo_root();
    if (!root || !out || outsz == 0 || !rel) return -1;
    return snprintf(out, outsz, "%s/%s", root, rel) >= (int)outsz ? -1 : 0;
}

/* ── The one entry table ──────────────────────────────────────────────────
 * Every check appears here exactly once, tagged with the lane it needs. The
 * partition below is a pure function of this table, so adding a check is a
 * one-line edit and it lands in a shard automatically. */

typedef int (*lint_gate_fn)(void);

enum lint_lane {
    LINT_LANE_SANDBOX = 0,
    LINT_LANE_REALROOT,
    /* Real-root-safe like REALROOT, but slow enough that sharing a group with
     * anything else makes that group the suite's critical path. Measured
     * standalone: fresh-boot-weld 45.8s, import-copy-prove 25.2s — together
     * they were a 106s serial lane, i.e. the whole reason the old runner took
     * ~95s. Each gets its own registered group. */
    LINT_LANE_HEAVY,
    LINT_LANE_EXCLUSIVE,
};

struct lint_gate_entry {
    lint_gate_fn   fn;
    enum lint_lane lane;
};

#define S_(f) { (f), LINT_LANE_SANDBOX }
#define N_(f) { (f), LINT_LANE_REALROOT }
#define H_(f) { (f), LINT_LANE_HEAVY }
#define X_(f) { (f), LINT_LANE_EXCLUSIVE }
static const struct lint_gate_entry g_lint_gate_entries[] = {
    S_(t_baseline_passes),
    S_(t_fixture_trips_gate),
    S_(t_node_db_exec_fixture_trips_gate),
    S_(t_gate_recovers_after_removal),
    S_(t_coins_guard_baseline_passes),
    S_(t_coins_guard_fixture_trips_gate),
    S_(t_coins_guard_gate_recovers),
    S_(t_coins_guard_gate_fails_loud_on_no_lookup_surface),
    S_(t_observability_fixture_trips_gate),
    S_(t_observability_positive_controls_pass),
    S_(t_raw_malloc_fixture_trips_gate),
    S_(t_raw_malloc_zcl_fixture_passes),
    S_(t_raw_malloc_gate_recovers),
    S_(t_service_tip_mutation_gate),
    S_(t_legacy_candidate_source_has_no_override_scope),
    N_(t_deprecated_tools_z_is_absent),          /* git grep, read-only */
    S_(t_canonical_operator_diagnostics_contract),
    S_(t_canonical_deploy_proof_binding_contract),
    S_(t_dev_lane_deploy_contract),
    /* Captures exact Git source identity through build-epoch-selftest. */
    N_(t_agent_fast_ci_contract),
    /* Hermetic: each script proves itself inside its own mktemp sandbox and
     * no tracked path is written, so this needs no worktree clone. */
    N_(t_slow_disk_progress_verdicts_contract),
    S_(t_native_operator_docs_contract),
    S_(t_remote_node_update_contract),
    S_(t_native_agent_api_contract),
    S_(t_mvp_reporters_resolve_live_service_rpc_contract),
    S_(t_soak_assert_requires_known_mirror_lag),
    S_(t_boot_chain_advance_diagnostics_contract),
    S_(t_boot_core_liveness_precedes_frontend_contract),
    S_(t_boot_addrman_persistence_contract),
    S_(t_lib_runtime_gauges_are_callback_injected),
    S_(t_boot_shutdown_persistence_order_contract),
    S_(t_hodl_history_uses_runtime_db_service),
    S_(t_db_service_query_handle_is_canonical),
    S_(t_txindex_releases_node_db_between_batches),
    S_(t_peer_save_busy_reports_db_error),
    S_(t_handshake_peer_save_is_async),
    S_(t_p2p_app_persistence_is_callback_injected),
    S_(t_tx_wallet_sync_is_callback_injected),
    S_(t_p2p_block_submit_is_callback_injected),
    S_(t_flyclient_proof_builder_is_callback_injected),
    S_(t_fast_sync_uses_lib_sqlite_helpers),
    S_(t_framework_reexport_headers_stay_deleted),
    S_(t_utxo_reimport_flag_is_storage_owned),
    S_(t_net_sync_planners_are_lib_owned),
    S_(t_header_peer_votes_are_callback_injected),
    S_(t_process_block_node_db_access_is_runtime_owned),
    S_(t_process_block_split_uses_reducer_language),
    S_(t_production_comments_do_not_carry_refactor_scaffold_labels),
    S_(t_wallet_view_never_invents_rpc_credentials),
    S_(t_deleted_engine_names_absent_from_production_sources),
    S_(t_build_commit_macro_stays_behind_getter),
    S_(t_boot_repaired_index_persistence_contract),
    S_(t_chain_evidence_reconstruct_uses_retry_persistence),
    S_(t_boot_genesis_init_preserves_restored_authority_contract),
    S_(t_refold_from_anchor_explicit_span_gate_contract),
    S_(t_sha3_window_tool_check_contract),
    S_(t_make_ignores_ephemeral_lint_fixture_sources),
    S_(t_block_index_flat_atomic_save_contract),
    S_(t_projection_deferral_is_not_block_rejected_contract),
    S_(t_trusted_peer_stall_guard_contract),
    S_(t_gap_fill_wakes_connman_dispatch_contract),
    S_(t_msg_process_yields_to_send_phase_contract),
    S_(t_e1_file_size_bands),
    S_(t_e1_file_size_baseline_and_hollow_scan),
    S_(t_long_functions_enforced_ratchet),
    S_(t_long_functions_lib_warn_tier),
    S_(t_no_new_repair_rung),
    S_(t_no_new_borrowed_seed_caller),
    S_(t_no_new_coin_backfill_caller),
    S_(t_no_writer_below_sealed_frontier),
    S_(t_e9_operator_needed_sink),
    S_(t_systemd_memory_budget),
    S_(t_quality_job_guard),
    /* Hermetic: each driver fakes its inputs inside its own `mktemp -d`
     * sandbox and touches nothing in the worktree. HEAVY, so one group each
     * — heavy_01 and heavy_02 in table order. */
    H_(t_import_copy_prove_selftest),
    H_(t_fresh_boot_weld_prove_selftest),
    S_(t_e14_condition_cooldown_gate),
    S_(t_fuzz_artifact_ledger_gate),  /* plants a fixture in lib/test/fuzz_seeds */
    N_(t_markdown_links_gate),                   /* git ls-files, read-only */
    N_(t_git_hooks_gate_enforces_tracked_pre_push),  /* reads .git/hooks */
    N_(t_git_hooks_gate_rejects_noop_pre_push),      /* writes only test-tmp/ */
    N_(t_git_hooks_gate_rejects_noop_pre_commit),    /* writes only test-tmp/ */
    S_(t_telemetry_ontology_gate),
    /* Hermetic: the script's --selftest builds its scan root and baseline in
     * its own mktemp dir and never mutates a tracked path. */
    N_(t_dumper_never_blocks_gate),
    S_(t_e10_framework_shape_ratchet),
    S_(t_e10_no_raw_sqlite_ratchet),
    S_(t_gate22_framework_filename_suffix),
    S_(t_gate_p2_group_purpose),
    S_(t_gate_p1_file_purpose),
    N_(t_gate_p3_orphan_placement),   /* judges a path list, nothing on disk */
    S_(t_e13_consensus_parity_fixture),
    S_(t_silent_errors_bool_fixture),
    S_(t_log_macro_return_type_gate),
    S_(t_e11_doc_accuracy),
    S_(t_model_ar_lifecycle_gate),
    S_(t_e2_one_result_type),
    S_(t_service_result_convergence_ratchet),
    S_(t_thread_supervision_ratchet),
    S_(t_supervisor_registration_widened_ratchet),
    S_(t_e3_shape_includes_header),
    S_(t_e4_projections_pure),
    S_(t_domain_purity),
    S_(t_shape_include_direction),
    S_(t_e5_stage_advances_or_blocks),
    S_(t_e6_one_write_path),
    S_(t_e7_no_authoritative_ram_state),
    S_(t_e12_honest_witness),
    S_(t_gate21_supervisor_worker_lockin),
    S_(t_hotswap_eligible_scope_gate),
    S_(t_hotswap_swappable_shape_gate),
    S_(t_hotswap_swappable_leaf_contract_gate),
    S_(t_hotswap_static_state_gate),
    S_(t_hotswap_static_state_covers_swappable),
    S_(t_hotswap_service_island_gate),
    S_(t_privileged_transition_receipt_gate),
    S_(t_blocker_escape_registered_gate),
    /* Plants app/services/src/_trust_order_fixture_tmp.c into the REAL tree
     * (the gate greps --untracked, which needs the real .git). */
    X_(t_no_trust_state_ordering_gate),
    S_(t_lint_gates_fail_loud_on_empty_scan),
    /* Hermetic: builds its fixture trees under TMPDIR and reads Makefile /
     * run_lint.sh, never writing into the worktree. */
    N_(t_lint_gate_wiring_gate),
    N_(t_lint_umbrellas_share_built_prereqs),
    S_(t_no_dev_history_in_contracts),
    S_(t_no_uncited_victory),
    /* Plants a stray file at the REAL repo root. */
    X_(t_no_stray_root_files),
};
#undef S_
#undef N_
#undef H_
#undef X_
#define LINT_GATE_ENTRY_COUNT \
    (sizeof(g_lint_gate_entries) / sizeof(g_lint_gate_entries[0]))

/* ── Partition ────────────────────────────────────────────────────────────
 * Owner of every entry: a shard index in [0, LINT_GATE_SHARD_COUNT) for the
 * sandbox lane, or one of the two negative tags. Pure function of the table,
 * so every process computes the SAME partition and
 * test_make_lint_gates_partition can prove it total and disjoint. */

#define LINT_OWNER_REALROOT   (-1)
#define LINT_OWNER_EXCLUSIVE  (-2)
#define LINT_OWNER_NONE       (-3)
/* Heavy lane owners are LINT_OWNER_HEAVY_BASE + k for the k-th HEAVY entry in
 * table order, so heavy_01 owns the first and heavy_02 the second. */
#define LINT_OWNER_HEAVY_BASE (100)
#define LINT_GATE_HEAVY_COUNT (2)

/* Per-check cost in milliseconds, used to balance the shards.
 *
 * These are MEASURED, not guessed: run the family under ZCL_LINT_GATE_TIMING=1
 * and read the `[lint-gate-timing] ... ms=` lines. They are taken with the
 * whole family running concurrently, so they carry the contention every shard
 * actually experiences in the pool; they only need to RANK correctly.
 *
 * The previous hand-estimated table was badly wrong in both directions and
 * produced shards of 7s and 60s: t_agent_fast_ci_contract was weighted 10 and
 * measures ~26s, t_gate22_framework_filename_suffix was 10 and measures ~12s,
 * while t_gate_p1_file_purpose was weighted 600 and does not even reach the
 * 500ms floor. Anything not listed is sub-500ms noise. */
static int lint_entry_weight(lint_gate_fn fn)
{
    if (fn == t_silent_errors_bool_fixture)              return 59651;
    if (fn == t_no_dev_history_in_contracts)             return 51629;
    if (fn == t_agent_fast_ci_contract)                  return 26287;
    /* Measured: the cutover selftest's slow-box cases poll real clocks
     * (~14s), plus the host-watchdog and deploy_verify selftests. */
    if (fn == t_slow_disk_progress_verdicts_contract)    return 15500;
    if (fn == t_lint_gates_fail_loud_on_empty_scan)      return 21827;
    if (fn == t_gate22_framework_filename_suffix)        return 12435;
    if (fn == t_e1_file_size_bands)                      return 10960;
    if (fn == t_e1_file_size_baseline_and_hollow_scan)   return 7211;
    if (fn == t_long_functions_enforced_ratchet)         return 5180;
    if (fn == t_baseline_passes)                         return 4893;
    if (fn == t_gate_recovers_after_removal)             return 4889;
    if (fn == t_node_db_exec_fixture_trips_gate)         return 4889;
    if (fn == t_fixture_trips_gate)                      return 4885;
    if (fn == t_supervisor_registration_widened_ratchet) return 4749;
    if (fn == t_log_macro_return_type_gate)              return 3728;
    if (fn == t_long_functions_lib_warn_tier)            return 3608;
    if (fn == t_e12_honest_witness)                      return 2202;
    /* Measured standalone, not under family contention (the dev host's build
     * lock was held by another lane): one real-tree run at ~1.17s plus the
     * script's 6-case --selftest at ~1.33s. Re-measure under
     * ZCL_LINT_GATE_TIMING=1 and correct it if the shards skew. */
    if (fn == t_dumper_never_blocks_gate)                return 2500;
    if (fn == t_blocker_escape_registered_gate)          return 2198;
    if (fn == t_shape_include_direction)                 return 1874;
    if (fn == t_e14_condition_cooldown_gate)             return 1654;
    if (fn == t_e2_one_result_type)                      return 1582;
    if (fn == t_systemd_memory_budget)                   return 1412;
    if (fn == t_e3_shape_includes_header)                return 1153;
    if (fn == t_privileged_transition_receipt_gate)      return 1030;
    if (fn == t_e5_stage_advances_or_blocks)             return 754;
    if (fn == t_no_uncited_victory)                      return 607;
    if (fn == t_hotswap_swappable_shape_gate)            return 540;
    if (fn == t_hotswap_swappable_leaf_contract_gate)    return 519;
    if (fn == t_hotswap_service_island_gate)             return 100;
    return 100;
}

/* Longest-processing-time-first bin packing: walk the sandbox entries
 * heaviest-first and drop each into the currently lightest shard. Recomputed
 * per query (a hundred-odd entries over 8 bins is nothing) so there is no
 * cached state to drift out of sync with the table. */
static int lint_owner_of(size_t idx)
{
    if (idx >= LINT_GATE_ENTRY_COUNT) return LINT_OWNER_NONE;
    switch (g_lint_gate_entries[idx].lane) {
    case LINT_LANE_REALROOT:  return LINT_OWNER_REALROOT;
    case LINT_LANE_EXCLUSIVE: return LINT_OWNER_EXCLUSIVE;
    case LINT_LANE_HEAVY: {
        int k = 0;
        for (size_t i = 0; i < idx; i++)
            if (g_lint_gate_entries[i].lane == LINT_LANE_HEAVY) k++;
        /* A third HEAVY entry with no group to run it would silently vanish;
         * the partition test asserts the count instead of letting that pass. */
        if (k >= LINT_GATE_HEAVY_COUNT) return LINT_OWNER_NONE;
        return LINT_OWNER_HEAVY_BASE + k;
    }
    case LINT_LANE_SANDBOX:   break;
    }

    int order[LINT_GATE_ENTRY_COUNT];
    int n = 0;
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++)
        if (g_lint_gate_entries[i].lane == LINT_LANE_SANDBOX)
            order[n++] = (int)i;

    for (int a = 1; a < n; a++) {   /* stable insertion sort, weight DESC */
        int cur = order[a];
        int cw = lint_entry_weight(g_lint_gate_entries[cur].fn);
        int b = a - 1;
        while (b >= 0 &&
               lint_entry_weight(g_lint_gate_entries[order[b]].fn) < cw) {
            order[b + 1] = order[b];
            b--;
        }
        order[b + 1] = cur;
    }

    long load[LINT_GATE_SHARD_COUNT];
    for (int b = 0; b < LINT_GATE_SHARD_COUNT; b++) load[b] = 0;

    int owner = LINT_OWNER_NONE;
    for (int k = 0; k < n; k++) {
        int lightest = 0;
        for (int b = 1; b < LINT_GATE_SHARD_COUNT; b++)
            if (load[b] < load[lightest]) lightest = b;
        load[lightest] += lint_entry_weight(g_lint_gate_entries[order[k]].fn);
        if ((size_t)order[k] == idx) owner = lightest;
    }
    return owner;
}

/* ── Runners ──────────────────────────────────────────────────────────── */

/* Run every entry this owner owns, in table order. Under
 * ZCL_LINT_GATE_TIMING=1 each check's wall time is reported on stderr; that is
 * the data lint_entry_weight() above is derived from. */
static int lint_run_owned(int owner)
{
    const char *timing = getenv("ZCL_LINT_GATE_TIMING");
    int report = (timing && *timing && strcmp(timing, "0") != 0);
    int failures = 0;

    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        if (lint_owner_of(i) != owner) continue;
        int64_t t0 = clock_now_monotonic_ns();
        failures += g_lint_gate_entries[i].fn();
        if (report) {
            long long ms =
                (long long)((clock_now_monotonic_ns() - t0) / 1000000);
            fprintf(stderr, "[lint-gate-timing] owner=%d entry=%zu ms=%lld\n",
                    owner, i, ms);
        }
    }
    return failures;
}

/* Build an inode-independent clone ("sandbox") of the worktree at sb_root.
 * Everything except build/.git/.cache/test-tmp/.claude is copied with
 * --reflink=auto: CoW on supporting filesystems, a safe regular copy
 * elsewhere. Hardlinks are forbidden because merely creating/removing one
 * changes the live inode ctime and falsely supersedes source proof epochs;
 * fixture chmod/write would be worse. test-tmp is created fresh. Returns 0.
 *
 * build/ is skipped wholesale (gigabytes of objects and node binaries) with
 * ONE exception: build/bin/file_size_policy, the E1 file-size gate. E1 is a
 * compiled C23 binary rather than a script, so unlike every other gate it
 * does not ride into the sandbox with the source tree, and its self-test
 * would exec a path that does not exist. The copy is best-effort — a tree
 * where it was never built must not fail every shard's sandbox
 * construction; t_e1_file_size_bands checks for it and says so instead.
 *
 * Uses fork_with_retry(), not a bare fork(): this runs once per shard (up to
 * LINT_GATE_SHARD_COUNT times concurrently) from the same large test_zcl
 * process the run_gate_script* family forks from, so it is exposed to the
 * exact same transient EAGAIN/ENOMEM under 32-worker load that
 * fork_with_retry's own comment (lint_gate_helpers.c) documents — a bare
 * fork() here was the weaker link, since it had *zero* retry margin. */
static int lint_sandbox_build(const char *real_root, const char *sb_root)
{
    pid_t pid = fork_with_retry();
    if (pid < 0) {
        fprintf(stderr, "[lint-gate] lint_sandbox_build: fork failed: %s\n",
                strerror(errno));
        return -1;
    }
    if (pid == 0) {
        static const char *script =
            "set -e\n"
            "rm -rf \"$2\"\n"
            "mkdir -p \"$2\"\n"
            "for e in \"$1\"/* \"$1\"/.[!.]*; do\n"
            "  [ -e \"$e\" ] || continue\n"
            "  b=${e##*/}\n"
            "  case \"$b\" in build|.git|.cache|test-tmp|.claude) continue;; esac\n"
            "  cp -a --reflink=auto \"$e\" \"$2\"/\n"
            "done\n"
            "mkdir -p \"$2\"/test-tmp \"$2\"/build/bin\n"
            "cp -a --reflink=auto \"$1\"/build/bin/file_size_policy \"$2\"/build/bin/ 2>/dev/null || :\n";
        execl("/bin/sh", "sh", "-c", script, "sh",
              real_root, sb_root, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "[lint-gate] lint_sandbox_build: waitpid failed: %s\n",
                strerror(errno));
        return -1;
    }
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* Remove sandbox bases left by a PREVIOUS run that was killed (SIGKILL/
 * SIGTERM) before its own teardown could run — the normal path rm -rf's its
 * base, but a hard kill leaks it.
 *
 * Only bases whose owning process is GONE are reaped. The shards run
 * concurrently now, so an unconditional sweep would delete a live sibling's
 * sandbox out from under it mid-scan. Called from the exclusive lane, which
 * runs alone before any shard starts. */
static void lint_purge_stale_sandboxes(const char *real_root)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", real_root) >= (int)sizeof(tmp))
        return;
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return;
    *slash = '\0';
    const char *parent = tmp;
    const char *base = slash + 1;

    char prefix[PATH_MAX];
    if (snprintf(prefix, sizeof(prefix), "%s.lint_sb_", base) >=
        (int)sizeof(prefix))
        return;
    size_t plen = strlen(prefix);

    DIR *d = opendir(parent);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, plen) != 0) continue;

        const char *pidstr = e->d_name + plen;
        char *end = NULL;
        long owner_pid = strtol(pidstr, &end, 10);
        if (end == pidstr || !end || *end != '\0' || owner_pid <= 0) continue;
        /* Alive — or alive but owned by another user (EPERM) — leave it be. */
        errno = 0;
        if (kill((pid_t)owner_pid, 0) == 0 || errno != ESRCH) continue;

        char victim[PATH_MAX];
        if (snprintf(victim, sizeof(victim), "%s/%s", parent, e->d_name) <
            (int)sizeof(victim))
            (void)test_rm_rf_recursive(victim);
    }
    closedir(d);
}

/* Resolve the real repo root, or print the historic SKIP. Returns 0 when the
 * caller should proceed and -1 when it should return 0 failures. */
static int lint_resolve_real_root(char *out, size_t outsz)
{
    struct stat st;
    char fixture_src[PATH_MAX];
    char makefile[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src), FIXTURE_SRC_REL) != 0 ||
        repo_path(makefile, sizeof(makefile), "Makefile") != 0 ||
        stat(fixture_src, &st) != 0 || stat(makefile, &st) != 0) {
        printf("[lint-gate] SKIP: repo root not discoverable from test_zcl path\n");
        return -1;
    }
    const char *root = repo_root();
    if (!root) {
        printf("[lint-gate] SKIP: repo root not discoverable from test_zcl path\n");
        return -1;
    }
    if (snprintf(out, outsz, "%s", root) >= (int)outsz) {
        printf("[lint-gate] SKIP: repo root path too long\n");
        return -1;
    }
    return 0;
}

/* One shard: build a private sandbox, run this shard's slice inside it, tear
 * the sandbox down.
 *
 * On ANY sandbox failure this FAILS LOUD rather than falling back to the real
 * worktree. The old single-group runner could fall back safely because it held
 * the tree exclusively; a shard cannot — planting fixtures into the live tree
 * while ~800 other groups run is exactly the flake this split exists to avoid.
 * A named failure is the honest outcome. */
static int lint_run_shard(int shard)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 0;

    printf("\n=== make_lint_gates shard %d tests ===\n", shard);

    char sb_base[PATH_MAX], sb_root[PATH_MAX];
    if (snprintf(sb_base, sizeof(sb_base), "%s.lint_sb_%d",
                 real_root, (int)getpid()) >= (int)sizeof(sb_base) ||
        snprintf(sb_root, sizeof(sb_root), "%s/w%d", sb_base, shard) >=
            (int)sizeof(sb_root)) {
        printf("[lint-gate] FAIL: shard %d sandbox path too long\n", shard);
        return 1;
    }

    if (mkdir(sb_base, 0700) != 0 && errno != EEXIST) {
        printf("[lint-gate] FAIL: shard %d could not create sandbox base %s "
               "(%s)\n", shard, sb_base, strerror(errno));
        return 1;
    }
    if (lint_sandbox_build(real_root, sb_root) != 0) {
        printf("[lint-gate] FAIL: shard %d could not build its sandbox at %s "
               "— refusing to plant fixtures into the live worktree\n",
               shard, sb_root);
        (void)test_rm_rf_recursive(sb_base);
        return 1;
    }

    /* Enter the sandbox: repo_root_set_override makes repo_path() resolve into
     * it, and chdir() makes cwd match so the checks that use RELATIVE paths
     * (long-function keep/baseline files, gate scratch output) land in the
     * SAME tree the gate scans. */
    if (chdir(sb_root) != 0) {
        printf("[lint-gate] FAIL: shard %d could not enter its sandbox %s "
               "(%s)\n", shard, sb_root, strerror(errno));
        (void)test_rm_rf_recursive(sb_base);
        return 1;
    }
    repo_root_set_override(sb_root);
    unlink_lint_fixtures();          /* defensive clean start in this sandbox */

    /* The sandbox is a copy of the worktree with .git deliberately EXCLUDED
     * (see lint_sandbox_build). Gates that verify their own scan coverage
     * against a git-derived expectation (gate_lib.sh gate_git_oracle) are
     * fail-closed by design: no git index means no independent oracle, which
     * is UNPROVEN (exit 2), never a quiet pass. That refusal is correct — and
     * inside a deliberately git-less clone it is also unavoidable, so opt those
     * checks out here, once, for every gate this shard runs. Their coverage is
     * proven where the oracle actually exists: each gate's own `--selftest`,
     * which `make lint` runs against the real checkout on every invocation.
     * Do NOT paper over this per-test; a new git-oracle gate belongs on this
     * list. */
    (void)setenv("ZCL_SUPDOM_COVERAGE",    "0", 1);
    (void)setenv("ZCL_THREADSUP_COVERAGE", "0", 1);
    (void)setenv("ZCL_SUPREG_COVERAGE",    "0", 1);
    (void)setenv("ZCL_LONGFN_COVERAGE",    "0", 1);
    (void)setenv("ZCL_NDH_COVERAGE",       "0", 1);

    int failures = lint_run_owned(shard);

    (void)unsetenv("ZCL_SUPDOM_COVERAGE");
    (void)unsetenv("ZCL_THREADSUP_COVERAGE");
    (void)unsetenv("ZCL_SUPREG_COVERAGE");
    (void)unsetenv("ZCL_LONGFN_COVERAGE");
    (void)unsetenv("ZCL_NDH_COVERAGE");

    repo_root_set_override(NULL);
    if (chdir(real_root) != 0)
        fprintf(stderr, "[lint-gate] shard %d: chdir back to %s failed: %s\n",
                shard, real_root, strerror(errno));
    (void)test_rm_rf_recursive(sb_base);
    return failures;
}

/* ── Registered entry points ──────────────────────────────────────────────
 * The shard bodies are macro-generated from ONE list so adding or removing a
 * shard is a single edit here plus the matching ZCL_TEST_GROUP row in
 * tools/dev/test_group_catalog.def. check-test-registration only treats a FILENAME-matching
 * `int test_<name>(void)` as an entry point, so these generated definitions
 * are invisible to it while the catalog rows still bind name -> symbol. */

#define LINT_SHARD_ENTRY(tag, idx) \
    int test_make_lint_gates_shard_##tag(void) { return lint_run_shard(idx); }
LINT_SHARD_LIST(LINT_SHARD_ENTRY)
#undef LINT_SHARD_ENTRY

/* The real-worktree read-only lane: git grep / git ls-files / .git/hooks
 * probes. Mutates no tracked path, so it is pool-eligible. */
int test_make_lint_gates_realroot(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 0;
    printf("\n=== make_lint_gates real-worktree tests ===\n");
    return lint_run_owned(LINT_OWNER_REALROOT);
}

/* One group per HEAVY check. heavy_01 is the import-copy-prove driver
 * selftest (~25s), heavy_02 the fresh-boot-weld one (~46s); both hermetic. */
int test_make_lint_gates_heavy_01(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 0;
    printf("\n=== make_lint_gates heavy 1 tests ===\n");
    return lint_run_owned(LINT_OWNER_HEAVY_BASE + 0);
}

int test_make_lint_gates_heavy_02(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 0;
    printf("\n=== make_lint_gates heavy 2 tests ===\n");
    return lint_run_owned(LINT_OWNER_HEAVY_BASE + 1);
}

/* The exclusive lane — the two checks that genuinely plant into the live
 * worktree. Keeps the historic group name, so `--only=make_lint_gates` (a
 * substring match) still selects this plus every shard, and every impact rule
 * naming `make_lint_gates` keeps resolving. */
int test_make_lint_gates(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 0;

    printf("\n=== make_lint_gates tests ===\n");

    /* Reap any sandbox base leaked by a hard-killed prior run. Safe here and
     * only here: this lane runs alone, before any shard exists. */
    lint_purge_stale_sandboxes(real_root);

    return lint_run_owned(LINT_OWNER_EXCLUSIVE);
}

/* ── The coverage proof ───────────────────────────────────────────────────
 * Sharding a test is exactly how coverage silently disappears, so the
 * partition is itself a registered test. It executes no gate (milliseconds).
 * Drop an entry from the table, mis-tag a lane, or widen
 * lint_gates_group_is_exclusive, and one of these fails. */

static int t_partition_covers_every_check(void)
{
    int failures = 0;
    unsigned char seen[LINT_GATE_ENTRY_COUNT];
    memset(seen, 0, sizeof(seen));

    int owned_total = 0, bad_owner = 0;
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        int owner = lint_owner_of(i);
        if ((owner >= 0 && owner < LINT_GATE_SHARD_COUNT) ||
            (owner >= LINT_OWNER_HEAVY_BASE &&
             owner < LINT_OWNER_HEAVY_BASE + LINT_GATE_HEAVY_COUNT) ||
            owner == LINT_OWNER_REALROOT || owner == LINT_OWNER_EXCLUSIVE) {
            seen[i]++;
            owned_total++;
        } else {
            bad_owner++;
        }
    }

    int uncovered = 0, doubled = 0;
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        if (seen[i] == 0) uncovered++;
        if (seen[i] > 1) doubled++;
    }

    TEST("[lint-gate] partition owns every check exactly once") {
        /* Fail-loud floor: a table that shrank to nothing must not report a
         * clean partition. Mirrors the >=100 floors the gate scripts use. */
        ASSERT(LINT_GATE_ENTRY_COUNT >= 100);
        ASSERT(bad_owner == 0);
        ASSERT(uncovered == 0);
        ASSERT(doubled == 0);
        ASSERT(owned_total == (int)LINT_GATE_ENTRY_COUNT);
        PASS();
    } _test_next:;
    return failures;
}

static int t_partition_shards_all_carry_work(void)
{
    int failures = 0;
    int shard_counts[LINT_GATE_SHARD_COUNT];
    for (int s = 0; s < LINT_GATE_SHARD_COUNT; s++) shard_counts[s] = 0;
    int heavy_counts[LINT_GATE_HEAVY_COUNT];
    for (int h = 0; h < LINT_GATE_HEAVY_COUNT; h++) heavy_counts[h] = 0;
    int realroot_count = 0, exclusive_count = 0, heavy_lane_entries = 0;

    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        if (g_lint_gate_entries[i].lane == LINT_LANE_HEAVY) heavy_lane_entries++;
        int owner = lint_owner_of(i);
        if (owner >= 0 && owner < LINT_GATE_SHARD_COUNT) shard_counts[owner]++;
        else if (owner >= LINT_OWNER_HEAVY_BASE &&
                 owner < LINT_OWNER_HEAVY_BASE + LINT_GATE_HEAVY_COUNT)
            heavy_counts[owner - LINT_OWNER_HEAVY_BASE]++;
        else if (owner == LINT_OWNER_REALROOT) realroot_count++;
        else if (owner == LINT_OWNER_EXCLUSIVE) exclusive_count++;
    }

    int empty_shards = 0;
    for (int s = 0; s < LINT_GATE_SHARD_COUNT; s++)
        if (shard_counts[s] == 0) empty_shards++;
    int empty_heavy = 0;
    for (int h = 0; h < LINT_GATE_HEAVY_COUNT; h++)
        if (heavy_counts[h] != 1) empty_heavy++;

    TEST("[lint-gate] every group carries work; both planters stay exclusive") {
        ASSERT(empty_shards == 0);
        /* Every heavy group owns exactly one check, and there is a group for
         * every HEAVY entry — tag a third one without adding its group and
         * lint_owner_of() returns NONE, which the coverage test above catches
         * and this makes legible. */
        ASSERT(empty_heavy == 0);
        ASSERT(heavy_lane_entries == LINT_GATE_HEAVY_COUNT);
        /* Exactly the two checks that write into the live worktree. If a new
         * check starts planting into the real tree, tag it X_ and bump this. */
        ASSERT(exclusive_count == 2);
        ASSERT(realroot_count >= 1);
        PASS();
    } _test_next:;
    return failures;
}

static int t_partition_only_base_group_is_exclusive(void)
{
    int failures = 0;
    TEST("[lint-gate] only the base group is scheduled exclusively") {
        ASSERT(lint_gates_group_is_exclusive("test_make_lint_gates"));
        ASSERT(lint_gates_group_is_exclusive("make_lint_gates"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_shard_01"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_shard_08"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_realroot"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_heavy_01"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_heavy_02"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_partition"));
        ASSERT(!lint_gates_group_is_exclusive(NULL));
        ASSERT(lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_shard_01"));
        ASSERT(lint_gates_group_requires_quiet_pool(
            "make_lint_gates_shard_08"));
        ASSERT(!lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_realroot"));
        ASSERT(!lint_gates_group_requires_quiet_pool(NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int t_sandbox_preserves_live_source_metadata(void)
{
    int failures = 0;
    TEST("[lint-gate] sandbox construction does not mutate live source metadata") {
        char real_root[PATH_MAX];
        char makefile[PATH_MAX];
        char sb_base[PATH_MAX];
        char sb_root[PATH_MAX];
        struct stat before;
        struct stat after;
        ASSERT(lint_resolve_real_root(real_root, sizeof(real_root)) == 0);
        ASSERT(snprintf(makefile, sizeof(makefile), "%s/Makefile", real_root) <
               (int)sizeof(makefile));
        ASSERT(snprintf(sb_base, sizeof(sb_base), "%s.lint_meta_%d",
                        real_root, (int)getpid()) < (int)sizeof(sb_base));
        ASSERT(snprintf(sb_root, sizeof(sb_root), "%s/w0", sb_base) <
               (int)sizeof(sb_root));
        ASSERT(stat(makefile, &before) == 0);
        ASSERT(lint_sandbox_build(real_root, sb_root) == 0);
        ASSERT(test_rm_rf_recursive(sb_base) == 0);
        ASSERT(stat(makefile, &after) == 0);
        ASSERT(before.st_dev == after.st_dev);
        ASSERT(before.st_ino == after.st_ino);
        ASSERT(before.st_mode == after.st_mode);
        ASSERT(before.st_size == after.st_size);
        ASSERT(before.st_mtim.tv_sec == after.st_mtim.tv_sec);
        ASSERT(before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
        ASSERT(before.st_ctim.tv_sec == after.st_ctim.tv_sec);
        ASSERT(before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
        PASS();
    } _test_next:;
    return failures;
}

int test_make_lint_gates_partition(void)
{
    printf("\n=== make_lint_gates partition tests ===\n");
    int failures = 0;
    failures += t_partition_covers_every_check();
    failures += t_partition_shards_all_carry_work();
    failures += t_partition_only_base_group_is_exclusive();
    failures += t_sandbox_preserves_live_source_metadata();
    return failures;
}

#else  /* !ZCL_TESTING, or _WIN32 */

#if defined(_WIN32)

#include <stdio.h>

/* These groups prove POSIX shell lint scripts by fork+execing them against
 * planted fixtures in private worktrees. Native Windows has no fork/exec
 * contract. Keep every catalog symbol present and report the unobserved
 * family explicitly; the Windows lane runs `make lint` itself separately. */
static int lint_gate_skip_windows(const char *group)
{
    printf("[lint-gate] SKIP (Windows): %s requires POSIX fork/exec; "
           "run make lint under MSYS2 for the Windows lint contract\n", group);
    return 0;
}

int test_make_lint_gates(void)
{ return lint_gate_skip_windows("make_lint_gates"); }
int test_make_lint_gates_realroot(void)
{ return lint_gate_skip_windows("make_lint_gates_realroot"); }
int test_make_lint_gates_heavy_01(void)
{ return lint_gate_skip_windows("make_lint_gates_heavy_01"); }
int test_make_lint_gates_heavy_02(void)
{ return lint_gate_skip_windows("make_lint_gates_heavy_02"); }
int test_make_lint_gates_partition(void)
{ return lint_gate_skip_windows("make_lint_gates_partition"); }

#define LINT_SHARD_SKIP(tag, idx) \
    int test_make_lint_gates_shard_##tag(void) \
    { \
        (void)idx; \
        return lint_gate_skip_windows("make_lint_gates_shard_" #tag); \
    }
LINT_SHARD_LIST(LINT_SHARD_SKIP)
#undef LINT_SHARD_SKIP

#else  /* !ZCL_TESTING */

/* No-ops when the lint-gate integration test is disabled. */
int test_make_lint_gates(void) { return 0; }
int test_make_lint_gates_realroot(void) { return 0; }
int test_make_lint_gates_heavy_01(void) { return 0; }
int test_make_lint_gates_heavy_02(void) { return 0; }
int test_make_lint_gates_partition(void) { return 0; }

#define LINT_SHARD_STUB(tag) \
    int test_make_lint_gates_shard_##tag(void) { return 0; }
LINT_SHARD_STUB(01) LINT_SHARD_STUB(02) LINT_SHARD_STUB(03) LINT_SHARD_STUB(04)
LINT_SHARD_STUB(05) LINT_SHARD_STUB(06) LINT_SHARD_STUB(07) LINT_SHARD_STUB(08)
#undef LINT_SHARD_STUB

#endif /* _WIN32 */

#endif /* ZCL_TESTING */
