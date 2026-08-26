/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared surface of the `make_lint_gates` self-test group: the fixture and
 * gate-script path constants every check plants or execs, plus the declaration
 * of every check function and the helpers they share.
 *
 * The group is one test — `test_make_lint_gates()` in test_make_lint_gates.c,
 * which owns the entry table and the sandbox worker pool — whose checks are
 * split across lint_gate_*.c by the gate family under test:
 *
 *   lint_gate_helpers.c               file/exec plumbing every check reuses
 *   lint_gate_defensive_selftests.c   raw sqlite3_step, raw malloc, coins
 *                                     lookup guard, observability pairing
 *   lint_gate_shape_selftests.c       file size and long function ratchets,
 *                                     the shape purity gates (E1, E3-E7, E12)
 *   lint_gate_quality_selftests.c     doc, comment and result-type gates
 *                                     (E2, E10, E11, E13, E14, P1-P3, gate 22)
 *   lint_gate_supervision_selftests.c thread and supervisor registration
 *                                     ratchets, hot-swap manifests, blocker
 *                                     escape, the empty-scan meta gate
 *   lint_gate_hygiene_selftests.c     git hooks, memory budget, ephemeral
 *                                     fixture filtering, dev-history and
 *                                     uncited-victory prose gates
 *   lint_gate_deploy_contracts.c      deploy proof binding, dev-lane deploy,
 *                                     agent fast CI
 *   lint_gate_native_api_contract.c   the native agent API surface contract
 *   lint_gate_operator_contracts.c    operator diagnostics, operator docs,
 *                                     remote node update, MVP reporters
 *   lint_gate_boot_contracts.c        boot ordering and persistence-ownership
 *                                     contracts
 *   lint_gate_chain_contracts.c       repair-ladder, borrowed-seed, writer
 *                                     frontier and chain-index contracts
 *
 * Everything declared here is internal to that group: only
 * lib/test/src/lint_gate_*.c and test_make_lint_gates.c include this file. */

#ifndef ZCL_LINT_GATE_SELFTESTS_H
#define ZCL_LINT_GATE_SELFTESTS_H

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ── fixture and gate-script paths ───────────────────────────────────── */

#define FIXTURE_SRC_REL "lib/test/fixtures/raw_sqlite_step_fixture.c"
#define FIXTURE_DST_REL "app/_lint_gate_fixture_tmp.c"
#define NODE_DB_EXEC_FIXTURE_SRC_REL "lib/test/fixtures/raw_sqlite_exec_node_db_fixture.c"
/* Direct self-test script calls intentionally leave
 * ZCL_LINT_PRODUCTION_SCAN unset, so this fixture remains visible to its own
 * gate while production scans and the live dev watcher ignore it. */
#define NODE_DB_EXEC_FIXTURE_DST_REL \
    "app/_node_db_exec_lint_fixture_probe_tmp.c"
#define COINS_FIXTURE_SRC_REL "lib/test/fixtures/coins_lookup_guard_fixture.c"
#define COINS_FIXTURE_DST_REL "app/controllers/src/_coins_lookup_guard_fixture_tmp.c"
#define OBS_FIXTURE_SRC_REL "lib/test/fixtures/observability_unpaired_stderr_fixture.c"
#define OBS_FIXTURE_DST_REL "app/_observability_lint_fixture_tmp.c"
#define OBS_OK_FIXTURE_SRC_REL "lib/test/fixtures/observability_paired_stderr_fixture.c"
#define OBS_OK_FIXTURE_DST_REL "app/_observability_ok_lint_fixture_tmp.c"
#define RAW_MALLOC_FIXTURE_DST_REL "app/_raw_malloc_lint_fixture_tmp.c"
#define RAW_MALLOC_OK_FIXTURE_DST_REL "app/_raw_malloc_ok_lint_fixture_tmp.c"
#define RAW_SQLITE_SCRIPT_REL "tools/scripts/check_raw_sqlite.sh"
#define RAW_MALLOC_SCRIPT_REL "tools/scripts/check_raw_malloc.sh"
#define HOTSWAP_SCOPE_SCRIPT_REL  "tools/lint/check_hotswap_eligible_scope.sh"
#define HOTSWAP_STATIC_SCRIPT_REL "tools/lint/check_hotswap_static_state.sh"
#define HOTSWAP_SERVICE_SCRIPT_REL \
    "tools/lint/check_hotswap_service_islands.sh"
#define HOTSWAP_SERVICE_BAD_MANIFEST_REL \
    "lib/test/fixtures/hotswap_services_bad.def"
#define HOTSWAP_SERVICE_STALE_CONTRACT_REL \
    "lib/test/fixtures/hotswap_services_stale_contract.def"
#define HOTSWAP_MANIFEST_REL "config/hotswap_eligible.def"
#define HOTSWAP_BAD_SCOPE_MANIFEST_REL \
    "lib/test/fixtures/hotswap_manifest_bad_scope.def"
#define HOTSWAP_BAD_STATIC_MANIFEST_REL \
    "lib/test/fixtures/hotswap_manifest_bad_static.def"
#define HOTSWAP_NO_MACRO_MANIFEST_REL \
    "lib/test/fixtures/hotswap_manifest_no_macro.def"
#define HOTSWAP_SWAPPABLE_SCRIPT_REL \
    "tools/lint/check_hotswap_swappable_shape.sh"
#define HOTSWAP_SWAPPABLE_MANIFEST_REL "config/hotswap_swappable.def"
#define HOTSWAP_SWAPPABLE_BAD_MANIFEST_REL \
    "lib/test/fixtures/hotswap_swappable_bad_shape.def"
#define HOTSWAP_SWAPPABLE_NOT_READY_READ_REL \
    "lib/test/fixtures/hotswap_swappable_not_ready_read.def"
#define HOTSWAP_SWAPPABLE_DUP_LEAF_REL \
    "lib/test/fixtures/hotswap_swappable_dup_leaf.def"
#define HOTSWAP_SWAPPABLE_BAD_STATIC_REL \
    "lib/test/fixtures/hotswap_swappable_bad_static.def"
#define HOTSWAP_ISLAND_BAD_SCOPE_REL \
    "lib/test/fixtures/hotswap_islands_bad_scope.def"
#define HOTSWAP_ISLAND_BAD_STATIC_REL \
    "lib/test/fixtures/hotswap_islands_bad_static.def"
#define GIT_HOOKS_SCRIPT_REL "tools/scripts/check_git_hooks_installed.sh"
#define PRIV_RECEIPT_SCRIPT_REL \
    "tools/lint/check_privileged_transition_receipt.sh"
/* Gate — no ordinal comparison of enum sync_trust_state. Plant a fixture with
 * an ordinal comparison into a scanned dir → trip; remove → recover. */
#define TRUST_ORDER_SCRIPT_REL \
    "tools/scripts/check_no_trust_state_ordering.sh"
#define TRUST_ORDER_FIXTURE_DST \
    "app/services/src/_trust_order_fixture_tmp.c"
#define GIT_HOOKS_PRE_PUSH_REL "tools/githooks/pre-push"
/* Fixture path PREFIXES, not whole paths: these two checks live in the
 * REALROOT lane, which runs inside the worker pool, so they are resolved
 * through repo_path_pid() and carry the pid. */
#define GIT_HOOKS_PRE_PUSH_FIXTURE_REL \
    "test-tmp/_pre_push_hook_fixture_tmp"
#define GIT_HOOKS_PRECOMMIT_REL "tools/githooks/pre-commit"
#define GIT_HOOKS_PRECOMMIT_FIXTURE_REL \
    "test-tmp/_pre_commit_hook_fixture_tmp"
#define NO_DEV_HISTORY_SCRIPT_REL \
    "tools/scripts/check_no_dev_history_in_contracts.sh"
#define NO_DEV_HISTORY_FIXTURE_DST \
    "lib/util/include/util/_dev_history_lint_fixture_tmp.h"
#define NO_DEV_HISTORY_ALLOWLIST_FIXTURE_DST \
    "lib/util/include/util/_dev_history_lint_fixture_test.h"
/* Gate — no UNCITED victory claim in docs/HANDOFF.md. The gate takes a
 * scanned-doc override via ZCL_LINT_MODE (which run_gate_script's 2nd arg
 * sets), so we point it at a planted fixture .md instead of the live page. */
#define NO_UNCITED_VICTORY_SCRIPT_REL \
    "tools/scripts/check_no_uncited_victory.sh"
#define NO_UNCITED_VICTORY_FIXTURE_REL \
    "test-tmp/_uncited_victory_fixture_tmp.md"
#define NO_UNCITED_VICTORY_CITED_FIXTURE_REL \
    "test-tmp/_uncited_victory_cited_fixture_tmp.md"

#define E1_SCRIPT_REL    "tools/scripts/check_file_size_ceiling.sh"
#define E1_FIXTURE_DST   "app/controllers/src/_e1_size_ceiling_fixture_tmp.c"
/* E1's lib/domain WARN tier (extended to every .c under lib/, excl.
 * lib/test/ -- see tools/scripts/check_file_size_ceiling.sh's lib_files_all
 * scan + the WARN branch). No per-file baseline override env exists for E1
 * (unlike gate #12 below), so this plants directly into the real lib/ tree
 * like E1_FIXTURE_DST does for app/ -- a single violation here must PRINT
 * (WARN) and never fail the build on its own. It CAN still fail in
 * aggregate: the tier's total (new + grown) violation count is separately
 * ratcheted via ZCL_FILE_SIZE_CEILING_LIB_DRIFT_RATCHET (defaulting to
 * tools/scripts/file_size_ceiling_lib_drift_count.txt) so silent
 * accumulation still trips `make lint`. This test points that ratchet at
 * an isolated, generously-large tmp file so planting ONE fixture proves the
 * per-file WARN invariant without depending on how much real drift the live
 * tree already carries. */
#define E1_LIB_FIXTURE_DST \
    "lib/storage/src/_e1_lib_size_ceiling_fixture_tmp.c"
#define E1_LIB_DRIFT_RATCHET_ENV "ZCL_FILE_SIZE_CEILING_LIB_DRIFT_RATCHET"
#define E1_LIB_DRIFT_RATCHET_TMP_REL \
    "test-tmp/_e1_lib_drift_ratchet_isolated_tmp.txt"
/* Gate #12 — check_long_functions.sh, extended to config/src/ (ENFORCED,
 * ratchet-baselined) and lib/ excl. lib/test/ (WARN, non-blocking). Both
 * sub-tiers run against an ISOLATED test-tmp/ scan dir + baseline (via
 * ZCL_LONGFN_ENFORCED_ROOTS/_BASELINE and ZCL_LONGFN_LIB_ROOTS/
 * _LIB_BASELINE) so the self-test never touches the real scanned trees or
 * the real baseline files — same convention as SVC_CONV above. */
#define LONGFN_SCRIPT_REL          "tools/scripts/check_long_functions.sh"
#define LONGFN_ENFORCED_DIR_REL    "test-tmp/_longfn_enforced_scan_dir_tmp"
#define LONGFN_ENFORCED_FIXTURE_REL \
    "test-tmp/_longfn_enforced_scan_dir_tmp/fixture.c"
/* A permanent, always-clean sibling file so the gate's non-empty-scan-set
 * floor stays satisfied once fixture.c is removed during recovery — same
 * reason SVC_CONV_KEEP_REL exists above. */
#define LONGFN_ENFORCED_KEEP_REL \
    "test-tmp/_longfn_enforced_scan_dir_tmp/keep.c"
#define LONGFN_ENFORCED_BASELINE_REL "test-tmp/_longfn_enforced_baseline_tmp.txt"
#define LONGFN_LIB_DIR_REL         "test-tmp/_longfn_lib_scan_dir_tmp"
#define LONGFN_LIB_FIXTURE_REL     "test-tmp/_longfn_lib_scan_dir_tmp/fixture.c"
#define LONGFN_LIB_KEEP_REL        "test-tmp/_longfn_lib_scan_dir_tmp/keep.c"
#define LONGFN_LIB_BASELINE_REL    "test-tmp/_longfn_lib_baseline_tmp.txt"
#define E9_SCRIPT_REL    "tools/scripts/check_operator_needed_sink.sh"
#define SYSMEM_SCRIPT_REL "tools/scripts/check_systemd_memory_budget.sh"
#define QUALITY_GUARD_TEST_REL "tools/scripts/test_quality_job_guard.sh"
/* ── the two hermetic copy-prove selftests, and how their bound is derived ──
 * Both are driven through run_gate_script_watched(), whose bound is on
 * SILENCE, not on runtime — see the long rationale on that function. Neither
 * number below is a runtime budget, and neither may be raised to make a
 * failing assertion pass; a failure from these scripts is a logic verdict,
 * reported with its own distinct exit status.
 *
 * DERIVATION (identical for both, so they share one value):
 *   Each script prints a line per hermetic assertion, so the only silent
 *   stretches are the driver's own polling windows. The longest one either
 *   script contains is a 20 s sample/deadline window with no intervening
 *   output (fresh-boot-weld's --deadline=20 positive leg; import-copy-prove's
 *   --deadline=15 phase with 5 s polls). Silent stretches are built from
 *   `sleep N`, which does not stretch under CPU load, so the elastic part is
 *   only the fork/exec around them. 120 s = 6x the longest deliberate
 *   silence. Measured on this 32-cpu box at loadavg ~22, the whole
 *   fresh-boot-weld selftest runs in ~75 s wall with a longest observed
 *   silence well under 25 s.
 *   Raise this ONLY if a script gains a genuinely longer silent poll — and
 *   prefer making that poll emit progress instead. */
#define GATE_SELFTEST_MAX_SILENT_SECS 120
#define GATE_SELFTEST_SILENCE_DERIVATION \
    "Derivation: the script prints a line per assertion; its longest " \
    "deliberate silent window is a ~20s poll loop, so the bound is 6x that. " \
    "It is a silence bound, never a runtime budget."
#define IMPORT_COPY_PROVE_SELFTEST_REL \
    "tools/scripts/import-copy-prove-selftest.sh"
#define FRESH_BOOT_WELD_PROVE_SELFTEST_REL \
    "tools/scripts/fresh-boot-weld-prove-selftest.sh"
/* Gate E14 — condition cooldown re-arm (a page-loop bug class).
 * The script's own selftest plants an isolated tmp-dir fixture (never the
 * real app/conditions/src tree) proving a network-dependent COND_CRITICAL
 * condition without cooldown_secs trips exit 2, and every sibling case
 * (cooldown-bearing, .progressing-exempt, local-only, WARN-severity,
 * hollow-scan) stays/becomes clean. */
#define CONDITION_COOLDOWN_SCRIPT_REL "tools/scripts/check_condition_cooldown.sh"
#define MARKDOWN_LINK_SCRIPT_REL "tools/lint/check_markdown_links.sh"
#define FUZZ_ARTIFACT_REPLAY_SCRIPT_REL "tools/lint/check_fuzz_artifact_replay.sh"
#define E10_SHAPE_SCRIPT_REL "tools/lint/framework_shape_check.sh"
/* Same direct-selftest convention as NODE_DB_EXEC_FIXTURE_DST_REL: visible
 * without ZCL_LINT_PRODUCTION_SCAN, ignored by production/watch scans. */
#define E10_SHAPE_FIXTURE_DST \
    "app/_e10_offshape_fixture_probe_tmp.c"
/* check-telemetry-ontology: the fixture pair is CHECKED IN (a .fixture suffix
 * keeps it out of every source glob), so the trip case runs against the REAL
 * ontology and the REAL floors — a shrunken scan would trip for the wrong
 * reason and prove nothing. */
#define TELEMETRY_ONTOLOGY_SCRIPT_REL "tools/lint/check_telemetry_ontology.sh"
#define TELEMETRY_ONTOLOGY_EXTRA_ENV "ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST"
#define TELEMETRY_ONTOLOGY_EXTRA_REL "tools/lint/fixtures/telemetry_scan_extra.txt"
#define TELEMETRY_ONTOLOGY_MANIFEST_ENV "ZCL_TELEMETRY_SCAN_MANIFEST"
/* check-dumper-never-blocks: the script owns its own fixture sandbox behind
 * `--selftest` (a throwaway scan root + an empty baseline, never a plant into
 * the real tree), so this side only dispatches the flag and asserts 0. It
 * covers the collector blind spot — a blocking primitive inside a
 * `*_dump_state_fill` provider, which the pre-widening scan could not see. */
#define DUMPER_BLOCKING_SCRIPT_REL "tools/scripts/check_dumper_never_blocks.sh"
#define E10_SQL_SCRIPT_REL "tools/lint/check_no_raw_sqlite_in_controllers.sh"
#define E10_SQL_FIXTURE_DST "app/controllers/src/_e10_rawsql_fixture_tmp.c"
#define E11_SCRIPT_REL   "tools/scripts/check_doc_accuracy.sh"
/* Not gitignored on purpose: E11's repo-wide prong scans tracked files plus
 * not-yet-added files git does not ignore, so an ignored path would make the
 * trip case silently vacuous. */
#define E11_FIXTURE_DST  "docs/_e11_doc_count_fixture_tmp.md"
#define MODEL_AR_SCRIPT_REL "tools/scripts/check_model_ar_lifecycle.sh"
#define MODEL_AR_FIXTURE_DST "app/models/src/_model_ar_lifecycle_fixture_tmp.c"
#define E2_SCRIPT_REL    "tools/scripts/check_one_result_type.sh"
#define E2_FIXTURE_DST   "app/services/src/_e2_one_result_fixture_tmp.c"
/* Phase 3 shrinking-floor ratchet (sibling to E2): counts exported bool
 * DEFINITIONS per file rather than "does the file mention zcl_result
 * anywhere". Run entirely against an isolated test-tmp/ scan dir + baseline
 * (via ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR / _BASELINE) so the self-test
 * never touches the real app/services/src tree or the real baseline. */
#define SVC_CONV_SCRIPT_REL   "tools/scripts/check_service_result_convergence.sh"
#define SVC_CONV_SCAN_DIR_REL "test-tmp/_svc_conv_scan_dir_tmp"
#define SVC_CONV_KEEP_REL     "test-tmp/_svc_conv_scan_dir_tmp/keep.c"
#define SVC_CONV_FIXTURE_REL  "test-tmp/_svc_conv_scan_dir_tmp/fixture.c"
#define SVC_CONV_BASELINE_REL "test-tmp/_svc_conv_baseline_tmp.txt"
#define E3_SCRIPT_REL    "tools/scripts/check_shape_includes_header.sh"
#define E3_FIXTURE_DST   "app/conditions/src/_e3_shape_include_fixture_tmp.c"
#define E4_SCRIPT_REL    "tools/scripts/check_projections_pure.sh"
#define E4_FIXTURE_DST   "lib/storage/src/_e4_pure_fixture_projection.c"
/* Gate #45 — domain/ source purity (HARD). The fixture is a domain/ src file
 * carrying a forbidden include; clean tree → exit 0, fixture → exit != 0. */
#define DOMAIN_PURITY_SCRIPT_REL  "tools/scripts/check_domain_purity.sh"
#define DOMAIN_PURITY_FIXTURE_DST "domain/wallet/src/_domain_purity_fixture_tmp.c"
/* Gate #49 — inter-shape include direction (RATCHET). The fixture is an
 * app/models/src/ file with an upward #include "services/..."; clean tree
 * (13 pre-existing services/ -> controllers/ entries grandfathered in the
 * baseline) -> exit 0, fixture -> exit != 0. */
#define SHAPE_DIR_SCRIPT_REL  "tools/scripts/check_shape_include_direction.sh"
#define SHAPE_DIR_FIXTURE_DST "app/models/src/_shape_dir_fixture_tmp.c"
#define E5_SCRIPT_REL    "tools/scripts/check_stage_advances_or_blocks.sh"
#define E5_FIXTURE_DST   "app/jobs/src/_e5_stage_fixture_tmp_stage.c"
#define E6_SCRIPT_REL    "tools/scripts/check_one_write_path.sh"
#define E6_FIXTURE_DST   "app/services/src/_e6_write_path_fixture_tmp.c"
#define E7_SCRIPT_REL    "tools/scripts/check_no_authoritative_ram_state.sh"
#define E7_FIXTURE_DST   "app/services/src/_e7_ram_state_fixture_tmp.c"
#define FSUF_SCRIPT_REL  "tools/lint/check_framework_filename_suffix.sh"
/* A foreign-shape suffix (*_controller) planted under app/services/src. */
#define FSUF_FIXTURE_DST "app/services/src/_fsuf_fixture_tmp_controller.c"
/* Gate E13 — check-consensus-parity (HARD, no baseline). Scans
 * core/params, core/chainparams, lib/validation, lib/chain, lib/mining,
 * app/jobs, core/consensus for a forbidden miner-signaled/versionbits
 * mechanism token; the fixture plants a verbatim forbidden identifier
 * (VersionBitsState) so the trip is a faithful stand-in for the doctrine
 * violation, not an arbitrary string. */
#define CONSENSUS_PARITY_SCRIPT_REL "tools/scripts/check_consensus_parity.sh"
#define CONSENSUS_PARITY_FIXTURE_DST \
    "lib/validation/src/_consensus_parity_fixture_tmp.c"
/* Gate check-silent-errors-bool — RATCHET (shrink-only
 * silent_bool_errors_baseline.txt). Scans app/{controllers,services,jobs,
 * conditions,models,views,supervisors}/src for a swallowed
 * call-guard failure: `if (!some_call(...)) return false;` with no LOG_*
 * and no `// raw-return-ok:` marker. */
#define SILENT_BOOL_SCRIPT_REL "tools/lint/check_silent_bool_errors.sh"
#define SILENT_BOOL_FIXTURE_DST \
    "app/services/src/_silent_bool_fixture_tmp.c"
/* Gate P2 (docs/work/palace-design.md §3) — check-group-purpose. Runs against
 * a test-tmp/ COPY of the real codeindex_group.c (via ZCL_GROUP_PURPOSE_SRC)
 * so the self-test never mutates the real source file. */
#define GRPPURPOSE_SCRIPT_REL      "tools/lint/check_group_purpose.sh"
#define GRPPURPOSE_REAL_SRC_REL    "lib/codeindex/src/codeindex_group.c"
#define GRPPURPOSE_OK_FIXTURE_REL  "test-tmp/_group_purpose_fixture_ok_tmp.c"
#define GRPPURPOSE_BAD_FIXTURE_REL "test-tmp/_group_purpose_fixture_bad_tmp.c"
/* Gate P1 (docs/work/palace-design.md §3) — check-file-purpose. The gate scans
 * an ISOLATED fixture tree under test-tmp/ (via ZCL_FILE_PURPOSE_ROOT), never
 * the real codebase; the two canned fixtures live in lib/test/fixtures/. */
#define FILEPURPOSE_SCRIPT_REL      "tools/lint/check_file_purpose.sh"
#define FILEPURPOSE_ROOT_REL        "test-tmp/_file_purpose_root_tmp"
#define FILEPURPOSE_PLANT_REL       "test-tmp/_file_purpose_root_tmp/app/" \
                                    "services/src/_file_purpose_lint_fixture_tmp.c"
#define FILEPURPOSE_BAD_FIXTURE_REL "lib/test/fixtures/file_purpose_missing_fixture.c"
#define FILEPURPOSE_OK_FIXTURE_REL  "lib/test/fixtures/file_purpose_present_fixture.c"
/* Gate P3 (docs/work/palace-design.md §3) — check-no-orphan-placement. The
 * gate judges an EXPLICIT path list (via ZCL_ORPHAN_PLACEMENT_FILES) instead
 * of git ls-files; placement is decided from the path alone, so no file needs
 * to exist on disk. */
#define ORPHAN_SCRIPT_REL "tools/lint/check_no_orphan_placement.sh"
#define LOG_MACRO_RETURN_SCRIPT_REL \
    "tools/lint/check_log_macro_return_type.sh"
#define LOG_MACRO_RETURN_FIXTURE_DST \
    "app/services/src/_log_macro_return_type_fixture_tmp.c"
#define E12_SCRIPT_REL   "tools/lint/check_honest_witness.sh"
/* A condition .c with a PURE-INVERSE witness (the canonical Law-7 lie:
 * "return !detect_x()"), planted under app/conditions/src so the gate's
 * scan scope sees it. */
#define E12_FIXTURE_DST  "app/conditions/src/_e12_honest_witness_fixture_tmp.c"
/* Gate #21 background-worker lock-in: the widened check_supervisor_domain.sh
 * also scans the boot worker file (config/src/boot_background_workers.c) and
 * fails any spawn (pthread_create / thread_registry_spawn) not paired with a
 * supervisor_register_in_domain. The fixtures are planted under test-tmp/ and
 * fed to the gate via ZCL_SUPERVISOR_WORKER_FILES so the assertion does not
 * depend on the live worker file's state. */
#define SUPDOM_SCRIPT_REL     "tools/lint/check_supervisor_domain.sh"
/* A worker that spawns a thread but registers NO domain contract — the lie
 * the widened gate must catch (an unsupervised background worker). */
#define SUPDOM_BAD_WORKER_REL "test-tmp/_supdom_unsupervised_worker_fixture_tmp.c"
/* The same worker WITH a supervisor_register_in_domain pairing — passes. */
#define SUPDOM_OK_WORKER_REL  "test-tmp/_supdom_supervised_worker_fixture_tmp.c"

/* ── shared helpers, then every check in the group ───────────────────── */

void repo_root_set_override(const char *path);
const char *repo_root(void);
int repo_path(char *out, size_t outsz, const char *rel);
int repo_path_pid(char *out, size_t outsz, const char *rel_prefix,
                  const char *suffix);
int lint_gate_out_path(char *out, size_t outsz);
int copy_file(const char *src, const char *dst);
char *str_replace_once(const char *hay, const char *needle,
                              const char *repl);
bool has_c_suffix(const char *path);
bool has_ch_suffix(const char *path);
int read_entire_file(const char *path, char **out_buf);
size_t count_occurrences(const char *haystack, const char *needle);
int check_coins_guard_file(const char *path);
bool line_has_obs_ok(const char *line);
bool line_has_event_emit(const char *line);
bool line_has_terminal_propagation(const char *line);
bool observability_line_allowed(char lines[][4096], size_t count,
                                       size_t idx);
int check_observability_file(const char *path);
bool active_chain_set_tip_file_allowed(const char *path);
int check_active_chain_set_tip_file(const char *path);
int walk_c_files(const char *dirpath,
                        int (*check_file)(const char *path));
int walk_ch_files(const char *dirpath,
                         int (*check_file)(const char *path));
int check_deleted_engine_names_file(const char *path);
bool build_commit_macro_file_allowed(const char *path);
int check_build_commit_macro_file(const char *path);
int run_check_build_commit_macro_contract(void);
int run_check_raw_sqlite(void);
int run_check_coins_lookup_nullcheck(void);
int run_check_service_tip_mutation_gate(void);
int run_check_deleted_engine_names(void);
int t_observability_fixture_trips_gate(void);
int t_observability_positive_controls_pass(void);
int t_baseline_passes(void);
int t_fixture_trips_gate(void);
int t_node_db_exec_fixture_trips_gate(void);
int t_gate_recovers_after_removal(void);
int t_coins_guard_baseline_passes(void);
int t_coins_guard_fixture_trips_gate(void);
int write_file(const char *path, const char *contents);
pid_t fork_with_retry(void);
int run_check_raw_malloc_script(void);
int run_gate_script(const char *script_rel, const char *mode);
int run_gate_script_arg(const char *script_rel, const char *mode,
                        const char *arg);
int run_gate_script_selftest(const char *script_rel);
int run_gate_script_with_worker_files(const char *script_rel,
                                             const char *mode,
                                             const char *worker_files_rel);
int run_gate_script_with_env(const char *script_rel,
                                    const char *env_name,
                                    const char *env_value);
int run_gate_script_with_env2(const char *script_rel,
                                     const char *env_name1,
                                     const char *env_value1,
                                     const char *env_name2,
                                     const char *env_value2);
int run_git_hooks_gate_with_path(const char *hooks_path);
int run_git_hooks_gate_with_file(const char *hook_path);
int run_git_hooks_gate_with_precommit_file(const char *hook_path);
int t_git_hooks_gate_enforces_tracked_pre_push(void);
int t_git_hooks_gate_rejects_noop_pre_push(void);
int t_git_hooks_gate_rejects_noop_pre_commit(void);
int plant_oversized_file(const char *rel, int n_lines);
void unlink_rel(const char *rel);
int plant_long_function_file(const char *rel, const char *func_name,
                                    int target_len, const char *tag);
int t_long_functions_enforced_ratchet(void);
int t_long_functions_lib_warn_tier(void);
int t_e1_file_size_ceiling(void);
int t_e1_lib_warn_tier(void);
int t_no_new_repair_rung(void);
int t_no_new_borrowed_seed_caller(void);
int t_no_new_coin_backfill_caller(void);
int t_no_writer_below_sealed_frontier(void);
int t_e9_operator_needed_sink(void);
int t_systemd_memory_budget(void);
int t_quality_job_guard(void);
/* Returned by run_gate_script_watched when the script was killed for making
 * no progress. Deliberately not 1 and not any exit status a gate script can
 * produce: a HANG and a failed assertion are different findings, and a caller
 * must be able to say which one it saw. */
#define GATE_SCRIPT_WEDGED (-2)
void lint_gate_loadavg(char *out, size_t outsz);
int run_gate_script_watched(const char *script_rel, int max_silent_secs,
                            const char *why_bound);
int t_import_copy_prove_selftest(void);
int t_fresh_boot_weld_prove_selftest(void);
int t_e14_condition_cooldown_gate(void);
int t_markdown_links_gate(void);
int t_fuzz_artifact_ledger_gate(void);
int t_e10_framework_shape_ratchet(void);
int t_telemetry_ontology_gate(void);
int t_e10_no_raw_sqlite_ratchet(void);
int t_gate22_framework_filename_suffix(void);
int t_gate_p2_group_purpose(void);
int t_gate_p1_file_purpose(void);
int t_gate_p3_orphan_placement(void);
int t_e13_consensus_parity_fixture(void);
int t_silent_errors_bool_fixture(void);
int t_log_macro_return_type_gate(void);
int t_e11_doc_accuracy(void);
int t_model_ar_lifecycle_gate(void);
int t_e2_one_result_type(void);
int t_service_result_convergence_ratchet(void);
int t_thread_supervision_ratchet(void);
int t_supervisor_registration_widened_ratchet(void);
int t_e3_shape_includes_header(void);
int t_e4_projections_pure(void);
int t_domain_purity(void);
int t_shape_include_direction(void);
int t_e5_stage_advances_or_blocks(void);
int t_e6_one_write_path(void);
int t_e7_no_authoritative_ram_state(void);
int t_e12_honest_witness(void);
int t_gate21_supervisor_worker_lockin(void);
int t_coins_guard_gate_fails_loud_on_no_lookup_surface(void);
int meta_gate_empty_scan_trips(const char *script_rel,
                                      const char *env_name,
                                      const char *empty_value);
int run_hotswap_gate_with_manifest(const char *script_rel,
                                          const char *manifest_rel);
int t_hotswap_eligible_scope_gate(void);
int run_hotswap_swappable_gate(const char *manifest_rel);
int t_hotswap_swappable_shape_gate(void);
int t_hotswap_swappable_leaf_contract_gate(void);
int t_hotswap_static_state_gate(void);
int t_hotswap_static_state_covers_swappable(void);
int t_hotswap_service_island_gate(void);
int t_privileged_transition_receipt_gate(void);
int t_dumper_never_blocks_gate(void);
int t_no_trust_state_ordering_gate(void);
int t_blocker_escape_registered_gate(void);
int t_lint_gates_fail_loud_on_empty_scan(void);
void unlink_lint_fixtures(void);
int t_raw_malloc_fixture_trips_gate(void);
int t_raw_malloc_zcl_fixture_passes(void);
int t_raw_malloc_gate_recovers(void);
int t_coins_guard_gate_recovers(void);
int tracked_active_tree_has_no_tools_z_reference(void);
int t_deprecated_tools_z_is_absent(void);
int t_canonical_operator_diagnostics_contract(void);
int t_service_tip_mutation_gate(void);
int t_legacy_candidate_source_has_no_override_scope(void);
int t_canonical_deploy_proof_binding_contract(void);
int t_dev_lane_deploy_contract(void);
int t_agent_fast_ci_contract(void);
int t_native_operator_docs_contract(void);
int t_remote_node_update_contract(void);
int t_native_agent_api_contract(void);
int t_mvp_reporters_resolve_live_service_rpc_contract(void);
int t_soak_assert_requires_known_mirror_lag(void);
int t_boot_chain_advance_diagnostics_contract(void);
int t_boot_core_liveness_precedes_frontend_contract(void);
int t_boot_addrman_persistence_contract(void);
int t_lib_runtime_gauges_are_callback_injected(void);
int t_boot_shutdown_persistence_order_contract(void);
int t_hodl_history_uses_runtime_db_service(void);
int t_db_service_query_handle_is_canonical(void);
int t_txindex_releases_node_db_between_batches(void);
int t_peer_save_busy_reports_db_error(void);
int t_handshake_peer_save_is_async(void);
int t_p2p_app_persistence_is_callback_injected(void);
int t_tx_wallet_sync_is_callback_injected(void);
int t_p2p_block_submit_is_callback_injected(void);
int t_flyclient_proof_builder_is_callback_injected(void);
int t_fast_sync_uses_lib_sqlite_helpers(void);
int t_framework_reexport_headers_stay_deleted(void);
int t_utxo_reimport_flag_is_storage_owned(void);
int t_net_sync_planners_are_lib_owned(void);
int t_header_peer_votes_are_callback_injected(void);
int t_process_block_node_db_access_is_runtime_owned(void);
int t_boot_repaired_index_persistence_contract(void);
int t_chain_evidence_reconstruct_uses_retry_persistence(void);
int t_boot_genesis_init_preserves_restored_authority_contract(void);
int t_refold_from_anchor_explicit_span_gate_contract(void);
int t_sha3_window_tool_check_contract(void);
int t_make_ignores_ephemeral_lint_fixture_sources(void);
int t_block_index_flat_atomic_save_contract(void);
int t_process_block_split_uses_reducer_language(void);
int t_production_comments_do_not_carry_refactor_scaffold_labels(void);
int t_deleted_engine_names_absent_from_production_sources(void);
int t_build_commit_macro_stays_behind_getter(void);
int t_projection_deferral_is_not_block_rejected_contract(void);
int t_trusted_peer_stall_guard_contract(void);
int t_gap_fill_wakes_connman_dispatch_contract(void);
int t_msg_process_yields_to_send_phase_contract(void);
int t_no_dev_history_in_contracts(void);
int t_no_uncited_victory(void);
int t_no_stray_root_files(void);

#endif /* ZCL_LINT_GATE_SELFTESTS_H */
