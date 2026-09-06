/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the split C23 lint runtime's gate table and CLI entry point
 * (z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"

static const struct lint_gate k_gates[] = {
    { "check-no-python", check_no_python_run, check_no_python_selftest },
    { "check-malloc", check_malloc_run, check_malloc_selftest },
    { "check-dev-proof-native-fast-path", check_dev_proof_native_fast_path_run,
      check_dev_proof_native_fast_path_selftest },
    { "check-before-save-hooks", check_before_save_hooks_run, check_before_save_hooks_selftest },
    { "check-pthread-create", check_pthread_create_run, check_pthread_create_selftest },
    { "check-silent-error-returns", check_silent_error_returns_run,
      check_silent_error_returns_selftest },
    { "check-no-gnu-va-args", check_no_gnu_va_args_run, check_no_gnu_va_args_selftest },
    { "check-sysinit-ordering", check_sysinit_ordering_run, check_sysinit_ordering_selftest },
    { "check-no-raw-clock-outside-platform", check_no_raw_clock_outside_platform_run,
      check_no_raw_clock_outside_platform_selftest },
    { "check-no-shellouts", check_no_shellouts_run, check_no_shellouts_selftest },
    { "check-command-contract", check_command_contract_run, check_command_contract_selftest },
    { "check-no-writer-below-sealed-frontier", check_no_writer_below_sealed_frontier_run,
      check_no_writer_below_sealed_frontier_selftest },
    { "check-no-stray-root-files", check_no_stray_root_files_run,
      check_no_stray_root_files_selftest },
    { "check-proc-self-shim", check_proc_self_shim_run, check_proc_self_shim_selftest },
    { "check-simd-os-support", check_simd_os_support_run, check_simd_os_support_selftest },
    { "check-c23-only", check_c23_only_run, check_c23_only_selftest },
    { "check-hotswap-dev-only", check_hotswap_dev_only_run, check_hotswap_dev_only_selftest },
    { "check-no-api-keys", check_no_api_keys_run, check_no_api_keys_selftest },
    { "check-error-doc-refs", check_error_doc_refs_run, check_error_doc_refs_selftest },
    { "check-core-seal-root-mirror", check_core_seal_root_mirror_run,
      check_core_seal_root_mirror_selftest },
    { "check-peer-floor-single-source", check_peer_floor_single_source_run,
      check_peer_floor_single_source_selftest },
    { "check-proof-server-pin", check_proof_server_pin_run,
      check_proof_server_pin_selftest },
    { "check-tu-random-seed", check_tu_random_seed_run,
      check_tu_random_seed_selftest },
    { "check-no-retired-agent-protocol", check_no_retired_agent_protocol_run,
      check_no_retired_agent_protocol_selftest },
    { "check-stopwatch-skip-detector", check_stopwatch_skip_detector_run,
      check_stopwatch_skip_detector_selftest },
    { "check-no-warning-suppression", check_no_warning_suppression_run,
      check_no_warning_suppression_selftest },
    { "check-privileged-transition-receipt", check_privileged_transition_receipt_run,
      check_privileged_transition_receipt_selftest },
    { "check-no-new-coin-backfill-caller", check_no_new_coin_backfill_caller_run,
      check_no_new_coin_backfill_caller_selftest },
    { "check-mind-owns-rebuild", check_mind_owns_rebuild_run,
      check_mind_owns_rebuild_selftest },
    { "check-codeindex-coverage", check_codeindex_coverage_run,
      check_codeindex_coverage_selftest },
    { "check-asan-adx-exception", check_asan_adx_exception_run,
      check_asan_adx_exception_selftest },
    { "check-framework-filename-suffix", check_framework_filename_suffix_run,
      check_framework_filename_suffix_selftest },
    { "check-no-stray-untracked-source", check_no_stray_untracked_source_run,
      check_no_stray_untracked_source_selftest },
    { "check-group-purpose", check_group_purpose_run, check_group_purpose_selftest },
    { "check-no-new-borrowed-seed", check_no_new_borrowed_seed_run,
      check_no_new_borrowed_seed_selftest },
    { "check-silent-errors-bool", check_silent_errors_bool_run,
      check_silent_errors_bool_selftest },
    { "check-no-raw-sqlite-in-controllers", check_no_raw_sqlite_in_controllers_run,
      check_no_raw_sqlite_in_controllers_selftest },
    { "check-blob-read-bounds", check_blob_read_bounds_run,
      check_blob_read_bounds_selftest },
};

int main(int argc, char **argv)
{
    g_lint_argv0 = argc > 0 ? argv[0] : NULL;
    if (argc >= 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++)
            printf("%s\n", k_gates[i].name);
        return 0;
    }
    if (argc < 2)
        return die("z23-lint: usage: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list\n",
                   "");
    const struct lint_gate *g = NULL;
    for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++) {
        if (strcmp(argv[1], k_gates[i].name) == 0)
            g = &k_gates[i];
    }
    if (!g)
        return die("z23-lint: unknown gate: %s\n", argv[1]);
    if (argc >= 3 && strcmp(argv[2], "--selftest") == 0)
        return g->selftest();
    return g->run(argc - 2, argv + 2);
}
