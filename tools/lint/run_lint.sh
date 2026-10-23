#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# run_lint.sh — timed, parallel driver for the `make lint` check-* umbrella.
#
# Why this exists: the umbrella grew to ~87 serial gates (measured p50 ~56 s
# wall on the dev reference host, 2026-07-18) with zero per-gate timing, and
# every gate paid a multi-second Make parse when run standalone. This driver
# execs each gate's script directly (same ZCL_LINT_PRODUCTION_SCAN=1 contract
# the Makefile `check-%` pattern rule sets), times every gate in ms, records
# results under .cache/lint-timing/ (dev-loop-bench artifact pattern), and
# runs independent gates concurrently.
#
# Parallel-safety contract (verified 2026-07-18): gates are read-only over
# the source tree in their default modes; ratchet baselines are written only
# under an explicit manual ZCL_LINT_MODE=UPDATE (never via `make lint`);
# every selftest-style gate works in a mktemp dir. Gates that read a live
# generated index need a stable view after the build-affecting gates finish.
# The serial exceptions are:
#   check-git-hooks-installed — validates checkout-local Git configuration
#     before the parallel pool, after its hermetic host-selection fixture.
#   check-build-epoch-integrity — its cold compile/publish probe has a 600s
#     wall bound that concurrent compiler sweeps can exhaust.
#   check-cookbook — RUN recipes query codeindex; a parallel gate can change
#     depfile metadata during its rebuild, producing a retryable CODEINDEX_OPEN
#     rather than the required answer. Run it after the parallel pool.
# check-no-stray-untracked-source was also verified read-only; it no longer
# needs to run first because the driver never circuit-breaks on the first
# failure — all gates run and every failure is reported, strays included.
#
# Every run is cold: each requested gate executes every time. There is no
# result cache; a gate's verdict is always its own fresh run.
#
# Usage:
#   tools/lint/run_lint.sh [--jobs N] [--bin-dir DIR] [--list] GATE...
#   tools/lint/run_lint.sh --print-command GATE   (one gate's exact command)
#   tools/lint/run_lint.sh --worker GATE         (internal: xargs child)
#
# Env:
#   ZCL_LINT_JOBS        default worker count when --jobs absent (default 8)
#   ZCL_LINT_BUDGET_SEC  soft wall-time budget, warn-only past it (default 75)
#   ZCL_LINT_TIMING_DIR  artifact dir (default .cache/lint-timing)
#   ZCL_LINT_VERBOSE=1   print the full per-gate timing table, not just top 10
#   ZCL_CC_JOBS           nested compiler workers for check-clang-portability;
#                         defaults to 3/8 of ZCL_HOST_JOBS, clamped 4..12,
#                         when a sweep gate runs, else 1
#   ZCL_WIN_CROSS_JOBS    nested compiler workers for check-windows-cross-
#                         syntax; defaults to 5/8 of ZCL_HOST_JOBS, clamped
#                         6..20, when a sweep gate runs, else unset (that
#                         gate then falls back to ZCL_CC_JOBS itself)
#   ZCL_TOOLS_LINK_JOBS   nested standalone-link workers; defaults to 1 here
#   ZCL_FUZZ_REPLAY_JOBS  nested fuzz-replay workers; defaults to 1 here
#
# Exit: 0 iff every gate passed; 1 if any gate failed (all gates still run,
# so one `make lint` reports every violation); 2 on driver misuse/unknown gate.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

STATE_DIR="${ZCL_LINT_TIMING_DIR:-$ROOT/.cache/lint-timing}"
# Per-run artifact dir, never a path two runs can share. Every run used to
# write .log/.rc/.ms into $STATE_DIR/gates and wipe that directory at start,
# so two `make lint` runs in one checkout stepped on each other: measured
# 2026-08-27, three concurrent runs reported byte-identical per-gate timings
# because each was reading the others' files. The same sharing lets one run
# print a verdict another run produced, or cat a log body another run's worker
# had just truncated to zero bytes. The parent picks the dir; workers inherit
# it through ZCL_LINT_GATES_DIR_X (they are re-execs of this script).
GATES_DIR="${ZCL_LINT_GATES_DIR_X:-$STATE_DIR/gates/run.$$}"
JOBS="${ZCL_LINT_JOBS:-8}"
BIN_DIR="build/bin"
BUDGET_SEC="${ZCL_LINT_BUDGET_SEC:-75}"

# Gates that must run serially — see the header contract. Code-index coverage
# snapshots source and depfile metadata, which parallel compile gates can
# change during its rebuild.
SERIAL_PROLOGUE=" check-git-hooks-installed check-build-epoch-integrity "
SERIAL_EPILOGUE=" check-codeindex-coverage check-cookbook "

# Parallel gates handed to the worker pool BEFORE every other gate, in this
# order. Dispatch order changes no gate's command, input or verdict — every
# requested gate still runs exactly once — it only decides which gate waits
# for a free worker. The pool used to take gates in LINT_GATES order, which
# put these compiler sweeps and link runs at positions 180-200 of ~210, so
# the longest gate of the whole run started last and the run's wall was its
# start offset PLUS its own duration. Longest-first is the classic fix for
# that list-scheduling tail. The landing-proof long pole comes first, then
# the other gates measured at 30 s or more cold (docs/quality/BENCHMARKS_LOG.md,
# 2026-09-25); read the lint timing table (ZCL_LINT_VERBOSE=1) before editing.
LONG_POLE_FIRST="check-windows-cross-syntax check-standalone-tools-link
    check-clang-portability check-vcs-no-sha1
    check-windows-acceptance check-outparam-init-before-return"

# ── Gate invocation table ────────────────────────────────────────────────
# One entry per check-* gate in the Makefile lint umbrella (LINT_GATES). The
# command must reproduce the gate's Make recipe EXACTLY (script path, args,
# and any ZCL_LINT_MODE prefix). A gate added to LINT_GATES without a table
# entry is a LOUD driver error (exit 2), never a silent skip.
gate_command() {
    case "$1" in
        check-lint-gate-wiring)            echo './build/bin/z23-lint check-lint-gate-wiring --selftest && ./build/bin/z23-lint check-lint-gate-wiring' ;;
        check-toolchain)                   echo './tools/dev/check-toolchain.sh --selftest && ./tools/dev/check-toolchain.sh' ;;
        check-dev-linker-threads)          echo 'make check-dev-linker-threads' ;;
        check-fuzz-artifact-ledger)        echo './tools/lint/check_fuzz_artifact_replay.sh --ledger-only' ;;
        check-build-epoch-integrity)       echo 'tools/dev/build-epoch-integrity-cached.sh' ;;
        check-checkout-lock)               echo 'tools/dev/checkout-lock-selftest.sh' ;;
        check-host-gc-selftest)            echo 'tools/scripts/host_gc_selftest.sh' ;;
        check-commons-journey-ordering)    echo 'tools/dev/commons-journey-ordering-selftest.sh' ;;
        check-no-stray-untracked-source)   echo './build/bin/z23-lint check-no-stray-untracked-source' ;;
        check-codeindex-coverage)          echo './build/bin/z23-lint check-codeindex-coverage --selftest && ./build/bin/z23-lint check-codeindex-coverage' ;;
        check-mind-owns-rebuild)           echo './build/bin/z23-lint check-mind-owns-rebuild --selftest && ./build/bin/z23-lint check-mind-owns-rebuild' ;;
        check-tor-full-default)            echo './build/bin/z23-lint check-tor-full-default --selftest && ./build/bin/z23-lint check-tor-full-default' ;;
        check-no-stray-root-files)         echo './build/bin/z23-lint check-no-stray-root-files' ;;
        check-scanner-immunity)            echo './tools/lint/selftest_scanner_immunity.sh' ;;
        check-zcc-cache)                   echo './tools/lint/check_zcc_cache.sh' ;;
        check-zcc-epoch-object)            echo './tools/lint/check_zcc_epoch_object.sh' ;;
        check-zcc-epoch-batch)             echo './tools/lint/check_zcc_epoch_batch.sh' ;;
        check-dev-proof-native-fast-path)  echo './build/bin/z23-lint check-dev-proof-native-fast-path' ;;
        check-tu-random-seed)              echo './build/bin/z23-lint check-tu-random-seed' ;;
        check-equihash-params)             echo './build/bin/z23-lint check-equihash-params --selftest && ./build/bin/z23-lint check-equihash-params' ;;
        check-determinism-ratchet)         echo './tools/lint/check_determinism_ratchet.sh --selftest && ./tools/lint/check_determinism_ratchet.sh' ;;
        check-git-hooks-installed)         echo './tools/scripts/check_git_hooks_installed.sh --self-test && ./tools/scripts/install_git_hooks_selftest.sh && ./tools/scripts/check_git_hooks_installed.sh' ;;
        check-malloc)                      echo './build/bin/z23-lint check-malloc' ;;
        check-hotswap-dev-only)            echo './build/bin/z23-lint check-hotswap-dev-only' ;;
        check-hotswap-eligible-scope)      echo 'build/bin/z23-lint check-hotswap-eligible-scope' ;;
        check-hotswap-denied-leaves)       echo 'build/bin/z23-lint check-hotswap-denied-leaves --selftest && build/bin/z23-lint check-hotswap-denied-leaves' ;;
        check-remote-command-classes)      echo './build/bin/z23-lint check-remote-command-classes --selftest && ./build/bin/z23-lint check-remote-command-classes' ;;
        check-hotswap-static-state)        echo 'build/bin/z23-lint check-hotswap-static-state' ;;
        check-hotswap-service-islands)     echo 'tools/lint/check_hotswap_service_islands.sh' ;;
        check-hotswap-swappable-shape)     echo 'build/bin/z23-lint check-hotswap-swappable-shape' ;;
        check-hotswap-candidates-ledger)   echo './build/bin/z23-lint check-hotswap-candidates-ledger --selftest && ./build/bin/z23-lint check-hotswap-candidates-ledger' ;;
        check-hotswap-package-receipt-is-not-authority) echo 'build/bin/z23-lint check-hotswap-package-receipt-is-not-authority --selftest && build/bin/z23-lint check-hotswap-package-receipt-is-not-authority' ;;
        check-hotswap-module-imports)      echo 'tools/lint/check_hotswap_module_imports.sh --selftest && tools/lint/check_hotswap_module_imports.sh' ;;
        check-release-no-dev-symbols)      echo 'tools/lint/check_release_no_dev_symbols.sh' ;;
        check-stable-publish-contained)    echo 'bash tools/scripts/check_stable_publish_containment.sh --self-test && bash tools/scripts/check_stable_publish_containment.sh' ;;
        check-raw-sqlite)                  echo 'tools/scripts/check_raw_sqlite.sh' ;;
        check-raw-malloc)                  echo 'tools/scripts/check_raw_malloc.sh --selftest && tools/scripts/check_raw_malloc.sh' ;;
        check-json-value-init)             echo './build/bin/z23-lint check-json-value-init --self-test && ./build/bin/z23-lint check-json-value-init' ;;
        check-blob-read-bounds)            echo './build/bin/z23-lint check-blob-read-bounds' ;;
        check-outparam-init-before-return) echo 'bash tools/lint/check_outparam_init_before_return.sh --selftest && bash tools/lint/check_outparam_init_before_return.sh' ;;
        check-byte-order-codec-single)     echo './build/bin/z23-lint check-byte-order-codec-single --selftest && ./build/bin/z23-lint check-byte-order-codec-single' ;;
        check-arm-symbol-single)           echo './build/bin/z23-lint check-arm-symbol-single --selftest && ./build/bin/z23-lint check-arm-symbol-single' ;;
        check-fortify-masked-decls)        echo './tools/lint/check_fortify_masked_decls.sh --selftest && ./tools/lint/check_fortify_masked_decls.sh' ;;
        check-model-sql-literals)          echo './build/bin/z23-lint check-model-sql-literals --selftest && ./build/bin/z23-lint check-model-sql-literals' ;;
        check-persona-resolves)            echo './build/bin/z23-lint check-persona-resolves --selftest && ./build/bin/z23-lint check-persona-resolves' ;;
        check-specialists)                 echo './build/bin/z23-lint check-specialists --selftest && ./build/bin/z23-lint check-specialists' ;;
        check-fleet-airship-rules)         echo './build/bin/z23-lint check-fleet-airship-rules --selftest && ./build/bin/z23-lint check-fleet-airship-rules' ;;
        check-fleet-facts)                 echo './build/bin/z23-lint check-fleet-facts --selftest && ./build/bin/z23-lint check-fleet-facts' ;;
        check-fleet-observations)          echo './build/bin/z23-lint check-fleet-observations --selftest && ./build/bin/z23-lint check-fleet-observations' ;;
        check-fleet-vitals)                echo './build/bin/z23-lint check-fleet-vitals --selftest && ./build/bin/z23-lint check-fleet-vitals' ;;
        check-prompt-templates)            echo './build/bin/z23-lint check-prompt-templates --selftest && ./build/bin/z23-lint check-prompt-templates' ;;
        check-rule-vocabulary)             echo './build/bin/z23-lint check-rule-vocabulary --selftest && ./build/bin/z23-lint check-rule-vocabulary' ;;
        check-cookbook)                    echo './build/bin/z23-lint check-cookbook --selftest && ./build/bin/z23-lint check-cookbook' ;;
        check-zcode-package-registry)      echo './build/bin/z23-lint check-zcode-package-registry' ;;
        check-zcode-package-standalone)    echo './build/bin/z23-lint check-zcode-package-standalone' ;;
        check-capability-closure)          echo './build/bin/z23-lint check-capability-closure --selftest && ./build/bin/z23-lint check-capability-closure' ;;
        check-package-capabilities)        echo './build/bin/z23-lint check-package-capabilities --selftest && ./build/bin/z23-lint check-package-capabilities' ;;
        check-package-anatomy)             echo './tools/lint/check_package_anatomy.sh --selftest && ./tools/lint/check_package_anatomy.sh' ;;
        check-coins-lookup-nullcheck)      echo 'tools/scripts/check_coins_lookup_nullcheck.sh' ;;
        check-observability-pairing)       echo '"$ZCL_LINT_BIN_DIR/check_observability_pairing"' ;;
        check-no-hardlink-seeding)         echo '"$ZCL_LINT_BIN_DIR/check_no_hardlink_seeding" --selftest && "$ZCL_LINT_BIN_DIR/check_no_hardlink_seeding"' ;;
        check-toolgen)                     echo '"$ZCL_LINT_BIN_DIR/z23-toolgen" --check' ;;
        check-silent-errors-services)      echo './build/bin/z23-lint check-silent-error-returns engine/services/src services service "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-controllers)   echo './build/bin/z23-lint check-silent-error-returns engine/controllers/src controllers controller "use LOG_ERR/LOG_RETURN, prev-line fprintf, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-jobs)          echo './build/bin/z23-lint check-silent-error-returns engine/jobs/src jobs job "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-conditions)    echo './build/bin/z23-lint check-silent-error-returns engine/conditions/src conditions condition "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-bool)          echo 'ZCL_LINT_MODE=FAIL ./build/bin/z23-lint check-silent-errors-bool' ;;
        check-log-macro-return-type)       echo './build/bin/z23-lint check-log-macro-return-type --selftest && ./build/bin/z23-lint check-log-macro-return-type' ;;
        check-no-runtime-abort)            echo './build/bin/z23-lint check-no-runtime-abort' ;;
        check-hardening-ratchet)           echo './build/bin/z23-lint check-hardening-ratchet --selftest && ./build/bin/z23-lint check-hardening-ratchet' ;;
        check-wallet-raw-prepare-log)      echo 'ZCL_LINT_MODE=FAIL ./build/bin/z23-lint check-wallet-raw-prepare-log' ;;
        check-before-save-hooks)           echo './build/bin/z23-lint check-before-save-hooks' ;;
        check-pthread-create)              echo './build/bin/z23-lint check-pthread-create' ;;
        check-model-validation)            echo './build/bin/z23-lint check-model-validation' ;;
        check-model-ar-lifecycle)          echo './tools/scripts/check_model_ar_lifecycle.sh --selftest && ./tools/scripts/check_model_ar_lifecycle.sh' ;;
        check-long-functions)              echo './tools/scripts/check_long_functions.sh --selftest && ./tools/scripts/check_long_functions.sh' ;;
        check-cyclomatic-complexity)       echo './build/bin/z23-lint check-cyclomatic-complexity --selftest && ./build/bin/z23-lint check-cyclomatic-complexity' ;;
        check-rpc-registrar)               echo './build/bin/z23-lint check-rpc-registrar' ;;
        check-lag-slo-observable)          echo './build/bin/z23-lint check-lag-slo-observable' ;;
        check-lib-layering)                echo './tools/scripts/check_lib_layering.sh --selftest && ./tools/scripts/check_lib_layering.sh' ;;
        check-lib-module-order)            echo './tools/scripts/check_lib_module_order.sh' ;;
        check-shape-include-direction)     echo './tools/scripts/check_shape_include_direction.sh --selftest && ./tools/scripts/check_shape_include_direction.sh' ;;
        check-controller-private-headers) echo './build/bin/z23-lint check-controller-private-headers --selftest && ./build/bin/z23-lint check-controller-private-headers' ;;
        check-domain-purity)               echo './tools/scripts/check_domain_purity.sh --selftest && ./tools/scripts/check_domain_purity.sh' ;;
        check-core-include-boundary)       echo './build/bin/z23-lint check-core-include-boundary --selftest && ./build/bin/z23-lint check-core-include-boundary' ;;
        check-core-seal)                   echo '__core_seal__' ;;
        check-core-seal-root-mirror)       echo './build/bin/z23-lint check-core-seal-root-mirror' ;;
        check-accel-oracle-pinned)         echo './build/bin/z23-lint check-accel-oracle-pinned --selftest && ./build/bin/z23-lint check-accel-oracle-pinned' ;;
        check-no-adx-overclaim)            echo './tools/lint/check_no_adx_overclaim.sh --selftest && ./tools/lint/check_no_adx_overclaim.sh && ./build/bin/z23-lint check-asan-adx-exception --selftest && ./build/bin/z23-lint check-asan-adx-exception' ;;
        check-simd-os-support)             echo './build/bin/z23-lint check-simd-os-support' ;;
        check-supervisor-registration)     echo './tools/scripts/check_supervisor_registration.sh --selftest && ./tools/scripts/check_supervisor_registration.sh' ;;
        check-test-registration)           echo './tools/scripts/check_test_registration.sh --selftest && ./tools/scripts/check_test_registration.sh' ;;
        check-typed-blocker)               echo './build/bin/z23-lint check-typed-blocker' ;;
        check-blocker-escape-registered)   echo './tools/scripts/check_blocker_escape_registered.sh --selftest && ./tools/scripts/check_blocker_escape_registered.sh' ;;
        check-blocker-remedy)              echo 'sh tools/scripts/check_blocker_remedy.sh' ;;
        check-blocker-handoff-declared)    echo './tools/lint/check_blocker_handoff_declared.sh' ;;
        check-supervisor-progress-declared) echo './build/bin/z23-lint check-supervisor-progress-declared' ;;
        check-stopwatch-skip-detector)     echo './build/bin/z23-lint check-stopwatch-skip-detector' ;;
        check-proof-server-pin)            echo './build/bin/z23-lint check-proof-server-pin' ;;
        check-promotion-receipt-chain)     echo './build/bin/z23-lint check-promotion-receipt-chain --selftest && ./build/bin/z23-lint check-promotion-receipt-chain' ;;
        check-ship-remote-transaction)     echo './tools/ship.sh --selftest && ./tools/ship_selftest.sh && ./tools/lint/check_ship_remote_transaction.sh' ;;
        check-z23-release-install)         echo 'make --no-print-directory -s z23-bootstrap install-selftest && "$ZCL_LINT_BIN_DIR/install_selftest" --selftest && bash platform/packaging/release/build_release.sh --selftest && bash tools/scripts/install_z23.sh --selftest && bash tools/scripts/deploy_z23_release.sh --selftest' ;;
        check-published-platforms)         echo './tools/lint/check_published_platforms.sh --selftest && ./tools/lint/check_published_platforms.sh' ;;
        check-identity-parser-single)      echo './tools/lint/check_identity_parser_single.sh --selftest && ./tools/lint/check_identity_parser_single.sh' ;;
        check-source-identity-authority)   echo './build/bin/z23-lint check-source-identity-authority --selftest && ./build/bin/z23-lint check-source-identity-authority' ;;
        check-status-reason-single)        echo './tools/lint/check_status_reason_single.sh --selftest && ./tools/lint/check_status_reason_single.sh' ;;
        check-pipefail-status-pipe)        echo './tools/lint/check_pipefail_status_pipe.sh --selftest && ./tools/lint/check_pipefail_status_pipe.sh' ;;
        check-shell-host-assumptions)      echo './build/bin/z23-lint check-shell-host-assumptions --selftest && ./tools/scripts/port_probe.sh --selftest && ./tools/scripts/commons_fix_admit.sh --selftest && ./tools/scripts/isolated_node_env_selftest.sh && ./tools/scripts/service_args_selftest.sh && bash tools/scripts/two_node_peer_tip_selftest.sh && ./build/bin/z23-lint check-shell-host-assumptions' ;;
        check-discarded-status)            echo './tools/lint/check_discarded_status.sh --selftest && ./tools/lint/check_discarded_status.sh' ;;
        check-no-wallclock-assertion)      echo './build/bin/z23-lint check-no-wallclock-assertion --selftest && ./build/bin/z23-lint check-no-wallclock-assertion' ;;
        check-no-real-clock-test-deadline) echo './build/bin/z23-lint check-no-real-clock-test-deadline --selftest && ./build/bin/z23-lint check-no-real-clock-test-deadline' ;;
        check-framework-shape)             echo 'ZCL_LINT_MODE=RATCHET ./build/bin/z23-lint check-framework-shape' ;;
        check-framework-filename-suffix)   echo './build/bin/z23-lint check-framework-filename-suffix' ;;
        check-no-raw-clock-outside-platform) echo './build/bin/z23-lint check-no-raw-clock-outside-platform' ;;
        check-sysinit-ordering)            echo './build/bin/z23-lint check-sysinit-ordering' ;;
        check-sandbox-wired)               echo './build/bin/z23-lint check-sandbox-wired' ;;
        check-no-shellouts)                echo './build/bin/z23-lint check-no-shellouts' ;;
        check-no-api-keys)                 echo './build/bin/z23-lint check-no-api-keys' ;;
        check-posix-ere-only)              echo './build/bin/z23-lint check-posix-ere-only' ;;
        check-flag-registry)               echo './build/bin/z23-lint check-flag-registry --selftest && ./build/bin/z23-lint check-flag-registry' ;;
        check-standalone-tools-link)       echo './tools/lint/check_standalone_tools_link.sh' ;;
        check-arena-view-stub)             echo './build/bin/z23-lint check-arena-view-stub --selftest && ./build/bin/z23-lint check-arena-view-stub' ;;
        check-hotfork-stories)             echo './build/bin/z23-lint check-hotfork-stories --selftest && ./build/bin/z23-lint check-hotfork-stories' ;;
        check-app-bundle-reproducible)     echo './build/bin/z23-lint check-app-bundle-reproducible --selftest && ./build/bin/z23-lint check-app-bundle-reproducible' ;;
        check-live-datadir-isolation)      echo './build/bin/z23-lint check-live-datadir-isolation --selftest && ./build/bin/z23-lint check-live-datadir-isolation' ;;
        check-no-operator-paths)           echo './tools/lint/check_no_operator_paths.sh --selftest && ./tools/lint/check_no_operator_paths.sh' ;;
        check-no-unattended-publish)       echo './build/bin/z23-lint check-no-unattended-publish --selftest && ./build/bin/z23-lint check-no-unattended-publish' ;;
        check-tor-dial-prewarm)            echo './build/bin/z23-lint check-tor-dial-prewarm' ;;
        check-fleet-source-status)         echo './tools/scripts/check_fleet_source_status.sh' ;;
        check-installed-acceptance-tools)  echo './build/bin/z23-lint check-installed-acceptance-tools' ;;
        check-no-writer-below-sealed-frontier) echo './build/bin/z23-lint check-no-writer-below-sealed-frontier' ;;
        check-peer-floor-single-source)    echo './build/bin/z23-lint check-peer-floor-single-source' ;;
        check-proc-self-shim)              echo './build/bin/z23-lint check-proc-self-shim' ;;
        check-no-raw-sqlite-in-controllers) echo 'ZCL_LINT_MODE=RATCHET ./build/bin/z23-lint check-no-raw-sqlite-in-controllers' ;;
        check-model-column-drift)          echo './build/bin/z23-lint check-model-column-drift --selftest && ZCL_LINT_MODE=RATCHET ./build/bin/z23-lint check-model-column-drift' ;;
        check-supervisor-domain)           echo './build/bin/z23-lint check-supervisor-domain --selftest && ./build/bin/z23-lint check-supervisor-domain' ;;
        check-thread-supervision)          echo './build/bin/z23-lint check-thread-supervision --selftest && ./build/bin/z23-lint check-thread-supervision' ;;
        check-file-purpose)                echo 'ZCL_LINT_MODE=RATCHET ./build/bin/z23-lint check-file-purpose' ;;
        check-group-purpose)               echo 'ZCL_LINT_MODE=FAIL ./build/bin/z23-lint check-group-purpose' ;;
        check-architecture-tree)           echo './build/bin/z23-lint check-architecture-tree' ;;
        check-retrieval-historical-evidence) echo './tools/dev/retrieval-gold-corpus-check.sh --check && ./tools/dev/retrieval-gold-identifier-graph-receipt-check.sh --check && ./tools/dev/retrieval-profile-sweep.sh --check' ;;
        check-no-orphan-placement)         echo 'ZCL_LINT_MODE=RATCHET ./build/bin/z23-lint check-no-orphan-placement' ;;
        check-file-size-ceiling)           echo '"$ZCL_LINT_BIN_DIR/file_size_policy"' ;;
        check-operator-needed-sink)        echo './tools/scripts/check_operator_needed_sink.sh' ;;
        check-systemd-memory-budget)       echo './tools/scripts/check_systemd_memory_budget.sh --selftest && ./tools/scripts/check_systemd_memory_budget.sh' ;;
        check-condition-cooldown)          echo './tools/scripts/check_condition_cooldown.sh' ;;
        check-doc-accuracy)                echo './tools/scripts/check_doc_accuracy.sh' ;;
        check-doc-counts)                  echo './tools/scripts/check_doc_counts.sh' ;;
        check-orient-facts)                echo './build/bin/z23-lint check-orient-facts --selftest && ./build/bin/z23-lint check-orient-facts' ;;
        check-no-stale-pinned-facts)       echo './build/bin/z23-lint check-no-stale-pinned-facts --selftest && ./build/bin/z23-lint check-no-stale-pinned-facts .' ;;
        check-no-uncited-victory)          echo './tools/scripts/check_no_uncited_victory.sh' ;;
        check-doc-claims)                  echo './tools/lint/check_doc_claims.sh' ;;
        check-error-doc-refs)              echo './build/bin/z23-lint check-error-doc-refs' ;;
        check-api-reference-generated)     echo './build/bin/z23-lint check-api-reference-generated --selftest && ./build/bin/z23-lint check-api-reference-generated' ;;
        check-capability-inventory-generated) echo './tools/lint/check_capability_inventory_generated.sh --selftest' ;;
        check-generated-artifact-contradictions) echo './build/bin/z23-lint check-generated-artifact-contradictions --selftest && ./build/bin/z23-lint check-generated-artifact-contradictions' ;;
        check-describe-budget)             echo './build/bin/z23-lint check-describe-budget --selftest && ./build/bin/z23-lint check-describe-budget' ;;
        check-catalog-rooms)               echo './build/bin/z23-lint check-catalog-rooms --selftest && ./build/bin/z23-lint check-catalog-rooms' ;;
        check-kpi-floor)                   echo './build/bin/z23-lint check-kpi-floor --selftest && ./build/bin/z23-lint check-kpi-floor' ;;
        check-markdown-links)              echo './build/bin/z23-lint check-markdown-links .' ;;
        check-doc-inline-paths)            echo './build/bin/z23-lint check-doc-inline-paths' ;;
        check-hex-codec-single)            echo './build/bin/z23-lint check-hex-codec-single --selftest && ./build/bin/z23-lint check-hex-codec-single' ;;
        check-one-result-type)             echo './tools/scripts/check_one_result_type.sh --selftest && ./tools/scripts/check_one_result_type.sh' ;;
        check-no-secret-printf)            echo './tools/scripts/check_no_secret_printf.sh --selftest && ./tools/scripts/check_no_secret_printf.sh' ;;
        check-service-result-convergence)  echo './tools/scripts/check_service_result_convergence.sh' ;;
        check-shape-includes-header)       echo './tools/scripts/check_shape_includes_header.sh' ;;
        check-projections-pure)            echo './tools/scripts/check_projections_pure.sh' ;;
        check-one-write-path)              echo './tools/scripts/check_one_write_path.sh' ;;
        check-frontier-single-writer)      echo './tools/scripts/check_frontier_single_writer.sh --selftest && ./tools/scripts/check_frontier_single_writer.sh' ;;
        check-dumper-never-blocks)         echo './tools/scripts/check_dumper_never_blocks.sh' ;;
        check-no-block-index-flat)         echo './build/bin/z23-lint check-no-block-index-flat' ;;
        check-no-utxo-projection)          echo './build/bin/z23-lint check-no-utxo-projection' ;;
        check-no-utxos-mirror-read)        echo './build/bin/z23-lint check-no-utxos-mirror-read --selftest && ./build/bin/z23-lint check-no-utxos-mirror-read' ;;
        check-no-authoritative-ram-state)  echo './tools/scripts/check_no_authoritative_ram_state.sh' ;;
        check-no-dev-history-in-contracts) echo './tools/scripts/check_no_dev_history_in_contracts.sh --selftest && ./tools/scripts/check_no_dev_history_in_contracts.sh' ;;
        check-no-live-lab-history)        echo './tools/scripts/check_no_live_lab_history.sh --selftest && ./tools/scripts/check_no_live_lab_history.sh' ;;
        check-stage-advances-or-blocks)    echo './tools/scripts/check_stage_advances_or_blocks.sh' ;;
        check-no-silent-ready)             echo './build/bin/z23-lint check-no-silent-ready' ;;
        check-honest-witness)              echo 'ZCL_LINT_MODE=FAIL ./build/bin/z23-lint check-honest-witness' ;;
        check-consensus-parity)            echo './tools/scripts/check_consensus_parity.sh --selftest && ./tools/scripts/check_consensus_parity.sh' ;;
        check-no-new-repair-rung)          echo './tools/scripts/check_no_new_repair_rung.sh --selftest && ./tools/scripts/check_no_new_repair_rung.sh' ;;
        check-no-new-coordination-shell)   echo './build/bin/z23-lint check-no-new-coordination-shell --selftest && ./build/bin/z23-lint check-no-new-coordination-shell' ;;
        check-no-new-bash)                 echo './build/bin/z23-lint check-no-new-bash --selftest && ./build/bin/z23-lint check-no-new-bash' ;;
        check-no-bare-tmp-fixture)         echo './build/bin/z23-lint check-no-bare-tmp-fixture --selftest && ./build/bin/z23-lint check-no-bare-tmp-fixture' ;;
        check-network-tool-hardening)         echo './build/bin/z23-lint check-network-tool-hardening --selftest && ./build/bin/z23-lint check-network-tool-hardening' ;;
        check-sqlite-cursor-lifetime)      echo './build/bin/z23-lint check-sqlite-cursor-lifetime --selftest && ./build/bin/z23-lint check-sqlite-cursor-lifetime' ;;
        check-object-reproducible)            echo 'make --no-print-directory check-object-reproducible' ;; # the Makefile recipe runs the pure selftest once
        check-riscv64-universal)              echo 'make check-riscv64-universal' ;;
        check-no-new-borrowed-seed)        echo './build/bin/z23-lint check-no-new-borrowed-seed .' ;;
        check-no-new-coin-backfill-caller) echo './build/bin/z23-lint check-no-new-coin-backfill-caller .' ;;
        check-route-command-parity)        echo './build/bin/z23-lint check-route-command-parity .' ;;
        check-doc-no-false-deleted)        echo './tools/lint/gate_doc_no_false_deleted.sh .' ;;
        check-zclassicd-reach-allowlist)   echo './build/bin/z23-lint check-zclassicd-reach-allowlist .' ;;
        check-stage-log-reorg-unsafe)      echo './tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh' ;;
        check-no-csr-lock-on-finalize-drive) echo './build/bin/z23-lint check-no-csr-lock-on-finalize-drive --selftest && ./build/bin/z23-lint check-no-csr-lock-on-finalize-drive .' ;;
        check-mint-skip-crypto-offline-only) echo './build/bin/z23-lint check-mint-skip-crypto-offline-only .' ;;
        check-wire-harness-security-gate)  echo './build/bin/z23-lint check-wire-harness-security-gate' ;;
        check-vcs-no-git)                  echo './build/bin/z23-lint check-vcs-no-git' ;;
        check-vcs-no-sha1)                 echo './build/bin/z23-lint check-vcs-no-sha1 && tools/dev/source-identity-selftest.sh' ;;
        check-vendor-provenance)           echo 'tools/scripts/test_vendor_provenance.sh' ;;
        check-tor-provenance)              echo './build/bin/z23-lint check-tor-provenance' ;;
        check-command-contract)            echo './build/bin/z23-lint check-command-contract' ;;
        check-command-availability-truthful) echo './build/bin/z23-lint check-command-availability-truthful' ;;
        check-command-input-keys)          echo './build/bin/z23-lint check-command-input-keys --selftest && ./build/bin/z23-lint check-command-input-keys' ;;
        check-read-leaf-no-boot-ceremony)  echo './tools/lint/check_read_leaf_no_boot_ceremony.sh' ;;
        check-telemetry-ontology)          echo './tools/lint/check_telemetry_ontology.sh' ;;
        check-privileged-transition-receipt) echo './build/bin/z23-lint check-privileged-transition-receipt' ;;
        check-c23-only)                     echo './build/bin/z23-lint check-c23-only --selftest && ./build/bin/z23-lint check-c23-only' ;;
        check-no-python)                    echo './build/bin/z23-lint check-no-python --selftest && ./build/bin/z23-lint check-no-python' ;;
        check-sync-state-no-ordinal)     echo './tools/scripts/check_sync_state_no_ordinal.sh' ;;
        check-no-gnu-va-args)              echo './build/bin/z23-lint check-no-gnu-va-args' ;;
        check-no-snapshot-struct-memcmp)   echo './build/bin/z23-lint check-no-snapshot-struct-memcmp --self-test && ./build/bin/z23-lint check-no-snapshot-struct-memcmp' ;;
        check-no-warning-suppression)      echo './build/bin/z23-lint check-no-warning-suppression .' ;;
        check-clang-portability)           echo './tools/lint/check_clang_portability.sh --self-test && ./tools/lint/check_clang_portability.sh' ;;
        check-windows-platform-seam)       echo './tools/lint/check_windows_platform_seam.sh --self-test && ./tools/lint/check_windows_platform_seam.sh' ;;
        check-windows-acceptance)          echo './tools/lint/check_windows_acceptance.sh --self-test && ./tools/lint/check_windows_acceptance.sh' ;;
        check-windows-acceptance-guard)    echo './build/bin/z23-lint check-windows-acceptance-guard --selftest && ./build/bin/z23-lint check-windows-acceptance-guard' ;;
        check-windows-cross-syntax)        echo './tools/lint/check_windows_cross_syntax.sh' ;;
        check-platform-header-guards)      echo './tools/lint/check_platform_header_guards.sh --self-test && ./tools/lint/check_platform_header_guards.sh' ;;
        check-macos-acceptance)            echo './build/bin/z23-lint check-macos-acceptance --selftest && ./build/bin/z23-lint check-macos-acceptance' ;;
        check-result-discard)              echo 'ZCL_LINT_MODE=FAIL ./build/bin/z23-lint check-result-discard' ;;
        *) return 1 ;;
    esac
}

now_ms() {
    local ns
    ns="$(date +%s%N 2>/dev/null || true)"
    [[ "$ns" =~ ^[0-9]+$ ]] && printf '%s' $((ns / 1000000)) || printf '%s000' "$(date +%s)"
}

# Execute one gate's command with the same semantics as its Make recipe.
run_gate_body() {
    local gate="$1" cmd
    cmd="$(gate_command "$gate")" || return 127
    if [ "$cmd" = '__core_seal__' ]; then
        # Mirror the check-core-seal recipe: an unseal token lifts the HARD
        # seal failure for exactly that commit (owner unseal ritual).
        # CORE_SEAL_PATHS mirror — MUST match the Makefile variable of the
        # same name (core/ + the sealed block-connection ordering layer).
        local seal_paths="core/
core/modules/validation/src/connect_block.c
core/modules/validation/src/chainstate.c
core/modules/validation/include/validation/connect_block.h
core/modules/validation/include/validation/chainstate.h"
        if [ -f .core-unseal-token ]; then
            echo "check-core-seal: unseal token present — seal check lifted for this commit"
            echo "  (owner unseal ritual active; re-run 'make core-seal' to refreeze before commit.)"
            git ls-files -z $seal_paths | "$ZCL_LINT_BIN_DIR/core_seal" check core/MANIFEST.sha3 || true
        else
            git ls-files -z $seal_paths | "$ZCL_LINT_BIN_DIR/core_seal" check core/MANIFEST.sha3
        fi
        return
    fi
    eval "$cmd"
}

# Worker: run one gate, capture log + ms + rc artifacts, print a one-line
# receipt. Line stays well under PIPE_BUF so concurrent workers never tear.
worker() {
    local gate="$1" start end ms rc log

    log="$GATES_DIR/$gate.log"
    start="$(now_ms)"
    run_gate_body "$gate" > "$log" 2>&1
    rc=$?
    end="$(now_ms)"
    ms=$((end - start))
    printf '%s\n' "$ms" > "$GATES_DIR/$gate.ms"
    printf '%s\n' "$rc" > "$GATES_DIR/$gate.rc"
    if [ "$rc" -eq 0 ]; then
        printf 'PASS %-42s %7s ms\n' "$gate" "$ms"
    else
        printf 'FAIL %-42s %7s ms (rc=%s)\n' "$gate" "$ms" "$rc"
    fi
    return 0
}

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
    local -a gates=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --jobs)    JOBS="${2:?--jobs needs N}"; shift 2 ;;
            --jobs=*)  JOBS="${1#--jobs=}"; shift ;;
            --bin-dir) BIN_DIR="${2:?--bin-dir needs a dir}"; shift 2 ;;
            --bin-dir=*) BIN_DIR="${1#--bin-dir=}"; shift ;;
            --worker)  worker "$2"; exit $? ;;
            --list)
                # Gate names = the case labels in gate_command() (read from
                # this file so reformatting cannot desync the probe).
                # Anchored at the start of an indented line and required to be
                # followed by the entry's `echo`, because the loose form
                # (\bcheck-[a-z0-9-]+\)) also matched PROSE — the header
                # sentence "...readers like check-core-seal)." was reported as
                # a gate. It was invisible only because that name happens to be
                # a real gate too; the next comment to end in a gate name and a
                # paren would have invented one.
                grep -oE '^[[:space:]]+check-[a-z0-9-]+\)[[:space:]]+echo[[:space:]]' "$0" \
                    | grep -oE 'check-[a-z0-9-]+' | sort -u
                exit 0 ;;
            --list-raw)
                # --list WITHOUT the sort -u dedup, in source order. The one
                # consumer is check-lint-gate-wiring's duplicate-label check:
                # bash case is first-match-wins, so a repeated label is a
                # dead row shadowing the live one (the 2026-09-29 drift that
                # silently dropped --selftest from check-no-new-repair-rung
                # in driver runs). --list itself must keep deduping — it
                # feeds set-parity checks.
                grep -oE '^[[:space:]]+check-[a-z0-9-]+\)[[:space:]]+echo[[:space:]]' "$0" \
                    | grep -oE 'check-[a-z0-9-]+'
                exit 0 ;;
            --print-command)
                # The one supported reader of gate_command() from outside this
                # file (check_lint_gate_wiring.sh audits the paths the table
                # names). Exits 1 on an unknown gate — same polarity as
                # gate_command itself, so a caller cannot mistake "no entry"
                # for "empty command".
                gate_command "${2:?--print-command needs a gate}"
                exit $? ;;
            --help|-h) usage; exit 0 ;;
            check-*)   gates+=("$1"); shift ;;
            *) echo "run_lint.sh: unknown argument '$1'" >&2; exit 2 ;;
        esac
    done
    [[ "$JOBS" =~ ^[0-9]+$ ]] && [ "$JOBS" -ge 1 ] || {
        echo "run_lint.sh: --jobs must be a positive integer (got '$JOBS')" >&2; exit 2; }
    [ "$JOBS" -le 32 ] || JOBS=32
    [ "${#gates[@]}" -gt 0 ] || { echo "run_lint.sh: no gates given" >&2; exit 2; }

    # This driver already spends the host budget across independent gates.
    # Compiler sweeps also have standalone parallelism, and allowing each
    # outer worker to auto-detect the full CPU count multiplies into dozens
    # of cc1/clang children (and OOM/backend crashes) on large Windows hosts.
    # Explicit operator overrides remain available for standalone profiling;
    # the umbrella's safe default is one nested worker per running gate —
    # EXCEPT the two compiler-sweep gates (check-clang-portability, reading
    # ZCL_CC_JOBS; check-windows-cross-syntax, reading ZCL_WIN_CROSS_JOBS
    # first and falling back to ZCL_CC_JOBS) — the ONLY readers of either
    # var anywhere in the tree (nothing else greps for them), so raising
    # their defaults here is already scoped to them without touching how
    # any other gate is dispatched.
    #
    # Both sweeps are dispatched first (LONG_POLE_FIRST), so they overlap
    # the short gates for the first few seconds and then run nearly alone
    # together. An even 50/50 split of the host between the two of them —
    # what this used to compute — leaves real wall on the table: measured
    # on the dev reference host, cache off, three runs each,
    # check-clang-portability (2395 TUs) finishes in 21-23 s at 12-16
    # workers while check-windows-cross-syntax (2376 TUs, roughly 2x the
    # per-TU cost) needs 40-55 s at the very same width. For most of its
    # own run the sibling has already exited and freed its half of the
    # host, while this gate stayed capped at its half. Skewing the SAME
    # combined budget — still what bounds concurrent cc1/clang children,
    # since both sweeps start together — 5/8 to windows-cross-syntax and
    # 3/8 to clang-portability keeps that peak no higher than the old
    # 50/50 split (same sweep_host on each side of the sum) while giving
    # the true long pole more of it for its whole run, not only after the
    # sibling finishes.
    local sweep_host win_cross_jobs clang_port_jobs
    sweep_host="${ZCL_HOST_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)}"
    [[ "$sweep_host" =~ ^[0-9]+$ ]] || sweep_host=8
    win_cross_jobs=$((sweep_host * 5 / 8))
    [ "$win_cross_jobs" -ge 6 ] || win_cross_jobs=6
    [ "$win_cross_jobs" -le 20 ] || win_cross_jobs=20
    clang_port_jobs=$((sweep_host * 3 / 8))
    [ "$clang_port_jobs" -ge 4 ] || clang_port_jobs=4
    [ "$clang_port_jobs" -le 12 ] || clang_port_jobs=12
    case " ${gates[*]} " in
        *' check-clang-portability '*|*' check-windows-cross-syntax '*)
            export ZCL_CC_JOBS="${ZCL_CC_JOBS:-$clang_port_jobs}"
            export ZCL_WIN_CROSS_JOBS="${ZCL_WIN_CROSS_JOBS:-$win_cross_jobs}" ;;
        *) export ZCL_CC_JOBS="${ZCL_CC_JOBS:-1}" ;;
    esac
    export ZCL_TOOLS_LINK_JOBS="${ZCL_TOOLS_LINK_JOBS:-1}"
    export ZCL_FUZZ_REPLAY_JOBS="${ZCL_FUZZ_REPLAY_JOBS:-1}"

    # Fail loud on table drift: every requested gate needs an entry, and any
    # table gate absent from the request is named (nonfatal) so the Makefile
    # umbrella and this table cannot silently diverge.
    local g missing=0
    for g in "${gates[@]}"; do
        if ! gate_command "$g" >/dev/null; then
            echo "run_lint.sh: FATAL — gate '$g' has no invocation-table entry." >&2
            echo "  Add its exact recipe command to gate_command() in $0" >&2
            missing=1
        fi
    done
    [ "$missing" -eq 0 ] || exit 2
    local requested=" ${gates[*]} " extra
    while read -r extra; do
        [ -n "$extra" ] || continue
        case "$requested" in
            *" $extra "*) ;;
            *) echo "run_lint.sh: note — table gate '$extra' not in this run's gate list" >&2 ;;
        esac
    done < <("$0" --list 2>/dev/null | grep '^check-' || true)

    # This run's private artifact dir, exported so every worker re-exec lands
    # in the same one. Old run dirs are pruned by age, never by "everything
    # that is here now" — that wipe is exactly what collided with live runs.
    rm -rf "$GATES_DIR"
    mkdir -p "$GATES_DIR"
    export ZCL_LINT_GATES_DIR_X="$GATES_DIR"
    # The gates this run will record a verdict for. A gate reading verdicts
    # (check-doc-claims) waits only for these; any other name never gets one.
    printf '%s\n' "${gates[@]}" > "$GATES_DIR/requested.list"
    find "$STATE_DIR/gates" -maxdepth 1 -type d -name 'run.*' -mmin +120 \
         -exec rm -rf {} + 2>/dev/null || true

    # Same scan-exclusion contract as the Makefile `check-%` pattern rule.
    export ZCL_LINT_PRODUCTION_SCAN=1
    export ZCL_LINT_BIN_DIR="$BIN_DIR"
    [[ "$BUDGET_SEC" =~ ^[0-9]+$ ]] || BUDGET_SEC=75

    local -a serial_gates=() par_gates=() final_gates=()
    for g in "${gates[@]}"; do
        case "$SERIAL_PROLOGUE" in
            *" $g "*) serial_gates+=("$g") ;;
            *)
                case "$SERIAL_EPILOGUE" in
                    *" $g "*) final_gates+=("$g") ;;
                    *)        par_gates+=("$g") ;;
                esac ;;
        esac
    done

    # Long poles first (see LONG_POLE_FIRST), then the rest in list order.
    local -a ordered_gates=()
    local -A is_pole=()
    local pole
    for pole in $LONG_POLE_FIRST; do
        # A misspelled or retired name would silently stop ordering anything.
        if ! gate_command "$pole" >/dev/null; then
            echo "run_lint.sh: FATAL — LONG_POLE_FIRST names '$pole'," \
                 "which has no gate_command() entry" >&2
            exit 2
        fi
        is_pole["$pole"]=1
        for g in "${par_gates[@]}"; do
            [ "$g" = "$pole" ] && ordered_gates+=("$g")
        done
    done
    for g in "${par_gates[@]}"; do
        [ -n "${is_pole[$g]:-}" ] || ordered_gates+=("$g")
    done
    # Reordering, never selection: the pool gets exactly the gates it got
    # before. Refuse to run a different set than was requested.
    if [ "${#ordered_gates[@]}" -ne "${#par_gates[@]}" ]; then
        echo "run_lint.sh: FATAL — long-pole ordering produced" \
             "${#ordered_gates[@]} gates from ${#par_gates[@]}" >&2
        exit 2
    fi

    # The capability inventory is untracked build output. Three gates read it
    # (check-capability-inventory-generated writes it, check-kpi-floor and
    # check-generated-artifact-contradictions consume it), and the pool runs
    # them concurrently, so it is generated ONCE, serially, before the pool.
    # Every path that dispatches through this driver (lint, lint-land,
    # lint-fast, the proof's lint dimension) therefore sees a fresh file.
    case "$requested" in
        *" check-capability-inventory-generated "*|*" check-kpi-floor "*|\
        *" check-generated-artifact-contradictions "*)
            echo "run_lint.sh: generating build/gen/CAPABILITY_INVENTORY.jsonl before the gate pool" >&2
            if ! make -s --no-print-directory docs-capability-inventory >&2; then
                echo "run_lint.sh: FATAL — make docs-capability-inventory failed;" \
                     "the gates that read it cannot be graded" >&2
                exit 1
            fi ;;
    esac

    local run_start run_end wall_ms
    run_start="$(now_ms)"
    for g in "${serial_gates[@]}"; do
        worker "$g"
    done
    if [ "${#ordered_gates[@]}" -gt 0 ]; then
        printf '%s\n' "${ordered_gates[@]}" | \
            xargs -r -P "$JOBS" -n1 "$0" --worker
    fi
    for g in "${final_gates[@]}"; do
        worker "$g"
    done
    run_end="$(now_ms)"
    wall_ms=$((run_end - run_start))

    # Aggregate. A gate that produced no .rc file crashed the worker itself.
    local -a failed=()
    local total=0 rc ms
    for g in "${gates[@]}"; do
        total=$((total + 1))
        if [ ! -f "$GATES_DIR/$g.rc" ]; then
            failed+=("$g (worker crash — no rc artifact)")
            continue
        fi
        rc="$(cat "$GATES_DIR/$g.rc")"
        [ "$rc" = "0" ] || failed+=("$g")
    done

    # Slowest gates first (per-gate ms artifacts make regressions visible).
    local ranked
    ranked="$(for f in "$GATES_DIR"/*.ms; do
        [ -f "$f" ] || continue
        printf '%s %s\n' "$(cat "$f")" "$(basename "$f" .ms)"
    done | sort -nr)"
    echo "── lint timing: ${total} gates, wall ${wall_ms} ms, jobs ${JOBS} ──"
    local show=10 line
    [ "${ZCL_LINT_VERBOSE:-0}" = "1" ] && show="$total"
    printf '%s\n' "$ranked" | head -n "$show" | while read -r ms g; do
        [ -n "$g" ] && printf '  %7s ms  %s\n' "$ms" "$g"
    done
    [ "$show" -ge "$total" ] || echo "  … (ZCL_LINT_VERBOSE=1 for the full table)"

    # Machine-readable artifact (dev-loop-bench pattern).
    {
        printf '{\n'
        printf '  "schema":"zcl.lint_timing.v1",\n'
        printf '  "generated_at_utc":"%s",\n' "$(date -u +%FT%TZ)"
        printf '  "wall_ms":%s,\n' "$wall_ms"
        printf '  "jobs":%s,\n' "$JOBS"
        printf '  "budget_sec":%s,\n' "$BUDGET_SEC"
        printf '  "gate_count":%s,\n' "$total"
        printf '  "failed_count":%s,\n' "${#failed[@]}"
        printf '  "gates":[\n'
        local first=1
        printf '%s\n' "$ranked" | while read -r ms g; do
            [ -n "$g" ] || continue
            [ "$first" -eq 0 ] && printf ',\n'
            first=0
            printf '    {"name":"%s","ms":%s,"rc":%s}' \
                "$g" "$ms" "$(cat "$GATES_DIR/$g.rc" 2>/dev/null || echo 2)"
        done
        printf '\n  ]\n}\n'
    } > "$STATE_DIR/last-run.json.$$.tmp" && mv -f "$STATE_DIR/last-run.json.$$.tmp" "$STATE_DIR/last-run.json"

    if [ "$wall_ms" -gt $((BUDGET_SEC * 1000)) ]; then
        echo "run_lint.sh: NOTE — wall ${wall_ms} ms exceeds the ${BUDGET_SEC}s soft budget" \
            "(ZCL_LINT_BUDGET_SEC; see the budget comment above the lint target)" >&2
    fi

    if [ "${#failed[@]}" -gt 0 ]; then
        echo "" >&2
        echo "══ LINT: ${#failed[@]} of ${total} gates FAILED ══" >&2
        for g in "${failed[@]}"; do
            echo "  ✗ $g" >&2
        done
        for g in "${failed[@]}"; do
            local name="${g%% *}" body frc cmd
            body="$(wc -c < "$GATES_DIR/$name.log" 2>/dev/null)"
            [[ "$body" =~ ^[0-9]+$ ]] || body=0
            echo "" >&2
            echo "──── FAIL log: $name ────────────────────────────" >&2
            if [ "$body" -gt 0 ]; then
                cat "$GATES_DIR/$name.log" >&2
                continue
            fi
            # A red with no message is unactionable, and it reads like a
            # flake — which is how a real failure gets waved through. A gate
            # that exits non-zero having printed nothing gets its silence
            # reported as the finding it is, with everything needed to
            # reproduce it by hand.
            frc="$(cat "$GATES_DIR/$name.rc" 2>/dev/null || echo '?')"
            cmd="$(gate_command "$name" 2>/dev/null || echo '(no invocation-table entry)')"
            echo "  (this gate produced NO output at all)" >&2
            echo "" >&2
            echo "  The gate exited ${frc} without printing a diagnosis, so the" >&2
            echo "  failure is real but self-reported nothing. That is a defect in" >&2
            echo "  the gate, on top of whatever it was failing on: a gate must say" >&2
            echo "  why it refused. Most often it is a script under 'set -e' whose" >&2
            echo "  checks are bare boolean assertions, dying on a missing build" >&2
            echo "  artifact, tool, or fixture before it prints anything." >&2
            echo "" >&2
            echo "  Reproduce it directly (this driver captured nothing more):" >&2
            echo "      $cmd" >&2
            echo "  and to see the exact assertion that failed:" >&2
            echo "      bash -x -c '$cmd'" >&2
        done
        exit 1
    fi
    exit 0
}

main "$@"
