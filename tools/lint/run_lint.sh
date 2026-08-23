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
# every selftest-style gate works in a mktemp dir. The ONE exception runs in
# a SERIAL prologue before the parallel pool:
#   check-git-hooks-installed — may normalize core.hooksPath via `git config`
#     (a write; keep it away from concurrent git readers like check-core-seal).
# check-no-stray-untracked-source was also verified read-only; it no longer
# needs to run first because the driver never circuit-breaks on the first
# failure — all gates run and every failure is reported, strays included.
#
# Result cache (tools/lint/lint_cache.sh): DEFAULT OFF. A gate whose whole
# scannable input is byte-identical to the last time it PASSED can be skipped,
# which makes a re-run on an unchanged tree near-instant. `make lint`, `make
# ci` and the pre-push gate stay COLD unless --cache is passed, so a cached
# SKIP never gates a push. --cold-audit runs everything fresh AND asserts every
# would-be cache hit matches its fresh verdict. See lint_cache.sh for why some
# gates are never cached (they build things, run compilers, read built
# binaries, git history, /proc, or untracked state) and always run.
#
# Usage:
#   tools/lint/run_lint.sh [--jobs N] [--bin-dir DIR] [--list] GATE...
#   tools/lint/run_lint.sh --cache GATE...       (opt in to the result cache)
#   tools/lint/run_lint.sh --cold-audit GATE...  (run all fresh, verify hits)
#   tools/lint/run_lint.sh --worker GATE         (internal: xargs child)
#
# Env:
#   ZCL_LINT_JOBS        default worker count when --jobs absent (default 8)
#   ZCL_LINT_BUDGET_SEC  soft wall-time budget, warn-only past it (default 75)
#   ZCL_LINT_TIMING_DIR  artifact dir (default .cache/lint-timing)
#   ZCL_LINT_VERBOSE=1   print the full per-gate timing table, not just top 10
#   ZCL_LINT_CACHE=1     opt in to the result cache (same as --cache)
#   ZCL_LINT_CACHE_DIR   cache record dir (default .cache/lint-cache/<schema>)
#   ZCL_LINT_CACHE_DUMP=<gate>
#                        print what that gate keys on (cacheability, tree key,
#                        gate key, hit/miss) and exit — the "why did/didn't
#                        this hit" diagnostic
#
# Exit: 0 iff every gate passed; 1 if any gate failed (all gates still run,
# so one `make lint` reports every violation) or a cold-audit divergence was
# found; 2 on driver misuse/unknown gate.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/lint_cache.sh
source "$SCRIPT_DIR/lint_cache.sh"

STATE_DIR="${ZCL_LINT_TIMING_DIR:-$ROOT/.cache/lint-timing}"
GATES_DIR="$STATE_DIR/gates"
JOBS="${ZCL_LINT_JOBS:-8}"
BIN_DIR="build/bin"
BUDGET_SEC="${ZCL_LINT_BUDGET_SEC:-75}"

# Gates that must run serially (and first) — see the header contract.
SERIAL_PROLOGUE=" check-git-hooks-installed "

# ── Gate invocation table ────────────────────────────────────────────────
# One entry per check-* gate in the Makefile lint umbrella (LINT_GATES). The
# command must reproduce the gate's Make recipe EXACTLY (script path, args,
# and any ZCL_LINT_MODE prefix). A gate added to LINT_GATES without a table
# entry is a LOUD driver error (exit 2), never a silent skip.
gate_command() {
    case "$1" in
        check-fuzz-artifact-ledger)        echo './tools/lint/check_fuzz_artifact_replay.sh --ledger-only' ;;
        check-no-retired-agent-protocol)   echo './tools/lint/check_no_retired_agent_protocol.sh' ;;
        check-build-epoch-integrity)       echo 'tools/dev/build-epoch-integrity-cached.sh' ;;
        check-checkout-lock)               echo 'tools/dev/checkout-lock-selftest.sh' ;;
        check-no-stray-untracked-source)   echo './tools/lint/check_no_stray_untracked_source.sh' ;;
        check-no-stray-root-files)         echo './tools/lint/check_no_stray_root_files.sh' ;;
        check-scanner-immunity)            echo './tools/lint/selftest_scanner_immunity.sh' ;;
        check-zcc-cache)                   echo './tools/lint/check_zcc_cache.sh' ;;
        check-equihash-params)             echo './tools/lint/check_equihash_params.sh --selftest && ./tools/lint/check_equihash_params.sh' ;;
        check-git-hooks-installed)         echo './tools/scripts/check_git_hooks_installed.sh' ;;
        check-malloc)                      echo './tools/lint/check_malloc.sh' ;;
        check-hotswap-dev-only)            echo './tools/lint/check_hotswap_dev_only.sh' ;;
        check-hotswap-eligible-scope)      echo 'tools/lint/check_hotswap_eligible_scope.sh' ;;
        check-hotswap-static-state)        echo 'tools/lint/check_hotswap_static_state.sh' ;;
        check-hotswap-service-islands)     echo 'tools/lint/check_hotswap_service_islands.sh' ;;
        check-hotswap-swappable-shape)     echo 'tools/lint/check_hotswap_swappable_shape.sh' ;;
        check-release-no-dev-symbols)      echo 'tools/lint/check_release_no_dev_symbols.sh' ;;
        check-stable-publish-contained)    echo 'bash tools/scripts/check_stable_publish_containment.sh --self-test && bash tools/scripts/check_stable_publish_containment.sh' ;;
        check-raw-sqlite)                  echo 'tools/scripts/check_raw_sqlite.sh' ;;
        check-raw-malloc)                  echo 'tools/scripts/check_raw_malloc.sh' ;;
        check-json-value-init)             echo 'bash tools/scripts/check_json_value_init.sh --self-test && bash tools/scripts/check_json_value_init.sh' ;;
        check-blob-read-bounds)            echo 'bash tools/lint/check_blob_read_bounds.sh' ;;
        check-byte-order-codec-single)     echo './tools/lint/check_byte_order_codec_single.sh --selftest && ./tools/lint/check_byte_order_codec_single.sh' ;;
        check-zcode-package-registry)      echo './tools/lint/check_zcode_package_registry.sh' ;;
        check-coins-lookup-nullcheck)      echo 'tools/scripts/check_coins_lookup_nullcheck.sh' ;;
        check-observability-pairing)       echo '"$ZCL_LINT_BIN_DIR/check_observability_pairing"' ;;
        check-silent-errors-services)      echo './tools/lint/check_silent_error_returns.sh app/services/src services service "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-controllers)   echo './tools/lint/check_silent_error_returns.sh app/controllers/src controllers controller "use LOG_ERR/LOG_RETURN, prev-line fprintf, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-jobs)          echo './tools/lint/check_silent_error_returns.sh app/jobs/src jobs job "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-conditions)    echo './tools/lint/check_silent_error_returns.sh app/conditions/src conditions condition "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"' ;;
        check-silent-errors-bool)          echo 'ZCL_LINT_MODE=FAIL ./tools/lint/check_silent_bool_errors.sh' ;;
        check-log-macro-return-type)       echo './tools/lint/check_log_macro_return_type.sh' ;;
        check-no-runtime-abort)            echo './tools/lint/check_no_runtime_abort.sh' ;;
        check-wallet-raw-prepare-log)      echo 'ZCL_LINT_MODE=FAIL ./tools/lint/check_wallet_raw_prepare_log.sh' ;;
        check-before-save-hooks)           echo './tools/lint/check_before_save_hooks.sh' ;;
        check-pthread-create)              echo './tools/lint/check_pthread_create.sh' ;;
        check-model-validation)            echo './tools/scripts/check_model_validation.sh' ;;
        check-model-ar-lifecycle)          echo './tools/scripts/check_model_ar_lifecycle.sh' ;;
        check-long-functions)              echo './tools/scripts/check_long_functions.sh' ;;
        check-rpc-registrar)               echo './tools/scripts/check_rpc_registrar.sh' ;;
        check-lag-slo-observable)          echo './tools/scripts/check_lag_slo_observable.sh' ;;
        check-lib-layering)                echo './tools/scripts/check_lib_layering.sh' ;;
        check-lib-module-order)            echo './tools/scripts/check_lib_module_order.sh' ;;
        check-shape-include-direction)     echo './tools/scripts/check_shape_include_direction.sh' ;;
        check-domain-purity)               echo './tools/scripts/check_domain_purity.sh' ;;
        check-core-include-boundary)       echo './tools/scripts/check_core_include_boundary.sh' ;;
        check-core-seal)                   echo '__core_seal__' ;;
        check-accel-oracle-pinned)         echo './tools/lint/check_accel_oracle_pinned.sh' ;;
        check-no-adx-overclaim)            echo './tools/lint/check_no_adx_overclaim.sh && ./tools/lint/check_asan_adx_exception.sh --selftest && ./tools/lint/check_asan_adx_exception.sh' ;;
        check-simd-os-support)             echo './tools/lint/check_simd_os_support.sh' ;;
        check-supervisor-registration)     echo './tools/scripts/check_supervisor_registration.sh' ;;
        check-test-registration)           echo './tools/scripts/check_test_registration.sh' ;;
        check-typed-blocker)               echo './tools/scripts/check_typed_blocker.sh' ;;
        check-blocker-escape-registered)   echo './tools/scripts/check_blocker_escape_registered.sh' ;;
        check-blocker-remedy)              echo './tools/scripts/check_blocker_remedy.sh' ;;
        check-blocker-handoff-declared)    echo './tools/lint/check_blocker_handoff_declared.sh' ;;
        check-supervisor-progress-declared) echo './tools/lint/check_supervisor_progress_declared.sh' ;;
        check-stopwatch-skip-detector)     echo './tools/lint/check_stopwatch_skip_detector.sh' ;;
        check-proof-server-pin)            echo './tools/lint/check_proof_server_pin.sh' ;;
        check-promotion-receipt-chain)     echo './tools/lint/check_promotion_receipt_chain.sh' ;;
        check-verification-coverage)       echo './tools/lint/check_verification_coverage.sh' ;;
        check-ship-remote-transaction)     echo './tools/lint/check_ship_remote_transaction.sh' ;;
        check-z23-release-install)         echo 'bash packaging/release/build_release.sh --selftest && bash tools/scripts/install_z23.sh --selftest' ;;
        check-identity-parser-single)      echo './tools/lint/check_identity_parser_single.sh --selftest && ./tools/lint/check_identity_parser_single.sh' ;;
        check-status-reason-single)        echo './tools/lint/check_status_reason_single.sh --selftest && ./tools/lint/check_status_reason_single.sh' ;;
        check-pipefail-status-pipe)        echo './tools/lint/check_pipefail_status_pipe.sh --selftest && ./tools/lint/check_pipefail_status_pipe.sh' ;;
        check-framework-shape)             echo 'ZCL_LINT_MODE=RATCHET ./tools/lint/framework_shape_check.sh' ;;
        check-framework-filename-suffix)   echo './tools/lint/check_framework_filename_suffix.sh' ;;
        check-no-raw-clock-outside-platform) echo './tools/lint/check_no_raw_clock_outside_platform.sh' ;;
        check-sysinit-ordering)            echo './tools/lint/check_sysinit_ordering.sh' ;;
        check-sandbox-wired)               echo './tools/lint/check_sandbox_wired.sh' ;;
        check-no-shellouts)                echo './tools/lint/check_no_shellouts.sh' ;;
        check-standalone-tools-link)       echo './tools/lint/check_standalone_tools_link.sh' ;;
        check-live-datadir-isolation)      echo './tools/lint/check_live_datadir_isolation.sh --selftest && ./tools/lint/check_live_datadir_isolation.sh' ;;
        check-installed-acceptance-tools)  echo './tools/lint/check_installed_acceptance_tools.sh' ;;
        check-no-writer-below-sealed-frontier) echo './tools/lint/check_no_writer_below_sealed_frontier.sh' ;;
        check-peer-floor-single-source)    echo './tools/lint/check_peer_floor_single_source.sh' ;;
        check-proc-self-shim)              echo './tools/lint/check_proc_self_shim.sh' ;;
        check-no-raw-sqlite-in-controllers) echo 'ZCL_LINT_MODE=RATCHET ./tools/lint/check_no_raw_sqlite_in_controllers.sh' ;;
        check-supervisor-domain)           echo './tools/lint/check_supervisor_domain.sh' ;;
        check-thread-supervision)          echo './tools/lint/check_thread_supervision.sh' ;;
        check-file-purpose)                echo 'ZCL_LINT_MODE=RATCHET ./tools/lint/check_file_purpose.sh' ;;
        check-group-purpose)               echo 'ZCL_LINT_MODE=FAIL ./tools/lint/check_group_purpose.sh' ;;
        check-no-orphan-placement)         echo 'ZCL_LINT_MODE=RATCHET ./tools/lint/check_no_orphan_placement.sh' ;;
        check-file-size-ceiling)           echo './tools/scripts/check_file_size_ceiling.sh' ;;
        check-operator-needed-sink)        echo './tools/scripts/check_operator_needed_sink.sh' ;;
        check-systemd-memory-budget)       echo './tools/scripts/check_systemd_memory_budget.sh' ;;
        check-condition-cooldown)          echo './tools/scripts/check_condition_cooldown.sh' ;;
        check-doc-accuracy)                echo './tools/scripts/check_doc_accuracy.sh' ;;
        check-doc-counts)                  echo './tools/scripts/check_doc_counts.sh' ;;
        check-no-stale-pinned-facts)       echo './tools/lint/check_no_stale_pinned_facts.sh' ;;
        check-no-uncited-victory)          echo './tools/scripts/check_no_uncited_victory.sh' ;;
        check-doc-claims)                  echo './tools/lint/check_doc_claims.sh' ;;
        check-error-doc-refs)              echo './tools/lint/check_error_doc_refs.sh' ;;
        check-api-reference-generated)     echo './tools/lint/check_api_reference_generated.sh' ;;
        check-describe-budget)             echo './tools/lint/check_describe_budget.sh --selftest && ./tools/lint/check_describe_budget.sh' ;;
        check-markdown-links)              echo './tools/lint/check_markdown_links.sh .' ;;
        check-doc-inline-paths)            echo './tools/lint/check_doc_inline_paths.sh' ;;
        check-hex-codec-single)            echo './tools/lint/check_hex_codec_single.sh --selftest && ./tools/lint/check_hex_codec_single.sh' ;;
        check-one-result-type)             echo './tools/scripts/check_one_result_type.sh' ;;
        check-service-result-convergence)  echo './tools/scripts/check_service_result_convergence.sh' ;;
        check-shape-includes-header)       echo './tools/scripts/check_shape_includes_header.sh' ;;
        check-projections-pure)            echo './tools/scripts/check_projections_pure.sh' ;;
        check-one-write-path)              echo './tools/scripts/check_one_write_path.sh' ;;
        check-frontier-single-writer)      echo './tools/scripts/check_frontier_single_writer.sh' ;;
        check-dumper-never-blocks)         echo './tools/scripts/check_dumper_never_blocks.sh' ;;
        check-no-block-index-flat)         echo './tools/scripts/check_no_block_index_flat.sh' ;;
        check-no-utxo-projection)          echo './tools/scripts/check_no_utxo_projection.sh' ;;
        check-no-utxos-mirror-read)        echo './tools/scripts/check_no_utxos_mirror_read.sh' ;;
        check-no-authoritative-ram-state)  echo './tools/scripts/check_no_authoritative_ram_state.sh' ;;
        check-no-dev-history-in-contracts) echo './tools/scripts/check_no_dev_history_in_contracts.sh' ;;
        check-no-live-lab-history)        echo './tools/scripts/check_no_live_lab_history.sh --selftest && ./tools/scripts/check_no_live_lab_history.sh' ;;
        check-stage-advances-or-blocks)    echo './tools/scripts/check_stage_advances_or_blocks.sh' ;;
        check-no-silent-ready)             echo './tools/scripts/check_no_silent_ready.sh' ;;
        check-honest-witness)              echo 'ZCL_LINT_MODE=FAIL ./tools/lint/check_honest_witness.sh' ;;
        check-consensus-parity)            echo './tools/scripts/check_consensus_parity.sh' ;;
        check-no-new-repair-rung)          echo './tools/scripts/check_no_new_repair_rung.sh' ;;
        check-no-new-borrowed-seed)        echo './tools/lint/check_no_new_borrowed_seed.sh .' ;;
        check-no-new-coin-backfill-caller) echo './tools/lint/check_no_new_coin_backfill_caller.sh .' ;;
        check-route-command-parity)        echo './tools/lint/check_route_command_parity.sh .' ;;
        check-doc-no-false-deleted)        echo './tools/lint/gate_doc_no_false_deleted.sh .' ;;
        check-zclassicd-reach-allowlist)   echo './tools/lint/gate_zclassicd_reach_allowlist.sh .' ;;
        check-stage-log-reorg-unsafe)      echo './tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh' ;;
        check-no-csr-lock-on-finalize-drive) echo './tools/lint/gate_no_csr_lock_on_finalize_drive.sh .' ;;
        check-mint-skip-crypto-offline-only) echo './tools/lint/check_mint_skip_crypto_offline_only.sh .' ;;
        check-wire-harness-security-gate)  echo 'bash tools/scripts/check_wire_harness_security_gate.sh' ;;
        check-vcs-no-git)                  echo 'tools/scripts/check_vcs_no_git.sh' ;;
        check-vcs-no-sha1)                 echo 'tools/scripts/check_vcs_no_sha1.sh && tools/dev/source-identity-selftest.sh' ;;
        check-vendor-provenance)           echo 'tools/scripts/test_vendor_provenance.sh' ;;
        check-command-contract)            echo './tools/lint/check_command_contract.sh' ;;
        check-command-availability-truthful) echo './tools/lint/check_command_availability_truthful.sh' ;;
        check-command-input-keys)          echo './tools/lint/check_command_input_keys.sh' ;;
        check-read-leaf-no-boot-ceremony)  echo './tools/lint/check_read_leaf_no_boot_ceremony.sh' ;;
        check-telemetry-ontology)          echo './tools/lint/check_telemetry_ontology.sh' ;;
        check-privileged-transition-receipt) echo './tools/lint/check_privileged_transition_receipt.sh' ;;
        check-c23-only)                     echo './tools/lint/check_c23_only.sh --selftest && ./tools/lint/check_c23_only.sh' ;;
        check-no-python)                    echo './tools/lint/check_no_python.sh --selftest && ./tools/lint/check_no_python.sh' ;;
        check-no-trust-state-ordering)     echo './tools/scripts/check_no_trust_state_ordering.sh' ;;
        check-no-gnu-va-args)              echo './tools/lint/check_no_gnu_va_args.sh' ;;
        check-no-warning-suppression)      echo './tools/lint/check_no_warning_suppression.sh .' ;;
        check-clang-portability)           echo './tools/lint/check_clang_portability.sh --self-test && ./tools/lint/check_clang_portability.sh' ;;
        check-result-discard)              echo 'ZCL_LINT_MODE=FAIL ./tools/lint/check_result_discard.sh' ;;
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
lib/validation/src/connect_block.c
lib/validation/src/chainstate.c
lib/validation/include/validation/connect_block.h
lib/validation/include/validation/chainstate.h"
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

# Adopt the cache state the parent derived (deriving it per worker would cost
# 116 redundant whole-tree hashes). The parent exports these three; absent or
# malformed means "no cache", which makes the gate run.
cache_adopt_from_env() {
    LINT_CACHE_AVAILABLE=0
    [ "${ZCL_LINT_CACHE_MODE:-off}" != "off" ] || return 1
    [[ "${ZCL_LINT_CACHE_TREE_KEY_X:-}" =~ ^[0-9a-f]{64}$ ]] || return 1
    [ -n "${ZCL_LINT_CACHE_DIR_X:-}" ] || return 1
    LINT_CACHE_TREE_KEY="$ZCL_LINT_CACHE_TREE_KEY_X"
    LINT_CACHE_DIR="$ZCL_LINT_CACHE_DIR_X"
    LINT_CACHE_AVAILABLE=1
    return 0
}

# Worker: run one gate, capture log + ms + rc artifacts, print a one-line
# receipt. Line stays well under PIPE_BUF so concurrent workers never tear.
#
# Cache path, in the one order that is safe:
#   probe (never mutates)  ->  skip on a hit, else RUN THE GATE UNCHANGED
#   ->  store ONLY on rc 0.
# Nothing here alters what a gate checks: on a miss it is the same command
# with the same environment as an uncached run.
worker() {
    local gate="$1" start end ms rc log cmd key="" cached=0 wouldhit=0

    if cache_adopt_from_env && lint_cache_gate_is_cacheable "$gate" \
       && cmd="$(gate_command "$gate")"; then
        key="$(lint_cache_key "$gate" "$cmd")"
        if lint_cache_has_pass "$key"; then
            wouldhit=1
            # --cold-audit deliberately does NOT skip: it runs every gate
            # fresh so the hit can be checked against the fresh verdict.
            if [ "${ZCL_LINT_CACHE_MODE:-off}" != "audit" ]; then
                cached=1
            fi
        fi
    fi
    printf '%s\n' "$wouldhit" > "$GATES_DIR/$gate.wouldhit"

    if [ "$cached" -eq 1 ]; then
        printf '%s\n' "0" > "$GATES_DIR/$gate.ms"
        printf '%s\n' "0" > "$GATES_DIR/$gate.rc"
        printf '%s\n' "1" > "$GATES_DIR/$gate.cached"
        printf 'cached (unchanged inputs since this gate last passed)\n' \
            > "$GATES_DIR/$gate.log"
        printf 'HIT  %-42s  cached (inputs unchanged)\n' "$gate"
        return 0
    fi
    printf '%s\n' "0" > "$GATES_DIR/$gate.cached"

    log="$GATES_DIR/$gate.log"
    start="$(now_ms)"
    run_gate_body "$gate" > "$log" 2>&1
    rc=$?
    end="$(now_ms)"
    ms=$((end - start))
    printf '%s\n' "$ms" > "$GATES_DIR/$gate.ms"
    printf '%s\n' "$rc" > "$GATES_DIR/$gate.rc"
    # ONLY a pass is ever stored. A failure is never cached, so a red gate
    # can never be turned green by a later run.
    if [ "$rc" -eq 0 ] && [ -n "$key" ] && [ "$LINT_CACHE_AVAILABLE" = "1" ]; then
        lint_cache_store_pass "$gate" "$key"
    fi
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
    # Cache mode precedence, mirroring test_parallel's: --cold-audit beats
    # --no-cache beats (--cache | ZCL_LINT_CACHE!=0) beats OFF. OFF is the
    # default and reproduces the historical driver exactly.
    local cli_cache=0 cli_no_cache=0 cli_cold_audit=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --jobs)    JOBS="${2:?--jobs needs N}"; shift 2 ;;
            --jobs=*)  JOBS="${1#--jobs=}"; shift ;;
            --bin-dir) BIN_DIR="${2:?--bin-dir needs a dir}"; shift 2 ;;
            --bin-dir=*) BIN_DIR="${1#--bin-dir=}"; shift ;;
            --cache)      cli_cache=1; shift ;;
            --no-cache)   cli_no_cache=1; shift ;;
            --cold-audit) cli_cold_audit=1; shift ;;
            --worker)  worker "$2"; exit $? ;;
            --list)
                # Gate names = the case labels in gate_command() (read from
                # this file so reformatting cannot desync the probe).
                grep -oE '\bcheck-[a-z0-9-]+\)' "$0" | tr -d ')' | sort -u
                exit 0 ;;
            --help|-h) usage; exit 0 ;;
            check-*)   gates+=("$1"); shift ;;
            *) echo "run_lint.sh: unknown argument '$1'" >&2; exit 2 ;;
        esac
    done
    # Diagnostic surface: ZCL_LINT_CACHE_DUMP=<gate> prints what that gate
    # keys on and whether it is a hit right now, then exits. Needs the same
    # two exported vars the key folds in, so set them first.
    if [ -n "${ZCL_LINT_CACHE_DUMP:-}" ]; then
        local dump_gate="$ZCL_LINT_CACHE_DUMP" dump_cmd
        export ZCL_LINT_PRODUCTION_SCAN=1
        export ZCL_LINT_BIN_DIR="$BIN_DIR"
        if ! dump_cmd="$(gate_command "$dump_gate")"; then
            echo "run_lint.sh: ZCL_LINT_CACHE_DUMP='$dump_gate' is not a known gate" >&2
            exit 2
        fi
        lint_cache_open "$ROOT" || true
        lint_cache_dump "$dump_gate" "$dump_cmd"
        exit 0
    fi

    [[ "$JOBS" =~ ^[0-9]+$ ]] && [ "$JOBS" -ge 1 ] || {
        echo "run_lint.sh: --jobs must be a positive integer (got '$JOBS')" >&2; exit 2; }
    [ "$JOBS" -le 32 ] || JOBS=32
    [ "${#gates[@]}" -gt 0 ] || { echo "run_lint.sh: no gates given" >&2; exit 2; }

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

    mkdir -p "$GATES_DIR"
    rm -f "$GATES_DIR"/*.log "$GATES_DIR"/*.ms "$GATES_DIR"/*.rc \
          "$GATES_DIR"/*.cached "$GATES_DIR"/*.wouldhit 2>/dev/null

    # Same scan-exclusion contract as the Makefile `check-%` pattern rule.
    export ZCL_LINT_PRODUCTION_SCAN=1
    export ZCL_LINT_BIN_DIR="$BIN_DIR"
    [[ "$BUDGET_SEC" =~ ^[0-9]+$ ]] || BUDGET_SEC=75

    # ── Resolve the cache mode and derive the tree key ONCE, here in the
    # parent, before any worker forks. Both env vars must be set before
    # lint_cache_key() is called anywhere, since both are folded into it.
    local cache_mode=off
    if [ "$cli_cold_audit" -eq 1 ]; then
        cache_mode=audit
    elif [ "$cli_no_cache" -eq 1 ]; then
        cache_mode=off
    elif [ "$cli_cache" -eq 1 ] || [ "${ZCL_LINT_CACHE:-0}" != "0" ]; then
        cache_mode=on
    fi
    export ZCL_LINT_CACHE_MODE=off ZCL_LINT_CACHE_TREE_KEY_X= ZCL_LINT_CACHE_DIR_X=
    if [ "$cache_mode" != "off" ]; then
        if lint_cache_open "$ROOT"; then
            export ZCL_LINT_CACHE_MODE="$cache_mode"
            export ZCL_LINT_CACHE_TREE_KEY_X="$LINT_CACHE_TREE_KEY"
            export ZCL_LINT_CACHE_DIR_X="$LINT_CACHE_DIR"
        else
            # Fail-safe: the cache could not bound its inputs, so it is not
            # used at all and every gate runs. Never a partial keyspace.
            lint_cache_note "disabled for this run — every gate will run"
            cache_mode=off
        fi
    fi

    local -a serial_gates=() par_gates=()
    for g in "${gates[@]}"; do
        case "$SERIAL_PROLOGUE" in
            *" $g "*) serial_gates+=("$g") ;;
            *)        par_gates+=("$g") ;;
        esac
    done

    local run_start run_end wall_ms
    run_start="$(now_ms)"
    for g in "${serial_gates[@]}"; do
        worker "$g"
    done
    if [ "${#par_gates[@]}" -gt 0 ]; then
        printf '%s\n' "${par_gates[@]}" | \
            xargs -r -P "$JOBS" -n1 "$0" --worker
    fi
    run_end="$(now_ms)"
    wall_ms=$((run_end - run_start))

    # Aggregate. A gate that produced no .rc file crashed the worker itself.
    local -a failed=()
    local total=0 rc ms
    local cached_n=0 ran_n=0 audit_hits=0 audit_diverged=0
    local -a diverged=()
    for g in "${gates[@]}"; do
        total=$((total + 1))
        if [ ! -f "$GATES_DIR/$g.rc" ]; then
            failed+=("$g (worker crash — no rc artifact)")
            continue
        fi
        rc="$(cat "$GATES_DIR/$g.rc")"
        [ "$rc" = "0" ] || failed+=("$g")
        if [ "$(cat "$GATES_DIR/$g.cached" 2>/dev/null || echo 0)" = "1" ]; then
            cached_n=$((cached_n + 1))
        else
            ran_n=$((ran_n + 1))
        fi
        # Cold audit: a gate that carried a stored PASS at its CURRENT key,
        # ran fresh anyway, and FAILED, proves the key does not bound the
        # gate's real inputs. That is a cache soundness bug, and it fails the
        # run loudly on top of the gate's own failure.
        if [ "$cache_mode" = "audit" ] \
           && [ "$(cat "$GATES_DIR/$g.wouldhit" 2>/dev/null || echo 0)" = "1" ]; then
            audit_hits=$((audit_hits + 1))
            if [ "$rc" != "0" ]; then
                audit_diverged=$((audit_diverged + 1))
                diverged+=("$g")
            fi
        fi
    done

    # Slowest gates first (per-gate ms artifacts make regressions visible).
    local ranked
    ranked="$(for f in "$GATES_DIR"/*.ms; do
        [ -f "$f" ] || continue
        printf '%s %s\n' "$(cat "$f")" "$(basename "$f" .ms)"
    done | sort -nr)"
    local cache_note=""
    case "$cache_mode" in
        on)    cache_note=", cached ${cached_n} / ran ${ran_n}" ;;
        audit) cache_note=", cold-audit: ran all ${ran_n}" ;;
    esac
    echo "── lint timing: ${total} gates, wall ${wall_ms} ms, jobs ${JOBS}${cache_note} ──"
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
        printf '  "cache_mode":"%s",\n' "$cache_mode"
        printf '  "cache_hits":%s,\n' "$cached_n"
        printf '  "cache_ran":%s,\n' "$ran_n"
        printf '  "cold_audit_verified":%s,\n' "$audit_hits"
        printf '  "cold_audit_divergences":%s,\n' "$audit_diverged"
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
    } > "$STATE_DIR/last-run.json.tmp" && mv -f "$STATE_DIR/last-run.json.tmp" "$STATE_DIR/last-run.json"

    if [ "$wall_ms" -gt $((BUDGET_SEC * 1000)) ]; then
        echo "run_lint.sh: NOTE — wall ${wall_ms} ms exceeds the ${BUDGET_SEC}s soft budget" \
            "(ZCL_LINT_BUDGET_SEC; see the budget comment above the lint target)" >&2
    fi

    if [ "$cache_mode" = "audit" ]; then
        echo "cold-audit: ${audit_hits} cache-hit(s) verified against fresh runs," \
             "${audit_diverged} divergence(s)"
        if [ "$audit_diverged" -gt 0 ]; then
            echo "" >&2
            for g in "${diverged[@]}"; do
                echo "COLD-AUDIT DIVERGENCE: $g carried a cached PASS at its current" >&2
                echo "  key but FAILED a fresh run — the cache is UNSOUND. Its real" >&2
                echo "  inputs are not covered by the key. Move it to the never-cached" >&2
                echo "  set in tools/lint/lint_cache.sh with the reason." >&2
            done
        fi
        if [ "$audit_hits" -eq 0 ]; then
            echo "cold-audit: NOTE — no gate carried a stored PASS, so nothing was" \
                 "actually verified. Warm the cache first (--cache), then re-audit." >&2
        fi
    fi

    if [ "$audit_diverged" -gt 0 ]; then
        echo "" >&2
        echo "══ LINT: ${audit_diverged} cold-audit divergence(s) ══" >&2
        exit 1
    fi

    if [ "${#failed[@]}" -gt 0 ]; then
        echo "" >&2
        echo "══ LINT: ${#failed[@]} of ${total} gates FAILED ══" >&2
        for g in "${failed[@]}"; do
            echo "  ✗ $g" >&2
        done
        for g in "${failed[@]}"; do
            local name="${g%% *}"
            if [ -f "$GATES_DIR/$name.log" ]; then
                echo "" >&2
                echo "──── FAIL log: $name ────────────────────────────" >&2
                cat "$GATES_DIR/$name.log" >&2
            fi
        done
        exit 1
    fi
    exit 0
}

main "$@"
