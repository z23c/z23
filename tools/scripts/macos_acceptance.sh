#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Validate the closed macOS capability matrix and run its exact evidence set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MATRIX="${ZCL_MACOS_CAPABILITY_MATRIX:-$REPO_ROOT/engine/composition/platform/macos_capabilities.def}"
REGISTRY="$REPO_ROOT/tools/dev/test_group_catalog.def"
EXPECTED_EXACT_GROUPS='test_arm_hw_tiers,test_binary_ab_fallback,test_binary_staleness,test_blake2b_batch_parity,test_boot_shutdown_marker_persistence,test_chacha20_isa_parity,test_cold_join_sovereign,test_confine,test_crypto,test_dev_activation,test_dev_platform,test_directory_watcher,test_encoding,test_fast_sync_coins_export,test_hw_profile,test_net,test_noise_nk_handshake,test_noise_transport_parity,test_noise_xx_handshake,test_os_proc,test_os_sandbox,test_rng,test_rpc,test_sandbox_process_budget,test_self_backtrace,test_service_state,test_service_state_driver,test_sha256_isa_parity,test_sha3_256_x4,test_sha3_512_x4,test_sha512_isa_parity,test_sqlite,test_thread_qos,test_tor,test_wallet,test_wallet_backup,test_watcher_record,test_z23_front_door,test_zcode_verify'

die() {
    printf 'macos-acceptance: FAIL: %s\n' "$*" >&2
    exit 1
}

matrix_rows() {
    awk '
        /^ZCL_MACOS_CAPABILITY\(/ {
            row=$0
            sub(/^ZCL_MACOS_CAPABILITY\(/, "", row)
            sub(/\)[[:space:]]*$/, "", row)
            print row
        }
    ' "$MATRIX"
}

required_groups() {
    awk '
        /^ZCL_MACOS_REQUIRED_TEST\([A-Za-z_0-9]+\)[[:space:]]*$/ {
            row=$0; sub(/^[^(]*\(/, "", row); sub(/\).*/, "", row)
            print row
        }
    ' "$MATRIX"
}

registered_groups() {
    awk '
        /^[[:space:]]*ZCL_TEST_GROUP\([A-Za-z_0-9]+\)[[:space:]]*$/ {
            row=$0; sub(/^[^(]*\(/, "", row); sub(/\).*/, "", row)
            print "test_" row
        }
        /^[[:space:]]*ZCL_SPEC_GROUP\([A-Za-z_0-9]+\)[[:space:]]*$/ {
            row=$0; sub(/^[^(]*\(/, "", row); sub(/\).*/, "", row)
            print "spec_" row
        }
    ' "$REGISTRY"
}

validate() {
    [ -f "$MATRIX" ] || die "missing capability matrix: $MATRIX"
    [ -f "$REGISTRY" ] || die "missing registered-test catalog: $REGISTRY"

    local rows expected actual registered required required_actual
    local id state reason groups group required_count union_count union_actual
    rows="$(matrix_rows)"
    [ -n "$rows" ] || die "capability matrix yielded no rows"
    expected='arm_acceleration hot_activation kqueue launchd node noise package_execution release_packaging resident_confinement scheduler_qos snapshot_export tor wallet'
    actual="$(printf '%s\n' "$rows" | awk -F',' '{gsub(/[[:space:]]/, "", $1); print $1}' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
    [ "$actual" = "$expected" ] || die "capability set drift: expected '$expected'; observed '$actual'"
    registered="$(registered_groups)"
    [ -n "$registered" ] || die "registered-test catalog yielded no groups"

    required="$(required_groups)"
    [ -n "$required" ] || die "required test set yielded no groups"
    required_count="$(printf '%s\n' "$required" | awk 'NF {n++} END {print n+0}')"
    [ "$required_count" = 8 ] ||
        die "required test set drift: expected 8 rows; observed $required_count"
    while IFS= read -r group; do
        grep -Fqx "$group" <<< "$registered" ||
            die "required test set names unregistered group '$group'"
    done <<< "$required"
    expected='test_binary_staleness test_cold_join_sovereign test_crypto test_dev_platform test_os_proc test_rng test_self_backtrace test_sqlite'
    required_actual="$(printf '%s\n' "$required" | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//')"
    [ "$required_actual" = "$expected" ] ||
        die "required test set drift: expected '$expected'; observed '$required_actual'"

    while IFS=',' read -r id state reason groups; do
        id="${id//[[:space:]]/}"
        state="${state//[[:space:]]/}"
        reason="${reason//[[:space:]]/}"
        groups="${groups//[[:space:]]/}"
        case "$state" in available|degraded|unavailable) ;; *) die "$id has invalid state '$state'" ;; esac
        [ -n "$reason" ] || die "$id has no typed reason"
        [ -n "$groups" ] || die "$id has no refusal/availability evidence group"
        while IFS= read -r group; do
            grep -Fqx "$group" <<< "$registered" || die "$id names unregistered group '$group'"
        # printf '%s' emits no trailing newline, so `tr ',' '\n'` leaves the
        # LAST group as an unterminated partial line and `read` returns
        # non-zero without running the body for it. Until check-macos-acceptance
        # started running this script, that silently skipped the last evidence
        # group of every row — and validated NOTHING at all for the rows that
        # name exactly one group (tor, release_packaging, snapshot_export).
        done < <(printf '%s\n' "$groups" | tr ',' '\n')
    done <<< "$rows"

    union_actual="$(exact_groups)"
    union_count="$(printf '%s\n' "$union_actual" | tr ',' '\n' |
        awk 'NF {n++} END {print n+0}')"
    [ "$union_count" = 39 ] ||
        die "exact evidence union drift: expected 39 groups; observed $union_count"
    [ "$union_actual" = "$EXPECTED_EXACT_GROUPS" ] ||
        die "exact evidence set drift: expected '$EXPECTED_EXACT_GROUPS'; observed '$union_actual'"
}

exact_groups() {
    {
        matrix_rows | cut -d',' -f4- | tr ',' '\n'
        required_groups
    } | sed 's/[[:space:]]//g' | sed '/^$/d' | LC_ALL=C sort -u | paste -sd, -
}

case "${1:---check}" in
    --check)
        validate
        printf 'macos-acceptance: capability matrix + required baseline PASS (39 exact groups)\n'
        ;;
    --groups)
        validate
        exact_groups
        ;;
    --run)
        validate
        [ "$(uname -s)" = Darwin ] || die "native darwin-arm64 execution required (host=$(uname -s))"
        [ "$(uname -m)" = arm64 ] || die "Tier-1 target requires arm64 (host=$(uname -m))"
        groups="$(exact_groups)"
        count="$(printf '%s' "$groups" | tr ',' '\n' | awk 'NF {n++} END {print n+0}')"
        printf 'macos-acceptance: running %s exact groups derived from %s\n' "$count" "${MATRIX#"$REPO_ROOT/"}"
        log="$(mktemp "${TMPDIR:-/tmp}/z23-macos-acceptance.XXXXXX")"
        package_root="$(mktemp -d "${TMPDIR:-/tmp}/z23-macos-runtime.XXXXXX")"
        trap 'rm -f "$log"; rm -rf "$package_root"' EXIT
        if make --no-print-directory t-fast-exact \
            ONLY="$groups" EXACT_ONLY_MATCHED="$groups" \
            T_FAST_EXACT_ARGS=--no-cache \
            >"$log" 2>&1; then
            sed -n '1,$p' "$log"
        else
            rc=$?
            sed -n '1,$p' "$log"
            exit "$rc"
        fi
        verdict="$(awk '/^SUITE VERDICT / {line=$0} END {print line}' "$log")"
        [ -n "$verdict" ] || die "runner emitted no SUITE VERDICT"
        ran="$(printf '%s\n' "$verdict" | sed -n 's/.* groups_ran=\([0-9][0-9]*\).*/\1/p')"
        failed="$(printf '%s\n' "$verdict" | sed -n 's/.* groups_failed=\([0-9][0-9]*\).*/\1/p')"
        skips="$(printf '%s\n' "$verdict" | sed -n 's/.* self_skips=\([0-9][0-9]*\).*/\1/p')"
        unobserved="$(printf '%s\n' "$verdict" | sed -n 's/.* env_unobserved=\([0-9][0-9]*\).*/\1/p')"
        [ "$ran" = "$count" ] || die "expected $count executed groups, verdict reports ${ran:-missing}"
        [ "$failed" = 0 ] || die "verdict reports ${failed:-missing} failed groups"
        [ "$skips" = 0 ] || die "unexpected eligible self-skips: ${skips:-missing}"
        [ "$unobserved" = 0 ] || die "unobserved eligible environments: ${unobserved:-missing}"

        # Accept the bytes a Mac user would actually receive, not only the
        # unstripped source-test binaries.  The canonical cutter requires the
        # closed four-member darwin-arm64 runtime, strips every Mach-O, checks
        # the macOS 14 floor and system-runtime-only dependency boundary, then
        # verifies its closed SHA256SUMS.  The node-free guide call proves the
        # stripped packaged node executes; it never opens a datadir or network.
        "$REPO_ROOT/platform/packaging/release/build_release.sh" --bin "$REPO_ROOT/build/bin" --out "$package_root/runtime" --platform darwin-arm64
        "$package_root/runtime/z23" code guide >"$package_root/code-guide.json"
        [ -s "$package_root/code-guide.json" ] || die "packaged z23 code guide emitted no response"

        printf 'macos-acceptance: runtime package PASS (darwin-arm64, macOS 14 floor, audited, checksummed, node-free execution)\n'
        printf 'macos-acceptance: UNOBSERVED installed=false synced=false published=false notarized=false\n'
        printf 'macos-acceptance: PASS (%s exact groups, zero skips, runtime package accepted)\n' "$count"
        ;;
    *) die "usage: $0 [--check|--groups|--run]" ;;
esac
