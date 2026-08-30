#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Validate the closed macOS capability matrix and run its exact evidence set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MATRIX="${ZCL_MACOS_CAPABILITY_MATRIX:-$REPO_ROOT/config/platform/macos_capabilities.def}"
REGISTRY="$REPO_ROOT/tools/dev/test_group_catalog.def"

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

    local rows expected actual registered id state reason groups group
    rows="$(matrix_rows)"
    [ -n "$rows" ] || die "capability matrix yielded no rows"
    expected='hot_activation kqueue launchd node noise package_execution release_packaging resident_confinement snapshot_export tor wallet'
    actual="$(printf '%s\n' "$rows" | awk -F',' '{gsub(/[[:space:]]/, "", $1); print $1}' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
    [ "$actual" = "$expected" ] || die "capability set drift: expected '$expected'; observed '$actual'"
    registered="$(registered_groups)"
    [ -n "$registered" ] || die "registered-test catalog yielded no groups"

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
        done < <(printf '%s' "$groups" | tr ',' '\n')
    done <<< "$rows"
}

exact_groups() {
    matrix_rows | cut -d',' -f4- | tr ',' '\n' | sed 's/[[:space:]]//g' | sed '/^$/d' | LC_ALL=C sort -u | paste -sd, -
}

case "${1:---check}" in
    --check)
        validate
        printf 'macos-acceptance: capability matrix PASS\n'
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
        trap 'rm -f "$log"' EXIT
        if make --no-print-directory t-fast-exact ONLY="$groups" T_FAST_EXACT_ARGS=--no-cache >"$log" 2>&1; then
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
        printf 'macos-acceptance: PASS (%s exact groups, zero skips)\n' "$count"
        ;;
    *) die "usage: $0 [--check|--groups|--run]" ;;
esac
