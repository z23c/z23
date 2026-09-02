#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Fail closed when Git-tracked maintained source is absent from the code index.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${ZCL_CODEINDEX_COVERAGE_BIN:-$ROOT/build/bin/z23-dev}"
BASELINE="${ZCL_CODEINDEX_COVERAGE_BASELINE:-$ROOT/tools/lint/codeindex_coverage_baseline.txt}"
SOURCE_ROOT="${ZCL_CODEINDEX_COVERAGE_ROOT:-$ROOT}"

coverage_ceiling() {
    awk '!/^#/ && NF { print $1; exit }' "$BASELINE"
}

run_gate() {
    local output verdict missing ceiling summary
    [ -x "$BIN" ] || {
        echo "check-codeindex-coverage: FATAL — missing executable $BIN" >&2
        return 2
    }
    [ -f "$BASELINE" ] || {
        echo "check-codeindex-coverage: FATAL — missing baseline $BASELINE" >&2
        return 2
    }
    ceiling="$(coverage_ceiling)"
    case "$ceiling" in
        ''|*[!0-9]*)
            echo "check-codeindex-coverage: FATAL — baseline must contain one nonnegative integer" >&2
            return 2
            ;;
    esac
    if ! output="$(ZCL_DEV_SOURCE_ROOT="$SOURCE_ROOT" "$BIN" code coverage 2>&1)"; then
        echo "check-codeindex-coverage: FATAL — code coverage could not measure the tree" >&2
        printf '%s\n' "$output" | sed 's/^/  /' >&2
        return 2
    fi
    verdict="$(printf '%s\n' "$output" | sed -n 's/.*"verdict":"\([A-Z]*\)".*/\1/p' | head -1)"
    missing="$(printf '%s\n' "$output" | sed -n 's/.*"missing_files":\([0-9][0-9]*\).*/\1/p' | head -1)"
    summary="$(printf '%s\n' "$output" | sed -n 's/.*"summary":"\([^"]*\)".*/\1/p' | head -1)"
    case "$missing" in
        ''|*[!0-9]*)
            echo "check-codeindex-coverage: FATAL — malformed code coverage reply" >&2
            printf '%s\n' "$output" | sed 's/^/  /' >&2
            return 2
            ;;
    esac
    if [ "$missing" -gt "$ceiling" ]; then
        echo "check-codeindex-coverage: FAIL — $summary; shrink-only ceiling=$ceiling" >&2
        printf '%s\n' "$output" | sed 's/^/  /' >&2
        return 1
    fi
    if [ "$verdict" != "GREEN" ] && [ "$missing" -eq 0 ]; then
        echo "check-codeindex-coverage: FATAL — zero misses did not earn GREEN" >&2
        return 2
    fi
    echo "check-codeindex-coverage: PASS — $summary; shrink-only ceiling=$ceiling"
}

run_selftest() {
    local tmp fixture rc
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/z23-codeindex-coverage.XXXXXX")"
    trap "rm -rf '$tmp'" EXIT HUP INT TERM
    fixture="$tmp/repo"
    mkdir -p "$fixture/src"
    printf '%s\n' 'int coverage_fixture(void) { return 23; }' > "$fixture/src/a.c"
    git -C "$fixture" init -q
    git -C "$fixture" add src/a.c
    printf '%s\n' 0 > "$tmp/baseline"

    if ! ZCL_CODEINDEX_COVERAGE_ROOT="$fixture" \
            ZCL_CODEINDEX_COVERAGE_BASELINE="$tmp/baseline" \
            "$0" >"$tmp/clean.log" 2>&1; then
        echo "check-codeindex-coverage: SELFTEST FAILED — clean tracked source was not GREEN" >&2
        sed 's/^/  /' "$tmp/clean.log" >&2
        exit 2
    fi

    printf '%s\n' 'int planted_missing(void) { return 1; }' > "$fixture/src/missing.c"
    git -C "$fixture" add src/missing.c
    rm "$fixture/src/missing.c"
    rc=0
    ZCL_CODEINDEX_COVERAGE_ROOT="$fixture" \
        ZCL_CODEINDEX_COVERAGE_BASELINE="$tmp/baseline" \
        "$0" >"$tmp/missing.log" 2>&1 || rc=$?
    if [ "$rc" -ne 1 ] || ! grep -q 'missing=1' "$tmp/missing.log"; then
        echo "check-codeindex-coverage: SELFTEST FAILED — planted tracked omission was not named RED" >&2
        sed 's/^/  /' "$tmp/missing.log" >&2
        exit 2
    fi

    git -C "$fixture" rm -q --cached --ignore-unmatch src/missing.c
    if ! ZCL_CODEINDEX_COVERAGE_ROOT="$fixture" \
            ZCL_CODEINDEX_COVERAGE_BASELINE="$tmp/baseline" \
            "$0" >"$tmp/restored.log" 2>&1; then
        echo "check-codeindex-coverage: SELFTEST FAILED — removing the planted manifest row did not restore GREEN" >&2
        sed 's/^/  /' "$tmp/restored.log" >&2
        exit 2
    fi
    echo "check-codeindex-coverage: SELFTEST PASS — clean and restored manifests are GREEN; one tracked missing file is RED"
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
    exit 0
fi

cd "$ROOT"
run_gate
