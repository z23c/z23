#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Prove the capability inventory is complete, internally consistent output of
# the C23 source scanner. The report is evidence, never authored prose, and it
# is NOT tracked: this gate generates it into build/gen/CAPABILITY_INVENTORY.jsonl
# (the same place `make docs-capability-inventory` writes it) and checks the
# generated file; there is no stored copy to diff against. Checks: the census
# floor, the public-header census against the tracked headers, every summary
# count against the rows actually emitted, and the generated-artifact header.
# --selftest also proves the check trips when a capability row is dropped and
# when a header claim is removed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

OUT_DIR="build/gen"
DOC="$OUT_DIR/CAPABILITY_INVENTORY.jsonl"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-capability-inventory.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

SOURCES=(
    tools/gen_capability_inventory.c
    cognition/modules/codeindex/src/codeindex_inventory.c
    cognition/modules/codeindex/src/codeindex_inventory_scan.c
    cognition/modules/codeindex/src/codeindex_inventory_render.c
    cognition/modules/codeindex/src/codeindex_inventory_body.c
    cognition/modules/codeindex/src/codeindex_inventory_evidence.c
    cognition/modules/codeindex/src/codeindex_scan.c
    cognition/modules/codeindex/src/codeindex_scan_doc.c
    platform/modules/base/src/safe_alloc.c
    platform/modules/base/src/log_level.c
    platform/modules/sha3/src/sha3.c
)
GEN="${2:-$TMP/gen_capability_inventory}"
LIBS=()
case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*)
        SOURCES+=(
            platform/modules/platform/src/directory_compat.c
            platform/modules/platform/src/positioned_file.c
        )
        LIBS+=( -ladvapi32 )
        if [ -z "${2:-}" ]; then GEN="$GEN.exe"; fi
        ;;
esac

CC_BIN="${CC:-cc}"
if [ -n "${2:-}" ]; then
    if [ ! -x "$GEN" ]; then
        echo "check_capability_inventory_generated: FATAL — generator absent: $GEN" >&2
        exit 2
    fi
elif ! "$CC_BIN" -std=c23 -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE \
        -O2 -Wall -Wextra \
        -Werror -pedantic -Icognition/modules/codeindex/include -Icognition/modules/codeindex/src \
        -Iplatform/modules/base/include -Iplatform/modules/util/include -Iplatform/modules/sha3/include \
        -Icore/modules/crypto/include -Iplatform/modules/platform/include \
        -o "$GEN" "${SOURCES[@]}" "${LIBS[@]}" \
        2>"$TMP/cc.log"; then
    echo "check_capability_inventory_generated: FATAL — generator compile failed" >&2
    sed 's/^/    /' "$TMP/cc.log" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"
if ! "$GEN" "$DOC" . 2>"$TMP/gen.log"; then
    echo "check_capability_inventory_generated: FATAL — derivation failed" >&2
    sed 's/^/    /' "$TMP/gen.log" >&2
    exit 2
fi

git ls-files core engine contexts cognition platform contexts/commons/packages |
    awk '/\/include\/.*\.h$/ && $0 !~ /^lib\/test\//' |
    LC_ALL=C sort -u >"$TMP/tracked_headers"
catalog_groups="$(awk '
    /^[[:space:]]*ZCL_TEST_GROUP\([[:alnum:]_]+\)[[:space:]]*$/ { n++ }
    /^[[:space:]]*ZCL_SPEC_GROUP\([[:alnum:]_]+\)[[:space:]]*$/ { n++ }
    END { print n + 0 }
' tools/dev/test_group_catalog.def)"

# verify FILE: 0 complete, 1 incomplete or inconsistent, 2 census floor failed.
# Messages go to stderr; the caller decides what a failure means.
verify() {
    local file="$1" meta
    meta="$(head -n 1 "$file")"
    field() {
        printf '%s\n' "$meta" | sed -n "s/.*\"$1\":\([0-9][0-9]*\).*/\1/p"
    }
    local capabilities duplicates invariants registered_groups roots_found
    local roots_missing roots_ambiguous root_gaps multi_arm_symbols definition_arms
    capabilities="$(field capabilities)"
    duplicates="$(field duplicates)"
    invariants="$(field untested_invariants)"
    registered_groups="$(field registered_test_groups)"
    roots_found="$(field registered_test_roots_found)"
    roots_missing="$(field registered_test_roots_missing)"
    roots_ambiguous="$(field ambiguous_registered_test_roots)"
    root_gaps="$(field test_root_gaps)"
    multi_arm_symbols="$(field multi_arm_symbols)"
    definition_arms="$(field definition_arms)"
    if [ "${capabilities:-0}" -lt 1000 ] || [ "${roots_found:-0}" -lt 500 ]; then
        echo "check_capability_inventory_generated: FATAL — census floor failed" >&2
        echo "  capabilities=${capabilities:-missing} roots_found=${roots_found:-missing}" >&2
        return 2
    fi
    sed -n 's/^{"record":"capability","header":"\([^"]*\)".*/\1/p' \
        "$file" | LC_ALL=C sort -u >"$TMP/report_headers"
    if ! diff -u "$TMP/tracked_headers" "$TMP/report_headers" \
            >"$TMP/headers.diff"; then
        echo "check_capability_inventory_generated: FAIL — public-header census is not exact" >&2
        head -60 "$TMP/headers.diff" | sed 's/^/    /' >&2
        return 1
    fi
    local cap_rows dup_rows inv_rows gap_rows multi_rows arm_rows
    cap_rows="$(grep -c '^{"record":"capability"' "$file" || true)"
    dup_rows="$(grep -c '^{"record":"duplicate"' "$file" || true)"
    inv_rows="$(grep -c '^{"record":"untested_invariant"' "$file" || true)"
    gap_rows="$(grep -c '^{"record":"test_root_gap"' "$file" || true)"
    multi_rows="$(grep -c '^{"record":"multi_arm_symbol"' "$file" || true)"
    arm_rows="$(grep -c '^{"record":"definition_arm"' "$file" || true)"
    if [ "$capabilities" -ne "$cap_rows" ] || [ "$duplicates" -ne "$dup_rows" ] ||
       [ "$invariants" -ne "$inv_rows" ] || [ "$registered_groups" -ne "$catalog_groups" ] ||
       [ "$multi_arm_symbols" -ne "$multi_rows" ] ||
       [ "$definition_arms" -ne "$arm_rows" ] ||
       [ $((roots_found + roots_missing + roots_ambiguous)) -ne "$registered_groups" ] ||
       [ "$root_gaps" -ne "$gap_rows" ] ||
       [ "$gap_rows" -ne $((roots_missing + roots_ambiguous)) ]; then
        echo "check_capability_inventory_generated: FAIL — report accounting is inconsistent" >&2
        echo "  capabilities=$capabilities/$cap_rows duplicates=$duplicates/$dup_rows invariants=$invariants/$inv_rows" >&2
        echo "  multi_arm_symbols=$multi_arm_symbols/$multi_rows definition_arms=$definition_arms/$arm_rows" >&2
        echo "  groups=$registered_groups/$catalog_groups roots=$roots_found+$roots_missing+$roots_ambiguous gaps=$root_gaps/$gap_rows" >&2
        return 1
    fi
    local claim
    for claim in \
        '"generated_artifact_schema":"zcl.generated_artifact.v1"' \
        '"artifact_id":"zcl.code_capability_inventory.v1"' \
        '"generated_by":"tools/gen_capability_inventory.c"' \
        '"regenerate":"make docs-capability-inventory"' \
        '"artifact_id":"zcl.arm_symbol_single_baseline.v1"'; do
        if ! grep -Fq "$claim" <<<"$meta"; then
            echo "check_capability_inventory_generated: FAIL — generated artifact header lacks $claim" >&2
            return 1
        fi
    done
    echo "check_capability_inventory_generated: clean — $capabilities capabilities; $roots_found registered roots resolved"
    return 0
}

if [ "${1:-}" = "--selftest" ]; then
    rc=0
    verify "$DOC" >"$TMP/clean.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        cat "$TMP/clean.log" >&2
        exit "$rc"
    fi
    # Drop one capability row: the summary count then disagrees with the rows
    # and the public-header census loses a header (when it was that header's
    # only row), so the check must refuse.
    awk '!dropped && /^\{"record":"capability"/ { dropped = 1; next } { print }' \
        "$DOC" >"$TMP/dropped_row.jsonl"
    if verify "$TMP/dropped_row.jsonl" >/dev/null 2>&1; then
        echo "check_capability_inventory_generated selftest: FAIL — a dropped capability row passed" >&2
        exit 1
    fi
    # Remove the regenerate claim from the header record.
    sed '1s/"regenerate":"make docs-capability-inventory"/"regenerate":"-"/' \
        "$DOC" >"$TMP/dropped_claim.jsonl"
    if verify "$TMP/dropped_claim.jsonl" >/dev/null 2>&1; then
        echo "check_capability_inventory_generated selftest: FAIL — a removed header claim passed" >&2
        exit 1
    fi
    echo "check_capability_inventory_generated selftest: PASS — the generated report passes; a dropped capability row and a removed header claim fail"
    cat "$TMP/clean.log"
    exit 0
fi

verify "$DOC"
