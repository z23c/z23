#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Prove docs/CAPABILITY_INVENTORY.jsonl is exactly what the C23 source scanner
# derives from this checkout.  The report is evidence, never authored prose.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

DOC="docs/CAPABILITY_INVENTORY.jsonl"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-capability-inventory.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

SOURCES=(
    tools/gen_capability_inventory.c
    cognition/modules/codeindex/src/codeindex_inventory.c
    cognition/modules/codeindex/src/codeindex_inventory_scan.c
    cognition/modules/codeindex/src/codeindex_inventory_body.c
    cognition/modules/codeindex/src/codeindex_inventory_evidence.c
    cognition/modules/codeindex/src/codeindex_scan.c
    cognition/modules/codeindex/src/codeindex_scan_doc.c
    platform/modules/base/src/safe_alloc.c
    platform/modules/base/src/log_level.c
    platform/modules/sha3/src/sha3.c
)
GEN="$TMP/gen_capability_inventory"
LIBS=()
case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*)
        SOURCES+=(
            platform/modules/platform/src/directory_compat.c
            platform/modules/platform/src/positioned_file.c
        )
        LIBS+=( -ladvapi32 )
        GEN="$GEN.exe"
        ;;
esac

if [ ! -f "$DOC" ]; then
    echo "check_capability_inventory_generated: FATAL — missing $DOC" >&2
    echo "  Fix: make docs-capability-inventory" >&2
    exit 2
fi

CC_BIN="${CC:-cc}"
if ! "$CC_BIN" -std=c23 -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE \
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

if ! "$GEN" "$TMP/expected.jsonl" . \
        2>"$TMP/gen.log"; then
    echo "check_capability_inventory_generated: FATAL — derivation failed" >&2
    sed 's/^/    /' "$TMP/gen.log" >&2
    exit 2
fi

meta="$(head -n 1 "$TMP/expected.jsonl")"
field() {
    printf '%s\n' "$meta" | sed -n "s/.*\"$1\":\([0-9][0-9]*\).*/\1/p"
}
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
    exit 2
fi

git ls-files core engine contexts cognition platform contexts/commons/packages |
    awk '/\/include\/.*\.h$/ && $0 !~ /^lib\/test\//' |
    LC_ALL=C sort -u >"$TMP/tracked_headers"
sed -n 's/^{"record":"capability","header":"\([^"]*\)".*/\1/p' \
    "$TMP/expected.jsonl" | LC_ALL=C sort -u >"$TMP/report_headers"
if ! diff -u "$TMP/tracked_headers" "$TMP/report_headers" \
        >"$TMP/headers.diff"; then
    echo "check_capability_inventory_generated: FATAL — public-header census is not exact" >&2
    head -60 "$TMP/headers.diff" | sed 's/^/    /' >&2
    exit 2
fi

catalog_groups="$(awk '
    /^[[:space:]]*ZCL_TEST_GROUP\([[:alnum:]_]+\)[[:space:]]*$/ { n++ }
    /^[[:space:]]*ZCL_SPEC_GROUP\([[:alnum:]_]+\)[[:space:]]*$/ { n++ }
    END { print n + 0 }
' tools/dev/test_group_catalog.def)"
cap_rows="$(grep -c '^{"record":"capability"' \
    "$TMP/expected.jsonl" || true)"
dup_rows="$(grep -c '^{"record":"duplicate"' \
    "$TMP/expected.jsonl" || true)"
inv_rows="$(grep -c '^{"record":"untested_invariant"' \
    "$TMP/expected.jsonl" || true)"
gap_rows="$(grep -c '^{"record":"test_root_gap"' \
    "$TMP/expected.jsonl" || true)"
multi_rows="$(grep -c '^{"record":"multi_arm_symbol"' \
    "$TMP/expected.jsonl" || true)"
arm_rows="$(grep -c '^{"record":"definition_arm"' \
    "$TMP/expected.jsonl" || true)"
if [ "$capabilities" -ne "$cap_rows" ] || [ "$duplicates" -ne "$dup_rows" ] ||
   [ "$invariants" -ne "$inv_rows" ] || [ "$registered_groups" -ne "$catalog_groups" ] ||
   [ "$multi_arm_symbols" -ne "$multi_rows" ] ||
   [ "$definition_arms" -ne "$arm_rows" ] ||
   [ $((roots_found + roots_missing + roots_ambiguous)) -ne "$registered_groups" ] ||
   [ "$root_gaps" -ne "$gap_rows" ] ||
   [ "$gap_rows" -ne $((roots_missing + roots_ambiguous)) ]; then
    echo "check_capability_inventory_generated: FATAL — report accounting is inconsistent" >&2
    echo "  capabilities=$capabilities/$cap_rows duplicates=$duplicates/$dup_rows invariants=$invariants/$inv_rows" >&2
    echo "  multi_arm_symbols=$multi_arm_symbols/$multi_rows definition_arms=$definition_arms/$arm_rows" >&2
    echo "  groups=$registered_groups/$catalog_groups roots=$roots_found+$roots_missing+$roots_ambiguous gaps=$root_gaps/$gap_rows" >&2
    exit 2
fi

for claim in \
    '"generated_artifact_schema":"zcl.generated_artifact.v1"' \
    '"artifact_id":"zcl.code_capability_inventory.v1"' \
    '"generated_by":"tools/gen_capability_inventory.c"' \
    '"regenerate":"make docs-capability-inventory"' \
    '"artifact_id":"zcl.arm_symbol_single_baseline.v1"'; do
    if ! grep -Fq "$claim" <<<"$meta"; then
        echo "check_capability_inventory_generated: FATAL — generated artifact header lacks $claim" >&2
        exit 2
    fi
done

compare_doc() {
    local candidate="$1"
    diff -u "$candidate" "$TMP/expected.jsonl" >"$TMP/diff.log" 2>&1
}

if [ "${1:-}" = "--selftest" ]; then
    if ! compare_doc "$DOC"; then
        echo "check_capability_inventory_generated selftest: FATAL — baseline is stale" >&2
        echo "  Fix: make docs-capability-inventory" >&2
        exit 2
    fi
    cp "$DOC" "$TMP/tampered.jsonl"
    printf '%s\n' '{"record":"handwritten_finding"}' >>"$TMP/tampered.jsonl"
    if compare_doc "$TMP/tampered.jsonl"; then
        echo "check_capability_inventory_generated selftest: FAIL — a hand edit passed" >&2
        exit 1
    fi
    echo "check_capability_inventory_generated selftest: PASS — clean output passes and a hand edit fails"
    exit 0
fi

if ! compare_doc "$DOC"; then
    echo "FAIL: $DOC is stale or hand-edited." >&2
    echo "  Regenerate only with: make docs-capability-inventory" >&2
    head -60 "$TMP/diff.log" | sed 's/^/    /' >&2
    exit 1
fi

echo "check_capability_inventory_generated: clean — $capabilities capabilities; $roots_found registered roots resolved"
