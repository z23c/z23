#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Every emitted navigator group must obtain useful purpose text.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"

SRC="${ZCL_GROUP_PURPOSE_SRC:-cognition/modules/codeindex/src/codeindex_group.c}"
[[ -f "$SRC" ]] || { echo "check-group-purpose: missing $SRC" >&2; exit 2; }

extract_array() {
    local name="$1"
    awk -v name="$name" '
        index($0, "static const char *const " name "[]") { inside=1 }
        inside {
            line=$0
            while (match(line, /"[^"]*"/)) {
                print substr(line, RSTART+1, RLENGTH-2)
                line=substr(line, RSTART+RLENGTH)
            }
        }
        inside && /\};/ {inside=0}
    ' "$SRC"
}

mapfile -t c_contexts < <(extract_array k_product_contexts)
gate_require_scanned "${#c_contexts[@]}" "${#ZCL_PRODUCT_CONTEXTS[@]}" \
    check-group-purpose "k_product_contexts[] is incomplete"

printf '%s\n' "${c_contexts[@]}" | sort -u > "${TMPDIR:-/tmp}/z23-group-contexts-c.$$"
printf '%s\n' "${ZCL_PRODUCT_CONTEXTS[@]}" | sort -u > "${TMPDIR:-/tmp}/z23-group-contexts-make.$$"
trap 'rm -f "${TMPDIR:-/tmp}/z23-group-contexts-c.$$" "${TMPDIR:-/tmp}/z23-group-contexts-make.$$"' EXIT
if ! cmp -s "${TMPDIR:-/tmp}/z23-group-contexts-c.$$" \
              "${TMPDIR:-/tmp}/z23-group-contexts-make.$$"; then
    echo "check-group-purpose: k_product_contexts[] differs from PRODUCT_CONTEXTS" >&2
    exit 1
fi

fail=0
scanned=0
for module in "${ZCL_LIB_MODULES[@]}"; do
    scanned=$((scanned + 1))
    if ! grep -qE "module_group_is\\(group, \"$module\"\\)\\) return \"[^\"]" "$SRC"; then
        echo "check-group-purpose: module '$module' has no non-empty purpose" >&2
        fail=1
    fi
done

for root in root core engine contexts cognition platform tools tests; do
    scanned=$((scanned + 1))
    if ! grep -qE "strcmp\\(group, \"$root\"\\) == 0\\) return \"[^\"]" "$SRC"; then
        echo "check-group-purpose: root '$root' has no non-empty purpose" >&2
        fail=1
    fi
done

for shape in "${ZCL_APP_SHAPES[@]}"; do
    scanned=$((scanned + 1))
    if ! grep -qE "group_ends_with\\(group, \"$shape\"\\)\\) return \"[^\"]" "$SRC"; then
        echo "check-group-purpose: shape '$shape' has no non-empty purpose" >&2
        fail=1
    fi
done

# These generic fallbacks cover every non-module room emitted below a physical
# authority. The architecture-tree gate separately proves the room set closed.
for authority in contexts core engine cognition platform; do
    scanned=$((scanned + 1))
    if ! grep -qE "starts_seg\\(group, \"$authority\"\\)\\) return \"[^\"]" "$SRC"; then
        echo "check-group-purpose: authority '$authority' lacks a room fallback" >&2
        fail=1
    fi
done
if ! grep -qE 'group_ends_with\(group, "modules"\)\) return "[^"]' "$SRC"; then
    echo "check-group-purpose: module-room fallback is missing" >&2
    fail=1
fi

gate_require_scanned "$scanned" "$(( ${#ZCL_LIB_MODULES[@]} + 20 ))" \
    check-group-purpose "purpose scan was incomplete"
echo "[check_group_purpose] scanned $scanned architecture purpose contracts"
echo "[check_group_purpose] $fail violation(s) found"
exit "$fail"
