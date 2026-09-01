#!/usr/bin/env bash
# Gate #18: every app/*.c file lives under a framework shape folder.
# Mode: WARN | RATCHET | FAIL (controlled by ZCL_LINT_MODE; default WARN).
#   WARN    — report violations, always exit 0 (Phase 0 measurement).
#   RATCHET — fail only on violations NOT in framework_shape_allowlist.txt
#             (the baseline). Allowlisted violations are tolerated; the
#             allowlist may only shrink. This is the E10 graduation mode.
#   FAIL    — fail on ANY violation, allowlist ignored.
set -euo pipefail

MODE="${ZCL_LINT_MODE:-WARN}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ALLOWLIST="$SCRIPT_DIR/framework_shape_allowlist.txt"

cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source "$SCRIPT_DIR/scan_exclusions.sh"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"

declare -A ALLOWED=()
gate_load_list_file "$ALLOWLIST" ALLOWED

# The shape set is DERIVED from the Makefile's APP_DIRS by repo_shape.sh, not
# spelled out here — a hand-written case arm per shape is a copy of the
# taxonomy that nothing cross-checks.
is_known_shape_path() {
    local path="$1" shape
    local base
    for base in "${ZCL_APP_AUTHORITY_DIRS[@]}"; do
        for shape in "${ZCL_APP_SHAPES[@]}"; do
            case "$path" in
                "$base/$shape/src/"*.c) return 0 ;;
            esac
        done
        case "$path" in
            "$base/"*.c) return 1 ;;
        esac
    done
    return 1
}

scanned=0
violations=0
allowlisted=0

# In RATCHET mode the allowlist IS the baseline: allowlisted files are
# tolerated, non-allowlisted violations fail. In FAIL mode the allowlist
# is ignored (any violation fails).
while IFS= read -r file; do
    scanned=$((scanned + 1))
    if is_known_shape_path "$file"; then
        continue
    fi
    if [[ "$MODE" != "FAIL" && -n "${ALLOWED[$file]:-}" ]]; then
        allowlisted=$((allowlisted + 1))
        continue
    fi
    violations=$((violations + 1))
    echo "$file: not in a known shape folder (expected one of: controllers, services, models, jobs, supervisors, conditions, views)" >&2
done < <(
    for base in "${ZCL_APP_AUTHORITY_DIRS[@]}"; do
        find "$base" -maxdepth 1 -type f -name '*.c' 2>/dev/null
        for shape in "${ZCL_APP_SHAPES[@]}"; do
            find "$base/$shape/src" -maxdepth 1 -type f -name '*.c' \
                2>/dev/null
        done
    done | sort -u
)

echo "[framework_shape_check] scanned $scanned application-shape .c files"
echo "[framework_shape_check] $violations violation(s) found (mode: $MODE)"
if (( allowlisted > 0 )); then
    echo "[framework_shape_check] $allowlisted allowlisted violation(s) ignored"
fi
echo "[framework_shape_check] write to tools/lint/framework_shape_allowlist.txt to allowlist existing violations"

if (( violations > 0 )) && [[ "$MODE" == "FAIL" || "$MODE" == "RATCHET" ]]; then
    exit 1
fi
exit 0
