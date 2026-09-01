#!/usr/bin/env bash
# Gate #20: controllers should not prepare/exec SQLite directly.
# Mode: WARN | RATCHET | FAIL (controlled by ZCL_LINT_MODE; default WARN).
#   WARN    — report violations, always exit 0 (Phase 0 measurement).
#   RATCHET — fail only on a violation in a file NOT listed in
#             no_raw_sqlite_in_controllers_baseline.txt. Baselined files
#             are tolerated; the baseline may only shrink. (E10 graduation.)
#   FAIL    — fail on ANY violation, baseline ignored.
set -euo pipefail

MODE="${ZCL_LINT_MODE:-WARN}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASELINE="$SCRIPT_DIR/no_raw_sqlite_in_controllers_baseline.txt"

cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

# Load baseline (set of relative file paths allowed to carry raw sqlite).
declare -A BASELINED=()
gate_load_list_file "$BASELINE" BASELINED

roots=()
for root in app/controllers; do
    [[ -d "$root" ]] && roots+=("$root")
done
set +e
scan_files=$(find app/controllers -type f \( -name '*.c' -o -name '*.h' \) \
    -print 2>/dev/null)
find_rc=$?
set -e
if (( find_rc != 0 )); then
    echo "check_no_raw_sqlite_in_controllers: FATAL — source enumeration failed (find=$find_rc)" >&2
    exit 2
fi
scan_count=$(awk 'NF { count++ } END { print count + 0 }' <<< "$scan_files")
gate_require_scanned "$scan_count" 1 \
    "check_no_raw_sqlite_in_controllers" \
    "expected controller C/header sources"

set +e
matches=$(grep -rn --include='*.c' --include='*.h' \
    -E '\bsqlite3_prepare_v[23]\b|\bsqlite3_exec\b' \
    "${roots[@]}" "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null)
grep_rc=$?
set -e
if (( grep_rc >= 2 )); then
    echo "check_no_raw_sqlite_in_controllers: FATAL — controller scan failed (grep=$grep_rc)" >&2
    exit 2
fi

# The exact per-height receipt read is model-owned. No controller/service file
# may know BOTH its table and storage-column names. Checking the pair per file
# catches case changes, split string literals, and generic SQL forwarding
# helpers without banning legitimate high-level mentions of the receipt.
set +e
context_files=$(find app/controllers app/services -type f \
    \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null)
context_find_rc=$?
set -e
if (( context_find_rc != 0 )); then
    echo "check_no_raw_sqlite_in_controllers: FATAL — context enumeration failed (find=$context_find_rc)" >&2
    exit 2
fi
context_count=$(awk 'NF { count++ } END { print count + 0 }' <<< "$context_files")
gate_require_scanned "$context_count" 2 \
    "check_no_raw_sqlite_in_controllers.receipt_owner" \
    "expected controller and service C/header sources"

receipt_matches=""
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    set +e
    normalized=$(LC_ALL=C tr '[:upper:]' '[:lower:]' < "$file" | \
        tr -d '"[:space:]')
    normalize_rc=$?
    set -e
    if (( normalize_rc != 0 )); then
        echo "check_no_raw_sqlite_in_controllers: FATAL — receipt-owner normalization failed for $file" >&2
        exit 2
    fi
    if [[ "$normalized" == *view_integrity* &&
          ( "$normalized" == *sha3_hash* ||
            "$normalized" == *height=\?* ) ]]; then
        receipt_matches+="${file}: owns view_integrity storage-column/exact-height knowledge"$'\n'
    fi
done <<< "$context_files"

violations=0
if [[ -n "${matches//[[:space:]]/}" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        # Sync controllers orchestrate model/service calls; they never own
        # ad-hoc SQL. Unlike the remaining grandfathered read-only controller
        # projections, neither an inline exception nor a baseline entry can
        # reopen this dependency.
        if [[ "$file" == app/controllers/src/sync_controller*.c ||
              "$file" == app/controllers/src/sync_controller*.h ||
              "$file" == app/controllers/include/controllers/sync_controller*.h ]]; then
            violations=$((violations + 1))
            echo "$line" >&2
            continue
        fi
        if [[ "$line" == *'// raw-controller-sql-ok'* ]]; then
            continue
        fi
        # In RATCHET mode a baselined file is tolerated. In FAIL mode the
        # baseline is ignored. In WARN mode everything is reported anyway.
        if [[ "$MODE" == "RATCHET" && -n "${BASELINED[$file]:-}" ]]; then
            continue
        fi
        violations=$((violations + 1))
        echo "$line" >&2
    done <<< "$matches"
fi

if [[ -n "${receipt_matches//[[:space:]]/}" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        violations=$((violations + 1))
        echo "$line" >&2
    done <<< "$receipt_matches"
fi

echo "[check_no_raw_sqlite_in_controllers] $violations violation(s) found (mode: $MODE)"
echo "[check_no_raw_sqlite_in_controllers] use projection_* or models; sync-controller sources permit no direct prepare/exec exception; view_integrity storage-column knowledge is model-only"
if [[ "$MODE" == "RATCHET" ]]; then
    echo "[check_no_raw_sqlite_in_controllers] baselined files in tools/lint/no_raw_sqlite_in_controllers_baseline.txt (ratchet may only shrink)"
fi

if (( violations > 0 )) && [[ "$MODE" == "FAIL" || "$MODE" == "RATCHET" ]]; then
    exit 1
fi
exit 0
