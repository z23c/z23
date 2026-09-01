#!/usr/bin/env bash
# Lint gate E2 — services return struct zcl_result, not bare bool/int (RATCHET).
#
# DEFENSIVE_CODING.md §2: "every function that can fail returns a result
# type — not bare bool". A `return false;` with no context leaves the
# caller blind. The standard is `struct zcl_result` (platform/modules/util/include/
# util/result.h): a {ok, code, message, file, line} carrier that forces
# the failure reason to travel with the failure.
#
# The tree is ~98% bare-bool today (67 of 68 service files), so this gate
# ratchets at FILE granularity rather than blocking on a mass migration:
#   - A service .c file is "result-clean" if it references `struct
#     zcl_result` anywhere (it has adopted the result type).
#   - Every file that does NOT is grandfathered via the baseline.
#   - A NEW engine/services/src/*.c file that is not in the baseline and does
#     not use `struct zcl_result` fails the gate.
# The baseline may only shrink: migrate a file to zcl_result, delete its
# baseline line, and the gate then enforces that it stays migrated.
#
# Override: a service file that genuinely owns no fallible service surface
# (a pure-table or registry helper) may carry a top-of-file marker
# `// one-result-type-ok:<tag>` (no space after the colon, non-empty tag).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

BASELINE=tools/scripts/one_result_type_baseline.txt
[ -f "$BASELINE" ] || touch "$BASELINE"

declare -A baseline
baseline_count=0
gate_load_list_file "$BASELINE" baseline baseline_count

fail=0
new_violations=()
stale_baseline=()

while IFS= read -r f; do
    uses_result=0
    grep -qE 'struct[[:space:]]+zcl_result' "$f" && uses_result=1
    has_override=0
    grep -qE '//[[:space:]]*one-result-type-ok:[A-Za-z][A-Za-z0-9_-]*' "$f" && has_override=1

    if [ -n "${baseline[$f]+x}" ]; then
        # Grandfathered. If it has since adopted zcl_result, the baseline
        # line is stale and should be deleted (ratchet-forward hygiene).
        if [ "$uses_result" = "1" ]; then
            stale_baseline+=("$f")
        fi
        continue
    fi

    # Not baselined: must use zcl_result (or carry the override).
    if [ "$uses_result" = "0" ] && [ "$has_override" = "0" ]; then
        new_violations+=("$f")
        fail=1
    fi
done < <(find engine/services/src -type f -name '*.c' | sort)

if [ "$fail" = "0" ]; then
    echo "check_one_result_type: clean — ${baseline_count} grandfathered service file(s), no new bare-result files"
    if [ "${#stale_baseline[@]}" -gt 0 ]; then
        echo "  note: ${#stale_baseline[@]} baselined file(s) now use zcl_result — delete their baseline line(s) to ratchet forward:"
        for v in "${stale_baseline[@]}"; do echo "    $v"; done
    fi
    exit 0
fi

echo ""
echo "check_one_result_type: ${#new_violations[@]} NEW service file(s) not using struct zcl_result"
echo ""
for v in "${new_violations[@]}"; do
    echo "  $v"
done
echo ""
echo "New service functions must return struct zcl_result (util/result.h) so"
echo "the failure reason travels with the failure. Fix options:"
echo "  1. Return struct zcl_result from the file's fallible functions"
echo "     (ZCL_OK / ZCL_ERR(code, fmt, ...))."
echo "  2. If the file owns no fallible service surface, add a top-of-file"
echo "     marker '// one-result-type-ok:<tag>' explaining why."
echo "  3. As a last resort, add the path to $BASELINE"
echo "     (a reviewable line; the baseline must only shrink)."
exit 1
