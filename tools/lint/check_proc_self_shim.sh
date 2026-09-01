#!/usr/bin/env bash
# Gate — no raw /proc/self/* or /proc/uptime reads outside platform/modules/platform/
# (Rung 1, docs/adr/0003-os-substrate-verdict.md). RATCHET: a file in
# tools/lint/proc_self_shim_baseline.txt is grandfathered; any OTHER file
# with a match fails. Shrink the baseline as sites migrate onto
# platform/os_proc.h — never add to it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASELINE="$SCRIPT_DIR/proc_self_shim_baseline.txt"

cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

roots=()
for root in app config lib tools; do
    [[ -d "$root" ]] && roots+=("$root")
done

declare -A baseline
gate_load_list_file "$BASELINE" baseline

matches=$(
    grep -rln --include='*.c' -E '"/proc/self|"/proc/uptime' \
        "${roots[@]}" "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
    | grep -v '^platform/modules/platform/' \
    || true
)

violations=()
if [[ -n "${matches//[[:space:]]/}" ]]; then
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        [[ -n "${baseline[$f]:-}" ]] && continue
        violations+=("$f")
    done <<< "$matches"
fi

if [[ "${#violations[@]}" -eq 0 ]]; then
    echo "check_proc_self_shim: clean — no new raw /proc/self or /proc/uptime reads"
    exit 0
fi

echo "check_proc_self_shim: raw /proc/self or /proc/uptime read(s) outside platform/modules/platform/, not in $BASELINE:" >&2
for v in "${violations[@]}"; do echo "  $v" >&2; done
echo "" >&2
echo "Route through platform/os_proc.h, or add the file to $BASELINE with a reason if genuinely exempt (e.g. async-signal-safety, per engine/modules/sim/src/postmortem.c:1040)." >&2
exit 1
