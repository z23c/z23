#!/usr/bin/env bash
# Lint gate E7 — no-authoritative-RAM-state (RATCHET).
#
# Consensus authority must live in the log, projections, and durable cursors.
# In-memory chain indexes can exist only as derived caches. This gate blocks
# new direct access to active_chain internals and new global/static active_chain
# instances, both of which make RAM look authoritative again.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

BASELINE=tools/scripts/no_authoritative_ram_state_baseline.txt
[ -f "$BASELINE" ] || touch "$BASELINE"

declare -A baseline
baseline_count=0
gate_load_list_file "$BASELINE" baseline baseline_count

pattern='(\.|->)chain_active\.(height|chain|capacity)|(^|[[:space:]])static[[:space:]]+struct[[:space:]]+active_chain[[:space:]]+[A-Za-z_][A-Za-z0-9_]*|(^|[[:space:]])struct[[:space:]]+active_chain[[:space:]]+g_[A-Za-z_][A-Za-z0-9_]*'

mapfile -t scan_files < <(find core engine contexts cognition platform tools -type f \( -name '*.c' -o -name '*.h' \) \
    ! -path '*/test/*' \
    ! -path 'tools/scripts/*' \
    ! -path 'tools/lint/*' \
    "${LINT_FIND_PRUNE_ARGS[@]}" \
    | sort)

# One batched grep over the whole scan set instead of a fork per file.
# `grep -H` emits FILE:LINE:content, byte-identical to the old
# printf '%s:%s' "$f" "<LINE:content>" key, so the marker skip and baseline
# dedup below are unchanged. `</dev/null` keeps grep from reading stdin (and
# hanging) in the degenerate empty-scan case; `|| true` masks the exit-1
# no-match exactly as the per-file `grep ... || true` did.
violations=()
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    key=$(printf '%s\n' "$hit" | sed -E 's/[[:space:]]+/ /g')
    line_content="${key#*:}"
    line_content="${line_content#*:}"
    if printf '%s\n' "$line_content" | grep -qE '//[[:space:]]*ram-state-ok:[A-Za-z][A-Za-z0-9_-]*'; then
        continue
    fi
    if [ -n "${baseline[$key]+x}" ]; then
        continue
    fi
    violations+=("$key")
done < <(grep -nHE "$pattern" "${scan_files[@]}" </dev/null || true)

if [ "${#violations[@]}" -eq 0 ]; then
    echo "check_no_authoritative_ram_state: clean — $baseline_count grandfathered RAM-authority surface(s), no new ones"
    exit 0
fi

echo ""
echo "check_no_authoritative_ram_state: ${#violations[@]} NEW RAM-authority surface(s)"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Use active_chain accessors for derived reads, and keep authoritative"
echo "consensus state in log/projection/cursor storage. If this is a deliberate"
echo "derived cache, add '// ram-state-ok:<tag>' with the invariant."
exit 1
