#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_coins_lookup_nullcheck.sh — ensure controller-level coins lookups
# are gated by the P24.14 chainstate safety guard.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# Overridable for the lint-gate self-test. Production scans the controller
# source tree where RPC/REST handlers can reach chainstate.
CONTROLLERS_DIR="${ZCL_COINS_LOOKUP_SCAN_DIR:-engine/controllers/src}"
mapfile -t scan_files < <(find "$CONTROLLERS_DIR" -type f -name '*.c' "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null | sort)
gate_require_scanned "${#scan_files[@]}" 1 check_coins_lookup_nullcheck \
    "no controller *.c files under '$CONTROLLERS_DIR'"

missing=""
hit_files=0
for file in "${scan_files[@]}"; do
    has_lookup=0
    while IFS= read -r _match; do
        has_lookup=1
    done < <(gate_grep -nE 'coins_view_cache_get_coins[[:space:]]*\(' "$file")

    [ "$has_lookup" = "1" ] || continue
    hit_files=$((hit_files + 1))
    if ! gate_grep -qE 'rpc_require_chainstate_lookup_ready[[:space:]]*\(' "$file"; then
        missing+="$file"$'\n'
    fi
done

missing="${missing%$'\n'}"

if [[ -n "$missing" ]]; then
    echo "check_coins_lookup_nullcheck: missing rpc_require_chainstate_lookup_ready in:"
    echo
    echo "$missing"
    exit 1
fi

gate_require_scanned "$hit_files" 1 check_coins_lookup_nullcheck \
    "no coins_view_cache_get_coins() call sites found; update this gate deliberately if the lookup API moved"

echo "check_coins_lookup_nullcheck: clean — all controller coin lookups guarded ($hit_files files)"
exit 0
