#!/usr/bin/env bash
# Lint gate E6 — one-write-path (RATCHET).
#
# There is one consensus writer: the reducer advances durable cursors and
# authors UTXO deltas. The legacy chain-state write surfaces this gate used
# to ratchet down have already been deleted (the baseline is intentionally
# empty — see tools/scripts/one_write_path_baseline.txt), so this gate now
# guards against regression: any NEW production file/line that writes chain
# state outside the recorded baseline fails the build.
#
# Baseline format:
#   <file>:<line>: <matched source>
#
# Do not add lines to the baseline without an ADR; growing it means a new
# chain writer appeared outside the reducer's single write path.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# Scan roots are overridable via ZCL_OWP_SCAN_ROOTS (space-separated) so the
# lint-gate self-test can point the gate at an EMPTY dir and prove the
# non-empty-floor preflight trips (exit 2) instead of passing hollow.
SCAN_ROOTS="${ZCL_OWP_SCAN_ROOTS:-core engine contexts cognition platform tools}"
# A custom (test) scan root has no 200-file production floor; the meta-gate's
# whole point is to feed an empty/tiny root and watch the floor fire.
if [ -n "${ZCL_OWP_SCAN_ROOTS:-}" ]; then
    SCAN_FLOOR_OVERRIDE=1
fi

BASELINE=tools/scripts/one_write_path_baseline.txt
[ -f "$BASELINE" ] || touch "$BASELINE"

declare -A baseline
baseline_count=0
gate_load_list_file "$BASELINE" baseline baseline_count

pattern='active_chain_set_tip[[:space:]]*\(|coins_view_sqlite_batch_write(_ex)?[[:space:]]*\(|coins_view_cache_flush[[:space:]]*\(|utxo_projection_set_author[[:space:]]*\(|process_new_block[[:space:]]*\(|connect_tip[[:space:]]*\(|disconnect_tip[[:space:]]*\('

# Fail-loud preflight: the scan set MUST be non-empty. If find silently
# produces nothing (a moved/renamed core dir), the loop runs zero times,
# `violations` stays empty, and the gate would print "clean" exit 0 — a
# hollow pass. Assert a known floor instead.
#
# find's nonzero exit (a missing root) is NOT swallowed: it would abort the
# process substitution and leave scan_files empty, which the floor below
# catches LOUD. We pass the roots through `find` directly so a renamed root
# makes find error → empty array → floor trip.
mapfile -t scan_files < <(find $SCAN_ROOTS -type f \( -name '*.c' -o -name '*.h' \) \
    ! -path '*/test/*' \
    ! -path 'tools/scripts/*' \
    ! -path 'tools/lint/*' \
    "${LINT_FIND_PRUNE_ARGS[@]}" \
    2>/dev/null | sort)
SCAN_FLOOR=200
[ -n "${SCAN_FLOOR_OVERRIDE:-}" ] && SCAN_FLOOR=1
gate_require_scanned "${#scan_files[@]}" "$SCAN_FLOOR" check_one_write_path \
    "find roots: $SCAN_ROOTS"

# One batched grep over the whole scan set instead of a fork per file.
# `grep -H` emits FILE:LINE:content, byte-identical to the old
# printf '%s:%s' "$f" "<LINE:content>" key, so every downstream filter
# (comment/marker skip, baseline dedup) is unchanged. gate_grep still makes a
# real grep error (exit >=2) FATAL, and the gate_require_scanned floor above
# still catches a hollow (empty) scan before we ever get here.
violations=()
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    key=$(printf '%s\n' "$hit" | sed -E 's/[[:space:]]+/ /g')
    line_content="${key#*:}"
    line_content="${line_content#*:}"
    trimmed="${line_content#"${line_content%%[![:space:]]*}"}"
    case "$trimmed" in
        '/*'*|'*'*|'//'*) continue ;;
    esac
    if printf '%s\n' "$line_content" | grep -qE '//[[:space:]]*one-write-path-ok:[A-Za-z][A-Za-z0-9_-]*'; then
        continue
    fi
    if [ -n "${baseline[$key]+x}" ]; then
        continue
    fi
    violations+=("$key")
done < <(gate_grep -nHE "$pattern" "${scan_files[@]}")

if [ "${#violations[@]}" -eq 0 ]; then
    echo "check_one_write_path: clean — $baseline_count grandfathered write surface(s), no new ones"
    exit 0
fi

echo ""
echo "check_one_write_path: ${#violations[@]} NEW chain-state write surface(s)"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Consensus chain writes must collapse to the reducer/log path. Move the"
echo "write behind the existing reducer/stage path, delete the legacy writer,"
echo "or add a tightly-scoped '// one-write-path-ok:<tag>' marker only for a"
echo "non-authoritative compatibility wrapper."
exit 1
