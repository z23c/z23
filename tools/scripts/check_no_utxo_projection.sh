#!/usr/bin/env bash
# Program H enforcement gate — the event-sourced UTXO projection is a demoted
# third UTXO copy (OBSERVE-style ratchet).
#
# The canonical UTXO set is the kernel coins store (coins_kv); utxo_projection
# (+ coins_view_projection and the EV_UTXO_ADD / EV_UTXO_SPEND emit path) is a
# third writable copy Program H1 deletes. This gate freezes their CURRENT
# consumer set: a NEW file referencing utxo_projection_* or the EV_UTXO_* events
# fails the build; as Program H1 deletes a consumer its baseline row goes stale
# and must be removed (shrink-only). When the baseline is comments-only the
# projection is gone and this becomes a zero-debt invariant.
#
# Model: tools/scripts/check_frontier_single_writer.sh (same ratchet discipline).
set -euo pipefail

cd "$(dirname "$0")/../.."

PATTERN='utxo_projection_|EV_UTXO_ADD|EV_UTXO_SPEND'
BASELINE="${ZCL_NO_UTXO_PROJECTION_BASELINE:-tools/scripts/check_no_utxo_projection_baseline.txt}"
SCAN_ROOTS_TEXT="${ZCL_NO_UTXO_PROJECTION_SCAN_ROOTS:-core engine contexts cognition platform}"
read -r -a SCAN_ROOTS <<< "$SCAN_ROOTS_TEXT"

if [ ! -r "$BASELINE" ]; then
    echo "check_no_utxo_projection: FATAL — baseline missing: $BASELINE" >&2
    exit 2
fi
if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    echo "check_no_utxo_projection: FATAL — empty scan-root set" >&2
    exit 2
fi
for root in "${SCAN_ROOTS[@]}"; do
    if [ ! -d "$root" ]; then
        echo "check_no_utxo_projection: FATAL — scan root missing: $root" >&2
        exit 2
    fi
done

declare -A allowed seen
baseline_count=0
while IFS= read -r path; do
    case "$path" in ''|'#'*) continue ;; esac
    if [ -n "${allowed[$path]+x}" ]; then
        echo "check_no_utxo_projection: FATAL — duplicate baseline row: $path" >&2
        exit 2
    fi
    allowed[$path]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

set +e
matches=$(grep -rlE --include='*.c' --include='*.h' -- "$PATTERN" "${SCAN_ROOTS[@]}")
grep_rc=$?
set -e
if [ "$grep_rc" -ge 2 ]; then
    echo "check_no_utxo_projection: FATAL — grep failed (rc=$grep_rc)" >&2
    exit 2
fi

new_violations=()
while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in
        */test/*|*/tests/*|*/include/*|*_test.*) continue ;;
    esac
    if [ -n "${allowed[$path]+x}" ]; then
        seen[$path]=1
    else
        new_violations+=("$path")
    fi
done <<< "$matches"

stale=()
for path in "${!allowed[@]}"; do
    if [ -z "${seen[$path]+x}" ]; then
        stale+=("$path")
    fi
done

if [ "${#new_violations[@]}" -gt 0 ] || [ "${#stale[@]}" -gt 0 ]; then
    if [ "${#new_violations[@]}" -gt 0 ]; then
        echo "check_no_utxo_projection: FAIL — new consumer(s) of the demoted UTXO projection"
        printf '  %s\n' "${new_violations[@]}"
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "check_no_utxo_projection: FAIL — stale baseline row(s) (consumer gone; shrink the baseline)"
        printf '  %s\n' "${stale[@]}"
    fi
    echo "The kernel coins store is the one UTXO ledger; do not add users of"
    echo "utxo_projection / EV_UTXO_*. Baselines shrink only."
    exit 1
fi

echo "check_no_utxo_projection: clean — $baseline_count reviewed consumer(s), no new use"
