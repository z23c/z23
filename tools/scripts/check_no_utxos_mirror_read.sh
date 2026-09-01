#!/usr/bin/env bash
# Program H enforcement gate — the node.db `utxos` mirror is a demoted read
# surface (OBSERVE-style ratchet).
#
# The canonical UTXO set is the kernel coins store; the node.db `utxos` table is
# an operator-view mirror that Program H4 deletes once no consensus reader
# depends on it. This gate freezes the CURRENT set of app/config files that read
# `FROM utxos`: a NEW such reader fails the build; as Program H4 re-points a
# reader at the kernel its baseline row goes stale and must be removed
# (shrink-only). Scope is the demotion-relevant trees only (app/services,
# app/jobs, app/conditions, engine/composition/src) — explorer/wallet views keep their own
# mirror coupling until H4.
#
# Model: tools/scripts/check_frontier_single_writer.sh (same ratchet discipline).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/repo_shape.sh
source tools/lint/repo_shape.sh

PATTERN='FROM utxos'
BASELINE="${ZCL_NO_UTXOS_MIRROR_READ_BASELINE:-tools/scripts/check_no_utxos_mirror_read_baseline.txt}"
if [ -n "${ZCL_NO_UTXOS_MIRROR_READ_SCAN_ROOTS:-}" ]; then
    read -r -a SCAN_ROOTS <<< "$ZCL_NO_UTXOS_MIRROR_READ_SCAN_ROOTS"
else
    mapfile -t SCAN_ROOTS < <(
        repo_shape_room_dirs services
        repo_shape_room_dirs jobs
        repo_shape_room_dirs conditions
        printf '%s\n' engine/reducer/services engine/reducer/jobs \
            engine/reducer/conditions engine/composition/src
    )
fi

if [ ! -r "$BASELINE" ]; then
    echo "check_no_utxos_mirror_read: FATAL — baseline missing: $BASELINE" >&2
    exit 2
fi
if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    echo "check_no_utxos_mirror_read: FATAL — empty scan-root set" >&2
    exit 2
fi
for root in "${SCAN_ROOTS[@]}"; do
    if [ ! -d "$root" ]; then
        echo "check_no_utxos_mirror_read: FATAL — scan root missing: $root" >&2
        exit 2
    fi
done

declare -A allowed seen
baseline_count=0
while IFS= read -r path; do
    case "$path" in ''|'#'*) continue ;; esac
    if [ -n "${allowed[$path]+x}" ]; then
        echo "check_no_utxos_mirror_read: FATAL — duplicate baseline row: $path" >&2
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
    echo "check_no_utxos_mirror_read: FATAL — grep failed (rc=$grep_rc)" >&2
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
        echo "check_no_utxos_mirror_read: FAIL — new reader(s) of the node.db utxos mirror"
        printf '  %s\n' "${new_violations[@]}"
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "check_no_utxos_mirror_read: FAIL — stale baseline row(s) (reader gone; shrink the baseline)"
        printf '  %s\n' "${stale[@]}"
    fi
    echo "Read the kernel coins store, not the node.db utxos mirror. Baselines"
    echo "shrink only."
    exit 1
fi

echo "check_no_utxos_mirror_read: clean — $baseline_count reviewed reader(s), no new use"
