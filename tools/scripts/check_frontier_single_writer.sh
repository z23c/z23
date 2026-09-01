#!/usr/bin/env bash
# Architecture gate — one canonical writer per durable frontier.
#
# The manifest names each frontier, its canonical owner basename, and the ERE
# that identifies a write. Existing debt is explicit in the ratchet baseline;
# any new non-owner writer fails. As Q2 removes cloned writers, delete their
# baseline rows until this becomes a zero-debt hard invariant.
set -euo pipefail

cd "$(dirname "$0")/../.."

MANIFEST="${ZCL_FRONTIER_MANIFEST:-tools/scripts/arch_frontier_owners.tsv}"
BASELINE="${ZCL_FRONTIER_BASELINE:-tools/scripts/frontier_single_writer_baseline.tsv}"
SCAN_ROOTS_TEXT="${ZCL_FRONTIER_SCAN_ROOTS:-core engine contexts cognition platform}"
read -r -a SCAN_ROOTS <<< "$SCAN_ROOTS_TEXT"

if [ ! -r "$MANIFEST" ] || [ ! -r "$BASELINE" ]; then
    echo "check_frontier_single_writer: FATAL — manifest or baseline missing" >&2
    echo "  manifest=$MANIFEST baseline=$BASELINE" >&2
    exit 2
fi
if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    echo "check_frontier_single_writer: FATAL — empty scan-root set" >&2
    exit 2
fi
for root in "${SCAN_ROOTS[@]}"; do
    if [ ! -d "$root" ]; then
        echo "check_frontier_single_writer: FATAL — scan root missing: $root" >&2
        exit 2
    fi
done

declare -A allowed seen manifest_frontiers
baseline_count=0
while IFS=$'\t' read -r frontier path extra; do
    case "$frontier" in ''|'#'*) continue ;; esac
    if [ -z "$path" ] || [ -n "$extra" ]; then
        echo "check_frontier_single_writer: FATAL — malformed baseline row: $frontier" >&2
        exit 2
    fi
    key="$frontier"$'\t'"$path"
    if [ -n "${allowed[$key]+x}" ]; then
        echo "check_frontier_single_writer: FATAL — duplicate baseline row: $key" >&2
        exit 2
    fi
    allowed[$key]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

manifest_count=0
new_violations=()
while IFS=$'\t' read -r frontier owner write_pattern extra; do
    case "$frontier" in ''|'#'*) continue ;; esac
    if [ -z "$owner" ] || [ -z "$write_pattern" ] || [ -n "$extra" ]; then
        echo "check_frontier_single_writer: FATAL — malformed manifest row: $frontier" >&2
        exit 2
    fi
    if [ -n "${manifest_frontiers[$frontier]+x}" ]; then
        echo "check_frontier_single_writer: FATAL — duplicate frontier: $frontier" >&2
        exit 2
    fi
    manifest_frontiers[$frontier]=1
    manifest_count=$((manifest_count + 1))

    mapfile -t owners < <(find "${SCAN_ROOTS[@]}" -type f -name "$owner" | sort)
    if [ "${#owners[@]}" -ne 1 ]; then
        echo "check_frontier_single_writer: FATAL — frontier $frontier owner" >&2
        echo "  expected exactly one $owner, found ${#owners[@]}" >&2
        exit 2
    fi

    set +e
    matches=$(grep -rlE --include='*.c' --include='*.h' -- "$write_pattern" \
        "${SCAN_ROOTS[@]}")
    grep_rc=$?
    set -e
    if [ "$grep_rc" -ge 2 ]; then
        echo "check_frontier_single_writer: FATAL — grep failed for $frontier (rc=$grep_rc)" >&2
        exit 2
    fi

    while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in
            */test/*|*/tests/*|*/include/*|*_test.*) continue ;;
        esac
        [ "$(basename "$path")" = "$owner" ] && continue
        key="$frontier"$'\t'"$path"
        if [ -n "${allowed[$key]+x}" ]; then
            seen[$key]=1
        else
            new_violations+=("$frontier: $path (owner: ${owners[0]})")
        fi
    done <<< "$matches"
done < "$MANIFEST"

if [ "$manifest_count" -eq 0 ]; then
    echo "check_frontier_single_writer: FATAL — manifest contains no frontiers" >&2
    exit 2
fi

stale=()
for key in "${!allowed[@]}"; do
    frontier="${key%%$'\t'*}"
    if [ -z "${manifest_frontiers[$frontier]+x}" ]; then
        stale+=("$key (frontier absent from manifest)")
    elif [ -z "${seen[$key]+x}" ]; then
        stale+=("$key (writer gone; shrink the baseline)")
    fi
done

if [ "${#new_violations[@]}" -gt 0 ] || [ "${#stale[@]}" -gt 0 ]; then
    if [ "${#new_violations[@]}" -gt 0 ]; then
        echo "check_frontier_single_writer: FAIL — new non-owner writer(s)"
        printf '  %s\n' "${new_violations[@]}"
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "check_frontier_single_writer: FAIL — stale baseline row(s)"
        printf '  %s\n' "${stale[@]}"
    fi
    echo "Move writes behind the manifest owner; never baseline new debt."
    exit 1
fi

echo "check_frontier_single_writer: clean — $manifest_count frontier(s), $baseline_count reviewed debt writer(s), no new clones"
