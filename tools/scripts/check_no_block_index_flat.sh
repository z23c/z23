#!/usr/bin/env bash
# Program H enforcement gate — the flat/LevelDB/SQLite header-index caches are
# a demoted representation (OBSERVE-style ratchet).
#
# The canonical header ledger is the reducer stage logs; the ONE surviving
# derived header snapshot is block_index_projection (event-sourced, kill-9
# durable, reorg-native). The flat block_index.bin save/load, the node.db
# block_index_cache, the LevelDB block-tree writer, and the blocks-table
# hydrate rung are all Program-H deletion targets. This gate freezes their
# CURRENT consumer set: a NEW file that touches one of these primitives fails
# the build; as each Program-H wave deletes a consumer, its baseline row goes
# stale and must be removed (shrink-only). When the baseline reaches
# comments-only the primitives are gone and this becomes a zero-debt invariant.
#
# Model: tools/scripts/check_frontier_single_writer.sh (same ratchet discipline).
set -euo pipefail

cd "$(dirname "$0")/../.."

PATTERN='save_block_index_flat|load_block_index_flat|save_block_index_recent|load_block_index_sqlite|block_tree_db_write_block_index|boot_dispatch_blocks_table_hydrate'
BASELINE="${ZCL_NO_BLOCK_INDEX_FLAT_BASELINE:-tools/scripts/check_no_block_index_flat_baseline.txt}"
SCAN_ROOTS_TEXT="${ZCL_NO_BLOCK_INDEX_FLAT_SCAN_ROOTS:-core engine contexts cognition platform}"
read -r -a SCAN_ROOTS <<< "$SCAN_ROOTS_TEXT"

if [ ! -r "$BASELINE" ]; then
    echo "check_no_block_index_flat: FATAL — baseline missing: $BASELINE" >&2
    exit 2
fi
if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    echo "check_no_block_index_flat: FATAL — empty scan-root set" >&2
    exit 2
fi
for root in "${SCAN_ROOTS[@]}"; do
    if [ ! -d "$root" ]; then
        echo "check_no_block_index_flat: FATAL — scan root missing: $root" >&2
        exit 2
    fi
done

declare -A allowed seen
baseline_count=0
while IFS= read -r path; do
    case "$path" in ''|'#'*) continue ;; esac
    if [ -n "${allowed[$path]+x}" ]; then
        echo "check_no_block_index_flat: FATAL — duplicate baseline row: $path" >&2
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
    echo "check_no_block_index_flat: FATAL — grep failed (rc=$grep_rc)" >&2
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
        echo "check_no_block_index_flat: FAIL — new consumer(s) of a demoted header cache"
        printf '  %s\n' "${new_violations[@]}"
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "check_no_block_index_flat: FAIL — stale baseline row(s) (consumer gone; shrink the baseline)"
        printf '  %s\n' "${stale[@]}"
    fi
    echo "Do not add new users of the flat/LevelDB/SQLite header caches; feed"
    echo "the event log and read block_index_projection. Baselines shrink only."
    exit 1
fi

echo "check_no_block_index_flat: clean — $baseline_count reviewed consumer(s), no new use"
