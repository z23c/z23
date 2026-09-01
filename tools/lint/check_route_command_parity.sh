#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — REST route <-> native command parity (OS-B3b).
#
# Every entry in k_api_resource_routes[] (engine/controllers/src/
# api_controller_routes.c) carries a command_path naming the native command
# registry leaf (engine/composition/commands/*.def) that owns the same data/service, or
# "none:<short-reason>" when no leaf owns it yet. This gate proves the
# mapping stays honest as both sides evolve:
#
#   - every non-"none:" command_path must exist as a real LEAF path in
#     engine/composition/commands/*.def (a BRANCH/group node does not count — it has no
#     handler)
#   - every "none:" command_path must be listed in
#     tools/lint/route_command_parity_baseline.txt (shrink-only: a NEW
#     "none:" entry not already in the baseline FAILS; deleting a route or
#     wiring up its native leaf requires removing the baseline line too, so
#     the baseline can only shrink or hold, never silently grow)
#
# Hollow-gate guard: if the route table or the command .def directory
# disappears/empties, the gate exits 2 rather than reporting a vacuous pass.
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

ROUTES_FILE=engine/controllers/src/api_controller_routes.c
BASELINE=tools/lint/route_command_parity_baseline.txt
CMD_DIR=engine/composition/commands

if [ ! -f "$ROUTES_FILE" ]; then
    echo "check_route_command_parity: FATAL — $ROUTES_FILE not found." >&2
    exit 2
fi
if [ ! -d "$CMD_DIR" ]; then
    echo "check_route_command_parity: FATAL — $CMD_DIR not found." >&2
    exit 2
fi

# Extract every command_path string literal that follows an API_ROUTE( call
# in k_api_resource_routes[] — the LAST quoted string argument on the entry
# (the macro's final parameter). Each API_ROUTE(...) call spans multiple
# source lines; join them into one logical line per entry first.
route_command_paths=()
while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    # The command_path is the final "..." literal before the closing ).
    cp=$(printf '%s' "$entry" | grep -oE '"[^"]*"[[:space:]]*\)[[:space:]]*,?[[:space:]]*$' | tail -1 | sed -E 's/^"(.*)"[^"]*$/\1/')
    if [ -z "$cp" ]; then
        echo "check_route_command_parity: FATAL — could not parse command_path from entry:" >&2
        echo "  $entry" >&2
        exit 2
    fi
    route_command_paths+=("$cp")
done < <(awk '
    /^#define/ { next }
    /API_ROUTE\(/ { buf = $0; depth = gsub(/\(/, "(", buf) - gsub(/\)/, ")", buf); collecting = 1; next }
    collecting {
        buf = buf " " $0
        depth += gsub(/\(/, "(", $0) - gsub(/\)/, ")", $0)
        if (depth <= 0) { print buf; collecting = 0 }
    }
' "$ROUTES_FILE")

gate_require_scanned "${#route_command_paths[@]}" 1 \
    "check_route_command_parity" \
    "k_api_resource_routes[] in $ROUTES_FILE parsed to zero entries — the API_ROUTE( call shape likely changed; update this gate's awk/grep."

# Build the set of real command LEAF paths (excludes ZCL_COMMAND_BRANCH
# group nodes, which have no handler and cannot be an honest route owner).
leaf_paths=$(for f in "$CMD_DIR"/*.def; do
    awk '
        /^ZCL_COMMAND_/ {
            match($0, /^ZCL_COMMAND_[A-Z_]+/)
            macro = substr($0, RSTART, RLENGTH)
            want_next = 1
            next
        }
        want_next == 1 {
            if ($0 ~ /^[[:space:]]*"/) {
                line = $0
                gsub(/^[[:space:]]*"/, "", line)
                gsub(/".*/, "", line)
                if (macro != "ZCL_COMMAND_BRANCH") print line
                want_next = 0
            }
        }
    ' "$f"
done | sort -u)

# Same set, held as a shell set for membership tests. Re-scanning the text
# blob per route (`printf '%s\n' "$leaf_paths" | grep -qxF "$cp"`) is unsafe
# under `set -o pipefail`: grep -q exits on its first match, so a match in the
# reader's first chunk closes the pipe while printf still has bytes to write,
# printf dies of SIGPIPE (141), pipefail promotes that to the pipeline status,
# and a REAL leaf gets reported as missing. Measured 4 false failures in 500
# runs at 32 concurrent invocations.
declare -A leaf_set=()
while IFS= read -r _lp; do
    [ -n "$_lp" ] && leaf_set["$_lp"]=1
done <<< "$leaf_paths"

gate_require_scanned "${#leaf_set[@]}" 1 \
    "check_route_command_parity" \
    "$CMD_DIR/*.def parsed to zero leaf paths — the ZCL_COMMAND_* macro shape likely changed; update this gate's awk."

[ -f "$BASELINE" ] || touch "$BASELINE"
declare -A baseline
baseline_count=0
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    baseline["$line"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

fail=0
bad_leaf=()
new_none=()
seen_none=()

for cp in "${route_command_paths[@]}"; do
    case "$cp" in
        none:*)
            seen_none+=("$cp")
            if [ -z "${baseline[$cp]+x}" ]; then
                new_none+=("$cp")
                fail=1
            fi
            ;;
        *)
            if [ -z "${leaf_set["$cp"]+set}" ]; then
                bad_leaf+=("$cp")
                fail=1
            fi
            ;;
    esac
done

# Flag a STALE baseline entry — a "none:" reason that no route emits any
# more (the route was deleted or the mapping got wired up). Keep the
# ratchet honest: shrink the baseline in the same commit.
stale=()
for b in "${!baseline[@]}"; do
    found=0
    for cp in "${seen_none[@]}"; do
        [ "$cp" = "$b" ] && { found=1; break; }
    done
    [ "$found" = "0" ] && stale+=("$b")
done

if [ "$fail" = "0" ] && [ "${#stale[@]}" = "0" ]; then
    echo "check_route_command_parity: clean — ${#route_command_paths[@]} route(s), $((${#route_command_paths[@]} - baseline_count)) mapped to a real leaf, ${baseline_count} grandfathered none:"
    exit 0
fi

echo ""
if [ "${#bad_leaf[@]}" -gt 0 ]; then
    echo "check_route_command_parity: ${#bad_leaf[@]} command_path(s) do NOT name a real leaf in $CMD_DIR/*.def:"
    for v in "${bad_leaf[@]}"; do echo "  $v"; done
    echo ""
    echo "Fix the route's command_path in $ROUTES_FILE to a real leaf path,"
    echo "or (if honestly unmapped) set it to \"none:<short-reason>\" and add"
    echo "that line to $BASELINE."
fi
if [ "${#new_none[@]}" -gt 0 ]; then
    echo "check_route_command_parity: ${#new_none[@]} NEW none: entry(ies) not in the baseline:"
    for v in "${new_none[@]}"; do echo "  $v"; done
    echo ""
    echo "Add each to $BASELINE (one per line) if the route genuinely has no"
    echo "native command leaf yet, or wire the route to a real leaf instead."
fi
if [ "${#stale[@]}" -gt 0 ]; then
    echo "check_route_command_parity: ${#stale[@]} STALE baseline entry(ies) (no route emits this reason any more):"
    for s in "${stale[@]}"; do echo "  $s"; done
    echo ""
    echo "A route was deleted or its command_path got mapped to a real leaf —"
    echo "good. Delete its line from $BASELINE so the ratchet reflects the"
    echo "smaller set."
fi
exit 1
