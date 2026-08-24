#!/usr/bin/env bash
# onion_pair_watch_loop.sh — run the sourced-isolated pair probe on a cycle.
#
#   tools/scripts/onion_pair_watch_loop.sh         # until killed
#   tools/scripts/onion_pair_watch_loop.sh --once  # one cycle
#
# Each cycle: run onion_pair_watch.sh and append its result to the latest
# host-local pair_probe.jsonl line. Telemetry never commits or pushes source
# history.
# flock-serialized so a timer and a long-lived loop cannot overlap.
# Never touches ~/.zclassic-c23. No Python.

set -euo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
WATCH="$REPO_ROOT/tools/scripts/onion_pair_watch.sh"
STATE_DIR="${PAIR_WATCH_STATE_DIR:-$HOME/.local/state/zclassic23-fleetsync}"
LEDGER="${PAIR_PROBE_FILE:-$STATE_DIR/pair_probe.jsonl}"
LOCK="$STATE_DIR/node3.pair.lock"
LOG="$STATE_DIR/pair_watch.log"
ONCE=0

for arg in "$@"; do
    case "$arg" in
        --once) ONCE=1 ;;
        --*) echo "onion-pair-watch-loop: unknown flag: $arg" >&2; exit 2 ;;
        *) echo "onion-pair-watch-loop: unexpected arg: $arg" >&2; exit 2 ;;
    esac
done

mkdir -p "$STATE_DIR"
# Close leftover operator pts before taking the lock so wall(1)/write(1)
# cannot target a logged-in terminal. Flock fd 9 is a file, not a tty.
if [ -r "$REPO_ROOT/tools/scripts/isolated_node_env.sh" ]; then
    # shellcheck source=tools/scripts/isolated_node_env.sh
    . "$REPO_ROOT/tools/scripts/isolated_node_env.sh"
    iso_drop_inherited_ttys
fi
exec 9>"$LOCK"
if ! flock -n 9; then
    echo "onion-pair-watch-loop: lock busy, skipping" >&2
    exit 75
fi

log() {
    printf '%s pair_watch %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

trailing_paired() {
    awk -F'"verdict":"' '
        { v=$2; sub(/".*/,"",v); if (v=="PAIRED") n++; else n=0 }
        END { print n+0 }
    ' "$LEDGER" 2>/dev/null || echo 0
}

last_pair_line() {
    [ -f "$LEDGER" ] || return 0
    tail -n 1 "$LEDGER"
}

cycle() {
    local requested_base
    cd "$REPO_ROOT"
    git fetch origin main --quiet || true
    requested_base=${PAIR_WATCH_PORT_BASE:-39250}
    log "cycle start probe_port_base=$requested_base streak=$(trailing_paired)"
    set +e
    PAIR_PROBE_FILE="$LEDGER" PAIR_WATCH_PORT_BASE="$requested_base" "$WATCH"
    set -e
    log "cycle done streak=$(trailing_paired) line=$(last_pair_line)"
}

if [ "$ONCE" = 1 ]; then
    cycle
    exit 0
fi

while true; do
    cycle || log "cycle error rc=$?"
    sleep "${PAIR_WATCH_SLEEP:-15}"
done
