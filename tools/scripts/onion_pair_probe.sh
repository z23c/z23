#!/usr/bin/env bash
# onion_pair_probe.sh — node3's always-on pair-probe ledger entry point.
#
# This is the instrument ONION_DIAL_GAP.md assigns to node3: run the
# isolated two-node onion pair from ANY checkout. Isolation is sourced,
# not executed. Recurring telemetry is JSONL under XDG state — this
# script does not commit, push, or write deploy/devfleet/. The client Tor can
# bootstrap target-free in parallel; its onion dial is gated on observed
# descriptor upload and client readiness, not on hostname-file presence.
#
# Usage:
#   tools/scripts/onion_pair_probe.sh
#   tools/scripts/onion_pair_probe.sh --selftest
#
# Environment:
#   PAIR_PROBE_FILE   JSONL path (default: $XDG_STATE_HOME/zclassic23-referee/pair_probe.jsonl)
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
case "${1:-}" in
    --selftest)
        exec "$ROOT/tools/scripts/onion_pair_watch.sh" --selftest
        ;;
    --*)
        echo "onion_pair_probe: unknown flag: $1" >&2
        exit 2
        ;;
esac
exec "$ROOT/tools/scripts/onion_pair_watch.sh"
