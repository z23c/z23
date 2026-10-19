#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# netdisrupt_two_node_run_and_record.sh — the runner behind
# `make netdisrupt-stopwatch`. Runs the SELF-CONTAINED two-node
# net-disruption RECOVERY drill (tools/scripts/netdisrupt_two_node_drill.sh)
# exactly once and appends ONE JSON line to the SAME durable ledger the
# live-client PROOF B collector writes:
#   ~/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl
# so the single documented judge (`make netdisrupt-stopwatch-report` /
# `z23 ops stopwatch judge`) reads the last line regardless
# of which PROOF B runner produced it.
#
# Ledger line schema is kept identical to
# tools/scripts/netdisrupt_stopwatch_run_and_record.sh so the shared judge
# needs no change: {ts, verdict, exit_code, wall_clock_seconds,
# budget_seconds, cut_seconds, peer, node_bin, build_commit, artifact_dir}.
#   "peer" here names the isolated follower's loopback RPC endpoint
#   (127.0.0.1:<follower-rpc>) — this self-contained variant has no external
#   peer to dial; it spawns its own two-node fixture.
#   verdict is one of pass|fail|skip|seam|stalled-named|error, mapped from
#   the drill's exit code (0/1/2/3/4/other).
#
# Exit contract — DELIBERATELY different from the sibling live-client
# collector (netdisrupt_stopwatch_run_and_record.sh, which is a pure
# timer-safe collector that always exits 0). THIS wrapper is the interactive
# `make netdisrupt-stopwatch` runner, so — after ALWAYS appending the ledger
# line first (evidence is never lost) — it surfaces the drill's verdict the
# same way the coldstart recipe does: SKIP (2) maps to a clean exit 0 (a
# missing precondition is not a verdict), PASS maps to 0, and SEAM (3) /
# STALLED-NAMED (4) / FAIL (1) propagate as a failing runner. The only hard
# wrapper-level failure independent of the drill is an unlockable /
# unappendable ledger.
#
# Env (forwarded to the drill via ZCL_ND2_*; see the drill header for the
# full list): ZCL_ND2_NODE_BIN, ZCL_ND2_RPC_BIN, ZCL_ND2_CUT_SECS,
# ZCL_ND2_BUDGET_SECS, ZCL_ND2_SEED_BLOCKS, ZCL_ND2_GAP_BLOCKS,
# ZCL_ND2_A_BASE, ZCL_ND2_B_BASE, ...  Plus:
#   ZCL_ND_HISTORY_DIR   ledger dir override (default shared with the
#                        live-client collector:
#                        ~/.local/state/zclassic23-netdisrupt-stopwatch)

set -uo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DRILL="$SCRIPT_DIR/netdisrupt_two_node_drill.sh"

NODE_BIN="${ZCL_ND2_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
CUT_SECS="${ZCL_ND2_CUT_SECS:-30}"
BUDGET="${ZCL_ND2_BUDGET_SECS:-120}"

HISTORY_DIR="${ZCL_ND_HISTORY_DIR:-${HOME:-/root}/.local/state/zclassic23-netdisrupt-stopwatch}"
HISTORY_FILE="$HISTORY_DIR/history.jsonl"
mkdir -p "$HISTORY_DIR"

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr '\n' ' '; }
json_string() { printf '"%s"' "$(json_escape "$1")"; }
json_num_or_null() { case "${1:-}" in ''|*[!0-9-]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

build_commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
[ -z "$build_commit" ] && build_commit="unknown"

echo "netdisrupt-two-node-run: bin=$NODE_BIN cut=${CUT_SECS}s budget=${BUDGET}s build_commit=$build_commit"

set +e
out="$(bash "$DRILL" 2>&1)"
rc=$?
set -e
printf '%s\n' "$out"

verdict="error"
case "$rc" in
    0) verdict="pass" ;;
    1) verdict="fail" ;;
    2) verdict="skip" ;;
    3) verdict="seam" ;;
    4) verdict="stalled-named" ;;
esac

wall_clock="$(printf '%s\n' "$out" | sed -n 's/^WALL_CLOCK_SECONDS=\([0-9][0-9]*\)$/\1/p' | tail -1)"
artifact_dir="$(printf '%s\n' "$out" | sed -n 's/^netdisrupt-two-node: artifact=\(.*\)$/\1/p' | tail -1)"
follower_rpc="$(printf '%s\n' "$out" | sed -n 's/.*B{dd=[^ ]* p2p=[0-9]* rpc=\([0-9]*\)}.*/\1/p' | tail -1)"
[ -z "$follower_rpc" ] && follower_rpc="0"
peer_desc="127.0.0.1:${follower_rpc}"

ts="$(date +%s)"
line="$(printf '{"ts":%s,"verdict":%s,"exit_code":%s,"wall_clock_seconds":%s,"budget_seconds":%s,"cut_seconds":%s,"peer":%s,"node_bin":%s,"build_commit":%s,"artifact_dir":%s}' \
    "$ts" "$(json_string "$verdict")" "$rc" "$(json_num_or_null "$wall_clock")" \
    "$(json_num_or_null "$BUDGET")" "$(json_num_or_null "$CUT_SECS")" "$(json_string "$peer_desc")" \
    "$(json_string "$NODE_BIN")" "$(json_string "$build_commit")" "$(json_string "${artifact_dir:-}")")"

append_rc=0
(
    flock -x -w 30 9 || exit 9
    printf '%s\n' "$line" >&9
) 9>>"$HISTORY_FILE" || append_rc=$?
if [ "$append_rc" -ne 0 ]; then
    if [ "$append_rc" -eq 9 ]; then
        echo "netdisrupt-two-node-run: FAIL could not acquire append lock on $HISTORY_FILE within 30s" >&2
    else
        echo "netdisrupt-two-node-run: FAIL could not append to $HISTORY_FILE (rc=$append_rc)" >&2
    fi
    exit 1
fi

echo "netdisrupt-two-node-run: appended file=$HISTORY_FILE verdict=$verdict rc=$rc"
echo "$line"

# Evidence is now durably recorded. Surface the drill verdict to the caller
# the same way the coldstart recipe does: SKIP is a clean exit 0, everything
# else propagates.
if [ "$rc" -eq 2 ]; then
    echo "netdisrupt-two-node-run: SKIP mapped to clean exit 0 (precondition absent — recorded, not a verdict)"
    exit 0
fi
exit "$rc"
