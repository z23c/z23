# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# two_node_peer_tip.sh — MVP criterion #7 (full claim) harness:
#   "kill -9 mid-block, restart, caught up to PEER-tip within 2 min".
#
# The existing `make test-crash-bootstrap` proves SINGLE-node kill-9 boot
# recovery (no peer). This harness proves the OTHER half of #7's literal
# claim: a node catches up to a REAL PEER over native P2P after a kill-9.
#
# Topology (two disjoint isolated nodes, sharing NO datadir):
#
#   Node A (miner)     : listens on $A_PORT, isolated from the live net by
#                        a dead -connect sink (39999); mines via `generate`.
#   Node B (follower)  : -connect=127.0.0.1:$A_PORT  → connects ONLY to A
#                        (connect-only: no DNS/seeds/auto-zclassicd dial).
#
# Steps:
#   1. Spawn A, mine $SEED_BLOCKS regtest blocks.
#   2. Spawn B (connect-only to A). Assert B SYNCS to A's tip  (≤ $SYNC_DEADLINE s).
#      → proves native P2P peer block sync works at all.
#   3. While B is down, mine $EXTRA_BLOCKS MORE on A (so "catch up to
#      peer-tip" is meaningful). kill -9 B's whole process group, restart B
#      (SAME datadir). Assert B RECOVERS and re-syncs to A's NEW tip
#      (≤ $RESYNC_DEADLINE s).
#   3. Print a single clean verdict: `two-node-peer-tip: PASS` | `FAIL`.
#
# SAFETY (mirrors isolated_node_env.sh + crash_recovery_test.c):
#   - /tmp-only datadirs (mktemp -d under /tmp/zcl23-2node-*).
#   - 39xxx isolation ports ONLY; every chosen port is checked against the
#     live refuse-set AND fail-closed LISTEN-probed before spawn.
#   - Each node spawned through the in-tree C23 process-group launcher → its
#     OWN process group; cleanup
#     kill -KILL's the whole GROUP (no orphan survives a harness crash).
#   - EXIT/INT/TERM trap tears down BOTH groups + BOTH /tmp datadirs,
#     re-asserting each datadir is under /tmp before rm -rf.
#   - Never touches the live node, live datadir, or any live port.
#
# Run:  make test-two-node-peer-tip   (opt-in; NOT in `make ci`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
PROCESS_GROUP_EXEC="${ZCL_PROCESS_GROUP_EXEC:-$REPO_ROOT/build/bin/process-group-exec}"
. "$REPO_ROOT/tools/scripts/port_probe.sh"

# ── Live-port refuse-set (verbatim from isolated_node_env.sh) ──────
TN_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"

# ── Tunables (env-overridable) ─────────────────────────────────────
SEED_BLOCKS="${SEED_BLOCKS:-10}"     # blocks A mines before B joins
EXTRA_BLOCKS="${EXTRA_BLOCKS:-5}"    # blocks A mines while B is killed
SYNC_DEADLINE="${SYNC_DEADLINE:-120}"   # step 2 budget (s)
RESYNC_DEADLINE="${RESYNC_DEADLINE:-120}" # step 3 re-sync budget (s)
RPC_WARMUP="${RPC_WARMUP:-60}"       # per-node RPC warmup budget (s)

# Two disjoint 39xxx quads (A: 39070.., B: 39080..). 39999 is the dead
# sink that keeps A off the live network while still listening for B.
A_PORT=39070; A_RPC=39071; A_FS=39072; A_HTTPS=39073
B_PORT=39080; B_RPC=39081; B_FS=39082; B_HTTPS=39083
DEAD_SINK=39999

# ── State ──────────────────────────────────────────────────────────
TN_DD_A=""; TN_DD_B=""
TN_PGID_A=""; TN_PGID_B=""
TN_PID_A=""; TN_PID_B=""
TN_CLEANED=0

tn_die() { echo "two-node-peer-tip: FATAL: $*" >&2; exit 2; }

# ── Port guards (same discipline as isolated_node_env.sh) ──────────
tn_assert_not_live_port() {
    local p="$1" lp
    for lp in $TN_LIVE_PORTS; do
        [ "$p" = "$lp" ] && tn_die "port $p is in the live refuse-set — refusing"
    done
    return 0
}
tn_assert_port_free() {
    local p="$1" rc
    if z23_tcp_port_listening "$p"; then
        tn_die "port $p is already LISTENING — refusing (operator port math is wrong)"
    else
        rc=$?
    fi
    [ "$rc" -eq 1 ] && return 0
    tn_die "port $p availability is UNOBSERVED — refusing"
}

# ── Cleanup: kill BOTH groups + rm BOTH /tmp datadirs ──────────────
tn_kill_group() {
    local pgid="$1"
    [ -n "$pgid" ] || return 0
    kill -TERM "-$pgid" 2>/dev/null || true
    local i
    for i in $(seq 1 25); do
        kill -0 "-$pgid" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}
tn_rm_datadir() {
    local dd="$1"
    [ -n "$dd" ] && [ -d "$dd" ] || return 0
    case "$dd" in
        /tmp/zcl23-2node-*) rm -rf "$dd" 2>/dev/null || true ;;
        *) echo "two-node-peer-tip: WARN: refusing to rm non-/tmp datadir '$dd'" >&2 ;;
    esac
}
tn_cleanup() {
    local status="$?"
    [ "$TN_CLEANED" = "1" ] && return 0
    TN_CLEANED=1
    tn_kill_group "$TN_PGID_A"
    tn_kill_group "$TN_PGID_B"
    # Belt-and-suspenders: only ever matches our throwaway datadir strings.
    [ -n "$TN_DD_A" ] && pkill -KILL -f -- "-datadir=$TN_DD_A" 2>/dev/null || true
    [ -n "$TN_DD_B" ] && pkill -KILL -f -- "-datadir=$TN_DD_B" 2>/dev/null || true
    if [ "$status" = "0" ]; then
        tn_rm_datadir "$TN_DD_A"
        tn_rm_datadir "$TN_DD_B"
    else
        echo "two-node-peer-tip: preserving failed fixtures: $TN_DD_A $TN_DD_B" >&2
    fi
    return "$status"
}

# ── RPC against a specific isolated node ───────────────────────────
# $1=datadir $2=rpcport $3.. = method/args
tn_rpc() {
    local dd="$1" rp="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$rp" "$RPC_BIN" "$@" 2>/dev/null || true
}
a_rpc() { tn_rpc "$TN_DD_A" "$A_RPC" "$@"; }
b_rpc() { tn_rpc "$TN_DD_B" "$B_RPC" "$@"; }

# Scrape the integer "result" out of a zcl-rpc JSON line.
tn_blockcount() {
    local out
    out="$(tn_rpc "$1" "$2" getblockcount)"
    # result is the first integer after "result":
    printf '%s' "$out" | sed -n 's/.*"result"[: ]*\([0-9-]*\).*/\1/p'
}

# ── Spawn a node in its OWN process group ──────────────────────────
# $1=datadir $2=p2p $3=rpc $4=fs $5=https $6=connect-target
tn_spawn() {
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5" conn="$6"
    "$PROCESS_GROUP_EXEC" "$NODE_BIN" \
        -datadir="$dd" -regtest \
        -port="$p2p" -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        -connect="$conn" \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >"$dd/node.log" 2>&1 &
    echo "$!"   # PID == PGID (setsid leader)
}

# Poll a node's RPC until getblockcount answers, or timeout. $1=dd $2=rpc $3=pid $4=secs
tn_wait_rpc() {
    local dd="$1" rp="$2" pid="$3" secs="$4" deadline t
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "two-node-peer-tip: node (pid $pid) exited during RPC warmup (see $dd/node.log)" >&2
            return 1
        fi
        if [ -f "$dd/.cookie" ]; then
            t="$(tn_blockcount "$dd" "$rp")"
            [ -n "$t" ] && return 0
        fi
        sleep 0.5
    done
    return 1
}

# Poll node ($1 dd, $2 rpc, $3 pid) until its blockcount == $4, or $5 s.
# Echoes the final observed height; returns 0 on match, 1 on timeout.
tn_wait_height() {
    local dd="$1" rp="$2" pid="$3" target="$4" secs="$5" deadline h
    deadline=$(( $(date +%s) + secs ))
    h="?"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "two-node-peer-tip: node (pid $pid) died while waiting for height $target" >&2
            return 1
        fi
        h="$(tn_blockcount "$dd" "$rp")"; [ -n "$h" ] || h="?"
        [ "$h" = "$target" ] && { echo "$h"; return 0; }
        sleep 1
    done
    echo "$h"
    return 1
}

# ── Preflight + setup ──────────────────────────────────────────────
command -v mktemp >/dev/null 2>&1 || tn_die "mktemp not found"
[ -x "$NODE_BIN" ] || tn_die "$NODE_BIN not built — run make first"
[ -x "$RPC_BIN" ]  || tn_die "$RPC_BIN not built — run make zcl-rpc"
[ -x "$PROCESS_GROUP_EXEC" ] || tn_die "$PROCESS_GROUP_EXEC not built — run make process-group-exec"

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "$DEAD_SINK"; do
    tn_assert_not_live_port "$p"
done

TN_DD_A="$(mktemp -d /tmp/zcl23-2node-A-XXXXXX)" || tn_die "mktemp A failed"
TN_DD_B="$(mktemp -d /tmp/zcl23-2node-B-XXXXXX)" || tn_die "mktemp B failed"
case "$TN_DD_A" in /tmp/zcl23-2node-A-*) : ;; *) tn_die "bad A datadir $TN_DD_A" ;; esac
case "$TN_DD_B" in /tmp/zcl23-2node-B-*) : ;; *) tn_die "bad B datadir $TN_DD_B" ;; esac
if [ -n "${HOME:-}" ]; then
    case "$TN_DD_A" in "$HOME"/.zclassic-c23*) tn_die "A datadir under live tree — refusing" ;; esac
    case "$TN_DD_B" in "$HOME"/.zclassic-c23*) tn_die "B datadir under live tree — refusing" ;; esac
fi

# Arm the cleanup trap BEFORE any abortable post-mint step.
trap tn_cleanup EXIT INT TERM

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "$DEAD_SINK"; do
    tn_assert_port_free "$p"
done

echo "two-node-peer-tip: A{dd=$TN_DD_A p2p=$A_PORT rpc=$A_RPC} B{dd=$TN_DD_B p2p=$B_PORT rpc=$B_RPC}"

# ── Step 1: spawn A (miner), seed the chain ────────────────────────
echo "two-node-peer-tip: [1] spawning miner A + seeding $SEED_BLOCKS blocks..."
TN_PID_A="$(tn_spawn "$TN_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
TN_PGID_A="$TN_PID_A"
tn_wait_rpc "$TN_DD_A" "$A_RPC" "$TN_PID_A" "$RPC_WARMUP" \
    || tn_die "miner A RPC never came up (see $TN_DD_A/node.log)"
a_rpc generate "$SEED_BLOCKS" >/dev/null
A_TIP="$(tn_blockcount "$TN_DD_A" "$A_RPC")"
echo "two-node-peer-tip:     A tip after seed = ${A_TIP:-?}"
[ "$A_TIP" = "$SEED_BLOCKS" ] \
    || tn_die "A did not mine to height $SEED_BLOCKS (got ${A_TIP:-?}) — regtest generate broken"

# ── Step 2: spawn B (connect-only to A), assert it syncs ───────────
echo "two-node-peer-tip: [2] spawning follower B (connect-only → A); waiting ≤ ${SYNC_DEADLINE}s for B == $A_TIP..."
TN_PID_B="$(tn_spawn "$TN_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
TN_PGID_B="$TN_PID_B"
tn_wait_rpc "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$RPC_WARMUP" \
    || tn_die "follower B RPC never came up (see $TN_DD_B/node.log)"

STEP2_PASS=no
if B_FINAL="$(tn_wait_height "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$A_TIP" "$SYNC_DEADLINE")"; then
    STEP2_PASS=yes
    echo "two-node-peer-tip:     B synced to A tip $A_TIP over native P2P."
else
    echo "two-node-peer-tip:     B did NOT reach A tip $A_TIP within ${SYNC_DEADLINE}s (stuck at ${B_FINAL:-?})."
    echo "two-node-peer-tip:     B peer view:"; b_rpc getpeerinfo | head -c 400; echo ""
    echo "two-node-peer-tip:     B log tail:"; tail -8 "$TN_DD_B/node.log" 2>/dev/null || true
fi

# ── Step 3: kill-9 B, mine more on A, restart B, assert re-sync ────
STEP3_PASS=no
if [ "$STEP2_PASS" = "yes" ]; then
    echo "two-node-peer-tip: [3] kill-9 B mid-life; A mines +$EXTRA_BLOCKS while B is down..."
    # SIGKILL B's whole process group (mid-block: no graceful shutdown).
    kill -KILL "-$TN_PGID_B" 2>/dev/null || true
    # Reap so the PID is gone before restart.
    wait "$TN_PID_B" 2>/dev/null || true
    TN_PID_B=""; # group dead; restart below sets a fresh one

    a_rpc generate "$EXTRA_BLOCKS" >/dev/null
    NEW_TIP="$(tn_blockcount "$TN_DD_A" "$A_RPC")"
    echo "two-node-peer-tip:     A new tip = ${NEW_TIP:-?} (was $A_TIP)"
    [ "$NEW_TIP" = "$((A_TIP + EXTRA_BLOCKS))" ] \
        || tn_die "A did not advance to $((A_TIP + EXTRA_BLOCKS)) (got ${NEW_TIP:-?})"

    echo "two-node-peer-tip:     restarting B (same datadir); waiting ≤ ${RESYNC_DEADLINE}s for B == $NEW_TIP..."
    TN_PID_B="$(tn_spawn "$TN_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
    TN_PGID_B="$TN_PID_B"
    if ! tn_wait_rpc "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$RPC_WARMUP"; then
        echo "two-node-peer-tip:     B RPC never came back after kill-9 restart (see $TN_DD_B/node.log)"
    elif B_FINAL2="$(tn_wait_height "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$NEW_TIP" "$RESYNC_DEADLINE")"; then
        STEP3_PASS=yes
        echo "two-node-peer-tip:     B recovered + caught up to peer-tip $NEW_TIP after kill-9."
    else
        echo "two-node-peer-tip:     B did NOT re-reach peer-tip $NEW_TIP within ${RESYNC_DEADLINE}s (stuck at ${B_FINAL2:-?})."
        echo "two-node-peer-tip:     B log tail:"; tail -8 "$TN_DD_B/node.log" 2>/dev/null || true
    fi
else
    echo "two-node-peer-tip: [3] SKIPPED — step 2 (initial peer sync) did not pass."
fi

# ── Verdict ────────────────────────────────────────────────────────
echo "two-node-peer-tip: results: initial-sync=$STEP2_PASS  kill9-resync=$STEP3_PASS"
if [ "$STEP2_PASS" = "yes" ] && [ "$STEP3_PASS" = "yes" ]; then
    echo "two-node-peer-tip: PASS"
    exit 0
else
    echo "two-node-peer-tip: FAIL"
    exit 1
fi
