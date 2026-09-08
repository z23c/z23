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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
JSONQ_BIN="$REPO_ROOT/build/bin/jsonq"
PROCESS_GROUP_EXEC="${ZCL_PROCESS_GROUP_EXEC:-$REPO_ROOT/build/bin/process-group-exec}"
tn_resolve_bin() {
    local p="$1"
    if [ -x "$p" ]; then
        printf '%s' "$p"
        return 0
    fi
    if [ -x "$p.exe" ]; then
        printf '%s' "$p.exe"
        return 0
    fi
    printf '%s' "$p"
}
NODE_BIN="$(tn_resolve_bin "$NODE_BIN")"
RPC_BIN="$(tn_resolve_bin "$RPC_BIN")"
JSONQ_BIN="$(tn_resolve_bin "$JSONQ_BIN")"
PROCESS_GROUP_EXEC="$(tn_resolve_bin "$PROCESS_GROUP_EXEC")"
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
    # Positive PID first: Windows Job Object supervisors reap descendants
    # when the owner process exits. Negative PGID remains the POSIX path.
    # taskkill /T is the Win32 process-tree equivalent of kill -PGID.
    if command -v taskkill >/dev/null 2>&1; then
        taskkill /F /T /PID "$pgid" >/dev/null 2>&1 || true
    fi
    kill -TERM "$pgid" 2>/dev/null || true
    kill -TERM "-$pgid" 2>/dev/null || true
    local i
    for i in $(seq 1 25); do
        kill -0 "$pgid" 2>/dev/null || kill -0 "-$pgid" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "$pgid" 2>/dev/null || true
    kill -KILL "-$pgid" 2>/dev/null || true
    if command -v taskkill >/dev/null 2>&1; then
        taskkill /F /T /PID "$pgid" >/dev/null 2>&1 || true
    fi
}
tn_rm_datadir() {
    local dd="$1" base resolved scratch
    [ -n "$dd" ] && [ -d "$dd" ] || return 0
    scratch="${TN_TMP:-}"
    [ -n "$scratch" ] || {
        echo "two-node-peer-tip: WARN: refusing to rm without scratch root '$dd'" >&2
        return 0
    }
    scratch="$(cd "$scratch" && pwd -P)" || return 0
    resolved="$(cd "$dd" && pwd -P)" || return 0
    case "$resolved" in
        "$scratch"/*) ;;
        *)
            echo "two-node-peer-tip: WARN: refusing to rm datadir outside scratch root '$dd'" >&2
            return 0
            ;;
    esac
    base="$(basename "$dd")"
    case "$base" in
        zcl23-2node-*) rm -rf "$dd" 2>/dev/null || true ;;
        *) echo "two-node-peer-tip: WARN: refusing to rm unexpected datadir '$dd'" >&2 ;;
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

tn_result() {
    local dd="$1" rp="$2" out error; shift 2
    out="$(ZCL_DATADIR="$dd" ZCL_RPCPORT="$rp" "$RPC_BIN" "$@" 2>/dev/null)" || return 1
    error="$(printf '%s' "$out" | "$JSONQ_BIN" raw error 2>/dev/null)" || return 1
    [ "$error" = null ] || return 1
    printf '%s' "$out" | "$JSONQ_BIN" raw result 2>/dev/null
}
tn_blockcount() {
    local out
    out="$(tn_result "$1" "$2" getblockcount)" || return 1
    case "$out" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$out"
}
tn_blockhash() {
    local out
    out="$(tn_result "$1" "$2" getblockhash "$3")" || return 1
    [ "${#out}" = 66 ] || return 1
    case "$out" in \"*\") out="${out#\"}"; out="${out%\"}" ;; *) return 1 ;; esac
    case "$out" in *[!0-9a-f]*) return 1 ;; esac
    printf '%s\n' "$out"
}

# ── Spawn a node in its OWN process group ──────────────────────────
# $1=datadir $2=p2p $3=rpc $4=fs $5=https $6=connect-target
tn_node_log() { printf '%s.node.log' "$1"; }

tn_spawn() {
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5" conn="$6"
    "$PROCESS_GROUP_EXEC" "$NODE_BIN" \
        -datadir="$dd" -regtest \
        -port="$p2p" -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        -connect="$conn" \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >"$(tn_node_log "$dd")" 2>&1 &
    echo "$!"   # PID == PGID (setsid leader / Windows job owner)
}

# Poll against an absolute deadline shared with the subsequent tip check.
tn_wait_rpc() {
    local dd="$1" rp="$2" pid="$3" deadline="$4" t
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "two-node-peer-tip: node (pid $pid) exited during RPC warmup (see $(tn_node_log "$dd"))" >&2
            return 1
        fi
        if [ -f "$dd/.cookie" ]; then
            t="$(tn_blockcount "$dd" "$rp")" || t=''
            [ -n "$t" ] && [ "$(date +%s)" -lt "$deadline" ] && return 0
        fi
        sleep 0.5
    done
    return 1
}

# Poll for the exact peer tip ($4 height, $6 hash) before absolute deadline $5.
# Echoes the final observed height; returns 0 on match, 1 on timeout.
tn_wait_height() {
    local dd="$1" rp="$2" pid="$3" target="$4" deadline="$5" expected="$6" h hash
    h="?"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "two-node-peer-tip: node (pid $pid) died while waiting for height $target" >&2
            return 1
        fi
        h="$(tn_blockcount "$dd" "$rp")" || h='?'
        if [ "$h" = "$target" ]; then
            hash="$(tn_blockhash "$dd" "$rp" "$target")" || hash=''
            if [ "$hash" = "$expected" ] && [ "$(date +%s)" -lt "$deadline" ]; then
                echo "$h"
                return 0
            fi
        fi
        sleep 1
    done
    echo "$h"
    return 1
}

# ── Preflight + setup ──────────────────────────────────────────────
# Sourcing exposes the same pollers to local refusal/deadline fixtures.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
command -v mktemp >/dev/null 2>&1 || tn_die "mktemp not found"
[ -x "$NODE_BIN" ] || tn_die "$NODE_BIN not built — run make first"
[ -x "$RPC_BIN" ]  || tn_die "$RPC_BIN not built — run make zcl-rpc"
[ -x "$JSONQ_BIN" ] || tn_die "$JSONQ_BIN not built — run make jsonq"
[ -x "$PROCESS_GROUP_EXEC" ] || tn_die "$PROCESS_GROUP_EXEC not built — run make process-group-exec"
case "$RESYNC_DEADLINE" in ''|*[!0-9]*) tn_die 'recovery budget must be numeric' ;; esac
[ "$RESYNC_DEADLINE" -gt 0 ] && [ "$RESYNC_DEADLINE" -le 120 ] ||
    tn_die 'recovery budget must be within the 120-second MVP bound'

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "$DEAD_SINK"; do
    tn_assert_not_live_port "$p"
done

# Native Windows nodes cannot create owner-only stores under MSYS /tmp.
# MSYS bash often strips LOCALAPPDATA; HOME/AppData/Local/Temp still exists
# on a native Windows profile.
TN_TMP="${ZCL_PEER_TIP_TMP:-}"
if [ -z "$TN_TMP" ] && [ -d "${HOME:-}/AppData/Local/Temp" ]; then
    TN_TMP="$HOME/AppData/Local/Temp"
fi
if [ -z "$TN_TMP" ] || [ ! -d "$TN_TMP" ]; then
    TN_TMP="${TMPDIR:-${TEMP:-/tmp}}"
fi
# Leave the leaf absent: Windows SetDataDir creates an owner+SYSTEM ACL
# directory. A pre-created mktemp leaf inherits the parent ACL and is refused.
echo "two-node-peer-tip: scratch-root=$TN_TMP" >&2
[ -d "$TN_TMP" ] || tn_die "scratch root does not exist: $TN_TMP"
TN_TMP="$(cd "$TN_TMP" && pwd -P)" || tn_die 'scratch root cannot be canonicalized'
# MSYS mktemp honors TMPDIR over an absolute /c/... template.
export TMPDIR="$TN_TMP"
TN_DD_A="$TN_TMP/$(cd "$TN_TMP" && mktemp -u zcl23-2node-A-XXXXXX)" ||
    tn_die "mktemp A failed"
TN_DD_B="$TN_TMP/$(cd "$TN_TMP" && mktemp -u zcl23-2node-B-XXXXXX)" ||
    tn_die "mktemp B failed"
case "$(basename "$TN_DD_A")" in zcl23-2node-A-*) : ;; *) tn_die "bad A datadir $TN_DD_A" ;; esac
case "$(basename "$TN_DD_B")" in zcl23-2node-B-*) : ;; *) tn_die "bad B datadir $TN_DD_B" ;; esac
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
tn_wait_rpc "$TN_DD_A" "$A_RPC" "$TN_PID_A" "$(( $(date +%s) + RPC_WARMUP ))" \
    || tn_die "miner A RPC never came up (see $(tn_node_log "$TN_DD_A"))"
a_rpc generate "$SEED_BLOCKS" >/dev/null
A_TIP="$(tn_blockcount "$TN_DD_A" "$A_RPC")"
echo "two-node-peer-tip:     A tip after seed = ${A_TIP:-?}"
[ "$A_TIP" = "$SEED_BLOCKS" ] \
    || tn_die "A did not mine to height $SEED_BLOCKS (got ${A_TIP:-?}) — regtest generate broken"
A_HASH="$(tn_blockhash "$TN_DD_A" "$A_RPC" "$A_TIP")" || tn_die 'miner tip hash unavailable'

# ── Step 2: spawn B (connect-only to A), assert it syncs ───────────
echo "two-node-peer-tip: [2] spawning follower B (connect-only → A); waiting ≤ ${SYNC_DEADLINE}s for B == $A_TIP..."
SYNC_END=$(( $(date +%s) + SYNC_DEADLINE ))
TN_PID_B="$(tn_spawn "$TN_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
TN_PGID_B="$TN_PID_B"
tn_wait_rpc "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$SYNC_END" \
    || tn_die "follower B RPC never came up (see $(tn_node_log "$TN_DD_B"))"

STEP2_PASS=no
if B_FINAL="$(tn_wait_height "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$A_TIP" "$SYNC_END" "$A_HASH")"; then
    STEP2_PASS=yes
    echo "two-node-peer-tip:     B synced to A tip $A_TIP over native P2P."
else
    echo "two-node-peer-tip:     B did NOT reach A tip $A_TIP within ${SYNC_DEADLINE}s (stuck at ${B_FINAL:-?})."
    echo "two-node-peer-tip:     B peer view:"; b_rpc getpeerinfo | head -c 400; echo ""
    echo "two-node-peer-tip:     B log tail:"; tail -8 "$(tn_node_log "$TN_DD_B")" 2>/dev/null || true
fi

# ── Step 3: kill-9 B, mine more on A, restart B, assert re-sync ────
STEP3_PASS=no
if [ "$STEP2_PASS" = "yes" ]; then
    echo "two-node-peer-tip: [3] kill-9 B mid-life; A mines +$EXTRA_BLOCKS while B is down..."
    RECOVERY_BEGAN=$(date +%s)
    RECOVERY_END=$((RECOVERY_BEGAN + RESYNC_DEADLINE))
    # SIGKILL B's whole process group (mid-block: no graceful shutdown).
    tn_kill_group "$TN_PGID_B"
    wait "$TN_PID_B" 2>/dev/null || true
    TN_PID_B=""; # group dead; restart below sets a fresh one
    # Windows pid-lock (ERROR_SHARING_VIOLATION=32) can outlive the process
    # by a beat; wait until a new node can take zclassic23.pid.
    sleep 1

    a_rpc generate "$EXTRA_BLOCKS" >/dev/null
    NEW_TIP="$(tn_blockcount "$TN_DD_A" "$A_RPC")"
    echo "two-node-peer-tip:     A new tip = ${NEW_TIP:-?} (was $A_TIP)"
    [ "$NEW_TIP" = "$((A_TIP + EXTRA_BLOCKS))" ] \
        || tn_die "A did not advance to $((A_TIP + EXTRA_BLOCKS)) (got ${NEW_TIP:-?})"
    NEW_HASH="$(tn_blockhash "$TN_DD_A" "$A_RPC" "$NEW_TIP")" || tn_die 'new miner tip hash unavailable'

    echo "two-node-peer-tip:     restarting B (same datadir); waiting ≤ ${RESYNC_DEADLINE}s for B == $NEW_TIP..."
    TN_PID_B="$(tn_spawn "$TN_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
    TN_PGID_B="$TN_PID_B"
    if ! tn_wait_rpc "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$RECOVERY_END"; then
        echo "two-node-peer-tip:     B RPC never came back after kill-9 restart (see $(tn_node_log "$TN_DD_B"))"
    elif B_FINAL2="$(tn_wait_height "$TN_DD_B" "$B_RPC" "$TN_PID_B" "$NEW_TIP" "$RECOVERY_END" "$NEW_HASH")"; then
        RECOVERY_SECONDS=$(( $(date +%s) - RECOVERY_BEGAN ))
        [ "$RECOVERY_SECONDS" -ge 0 ] && [ "$RECOVERY_SECONDS" -lt "$RESYNC_DEADLINE" ] ||
            tn_die 'recovery observation exceeded its shared deadline'
        STEP3_PASS=yes
        echo "two-node-peer-tip:     B recovered + caught up to peer-tip $NEW_TIP after kill-9."
        echo "two-node-peer-tip: recovery_seconds=$RECOVERY_SECONDS tip_hash=$NEW_HASH"
    else
        echo "two-node-peer-tip:     B did NOT re-reach peer-tip $NEW_TIP within ${RESYNC_DEADLINE}s (stuck at ${B_FINAL2:-?})."
        echo "two-node-peer-tip:     B log tail:"; tail -8 "$(tn_node_log "$TN_DD_B")" 2>/dev/null || true
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
