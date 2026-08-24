#!/usr/bin/env bash
# session_drill.sh — two isolated nodes agree to talk via zses:v1.
#
# Sources tools/scripts/isolated_node_env.sh (does not copy isolation).
# A creates a signed invite, B accepts it, B joins via ops.mesh.join.
# join_status.peered=true is the live gate. Clocks are recorded fail-closed
# (null + named DEFECT, never a fake pass). Isolation never uses production
# datadir/ports/unit.
#
# Usage:
#   tools/scripts/session_drill.sh            # live two-node drill
#
# Environment:
#   ZCL_CLI, ZCL_JSONQ, ISO_NODE_BIN, ISO_RPC_BIN
#   SESSION_DRILL_PORT_BASE   isolated 39xxx P2P port (default 39220)
#   SESSION_DRILL_STEP_BUDGET seconds before a step is a DEFECT (default 60)
#
# No Python, no jq: nested JSON via jsonq. No `| grep -q` under pipefail.

set -euo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
ZCL_CLI=${ZCL_CLI:-"$REPO_ROOT/build/bin/z23"}
ZCL_JSONQ=${ZCL_JSONQ:-"$REPO_ROOT/build/bin/jsonq"}
ISO_NODE_BIN=${ISO_NODE_BIN:-"$REPO_ROOT/build/bin/zclassic23"}
ISO_RPC_BIN=${ISO_RPC_BIN:-"$REPO_ROOT/build/bin/zcl-rpc"}
STEP_BUDGET=${SESSION_DRILL_STEP_BUDGET:-60}
ISO_KIND=zses
ISO_PORT_BASE=${SESSION_DRILL_PORT_BASE:-39220}
if [ "$#" -ne 0 ]; then
    echo "session-drill: unexpected argument: $1" >&2
    exit 2
fi

jsonq_get() {
    printf '%s' "$1" | "$ZCL_JSONQ" get "$2" 2>/dev/null || true
}

jsonq_eq() {
    printf '%s' "$1" | "$ZCL_JSONQ" eq "$2" "$3" >/dev/null 2>&1
}

now_s() { date +%s; }

elapsed() {
    now=$(now_s)
    echo $((now - T0))
}

defect() {
    token=$1
    secs=$2
    detail=$3
    echo "DEFECT=$token seconds=$secs detail=$detail"
    if [ -n "${DEFECTS:-}" ]; then
        DEFECTS="$DEFECTS $token"
    else
        DEFECTS=$token
    fi
}

num_or_null() {
    case ${1:-} in
        ''|null) echo null ;;
        *) echo "$1" ;;
    esac
}

cli_a() {
    timeout 60 "$ZCL_CLI" -datadir="$ISO_DD" -rpcport="$ISO_RPCPORT" \
        "$@" --format=json 2>/dev/null || true
}

cli_b() {
    timeout 60 "$ZCL_CLI" -datadir="$ISO_PEER_DD" -rpcport="$ISO_PEER_RPCPORT" \
        "$@" --format=json 2>/dev/null || true
}

# ── live two-node drill ────────────────────────────────────────────────
if [ ! -x "$ZCL_CLI" ] || [ ! -x "$ZCL_JSONQ" ] || [ ! -x "$ISO_NODE_BIN" ]; then
    echo "SESSION_DRILL=fail STEP=ENV WALL_SECONDS=0 DETAIL=missing_binary"
    echo "CREATE_S=null ACCEPT_S=null JOIN_S=null PEERED_S=null PEERED=false GAPS=missing_binary"
    exit 2
fi

# Isolation is sourced, not copied. ISO_PEER_DIAL=sink so the pair is NOT
# already peered: B must join through ops.mesh.join.
# shellcheck disable=SC1091
. "$SCRIPT_DIR/isolated_node_env.sh"
iso_init
ISO_PEER_DIAL=$ISO_CONNECT_SINK
iso_spawn_node
iso_spawn_peer

T0=$(now_s)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SHA=$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)
DEFECTS=""
CREATE_S=""
ACCEPT_S=""
JOIN_S=""
PEERED_S=""
PEERED=false
INVITE=""
ENDPOINT=""
GAPS=""

echo "session-drill: isolated A port=$ISO_PORT B port=$ISO_PEER_PORT sha=$SHA ts=$TS"

if ! iso_wait_rpc_ready "$STEP_BUDGET"; then
    defect rpc_a "$(elapsed)" "primary RPC never became ready"
    GAPS=rpc_a
    echo "SESSION_DRILL=fail STEP=RPC_A WALL_SECONDS=$(elapsed) DETAIL=primary_rpc_not_ready"
    echo "CREATE_S=$(num_or_null "$CREATE_S") ACCEPT_S=$(num_or_null "$ACCEPT_S") JOIN_S=$(num_or_null "$JOIN_S") PEERED_S=$(num_or_null "$PEERED_S") PEERED=$PEERED GAPS=$GAPS"
    exit 1
fi

# Peer RPC warmup (iso_wait_rpc_ready is primary-only).
peer_deadline=$(( $(now_s) + STEP_BUDGET ))
peer_ready=0
while [ "$(now_s)" -lt "$peer_deadline" ]; do
    if [ -n "$ISO_PEER_PID" ] && ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
        break
    fi
    if [ -f "$ISO_PEER_DD/.cookie" ]; then
        t="$(iso_peer_rpc getblockcount | tr -dc '0-9-')"
        if [ -n "$t" ]; then
            peer_ready=1
            break
        fi
    fi
    sleep 0.5
done
if [ "$peer_ready" != 1 ]; then
    defect rpc_b "$(elapsed)" "peer RPC never became ready"
    GAPS=rpc_b
    echo "SESSION_DRILL=fail STEP=RPC_B WALL_SECONDS=$(elapsed) DETAIL=peer_rpc_not_ready"
    echo "CREATE_S=$(num_or_null "$CREATE_S") ACCEPT_S=$(num_or_null "$ACCEPT_S") JOIN_S=$(num_or_null "$JOIN_S") PEERED_S=$(num_or_null "$PEERED_S") PEERED=$PEERED GAPS=$GAPS"
    exit 1
fi

# Isolated loopback pair: explicit operator act (posture=clearnet) so the
# invite names A's numeric listen address. Committed truth cards never
# record that address.
ENDPOINT="127.0.0.1:${ISO_PORT}"
CREATE=$(cli_a zses invite create --endpoint="$ENDPOINT" --posture=clearnet --expires=$(( $(now_s) + 3600 )))
CREATE_S=$(elapsed)
INVITE=$(jsonq_get "$CREATE" data.invite)
if [ -z "$INVITE" ] || ! jsonq_eq "$CREATE" ok true; then
    defect create "$CREATE_S" "invite create failed code=$(jsonq_get "$CREATE" error.code)"
    GAPS=create
    echo "SESSION_DRILL=fail STEP=CREATE WALL_SECONDS=$CREATE_S DETAIL=invite_create_failed"
    echo "CREATE_S=$(num_or_null "$CREATE_S") ACCEPT_S=$(num_or_null "$ACCEPT_S") JOIN_S=$(num_or_null "$JOIN_S") PEERED_S=$(num_or_null "$PEERED_S") PEERED=$PEERED GAPS=$GAPS"
    exit 1
fi
echo "CLOCK create_s=$CREATE_S"

ACCEPT=$(cli_b zses invite accept --invite="$INVITE")
ACCEPT_S=$(elapsed)
if ! jsonq_eq "$ACCEPT" data.accepted true; then
    defect accept "$ACCEPT_S" "invite accept failed code=$(jsonq_get "$ACCEPT" error.code)"
    GAPS=accept
    echo "SESSION_DRILL=fail STEP=ACCEPT WALL_SECONDS=$ACCEPT_S DETAIL=invite_accept_failed"
    echo "CREATE_S=$(num_or_null "$CREATE_S") ACCEPT_S=$(num_or_null "$ACCEPT_S") JOIN_S=$(num_or_null "$JOIN_S") PEERED_S=$(num_or_null "$PEERED_S") PEERED=$PEERED GAPS=$GAPS"
    exit 1
fi
ACCEPTED_EP=$(jsonq_get "$ACCEPT" data.endpoint)
echo "CLOCK accept_s=$ACCEPT_S"

JOIN=$(cli_b ops mesh join --endpoint="$ACCEPTED_EP")
JOIN_S=$(elapsed)
echo "CLOCK join_s=$JOIN_S"

if jsonq_eq "$JOIN" data.peered true; then
    PEERED=true
    PEERED_S=$JOIN_S
else
    join_deadline=$(( T0 + STEP_BUDGET ))
    while [ "$(now_s)" -lt "$join_deadline" ]; do
        STATUS=$(cli_b ops mesh join_status --endpoint="$ACCEPTED_EP")
        if jsonq_eq "$STATUS" data.peered true; then
            PEERED=true
            PEERED_S=$(elapsed)
            JOIN="$STATUS"
            break
        fi
        sleep 0.5
    done
fi

if [ "$PEERED" = true ]; then
    echo "CLOCK peered_s=$PEERED_S"
    echo "join_status $(printf '%s' "$JOIN" | "$ZCL_JSONQ" raw data 2>/dev/null || true)"
    echo "SESSION_DRILL=pass CREATE_S=$CREATE_S ACCEPT_S=$ACCEPT_S JOIN_S=$JOIN_S PEERED_S=$PEERED_S PEERED=true GAPS=none"
    exit 0
fi

defect join_not_peered "$(elapsed)" "ops.mesh.join did not report peered=true"
GAPS=join_not_peered
echo "join_status $(printf '%s' "$JOIN" | "$ZCL_JSONQ" raw data 2>/dev/null || true)"
echo "SESSION_DRILL=fail STEP=JOIN WALL_SECONDS=$(elapsed) DETAIL=join_not_peered"
echo "CREATE_S=$(num_or_null "$CREATE_S") ACCEPT_S=$(num_or_null "$ACCEPT_S") JOIN_S=$(num_or_null "$JOIN_S") PEERED_S=$(num_or_null "$PEERED_S") PEERED=$PEERED GAPS=$GAPS"
exit 1
