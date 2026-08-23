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
#   tools/scripts/session_drill.sh --selftest # hermetic, no spawn
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
SELFTEST=0

for arg in "$@"; do
    case "$arg" in
        --selftest) SELFTEST=1 ;;
        --*) echo "session-drill: unknown flag: $arg" >&2; exit 2 ;;
        *) echo "session-drill: unexpected positional arg: $arg" >&2; exit 2 ;;
    esac
done

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

# Named refuse classifier — the fail-closed contract the selftest proves
# without a live node. Live CLI errors must land in this set.
classify_refuse() {
    case ${1:-} in
        unsigned|wrong_key|tampered|expired|malformed|CLEARNET_FORBIDDEN|NO_ONION_ENDPOINT|MISSING_INVITE)
            echo refuse ;;
        *) echo other ;;
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

cli_local() {
    timeout 60 "$ZCL_CLI" "$@" --format=json 2>/dev/null || true
}

# ── --selftest: hermetic, no live spawn ────────────────────────────────
if [ "$SELFTEST" = "1" ]; then
    st_fail=0
    st_check() {
        if [ "$3" = "$2" ]; then
            echo "  ok: $1"
        else
            echo "  FAIL: $1 (expected $2 got $3)"
            st_fail=1
        fi
    }
    echo "session-drill: --selftest running hermetic fail-closed checks"

    st_check "unsigned is a named refuse" refuse "$(classify_refuse unsigned)"
    st_check "wrong_key is a named refuse" refuse "$(classify_refuse wrong_key)"
    st_check "tampered is a named refuse" refuse "$(classify_refuse tampered)"
    st_check "expired is a named refuse" refuse "$(classify_refuse expired)"
    st_check "malformed is a named refuse" refuse "$(classify_refuse malformed)"
    st_check "CLEARNET_FORBIDDEN is a named refuse" refuse "$(classify_refuse CLEARNET_FORBIDDEN)"
    st_check "ok is not a refuse" other "$(classify_refuse ok)"
    st_check "empty is not a refuse" other "$(classify_refuse '')"

    if [ ! -x "$ZCL_CLI" ]; then
        echo "  FAIL: missing z23 binary at $ZCL_CLI"
        st_fail=1
    else
        ONION_EP="abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055"
        CREATE=$(cli_local zses invite create --endpoint="$ONION_EP" --expires=2000000000)
        CODE=$(jsonq_get "$CREATE" error.code)
        INVITE=$(jsonq_get "$CREATE" data.invite)
        if [ -n "$INVITE" ] && jsonq_eq "$CREATE" ok true; then
            echo "  ok: create signed a zses:v1 invite"
        else
            echo "  FAIL: create did not return an invite (code=${CODE:-none})"
            st_fail=1
        fi

        if [ -n "$INVITE" ]; then
            ACCEPT=$(cli_local zses invite accept --invite="$INVITE" --now=1900000000)
            if jsonq_eq "$ACCEPT" data.accepted true; then
                echo "  ok: accept verified the signed invite"
            else
                echo "  FAIL: accept of a valid invite did not accept (code=$(jsonq_get "$ACCEPT" error.code))"
                st_fail=1
            fi
        fi

        FORBIDDEN=$(cli_local zses invite create --endpoint=203.0.113.9:8033)
        FCODE=$(jsonq_get "$FORBIDDEN" error.code)
        st_check "numeric IP without posture=clearnet is CLEARNET_FORBIDDEN" \
            "CLEARNET_FORBIDDEN" "$FCODE"
        st_check "CLEARNET_FORBIDDEN classifies as refuse" refuse "$(classify_refuse "$FCODE")"

        UNSIGNED='{"schema":"zses:v1","endpoint":"'"$ONION_EP"'","expires":2000000000,"capability_tag":"session"}'
        UACC=$(cli_local zses invite accept --invite="$UNSIGNED" --now=1900000000)
        UCODE=$(jsonq_get "$UACC" error.code)
        st_check "unsigned invite is refused as unsigned" unsigned "$UCODE"

        EXPIRED=$(cli_local zses invite create --endpoint="$ONION_EP" --expires=1)
        EINV=$(jsonq_get "$EXPIRED" data.invite)
        if [ -n "$EINV" ]; then
            EACC=$(cli_local zses invite accept --invite="$EINV" --now=2)
            ECODE=$(jsonq_get "$EACC" error.code)
            st_check "expired invite is refused as expired" expired "$ECODE"
        else
            echo "  FAIL: could not create an expired invite"
            st_fail=1
        fi

        if [ -n "$INVITE" ]; then
            TAMPERED=$(printf '%s' "$INVITE" | sed 's/"endpoint":"[^"]*"/"endpoint":"xbcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055"/')
            TACC=$(cli_local zses invite accept --invite="$TAMPERED" --now=1900000000)
            TCODE=$(jsonq_get "$TACC" error.code)
            case $TCODE in
                wrong_key|tampered)
                    echo "  ok: body tamper refused as $TCODE"
                    ;;
                *)
                    echo "  FAIL: body tamper expected wrong_key|tampered got ${TCODE:-none}"
                    st_fail=1
                    ;;
            esac
        fi
    fi

    if [ "$st_fail" = 0 ]; then
        echo "session-drill: --selftest PASS"
        exit 0
    fi
    echo "session-drill: --selftest FAIL" >&2
    exit 1
fi

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
