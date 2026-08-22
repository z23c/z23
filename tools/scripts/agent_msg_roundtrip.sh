#!/bin/sh
# agent_msg_roundtrip.sh — prove a ZMSG P2P round-trip from the isolated
# fleet node to one fleet peer.
#
#   agent_msg_roundtrip.sh <endpoint host:port> <message>
#
# The endpoint is the peer's advertised P2P endpoint (ip:port or
# onion:port). The script drives THIS box's isolated node through four
# named assertions, in order, and stops at the first one that breaks:
#
#   ADDNODE_ACCEPTED  the legacy addnode RPC accepted the endpoint
#   PEER_CONNECTED    getpeerinfo lists the endpoint as a connected peer
#   SEND_COMMITTED    app messaging send committed with status=sent
#   ACK_OBSERVED      the peer's zmsgack reached this node's log
#
# Stdout contract (the final line is the verdict):
#   ROUNDTRIP=pass WALL_SECONDS=<n>
#   ROUNDTRIP=fail ASSERTION=<name> WALL_SECONDS=<n> DETAIL=<text>
# Exit 0 on pass, 1 on fail, 2 on usage/environment errors.
#
# No Python, no jq (project rule): flat fields come from grep/sed, nested
# JSON from build/bin/jsonq. No `| grep -q` under pipefail (LANE_CONTRACT
# A3): every grep either reads a file directly or is counted with -c.
#
# Environment overrides:
#   ZCL_CLI               z23 binary        (default <repo>/build/bin/z23)
#   ZCL_JSONQ             jsonq binary      (default <repo>/build/bin/jsonq)
#   ZCL_ROUNDTRIP_DATADIR isolated datadir  (default ~/.zclassic-c23-devfleet)
#   ZCL_ROUNDTRIP_RPCPORT RPC port          (default 18255)
#   ZCL_ROUNDTRIP_LOG     node stdout log   (default <datadir>/node.log)
#   ZCL_ROUNDTRIP_TIMEOUT total budget, sec (default 120)

set -u

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: $0 <endpoint host:port> <message>" >&2
    exit 2
fi
ENDPOINT="$1"
MESSAGE="$2"
ENDPOINT_HOST=${ENDPOINT%:*}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
ZCL_CLI=${ZCL_CLI:-"$REPO_ROOT/build/bin/z23"}
ZCL_JSONQ=${ZCL_JSONQ:-"$REPO_ROOT/build/bin/jsonq"}
DATADIR=${ZCL_ROUNDTRIP_DATADIR:-"$HOME/.zclassic-c23-devfleet"}
RPCPORT=${ZCL_ROUNDTRIP_RPCPORT:-18255}
NODE_LOG=${ZCL_ROUNDTRIP_LOG:-"$DATADIR/node.log"}
TIMEOUT=${ZCL_ROUNDTRIP_TIMEOUT:-120}

if [ ! -x "$ZCL_CLI" ] || [ ! -x "$ZCL_JSONQ" ]; then
    echo "ROUNDTRIP=fail ASSERTION=ENV WALL_SECONDS=0 DETAIL=z23_or_jsonq_missing"
    exit 2
fi
if [ ! -d "$DATADIR" ]; then
    echo "ROUNDTRIP=fail ASSERTION=ENV WALL_SECONDS=0 DETAIL=datadir_absent:$DATADIR"
    exit 2
fi

T0=$(date +%s)
DEADLINE=$((T0 + TIMEOUT))
# Only ack lines written after this run started count as this round-trip.
if [ -f "$NODE_LOG" ]; then
    LOG_MARK=$(wc -c <"$NODE_LOG" | tr -d ' ')
else
    LOG_MARK=0
fi

fail() {
    now=$(date +%s)
    echo "ROUNDTRIP=fail ASSERTION=$1 WALL_SECONDS=$((now - T0)) DETAIL=$2"
    exit 1
}

cli() {
    timeout 30 "$ZCL_CLI" -datadir="$DATADIR" -rpcport="$RPCPORT" "$@" 2>/dev/null
}

# peer_id_for <endpoint> — print the connected peer's numeric id, or nothing.
# The CLI prints legacy RPC results bare (getpeerinfo is a raw array) but
# wraps native commands in the zcl.result.v1 envelope, so accept both.
peer_id_for() {
    peers=$(cli getpeerinfo) || return 1
    case "$peers" in
        \{*) u=$(printf '%s' "$peers" | "$ZCL_JSONQ" unwrap 2>/dev/null) \
            && peers=$u ;;
    esac
    count=$(printf '%s' "$peers" | "$ZCL_JSONQ" count . 2>/dev/null) || return 1
    i=0
    while [ "$i" -lt "$count" ]; do
        addr=$(printf '%s' "$peers" | "$ZCL_JSONQ" get "[$i].addr" 2>/dev/null || true)
        case "$addr" in
            "$1"|"$1 "*) ;;
            *) i=$((i + 1)); continue ;;
        esac
        printf '%s' "$peers" | "$ZCL_JSONQ" get "[$i].id" 2>/dev/null
        return 0
    done
    return 1
}

# ── 1. ADDNODE_ACCEPTED ──────────────────────────────────────────────
if ! cli addnode "$ENDPOINT" onetry >/dev/null 2>&1; then
    fail ADDNODE_ACCEPTED "addnode_rpc_refused:$ENDPOINT"
fi
echo "assertion ADDNODE_ACCEPTED ok"

# ── 2. PEER_CONNECTED ────────────────────────────────────────────────
PEER_ID=""
retried=0
while :; do
    PEER_ID=$(peer_id_for "$ENDPOINT" 2>/dev/null || true)
    [ -n "$PEER_ID" ] && break
    now=$(date +%s)
    [ "$now" -ge "$DEADLINE" ] && \
        fail PEER_CONNECTED "endpoint_not_in_getpeerinfo:${ENDPOINT}"
    if [ "$retried" -eq 0 ] && [ "$now" -ge $((T0 + TIMEOUT / 2)) ]; then
        retried=1
        cli addnode "$ENDPOINT" onetry >/dev/null 2>&1 || true
    fi
    sleep 2
done
echo "assertion PEER_CONNECTED ok peer_id=$PEER_ID"

# ── 3. SEND_COMMITTED ────────────────────────────────────────────────
send_out=$(cli app messaging send \
    --input="{\"channel\":\"p2p\",\"peer_id\":$PEER_ID,\"message\":\"$MESSAGE\",\"confirm\":true}") \
    || fail SEND_COMMITTED "messaging_send_rpc_error"
# Native-command envelope: data.status; JSON-RPC envelope: result.data.status.
send_status=$(printf '%s' "$send_out" | "$ZCL_JSONQ" get data.status 2>/dev/null || true)
if [ -z "$send_status" ]; then
    send_status=$(printf '%s' "$send_out" | "$ZCL_JSONQ" unwrap 2>/dev/null \
        | "$ZCL_JSONQ" get data.status 2>/dev/null || true)
fi
if [ "$send_status" != "sent" ]; then
    detail=$(printf '%s' "$send_out" | tr '\n' ' ' | cut -c1-160)
    fail SEND_COMMITTED "status=${send_status:-absent} raw=$detail"
fi
echo "assertion SEND_COMMITTED ok peer_id=$PEER_ID"

# ── 4. ACK_OBSERVED ──────────────────────────────────────────────────
while :; do
    if [ -f "$NODE_LOG" ]; then
        hits=$(tail -c "+$((LOG_MARK + 1))" "$NODE_LOG" 2>/dev/null \
            | grep -c "delivery ack from peer $ENDPOINT_HOST" 2>/dev/null || true)
        [ "${hits:-0}" -gt 0 ] && break
    fi
    [ "$(date +%s)" -ge "$DEADLINE" ] && \
        fail ACK_OBSERVED "no_zmsgack_from:${ENDPOINT_HOST}"
    sleep 2
done
echo "assertion ACK_OBSERVED ok"

now=$(date +%s)
echo "ROUNDTRIP=pass WALL_SECONDS=$((now - T0))"
exit 0
