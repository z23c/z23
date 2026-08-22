#!/bin/sh
# agent_msg_roundtrip.sh — prove a ZMSG agent-message round-trip from this
# box's isolated node to one fleet peer and back.
#
#   agent_msg_roundtrip.sh <peer_endpoint host:port> <text>
#
# The endpoint is the peer's advertised dial address (ip:port or
# onion:port). The script drives THIS box's isolated node through a chain
# of named assertions and stops at the first one that breaks:
#
#   MY_NODE_UP       this node's RPC answers at all
#   MY_ONION_READY   tor_ready + onion_service_ready + a minted persistent
#                    v3 address on disk (rhett4 readiness contract: the
#                    onion-status envelope need not carry bootstrap_state)
#   PEER_ADDED       the legacy addnode RPC accepted the endpoint
#   PEER_LISTED      the peers list shows the endpoint connected
#   SEND_PLANNED     app messaging send without confirm returns a plan
#   SEND_COMMITTED   the same send with confirm:true reports status=sent
#   ACK_OBSERVED     the peer's zmsgack reached this node's log
#   INBOX_RECEIVED   an inbound echo of <text> appears in msg_inbox
#   MSG_READ         msg_read on the echo returns status=read
#   CONTENT_MATCH    the echo body equals <text> exactly
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
#   ZCL_ROUNDTRIP_TIMEOUT total budget, sec (default 300)

set -u

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: $0 <peer_endpoint host:port> <text>" >&2
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
TIMEOUT=${ZCL_ROUNDTRIP_TIMEOUT:-300}
ONION_HOSTNAME_FILE="$DATADIR/tor_data/onion_service/hostname"

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
    timeout 60 "$ZCL_CLI" -datadir="$DATADIR" -rpcport="$RPCPORT" "$@" 2>/dev/null
}

jqget() {  # jqget <path> — read one path from JSON on stdin, empty on miss
    "$ZCL_JSONQ" get "$1" 2>/dev/null || true
}

# ── MY_NODE_UP ───────────────────────────────────────────────────────
if ! cli getconnectioncount >/dev/null 2>&1; then
    fail MY_NODE_UP "rpc_unanswered_at:$DATADIR"
fi
echo "assertion MY_NODE_UP ok"

# ── MY_ONION_READY ───────────────────────────────────────────────────
hc=$(cli healthcheck) || fail MY_ONION_READY "healthcheck_rpc_error"
tor_ready=$(printf '%s' "$hc" | jqget checks.tor_ready)
svc_ready=$(printf '%s' "$hc" | jqget checks.onion_service_ready)
my_onion=""
[ -f "$ONION_HOSTNAME_FILE" ] && \
    my_onion=$(tr -d '[:space:]' <"$ONION_HOSTNAME_FILE")
case "$my_onion" in
    ????????????????????????????????????????????????????????.onion) ;;
    *) my_onion="" ;;
esac
if [ "$tor_ready" != "true" ] || [ "$svc_ready" != "true" ] || \
   [ -z "$my_onion" ]; then
    fail MY_ONION_READY \
        "tor_ready=${tor_ready:-absent} onion_service_ready=${svc_ready:-absent} minted=${my_onion:-none}"
fi
echo "assertion MY_ONION_READY ok onion=$my_onion"

# ── PEER_ADDED ───────────────────────────────────────────────────────
addnode_out=$(cli addnode "$ENDPOINT" onetry 2>&1)
if [ $? -ne 0 ] || [ "$addnode_out" != "null" ]; then
    detail=$(printf '%s' "$addnode_out" | tr '\n' ' ' | cut -c1-160)
    fail PEER_ADDED "addnode_refused:$ENDPOINT rpc=${detail:-empty}"
fi
echo "assertion PEER_ADDED ok"

# ── PEER_LISTED ──────────────────────────────────────────────────────
PEER_ID=""
retried=0
while :; do
    peers=$(cli getpeerinfo 2>/dev/null || true)
    case "$peers" in
        \{*) u=$(printf '%s' "$peers" | "$ZCL_JSONQ" unwrap 2>/dev/null) \
            && peers=$u ;;
    esac
    count=$(printf '%s' "$peers" | "$ZCL_JSONQ" count . 2>/dev/null || true)
    i=0
    while [ -n "$count" ] && [ "$i" -lt "$count" ]; do
        addr=$(printf '%s' "$peers" | jqget "[$i].addr")
        if [ "$addr" = "$ENDPOINT" ]; then
            PEER_ID=$(printf '%s' "$peers" | jqget "[$i].id")
            break
        fi
        i=$((i + 1))
    done
    [ -n "$PEER_ID" ] && break
    now=$(date +%s)
    [ "$now" -ge "$DEADLINE" ] && \
        fail PEER_LISTED "endpoint_not_connected:$ENDPOINT"
    if [ "$retried" -eq 0 ] && [ "$now" -ge $((T0 + TIMEOUT / 4)) ]; then
        retried=1
        cli addnode "$ENDPOINT" onetry >/dev/null 2>&1 || true
    fi
    sleep 2
done
echo "assertion PEER_LISTED ok peer_id=$PEER_ID"

# ── SEND_PLANNED ─────────────────────────────────────────────────────
plan_out=$(cli app messaging send \
    --input="{\"channel\":\"p2p\",\"peer_id\":$PEER_ID,\"message\":\"$MESSAGE\"}") \
    || fail SEND_PLANNED "messaging_send_plan_rpc_error"
plan_stage=$(printf '%s' "$plan_out" | jqget data.stage)
[ -z "$plan_stage" ] && \
    plan_stage=$(printf '%s' "$plan_out" | "$ZCL_JSONQ" unwrap 2>/dev/null \
        | jqget data.stage)
if [ "$plan_stage" != "plan" ]; then
    detail=$(printf '%s' "$plan_out" | tr '\n' ' ' | cut -c1-160)
    fail SEND_PLANNED "stage=${plan_stage:-absent} raw=$detail"
fi
echo "assertion SEND_PLANNED ok"

# ── SEND_COMMITTED ───────────────────────────────────────────────────
send_out=$(cli app messaging send \
    --input="{\"channel\":\"p2p\",\"peer_id\":$PEER_ID,\"message\":\"$MESSAGE\",\"confirm\":true}") \
    || fail SEND_COMMITTED "messaging_send_rpc_error"
send_status=$(printf '%s' "$send_out" | jqget data.status)
[ -z "$send_status" ] && \
    send_status=$(printf '%s' "$send_out" | "$ZCL_JSONQ" unwrap 2>/dev/null \
        | jqget data.status)
if [ "$send_status" != "sent" ]; then
    detail=$(printf '%s' "$send_out" | tr '\n' ' ' | cut -c1-160)
    fail SEND_COMMITTED "status=${send_status:-absent} raw=$detail"
fi
echo "assertion SEND_COMMITTED ok peer_id=$PEER_ID"

# ── ACK_OBSERVED ─────────────────────────────────────────────────────
while :; do
    if [ -f "$NODE_LOG" ]; then
        hits=$(tail -c "+$((LOG_MARK + 1))" "$NODE_LOG" 2>/dev/null \
            | grep -c "delivery ack from peer $ENDPOINT_HOST" 2>/dev/null || true)
        [ "${hits:-0}" -gt 0 ] && break
    fi
    [ "$(date +%s)" -ge "$DEADLINE" ] && \
        fail ACK_OBSERVED "no_zmsgack_from:$ENDPOINT_HOST"
    sleep 2
done
echo "assertion ACK_OBSERVED ok"

# ── INBOX_RECEIVED ───────────────────────────────────────────────────
# The round-trip closes when the peer's echo of <text> lands inbound.
ECHO_ID=""
while :; do
    inbox=$(cli msg_inbox 2>/dev/null || true)
    case "$inbox" in
        \{*) u=$(printf '%s' "$inbox" | "$ZCL_JSONQ" unwrap 2>/dev/null) \
            && inbox=$u ;;
    esac
    count=$(printf '%s' "$inbox" | "$ZCL_JSONQ" count . 2>/dev/null || true)
    i=0
    while [ -n "$count" ] && [ "$i" -lt "$count" ]; do
        dir=$(printf '%s' "$inbox" | jqget "[$i].direction")
        body=$(printf '%s' "$inbox" | jqget "[$i].body")
        if [ "$dir" = "inbound" ] && [ "$body" = "$MESSAGE" ]; then
            ECHO_ID=$(printf '%s' "$inbox" | jqget "[$i].msg_id")
            break
        fi
        i=$((i + 1))
    done
    [ -n "$ECHO_ID" ] && break
    [ "$(date +%s)" -ge "$DEADLINE" ] && \
        fail INBOX_RECEIVED "no_echo_of_message_in_inbox"
    sleep 3
done
echo "assertion INBOX_RECEIVED ok msg_id=$ECHO_ID"

# ── MSG_READ ─────────────────────────────────────────────────────────
read_out=$(cli app messaging read \
    --input="{\"msg_id\":\"$ECHO_ID\"}") \
    || fail MSG_READ "messaging_read_rpc_error"
read_status=$(printf '%s' "$read_out" | jqget data.status)
[ -z "$read_status" ] && \
    read_status=$(printf '%s' "$read_out" | "$ZCL_JSONQ" unwrap 2>/dev/null \
        | jqget data.status)
if [ "$read_status" != "read" ]; then
    detail=$(printf '%s' "$read_out" | tr '\n' ' ' | cut -c1-160)
    fail MSG_READ "status=${read_status:-absent} raw=$detail"
fi
echo "assertion MSG_READ ok msg_id=$ECHO_ID"

# ── CONTENT_MATCH ────────────────────────────────────────────────────
inbox=$(cli msg_inbox 2>/dev/null || true)
case "$inbox" in
    \{*) u=$(printf '%s' "$inbox" | "$ZCL_JSONQ" unwrap 2>/dev/null) \
        && inbox=$u ;;
esac
count=$(printf '%s' "$inbox" | "$ZCL_JSONQ" count . 2>/dev/null || true)
i=0
matched=0
while [ -n "$count" ] && [ "$i" -lt "$count" ]; do
    id=$(printf '%s' "$inbox" | jqget "[$i].msg_id")
    if [ "$id" = "$ECHO_ID" ]; then
        body=$(printf '%s' "$inbox" | jqget "[$i].body")
        [ "$body" = "$MESSAGE" ] && matched=1
        break
    fi
    i=$((i + 1))
done
[ "$matched" = 1 ] || fail CONTENT_MATCH "echo_body_differs_from_sent_text"
echo "assertion CONTENT_MATCH ok"

now=$(date +%s)
echo "ROUNDTRIP=pass WALL_SECONDS=$((now - T0))"
exit 0
