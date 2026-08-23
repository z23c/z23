#!/usr/bin/env bash
# ux_join_drill.sh — one stranger-join clock from a throwaway /tmp datadir.
#
# Fully scripted: t0 → iso_init (audited isolation) → spawn -tor
# -onion-persist → onion ready → addnode node1's committed onion:port.
# Records seconds-to PEERED (verack), SYNCED (tip parity with that peer),
# FIRST_MSG (ZMSG sent + delivery ack over the P2P channel).
#
# Usage: tools/scripts/ux_join_drill.sh
#
# Isolation is sourced, not copied: tools/scripts/isolated_node_env.sh.
# iso_spawn_node is a *regtest* harness helper and is not used — a
# stranger joining the fleet mesh must speak node1's network. iso_init
# still owns the /tmp datadir, 39xxx ports, live-port refusal, LISTEN
# preflight, and EXIT cleanup.
#
# Any named step that needs >60s, or that cannot complete without a
# human hand, is a UX DEFECT. Defects are printed as
#   DEFECT=<token> seconds=<n> detail=<text>
# and never worked around. The JSONL line still lands with nulls for
# unfinished clocks.
#
# Appends one JSONL object to deploy/devfleet/ux_join_clock.jsonl:
#   {"ts":"...","box":"node3","peered_s":N|null,"synced_s":N|null,
#    "first_msg_s":N|null,"sha":"..."}
#
# Environment:
#   ZCL_CLI, ZCL_JSONQ          binaries (default <repo>/build/bin/...)
#   UX_JOIN_CLOCK               JSONL path (default deploy/devfleet/ux_join_clock.jsonl)
#   UX_JOIN_PORT_BASE           isolated 39xxx P2P port (default 39150)
#   UX_JOIN_STEP_BUDGET         seconds before a step is a UX DEFECT (default 60)
#   UX_JOIN_PEER_WAIT           extra wait for onion circuit after the 60s defect
#                               line is recorded (default 120; circuit budget)
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
CLOCK_FILE=${UX_JOIN_CLOCK:-"$REPO_ROOT/deploy/devfleet/ux_join_clock.jsonl"}
NODE1_FILE="$REPO_ROOT/deploy/devfleet/node1.txt"
STEP_BUDGET=${UX_JOIN_STEP_BUDGET:-60}
PEER_WAIT=${UX_JOIN_PEER_WAIT:-120}
ISO_KIND=uxjoin
ISO_PORT_BASE=${UX_JOIN_PORT_BASE:-39150}

field() {
    key=$1
    file=$2
    sed -n "s/^${key}=//p" "$file" | head -n 1
}

jsonq_get() {
    "$ZCL_JSONQ" get "$1" 2>/dev/null || true
}

now_s() { date +%s; }

elapsed() {
    now=$(now_s)
    echo $((now - T0))
}

# Print DEFECT and record it. Never converts a miss into a pass.
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

cli() {
    timeout 60 "$ZCL_CLI" -datadir="$ISO_DD" -rpcport="$ISO_RPCPORT" "$@" 2>/dev/null || true
}

write_clock() {
    mkdir -p "$(dirname "$CLOCK_FILE")"
    extra=""
    case " ${DEFECTS:-} " in
        *" first_msg_over_60s "*) extra=',"defect":"first_msg_over_60s","dial_cap_s":120' ;;
    esac
    printf '{"ts":"%s","box":"node3","peered_s":%s,"synced_s":%s,"first_msg_s":%s,"sha":"%s"%s}\n' \
        "$TS" \
        "$(num_or_null "$PEERED_S")" \
        "$(num_or_null "$SYNCED_S")" \
        "$(num_or_null "$FIRST_MSG_S")" \
        "$SHA" \
        "$extra" >>"$CLOCK_FILE"
}

save_evidence() {
    EVIDENCE_DIR=${UX_JOIN_EVIDENCE:-}
    if [ -n "$EVIDENCE_DIR" ] && [ -d "$EVIDENCE_DIR" ] && [ -n "${ISO_DD:-}" ]; then
        stamp=$(date -u +%Y%m%dT%H%M%SZ)
        if [ -f "$ISO_DD/node.log" ]; then
            tail -n 250 "$ISO_DD/node.log" >"$EVIDENCE_DIR/node-$stamp.log" || true
        fi
        printf 'onion=%s peered_s=%s synced_s=%s first_msg_s=%s defects=%s\n' \
            "${ONION_ADDR:-}" "${PEERED_S:-null}" "${SYNCED_S:-null}" \
            "${FIRST_MSG_S:-null}" "${DEFECTS:-none}" \
            >"$EVIDENCE_DIR/run-$stamp.txt" || true
    fi
}

clock_fail() {
    step=$1
    detail=$2
    secs=$(elapsed)
    save_evidence
    write_clock
    echo "UX_JOIN=fail STEP=$step WALL_SECONDS=$secs DETAIL=$detail"
    exit 1
}

# ── environment ─────────────────────────────────────────────────────
if [ ! -x "$ZCL_CLI" ] || [ ! -x "$ZCL_JSONQ" ] || [ ! -x "$ISO_NODE_BIN" ]; then
    echo "UX_JOIN=fail STEP=ENV WALL_SECONDS=0 DETAIL=missing_binary"
    exit 2
fi
if [ ! -f "$NODE1_FILE" ]; then
    echo "UX_JOIN=fail STEP=ENV WALL_SECONDS=0 DETAIL=missing_node1_identity"
    exit 2
fi

PEER_ONION=$(field ONION_ADDRESS "$NODE1_FILE")
PEER_PORT=$(field P2P_PORT "$NODE1_FILE")
case $PEER_ONION in
    *[!a-z2-7.]*|'' ) echo "UX_JOIN=fail STEP=ENV WALL_SECONDS=0 DETAIL=invalid_node1_onion"; exit 2 ;;
esac
case $PEER_PORT in
    ''|*[!0-9]*) echo "UX_JOIN=fail STEP=ENV WALL_SECONDS=0 DETAIL=invalid_node1_port"; exit 2 ;;
esac
PEER_ENDPOINT="$PEER_ONION:$PEER_PORT"
SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
MSG="uxjoin-${TS}-$$"
DEFECTS=""
PEERED_S=""
SYNCED_S=""
FIRST_MSG_S=""
ONION_ADDR=""
T0=$(now_s)

# ── isolation (sourced, not copied) ────────────────────────────────
# shellcheck source=tools/scripts/isolated_node_env.sh
. "$REPO_ROOT/tools/scripts/isolated_node_env.sh"
iso_init

# Spawn a stranger node on the fleet network. iso_spawn_node hardcodes
# -regtest and is the wrong network for node1; isolation (datadir, ports,
# trap) still comes from iso_init above.
setsid "$ISO_NODE_BIN" \
    -datadir="$ISO_DD" \
    -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
    -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
    -connect=127.0.0.1:"$ISO_CONNECT_SINK" \
    -listen -tor -onion-persist \
    -operator-lane=test \
    -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
    </dev/null >"$ISO_DD/node.log" 2>&1 &
ISO_NODE_PID=$!
ISO_PGID="$ISO_NODE_PID"
echo "spawned pid=$ISO_NODE_PID datadir=$ISO_DD p2p=$ISO_PORT rpc=$ISO_RPCPORT"

# ── RPC ready ───────────────────────────────────────────────────────
if ! iso_wait_rpc_ready "$STEP_BUDGET"; then
    secs=$(elapsed)
    defect rpc_ready_timeout "$secs" "rpc_unanswered_in_${STEP_BUDGET}s"
    clock_fail RPC_READY rpc_unanswered
fi
secs=$(elapsed)
echo "rpc_ready_s=$secs"
if [ "$secs" -gt "$STEP_BUDGET" ]; then
    defect rpc_ready_over_60s "$secs" "rpc_ready_exceeded_step_budget"
fi

# ── onion ready ─────────────────────────────────────────────────────
onion_deadline=$((T0 + STEP_BUDGET))
onion_wait_until=$((T0 + PEER_WAIT))
while :; do
    status=$(cli core network onion status)
    bootstrap=$(printf '%s' "$status" | jsonq_get data.bootstrap_state)
    [ -z "$bootstrap" ] && bootstrap=$(printf '%s' "$status" | jsonq_get bootstrap_state)
    addr=$(printf '%s' "$status" | jsonq_get data.onion_address)
    [ -z "$addr" ] && addr=$(printf '%s' "$status" | jsonq_get onion_address)
    if [ "$bootstrap" = ready ] && [ -n "$addr" ]; then
        ONION_ADDR=$addr
        break
    fi
    if [ "$(now_s)" -ge "$onion_wait_until" ]; then
        break
    fi
    if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
        secs=$(elapsed)
        defect node_exited "$secs" "node_exited_during_onion_bootstrap"
        break
    fi
    sleep 1
done
secs=$(elapsed)
if [ -z "$ONION_ADDR" ] || [ "${bootstrap:-}" != ready ]; then
    defect onion_ready_timeout "$secs" "bootstrap_state=${bootstrap:-absent} addr=${ONION_ADDR:-none}"
    echo "onion_ready FAIL seconds=$secs bootstrap=${bootstrap:-absent}"
    clock_fail ONION_READY onion_not_ready
fi
echo "onion_ready_s=$secs onion=$ONION_ADDR"
if [ "$secs" -gt "$STEP_BUDGET" ]; then
    defect onion_ready_over_60s "$secs" "onion_ready_exceeded_step_budget"
fi
case $ONION_ADDR in
    ????????????????????????????????????????????????????????.onion) ;;
    *)
        defect onion_invalid_address "$secs" "addr=$ONION_ADDR"
        ;;
esac

# ── addnode node1 ───────────────────────────────────────────────────
# The typed native wrapper is the stranger-facing command. Its 250ms
# budget has already been observed to expire while the node is still
# finishing Tor bootstrap; that is a named UX defect, not a reason to
# skip the load-bearing RPC addnode the wrapper exists to call.
add_out=$(cli core network peers add --address="$PEER_ENDPOINT")
add_ok=$(printf '%s' "$add_out" | jsonq_get ok)
add_status=$(printf '%s' "$add_out" | jsonq_get data.status)
add_code=$(printf '%s' "$add_out" | jsonq_get error.code)
if [ "$add_ok" != true ] || [ "$add_status" != dial_requested ]; then
    secs=$(elapsed)
    detail=$(printf '%s' "$add_out" | tr '\n' ' ' | tr '"' "'" | cut -c1-240)
    echo "typed_peer_add_raw=$detail"
    # Named defects, not workarounds: the typed wrapper is the stranger
    # command and it is currently not a clean addnode. RPC addnode below
    # is the node method the wrapper is supposed to call.
    if [ "$add_code" = BAD_RPC_BODY ]; then
        defect typed_peer_add_bad_rpc_body "$secs" "code=$add_code $detail"
    elif [ "$add_code" = TOOL_ERROR ]; then
        defect typed_peer_add_budget_exceeded "$secs" "code=$add_code $detail"
    else
        defect typed_peer_add_failed "$secs" "code=${add_code:-absent} $detail"
    fi
fi
# zcl-rpc joins argv into a JSON params array; each value must already
# be a JSON token. Unquoted host:port is a parse error (-32700).
rpc_add=$(iso_rpc addnode "\"$PEER_ENDPOINT\"" "\"add\"")
rpc_err=$(printf '%s' "$rpc_add" | jsonq_get error)
rpc_err_code=$(printf '%s' "$rpc_add" | jsonq_get error.code)
rpc_err_msg=$(printf '%s' "$rpc_add" | jsonq_get error.message)
case $rpc_err in
    ''|null|'null')
        echo "rpc_addnode_ok $PEER_ENDPOINT"
        ;;
    *)
        secs=$(elapsed)
        detail=$(printf '%s' "$rpc_add" | tr '\n' ' ' | tr '"' "'" | cut -c1-240)
        defect addnode_refused "$secs" "code=${rpc_err_code:-absent} msg=${rpc_err_msg:-absent} rpc=$detail"
        echo "rpc_addnode_raw=$detail"
        clock_fail ADDNODE addnode_refused
        ;;
esac
echo "addnode_requested $PEER_ENDPOINT"

# ── PEERED (verack) ────────────────────────────────────────────────
peer_deadline=$(( $(now_s) + PEER_WAIT ))
PEER_ID=""
PEER_HEIGHT=""
PEERED_MARKED=0
while :; do
    peers=$(cli getpeerinfo)
    case "$peers" in
        \{*) u=$(printf '%s' "$peers" | "$ZCL_JSONQ" unwrap 2>/dev/null) && peers=$u ;;
    esac
    count=$(printf '%s' "$peers" | "$ZCL_JSONQ" count . 2>/dev/null || true)
    i=0
    while [ -n "$count" ] && [ "$i" -lt "$count" ]; do
        paddr=$(printf '%s' "$peers" | jsonq_get "[$i].addr")
        pver=$(printf '%s' "$peers" | jsonq_get "[$i].version")
        case "$paddr" in
            *"$PEER_ONION"*)
                case $pver in
                    ''|0|null) ;;
                    *)
                        PEER_ID=$(printf '%s' "$peers" | jsonq_get "[$i].id")
                        PEER_HEIGHT=$(printf '%s' "$peers" | jsonq_get "[$i].startingheight")
                        PEERED_S=$(elapsed)
                        break
                        ;;
                esac
                ;;
        esac
        i=$((i + 1))
    done
    [ -n "$PEERED_S" ] && break
    now=$(now_s)
    if [ "$PEERED_MARKED" = 0 ] && [ $((now - T0)) -gt "$STEP_BUDGET" ]; then
        defect peered_over_60s $((now - T0)) "no_verack_yet endpoint=$PEER_ENDPOINT"
        PEERED_MARKED=1
    fi
    [ "$now" -ge "$peer_deadline" ] && break
    if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
        defect node_exited "$(elapsed)" "node_exited_during_peer"
        break
    fi
    sleep 2
done
if [ -z "$PEERED_S" ]; then
    secs=$(elapsed)
    defect peered_timeout "$secs" "endpoint_not_handshaked:$PEER_ENDPOINT"
    echo "peered FAIL seconds=$secs"
    clock_fail PEERED no_verack
fi
echo "peered_s=$PEERED_S peer_id=$PEER_ID startingheight=$PEER_HEIGHT"

# ── FIRST_MSG (ZMSG sent + delivery ack) ───────────────────────────
# Clocked from t0 as soon as a verack peer exists. Waiting for IBD
# before sending would pad this number with an unrelated sync stall.
if [ -f "$ISO_DD/node.log" ]; then
    LOG_MARK=$(wc -c <"$ISO_DD/node.log" | tr -d ' ')
else
    LOG_MARK=0
fi
plan_out=$(cli app messaging send \
    --input="{\"channel\":\"p2p\",\"peer_id\":${PEER_ID:-0},\"message\":\"$MSG\"}")
plan_stage=$(printf '%s' "$plan_out" | jsonq_get data.stage)
[ -z "$plan_stage" ] && plan_stage=$(printf '%s' "$plan_out" | "$ZCL_JSONQ" unwrap 2>/dev/null | jsonq_get data.stage || true)
if [ "$plan_stage" != plan ]; then
    secs=$(elapsed)
    detail=$(printf '%s' "$plan_out" | tr '\n' ' ' | cut -c1-160)
    defect first_msg_plan_refused "$secs" "stage=${plan_stage:-absent} raw=$detail"
    echo "first_msg FAIL plan seconds=$secs"
else
    send_out=$(cli app messaging send \
        --input="{\"channel\":\"p2p\",\"peer_id\":${PEER_ID:-0},\"message\":\"$MSG\",\"confirm\":true}")
    send_status=$(printf '%s' "$send_out" | jsonq_get data.status)
    [ -z "$send_status" ] && send_status=$(printf '%s' "$send_out" | "$ZCL_JSONQ" unwrap 2>/dev/null | jsonq_get data.status || true)
    if [ "$send_status" != sent ]; then
        secs=$(elapsed)
        detail=$(printf '%s' "$send_out" | tr '\n' ' ' | cut -c1-160)
        defect first_msg_send_refused "$secs" "status=${send_status:-absent} raw=$detail"
        echo "first_msg FAIL send seconds=$secs"
    else
        ack_deadline=$(( $(now_s) + STEP_BUDGET ))
        ACKED=0
        while :; do
            if [ -f "$ISO_DD/node.log" ]; then
                hits=$(tail -c "+$((LOG_MARK + 1))" "$ISO_DD/node.log" 2>/dev/null \
                    | grep -c "delivery ack from peer" 2>/dev/null || true)
                [ "${hits:-0}" -gt 0 ] && ACKED=1 && FIRST_MSG_S=$(elapsed) && break
            fi
            [ "$(now_s)" -ge "$ack_deadline" ] && break
            sleep 2
        done
        if [ "$ACKED" != 1 ]; then
            secs=$(elapsed)
            defect first_msg_no_ack "$secs" "no_zmsgack_from:$PEER_ONION"
            echo "first_msg FAIL ack seconds=$secs"
        else
            echo "first_msg_s=$FIRST_MSG_S"
            if [ "$FIRST_MSG_S" -gt "$STEP_BUDGET" ]; then
                defect first_msg_over_60s "$FIRST_MSG_S" "ack_exceeded_step_budget"
            fi
        fi
    fi
fi

# ── SYNCED (tip parity with the peered node) ───────────────────────
# From-genesis IBD against a live mainnet tip cannot finish inside the
# 60s UX budget; that is a named defect, not a reason to stall FIRST_MSG.
sync_deadline=$((T0 + STEP_BUDGET))
SYNCED_MARKED=0
while :; do
    height=$(cli getblockcount | tr -dc '0-9-')
    case $PEER_HEIGHT in
        ''|null) break ;;
    esac
    case $height in
        ''|-* ) ;;
        *)
            if [ "$height" -ge "$PEER_HEIGHT" ]; then
                SYNCED_S=$(elapsed)
                break
            fi
            ;;
    esac
    now=$(now_s)
    if [ "$now" -ge "$sync_deadline" ]; then
        if [ "$SYNCED_MARKED" = 0 ]; then
            defect synced_over_60s $((now - T0)) "local_height=${height:-absent} peer_tip=$PEER_HEIGHT"
            SYNCED_MARKED=1
        fi
        break
    fi
    sleep 2
done
if [ -z "$SYNCED_S" ]; then
    height=$(cli getblockcount | tr -dc '0-9-')
    secs=$(elapsed)
    if [ "$SYNCED_MARKED" = 0 ]; then
        defect synced_timeout "$secs" "local_height=${height:-absent} peer_tip=${PEER_HEIGHT:-absent}"
    fi
    echo "synced FAIL seconds=$secs local_height=${height:-absent} peer_tip=${PEER_HEIGHT:-absent}"
else
    echo "synced_s=$SYNCED_S"
fi

save_evidence
write_clock

WALL=$(elapsed)
if [ -n "$PEERED_S" ] && [ -n "$SYNCED_S" ] && [ -n "$FIRST_MSG_S" ] && [ -z "$DEFECTS" ]; then
    echo "UX_JOIN=pass WALL_SECONDS=$WALL PEERED_S=$PEERED_S SYNCED_S=$SYNCED_S FIRST_MSG_S=$FIRST_MSG_S onion=$ONION_ADDR"
    exit 0
fi
echo "UX_JOIN=fail WALL_SECONDS=$WALL PEERED_S=${PEERED_S:-null} SYNCED_S=${SYNCED_S:-null} FIRST_MSG_S=${FIRST_MSG_S:-null} DEFECTS=${DEFECTS:-none} onion=$ONION_ADDR"
# Fail closed: a defect or a missing clock is not a green join.
exit 1
