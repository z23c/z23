#!/usr/bin/env bash
# onion_pair_watch.sh — two-node sourced-isolated onion pair probe + ledger.
#
# Sources tools/scripts/isolated_node_env.sh (does not execute it). iso_init
# owns the throwaway /tmp datadir, 39xxx ports, live-port refusal, LISTEN
# preflight, and EXIT cleanup. This script never points a spawn at
# ~/.zclassic-c23 or any production unit.
#
# Probe (one cycle):
#   spawn A -tor -onion-persist
#   wait hostname
#   spawn B -addnode=A.onion:port
#   poll getconnectioncount 150s
#
# Appends one JSON object per run to deploy/devfleet/pair_probe.jsonl:
#   {"ts":"...","head_sha":"...","verdict":"TOKEN","paired_at_s":N|null,
#    "dial_attempted":true|false,"rendezvous_seen":true|false,
#    "descriptor_uploaded":true|false}
#
# verdict is a named token only. PAIRED means getconnectioncount >= 1 within
# the poll window. Any miss is the first-dead-stage token. The three stage
# flags are what that run actually observed.
#
# Usage:
#   tools/scripts/onion_pair_watch.sh            # live two-node probe
#   tools/scripts/onion_pair_watch.sh --selftest # hermetic, no spawn
#
# Environment:
#   PAIR_PROBE_FILE           JSONL path (default deploy/devfleet/pair_probe.jsonl)
#   PAIR_WATCH_PORT_BASE      isolated 39xxx P2P port (default 39350)
#   PAIR_WATCH_ONION_WAIT     seconds to wait for A's hostname (default 60)
#   PAIR_WATCH_RPC_WAIT       seconds to wait for RPC (default 60)
#   PAIR_WATCH_POLL           seconds to poll getconnectioncount (default 150)
#
# No Python, no jq. No `| grep -q` under pipefail.

set -euo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
ZCL_CLI=${ZCL_CLI:-"$REPO_ROOT/build/bin/z23"}
ZCL_JSONQ=${ZCL_JSONQ:-"$REPO_ROOT/build/bin/jsonq"}
ISO_NODE_BIN=${ISO_NODE_BIN:-"$REPO_ROOT/build/bin/zclassic23"}
ISO_RPC_BIN=${ISO_RPC_BIN:-"$REPO_ROOT/build/bin/zcl-rpc"}
ONION_WAIT=${PAIR_WATCH_ONION_WAIT:-60}
RPC_WAIT=${PAIR_WATCH_RPC_WAIT:-60}
PAIR_POLL=${PAIR_WATCH_POLL:-150}
ISO_KIND=pairwatch
ISO_PORT_BASE=${PAIR_WATCH_PORT_BASE:-39350}
SELFTEST=0
LIVE_PROBE_DEFAULT="$REPO_ROOT/deploy/devfleet/pair_probe.jsonl"

for arg in "$@"; do
    case "$arg" in
        --selftest) SELFTEST=1 ;;
        --*) echo "onion-pair-watch: unknown flag: $arg" >&2; exit 2 ;;
        *) echo "onion-pair-watch: unexpected positional arg: $arg" >&2; exit 2 ;;
    esac
done

now_s() { date +%s; }

elapsed() {
    now=$(now_s)
    echo $((now - T0))
}

json_bool() {
    case ${1:-} in
        true|1|yes) echo true ;;
        *) echo false ;;
    esac
}

num_or_null() {
    case ${1:-} in
        ''|null) echo null ;;
        *) echo "$1" ;;
    esac
}

# First-dead-stage mapping used by the live probe and --selftest.
named_verdict() {
    if [ "${PAIRED:-0}" = 1 ]; then
        echo PAIRED
        return 0
    fi
    case ${STAGE:-env} in
        env) echo ENV_MISSING_BINARY ;;
        spawn_a) echo SPAWN_A_FAILED ;;
        rpc_a) echo RPC_A_NOT_READY ;;
        onion) echo ONION_HOSTNAME_TIMEOUT ;;
        spawn_b) echo SPAWN_B_FAILED ;;
        rpc_b) echo RPC_B_NOT_READY ;;
        pair|*)
            if [ "${DIAL_ATTEMPTED:-false}" != true ]; then
                echo DIAL_NOT_ATTEMPTED
            elif [ "${DESCRIPTOR_UPLOADED:-false}" != true ]; then
                echo DESCRIPTOR_NOT_UPLOADED
            elif [ "${RENDEZVOUS_SEEN:-false}" != true ]; then
                echo RENDEZVOUS_NOT_SEEN
            else
                echo PAIR_TIMEOUT
            fi
            ;;
    esac
}

append_probe() {
    [ "${PROBE_WRITTEN:-0}" = 1 ] && return 0
    mkdir -p "$(dirname "$PROBE_FILE")"
    if [ -z "${VERDICT:-}" ]; then
        VERDICT=$(named_verdict)
    fi
    printf '{"ts":"%s","head_sha":"%s","verdict":"%s","paired_at_s":%s,"dial_attempted":%s,"rendezvous_seen":%s,"descriptor_uploaded":%s}\n' \
        "${TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
        "${HEAD_SHA:-unknown}" \
        "$VERDICT" \
        "$(num_or_null "${PAIRED_AT_S:-}")" \
        "$(json_bool "${DIAL_ATTEMPTED:-false}")" \
        "$(json_bool "${RENDEZVOUS_SEEN:-false}")" \
        "$(json_bool "${DESCRIPTOR_UPLOADED:-false}")" \
        >>"$PROBE_FILE"
    PROBE_WRITTEN=1
}

log_has() {
    file=$1
    pattern=$2
    [ -f "$file" ] || return 1
    if grep -a -E "$pattern" "$file" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

observe_stages() {
    # Client dial: boot_node_utilities.c prints this when B's -addnode is an
    # onion. Observed on every successful pair.
    if log_has "${ISO_PEER_DD:-}/node.log" "Connecting to onion addnode"; then
        DIAL_ATTEMPTED=true
    fi
    # This fork's client path is dynhost, not vanilla INTRODUCE/rendezvous
    # log lines (those count 0 on a PAIRED run). B.tor.log actually prints
    # "Dynhost stream: initiated stream to <A.onion>:<port>" and
    # "Dynhost stream: queued open to ...". onion_stream.c may also log
    # "onion circuit established".
    if log_has "${ISO_PEER_DD:-}/tor.log" \
        "Dynhost stream: initiated stream|Dynhost stream: queued open|rendezvous point|rendezvous circuit|INTRODUCE|intro point" ||
       log_has "${ISO_PEER_DD:-}/node.log" \
        "onion circuit established|Dynhost stream: initiated stream|rendezvous point|rendezvous circuit"; then
        RENDEZVOUS_SEEN=true
    fi
    # Service half: this fork never prints "Uploading HS descriptor" on a
    # PAIRED run. A's tor.log prints "hs_service_callback conditions now met"
    # then "hs_service_callback running, calling dynhost_check_and_activate"
    # and may print "Dynhost service successfully activated".
    if log_has "${ISO_DD:-}/tor.log" \
        "hs_service_callback running, calling dynhost_check_and_activate|hs_service_callback conditions now met|Dynhost service successfully activated|Uploading HS descriptor|HS_DESC UPLOAD|hidden-service descriptor upload" ||
       log_has "${ISO_DD:-}/node.log" \
        "hs_service_callback running, calling dynhost_check_and_activate|Uploading HS descriptor|HS_DESC UPLOAD"; then
        DESCRIPTOR_UPLOADED=true
    fi
}

conn_count() {
    local n
    n="$(iso_rpc getconnectioncount \
        | sed -n 's/.*"result"[^0-9-]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1)"
    case $n in
        ''|*[!0-9-]*) n=0 ;;
    esac
    if [ -n "${ISO_PEER_DD:-}" ]; then
        local pn
        pn="$(iso_peer_rpc getconnectioncount \
            | sed -n 's/.*"result"[^0-9-]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1)"
        case $pn in
            ''|*[!0-9-]*) pn=0 ;;
        esac
        if [ "$pn" -gt "$n" ]; then
            n=$pn
        fi
    fi
    echo "$n"
}

if [ "$SELFTEST" = 1 ]; then
    PROBE_FILE=${PAIR_PROBE_FILE:-}
    if [ -z "$PROBE_FILE" ]; then
        PROBE_FILE=$(mktemp "${TMPDIR:-/tmp}/zcl23-pairwatch-selftest-XXXXXX.jsonl")
    fi
else
    PROBE_FILE=${PAIR_PROBE_FILE:-"$LIVE_PROBE_DEFAULT"}
fi

# Isolation is sourced, not executed. ISO_KIND / ISO_PORT_BASE / ISO_NODE_BIN
# are already set so iso_init (live path only) inherits them.
# shellcheck source=tools/scripts/isolated_node_env.sh
. "$REPO_ROOT/tools/scripts/isolated_node_env.sh"

HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
T0=$(now_s)
PROBE_WRITTEN=0
PAIRED=0
PAIRED_AT_S=""
DIAL_ATTEMPTED=false
RENDEZVOUS_SEEN=false
DESCRIPTOR_UPLOADED=false
STAGE=env
VERDICT=""
ONION_ADDR=""

if [ "$SELFTEST" = 1 ]; then
    st_fail=0
    st_check() {
        if [ "$3" = "$2" ]; then
            echo "  ok: $1"
        else
            echo "  FAIL: $1 (expected $2 got $3)"
            st_fail=1
        fi
    }
    echo "onion-pair-watch: --selftest driving named_verdict + append_probe"

    case ${ISO_LIVE_PORTS:-} in
        *8033*) echo "  ok: sourced isolated_node_env.sh (ISO_LIVE_PORTS set)" ;;
        *)
            echo "  FAIL: sourcing isolated_node_env.sh did not set ISO_LIVE_PORTS"
            st_fail=1
            ;;
    esac
    if type iso_init >/dev/null 2>&1 && type iso_die >/dev/null 2>&1; then
        echo "  ok: iso_init/iso_die loaded from sourced helper"
    else
        echo "  FAIL: sourced helper did not expose iso_init/iso_die"
        st_fail=1
    fi

    STAGE=env PAIRED=0 DIAL_ATTEMPTED=false DESCRIPTOR_UPLOADED=false RENDEZVOUS_SEEN=false
    st_check "env miss is ENV_MISSING_BINARY" ENV_MISSING_BINARY "$(named_verdict)"
    STAGE=spawn_a
    st_check "spawn A miss is SPAWN_A_FAILED" SPAWN_A_FAILED "$(named_verdict)"
    STAGE=rpc_a
    st_check "rpc A miss is RPC_A_NOT_READY" RPC_A_NOT_READY "$(named_verdict)"
    STAGE=onion
    st_check "hostname miss is ONION_HOSTNAME_TIMEOUT" ONION_HOSTNAME_TIMEOUT "$(named_verdict)"
    STAGE=spawn_b
    st_check "spawn B miss is SPAWN_B_FAILED" SPAWN_B_FAILED "$(named_verdict)"
    STAGE=rpc_b
    st_check "rpc B miss is RPC_B_NOT_READY" RPC_B_NOT_READY "$(named_verdict)"
    STAGE=pair
    st_check "pair with no dial is DIAL_NOT_ATTEMPTED" DIAL_NOT_ATTEMPTED "$(named_verdict)"
    DIAL_ATTEMPTED=true
    st_check "dialed, no descriptor is DESCRIPTOR_NOT_UPLOADED" DESCRIPTOR_NOT_UPLOADED "$(named_verdict)"
    DESCRIPTOR_UPLOADED=true
    st_check "descriptor up, no rendezvous is RENDEZVOUS_NOT_SEEN" RENDEZVOUS_NOT_SEEN "$(named_verdict)"
    RENDEZVOUS_SEEN=true
    st_check "all stages, no conn is PAIR_TIMEOUT" PAIR_TIMEOUT "$(named_verdict)"
    PAIRED=1 PAIRED_AT_S=5
    st_check "getconnectioncount>=1 is PAIRED" PAIRED "$(named_verdict)"

    PROBE_WRITTEN=0
    VERDICT=""
    append_probe
    if [ -s "$PROBE_FILE" ]; then
        echo "  ok: append_probe wrote $PROBE_FILE"
    else
        echo "  FAIL: append_probe did not write $PROBE_FILE"
        st_fail=1
    fi

    if [ "$st_fail" = 0 ]; then
        echo "onion-pair-watch: --selftest PASS"
        exit 0
    fi
    echo "onion-pair-watch: --selftest FAIL" >&2
    exit 1
fi

if [ ! -x "$ZCL_CLI" ] || [ ! -x "$ISO_NODE_BIN" ] || [ ! -x "$ISO_RPC_BIN" ]; then
    VERDICT=ENV_MISSING_BINARY
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=missing_binary"
    exit 2
fi

iso_init
echo "onion-pair-watch: datadir=$ISO_DD p2p=$ISO_PORT peer_p2p=$ISO_PEER_PORT sha=$HEAD_SHA"

# If the live probe dies under set -e, still append one named line. Copy the
# helper's cleanup function under a new name, then replace iso_cleanup so the
# existing EXIT trap (installed by iso_init) still fires one function.
eval "$(declare -f iso_cleanup | sed '1s/^iso_cleanup/_iso_cleanup_inner/')"
iso_cleanup() {
    if [ "$PROBE_WRITTEN" != 1 ]; then
        observe_stages || true
        VERDICT=$(named_verdict)
        append_probe || true
    fi
    _iso_cleanup_inner
}

# ── A: listen + tor + onion-persist (not iso_spawn_node: that is -regtest)
STAGE=spawn_a
T0=$(now_s)
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
if [ -z "$ISO_NODE_PID" ] || ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
    VERDICT=SPAWN_A_FAILED
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=spawn_a_dead"
    exit 1
fi
echo "spawned A pid=$ISO_NODE_PID p2p=$ISO_PORT"

STAGE=rpc_a
if ! iso_wait_rpc_ready "$RPC_WAIT"; then
    VERDICT=RPC_A_NOT_READY
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=rpc_a_unanswered"
    exit 1
fi
echo "rpc_a_ready_s=$(elapsed)"

STAGE=onion
onion_deadline=$(( $(now_s) + ONION_WAIT ))
while [ "$(now_s)" -lt "$onion_deadline" ]; do
    if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
        VERDICT=SPAWN_A_FAILED
        append_probe
        echo "PAIR_PROBE=$VERDICT DETAIL=a_exited_during_onion"
        exit 1
    fi
    hn="$ISO_DD/tor_data/onion_service/hostname"
    if [ -f "$hn" ]; then
        ONION_ADDR=$(tr -d ' \n' <"$hn")
        case $ONION_ADDR in
            ????????????????????????????????????????????????????????.onion)
                break
                ;;
            *) ONION_ADDR="" ;;
        esac
    fi
    sleep 1
done
if [ -z "$ONION_ADDR" ]; then
    VERDICT=ONION_HOSTNAME_TIMEOUT
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=hostname_absent_in_${ONION_WAIT}s"
    exit 1
fi
echo "onion_ready_s=$(elapsed) onion=$ONION_ADDR"

# ── B: isolated peer quad, -addnode=A.onion:port
STAGE=spawn_b
[ "$ISO_PEER_HTTPSPORT" -lt "$ISO_CONNECT_SINK" ] \
    || iso_die "ISO_PORT_BASE too high for a +10 peer quad"
for p in "$ISO_PEER_PORT" "$ISO_PEER_RPCPORT" "$ISO_PEER_FSPORT" "$ISO_PEER_HTTPSPORT"; do
    iso_assert_not_live_port "$p"
    iso_assert_port_free "$p"
done
ISO_PEER_DD="$ISO_DD/peer"
mkdir -p "$ISO_PEER_DD"

setsid "$ISO_NODE_BIN" \
    -datadir="$ISO_PEER_DD" \
    -port="$ISO_PEER_PORT" -rpcport="$ISO_PEER_RPCPORT" \
    -fsport="$ISO_PEER_FSPORT" -httpsport="$ISO_PEER_HTTPSPORT" \
    -connect=127.0.0.1:"$ISO_CONNECT_SINK" \
    -addnode="${ONION_ADDR}:${ISO_PORT}" \
    -listen -tor -onion-persist \
    -operator-lane=test \
    -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
    </dev/null >"$ISO_PEER_DD/node.log" 2>&1 &
ISO_PEER_PID=$!
ISO_PEER_PGID="$ISO_PEER_PID"
if [ -z "$ISO_PEER_PID" ] || ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
    VERDICT=SPAWN_B_FAILED
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=spawn_b_dead"
    exit 1
fi
echo "spawned B pid=$ISO_PEER_PID p2p=$ISO_PEER_PORT addnode=${ONION_ADDR}:${ISO_PORT}"

STAGE=rpc_b
peer_deadline=$(( $(now_s) + RPC_WAIT ))
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
    observe_stages
    VERDICT=RPC_B_NOT_READY
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=rpc_b_unanswered"
    exit 1
fi
echo "rpc_b_ready_s=$(elapsed)"

# ── poll getconnectioncount
STAGE=pair
poll_deadline=$(( $(now_s) + PAIR_POLL ))
while [ "$(now_s)" -lt "$poll_deadline" ]; do
    if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
        observe_stages
        VERDICT=SPAWN_A_FAILED
        append_probe
        echo "PAIR_PROBE=$VERDICT DETAIL=a_exited_during_poll"
        exit 1
    fi
    if [ -n "$ISO_PEER_PID" ] && ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
        observe_stages
        VERDICT=SPAWN_B_FAILED
        append_probe
        echo "PAIR_PROBE=$VERDICT DETAIL=b_exited_during_poll"
        exit 1
    fi
    observe_stages
    n=$(conn_count)
    if [ "$n" -ge 1 ]; then
        PAIRED=1
        PAIRED_AT_S=$(elapsed)
        break
    fi
    sleep 2
done
observe_stages
VERDICT=$(named_verdict)
append_probe
echo "PAIR_PROBE=$VERDICT paired_at_s=${PAIRED_AT_S:-null} dial_attempted=$DIAL_ATTEMPTED rendezvous_seen=$RENDEZVOUS_SEEN descriptor_uploaded=$DESCRIPTOR_UPLOADED onion=$ONION_ADDR"
if [ "$VERDICT" = PAIRED ]; then
    exit 0
fi
exit 1
