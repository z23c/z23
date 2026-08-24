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
#   spawn B -tor without a peer target so both Tor instances bootstrap
#   wait for A's descriptor upload and B's Tor readiness
#   trigger B's onion dial through isolated RPC
#   poll getconnectioncount 150s
#
# Hostname creation is not publication. Cycle 3 (2026-08-23T19:49:55Z,
# onion=qi4klh77naxt6cugxm2cislvgcpbyzmffj2hr2zmbqn22qbjlk4pjxad.onion)
# launched B at onion_ready_s=31 after the hostname file appeared, then
# finished DESCRIPTOR_NOT_UPLOADED with dial_attempted=true. Do not infer
# upload from timing or from hs_service_callback / Dynhost-activated lines.
#
# Appends one JSON object per run to host-local referee state:
#   {"ts":"...","head_sha":"...","verdict":"TOKEN","paired_at_s":N|null,
#    "dial_attempted":true|false,"rendezvous_seen":true|false,
#    "descriptor_uploaded":true|false,"client_tor_ready":true|false,
#    "introduce1_seen":true|false,
#    "rendezvous1_seen":true|false,"circuit_ready":true|false,
#    "p2p_framing_seen":true|false}
#
# verdict is a named token only. PAIRED means getconnectioncount >= 1 within
# the poll window and every declared stage was observed. Any miss is the
# first-dead-stage token; every boolean records what that run actually saw.
#
# Usage:
#   tools/scripts/onion_pair_watch.sh            # live two-node probe
#   tools/scripts/onion_pair_watch.sh --selftest # hermetic, no spawn
#
# Environment:
#   PAIR_PROBE_FILE           JSONL path (default local state below)
#   PAIR_WATCH_PORT_BASE      first probe-owned quad base (default 39250)
#   PAIR_WATCH_PORT_QUAD_ATTEMPTS  bounded quads to inspect (default 32)
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
PROBE_QUAD_FLOOR=39250
PROBE_PORT_BASE=${PAIR_WATCH_PORT_BASE:-39250}
PROBE_PORT_QUAD_ATTEMPTS=${PAIR_WATCH_PORT_QUAD_ATTEMPTS:-32}
ISO_PORT_BASE=$PROBE_PORT_BASE
ISO_PEER_PORT_BASE=""
ISO_FLEET_DIR="$REPO_ROOT/deploy/devfleet"
SELFTEST=0
LIVE_PROBE_DEFAULT="${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23-referee/pair_probe.jsonl"

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
    case ${STAGE:-env} in
        env) echo ENV_MISSING_BINARY ;;
        ports) echo PORT_QUAD_EXHAUSTED ;;
        spawn_a) echo SPAWN_A_FAILED ;;
        rpc_a) echo RPC_A_NOT_READY ;;
        onion)
            if [ -n "${ONION_ADDR:-}" ]; then
                echo DESCRIPTOR_NOT_UPLOADED
            else
                echo ONION_HOSTNAME_TIMEOUT
            fi
            ;;
        spawn_b) echo SPAWN_B_FAILED ;;
        rpc_b) echo RPC_B_NOT_READY ;;
        ready|pair|*)
            if [ "${DESCRIPTOR_UPLOADED:-false}" != true ]; then
                echo DESCRIPTOR_NOT_UPLOADED
            elif [ "${CLIENT_TOR_READY:-false}" != true ]; then
                echo CLIENT_TOR_NOT_READY
            elif [ "${DIAL_ATTEMPTED:-false}" != true ]; then
                echo DIAL_NOT_ATTEMPTED
            elif [ "${INTRODUCE1_SEEN:-false}" != true ]; then
                echo INTRODUCE1_NOT_SEEN
            elif [ "${RENDEZVOUS1_SEEN:-false}" != true ]; then
                echo RENDEZVOUS1_NOT_SEEN
            elif [ "${CIRCUIT_READY:-false}" != true ]; then
                echo CIRCUIT_NOT_READY
            elif [ "${P2P_FRAMING_SEEN:-false}" != true ] ||
                 [ "${PAIRED:-0}" != 1 ]; then
                echo P2P_FRAMING_NOT_SEEN
            else
                echo PAIRED
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
    printf '{"ts":"%s","head_sha":"%s","verdict":"%s","paired_at_s":%s,"dial_attempted":%s,"rendezvous_seen":%s,"descriptor_uploaded":%s,"client_tor_ready":%s,"introduce1_seen":%s,"rendezvous1_seen":%s,"circuit_ready":%s,"p2p_framing_seen":%s}\n' \
        "${TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
        "${HEAD_SHA:-unknown}" \
        "$VERDICT" \
        "$(num_or_null "${PAIRED_AT_S:-}")" \
        "$(json_bool "${DIAL_ATTEMPTED:-false}")" \
        "$(json_bool "${RENDEZVOUS_SEEN:-false}")" \
        "$(json_bool "${DESCRIPTOR_UPLOADED:-false}")" \
        "$(json_bool "${CLIENT_TOR_READY:-false}")" \
        "$(json_bool "${INTRODUCE1_SEEN:-false}")" \
        "$(json_bool "${RENDEZVOUS1_SEEN:-false}")" \
        "$(json_bool "${CIRCUIT_READY:-false}")" \
        "$(json_bool "${P2P_FRAMING_SEEN:-false}")" \
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
    # Client dial: accept the boot-time line for backward-compatible ledgers;
    # the monotonic dial_started counter below is authoritative for the
    # descriptor-gated RPC path.
    if log_has "${ISO_PEER_DD:-}/node.log" "Connecting to onion addnode"; then
        DIAL_ATTEMPTED=true
    fi
    # Exact client/service milestones from the maintained Tor fork. Queuing a
    # dynhost stream is only intent; it is not INTRODUCE1 or rendezvous proof.
    if log_has "${ISO_PEER_DD:-}/tor.log" "INTRODUCE1 sent"; then
        INTRODUCE1_SEEN=true
    fi
    if log_has "${ISO_DD:-}/tor.log" "RENDEZVOUS1 sent"; then
        RENDEZVOUS1_SEEN=true
    fi
    if [ "$INTRODUCE1_SEEN" = true ] && [ "$RENDEZVOUS1_SEEN" = true ]; then
        RENDEZVOUS_SEEN=true
    fi
    # RENDEZVOUS2 is Tor's exact client-side circuit-ready milestone. The
    # public counter is the application-side equivalent and survives stdio
    # buffering or log rotation. Query both: either is exact evidence that
    # the raw stream reached CONNECTED.
    if log_has "${ISO_PEER_DD:-}/node.log" \
        "onion stage=circuit_ready|onion circuit established" ||
       log_has "${ISO_PEER_DD:-}/tor.log" "RENDEZVOUS2 received"; then
        CIRCUIT_READY=true
    fi
    if [ -n "${ISO_PEER_DD:-}" ] && [ -f "${ISO_PEER_DD}/.cookie" ]; then
        local status tor_ready dial circuit bytes_to bytes_from
        status=$(iso_peer_rpc onionstatus)
        tor_ready=$(printf '%s' "$status" | "$ZCL_JSONQ" get \
            result.tor_ready 2>/dev/null || true)
        dial=$(printf '%s' "$status" | "$ZCL_JSONQ" get \
            result.outbound_streams.dial_started 2>/dev/null || true)
        circuit=$(printf '%s' "$status" | "$ZCL_JSONQ" get \
            result.outbound_streams.circuit_ready 2>/dev/null || true)
        bytes_to=$(printf '%s' "$status" | "$ZCL_JSONQ" get \
            result.outbound_streams.bytes_to_peer 2>/dev/null || true)
        bytes_from=$(printf '%s' "$status" | "$ZCL_JSONQ" get \
            result.outbound_streams.bytes_from_peer 2>/dev/null || true)
        [ "$tor_ready" = true ] && CLIENT_TOR_READY=true
        case $dial in
            ''|*[!0-9]*) ;;
            *) [ "$dial" -gt 0 ] && DIAL_ATTEMPTED=true ;;
        esac
        case $circuit in
            ''|*[!0-9]*) ;;
            *) [ "$circuit" -gt 0 ] && CIRCUIT_READY=true ;;
        esac
        case $bytes_to:$bytes_from in
            *[!0-9:]*) ;;
            :|*:|:*) ;;
            *)
                if [ "$bytes_to" -gt 0 ] || [ "$bytes_from" -gt 0 ]; then
                    P2P_FRAMING_SEEN=true
                fi
                ;;
        esac
    fi
    # Service half: require a successful HSDir upload or the application
    # marker emitted only after that success. Hostname creation, activation,
    # and callback entry are deliberately insufficient.
    if descriptor_publication_observed; then
        DESCRIPTOR_UPLOADED=true
    fi
}

# Success-only publication, matching lib/net/src/tor_integration.c
# tor_log_has_descriptor_publication(). Hostname-file presence, the
# "waiting for DESCRIPTOR PUBLICATION" stdout line, hs_service_callback
# running, calling dynhost_check_and_activate, and "Dynhost service
# successfully activated" are not upload.
descriptor_publication_observed() {
    if log_has "${ISO_DD:-}/tor.log" \
        "Hidden service descriptor upload complete|Uploaded hidden service descriptor \\(status 200|Uploading hidden service descriptor: finished with status 200|HS_DESC UPLOADED"; then
        return 0
    fi
    if log_has "${ISO_DD:-}/node.log" \
        "DESCRIPTOR PUBLICATION observed|Uploaded hidden service descriptor \\(status 200|HS_DESC UPLOADED"; then
        return 0
    fi
    return 1
}

read_onion_hostname() {
    local hn addr
    hn="${ISO_DD:-}/tor_data/onion_service/hostname"
    [ -f "$hn" ] || return 1
    addr=$(tr -d ' \n' <"$hn")
    case $addr in
        ????????????????????????????????????????????????????????.onion)
            ONION_ADDR=$addr
            return 0
            ;;
    esac
    return 1
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

# Unit files own their published P2P_PORT values even while stopped. Add
# those ports to the same refuse-set used by the bounded quad allocator
# before inspecting any candidate.
iso_append_published_fleet_ports

probe_port_is_listening() {
    local p=$1
    ss -tlnH "sport = :$p" 2>/dev/null | grep -q .
}

probe_port_is_reserved() {
    local p=$1 live
    for live in $ISO_LIVE_PORTS; do
        [ "$p" = "$live" ] && return 0
    done
    return 1
}

probe_quad_available() {
    local quad_base=$1 offset=0 p
    while [ "$offset" -lt 4 ]; do
        p=$((quad_base + offset))
        if probe_port_is_reserved "$p" || probe_port_is_listening "$p"; then
            return 1
        fi
        offset=$((offset + 1))
    done
    return 0
}

# Rent two non-overlapping quads solely from the probe-owned 39250+ band.
# Every port in a candidate quad is checked. Occupied quads are skipped in
# four-port steps; the fixed attempt count bounds both work and port reach.
select_probe_port_quads() {
    local candidate attempts inspected=0
    candidate=$PROBE_PORT_BASE
    attempts=$PROBE_PORT_QUAD_ATTEMPTS
    PROBE_PORT_DETAIL=""
    ISO_PORT_BASE=""
    ISO_PEER_PORT_BASE=""

    case $candidate in
        ''|*[!0-9]*) PROBE_PORT_DETAIL="base_not_numeric"; return 1 ;;
    esac
    case $attempts in
        ''|*[!0-9]*) PROBE_PORT_DETAIL="attempts_not_numeric"; return 1 ;;
    esac
    if [ "$candidate" -lt 39250 ] || [ "$candidate" -gt 39995 ]; then
        PROBE_PORT_DETAIL="base_out_of_probe_band"
        return 1
    fi
    if [ "$attempts" -lt 2 ] || [ "$attempts" -gt 128 ]; then
        PROBE_PORT_DETAIL="attempt_budget_out_of_range"
        return 1
    fi

    while [ "$inspected" -lt "$attempts" ]; do
        if [ $((candidate + 3)) -ge "$ISO_CONNECT_SINK" ]; then
            PROBE_PORT_DETAIL="probe_band_exhausted"
            break
        fi
        if probe_quad_available "$candidate"; then
            if [ -z "$ISO_PORT_BASE" ]; then
                ISO_PORT_BASE=$candidate
            else
                ISO_PEER_PORT_BASE=$candidate
                PROBE_PORT_DETAIL="selected"
                return 0
            fi
        fi
        candidate=$((candidate + 4))
        inspected=$((inspected + 1))
    done
    [ -n "$PROBE_PORT_DETAIL" ] || PROBE_PORT_DETAIL="no_two_free_quads_in_${attempts}_attempts"
    return 1
}

HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
T0=$(now_s)
PROBE_WRITTEN=0
PAIRED=0
PAIRED_AT_S=""
DIAL_ATTEMPTED=false
RENDEZVOUS_SEEN=false
DESCRIPTOR_UPLOADED=false
CLIENT_TOR_READY=false
INTRODUCE1_SEEN=false
RENDEZVOUS1_SEEN=false
CIRCUIT_READY=false
P2P_FRAMING_SEEN=false
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
    CLIENT_TOR_READY=false
    INTRODUCE1_SEEN=false RENDEZVOUS1_SEEN=false CIRCUIT_READY=false P2P_FRAMING_SEEN=false
    st_check "env miss is ENV_MISSING_BINARY" ENV_MISSING_BINARY "$(named_verdict)"
    STAGE=ports
    st_check "no free probe quad is PORT_QUAD_EXHAUSTED" PORT_QUAD_EXHAUSTED "$(named_verdict)"
    if [ "$PROBE_QUAD_FLOOR" = 39250 ]; then
        echo "  ok: probe quad floor is 39250"
    else
        echo "  FAIL: probe quad floor is $PROBE_QUAD_FLOOR (want 39250)"
        st_fail=1
    fi
    if probe_port_is_reserved 39360; then
        echo "  ok: published node2 P2P 39360 is reserved"
    else
        echo "  FAIL: published node2 P2P 39360 must never be a bind candidate"
        st_fail=1
    fi
    if probe_port_is_reserved 39150; then
        echo "  ok: published node3 P2P 39150 is reserved"
    else
        echo "  FAIL: published node3 P2P 39150 must never be a bind candidate"
        st_fail=1
    fi
    if [ "$PROBE_QUAD_FLOOR" -ge 39250 ] &&
       ! probe_port_is_reserved 39250; then
        echo "  ok: documented probe base 39250 is not fleet-owned"
    else
        echo "  FAIL: documented probe base 39250 is forbidden"
        st_fail=1
    fi
    STAGE=spawn_a
    st_check "spawn A miss is SPAWN_A_FAILED" SPAWN_A_FAILED "$(named_verdict)"
    STAGE=rpc_a
    st_check "rpc A miss is RPC_A_NOT_READY" RPC_A_NOT_READY "$(named_verdict)"
    STAGE=ports
    st_check "port exhaustion is PORT_QUAD_EXHAUSTED" PORT_QUAD_EXHAUSTED "$(named_verdict)"
    STAGE=onion ONION_ADDR=""
    st_check "hostname miss is ONION_HOSTNAME_TIMEOUT" ONION_HOSTNAME_TIMEOUT "$(named_verdict)"
    STAGE=onion ONION_ADDR="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
    st_check "hostname without upload is DESCRIPTOR_NOT_UPLOADED" DESCRIPTOR_NOT_UPLOADED "$(named_verdict)"
    ONION_ADDR=""
    STAGE=spawn_b
    st_check "spawn B miss is SPAWN_B_FAILED" SPAWN_B_FAILED "$(named_verdict)"
    STAGE=rpc_b
    st_check "rpc B miss is RPC_B_NOT_READY" RPC_B_NOT_READY "$(named_verdict)"
    STAGE=ready
    st_check "unpublished service is DESCRIPTOR_NOT_UPLOADED" DESCRIPTOR_NOT_UPLOADED "$(named_verdict)"
    DESCRIPTOR_UPLOADED=true
    st_check "unready client Tor is CLIENT_TOR_NOT_READY" CLIENT_TOR_NOT_READY "$(named_verdict)"
    CLIENT_TOR_READY=true
    st_check "ready loop with no dial is DIAL_NOT_ATTEMPTED" DIAL_NOT_ATTEMPTED "$(named_verdict)"
    DIAL_ATTEMPTED=true
    STAGE=pair
    st_check "descriptor up, no INTRODUCE1 is INTRODUCE1_NOT_SEEN" INTRODUCE1_NOT_SEEN "$(named_verdict)"
    INTRODUCE1_SEEN=true
    st_check "INTRODUCE1, no RENDEZVOUS1 is RENDEZVOUS1_NOT_SEEN" RENDEZVOUS1_NOT_SEEN "$(named_verdict)"
    RENDEZVOUS1_SEEN=true RENDEZVOUS_SEEN=true
    st_check "rendezvous, no circuit is CIRCUIT_NOT_READY" CIRCUIT_NOT_READY "$(named_verdict)"
    CIRCUIT_READY=true
    st_check "circuit, no P2P framing is P2P_FRAMING_NOT_SEEN" P2P_FRAMING_NOT_SEEN "$(named_verdict)"
    PAIRED=1 PAIRED_AT_S=5 P2P_FRAMING_SEEN=true
    st_check "getconnectioncount>=1 is PAIRED" PAIRED "$(named_verdict)"

    # The first simulated quad is occupied. The allocator must advance by a
    # whole quad and return the next two free quads, never base+node math.
    probe_port_is_listening() {
        [ "$1" = 39250 ]
    }
    PROBE_PORT_BASE=39250
    PROBE_PORT_QUAD_ATTEMPTS=3
    if select_probe_port_quads &&
       [ "$ISO_PORT_BASE" = 39254 ] &&
       [ "$ISO_PEER_PORT_BASE" = 39258 ]; then
        echo "  ok: occupied quad advances to two dedicated free quads"
    else
        echo "  FAIL: bounded quad allocator selected primary=$ISO_PORT_BASE peer=$ISO_PEER_PORT_BASE detail=$PROBE_PORT_DETAIL"
        st_fail=1
    fi
    PROBE_PORT_QUAD_ATTEMPTS=2
    if select_probe_port_quads; then
        echo "  FAIL: allocator exceeded its bounded two-quad search"
        st_fail=1
    else
        echo "  ok: bounded search fails when two free quads are unavailable"
    fi

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

STAGE=ports
if ! select_probe_port_quads; then
    VERDICT=PORT_QUAD_EXHAUSTED
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=$PROBE_PORT_DETAIL base=$PROBE_PORT_BASE attempts=$PROBE_PORT_QUAD_ATTEMPTS"
    exit 1
fi
echo "probe_port_quads primary=$ISO_PORT_BASE-$((ISO_PORT_BASE + 3)) peer=$ISO_PEER_PORT_BASE-$((ISO_PEER_PORT_BASE + 3))"

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
# The cleanup trap retains the PID/PGID and remains the sole lifetime owner.
# Remove the child only from Bash's job table so intentional trap teardown
# cannot print a misleading asynchronous "Killed" notification.
disown "$ISO_NODE_PID" 2>/dev/null || true
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
    if read_onion_hostname; then
        break
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

# ── B: isolated peer quad. Bootstrap Tor without spending an onion-stream
# budget; the target is added only after A's descriptor and B's own Tor are
# both observed ready below.
STAGE=spawn_b
[ "$ISO_PEER_HTTPSPORT" -lt "$ISO_CONNECT_SINK" ] \
    || iso_die "peer port quad reaches the dead-connect sink"
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
    -listen -tor -onion-persist \
    -operator-lane=test \
    -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
    </dev/null >"$ISO_PEER_DD/node.log" 2>&1 &
ISO_PEER_PID=$!
ISO_PEER_PGID="$ISO_PEER_PID"
# As with A, disown changes only Bash job reporting. The recorded process
# group is still terminated by the fail-closed isolation cleanup trap.
disown "$ISO_PEER_PID" 2>/dev/null || true
if [ -z "$ISO_PEER_PID" ] || ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
    VERDICT=SPAWN_B_FAILED
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=spawn_b_dead"
    exit 1
fi
echo "spawned B pid=$ISO_PEER_PID p2p=$ISO_PEER_PORT bootstrap_only=true"

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

# Observe the two prerequisites in parallel. PAIR_POLL remains the existing
# bounded public-network allowance; this wait does not start or retry a
# dynhost stream, so no circuit budget is spent before the descriptor exists.
STAGE=ready
ready_deadline=$(( $(now_s) + PAIR_POLL ))
while [ "$(now_s)" -lt "$ready_deadline" ]; do
    if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
        VERDICT=SPAWN_A_FAILED
        append_probe
        echo "PAIR_PROBE=$VERDICT DETAIL=a_exited_during_readiness"
        exit 1
    fi
    if [ -n "$ISO_PEER_PID" ] && ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
        VERDICT=SPAWN_B_FAILED
        append_probe
        echo "PAIR_PROBE=$VERDICT DETAIL=b_exited_during_readiness"
        exit 1
    fi
    observe_stages
    if [ "$DESCRIPTOR_UPLOADED" = true ] &&
       [ "$CLIENT_TOR_READY" = true ]; then
        break
    fi
    sleep 2
done
if [ "$DESCRIPTOR_UPLOADED" != true ] || [ "$CLIENT_TOR_READY" != true ]; then
    VERDICT=$(named_verdict)
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=readiness_timeout descriptor_uploaded=$DESCRIPTOR_UPLOADED client_tor_ready=$CLIENT_TOR_READY"
    exit 1
fi
echo "dial_prerequisites_ready_s=$(elapsed) descriptor_uploaded=true client_tor_ready=true"

# The operator-directed RPC is the single dial edge. Its result is checked
# before polling; a refused trigger is a named DIAL_NOT_ATTEMPTED failure.
STAGE=pair
dial_out=$(iso_peer_rpc addnode "\"${ONION_ADDR}:${ISO_PORT}\"" '"onetry"')
if ! printf '%s' "$dial_out" | "$ZCL_JSONQ" eq error null \
    >/dev/null 2>&1; then
    VERDICT=DIAL_NOT_ATTEMPTED
    append_probe
    echo "PAIR_PROBE=$VERDICT DETAIL=addnode_rpc_refused"
    exit 1
fi
observe_stages

# ── poll getconnectioncount and exact framing stages
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
    if [ "$n" -ge 1 ] && [ "$P2P_FRAMING_SEEN" = true ]; then
        PAIRED=1
        PAIRED_AT_S=$(elapsed)
        break
    fi
    sleep 2
done
observe_stages
VERDICT=$(named_verdict)
append_probe
echo "PAIR_PROBE=$VERDICT paired_at_s=${PAIRED_AT_S:-null} dial_attempted=$DIAL_ATTEMPTED descriptor_uploaded=$DESCRIPTOR_UPLOADED client_tor_ready=$CLIENT_TOR_READY introduce1_seen=$INTRODUCE1_SEEN rendezvous1_seen=$RENDEZVOUS1_SEEN circuit_ready=$CIRCUIT_READY p2p_framing_seen=$P2P_FRAMING_SEEN onion=$ONION_ADDR"
if [ "$VERDICT" = PAIRED ]; then
    exit 0
fi
exit 1
