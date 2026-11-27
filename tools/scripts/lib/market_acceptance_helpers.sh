#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Node-driving helpers shared by tools/dev/market_acceptance.sh,
# market_moderation_acceptance.sh and market_onion_acceptance.sh. Source it
# near the top of the script; the helpers read RPC_BIN, NODE_BIN, MKT_WAIT
# and the script's own mkt_die and mkt_result when they run.

mkt_kill_group() {
    local pgid="$1" sig="${2:-TERM}" i
    [ -n "$pgid" ] || return 0
    kill -"$sig" "-$pgid" 2>/dev/null || true
    for i in $(seq 1 50); do
        kill -0 "-$pgid" 2>/dev/null || return 0
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}

mkt_rpc() {
    local dd="$1" port="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" "$RPC_BIN" "$@" 2>/dev/null
}

mkt_hex64() {
    local h="$1"
    [ "${#h}" -eq 64 ] || return 1
    case "$h" in
        *[!0-9a-fA-F]*) return 1 ;;
        *[!0]*) return 0 ;;
        *) return 1 ;;
    esac
}

mkt_native() {
    local dd="$1" rpc="$2"; shift 2
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$@" 2>/dev/null | tail -1
}

mkt_height() {
    mkt_rpc "$1" "$2" getblockcount | mkt_result
}

mkt_wait_rpc() {
    local dd="$1" rpc="$2" pid="$3" deadline
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$pid" 2>/dev/null || return 1
        [ -f "$dd/.cookie" ] && mkt_height "$dd" "$rpc" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}

mkt_wait_height() {
    local dd="$1" rpc="$2" target="$3" deadline h
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        h="$(mkt_height "$dd" "$rpc" 2>/dev/null || true)"
        [ "$h" = "$target" ] && return 0
        sleep 0.5
    done
    return 1
}

# The regtest miner stamps blocks from whole-second wall time.  More than six
# consecutive blocks with one timestamp becomes <= the peer's 11-block MTP
# even though the local submission path accepted the batch.  Mine in groups
# of five with a wall-clock step so the second node validates the same chain.
mkt_mine_to_address() {
    local rpc_fn="$1" count="$2" address="$3" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        "$rpc_fn" generatetoaddress "$chunk" "\"$address\"" | mkt_result >/dev/null
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}

mkt_wait_connected() {
    local dd="$1" rpc="$2" deadline n
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n="$(mkt_rpc "$dd" "$rpc" getconnectioncount 2>/dev/null | mkt_result 2>/dev/null || true)"
        [ "${n:-0}" -ge 1 ] 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}
