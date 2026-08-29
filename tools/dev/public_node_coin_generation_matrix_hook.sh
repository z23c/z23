#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Physical adversarial campaign for the mempool/coins/finalization ownership
# boundary.  This is a composition hook for zcode_dht_acceptance.sh: it reuses
# that harness's process ownership, encrypted fixture wallets, authenticated
# three-node topology, confined proof workers, cleanup, and port-rebind proof.
# Canonical chain/mempool/coins facts remain the only acceptance authority.

ZAPS_HELPERS_ONLY=1
# shellcheck source=tools/dev/zcode_async_proof_scaling_hook.sh
. "$SCRIPT_DIR/zcode_async_proof_scaling_hook.sh"
unset ZAPS_HELPERS_ONLY

PCM_RUNS="${ZCL_COIN_MATRIX_RUNS:-10}"
PCM_SEED="${ZCL_COIN_MATRIX_SEED:-}"
case "$PCM_RUNS" in
    ''|*[!0-9]*) dht_die "coin matrix run count must be an integer" ;;
esac
[ "$PCM_RUNS" -ge 1 ] || dht_die "coin matrix requires at least one run"
if [ -z "$PCM_SEED" ]; then
    PCM_SEED="$(od -An -N8 -tu8 /dev/urandom | tr -d ' ')"
fi
case "$PCM_SEED" in
    ''|*[!0-9]*) dht_die "coin matrix seed must be an unsigned integer" ;;
esac

PCM_ROOT="$DHT_WORK/public-node-coin-generation"
PCM_SCHEDULE="$PCM_ROOT/schedule.csv"
PCM_METRICS="$PCM_ROOT/metrics.csv"
PCM_RESOURCES="$PCM_ROOT/resources.csv"
mkdir -p "$PCM_ROOT"
printf '%s\n' \
    'run,seed,miner_a,miner_b,restart_node,proof_actions' >"$PCM_SCHEDULE"
printf '%s\n' \
    'run,phase,node,elapsed_ms,value,ok' >"$PCM_METRICS"
printf '%s\n' \
    'run,phase,node,cpu_ticks,read_bytes,write_bytes,rss_kb,connections,height' \
    >"$PCM_RESOURCES"

JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"
[ -x "$JSONQ" ] || dht_die "build/bin/jsonq is missing — run make jsonq"

pcm_json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

pcm_field() {
    "$JSONQ" get "$1"
}

pcm_rpc_result() {
    local node="$1"; shift
    dht_rpc "${DDS[$node]}" "${RPCS[$node]}" "$@" | dht_result
}

pcm_hash_at() {
    local node="$1" height="$2"
    pcm_rpc_result "$node" getblockhash "$height"
}

pcm_mempool_count() {
    local node="$1" txid="$2" rows n i tx count=0
    rows="$(pcm_rpc_result "$node" getrawmempool 2>/dev/null || true)"
    n="$(printf '%s' "$rows" | "$JSONQ" count . 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) printf '%s' -1; return ;;
    esac
    i=0
    while [ "$i" -lt "$n" ]; do
        tx="$(printf '%s' "$rows" | "$JSONQ" get "[$i]" 2>/dev/null || true)"
        [ "$tx" = "$txid" ] && count=$((count + 1))
        i=$((i + 1))
    done
    printf '%s' "$count"
}

pcm_wait_mempool_count() {
    local node="$1" txid="$2" want="$3" deadline count
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        count="$(pcm_mempool_count "$node" "$txid")"
        [ "$count" = "$want" ] && return 0
        sleep 0.1
    done
    return 1
}

pcm_wait_tip() {
    local node="$1" height="$2" hash="$3" deadline got_h got_hash
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        got_h="$(dht_height "${DDS[$node]}" "${RPCS[$node]}" 2>/dev/null || true)"
        if [ "$got_h" = "$height" ]; then
            got_hash="$(pcm_hash_at "$node" "$height" 2>/dev/null || true)"
            [ "$got_hash" = "$hash" ] && return 0
        fi
        sleep 0.1
    done
    return 1
}

pcm_wait_all_tip() {
    local height="$1" hash="$2" node
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        pcm_wait_tip "$node" "$height" "$hash" ||
            dht_die "coin matrix node $node did not reach h=$height hash=$hash"
    done
}

pcm_metric() {
    local run="$1" phase="$2" node="$3" elapsed="$4" value="$5" ok="$6"
    printf '%s,%s,%s,%s,%s,%s\n' \
        "$run" "$phase" "$node" "$elapsed" "$value" "$ok" \
        >>"$PCM_METRICS"
}

pcm_resource_snapshot() {
    local run="$1" phase="$2" node cpu read_bytes write_bytes rss conns height
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        cpu="$(zaps_proc_cpu_ticks "$node")"
        read_bytes="$(zaps_proc_io_value "$node" read_bytes)"
        write_bytes="$(zaps_proc_io_value "$node" write_bytes)"
        rss="$(awk '$1 == "VmRSS:" { print $2; found=1 } END { if (!found) print 0 }' \
            "/proc/${PIDS[$node]}/status" 2>/dev/null || true)"
        conns="$(pcm_rpc_result "$node" getconnectioncount)"
        height="$(dht_height "${DDS[$node]}" "${RPCS[$node]}")"
        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$run" "$phase" "$node" "$cpu" "$read_bytes" "$write_bytes" \
            "${rss:-0}" "$conns" "$height" >>"$PCM_RESOURCES"
    done
}

pcm_peer_state_ready() {
    case "$1" in
        handshake_complete|active|syncing_headers|syncing_blocks|snapshot_serving|snapshot_receiving)
            return 0
            ;;
        *) return 1 ;;
    esac
}

pcm_ready_peer_count() {
    local node="$1" rows n i state count=0
    rows="$(pcm_rpc_result "$node" getpeerinfo 2>/dev/null || true)"
    n="$(printf '%s' "$rows" | "$JSONQ" count . 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) printf '%s' -1; return ;;
    esac
    i=0
    while [ "$i" -lt "$n" ]; do
        state="$(printf '%s' "$rows" | "$JSONQ" get "[$i].state" 2>/dev/null || true)"
        if pcm_peer_state_ready "$state"; then
            count=$((count + 1))
        fi
        i=$((i + 1))
    done
    printf '%s' "$count"
}

pcm_wait_relay_floor() {
    local node="$1" want="$2" deadline ready
    deadline=$(( $(date +%s) + DHT_WAIT ))
    ready=-1
    while [ "$(date +%s)" -lt "$deadline" ]; do
        ready="$(pcm_ready_peer_count "$node")"
        case "$ready" in
            ''|*[!0-9]*) ready=-1 ;;
        esac
        [ "$ready" -ge "$want" ] && return 0
        sleep 0.1
    done
    return 1
}

pcm_ready_peer_snapshot() {
    local node="$1" target rows n i live owners state pid inbound addr
    if [ "$node" = "$ZAP_A" ]; then
        target="127.0.0.1:${PORTS[$ZAP_B]}"
    elif [ "$node" = "$ZAP_B" ]; then
        target="127.0.0.1:${PORTS[$ZAP_C]}"
    elif [ "$node" = "$ZAP_C" ]; then
        target="127.0.0.1:${PORTS[$ZAP_A]}"
    else
        printf '%s' '-1:'
        return
    fi
    rows="$(pcm_rpc_result "$node" getpeerinfo 2>/dev/null || true)"
    n="$(printf '%s' "$rows" | "$JSONQ" count . 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) printf '%s' '-1:'; return ;;
    esac
    i=0
    live=0
    owners=""
    while [ "$i" -lt "$n" ]; do
        state="$(printf '%s' "$rows" | "$JSONQ" get "[$i].state" 2>/dev/null || true)"
        pid="$(printf '%s' "$rows" | "$JSONQ" get "[$i].id" 2>/dev/null || true)"
        inbound="$(printf '%s' "$rows" | "$JSONQ" get "[$i].inbound" 2>/dev/null || true)"
        addr="$(printf '%s' "$rows" | "$JSONQ" get "[$i].addr" 2>/dev/null || true)"
        case "$pid" in
            ''|*[!0-9]*) i=$((i + 1)); continue ;;
        esac
        if pcm_peer_state_ready "$state"; then
            live=$((live + 1))
            if [ "$inbound" != true ] && [ "$addr" = "$target" ]; then
                owners="${owners}${owners:+$'\n'}${pid}"
            fi
        fi
        i=$((i + 1))
    done
    if [ -n "$owners" ]; then
        owners="$(printf '%s\n' "$owners" | sort -n | paste -sd, -)"
    fi
    printf '%s:%s' "$live" "$owners"
}

pcm_wait_mesh_relay_stable() {
    local deadline node snapshot count ids combined previous=""
    local stable_started_ns=0 now_ns
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        combined=""
        for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
            snapshot="$(pcm_ready_peer_snapshot "$node")"
            count="${snapshot%%:*}"
            ids="${snapshot#*:}"
            case "$count" in
                ''|*[!0-9]*) count=-1 ;;
            esac
            if [ "$count" -lt 2 ] || [ -z "$ids" ]; then
                combined=""
                break
            fi
            combined="${combined}${node}:${ids};"
        done
        now_ns="$(date +%s%N)"
        if [ -n "$combined" ] && [ "$combined" = "$previous" ]; then
            [ $((now_ns-stable_started_ns)) -ge 2000000000 ] && return 0
        elif [ -n "$combined" ]; then
            previous="$combined"
            stable_started_ns="$now_ns"
        else
            previous=""
            stable_started_ns=0
        fi
        # The controlled plaintext-to-Noise replacement completes in about
        # one second on the fixture. Require the three declared outbound
        # owner identities, plus a live two-peer floor on every node, to remain
        # unchanged for two wall-clock seconds. Wall time is intentional: RPC
        # latency must not turn a nominal sample count into a hidden timeout.
        sleep 0.1
    done
    return 1
}

pcm_dump_mesh_snapshot() {
    local node
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        echo "zcode-dht-acceptance: coin mesh snapshot node=$node "\
"signature=$(pcm_ready_peer_snapshot "$node") peers=$(pcm_rpc_result "$node" getpeerinfo 2>/dev/null || true)" >&2
    done
}

pcm_quarantine_runtime_discovery() {
    local run="$1" node="$2" rel path q key
    q="$PCM_ROOT/discovery-reset-$run/$node"
    mkdir -p "$q"
    # These are rebuildable runtime routing/contact projections, not endpoint,
    # identity, package, receipt, chain, wallet, or consensus authority. A
    # proof-bearing cold boot otherwise replays every prior run's reachability
    # contacts and autonomously opens extra sessions while the declared relay
    # cycle is still completing its Noise replacement. Preserve the exact old
    # files in the run artifact, then let signed endpoint demand rebuild only
    # the contacts this run actually needs.
    for rel in contacts_projection.db zcode/dht/contacts.v2; do
        path="${DDS[$node]}/$rel"
        [ ! -e "$path" ] || {
            key="${rel//\//__}"
            mv "$path" "$q/$key"
        }
    done
}

pcm_assert_peer_floor() {
    local run="$1" node ready start_ns elapsed
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        start_ns="$(date +%s%N)"
        pcm_wait_relay_floor "$node" 2 ||
            dht_die "coin matrix run $run node $node relay peer floor did not recover within ${DHT_WAIT}s (got=$(pcm_ready_peer_count "$node") want>=2)"
        ready="$(pcm_ready_peer_count "$node")"
        elapsed=$((($(date +%s%N)-start_ns)/1000000))
        pcm_metric "$run" peer_floor "$node" "$elapsed" "$ready" true
    done
}

pcm_assert_mempool_exact() {
    local run="$1" txid="$2" want="$3" label="$4" node
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        pcm_wait_mempool_count "$node" "$txid" "$want" ||
            dht_die "coin matrix run $run $label tx=$txid node=$node want=$want got=$(pcm_mempool_count "$node" "$txid")"
    done
}

pcm_wait_all_mempool_timed() {
    local run="$1" txid="$2" want="$3" phase="$4" started_ns="$5"
    local node elapsed
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        pcm_wait_mempool_count "$node" "$txid" "$want" ||
            dht_die "coin matrix run $run $phase tx=$txid node=$node want=$want got=$(pcm_mempool_count "$node" "$txid")"
        elapsed=$((($(date +%s%N)-started_ns)/1000000))
        pcm_metric "$run" "$phase" "$node" "$elapsed" "$txid" true
    done
}

pcm_command_probe() {
    local run="$1" phase="$2" node started_ns elapsed response
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        started_ns="$(date +%s%N)"
        response="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" core status || true)"
        elapsed=$((($(date +%s%N)-started_ns)/1000000))
        [ "$(printf '%s' "$response" | pcm_field ok 2>/dev/null || true)" = true ] ||
            dht_die "coin matrix run $run command probe failed on node $node: $response"
        pcm_metric "$run" "command_responsiveness_$phase" "$node" "$elapsed" ok true
    done
}

pcm_select_unspent() {
    local node="$1" response n i amount best_i=0 best_amt="" txid vout
    response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" listunspent || true)"
    printf '%s' "$response" | "$JSONQ" eq error null || return 1
    n="$(printf '%s' "$response" | "$JSONQ" count result)" || return 1
    [ "$n" -gt 0 ] || return 1
    i=0
    while [ "$i" -lt "$n" ]; do
        amount="$(printf '%s' "$response" | "$JSONQ" get "result[$i].amount")"
        if [ -z "$best_amt" ] || awk -v a="$amount" -v b="$best_amt" \
            'BEGIN { exit !(a + 0 > b + 0) }'
        then
            best_amt="$amount"
            best_i="$i"
        fi
        i=$((i + 1))
    done
    txid="$(printf '%s' "$response" | "$JSONQ" get "result[$best_i].txid")"
    vout="$(printf '%s' "$response" | "$JSONQ" get "result[$best_i].vout")"
    amount="$(awk -v a="$best_amt" 'BEGIN { printf "%.8f\n", a + 0 }')"
    printf '%s\n%s\n%s\n' "$txid" "$vout" "$amount"
}

# Emit signed hex, txid, and exact output amount on separate lines.  All
# transactions have one input, one wallet-owned output, and no change.
pcm_create_signed_child() {
    local node="$1" parent="$2" vout="$3" amount="$4"
    local inputs outputs out_amount raw_response raw sign_response signed
    local decoded txid esc
    out_amount="$(awk -v a="$amount" 'BEGIN {
        v = a - 0.00100000
        if (!(v > 0)) exit 1
        printf "%.8f\n", v
    }')" || return 1
    esc="$(pcm_json_escape "$ADDR")"
    inputs="[{\"txid\":\"${parent}\",\"vout\":${vout}}]"
    outputs="{\"${esc}\":${out_amount}}"
    raw_response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
        createrawtransaction "$inputs" "$outputs" || true)"
    raw="$(printf '%s' "$raw_response" | dht_result 2>/dev/null || true)"
    [ -n "$raw" ] || return 1
    sign_response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
        signrawtransaction "\"$raw\"" || true)"
    printf '%s' "$sign_response" | "$JSONQ" eq error null || return 1
    printf '%s' "$sign_response" | "$JSONQ" eq result.complete true || return 1
    signed="$(printf '%s' "$sign_response" | "$JSONQ" get result.hex \
        2>/dev/null || true)"
    [ -n "$signed" ] || return 1
    decoded="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
        decoderawtransaction "\"$signed\"" || true)"
    printf '%s' "$decoded" | "$JSONQ" eq error null || return 1
    txid="$(printf '%s' "$decoded" | "$JSONQ" get result.txid \
        2>/dev/null || true)"
    [ "${#txid}" -eq 64 ] || return 1
    printf '%s\n%s\n%s\n' "$signed" "$txid" "$out_amount"
}

pcm_submit_same_node_concurrently() {
    local run="$1" node="$2" raw="$3" txid="$4" label="$5"
    local p1 p2 started_ns elapsed r1 r2
    started_ns="$(date +%s%N)"
    dht_rpc "${DDS[$node]}" "${RPCS[$node]}" sendrawtransaction \
        "\"$raw\"" >"$PCM_ROOT/$run-$label-submit-1.json" 2>&1 & p1="$!"
    dht_rpc "${DDS[$node]}" "${RPCS[$node]}" sendrawtransaction \
        "\"$raw\"" >"$PCM_ROOT/$run-$label-submit-2.json" 2>&1 & p2="$!"
    wait "$p1" || true
    wait "$p2" || true
    elapsed=$((($(date +%s%N)-started_ns)/1000000))
    r1="$(cat "$PCM_ROOT/$run-$label-submit-1.json")"
    r2="$(cat "$PCM_ROOT/$run-$label-submit-2.json")"
    printf '%s\n%s\n' "$r1" "$r2" | grep -Fq "$txid" ||
        dht_die "coin matrix run $run concurrent $label delivery never admitted $txid"
    pcm_metric "$run" concurrent_delivery "$node" "$elapsed" "$txid" true
}

pcm_template_probe() {
    local run="$1" node="$2" started_ns elapsed response
    started_ns="$(date +%s%N)"
    response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
        getblocktemplate '{}' || true)"
    elapsed=$((($(date +%s%N)-started_ns)/1000000))
    printf '%s' "$response" | dht_result >/dev/null 2>&1 ||
        dht_die "coin matrix run $run block template failed: $response"
    pcm_metric "$run" block_template "$node" "$elapsed" ok true
}

pcm_mine_one() {
    local run="$1" node="$2" label="$3" before started_ns elapsed response
    before="$(dht_height "${DDS[$node]}" "${RPCS[$node]}")"
    started_ns="$(date +%s%N)"
    response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
        generatetoaddress 1 "\"$ADDR\"" || true)"
    elapsed=$((($(date +%s%N)-started_ns)/1000000))
    printf '%s' "$response" | dht_result >/dev/null 2>&1 ||
        dht_die "coin matrix run $run $label mining failed: $response"
    pcm_metric "$run" "$label" "$node" "$elapsed" "$((before+1))" true
}

pcm_start_coin_node() {
    local run="$1" node="$2" label="$3"
    local connects=()
    if [ "$node" = "$ZAP_A" ]; then
        connects+=("127.0.0.1:${PORTS[$ZAP_B]}")
    elif [ "$node" = "$ZAP_B" ]; then
        connects+=("127.0.0.1:${PORTS[$ZAP_C]}")
    elif [ "$node" = "$ZAP_C" ]; then
        connects+=("127.0.0.1:${PORTS[$ZAP_A]}")
    else
        dht_die "coin matrix run $run $label unknown coin-mesh node $node"
    fi
    dht_spawn "PIDS[$node]" "${DDS[$node]}" "${PORTS[$node]}" \
        "${RPCS[$node]}" "${FSPORTS[$node]}" "${HTTPSPORTS[$node]}" \
        "${connects[@]}"
    dht_wait_rpc "${DDS[$node]}" "${RPCS[$node]}" "${PIDS[$node]}" ||
        dht_die "coin matrix run $run $label node $node failed to start"
}

pcm_reset_coin_mesh() {
    local run="$1" height="$2" hash="$3" node started_ns elapsed
    started_ns="$(date +%s%N)"
    # Package proofs have completed and their exact receipts are durable.
    # Replace their demand-driven DHT sessions with one directed P2P owner per
    # physical edge: A->B, B->C, and C->A. This prevents simultaneous
    # bidirectional redials from turning a coin/finalization restart into
    # duplicate-session churn. The cycle also gives every freshly restarted
    # node an outbound peer, which is the sync state machine's authority to
    # request headers rather than merely serve its two inbound relay peers.
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        dht_kill_group "${PIDS[$node]:-}"
        PIDS[$node]=""
        pcm_quarantine_runtime_discovery "$run-coin" "$node"
    done
    # Proof receipts are durable before this boundary. The subsequent coin,
    # cache, restart, and reorg assertions need only the public-node P2P
    # service, so do not let persisted package demand reopen competing overlay
    # sessions while the single-owner relay cycle is under test.
    DHT_PACKAGEHOST=0
    DHT_BUILDWORKERS=0
    pcm_start_coin_node "$run" "$ZAP_A" coin_phase_mesh_restart
    pcm_start_coin_node "$run" "$ZAP_B" coin_phase_mesh_restart
    pcm_start_coin_node "$run" "$ZAP_C" coin_phase_mesh_restart
    DHT_EXTRA_PGIDS=(
        "${PIDS[$ZAP_A]}" "${PIDS[$ZAP_B]}" "${PIDS[$ZAP_C]}")
    pcm_wait_mesh_relay_stable || {
        pcm_dump_mesh_snapshot
        dht_die "coin matrix run $run coin-phase mesh did not stabilize"
    }
    pcm_wait_all_tip "$height" "$hash"
    dht_unlock_wallet "${DDS[$PCM_CHAIN_OWNER]}" \
        "${RPCS[$PCM_CHAIN_OWNER]}" ||
        dht_die "coin matrix run $run coin-phase wallet unlock failed"
    elapsed=$((($(date +%s%N)-started_ns)/1000000))
    pcm_metric "$run" coin_phase_mesh_restart "$PCM_CHAIN_OWNER" \
        "$elapsed" "$height" true
}

pcm_restart_node() {
    local run="$1" node="$2" height="$3" hash="$4" label="$5"
    local old_pid old_start="" started_ns elapsed first second new_start
    old_pid="${PIDS[$node]:-}"
    if [ -n "$old_pid" ]; then
        old_start="$(awk '{print $22}' "/proc/$old_pid/stat")"
        dht_kill_group "$old_pid"; PIDS[$node]=""
    fi
    if [ "$node" != "$ZAP_A" ]; then first="$ZAP_A"; else first="$ZAP_B"; fi
    if [ "$node" != "$ZAP_C" ]; then second="$ZAP_C"; else second="$ZAP_B"; fi
    [ "$first" != "$node" ] && [ "$second" != "$node" ] && [ "$first" != "$second" ] ||
        dht_die "coin matrix restart topology selection failed"
    started_ns="$(date +%s%N)"
    # Preserve the coin mesh's single directed owner per physical edge. The
    # surviving predecessor redials its owned inbound edge, while this node
    # redials its one assigned outbound edge. Proof actions finish before the
    # coin phase and therefore cannot create competing DHT reachability dials
    # here.
    pcm_start_coin_node "$run" "$node" "$label"
    # Keep both physical P2P edges. Proof actions, when present, prove
    # their own authenticated remote execution and signed receipts before this
    # restart. Do not make a coin/finalization restart depend on a live DHT
    # session when the randomized run has no package work: the overlay may
    # legitimately be idle or between bounded reachability attempts, whereas
    # transaction relay requires the two base P2P edges below.
    # The DHT Noise session and the base P2P noise-upgrade reconnect have
    # independent readiness.  A transaction admitted in the gap is valid but
    # honestly has zero relay peers and is not retroactively announced when
    # the P2P handshakes finish.  Require both physical edges to reach the
    # node's relay-ready states before the restart is declared recovered.
    pcm_wait_relay_floor "$node" 2 ||
        dht_die "coin matrix run $run $label node $node did not recover two relay-ready peers"
    # Relay readiness is directional, and getpeerinfo briefly retains a
    # completed plaintext handshake after its controlled Noise replacement
    # has been requested. Require the complete three-node peer-ID set to stay
    # unchanged across that replacement window before admitting a transaction.
    pcm_wait_mesh_relay_stable ||
        dht_die "coin matrix run $run $label mesh did not reach a stable symmetric relay floor"
    if ! pcm_wait_tip "$node" "$height" "$hash"; then
        local diag_node diag_height diag
        for diag_node in "$node" "$first" "$second"; do
            for diag_height in "$((height-1))" "$height"; do
                diag="$(dht_native "${DDS[$diag_node]}" "${RPCS[$diag_node]}" \
                    dumpstate block_index "$diag_height" || true)"
                echo "zcode-dht-acceptance: coin matrix stall block_index node=$diag_node height=$diag_height: $diag" >&2
            done
            diag="$(dht_native "${DDS[$diag_node]}" "${RPCS[$diag_node]}" \
                dumpstate reducer_frontier || true)"
            echo "zcode-dht-acceptance: coin matrix stall reducer_frontier node=$diag_node: $diag" >&2
        done
        dht_die "coin matrix run $run $label node $node failed to recover tip"
    fi
    elapsed=$((($(date +%s%N)-started_ns)/1000000))
    new_start="$(awk '{print $22}' "/proc/${PIDS[$node]}/stat")"
    if [ -n "$old_start" ]; then
        [ "$new_start" != "$old_start" ] ||
            dht_die "coin matrix run $run $label did not replace process identity"
    fi
    if [ "$node" = "$PCM_CHAIN_OWNER" ]; then
        dht_unlock_wallet "${DDS[$node]}" "${RPCS[$node]}" ||
            dht_die "coin matrix run $run chain-owner wallet remained locked after restart"
    fi
    pcm_metric "$run" "$label" "$node" "$elapsed" "$height" true
}

pcm_reset_mesh() {
    local run="$1" proof_count="${2:-1}" height hash node started_ns elapsed
    height="$(dht_height "${DDS[$ZAP_A]}" "${RPCS[$ZAP_A]}")"
    hash="$(pcm_hash_at "$ZAP_A" "$height")"
    started_ns="$(date +%s%N)"

    # Every randomized sample begins with new process identities and empty
    # in-memory reachability/backoff state. Durable chain, wallet, endpoint,
    # task, and receipt authorities remain in their isolated datadirs.
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        dht_kill_group "${PIDS[$node]:-}"
        PIDS[$node]=""
        pcm_quarantine_runtime_discovery "$run-baseline" "$node"
    done
    # Only proof-bearing samples need package hosting, workers, and overlay
    # authentication. A zero-proof sample must not fail on a service it never
    # uses; it begins directly in the public-node-only posture.
    if [ "$proof_count" -gt 0 ]; then
        DHT_PACKAGEHOST=1
        DHT_BUILDWORKERS=1
    else
        DHT_PACKAGEHOST=0
        DHT_BUILDWORKERS=0
    fi
    # Use the same single-owner physical graph as the coin phase, then demand
    # authenticated DHT sessions over those already-owned edges. Extra
    # one-shot dials would compete with the persistent owner during the
    # controlled Noise replacement and can leave one direction unauthenticated.
    pcm_start_coin_node "$run" "$ZAP_A" clean_baseline_restart
    pcm_start_coin_node "$run" "$ZAP_B" clean_baseline_restart
    pcm_start_coin_node "$run" "$ZAP_C" clean_baseline_restart
    if [ "$proof_count" -gt 0 ]; then
        # Let each owned P2P edge finish its controlled plaintext-to-Noise
        # replacement before admitting package demand. A reverse retry during
        # that transition can otherwise compete with the persistent owner and
        # churn the public relay-ready set.
        pcm_wait_mesh_relay_stable || {
            pcm_dump_mesh_snapshot
            dht_die "coin matrix run $run proof-bearing relay mesh did not stabilize"
        }
        ZAP_CONNECT_SKIP_ONETRY=1
        ZAP_CONNECT_DIRECTED_REARM=1
        zap_connect "$ZAP_A" "$ZAP_B"
        zap_connect "$ZAP_B" "$ZAP_C"
        zap_connect "$ZAP_C" "$ZAP_A"
        unset ZAP_CONNECT_DIRECTED_REARM
        unset ZAP_CONNECT_SKIP_ONETRY
    else
        pcm_wait_mesh_relay_stable || {
            pcm_dump_mesh_snapshot
            dht_die "coin matrix run $run zero-proof mesh did not stabilize"
        }
    fi
    DHT_EXTRA_PGIDS=("${PIDS[$ZAP_A]}" "${PIDS[$ZAP_B]}" "${PIDS[$ZAP_C]}")

    pcm_assert_peer_floor "$run"
    pcm_wait_all_tip "$height" "$hash"
    dht_unlock_wallet "${DDS[$PCM_CHAIN_OWNER]}" "${RPCS[$PCM_CHAIN_OWNER]}" ||
        dht_die "coin matrix run $run clean-baseline wallet unlock failed"
    elapsed=$((($(date +%s%N)-started_ns)/1000000))
    pcm_metric "$run" clean_baseline_restart "$PCM_CHAIN_OWNER" \
        "$elapsed" "$height" true
}

pcm_prepare_proofs() {
    local run="$1" count="$2" slot
    PCM_PROOF_SLOTS=()
    [ "$count" -gt 0 ] || return 0
    slot="matrix-$run-a"; zaps_prepare matrix "$slot" "$ZAP_A" "$((1000+run))"
    PCM_PROOF_SLOTS+=("$slot")
    if [ "$count" -ge 3 ]; then
        slot="matrix-$run-b"; zaps_prepare matrix "$slot" "$ZAP_B" "$((2000+run))"
        PCM_PROOF_SLOTS+=("$slot")
        slot="matrix-$run-c"; zaps_prepare matrix "$slot" "$ZAP_C" "$((3000+run))"
        PCM_PROOF_SLOTS+=("$slot")
    fi
    zaps_admit_parallel "${PCM_PROOF_SLOTS[@]}"
}

pcm_finish_proofs() {
    local slot
    [ "${#PCM_PROOF_SLOTS[@]}" -gt 0 ] || return 0
    for slot in "${PCM_PROOF_SLOTS[@]}"; do zaps_finish "$slot"; done
}

# Reduce the seven-identity discovery fixture to three equal full nodes while
# retaining its authenticated identities and common verified chain.
export ZCL_DB_LIFETIME_TRACE=1
ZAP_A="$ORIGIN"; ZAP_B="$NEXT"; ZAP_C="$TARGET"
for i in 0 1 2 3 4 5 6; do
    dht_kill_group "${PIDS[$i]:-}"; PIDS[$i]=""
done
DHT_PGID_A=""; DHT_PGID_B=""; DHT_EXTRA_PGIDS=()
pcm_start_coin_node 0 "$ZAP_A" initial_proof_mesh
pcm_start_coin_node 0 "$ZAP_B" initial_proof_mesh
pcm_start_coin_node 0 "$ZAP_C" initial_proof_mesh

# The sparse-routing proof above intentionally files all seven endpoint
# records only at its lookup origin. This matrix has a different product
# contract: three interchangeable full nodes must each be able to recover
# either peer after repeated process replacement. File only these three
# already-published, chain-verified signed documents at all three nodes. No
# address is trusted from the transport and no new identity is introduced.
for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
    # ZAP_A is the sparse lookup origin and already filed every exact doc.
    # endpoint.accept correctly rejects an equal sequence as STALE_SEQ rather
    # than pretending it mutated state, so there is nothing to replay there.
    [ "$node" = "$ZAP_A" ] && continue
    for publisher in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        [ "$node" = "$publisher" ] && continue
        accepted="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
            zcode endpoint accept \
            --input="{\"doc\":\"${DOCS[$publisher]}\"}" || true)"
        [ "$(printf '%s' "$accepted" | "$JSONQ" get ok 2>/dev/null || true)" = true ] ||
            dht_die "coin matrix node $node refused signed endpoint $publisher: $accepted"
    done
done
pcm_wait_mesh_relay_stable ||
    dht_die "coin matrix initial proof-bearing relay mesh did not stabilize"
ZAP_CONNECT_SKIP_ONETRY=1
ZAP_CONNECT_DIRECTED_REARM=1
zap_connect "$ZAP_A" "$ZAP_B"
zap_connect "$ZAP_B" "$ZAP_C"
zap_connect "$ZAP_C" "$ZAP_A"
unset ZAP_CONNECT_DIRECTED_REARM
unset ZAP_CONNECT_SKIP_ONETRY
DHT_EXTRA_PGIDS=("${PIDS[@]}")

PCM_CHAIN_OWNER=""
for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
    if [ "$node" -ne 1 ]; then PCM_CHAIN_OWNER="$node"; break; fi
done
[ -n "$PCM_CHAIN_OWNER" ] || dht_die "coin matrix has no funded chain owner"
dht_unlock_wallet "${DDS[$PCM_CHAIN_OWNER]}" "${RPCS[$PCM_CHAIN_OWNER]}" ||
    dht_die "coin matrix chain-owner wallet unlock failed"
dht_wait_spendable "${DDS[$PCM_CHAIN_OWNER]}" "${RPCS[$PCM_CHAIN_OWNER]}" ||
    dht_die "coin matrix chain owner has no spendable fixture output"

awk -v runs="$PCM_RUNS" -v print_seed="$PCM_SEED" \
    -v a="$ZAP_A" -v b="$ZAP_B" -v c="$ZAP_C" '
function lcg() {
    seed = (16807 * seed) % 2147483647
    if (seed <= 0) seed += 2147483646
    return seed
}
function randint(n) {
    return int(n * (lcg() / 2147483647))
}
function shuffle(arr, n,    i, j, t) {
    for (i = n; i > 1; i--) {
        j = randint(i) + 1
        t = arr[i]; arr[i] = arr[j]; arr[j] = t
    }
}
BEGIN {
    seed = print_seed + 0
    if (seed < 0) seed = -seed
    seed = seed % 2147483646
    if (seed == 0) seed = 1
    loads[1] = 0; loads[2] = 1; loads[3] = 3
    ns = 0
    while (ns < runs) {
        batch[1] = loads[1]; batch[2] = loads[2]; batch[3] = loads[3]
        shuffle(batch, 3)
        for (i = 1; i <= 3 && ns < runs; i++) {
            ns++
            sched[ns] = batch[i]
        }
    }
    nodes[1] = a; nodes[2] = b; nodes[3] = c
    for (run = 1; run <= runs; run++) {
        roles[1] = nodes[1]; roles[2] = nodes[2]; roles[3] = nodes[3]
        shuffle(roles, 3)
        printf "%d,%s,%s,%s,%s,%s\n", run, print_seed, roles[1], roles[2], roles[3], sched[run]
    }
}
' >>"$PCM_SCHEDULE"

mapfile -t PCM_PREV < <(pcm_select_unspent "$PCM_CHAIN_OWNER")
[ "${#PCM_PREV[@]}" -eq 3 ] || dht_die "coin matrix could not select initial UTXO"
PCM_PARENT_TXID="${PCM_PREV[0]}"
PCM_PARENT_VOUT="${PCM_PREV[1]}"
PCM_PARENT_AMOUNT="${PCM_PREV[2]}"

while IFS=, read -r run seed miner_a miner_b restart_node proof_count; do
    [ "$run" = run ] && continue
    dht_note "coin matrix run=$run seed=$seed miners=$miner_a/$miner_b restart=$restart_node proofs=$proof_count"
    pcm_reset_mesh "$run" "$proof_count"
    pcm_resource_snapshot "$run" before
    pcm_command_probe "$run" before
    pcm_prepare_proofs "$run" "$proof_count"

    dht_unlock_wallet "${DDS[$PCM_CHAIN_OWNER]}" "${RPCS[$PCM_CHAIN_OWNER]}" ||
        dht_die "coin matrix run $run chain-owner wallet unlock failed"
    mapfile -t tx_a < <(pcm_create_signed_child "$PCM_CHAIN_OWNER" \
        "$PCM_PARENT_TXID" "$PCM_PARENT_VOUT" "$PCM_PARENT_AMOUNT")
    [ "${#tx_a[@]}" -eq 3 ] || dht_die "coin matrix run $run could not build transaction A"
    raw_a="${tx_a[0]}"; txid_a="${tx_a[1]}"; amount_a="${tx_a[2]}"

    relay_started_ns="$(date +%s%N)"
    pcm_template_probe "$run" "$miner_b" & template_pid="$!"
    pcm_submit_same_node_concurrently "$run" "$miner_a" "$raw_a" "$txid_a" A
    wait "$template_pid" || dht_die "coin matrix run $run template probe failed"
    pcm_wait_all_mempool_timed "$run" "$txid_a" 1 tx_relay_a "$relay_started_ns"
    pcm_command_probe "$run" proof_load

    # A duplicate submission races the physical miner/finalizer. The shared
    # accept_to_mempool + locked tx_mempool insertion must leave one owner.
    pcm_submit_same_node_concurrently "$run" "$miner_b" "$raw_a" "$txid_a" A-finalize & dup_pid="$!"
    pcm_mine_one "$run" "$miner_a" block_production_a & mine_pid="$!"
    wait "$dup_pid" || dht_die "coin matrix run $run duplicate-finalize delivery failed"
    wait "$mine_pid" || dht_die "coin matrix run $run A mining failed"
    height_a="$(dht_height "${DDS[$miner_a]}" "${RPCS[$miner_a]}")"
    hash_a="$(pcm_hash_at "$miner_a" "$height_a")"
    pcm_wait_all_tip "$height_a" "$hash_a"
    pcm_assert_mempool_exact "$run" "$txid_a" 0 "confirmed A"
    pcm_finish_proofs
    pcm_reset_coin_mesh "$run" "$height_a" "$hash_a"

    # Build both B and a conflicting stale spend while A is the live parent.
    # B wins; the stale spend is retained as an exact post-finalize cache probe.
    mapfile -t tx_b < <(pcm_create_signed_child "$PCM_CHAIN_OWNER" \
        "$txid_a" 0 "$amount_a")
    [ "${#tx_b[@]}" -eq 3 ] ||
        dht_die "coin matrix run $run could not build transaction B"
    raw_b="${tx_b[0]}"; txid_b="${tx_b[1]}"; amount_b="${tx_b[2]}"
    # The raw builder is deterministic; alter the conflicting output amount
    # by one additional fee so the stale probe is a distinct transaction.
    mapfile -t stale_a < <(pcm_create_signed_child "$PCM_CHAIN_OWNER" \
        "$txid_a" 0 "$(awk -v a="$amount_a" 'BEGIN { printf "%.8f\n", a - 0.00010000 }')")
    raw_stale_a="${stale_a[0]}"; stale_txid_a="${stale_a[1]}"
    [ "$stale_txid_a" != "$txid_b" ] || dht_die "coin matrix stale spend did not differ from B"

    relay_started_ns="$(date +%s%N)"
    pcm_submit_same_node_concurrently "$run" "$restart_node" "$raw_b" "$txid_b" B
    pcm_wait_all_mempool_timed "$run" "$txid_b" 1 tx_relay_b "$relay_started_ns"
    dht_kill_group "${PIDS[$restart_node]}"; PIDS[$restart_node]=""
    started_sync_ns="$(date +%s%N)"
    pcm_mine_one "$run" "$miner_b" block_production_b
    height_b="$(dht_height "${DDS[$miner_b]}" "${RPCS[$miner_b]}")"
    hash_b="$(pcm_hash_at "$miner_b" "$height_b")"
    pcm_restart_node "$run" "$restart_node" "$height_b" "$hash_b" peer_restart_after_finalize
    pcm_wait_all_tip "$height_b" "$hash_b"
    pcm_metric "$run" block_sync "$restart_node" \
        "$((($(date +%s%N)-started_sync_ns)/1000000))" "$height_b" true
    pcm_assert_mempool_exact "$run" "$txid_b" 0 "confirmed B"

    # A second restart begins with the committed coins generation already
    # durable. Immediate cache probes after it must still classify the spent
    # A parent as absent and B's new output as available.
    pcm_restart_node "$run" "$restart_node" "$height_b" "$hash_b" durable_generation_restart
    stale_response="$(dht_rpc "${DDS[$restart_node]}" "${RPCS[$restart_node]}" \
        sendrawtransaction "\"$raw_stale_a\"" 2>&1 || true)"
    printf '%s' "$stale_response" | grep -Eq 'inputs missing|already spent' ||
        dht_die "coin matrix run $run stale spent-parent cache accepted $stale_txid_a: $stale_response"
    pcm_metric "$run" stale_parent_refusal "$restart_node" 0 "$stale_txid_a" true

    # C spends B and therefore proves the just-published B output is visible
    # through the long-lived cache generation on every process.
    mapfile -t tx_c < <(pcm_create_signed_child "$PCM_CHAIN_OWNER" \
        "$txid_b" 0 "$amount_b")
    [ "${#tx_c[@]}" -eq 3 ] || dht_die "coin matrix run $run could not build cache-probe C"
    raw_c="${tx_c[0]}"; txid_c="${tx_c[1]}"; amount_c="${tx_c[2]}"
    pcm_submit_same_node_concurrently "$run" "$restart_node" "$raw_c" "$txid_c" C
    pcm_assert_mempool_exact "$run" "$txid_c" 1 "new-output C"

    started_reorg_ns="$(date +%s%N)"
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
            invalidateblock "\"$hash_b\"" || true)"
        printf '%s' "$response" | dht_result >/dev/null 2>&1 ||
            dht_die "coin matrix run $run invalidate B failed on node $node: $response"
    done
    pcm_wait_all_tip "$height_a" "$hash_a"
    pcm_metric "$run" reorg_disconnect "$miner_b" \
        "$((($(date +%s%N)-started_reorg_ns)/1000000))" "$height_a" true
    pcm_assert_mempool_exact "$run" "$txid_b" 1 "reorg-resurrected B"
    pcm_assert_mempool_exact "$run" "$txid_c" 1 "reorg-preserved child C"

    started_reconnect_ns="$(date +%s%N)"
    for node in "$ZAP_A" "$ZAP_B" "$ZAP_C"; do
        response="$(dht_rpc "${DDS[$node]}" "${RPCS[$node]}" \
            reconsiderblock "\"$hash_b\"" || true)"
        printf '%s' "$response" | dht_result >/dev/null 2>&1 ||
            dht_die "coin matrix run $run reconsider B failed on node $node: $response"
    done
    pcm_wait_all_tip "$height_b" "$hash_b"
    pcm_metric "$run" reorg_reconnect "$miner_b" \
        "$((($(date +%s%N)-started_reconnect_ns)/1000000))" "$height_b" true
    pcm_assert_mempool_exact "$run" "$txid_b" 0 "reconnected confirmed B"
    pcm_assert_mempool_exact "$run" "$txid_c" 1 "reconnected child C"

    pcm_mine_one "$run" "$miner_a" cleanup_block_c
    height_c="$(dht_height "${DDS[$miner_a]}" "${RPCS[$miner_a]}")"
    hash_c="$(pcm_hash_at "$miner_a" "$height_c")"
    pcm_wait_all_tip "$height_c" "$hash_c"
    pcm_assert_mempool_exact "$run" "$txid_c" 0 "confirmed cleanup C"
    pcm_assert_peer_floor "$run"
    pcm_command_probe "$run" after
    pcm_resource_snapshot "$run" after
    PCM_PARENT_TXID="$txid_c"; PCM_PARENT_VOUT=0; PCM_PARENT_AMOUNT="$amount_c"
done <"$PCM_SCHEDULE"

pcm_write_receipt() {
    local want="$PCM_RUNS" n_sched=0 n_metrics=0 n_resources=0
    local run seed miner_a miner_b restart_node proof_actions
    local phase node elapsed value ok first_seed="" rotated=false
    local counts="" p r req
    declare -A miners=() proofs=() phases=()
    while IFS=, read -r run seed miner_a miner_b restart_node proof_actions; do
        [ "$run" = run ] && continue
        n_sched=$((n_sched + 1))
        [ -n "$first_seed" ] || first_seed="$seed"
        miners[$miner_a]=1
        miners[$miner_b]=1
        proofs[$proof_actions]=1
    done <"$PCM_SCHEDULE"
    [ "$n_sched" -eq "$want" ] || return 1
    while IFS=, read -r run phase node elapsed value ok; do
        [ "$run" = run ] && continue
        n_metrics=$((n_metrics + 1))
        [ "$ok" = true ] || return 1
        phases["$run $phase"]=1
    done <"$PCM_METRICS"
    while IFS=, read -r run phase node elapsed value ok extra; do
        [ "$run" = run ] && continue
        n_resources=$((n_resources + 1))
    done <"$PCM_RESOURCES"
    [ "$n_metrics" -gt 0 ] && [ "$n_resources" -gt 0 ] || return 1
    if [ "$want" -ge 3 ]; then
        [ "${#miners[@]}" -eq 3 ] || return 1
        [ -n "${proofs[0]:-}" ] && [ -n "${proofs[1]:-}" ] && [ -n "${proofs[3]:-}" ] || return 1
        [ "${#proofs[@]}" -eq 3 ] || return 1
    fi
    r=1
    while [ "$r" -le "$want" ]; do
        for req in block_template concurrent_delivery block_production_a \
            block_production_b block_sync peer_restart_after_finalize \
            coin_phase_mesh_restart durable_generation_restart \
            stale_parent_refusal reorg_disconnect reorg_reconnect \
            cleanup_block_c peer_floor tx_relay_a tx_relay_b \
            command_responsiveness_proof_load
        do
            [ -n "${phases[$r $req]:-}" ] || return 1
        done
        r=$((r + 1))
    done
    for p in $(printf '%s\n' "${!proofs[@]}" | sort -n); do
        counts="${counts}${counts:+,}${p}"
    done
    [ "${#miners[@]}" -eq 3 ] && rotated=true
    printf '{"schema":"zcl.public_node_coin_generation_matrix.v1","seed":%s,"runs":%s,"physical_nodes":3,"miner_roles_rotated":%s,"background_proof_action_counts":[%s],"duplicate_mempool_owners":0,"stale_cache_generations":0,"synchronization_divergences":0,"deadlocks":0,"metrics_rows":%s,"resource_rows":%s,"verdict":"PASS"}\n' \
        "$first_seed" "$want" "$rotated" "$counts" "$n_metrics" "$n_resources"
}

pcm_write_receipt >"$PCM_ROOT/receipt.json" ||
    dht_die "coin matrix aggregate receipt failed"

dht_note "public-node coin-generation matrix PASS: runs=$PCM_RUNS seed=$PCM_SEED physical_nodes=3 roles=randomized"
