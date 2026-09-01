#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# B3 acceptance: two isolated regtest daemons run the full P2P file-market
# trade end-to-end. A (seller, -externalip + file service) plans and commits a
# signed paid offer; the offer gossips to B (buyer) over the live peer link;
# B plans, commits a real Sapling payment (z_sendmany t->z + exact memo), is
# REFUSED delivery before confirmation (authorize-before-read), then after one
# mined block the seller wallet trial-decrypts its exact payment note and B
# retrieves the file chunk-by-chunk — each paid-chunk request makes the seller
# reconcile the claim live (that, not block arrival, flips the row to
# CONFIRMED) — into an atomically published destination.
# Idempotent replays (offer re-commit, plan re-plan, purchase re-commit) and
# the seller-side confirmed claim row close the proof.
#
# Modelled on tools/dev/zcode_dht_acceptance.sh: same setsid isolation, port
# refuse-set discipline, wallet-custody recipe, mining cadence, pgid cleanup.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
MKT_HELPER="${ZCL_MARKET_HELPER:-$REPO_ROOT/build/bin/zclassic23-market-acceptance-helper}"

MKT_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"
# Fresh block vs the siblings (dht: 29211-29273, science: 39111-39123,
# p2p 20022-20027 + 18033) and vs this host's zclassic23-live instance,
# which already owns 39311/39312 — the refuse-set check caught it.
# P2P reconnects pass the production reachable-port policy only for
# explicit test-safe ports, so the one post-restart link is an
# operator-directed onetry, never a redial.
A_PORT=20030; A_RPC=39511; A_FS=39512; A_HTTPS=39513
B_PORT=20031; B_RPC=39521; B_FS=39522; B_HTTPS=39523
DEAD_SINK=39999
MKT_WAIT="${MKT_WAIT:-90}"
MKT_NETWORK_WAIT="${MKT_NETWORK_WAIT:-$MKT_WAIT}"
MKT_WORK=""; MKT_DD_A=""; MKT_DD_B=""; MKT_PGID_A=""; MKT_PGID_B=""
MKT_EXTRA_FLAGS=()
MKT_CLEANED=0
MKT_KEEP="${MKT_KEEP:-0}"
# Throwaway passphrases for the wallet-custody recipe (never argv: they
# ride the wallet-passphrase credential file and --input=- stdin only).
MKT_WALLET_PASS="market-acceptance-wallet-pass"
MKT_BACKUP_PASS="market-acceptance-backup-pass"

# Trade terms: a three-chunk fixture (two full 50 MiB chunks + a tail).
# Retrieve requires the full-file purchase, so chunks_paid is always
# num_chunks below. The price keeps the whole trade inside the dev wallet
# scope's lifetime lab cap (DEV_LAB_CAP_ZAT = 0.05 ZCL,
# contexts/wallet/services/src/wallet_money_service.c) plus the wallet default fee:
# total is 100 * 30000 + ceil(12345 * 30000 / 2**20) = 3000354 zat.
PRICE_PER_MB_ZAT=30000
FIXTURE_TAIL_BYTES=12345
IDEMPOTENCY_KEY="market-acceptance-purchase-1"
T_TO_T_AMOUNT="0.00100000"
T_TO_Z_AMOUNT="0.00400000"
Z_TO_Z_AMOUNT="0.00200000"
Z_TO_T_AMOUNT="0.00100000"
# Regtest heights in this journey are below the first halving at 150.
MKT_COINBASE_REWARD_ZAT=1250000000

mkt_die() {
    echo "market-acceptance: FATAL: $*" >&2
    if [ -n "$MKT_WORK" ] && [ -d "$MKT_WORK" ]; then
        printf '%s\n' "$*" >"$MKT_WORK/FAILURE"
    fi
    exit 2
}
mkt_note() { echo "market-acceptance: $*"; }

mkt_assert_port() {
    local p="$1" live
    for live in $MKT_LIVE_PORTS; do
        [ "$p" = "$live" ] && mkt_die "port $p is in the live refuse-set"
    done
    [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ] &&
        mkt_die "port $p is already listening"
    return 0
}

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

mkt_cleanup() {
    [ "$MKT_CLEANED" = 1 ] && return 0
    MKT_CLEANED=1
    mkt_kill_group "$MKT_PGID_A"
    mkt_kill_group "$MKT_PGID_B"
    if [ "$MKT_KEEP" = 1 ] && [ -n "$MKT_WORK" ]; then
        mkt_note "preserved isolated acceptance artifacts for diagnosis"
    elif [ -n "$MKT_WORK" ] && [ -d "$MKT_WORK" ]; then
        case "$MKT_WORK" in
            "$REPO_ROOT"/test-tmp/zcl23-mktacc-*) rm -rf "$MKT_WORK" ;;
            *) mkt_note "WARN refusing to remove non-scratch $MKT_WORK" ;;
        esac
    fi
}
trap mkt_cleanup EXIT INT TERM

mkt_rpc() {
    local dd="$1" port="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" "$RPC_BIN" "$@" 2>/dev/null
}
a_rpc() { mkt_rpc "$MKT_DD_A" "$A_RPC" "$@"; }
b_rpc() { mkt_rpc "$MKT_DD_B" "$B_RPC" "$@"; }
mkt_result() {
    "$MKT_HELPER" rpc-result
}
mkt_jget() {
    "$MKT_HELPER" get "$1"
}
mkt_native() {
    local dd="$1" rpc="$2"; shift 2
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$@" 2>/dev/null | tail -1
}

mkt_spawn() {
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5"; shift 5
    local args=() connect
    for connect in "$@"; do args+=("-connect=$connect"); done
    [ "${#args[@]}" -gt 0 ] || args+=("-connect=127.0.0.1:$DEAD_SINK")
    # No -allow-plaintext-wallet: the wallet-passphrase credential
    # (CREDENTIALS_DIRECTORY, exported below) encrypts key writes at rest
    # (WKS1); -operator-lane=dev arms the dev wallet scope the purchase
    # plan/commit leaves require. -regtestshielded activates
    # Overwinter+Sapling from genesis on BOTH nodes (the zcashd -nuparams
    # equivalent; regtest otherwise pins them NO_ACTIVATION and no shielded
    # payment can ever be mined or relayed).
    setsid "$NODE_BIN" -datadir="$dd" -regtest -port="$p2p" \
        -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        "${args[@]}" -packagehost=0 -regtestshielded \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        "${MKT_EXTRA_FLAGS[@]}" \
        >>"$dd/node.log" 2>&1 &
    echo "$!"
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
# The money freshness classifier fails closed on finding_peers; the sync
# FSM only leaves it behind a peer it can sync FROM (outbound).
mkt_wait_sync_live() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(mkt_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | mkt_jget 'result.sync_state' 2>/dev/null || true)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        sleep 0.5
    done
    return 1
}
# The seller's market payment gate (market_payment_claim_ingest /
# market_payment_authorize_chunk) reads sync_get_state()==SYNC_AT_TIP as
# "chain current" and persists UNKNOWN otherwise; a node whose only links
# are inbound never leaves finding_peers, so the seller needs its own
# outbound link AND the full walk to at_tip before any payment arrives.
mkt_wait_at_tip() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(mkt_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | mkt_jget 'result.sync_state' 2>/dev/null || true)"
        [ "$state" = "at_tip" ] && return 0
        sleep 0.5
    done
    return 1
}
# The money gate reads the REDUCER pipeline, not the active chain: the
# authoritative coins tip AND H* must both reach the mined height.
mkt_wait_fold() {
    local dd="$1" rpc="$2" tip="$3" deadline dump coins hstar
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        dump="$(mkt_native "$dd" "$rpc" dumpstate reducer_frontier || true)"
        coins="$(printf '%s' "$dump" | mkt_jget 'state.coins_best_height' 2>/dev/null || true)"
        hstar="$(printf '%s' "$dump" | mkt_jget 'state.hstar' 2>/dev/null || true)"
        [ "$coins" = "$tip" ] && [ "$hstar" = "$tip" ] && return 0
        sleep 1
    done
    echo "market-acceptance: reducer_frontier at stall: $dump" >&2
    return 1
}
# RPC-ready != chain-loaded: the money gate needs the active chain index,
# which loads after the RPC starts serving.
mkt_wait_chain_loaded() {
    local dd="$1" rpc="$2" tip="$3" deadline chain blocks ibd
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        chain="$(mkt_rpc "$dd" "$rpc" getblockchaininfo 2>/dev/null || true)"
        blocks="$(printf '%s' "$chain" | mkt_jget 'result.blocks' 2>/dev/null || true)"
        ibd="$(printf '%s' "$chain" | mkt_jget 'result.initialblockdownload' 2>/dev/null || true)"
        [ "$blocks" = "$tip" ] && [ "$ibd" != "True" ] && return 0
        sleep 1
    done
    return 1
}
# The purchase plan's reservation reads the vault read model's confirmed
# custody, which lags the reducer fold while the wallet re-derives its
# spendable coins.
mkt_wait_spendable() {
    local dd="$1" rpc="$2" deadline spend
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        spend="$(mkt_native "$dd" "$rpc" dumpstate vault 2>/dev/null \
            | mkt_jget 'state.zcl.spendable' 2>/dev/null || true)"
        case "$spend" in
            ''|*[!0-9]*) ;;
            *) [ "$spend" -gt 0 ] && return 0 ;;
        esac
        sleep 1
    done
    return 1
}
mkt_unlock_wallet() {
    local dd="$1" rpc="$2" status unlock
    status="$(mkt_native "$dd" "$rpc" core wallet security status || true)"
    [ "$(printf '%s' "$status" | mkt_jget 'ok' 2>/dev/null || true)" = "True" ] || {
        printf '%s\n' "$status" >&2; return 1; }
    if [ "$(printf '%s' "$status" | mkt_jget 'data.unlocked' 2>/dev/null || true)" != "True" ]; then
        unlock="$(printf '%s' "{\"passphrase\":\"$MKT_WALLET_PASS\",\"timeout_seconds\":3600}" \
            | mkt_native "$dd" "$rpc" core wallet security unlock --input=- || true)"
        [ "$(printf '%s' "$unlock" | mkt_jget 'data.unlocked' 2>/dev/null || true)" = "True" ] || {
            printf '%s\n' "$unlock" >&2; return 1; }
    fi
    return 0
}
mkt_backup_wallet() {
    local dd="$1" rpc="$2" out
    out="$(printf '%s' "{\"confirm\":true,\"password\":\"$MKT_BACKUP_PASS\"}" \
        | mkt_native "$dd" "$rpc" core wallet backup now --input=- || true)"
    [ "$(printf '%s' "$out" | mkt_jget 'ok' 2>/dev/null || true)" = "True" ] || {
        printf '%s\n' "$out" >&2; return 1; }
}

mkt_new_address() {
    local dd="$1" rpc="$2" kind="$3" out parsed code
    if [ "$kind" = "sapling" ]; then
        out="$(mkt_native "$dd" "$rpc" core wallet shielded address || true)"
    else
        out="$(mkt_native "$dd" "$rpc" core wallet address new || true)"
    fi
    parsed="$(printf '%s' "$out" | "$MKT_HELPER" address "$kind" 2>/dev/null || true)"
    if [ -z "$parsed" ]; then
        code="$(printf '%s' "$out" | "$MKT_HELPER" get error.code 2>/dev/null || true)"
        [ -n "$code" ] || code="MALFORMED_ADDRESS_RESULT"
        echo "market-acceptance: address derivation refused ($kind, code=$code)" >&2
        return 1
    fi
    printf '%s\n' "$parsed"
}

mkt_wallet_total() {
    local dd="$1" rpc="$2" out info spendable immature
    out="$(mkt_native "$dd" "$rpc" core wallet balance || true)"
    spendable="$(printf '%s' "$out" | "$MKT_HELPER" amount data.total)" ||
        return 1
    info="$(mkt_rpc "$dd" "$rpc" getwalletinfo 2>/dev/null || true)"
    immature="$(printf '%s' "$info" |
        "$MKT_HELPER" amount result.immature_balance)" || return 1
    printf '%s\n' "$((spendable + immature))"
}

mkt_shielded_balance() {
    local dd="$1" rpc="$2" address="$3" out
    out="$(printf '%s' "{\"address\":\"$address\"}" |
        mkt_native "$dd" "$rpc" core wallet shielded balance --input=- || true)"
    printf '%s' "$out" | "$MKT_HELPER" amount data.balance
}

mkt_intent_plan() {
    local dd="$1" rpc="$2" route="$3" from="$4" to="$5" amount="$6" idem="$7"
    local input
    if [ "$route" = "transparent" ]; then
        input="{\"wallet_scope\":\"dev\",\"route\":\"$route\",\"effects\":[{\"asset\":\"ZCL\",\"to\":\"$to\",\"amount\":\"$amount\"}],\"idempotency_key\":\"$idem\"}"
    else
        input="{\"wallet_scope\":\"dev\",\"route\":\"$route\",\"from\":\"$from\",\"effects\":[{\"asset\":\"ZCL\",\"to\":\"$to\",\"amount\":\"$amount\"}],\"idempotency_key\":\"$idem\"}"
    fi
    printf '%s' "$input" |
        mkt_native "$dd" "$rpc" vault intent plan --input=- || true
}

mkt_intent_commit() {
    local dd="$1" rpc="$2" plan="$3"
    printf '%s' "{\"wallet_scope\":\"dev\",\"plan_id\":\"$plan\",\"confirm\":true}" |
        mkt_native "$dd" "$rpc" vault intent commit --input=- || true
}

mkt_intent_status() {
    local dd="$1" rpc="$2" plan="$3"
    printf '%s' "{\"plan_id\":\"$plan\"}" |
        mkt_native "$dd" "$rpc" vault intent status --input=- || true
}

mkt_chain_tx() {
    local dd="$1" rpc="$2" txid="$3"
    printf '%s' "{\"txid\":\"$txid\"}" |
        mkt_native "$dd" "$rpc" core chain transaction get --input=- || true
}

mkt_mempool_size() {
    local dd="$1" rpc="$2" out
    out="$(mkt_native "$dd" "$rpc" core chain mempool status 2>/dev/null || true)"
    printf '%s' "$out" | "$MKT_HELPER" get data.size
}

mkt_assert_tx_local() {
    local dd="$1" rpc="$2" txid="$3" stage="$4" lookup pool
    lookup="$(mkt_chain_tx "$dd" "$rpc" "$txid")"
    pool="$(mkt_mempool_size "$dd" "$rpc" 2>/dev/null || true)"
    if ! printf '%s' "$lookup" | "$MKT_HELPER" chain-tx "$txid" mempool \
            >/dev/null 2>&1 || [ "${pool:-0}" -lt 1 ] 2>/dev/null; then
        mkt_die "$stage did not retain the transaction locally (lookup=$(
            printf '%s' "$lookup" | "$MKT_HELPER" chain-tx "$txid" mempool \
                >/dev/null 2>&1 && printf 1 || printf 0) mempool=${pool:-unknown})"
    fi
}

mkt_assert_totals() {
    local want_a="$1" want_b="$2" context="$3" got_a got_b a_match b_match
    local a_without_reward b_delta b_diag b_source b_agree b_wh b_ch b_mc b_dc
    got_a="$(mkt_wallet_total "$MKT_DD_A" "$A_RPC")" ||
        mkt_die "$context: A total unavailable"
    got_b="$(mkt_wallet_total "$MKT_DD_B" "$B_RPC")" ||
        mkt_die "$context: B total unavailable"
    a_match=0; b_match=0
    [ "$got_a" = "$want_a" ] && a_match=1
    [ "$got_b" = "$want_b" ] && b_match=1
    a_without_reward=0
    [ "$got_a" = "$((want_a - MKT_COINBASE_REWARD_ZAT))" ] &&
        a_without_reward=1
    b_delta=$((got_b - want_b))
    b_diag="$(mkt_native "$MKT_DD_B" "$B_RPC" core wallet balance \
        2>/dev/null || true)"
    b_source="$(printf '%s' "$b_diag" | "$MKT_HELPER" get \
        data.transparent_source 2>/dev/null || true)"
    b_agree="$(printf '%s' "$b_diag" | "$MKT_HELPER" get \
        data.transparent_sources_agree 2>/dev/null || true)"
    b_wh="$(printf '%s' "$b_diag" | "$MKT_HELPER" get \
        data.wallet_height 2>/dev/null || true)"
    b_ch="$(printf '%s' "$b_diag" | "$MKT_HELPER" get \
        data.chain_height 2>/dev/null || true)"
    b_mc="$(printf '%s' "$b_diag" | "$MKT_HELPER" get \
        data.memory_confirmed_transactions 2>/dev/null || true)"
    b_dc="$(printf '%s' "$b_diag" | "$MKT_HELPER" get \
        data.durable_confirmed_transactions 2>/dev/null || true)"
    [ "$a_match" = 1 ] && [ "$b_match" = 1 ] ||
        mkt_die "$context: wallet total accounting mismatch (a_match=$a_match b_match=$b_match a_matches_without_new_reward=$a_without_reward b_delta_zat=$b_delta b_source=${b_source:-unknown} b_sources_agree=${b_agree:-unknown} b_wallet_height=${b_wh:-unknown} b_chain_height=${b_ch:-unknown} b_memory_confirmed=${b_mc:-unknown} b_durable_confirmed=${b_dc:-unknown})"
}

mkt_restart_b() {
    local tip="$1" signal="${2:-TERM}"
    mkt_kill_group "$MKT_PGID_B" "$signal"; MKT_PGID_B=""
    MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
        "$B_HTTPS" "127.0.0.1:$DEAD_SINK")"
    mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" ||
        mkt_die "B transaction restart failed"
    mkt_wait_fold "$MKT_DD_B" "$B_RPC" "$tip" ||
        mkt_die "B transaction restart lost the reducer frontier"
    b_rpc addnode "\"127.0.0.1:$A_PORT\"" "\"onetry\"" >/dev/null || true
    a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
    mkt_wait_connected "$MKT_DD_B" "$B_RPC" ||
        mkt_die "B transaction restart did not reconnect"
    mkt_wait_sync_live "$MKT_DD_B" "$B_RPC" ||
        mkt_die "B transaction restart did not regain live sync"
    mkt_wait_chain_loaded "$MKT_DD_B" "$B_RPC" "$tip" ||
        mkt_die "B transaction restart did not load the active chain"
    mkt_unlock_wallet "$MKT_DD_B" "$B_RPC" ||
        mkt_die "B transaction restart wallet unlock failed"
}

mkt_wait_intent_confirmed() {
    local dd="$1" rpc="$2" plan="$3" txid="$4" deadline status
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        status="$(mkt_intent_status "$dd" "$rpc" "$plan")"
        if printf '%s' "$status" | "$MKT_HELPER" intent-status \
                "$plan" "$txid" confirmed >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

mkt_assert_tx_network() {
    local txid="$1" state="$2" a b mempool deadline
    local a_ok b_ok a_pool b_pool a_peers b_peers a_limits b_limits
    local a_expired b_expired a_evicted b_evicted
    local a_mempool_status b_mempool_status a_direct b_direct a_block b_block
    local a_branch b_branch a_cleared b_cleared a_added b_added
    local a_confirmed b_confirmed a_height b_height
    local a_conf_value b_conf_value a_error b_error
    deadline=$(( $(date +%s) + MKT_NETWORK_WAIT ))
    while :; do
        a="$(mkt_chain_tx "$MKT_DD_A" "$A_RPC" "$txid")"
        b="$(mkt_chain_tx "$MKT_DD_B" "$B_RPC" "$txid")"
        if printf '%s' "$a" | "$MKT_HELPER" chain-tx "$txid" "$state" \
                >/dev/null 2>&1 &&
           printf '%s' "$b" | "$MKT_HELPER" chain-tx "$txid" "$state" \
                >/dev/null 2>&1; then
            break
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            a_ok=0; b_ok=0
            printf '%s' "$a" | "$MKT_HELPER" chain-tx "$txid" "$state" \
                >/dev/null 2>&1 && a_ok=1
            printf '%s' "$b" | "$MKT_HELPER" chain-tx "$txid" "$state" \
                >/dev/null 2>&1 && b_ok=1
            a_confirmed=0; b_confirmed=0
            printf '%s' "$a" | "$MKT_HELPER" chain-tx "$txid" confirmed \
                >/dev/null 2>&1 && a_confirmed=1
            printf '%s' "$b" | "$MKT_HELPER" chain-tx "$txid" confirmed \
                >/dev/null 2>&1 && b_confirmed=1
            a_conf_value="$(printf '%s' "$a" |
                "$MKT_HELPER" get data.confirmations 2>/dev/null || true)"
            b_conf_value="$(printf '%s' "$b" |
                "$MKT_HELPER" get data.confirmations 2>/dev/null || true)"
            a_error="$(printf '%s' "$a" |
                "$MKT_HELPER" get error.code 2>/dev/null || true)"
            b_error="$(printf '%s' "$b" |
                "$MKT_HELPER" get error.code 2>/dev/null || true)"
            a_mempool_status="$(mkt_native "$MKT_DD_A" "$A_RPC" \
                core chain mempool status 2>/dev/null || true)"
            b_mempool_status="$(mkt_native "$MKT_DD_B" "$B_RPC" \
                core chain mempool status 2>/dev/null || true)"
            a_pool="$(printf '%s' "$a_mempool_status" |
                "$MKT_HELPER" get data.size 2>/dev/null || true)"
            b_pool="$(printf '%s' "$b_mempool_status" |
                "$MKT_HELPER" get data.size 2>/dev/null || true)"
            a_direct="$(printf '%s' "$a_mempool_status" |
                "$MKT_HELPER" get data.removed_direct_total 2>/dev/null || true)"
            b_direct="$(printf '%s' "$b_mempool_status" |
                "$MKT_HELPER" get data.removed_direct_total 2>/dev/null || true)"
            a_block="$(printf '%s' "$a_mempool_status" |
                "$MKT_HELPER" get data.removed_for_block_total 2>/dev/null || true)"
            b_block="$(printf '%s' "$b_mempool_status" |
                "$MKT_HELPER" get data.removed_for_block_total 2>/dev/null || true)"
            a_branch="$(printf '%s' "$a_mempool_status" |
                "$MKT_HELPER" get data.removed_for_branch_total 2>/dev/null || true)"
            b_branch="$(printf '%s' "$b_mempool_status" |
                "$MKT_HELPER" get data.removed_for_branch_total 2>/dev/null || true)"
            a_cleared="$(printf '%s' "$a_mempool_status" |
                "$MKT_HELPER" get data.cleared_total 2>/dev/null || true)"
            b_cleared="$(printf '%s' "$b_mempool_status" |
                "$MKT_HELPER" get data.cleared_total 2>/dev/null || true)"
            a_added="$(printf '%s' "$a_mempool_status" |
                "$MKT_HELPER" get data.added_total 2>/dev/null || true)"
            b_added="$(printf '%s' "$b_mempool_status" |
                "$MKT_HELPER" get data.added_total 2>/dev/null || true)"
            a_peers="$(a_rpc getconnectioncount 2>/dev/null |
                mkt_result 2>/dev/null || true)"
            b_peers="$(b_rpc getconnectioncount 2>/dev/null |
                mkt_result 2>/dev/null || true)"
            a_height="$(mkt_height "$MKT_DD_A" "$A_RPC" 2>/dev/null || true)"
            b_height="$(mkt_height "$MKT_DD_B" "$B_RPC" 2>/dev/null || true)"
            a_limits="$(mkt_native "$MKT_DD_A" "$A_RPC" \
                dumpstate mempool_limits 2>/dev/null || true)"
            b_limits="$(mkt_native "$MKT_DD_B" "$B_RPC" \
                dumpstate mempool_limits 2>/dev/null || true)"
            a_expired="$(printf '%s' "$a_limits" |
                "$MKT_HELPER" get state.expired_total 2>/dev/null || true)"
            b_expired="$(printf '%s' "$b_limits" |
                "$MKT_HELPER" get state.expired_total 2>/dev/null || true)"
            a_evicted="$(printf '%s' "$a_limits" |
                "$MKT_HELPER" get state.evicted_total 2>/dev/null || true)"
            b_evicted="$(printf '%s' "$b_limits" |
                "$MKT_HELPER" get state.evicted_total 2>/dev/null || true)"
            mkt_die "transaction lookup convergence failed (expected_state=$state a_lookup=$a_ok b_lookup=$b_ok a_confirmed=$a_confirmed b_confirmed=$b_confirmed a_confirmations=${a_conf_value:-missing} b_confirmations=${b_conf_value:-missing} a_error=${a_error:-none} b_error=${b_error:-none} a_height=${a_height:-unknown} b_height=${b_height:-unknown} a_mempool=${a_pool:-unknown} b_mempool=${b_pool:-unknown} a_peers=${a_peers:-unknown} b_peers=${b_peers:-unknown} a_added=${a_added:-unknown} b_added=${b_added:-unknown} a_direct=${a_direct:-unknown} b_direct=${b_direct:-unknown} a_block=${a_block:-unknown} b_block=${b_block:-unknown} a_branch=${a_branch:-unknown} b_branch=${b_branch:-unknown} a_cleared=${a_cleared:-unknown} b_cleared=${b_cleared:-unknown} a_expired=${a_expired:-unknown} b_expired=${b_expired:-unknown} a_evicted=${a_evicted:-unknown} b_evicted=${b_evicted:-unknown})"
        fi
        sleep 1
    done
    if [ "$state" = "mempool" ]; then
        mempool="$(mkt_native "$MKT_DD_A" "$A_RPC" core chain mempool status || true)"
        printf '%s' "$mempool" | "$MKT_HELPER" mempool-at-least 1 ||
            mkt_die "A mempool status did not account for the transaction"
    fi
}

for port in $A_PORT $A_RPC $A_FS $A_HTTPS $B_PORT $B_RPC $B_FS $B_HTTPS; do
    mkt_assert_port "$port"
done
[ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] && [ -x "$MKT_HELPER" ] ||
    mkt_die "build node, RPC, and market acceptance helper binaries first"
mkdir -p "$REPO_ROOT/test-tmp"
MKT_WORK="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-mktacc-XXXXXX")"
MKT_DD_A="$MKT_WORK/a"; MKT_DD_B="$MKT_WORK/b"
MKT_CONTENT="$MKT_WORK/content"
MKT_DOWNLOADS="$MKT_WORK/downloads"
mkdir -p "$MKT_DD_A" "$MKT_DD_B" "$MKT_CONTENT" "$MKT_DOWNLOADS"
FIXTURE="$MKT_CONTENT/seller-fixture.bin"
DESTINATION="$MKT_DOWNLOADS/bought-copy.bin"

# Deterministic three-chunk fixture (2 x 50 MiB + tail), plus the exact
# manifest root the offer must commit (sha3-256 over the concatenated
# per-chunk sha3-256 digests) and the exact total price.
read -r FIXTURE_SIZE EXPECT_ROOT EXPECT_TOTAL_ZAT \
    <<<"$("$MKT_HELPER" fixture-create "$FIXTURE" "$PRICE_PER_MB_ZAT" \
        "$FIXTURE_TAIL_BYTES")" || mkt_die "fixture build failed"
EXPECTED_CHUNKS=3

# Wallet custody: boot both nodes with a passphrase credential so key writes
# encrypt at rest (WKS1). The seller-key envelope (metadata DEK) and the
# buyer's money gate both refuse a locked or plaintext wallet.
MKT_CRED_DIR="$MKT_WORK/cred"
install -d -m 700 "$MKT_CRED_DIR"
install -m 600 /dev/null "$MKT_CRED_DIR/wallet-passphrase"
printf '%s\n' "$MKT_WALLET_PASS" >"$MKT_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$MKT_CRED_DIR"

mkt_note "booting seller A (-externalip + file service) and buyer B"
MKT_EXTRA_FLAGS=("-externalip=127.0.0.1")
MKT_PGID_A="$(mkt_spawn "$MKT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_A" "$A_RPC" "$MKT_PGID_A" || mkt_die "seller A RPC warmup failed"
MKT_EXTRA_FLAGS=()
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "buyer B RPC warmup failed"
! grep -qaF "unrecognized flag" "$MKT_DD_A/node.log" "$MKT_DD_B/node.log" ||
    mkt_die "a boot flag was not recognized"

mkt_note "mining 101 spendable regtest blocks to the buyer"
BUYER_ADDR="$(b_rpc getnewaddress | mkt_result)"
mkt_mine_to_address b_rpc 101 "$BUYER_ADDR"
mkt_wait_height "$MKT_DD_A" "$A_RPC" 101 || mkt_die "A did not sync the funding chain"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 101 || mkt_die "B reducer fold did not reach the funding tip"

# The buyer's purchase money gate reads the forward-folded coins set, whose
# authority stamps land only at boot: restart B (the funded node) so they
# stamp, then re-link with an operator-directed onetry so B owns the
# OUTBOUND peer the money-freshness classifier demands (it fails closed on
# finding_peers). A stays up on the dead sink the whole time, so no
# already-connected skip can delay the link.
mkt_note "restarting B so the forward-folded coins set stamps its authority"
mkt_kill_group "$MKT_PGID_B"; MKT_PGID_B=""
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "B custody restart failed"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 101 || mkt_die "B reducer fold did not survive the restart"
b_rpc addnode "\"127.0.0.1:$A_PORT\"" "\"onetry\"" >/dev/null || true
mkt_wait_connected "$MKT_DD_B" "$B_RPC" || mkt_die "B never connected outbound to A"
mkt_wait_sync_live "$MKT_DD_B" "$B_RPC" || mkt_die "B sync never left finding_peers"
mkt_wait_chain_loaded "$MKT_DD_B" "$B_RPC" 101 || mkt_die "B active chain index did not load"

# Symmetric one-shot link: the seller's paid-chunk gate reads
# sync_get_state()==SYNC_AT_TIP, which a listen-only node never reaches.
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
mkt_wait_connected "$MKT_DD_A" "$A_RPC" || mkt_die "A never connected outbound to B"
mkt_wait_at_tip "$MKT_DD_A" "$A_RPC" || mkt_die "A sync never reached at_tip"

# The restart re-locks the encrypted-at-rest wallet (and A booted locked):
# unlock both (passphrase via --input=- only), re-top the RAM-only keypool
# bookkeeping, take the current-key encrypted backup, then wait for the
# buyer's spendable custody to turn positive.
mkt_note "unlocking both wallets and taking current-key encrypted backups"
mkt_unlock_wallet "$MKT_DD_A" "$A_RPC" || mkt_die "A wallet unlock failed"
mkt_unlock_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B wallet unlock failed"
mkt_note "deriving fresh private-local payment destinations before backup"
A_T1="$(mkt_new_address "$MKT_DD_A" "$A_RPC" transparent)" ||
    mkt_die "A transparent destination derivation failed"
A_T2="$(mkt_new_address "$MKT_DD_A" "$A_RPC" transparent)" ||
    mkt_die "A unshield destination derivation failed"
A_MINER="$(mkt_new_address "$MKT_DD_A" "$A_RPC" transparent)" ||
    mkt_die "A mining destination derivation failed"
STALE_T="$(mkt_new_address "$MKT_DD_A" "$A_RPC" transparent)" ||
    mkt_die "stale-plan destination derivation failed"
B_Z1="$(mkt_new_address "$MKT_DD_B" "$B_RPC" sapling)" ||
    mkt_die "B shielding destination derivation failed"
A_Z2="$(mkt_new_address "$MKT_DD_A" "$A_RPC" sapling)" ||
    mkt_die "A private-payment destination derivation failed"
a_rpc getnewaddress | mkt_result >/dev/null || mkt_die "A keypool top-up failed"
b_rpc getnewaddress | mkt_result >/dev/null || mkt_die "B keypool top-up failed"
mkt_backup_wallet "$MKT_DD_A" "$A_RPC" || mkt_die "A custody backup failed"
mkt_backup_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B custody backup failed"
mkt_wait_spendable "$MKT_DD_B" "$B_RPC" || mkt_die "B vault spendable never became positive"

# ── Phase 0: ordinary public-node payment journey ────────────────────
# Every payment below uses the durable vault intent path. Addresses stay in
# process-local variables and are never printed. A mines confirmations to a
# separate immature coinbase destination, so confirmed wallet-total deltas
# remain exactly recipient value plus the planned fee.
A_TOTAL="$(mkt_wallet_total "$MKT_DD_A" "$A_RPC")" ||
    mkt_die "A opening wallet total unavailable"
B_TOTAL="$(mkt_wallet_total "$MKT_DD_B" "$B_RPC")" ||
    mkt_die "B opening wallet total unavailable"
[ "$A_TOTAL" = 0 ] || mkt_die "A opening wallet unexpectedly held spendable value"

mkt_note "vault t-to-t: plan, idempotent re-plan, planned restart, one broadcast"
TT_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" transparent "" \
    "$A_T1" "$T_TO_T_AMOUNT" "v1-t-to-t")"
TT_PLAN="$(printf '%s' "$TT_PLAN_RAW" | "$MKT_HELPER" intent-plan \
    transparent "$T_TO_T_AMOUNT" fresh)" || mkt_die "t-to-t plan contract failed"
TT_FEE="$(printf '%s' "$TT_PLAN_RAW" | "$MKT_HELPER" amount data.maximum_fee)" ||
    mkt_die "t-to-t fee preview missing"
TT_REPLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" transparent "" \
    "$A_T1" "$T_TO_T_AMOUNT" "v1-t-to-t")"
[ "$(printf '%s' "$TT_REPLAN_RAW" | "$MKT_HELPER" intent-plan \
        transparent "$T_TO_T_AMOUNT" replay)" = "$TT_PLAN" ] ||
    mkt_die "t-to-t re-plan did not reproduce the exact plan"
mkt_restart_b 101
TT_AFTER_RESTART="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" transparent "" \
    "$A_T1" "$T_TO_T_AMOUNT" "v1-t-to-t")"
TT_AFTER_ID="$(printf '%s' "$TT_AFTER_RESTART" | "$MKT_HELPER" intent-plan \
    transparent "$T_TO_T_AMOUNT" replay 2>/dev/null || true)"
if [ "$TT_AFTER_ID" != "$TT_PLAN" ]; then
    TT_AFTER_CODE="$(printf '%s' "$TT_AFTER_RESTART" |
        "$MKT_HELPER" get error.code 2>/dev/null || true)"
    TT_AFTER_STATE="$(printf '%s' "$TT_AFTER_RESTART" |
        "$MKT_HELPER" get data.state 2>/dev/null || true)"
    mkt_die "planned t-to-t intent did not survive restart (code=${TT_AFTER_CODE:-CONTRACT_MISMATCH} state=${TT_AFTER_STATE:-unknown})"
fi
TT_COMMIT_RAW="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$TT_PLAN")"
TT_TXID="$(printf '%s' "$TT_COMMIT_RAW" | "$MKT_HELPER" intent-commit \
    "$TT_PLAN" mempool_accepted fresh)" || mkt_die "t-to-t commit failed"
mkt_assert_tx_local "$MKT_DD_B" "$B_RPC" "$TT_TXID" "fresh t-to-t commit"
TT_RECOMMIT="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$TT_PLAN")"
[ "$(printf '%s' "$TT_RECOMMIT" | "$MKT_HELPER" intent-commit \
        "$TT_PLAN" mempool_accepted replay)" = "$TT_TXID" ] ||
    mkt_die "t-to-t repeated commit was not the same transaction"
mkt_assert_tx_local "$MKT_DD_B" "$B_RPC" "$TT_TXID" "replayed t-to-t commit"
mkt_assert_tx_network "$TT_TXID" mempool
mkt_mine_to_address a_rpc 1 "$A_MINER"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 102 || mkt_die "B missed t-to-t confirmation"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" 102 || mkt_die "A t-to-t fold stalled"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 102 || mkt_die "B t-to-t fold stalled"
mkt_wait_intent_confirmed "$MKT_DD_B" "$B_RPC" "$TT_PLAN" "$TT_TXID" ||
    mkt_die "t-to-t intent did not become confirmed"
mkt_assert_tx_network "$TT_TXID" confirmed
A_TOTAL=$((A_TOTAL + MKT_COINBASE_REWARD_ZAT + 100000 + TT_FEE))
B_TOTAL=$((B_TOTAL - 100000 - TT_FEE))
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "confirmed t-to-t"

mkt_note "vault t-to-Sapling: exact plan, broadcast kill-9, same-byte recovery"
TZ_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" shield "$BUYER_ADDR" \
    "$B_Z1" "$T_TO_Z_AMOUNT" "v1-t-to-z")"
TZ_PLAN="$(printf '%s' "$TZ_PLAN_RAW" | "$MKT_HELPER" intent-plan \
    shield "$T_TO_Z_AMOUNT" fresh)" || mkt_die "t-to-Sapling plan contract failed"
TZ_FEE="$(printf '%s' "$TZ_PLAN_RAW" | "$MKT_HELPER" amount data.maximum_fee)" ||
    mkt_die "t-to-Sapling fee preview missing"
TZ_COMMIT_RAW="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$TZ_PLAN")"
TZ_TXID="$(printf '%s' "$TZ_COMMIT_RAW" | "$MKT_HELPER" intent-commit \
    "$TZ_PLAN" mempool_accepted fresh)" || mkt_die "t-to-Sapling commit failed"
mkt_assert_tx_network "$TZ_TXID" mempool
# The commit reply, durable intent bytes and peer-visible mempool transaction
# are established above. Kill the isolated buyer without shutdown callbacks,
# then require the public intent path to recover the same transaction bytes.
mkt_restart_b 102 KILL
TZ_RECOVER="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$TZ_PLAN")"
[ "$(printf '%s' "$TZ_RECOVER" | "$MKT_HELPER" intent-commit \
        "$TZ_PLAN" mempool_accepted replay)" = "$TZ_TXID" ] ||
    mkt_die "broadcast t-to-Sapling restart did not recover the same bytes"
mkt_assert_tx_network "$TZ_TXID" mempool
mkt_mine_to_address a_rpc 1 "$A_MINER"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 103 || mkt_die "B missed t-to-Sapling confirmation"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" 103 || mkt_die "A t-to-Sapling fold stalled"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 103 || mkt_die "B t-to-Sapling fold stalled"
mkt_wait_intent_confirmed "$MKT_DD_B" "$B_RPC" "$TZ_PLAN" "$TZ_TXID" ||
    mkt_die "t-to-Sapling intent did not become confirmed"
mkt_assert_tx_network "$TZ_TXID" confirmed
A_TOTAL=$((A_TOTAL + MKT_COINBASE_REWARD_ZAT + TZ_FEE))
B_TOTAL=$((B_TOTAL - TZ_FEE))
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "confirmed t-to-Sapling"
[ "$(mkt_shielded_balance "$MKT_DD_B" "$B_RPC" "$B_Z1")" = 400000 ] ||
    mkt_die "B Sapling self-shield balance disagrees after confirmation"

mkt_note "vault Sapling-to-Sapling: confirmed-note spend and recipient accounting"
ZZ_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" private "$B_Z1" \
    "$A_Z2" "$Z_TO_Z_AMOUNT" "v1-z-to-z")"
ZZ_CODE="$(printf '%s' "$ZZ_PLAN_RAW" | "$MKT_HELPER" get error.code 2>/dev/null || true)"
if [ "$ZZ_CODE" = "WITNESS_RESCAN_REQUIRED" ]; then
    mkt_note "shielded plan named witness repair; running the exact typed recovery"
    ZZ_RESCAN="$(mkt_native "$MKT_DD_B" "$B_RPC" \
        core wallet rescan-witnesses 2>/dev/null || true)"
    ZZ_RESCAN_OK="$(printf '%s' "$ZZ_RESCAN" | "$MKT_HELPER" get ok 2>/dev/null || true)"
    ZZ_RESCAN_DONE="$(printf '%s' "$ZZ_RESCAN" | "$MKT_HELPER" get data.completed 2>/dev/null || true)"
    ZZ_RESCAN_SAVED="$(printf '%s' "$ZZ_RESCAN" | "$MKT_HELPER" get data.result.witnesses_saved 2>/dev/null || true)"
    [ "$ZZ_RESCAN_OK" = "True" ] && [ "$ZZ_RESCAN_DONE" = "True" ] &&
        [ "${ZZ_RESCAN_SAVED:-0}" -ge 1 ] 2>/dev/null ||
        mkt_die "typed witness recovery did not complete"
    ZZ_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" private \
        "$B_Z1" "$A_Z2" "$Z_TO_Z_AMOUNT" \
        "v1-z-to-z-after-witness-rescan")"
    ZZ_CODE="$(printf '%s' "$ZZ_PLAN_RAW" | "$MKT_HELPER" get error.code 2>/dev/null || true)"
fi
if ! ZZ_PLAN="$(printf '%s' "$ZZ_PLAN_RAW" | "$MKT_HELPER" intent-plan \
        private "$Z_TO_Z_AMOUNT" fresh)"; then
    ZZ_STATE="$(printf '%s' "$ZZ_PLAN_RAW" | "$MKT_HELPER" get error.current_state 2>/dev/null || true)"
    ZZ_RETRY="$(printf '%s' "$ZZ_PLAN_RAW" | "$MKT_HELPER" get error.retryable 2>/dev/null || true)"
    mkt_die "Sapling-to-Sapling plan refused (code=${ZZ_CODE:-CONTRACT_MISMATCH} state=${ZZ_STATE:-unknown} retryable=${ZZ_RETRY:-unknown})"
fi
ZZ_FEE="$(printf '%s' "$ZZ_PLAN_RAW" | "$MKT_HELPER" amount data.maximum_fee)" ||
    mkt_die "Sapling-to-Sapling fee preview missing"
ZZ_COMMIT_RAW="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$ZZ_PLAN")"
ZZ_TXID="$(printf '%s' "$ZZ_COMMIT_RAW" | "$MKT_HELPER" intent-commit \
    "$ZZ_PLAN" mempool_accepted fresh)" || mkt_die "Sapling-to-Sapling commit failed"
mkt_assert_tx_network "$ZZ_TXID" mempool
mkt_mine_to_address a_rpc 1 "$A_MINER"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 104 || mkt_die "B missed Sapling-to-Sapling confirmation"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" 104 || mkt_die "A Sapling-to-Sapling fold stalled"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 104 || mkt_die "B Sapling-to-Sapling fold stalled"
mkt_wait_intent_confirmed "$MKT_DD_B" "$B_RPC" "$ZZ_PLAN" "$ZZ_TXID" ||
    mkt_die "Sapling-to-Sapling intent did not become confirmed"
mkt_assert_tx_network "$ZZ_TXID" confirmed
A_TOTAL=$((A_TOTAL + MKT_COINBASE_REWARD_ZAT + 200000 + ZZ_FEE))
B_TOTAL=$((B_TOTAL - 200000 - ZZ_FEE))
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "confirmed Sapling-to-Sapling"
[ "$(mkt_shielded_balance "$MKT_DD_A" "$A_RPC" "$A_Z2")" = 200000 ] ||
    mkt_die "A Sapling recipient balance disagrees after private payment"
[ "$(mkt_shielded_balance "$MKT_DD_B" "$B_RPC" "$B_Z1")" = 190000 ] ||
    mkt_die "B Sapling change balance disagrees after private payment"

mkt_note "vault Sapling-to-t: confirmation, reorg rollback, reconfirmation"
ZT_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" unshield "$B_Z1" \
    "$A_T2" "$Z_TO_T_AMOUNT" "v1-z-to-t")"
ZT_CODE="$(printf '%s' "$ZT_PLAN_RAW" | "$MKT_HELPER" get error.code 2>/dev/null || true)"
if [ "$ZT_CODE" = "WITNESS_RESCAN_REQUIRED" ]; then
    mkt_note "Sapling change plan named witness repair; running the exact typed recovery"
    ZT_RESCAN="$(mkt_native "$MKT_DD_B" "$B_RPC" \
        core wallet rescan-witnesses 2>/dev/null || true)"
    ZT_RESCAN_OK="$(printf '%s' "$ZT_RESCAN" | "$MKT_HELPER" get ok 2>/dev/null || true)"
    ZT_RESCAN_DONE="$(printf '%s' "$ZT_RESCAN" | "$MKT_HELPER" get data.completed 2>/dev/null || true)"
    ZT_RESCAN_SAVED="$(printf '%s' "$ZT_RESCAN" | "$MKT_HELPER" get data.result.witnesses_saved 2>/dev/null || true)"
    [ "$ZT_RESCAN_OK" = "True" ] && [ "$ZT_RESCAN_DONE" = "True" ] &&
        [ "${ZT_RESCAN_SAVED:-0}" -ge 1 ] 2>/dev/null ||
        mkt_die "typed Sapling change witness recovery did not complete"
    ZT_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" unshield \
        "$B_Z1" "$A_T2" "$Z_TO_T_AMOUNT" \
        "v1-z-to-t-after-witness-rescan")"
    ZT_CODE="$(printf '%s' "$ZT_PLAN_RAW" | "$MKT_HELPER" get error.code 2>/dev/null || true)"
fi
if ! ZT_PLAN="$(printf '%s' "$ZT_PLAN_RAW" | "$MKT_HELPER" intent-plan \
        unshield "$Z_TO_T_AMOUNT" fresh)"; then
    ZT_STATE="$(printf '%s' "$ZT_PLAN_RAW" | "$MKT_HELPER" get error.current_state 2>/dev/null || true)"
    ZT_RETRY="$(printf '%s' "$ZT_PLAN_RAW" | "$MKT_HELPER" get error.retryable 2>/dev/null || true)"
    mkt_die "Sapling-to-t plan refused (code=${ZT_CODE:-CONTRACT_MISMATCH} state=${ZT_STATE:-unknown} retryable=${ZT_RETRY:-unknown})"
fi
ZT_FEE="$(printf '%s' "$ZT_PLAN_RAW" | "$MKT_HELPER" amount data.maximum_fee)" ||
    mkt_die "Sapling-to-t fee preview missing"
ZT_COMMIT_RAW="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$ZT_PLAN")"
ZT_TXID="$(printf '%s' "$ZT_COMMIT_RAW" | "$MKT_HELPER" intent-commit \
    "$ZT_PLAN" mempool_accepted fresh)" || mkt_die "Sapling-to-t commit failed"
mkt_assert_tx_network "$ZT_TXID" mempool
mkt_mine_to_address a_rpc 1 "$A_MINER"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 105 || mkt_die "B missed Sapling-to-t confirmation"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" 105 || mkt_die "A Sapling-to-t fold stalled"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 105 || mkt_die "B Sapling-to-t fold stalled"
mkt_wait_intent_confirmed "$MKT_DD_B" "$B_RPC" "$ZT_PLAN" "$ZT_TXID" ||
    mkt_die "Sapling-to-t intent did not become confirmed"
mkt_assert_tx_network "$ZT_TXID" confirmed
A_BEFORE_ZT="$A_TOTAL"; B_BEFORE_ZT="$B_TOTAL"
A_TOTAL=$((A_TOTAL + MKT_COINBASE_REWARD_ZAT + 100000 + ZT_FEE))
B_TOTAL=$((B_TOTAL - 100000 - ZT_FEE))
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "confirmed Sapling-to-t"
ZT_BLOCK="$(a_rpc getblockhash 105 | mkt_result)"
for node in A B; do
    if [ "$node" = A ]; then
        OUT="$(a_rpc invalidateblock "\"$ZT_BLOCK\"" || true)"
    else
        OUT="$(b_rpc invalidateblock "\"$ZT_BLOCK\"" || true)"
    fi
    printf '%s' "$OUT" | mkt_result >/dev/null || mkt_die "Sapling-to-t reorg disconnect failed"
done
mkt_wait_height "$MKT_DD_A" "$A_RPC" 104 || mkt_die "A did not roll back Sapling-to-t block"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 104 || mkt_die "B did not roll back Sapling-to-t block"
ZT_REORG="$(mkt_intent_status "$MKT_DD_B" "$B_RPC" "$ZT_PLAN")"
printf '%s' "$ZT_REORG" | "$MKT_HELPER" intent-status \
    "$ZT_PLAN" "$ZT_TXID" reorged || mkt_die "Sapling-to-t intent did not report reorged"
mkt_assert_totals "$A_BEFORE_ZT" "$B_BEFORE_ZT" "reorged Sapling-to-t"
for node in A B; do
    if [ "$node" = A ]; then
        OUT="$(a_rpc reconsiderblock "\"$ZT_BLOCK\"" || true)"
    else
        OUT="$(b_rpc reconsiderblock "\"$ZT_BLOCK\"" || true)"
    fi
    printf '%s' "$OUT" | mkt_result >/dev/null || mkt_die "Sapling-to-t reconsider failed"
done
mkt_wait_height "$MKT_DD_A" "$A_RPC" 105 || mkt_die "A did not reconsider Sapling-to-t block"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 105 || mkt_die "B did not reconsider Sapling-to-t block"
mkt_wait_intent_confirmed "$MKT_DD_B" "$B_RPC" "$ZT_PLAN" "$ZT_TXID" ||
    mkt_die "Sapling-to-t intent did not reconfirm"
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "reconfirmed Sapling-to-t"

MARKET_CONFIRM_HEIGHT=106

# ── Phase 1: seller offer plan (non-mutating) then commit ────────────
mkt_note "seller plans the offer (non-mutating preview)"
OFFER_PLAN="$(printf '%s' "{\"filepath\":\"$FIXTURE\",\"price_per_mb_zat\":$PRICE_PER_MB_ZAT}" \
    | mkt_native "$MKT_DD_A" "$A_RPC" app market offer --input=- || true)"
printf '%s' "$OFFER_PLAN" | "$MKT_HELPER" offer-plan "$EXPECT_ROOT" \
    "$FIXTURE_SIZE" "$EXPECTED_CHUNKS" "$EXPECT_TOTAL_ZAT" ||
    mkt_die "offer plan preview contract mismatch"
OFFER_COUNT="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
    --input='{"sql":"SELECT COUNT(*) AS n FROM file_offers"}' || true)"
[ "$(printf '%s' "$OFFER_COUNT" | mkt_jget 'data.rows.0.0' 2>/dev/null || true)" = "0" ] ||
    mkt_die "offer plan mutated seller storage"
SELLER_LIST_RAW="$(a_rpc zmarket_list 2>&1 || true)"
SELLER_LIST="$(printf '%s' "$SELLER_LIST_RAW" | mkt_result 2>&1 || true)"
printf '%s' "$SELLER_LIST" | "$MKT_HELPER" market-empty ||
    mkt_die "offer plan changed or malformed the seller market view"

mkt_note "seller commits the offer (seal, persist, bind, flood)"
OFFER_COMMIT="$(printf '%s' "{\"filepath\":\"$FIXTURE\",\"price_per_mb_zat\":$PRICE_PER_MB_ZAT,\"confirm\":true}" \
    | mkt_native "$MKT_DD_A" "$A_RPC" app market offer --input=- || true)"
OFFER_ID="$(printf '%s' "$OFFER_COMMIT" |
    "$MKT_HELPER" offer-commit "$EXPECT_ROOT" ||
    mkt_die "offer commit refused")"
mkt_note "seller offer committed"

# ── Phase 2: the offer gossips to the buyer ──────────────────────────
mkt_note "waiting for the signed offer to gossip to the buyer"
LIST_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    BUYER_LIST="$(printf '%s' '{"profile":"open"}' |
        mkt_native "$MKT_DD_B" "$B_RPC" app market list --input=- 2>/dev/null || true)"
    case "$BUYER_LIST" in
        *"$OFFER_ID"*) break ;;
    esac
    [ "$(date +%s)" -lt "$LIST_DEADLINE" ] ||
        mkt_die "offer never gossiped to the buyer"
    sleep 1
done
DEFAULT_BUYER_LIST="$(mkt_native "$MKT_DD_B" "$B_RPC" app market list 2>/dev/null || true)"
printf '%s' "$DEFAULT_BUYER_LIST" | "$MKT_HELPER" market-hidden "$OFFER_ID" ||
    mkt_die "default moderation view did not honestly hide the unreviewed offer"
BUYER_ENTRY="$BUYER_LIST"
printf '%s' "$BUYER_ENTRY" | "$MKT_HELPER" buyer-entry "$OFFER_ID" \
    "$EXPECT_ROOT" "$PRICE_PER_MB_ZAT" "$EXPECTED_CHUNKS" \
    "$EXPECT_TOTAL_ZAT" || mkt_die "buyer market list entry mismatch"

# ── Phase 3: buyer purchase plan + commit (real Sapling payment) ─────
mkt_note "buyer plans the full-file purchase"
PLAN=""
for try in $(seq 1 20); do
    PLAN="$(printf '%s' "{\"wallet_scope\":\"dev\",\"offer_id\":\"$OFFER_ID\",\"source_address\":\"$BUYER_ADDR\",\"chunk_start\":0,\"chunks_paid\":$EXPECTED_CHUNKS,\"idempotency_key\":\"$IDEMPOTENCY_KEY\"}" \
        | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase plan --input=- || true)"
    case "$PLAN" in
        *MONEY_STATE_NOT_CURRENT*|*MONEY_SNAPSHOT_CHANGED*) sleep 1 ;;
        *) break ;;
    esac
done
PLAN_ID="$(printf '%s' "$PLAN" |
    "$MKT_HELPER" purchase-plan "$OFFER_ID" "$EXPECT_TOTAL_ZAT" ||
    mkt_die "purchase plan refused")"
MARKET_FEE_ZAT="$(printf '%s' "$PLAN" | "$MKT_HELPER" get data.maximum_fee_zat)" ||
    mkt_die "purchase plan did not expose its maximum fee"
mkt_note "buyer purchase planned"

mkt_note "buyer commits the purchase (broadcasts the Sapling payment)"
COMMIT="$(printf '%s' "{\"wallet_scope\":\"dev\",\"plan_id\":\"$PLAN_ID\",\"confirm\":true}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase commit --input=- || true)"
TXID="$(printf '%s' "$COMMIT" | "$MKT_HELPER" purchase-commit ||
    mkt_die "purchase commit refused")"
mkt_note "purchase payment broadcast"

# ── Phase 4: authorize-before-read — delivery refused pre-confirmation ──
mkt_note "buyer retrieves before confirmation: the seller must refuse"
EARLY_RETRIEVE="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\",\"destination_path\":\"$DESTINATION\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase retrieve --input=- || true)"
printf '%s' "$EARLY_RETRIEVE" | "$MKT_HELPER" early-refusal ||
    mkt_die "pre-confirmation retrieve was not refused"
[ ! -e "$DESTINATION" ] ||
    mkt_die "destination published before payment confirmation"

# Mempool relay is trickle, not instant: mining the confirmation before A
# has the payment produces a coinbase-only block and the purchase never
# confirms. Wait until A's mempool names the exact txid (either hex order).
mkt_note "waiting for the seller mempool to hold the payment"
TXID_REV="$("$MKT_HELPER" reverse-hex "$TXID")"
MEMPOOL_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    MEMPOOL="$(a_rpc getrawmempool 2>/dev/null | mkt_result 2>/dev/null || true)"
    case "$MEMPOOL" in
        *"$TXID"*|*"$TXID_REV"*) break ;;
    esac
    [ "$(date +%s)" -lt "$MEMPOOL_DEADLINE" ] ||
        mkt_die "payment never reached the seller mempool"
    sleep 1
done

# ── Phase 5: mine the confirmation; both sides reconcile ─────────────
mkt_note "mining the payment confirmation block"
mkt_mine_to_address a_rpc 1 "$A_MINER"
mkt_wait_height "$MKT_DD_B" "$B_RPC" "$MARKET_CONFIRM_HEIGHT" || mkt_die "B did not sync the confirmation block"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" "$MARKET_CONFIRM_HEIGHT" || mkt_die "A reducer fold did not reach the confirmation tip"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" "$MARKET_CONFIRM_HEIGHT" || mkt_die "B reducer fold did not reach the confirmation tip"

# The market purchase status leaf is a dumb durable read by design; the
# vault controller's reconcile (triggered here by the native intent-status
# leaf) is
# what advances mempool_accepted -> confirmed against the canonical chain.
mkt_note "polling the buyer purchase status until confirmed"
STATUS_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    VI_REFRESH="$(mkt_intent_status "$MKT_DD_B" "$B_RPC" "$PLAN_ID")"
    STATUS="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\"}" \
        | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase status --input=- || true)"
    state="$(printf '%s' "$STATUS" | mkt_jget 'data.state' 2>/dev/null || true)"
    [ "$state" = "confirmed" ] && break
    [ "$(date +%s)" -lt "$STATUS_DEADLINE" ] ||
        mkt_die "purchase never confirmed"
    sleep 1
done
printf '%s' "$STATUS" | "$MKT_HELPER" purchase-status "$TXID" ||
    mkt_die "confirmed purchase status mismatch"
A_TOTAL=$((A_TOTAL + MKT_COINBASE_REWARD_ZAT + EXPECT_TOTAL_ZAT + MARKET_FEE_ZAT))
B_TOTAL=$((B_TOTAL - EXPECT_TOTAL_ZAT - MARKET_FEE_ZAT))

# The seller claim row is a rebuildable projection: nothing reconciles it on
# block arrival. The seller re-derives authority live inside
# market_payment_authorize_chunk on each paid-chunk request (the buyer's
# retrieve), so the row only flips to CONFIRMED during authorized delivery.
# First wait for the seller wallet to have trial-decrypted its exact payment
# note at the confirmation height (tip_finalize scans every connected block);
# that note is the receipt authority the chunk gate binds against.
mkt_note "waiting for the seller wallet to decrypt its exact payment note"
NOTE_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    NOTE="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
        --input="{\"sql\":\"SELECT COUNT(*) FROM wallet_sapling_notes WHERE value=$EXPECT_TOTAL_ZAT AND block_height=$MARKET_CONFIRM_HEIGHT\"}" || true)"
    ncount="$(printf '%s' "$NOTE" | mkt_jget 'data.rows.0.0' 2>/dev/null || true)"
    [ "$ncount" = "1" ] && break
    [ "$(date +%s)" -lt "$NOTE_DEADLINE" ] ||
        mkt_die "seller never decrypted its payment note"
    sleep 1
done
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "confirmed market payment"

# ── Phase 6: authorized retrieval + verified publication ─────────────
# Retry on DELIVERY_NOT_READY: the seller's per-chunk authorization
# reconciles the claim live, so a still-lagging seller projection is a
# transient refusal, not a verdict.
mkt_note "buyer retrieves the file; each chunk authorizes against the chain"
RETRIEVE_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    RETRIEVE="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\",\"destination_path\":\"$DESTINATION\"}" \
        | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase retrieve --input=- || true)"
    rok="$(printf '%s' "$RETRIEVE" | mkt_jget 'ok' 2>/dev/null || true)"
    [ "$rok" = "True" ] && break
    case "$RETRIEVE" in
        *DELIVERY_NOT_READY*) ;;
        *) mkt_die "retrieve failed with a non-delivery error" ;;
    esac
    [ "$(date +%s)" -lt "$RETRIEVE_DEADLINE" ] ||
        mkt_die "retrieve never authorized"
    sleep 2
done
printf '%s' "$RETRIEVE" | "$MKT_HELPER" retrieve "$FIXTURE_SIZE" \
    "$EXPECTED_CHUNKS" || mkt_die "retrieve contract failed"
cmp -s "$FIXTURE" "$DESTINATION" ||
    mkt_die "delivered bytes differ from the seller fixture"
DELIVERED_ROOT="$("$MKT_HELPER" file-root "$DESTINATION")"
[ "$DELIVERED_ROOT" = "$EXPECT_ROOT" ] ||
    mkt_die "delivered bytes re-derive a different content root"

# The authorized delivery above made the seller reconcile the claim against
# its exact canonical note; the durable row must now read CONFIRMED.
mkt_note "verifying the seller-side payment claim is confirmed"
CLAIM="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
    --input='{"sql":"SELECT status, status_reason, confirmations, block_height FROM market_payment_claims"}' || true)"
printf '%s' "$CLAIM" | "$MKT_HELPER" claim "$MARKET_CONFIRM_HEIGHT" ||
    mkt_die "seller claim row mismatch"
FINAL_STATUS="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase status --input=- || true)"
[ "$(printf '%s' "$FINAL_STATUS" | mkt_jget 'data.destination_published' 2>/dev/null || true)" = "True" ] ||
    mkt_die "purchase status does not show the completed download"

# ── Phase 7: idempotent replays ──────────────────────────────────────
mkt_note "re-committing the same purchase plan (idempotent replay, no double-spend)"
RECOMMIT="$(printf '%s' "{\"wallet_scope\":\"dev\",\"plan_id\":\"$PLAN_ID\",\"confirm\":true}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase commit --input=- || true)"
printf '%s' "$RECOMMIT" | "$MKT_HELPER" recommit "$TXID" ||
    mkt_die "purchase re-commit was not an exact replay"
REPLAN="$(printf '%s' "{\"wallet_scope\":\"dev\",\"offer_id\":\"$OFFER_ID\",\"source_address\":\"$BUYER_ADDR\",\"chunk_start\":0,\"chunks_paid\":$EXPECTED_CHUNKS,\"idempotency_key\":\"$IDEMPOTENCY_KEY\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase plan --input=- || true)"
printf '%s' "$REPLAN" | "$MKT_HELPER" replan "$PLAN_ID" ||
    mkt_die "purchase re-plan was not an exact replay"

mkt_note "seller re-commits the same offer (content-addressed idempotent)"
REOFFER="$(printf '%s' "{\"filepath\":\"$FIXTURE\",\"price_per_mb_zat\":$PRICE_PER_MB_ZAT,\"confirm\":true}" \
    | mkt_native "$MKT_DD_A" "$A_RPC" app market offer --input=- || true)"
printf '%s' "$REOFFER" | "$MKT_HELPER" reoffer "$OFFER_ID" ||
    mkt_die "offer re-commit was not an exact replay"

# ── Phase 8: stale-plan and idempotency conflict refusal ─────────────
mkt_note "proving a changed tip cannot commit a stale payment plan"
STALE_PLAN_RAW="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" transparent "" \
    "$STALE_T" "$T_TO_T_AMOUNT" "v1-stale-plan")"
STALE_PLAN="$(printf '%s' "$STALE_PLAN_RAW" | "$MKT_HELPER" intent-plan \
    transparent "$T_TO_T_AMOUNT" fresh)" || mkt_die "stale plan creation failed"
IDEM_CONFLICT="$(mkt_intent_plan "$MKT_DD_B" "$B_RPC" transparent "" \
    "$STALE_T" "0.00090000" "v1-stale-plan")"
printf '%s' "$IDEM_CONFLICT" | "$MKT_HELPER" intent-error IDEMPOTENCY_CONFLICT ||
    mkt_die "changed request reused an idempotency identity"
mkt_mine_to_address a_rpc 1 "$A_MINER"
A_TOTAL=$((A_TOTAL + MKT_COINBASE_REWARD_ZAT))
STALE_HEIGHT=$((MARKET_CONFIRM_HEIGHT + 1))
mkt_wait_height "$MKT_DD_B" "$B_RPC" "$STALE_HEIGHT" ||
    mkt_die "B missed stale-plan tip change"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" "$STALE_HEIGHT" ||
    mkt_die "A stale-plan fold stalled"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" "$STALE_HEIGHT" ||
    mkt_die "B stale-plan fold stalled"
STALE_COMMIT="$(mkt_intent_commit "$MKT_DD_B" "$B_RPC" "$STALE_PLAN")"
printf '%s' "$STALE_COMMIT" | "$MKT_HELPER" intent-error MONEY_SNAPSHOT_CHANGED ||
    mkt_die "changed tip did not fail the exact stale plan closed"
INTENT_LIST="$(mkt_native "$MKT_DD_B" "$B_RPC" vault intent list || true)"
printf '%s' "$INTENT_LIST" | "$MKT_HELPER" intent-list-at-least 5 ||
    mkt_die "durable intent list omitted the payment history"
mkt_assert_totals "$A_TOTAL" "$B_TOTAL" "stale plan refusal"

mkt_note "PASS: two-daemon public-node V1 — t-to-t, t-to-Sapling, Sapling-to-Sapling, Sapling-to-t, restart/idempotency/reorg safety, and paid verified file delivery"
