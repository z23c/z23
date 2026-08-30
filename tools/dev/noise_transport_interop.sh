#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# noise_transport_interop.sh — two-node/three-node Noise transport interop
# acceptance. This is the evidence artifact for the owner's default-flip
# decision on -noisetransport: it proves, against REAL isolated regtest
# daemons, that a noise-enabled node interoperates with plaintext peers in
# both directions and upgrades to Noise XX when both sides advertise
# NODE_NOISE_TRANSPORT.
#
# Four scenarios, asserted only on OPERATOR-VISIBLE surfaces
# (`dumpstate transport` per-peer mode/state/frame counters and the
# `dumpstate connman` noisetransport census), never on log scraping:
#
#   S1  noise -> plaintext outbound: A(-noisetransport=1) dials
#       B(plaintext). The peer lacks the service bit, so A never arms the
#       transport: the link stays plaintext and blocks flow A<-B.
#   S2  plaintext -> noise inbound: B(plaintext) dials A(noise listener).
#       A's NOISE_DETECT sees plaintext network magic, takes
#       NOISE_PLAINTEXT_FALLBACK, frees the transport and replays the
#       buffered bytes: the link is plaintext and blocks flow.
#   S3  noise <-> noise: N1 dials N2 (both -noisetransport=1). First contact
#       is plaintext (a manual -connect address carries no service bits);
#       N2's version advertises NODE_NOISE_TRANSPORT, so
#       connman_request_noise_upgrade persists the capability and drives ONE
#       controlled reconnect that arms Noise XX. Asserted: session
#       established, send/recv frames > 0 both directions, blocks flow
#       sealed.
#   S4  mixed swarm: P(plaintext) + N1 + N2 fully interconnected, tip
#       consensus before and after fresh mining — the live network
#       mid-rollout shape.
#
# Port discipline: P2P listeners that a noise peer redials after the
# capability-learning upgrade must pass the production reachable-port
# policy (lib/net/include/net/port_policy.h) — only 8033, 18033, 8034,
# 9033 and 20022-20028 qualify, and 8033/8034 are in the live refuse-set.
# The harness uses 9033, 18033, 20028 for P2P and disjoint 392xx/393xx/394xx
# quads for RPC/FS/HTTPS. Process ownership, cleanup traps and port
# rebind proofs come from node_lifecycle.sh (single owner doctrine).
#
# Run:  make test-noise-transport-interop   (opt-in; NOT in `make ci`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=node_lifecycle.sh
. "$SCRIPT_DIR/node_lifecycle.sh"

TAG="noise-transport-interop"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"
NT_WAIT="${NT_WAIT:-60}"          # per-condition bounded wait (s)
SEED_BLOCKS="${SEED_BLOCKS:-10}"  # blocks mined before followers join
EXTRA_BLOCKS="${EXTRA_BLOCKS:-5}" # blocks mined over the mixed fabric

NT_FAILED=0

nt_die() {
    echo "$TAG: FATAL: $*" >&2
    if [ -n "$DHT_WORK" ] && [ -d "$DHT_WORK" ]; then
        printf '%s\n' "$*" >"$DHT_WORK/FAILURE"
    fi
    exit 2
}
nt_note() { echo "$TAG: $*"; }

nt_ok() { echo "$TAG:   OK: $1"; }
nt_bad() { echo "$TAG:   FAIL: $1" >&2; NT_FAILED=1; }

# $1=label $2=expected $3=actual
nt_assert_eq() {
    if [ "$2" = "$3" ]; then nt_ok "$1 = $3"; else
        nt_bad "$1 — expected '$2', got '$3'"; fi
}
# $1=label $2=actual integer; asserts > 0
nt_assert_positive() {
    case "$2" in
        ''|*[!0-9]*) nt_bad "$1 — expected a positive integer, got '$2'" ;;
        *) [ "$2" -gt 0 ] && nt_ok "$1 = $2 (>0)" || \
               nt_bad "$1 — expected >0, got $2" ;;
    esac
}

# ── Node spawn (node_lifecycle owns groups; dht_spawn hardcodes flags this
#    harness must vary, so the spawn line itself stays local) ──────────
# $1=out_name $2=dd $3=p2p $4=rpc $5=fs $6=https $7=noise(0|1) $8..=connect
nt_spawn() {
    local out_name="$1" dd="$2" p2p="$3" rpc="$4" fs="$5" https="$6"
    local noise="$7" connect pid
    shift 7
    local args=()
    for connect in "$@"; do args+=("-connect=$connect"); done
    [ "${#args[@]}" -gt 0 ] || args+=("-connect=127.0.0.1:$DEAD_SINK")
    local noise_args=()
    [ "$noise" = 1 ] && noise_args+=("-noisetransport=1")
    mkdir -p "$dd"
    setsid "$NODE_BIN" -datadir="$dd" -regtest -port="$p2p" \
        -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        "${args[@]}" "${noise_args[@]}" \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >>"$dd/node.log" 2>&1 &
    pid="$!"
    dht_register_owned_group "$pid"
    printf -v "$out_name" '%s' "$pid"
}

# ── Operator-surface readers ─────────────────────────────────────────
# $1=dd $2=rpc → dumpstate transport state object (or empty)
nt_transport() {
    dht_rpc "$1" "$2" dumpstate '"transport"' 2>/dev/null |
        "$JSONQ" get result.state 2>/dev/null || true
}
# $1=dd $2=rpc → dumpstate connman noisetransport census object (or empty)
nt_census() {
    dht_rpc "$1" "$2" dumpstate '"connman"' 2>/dev/null |
        "$JSONQ" get result.state.noisetransport 2>/dev/null || true
}
# stdin doc, $1=jsonq path
nt_jq() { "$JSONQ" get "$1" 2>/dev/null || true; }

# Bounded wait until a node's dumpstate transport field equals a value.
# $1=dd $2=rpc $3=jsonq path under state $4=expected $5=label
nt_wait_transport_eq() {
    local dd="$1" rpc="$2" path="$3" want="$4" label="$5"
    local deadline doc val
    deadline=$(( $(date +%s) + NT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        doc="$(nt_transport "$dd" "$rpc")"
        val="$(printf '%s' "$doc" | nt_jq "$path")"
        [ "$val" = "$want" ] && { printf '%s' "$doc"; return 0; }
        sleep 0.5
    done
    printf '%s' "$doc"
    echo "$TAG:   timeout waiting for $label ($path == $want)" >&2
    return 1
}

nt_wait_port_free() {
    local p="$1" deadline
    deadline=$(( $(date +%s) + 30 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        [ -z "$(ss -tlnH "sport = :$p" 2>/dev/null)" ] && return 0
        sleep 0.2
    done
    return 1
}

# ── Preflight ────────────────────────────────────────────────────────
command -v ss >/dev/null 2>&1 || nt_die "ss(8) not found (need iproute2)"
[ -x "$NODE_BIN" ] || nt_die "$NODE_BIN not built — run make zclassic23"
[ -x "$RPC_BIN" ]  || nt_die "$RPC_BIN not built — run make zcl-rpc"
[ -x "$JSONQ" ]    || nt_die "$JSONQ not built — run make jsonq"
[ -x "$DHT_ACCEPTANCE_C23" ] || \
    nt_die "$DHT_ACCEPTANCE_C23 not built — run the acceptance-binaries target"

dht_make_work zcl23-noise
nt_note "workdir $DHT_WORK"

# Phase ports. P2P listeners take reachable-policy ports (9033/18033/20028);
# RPC/FS/HTTPS take disjoint quads.
P1_P2P=9033;  P1_RPC=39211; P1_FS=39311; P1_HTTPS=39411
A1_P2P=39140; A1_RPC=39212; A1_FS=39312; A1_HTTPS=39412
A2_P2P=20028; A2_RPC=39222; A2_FS=39322; A2_HTTPS=39422
B2_P2P=39141; B2_RPC=39223; B2_FS=39323; B2_HTTPS=39423
P_P2P=18033;  P_RPC=39231;  P_FS=39331;  P_HTTPS=39431
N1_P2P=9033;  N1_RPC=39232; N1_FS=39332; N1_HTTPS=39432
N2_P2P=20028; N2_RPC=39233; N2_FS=39333; N2_HTTPS=39433

for p in $P1_P2P $P1_RPC $P1_FS $P1_HTTPS \
         $A1_P2P $A1_RPC $A1_FS $A1_HTTPS \
         $A2_P2P $A2_RPC $A2_FS $A2_HTTPS \
         $B2_P2P $B2_RPC $B2_FS $B2_HTTPS \
         $P_P2P  $P_RPC  $P_FS  $P_HTTPS \
         $N1_P2P $N1_RPC $N1_FS $N1_HTTPS \
         $N2_P2P $N2_RPC $N2_FS $N2_HTTPS; do
    dht_assert_port "$p"
done

DD_P1="$DHT_WORK/p1"; DD_A1="$DHT_WORK/a1"
DD_A2="$DHT_WORK/a2"; DD_B2="$DHT_WORK/b2"
DD_P="$DHT_WORK/p";   DD_N1="$DHT_WORK/n1"; DD_N2="$DHT_WORK/n2"

# ═══ S1: noise -> plaintext outbound ═══════════════════════════════
nt_note "[S1] noise->plaintext outbound: B plaintext miner, A noise dials B"
nt_spawn PGID_P1 "$DD_P1" $P1_P2P $P1_RPC $P1_FS $P1_HTTPS 0
dht_wait_rpc "$DD_P1" $P1_RPC "$PGID_P1" || nt_die "P1 RPC warmup failed"
DHT_MINE_DD="$DD_P1"; DHT_MINE_RPC=$P1_RPC
dht_mine_empty "$SEED_BLOCKS"
S1_TIP="$(dht_height "$DD_P1" $P1_RPC)"
[ "$S1_TIP" = "$SEED_BLOCKS" ] || nt_die "P1 did not mine $SEED_BLOCKS (got $S1_TIP)"

nt_spawn PGID_A1 "$DD_A1" $A1_P2P $A1_RPC $A1_FS $A1_HTTPS 1 \
    "127.0.0.1:$P1_P2P"
dht_wait_rpc "$DD_A1" $A1_RPC "$PGID_A1" || nt_die "A1 RPC warmup failed"
dht_wait_height "$DD_A1" $A1_RPC "$S1_TIP" ||
    nt_die "A1 did not sync to P1 tip $S1_TIP over the interop link"
nt_ok "S1 tip propagated A<-B over plaintext: height $S1_TIP"

A1_T="$(nt_wait_transport_eq "$DD_A1" $A1_RPC plaintext_peers 1 \
        "A1 plaintext peer" || true)"
[ -n "$A1_T" ] || nt_bad "A1 dumpstate transport never answered"
nt_assert_eq "S1 A noise_enabled" true \
    "$(printf '%s' "$A1_T" | nt_jq noise_enabled)"
nt_assert_eq "S1 A noise_peers" 0 \
    "$(printf '%s' "$A1_T" | nt_jq noise_peers)"
nt_assert_eq "S1 A plaintext_peers" 1 \
    "$(printf '%s' "$A1_T" | nt_jq plaintext_peers)"
nt_assert_eq "S1 A peers[0].mode" plaintext \
    "$(printf '%s' "$A1_T" | nt_jq 'peers[0].mode')"
A1_C="$(nt_census "$DD_A1" $A1_RPC)"
nt_assert_eq "S1 A census advertising_now (B has no bit)" 0 \
    "$(printf '%s' "$A1_C" | nt_jq advertising_now)"
nt_assert_eq "S1 A census default_enabled" true \
    "$(printf '%s' "$A1_C" | nt_jq default_enabled)"
P1_T="$(nt_transport "$DD_P1" $P1_RPC)"
nt_assert_eq "S1 B noise_enabled" false \
    "$(printf '%s' "$P1_T" | nt_jq noise_enabled)"
nt_assert_eq "S1 B plaintext_peers" 1 \
    "$(printf '%s' "$P1_T" | nt_jq plaintext_peers)"
P1_C="$(nt_census "$DD_P1" $P1_RPC)"
nt_assert_eq "S1 B census sees A's advertisement" 1 \
    "$(printf '%s' "$P1_C" | nt_jq advertising_now)"

dht_kill_group "$PGID_A1"; dht_kill_group "$PGID_P1"
nt_wait_port_free $P1_P2P || nt_die "P1 p2p port did not release"

# ═══ S2: plaintext -> noise inbound ════════════════════════════════
nt_note "[S2] plaintext->noise inbound: A noise listener+miner, B plaintext dials A"
nt_spawn PGID_A2 "$DD_A2" $A2_P2P $A2_RPC $A2_FS $A2_HTTPS 1
dht_wait_rpc "$DD_A2" $A2_RPC "$PGID_A2" || nt_die "A2 RPC warmup failed"
DHT_MINE_DD="$DD_A2"; DHT_MINE_RPC=$A2_RPC
dht_mine_empty "$SEED_BLOCKS"
S2_TIP="$(dht_height "$DD_A2" $A2_RPC)"
[ "$S2_TIP" = "$SEED_BLOCKS" ] || nt_die "A2 did not mine $SEED_BLOCKS (got $S2_TIP)"

nt_spawn PGID_B2 "$DD_B2" $B2_P2P $B2_RPC $B2_FS $B2_HTTPS 0 \
    "127.0.0.1:$A2_P2P"
dht_wait_rpc "$DD_B2" $B2_RPC "$PGID_B2" || nt_die "B2 RPC warmup failed"
dht_wait_height "$DD_B2" $B2_RPC "$S2_TIP" ||
    nt_die "B2 did not sync to A2 tip $S2_TIP over the fallback link"
nt_ok "S2 tip propagated B<-A over plaintext fallback: height $S2_TIP"

A2_T="$(nt_wait_transport_eq "$DD_A2" $A2_RPC plaintext_peers 1 \
        "A2 plaintext peer" || true)"
nt_assert_eq "S2 A noise_enabled" true \
    "$(printf '%s' "$A2_T" | nt_jq noise_enabled)"
nt_assert_eq "S2 A noise_peers" 0 \
    "$(printf '%s' "$A2_T" | nt_jq noise_peers)"
nt_assert_eq "S2 A plaintext_peers (NOISE_DETECT fallback)" 1 \
    "$(printf '%s' "$A2_T" | nt_jq plaintext_peers)"
nt_assert_eq "S2 A peers[0].mode" plaintext \
    "$(printf '%s' "$A2_T" | nt_jq 'peers[0].mode')"
A2_C="$(nt_census "$DD_A2" $A2_RPC)"
nt_assert_eq "S2 A census advertising_now (B has no bit)" 0 \
    "$(printf '%s' "$A2_C" | nt_jq advertising_now)"
B2_T="$(nt_transport "$DD_B2" $B2_RPC)"
nt_assert_eq "S2 B noise_enabled" false \
    "$(printf '%s' "$B2_T" | nt_jq noise_enabled)"
nt_assert_eq "S2 B plaintext_peers" 1 \
    "$(printf '%s' "$B2_T" | nt_jq plaintext_peers)"

dht_kill_group "$PGID_B2"; dht_kill_group "$PGID_A2"
nt_wait_port_free $A2_P2P || nt_die "A2 p2p port did not release"

# ═══ S3+S4: noise<->noise inside a 3-node mixed swarm ══════════════
nt_note "[S3+S4] mixed swarm: P plaintext miner, N2 noise dials P, N1 noise dials P+N2"
nt_spawn PGID_P "$DD_P" $P_P2P $P_RPC $P_FS $P_HTTPS 0
dht_wait_rpc "$DD_P" $P_RPC "$PGID_P" || nt_die "P RPC warmup failed"
DHT_MINE_DD="$DD_P"; DHT_MINE_RPC=$P_RPC
dht_mine_empty "$SEED_BLOCKS"
S4_TIP="$(dht_height "$DD_P" $P_RPC)"
[ "$S4_TIP" = "$SEED_BLOCKS" ] || nt_die "P did not mine $SEED_BLOCKS (got $S4_TIP)"

nt_spawn PGID_N2 "$DD_N2" $N2_P2P $N2_RPC $N2_FS $N2_HTTPS 1 \
    "127.0.0.1:$P_P2P"
dht_wait_rpc "$DD_N2" $N2_RPC "$PGID_N2" || nt_die "N2 RPC warmup failed"
nt_spawn PGID_N1 "$DD_N1" $N1_P2P $N1_RPC $N1_FS $N1_HTTPS 1 \
    "127.0.0.1:$P_P2P" "127.0.0.1:$N2_P2P"
dht_wait_rpc "$DD_N1" $N1_RPC "$PGID_N1" || nt_die "N1 RPC warmup failed"

# S3: N1<->N2 must ride one controlled capability-learning upgrade to a real
# Noise XX session. Bounded wait on the operator surface.
N1_T="$(nt_wait_transport_eq "$DD_N1" $N1_RPC noise_peers 1 \
        "N1 noise peer (upgrade)" || true)"
nt_assert_eq "S3 N1 noise_peers" 1 \
    "$(printf '%s' "$N1_T" | nt_jq noise_peers)"
nt_assert_eq "S3 N1 plaintext_peers (link to P)" 1 \
    "$(printf '%s' "$N1_T" | nt_jq plaintext_peers)"
# Find the noise_xx peer entry on N1 and assert the live session facts.
N1_NPEERS="$(printf '%s' "$N1_T" | "$JSONQ" count peers 2>/dev/null || true)"
N1_NIDX=""
for i in $(seq 0 $(( ${N1_NPEERS:-1} - 1 ))); do
    [ "$(printf '%s' "$N1_T" | nt_jq "peers[$i].mode")" = "noise_xx" ] && N1_NIDX="$i"
done
[ -n "$N1_NIDX" ] || nt_bad "S3 N1 has no noise_xx peer entry"
if [ -n "$N1_NIDX" ]; then
    nt_assert_eq "S3 N1 noise peer state" established \
        "$(printf '%s' "$N1_T" | nt_jq "peers[$N1_NIDX].state")"
    nt_assert_eq "S3 N1 noise peer is_initiator" true \
        "$(printf '%s' "$N1_T" | nt_jq "peers[$N1_NIDX].is_initiator")"
    nt_assert_positive "S3 N1 noise send_frames" \
        "$(printf '%s' "$N1_T" | nt_jq "peers[$N1_NIDX].send_frames")"
    nt_assert_positive "S3 N1 noise recv_frames" \
        "$(printf '%s' "$N1_T" | nt_jq "peers[$N1_NIDX].recv_frames")"
fi

N2_T="$(nt_wait_transport_eq "$DD_N2" $N2_RPC noise_peers 1 \
        "N2 noise peer" || true)"
nt_assert_eq "S3 N2 noise_peers" 1 \
    "$(printf '%s' "$N2_T" | nt_jq noise_peers)"
nt_assert_eq "S3 N2 plaintext_peers (link to P)" 1 \
    "$(printf '%s' "$N2_T" | nt_jq plaintext_peers)"
N2_NPEERS="$(printf '%s' "$N2_T" | "$JSONQ" count peers 2>/dev/null || true)"
N2_NIDX=""
for i in $(seq 0 $(( ${N2_NPEERS:-1} - 1 ))); do
    [ "$(printf '%s' "$N2_T" | nt_jq "peers[$i].mode")" = "noise_xx" ] && N2_NIDX="$i"
done
[ -n "$N2_NIDX" ] || nt_bad "S3 N2 has no noise_xx peer entry"
if [ -n "$N2_NIDX" ]; then
    nt_assert_eq "S3 N2 noise peer state" established \
        "$(printf '%s' "$N2_T" | nt_jq "peers[$N2_NIDX].state")"
    nt_assert_eq "S3 N2 noise peer is_initiator (responder)" false \
        "$(printf '%s' "$N2_T" | nt_jq "peers[$N2_NIDX].is_initiator")"
    nt_assert_positive "S3 N2 noise send_frames" \
        "$(printf '%s' "$N2_T" | nt_jq "peers[$N2_NIDX].send_frames")"
    nt_assert_positive "S3 N2 noise recv_frames" \
        "$(printf '%s' "$N2_T" | nt_jq "peers[$N2_NIDX].recv_frames")"
fi

# S4: full-mesh plaintext floor + census visibility + tip consensus.
P_T="$(nt_wait_transport_eq "$DD_P" $P_RPC plaintext_peers 2 \
        "P two plaintext peers" || true)"
nt_assert_eq "S4 P noise_enabled" false \
    "$(printf '%s' "$P_T" | nt_jq noise_enabled)"
nt_assert_eq "S4 P plaintext_peers (both noise nodes inbound/outbound)" 2 \
    "$(printf '%s' "$P_T" | nt_jq plaintext_peers)"
P_C="$(nt_census "$DD_P" $P_RPC)"
nt_assert_eq "S4 P census sees both advertisements mid-rollout" 2 \
    "$(printf '%s' "$P_C" | nt_jq advertising_now)"
nt_assert_eq "S4 P census default_enabled" false \
    "$(printf '%s' "$P_C" | nt_jq default_enabled)"
N1_C="$(nt_census "$DD_N1" $N1_RPC)"
nt_assert_eq "S4 N1 census advertising_now (N2)" 1 \
    "$(printf '%s' "$N1_C" | nt_jq advertising_now)"

dht_wait_height "$DD_N1" $N1_RPC "$S4_TIP" ||
    nt_die "N1 did not reach swarm tip $S4_TIP"
dht_wait_height "$DD_N2" $N2_RPC "$S4_TIP" ||
    nt_die "N2 did not reach swarm tip $S4_TIP"
nt_ok "S4 initial tip consensus at $S4_TIP across P/N1/N2"

# Mine over the mixed fabric: every node must converge again, with the
# N1<->N2 hop provably sealed (asserted above, still established after).
dht_mine_empty "$EXTRA_BLOCKS"
NEW_TIP=$(( S4_TIP + EXTRA_BLOCKS ))
dht_wait_height "$DD_N1" $N1_RPC "$NEW_TIP" ||
    nt_die "N1 did not converge to $NEW_TIP"
dht_wait_height "$DD_N2" $N2_RPC "$NEW_TIP" ||
    nt_die "N2 did not converge to $NEW_TIP"
nt_ok "S4 post-mining tip consensus at $NEW_TIP across the mixed fabric"
N1_T2="$(nt_transport "$DD_N1" $N1_RPC)"
nt_assert_eq "S4 N1 noise session survived block relay" established \
    "$(printf '%s' "$N1_T2" | nt_jq "peers[${N1_NIDX:-0}].state")"

dht_kill_group "$PGID_N1"; dht_kill_group "$PGID_N2"; dht_kill_group "$PGID_P"

# ═══ Verdict ═══════════════════════════════════════════════════════
if [ "$NT_FAILED" = 0 ]; then
    if ! dht_cleanup; then
        nt_die "owned process groups did not terminate during success cleanup"
    fi
    dht_assert_no_owned_processes
    dht_assert_ports_rebindable
    nt_note "PASS: S1 noise->plaintext outbound, S2 plaintext->noise inbound fallback, S3 noise<->noise Noise XX upgrade (sealed frames), S4 mixed-swarm tip consensus; owned_processes_remaining=0 ports_rebindable=true"
    exit 0
fi
nt_note "FAIL — one or more interop assertions did not hold"
exit 1
