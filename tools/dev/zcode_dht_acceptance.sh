#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# S6 acceptance: seven isolated regtest nodes anchor independent ZID masters,
# provision chain-bound DHT delegations, then prove hostile-frame rejection,
# sparse iterative FIND_NODE, fair concurrency, persistence, and cold reauth.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# tools/dev/node_lifecycle.sh owns work-dir creation, port claims, process
# group ownership, cleanup and the EXIT trap for every acceptance that spawns
# real nodes. It used to live inline here; it is shared so a second harness
# cannot drift into a second lifecycle state machine.
. "$SCRIPT_DIR/node_lifecycle.sh"

A_PORT=20022; A_RPC=29211; A_FS=29212; A_HTTPS=29213
B_PORT=18033; B_RPC=29221; B_FS=29222; B_HTTPS=29223
a_rpc() { dht_rpc "$DHT_DD_A" "$A_RPC" "$@"; }
b_rpc() { dht_rpc "$DHT_DD_B" "$B_RPC" "$@"; }

dht_probe_read_report() {
    local path="$1" pid_name="$2" port_name="$3" start_name="$4"
    local probe_pid probe_port probe_start extra
    read -r probe_pid probe_port extra <"$path"
    probe_start="$(awk '{print $22}' "/proc/$probe_pid/stat" \
        2>/dev/null || true)"
    [ -n "$probe_pid" ] && [ -n "$probe_port" ] &&
        [ -n "$probe_start" ] && [ -z "${extra:-}" ] ||
        dht_die "invalid lifecycle probe report $path"
    printf -v "$pid_name" '%s' "$probe_pid"
    printf -v "$port_name" '%s' "$probe_port"
    printf -v "$start_name" '%s' "$probe_start"
}

dht_lifecycle_probe_child() {
    local report="${DHT_PROBE_REPORT:?}" release="${DHT_PROBE_RELEASE:?}"
    local outcome="${DHT_PROBE_OUTCOME:?}" listener="" listener_port
    dht_make_work zcl23-dhtprobe
    setsid "$DHT_ACCEPTANCE_C23" listen-report "$report" \
        >>"$DHT_WORK/listener.log" 2>&1 &
    listener="$!"
    dht_register_owned_group "$listener"
    dht_wait_file "$report" "$listener" ||
        dht_die "lifecycle probe listener failed before readiness"
    read -r _ listener_port _ <"$report"
    DHT_OWNED_PORTS+=("$listener_port")
    dht_wait_file "$release" "$$" ||
        dht_die "lifecycle probe release was not observed"
    [ "$outcome" = success ] || dht_die "forced middle-of-run failure"
    if ! dht_cleanup; then
        echo "zcode-dht-acceptance: FATAL: lifecycle probe cleanup failed" >&2
        exit 2
    fi
    dht_assert_no_owned_processes
    dht_assert_ports_rebindable
    dht_note "PASS lifecycle probe; owned_processes_remaining=0 ports_rebindable=true"
}

dht_lifecycle_selftest() {
    local one_shell two_shell three_shell signal_shell
    local one_pid one_port one_start two_pid two_port two_start
    local three_pid three_port three_start signal_pid signal_port signal_start
    dht_make_work zcl23-dhtprobe

    dht_spawn_owned_command one_shell "$DHT_WORK/one.log" env \
        DHT_LIFECYCLE_MODE=probe DHT_PROBE_OUTCOME=success \
        DHT_PROBE_REPORT="$DHT_WORK/one.report" \
        DHT_PROBE_RELEASE="$DHT_WORK/one.release" \
        bash "$SCRIPT_DIR/zcode_dht_acceptance.sh"
    dht_spawn_owned_command two_shell "$DHT_WORK/two.log" env \
        DHT_LIFECYCLE_MODE=probe DHT_PROBE_OUTCOME=failure \
        DHT_PROBE_REPORT="$DHT_WORK/two.report" \
        DHT_PROBE_RELEASE="$DHT_WORK/two.release" \
        bash "$SCRIPT_DIR/zcode_dht_acceptance.sh"
    dht_wait_file "$DHT_WORK/one.report" "$one_shell" ||
        dht_die "first concurrent lifecycle probe did not become ready"
    dht_wait_file "$DHT_WORK/two.report" "$two_shell" ||
        dht_die "second concurrent lifecycle probe did not become ready"
    dht_probe_read_report "$DHT_WORK/one.report" one_pid one_port one_start
    dht_probe_read_report "$DHT_WORK/two.report" two_pid two_port two_start
    [ "$one_port" != "$two_port" ] || dht_die "concurrent probes shared a port"
    DHT_OWNED_PORTS+=("$one_port" "$two_port")

    printf '%s\n' release >"$DHT_WORK/two.release"
    dht_wait_owned_exit "$two_shell" 2 "forced-failure lifecycle probe"
    ! dht_process_identity_alive "$two_pid" "$two_start" ||
        dht_die "failed probe left its owned listener alive"
    dht_process_identity_alive "$one_pid" "$one_start" ||
        dht_die "failed probe cleaned the other probe's listener"

    printf '%s\n' release >"$DHT_WORK/one.release"
    dht_wait_owned_exit "$one_shell" 0 "successful lifecycle probe"
    ! dht_process_identity_alive "$one_pid" "$one_start" ||
        dht_die "successful probe left its owned listener alive"
    dht_assert_ports_rebindable

    dht_spawn_owned_command three_shell "$DHT_WORK/three.log" env \
        DHT_LIFECYCLE_MODE=probe DHT_PROBE_OUTCOME=success \
        DHT_PROBE_REPORT="$DHT_WORK/three.report" \
        DHT_PROBE_RELEASE="$DHT_WORK/three.release" \
        bash "$SCRIPT_DIR/zcode_dht_acceptance.sh"
    dht_wait_file "$DHT_WORK/three.report" "$three_shell" ||
        dht_die "immediate rerun lifecycle probe did not become ready"
    dht_probe_read_report "$DHT_WORK/three.report" three_pid three_port three_start
    DHT_OWNED_PORTS+=("$three_port")
    printf '%s\n' release >"$DHT_WORK/three.release"
    dht_wait_owned_exit "$three_shell" 0 "immediate-rerun lifecycle probe"
    ! dht_process_identity_alive "$three_pid" "$three_start" ||
        dht_die "immediate rerun left its owned listener alive"

    dht_spawn_owned_command signal_shell "$DHT_WORK/signal.log" env \
        DHT_LIFECYCLE_MODE=probe DHT_PROBE_OUTCOME=success \
        DHT_PROBE_REPORT="$DHT_WORK/signal.report" \
        DHT_PROBE_RELEASE="$DHT_WORK/signal.release" \
        bash "$SCRIPT_DIR/zcode_dht_acceptance.sh"
    dht_wait_file "$DHT_WORK/signal.report" "$signal_shell" ||
        dht_die "signal lifecycle probe did not become ready"
    dht_probe_read_report "$DHT_WORK/signal.report" \
        signal_pid signal_port signal_start
    DHT_OWNED_PORTS+=("$signal_port")
    kill -TERM "-$signal_shell"
    dht_wait_owned_exit "$signal_shell" 143 "interrupted lifecycle probe"
    ! dht_process_identity_alive "$signal_pid" "$signal_start" ||
        dht_die "interrupted probe left its owned listener alive"

    if ! dht_cleanup; then
        echo "zcode-dht-acceptance: FATAL: lifecycle selftest cleanup failed" >&2
        exit 2
    fi
    dht_assert_no_owned_processes
    dht_assert_ports_rebindable
    dht_note "PASS lifecycle ownership: concurrent isolation, failure, interruption, immediate rerun"
}

case "${DHT_LIFECYCLE_MODE:-scenario}" in
    probe) dht_lifecycle_probe_child; exit 0 ;;
    selftest) dht_lifecycle_selftest; exit 0 ;;
    scenario) ;;
    *) dht_die "unknown DHT_LIFECYCLE_MODE=${DHT_LIFECYCLE_MODE:-}" ;;
esac


dht_build_helper() {
    cc -std=c23 -O1 -w -D_GNU_SOURCE -ffunction-sections -fdata-sections \
        -Wl,--gc-sections -I"$REPO_ROOT/lib/base/include" \
        -I"$REPO_ROOT/lib/sha3/include" -I"$REPO_ROOT/lib/crypto/include" \
        -I"$REPO_ROOT/lib/support/include" \
        -I"$REPO_ROOT/lib/util/include" -I"$REPO_ROOT/lib/platform/include" \
        -I"$REPO_ROOT/lib/json/include" -I"$REPO_ROOT/lib/core/include" \
        -I"$REPO_ROOT/lib/net/include" -I"$REPO_ROOT/lib/noise/include" \
        -I"$REPO_ROOT/lib/vcs/include" -I"$REPO_ROOT/lib/zid/include" \
        -I"$REPO_ROOT/core/math/include" -o "$DHT_WORK/dht-peer" \
        "$REPO_ROOT/tools/zcode_dht_acceptance_peer.c" \
        "$REPO_ROOT/lib/net/src/noise_transport.c" \
        "$REPO_ROOT/lib/noise/src/noise_handshake.c" \
        "$REPO_ROOT/lib/noise/src/session_transport.c" \
        "$REPO_ROOT/lib/vcs/src/zcode_dht.c" \
        "$REPO_ROOT/lib/vcs/src/zcode_dht_delegation.c" \
        "$REPO_ROOT/lib/vcs/src/zcode_dht_identity.c" \
        "$REPO_ROOT/lib/vcs/src/zcode_dht_msgs.c" \
        "$REPO_ROOT/lib/zid/src/zid.c" \
        "$REPO_ROOT/lib/zid/src/zendp.c" \
        "$REPO_ROOT/lib/crypto/src/ed25519.c" \
        "$REPO_ROOT/lib/crypto/src/sha512.c" \
        "$REPO_ROOT/lib/crypto/src/sha256.c" \
        "$REPO_ROOT/lib/sha3/src/sha3.c" \
        "$REPO_ROOT/lib/crypto/src/hmac_sha256.c" \
        "$REPO_ROOT/lib/crypto/src/hkdf_sha256.c" \
        "$REPO_ROOT/lib/crypto/src/chacha20poly1305.c" \
        "$REPO_ROOT/lib/support/src/log_throttle.c" \
        "$REPO_ROOT/lib/crypto/src/curve25519.c" \
        "$REPO_ROOT/lib/crypto/src/x25519_safe.c" \
        "$REPO_ROOT/lib/crypto/src/random_secret.c" \
        "$REPO_ROOT/core/math/src/hash.c" \
        "$REPO_ROOT/lib/core/src/utiltime.c" \
        "$REPO_ROOT/lib/core/src/random.c" \
        "$REPO_ROOT/lib/base/src/safe_alloc.c" \
        "$REPO_ROOT/lib/base/src/log_level.c" \
        "$REPO_ROOT/lib/base/src/result.c" \
        "$REPO_ROOT/lib/base/src/cleanse.c" \
        "$REPO_ROOT/lib/platform/src/clock.c" \
        "$REPO_ROOT/lib/platform/src/rng.c" \
        "$REPO_ROOT/lib/util/src/write_all.c" \
        "$REPO_ROOT/lib/json/src/json.c" \
        "$REPO_ROOT/lib/util/src/hw_profile.c" \
        "$REPO_ROOT/lib/util/src/cpu_topology.c" ||
        dht_die "acceptance helper compile failed"
}

dht_check_find() {
    local reply="$1" target="$2" a_id="$3" b_id="$4"
    "$DHT_ACCEPTANCE_C23" find-check "$reply" "$target" "$a_id" "$b_id" ||
        dht_die "FIND_NODE result/order mismatch"
}

dht_check_contacts_file() {
    local path="$1" self_id="$2" expected="${3:-1}"
    "$DHT_ACCEPTANCE_C23" contacts-check "$path" "$self_id" "$expected" ||
        dht_die "non-canonical contacts file: $path"
}

dht_check_attack_deltas() {
    local before="$1" after="$2"
    "$DHT_ACCEPTANCE_C23" attack-deltas "$before" "$after" ||
        dht_die "hostile Noise-frame counter deltas differ"
}

for port in $A_PORT $A_RPC $A_FS $A_HTTPS $B_PORT $B_RPC $B_FS $B_HTTPS; do
    dht_assert_port "$port"
done
[ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] && [ -x "$DHT_ACCEPTANCE_C23" ] ||
    dht_die "build node, RPC, and native C23 acceptance binaries first"
dht_make_work zcl23-dhtacc
# This regtest transport/package fixture never proves a shielded transaction.
# Keep its boot cost and outcome independent of any operator-installed proving
# parameters; callers that really need a particular fixture can still provide
# DHT_PARAMS_DIR explicitly.
if [ -z "$DHT_PARAMS_DIR" ]; then
    DHT_PARAMS_DIR="$DHT_WORK/no-zk-params"
    mkdir -p "$DHT_PARAMS_DIR"
fi
DHT_DD_A="$DHT_WORK/a"; DHT_DD_B="$DHT_WORK/b"
# node_lifecycle.sh mines through whichever node the harness nominates.
DHT_MINE_DD="$DHT_DD_A"; DHT_MINE_RPC="$A_RPC"
mkdir -p "$DHT_DD_A" "$DHT_DD_B"
dht_build_helper

SEED_A=1111111111111111111111111111111111111111111111111111111111111111
SEED_B=2222222222222222222222222222222222222222222222222222222222222222
install -m 600 /dev/null "$DHT_WORK/master-a.hex"
install -m 600 /dev/null "$DHT_WORK/master-b.hex"
printf '%s\n' "$SEED_A" >"$DHT_WORK/master-a.hex"
printf '%s\n' "$SEED_B" >"$DHT_WORK/master-b.hex"
PUB_A="$("$DHT_WORK/dht-peer" pubkey "$SEED_A")"
PUB_B="$("$DHT_WORK/dht-peer" pubkey "$SEED_B")"

declare -a DDS RPCS PORTS FSPORTS HTTPSPORTS SEEDS PUBS NODES PIDS DOCS
DDS=("$DHT_DD_A" "$DHT_DD_B")
RPCS=("$A_RPC" "$B_RPC")
PORTS=("$A_PORT" "$B_PORT" 20023 20024 20025 20026 20027)
FSPORTS=("$A_FS" "$B_FS" 29232 29242 29252 29262 29272)
HTTPSPORTS=("$A_HTTPS" "$B_HTTPS" 29233 29243 29253 29263 29273)
SEEDS=("$SEED_A" "$SEED_B"
  3333333333333333333333333333333333333333333333333333333333333333
  4444444444444444444444444444444444444444444444444444444444444444
  5555555555555555555555555555555555555555555555555555555555555555
  6666666666666666666666666666666666666666666666666666666666666666
  7777777777777777777777777777777777777777777777777777777777777777)
PUBS=("$PUB_A" "$PUB_B")
for port in 20023 20024 20025 20026 20027 \
    29231 29232 29233 29241 29242 29243 29251 29252 29253 \
    29261 29262 29263 29271 29272 29273; do
    dht_assert_port "$port"
done
for i in 2 3 4 5 6; do
    DDS[$i]="$DHT_WORK/node-$i"
    RPCS[$i]=$((29211 + i * 10))
    mkdir -p "${DDS[$i]}"
    seed_file="$DHT_WORK/master-$i.hex"
    install -m 600 /dev/null "$seed_file"
    printf '%s\n' "${SEEDS[$i]}" >"$seed_file"
    PUBS[$i]="$("$DHT_WORK/dht-peer" pubkey "${SEEDS[$i]}")"
done

# Wallet custody: boot every node with a passphrase credential so key
# writes encrypt at rest (WKS1) — the ZID anchor's overlay-intent custody
# gate refuses a plaintext-at-rest wallet. The current-key encrypted
# backup itself happens after mining below, once the spend key exists.
DHT_CRED_DIR="$DHT_WORK/cred"
install -d -m 700 "$DHT_CRED_DIR"
install -m 600 /dev/null "$DHT_CRED_DIR/wallet-passphrase"
printf '%s\n' "$DHT_WALLET_PASS" >"$DHT_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$DHT_CRED_DIR"

dht_note "booting two clean packagehost=$DHT_PACKAGEHOST regtest nodes"
dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
    "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" || dht_die "node A RPC warmup failed"
dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
    "$B_HTTPS" "127.0.0.1:$A_PORT"
dht_wait_rpc "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" || dht_die "node B RPC warmup failed"
! grep -qaF "unrecognized flag '-noisetransport'" "$DHT_DD_A/node.log" "$DHT_DD_B/node.log" ||
    dht_die "noisetransport was not recognized"

dht_note "mining spendable regtest funds"
ADDR="$(a_rpc getnewaddress | dht_result)"
dht_mine_to_address 101 "$ADDR"
dht_wait_height "$DHT_DD_B" "$B_RPC" 101 || dht_die "B did not sync funding chain"
dht_wait_fold "$DHT_DD_A" "$A_RPC" 101 || dht_die "A reducer fold did not reach the funding tip"

# The ZID anchor's overlay-intent custody gate requires the wallet
# encrypted at rest, unlocked, and covered by a current-key encrypted
# backup; its money gate requires A to hold an OUTBOUND peer with a live
# sync state (the money-freshness classifier fails closed on
# finding_peers, and the sync FSM only leaves it behind an outbound peer).
# Mirror the metaverse-tour recipe: bounce B onto the dead sink so the
# pair's only post-restart link is A's outbound onetry below (B's own
# redial-backoff was measured >60s — deterministic, no already-connected
# skip), then restart A so the forward-folded coins set stamps its
# authority (the coins_kv authority stamps land only at boot).
dht_note "bouncing B onto the dead sink (A will own the custody-phase link)"
dht_kill_group "$DHT_PGID_B"; DHT_PGID_B=""
dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
    "$B_HTTPS" "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" || dht_die "B dead-sink bounce failed"
dht_note "restarting A so the forward-folded coins set stamps its authority"
dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
    "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" || dht_die "A custody restart failed"
dht_wait_fold "$DHT_DD_A" "$A_RPC" 101 || dht_die "A reducer fold did not survive the restart"
# Operator-directed onetry: bypasses the reachable-port policy and lands
# immediately — B is up, listening, and not connected to us.
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
dht_wait_connected "$DHT_DD_A" "$A_RPC" || dht_die "A never connected outbound to B"
dht_wait_sync_live "$DHT_DD_A" "$A_RPC" || dht_die "A sync never left finding_peers"
dht_wait_chain_loaded "$DHT_DD_A" "$A_RPC" 101 || dht_die "A active chain index did not load"

# The restart re-locks the encrypted-at-rest wallet; the anchor's
# funding-input build draws from the key pool, which a locked wallet
# refuses. Unlock explicitly (passphrase via --input=- only), re-top the
# RAM-only keypool bookkeeping with one getnewaddress, then take the
# current-key encrypted backup the custody gate demands (AFTER the top-up,
# so the backup covers the key the anchor spends from).
dht_note "unlocking the wallet and taking the current-key encrypted backup"
dht_unlock_wallet "$DHT_DD_A" "$A_RPC" || dht_die "A wallet unlock failed"
a_rpc getnewaddress | dht_result >/dev/null || dht_die "post-restart keypool top-up failed"
dht_backup_wallet "$DHT_DD_A" "$A_RPC" || dht_die "A custody backup failed"
dht_wait_spendable "$DHT_DD_A" "$A_RPC" || dht_die "A vault spendable never became positive"

dht_note "anchoring seven masters (plan/commit under identity custody)"
ANCHOR_A="$(dht_anchor "$DHT_DD_A" "$A_RPC" "$PUB_A" "dht-anchor-a")" || dht_die "A anchor failed"
dht_mine_empty 1; sleep 1
ANCHOR_B="$(dht_anchor "$DHT_DD_A" "$A_RPC" "$PUB_B" "dht-anchor-b")" || dht_die "B anchor failed"
dht_mine_empty 1; sleep 1
for i in 2 3 4 5 6; do
    dht_anchor "$DHT_DD_A" "$A_RPC" "${PUBS[$i]}" "dht-anchor-$i" >/dev/null ||
        dht_die "anchor $i failed"
    dht_mine_empty 1; sleep 1
done
dht_mine_empty 21
dht_wait_height "$DHT_DD_B" "$B_RPC" 129 || dht_die "B did not sync final beacon chain"

dht_note "provisioning independent delegations through the operator leaf"
DELEGATE_A="$(dht_native "$DHT_DD_A" "$A_RPC" zcode network delegate --input="{\"seed_file\":\"$DHT_WORK/master-a.hex\"}")"
DELEGATE_B="$(dht_native "$DHT_DD_B" "$B_RPC" zcode network delegate --input="{\"seed_file\":\"$DHT_WORK/master-b.hex\"}")"
[ "$(printf '%s' "$DELEGATE_A" | dht_jget ok)" = True ] || dht_die "A delegation failed: $DELEGATE_A"
[ "$(printf '%s' "$DELEGATE_B" | dht_jget ok)" = True ] || dht_die "B delegation failed: $DELEGATE_B"
NODE_A="$(printf '%s' "$DELEGATE_A" | dht_jget data.node_id)"
NODE_B="$(printf '%s' "$DELEGATE_B" | dht_jget data.node_id)"
NODES=("$NODE_A" "$NODE_B")
[ "$NODE_A" != "$NODE_B" ] || dht_die "independent masters derived one node ID"

# Close A to obtain a coherent chain fixture while B remains on its original
# boot with a provable RPC tip.  The delegate leaf can authorize a distinct
# target datadir explicitly: it reads that clone's chain projection, uses B's
# authenticated chain RPC for genesis/beacon, and creates new target-local
# Noise and online keys.  No DHT contacts or endpoint records are copied.
dht_note "preparing five closed-chain fixtures with independent identities"
dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
for i in 2 3 4 5 6; do
    cp -a "$DHT_DD_A/." "${DDS[$i]}/"
    rm -rf "${DDS[$i]}/zcode"
    rm -f "${DDS[$i]}/v2_identity.key" "${DDS[$i]}/.cookie" \
        "${DDS[$i]}/.rpcport" "${DDS[$i]}/zclassic23.pid" \
        "${DDS[$i]}/node.log" "${DDS[$i]}/peers.dat" \
        "${DDS[$i]}/peers.dat.sha3" "${DDS[$i]}/anchors.dat" \
        "${DDS[$i]}/anchors.dat.sha3" "${DDS[$i]}/banlist.dat"
    delegated="$(dht_native "$DHT_DD_B" "$B_RPC" zcode network delegate \
        --input="{\"seed_file\":\"$DHT_WORK/master-$i.hex\",\"datadir\":\"${DDS[$i]}\"}")"
    [ "$(printf '%s' "$delegated" | dht_jget ok)" = True ] ||
        dht_die "delegation $i failed: $delegated"
    NODES[$i]="$(printf '%s' "$delegated" | dht_jget data.node_id)"
    [ -s "${DDS[$i]}/v2_identity.key" ] &&
    [ -s "${DDS[$i]}/zcode/dht/online_ed25519.key" ] &&
    [ -s "${DDS[$i]}/zcode/dht/delegation.v1" ] ||
        dht_die "independent identity files missing for node $i"
done
"$DHT_ACCEPTANCE_C23" ids-distinct "${NODES[@]}" ||
    dht_die "seven identities were not independent"

dht_note "restarting to prove capability learning, Noise, and DHT bootstrap"
dht_kill_group "$DHT_PGID_B"; DHT_PGID_B=""
dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
    "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" || dht_die "A restart failed"
dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
    "$B_HTTPS" "127.0.0.1:$A_PORT"
dht_wait_rpc "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" || dht_die "B restart failed"
dht_wait_auth "$DHT_DD_A" "$A_RPC" || dht_die "A never authenticated B over DHT"
dht_wait_auth "$DHT_DD_B" "$B_RPC" || dht_die "B never authenticated A over DHT"
grep -qaF 'controlled Noise reconnect requested' "$DHT_DD_B/node.log" ||
    dht_die "plaintext capability-learning reconnect was not observed"

TARGET_A=0101010101010101010101010101010101010101010101010101010101010101
TARGET_B=fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe
FIND_A="$(dht_native "$DHT_DD_A" "$A_RPC" zcode network find --input="{\"node_id\":\"$TARGET_A\"}")"
FIND_B="$(dht_native "$DHT_DD_B" "$B_RPC" zcode network find --input="{\"node_id\":\"$TARGET_B\"}")"
dht_check_find "$FIND_A" "$TARGET_A" "$NODE_A" "$NODE_B"
dht_check_find "$FIND_B" "$TARGET_B" "$NODE_A" "$NODE_B"

dht_note "rejecting hostile frames inside an authenticated Noise session"
ATTACK_BEFORE="$(dht_status "$DHT_DD_A" "$A_RPC")"
# Use the already-anchored but currently offline third identity. Reusing B's
# live node ID would intentionally trigger the S6 duplicate-session eviction
# path and mix B's late frames into this hostile-payload counter proof.
"$DHT_WORK/dht-peer" attack 127.0.0.1 "$A_PORT" "${DDS[2]}" |
    grep -qx 'attack-sequence-sent' || dht_die "hostile Noise peer failed"
ATTACK_AFTER="$(dht_status "$DHT_DD_A" "$A_RPC")"
dht_check_attack_deltas "$ATTACK_BEFORE" "$ATTACK_AFTER"

dht_note "clean shutdown, canonical-file check, and cold reload"
dht_kill_group "$DHT_PGID_B"; DHT_PGID_B=""
dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
dht_check_contacts_file "$DHT_DD_A/zcode/dht/contacts.v2" "$NODE_A" 2
dht_check_contacts_file "$DHT_DD_B/zcode/dht/contacts.v2" "$NODE_B"

# Start each node without its peer: the loaded contact must be visible as
# cold before any network refresh can authenticate it.
dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
    "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" || dht_die "A cold-load boot failed"
dht_wait_cold_load "$DHT_DD_A" "$A_RPC" ||
    dht_die "A persisted contact did not publish cold"
dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
    "$B_HTTPS" "127.0.0.1:$A_PORT"
dht_wait_rpc "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" || dht_die "B reload boot failed"
dht_wait_auth "$DHT_DD_A" "$A_RPC" || dht_die "A reload did not refresh B"
dht_wait_auth "$DHT_DD_B" "$B_RPC" || dht_die "B reload did not refresh A"

dht_note "short disconnect retains incumbent, then reconnect resets it"
dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
sleep 2
PEERS="$(dht_native "$DHT_DD_B" "$B_RPC" zcode network peers --input='{"limit":64}')"
[ "$(printf '%s' "$PEERS" | dht_jget data.count)" -eq 1 ] || dht_die "B evicted A during a short disconnect"
dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
    "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" || dht_die "A recovery boot failed"
dht_wait_auth "$DHT_DD_B" "$B_RPC" || dht_die "B did not reauthenticate A"
FINAL_FIND="$(dht_native "$DHT_DD_B" "$B_RPC" zcode network find --input="{\"node_id\":\"$TARGET_A\"}")"
dht_check_find "$FINAL_FIND" "$TARGET_A" "$NODE_A" "$NODE_B"

dht_note "expanding to seven independent daemons for iterative sparse lookup"
PIDS[0]="$DHT_PGID_A"
PIDS[1]="$DHT_PGID_B"

# The five closed-chain fixtures and their distinct identities were prepared
# above while B still exposed the original boot's provable tip.
dht_note "closing the two-node phase before seven-node isolated boot"
dht_kill_group "$DHT_PGID_B"; DHT_PGID_B=""
dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
# The two-node persistence proof above is complete.  Reset only its learned
# contact files so the multi-node phase starts from topology edges, not from a
# historical A<->B shortcut.  Signed delegations and online keys stay intact.
rm -f "$DHT_DD_A/zcode/dht/contacts.v2" \
    "$DHT_DD_B/zcode/dht/contacts.v2"

dht_note "booting seven isolated identities on the common chain fixture"
for i in 0 1 2 3 4 5 6; do
    dht_spawn "PIDS[$i]" "${DDS[$i]}" "${PORTS[$i]}" "${RPCS[$i]}" \
        "${FSPORTS[$i]}" "${HTTPSPORTS[$i]}" \
        "127.0.0.1:$DEAD_SINK"
    dht_wait_rpc "${DDS[$i]}" "${RPCS[$i]}" "${PIDS[$i]}" ||
        dht_die "isolated node $i warmup failed"
    dht_wait_height "${DDS[$i]}" "${RPCS[$i]}" 129 ||
        dht_die "isolated node $i lost the common verified chain"
done
DHT_PGID_A="${PIDS[0]}"; DHT_PGID_B="${PIDS[1]}"

dht_note "publishing seven chain-bound ZENDP records without DHT contacts"
for i in 0 1 2 3 4 5 6; do
    seed_file="$DHT_WORK/master-$i.hex"
    if [ "$i" -eq 0 ]; then
        seed_file="$DHT_WORK/master-a.hex"
    elif [ "$i" -eq 1 ]; then
        seed_file="$DHT_WORK/master-b.hex"
    fi
    published="$(dht_native "${DDS[$i]}" "${RPCS[$i]}" zcode endpoint publish \
        --input="{\"ipv4\":\"127.0.0.1\",\"ipv4_port\":\"${PORTS[$i]}\",\"seed_file\":\"$seed_file\",\"seq\":\"1\",\"height\":129}")"
    [ "$(printf '%s' "$published" | dht_jget ok)" = True ] ||
        dht_die "endpoint publish $i failed: $published"
    DOCS[$i]="$(printf '%s' "$published" | dht_jget data.doc_hex)"
done

# Choose a deterministic XOR-progress path ending at node 6. Only neighbours
# (plus B-D) are connected initially; learned ZENDP hints create later edges.
read -r -a ORDER <<<"$("$DHT_ACCEPTANCE_C23" xor-order "${NODES[@]}")"
# Only the lookup origin needs reachability hints: responders return
# address-free IDs and never initiate a learned dial. Filing each signed doc
# once at that origin is the genuine minimum and avoids manufacturing an
# irrelevant all-to-all directory projection on the other six nodes.
ORIGIN="${ORDER[0]}"
dht_note "filing signed endpoints at the future lookup origin only"
for publisher in 0 1 2 3 4 5 6; do
    [ "$ORIGIN" -eq "$publisher" ] && continue
    accepted="$(dht_native "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" \
        zcode endpoint accept --input="{\"doc\":\"${DOCS[$publisher]}\"}")"
    [ "$(printf '%s' "$accepted" | dht_jget ok)" = True ] ||
        dht_die "origin refused endpoint $publisher: $accepted"
done
for i in 0 1 2 3 4 5 6; do dht_kill_group "${PIDS[$i]}"; PIDS[$i]=""; done
DHT_PGID_A=""; DHT_PGID_B=""

for pos in 0 1 2 3 4 5 6; do
    idx="${ORDER[$pos]}"
    connects=()
    if [ "$pos" -eq 0 ]; then
        connects=("127.0.0.1:$DEAD_SINK")
    else
        prev="${ORDER[$((pos - 1))]}"
        connects=("127.0.0.1:${PORTS[$prev]}")
        if [ "$pos" -eq 3 ]; then
            alt="${ORDER[1]}"
            connects+=("127.0.0.1:${PORTS[$alt]}")
        fi
    fi
    dht_spawn "PIDS[$idx]" "${DDS[$idx]}" "${PORTS[$idx]}" "${RPCS[$idx]}" \
        "${FSPORTS[$idx]}" "${HTTPSPORTS[$idx]}" "${connects[@]}"
    dht_wait_rpc "${DDS[$idx]}" "${RPCS[$idx]}" "${PIDS[$idx]}" ||
        dht_die "sparse restart failed for node $idx"
done
# Do not infer topology readiness from one authenticated edge: that races the
# alternate route's Noise upgrade and turns a real recovery proof into a
# single dead-candidate wait. Wait for the exact sparse graph degree first.
EXPECTED_AUTH=(1 3 2 3 2 2 1)
for pos in 0 1 2 3 4 5 6; do
    idx="${ORDER[$pos]}"
    dht_wait_auth "${DDS[$idx]}" "${RPCS[$idx]}" \
        "${EXPECTED_AUTH[$pos]}" ||
        dht_die "sparse node $idx did not authenticate all declared edges"
done

NEXT="${ORDER[1]}"; BROKEN="${ORDER[2]}"; TARGET=6
origin_status="$(dht_status "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}")"
[ "$(printf '%s' "$origin_status" | dht_jget data.connected_authenticated)" -eq 1 ] ||
    dht_die "origin was not sparse before lookup: $origin_status"

dht_note "breaking the nearest path; FIND_NODE must recover through B-D"
dht_kill_group "${PIDS[$BROKEN]}"; PIDS[$BROKEN]=""
before_find="$(dht_status "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}")"
iterative="$(dht_native "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" zcode network find \
    --input="{\"node_id\":\"${NODES[$TARGET]}\"}" || true)"
after_find="$(dht_status "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}")"
printf '%s\n' "$iterative" >"$DHT_WORK/iterative.json"
if ! "$DHT_ACCEPTANCE_C23" sparse-proof "$iterative" "$before_find" \
    "$after_find" "${NODES[$TARGET]}"
then
    dht_die "iterative sparse proof failed: $iterative"
fi

dht_note "admitting eight external callers while exactly three queries stall"
concurrent_dir="$DHT_WORK/concurrent"; mkdir -p "$concurrent_dir"
# Freeze every remote daemon after authentication. TCP/Noise sessions remain
# live, but no NODES reply can race the status sample below. This proves eight
# separate CLI processes occupy all eight service lookup slots at once while
# the global network-query cap remains exactly three.
for i in 0 1 2 3 4 5 6; do
    [ "$i" -eq "$ORIGIN" ] && continue
    [ -n "${PIDS[$i]:-}" ] && kill -STOP "-${PIDS[$i]}"
done
jobs=()
for i in 1 2 3 4 5 6 7 8; do
    target="$(printf '%064x' "$i")"
    (dht_native "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" \
        zcode network find begin --input="{\"node_id\":\"$target\"}" \
        >"$concurrent_dir/$i.begin.json") &
    jobs+=("$!")
done
for job in "${jobs[@]}"; do wait "$job" || dht_die "lookup admission process failed"; done
burst="$(dht_status "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}")"
"$DHT_ACCEPTANCE_C23" burst-proof "$concurrent_dir" "$burst" ||
    dht_die "true eight-caller admission proof failed"
for i in 1 2 3 4 5 6 7 8; do
    read -r lookup owner <<<"$("$DHT_ACCEPTANCE_C23" begin-fields \
        "$concurrent_dir/$i.begin.json")"
    polled="$(dht_native "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" \
        zcode network find poll \
        --input="{\"lookup_id\":\"$lookup\",\"owner_token\":\"$owner\"}")"
    [ "$(printf '%s' "$polled" | dht_jget data.state)" = pending ] ||
        dht_die "stalled lookup $i was not pending: $polled"
    canceled="$(dht_native "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" \
        zcode network find cancel \
        --input="{\"lookup_id\":\"$lookup\",\"owner_token\":\"$owner\"}")"
    [ "$(printf '%s' "$canceled" | dht_jget ok)" = True ] ||
        dht_die "lookup cancel $i failed: $canceled"
done
for i in 0 1 2 3 4 5 6; do
    [ "$i" -eq "$ORIGIN" ] && continue
    [ -n "${PIDS[$i]:-}" ] && kill -CONT "-${PIDS[$i]}"
done

dht_note "cold-loading with no peer database, then reconnecting autonomously"
for i in 0 1 2 3 4 5 6; do
    dht_kill_group "${PIDS[$i]:-}"
    PIDS[$i]=""
done
"$DHT_ACCEPTANCE_C23" contact-reduce \
    "${DDS[$ORIGIN]}/zcode/dht/contacts.v2" "${NODES[$NEXT]}" ||
    dht_die "multi contact file is not canonical"

# peers.dat is deliberately absent. The only origin-side network facts are
# one address-free authenticated-history ID plus the independently accepted,
# chain-bound ZENDP files already created above.
rm -f "${DDS[$ORIGIN]}/peers.dat" "${DDS[$ORIGIN]}/peers.dat.sha3"
[ "$(find "${DDS[$ORIGIN]}/zcode/endpoints" -maxdepth 1 -type f -name '*.zid' | wc -l)" -ge 6 ] ||
    dht_die "origin lost its accepted ZENDP records"

# Rebuild a six-node chain that has no edge to the origin. Start from the far
# end so every explicit -connect target is already listening. None of these
# nodes accepted the origin's directory, so no DHT hint can create a shortcut.
for pos in 6 5 4 3 2 1; do
    idx="${ORDER[$pos]}"
    connects=("127.0.0.1:$DEAD_SINK")
    if [ "$pos" -lt 6 ]; then
        farther="${ORDER[$((pos + 1))]}"
        connects=("127.0.0.1:${PORTS[$farther]}")
    fi
    dht_spawn "PIDS[$idx]" "${DDS[$idx]}" "${PORTS[$idx]}" \
        "${RPCS[$idx]}" "${FSPORTS[$idx]}" "${HTTPSPORTS[$idx]}" \
        "${connects[@]}"
    dht_wait_rpc "${DDS[$idx]}" "${RPCS[$idx]}" "${PIDS[$idx]}" ||
        dht_die "cold-bootstrap remote node $idx failed"
done
for pos in 1 2 3 4 5 6; do
    idx="${ORDER[$pos]}"
    dht_wait_auth "${DDS[$idx]}" "${RPCS[$idx]}" 1 ||
        dht_die "remote sparse chain node $idx did not authenticate"
done

dht_spawn "PIDS[$ORIGIN]" "${DDS[$ORIGIN]}" "${PORTS[$ORIGIN]}" \
    "${RPCS[$ORIGIN]}" "${FSPORTS[$ORIGIN]}" "${HTTPSPORTS[$ORIGIN]}" \
    "127.0.0.1:$DEAD_SINK"
dht_wait_rpc "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" "${PIDS[$ORIGIN]}" ||
    dht_die "origin zero-peer cold restart failed"
dht_wait_cold_load "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" 1 ||
    dht_die "origin did not load its address-free cold contact"
cold="$(dht_status "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}")"
connections="$(dht_rpc "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" getconnectioncount | dht_result)"
[ "$connections" -eq 0 ] &&
[ "$(printf '%s' "$cold" | dht_jget data.connected_authenticated)" -eq 0 ] &&
[ "$(printf '%s' "$cold" | dht_jget data.cold_contacts)" -eq 1 ] ||
    dht_die "origin did not start with exactly zero peers: $cold connections=$connections"

before_cold_find="$cold"
cold_find="$(dht_native "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}" \
    zcode network find --input="{\"node_id\":\"${NODES[$TARGET]}\"}" || true)"
after_cold_find="$(dht_status "${DDS[$ORIGIN]}" "${RPCS[$ORIGIN]}")"
"$DHT_ACCEPTANCE_C23" cold-proof "$cold_find" "$before_cold_find" \
    "$after_cold_find" "${NODES[$TARGET]}" ||
    dht_die "autonomous cold-bootstrap lookup failed"

# Optional composition point for larger real-process acceptances. Run it only
# after this owner's sparse/recovery assertions are complete: a composed proof
# may legitimately publish records, dial discovered providers, and restart
# roles, none of which may retroactively perturb the DHT fixture's topology
# assertions. All seven independent identities are live and authenticated here,
# so the hook still reuses the production DHT/Noise ceremony above. Restrict it
# to this repository's tools/dev directory: an ambient path must never become
# executable acceptance input.
if [ -n "$DHT_AFTER_SPARSE_HOOK" ]; then
    hook_real="$(readlink -f "$DHT_AFTER_SPARSE_HOOK" 2>/dev/null || true)"
    case "$hook_real" in
        "$REPO_ROOT"/tools/dev/*.sh) ;;
        *) dht_die "after-sparse hook must be a tools/dev shell script" ;;
    esac
    [ -f "$hook_real" ] || dht_die "after-sparse hook is not a regular file"
    dht_note "running composed after-sparse acceptance hook $(basename "$hook_real")"
    # shellcheck source=/dev/null
    . "$hook_real"
fi

if ! dht_cleanup; then
    dht_die "owned process groups did not terminate during success cleanup"
fi
dht_assert_no_owned_processes
dht_assert_ports_rebindable
dht_note "PASS: seven-node sparse lookup, true async admission, persistence, autonomous cold bootstrap; owned_processes_remaining=0 ports_rebindable=true"
