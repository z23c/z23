#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Exercise actual peer-tip pollers without opening a socket or node datadir.
set -euo pipefail
SELF_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
source "$SELF_DIR/two_node_peer_tip.sh"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/z23-peer-tip-contract.XXXXXX")"
trap 'if [ -n "${TN_PID_B:-}" ]; then tn_kill_group "$TN_PGID_B"; wait "$TN_PID_B" 2>/dev/null || true; fi; rm -rf -- "$fixture"' EXIT
fail() { printf 'peer-tip selftest: FAIL: %s\n' "$*" >&2; exit 1; }
RPC_BIN="$fixture/rpc"
cat > "$RPC_BIN" <<'RPC'
#!/bin/sh
printf '%s\n' "$fixture_reply"
exit "$fixture_rpc_rc"
RPC
chmod 700 "$RPC_BIN"
export fixture_reply='' fixture_rpc_rc=0
for fixture_reply in \
    '{"result":15,"error":{"code":-28}}' \
    '{"result":"15","error":null}' \
    '{"result":15,"error":"null"}' \
    '{"result":15}' '{"result":-1,"error":null}' \
    '{"result":1.5,"error":null}' '{"result":true,"error":null}' \
    '{"result":15,"error":null} trailing' ''; do
    if tn_blockcount "$fixture" 39071 >/dev/null; then fail 'invalid height accepted'; fi
done
fixture_reply='{"result":0,"error":null}'
[ "$(tn_blockcount "$fixture" 39071)" = 0 ] || fail 'height zero refused'
fixture_rpc_rc=1
if tn_blockcount "$fixture" 39071 >/dev/null; then fail 'failed transport accepted'; fi
fixture_rpc_rc=0
tip_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
fixture_reply="{\"result\":\"$tip_hash\",\"error\":null}"
[ "$(tn_blockhash "$fixture" 39071 15)" = "$tip_hash" ] || fail 'exact hash refused'
fixture_reply='{"result":"abc","error":null}'
if tn_blockhash "$fixture" 39071 15 >/dev/null; then fail 'short hash accepted'; fi

# Durable NEXT C must agree with its exact LE counter and last applied row.
interior=$'3\t0300000000000000\t2\t1\t01\t2'
tn_sync_interior "$interior" 10 || fail 'consistent interior frontier refused'
for bad in \
    $'NULL\tNULL\tNULL\tNULL\tNULL\t0' \
    $'3\t03\t2\t1\t01\t2' \
    $'3\t0400000000000000\t2\t1\t01\t2' \
    $'3\t0300000000000000\t1\t1\t01\t2' \
    $'3\t0300000000000000\t2\t0\t01\t2' \
    $'3\t0300000000000000\t2\t1\t00\t2' \
    $'3\t0300000000000000\t2\t1\t01\t0' \
    $'03\t0300000000000000\t2\t1\t01\t2' \
    $'11\t0B00000000000000\t10\t1\t01\t10'; do
    if tn_sync_interior "$bad" 10; then fail 'invalid/completed frozen frontier accepted'; fi
done
printf '42 T\n42 Tl\n' | tn_group_stopped 42 || fail 'stopped group refused'
if printf '42 T\n42 S\n' | tn_group_stopped 42; then fail 'unstopped group member accepted'; fi
if printf '43 T\n' | tn_group_stopped 42; then fail 'absent owned group accepted'; fi
tn_sync_startup $'NULL\tNULL\tNULL\tNULL\tNULL\t0' || fail 'empty startup refused'
if tn_sync_startup $'1\t0200000000000000\t0\t1\t01\t2'; then fail 'inconsistent startup accepted'; fi
fixture_reply="{\"result\":{\"height\":15,\"utxo_count\":9,\"sha3_hash\":\"$tip_hash\"},\"error\":null}"
tn_commitment "$fixture" 39071 15 >/dev/null || fail 'typed coin commitment refused'
fixture_reply="{\"result\":{\"height\":\"15\",\"utxo_count\":9,\"sha3_hash\":\"$tip_hash\"},\"error\":null}"
if tn_commitment "$fixture" 39071 15 >/dev/null; then fail 'string commitment height accepted'; fi
fixture_reply="{\"result\":{\"height\":15,\"utxo_count\":\"9\",\"sha3_hash\":\"$tip_hash\"},\"error\":null}"
if tn_commitment "$fixture" 39071 15 >/dev/null; then fail 'string coin count accepted'; fi

TN_TMP="$fixture/"
mkdir "$fixture/zcl23-2node-cleanup"
tn_rm_datadir "$fixture/zcl23-2node-cleanup"
[ ! -e "$fixture/zcl23-2node-cleanup" ] || fail 'trailing-slash scratch cleanup refused'
mkdir "$fixture/zcl23-2node-scratch" "$fixture/zcl23-2node-outside"
TN_TMP="$fixture/zcl23-2node-scratch"
tn_rm_datadir "$TN_TMP"
[ -d "$TN_TMP" ] || fail 'scratch root itself removed'
tn_rm_datadir "$fixture/zcl23-2node-outside"
[ -d "$fixture/zcl23-2node-outside" ] || fail 'outside scratch root removed'

# A real owned group proves immediate SIGKILL, without a preceding TERM.
if [ "$(uname -s)" = Linux ]; then
    export fixture_ready="$fixture/ready" fixture_term="$fixture/term"
    cat > "$fixture/child" <<'CHILD'
#!/bin/sh
trap 'printf TERM > "$fixture_term"; exit 0' TERM
printf ready > "$fixture_ready"
while :; do sleep 1; done
CHILD
    chmod 700 "$fixture/child"
    NODE_BIN="$fixture/child"
    REQUIRE_SIGKILL=1
    tn_spawn "$fixture" 0 0 0 0 unused
    TN_PID_B="$TN_SPAWN_PID"; TN_PGID_B="$TN_PID_B"
    for i in $(seq 1 100); do
        [ -f "$fixture_ready" ] && break
        sleep 0.01
    done
    [ -f "$fixture_ready" ] || fail 'owned child never armed TERM trap'
    tn_stop_follower > "$fixture/stop.log"
    grep -q 'status=137 require_sigkill=1' "$fixture/stop.log" || fail 'SIGKILL wait witness absent'
    [ ! -f "$fixture_term" ] || fail 'SIGKILL path delivered TERM first'
    [ -z "$TN_PID_B$TN_PGID_B" ] || fail 'reaped follower ownership not cleared'
    # Suppress the signal to prove a natural exit cannot masquerade as KILL.
    if (
        kill() { return 0; }
        NODE_BIN=/bin/true
        tn_spawn "$fixture" 0 0 0 0 unused
        TN_PID_B="$TN_SPAWN_PID"; TN_PGID_B="$TN_PID_B"
        tn_stop_follower
    ) > "$fixture/natural.log" 2>&1; then fail 'natural exit accepted as SIGKILL'; fi
    grep -q 'status=0 require_sigkill=1' "$fixture/natural.log" || fail 'natural-exit control did not run'
    if (
        kill() { return 0; }
        TN_PID_B=$$; TN_PGID_B=$$
        tn_stop_follower
    ) > "$fixture/not-child.log" 2>&1; then fail 'invalid wait accepted as SIGKILL'; fi
    grep -q 'status=127 require_sigkill=1' "$fixture/not-child.log" || fail 'invalid-wait control did not run'
else
    printf 'peer-tip selftest: Linux SIGKILL witness not applicable\n'
fi

# A deterministic clock exposes budget resets and late RPC answers.
printf '100\n' > "$fixture/clock"
touch "$fixture/.cookie"
date() { cat "$fixture/clock"; }
sleep() { local tick; tick=$(date); printf '%s\n' "$((tick + 1))" > "$fixture/clock"; }
tn_blockcount() { printf '15\n'; }
tn_blockhash() { printf '%s\n' "$tip_hash"; }
tn_wait_rpc "$fixture" 39071 '' 102 || fail 'ready RPC refused'
tn_wait_height "$fixture" 39071 '' 15 102 "$tip_hash" >/dev/null || fail 'exact tip refused'
if tn_wait_height "$fixture" 39071 '' 15 102 wrong >/dev/null; then
    fail 'same height with different hash accepted'
fi
[ "$(date)" = 102 ] || fail 'poll exceeded shared deadline'
if tn_wait_rpc "$fixture" 39071 '' 102; then fail 'expired warmup accepted'; fi
if tn_wait_height "$fixture" 39071 '' 15 102 "$tip_hash" >/dev/null; then
    fail 'expired catch-up got a fresh budget'
fi
printf '100\n' > "$fixture/clock"
tn_blockcount() { printf '102\n' > "$fixture/clock"; printf '15\n'; }
if tn_wait_rpc "$fixture" 39071 '' 102; then fail 'late RPC readiness accepted'; fi
printf '100\n' > "$fixture/clock"
if tn_wait_height "$fixture" 39071 '' 15 102 "$tip_hash" >/dev/null; then
    fail 'late tip accepted'
fi
# Exercise the actual freeze orchestration with a deterministic process/SQL seam.
# STOP success alone cannot witness a completed frontier or an unstopped member.
freeze_case() (
    local mode="$1"
    REPO_ROOT="$fixture"; mkdir -p "$fixture/build"
    TN_DD_B="$fixture/follower"; TN_PID_B=42; TN_PGID_B=42
    A_TIP=10; A_HASH="$tip_hash"; SYNC_END=102; RESYNC_DEADLINE=120
    printf '100\n' > "$fixture/clock"
    printf '0\n' > "$fixture/reads"
    printf 'boot -> db_open\n' > "$(tn_node_log "$TN_DD_B")"
    kill() { return 0; }
    ps() { if [ "$mode" = unstopped ]; then printf '42 S\n'; else printf '42 T\n'; fi; }
    tn_sync_tuple() {
        local n; n=$(cat "$fixture/reads"); printf '%s\n' "$((n + 1))" > "$fixture/reads"
        if [ "$mode" = late ]; then printf '102\n' > "$fixture/clock"; fi
        if [ "$mode" = completed ] && [ "$n" -gt 0 ]; then
            printf '11\t0B00000000000000\t10\t1\t01\t10\n'
        else printf '%s\n' "$interior"; fi
    }
    tn_freeze_sync
    [ "$TN_FROZEN_SYNC" = "$interior" ] || fail 'freeze did not retain exact tuple'
)
freeze_case valid > "$fixture/freeze-valid.log" 2>&1 || fail 'valid frozen interior refused'
for mode in completed unstopped late; do
    if freeze_case "$mode" > "$fixture/freeze-$mode.log" 2>&1; then fail "invalid $mode freeze accepted"; fi
done
printf '100\n' > "$fixture/clock"
TN_DD_A=a; TN_DD_B=b
tn_commitment() { printf '15\t9\t%s\n' "$tip_hash"; }
tn_commitments_match 102 15 >/dev/null || fail 'matching coin commitments refused'
tn_commitment() { printf '15\t%s\t%s\n' "$([ "$1" = a ] && echo 9 || echo 8)" "$tip_hash"; }
if tn_commitments_match 102 15 >/dev/null; then fail 'coin count mismatch accepted'; fi
tn_commitment() { printf '15\t9\t%s\n' "$1"; }
if tn_commitments_match 102 15 >/dev/null; then fail 'coin hash mismatch accepted'; fi
printf '102\n' > "$fixture/clock"
if tn_commitments_match 102 15 >/dev/null; then fail 'expired commitment deadline accepted'; fi
printf 'peer-tip selftest: PASS (typed RPC, exact hash, shared deadline, late replies, cleanup containment, applicable SIGKILL witness)\n'
