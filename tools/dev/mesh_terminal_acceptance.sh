#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Mesh terminal acceptance: two isolated regtest nodes anchor independent
# ZID masters, provision chain-bound delegations, authenticate mutually
# over the DHT, pair bilaterally with the commit-time terminal-exec
# capability, then drive a confined fbsh (the project's static shell) on
# the responder through the ZMTERM lane — open, poll, write, read,
# resize, close — and prove that a
# mid-session revoke on the responder ends the live terminal with its
# named evidence, and that a wrong fingerprint never writes a pairing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# node_lifecycle.sh owns work-dir creation, port claims, process group
# ownership, cleanup and the EXIT trap; this harness adds no lifecycle
# rules of its own.
. "$SCRIPT_DIR/node_lifecycle.sh"

A_PORT=20032; A_RPC=29311; A_FS=29312; A_HTTPS=29313
B_PORT=18043; B_RPC=29321; B_FS=29322; B_HTTPS=29323
a_rpc() { dht_rpc "$TERM_DD_A" "$A_RPC" "$@"; }
b_rpc() { dht_rpc "$TERM_DD_B" "$B_RPC" "$@"; }
# Envelope-stripped call: prints the result value, nonzero on error.
a_res() { a_rpc "$@" | dht_result; }
b_res() { b_rpc "$@" | dht_result; }
jget() { dht_jget "$@"; }

term_note() { printf 'mesh-terminal-acceptance: %s\n' "$*" >&2; }
term_j() { dht_jget "$@"; }

# dht_spawn's local branch, plus the extra node flags the terminal lane
# needs: TERM_EXTRA_ARGS carries -terminalshell=<fbsh> for the responder.
#
# The granted shell is fbsh, not /bin/sh: the cage's grant IS the
# filesystem — the per-terminal workdir plus the one granted binary — and
# a dynamically linked shell execve-fails closed inside it (the kernel's
# ELF-interpreter open and every shared-library open land outside the
# grant). fbsh is the project's statically linked confined shell, the
# same binary the worker group's live cases drive.
FBSH_BIN="$REPO_ROOT/build/bin/fbsh"
term_spawn() {
    local out_name="$1" dd="$2" p2p="$3" rpc="$4" fs="$5" https="$6"
    shift 6
    local args=() connect pid
    for connect in "$@"; do args+=("-connect=$connect"); done
    [ "${#args[@]}" -gt 0 ] || args+=("-connect=127.0.0.1:$DEAD_SINK")
    setsid "$NODE_BIN" -datadir="$dd" -regtest -port="$p2p" \
        -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        "${args[@]}" -packagehost="$DHT_PACKAGEHOST" -noisetransport \
        -paramsdir="$TERM_PARAMS_DIR" \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        ${TERM_EXTRA_ARGS+"${TERM_EXTRA_ARGS[@]}"} \
        >>"$dd/node.log" 2>&1 &
    pid="$!"
    dht_register_owned_group "$pid"
    printf -v "$out_name" '%s' "$pid"
}

# Poll until the terminal's poll view satisfies the given state; the view
# JSON is printed on success for further assertions.
term_wait_state() {
    local tid="$1" want="$2" deadline out state
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        out="$(a_res mesh_terminal_poll "{\"terminal_id\":\"$tid\"}")" || {
            sleep 0.5; continue;
        }
        state="$(printf '%s' "$out" | term_j state "")"
        [ "$state" = "$want" ] && { printf '%s' "$out"; return 0; }
        sleep 0.5
    done
    term_note "terminal $tid never reached state=$want (last: $out)"
    return 1
}

# Read pending screen output until the marker appears, draining in bounded
# chunks so nothing is left behind.
term_wait_output() {
    local tid="$1" marker="$2" deadline out hex text pending
    deadline=$(( $(date +%s) + DHT_WAIT ))
    text=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        out="$(a_res mesh_terminal_read "{\"terminal_id\":\"$tid\",\"max_bytes\":4096}")" ||
            { sleep 0.5; continue; }
        hex="$(printf '%s' "$out" | term_j output_hex "")"
        [ -n "$hex" ] && text+="$(printf '%s' "$hex" | xxd -r -p 2>/dev/null || true)"
        case "$text" in *"$marker"*) return 0 ;; esac
        sleep 0.5
    done
    term_note "marker never appeared in terminal output (got: ${text:0:400})"
    return 1
}

for port in $A_PORT $A_RPC $A_FS $A_HTTPS $B_PORT $B_RPC $B_FS $B_HTTPS; do
    dht_assert_port "$port"
done
[ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] && [ -x "$DHT_ACCEPTANCE_C23" ] ||
    dht_die "build node, RPC, and native C23 acceptance binaries first"
[ -x "$FBSH_BIN" ] || dht_die "$FBSH_BIN not built — run make fbsh (the cage's static shell)"
command -v xxd >/dev/null || dht_die "xxd is required to decode screen hex"
dht_make_work zcl23-termacc
TERM_PARAMS_DIR="$DHT_WORK/no-zk-params"
mkdir -p "$TERM_PARAMS_DIR"
TERM_DD_A="$DHT_WORK/a"; TERM_DD_B="$DHT_WORK/b"
DHT_MINE_DD="$TERM_DD_A"; DHT_MINE_RPC="$A_RPC"
mkdir -p "$TERM_DD_A" "$TERM_DD_B"
# The master-pubkey derivation helper is built with the DHT acceptance's
# own compile recipe — source just that function so the recipe has exactly
# one definition in the tree and cannot drift from the acceptance that
# exercises it.
eval "$(sed -n '/^dht_build_helper()/,/^}/p' "$SCRIPT_DIR/zcode_dht_acceptance.sh")"
dht_build_helper

SEED_A=8888888888888888888888888888888888888888888888888888888888888888
SEED_B=9999999999999999999999999999999999999999999999999999999999999999
install -m 600 /dev/null "$DHT_WORK/master-a.hex"
install -m 600 /dev/null "$DHT_WORK/master-b.hex"
printf '%s\n' "$SEED_A" >"$DHT_WORK/master-a.hex"
printf '%s\n' "$SEED_B" >"$DHT_WORK/master-b.hex"
PUB_A="$("$DHT_WORK/dht-peer" pubkey "$SEED_A")"
PUB_B="$("$DHT_WORK/dht-peer" pubkey "$SEED_B")"

# Wallet custody: the ZID anchor's overlay-intent custody gate refuses a
# plaintext-at-rest wallet, so both nodes boot with the passphrase
# credential and key writes encrypt at rest (WKS1).
TERM_CRED_DIR="$DHT_WORK/cred"
install -d -m 700 "$TERM_CRED_DIR"
install -m 600 /dev/null "$TERM_CRED_DIR/wallet-passphrase"
printf '%s\n' "$DHT_WALLET_PASS" >"$TERM_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$TERM_CRED_DIR"

term_note "booting two clean regtest nodes (B is the terminal responder)"
TERM_EXTRA_ARGS=()
term_spawn TERM_PGID_A "$TERM_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS"
TERM_EXTRA_ARGS+=("-terminalshell=$FBSH_BIN")
# B's initial link is A: the funding chain is mined on A and must reach B
# before any custody work (later bounces use the dead sink; A owns the
# link via operator-directed onetry there).
term_spawn TERM_PGID_B "$TERM_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" \
    "127.0.0.1:$A_PORT"
dht_wait_rpc "$TERM_DD_A" "$A_RPC" "$TERM_PGID_A" || dht_die "node A RPC warmup failed"
dht_wait_rpc "$TERM_DD_B" "$B_RPC" "$TERM_PGID_B" || dht_die "node B RPC warmup failed"

term_note "mining spendable regtest funds"
ADDR="$(a_rpc getnewaddress | dht_result)"
dht_mine_to_address 101 "$ADDR"
dht_wait_height "$TERM_DD_B" "$B_RPC" 101 || dht_die "B did not sync funding chain"
dht_wait_fold "$TERM_DD_A" "$A_RPC" 101 || dht_die "A reducer fold did not reach the funding tip"

# Custody phase, mirroring the DHT acceptance recipe: B bounces onto the
# dead sink so the pair's only post-restart link is A's operator-directed
# onetry, and A restarts so the forward-folded coins set stamps its
# authority; then unlock, keypool top-up, and the current-key encrypted
# backup the custody gate demands.
term_note "bouncing B onto the dead sink (A owns the custody-phase link)"
dht_kill_group "$TERM_PGID_B"; TERM_PGID_B=""
TERM_EXTRA_ARGS=("-terminalshell=$FBSH_BIN")
term_spawn TERM_PGID_B "$TERM_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS"
dht_wait_rpc "$TERM_DD_B" "$B_RPC" "$TERM_PGID_B" || dht_die "B dead-sink bounce failed"
term_note "restarting A so the forward-folded coins set stamps its authority"
dht_kill_group "$TERM_PGID_A"; TERM_PGID_A=""
term_spawn TERM_PGID_A "$TERM_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS"
dht_wait_rpc "$TERM_DD_A" "$A_RPC" "$TERM_PGID_A" || dht_die "A custody restart failed"
dht_wait_fold "$TERM_DD_A" "$A_RPC" 101 || dht_die "A reducer fold did not survive the restart"
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
dht_wait_connected "$TERM_DD_A" "$A_RPC" || dht_die "A never connected outbound to B"
dht_wait_sync_live "$TERM_DD_A" "$A_RPC" || dht_die "A sync never left finding_peers"
dht_wait_chain_loaded "$TERM_DD_A" "$A_RPC" 101 || dht_die "A active chain index did not load"
term_note "unlocking the wallet and taking the current-key encrypted backup"
dht_unlock_wallet "$TERM_DD_A" "$A_RPC" || dht_die "A wallet unlock failed"
a_rpc getnewaddress | dht_result >/dev/null || dht_die "post-restart keypool top-up failed"
dht_backup_wallet "$TERM_DD_A" "$A_RPC" || dht_die "A custody backup failed"
dht_wait_spendable "$TERM_DD_A" "$A_RPC" || dht_die "A vault spendable never became positive"

term_note "anchoring both masters (plan/commit under identity custody)"
dht_anchor "$TERM_DD_A" "$A_RPC" "$PUB_A" "term-anchor-a" >/dev/null || dht_die "A anchor failed"
dht_mine_empty 1; sleep 1
dht_anchor "$TERM_DD_A" "$A_RPC" "$PUB_B" "term-anchor-b" >/dev/null || dht_die "B anchor failed"
dht_mine_empty 1; sleep 1
dht_mine_empty 21
dht_wait_height "$TERM_DD_B" "$B_RPC" 124 || dht_die "B did not sync final beacon chain"

term_note "provisioning independent delegations through the operator leaf"
DELEGATE_A="$(dht_native "$TERM_DD_A" "$A_RPC" zcode network delegate --input="{\"seed_file\":\"$DHT_WORK/master-a.hex\"}")"
DELEGATE_B="$(dht_native "$TERM_DD_B" "$B_RPC" zcode network delegate --input="{\"seed_file\":\"$DHT_WORK/master-b.hex\"}")"
[ "$(printf '%s' "$DELEGATE_A" | dht_jget ok)" = True ] || dht_die "A delegation failed: $DELEGATE_A"
[ "$(printf '%s' "$DELEGATE_B" | dht_jget ok)" = True ] || dht_die "B delegation failed: $DELEGATE_B"
for f in "$TERM_DD_A/v2_identity.key" "$TERM_DD_A/zcode/dht/online_ed25519.key" \
         "$TERM_DD_A/zcode/dht/delegation.v1" \
         "$TERM_DD_B/v2_identity.key" "$TERM_DD_B/zcode/dht/online_ed25519.key" \
         "$TERM_DD_B/zcode/dht/delegation.v1"; do
    [ -s "$f" ] || dht_die "provisioned identity file missing: $f"
done

term_note "restarting both nodes and waiting for mutual DHT authentication"
dht_kill_group "$TERM_PGID_B"; TERM_PGID_B=""
TERM_EXTRA_ARGS=("-terminalshell=$FBSH_BIN")
term_spawn TERM_PGID_B "$TERM_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS"
dht_wait_rpc "$TERM_DD_B" "$B_RPC" "$TERM_PGID_B" || dht_die "B restart failed"
dht_kill_group "$TERM_PGID_A"; TERM_PGID_A=""
term_spawn TERM_PGID_A "$TERM_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS"
dht_wait_rpc "$TERM_DD_A" "$A_RPC" "$TERM_PGID_A" || dht_die "A restart failed"
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
dht_wait_auth "$TERM_DD_A" "$A_RPC" || dht_die "A never authenticated B over DHT"
dht_wait_auth "$TERM_DD_B" "$B_RPC" || dht_die "B never authenticated A over DHT"

# ── Pairing ceremony ──────────────────────────────────────────────────
term_note "pairing A -> B with the terminal-exec grant"
PLAN_A="$(a_res mesh_pairing_plan '{}')"
FINGER_B="$(printf '%s' "$PLAN_A" | term_j peer_noise_fingerprint_sha3 "")"
PAIR_A="$(printf '%s' "$PLAN_A" | term_j pairing_id "")"
[ -n "$FINGER_B" ] && [ -n "$PAIR_A" ] || dht_die "A plan did not name B: $PLAN_A"

# A wrong fingerprint must refuse and write nothing. The flip stays inside
# the hex alphabet so this proves the fingerprint COMPARISON gate, not the
# earlier decode gate.
case "${FINGER_B#"${FINGER_B%?}"}" in
    0) WRONG="${FINGER_B%?}1" ;;
    *) WRONG="${FINGER_B%?}0" ;;
esac
[ "$WRONG" != "$FINGER_B" ] || dht_die "fingerprint flip produced no delta"
BAD="$(a_res mesh_pairing_commit "{\"fingerprint\":\"$WRONG\",\"terminal\":true,\"days\":1}" || true)"
[ "$(printf '%s' "$BAD" | term_j ok False)" = False ] ||
    dht_die "a wrong fingerprint was accepted: $BAD"
term_note "PASS wrong-fingerprint commit refused ($(printf '%s' "$BAD" | term_j code '?' ))"

COMMIT_A="$(a_res mesh_pairing_commit "{\"fingerprint\":\"$FINGER_B\",\"terminal\":true,\"days\":1}")"
[ "$(printf '%s' "$COMMIT_A" | term_j ok)" = True ] || dht_die "A commit failed: $COMMIT_A"
[ "$(printf '%s' "$COMMIT_A" | term_j pairing.capability '')" = status_read+terminal_exec ] ||
    dht_die "A commit did not record the terminal capability: $COMMIT_A"

term_note "pairing B -> A with the terminal-exec grant"
PLAN_B="$(b_res mesh_pairing_plan '{}')"
FINGER_A="$(printf '%s' "$PLAN_B" | term_j peer_noise_fingerprint_sha3 "")"
[ -n "$FINGER_A" ] || dht_die "B plan did not name A: $PLAN_B"
COMMIT_B="$(b_res mesh_pairing_commit "{\"fingerprint\":\"$FINGER_A\",\"terminal\":true,\"days\":1}")"
[ "$(printf '%s' "$COMMIT_B" | term_j ok)" = True ] || dht_die "B commit failed: $COMMIT_B"
PAIR_B="$(printf '%s' "$COMMIT_B" | term_j pairing.pairing_id "")"
[ -n "$PAIR_B" ] || PAIR_B="$(printf '%s' "$COMMIT_B" | term_j pairing_id "")"
[ -n "$PAIR_B" ] || dht_die "B commit did not return its pairing id: $COMMIT_B"

# ── Confined terminal drive ───────────────────────────────────────────
term_note "opening a confined terminal on B"
OPEN="$(a_res mesh_terminal_open "{\"pairing_id\":\"$PAIR_A\",\"cols\":80,\"rows\":24}")"
[ "$(printf '%s' "$OPEN" | term_j ok)" = True ] || dht_die "terminal open failed: $OPEN"
TID="$(printf '%s' "$OPEN" | term_j terminal_id "")"
[ -n "$TID" ] || dht_die "open returned no terminal id: $OPEN"

LIVE_VIEW="$(term_wait_state "$TID" live)" || dht_die "terminal never went live: $LIVE_VIEW"
[ "$(printf '%s' "$LIVE_VIEW" | term_j cols)" = 80 ] ||
    dht_die "live view lost the requested geometry: $LIVE_VIEW"
term_note "PASS terminal is live on B's confined cage"

MARKER="z23-term-$(date +%s)"
a_res mesh_terminal_write "{\"terminal_id\":\"$TID\",\"input_hex\":\"$(printf 'echo %s\n' "$MARKER" | xxd -p | tr -d '\n')\"}" >/dev/null \
    || dht_die "terminal write failed"
term_wait_output "$TID" "$MARKER" || dht_die "the confined shell never echoed the marker"
term_note "PASS the confined shell echoed through the mesh"

RESIZE="$(a_res mesh_terminal_resize "{\"terminal_id\":\"$TID\",\"cols\":100,\"rows\":30}")"
[ "$(printf '%s' "$RESIZE" | term_j ok)" = True ] || dht_die "resize failed: $RESIZE"
CLOSE="$(a_res mesh_terminal_close "{\"terminal_id\":\"$TID\"}")"
[ "$(printf '%s' "$CLOSE" | term_j ok)" = True ] ||
    dht_die "close failed: $CLOSE"
ENDED_VIEW="$(term_wait_state "$TID" ended)" || dht_die "terminal never ended: $ENDED_VIEW"
[ "$(printf '%s' "$ENDED_VIEW" | term_j close_reason '')" = requested ] ||
    dht_die "operator close did not end the session by name: $ENDED_VIEW"
term_note "PASS operator close ended the session by name"

# A second open proves the responder spawns again after a clean end.
OPEN2="$(a_res mesh_terminal_open "{\"pairing_id\":\"$PAIR_A\",\"cols\":80,\"rows\":24}")"
[ "$(printf '%s' "$OPEN2" | term_j ok)" = True ] || dht_die "second open failed: $OPEN2"
TID2="$(printf '%s' "$OPEN2" | term_j terminal_id "")"
term_wait_state "$TID2" live >/dev/null || dht_die "second terminal never went live"

# ── Mid-session revoke drill ──────────────────────────────────────────
term_note "revoking B's pairing mid-session"
RPLAN="$(b_res mesh_pairing_revoke_plan "{\"pairing_id\":\"$PAIR_B\"}")"
TOKEN="$(printf '%s' "$RPLAN" | term_j confirmation "")"
[ -n "$TOKEN" ] || dht_die "revoke plan returned no confirmation: $RPLAN"
RCOMMIT="$(b_res mesh_pairing_revoke_commit "{\"pairing_id\":\"$PAIR_B\",\"confirm\":\"$TOKEN\"}")"
[ "$(printf '%s' "$RCOMMIT" | term_j ok False)" = True ] ||
    dht_die "revoke commit failed: $RCOMMIT"

DEAD_VIEW="$(term_wait_state "$TID2" ended)" ||
    dht_die "the revoked pairing did not end the live terminal: $DEAD_VIEW"
REASON="$(printf '%s' "$DEAD_VIEW" | term_j close_reason '')"
VERDICT="$(printf '%s' "$DEAD_VIEW" | term_j verdict '')"
if [ "$REASON" = revoked ] || [ "$VERDICT" = closed ]; then
    term_note "PASS revoke ended the live terminal (reason=$REASON verdict=$VERDICT)"
else
    dht_die "the terminal ended without revoked/closed evidence: $DEAD_VIEW"
fi

# After the revoke, the pairing no longer grants terminal-exec. The open
# is asynchronous on the requester: A's own row is untouched (only B
# revoked), so the admit succeeds and the verdict has to arrive as B's
# signed refusal receipt through the poll. Anything else — a simulated
# local refusal, or no refusal at all — fails here.
REOPEN="$(a_res mesh_terminal_open "{\"pairing_id\":\"$PAIR_A\",\"cols\":80,\"rows\":24}")"
[ "$(printf '%s' "$REOPEN" | term_j ok)" = True ] ||
    dht_die "the post-revoke open never even went out: $REOPEN"
TID3="$(printf '%s' "$REOPEN" | term_j terminal_id "")"
[ -n "$TID3" ] || dht_die "post-revoke open returned no terminal id: $REOPEN"
DEAD2="$(term_wait_state "$TID3" refused)" ||
    dht_die "the revoked pairing did not refuse the next open: $DEAD2"
[ "$(printf '%s' "$DEAD2" | term_j verdict '')" = revoked ] ||
    dht_die "the post-revoke refusal is not named revoked: $DEAD2"
term_note "PASS post-revoke open refused by name (verdict=revoked)"

term_note "cleaning up owned nodes"
dht_cleanup || dht_die "cleanup failed"
dht_assert_no_owned_processes
dht_assert_ports_rebindable
term_note "ALL MESH TERMINAL ACCEPTANCE PROOFS PASSED"
