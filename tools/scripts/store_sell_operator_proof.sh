#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# store_sell_operator_proof.sh — MVP criterion #5 "rung A" OPERATOR proof:
# a full-binary, real-chain, isolated regtest run of
#
#   "Operator lists product → buyer pays shielded → buyer receives file"
#
# The hermetic C5 gates (store_e2e / store_e2e_shielded in test_zcl) prove the
# store's persistence, memo-bound reconcile, and real Sapling ivk decryption
# IN-PROCESS. This harness proves the same claim through the surfaces an
# operator actually uses: a booted zclassic23 node, the native typed CLI
# (app.store.*), and real regtest blocks mined by the node itself.
#
# Stages (each one names itself on failure):
#   1.  SPAWN        an isolated regtest witness peer and, beside it, the
#                    isolated regtest store node that -connects to it (fresh
#                    mktemp datadirs, 391xx ports, no Tor, no legacy import,
#                    -regtestshielded so Overwinter+Sapling are active —
#                    regtest otherwise pins them NO_ACTIVATION and no shielded
#                    tx can ever enter its mempool). The peer is load-bearing:
#                    the wallet money gate reads a peerless node as UNKNOWN.
#   2.  FUND         getnewaddress + generatetoaddress past COINBASE_MATURITY
#                    (100) so the wallet holds spendable transparent coinbase,
#                    plus one z_getnewaddress so the merchant Sapling keystore
#                    is seeded (order minting refuses an unseeded keystore).
#   2a. SETTLE       restart the store node so the forward-folded coins set
#                    stamps its authority, then wait for the peer link, the
#                    live sync state, and the reducer fold the money gate reads.
#   2b. CUSTODY      unlock the encrypted-at-rest wallet and take a
#                    current-key encrypted backup — the ZSLP intent plan leg
#                    reserves real custody and refuses anything less.
#   3.  TOKEN_GENESIS app.tokens.create plan → commit by plan_id → real ZSLP
#                    GENESIS on-chain (the store's access token gate settles in
#                    ZSLP: zslp_mint only accepts the 64-hex genesis token_id,
#                    never a ticker), then mines TOKEN_CONFS blocks so the
#                    mint baton is confirmed-valid.
#   4.  LIST_PRODUCT app.store.list-product attaches a real binary blob WITH
#                    embedded NUL bytes (the hermetic gate proved binary-safety;
#                    this proof must too), priced in the stage-3 token.
#   5.  CATALOG      the product is visible through app.store.catalog.
#   6.  ORDER        app.store.order (real order route: CSRF + PoW puzzle
#                    solved in-process) → one-time SHIELDED payment address.
#   7.  PAY          app.store.pay plan → confirm:true → real z_sendmany
#                    t→z carrying memo ZCL23ORDER:<order_id>, broadcast
#                    (asserted via gettransaction: wallet-recorded,
#                    unconfirmed — getrawmempool has no RPC surface here).
#   8.  CONFIRM      generate blocks until the payment is 3+ deep
#                    (gettransaction confirmations ≥ 3).
#   9.  WAIT_PAID    the node's 30 s payment sweep credits the order by memo
#                    bind, mints the access tokens (order → SENT) →
#                    app.store.purchases reports ready_to_collect.
#   9.5 MINT_CONFIRM mine 3 blocks so the access-token mint confirms — the
#                    token gate reads the chain-derived zslp_ledger, which
#                    only counts a mint once its block is connected.
#   10. COLLECT      app.store.collect through the token gate (SHA3-256
#                    verify-before-write, hash_verified=true; bounded retry
#                    while the ledger projection folds the mint block).
#   11. BYTES        cmp delivered file vs original blob — byte-identical.
#
# Verdict lines:
#   VERDICT=PASS               every stage passed
#   VERDICT=SKIP reason=...    host lacks Sapling params or regtest mining
#   VERDICT=FAIL stage=<name>  a stage failed; the stage is named
#
# SAFETY (mirrors isolated_node_env.sh / two_node_peer_tip.sh):
#   - /tmp-only datadirs (mktemp -d under /tmp/zcl23-storeproof-*), re-asserted
#     under /tmp before rm -rf; kept instead when ZCL_STOREPROOF_KEEP=1.
#   - 391xx isolation ports ONLY; every chosen port is checked against the
#     live refuse-set AND ss(8)-LISTEN-probed before spawn.
#   - Each node spawned under setsid → its OWN process group; cleanup kill
#     -KILLs the whole GROUP (no orphan survives a harness crash).
#   - Never touches the live node (8033/18232), the zclassicd oracle
#     (8034/8232), their datadirs, or their systemd units.
#
# Run:  make test-store-operator-proof   (opt-in; NOT in `make ci`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Pipeline-free substring predicates: this script runs under pipefail, so a
# status-carrying `printf '%s' "$out" | grep -q needle` can report printf's
# SIGPIPE (141) instead of grep's 0 on a MATCH — inverting the decision
# (check_pipefail_status_pipe refuses new ones; see sh_str.sh's header).
. "$REPO_ROOT/tools/scripts/sh_str.sh"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"

# ── Live-port refuse-set (verbatim from isolated_node_env.sh) ──────
SP_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"

# ── Tunables (env-overridable) ─────────────────────────────────────
MATURE_BLOCKS="${MATURE_BLOCKS:-105}"   # past COINBASE_MATURITY (100)
TOKEN_CONFS="${TOKEN_CONFS:-4}"         # blocks burying the token GENESIS so
                                        # the mint baton is confirmed-valid
CONFIRM_BLOCKS="${CONFIRM_BLOCKS:-6}"   # payment must end up ≥3 deep
RPC_WARMUP="${RPC_WARMUP:-60}"          # node RPC warmup budget (s)
PAID_DEADLINE="${PAID_DEADLINE:-180}"   # payment-sweep budget (s); the
                                        # merchant reconcile ticks every 30 s
PRICE_ZAT="${PRICE_ZAT:-25000000}"      # 0.25 ZCL
TOKEN_TICKER="${TOKEN_TICKER:-OPPROOF}" # ZSLP ticker; the on-chain token_id
                                        # (64-hex genesis txid) is minted live
                                        # in stage 3 — zslp_mint only accepts
                                        # the hex id, never the ticker.
# The custody scope the token genesis is planned and committed under. The
# node boots with -operator-lane=dev, and the ZSLP intent contract refuses
# any plan whose wallet_scope does not match the persisted operator lane.
WALLET_SCOPE=dev
# One stable key per proof run: the ZSLP intent contract keys the durable plan
# by it, so a repeated plan leg returns the SAME reservation instead of
# reserving the genesis fee twice.
TOKEN_IDEMPOTENCY_KEY="store-operator-proof-genesis-1"
# How long this proof's own native-CLI calls wait for the node to answer. The
# CLI default is 10 s (engine/controllers/src/rpc_client.c, ZCL_RPC_DEADLINE_MS)
# — right for an interactive operator, wrong for a proof that asks a node still
# folding a freshly mined chain to run a synchronous whole-wallet backup, or
# even to read backup status while the wallet lock is held. A node that is
# working is not a node that is wedged, so the client waits instead of
# abandoning the call; every gate the node enforces is unchanged.
SP_RPC_DEADLINE_MS=120000

# Isolation port quads (two_node uses 39070/39080, iso env defaults 39030).
# The store node keeps 391x0; the witness peer takes the next quad.
SP_PORT=39110; SP_RPC=39111; SP_FS=39112; SP_HTTPS=39113
PEER_PORT=39114; PEER_RPC=39115; PEER_FS=39116; PEER_HTTPS=39117
DEAD_SINK=39999

# ── State ──────────────────────────────────────────────────────────
SP_DD=""
SP_PID=""
SP_PGID=""
PEER_DD=""
PEER_PID=""
PEER_PGID=""
SP_CLEANED=0
SP_KEEP="${ZCL_STOREPROOF_KEEP:-0}"
# Throwaway wallet custody passphrases for this run's throwaway /tmp regtest
# datadir. They never ride argv: the wallet passphrase is written to a 0600
# credential file the node reads at boot (CREDENTIALS_DIRECTORY), and the
# backup password is fed to the backup command on stdin. The ZSLP intent
# contract refuses to plan against a plaintext, locked, or un-backed-up
# wallet, so an operator proof has to hold real custody like any operator.
SP_WALLET_PASS="${ZCL_STOREPROOF_WALLET_PASS:-store-operator-proof-wallet-pass}"
SP_BACKUP_PASS="${ZCL_STOREPROOF_BACKUP_PASS:-store-operator-proof-backup-pass}"

sp_log()  { echo "store-sell-operator-proof: $*"; }
sp_skip() { sp_log "VERDICT=SKIP reason=$*"; exit 0; }
sp_fail() {
    sp_log "FAIL stage=$1: $2"
    sp_log "VERDICT=FAIL stage=$1"
    exit 1
}
# This file's contract is that a failure NAMES itself. `set -e` breaks that
# promise on its own: any command the script did not guard kills the run with a
# bare status and no verdict line at all, which is unreadable from a make log
# (observed: a restart that exited 1 between two stages, printing nothing).
# The ERR trap closes that hole — it never converts a failure into a pass, it
# only makes an unguarded one say where it happened. set -E propagates it into
# functions and command substitutions; sp_fail/sp_skip exit deliberately and do
# not trip it.
set -E
sp_unexpected() {
    local status="$1" line="$2"
    sp_log "FAIL stage=UNNAMED: the proof exited $status at line $line without reaching a stage verdict"
    sp_log "VERDICT=FAIL stage=UNNAMED"
}
trap 'sp_unexpected "$?" "$LINENO"' ERR

# ── Port guards (same discipline as isolated_node_env.sh) ──────────
sp_assert_not_live_port() {
    local p="$1" lp
    for lp in $SP_LIVE_PORTS; do
        [ "$p" = "$lp" ] && { sp_log "FATAL: port $p is in the live refuse-set — refusing" >&2; exit 2; }
    done
    return 0
}
sp_assert_port_free() {
    local p="$1"
    if [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ]; then
        sp_log "FATAL: port $p is already LISTENING — refusing (operator port math is wrong)" >&2
        exit 2
    fi
    return 0
}

# ── Cleanup: kill the process groups + rm the /tmp datadirs ────────
sp_kill_group() {
    local pgid="$1" i
    [ -n "$pgid" ] || return 0
    kill -TERM "-$pgid" 2>/dev/null || true
    for i in $(seq 1 25); do
        kill -0 "-$pgid" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}
sp_rm_datadir() {
    local dd="$1"
    [ -n "$dd" ] && [ -d "$dd" ] || return 0
    if [ "$SP_KEEP" = "1" ]; then
        sp_log "KEEP=1: datadir preserved at $dd"
        return 0
    fi
    case "$dd" in
        /tmp/zcl23-storeproof-*) rm -rf "$dd" 2>/dev/null || true ;;
        *) sp_log "WARN: refusing to rm non-/tmp datadir '$dd'" >&2 ;;
    esac
}
sp_cleanup() {
    [ "$SP_CLEANED" = "1" ] && return 0
    SP_CLEANED=1
    sp_kill_group "$SP_PGID"
    sp_kill_group "$PEER_PGID"
    # Belt-and-suspenders: only ever matches our throwaway datadir strings.
    [ -n "$SP_DD" ] && pkill -KILL -f -- "-datadir=$SP_DD" 2>/dev/null || true
    [ -n "$PEER_DD" ] && pkill -KILL -f -- "-datadir=$PEER_DD" 2>/dev/null || true
    sp_rm_datadir "$SP_DD"
    sp_rm_datadir "$PEER_DD"
}

# ── RPC + native-CLI wrappers, pinned to the ISOLATED node ONLY ────
sp_rpc() {
    ZCL_DATADIR="$SP_DD" ZCL_RPCPORT="$SP_RPC" "$RPC_BIN" "$@" 2>/dev/null || true
}
# Native typed CLI. The reply envelope is the single line starting with '{';
# anything else on the stream is node/CLI log chatter. NEVER lets a nonzero
# CLI exit or a no-match grep escape with a nonzero status: under
# `set -euo pipefail` either would kill the script silently at the call site
# and the failing stage would never be named (observed live: a refused order
# exited the run with no verdict at all).
sp_cli() {
    local out
    out="$(ZCL_DATADIR="$SP_DD" ZCL_RPCPORT="$SP_RPC" \
        ZCL_RPC_DEADLINE_MS="$SP_RPC_DEADLINE_MS" "$NODE_BIN" "$@" 2>&1)" || true
    printf '%s\n' "$out" | grep '^{' | tail -1 || true
}
# Same wrapper, but the JSON input rides stdin (--input=-) instead of argv: a
# wallet passphrase must never be visible in a process argument list.
sp_cli_input() {
    local payload="$1"
    shift
    local out
    out="$(printf '%s' "$payload" | ZCL_DATADIR="$SP_DD" ZCL_RPCPORT="$SP_RPC" \
        ZCL_RPC_DEADLINE_MS="$SP_RPC_DEADLINE_MS" \
        "$NODE_BIN" "$@" --input=- 2>&1)" || true
    printf '%s\n' "$out" | grep '^{' | tail -1 || true
}
sp_json_int() { printf '%s' "$1" | sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p"; }
sp_json_str() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

# zcl-rpc hard-caps curl at --max-time 30, so a getblockcount issued while the
# node holds cs_main for a mining batch can come back with no body at all. That
# is a CLIENT read that did not complete, not a chain without a height, so the
# read is retried a bounded number of times; callers still decide what an
# unreadable height means for their stage.
sp_blockcount() {
    local i h
    for i in $(seq 1 10); do
        h="$(sp_rpc getblockcount | sed -n 's/.*"result"[: ]*\([0-9-]*\).*/\1/p')"
        [ -n "$h" ] && { printf '%s\n' "$h"; return 0; }
        sleep 1
    done
    return 0
}
sp_connection_count() {
    sp_rpc getconnectioncount | sed -n 's/.*"result"[: ]*\([0-9]*\).*/\1/p'
}
sp_sync_state() {
    sp_rpc downloadstats | sed -n 's/.*"sync_state":"\([a-z_]*\)".*/\1/p'
}

# ── Money-gate readiness waits ─────────────────────────────────────
# The wallet money gate does not read the active chain: it reads the REDUCER
# frontier (coins_best_height and H* must both stand at the mined tip), the
# peer set (a peerless node's money is UNKNOWN by construction), and the sync
# FSM (only blocks_download / connecting_blocks / at_tip count as live). Each
# wait below is one of those three authorities, and each fails the stage by
# name instead of letting the token plan report a confusing money refusal.
sp_wait_connected() {
    local stage="$1" deadline n
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n="$(sp_connection_count)"
        case "$n" in
            ''|*[!0-9]*) ;;
            *) [ "$n" -ge 1 ] && return 0 ;;
        esac
        sleep 1
    done
    sp_fail "$stage" "the store node never connected to the witness peer (getconnectioncount stayed ${n:-?})"
}
sp_wait_sync_live() {
    local stage="$1" deadline state
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(sp_sync_state)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        sleep 1
    done
    sp_fail "$stage" "sync state stayed '${state:-?}' — the money gate reads anything else as not live"
}
# The money gate publishes numbers only when the exact coins tip, the network
# target and the freshness classification hold STILL for the whole observation
# (wallet_money_snapshot_build re-reads every authority and answers STALE if
# any of them moved). A regtest node that is still landing a mine batch it
# accepted after the client's reply deadline moves all three, so this wait
# demands the same stability the gate does: peers, a live sync state, the
# reducer folded exactly to the tip, and a tip that did not move across the
# whole reading. Without it the token plan is refused "wallet coins tip is 1
# blocks behind network tip" for a node that is perfectly healthy, just busy.
sp_wait_money_ready() {
    local stage="$1" deadline tip tip_after dump coins hstar peers state
    deadline=$(( $(date +%s) + 240 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        tip="$(sp_blockcount)"
        case "$tip" in
            ''|*[!0-9]*) sleep 2; continue ;;
        esac
        dump="$(sp_cli dumpstate reducer_frontier)"
        coins="$(sp_json_int "$dump" coins_best_height)"
        hstar="$(sp_json_int "$dump" hstar)"
        peers="$(sp_connection_count)"
        state="$(sp_sync_state)"
        tip_after="$(sp_blockcount)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) ;;
            *) sleep 2; continue ;;
        esac
        if [ "$coins" = "$tip" ] && [ "$hstar" = "$tip" ] &&
           [ "$tip_after" = "$tip" ] && [ -n "$peers" ] && [ "$peers" -ge 1 ]; then
            return 0
        fi
        sleep 2
    done
    sp_fail "$stage" "the wallet money authorities never settled: tip=${tip:-?}->${tip_after:-?} coins_best_height=${coins:-?} hstar=${hstar:-?} peers=${peers:-?} sync=${state:-?}"
}

# ── Preflight ──────────────────────────────────────────────────────
command -v ss     >/dev/null 2>&1 || { sp_log "FATAL: ss(8) not found" >&2; exit 2; }
command -v mktemp >/dev/null 2>&1 || { sp_log "FATAL: mktemp not found" >&2; exit 2; }
command -v cmp    >/dev/null 2>&1 || { sp_log "FATAL: cmp not found" >&2; exit 2; }
[ -x "$NODE_BIN" ] || { sp_log "FATAL: $NODE_BIN not built — run make first" >&2; exit 2; }
[ -x "$RPC_BIN" ]  || { sp_log "FATAL: $RPC_BIN not built — run make zcl-rpc" >&2; exit 2; }

# Sapling proving params: the shielded pay leg is impossible without them.
PARAMS_DIR="${ZCL_PARAMS_DIR:-$HOME/.zcash-params}"
for f in sapling-spend.params sapling-output.params sprout-groth16.params sprout-verifying.key; do
    [ -r "$PARAMS_DIR/$f" ] || sp_skip "sapling-params-missing ($PARAMS_DIR/$f)"
done

for p in "$SP_PORT" "$SP_RPC" "$SP_FS" "$SP_HTTPS" \
         "$PEER_PORT" "$PEER_RPC" "$PEER_FS" "$PEER_HTTPS" "$DEAD_SINK"; do
    sp_assert_not_live_port "$p"
done

sp_mktemp_datadir() {
    local dd
    dd="$(mktemp -d /tmp/zcl23-storeproof-XXXXXX)" || { sp_log "FATAL: mktemp failed" >&2; exit 2; }
    case "$dd" in
        /tmp/zcl23-storeproof-*) : ;;
        *) sp_log "FATAL: bad datadir $dd" >&2; exit 2 ;;
    esac
    if [ -n "${HOME:-}" ]; then
        case "$dd" in
            "$HOME"/.zclassic-c23*) sp_log "FATAL: datadir under live tree — refusing" >&2; exit 2 ;;
        esac
    fi
    printf '%s\n' "$dd"
}
SP_DD="$(sp_mktemp_datadir)"
PEER_DD="$(sp_mktemp_datadir)"

# Arm the cleanup trap BEFORE any abortable post-mint step.
trap sp_cleanup EXIT INT TERM

for p in "$SP_PORT" "$SP_RPC" "$SP_FS" "$SP_HTTPS" \
         "$PEER_PORT" "$PEER_RPC" "$PEER_FS" "$PEER_HTTPS"; do
    sp_assert_port_free "$p"
done

sp_log "datadir=$SP_DD ports{p2p=$SP_PORT rpc=$SP_RPC fs=$SP_FS https=$SP_HTTPS} sink=$DEAD_SINK"
sp_log "witness peer datadir=$PEER_DD ports{p2p=$PEER_PORT rpc=$PEER_RPC fs=$PEER_FS https=$PEER_HTTPS}"

# ── Wallet custody credential (read by the node at boot) ───────────
# No -allow-plaintext-wallet: the wallet-passphrase credential encrypts key
# writes at rest (WKS1), which is what the ZSLP intent plan leg demands
# (vault_intent_controller.c refuses WALLET_NOT_ENCRYPTED otherwise). 0700
# directory, 0600 file, inside the throwaway datadir that cleanup removes.
SP_CRED_DIR="$SP_DD/cred"
install -d -m 700 "$SP_CRED_DIR" || { sp_log "FATAL: could not create the credential directory" >&2; exit 2; }
install -m 600 /dev/null "$SP_CRED_DIR/wallet-passphrase" || { sp_log "FATAL: could not create the wallet passphrase credential" >&2; exit 2; }
printf '%s\n' "$SP_WALLET_PASS" >"$SP_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$SP_CRED_DIR"

# ── Stage 1: SPAWN ─────────────────────────────────────────────────
# One isolated regtest node runs the store; one isolated witness peer sits
# beside it. The peer is not decoration: the wallet money gate classifies a
# peerless node's money as UNKNOWN by construction
# (wallet_money_freshness_classify refuses peer_count == 0,
# contexts/wallet/services/src/wallet_money_service.c), and the token genesis
# reserves real custody through that gate. A store operator has peers, so the
# proof has one too.
# -operator-lane=dev persists the dev operator lane the token genesis plans
# under (a wallet_scope that does not match the persisted lane is CONFLICTED);
# -wallet-no-phrase-backup is the non-interactive first-run acknowledgement
# for a throwaway wallet that will be destroyed with the datadir.
sp_spawn_node() {
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5" connect="$6"
    setsid "$NODE_BIN" \
        -datadir="$dd" -regtest -regtestshielded \
        -port="$p2p" -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        -connect="$connect" \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
        >>"$dd/node.log" 2>&1 &
    printf '%s\n' "$!"
}
# RPC-up on a specific node: the cookie exists AND getblockcount answers.
sp_wait_rpc() {
    local dd="$1" rpc="$2" pid="$3" stage="$4" deadline t
    deadline=$(( $(date +%s) + RPC_WARMUP ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            tail -20 "$dd/node.log" >&2 || true
            sp_fail "$stage" "node exited during RPC warmup (see $dd/node.log)"
        fi
        if [ -f "$dd/.cookie" ]; then
            # A node whose RPC is not serving yet makes zcl-rpc exit nonzero,
            # and under `set -e` that killed the whole run mid-restart with a
            # bare status and no verdict. Not answering YET is the normal state
            # of this loop, so the status is absorbed and the deadline above is
            # the only thing that decides.
            t="$(ZCL_DATADIR="$dd" ZCL_RPCPORT="$rpc" \
                 "$RPC_BIN" getblockcount 2>/dev/null || true)"
            t="$(printf '%s' "$t" | sed -n 's/.*"result"[: ]*\([0-9-]*\).*/\1/p')"
            [ -n "$t" ] && return 0
        fi
        sleep 0.5
    done
    tail -20 "$dd/node.log" >&2 || true
    sp_fail "$stage" "RPC never came up within ${RPC_WARMUP}s (see $dd/node.log)"
}
sp_log "[1/11] SPAWN: booting the isolated witness peer and the store node..."
PEER_PID="$(sp_spawn_node "$PEER_DD" "$PEER_PORT" "$PEER_RPC" "$PEER_FS" "$PEER_HTTPS" "127.0.0.1:$DEAD_SINK")"
PEER_PGID="$PEER_PID"   # setsid leader: PGID == PID
sp_wait_rpc "$PEER_DD" "$PEER_RPC" "$PEER_PID" SPAWN
SP_PID="$(sp_spawn_node "$SP_DD" "$SP_PORT" "$SP_RPC" "$SP_FS" "$SP_HTTPS" "127.0.0.1:$PEER_PORT")"
SP_PGID="$SP_PID"
sp_wait_rpc "$SP_DD" "$SP_RPC" "$SP_PID" SPAWN
sp_log "       peer up (pid $PEER_PID), node up (pid $SP_PID), chain height $(sp_blockcount)"

# Mine in batches of 20 up to a TARGET HEIGHT, asserting progress by
# getblockcount rather than by the RPC body: zcl-rpc hard-caps curl at
# --max-time 30, and a single 105-block generate outlives it (the node keeps
# mining regardless), so the batch body is advisory — chain height is the
# truth. Skips (not fails) when the node names mining unavailable. A
# 'mint refused' body is NOT that: the on-demand-mint sovereignty gate
# compares coins_applied_height against the CACHED provable tip
# (reducer_frontier_provable_tip_cached), and under fast regtest mining the
# applied frontier legitimately runs ~1 block ahead of the cache, so the
# gate false-refuses until tip_finalize catches up — back off and retry.
# A single no-progress poll is likewise not a verdict (a 30 s curl can die
# while the server keeps working); only a tip frozen for a sustained 60 s
# window fails the stage.
sp_mine_to() {
    local target="$1" stage="$2" h n out h2 refusals stall
    h="$(sp_blockcount)"
    [ -n "$h" ] || sp_fail "$stage" "getblockcount silent"
    stall=0
    refusals=0
    while [ "$h" -lt "$target" ]; do
        n=$(( target - h ))
        [ "$n" -gt 20 ] && n=20
        out="$(sp_rpc generatetoaddress "$n" "\"$TADDR\"")"
        mine_err="$(printf '%s\n' "$out" | grep -E 'regtest only|not mine-blocks-on-demand' || true)"
        if [ -n "$mine_err" ]; then
            sp_skip "regtest-mining-unavailable ($(printf '%s' "$out" | head -c 200))"
        fi
        if str_contains "$out" 'mint refused'; then
            # A refused batch may still have mined part of itself before the
            # gate closed, so a retry must re-read the height and ask for the
            # REMAINING blocks — re-sending the original count is how this
            # loop used to overshoot the target (observed: 107 for a target of
            # 105, which then failed the stage's own height assertion).
            refusals=$(( refusals + 1 ))
            [ "$refusals" -lt 15 ] || sp_fail "$stage" "mint refused persisted across $refusals retries (a fresh self-mined node must read sovereign): $(printf '%s' "$out" | head -c 200)"
            sleep 2
            h2="$(sp_blockcount)"
            [ -n "$h2" ] && h="$h2"
            continue
        fi
        refusals=0
        h2="$(sp_blockcount)"
        if [ -z "$h2" ] || [ "$h2" -le "$h" ]; then
            # No READABLE progress THIS poll. Not yet a failure: an empty body
            # means the curl side of zcl-rpc gave up at --max-time 30 while the
            # server may still be working (mining the batch behind the
            # catchup lean-index/wallet scan), and a slow or silent
            # getblockcount is that same lock contention seen from the client
            # side — the height it could not read is not a height that stopped
            # advancing. HEIGHT over TIME is the verdict: fail only after a
            # sustained no-progress window (12 polls x 5 s = 60 s of a tip that
            # never reads higher is never a transient).
            stall=$(( stall + 1 ))
            [ "$stall" -lt 12 ] || sp_fail "$stage" "chain tip stuck at height $h for $(( stall * 5 ))s (target $target, last read '${h2:-silent}'): $(printf '%s' "$out" | head -c 200)"
            sleep 5
            continue
        fi
        stall=0
        h="$h2"
    done
    # One batch the node finished AFTER the client's 30 s curl deadline can
    # land blocks this loop never saw it start, so the tip is allowed to sit a
    # little past the target — but only by one batch. More than that is a
    # runaway miner, not a slow reply, and the stage says so.
    [ "$h" -ge "$target" ] || sp_fail "$stage" "chain height $h is below the mining target $target"
    [ "$h" -le "$(( target + 20 ))" ] || sp_fail "$stage" "chain height $h overshot the mining target $target by more than one batch"
}

# ── Stage 2: FUND ──────────────────────────────────────────────────
sp_log "[2/11] FUND: mining $MATURE_BLOCKS blocks to a wallet t-address (past COINBASE_MATURITY=100)..."
# The RPC surface answers before the on-demand key minter is warm: a first
# getnewaddress right at RPC-up can return an empty result. Bounded retry
# (the node itself is the only clock that matters).
TADDR=""
for _ in $(seq 1 20); do
    TADDR="$(sp_rpc getnewaddress | sed -n 's/.*"result"[: ]*"\([^"]*\)".*/\1/p')"
    [ -n "$TADDR" ] && break
    sleep 1
done
[ -n "$TADDR" ] || sp_fail FUND "getnewaddress returned nothing after 20 tries"
sp_mine_to "$MATURE_BLOCKS" FUND
HEIGHT="$(sp_blockcount)"
# sp_mine_to already bounded the tip to [target, target+one batch]; what this
# stage needs from the number is the maturity property: at least MATURE_BLOCKS,
# so the first MATURE_BLOCKS-100 coinbases are spendable.
case "$HEIGHT" in
    ''|*[!0-9]*) sp_fail FUND "getblockcount answered '${HEIGHT:-?}' after mining" ;;
esac
[ "$HEIGHT" -ge "$MATURE_BLOCKS" ] || sp_fail FUND "height is $HEIGHT, expected at least $MATURE_BLOCKS"
# Seed + persist the merchant Sapling keystore: the shielded order mint
# (zslp_generate_payment_address) refuses an unseeded keystore, so the
# seller's node must hold at least one z-address before any order.
ZADDR=""
for _ in $(seq 1 20); do
    ZADDR="$(sp_rpc z_getnewaddress | sed -n 's/.*"result"[: ]*"\([^"]*\)".*/\1/p')"
    [ -n "$ZADDR" ] && break
    sleep 1
done
case "$ZADDR" in
    zregtestsapling1*) : ;;
    *) sp_fail FUND "z_getnewaddress returned '${ZADDR:-?}' — merchant Sapling keystore not seeded" ;;
esac
sp_log "       height=$HEIGHT taddr=$TADDR (first $((MATURE_BLOCKS - 100)) coinbases mature)"
sp_log "       merchant z-address seeded: ${ZADDR:0:28}..."

# ── Stage 2a: SETTLE (restart, then let the money authorities catch up) ──
# The forward-folded coins set only becomes an AUTHORITY at boot: a node that
# mined its first coins into an empty coins_kv leaves the set populated but
# unstamped, and coins_kv_boot_rebuild_if_needed stamps it on the NEXT boot
# (engine/modules/storage/src/coins_kv_boot_rebuild.c). Until that stamp lands
# the money gate answers "authoritative wallet coins tip is unavailable" and no
# custody plan can be reserved — so the operator proof restarts the store node
# exactly once, after funding, before any custody work.
sp_log "[2a/11] SETTLE: restarting the store node so the forward-folded coins set stamps its authority..."
sp_kill_group "$SP_PGID"; SP_PGID=""; SP_PID=""
SP_PID="$(sp_spawn_node "$SP_DD" "$SP_PORT" "$SP_RPC" "$SP_FS" "$SP_HTTPS" "127.0.0.1:$PEER_PORT")"
SP_PGID="$SP_PID"
sp_wait_rpc "$SP_DD" "$SP_RPC" "$SP_PID" SETTLE
HEIGHT_AFTER_RESTART="$(sp_blockcount)"
case "$HEIGHT_AFTER_RESTART" in
    ''|*[!0-9]*) sp_fail SETTLE "getblockcount answered '${HEIGHT_AFTER_RESTART:-?}' after the restart" ;;
esac
# A restart may not lose a single mined block: the funding chain is what every
# later stage spends.
[ "$HEIGHT_AFTER_RESTART" -ge "$HEIGHT" ] || sp_fail SETTLE "height fell from $HEIGHT to $HEIGHT_AFTER_RESTART across the restart — the funding chain did not survive"
sp_wait_connected SETTLE
sp_wait_sync_live SETTLE
sp_wait_money_ready SETTLE
sp_log "       restarted at height $(sp_blockcount), peer linked, sync=$(sp_sync_state), money authorities settled"

# ── Stage 2b: CUSTODY (encrypted at rest, unlocked, currently backed up) ──
# The ZSLP intent plan leg reserves real custody, so it refuses anything less
# than a real operator's wallet posture: encrypted at rest, unlocked, and
# covered by a current-key encrypted backup under 24 hours old
# (vi_context_ready, contexts/wallet/controllers/src/vault_intent_controller.c).
# The backup is taken AFTER every key this proof derives up front, because the
# gate compares the backup's key count against the live keystore's.
sp_log "[2b/11] CUSTODY: unlocking the encrypted wallet and taking a current-key encrypted backup..."
SEC_STATUS="$(sp_cli core wallet security status)"
str_contains "$SEC_STATUS" '"ok":true' || sp_fail CUSTODY "wallet security status refused: $SEC_STATUS"
str_contains "$SEC_STATUS" '"encrypted_at_rest":true' || sp_fail CUSTODY "the wallet is not encrypted at rest — the passphrase credential did not take: $SEC_STATUS"
if ! str_contains "$SEC_STATUS" '"unlocked":true'; then
    UNLOCK_OUT="$(sp_cli_input "{\"passphrase\":\"$SP_WALLET_PASS\",\"timeout_seconds\":3600}" core wallet security unlock)"
    str_contains "$UNLOCK_OUT" '"unlocked":true' || sp_fail CUSTODY "wallet unlock refused: $UNLOCK_OUT"
fi
# core.wallet.backup.now is contract-idempotent and runs synchronously inside
# the node, but the native CLI gives up on its own reply deadline (~10 s) while
# a node that is still folding blocks can take longer to copy and verify every
# wallet table. The verdict is therefore the END STATE the ZSLP plan leg
# actually reads — core.wallet.backup.status reporting an encrypted backup —
# never the exit status of one call: a call whose write did land is accepted on
# the next status read, a call whose write did not land is retried, and a
# backup that never lands fails this stage by name instead of surfacing later
# as a confusing ENCRYPTED_BACKUP_REQUIRED refusal from the token genesis.
BACKUP_OUT=""
BACKUP_STATUS=""
backup_ready=no
for _ in 1 2 3; do
    BACKUP_OUT="$(sp_cli_input "{\"confirm\":true,\"password\":\"$SP_BACKUP_PASS\"}" core wallet backup now)"
    BACKUP_STATUS="$(sp_cli core wallet backup status)"
    if str_contains "$BACKUP_STATUS" '"encrypted_backup_available":true'; then
        backup_ready=yes
        break
    fi
done
[ "$backup_ready" = "yes" ] || sp_fail CUSTODY "no encrypted wallet backup exists after 3 attempts; last reply: $BACKUP_OUT; status: $BACKUP_STATUS"
sp_log "       wallet encrypted at rest, unlocked, current-key encrypted backup taken"

# ── Stage 3: TOKEN_GENESIS (real ZSLP GENESIS on-chain) ────────────
# app.tokens.create is a durable custody intent, not a one-shot RPC: the plan
# leg names the wallet scope and an idempotency key and atomically reserves
# the genesis fee, and the commit leg names ONLY the 64-hex plan_id it
# answered plus confirm:true (contract row: app.tokens.create in
# engine/composition/commands/app_features.def; enforced in
# contexts/market/controllers/src/zslp_intent_native_handler.c). The operator
# proof speaks that contract exactly — it never re-sends the genesis fields on
# the commit leg, so the bytes that get signed are the bytes that were planned.
sp_log "[3/11] TOKEN_GENESIS: creating the $TOKEN_TICKER access token on-chain (plan → commit)..."
# The custody work above takes real time, and a mine batch the node accepted
# after the client gave up can still be landing blocks underneath it. The plan
# leg reads the money authorities at call time, so settle them again here
# rather than let a moving tip surface as a money refusal on a healthy node.
sp_wait_money_ready TOKEN_GENESIS
TOKEN_PLAN="$(sp_cli app tokens create --input="{\"wallet_scope\":\"$WALLET_SCOPE\",\"ticker\":\"$TOKEN_TICKER\",\"name\":\"Operator Proof Token\",\"decimals\":0,\"supply\":1000,\"idempotency_key\":\"$TOKEN_IDEMPOTENCY_KEY\"}")"
str_contains "$TOKEN_PLAN" '"stage":"plan"' || sp_fail TOKEN_GENESIS "create did not answer a plan: $TOKEN_PLAN"
str_contains "$TOKEN_PLAN" '"committed":false' || sp_fail TOKEN_GENESIS "the plan leg claims it committed: $TOKEN_PLAN"
TOKEN_PLAN_ID="$(sp_json_str "$TOKEN_PLAN" plan_id)"
case "$TOKEN_PLAN_ID" in
    ????????????????????????????????????????????????????????????????) : ;;
    *) sp_fail TOKEN_GENESIS "plan_id '${TOKEN_PLAN_ID:-?}' is not a 64-char durable plan id: $TOKEN_PLAN" ;;
esac
case "$TOKEN_PLAN_ID" in
    *[!0-9a-fA-F]*) sp_fail TOKEN_GENESIS "plan_id '$TOKEN_PLAN_ID' is not hex: $TOKEN_PLAN" ;;
esac
TOKEN_OUT="$(sp_cli app tokens create --input="{\"wallet_scope\":\"$WALLET_SCOPE\",\"plan_id\":\"$TOKEN_PLAN_ID\",\"confirm\":true}")"
str_contains "$TOKEN_OUT" '"ok":true' || sp_fail TOKEN_GENESIS "$TOKEN_OUT"
str_contains "$TOKEN_OUT" '"committed":true' || sp_fail TOKEN_GENESIS "the commit leg did not commit: $TOKEN_OUT"
TOKEN_ID="$(sp_json_str "$TOKEN_OUT" token_id)"
case "$TOKEN_ID" in
    ????????????????????????????????????????????????????????????????) : ;;
    *) sp_fail TOKEN_GENESIS "token_id '${TOKEN_ID:-?}' is not 64 chars: $TOKEN_OUT" ;;
esac
case "$TOKEN_ID" in
    *[!0-9a-fA-F]*) sp_fail TOKEN_GENESIS "token_id '$TOKEN_ID' is not hex: $TOKEN_OUT" ;;
esac
# Bury the GENESIS from where it actually landed: the commit broadcast into a
# chain whose height this stage reads now, not from the height recorded before
# the custody work.
HEIGHT_AT_GENESIS="$(sp_blockcount)"
case "$HEIGHT_AT_GENESIS" in
    ''|*[!0-9]*) sp_fail TOKEN_GENESIS "getblockcount answered '${HEIGHT_AT_GENESIS:-?}' after the genesis commit" ;;
esac
sp_mine_to "$((HEIGHT_AT_GENESIS + TOKEN_CONFS))" TOKEN_GENESIS
TOK_LIST="$(sp_cli app tokens list)"
# The two ZSLP surfaces print this one identity in MIRRORED strings, so the
# membership check compares the 32 bytes, never the text:
#   * app.tokens.create answers the genesis txid in DISPLAY order — the form
#     every wallet-facing surface parses back with uint256_set_hex, including
#     the store's own access gate (store_ledger_access_balance,
#     engine/controllers/src/store_access_gate.c:39) and app.tokens.mint/send/
#     burn. That is the id this proof lists the product under, and the id the
#     token gate must credit.
#   * app.tokens.list renders the SAME bytes forward and uppercase, because the
#     explorer index reads them with SQL hex() (contexts/market/models/src/
#     zslp.c:389), which does not apply the txid display reversal.
# Two commands in one branch printing one identity in two orders is a product
# defect an operator hits the moment they paste a listed id into mint or into
# a product listing; it is reported separately. This proof still asserts the
# genesis is indexed — under the exact bytes it minted, and under the ticker
# it asked for.
sp_hex_reverse() {
    local hex="$1" out="" i
    for (( i=${#hex} - 2; i >= 0; i -= 2 )); do
        out="$out${hex:i:2}"
    done
    printf '%s\n' "$out"
}
TOKEN_ID_INDEXED="$(sp_hex_reverse "$TOKEN_ID")"
tok_hit="$(printf '%s\n' "$TOK_LIST" | grep -i "\"token_id\":\"$TOKEN_ID_INDEXED\"" || true)"
[ -n "$tok_hit" ] || sp_fail TOKEN_GENESIS "token $TOKEN_ID (indexed byte order $TOKEN_ID_INDEXED) not indexed after $TOKEN_CONFS confirmations: $TOK_LIST"
str_contains "$TOK_LIST" "\"ticker\":\"$TOKEN_TICKER\"" || sp_fail TOKEN_GENESIS "the indexed token does not carry ticker $TOKEN_TICKER: $TOK_LIST"
sp_log "       token_id=${TOKEN_ID:0:16}... confirmed at height $(sp_blockcount), indexed as ${TOKEN_ID_INDEXED:0:16}..."

# ── Stage 4: LIST_PRODUCT (binary blob with embedded NULs) ─────────
sp_log "[4/11] LIST_PRODUCT: listing a product with a binary blob (embedded NULs)..."
BLOB="$SP_DD/operator-proof-blob.bin"
{
    printf 'ZCL23-STORE-OPERATOR-PROOF\0\0binary-safe\0'
    head -c 2048 /dev/urandom
    printf '\0tail-marker\0\0'
} > "$BLOB"
# Prove the blob really carries NUL bytes before staking the proof on it:
# stripping NULs must CHANGE the bytes, or the binary-safety proof is hollow.
TRIMMED="$(mktemp /tmp/zcl23-storeproof-trim-XXXXXX)"
tr -d '\0' < "$BLOB" > "$TRIMMED"
if cmp -s "$TRIMMED" "$BLOB"; then
    rm -f "$TRIMMED"
    sp_fail LIST_PRODUCT "generated blob has no NUL bytes — binary-safety proof would be hollow"
fi
rm -f "$TRIMMED"
BLOB_BYTES="$(stat -c %s "$BLOB")"
LIST_OUT="$(sp_cli app store list-product --input="{\"name\":\"Operator Proof Blob\",\"description\":\"MVP C5 rung-A operator proof payload\",\"price_zatoshi\":$PRICE_ZAT,\"token_id\":\"$TOKEN_ID\",\"tokens_per_purchase\":1,\"content_path\":\"$BLOB\",\"content_filename\":\"operator-proof-blob.bin\",\"content_type\":\"engine/application/octet-stream\"}")"
str_contains "$LIST_OUT" '"ok":true' || sp_fail LIST_PRODUCT "$LIST_OUT"
PRODUCT_ID="$(sp_json_int "$LIST_OUT" id)"
CONTENT_HASH="$(sp_json_str "$LIST_OUT" content_hash)"
[ -n "$PRODUCT_ID" ] || sp_fail LIST_PRODUCT "no product id in reply: $LIST_OUT"
str_contains "$LIST_OUT" '"has_content":true' || sp_fail LIST_PRODUCT "has_content is not true: $LIST_OUT"
sp_log "       product_id=$PRODUCT_ID bytes=$BLOB_BYTES sha3-256=$CONTENT_HASH"

# ── Stage 5: CATALOG ───────────────────────────────────────────────
sp_log "[5/11] CATALOG: verifying the product is on sale..."
CAT_OUT="$(sp_cli app store catalog)"
str_contains "$CAT_OUT" '"ok":true' || sp_fail CATALOG "$CAT_OUT"
str_contains "$CAT_OUT" "\"product_id\":$PRODUCT_ID" || sp_fail CATALOG "product $PRODUCT_ID not in catalog: $CAT_OUT"
# the store upcases token_id at save (model before_validate); create answered
# it lowercase — same id, so the catalog membership check is case-insensitive.
cat_tok_hit="$(printf '%s\n' "$CAT_OUT" | grep -i "\"token_id\":\"$TOKEN_ID\"" || true)"
[ -n "$cat_tok_hit" ] || sp_fail CATALOG "token $TOKEN_ID not in catalog"
str_contains "$CAT_OUT" '"has_file":true' || sp_fail CATALOG "catalog does not report has_file:true for the product"
sp_log "       catalog shows product_id=$PRODUCT_ID token=$TOKEN_ID has_file=true"

# ── Stage 6: ORDER ─────────────────────────────────────────────────
sp_log "[6/11] ORDER: placing an order (real order route: CSRF + PoW puzzle solved in-process)..."
DELIVERED="$SP_DD/delivered-blob.bin"
ORDER_OUT="$(sp_cli app store order --input="{\"product_id\":$PRODUCT_ID,\"customer_address\":\"$TADDR\",\"output_path\":\"$DELIVERED\"}")"
str_contains "$ORDER_OUT" '"ok":true' || sp_fail ORDER "$ORDER_OUT"
PURCHASE_ID="$(sp_json_int "$ORDER_OUT" purchase_id)"
ORDER_ID="$(sp_json_int "$ORDER_OUT" order_id)"
PAY_ADDR="$(sp_json_str "$ORDER_OUT" payment_address)"
AMOUNT_ZAT="$(sp_json_int "$ORDER_OUT" amount_zatoshi)"
MEMO="$(sp_json_str "$ORDER_OUT" memo)"
[ -n "$PURCHASE_ID" ] && [ -n "$ORDER_ID" ] || sp_fail ORDER "missing ids in reply: $ORDER_OUT"
[ "$AMOUNT_ZAT" = "$PRICE_ZAT" ] || sp_fail ORDER "amount is ${AMOUNT_ZAT:-?}, expected $PRICE_ZAT"
[ "$MEMO" = "ZCL23ORDER:$ORDER_ID" ] || sp_fail ORDER "memo is '${MEMO:-?}', expected ZCL23ORDER:$ORDER_ID"
case "$PAY_ADDR" in
    zregtestsapling1*) : ;;
    *) sp_fail ORDER "payment address '${PAY_ADDR:-?}' is not a regtest Sapling address — order is not on the shielded lane" ;;
esac
sp_log "       purchase_id=$PURCHASE_ID order_id=$ORDER_ID amount=${AMOUNT_ZAT}zat pay=${PAY_ADDR:0:24}... memo=$MEMO"

# ── Stage 7: PAY (plan → confirm, real shielded z_sendmany) ────────
sp_log "[7/11] PAY: plan, then confirm — real t→z z_sendmany carrying $MEMO..."
PLAN_OUT="$(sp_cli app store pay --input="{\"purchase_id\":$PURCHASE_ID,\"from_address\":\"$TADDR\"}")"
str_contains "$PLAN_OUT" '"stage":"plan"' || sp_fail PAY "plan stage did not answer a plan: $PLAN_OUT"
str_contains "$PLAN_OUT" '"committed":false' || sp_fail PAY "plan claims committed: $PLAN_OUT"
PAY_OUT="$(sp_cli app store pay --input="{\"purchase_id\":$PURCHASE_ID,\"from_address\":\"$TADDR\",\"confirm\":true}")"
str_contains "$PAY_OUT" '"ok":true' || sp_fail PAY "$PAY_OUT"
OPID="$(sp_json_str "$PAY_OUT" operation_id)"
if [ "${#OPID}" -ne 64 ]; then
    sp_fail PAY "operation_id '$OPID' is not a 64-char txid: $PAY_OUT"
fi
case "$OPID" in
    *[!0-9a-fA-F]*) sp_fail PAY "operation_id '$OPID' is not hex: $PAY_OUT" ;;
esac
# getrawmempool is not on this node's RPC surface ("Method not found");
# gettransaction is the wallet-truth check: the payment must be recorded as
# broadcast-but-unconfirmed (confirmations:0), which is STRONGER evidence
# than a mempool substring scan — the wallet only knows a tx it actually
# built and relayed.
TX_REC="$(sp_rpc gettransaction "\"$OPID\"")"
str_contains "$TX_REC" "\"txid\":\"$OPID\"" || sp_fail PAY "payment txid $OPID not recorded by the wallet — nothing was broadcast: $TX_REC"
str_contains "$TX_REC" '"confirmations":0' || sp_fail PAY "payment tx already confirmed before CONFIRM stage — flow ordering broken: $TX_REC"
sp_log "       broadcast txid=$OPID (wallet-recorded, unconfirmed)"

# ── Stage 8: CONFIRM ───────────────────────────────────────────────
sp_log "[8/11] CONFIRM: mining $CONFIRM_BLOCKS blocks to bury the payment ≥3 deep..."
HEIGHT_AT_PAY="$(sp_blockcount)"
case "$HEIGHT_AT_PAY" in
    ''|*[!0-9]*) sp_fail CONFIRM "getblockcount answered '${HEIGHT_AT_PAY:-?}' before burying the payment" ;;
esac
sp_mine_to "$((HEIGHT_AT_PAY + CONFIRM_BLOCKS))" CONFIRM
HEIGHT2="$(sp_blockcount)"
# The burial DEPTH is the property, and it is measured directly below from the
# payment tx's own confirmations; the height only has to have advanced by the
# blocks this stage asked for.
[ "$HEIGHT2" -ge "$((HEIGHT_AT_PAY + CONFIRM_BLOCKS))" ] || sp_fail CONFIRM "height is ${HEIGHT2:-?}, expected at least $((HEIGHT_AT_PAY + CONFIRM_BLOCKS))"
# The payment must now be mined and buried ≥3 deep (the merchant reconcile
# credits at height ≤ tip−3). gettransaction confirmations is the exact
# measurement; the old getrawmempool inverse-check has no RPC surface here.
TX_REC2="$(sp_rpc gettransaction "\"$OPID\"")"
CONFS="$(printf '%s' "$TX_REC2" | sed -n 's/.*"confirmations":\([0-9]*\).*/\1/p')"
case "$CONFS" in
    ''|*[!0-9]*) sp_fail CONFIRM "no confirmations for payment tx after mining: $TX_REC2" ;;
esac
[ "$CONFS" -ge 3 ] || sp_fail CONFIRM "payment tx has only $CONFS confirmations after mining $CONFIRM_BLOCKS blocks — never mined: $TX_REC2"
sp_log "       height=$HEIGHT2, payment mined with $CONFS confirmations (≥3)"

# ── Stage 9: WAIT_PAID ─────────────────────────────────────────────
sp_log "[9/11] WAIT_PAID: polling app.store.purchases until the merchant credits the order (≤ ${PAID_DEADLINE}s)..."
deadline=$(( $(date +%s) + PAID_DEADLINE ))
paid=no
LAST_PURCHASE_OUT=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$SP_PID" 2>/dev/null; then
        tail -20 "$SP_DD/node.log" >&2 || true
        sp_fail WAIT_PAID "node died while waiting for payment credit"
    fi
    LAST_PURCHASE_OUT="$(sp_cli app store purchases --input="{\"purchase_id\":$PURCHASE_ID}")"
    if str_contains "$LAST_PURCHASE_OUT" '"ready_to_collect":true'; then
        paid=yes
        break
    fi
    sleep 5
done
[ "$paid" = "yes" ] || { tail -12 "$SP_DD/node.log" >&2 || true; sp_fail WAIT_PAID "purchase never became ready_to_collect within ${PAID_DEADLINE}s: $LAST_PURCHASE_OUT"; }
CONFIRMED_ZAT="$(sp_json_int "$LAST_PURCHASE_OUT" confirmed_zatoshi)"
STAGE="$(sp_json_str "$LAST_PURCHASE_OUT" stage)"
case "$CONFIRMED_ZAT" in
    ''|*[!0-9]*) sp_fail WAIT_PAID "no confirmed_zatoshi in reply: $LAST_PURCHASE_OUT" ;;
esac
[ "$CONFIRMED_ZAT" -ge "$PRICE_ZAT" ] || sp_fail WAIT_PAID "confirmed_zatoshi=$CONFIRMED_ZAT < $PRICE_ZAT"
sp_log "       stage=$STAGE confirmed_zatoshi=$CONFIRMED_ZAT ready_to_collect=true"

# ── Stage 9.5: MINT_CONFIRM ─────────────────────────────────────────
# ready_to_collect means the merchant's payment sweep broadcast the access
# token MINT; it does NOT mean that mint is confirmed. The token gate reads
# the chain-derived zslp_ledger, which only counts a mint once the block
# carrying it is connected — so mine the mint in, then let the ledger fold
# it. Without this, COLLECT raced the mempool and the gate correctly (but
# unhelpfully) answered 0.
sp_log "[9.5/11] MINT_CONFIRM: mining 3 blocks so the access-token mint confirms..."
HEIGHT3="$(sp_blockcount)"
case "$HEIGHT3" in
    ''|*[!0-9]*) sp_fail MINT_CONFIRM "getblockcount silent before mint-confirm mining" ;;
esac
sp_mine_to "$((HEIGHT3 + 3))" MINT_CONFIRM

# ── Stage 10: COLLECT ───────────────────────────────────────────────
sp_log "[10/11] COLLECT: downloading through the token gate (verify-before-write)..."
# The ledger fold is asynchronous to the block connection (live tip hook /
# backfill cursor), so the first collect can still beat the projection by a
# beat. Bounded retry — HEIGHT over TIME is the verdict, same posture as
# WAIT_PAID.
COLLECT_OUT=""
collect_ok=no
deadline=$(( $(date +%s) + 150 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$SP_PID" 2>/dev/null; then
        tail -20 "$SP_DD/node.log" >&2 || true
        sp_fail COLLECT "node died while waiting for the token gate"
    fi
    COLLECT_OUT="$(sp_cli app store collect --input="{\"purchase_id\":$PURCHASE_ID,\"output_path\":\"$DELIVERED\"}")"
    if str_contains "$COLLECT_OUT" '"ok":true'; then
        collect_ok=yes
        break
    fi
    sleep 10
done
[ "$collect_ok" = "yes" ] || sp_fail COLLECT "token gate never served after mint-confirm mining + 150s: $COLLECT_OUT"
str_contains "$COLLECT_OUT" '"hash_verified":true' || sp_fail COLLECT "hash_verified is not true: $COLLECT_OUT"
GOT_BYTES="$(sp_json_int "$COLLECT_OUT" bytes)"
GOT_HASH="$(sp_json_str "$COLLECT_OUT" content_hash)"
[ "$GOT_BYTES" = "$BLOB_BYTES" ] || sp_fail COLLECT "delivered ${GOT_BYTES:-?} bytes, expected $BLOB_BYTES"
[ "$GOT_HASH" = "$CONTENT_HASH" ] || sp_fail COLLECT "delivered hash ${GOT_HASH:-?} != product hash $CONTENT_HASH"
[ -f "$DELIVERED" ] || sp_fail COLLECT "collect reported success but $DELIVERED does not exist"
sp_log "       delivered $GOT_BYTES bytes, sha3-256=$GOT_HASH hash_verified=true"

# ── Stage 11: BYTES (byte-identical, NULs and all) ─────────────────
sp_log "[11/11] BYTES: cmp delivered file against the original blob..."
cmp "$BLOB" "$DELIVERED" || sp_fail BYTES "delivered bytes differ from the original blob"
sp_log "       byte-identical: $BLOB_BYTES bytes including embedded NULs"

# ── Verdict ────────────────────────────────────────────────────────
sp_log "evidence: product_id=$PRODUCT_ID purchase_id=$PURCHASE_ID order_id=$ORDER_ID txid=$OPID"
sp_log "evidence: paid ${AMOUNT_ZAT}zat shielded (t→z, memo=$MEMO), delivered ${GOT_BYTES}B sha3-256=$GOT_HASH"
sp_log "VERDICT=PASS"
exit 0
