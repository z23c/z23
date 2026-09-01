#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# store_sell_operator_proof.sh — MVP criterion #5 "rung A" OPERATOR proof:
# a full-binary, real-chain, single-node regtest run of
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
#   1.  SPAWN        isolated regtest node (fresh mktemp datadir, 391xx ports,
#                    dead -connect sink, no Tor, no legacy import,
#                    -regtestshielded so Overwinter+Sapling are active —
#                    regtest otherwise pins them NO_ACTIVATION and no shielded
#                    tx can ever enter its mempool).
#   2.  FUND         getnewaddress + generatetoaddress past COINBASE_MATURITY
#                    (100) so the wallet holds spendable transparent coinbase,
#                    plus one z_getnewaddress so the merchant Sapling keystore
#                    is seeded (order minting refuses an unseeded keystore).
#   3.  TOKEN_GENESIS app.tokens.create plan → confirm:true → real ZSLP
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
#   - /tmp-only datadir (mktemp -d under /tmp/zcl23-storeproof-*), re-asserted
#     under /tmp before rm -rf; kept instead when ZCL_STOREPROOF_KEEP=1.
#   - 391xx isolation ports ONLY; every chosen port is checked against the
#     live refuse-set AND ss(8)-LISTEN-probed before spawn.
#   - Node spawned under setsid → its OWN process group; cleanup kill -KILLs
#     the whole GROUP (no orphan survives a harness crash).
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

# Isolation port quad (two_node uses 39070/39080, iso env defaults 39030).
SP_PORT=39110; SP_RPC=39111; SP_FS=39112; SP_HTTPS=39113
DEAD_SINK=39999

# ── State ──────────────────────────────────────────────────────────
SP_DD=""
SP_PID=""
SP_PGID=""
SP_CLEANED=0
SP_KEEP="${ZCL_STOREPROOF_KEEP:-0}"

sp_log()  { echo "store-sell-operator-proof: $*"; }
sp_skip() { sp_log "VERDICT=SKIP reason=$*"; exit 0; }
sp_fail() {
    sp_log "FAIL stage=$1: $2"
    sp_log "VERDICT=FAIL stage=$1"
    exit 1
}

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

# ── Cleanup: kill the process group + rm the /tmp datadir ──────────
sp_cleanup() {
    [ "$SP_CLEANED" = "1" ] && return 0
    SP_CLEANED=1
    if [ -n "$SP_PGID" ]; then
        kill -TERM "-$SP_PGID" 2>/dev/null || true
        local i
        for i in $(seq 1 25); do
            kill -0 "-$SP_PGID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "-$SP_PGID" 2>/dev/null || true
    fi
    # Belt-and-suspenders: only ever matches our throwaway datadir string.
    [ -n "$SP_DD" ] && pkill -KILL -f -- "-datadir=$SP_DD" 2>/dev/null || true
    if [ -n "$SP_DD" ] && [ -d "$SP_DD" ]; then
        if [ "$SP_KEEP" = "1" ]; then
            sp_log "KEEP=1: datadir preserved at $SP_DD"
        else
            case "$SP_DD" in
                /tmp/zcl23-storeproof-*) rm -rf "$SP_DD" 2>/dev/null || true ;;
                *) sp_log "WARN: refusing to rm non-/tmp datadir '$SP_DD'" >&2 ;;
            esac
        fi
    fi
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
    out="$(ZCL_DATADIR="$SP_DD" ZCL_RPCPORT="$SP_RPC" "$NODE_BIN" "$@" 2>&1)" || true
    printf '%s\n' "$out" | grep '^{' | tail -1 || true
}
sp_json_int() { printf '%s' "$1" | sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p"; }
sp_json_str() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

sp_blockcount() {
    sp_rpc getblockcount | sed -n 's/.*"result"[: ]*\([0-9-]*\).*/\1/p'
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

for p in "$SP_PORT" "$SP_RPC" "$SP_FS" "$SP_HTTPS" "$DEAD_SINK"; do
    sp_assert_not_live_port "$p"
done

SP_DD="$(mktemp -d /tmp/zcl23-storeproof-XXXXXX)" || { sp_log "FATAL: mktemp failed" >&2; exit 2; }
case "$SP_DD" in
    /tmp/zcl23-storeproof-*) : ;;
    *) sp_log "FATAL: bad datadir $SP_DD" >&2; exit 2 ;;
esac
if [ -n "${HOME:-}" ]; then
    case "$SP_DD" in
        "$HOME"/.zclassic-c23*) sp_log "FATAL: datadir under live tree — refusing" >&2; exit 2 ;;
    esac
fi

# Arm the cleanup trap BEFORE any abortable post-mint step.
trap sp_cleanup EXIT INT TERM

for p in "$SP_PORT" "$SP_RPC" "$SP_FS" "$SP_HTTPS"; do
    sp_assert_port_free "$p"
done

sp_log "datadir=$SP_DD ports{p2p=$SP_PORT rpc=$SP_RPC fs=$SP_FS https=$SP_HTTPS} sink=$DEAD_SINK"

# ── Stage 1: SPAWN ─────────────────────────────────────────────────
sp_log "[1/11] SPAWN: booting isolated regtest node..."
setsid "$NODE_BIN" \
    -datadir="$SP_DD" -regtest -regtestshielded \
    -port="$SP_PORT" -rpcport="$SP_RPC" -fsport="$SP_FS" -httpsport="$SP_HTTPS" \
    -connect=127.0.0.1:"$DEAD_SINK" \
    -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
    >"$SP_DD/node.log" 2>&1 &
SP_PID=$!
SP_PGID="$SP_PID"   # setsid leader: PGID == PID

deadline=$(( $(date +%s) + RPC_WARMUP ))
ready=no
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$SP_PID" 2>/dev/null; then
        tail -20 "$SP_DD/node.log" >&2 || true
        sp_fail SPAWN "node exited during RPC warmup (see $SP_DD/node.log)"
    fi
    if [ -f "$SP_DD/.cookie" ]; then
        t="$(sp_blockcount)"
        [ -n "$t" ] && { ready=yes; break; }
    fi
    sleep 0.5
done
[ "$ready" = "yes" ] || { tail -20 "$SP_DD/node.log" >&2 || true; sp_fail SPAWN "RPC never came up within ${RPC_WARMUP}s"; }
sp_log "       node up (pid $SP_PID), chain height $(sp_blockcount)"

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
    local target="$1" stage="$2" h n out h2 attempt stall
    h="$(sp_blockcount)"
    [ -n "$h" ] || sp_fail "$stage" "getblockcount silent"
    stall=0
    while [ "$h" -lt "$target" ]; do
        n=$(( target - h ))
        [ "$n" -gt 20 ] && n=20
        out="$(sp_rpc generatetoaddress "$n" "\"$TADDR\"")"
        mine_err="$(printf '%s\n' "$out" | grep -E 'regtest only|not mine-blocks-on-demand' || true)"
        if [ -n "$mine_err" ]; then
            sp_skip "regtest-mining-unavailable ($(printf '%s' "$out" | head -c 200))"
        fi
        attempt=0
        while str_contains "$out" 'mint refused' && [ "$attempt" -lt 15 ]; do
            sleep 2
            attempt=$(( attempt + 1 ))
            out="$(sp_rpc generatetoaddress "$n" "\"$TADDR\"")"
        done
        if str_contains "$out" 'mint refused'; then
            sp_fail "$stage" "mint refused persisted across $attempt retries (a fresh self-mined node must read sovereign): $(printf '%s' "$out" | head -c 200)"
        fi
        h2="$(sp_blockcount)"
        if [ -z "$h2" ]; then
            sp_fail "$stage" "getblockcount silent mid-mining at height $h (target $target)"
        fi
        if [ "$h2" -le "$h" ]; then
            # No progress THIS poll. Not yet a failure: an empty body means
            # the curl side of zcl-rpc gave up at --max-time 30 while the
            # server may still be working (mining the batch behind the
            # catchup lean-index/wallet scan), and a slow getblockcount can
            # just be the same lock contention. HEIGHT over TIME is the
            # verdict: fail only after a sustained no-progress window
            # (12 polls x 5 s = 60 s of a frozen tip is never a transient).
            stall=$(( stall + 1 ))
            [ "$stall" -lt 12 ] || sp_fail "$stage" "chain tip frozen at height $h2 for $(( stall * 5 ))s (target $target): $(printf '%s' "$out" | head -c 200)"
            sleep 5
            continue
        fi
        stall=0
        h="$h2"
    done
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
[ "$HEIGHT" = "$MATURE_BLOCKS" ] || sp_fail FUND "height is ${HEIGHT:-?}, expected $MATURE_BLOCKS"
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

# ── Stage 3: TOKEN_GENESIS (real ZSLP GENESIS on-chain) ────────────
sp_log "[3/11] TOKEN_GENESIS: creating the $TOKEN_TICKER access token on-chain (plan → commit)..."
TOKEN_PLAN="$(sp_cli app tokens create --input="{\"ticker\":\"$TOKEN_TICKER\",\"name\":\"Operator Proof Token\",\"decimals\":0,\"supply\":1000}")"
str_contains "$TOKEN_PLAN" '"stage":"plan"' || sp_fail TOKEN_GENESIS "create did not answer a plan: $TOKEN_PLAN"
TOKEN_OUT="$(sp_cli app tokens create --input="{\"ticker\":\"$TOKEN_TICKER\",\"name\":\"Operator Proof Token\",\"decimals\":0,\"supply\":1000,\"confirm\":true}")"
str_contains "$TOKEN_OUT" '"ok":true' || sp_fail TOKEN_GENESIS "$TOKEN_OUT"
TOKEN_ID="$(sp_json_str "$TOKEN_OUT" token_id)"
case "$TOKEN_ID" in
    ????????????????????????????????????????????????????????????????) : ;;
    *) sp_fail TOKEN_GENESIS "token_id '${TOKEN_ID:-?}' is not 64 chars: $TOKEN_OUT" ;;
esac
case "$TOKEN_ID" in
    *[!0-9a-fA-F]*) sp_fail TOKEN_GENESIS "token_id '$TOKEN_ID' is not hex: $TOKEN_OUT" ;;
esac
sp_mine_to "$((MATURE_BLOCKS + TOKEN_CONFS))" TOKEN_GENESIS
TOK_LIST="$(sp_cli app tokens list)"
# app.tokens.create answers the token_id lowercase; the index renders it
# uppercase — same 32 bytes, so the membership check is case-insensitive.
tok_hit="$(printf '%s\n' "$TOK_LIST" | grep -i "$TOKEN_ID" || true)"
[ -n "$tok_hit" ] || sp_fail TOKEN_GENESIS "token $TOKEN_ID not indexed after $TOKEN_CONFS confirmations: $TOK_LIST"
sp_log "       token_id=${TOKEN_ID:0:16}... confirmed at height $(sp_blockcount), indexed"

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
sp_mine_to "$((MATURE_BLOCKS + TOKEN_CONFS + CONFIRM_BLOCKS))" CONFIRM
HEIGHT2="$(sp_blockcount)"
[ "$HEIGHT2" = "$((MATURE_BLOCKS + TOKEN_CONFS + CONFIRM_BLOCKS))" ] || sp_fail CONFIRM "height is ${HEIGHT2:-?}, expected $((MATURE_BLOCKS + TOKEN_CONFS + CONFIRM_BLOCKS))"
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
