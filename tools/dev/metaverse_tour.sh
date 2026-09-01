#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# metaverse_tour.sh — the hermetic five-step "metaverse tour" proof
# (docs/METAVERSE_MVP.md criterion MM1). Drives ONE isolated regtest node
# (unique /tmp datadir, 39xxx non-live ports, dead-sink -connect, armed by
# tools/scripts/isolated_node_env.sh) through:
#
#   1. publish a small package to the local CAS
#      (zcode package publish plan|commit over a fixture built by
#      tools/metaverse_tour_fixture.c, compiled at runtime the same way
#      tools/dev/zcode_dht_acceptance.sh builds its peer helper)
#   2. metaverse space plan|commit|show — a signed space manifest
#   3. metaverse space scout plan|run|show — a bounded read-only mission
#      over the manifest committed in step 2
#   4. zcode commons status — the Living Commons projection answers
#   5. metaverse property list — the property catalog answers
#
# Exits 0 only when every step's typed output confirms success; prints
# `metaverse-tour: PASS` (exit 0) or `metaverse-tour: FAIL <step>` (exit 1).
#
# Isolation: the node is spawned by isolated_node_env.sh — it can never
# touch the live datadir, a live port, or the live units; the cleanup
# trap kills the process group and removes the /tmp datadir.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"
cd "$REPO_ROOT"

# ── Isolation setup (the audited chokepoint owns the cleanup trap) ────
ISO_KIND="metaverse-tour"
ISO_PORT_BASE="${METAVERSE_TOUR_PORT_BASE:-39470}"
# shellcheck source=../scripts/isolated_node_env.sh
. "$REPO_ROOT/tools/scripts/isolated_node_env.sh"

TOUR_STEP="setup"
tour_fail() {
    echo "metaverse-tour: FAIL $TOUR_STEP: $*" >&2
    # The isolation trap deletes the datadir on exit — capture the node's
    # own account of the stall first: the boot ledger (wallet_utxos rebuild,
    # staged refold, coins_kv stamps) AND the tail (the immediate cause).
    if [ -f "$ISO_DD/node.log" ]; then
        grep -aE "Wallet:|wallet_utxos|refold|coins_kv|Rescan|rescan|staged" \
            "$ISO_DD/node.log" | tail -20 >&2 || true
        tail -20 "$ISO_DD/node.log" >&2 || true
    fi
    exit 1
}
tour_note() { echo "metaverse-tour: $*"; }
tour_pass() { echo "metaverse-tour: PASS step $1 — $2"; }

# JSON helpers (jsonq over nested RPC and native-command envelopes).
tour_jget() { "$JSONQ" get "$1"; }
tour_native() {
    # The CLI exits nonzero on a typed failure reply; under `set -o pipefail`
    # that would kill the script before the reply body is asserted. Swallow
    # the exit code here — tour_assert_ok reads ok/error from the JSON.
    "$ISO_NODE_BIN" -datadir="$ISO_DD" -rpcport="$ISO_RPCPORT" "$@" 2>/dev/null | tail -1 || true
}
tour_assert_ok() {
    # $1 = raw reply, $2 = human label; prints nothing on success.
    local out="$1" label="$2"
    local ok
    ok="$(printf '%s' "$out" | "$JSONQ" get ok 2>/dev/null || echo unparseable)"
    [ "$ok" = "true" ] || tour_fail "$label refused: $out"
}
tour_result() { "$JSONQ" unwrap; }

# ── Fixture helper (built at runtime, never installed) ────────────────
tour_build_helper() {
    local out="$1" incs d
    incs=""
    for d in "$REPO_ROOT"/lib/*/include "$REPO_ROOT"/domain/*/include \
             "$REPO_ROOT"/core/*/include "$REPO_ROOT"/ports/include \
             "$REPO_ROOT"/vendor/include; do
        [ -d "$d" ] && incs="$incs -I$d"
    done
    # shellcheck disable=SC2086
    cc -std=c23 -O1 -w -D_GNU_SOURCE -ffunction-sections -fdata-sections \
        -Wl,--gc-sections $incs -o "$out" \
        "$REPO_ROOT/tools/metaverse_tour_fixture.c" \
        "$REPO_ROOT/core/modules/crypto/src/ed25519.c" \
        "$REPO_ROOT/core/modules/crypto/src/sha512.c" \
        "$REPO_ROOT/core/modules/crypto/src/sha256.c" \
        "$REPO_ROOT/core/modules/crypto/src/hmac_sha512.c" \
        "$REPO_ROOT/core/modules/crypto/src/hmac_sha256.c" \
        "$REPO_ROOT/core/modules/crypto/src/random_secret.c" \
        "$REPO_ROOT/platform/modules/base/src/cleanse.c" \
        "$REPO_ROOT/platform/modules/base/src/safe_alloc.c" \
        "$REPO_ROOT/platform/modules/base/src/log_level.c" \
        "$REPO_ROOT/platform/modules/base/src/result.c" \
        "$REPO_ROOT/platform/modules/sha3/src/sha3.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_manifest.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_recipe.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_release.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_accept.c" \
        "$REPO_ROOT/contexts/wallet/modules/keys/src/key.c" \
        "$REPO_ROOT/contexts/wallet/modules/keys/src/key_io.c" \
        "$REPO_ROOT/contexts/wallet/modules/keys/src/pubkey.c" \
        "$REPO_ROOT/contexts/wallet/modules/keys/src/secp256k1_compat.c" \
        "$REPO_ROOT/core/chainparams/src/chainparams.c" \
        "$REPO_ROOT/core/chainparams/src/chainparamsbase.c" \
        "$REPO_ROOT/core/consensus/src/upgrades.c" \
        "$REPO_ROOT/core/math/src/hash.c" \
        "$REPO_ROOT/core/math/src/uint256.c" \
        "$REPO_ROOT/core/math/src/arith_uint256.c" \
        "$REPO_ROOT/core/math/src/core_io.c" \
        "$REPO_ROOT/core/math/src/serialize.c" \
        "$REPO_ROOT/core/modules/core/src/random.c" \
        "$REPO_ROOT/core/modules/core/src/utiltime.c" \
        "$REPO_ROOT/platform/modules/encoding/src/utilstrencodings.c" \
        "$REPO_ROOT/platform/domain/encoding/src/base58.c" \
        "$REPO_ROOT/platform/modules/codec/src/cursor.c" \
        "$REPO_ROOT/platform/modules/platform/src/rng.c" \
        "$REPO_ROOT/platform/modules/platform/src/clock.c" \
        -L"$REPO_ROOT/vendor/lib" -l:libsecp256k1.a -lpthread -lm ||
        tour_fail "fixture helper compile failed"
}

# The regtest miner stamps blocks from whole-second wall time; more than
# six consecutive blocks with one timestamp breaks the 11-block MTP on
# restart, so mine in groups of five with a wall-clock step (the
# zcode_dht_acceptance.sh convention).
tour_mine_to_address() {
    local count="$1" address="$2" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        iso_rpc generatetoaddress "$chunk" "\"$address\"" | tour_result >/dev/null \
            || tour_fail "generatetoaddress $chunk failed"
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}
tour_mine_empty() {
    local count="$1" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        iso_rpc generate "$chunk" | tour_result >/dev/null \
            || tour_fail "generate $chunk failed"
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}

# The money gate behind overlay intents (wallet_money_snapshot_build)
# reads the REDUCER pipeline, not the active chain: it requires the
# authoritative coins tip AND H* (the provable fold edge) at the chain
# tip. generatetoaddress returns after connection, but utxo_apply /
# tip_finalize lag it asynchronously, so poll dumpstate reducer_frontier
# until both reach the mined height (or fail with a named blocker).
tour_wait_fold() {
    local tip="$1" tries=0 dump coins hstar
    while [ "$tries" -lt 90 ]; do
        dump="$(tour_native dumpstate reducer_frontier)"
        coins="$(printf '%s' "$dump" \
            | tour_jget state.coins_best_height 2>/dev/null)" \
            || coins=""
        hstar="$(printf '%s' "$dump" \
            | tour_jget state.hstar 2>/dev/null)" \
            || hstar=""
        [ "$coins" = "$tip" ] && [ "$hstar" = "$tip" ] && return 0
        tries=$((tries + 1))
        sleep 1
    done
    # A stall is always a named blocker — surface it (and the reducer's own
    # log tail) before the isolation trap deletes the datadir.
    echo "metaverse-tour: reducer_frontier at stall: $dump" >&2
    tail -30 "$ISO_DD/node.log" >&2 || true
    tour_fail "reducer fold did not reach tip $tip (coins_best_height=$coins hstar=$hstar)"
}

# iso_wait_rpc_ready returns as soon as getblockcount answers — but that
# serves the provable-tip CACHE, not the active chain index. Right after a
# restart the RPC is up while the chain index is still loading, and the ZID
# anchor's runtime gate (active_chain_tip() == NULL) ships a causeless
# {"result":null,"error":null}. getblockchaininfo exposes the difference: it
# pushes the IBD-shaped object (initialblockdownload=true) until the H* slot
# resolves inside the loaded active chain. Poll until the loaded object
# reports the expected height (or fail with a named blocker).
tour_wait_chain_loaded() {
    local tip="$1" tries=0 info blocks ibd
    while [ "$tries" -lt 90 ]; do
        info="$(iso_rpc getblockchaininfo 2>/dev/null)" || info=""
        blocks="$(printf '%s' "$info" | "$JSONQ" get result.blocks 2>/dev/null || true)"
        ibd="$(printf '%s' "$info" | "$JSONQ" get result.initialblockdownload 2>/dev/null || true)"
        [ "$blocks" = "$tip" ] && [ "$ibd" != "true" ] && [ -n "$blocks" ] && return 0
        tries=$((tries + 1))
        sleep 1
    done
    tour_fail "active chain index did not load tip $tip (last getblockchaininfo: $info)"
}

# Stop the isolated node (TERM, then KILL the process group — the same
# discipline as the env's cleanup trap) and boot it again on the same
# datadir. Needed once after the first mine: the coins_kv authority stamps
# (coins_kv_boot_rebuild_if_needed: migration-complete + self-folded for a
# populated, unstamped — therefore self-derived — fold) land at BOOT, so
# only a restart after the fold recognises the node's own coins as the
# canonical, self-derived authority the wallet money gate and the
# sovereignty spend gate both demand.
tour_restart_node() {
    local extras="$1"
    kill -TERM "-$ISO_PGID" 2>/dev/null || true
    # Grace window matters: a KILLed primary reboots into the staged refold
    # (projections wiped, re-folded asynchronously), and the boot-time
    # wallet_utxos rebuild then races the refold and can JOIN an empty
    # utxos projection — leaving the vault spendable at 0 forever (the
    # anchor's fee-reserve rung fails closed on it). A clean TERM shutdown
    # keeps the projections intact, so wait generously before escalating.
    local tries=0
    while [ "$tries" -lt 120 ]; do
        kill -0 "-$ISO_PGID" 2>/dev/null || break
        tries=$((tries + 1))
        sleep 0.5
    done
    kill -KILL "-$ISO_PGID" 2>/dev/null || true
    iso_spawn_node "$extras"
    iso_wait_rpc_ready 90 || tour_fail "node restart warmup (see $ISO_DD/node.log)"
}

# The money freshness classifier also demands a live catch-up sync state
# (blocks_download / connecting_blocks / at_tip); right after a restart the
# node sits in finding_peers until the sync monitor notices the peer. Poll
# the downloadstats RPC until the state machine moves.
tour_wait_sync_live() {
    local tries=0 state
    while [ "$tries" -lt 90 ]; do
        state="$(iso_rpc downloadstats \
            | tour_jget result.sync_state 2>/dev/null)" || state=""
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        tries=$((tries + 1))
        sleep 1
    done
    tour_fail "sync state never left finding_peers (state=$state)"
}

# The fee-reserve rung (custody allocation) reads the vault read model's
# zcl_spendable; post-restart that projection lags the reducer fold while
# the wallet re-derives its spendable coins. Poll dumpstate vault — the
# same read model the gate uses — until spendable is positive (any
# positive covers maximum_fee_zat + the dev reserve on this chain).
tour_wait_spendable() {
    local tries=0 dump spend
    while [ "$tries" -lt 90 ]; do
        dump="$(tour_native dumpstate vault)"
        spend="$(printf '%s' "$dump" \
            | tour_jget state.zcl.spendable 2>/dev/null)" \
            || spend=""
        [ -n "$spend" ] && [ "$spend" -gt 0 ] && return 0
        tries=$((tries + 1))
        sleep 1
    done
    echo "metaverse-tour: vault at stall: $dump" >&2
    tour_fail "vault spendable never became positive (spendable=$spend)"
}

# One sovereignty-policy allow rule (plan then exact-token commit).
tour_policy_allow() {
    local service_type="$1" plan token commit
    plan="$(tour_native zcode network policy mutate \
        --input="{\"mode\":\"plan\",\"operation\":\"add\",\"source\":\"local\",\"effect\":\"allow\",\"scope\":\"service_type\",\"action_mask\":63,\"value\":\"$service_type\"}")"
    tour_assert_ok "$plan" "policy plan $service_type"
    token="$(printf '%s' "$plan" | tour_jget data.plan_token)" \
        || tour_fail "policy plan $service_type has no plan_token"
    commit="$(tour_native zcode network policy mutate \
        --input="{\"mode\":\"commit\",\"operation\":\"add\",\"source\":\"local\",\"effect\":\"allow\",\"scope\":\"service_type\",\"action_mask\":63,\"value\":\"$service_type\",\"plan_token\":\"$token\"}")"
    tour_assert_ok "$commit" "policy commit $service_type"
    [ "$(printf '%s' "$commit" | tour_jget data.committed)" = "true" ] \
        || tour_fail "policy commit $service_type did not commit: $commit"
}

command -v cc >/dev/null 2>&1 || tour_fail "cc not found"
[ -x "$JSONQ" ] || tour_fail "build/bin/jsonq is missing — run make jsonq"

iso_init
TOUR_WORK="$ISO_DD/tour"
mkdir -p "$TOUR_WORK"
tour_note "building the package/identity fixture helper"
tour_build_helper "$TOUR_WORK/mtour-fixture"

# Wallet custody: the ZID anchor's overlay-intent gate requires the wallet
# encrypted at rest, unlocked, and covered by a current-key encrypted
# backup. Boot with a passphrase credential so key writes encrypt (WKS1);
# the backup itself happens after mining below, once the spend key exists.
tour_note "booting the isolated regtest node"
TOUR_CRED_DIR="$TOUR_WORK/cred"
install -d -m 700 "$TOUR_CRED_DIR"
install -m 600 /dev/null "$TOUR_CRED_DIR/wallet-passphrase"
printf '%s\n' "metaverse-tour-wallet-pass" >"$TOUR_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$TOUR_CRED_DIR"
iso_spawn_node "-operator-lane=dev -wallet-no-phrase-backup -packagehost=0"
iso_wait_rpc_ready 90 || tour_fail "isolated node RPC warmup (see $ISO_DD/node.log)"

# The wallet money-freshness classifier fails closed to UNKNOWN on a
# zero-peer node (peer_count == 0), so the ZID anchor's money gate can
# never pass against the dead-sink-only primary. Spawn the optional peer
# node: it dials the primary over the same isolated -connect lane, giving
# the primary one real connected peer while the pair stays a closed
# two-node loop inside the same /tmp datadir tree.
tour_note "spawning the isolated peer node (money gate needs a real peer)"
iso_spawn_peer "-operator-lane=dev -wallet-no-phrase-backup -packagehost=0"
iso_wait_peer_connected 60 \
    || tour_fail "peer node never connected (see $ISO_DD/peer/node.log)"

tour_note "mining spendable regtest funds"
ADDR="$(iso_rpc getnewaddress | tour_result)" \
    || tour_fail "getnewaddress failed"
tour_mine_to_address 101 "$ADDR"
tour_wait_fold 101
# The money gate needs the PRIMARY to hold an OUTBOUND peer (the sync FSM
# only leaves finding_peers behind a peer it can sync FROM —
# syncsvc_begin_peer_sync refuses inbound nodes), and
# connman_open_connection skips an already-connected address. So the peer
# must NOT be dialling the primary when the primary dials it. Bounce the
# peer FIRST with its -connect aimed at the dead sink (ISO_PEER_DIAL): the
# pair's only post-restart link is the primary's outbound onetry below —
# deterministic, no already-connected skip, no redial-backoff wait (the
# peer's own redial was measured >60s).
tour_note "bouncing the peer node onto the dead sink (primary will own the link)"
kill -TERM "-$ISO_PEER_PGID" 2>/dev/null || true
_tries=0
while [ "$_tries" -lt 20 ]; do
    kill -0 "-$ISO_PEER_PGID" 2>/dev/null || break
    _tries=$((_tries + 1))
    sleep 0.5
done
kill -KILL "-$ISO_PEER_PGID" 2>/dev/null || true
ISO_PEER_PGID=""
ISO_PEER_PID=""
ISO_PEER_DIAL="$ISO_CONNECT_SINK"
iso_spawn_peer "-operator-lane=dev -wallet-no-phrase-backup -packagehost=0"
iso_wait_peer_listen 60 \
    || tour_fail "peer node never listened after bounce (see $ISO_DD/peer/node.log)"
tour_note "restarting so the forward-folded coins set stamps its authority"
tour_restart_node "-operator-lane=dev -wallet-no-phrase-backup -packagehost=0"
tour_wait_fold 101
# Direct outbound onetry: an operator dial, so it bypasses the
# reachable-port policy (core/modules/net/include/net/port_policy.h) and lands
# immediately — the peer is up, listening, and not connected to us.
iso_rpc addnode "\"127.0.0.1:$ISO_PEER_PORT\"" "\"onetry\"" >/dev/null || true
iso_wait_peer_connected 60 \
    || tour_fail "primary never connected outbound to the peer (see $ISO_DD/node.log)"
tour_wait_sync_live

# RPC-ready ≠ chain-loaded: the ZID anchor's runtime gate needs the active
# chain index (active_chain_tip()), which loads after the RPC starts serving.
tour_wait_chain_loaded 101

# The restart re-locks the encrypted-at-rest wallet: the boot passphrase
# credential arms key WRITES, it does not leave decrypted keys resident, and
# the anchor's funding-input build draws from the key pool — which a locked
# wallet refuses (wallet_get_key_from_pool). Unlock explicitly (passphrase
# via --input=- only, maximum timeout) unless the wallet is already unlocked.
tour_note "unlocking the wallet for the anchor's key-pool draw"
LOCKSTATUS="$(tour_native core wallet security status)"
tour_assert_ok "$LOCKSTATUS" "core wallet security status"
if [ "$(printf '%s' "$LOCKSTATUS" | tour_jget data.unlocked)" != "true" ]; then
    UNLOCK="$(printf '%s' '{"passphrase":"metaverse-tour-wallet-pass","timeout_seconds":3600}' \
        | tour_native core wallet security unlock --input=-)"
    tour_assert_ok "$UNLOCK" "core wallet security unlock"
    [ "$(printf '%s' "$UNLOCK" | tour_jget data.unlocked)" = "true" ] \
        || tour_fail "wallet did not unlock: $UNLOCK"
fi

# The keypool's persisted bookkeeping is RAM-only: after the restart the
# pool is empty until the next top-up (only the fresh-create boot and the
# address RPCs re-persist it). One getnewaddress re-tops and re-persists
# the pool the ZID tx build draws its owner/change key from
# (build_genesis_base_tx -> wallet_get_key_from_pool).
iso_rpc getnewaddress | tour_result >/dev/null \
    || tour_fail "post-restart keypool top-up failed"

tour_note "taking the encrypted wallet backup (custody gate)"
# AFTER getnewaddress: the intent gate demands a CURRENT-KEY backup, so the
# backup must cover the key the miner/anchor will spend from. The handler
# refuses an inline password (STDIN_REQUIRED): it is accepted only through
# --input=- so it never lands in argv / shell history.
BACKUP="$(printf '%s' '{"confirm":true,"password":"metaverse-tour-backup-pass"}' \
    | tour_native core wallet backup now --input=-)"
tour_assert_ok "$BACKUP" "core wallet backup now"

SEED=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
install -m 600 /dev/null "$TOUR_WORK/master.hex"
printf '%s\n' "$SEED" >"$TOUR_WORK/master.hex"
PUB="$("$TOUR_WORK/mtour-fixture" pubkey "$SEED")" \
    || tour_fail "fixture pubkey derivation failed"

tour_note "anchoring the tour ZID master on-chain"
# The intent's fee-reserve rung reads confirmed_zat = vault zcl_spendable
# (overlay_transaction_intent_service.c → vault_read_snapshot). Post-restart
# the wallet's spendable projection lags the reducer fold while the wallet
# re-derives its coins, and the reserve refuses until it is positive. Poll
# the SAME read model (dumpstate vault) instead of guessing.
tour_wait_spendable
# Retry only OVERLAY_INTENT_REFUSED (transient money-currency skew between
# the reducer fold, H*, and the peer reconnect); the idempotency key makes
# a repeated plan safe. Any other verdict fails immediately.
ANCHOR_PLAN=""
for _try in $(seq 1 20); do
    ANCHOR_PLAN="$(tour_native core identity anchor \
        --input="{\"wallet_scope\":\"dev\",\"pubkey\":\"$PUB\",\"idempotency_key\":\"metaverse-tour-anchor-1\"}")"
    case "$ANCHOR_PLAN" in
        *OVERLAY_INTENT_REFUSED*) sleep 1 ;;
        *) break ;;
    esac
done
tour_assert_ok "$ANCHOR_PLAN" "core identity anchor plan"
[ "$(printf '%s' "$ANCHOR_PLAN" | tour_jget data.stage)" = "plan" ] \
    || tour_fail "anchor did not plan: $ANCHOR_PLAN"
ANCHOR_PLAN_ID="$(printf '%s' "$ANCHOR_PLAN" | tour_jget data.plan_id)" \
    || tour_fail "anchor plan has no plan_id"
ANCHOR="$(tour_native core identity anchor \
    --input="{\"wallet_scope\":\"dev\",\"plan_id\":\"$ANCHOR_PLAN_ID\",\"confirm\":true}")"
tour_assert_ok "$ANCHOR" "core identity anchor commit"
[ "$(printf '%s' "$ANCHOR" | tour_jget data.stage)" = "committed" ] &&
[ "$(printf '%s' "$ANCHOR" | tour_jget data.committed)" = "true" ] \
    || tour_fail "anchor did not commit: $ANCHOR"
# zcode network delegate requires the anchor's finality-delayed beacon
# (anchor_height + ZCL_FINALITY_DEPTH) to be itself ten blocks deep:
# tip >= anchor_height + 2*finality, so 21 blocks always covers it (the
# zcode_dht_acceptance.sh convention).
tour_mine_empty 21
tour_wait_fold 122

tour_note "delegating the DHT identity"
DELEGATE="$(tour_native zcode network delegate \
    --input="{\"seed_file\":\"$TOUR_WORK/master.hex\"}")"
tour_assert_ok "$DELEGATE" "zcode network delegate"
NODE_ID="$(printf '%s' "$DELEGATE" | tour_jget data.node_id)" \
    || tour_fail "delegation reply has no node_id"

# Local sovereignty policy: the default rule set allows DISCOVER only, so
# the space commit (STORE|INDEX) and the scout evidence store need exact
# service_type allows. mask 63 = DISCOVER|FETCH|STORE|INDEX|SERVE|FORWARD.
tour_note "installing exact local sovereignty allows"
tour_policy_allow "space.manifest"
tour_policy_allow "space.scout.mission"
tour_policy_allow "space.scout.evidence_map"
tour_policy_allow "space.scout.attestation"

# ── Step 1: publish a small package to the local CAS ──────────────────
TOUR_STEP="1 package publish"
PKG_DIR="$TOUR_WORK/pkg"
FIXTURE="$("$TOUR_WORK/mtour-fixture" fixture "$PKG_DIR" \
    "tour/ring-buffer" "MIT" "5a" "1")" \
    || tour_fail "fixture build failed"
RELEASE_HEX="$(printf '%s' "$FIXTURE" | tour_jget release_hex)" \
    || tour_fail "fixture reply has no release_hex"
MANIFEST_HEX="$(printf '%s' "$FIXTURE" | tour_jget manifest_hex)" \
    || tour_fail "fixture reply has no manifest_hex"
RECIPE_HEX="$(printf '%s' "$FIXTURE" | tour_jget recipe_hex)" \
    || tour_fail "fixture reply has no recipe_hex"
PACKAGE_ROOT="$(printf '%s' "$FIXTURE" | tour_jget package_root)" \
    || tour_fail "fixture reply has no package_root"
PUB_INPUT="{\"release_hex\":\"$RELEASE_HEX\",\"manifest_hex\":\"$MANIFEST_HEX\",\"recipe_hex\":\"$RECIPE_HEX\",\"dir\":\"$PKG_DIR\"}"

PLAN1="$(tour_native zcode package publish plan --input="$PUB_INPUT")"
tour_assert_ok "$PLAN1" "zcode package publish plan"
[ "$(printf '%s' "$PLAN1" | tour_jget data.stage)" = "plan" ] &&
[ "$(printf '%s' "$PLAN1" | tour_jget data.valid)" = "true" ] \
    || tour_fail "publish plan did not validate: $PLAN1"
COMMIT1="$(tour_native zcode package publish commit --input="$PUB_INPUT")"
tour_assert_ok "$COMMIT1" "zcode package publish commit"
[ "$(printf '%s' "$COMMIT1" | tour_jget data.stage)" = "commit" ] &&
[ "$(printf '%s' "$COMMIT1" | tour_jget data.result)" = "committed" ] &&
[ "$(printf '%s' "$COMMIT1" | tour_jget data.package_root)" = "$PACKAGE_ROOT" ] \
    || tour_fail "publish commit did not commit locally: $COMMIT1"
tour_pass 1 "package tour/ring-buffer committed locally (root ${PACKAGE_ROOT:0:16}…)"

# ── Step 2: design + commit a signed space manifest ───────────────────
TOUR_STEP="2 space plan|commit|show"
# The manifest window must fit INSIDE the DHT delegation window
# (vcs_space_manifest_sign → manifest_shape: not_before >= delegation.not_before
# and expiry <= delegation.expiry). The delegation was minted seconds ago, so
# backdating not_before (e.g. NOW-60) starts the manifest BEFORE its own
# delegation existed and the signer refuses with VCS_SPACE_ERR_TIME — start at
# NOW instead. The delegation default lifetime (259200s) comfortably covers
# the +172800 expiry.
NOW="$(date +%s)"
MANIFEST_INPUT="{\"kind\":\"space_manifest\",\"sequence\":1,\"not_before\":$NOW,\"expiry\":$((NOW + 172800)),\"name\":\"tour-space\",\"description\":\"metaverse tour proof space\"}"
PLAN2="$(tour_native metaverse space plan --input="$MANIFEST_INPUT")"
tour_assert_ok "$PLAN2" "metaverse space plan"
[ "$(printf '%s' "$PLAN2" | tour_jget data.state)" = "PLANNED" ] \
    || tour_fail "space plan not PLANNED: $PLAN2"
OBJECT_ROOT="$(printf '%s' "$PLAN2" | tour_jget data.object_root)" \
    || tour_fail "space plan has no object_root"
SPACE_TOKEN="$(printf '%s' "$PLAN2" | tour_jget data.plan_token)" \
    || tour_fail "space plan has no plan_token"
COMMIT2="$(tour_native metaverse space commit \
    --input="{\"kind\":\"space_manifest\",\"sequence\":1,\"not_before\":$NOW,\"expiry\":$((NOW + 172800)),\"name\":\"tour-space\",\"description\":\"metaverse tour proof space\",\"plan_token\":\"$SPACE_TOKEN\",\"confirm\":true}")"
tour_assert_ok "$COMMIT2" "metaverse space commit"
[ "$(printf '%s' "$COMMIT2" | tour_jget data.state)" = "COMMITTED" ] &&
[ "$(printf '%s' "$COMMIT2" | tour_jget data.object_root)" = "$OBJECT_ROOT" ] \
    || tour_fail "space commit did not COMMIT the planned root: $COMMIT2"
SHOW2="$(tour_native metaverse space show --input="{\"root\":\"$OBJECT_ROOT\"}")"
tour_assert_ok "$SHOW2" "metaverse space show"
[ "$(printf '%s' "$SHOW2" | tour_jget data.signature_verified)" = "true" ] &&
[ "$(printf '%s' "$SHOW2" | tour_jget data.currently_active)" = "true" ] &&
[ "$(printf '%s' "$SHOW2" | tour_jget data.owner_zid)" = "$PUB" ] \
    || tour_fail "space show did not re-derive the signed manifest: $SHOW2"
tour_pass 2 "signed space manifest committed (root ${OBJECT_ROOT:0:16}…)"

# ── Step 3: bounded read-only scout mission over the manifest ─────────
TOUR_STEP="3 space scout plan|run|show"
SCOUT_INPUT="{\"starting_roots\":[\"$OBJECT_ROOT\"],\"observation_unix\":$NOW,\"maximum_depth\":1,\"maximum_spaces\":4,\"maximum_portals\":4,\"maximum_bytes\":65536,\"deadline_ms\":30000}"
PLAN3="$(tour_native metaverse space scout plan --input="$SCOUT_INPUT")"
tour_assert_ok "$PLAN3" "metaverse space scout plan"
[ "$(printf '%s' "$PLAN3" | tour_jget data.state)" = "PLANNED" ] &&
[ "$(printf '%s' "$PLAN3" | tour_jget data.read_only_mission)" = "true" ] \
    || tour_fail "scout plan not PLANNED: $PLAN3"
MISSION_ROOT="$(printf '%s' "$PLAN3" | tour_jget data.mission_root)" \
    || tour_fail "scout plan has no mission_root"
SCOUT_TOKEN="$(printf '%s' "$PLAN3" | tour_jget data.plan_token)" \
    || tour_fail "scout plan has no plan_token"
RUN3="$(tour_native metaverse space scout run \
    --input="{\"starting_roots\":[\"$OBJECT_ROOT\"],\"observation_unix\":$NOW,\"maximum_depth\":1,\"maximum_spaces\":4,\"maximum_portals\":4,\"maximum_bytes\":65536,\"deadline_ms\":30000,\"plan_token\":\"$SCOUT_TOKEN\",\"confirm\":true}")"
tour_assert_ok "$RUN3" "metaverse space scout run"
[ "$(printf '%s' "$RUN3" | tour_jget data.state)" = "RECORDED" ] &&
[ "$(printf '%s' "$RUN3" | tour_jget data.mission_root)" = "$MISSION_ROOT" ] \
    || tour_fail "scout run did not RECORD the planned mission: $RUN3"
ATTEST_ROOT="$(printf '%s' "$RUN3" | tour_jget data.attestation_root)" \
    || tour_fail "scout run has no attestation_root"
SHOW3="$(tour_native metaverse space scout show \
    --input="{\"root\":\"$ATTEST_ROOT\"}")"
tour_assert_ok "$SHOW3" "metaverse space scout show"
[ "$(printf '%s' "$SHOW3" | tour_jget data.signature_verified)" = "true" ] &&
[ "$(printf '%s' "$SHOW3" | tour_jget 'data.visited_spaces[0].manifest_result')" = "verified" ] &&
[ "$(printf '%s' "$SHOW3" | tour_jget 'data.visited_spaces[0].space_root')" = "$OBJECT_ROOT" ] \
    || tour_fail "scout attestation did not verify the manifest: $SHOW3"
tour_pass 3 "scout mission verified the space (attestation ${ATTEST_ROOT:0:16}…)"

# ── Step 4: the Living Commons projection answers ─────────────────────
TOUR_STEP="4 zcode commons status"
COMMONS="$(tour_native zcode commons status \
    --input="{\"workspace\":\"$ISO_DD/zcode\"}")"
tour_assert_ok "$COMMONS" "zcode commons status"
[ "$(printf '%s' "$COMMONS" | tour_jget data.structural_integrity)" = "true" ] &&
[ -n "$(printf '%s' "$COMMONS" | tour_jget data.verification_status)" ] \
    || tour_fail "commons projection did not answer: $COMMONS"
VERIFICATION="$(printf '%s' "$COMMONS" | tour_jget data.verification_status)"
tour_pass 4 "Living Commons projection answers (verification_status=$VERIFICATION)"

# ── Step 5: the property catalog answers ──────────────────────────────
TOUR_STEP="5 metaverse property list"
PROPS="$(tour_native metaverse property list)"
tour_assert_ok "$PROPS" "metaverse property list"
KINDS="$(printf '%s' "$PROPS" | tour_jget data.kinds_scanned)" \
    || tour_fail "property catalog scanned no kinds: $PROPS"
[ "$KINDS" -ge 1 ] \
    || tour_fail "property catalog scanned no kinds: $PROPS"
TOTAL="$(printf '%s' "$PROPS" | tour_jget data.total)"
tour_pass 5 "property catalog answers ($KINDS kinds scanned, $TOTAL properties)"

tour_note "node_id=$NODE_ID datadir=$ISO_DD (removed by the isolation trap)"
echo "metaverse-tour: PASS"
