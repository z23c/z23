# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# isolated_mainnet_env.sh — node isolation for a MAINNET scratch node.
#
# Sibling of isolated_node_env.sh (the regtest path). It is *sourced*
# (not executed) by the replay-canary harness (replay_canary.sh, the
# `make replay-canary-{anchor,genesis}` targets). It is the single
# audited chokepoint guaranteeing the spawned canary node can NEVER
# touch the live node, the live datadir, the read-only zclassicd
# datadir, or a live port.
#
# It does ALL of the following, in this order, before any node is spawned:
#
#   1. Mint a throwaway datadir under /tmp (mktemp -d). REFUSE if the
#      resolved path is the live datadir ($HOME/.zclassic-c23*) OR the
#      zclassicd datadir ($HOME/.zclassic*) — this harness reads the
#      zclassicd datadir read-only, so the scratch dd must never collide.
#   2. Derive an isolated 39xxx port quad (port/rpcport/fsport/httpsport)
#      plus a dead -connect sink (39999). REFUSE if any chosen port is in
#      the hardcoded live set.
#   3. ss(8) LISTEN preflight: REFUSE if ANY chosen port is already
#      bound. This ss LISTEN check is the AUTHORITATIVE collision guard.
#   4. Install an EXIT/INT/TERM cleanup trap that kills the spawned
#      node's whole PROCESS GROUP and rm -rf's the /tmp datadir (only
#      after re-asserting the datadir is under /tmp and non-empty).
#
# It then exposes the functions the harness uses:
#   iso_import_blockindex "<src-datadir>"  — one-shot header import from a
#                                            (possibly LOCKed, read-only)
#                                            source datadir into ISO_DD.
#   iso_spawn_mainnet_node "<extra args>"  — fork a MAINNET node in its
#                                            OWN process group (setsid).
#   iso_rpc <method> [params...]           — call zcl-rpc against the
#                                            ISOLATED datadir+rpcport ONLY.
#   iso_wait_rpc_ready <secs>              — poll until getblockcount answers.
#
# Contract for the sourcing script:
#   - `set -euo pipefail` is assumed; this file also sets it.
#   - Define ISO_KIND ("replay") and (optionally) ISO_PORT_BASE BEFORE
#     sourcing, then call `iso_init`.
#   - The sourcing script MUST NOT install its own conflicting EXIT trap.
#
# Differences from the regtest sibling, and ONLY these:
#   - ISO_KIND default = "replay".
#   - iso_spawn_mainnet_node spawns with NO -regtest (real mainnet
#     genesis + checkpoints). The legacy-import policy is CALLER-supplied
#     in $1, not fixed here: the from-ANCHOR variant deliberately does NOT
#     pass -nolegacyimport (it relies on boot's read-only legacy auto-import
#     of ~/.zclassic to seed the anchor UTXO set — the proven cold recipe),
#     while the from-GENESIS variant DOES pass -nolegacyimport so boot does
#     not seed to the anchor and instead replays genesis->tip via P2P. Either
#     way the only header path is the explicit iso_import_blockindex
#     (--importblockindex, read-only). See iso_spawn_mainnet_node's seed
#     policy block for the empirical justification.
#   - bg-validation is caller-controlled (NOT forced off): the weekly
#     from-genesis run needs it ON to replay every body.
#   - iso_import_blockindex runs `--importblockindex` (the proven 60-74 s
#     header path) which copies the source LevelDB index to its own temp
#     and strips the copied LOCK — it never opens the source for write.

set -euo pipefail

# ── Live-port refuse-set ───────────────────────────────────────────
# Every port any live zclassic23 / zclassicd / dev-peer is known to bind.
# Verified live (ss): 8033 (zclassic23 P2P), 8034 (zclassicd P2P),
# 18232 (zclassic23 RPC), 8232 (zclassicd RPC), 18034 (zclassic23 FS).
# Historical 8023 remains reserved so old lanes cannot be accidentally reused.
ISO_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"

# ── State (populated by iso_init / iso_spawn_mainnet_node) ─────────
ISO_KIND="${ISO_KIND:-replay}"
ISO_DD=""
ISO_PORT=0
ISO_RPCPORT=0
ISO_FSPORT=0
ISO_HTTPSPORT=0
ISO_CONNECT_SINK=39999
ISO_NODE_PID=""
ISO_PGID=""
ISO_CLEANED=0
ISO_PARAMS_DIR=""
ISO_NODE_BIN="${ISO_NODE_BIN:-./build/bin/zclassic23}"
ISO_RPC_BIN="${ISO_RPC_BIN:-./build/bin/zcl-rpc}"

# iso_die: a fatal isolation-setup problem (missing tooling, port collision,
# an unsafe datadir path, ...). Full detail always goes to stderr (captured
# by the journal same as before). When the sourcing script defines `blocked`
# (replay_canary.sh's typed-verdict function — see its doc comment), route
# through it so the failure ALSO leaves a durable BLOCKED sentinel instead of
# a bare non-zero exit: these are exactly the "cannot even attempt a replay"
# conditions blocked() exists for, never a replay finding. Falls back to a
# plain exit 1 for any other/older sourcer that doesn't define blocked (this
# file is a general isolation helper, not exclusively replay_canary.sh's).
iso_die() {
    echo "isolated_mainnet_env: FATAL: $*" >&2
    if command -v blocked >/dev/null 2>&1; then
        ELAPSED=$(( $(date +%s) - ${START_TS:-$(date +%s)} ))
        blocked "isolation_setup_failed"
    fi
    exit 1
}

# Abort if a chosen port collides with the static live set.
# NOTE: the trailing `return 0` is load-bearing — without it the
# function returns the rc of the final failed `[ ]` test (1), which
# would trip the caller's `set -e` on the all-clear path.
iso_assert_not_live_port() {
    local p="$1" lp
    for lp in $ISO_LIVE_PORTS; do
        [ "$p" = "$lp" ] && iso_die "port $p is in the live refuse-set — refusing"
    done
    return 0
}

# Abort if a chosen port is already LISTENING (the authoritative guard).
iso_assert_port_free() {
    local p="$1"
    if [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ]; then
        iso_die "port $p is already LISTENING — refusing (operator port math is wrong)"
    fi
    return 0
}

# ── Cleanup: kill the process group + remove the /tmp datadir ───────
iso_cleanup() {
    [ "$ISO_CLEANED" = "1" ] && return 0
    ISO_CLEANED=1

    if [ -n "$ISO_PGID" ]; then
        kill -TERM "-$ISO_PGID" 2>/dev/null || true
        local i
        for i in $(seq 1 50); do
            kill -0 "-$ISO_PGID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "-$ISO_PGID" 2>/dev/null || true
    fi

    # Belt-and-suspenders: only ever matches our throwaway datadir
    # string — cannot match the live "-datadir=.../.zclassic-c23".
    if [ -n "$ISO_DD" ]; then
        pkill -KILL -f -- "-datadir=$ISO_DD" 2>/dev/null || true
    fi

    if [ -n "$ISO_DD" ] && [ -d "$ISO_DD" ]; then
        case "$ISO_DD" in
            /tmp/zcl23-*) rm -rf "$ISO_DD" 2>/dev/null || true ;;
            *) echo "isolated_mainnet_env: WARN: refusing to rm non-/tmp datadir '$ISO_DD'" >&2 ;;
        esac
    fi
}

# ── One-time isolation setup. Call exactly once after sourcing. ────
#
# Ordering is safety-critical:
#   tooling checks → port DERIVE+VALIDATE → mint datadir → ARM TRAP →
#   port LISTEN refusal. The trap is armed BEFORE any abortable LISTEN
#   check that runs after the datadir is minted, so a refusal can never
#   leak a /tmp datadir.
iso_init() {
    command -v ss     >/dev/null 2>&1 || iso_die "ss(8) not found (need iproute2 for the port preflight)"
    command -v mktemp >/dev/null 2>&1 || iso_die "mktemp not found"
    [ -x "$ISO_NODE_BIN" ] || iso_die "$ISO_NODE_BIN not built — run make first"
    [ -x "$ISO_RPC_BIN" ]  || iso_die "$ISO_RPC_BIN not built — run make zcl-rpc"

    # 1) Derive + validate the 39xxx port quad FIRST (no datadir yet).
    local base="${ISO_PORT_BASE:-39050}"
    case "$base" in
        ''|*[!0-9]*) iso_die "ISO_PORT_BASE must be numeric, got '$base'" ;;
    esac
    [ "$base" -ge 39000 ] && [ "$base" -le 39990 ] \
        || iso_die "ISO_PORT_BASE $base out of the 39000-39990 isolation band"
    ISO_PORT=$base
    ISO_RPCPORT=$((base + 1))
    ISO_FSPORT=$((base + 2))
    ISO_HTTPSPORT=$((base + 3))

    local p
    for p in "$ISO_PORT" "$ISO_RPCPORT" "$ISO_FSPORT" "$ISO_HTTPSPORT"; do
        iso_assert_not_live_port "$p"
    done

    # 2) Throwaway datadir under /tmp.
    ISO_DD="$(mktemp -d "/tmp/zcl23-${ISO_KIND}-XXXXXX")" \
        || iso_die "mktemp -d failed"
    case "$ISO_DD" in
        /tmp/zcl23-*) : ;;
        *) iso_die "mktemp produced an unexpected path: $ISO_DD" ;;
    esac
    # Structural refusal: never the live datadir, nor the zclassicd
    # datadir this harness reads. The $HOME/.zclassic* glob covers BOTH
    # ~/.zclassic (zclassicd source, read-only) and ~/.zclassic-c23
    # (the live node) — neither may ever be the scratch dd.
    if [ -n "${HOME:-}" ]; then
        case "$ISO_DD" in
            "$HOME"/.zclassic*) iso_die "datadir resolved under the live ~/.zclassic* — refusing" ;;
        esac
    fi
    # Validation must prove the binary's embedded verifying keys. An explicit
    # empty directory prevents the child from inheriting operator proving or
    # verifying files from $HOME/.zcash-params. The replay node never writes
    # here; replay_canary.sh rechecks that it remained empty before PASS.
    ISO_PARAMS_DIR="$ISO_DD/empty-params"
    mkdir -m 0700 "$ISO_PARAMS_DIR" \
        || iso_die "could not create isolated empty params directory"

    # 3) ARM THE CLEANUP TRAP NOW — before any further abortable step.
    trap iso_cleanup EXIT INT TERM

    # 4) Live-LISTEN refusal (the authoritative collision guard).
    for p in "$ISO_PORT" "$ISO_RPCPORT" "$ISO_FSPORT" "$ISO_HTTPSPORT"; do
        iso_assert_port_free "$p"
    done

    echo "isolated_mainnet_env: datadir=$ISO_DD ports{p2p=$ISO_PORT rpc=$ISO_RPCPORT fs=$ISO_FSPORT https=$ISO_HTTPSPORT} sink=$ISO_CONNECT_SINK"
}

# ── Header import from a read-only source datadir ──────────────────
# $1: source datadir (the PARENT of blocks/index — e.g. ~/.zclassic for
#     a running zclassicd). Returns the import rc.
#
# Read-only justification: `--importblockindex` copies blocks/index to a
# temp dir next to ISO_DD's node.db and strips the COPIED LOCK; it never
# opens the source LevelDB for write and never touches the source LOCK
# (src/main.c:1473-1509). zclassicd keeps running on 8034/8232 untouched.
# This is the proven cold-sync recipe step 1 the operator runs by hand.
iso_import_blockindex() {
    local src="${1:-}"
    [ -n "$ISO_DD" ] || iso_die "iso_import_blockindex called before iso_init"
    [ -n "$src" ]    || iso_die "iso_import_blockindex needs a source datadir"
    [ -d "$src/blocks/index" ] \
        || iso_die "source '$src' has no blocks/index — not a node datadir"
    echo "isolated_mainnet_env: importing block index from $src (read-only)"
    "$ISO_NODE_BIN" --importblockindex "$src" "$ISO_DD/node.db"
}

# ── Spawn a mainnet node in its own process group ──────────────────
# $1 (optional): extra args appended verbatim. The CALLER decides the
#    seed + peer + legacy-import policy via $1 — this function only fixes
#    the isolation invariants (scratch datadir, 39xxx ports, fs port).
#
# Seed policy (EMPIRICALLY VERIFIED 2026-06-12 against HEAD on this box):
#   - The from-ANCHOR run uses the PROVEN cold recipe: header import via
#     iso_import_blockindex (--importblockindex, read-only) then a NORMAL
#     boot WITH legacy auto-import ON (the caller does NOT pass
#     -nolegacyimport). Boot auto-links the read-only ~/.zclassic and seeds
#     the anchor UTXO set; the node reconciles and serves. NOTE: the
#     spec's `-snapshot=$SRC` + `-nolegacyimport` combination was tested
#     and FATALs at HEAD ("DB_ERR_TIP_MISMATCH: utxos present but
#     coins_best_block is unset" → torn-anchor heal refused because
#     -nolegacyimport blocks the heal). So the anchor run uses legacy
#     auto-import, NOT -snapshot. Read-only is preserved: legacy
#     auto-import hardlinks the source SST files into a scratch
#     .legacy_ldb_snap under ISO_DD and never writes ~/.zclassic.
#   - The from-GENESIS run passes -nolegacyimport (so boot does NOT seed
#     to the anchor) and replays genesis->tip via P2P.
#
# Peer policy (also caller-supplied in $1):
#   - anchor: -connect=127.0.0.1:39999 — a dead sink that sets
#     g_connect_only, skipping DNS/fixed seeds AND the auto-addnode-to-
#     127.0.0.1:8034 path, so peer_count stays 0.
#   - genesis: -connect=127.0.0.1:8034 (the co-located zclassicd P2P)
#     because it must fetch bodies; the ONE place a real peer is dialed,
#     and it is the read-only co-located zclassicd, never a public peer.
#     MUST be -connect=, not -addnode=: -addnode= only adds a candidate
#     peer, it does NOT set g_connect_only, so the node's normal DNS-seed
#     + addrman outbound discovery stays live and dials the real public
#     network alongside zclassicd — an isolation-invariant violation
#     confirmed live 2026-07-19 (a weekly run reached four real mainnet
#     IPs). -connect= still adds its argument as a peer exactly like
#     -addnode= does (src/main.c applies app_add_node() to both
#     identically), so this keeps fetching bodies from zclassicd while
#     actually enforcing "never a public peer".
#
# -fsport is REQUIRED or the node binds the hardcoded live FS port 18034.
# setsid puts the node in its own group so cleanup kills the whole group.
iso_spawn_mainnet_node() {
    local extra="${1:-}"
    [ -n "$ISO_DD" ] || iso_die "iso_spawn_mainnet_node called before iso_init"

    # -allow-plaintext-wallet: the throwaway /tmp datadir holds NO real keys
    # (0 keys, 0 sapling keys — a fresh replay node never imports a wallet), so
    # the wallet-encryption-default boot gate (src/main.c) has nothing to
    # protect here. Without this flag that gate FATALs at boot ("refusing to
    # create a new PLAINTEXT wallet") and the node never reaches RPC-ready —
    # every from-fresh canary would FAIL with reason=rpc_never_ready.
    #
    # -wallet-no-phrase-backup: the SECOND wallet gate (config/src/
    # boot_wallet_phrase.c) refuses a headless first boot even after the
    # plaintext opt-in, because the twelve words could only land in node.log.
    # Its SKIP list is ZCL_WALLET_PASSPHRASE / mint-anchor / a declared
    # dev|soak|test|copy|standby lane / this flag — and -allow-plaintext-wallet
    # is deliberately NOT on it ("keep keys in the clear" ≠ "no written
    # backup"). A replay datadir is deleted on exit, so no backup can ever
    # exist; this flag says so in as many words. Without it the canary FAILs
    # reason=rpc_never_ready with the wallet_phrase_no_terminal blocker —
    # confirmed live 2026-08-01 on the anchor track.
    # shellcheck disable=SC2086
    setsid "$ISO_NODE_BIN" \
        -datadir="$ISO_DD" \
        -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
        -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
        -paramsdir="$ISO_PARAMS_DIR" \
        -showmetrics=0 \
        -allow-plaintext-wallet \
        -wallet-no-phrase-backup \
        $extra \
        >"$ISO_DD/node.log" 2>&1 &
    ISO_NODE_PID=$!
    ISO_PGID="$ISO_NODE_PID"   # setsid leader: PGID == PID
}

# ── RPC against the ISOLATED node ONLY ─────────────────────────────
# Threads ZCL_DATADIR + ZCL_RPCPORT on EVERY call so zcl-rpc can never
# fall through to the live default RPC port (18232) / the live cookie.
iso_rpc() {
    ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" "$ISO_RPC_BIN" "$@" 2>/dev/null || true
}

# Poll the isolated RPC until getblockcount answers, or timeout. $1=secs.
iso_wait_rpc_ready() {
    local timeout="${1:-60}" deadline
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            echo "isolated_mainnet_env: node exited during RPC warmup (see $ISO_DD/node.log)" >&2
            return 1
        fi
        if [ -f "$ISO_DD/.cookie" ]; then
            local t
            t="$(iso_rpc getblockcount | tr -dc '0-9-')"
            [ -n "$t" ] && return 0
        fi
        sleep 0.5
    done
    return 1
}
