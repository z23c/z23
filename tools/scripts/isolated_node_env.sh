# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# isolated_node_env.sh — the ONE place node isolation is enforced.
#
# This file is *sourced* (not executed) by the soak/chaos harness make
# targets (`make soak-ci`, the bootstrap branch of `make test-crash`).
# It is the single, audited chokepoint that guarantees a spawned test
# node can NEVER touch the live node, the live datadir, or a live port.
#
# It does ALL of the following, in this order, before any node is spawned:
#
#   1. Mint a throwaway datadir under /tmp (mktemp -d). REFUSE if the
#      resolved path is the live datadir ($HOME/.zclassic-c23*) — so a
#      caller cannot point us at the live chainstate even by mistake.
#   2. Derive an isolated 39xxx port quad (port/rpcport/fsport/httpsport)
#      plus a dead -connect sink (39999). REFUSE if any chosen port is in
#      the hardcoded live set.
#   3. ss(8) LISTEN preflight: REFUSE if ANY chosen port is already
#      bound — a collision means the operator's port math is wrong; we
#      abort loud rather than silently dodging onto another port. This
#      ss LISTEN check is the AUTHORITATIVE collision guard.
#   4. Install an EXIT/INT/TERM cleanup trap that kills the spawned
#      node's whole PROCESS GROUP and rm -rf's the /tmp datadir (only
#      after re-asserting the datadir is under /tmp and non-empty).
#
# It then exposes two functions the harness uses:
#   iso_spawn_node "<extra node args>"   — fork a regtest node in its
#                                          OWN process group (setsid),
#                                          recording ISO_PGID/ISO_NODE_PID.
#   iso_rpc <method> [params...]         — call zcl-rpc against the
#                                          ISOLATED datadir+rpcport ONLY.
#
# Contract for the sourcing script:
#   - `set -euo pipefail` is assumed; this file also sets it.
#   - Define ISO_KIND ("soak"|"crash") and (optionally) ISO_PORT_BASE
#     BEFORE sourcing, then call `iso_init`.
#   - The sourcing script MUST NOT install its own conflicting EXIT trap.
#
# WHY a process-GROUP kill: the node embeds Tor as an in-process pthread
# (we never enable -tor here), and does not daemonize, so it is a single
# process — but spawning under setsid and killing the GROUP is strictly
# safer (no orphan can survive a harness crash). The final belt-and-
# suspenders pkill matches ONLY our throwaway "-datadir=$ISO_DD" string,
# which structurally cannot match the live "-datadir=%h/.zclassic-c23".

set -euo pipefail

# ── Live-port refuse-set ───────────────────────────────────────────
# Every port any live zclassic23 / zclassicd / dev-peer is known to bind.
# Verified live (ss): 8033 (zclassic23 P2P), 8034 (zclassicd P2P),
# 18232 (zclassic23 RPC), 8232 (zclassicd RPC), 18034 (zclassic23 FS).
# Historical 8023 remains reserved; the 80xx/180xx
# dev-peer siblings are included defensively even when not currently up.
ISO_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"

# ── State (populated by iso_init / iso_spawn_node) ─────────────────
ISO_KIND="${ISO_KIND:-soak}"
ISO_DD=""
ISO_PORT=0
ISO_RPCPORT=0
ISO_FSPORT=0
ISO_HTTPSPORT=0
ISO_CONNECT_SINK=39999
ISO_NODE_PID=""
ISO_PGID=""
# Optional second node (iso_spawn_peer): a real P2P peer for gates that
# require peer_count > 0 (e.g. the wallet money-freshness classifier, which
# fails closed to UNKNOWN on a zero-peer node). The peer lives INSIDE
# $ISO_DD/peer so the cleanup trap's rm -rf and the datadir-substring pkill
# cover it too. The port quad is derived in iso_init (values only — the
# live-set refusal, band check, and LISTEN preflight all stay in
# iso_spawn_peer) so a primary that must dial the peer can name the
# -connect target before the peer process exists.
ISO_PEER_DD=""
ISO_PEER_PORT=0
ISO_PEER_RPCPORT=0
ISO_PEER_FSPORT=0
ISO_PEER_HTTPSPORT=0
ISO_PEER_PID=""
ISO_PEER_PGID=""
ISO_CLEANED=0
ISO_NODE_BIN="${ISO_NODE_BIN:-./build/bin/zclassic23}"
ISO_RPC_BIN="${ISO_RPC_BIN:-./build/bin/zcl-rpc}"

iso_die() { echo "isolated_node_env: FATAL: $*" >&2; exit 1; }

# Drop inherited /dev/pts and /dev/tty descriptors. A leftover operator
# pts (not stdin — that is already /dev/null) lets a child hit wall(1)
# "Broadcast message from user@host" on every logged-in terminal.
iso_drop_inherited_ttys() {
    local fd n target
    for fd in /proc/self/fd/*; do
        n=${fd##*/}
        case $n in
            ''|*[!0-9]*) continue ;;
            0|1|2) continue ;;
        esac
        target=$(readlink "$fd" 2>/dev/null || true)
        case $target in
            /dev/pts/*|/dev/tty|/dev/tty*) eval "exec ${n}>&-" 2>/dev/null || true ;;
        esac
    done
    return 0
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
    # ss -tlnH: TCP, listening, numeric, no header. Match the exact
    # local port so we don't false-positive on a substring.
    if ss -tlnH "sport = :$p" 2>/dev/null | grep -q .; then
        iso_die "port $p is already LISTENING — refusing (operator port math is wrong)"
    fi
    return 0
}

# ── Cleanup: kill the process group + remove the /tmp datadir ───────
iso_cleanup() {
    # Idempotent: the EXIT trap fires once even with INT/TERM chained.
    [ "$ISO_CLEANED" = "1" ] && return 0
    ISO_CLEANED=1

    # Peer first (it is the leaf; the primary outlives it by milliseconds).
    if [ -n "$ISO_PEER_PGID" ]; then
        kill -TERM "-$ISO_PEER_PGID" 2>/dev/null || true
    fi
    if [ -n "$ISO_PGID" ]; then
        # Graceful first, then hard. Negative PID == "the whole group".
        kill -TERM "-$ISO_PGID" 2>/dev/null || true
        # Poll up to 10s for the group to drain.
        local i
        for i in $(seq 1 50); do
            kill -0 "-$ISO_PGID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "-$ISO_PGID" 2>/dev/null || true
    fi
    if [ -n "$ISO_PEER_PGID" ]; then
        kill -KILL "-$ISO_PEER_PGID" 2>/dev/null || true
    fi

    # Belt-and-suspenders: only ever matches our throwaway datadir
    # string — cannot match the live "-datadir=.../.zclassic-c23".
    if [ -n "$ISO_DD" ]; then
        pkill -KILL -f -- "-datadir=$ISO_DD" 2>/dev/null || true
    fi

    # Remove the datadir, but ONLY after re-proving it is under /tmp and
    # non-empty — never rm -rf an empty/garbage path.
    if [ -n "$ISO_DD" ] && [ -d "$ISO_DD" ]; then
        case "$ISO_DD" in
            /tmp/zcl23-*) rm -rf "$ISO_DD" 2>/dev/null || true ;;
            *) echo "isolated_node_env: WARN: refusing to rm non-/tmp datadir '$ISO_DD'" >&2 ;;
        esac
    fi
}

# ── One-time isolation setup. Call exactly once after sourcing. ────
#
# Ordering is safety-critical:
#   tooling checks → port DERIVE+VALIDATE → mint datadir → ARM TRAP →
#   port LISTEN refusal. The trap is armed BEFORE any abortable LISTEN
#   check that runs after the datadir is minted, so a refusal can never
#   leak a /tmp datadir. Port validation that needs no datadir runs
#   first so a bad base aborts before anything is created.
iso_init() {
    iso_drop_inherited_ttys
    command -v ss   >/dev/null 2>&1 || iso_die "ss(8) not found (need iproute2 for the port preflight)"
    command -v mktemp >/dev/null 2>&1 || iso_die "mktemp not found"
    [ -x "$ISO_NODE_BIN" ] || iso_die "$ISO_NODE_BIN not built — run make first"
    [ -x "$ISO_RPC_BIN" ]  || iso_die "$ISO_RPC_BIN not built — run make zcl-rpc"

    # 1) Derive + validate the 39xxx port quad FIRST (no datadir yet, so
    #    a bad base or a live-set member aborts before we create anything).
    local base="${ISO_PORT_BASE:-39030}"
    case "$base" in
        ''|*[!0-9]*) iso_die "ISO_PORT_BASE must be numeric, got '$base'" ;;
    esac
    [ "$base" -ge 39000 ] && [ "$base" -le 39990 ] \
        || iso_die "ISO_PORT_BASE $base out of the 39000-39990 isolation band"
    ISO_PORT=$base
    ISO_RPCPORT=$((base + 1))
    ISO_FSPORT=$((base + 2))
    ISO_HTTPSPORT=$((base + 3))

    # Derive the optional-peer quad eagerly (iso_spawn_peer validates and
    # binds it later). A primary that must DIAL its peer — required for
    # money-gated flows, whose sync-state machine only leaves finding_peers
    # on an OUTBOUND peer — needs the peer's -connect target before the
    # peer process exists; the +10 quad is deterministic, so it can be
    # named up front.
    ISO_PEER_PORT=$((base + 10))
    ISO_PEER_RPCPORT=$((ISO_PEER_PORT + 1))
    ISO_PEER_FSPORT=$((ISO_PEER_PORT + 2))
    ISO_PEER_HTTPSPORT=$((ISO_PEER_PORT + 3))

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
    # Structural refusal: never the live datadir or any sibling.
    if [ -n "${HOME:-}" ]; then
        case "$ISO_DD" in
            "$HOME"/.zclassic-c23*) iso_die "datadir resolved under the live ~/.zclassic-c23 — refusing" ;;
        esac
    fi

    # 3) ARM THE CLEANUP TRAP NOW — before any further abortable step —
    #    so a LISTEN refusal below can never leak the just-minted datadir.
    trap iso_cleanup EXIT INT TERM

    # 4) Live-LISTEN refusal (the authoritative collision guard). Runs
    #    after the trap is armed: a refusal here still cleans up.
    for p in "$ISO_PORT" "$ISO_RPCPORT" "$ISO_FSPORT" "$ISO_HTTPSPORT"; do
        iso_assert_port_free "$p"
    done

    echo "isolated_node_env: datadir=$ISO_DD ports{p2p=$ISO_PORT rpc=$ISO_RPCPORT fs=$ISO_FSPORT https=$ISO_HTTPSPORT} sink=$ISO_CONNECT_SINK"
}

# ── Spawn a regtest node in its own process group ──────────────────
# $1 (optional): extra args appended verbatim (e.g. extra -flags).
#
# -connect=39999 is LOAD-BEARING isolation: it sets g_connect_only,
# which both skips DNS/fixed seeds AND bypasses the auto-addnode-to-
# 127.0.0.1:8034 path that would otherwise dial zclassicd. 39999 is a
# dead sink so peer_count stays 0. -fsport is REQUIRED or the node binds
# the hardcoded live FS port 18034. setsid puts the node in its own
# group so the cleanup trap can kill the whole group atomically.
#
# -nofilesync is BELT-AND-BRACES, kept on purpose. -connect isolates the
# P2P wire only; it never implied anything about the instant-on bundle
# fetch, which builds its OWN file-service peer set. That set used to be
# built by STRIPPING the port off -connect and re-adding the compiled-in
# default FS port, so -connect=127.0.0.1:39999 became 127.0.0.1:18034 —
# the LIVE node's file service on a host that runs one. Measured twice:
# ~1.1 GB and ~1 GB of mainnet state pulled into a "regtest" datadir,
# which then began re-serving it to the swarm.
#
# Both node-side causes are now fixed and regression-tested (see
# lib/test/src/test_boot_bundle_fetch.c case_network_gate /
# case_seed_set): boot_bundle_fetch_should_run is mainnet-only, and
# bbf_add_connect_seed refuses to substitute a NON-DEFAULT port the
# operator named (39xxx fixture sinks stay dead; :8033 is the published
# mainnet P2P port and is allowed to seed file-service at FS_PORT).
# The flag stays anyway — a harness must not depend on a node-side gate
# staying correct, and this is the layer that fails safe.
iso_spawn_node() {
    local extra="${1:-}"
    [ -n "$ISO_DD" ] || iso_die "iso_spawn_node called before iso_init"

    # setsid → new session+group led by the node; we record its PGID
    # (== its PID, since setsid makes it the group leader).
    # stdin is /dev/null: do not inherit the operator pts. A child that
    # keeps the TUI as stdin can wall(1) "Broadcast message from user@host"
    # onto every logged-in terminal.
    # shellcheck disable=SC2086
    setsid "$ISO_NODE_BIN" \
        -datadir="$ISO_DD" -regtest \
        -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
        -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
        -connect=127.0.0.1:"$ISO_CONNECT_SINK" \
        -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
        $extra \
        </dev/null >"$ISO_DD/node.log" 2>&1 &
    ISO_NODE_PID=$!
    ISO_PGID="$ISO_NODE_PID"   # setsid leader: PGID == PID
}

# ── Optional second node: a REAL peer for the primary ──────────────
# Some gates fail closed on a zero-peer node (the wallet money-freshness
# classifier returns UNKNOWN when connman has no connected node, so any
# money-gated intent is refused no matter how caught-up the chain is).
# iso_spawn_peer forks a second regtest node on the +10 port quad whose
# ONLY job is to be a connected peer: it dials the primary over the same
# -connect operator lane, giving the primary peer_count=1 (inbound) while
# staying inside every isolation invariant above:
#   - datadir is $ISO_DD/peer — inside the throwaway tree, so the trap's
#     rm -rf and the "-datadir=$ISO_DD" substring pkill both cover it;
#   - ports are derived, live-set-refused, and LISTEN-preflighted exactly
#     like the primary quad (the trap is already armed, so a refusal here
#     still cleans up).
#
# INBOUND alone is not enough for every gate: the sync-state machine only
# leaves finding_peers on an OUTBOUND peer (syncsvc_begin_peer_sync
# refuses inbound nodes), and the money-freshness classifier fails closed
# on finding_peers. A sourcing script whose flow is money-gated should
# therefore also pass `-connect=127.0.0.1:$ISO_PEER_PORT` in the primary's
# iso_spawn_node extras — each -connect is a one-shot direct dial
# (main.c → app_add_node → connman_open_connection) re-issued on every
# fresh primary boot, so the primary (re)connects outbound to the peer as
# soon as both are up. The pair stays a closed two-node loop either way:
# nobody dials anything but the dead sink and each other.
iso_spawn_peer() {
    local extra="${1:-}"
    [ -n "$ISO_DD" ] || iso_die "iso_spawn_peer called before iso_init"
    [ -n "$ISO_PGID" ] || iso_die "iso_spawn_peer called before iso_spawn_node"
    [ -z "$ISO_PEER_PGID" ] || iso_die "iso_spawn_peer called twice"

    # The quad itself was derived in iso_init; validate + preflight it here
    # (only peer users pay the band check).
    # Keep the whole peer quad inside the isolation band and clear of the
    # dead-sink port (39999).
    [ "$ISO_PEER_HTTPSPORT" -lt "$ISO_CONNECT_SINK" ] \
        || iso_die "ISO_PORT_BASE too high for a +10 peer quad (peer https $ISO_PEER_HTTPSPORT >= sink $ISO_CONNECT_SINK)"

    local p
    for p in "$ISO_PEER_PORT" "$ISO_PEER_RPCPORT" "$ISO_PEER_FSPORT" "$ISO_PEER_HTTPSPORT"; do
        iso_assert_not_live_port "$p"
        iso_assert_port_free "$p"
    done

    ISO_PEER_DD="$ISO_DD/peer"
    mkdir -p "$ISO_PEER_DD"

    # The peer dials ISO_PEER_DIAL (default: the PRIMARY; never anything
    # external). A sourcing script can set ISO_PEER_DIAL="$ISO_CONNECT_SINK"
    # before calling (e.g. for a post-restart respawn) when the PRIMARY
    # will own the pair's only link via its own outbound dial — the
    # sync-state machine needs an OUTBOUND peer on the gated node, and
    # connman_open_connection skips an already-connected address, so the
    # peer must not be dialling the primary when the primary dials it.
    # Either way the pair is a closed two-node loop.
    # shellcheck disable=SC2086
    setsid "$ISO_NODE_BIN" \
        -datadir="$ISO_PEER_DD" -regtest \
        -port="$ISO_PEER_PORT" -rpcport="$ISO_PEER_RPCPORT" \
        -fsport="$ISO_PEER_FSPORT" -httpsport="$ISO_PEER_HTTPSPORT" \
        -connect=127.0.0.1:"${ISO_PEER_DIAL:-$ISO_PORT}" \
        -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
        $extra \
        </dev/null >"$ISO_PEER_DD/node.log" 2>&1 &
    ISO_PEER_PID=$!
    ISO_PEER_PGID="$ISO_PEER_PID"
}

# ── RPC against the ISOLATED node ONLY ─────────────────────────────
# Threads ZCL_DATADIR + ZCL_RPCPORT on EVERY call so zcl-rpc can never
# fall through to the live default RPC port (18232) / the live cookie.
iso_rpc() {
    ZCL_DATADIR="$ISO_DD" ZCL_RPCPORT="$ISO_RPCPORT" "$ISO_RPC_BIN" "$@" 2>/dev/null || true
}

# RPC against the PEER node spawned by iso_spawn_peer (same threading rules).
iso_peer_rpc() {
    ZCL_DATADIR="$ISO_PEER_DD" ZCL_RPCPORT="$ISO_PEER_RPCPORT" "$ISO_RPC_BIN" "$@" 2>/dev/null || true
}

# Poll until the peer's P2P port is LISTENING — the precondition for an
# outbound dial TO the peer landing (e.g. the primary's addnode onetry).
# $1=secs.
iso_wait_peer_listen() {
    local timeout="${1:-60}" deadline
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$ISO_PEER_PID" ] && ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
            echo "isolated_node_env: peer node exited (see $ISO_PEER_DD/node.log)" >&2
            return 1
        fi
        ss -tlnH "sport = :$ISO_PEER_PORT" 2>/dev/null | grep -q . && return 0
        sleep 0.5
    done
    return 1
}

# Poll the primary until it reports >=1 connected peer (i.e. the peer node's
# inbound handshake completed), or timeout. $1=secs.
iso_wait_peer_connected() {    local timeout="${1:-60}" deadline n
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$ISO_PEER_PID" ] && ! kill -0 "$ISO_PEER_PID" 2>/dev/null; then
            echo "isolated_node_env: peer node exited (see $ISO_PEER_DD/node.log)" >&2
            return 1
        fi
        # Extract the integer after "result": — never tr(1) the whole JSON
        # line, which would mash version/id digits into a false positive.
        n="$(iso_rpc getconnectioncount \
            | sed -n 's/.*"result"[^0-9-]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1)"
        [ -n "$n" ] && [ "$n" -ge 1 ] && return 0
        sleep 0.5
    done
    return 1
}

# Poll the isolated RPC until getblockcount answers, or timeout. $1=secs.
iso_wait_rpc_ready() {
    local timeout="${1:-60}" deadline
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "$ISO_NODE_PID" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            echo "isolated_node_env: node exited during RPC warmup (see $ISO_DD/node.log)" >&2
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
