#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# commons-journey-acceptance — one complete two-node C23 Commons journey.
#
# A person describes useful software behavior. Z23 reuses existing C23 first,
# creates only what is missing, shows the result, reproduces the exact bytes
# on another node, and lets the person accept and use that exact version.
# This proves that sentence, end to end, on three fresh isolated datadirs
# (A publishes, B reproduces, A is killed, C still fetches from B):
#
#   zcode guide -> work start -> work run -> work show
#     -> publish -> discover -> fetch -> source reproduce
#     -> work accept -> zcode use
#
# After checkout and build it contacts nothing: no GitHub, no registry, no
# package server. Node B learns the package from node A over the node's own
# authenticated DHT and gets every byte from node A's package swarm.
#
# WHAT IT PROVES, in the order the script asserts it:
#   1. Code that is not available locally is never reported as reused.
#   2. Reusable code is selected before new code is written.
#   3. Only the behavior still missing enters candidate work.
#   4. Fetched source stays inert; nothing builds or runs it on arrival.
#   5. Building and testing it requires an explicit local admission — and a
#      node announces a package pointer only after its own admission plus a
#      distinct byte-identical rebuild receipt (the pointer gate).
#   6. Source, dependency, recipe, toolchain, action, artifact and receipt
#      identities stay bound to each other.
#   7. Node B reconstructs the inputs and reproduces byte-identical output.
#   8. Altered source, dependency, receipt or artifact is refused BY NAME.
#   9. Acceptance is explicit; the accepted tree publishes as an ordinary
#      package (apps/wordcount) whose manifest declares the program it ships,
#      and `zcode use` then builds, installs and names that program
#      (bin/wordcount) under the same build receipt as the library — this
#      proof runs no compiler.
#  10. Ask-to-running-program time and the exact C23 source-closure reuse
#      ratio are measured across the roots held by at least two nodes.
#  11. Independently learned source facts publish as signed reproduction
#      receipts: A consumes B's receipt, then B consumes C's.
#
# The fixture is deliberately small and real: tools/dev/fixtures/commons_journey
# holds z23/textstat (a finished, dependency-free counter package) and
# you/wordcount (an application that reuses it and needs one behavior nothing
# in the commons provides — the longest line). Nothing here is a mock.
#
# DELIBERATELY opt-in (NOT in `make ci`): it spawns three real regtest
# daemons, mines a regtest chain, and runs confined package builds. It
# touches no production datadir, no wallet key of yours, and no live port.

set -euo pipefail
# Display I/O (echo/printf/cat to a closed make/CI pipe) must not abort a
# journey whose assertions already passed. SIGPIPE 141 under pipefail is how
# `cj_strip | tee` un-earned an 11/11 PASS. Writes return EPIPE instead.
trap '' PIPE

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# tools/dev/node_lifecycle.sh is the single owner of process-group ownership,
# port claims, work-dir creation and cleanup. Reusing it is the point: a
# second lifecycle state machine is a second thing that can lie about whether
# the last run really went away.
. "$SCRIPT_DIR/node_lifecycle.sh"

CJ_FIXTURES="$SCRIPT_DIR/fixtures/commons_journey"
CJ_SIGNER="${ZCL_PACKAGE_SIGN_BIN:-$REPO_ROOT/build/bin/zclassic23-package-sign}"

# Three nodes, all on the production reachable-port policy's test-safe ports.
# Both P2P ports must be in the production reachable-port allowlist
# (core/modules/net/include/net/port_policy.h). The initial operator-directed dial
# bypasses that policy, but the controlled Noise reconnect does not, so an
# arbitrary high port connects once and then silently drops to zero peers.
A_PORT=20028; A_RPC=29281; A_FS=29282; A_HTTPS=29283
B_PORT=20027; B_RPC=29291; B_FS=29292; B_HTTPS=29293
C_PORT=20026; C_RPC=29301; C_FS=29302; C_HTTPS=29303

# ── node locations ───────────────────────────────────────────────────────
# Default: every node is a local process and this is `make commons-demo` —
# three isolated datadirs on one host, then A's process is killed so C can
# only learn from B. ZCL_COMMONS_MULTIHOST=1 runs the SAME journey with
# node B and node C on their own ssh hosts (CJ_HOST_B/CJ_HOST_C): binaries
# are shipped and sha3-verified, and host A itself is gone. It fails closed
# without both hosts. Same-host proves the publisher process can disappear;
# multi-host proves the publisher's machine can disappear.
CJ_MULTIHOST="${ZCL_COMMONS_MULTIHOST:-0}"
CJ_HOST_B="${CJ_HOST_B:-}"   # ssh destination of the reproducer/onward provider
CJ_HOST_C="${CJ_HOST_C:-}"   # ssh destination of the latecomer
# The P2P addresses nodes dial. Local runs keep loopback; in multi-host mode
# these are the LAN addresses of the driver (A), B and C. B's and C's default
# to their ssh host part when unset.
CJ_PEER_ADDR_A="${CJ_PEER_ADDR_A:-}"
CJ_PEER_ADDR_B="${CJ_PEER_ADDR_B:-}"
CJ_PEER_ADDR_C="${CJ_PEER_ADDR_C:-}"
CJ_RDIR_B=""; CJ_RDIR_C=""   # remote scratch dirs, set by cj_multihost_setup

CJ_WALLET_PASS="commons-journey-wallet-pass"
CJ_BACKUP_PASS="commons-journey-backup-pass"
CJ_SEED_A=1212121212121212121212121212121212121212121212121212121212121212
CJ_SEED_B=3434343434343434343434343434343434343434343434343434343434343434
CJ_SEED_C=5656565656565656565656565656565656565656565656565656565656565656

# What the person asks for, in plain words. "use <package>" is the deliberately
# narrow grammar that may prove reuse; the rest is the behavior that is missing.
CJ_GOAL="use z23/textstat and report the longest line of a text file"

# The proof profile. `quick` proves the candidate on this node: it compiles it,
# runs its acceptance tests, and writes receipts here. `standard` additionally
# demands receipts from a SECOND independent build node — the zero-wait
# development protocol that zcode-async-proof-acceptance already owns. This
# journey keeps node B for what the mission asks of it: independently
# reconstructing the source and reproducing the exact bytes.
CJ_PROFILE="quick"

# A syntactically perfect 64-hex root that names nothing anywhere. Every
# tamper case below hands one of these — or altered bytes — to a leaf that
# must refuse it BY NAME rather than by silence, empty result, or crash.
CJ_FAKE_ROOT="deadbeef00000000000000000000000000000000000000000000000000000001"
CJ_REFUSAL_SOURCE="LANE_NOT_ACCEPTED"
CJ_REFUSAL_DEPENDENCY="TARGET_UNRESOLVED"
CJ_REFUSAL_ARTIFACT="SOURCE_PACKAGE_CHECKOUT_REFUSED"
# The fourth tamper is the stale acceptance in step 8: a confirmation bound
# to a decision the person was never shown.
CJ_REFUSAL_RECEIPT="CONFIRMATION_IDENTITY_STALE"

# The application manifest is written at run time because a dependency is named
# by its exact root, and that root is not known until the package it names has
# been prepared. Passing an empty root writes the no-dependency form.
cj_write_package_json() {
    local ws="$1" dep_root="$2" name="${3:-you/wordcount}" deps="[]"
    if [ -n "$dep_root" ]; then
        deps="[{\"root\": \"$dep_root\", \"name\": \"z23/textstat\", \"semver\": \"0.1.0\"}]"
    fi
    cat >"$ws/zcode-package.json" <<JSON
{
  "schema": 1,
  "name": "$name",
  "semver": "0.1.0",
  "language": "c23",
  "license": "Apache-2.0",
  "include_dir": "include",
  "source_dir": "src",
  "dependencies": $deps,
  "programs": ["app/main.c"],
  "files": [
    "LICENSE",
    "app/main.c",
    "include/wordcount/wordcount.h",
    "src/wordcount.c",
    "tests/test_wordcount.c",
    "zcode-package.json"
  ]
}
JSON
}

cj_die()  { dht_die "commons-journey: $*"; }
# Display only: a closed stdout (make/CI pipe, SIGPIPE 141 under pipefail)
# must not abort a journey whose assertions already passed.
cj_note() { echo "commons-journey: $*" || true; }
cj_step() { { echo; echo "commons-journey: ── $* ──"; } || true; }

# Every leaf answers with one JSON line, and that line is the contract: a
# refusal is a named `ok:false` document, not a shell status. `pipefail` would
# otherwise turn an ordinary refusal into a silent `set -e` abort inside a
# `x="$(cj_a ...)"` assignment, losing the very name the refusal carries. So
# these never fail — cj_require_ok / cj_require_refusal read the answer.
# `-regtest` is not decoration. A one-shot CLI derives its chain params from
# its own flags, not from the datadir it is pointed at, so without it these
# leaves run under MAINNET rules against a regtest node: `zcode package dev
# prepare` stamps chain_id "zclassic-main" into the signed release, the
# publishing node accepts it (its CLI is equally mainnet), and the fetching
# node's daemon — which really is regtest — refuses the carrier with
# acceptance: wrong-chain-id. Every other node hook in this tree wraps
# dht_native the same way.
cj_a() { dht_native "$DHT_DD_A" "$A_RPC" -regtest "$@" || true; }
cj_b() { dht_native "$DHT_DD_B" "$B_RPC" -regtest "$@" || true; }
cj_c() { dht_native "$DHT_DD_C" "$C_RPC" -regtest "$@" || true; }
cj_jget() { "$DHT_ACCEPTANCE_C23" json-get "$@"; }
cj_field() { printf '%s' "$2" | cj_jget "$1" "${3:-}"; }

cj_require_ok() {
    local label="$1" doc="$2"
    [ "$(cj_field ok "$doc" False)" = True ] ||
        cj_die "$label failed: $doc"
}

# A refusal is only useful if it says which rule failed. Assert the exact
# name, never just "it returned false".
cj_require_refusal() {
    local label="$1" doc="$2" want="$3" got
    [ "$(cj_field ok "$doc" True)" = False ] ||
        cj_die "$label was ACCEPTED but must be refused: $doc"
    got="$(cj_field error.code "$doc" '')$(cj_field error.rule "$doc" '')"
    got="$got $(cj_field error.message "$doc" '')"
    case "$got" in
        *"$want"*) cj_note "refused by name: $label -> $want" ;;
        *) cj_die "$label was refused, but not by name '$want': $doc" ;;
    esac
}

# ── bring-up ─────────────────────────────────────────────────────────────
# The custody/anchor/delegation ordering below is the recipe proven by
# zcode-dht-acceptance. It is a sequence of ordinary product commands, not a
# private test path: the wallet must be encrypted at rest, unlocked, and
# backed up before the identity anchor's custody gate will pass, and the
# money-freshness gate needs a live outbound peer.
cj_wait_rpc_or_die() {
    dht_wait_rpc "$1" "$2" "$3" || cj_die "$4 RPC warmup failed"
}

# Multi-host bring-up, before any node boots. Probes both ssh hosts
# fail-closed, gives each a scratch dir, and ships the exact local binaries
# (verified by sha3 after the copy) so every host runs the same bytes the
# facts file names. Nothing here runs unless ZCL_COMMONS_MULTIHOST=1.
cj_multihost_setup() {
    if [ "$CJ_MULTIHOST" != 1 ]; then
        CJ_PEER_ADDR_A=127.0.0.1; CJ_PEER_ADDR_B=127.0.0.1; CJ_PEER_ADDR_C=127.0.0.1
        return 0
    fi
    [ -n "$CJ_HOST_B" ] && [ -n "$CJ_HOST_C" ] ||
        cj_die "multi-host acceptance needs CJ_HOST_B and CJ_HOST_C ssh destinations"
    [ "$CJ_HOST_B" != "$CJ_HOST_C" ] ||
        cj_die "CJ_HOST_B and CJ_HOST_C must be different hosts"
    case "$CJ_HOST_B:$CJ_HOST_C" in
        *localhost*|*127.0.0.1*)
            cj_die "multi-host hosts must not be loopback; that is make commons-demo" ;;
    esac
    if [ "$DHT_SSH" = ssh ]; then
        [ "$CJ_PEER_ADDR_A" != 127.0.0.1 ] ||
            cj_die "multi-host needs CJ_PEER_ADDR_A — the LAN address B and C dial to reach this host's node A"
    else
        # An overridden DHT_SSH is the local plumbing shim: loopback peer
        # addresses are exactly what it exists to exercise.
        [ -n "$CJ_PEER_ADDR_A" ] ||
            cj_die "multi-host needs CJ_PEER_ADDR_A even with a shimmed DHT_SSH"
    fi
    local host rdir bin local_sha3 remote_sha3
    for host in "$CJ_HOST_B" "$CJ_HOST_C"; do
        "$DHT_SSH" -o BatchMode=yes -o ConnectTimeout=5 "$host" -- true ||
            cj_die "cannot reach $host (BatchMode ssh); multi-host acceptance fails closed"
    done
    CJ_RDIR_B="$("$DHT_SSH" -o BatchMode=yes "$CJ_HOST_B" -- 'mktemp -d /tmp/z23-mh-XXXXXXXX')" ||
        cj_die "no scratch dir on $CJ_HOST_B"
    CJ_RDIR_C="$("$DHT_SSH" -o BatchMode=yes "$CJ_HOST_C" -- 'mktemp -d /tmp/z23-mh-XXXXXXXX')" ||
        cj_die "no scratch dir on $CJ_HOST_C"
    for host in "$CJ_HOST_B:$CJ_RDIR_B" "$CJ_HOST_C:$CJ_RDIR_C"; do
        rdir="${host#*:}"; host="${host%%:*}"
        "$DHT_SSH" -o BatchMode=yes "$host" -- "mkdir -p '$rdir/bin' '$rdir/cred' '$rdir/no-zk-params' && chmod 700 '$rdir/cred'" ||
            cj_die "scratch layout failed on $host"
        for bin in zclassic23 zcl-rpc arena_product_journey_c23 \
                   zclassic23-package-verify; do
            "$DHT_SCP" -o BatchMode=yes "$REPO_ROOT/build/bin/$bin" "$host:$rdir/bin/$bin" >/dev/null ||
                cj_die "shipping $bin to $host failed"
            local_sha3="$(openssl dgst -sha3-256 "$REPO_ROOT/build/bin/$bin" | awk '{print $NF}')"
            remote_sha3="$("$DHT_SSH" -o BatchMode=yes "$host" -- \
                "openssl dgst -sha3-256 '$rdir/bin/$bin' | awk '{print \$NF}'")" ||
                cj_die "sha3 verify of $bin on $host failed"
            [ "$local_sha3" = "$remote_sha3" ] ||
                cj_die "$bin on $host is not the local build's bytes"
        done
    done
    dht_register_remote_node "$B_RPC" "$CJ_HOST_B" "$CJ_RDIR_B"
    dht_register_remote_node "$C_RPC" "$CJ_HOST_C" "$CJ_RDIR_C"
    if [ "$DHT_SSH" != ssh ]; then
        # Shimmed plumbing: every "host" is this kernel, so peers dial loopback.
        [ -n "$CJ_PEER_ADDR_B" ] || CJ_PEER_ADDR_B=127.0.0.1
        [ -n "$CJ_PEER_ADDR_C" ] || CJ_PEER_ADDR_C=127.0.0.1
    else
        [ -n "$CJ_PEER_ADDR_B" ] || CJ_PEER_ADDR_B="${CJ_HOST_B#*@}"
        [ -n "$CJ_PEER_ADDR_C" ] || CJ_PEER_ADDR_C="${CJ_HOST_C#*@}"
    fi
    # Remote hosts build for themselves; that needs a C23 compiler there.
    for host in "$CJ_HOST_B" "$CJ_HOST_C"; do
        "$DHT_SSH" -o BatchMode=yes "$host" -- cc --version >/dev/null 2>&1 ||
            cj_die "$host has no usable cc; multi-host acceptance fails closed"
    done
    cj_note "multi-host: B=$CJ_HOST_B ($CJ_RDIR_B), C=$CJ_HOST_C ($CJ_RDIR_C), binaries sha3-verified"
}

# ── per-node operation seam ──────────────────────────────────────────────
# Everything below treats a node's files and shell as living WHERE THE NODE
# LIVES. Same-host that is plain local exec; in multi-host mode it is ssh to
# the registered host (node_lifecycle owns the routing). No journey step may
# read another node's datadir through the driver's filesystem.
cj_node_rpc() {
    case "$1" in
        a) printf '%s' "$A_RPC" ;;
        b) printf '%s' "$B_RPC" ;;
        c) printf '%s' "$C_RPC" ;;
        *) cj_die "unknown node '$1'" ;;
    esac
}
cj_on() { local node="$1"; shift; dht_node_exec "$(cj_node_rpc "$node")" "$@"; }
# A scratch directory on the node's own host.
cj_node_dir() {
    case "$1" in
        a) printf '%s' "$DHT_WORK" ;;
        b) printf '%s' "${CJ_RDIR_B:-$DHT_WORK}" ;;
        c) printf '%s' "${CJ_RDIR_C:-$DHT_WORK}" ;;
        *) cj_die "unknown node '$1'" ;;
    esac
}
cj_sha3_on() { cj_on "$1" openssl dgst -sha3-256 "$2" | awk '{print $NF}'; }
cj_bytes_on() { cj_on "$1" wc -c "$2" | awk '{print $1}'; }

# Exact C23 source bytes in one rooted tree.  One wc invocation per path keeps
# this portable to macOS (no GNU find/sort extensions) and safe for spaces.
cj_c23_source_bytes() {
    find "$1" -type f \( -name '*.c' -o -name '*.h' \) \
        -exec wc -c {} \; | awk '{ total += $1 } END { print total + 0 }'
}
# The C23 acceptance helper as the node sees it (shipped in multi-host mode).
cj_helper_on() {
    local rpc; rpc="$(cj_node_rpc "$1")"
    if [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ]; then
        printf '%s' "${DHT_REMOTE_DIR[$rpc]}/bin/arena_product_journey_c23"
    else
        printf '%s' "$DHT_ACCEPTANCE_C23"
    fi
}

cj_boot() {
    local dd rpc
    cj_multihost_setup
    for port in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS"; do
        dht_assert_port "$port" "$A_RPC"
    done
    for port in "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS"; do
        dht_assert_port "$port" "$B_RPC"
    done
    [ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] && [ -x "$DHT_ACCEPTANCE_C23" ] &&
    [ -x "$CJ_SIGNER" ] ||
        cj_die "build the node, RPC, C23 acceptance helper and package signer first"
    [ -d "$CJ_FIXTURES/textstat" ] && [ -d "$CJ_FIXTURES/wordcount" ] ||
        cj_die "missing fixture packages under $CJ_FIXTURES"

    dht_make_work zcl23-journey
    # This journey never proves a shielded transaction; keep its boot cost and
    # outcome independent of operator-installed proving parameters.
    if [ -z "$DHT_PARAMS_DIR" ]; then
        DHT_PARAMS_DIR="$DHT_WORK/no-zk-params"
        mkdir -p "$DHT_PARAMS_DIR"
    fi
    # A always runs where the demo runs. B's datadir is a path on B's host;
    # every read of it routes through the dht_node_* seam.
    DHT_DD_A="$DHT_WORK/node-a"
    if [ -n "$CJ_RDIR_B" ]; then DHT_DD_B="$CJ_RDIR_B/node-b"; else DHT_DD_B="$DHT_WORK/node-b"; fi
    DHT_MINE_DD="$DHT_DD_A"; DHT_MINE_RPC="$A_RPC"
    mkdir -p "$DHT_DD_A"
    if [ -n "$CJ_RDIR_B" ]; then
        dht_node_exec "$B_RPC" mkdir -p "$DHT_DD_B" ||
            cj_die "could not create node B datadir on $CJ_HOST_B"
    else
        mkdir -p "$DHT_DD_B"
    fi

    install -d -m 700 "$DHT_WORK/cred"
    install -m 600 /dev/null "$DHT_WORK/cred/wallet-passphrase"
    printf '%s\n' "$CJ_WALLET_PASS" >"$DHT_WORK/cred/wallet-passphrase"
    export CREDENTIALS_DIRECTORY="$DHT_WORK/cred"

    for dd in a b; do
        install -m 600 /dev/null "$DHT_WORK/master-$dd.hex"
    done
    printf '%s\n' "$CJ_SEED_A" >"$DHT_WORK/master-a.hex"
    printf '%s\n' "$CJ_SEED_B" >"$DHT_WORK/master-b.hex"
    # Seed and credential paths AS SEEN BY EACH NODE: local for A, shipped
    # copies on B's own disk in multi-host mode.
    CJ_SEED_FILE_A="$DHT_WORK/master-a.hex"
    CJ_SEED_FILE_B="$DHT_WORK/master-b.hex"
    if [ -n "$CJ_RDIR_B" ]; then
        dht_node_put "$B_RPC" "$DHT_WORK/cred/wallet-passphrase" \
            "$CJ_RDIR_B/cred/wallet-passphrase" ||
            cj_die "shipping the wallet credential to $CJ_HOST_B failed"
        dht_node_exec "$B_RPC" chmod 600 "$CJ_RDIR_B/cred/wallet-passphrase" ||
            cj_die "credential permissions failed on $CJ_HOST_B"
        dht_node_put "$B_RPC" "$DHT_WORK/master-b.hex" "$CJ_RDIR_B/master-b.hex" ||
            cj_die "shipping node B's master seed failed"
        CJ_SEED_FILE_B="$CJ_RDIR_B/master-b.hex"
    fi
    cj_note "booting two clean regtest nodes (A asks, B proves)"
    cj_note "booting two clean regtest nodes (A hosts packages and builds)"
    DHT_PACKAGEHOST=1
    DHT_BUILDWORKERS=0
    dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
        "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
    cj_wait_rpc_or_die "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" "node A"
    DHT_BUILDWORKERS=1
    dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
        "$B_HTTPS" "$CJ_PEER_ADDR_A:$A_PORT"
    cj_wait_rpc_or_die "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" "node B"
    rpc="$(a_rpc getnewaddress | dht_result)"
    [ -n "$rpc" ] || cj_die "node A produced no funding address"
    CJ_ADDR="$rpc"
}

a_rpc() { dht_rpc "$DHT_DD_A" "$A_RPC" "$@"; }
b_rpc() { dht_rpc "$DHT_DD_B" "$B_RPC" "$@"; }
# ── the node identities the package swarm authenticates with ─────────────
cj_wait_height() {
    dht_wait_height "$1" "$2" "$3" || cj_die "$4 did not reach height $3"
}

cj_identities() {
    local anchor
    cj_note "mining spendable regtest funds"
    dht_mine_to_address 101 "$CJ_ADDR"
    cj_wait_height "$DHT_DD_B" "$B_RPC" 101 "node B"
    dht_wait_fold "$DHT_DD_A" "$A_RPC" 101 ||
        cj_die "node A reducer fold did not reach the funding tip"

    # A must own the only link during the custody phase, and its coins-set
    # authority stamp lands at boot, so B goes to the dead sink and A restarts.
    dht_kill_group "$DHT_PGID_B"; DHT_PGID_B=""
    DHT_BUILDWORKERS=1
    dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
        "$B_HTTPS" "127.0.0.1:$DEAD_SINK"
    cj_wait_rpc_or_die "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" "node B dead-sink bounce"
    dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
    DHT_BUILDWORKERS=0
    dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
        "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
    cj_wait_rpc_or_die "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" "node A custody restart"
    dht_wait_fold "$DHT_DD_A" "$A_RPC" 101 ||
        cj_die "node A reducer fold did not survive the restart"
    a_rpc addnode "\"$CJ_PEER_ADDR_B:$B_PORT\"" "\"onetry\"" >/dev/null || true
    dht_wait_connected "$DHT_DD_A" "$A_RPC" || cj_die "node A never connected outbound"
    dht_wait_sync_live "$DHT_DD_A" "$A_RPC" || cj_die "node A sync never left finding_peers"
    dht_wait_chain_loaded "$DHT_DD_A" "$A_RPC" 101 ||
        cj_die "node A active chain index did not load"

    cj_note "unlocking the wallet and taking the current-key encrypted backup"
    DHT_WALLET_PASS="$CJ_WALLET_PASS" dht_unlock_wallet "$DHT_DD_A" "$A_RPC" ||
        cj_die "node A wallet unlock failed"
    a_rpc getnewaddress | dht_result >/dev/null ||
        cj_die "post-restart keypool top-up failed"
    DHT_BACKUP_PASS="$CJ_BACKUP_PASS" dht_backup_wallet "$DHT_DD_A" "$A_RPC" ||
        cj_die "node A custody backup failed"
    dht_wait_spendable "$DHT_DD_A" "$A_RPC" ||
        cj_die "node A vault spendable never became positive"

    cj_note "anchoring both masters, then provisioning independent delegations"
    CJ_PUB_A="$("$DHT_WORK/journey-peer" pubkey "$CJ_SEED_A")"
    CJ_PUB_B="$("$DHT_WORK/journey-peer" pubkey "$CJ_SEED_B")"
    [ "$CJ_PUB_A" != "$CJ_PUB_B" ] || cj_die "both masters derived one pubkey"
    anchor="$(dht_anchor "$DHT_DD_A" "$A_RPC" "$CJ_PUB_A" "journey-anchor-a")" ||
        cj_die "node A anchor failed"
    dht_mine_empty 1; sleep 1
    anchor="$(dht_anchor "$DHT_DD_A" "$A_RPC" "$CJ_PUB_B" "journey-anchor-b")" ||
        cj_die "node B anchor failed"
    dht_mine_empty 22
    # Ask the chain how tall it is rather than hardcoding a number that drifts
    # the moment an anchor costs a block more or less.
    local tip
    tip="$(dht_height "$DHT_DD_A" "$A_RPC")"
    [ -n "$tip" ] || cj_die "node A reported no chain height after anchoring"
    cj_wait_height "$DHT_DD_B" "$B_RPC" "$tip" "node B"

    local del_a del_b
    del_a="$(cj_a zcode network delegate \
        --input="{\"seed_file\":\"$CJ_SEED_FILE_A\"}")"
    cj_require_ok "node A delegation" "$del_a"
    del_b="$(cj_b zcode network delegate \
        --input="{\"seed_file\":\"$CJ_SEED_FILE_B\"}")"
    cj_require_ok "node B delegation" "$del_b"
    CJ_NODE_A="$(cj_field data.node_id "$del_a")"
    CJ_NODE_B="$(cj_field data.node_id "$del_b")"
    [ -n "$CJ_NODE_A" ] && [ "$CJ_NODE_A" != "$CJ_NODE_B" ] ||
        cj_die "the two masters derived one node identity"
    cj_note "independent node identities: A=${CJ_NODE_A:0:16}… B=${CJ_NODE_B:0:16}…"
}

# The seed-to-pubkey derivation is the node's own ZID code; compile the same
# helper the DHT acceptance uses rather than inventing a second derivation.
cj_build_peer_helper() {
    cc -std=c23 -O1 -w -D_GNU_SOURCE -ffunction-sections -fdata-sections \
        "${DHT_GC_SECTIONS_LDFLAGS[@]}" \
        -I"$REPO_ROOT/platform/modules/base/include" -I"$REPO_ROOT/platform/modules/sha3/include" \
        -I"$REPO_ROOT/core/modules/crypto/include" -I"$REPO_ROOT/platform/modules/support/include" \
        -I"$REPO_ROOT/platform/modules/util/include" -I"$REPO_ROOT/platform/modules/platform/include" \
        -I"$REPO_ROOT/platform/modules/json/include" -I"$REPO_ROOT/core/modules/core/include" \
        -I"$REPO_ROOT/core/modules/net/include" -I"$REPO_ROOT/core/modules/noise/include" \
        -I"$REPO_ROOT/contexts/commons/modules/vcs/include" -I"$REPO_ROOT/contexts/wallet/modules/zid/include" \
        -I"$REPO_ROOT/core/math/include" -o "$DHT_WORK/journey-peer" \
        "$REPO_ROOT/tools/zcode_dht_acceptance_peer.c" \
        "$REPO_ROOT/core/modules/net/src/noise_transport.c" \
        "$REPO_ROOT/core/modules/noise/src/noise_handshake.c" \
        "$REPO_ROOT/core/modules/noise/src/session_transport.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_dht.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_dht_delegation.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_dht_identity.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_dht_msgs.c" \
        "$REPO_ROOT/contexts/wallet/modules/zid/src/zid.c" "$REPO_ROOT/contexts/wallet/modules/zid/src/zendp.c" \
        "$REPO_ROOT/core/modules/crypto/src/ed25519.c" \
        "$REPO_ROOT/core/modules/crypto/src/sha512.c" \
        "$REPO_ROOT/core/modules/crypto/src/sha256.c" \
        "$REPO_ROOT/platform/modules/sha3/src/sha3.c" \
        "$REPO_ROOT/core/modules/crypto/src/hmac_sha256.c" \
        "$REPO_ROOT/core/modules/crypto/src/hkdf_sha256.c" \
        "$REPO_ROOT/core/modules/crypto/src/chacha20poly1305.c" \
        "$REPO_ROOT/platform/modules/support/src/log_throttle.c" \
        "$REPO_ROOT/core/modules/crypto/src/curve25519.c" \
        "$REPO_ROOT/core/modules/crypto/src/x25519_safe.c" \
        "$REPO_ROOT/core/modules/crypto/src/random_secret.c" \
        "$REPO_ROOT/core/math/src/hash.c" \
        "$REPO_ROOT/core/modules/core/src/utiltime.c" \
        "$REPO_ROOT/core/modules/core/src/random.c" \
        "$REPO_ROOT/platform/modules/base/src/safe_alloc.c" \
        "$REPO_ROOT/platform/modules/base/src/log_level.c" \
        "$REPO_ROOT/platform/modules/base/src/result.c" \
        "$REPO_ROOT/platform/modules/base/src/cleanse.c" \
        "$REPO_ROOT/platform/modules/platform/src/clock.c" \
        "$REPO_ROOT/platform/modules/platform/src/rng.c" \
        "$REPO_ROOT/platform/modules/platform/src/positioned_file.c" \
        "$REPO_ROOT/platform/modules/platform/src/private_directory.c" \
        "$REPO_ROOT/platform/modules/util/src/write_all.c" \
        "$REPO_ROOT/platform/modules/json/src/json.c" \
        "$REPO_ROOT/platform/modules/util/src/hw_profile.c" \
        "$REPO_ROOT/platform/modules/util/src/cpu_topology.c" ||
        cj_die "node identity helper compile failed"
}


# ── human-first assertions ───────────────────────────────────────────────
# Item 4 of the mission is a product property, not a comment: every terminal
# step must show current state, the important result, and exactly ONE safe
# next command, with roots and proof internals hidden unless details=true.
cj_has_root() {
    # Not `grep -q`: under pipefail a MATCH can surface printf's SIGPIPE 141
    # instead of grep's 0, so the decision would invert exactly when a root
    # IS present — the case this predicate exists to catch.
    local hit
    hit="$(printf '%s' "$1" | grep -oE '[0-9a-f]{64}' || true)"
    [ -n "$hit" ]
}

cj_human_first() {
    local label="$1" doc="$2" next
    next="$(cj_field data.next_safe_command "$doc" '')"
    [ -n "$next" ] ||
        cj_die "$label showed no next safe command: $doc"
    case "$next" in
        *" and "*|*";"*|*" or "*)
            cj_die "$label offered more than one next command: $next" ;;
    esac
    [ "$(cj_field data.stage "$doc" '')" != "" ] ||
        cj_die "$label did not say what stage the work is in: $doc"
    cj_note "$label -> next safe command: $next"
}

cj_roots_hidden() {
    local label="$1" plain="$2" detailed="$3"
    ! cj_has_root "$(cj_field data.expert "$plain" '')" ||
        cj_die "$label exposed proof internals without details=true: $plain"
    cj_has_root "$(cj_field data.expert "$detailed" '')" ||
        cj_die "$label hid its proof internals even with details=true: $detailed"
    [ "$(cj_field data.details_available "$plain" False)" = True ] ||
        cj_die "$label never told the reader details=true exists: $plain"
    cj_note "$label -> roots hidden by default, present with details=true"
}

# ── the offline publisher identity ───────────────────────────────────────
# A 32-byte mode-0600 secret used only through inherited descriptors. It
# never reaches a command JSON body or a daemon datadir.
cj_sign_digest() {
    local digest="$1" key="${2:-$DHT_WORK/publisher.key}" out
    printf '%s' "$digest" | xxd -r -p >"$DHT_WORK/release.digest"
    : >"$DHT_WORK/release.signature"
    chmod 0600 "$DHT_WORK/release.digest" "$DHT_WORK/release.signature"
    exec 7<"$key" 8<"$DHT_WORK/release.digest" \
         9>"$DHT_WORK/release.signature"
    "$CJ_SIGNER" --sign --key-fd 7 --digest-fd 8 --signature-fd 9 ||
        cj_die "offline release signing failed"
    exec 7<&- 8<&- 9>&-
    out="$(xxd -p -c 128 "$DHT_WORK/release.signature")"
    [ -n "$out" ] || cj_die "offline signing produced no signature"
    printf '%s' "$out"
}

# Publish one package tree into a node's own store. prepare -> sign -> seal
# -> plan -> commit, all through the ordinary leaves.
# Sets CJ_PKG_ROOT, CJ_PKG_RELEASE, CJ_PKG_RELEASE_HEX.
# Publisher identity is a parameter with a default, because the publish
# frequency rule is real and must not be worked around: a new-user key gets one
# publish per ISO week, so each package this journey publishes carries its OWN
# offline identity. That is also the truthful story — zprng, zdogfight and the
# person's own changed version are three different publishers, not one.
cj_publish_package() {
    local node="$1" dir="$2" seq="$3"
    local pub="${4:-$CJ_PUBLISHER}" key="${5:-$DHT_WORK/publisher.key}"
    local prepare digest body manifest recipe signature seal plan commit
    prepare="$("cj_$node" zcode package dev prepare \
        --input="{\"dir\":\"$dir\",\"publisher_pubkey\":\"$pub\",\"publisher_sequence\":$seq}")"
    cj_require_ok "prepare $dir" "$prepare"
    CJ_PKG_ROOT="$(cj_field data.package_root "$prepare")"
    digest="$(cj_field data.release_signing_digest "$prepare")"
    body="$(cj_field data.release_body_hex "$prepare")"
    manifest="$(cj_field data.manifest_hex "$prepare")"
    recipe="$(cj_field data.recipe_hex "$prepare")"
    signature="$(cj_sign_digest "$digest" "$key")"
    seal="$("cj_$node" zcode package dev seal \
        --input="{\"release_body_hex\":\"$body\",\"signature_hex\":\"$signature\"}")"
    cj_require_ok "seal $dir" "$seal"
    CJ_PKG_RELEASE_HEX="$(cj_field data.release_hex "$seal")"
    CJ_PKG_RELEASE="$(cj_field data.release_id "$seal")"
    plan="$("cj_$node" zcode package publish plan \
        --input="{\"release_hex\":\"$CJ_PKG_RELEASE_HEX\",\"manifest_hex\":\"$manifest\",\"recipe_hex\":\"$recipe\",\"dir\":\"$dir\"}")"
    cj_require_ok "publish plan $dir" "$plan"
    [ "$(cj_field data.valid "$plan" False)" = True ] ||
        cj_die "publish plan refused $dir: $plan"
    commit="$("cj_$node" zcode package publish commit \
        --input="{\"release_hex\":\"$CJ_PKG_RELEASE_HEX\",\"manifest_hex\":\"$manifest\",\"recipe_hex\":\"$recipe\",\"dir\":\"$dir\"}")"
    cj_require_ok "publish commit $dir" "$commit"
    CJ_PKG_TRANSPORT="$(cj_field data.transport_root "$commit")"
    [ "${#CJ_PKG_TRANSPORT}" -eq 64 ] ||
        cj_die "publish commit named no carrier for $dir: $commit"
    [ "$(cj_field data.release_id "$commit")" = "$CJ_PKG_RELEASE" ] ||
        cj_die "publish commit changed the release id for $dir: $commit"
}

# Admit one package for local build and install: plan, then commit the plan.
cj_use_package() {
    local node="$1" ref="$2" plan commit plan_id
    plan="$("cj_$node" zcode use --input="{\"name_or_root\":\"$ref\"}")"
    cj_require_ok "zcode use plan $ref" "$plan"
    plan_id="$(cj_field data.plan_id "$plan")"
    [ -n "$plan_id" ] || cj_die "zcode use produced no plan for $ref: $plan"
    [ "$(cj_field data.ready "$plan" False)" = True ] ||
        cj_die "zcode use plan is not ready for $ref: $plan"
    commit="$("cj_$node" zcode use --input="{\"plan_id\":\"$plan_id\"}")"
    cj_require_ok "zcode use commit $ref" "$commit"
    [ "$(cj_field data.installed "$commit" False)" = True ] ||
        cj_die "zcode use did not install $ref: $commit"
    CJ_USE_COMMIT="$commit"
}

# The pointer publication gate refuses REPRODUCTION_NOT_EVIDENCED unless the
# announcing node's own store holds two distinct byte-identical build
# receipts for the exact (package root, recipe root) pair the signed release
# commits. The explicit admission (`zcode use`) files the first; this
# deterministic rebuild files the distinct second, before the pointer plan
# exists. A node announces only what it has itself built twice.
cj_reproduce_package() {
    local node="$1" root="$2" reproduced
    reproduced="$("cj_$node" zcode package reproduce \
        --input="{\"name_or_root\":\"$root\"}")"
    cj_require_ok "zcode package reproduce $root" "$reproduced"
    [ "$(cj_field data.reproduced "$reproduced" False)" = True ] ||
        cj_die "node $node filed no distinct rebuild receipt for $root: $reproduced"
}

# Turn the accepted-work carrier back into the exact accepted source. The
# command is handed three independent identities — the package it holds, the
# source tree it must derive, and the accepted work that authorizes it — and
# refuses unless all three agree, so a destination directory is only ever
# written from bytes that verified.
cj_checkout_accepted() {
    local node="$1" dest="$2" dd cas
    # The three identities default to the accepted application of steps 8-9;
    # step 10 passes its own so the same refusal logic guards both laps.
    local pkg="${3:-$CJ_APP_ROOT}" src="${4:-$CJ_ACCEPTED_SOURCE}"
    local work="${5:-$CJ_ACCEPTED_WORK}"
    case "$node" in a) dd="$DHT_DD_A" ;; b) dd="$DHT_DD_B" ;; c) dd="$DHT_DD_C" ;;
        *) cj_die "cj_checkout_accepted: unknown node '$node'" ;; esac
    cas="$dest-cas"
    cj_on "$node" rm -rf "$dest" "$cas"
    cj_on "$node" mkdir -p "$dest" "$cas"
    "cj_$node" zcode workspace source package checkout \
        --input="{\"datadir\":\"$dd\",\"package_root\":\"$pkg\",\"source_root\":\"$src\",\"accepted_work_root\":\"$work\",\"workspace\":\"$cas\",\"destination\":\"$dest\"}"
}

# The executable `zcode use` installed for a package whose manifest declares
# a program. The reply names it (data.programs[i].path) and hands the person
# the next action ("run <path>"); nothing here guesses an install path, and
# nothing here compiles: the program is a build-receipt output, built by the
# node's own confined worker from the recipe, exactly like the library.
# Prints the path; an empty result is the caller's failure to check.
cj_program_path() {
    local commit="$1" want="$2" i=0 output path next
    while :; do
        output="$(cj_field "data.programs.$i.output" "$commit" '')"
        [ -n "$output" ] || break
        if [ "$output" = "bin/$want" ]; then
            path="$(cj_field "data.programs.$i.path" "$commit" '')"
            [ -n "$path" ] ||
                cj_die "zcode use named program $output without a path: $commit"
            next="$(cj_field data.next_action "$commit" '')"
            case "$next" in
                "run $path"*) ;;
                *) cj_die "zcode use installed $output but did not hand the person 'run $path' as the next action: $commit" ;;
            esac
            printf '%s' "$path"
            return 0
        fi
        i=$((i + 1))
    done
    cj_die "zcode use installed no program bin/$want: $commit"
}

# The one file in a node's content store that holds the largest source shard
# of a package. The store is content-addressed and stores each chunk whole,
# so the shard's exact size names its chunk; if that is ever ambiguous this
# says so instead of tampering with something else and calling it a proof.
cj_source_chunk_file() {
    local node="$1" root="$2" show dd i path size best=0 hits
    case "$node" in a) dd="$DHT_DD_A" ;; b) dd="$DHT_DD_B" ;; c) dd="$DHT_DD_C" ;;
        *) cj_die "cj_source_chunk_file: unknown node '$node'" ;; esac
    show="$("cj_$node" zcode package show --input="{\"root\":\"$root\"}")"
    cj_require_ok "package show $root" "$show"
    i=0
    while :; do
        path="$(cj_field "data.files_page.$i.path" "$show" '')"
        [ -n "$path" ] || break
        size="$(cj_field "data.files_page.$i.size" "$show" 0)"
        case "$path" in
            zclassic23-source/shard-*)
                if [ "$size" -gt "$best" ]; then best="$size"; fi ;;
        esac
        i=$((i + 1))
    done
    [ "$best" -gt 0 ] ||
        cj_die "package $root carries no source shard to alter"
    hits="$(cj_on "$node" find "$dd/zcode/cas" -type f -size "${best}c")"
    [ -n "$hits" ] && [ "$(printf '%s\n' "$hits" | wc -l)" -eq 1 ] ||
        cj_die "the $best-byte source shard does not name exactly one stored chunk"
    printf '%s\n' "$hits"
}

# ── peer-to-peer distribution ────────────────────────────────────────────
# The frozen DHT grammar keeps naming and custody apart. A POINTER binds the
# package root a person asks for to the carrier root that holds its bytes; a
# PROVIDER names an authenticated peer currently serving that exact carrier.
# Nothing here is a registry: a provider can vanish and the package survives,
# because the name is the content and any other holder answers for it.
cj_publish_record() {
    local node="$1" ns="$2" kind="$3" root="$4" transport="$5" seq="$6"
    local now expiry common plan token commit
    now="$(date +%s)"; expiry=$((now + 3600))
    common="\"kind\":\"$kind\",\"namespace\":\"$ns\",\"transport_root\":\"$transport\",\"sequence\":$seq,\"not_before\":$((now - 5)),\"expiry\":$expiry"
    [ "$kind" != pointer ] || common="$common,\"semantic_root\":\"$root\""
    plan="$("cj_$node" zcode network publish --input="{\"mode\":\"plan\",$common}")"
    cj_require_ok "node $node $ns $kind plan $root" "$plan"
    token="$(cj_field data.plan_token "$plan")"
    commit="$("cj_$node" zcode network publish \
        --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}")"
    cj_require_ok "node $node $ns $kind commit $root" "$commit"
}

# Consume one other node's signed SOURCE_REPRODUCTION_ACK through ordinary
# DHT discovery.  The canonical wire is required: a displayed root alone is
# not evidence another worker can independently verify and bind later.
CJ_SIGNED_RECEIPTS_CONSUMED=0
cj_consume_source_receipt() {
    local consumer="$1" producer_node_id="$2" package_root="$3"
    local source_root="$4" attempt=0 out count i provider semantic wire
    while [ "$attempt" -lt 6 ]; do
        out="$("cj_$consumer" zcode network records \
            --input="{\"kind\":\"source_reproduction_ack\",\"namespace\":\"zclassic23.source\",\"transport_root\":\"$package_root\",\"include_evidence_wires\":true}" || true)"
        if [ "$(cj_field ok "$out" False)" = True ]; then
            count="$(cj_field data.count "$out" 0)"
            i=0
            while [ "$i" -lt "$count" ]; do
                provider="$(cj_field "data.records.$i.provider_node_id" "$out" '')"
                semantic="$(cj_field "data.records.$i.semantic_root" "$out" '')"
                wire="$(cj_field "data.records.$i.record_wire" "$out" '')"
                if [ "$provider" = "$producer_node_id" ] &&
                   [ "$semantic" = "$source_root" ] &&
                   [ -n "$wire" ] &&
                   [ "$(cj_field "data.records.$i.conflicted" "$out" False)" = False ] &&
                   [ "$(cj_field "data.records.$i.superseded" "$out" False)" = False ]; then
                    CJ_SIGNED_RECEIPTS_CONSUMED=$((CJ_SIGNED_RECEIPTS_CONSUMED + 1))
                    printf '%s\n' "$out" >"$DHT_WORK/source-receipt-$consumer-${producer_node_id:0:16}.json"
                    cj_note "node ${consumer^^} consumed node ${producer_node_id:0:12}…'s signed source receipt"
                    return 0
                fi
                i=$((i + 1))
            done
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    cj_die "node $consumer did not consume the signed source receipt from $producer_node_id: $out"
}

cj_announce_package() {
    local node="$1" root="$2" transport="$3" seq="$4"
    cj_publish_record "$node" zclassic23.package pointer  "$root" "$transport" "$seq"
    cj_publish_record "$node" zclassic23.package provider "$root" "$transport" "$seq"
}

# Serving a package's BYTES and serving its SOURCE are two different
# services, and a node offers them separately. `zcode package source
# reproduce` asks the zclassic23.source namespace for a package root, so a
# publisher who wants its source independently re-derivable says so here.
cj_announce_source() {
    local node="$1" root="$2" seq="$3"
    cj_publish_record "$node" zclassic23.source provider "$root" "$root" "$seq"
}

# An accepted-work publication is a SOURCE TRANSPORT: its recipe is the
# synthetic carrier, not a build recipe with declared tests, so the store
# can never evidence it the way the pointer gate demands — the standard
# profile refuses to sign evidence for a recipe with no tests
# (zbuild-package-standard-refused, measured). Transports announce the two
# claims that are theirs to make: PROVIDER for the bytes (I hold and serve
# this exact root) and PROVIDER in the source namespace (anyone can
# re-derive the source I accepted). The POINTER stays reserved for
# packages whose local reproduction the store can prove — that gate is the
# whole point of the pointer, and refusing here is it working.
cj_announce_transport() {
    local node="$1" root="$2" transport="$3" seq="$4"
    cj_publish_record "$node" zclassic23.package provider "$root" "$transport" "$seq"
    cj_publish_record "$node" zclassic23.source provider "$root" "$root" "$seq"
}

cj_pin_root() {
    local node="$1" root="$2" plan token commit attempt=0
    while [ "$attempt" -lt 3 ]; do
        plan="$("cj_$node" zcode package pin --input="{\"root\":\"$root\",\"mode\":\"plan\"}")"
        cj_require_ok "node $node pin plan $root" "$plan"
        token="$(cj_field data.plan_token "$plan")"
        commit="$("cj_$node" zcode package pin \
            --input="{\"root\":\"$root\",\"mode\":\"commit\",\"plan_token\":\"$token\"}")"
        if [ "$(cj_field ok "$commit" False)" = True ]; then
            return 0
        fi
        [ "$(cj_field error.code "$commit" '')" = STALE_PLAN ] ||
            cj_die "node $node pin commit $root failed: $commit"
        attempt=$((attempt + 1))
    done
    cj_die "node $node pin commit $root failed: $commit"
}

# Fetch one package over the overlay and reconstruct it locally. Returns only
# when this node itself reports the exact package tracked and complete.
# Sets CJ_FETCH_BYTES from the local store's own accounting.
cj_fetch_package() {
    local node="$1" root="$2" transport="$3"
    local out deadline complete=False plan next_resume
    # Admitting the exact carrier root is the whole request. The first call
    # must be accepted and routed by the live daemon — that is the fact worth
    # asserting about the network. Everything after it is answered by this
    # node about itself: `zcode package pin --mode=plan` says whether the
    # bytes are here and whole. Provider discovery is explicitly retryable,
    # so re-admitting the same root resumes the same durable download slot;
    # a refused re-admission is never allowed to stand in for completion.
    out="$("cj_$node" zcode package fetch \
        --input="{\"root\":\"$transport\",\"namespace\":\"zclassic23.package\",\"maximum_bytes\":67108864}")"
    cj_require_ok "node $node fetch $transport" "$out"
    printf '%s\n' "$out" >"$DHT_WORK/fetch-$node-${transport:0:16}.json"
    [ "$(cj_field data.live "$out" False)" = True ] ||
        cj_die "node $node did not route the fetch through its live daemon: $out"
    deadline=$(( $(date +%s) + 180 )); next_resume=$(( $(date +%s) + 15 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        plan="$("cj_$node" zcode package pin \
            --input="{\"root\":\"$root\",\"mode\":\"plan\"}" || true)"
        complete="$(cj_field data.package.complete "$plan" False)"
        [ "$complete" = True ] && break
        if [ "$(date +%s)" -ge "$next_resume" ]; then
            "cj_$node" zcode package fetch \
                --input="{\"root\":\"$transport\",\"namespace\":\"zclassic23.package\",\"maximum_bytes\":67108864}" \
                >/dev/null 2>&1 || true
            next_resume=$(( $(date +%s) + 15 ))
        fi
        sleep 1
    done
    [ "$complete" = True ] ||
        cj_die "node $node never reconstructed $root from carrier $transport: $plan"
    printf '%s\n' "$plan" >"$DHT_WORK/complete-$node-${root:0:16}.json"
    [ "$(cj_field data.package.tracked "$plan" False)" = True ] ||
        cj_die "node $node holds the bytes but does not track the package: $plan"
    CJ_FETCH_BYTES="$(cj_field data.package.total_bytes "$plan" 0)"
    # The bytes are here; the signed release still has to be admitted into
    # this node's own index before anything can name or build it. That is one
    # more routed call, once the carrier is whole. Provider discovery runs a
    # real bounded DHT lookup, so give it room between attempts instead of
    # hammering the node's discovery queue with a tight loop.
    local attempt=0 imported=False
    while [ "$attempt" -lt 6 ]; do
        out="$("cj_$node" zcode package fetch \
            --input="{\"root\":\"$transport\",\"namespace\":\"zclassic23.package\",\"maximum_bytes\":67108864}")"
        imported="$(cj_field data.reconstructed "$out" False)"
        [ "$imported" = True ] && break
        attempt=$((attempt + 1))
        sleep 5
    done
    [ "$imported" = True ] ||
        cj_die "node $node never imported the signed release for $root: $out"
    printf '%s\n' "$out" >"$DHT_WORK/import-$node-${root:0:16}.json"
    [ "$(cj_field data.package_root "$out" '')" = "$root" ] ||
        cj_die "node $node imported a carrier naming a different package: $out"
    cj_pin_root "$node" "$transport"
    cj_pin_root "$node" "$root"
}

# ── the journey ──────────────────────────────────────────────────────────
cj_journey_guide() {
    cj_step "1/12  zcode guide — the person says what they want"
    local guide
    guide="$(cj_a zcode guide)"
    cj_require_ok "zcode guide" "$guide"
    [ -n "$(cj_field data.start_command "$guide" '')" ] ||
        cj_die "zcode guide named no start command: $guide"
    case "$(cj_field data.journey "$guide" '')" in
        *reuse*) ;;
        *) cj_die "zcode guide does not describe reuse-first: $guide" ;;
    esac
    cj_note "guide -> $(cj_field data.next_action "$guide")"
}

cj_journey_publish_reusable() {
    cj_step "2/12  the commons already contains one finished, reusable package"
    CJ_PUBLISHER="$("$CJ_SIGNER" --generate "$DHT_WORK/publisher.key")"
    [ -n "$CJ_PUBLISHER" ] || cj_die "could not create the offline publisher identity"
    CJ_TEXTSTAT_SRC="$DHT_WORK/textstat"
    cp -a "$CJ_FIXTURES/textstat" "$CJ_TEXTSTAT_SRC"
    cj_publish_package a "$CJ_TEXTSTAT_SRC" 1
    CJ_TEXTSTAT_ROOT="$CJ_PKG_ROOT"
    CJ_TEXTSTAT_RELEASE="$CJ_PKG_RELEASE"
    CJ_TEXTSTAT_RELEASE_HEX="$CJ_PKG_RELEASE_HEX"
    CJ_TEXTSTAT_TRANSPORT="$CJ_PKG_TRANSPORT"
    cj_note "z23/textstat published on node A: ${CJ_TEXTSTAT_ROOT:0:16}…"

    # Discovery is a local index query over what the node actually holds.
    local search
    search="$(cj_a zcode package search --input='{"name_prefix":"z23/"}')"
    cj_require_ok "package search" "$search"
    case "$search" in
        *z23/textstat*) ;;
        *) cj_die "the published package is not discoverable: $search" ;;
    esac
}

# A second, independent node gets the package over the network. Nothing
# central is involved: node A announces what it holds, node B asks the
# overlay for that exact content, and the bytes arrive as inert source.
# Both nodes run on one physical host; nothing here claims otherwise.
cj_journey_peer_distribution() {
    cj_step "3/12  a second node fetches it peer-to-peer — and the bytes stay inert"
    # The pointer gate: A may announce only what its own store evidences as
    # reproduced — the publisher admits its own package explicitly (first
    # receipt), then re-runs the deterministic rebuild (distinct second
    # receipt), before the pointer plan exists.
    cj_use_package a "$CJ_TEXTSTAT_ROOT"
    cj_reproduce_package a "$CJ_TEXTSTAT_ROOT"
    cj_announce_package a "$CJ_TEXTSTAT_ROOT" "$CJ_TEXTSTAT_TRANSPORT" 1

    # Before: node B has never seen this package.
    [ "$(cj_sql b "SELECT count(*) FROM build_receipts")" = 0 ] ||
        cj_die "node B already held build evidence before fetching anything"
    cj_fetch_package b "$CJ_TEXTSTAT_ROOT" "$CJ_TEXTSTAT_TRANSPORT"
    CJ_TEXTSTAT_BYTES="$CJ_FETCH_BYTES"
    cj_note "node B fetched z23/textstat from the overlay: $CJ_TEXTSTAT_BYTES bytes"

    # PROOF: fetched source stays inert. Arriving at this node executed
    # nothing and produced no evidence; only an explicit local decision can.
    [ "$(cj_sql b "SELECT count(*) FROM build_actions")" = 0 ] &&
    [ "$(cj_sql b "SELECT count(*) FROM build_receipts")" = 0 ] ||
        cj_die "fetching alone executed code or projected evidence on node B"

    # PROOF: build requires explicit local admission — and it is the person
    # on THIS node who gives it. `zcode use` is that decision.
    # By content, not by a name anyone controls: node B admits the exact
    # root it fetched. Two nodes agreeing on 64 hex characters is the
    # whole trust story.
    cj_use_package b "$CJ_TEXTSTAT_ROOT"
    cj_note "node B admitted z23/textstat explicitly: it is now installed there"
}

cj_journey_work_start_unavailable() {
    cj_step "4/12  zcode work start — reuse is searched before any code is written"
    CJ_WS="$DHT_WORK/wordcount"
    cp -a "$CJ_FIXTURES/wordcount" "$CJ_WS"
    # The application declares NO dependency yet. Whether z23/textstat may be
    # reused is a question about this node, and the honest answer before any
    # local admission is "not yet". Published is not installed: the release
    # is in A's index from step 2, but nobody on A has admitted it — the
    # pointer gate makes admission the publisher's own explicit act, one
    # step below.
    cj_write_package_json "$CJ_WS" ""
    rm -f "$CJ_WS/zcode-package.json.in"

    local start plan
    start="$(cj_a zcode work start \
        --input="{\"workspace\":\"$CJ_WS\",\"goal\":\"$CJ_GOAL\",\"profile\":\"$CJ_PROFILE\"}")"
    cj_require_ok "work start (before local admission)" "$start"
    plan="$(cj_field data.reuse_plan "$start")"

    # PROOF 2: unavailable code is never claimed as reused.
    [ "$(printf '%s' "$plan" | cj_jget reused.0.name '')" = "" ] ||
        cj_die "a package that is not installed here was claimed as reused: $plan"
    [ "$(printf '%s' "$plan" | cj_jget available_after_use.0.name '')" = "z23/textstat" ] ||
        cj_die "the reusable package was not offered at all: $plan"
    [ "$(printf '%s' "$plan" | cj_jget available_after_use.0.composition '')" = \
      "explicit_use_required" ] ||
        cj_die "reuse did not require an explicit local admission: $plan"
    cj_note "before admission: reused=[] available_after_use=[z23/textstat]"

    # PROOF 3: the next step is to reuse, not to write code.
    case "$(cj_field data.next_safe_command "$start" '')" in
        "zcode use") ;;
        *) cj_die "work start told the person to write code before reusing: $start" ;;
    esac
    cj_human_first "work start (before admission)" "$start"
}

cj_journey_admit_reuse() {
    cj_step "5/12  zcode use — explicit local admission builds and installs it"
    cj_use_package a "$CJ_TEXTSTAT_ROOT"
    local installed="$DHT_DD_A/zcode/installed/$CJ_TEXTSTAT_ROOT"
    [ -f "$installed/lib/libtextstat.a" ] ||
        cj_die "admission produced no artifact for z23/textstat"
    [ -f "$installed/include/textstat/textstat.h" ] ||
        cj_die "admission produced no public header for z23/textstat"
    CJ_TEXTSTAT_ARTIFACT="$installed/lib/libtextstat.a"

    # Now that the person has admitted it, the application declares the
    # dependency by its exact root — the same manifest an author writes by
    # hand. The declaration travels inside the accepted source, so the tree
    # that leaves this workshop as an ordinary package (step 9) names what
    # it needs, and any node that admits it resolves the same exact bytes.
    cj_write_package_json "$CJ_WS" "$CJ_TEXTSTAT_ROOT"

    # Wait until A's live swarm has actually learned B's carrier inventory.
    # The signed package POINTER already held by A maps this transport root
    # back to the semantic package root work-start ranks.
    local offered deadline i offered_root advertisers peer_seen=0
    deadline=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        offered="$(cj_a zcode package offered)"
        cj_require_ok "peer inventory before work start" "$offered"
        i=0
        while :; do
            offered_root="$(cj_field "data.items.$i.root" "$offered" '')"
            [ -n "$offered_root" ] || break
            advertisers="$(cj_field "data.items.$i.advertisers" "$offered" 0)"
            if [ "$offered_root" = "$CJ_TEXTSTAT_TRANSPORT" ] &&
               [ "$advertisers" -ge 1 ] 2>/dev/null; then
                peer_seen=1
                break
            fi
            i=$((i + 1))
        done
        [ "$peer_seen" -eq 1 ] && break
        sleep 1
    done
    [ "$peer_seen" -eq 1 ] ||
        cj_die "node A never learned node B's reusable carrier inventory: $offered"

    local start plan
    start="$(cj_a zcode work start \
        --input="{\"workspace\":\"$CJ_WS\",\"goal\":\"$CJ_GOAL\",\"profile\":\"$CJ_PROFILE\",\"details\":true}")"
    cj_require_ok "work start (after admission)" "$start"
    plan="$(cj_field data.reuse_plan "$start")"

    # PROOF 1: reusable code is selected before new code.
    [ "$(printf '%s' "$plan" | cj_jget reused.0.name '')" = "z23/textstat" ] ||
        cj_die "the admitted package was not selected for reuse: $plan"
    [ "$(printf '%s' "$plan" | cj_jget reused.0.installed False)" = True ] ||
        cj_die "reuse claimed a package that is not installed: $plan"
    [ "$(printf '%s' "$plan" | cj_jget network_discovery '')" = \
      "signed_pointer_peer_inventory_consulted" ] ||
        cj_die "work start did not consult the signed peer inventory: $plan"
    [ "$(printf '%s' "$plan" | cj_jget reused.0.peer_advertisers 0)" -ge 1 ] ||
        cj_die "work start did not bind the selected reuse to a peer carrier: $plan"
    [ "$(printf '%s' "$plan" | cj_jget available_after_use.0.name '')" = "" ] ||
        cj_die "an admitted package is still pending admission: $plan"
    # Its API is known by symbol, not guessed from the name.
    case "$(printf '%s' "$plan" | cj_jget reused.0.apis '')" in
        *textstat_words*) ;;
        *) cj_die "reuse selected a package without reading its API: $plan" ;;
    esac

    # PROOF 3: only the behavior still missing enters candidate work.
    [ "$(printf '%s' "$plan" | cj_jget new_code_required False)" = True ] ||
        cj_die "the missing behavior was not recognised as missing: $plan"
    [ "$(printf '%s' "$plan" | cj_jget missing '')" = "$CJ_GOAL" ] ||
        cj_die "the missing behavior is not the goal: $plan"
    CJ_WORK_ID="$(cj_field data.work_id "$start")"
    CJ_TASK_ROOT="$(printf '%s' "$(cj_field data.expert "$start")" | cj_jget task_root)"
    [ -n "$CJ_TASK_ROOT" ] || cj_die "work start bound no task root: $start"
    cj_note "after admission: reused=[z23/textstat installed] work=$CJ_WORK_ID"
}

# The one behavior nothing in the commons provides. It is written here, in
# the acceptance, because the acceptance is playing the part of the person
# (or the adapter) who supplies the missing code: the journey has to prove
# that only THIS enters candidate work, not that a model invented it.
cj_write_missing_behavior() {
    cat >>"$1/src/wordcount.c" <<'CREATED'

/* Created by this journey. Nothing in the commons measured a longest line,
 * so this is the only behavior that was written rather than reused. */
size_t wordcount_longest_line(const char *text, size_t len)
{
    if (!text) return 0;
    size_t longest = 0, current = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\n') {
            if (current > longest) longest = current;
            current = 0;
            continue;
        }
        current++;
    }
    return current > longest ? current : longest;
}
CREATED
}

# The requester learns which identity proved its work from the receipt itself
# and approves that exact signer. There is no harness-side lifecycle bit: once
# the worker is approved the query returns no row and this is a no-op.
cj_sql() {
    local node="$1" sql="$2"
    "cj_$node" core storage query --sql="$sql" 2>/dev/null | cj_jget data.rows.0.0 ''
}

cj_approve_proving_worker() {
    local identity worker pubkey response
    identity="$(cj_sql a "SELECT r.worker_id||':'||w.signer_pubkey FROM build_receipts r JOIN build_workers w ON w.worker_id=r.worker_id WHERE r.trust_state='REMOTE_OBSERVED' AND w.approved=0 AND w.revoked=0 LIMIT 1")"
    [ -n "$identity" ] || return 0
    worker="${identity%%:*}"; pubkey="${identity#*:}"
    [ "${#worker}" -eq 64 ] && [ "${#pubkey}" -eq 64 ] ||
        cj_die "a remote receipt did not name its exact signer: $identity"
    # `datadir` again, and for the same reason as `zcode work run`: only an
    # explicitly targeted node ledger receives a live trust write. Without it
    # the leaf refuses with MISSING_DATADIR rather than quietly approving a
    # signer in a one-shot scratch lifecycle nobody will ever read.
    response="$(cj_a metaverse build worker approve \
        --input="{\"worker_id\":\"$worker\",\"signer_pubkey\":\"$pubkey\",\"capabilities\":\"p2p-approved,c23.package.recipe.v1\",\"datadir\":\"$DHT_DD_A\"}")"
    cj_require_ok "approving the proving worker" "$response"
    [ "$(cj_field data.approved "$response" False)" = True ] ||
        cj_die "the proving worker was not approved: $response"
    CJ_PROVER_WORKER="$worker"
    cj_note "node A approved the exact identity that proved its work: ${worker:0:16}…"
}

# The workspace is a parameter with a default so the nine steps above read
# exactly as they did, while step 10 can wait on its own work.
cj_wait_work_state() {
    local want="$1" budget="${2:-300}" ws="${3:-$CJ_WS}" deadline state show
    deadline=$(( $(date +%s) + budget ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        cj_approve_proving_worker
        show="$(cj_a zcode work status \
            --input="{\"workspace\":\"$ws\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\"}")"
        state="$(cj_field data.state "$show" '')"
        [ "$state" = "$want" ] && { CJ_LAST_SHOW="$show"; return 0; }
        sleep 1
    done
    CJ_LAST_SHOW="$show"
    return 1
}

cj_journey_create_missing() {
    cj_step "6/12  zcode work run — only the missing behavior enters candidate work"
    local handoff candidate run
    handoff="$(cj_a zcode work run \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"adapter\":\"manual\",\"details\":true}")"
    cj_require_ok "work run (handoff)" "$handoff"
    candidate="$(cj_field data.candidate_workspace "$handoff" '')"
    [ -d "$candidate" ] || cj_die "work run exported no candidate workspace: $handoff"
    [ "$(cj_field data.authority "$handoff" '')" = "NONE_MANUAL_HANDOFF" ] ||
        cj_die "the manual handoff claimed authority it must not have: $handoff"
    # The packet carries the goal and the exact locked dependency, so the
    # creator is told what is already reused rather than reimplementing it.
    local packet
    packet="$(cat "$candidate/.zcode-adapter-packet.json")"
    [ "$(printf '%s' "$packet" | cj_jget locked_dependencies.0.name '')" = \
      "z23/textstat" ] ||
        cj_die "the candidate packet did not carry the reused dependency"
    [ "$(printf '%s' "$packet" | cj_jget locked_dependencies.0.package_root '')" = \
      "$CJ_TEXTSTAT_ROOT" ] ||
        cj_die "the candidate packet bound a different dependency root"
    cj_write_missing_behavior "$candidate"
    CJ_REUSED_C23_BYTES="$(cj_c23_source_bytes "$CJ_TEXTSTAT_SRC")"
    CJ_APPLICATION_C23_BYTES="$(cj_c23_source_bytes "$candidate")"
    CJ_C23_CLOSURE_BYTES=$((CJ_REUSED_C23_BYTES + CJ_APPLICATION_C23_BYTES))
    [ "$CJ_REUSED_C23_BYTES" -gt 0 ] &&
    [ "$CJ_APPLICATION_C23_BYTES" -gt 0 ] &&
    [ "$CJ_C23_CLOSURE_BYTES" -gt "$CJ_REUSED_C23_BYTES" ] ||
        cj_die "the C23 source closure could not be measured"
    CJ_REUSE_RATIO_BPS=$((CJ_REUSED_C23_BYTES * 10000 / CJ_C23_CLOSURE_BYTES))
    # `datadir` is what turns this from a local-only projection into a real
    # submission by the live node: the requester binds the immutable action
    # and asks the overlay for an independent prover. A node never proves its
    # own work, so without this the action would simply sit SNAPSHOTTED.
    run="$(cj_a zcode work run \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"adapter\":\"manual\",\"datadir\":\"$DHT_DD_A\",\"details\":true}")"
    cj_require_ok "work run (candidate)" "$run"
    [ "$(cj_field data.state "$run" '')" = "CANDIDATE_ADMITTED" ] ||
        cj_die "the candidate was not admitted: $run"
    # Exactly one source file changed: the created behavior, nothing else.
    CJ_CANDIDATE_ROOT="$(printf '%s' "$(cj_field data.expert "$run")" | cj_jget candidate_root)"
    CJ_ACTION_ID="$(printf '%s' "$(cj_field data.expert "$run")" | cj_jget action_id)"
    [ -n "$CJ_CANDIDATE_ROOT" ] && [ -n "$CJ_ACTION_ID" ] ||
        cj_die "the admitted candidate bound no candidate root or action: $run"
    # PROOF: the requester asked the commons instead of proving itself. It
    # owns the immutable action and one REQUESTED proof event, and its own
    # copy of that action stays SNAPSHOTTED with no worker and no attempt.
    CJ_PROOF_EVENT="$(cj_field data.async_proof_event_root "$run" '')"
    [ "${#CJ_PROOF_EVENT}" -eq 64 ] ||
        cj_die "the admitted candidate carried no async proof event root: $run"
    [ "$(cj_sql a "SELECT count(*) FROM build_proof_events WHERE action_id='$CJ_ACTION_ID' AND state='REQUESTED'")" = 1 ] ||
        cj_die "node A did not request independent proof for $CJ_ACTION_ID"
    [ "$(cj_sql a "SELECT count(*) FROM build_actions WHERE action_id='$CJ_ACTION_ID' AND state='SNAPSHOTTED' AND attempt_count=0 AND started_at=0 AND length(worker_id)=0")" = 1 ] ||
        cj_die "node A executed its own work instead of asking the commons"
    cj_human_first "work run (candidate)" "$run"
    cj_note "candidate admitted: ${CJ_CANDIDATE_ROOT:0:16}… action ${CJ_ACTION_ID:0:16}…"
}

# EVIDENCE_READY says the proof arrived, not that it counts. A receipt from
# another node lands as REMOTE_OBSERVED: real evidence, no authority. The
# operator has to approve that exact signer before the ledger will let it
# stand as a build result — which is the whole point, and also why polling
# only for the state is not enough. Approve, then wait for the result the
# person actually reads.
cj_wait_proof_result() {
    local budget="${1:-180}" ws="${2:-$CJ_WS}" deadline show result
    deadline=$(( $(date +%s) + budget ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        cj_approve_proving_worker
        show="$(cj_a zcode work show \
            --input="{\"workspace\":\"$ws\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\"}")"
        result="$(cj_field data.confirmation_ready "$show" False)"
        [ "$result" = True ] && { CJ_LAST_SHOW="$show"; return 0; }
        sleep 1
    done
    CJ_LAST_SHOW="$show"
    return 1
}

cj_journey_show() {
    cj_step "7/12  zcode work show — the person sees the real consequence"
    cj_wait_work_state EVIDENCE_READY ||
        cj_die "the candidate never reached EVIDENCE_READY: $CJ_LAST_SHOW"
    cj_wait_proof_result ||
        cj_die "node B proved it, but node A never counted the result: $CJ_LAST_SHOW"
    local plain detailed
    # The same `datadir` the proof was submitted through. Without it this leaf
    # reads no canonical proof ledger at all and answers build_result and
    # test_result "unknown" for work that is demonstrably EVIDENCE_READY —
    # the person is shown "no proof result inferred" about their own proven
    # change. `zcode.work.show` used to REJECT this key outright while its
    # twin `zcode.work.status` accepted it; check_command_input_keys now
    # fails on that divergence.
    plain="$(cj_a zcode work show \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\"}")"
    cj_require_ok "work show" "$plain"
    detailed="$(cj_a zcode work show \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\",\"details\":true}")"
    cj_require_ok "work show (details)" "$detailed"

    # The consequence is the changed files and the proof result, in words.
    [ "$(cj_field data.changed_files "$plain" 0)" -ge 1 ] ||
        cj_die "work show reported no change at all: $plain"
    case "$(cj_field data.changed_paths "$plain" '')" in
        *src/wordcount.c*) ;;
        *) cj_die "work show did not name the file that changed: $plain" ;;
    esac
    [ "$(cj_field data.build_result "$plain" '')" = passed ] ||
        cj_die "work show does not report a passing build: $plain"
    case "$(cj_field data.test_result "$plain" '')" in
        passed*) ;;
        *) cj_die "work show does not report passing tests: $plain" ;;
    esac
    # The grade is the whole point of the second node: node A did not build
    # this, node B did, and node A counts it only because it approved that
    # exact signer.
    [ "$(cj_field data.reproduction_grade "$plain" '')" != none ] ||
        cj_die "work show claims no independent reproduction at all: $plain"
    [ "$(cj_field data.confirmation_ready "$plain" False)" = True ] ||
        cj_die "work show does not offer the person a decision: $plain"
    cj_human_first "work show" "$plain"
    cj_roots_hidden "work show" "$plain" "$detailed"
}

# ── the authenticated overlay the journey travels over ───────────────────
# Two service types cross it. `zclassic23.package` carries software bytes
# from whoever holds them; `zclassic23.work` carries one immutable action to
# whoever is willing to prove it. A node never proves its own work: `zcode
# work run` deliberately leaves its action SNAPSHOTTED so the requester's own
# worker cannot race the peer and mask missing remote evidence. Node B is
# therefore the independent build worker, and this is what makes that
# possible — one allow rule per service type on each node, and one real
# authenticated DHT session between them.
cj_allow_policy() {
    local node="$1" service="$2" common plan token commit ok code message
    common='"operation":"add","source":"local","effect":"allow","scope":"service_type","action_mask":63,"value":"'"$service"'"'
    plan="$("cj_$node" zcode network policy mutate --input="{\"mode\":\"plan\",$common}")"
    cj_require_ok "node $node $service policy plan" "$plan"
    token="$(cj_field data.plan_token "$plan")"
    commit="$("cj_$node" zcode network policy mutate \
        --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}")"
    ok="$(cj_field ok "$commit" False)"
    code="$(cj_field error.code "$commit" '')"
    message="$(cj_field error.message "$commit" '')"
    [ "$ok" = True ] ||
        { [ "$code" = POLICY_REFUSED ] && [ "$message" = duplicate ]; } ||
        cj_die "node $node could not allow the $service service type: $commit"
}

cj_wait_dht_enabled() {
    local deadline a b
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        a="$(cj_field data.enabled "$(dht_status "$DHT_DD_A" "$A_RPC")" False)"
        b="$(cj_field data.enabled "$(dht_status "$DHT_DD_B" "$B_RPC")" False)"
        [ "$a" = True ] && [ "$b" = True ] && return 0
        sleep 0.5
    done
    return 1
}

# Capability learning tears down the first plaintext P2P connection and
# replaces it with Noise, and a lookup admitted in that interval belongs to
# the retired transport. Observe both ends and re-arm one fresh lookup once.
cj_connect_authenticated() {
    local deadline find lookup owner rearmed=0 auth_a auth_b started
    # Both directions. Software travels the same links the chain does, and a
    # node that only ever accepts inbound connections is not a participant in
    # the commons: it has to be able to ask a peer for bytes too.
    a_rpc addnode "\"$CJ_PEER_ADDR_B:$B_PORT\"" '"onetry"' >/dev/null || true
    b_rpc addnode "\"$CJ_PEER_ADDR_A:$A_PORT\"" '"onetry"' >/dev/null || true
    cj_wait_dht_enabled || cj_die "the two nodes' DHTs never both enabled"
    find="$(cj_a zcode network find begin --input="{\"node_id\":\"$CJ_NODE_B\"}")"
    cj_require_ok "node A lookup of node B" "$find"
    lookup="$(cj_field data.lookup_id "$find")"
    owner="$(cj_field data.owner_token "$find")"
    started="$(date +%s)"
    deadline=$((started + DHT_WAIT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        auth_a="$(cj_field data.connected_authenticated \
            "$(dht_status "$DHT_DD_A" "$A_RPC")" 0)"
        auth_b="$(cj_field data.connected_authenticated \
            "$(dht_status "$DHT_DD_B" "$B_RPC")" 0)"
        if [ "${auth_a:-0}" -ge 1 ] 2>/dev/null &&
           [ "${auth_b:-0}" -ge 1 ] 2>/dev/null; then
            cj_a zcode network find cancel \
                --input="{\"lookup_id\":\"$lookup\",\"owner_token\":\"$owner\"}" \
                >/dev/null || true
            cj_note "authenticated overlay session established A <-> B"
            return 0
        fi
        if [ "$rearmed" -eq 0 ] && [ "$(date +%s)" -ge $((started + 20)) ]; then
            rearmed=1
            find="$(cj_a zcode network find begin \
                --input="{\"node_id\":\"$CJ_NODE_B\"}")"
            lookup="$(cj_field data.lookup_id "$find" '')"
            owner="$(cj_field data.owner_token "$find" '')"
        fi
        sleep 0.5
    done
    cj_die "the two nodes never formed an authenticated overlay session"
}

cj_overlay() {
    cj_step "the authenticated overlay the two nodes share"
    # Four service types cross this overlay: package bytes, one immutable
    # work action, the signed source-reproduction evidence node B publishes
    # after it rebuilds what node A accepted, and the fastobj carrier node B
    # exports in step 10. Sovereignty denies everything but discovery unless
    # a rule says otherwise, so a node storing or serving a new service type
    # is always an explicit opt-in made here — before the restart below,
    # because a policy mutation only governs after the DHT restarts.
    cj_allow_policy a zclassic23.package; cj_allow_policy a zclassic23.work
    cj_allow_policy a zclassic23.source
    cj_allow_policy b zclassic23.package; cj_allow_policy b zclassic23.work
    cj_allow_policy b zclassic23.source
    cj_allow_policy b zclassic23.fastobj
    dht_kill_group "$DHT_PGID_B"; DHT_PGID_B=""
    dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
    DHT_BUILDWORKERS=1
    dht_spawn DHT_PGID_B "$DHT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" \
        "$B_HTTPS" "127.0.0.1:$DEAD_SINK"
    cj_wait_rpc_or_die "$DHT_DD_B" "$B_RPC" "$DHT_PGID_B" "node B (build worker)"
    DHT_BUILDWORKERS=0
    dht_spawn DHT_PGID_A "$DHT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" \
        "$A_HTTPS" "127.0.0.1:$DEAD_SINK"
    cj_wait_rpc_or_die "$DHT_DD_A" "$A_RPC" "$DHT_PGID_A" "node A (requester)"
    cj_connect_authenticated
}

# ── 8/12  the person decides, and the exact bytes travel ──────────────────
# CANDIDATE is proof readiness. PROVEN is a human decision, and only this
# command makes it. Everything downstream — publication, the source carrier
# another node reconstructs — is derived from that one decision, which is
# why acceptance can be bound to the exact facts the person was shown.
cj_journey_accept() {
    cj_step "8/12  zcode work accept — the person decides, and the exact bytes travel"
    local stale accept again

    # TAMPER (receipt): an acceptance bound to a decision that was never
    # shown. The identity is a hash over the exact task, candidate, policy
    # and proof set; anything else is a different decision.
    stale="$(cj_a zcode work accept \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\",\"confirmation_identity\":\"$CJ_FAKE_ROOT\"}")"
    cj_require_refusal "acceptance bound to a decision nobody was shown" \
        "$stale" "CONFIRMATION_IDENTITY_STALE"

    accept="$(cj_a zcode work accept \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\",\"details\":true}")"
    cj_require_ok "work accept" "$accept"
    printf '%s\n' "$accept" >"$DHT_WORK/accept.json"
    [ "$(cj_field data.state "$accept" '')" = PROVEN ] ||
        cj_die "acceptance did not reach PROVEN: $accept"
    [ "$(cj_field data.goal_decision "$accept" '')" = accepted ] ||
        cj_die "acceptance did not record the person's decision: $accept"
    CJ_ACCEPTED_SOURCE="$(printf '%s' "$(cj_field data.expert "$accept")" | cj_jget source_root '')"
    [ "${#CJ_ACCEPTED_SOURCE}" -eq 64 ] ||
        cj_die "acceptance bound no accepted source root: $accept"
    # The lane receipt IS the accepted work: every later step that has to
    # prove "a person accepted exactly this" resolves that chain from here.
    CJ_ACCEPTED_WORK="$(printf '%s' "$(cj_field data.expert "$accept")" | cj_jget lane_receipt_root '')"
    [ "${#CJ_ACCEPTED_WORK}" -eq 64 ] ||
        cj_die "acceptance bound no lane receipt root: $accept"

    # Saying yes twice is the same yes.
    again="$(cj_a zcode work accept \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\"}")"
    cj_require_ok "work accept (repeat)" "$again"
    [ "$(cj_field data.idempotent "$again" False)" = True ] ||
        cj_die "repeating an acceptance was not idempotent: $again"
    cj_human_first "work accept" "$again"
    cj_roots_hidden "work accept" "$again" "$accept"

    # One lifecycle fact, one interpretation: with the work PROVEN, run and
    # status must agree. A repeated run observes the accepted state; it never
    # opens a fresh candidate attempt on work already accepted.
    local rerun
    rerun="$(cj_a zcode work run \
        --input="{\"workspace\":\"$CJ_WS\",\"work\":\"latest\",\"adapter\":\"manual\",\"datadir\":\"$DHT_DD_A\"}")"
    cj_require_ok "work run after acceptance" "$rerun"
    [ "$(cj_field data.state "$rerun" '')" = PROVEN ] ||
        cj_die "run after acceptance disagreed with status: $rerun"
    [ -z "$(cj_field data.candidate_workspace "$rerun" '')" ] ||
        cj_die "run after acceptance opened a fresh candidate: $rerun"
    cj_note "accepted: PROVEN, source ${CJ_ACCEPTED_SOURCE:0:16}…"
}

# The accepted work becomes an ordinary package anyone can hold. It is
# published by a SECOND offline identity under a SECOND namespace:
# z23/textstat came from whoever wrote it, and `you/wordcount` is this
# person's own. Both halves matter — a publisher namespace binds first-come
# to one key, so the person's application cannot be published into someone
# else's name and their own name cannot be taken from them. The publisher
# secret never enters the node: plan returns a digest, the signature is made
# outside, and commit carries the sealed envelope.
cj_journey_publish_accepted() {
    local plan digest body signature seal commit
    CJ_APP_PUBLISHER="$("$CJ_SIGNER" --generate "$DHT_WORK/app-publisher.key")"
    [ -n "$CJ_APP_PUBLISHER" ] ||
        cj_die "could not create the application publisher identity"
    plan="$(cj_a zcode publish plan \
        --input="{\"workspace\":\"$CJ_WS\",\"datadir\":\"$DHT_DD_A\",\"source_root\":\"$CJ_ACCEPTED_SOURCE\",\"publisher_pubkey\":\"$CJ_APP_PUBLISHER\"}")"
    cj_require_ok "publish plan (accepted work)" "$plan"
    printf '%s\n' "$plan" >"$DHT_WORK/app-publish-plan.json"
    digest="$(cj_field data.release_signing_digest "$plan" '')"
    body="$(cj_field data.release_body_hex "$plan" '')"
    [ -n "$digest" ] && [ -n "$body" ] ||
        cj_die "publish plan returned nothing to sign: $plan"
    signature="$(cj_sign_digest "$digest" "$DHT_WORK/app-publisher.key")"
    seal="$(cj_a zcode package dev seal \
        --input="{\"release_body_hex\":\"$body\",\"signature_hex\":\"$signature\"}")"
    cj_require_ok "seal (accepted work)" "$seal"
    CJ_APP_RELEASE_HEX="$(cj_field data.release_hex "$seal" '')"
    [ -n "$CJ_APP_RELEASE_HEX" ] || cj_die "sealing produced no release: $seal"
    commit="$(cj_a zcode publish \
        --input="{\"workspace\":\"$CJ_WS\",\"datadir\":\"$DHT_DD_A\",\"source_root\":\"$CJ_ACCEPTED_SOURCE\",\"release_hex\":\"$CJ_APP_RELEASE_HEX\"}")"
    cj_require_ok "publish commit (accepted work)" "$commit"
    printf '%s\n' "$commit" >"$DHT_WORK/app-publish-commit.json"
    CJ_APP_ROOT="$(cj_field data.package_root "$commit" '')"
    CJ_APP_TRANSPORT="$(cj_field data.transport_root "$commit" '')"
    [ "${#CJ_APP_ROOT}" -eq 64 ] ||
        cj_die "the accepted application was published without a package root: $commit"
    [ "${#CJ_APP_TRANSPORT}" -eq 64 ] ||
        cj_die "the accepted application was published without a carrier: $commit"
    cj_note "you/wordcount published from the accepted work: ${CJ_APP_ROOT:0:16}…"
}

# A second node reconstructs the exact source from the carrier it fetched
# and signs one SOURCE_REPRODUCTION_ACK for it. The ACK names the source tree
# root it derived; if that root equals the one node A accepted, two
# independent nodes built the same bytes from the same evidence.
# cj_reproduce_accepted_source is the leg itself; node C reuses it after the
# publisher disappears, so the proof has one owner.
cj_reproduce_accepted_source() {
    local node="$1" dd="$2"
    local plan commit seq nb exp token derived
    plan="$("cj_$node" zcode package source reproduce \
        --input="{\"mode\":\"plan\",\"root\":\"$CJ_APP_ROOT\",\"datadir\":\"$dd\"}")"
    cj_require_ok "node $node source reproduce plan" "$plan"
    printf '%s\n' "$plan" >"$DHT_WORK/reproduce-plan-$node.json"
    [ "$(cj_field data.reconstructed "$plan" False)" = True ] ||
        cj_die "node $node did not reconstruct the source: $plan"
    derived="$(cj_field data.source_tree_root "$plan" '')"
    [ "$derived" = "$CJ_ACCEPTED_SOURCE" ] ||
        cj_die "node $node reconstructed different source bytes: got $derived want $CJ_ACCEPTED_SOURCE"
    seq="$(printf '%s' "$(cj_field data.commit_input "$plan")" | cj_jget sequence 0)"
    nb="$(printf '%s' "$(cj_field data.commit_input "$plan")" | cj_jget not_before 0)"
    exp="$(printf '%s' "$(cj_field data.commit_input "$plan")" | cj_jget expiry 0)"
    token="$(printf '%s' "$(cj_field data.commit_input "$plan")" | cj_jget plan_token '')"
    commit="$("cj_$node" zcode package source reproduce \
        --input="{\"mode\":\"commit\",\"root\":\"$CJ_APP_ROOT\",\"datadir\":\"$dd\",\"sequence\":$seq,\"not_before\":$nb,\"expiry\":$exp,\"plan_token\":\"$token\"}")"
    cj_require_ok "node $node source reproduce commit" "$commit"
    printf '%s\n' "$commit" >"$DHT_WORK/reproduce-commit-$node.json"
    [ "$(cj_field data.evidence_signed "$commit" False)" = True ] ||
        cj_die "node $node published no signed reproduction evidence: $commit"
    [ "$(cj_field data.physical_independence_attested "$commit" True)" = False ] ||
        cj_die "a same-host reproduction claimed physical independence: $commit"
    cj_note "node ${node^^} reproduced the exact source and signed for it: ${derived:0:16}…"
}

cj_journey_remote_reproduction() {
    # The accepted application is a source transport: it announces provider
    # (the bytes) and source (the derivation), never a pointer — the pointer
    # gate requires local reproduction evidence, and the standard profile
    # refuses a recipe without declared tests. Cross-node proof for a
    # transport is the source ACK below, which is stronger than a pointer
    # anyway: B re-derives the exact source root A accepted.
    cj_announce_transport a "$CJ_APP_ROOT" "$CJ_APP_TRANSPORT" 1
    cj_fetch_package b "$CJ_APP_ROOT" "$CJ_APP_TRANSPORT"
    CJ_APP_BYTES="$CJ_FETCH_BYTES"
    cj_note "node B fetched the accepted application: $CJ_APP_BYTES bytes"
    cj_reproduce_accepted_source b "$DHT_DD_B"
    cj_consume_source_receipt a "$CJ_NODE_B" "$CJ_APP_ROOT" \
        "$CJ_ACCEPTED_SOURCE"
}

# Four ways to hand a node something that is not what it claims to be. Each
# one must be refused BY NAME: a refusal whose reason the person can read is
# the difference between a system that is safe and a system that is silent.
# The fourth (a receipt bound to a decision nobody was shown) was already
# refused in step 8, where that decision is made.
cj_journey_tamper_refusals() {
    local refused restored chunk saved

    # ALTERED SOURCE: a source root nobody accepted cannot be published, even
    # by the person who owns the workspace and the publisher key.
    refused="$(cj_a zcode publish plan \
        --input="{\"workspace\":\"$CJ_WS\",\"datadir\":\"$DHT_DD_A\",\"source_root\":\"$CJ_FAKE_ROOT\",\"publisher_pubkey\":\"$CJ_APP_PUBLISHER\"}")"
    cj_require_refusal "altered source" "$refused" "$CJ_REFUSAL_SOURCE"

    # ALTERED DEPENDENCY: a dependency nobody holds is never silently skipped.
    refused="$(cj_b zcode use --input="{\"name_or_root\":\"$CJ_FAKE_ROOT\"}")"
    cj_require_refusal "altered dependency" "$refused" "$CJ_REFUSAL_DEPENDENCY"

    # ALTERED ARTIFACT: the bytes node B is holding for the accepted
    # application are changed on disk, in the content store itself. The next
    # command that turns those bytes back into source must notice by content
    # — the store is addressed by hash, so a chunk that no longer hashes to
    # its own name is not the artifact it claims to be.
    chunk="$(cj_source_chunk_file b "$CJ_APP_ROOT")"
    saved="$(cj_node_dir b)/app-chunk.saved"
    cj_on b cp "$chunk" "$saved"
    cj_on b "$(cj_helper_on b)" flip-byte "$chunk" last >/dev/null
    refused="$(cj_checkout_accepted b "$(cj_node_dir b)/tamper-checkout")"
    cj_on b cp "$saved" "$chunk"
    cj_require_refusal "altered artifact" "$refused" "$CJ_REFUSAL_ARTIFACT"

    # And the restored store is whole again: a tamper test that leaves the
    # node broken proves nothing about the node.
    restored="$(cj_checkout_accepted b "$(cj_node_dir b)/restored-checkout")"
    cj_require_ok "checkout after the altered bytes were restored" "$restored"
    cj_note "tamper refused by name: source, dependency, receipt, artifact"
}

# ── 9/12  the accepted application runs ───────────────────────────────────
# What was published from the accepted work is a source carrier: it holds the
# exact accepted source as verified shards, its closed authority chain, and
# an inert marker. That is deliberate — distributing software is not the same
# act as running it, and nothing a peer sends may build itself on arrival.
# So the last step is the one a person actually performs: admit the package
# locally, turn it back into source, and build it against the dependency this
# node already admitted.
cj_journey_use_app() {
    cj_step "9/12  zcode use — the accepted application runs on the second node"
    local src_b src_a bin_b bin_a sample out want ts_a ts_b

    # The person on node B admits the accepted application explicitly.
    cj_use_package b "$CJ_APP_ROOT"
    cj_on b test -d "$DHT_DD_B/zcode/installed/$CJ_APP_ROOT" ||
        cj_die "node B admitted the accepted application but installed nothing"

    # Two nodes, one dependency, one set of bytes: node A and node B each
    # built z23/textstat with their own build fabric from source they each
    # obtained separately, and the artifacts match byte for byte.
    ts_a="$DHT_DD_A/zcode/installed/$CJ_TEXTSTAT_ROOT/lib/libtextstat.a"
    ts_b="$DHT_DD_B/zcode/installed/$CJ_TEXTSTAT_ROOT/lib/libtextstat.a"
    [ "$(cj_sha3_on a "$ts_a")" = "$(cj_sha3_on b "$ts_b")" ] ||
        cj_die "the two nodes built different bytes for the reused package"
    CJ_LIB_BYTES="$(cj_bytes_on b "$ts_b")"
    cj_note "both nodes built byte-identical z23/textstat ($CJ_LIB_BYTES bytes)"

    # Node B turns the carrier back into the accepted source. The command
    # verifies every shard against the accepted source root and re-resolves
    # the PROVEN authority before it writes a single file.
    src_b="$(cj_node_dir b)/checkout-b"
    cj_require_ok "node B accepted-source checkout" \
        "$(cj_checkout_accepted b "$src_b")"
    cj_on b test -f "$src_b/include/wordcount/wordcount.h" ||
        cj_die "the accepted source arrived without its public header"
    cj_on b grep -q wordcount_longest_line "$src_b/src/wordcount.c" ||
        cj_die "the accepted source does not contain the behavior this journey created"

    # The visible result — produced by the product, not by this script. The
    # accepted tree's own manifest declares the program it ships
    # ("programs": ["app/main.c"]), so publishing it as an ordinary package
    # gives it a recipe whose build receipt covers the executable as well as
    # the library. `zcode use` then builds and installs bin/wordcount on each
    # node, from bytes that node verified itself, in that node's confined
    # worker. This proof spawns no compiler: every program it runs below is
    # a receipt-bound install output, and each node's reply hands the person
    # the exact next action.
    src_a="$(cj_node_dir a)/checkout-a"
    cj_require_ok "node A accepted-source checkout" \
        "$(cj_checkout_accepted a "$src_a")"
    # The accepted source already travelled as the inert transport
    # you/wordcount, released by this person's key. Two rules the commons
    # enforces stop that same release from doubling as the runnable product:
    # a namespace is bound to the first key that releases under it, and a
    # new-user key gets one publish per ISO week. So the product is a
    # separate package, apps/wordcount, from its own key: the accepted
    # checkout unchanged except for the package name in its manifest.
    cj_write_package_json "$src_a" "$CJ_TEXTSTAT_ROOT" apps/wordcount
    CJ_APP_PKG_PUBLISHER="$("$CJ_SIGNER" --generate "$DHT_WORK/app-package-publisher.key")"
    [ -n "$CJ_APP_PKG_PUBLISHER" ] ||
        cj_die "could not create the application package publisher identity"
    cj_publish_package a "$src_a" 1 "$CJ_APP_PKG_PUBLISHER" \
        "$DHT_WORK/app-package-publisher.key"
    CJ_APP_PKG_ROOT="$CJ_PKG_ROOT"
    CJ_APP_PKG_TRANSPORT="$CJ_PKG_TRANSPORT"
    cj_note "apps/wordcount published as an ordinary package on node A: ${CJ_APP_PKG_ROOT:0:16}…"
    # The pointer gate binds A here exactly as it bound A for z23/textstat:
    # admit (first receipt — and the install that carries bin/wordcount),
    # rebuild (distinct second receipt), then announce.
    cj_use_package a "$CJ_APP_PKG_ROOT"
    bin_a="$(cj_program_path "$CJ_USE_COMMIT" wordcount)"
    [ -n "$bin_a" ] && cj_on a test -x "$bin_a" ||
        cj_die "node A admitted apps/wordcount but installed no executable program"
    cj_reproduce_package a "$CJ_APP_PKG_ROOT"
    cj_announce_package a "$CJ_APP_PKG_ROOT" "$CJ_APP_PKG_TRANSPORT" 1

    # Node B: fetch the exact root, admit it explicitly, and the program is
    # there — built by node B, on node B, from source node B verified.
    cj_fetch_package b "$CJ_APP_PKG_ROOT" "$CJ_APP_PKG_TRANSPORT"
    cj_use_package b "$CJ_APP_PKG_ROOT"
    bin_b="$(cj_program_path "$CJ_USE_COMMIT" wordcount)"
    [ -n "$bin_b" ] && cj_on b test -x "$bin_b" ||
        cj_die "node B admitted apps/wordcount but installed no executable program"
    case "$bin_b" in
        "$DHT_DD_B/zcode/installed/$CJ_APP_PKG_ROOT/bin/wordcount") ;;
        *) cj_die "node B installed the program somewhere other than its own package tree: $bin_b" ;;
    esac
    CJ_APP_BIN_B="$bin_b"

    sample="$DHT_WORK/sample.txt"
    printf '%s\n' \
        'the commons is not a registry' \
        'it is whoever happens to hold the bytes right now' \
        'and the name of a thing is what it contains' >"$sample"
    sample_b="$(cj_node_dir b)/sample-b.txt"
    dht_node_put "$B_RPC" "$sample" "$sample_b" ||
        cj_die "sample input never reached node B"
    out="$(cj_on b "$bin_b" "$sample_b")"
    # The oracle is deliberately not this project: coreutils wc and awk count
    # the same file independently, so the assertion cannot drift into "what
    # our own code happened to print".
    want="lines $(wc -l <"$sample") words $(wc -w <"$sample") bytes $(wc -c <"$sample") longest_line $(awk "{ if (length(\$0) > m) m = length(\$0) } END { print m + 0 }" "$sample")"
    [ "$out" = "$want" ] ||
        cj_die "the application ran but answered '$out' instead of '$want'"
    CJ_APP_OUTPUT="$out"

    # And it is the same program on both nodes: node A built it from the
    # source it accepted, node B from the source it fetched and verified,
    # each in its own confined worker, and the two receipt-bound executables
    # are the same bytes.
    [ "$(cj_sha3_on a "$bin_a")" = "$(cj_sha3_on b "$bin_b")" ] ||
        cj_die "the two nodes built different programs from the same accepted source"
    CJ_APP_BINARY_BYTES="$(cj_bytes_on b "$bin_b")"
    cj_note "wordcount sample.txt -> $CJ_APP_OUTPUT"
    cj_note "identical $CJ_APP_BINARY_BYTES-byte program on both nodes, installed by zcode use as bin/wordcount"
    cj_note "the longest_line number is the behavior this journey created"
}

# ── 10/12  the object-set carrier: the compile cache itself travels ───────
# Steps 1-9 moved source. This step moves the WORK: node B's confined rebuild
# of the z23/textstat library fills a fastobj cache (one object + one sidecar
# per translation unit, each keyed by content the cache itself re-derives),
# the cache leaves as ONE ordinary content.v2 package, and node C — which has
# never compiled this library — reproduces it with ZERO compiler spawns and
# files the byte-identical receipt. The library, not the accepted application,
# is the reproduce leaf's vehicle: `zcode package reproduce` re-runs the
# package's own committed recipe under the standard profile, which signs
# evidence only for recipes with declared tests — the accepted application is
# a source transport whose recipe carries no tests, while the library's
# recipe (tests/test_textstat.c) is exactly what the standard profile is for.
# The carrier rides its own namespace (zclassic23.fastobj): a fetch under
# zclassic23.package would force the transport-import path on a root that is
# not a transport.
cj_journey_object_set_carrier() {
    cj_step "10/12  object-set carrier — the compile cache leaves node B as one ordinary package"
    local cache_b cold cold_id carrier export_out shape
    local cold_misses cold_hits

    # Node B admitted z23/textstat explicitly in step 3. Its reproduce build
    # now runs with a fastobj cache attached: every TU it compiles lands in
    # the cache; nothing is reused yet.
    cache_b="$(cj_node_dir b)/fastobj-cache"
    cj_on b rm -rf "$cache_b"
    cold="$("cj_b" zcode package reproduce \
        --input="{\"name_or_root\":\"$CJ_TEXTSTAT_ROOT\",\"datadir\":\"$DHT_DD_B\",\"fast_cache\":\"$cache_b\"}")"
    cj_require_ok "node B cached reproduce (cold)" "$cold"
    printf '%s\n' "$cold" >"$DHT_WORK/carrier-reproduce-cold.json"
    [ "$(cj_field data.reproduced "$cold" False)" = True ] ||
        cj_die "node B's cached reproduce did not match its install build: $cold"
    cold_misses="$(cj_field data.fast_cache.misses "$cold" 0)"
    cold_hits="$(cj_field data.fast_cache.hits "$cold" 0)"
    [ "$cold_misses" -ge 1 ] 2>/dev/null ||
        cj_die "the cold lap compiled nothing (misses=$cold_misses) — the cache never filled: $cold"
    [ "$cold_hits" = 0 ] 2>/dev/null ||
        cj_die "the cold lap claimed hits=$cold_hits on an empty cache: $cold"
    cold_id="$(cj_field data.receipt_id "$cold")"
    cj_note "node B filled the cache cold: misses=$cold_misses hits=$cold_hits, receipt ${cold_id:0:16}…"

    # The cache leaves as one ordinary package in node B's own store. The
    # export leaf reports the carrier root and the public-shape verdict, so
    # the journey asserts the serving gate said yes, not just that a root
    # came back.
    export_out="$("cj_b" zcode package fastobj export \
        --input="{\"datadir\":\"$DHT_DD_B\",\"cache_dir\":\"$cache_b\"}")"
    cj_require_ok "node B exported its cache as the carrier" "$export_out"
    printf '%s\n' "$export_out" >"$DHT_WORK/carrier-export.json"
    carrier="$(cj_field data.package_root "$export_out")"
    [ "${#carrier}" = 64 ] ||
        cj_die "the carrier export returned no package root: $export_out"
    shape="$(cj_field data.possession.public_shape "$export_out")"
    [ "$shape" = "fastobj-carrier" ] ||
        cj_die "the carrier is not publicly serveable (shape=$shape): $export_out"
    cj_publish_record b zclassic23.fastobj provider "$carrier" "$carrier" 1

    # The CARRY, ADMIT and zero-compiler REBUILD live in the survival step,
    # where they are the stronger fact: node C only exists there, and it
    # fetches the carrier from B after the publisher has disappeared, when B
    # is the only node that ever held the cache.
    CJ_CARRIER_ROOT="$carrier"
    CJ_CARRIER_ENTRIES="$cold_misses"
    CJ_CARRIER_RECEIPT="$cold_id"
    cj_note "carrier ${carrier:0:16}… holds $CJ_CARRIER_ENTRIES objects in node B's store under zclassic23.fastobj"
}

# A carrier is fetched by root through the live daemon like any package, but
# under its own namespace: under zclassic23.package the completion of a fetch
# triggers the zcode transport import, which a compile-cache carrier is not.
# Provider discovery is retryable, so re-admit the same root until the pin
# says whole — the same discipline cj_fetch_package applies to transports.
cj_fetch_fastobj_carrier() {
    local node="$1" root="$2" out plan complete=False deadline next_resume
    out="$("cj_$node" zcode package fetch \
        --input="{\"root\":\"$root\",\"namespace\":\"zclassic23.fastobj\",\"maximum_bytes\":67108864}")"
    cj_require_ok "node $node fetch carrier $root" "$out"
    printf '%s\n' "$out" >"$DHT_WORK/carrier-fetch-$node.json"
    [ "$(cj_field data.live "$out" False)" = True ] ||
        cj_die "node $node did not route the carrier fetch through its live daemon: $out"
    deadline=$(( $(date +%s) + 180 )); next_resume=$(( $(date +%s) + 15 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        plan="$("cj_$node" zcode package pin \
            --input="{\"root\":\"$root\",\"mode\":\"plan\"}" || true)"
        complete="$(cj_field data.package.complete "$plan" False)"
        [ "$complete" = True ] && break
        if [ "$(date +%s)" -ge "$next_resume" ]; then
            "cj_$node" zcode package fetch \
                --input="{\"root\":\"$root\",\"namespace\":\"zclassic23.fastobj\",\"maximum_bytes\":67108864}" \
                >/dev/null 2>&1 || true
            next_resume=$(( $(date +%s) + 15 ))
        fi
        sleep 1
    done
    [ "$complete" = True ] ||
        cj_die "node $node never received the carrier $root whole: $plan"
}

# ── 11/12  one bounded change to a package that already exists ───────────
# Steps 1-9 prove the commons can CREATE something. This proves the other
# half, and it is the half a stranger actually wants: take software that
# already works, change one thing about how it behaves, keep that exact
# version, and have another machine run it.
#
# The subject is the repository's own contexts/commons/packages/zdogfight — a deterministic,
# integer-only dogfight match core — and the change is the smallest visible
# one there is: the aircraft turns faster. Nothing here is a second demo. It
# is the SAME nodes, the SAME overlay and the SAME lifecycle leaves the nine
# steps above already travelled, pointed at an existing package instead of an
# empty workspace.
CJ_TURN_GOAL="make the aircraft turn faster in zdogfight/zdogfight"

# The measuring instrument. It belongs to the lap, not to the package under
# test, for the same reason sample.txt belongs to step 9: a change is only
# "visible" if something independent of it prints a number a person can read.
# Integer-only and seed-fixed, so the two nodes are comparing answers rather
# than trusting each other's floating point.
cj_zdog_write_probe() {
    mkdir -p "$1/app"
    cat >"$1/app/turnrate.c" <<'PROBE'
/* How fast does the aircraft turn? Hold the stick full right from a fixed
 * seed and count the degrees it comes around, per second of match time.
 * No clock, no input, no floating point: the same source always prints the
 * same number on any machine, which is what makes it evidence. */
#include "zdogfight/zdogfight.h"

#include <stdio.h>

#define TURN_TICKS 180u   /* 3 s at 60 Hz */

int main(void)
{
    zdog_match m;
    zdog_ctl ctls[ZDOG_MAX_PLANES] = {{0}};
    long total_brad = 0;

    zdog_match_init(&m, 42, 2);
    /* Everyone flies full throttle and holds fire, so nothing dies and the
     * measurement is only ever about turning. Plane 0 holds full right bank. */
    for (unsigned i = 0; i < ZDOG_MAX_PLANES; i++)
        ctls[i].throttle = 32767;
    ctls[0].roll = 32767;

    for (unsigned t = 0; t < TURN_TICKS; t++) {
        uint16_t before = m.planes[0].yaw;
        zdog_tick(&m, ctls);
        /* brad16 wraps at 360 deg; the signed 16-bit difference is this
         * tick's turn, so a multi-turn window still totals correctly. */
        total_brad += (long)(int16_t)(uint16_t)(m.planes[0].yaw - before);
    }

    printf("turn_rate %ld deg/s\n",
           (total_brad * 360 / 65536) * 60 / (long)TURN_TICKS);
    return 0;
}
PROBE
}

# zdogfight's own manifest plus the probe. Written out rather than patched so
# the published file list is exactly what this lap claims it is. The zprng
# dependency keeps the root the repository package already declares: a package
# root is derived from content, so the root published here is the same 64 hex
# characters contexts/commons/packages/zdogfight names on disk.
cj_zdog_write_manifest() {
    cat >"$1/zcode-package.json" <<JSON
{
  "schema": 1,
  "name": "${2:-zdogfight/zdogfight}",
  "semver": "0.1.0",
  "language": "c23",
  "license": "Apache-2.0",
  "include_dir": "include",
  "source_dir": "src",
  "dependencies": [
    {
      "name": "zprng/zprng",
      "root": "$CJ_ZPRNG_ROOT",
      "semver": "0.1.0"
    }
  ],
  "files": [
    "LICENSE",
    "README.md",
    "app/main.c",
    "app/turnrate.c",
    "include/zdogfight/zdogfight.h",
    "src/zdogfight.c",
    "src/zdogfix.c",
    "src/zdogfix.h",
    "tests/test_zdogfight.c",
    "zcode-package.json"
  ]
}
JSON
}

# The one bounded change. ZDOG_YAW_RATE_BRAD is the yaw the flight model
# applies per second at full bank, in brad16 (65536 == 360 deg): 27307 is
# 150 deg/s, 45511 is 250. One constant, one line, one visible consequence.
cj_zdog_turn_faster_edit() {
    local hdr="$1/include/zdogfight/zdogfight.h"
    grep -q '^#define ZDOG_YAW_RATE_BRAD 27307' "$hdr" ||
        cj_die "the candidate does not carry the yaw rate this lap changes: $hdr"
    sed -i -E 's|^#define ZDOG_YAW_RATE_BRAD 27307.*$|#define ZDOG_YAW_RATE_BRAD 45511    /* 250 deg/s in brad16 (was 150) */|' "$hdr"
    grep -q '^#define ZDOG_YAW_RATE_BRAD 45511' "$hdr" ||
        cj_die "the bounded change did not land in the candidate: $hdr"
}

# Build the probe where the node lives, against the zprng THAT node admitted
# for itself. Same discipline as cj_build_wordcount: no node reaches into
# another node's datadir.
cj_build_zdog_probe() {
    local node="$1" src="$2" dd="$3" out="$4"
    cj_on "$node" test -f "$dd/zcode/installed/$CJ_ZPRNG_ROOT/lib/libzprng.a" ||
        cj_die "node $node has no admitted zprng artifact to link the probe against"
    cj_on "$node" cc -std=c23 -O1 \
        -I"$src/include" \
        -I"$dd/zcode/installed/$CJ_ZPRNG_ROOT/include" \
        "$src/app/turnrate.c" "$src/src/zdogfight.c" "$src/src/zdogfix.c" \
        "$dd/zcode/installed/$CJ_ZPRNG_ROOT/lib/libzprng.a" \
        -o "$out"
}

# Why a proof did not arrive. The journey deletes its work directory on the
# way out, so a stalled proof leaves nothing to read afterwards — this prints
# the two ledgers that decide it, from both nodes, while they still exist.
cj_zdog_diagnose() {
    cj_note "── why the proof did not arrive ──"
    cj_note "A actions:  $(cj_sql a "SELECT group_concat(state||'/'||substr(action_id,1,12),' ') FROM build_actions")"
    cj_note "A events:   $(cj_sql a "SELECT group_concat(state||'/'||substr(action_id,1,12),' ') FROM build_proof_events")"
    cj_note "A receipts: $(cj_sql a "SELECT group_concat(trust_state||'/'||substr(action_id,1,12),' ') FROM build_receipts")"
    cj_note "B actions:  $(cj_sql b "SELECT group_concat(state||'/'||substr(action_id,1,12),' ') FROM build_actions")"
    cj_note "B receipts: $(cj_sql b "SELECT group_concat(trust_state||'/'||substr(action_id,1,12),' ') FROM build_receipts")"
    # The named reason, on both sides. A proof that fell back to LOCAL_FALLBACK
    # wrote WHY into last_error, and without that line every diagnosis of this
    # is a guess: state tells you it stopped, last_error tells you what refused.
    cj_sql b "SELECT substr(action_id,1,12)||' outcome='||coalesce(outcome,'')||' attempts='||attempt_count||' err='||coalesce(last_error,'(none)') FROM build_actions ORDER BY sequence" |
        while IFS= read -r row; do [ -n "$row" ] && cj_note "B  $row"; done
    cj_sql a "SELECT substr(action_id,1,12)||' outcome='||coalesce(outcome,'')||' attempts='||attempt_count||' err='||coalesce(last_error,'(none)') FROM build_actions ORDER BY sequence" |
        while IFS= read -r row; do [ -n "$row" ] && cj_note "A  $row"; done
    cj_sql a "SELECT substr(action_id,1,12)||' '||state||' peer='||peer_id||' at='||created_at FROM build_proof_events ORDER BY created_at,state" |
        while IFS= read -r row; do [ -n "$row" ] && cj_note "A ev $row"; done
}

# Run the probe and return the integer it printed, refusing anything that is
# not the exact shape this lap measures.
cj_zdog_turn_rate() {
    local node="$1" bin="$2" out rate
    out="$(cj_on "$node" "$bin")"
    case "$out" in
        "turn_rate "*" deg/s") ;;
        *) cj_die "the turn-rate probe on node $node printed '$out'" ;;
    esac
    rate="${out#turn_rate }"; rate="${rate% deg/s}"
    case "$rate" in
        ''|*[!0-9]*) cj_die "the turn-rate probe on node $node printed no number: $out" ;;
    esac
    printf '%s' "$rate"
}

# Publishing happens BEFORE the hosting engine comes up, for the reason the
# main flow already states about z23/textstat: a node builds what it serves
# from the store it has on disk at start. Put the software on the machine,
# then run the node that shares it. Everything else about this lap — the
# measurement, the change, the decision, the reproduction — is step 10 below.
cj_journey_turn_faster_stage() {
    cj_step "staging step 10: the commons receives two real packages, unchanged"
    # These are the repository's own contexts/commons/packages/zprng and contexts/commons/packages/zdogfight,
    # not fixtures. zdogfight names zprng by root, and a package root is
    # derived from content, so the root the node computes here is the same one
    # the manifest on disk already declares — which is the whole point of
    # naming a dependency by what it contains instead of by who published it.
    CJ_ZPRNG_SRC="$DHT_WORK/zprng"
    CJ_ZDOG_SRC="$DHT_WORK/zdogfight"
    rm -rf "$CJ_ZPRNG_SRC" "$CJ_ZDOG_SRC"
    cp -a "$REPO_ROOT/contexts/commons/packages/zprng" "$CJ_ZPRNG_SRC"
    cp -a "$REPO_ROOT/contexts/commons/packages/zdogfight" "$CJ_ZDOG_SRC"

    CJ_ZPRNG_PUBLISHER="$("$CJ_SIGNER" --generate "$DHT_WORK/zprng-publisher.key")"
    CJ_ZDOG_PUBLISHER_PKG="$("$CJ_SIGNER" --generate "$DHT_WORK/zdog-publisher.key")"
    [ -n "$CJ_ZPRNG_PUBLISHER" ] && [ -n "$CJ_ZDOG_PUBLISHER_PKG" ] ||
        cj_die "could not create the two package publisher identities"

    cj_publish_package a "$CJ_ZPRNG_SRC" 1 \
        "$CJ_ZPRNG_PUBLISHER" "$DHT_WORK/zprng-publisher.key"
    CJ_ZPRNG_ROOT="$CJ_PKG_ROOT"
    CJ_ZPRNG_TRANSPORT="$CJ_PKG_TRANSPORT"
    [ "$CJ_ZPRNG_ROOT" = \
      "$(cj_jget dependencies.0.root '' <"$REPO_ROOT/contexts/commons/packages/zdogfight/zcode-package.json")" ] ||
        cj_die "the published zprng root does not match the one contexts/commons/packages/zdogfight names on disk: $CJ_ZPRNG_ROOT"

    cj_zdog_write_probe "$CJ_ZDOG_SRC"
    cj_zdog_write_manifest "$CJ_ZDOG_SRC"
    cj_publish_package a "$CJ_ZDOG_SRC" 1 \
        "$CJ_ZDOG_PUBLISHER_PKG" "$DHT_WORK/zdog-publisher.key"
    CJ_ZDOG_ROOT="$CJ_PKG_ROOT"
    CJ_ZDOG_TRANSPORT="$CJ_PKG_TRANSPORT"
    cj_note "zdogfight/zdogfight published on node A: ${CJ_ZDOG_ROOT:0:16}… (dep zprng ${CJ_ZPRNG_ROOT:0:12}…)"
}

cj_journey_turn_faster() {
    cj_step "11/12  the same journey, on software that already exists: the aircraft turns faster"
    local before_bin start handoff candidate run show accept again
    local plan digest body signature seal commit src_b bin_b

    # Node B is the independent prover for this lap, and it cannot build a
    # package whose dependency it does not hold. So the dependencies cross the
    # overlay FIRST and node B admits them explicitly, exactly as node A must —
    # reuse is a decision each machine makes for itself, prover or not.
    #
    # BOTH packages, and the second one is the non-obvious half. Asking to
    # change software that already exists locks the version you are changing
    # FROM: the work reuses the published zdogfight and edits from there, so
    # its dependency lock names that exact root. A prover that holds only
    # zprng refuses the action by name — `locked-dependency-not-installed` —
    # which is the correct refusal, not a missing feature. The remedy is the
    # ordinary one: the prover admits what the work depends on, for itself.
    # The same gate binds node A's announcements below: A admits both
    # packages and files the distinct rebuild receipts BEFORE the pointer
    # plans exist (the re-admissions under BEFORE are then idempotent).
    cj_use_package a "$CJ_ZPRNG_ROOT"
    cj_reproduce_package a "$CJ_ZPRNG_ROOT"
    cj_use_package a "$CJ_ZDOG_ROOT"
    cj_reproduce_package a "$CJ_ZDOG_ROOT"
    cj_announce_package a "$CJ_ZPRNG_ROOT" "$CJ_ZPRNG_TRANSPORT" 1
    cj_fetch_package b "$CJ_ZPRNG_ROOT" "$CJ_ZPRNG_TRANSPORT"
    cj_use_package b "$CJ_ZPRNG_ROOT"
    cj_announce_package a "$CJ_ZDOG_ROOT" "$CJ_ZDOG_TRANSPORT" 1
    cj_fetch_package b "$CJ_ZDOG_ROOT" "$CJ_ZDOG_TRANSPORT"
    cj_use_package b "$CJ_ZDOG_ROOT"

    # ── BEFORE: what the software does today, measured, not assumed ──────
    cj_use_package a "$CJ_ZPRNG_ROOT"
    cj_use_package a "$CJ_ZDOG_ROOT"
    before_bin="$(cj_node_dir a)/turnrate-before"
    cj_build_zdog_probe a "$CJ_ZDOG_SRC" "$DHT_DD_A" "$before_bin" ||
        cj_die "the turn-rate probe did not build against the published package"
    CJ_TURN_BEFORE="$(cj_zdog_turn_rate a "$before_bin")"
    cj_note "before: the aircraft turns $CJ_TURN_BEFORE deg/s"

    # ── the person asks for the change ───────────────────────────────────
    # The workspace IS the existing package. Nothing is missing here and no
    # new code is required: this lap is about altering behavior that already
    # ships, which is the case steps 4-6 deliberately do not cover.
    CJ_ZDOG_WS="$DHT_WORK/zdogfight-work"
    rm -rf "$CJ_ZDOG_WS"
    cp -a "$CJ_ZDOG_SRC" "$CJ_ZDOG_WS"
    # The person's version carries the person's own name, in a namespace no
    # one has claimed. A publisher namespace binds first-come to one key, so
    # `zdogfight/…` belongs to whoever published it and cannot be republished
    # into by anyone else — that is the protection, not an obstacle. `you/` is
    # taken too, by the application step 8 published under a different key.
    # What you change is yours, under a name that is yours, and the original
    # stays exactly where it was for anyone who still wants it.
    cj_zdog_write_manifest "$CJ_ZDOG_WS" "pilot/zdogfight-quickturn"
    # No details=true here: this workspace is a real package with a real
    # dependency, and the detailed reuse plan does not fit the bounded response
    # budget. The bound is the contract; the journey asks for what fits.
    start="$(cj_a zcode work start \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"goal\":\"$CJ_TURN_GOAL\",\"profile\":\"$CJ_PROFILE\"}")"
    cj_require_ok "work start (turn faster)" "$start"
    printf '%s\n' "$start" >"$DHT_WORK/turn-work-start.json"
    CJ_ZDOG_WORK_ID="$(cj_field data.work_id "$start" '')"
    [ -n "$CJ_ZDOG_WORK_ID" ] || cj_die "work start bound no work id: $start"
    cj_human_first "work start (turn faster)" "$start"

    # ── the change is made, and only the change ──────────────────────────
    handoff="$(cj_a zcode work run \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"work\":\"latest\",\"adapter\":\"manual\",\"details\":true}")"
    cj_require_ok "work run (turn faster handoff)" "$handoff"
    candidate="$(cj_field data.candidate_workspace "$handoff" '')"
    [ -d "$candidate" ] || cj_die "work run exported no candidate workspace: $handoff"
    [ "$(cj_field data.authority "$handoff" '')" = "NONE_MANUAL_HANDOFF" ] ||
        cj_die "the manual handoff claimed authority it must not have: $handoff"
    cj_zdog_turn_faster_edit "$candidate"

    run="$(cj_a zcode work run \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"work\":\"latest\",\"adapter\":\"manual\",\"datadir\":\"$DHT_DD_A\",\"details\":true}")"
    cj_require_ok "work run (turn faster candidate)" "$run"
    printf '%s\n' "$run" >"$DHT_WORK/turn-work-run.json"
    [ "$(cj_field data.state "$run" '')" = "CANDIDATE_ADMITTED" ] ||
        cj_die "the candidate was not admitted: $run"
    CJ_ZDOG_ACTION_ID="$(printf '%s' "$(cj_field data.expert "$run")" | cj_jget action_id)"
    [ -n "$CJ_ZDOG_ACTION_ID" ] || cj_die "the admitted candidate bound no action: $run"
    # Same rule as step 6, and it has to hold for a change as much as for a
    # creation: the requester asked the commons instead of proving itself.
    [ "$(cj_sql a "SELECT count(*) FROM build_actions WHERE action_id='$CJ_ZDOG_ACTION_ID' AND state='SNAPSHOTTED' AND attempt_count=0 AND started_at=0 AND length(worker_id)=0")" = 1 ] ||
        cj_die "node A proved its own change instead of asking the commons"

    # ── the person sees the consequence ──────────────────────────────────
    cj_wait_work_state EVIDENCE_READY 300 "$CJ_ZDOG_WS" ||
        { cj_zdog_diagnose; cj_die "the change never reached EVIDENCE_READY: $CJ_LAST_SHOW"; }
    cj_wait_proof_result 180 "$CJ_ZDOG_WS" ||
        cj_die "node B proved the change, but node A never counted it: $CJ_LAST_SHOW"
    show="$(cj_a zcode work show \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\"}")"
    cj_require_ok "work show (turn faster)" "$show"
    printf '%s\n' "$show" >"$DHT_WORK/turn-work-show.json"
    # The consequence is named by file: one header, the one that carries the
    # constant. A change nobody can point at is not a visible change.
    case "$(cj_field data.changed_paths "$show" '')" in
        *include/zdogfight/zdogfight.h*) ;;
        *) cj_die "work show did not name the file that changed: $show" ;;
    esac
    [ "$(cj_field data.build_result "$show" '')" = passed ] ||
        cj_die "work show does not report a passing build: $show"
    case "$(cj_field data.test_result "$show" '')" in
        passed*) ;;
        *) cj_die "work show does not report passing tests: $show" ;;
    esac
    [ "$(cj_field data.confirmation_ready "$show" False)" = True ] ||
        cj_die "work show does not offer the person a decision: $show"
    cj_human_first "work show (turn faster)" "$show"

    # ── the person decides, and the exact bytes travel ───────────────────
    accept="$(cj_a zcode work accept \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\",\"details\":true}")"
    cj_require_ok "work accept (turn faster)" "$accept"
    printf '%s\n' "$accept" >"$DHT_WORK/turn-accept.json"
    [ "$(cj_field data.state "$accept" '')" = PROVEN ] ||
        cj_die "acceptance did not reach PROVEN: $accept"
    [ "$(cj_field data.goal_decision "$accept" '')" = accepted ] ||
        cj_die "acceptance did not record the person's decision: $accept"
    CJ_ZDOG_ACCEPTED_SOURCE="$(printf '%s' "$(cj_field data.expert "$accept")" | cj_jget source_root '')"
    CJ_ZDOG_ACCEPTED_WORK="$(printf '%s' "$(cj_field data.expert "$accept")" | cj_jget lane_receipt_root '')"
    [ "${#CJ_ZDOG_ACCEPTED_SOURCE}" -eq 64 ] && [ "${#CJ_ZDOG_ACCEPTED_WORK}" -eq 64 ] ||
        cj_die "acceptance bound no accepted source / lane receipt root: $accept"
    again="$(cj_a zcode work accept \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"work\":\"latest\",\"datadir\":\"$DHT_DD_A\"}")"
    cj_require_ok "work accept (turn faster, repeat)" "$again"
    [ "$(cj_field data.idempotent "$again" False)" = True ] ||
        cj_die "repeating the acceptance was not idempotent: $again"
    cj_note "accepted: PROVEN, source ${CJ_ZDOG_ACCEPTED_SOURCE:0:16}…"

    # ── published as an ordinary package under the person's own name ─────
    CJ_ZDOG_PUBLISHER="$("$CJ_SIGNER" --generate "$DHT_WORK/turn-publisher.key")"
    [ -n "$CJ_ZDOG_PUBLISHER" ] ||
        cj_die "could not create the turn-faster publisher identity"
    plan="$(cj_a zcode publish plan \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"datadir\":\"$DHT_DD_A\",\"source_root\":\"$CJ_ZDOG_ACCEPTED_SOURCE\",\"publisher_pubkey\":\"$CJ_ZDOG_PUBLISHER\"}")"
    cj_require_ok "publish plan (turn faster)" "$plan"
    digest="$(cj_field data.release_signing_digest "$plan" '')"
    body="$(cj_field data.release_body_hex "$plan" '')"
    [ -n "$digest" ] && [ -n "$body" ] ||
        cj_die "publish plan returned nothing to sign: $plan"
    signature="$(cj_sign_digest "$digest" "$DHT_WORK/turn-publisher.key")"
    seal="$(cj_a zcode package dev seal \
        --input="{\"release_body_hex\":\"$body\",\"signature_hex\":\"$signature\"}")"
    cj_require_ok "seal (turn faster)" "$seal"
    commit="$(cj_a zcode publish \
        --input="{\"workspace\":\"$CJ_ZDOG_WS\",\"datadir\":\"$DHT_DD_A\",\"source_root\":\"$CJ_ZDOG_ACCEPTED_SOURCE\",\"release_hex\":\"$(cj_field data.release_hex "$seal" '')\"}")"
    cj_require_ok "publish commit (turn faster)" "$commit"
    CJ_ZDOG_APP_ROOT="$(cj_field data.package_root "$commit" '')"
    CJ_ZDOG_APP_TRANSPORT="$(cj_field data.transport_root "$commit" '')"
    [ "${#CJ_ZDOG_APP_ROOT}" -eq 64 ] && [ "${#CJ_ZDOG_APP_TRANSPORT}" -eq 64 ] ||
        cj_die "the accepted change was published without a root or carrier: $commit"
    # The accepted version is a DIFFERENT package root from the one it came
    # from. That is what "keep one exact version" means: the original still
    # exists, unaltered, and anyone can still fetch it.
    [ "$CJ_ZDOG_APP_ROOT" != "$CJ_ZDOG_ROOT" ] ||
        cj_die "the accepted change published the same root as the original"
    cj_note "the changed version published: ${CJ_ZDOG_APP_ROOT:0:16}… (was ${CJ_ZDOG_ROOT:0:16}…)"

    # ── AFTER: another machine reproduces it and runs it ─────────────────
    # The changed version is published from accepted work, so it is a
    # source transport like the application: provider + source, no pointer
    # (its recipe carries no declared tests to evidence).
    cj_announce_transport a "$CJ_ZDOG_APP_ROOT" "$CJ_ZDOG_APP_TRANSPORT" 1
    cj_fetch_package b "$CJ_ZDOG_APP_ROOT" "$CJ_ZDOG_APP_TRANSPORT"
    CJ_ZDOG_BYTES="$CJ_FETCH_BYTES"

    src_b="$(cj_node_dir b)/turn-checkout-b"
    cj_require_ok "node B accepted-change checkout" \
        "$(cj_checkout_accepted b "$src_b" "$CJ_ZDOG_APP_ROOT" \
            "$CJ_ZDOG_ACCEPTED_SOURCE" "$CJ_ZDOG_ACCEPTED_WORK")"
    cj_on b grep -q '^#define ZDOG_YAW_RATE_BRAD 45511' \
        "$src_b/include/zdogfight/zdogfight.h" ||
        cj_die "the source node B reconstructed does not carry the accepted change"

    bin_b="$(cj_node_dir b)/turnrate-after-b"
    cj_build_zdog_probe b "$src_b" "$DHT_DD_B" "$bin_b" ||
        cj_die "the accepted change did not build on node B"
    CJ_TURN_AFTER="$(cj_zdog_turn_rate b "$bin_b")"

    # The whole lap, in one comparison: the same probe, the same seed, the
    # same controls, on a different machine — and the aircraft turns faster.
    [ "$CJ_TURN_AFTER" -gt "$CJ_TURN_BEFORE" ] ||
        cj_die "the accepted change did not make the aircraft turn faster: before=$CJ_TURN_BEFORE after=$CJ_TURN_AFTER"
    cj_note "after:  the aircraft turns $CJ_TURN_AFTER deg/s on node B (was $CJ_TURN_BEFORE on node A)"
    cj_note "the change travelled as $CJ_ZDOG_BYTES bytes, reproduced from its own root"
}

# ── the original publisher disappears ────────────────────────────────────
# C boots against B, A is killed, and C still discovers, fetches,
# reproduces and runs the exact accepted bytes — served by B, the only
# holder left. Same-host: three processes, A's process group is signalled
# and never comes back. Multi-host: B and C are other machines. Reaching
# the end of this function IS the survival proof: with A dead, only B
# could have answered.
cj_boot_c() {
    local port
    for port in "$C_PORT" "$C_RPC" "$C_FS" "$C_HTTPS"; do
        dht_assert_port "$port" "$C_RPC"
    done
    DHT_DD_C="$(cj_node_dir c)/node-c"
    cj_on c mkdir -p "$DHT_DD_C" ||
        cj_die "could not create node C datadir on ${CJ_HOST_C:-this host}"
    install -m 600 /dev/null "$DHT_WORK/master-c.hex"
    printf '%s\n' "$CJ_SEED_C" >"$DHT_WORK/master-c.hex"
    # Seed and credential paths AS SEEN BY NODE C (the B pattern, one host on).
    CJ_SEED_FILE_C="$DHT_WORK/master-c.hex"
    if [ -n "$CJ_RDIR_C" ]; then
        dht_node_put "$C_RPC" "$DHT_WORK/cred/wallet-passphrase" \
            "$CJ_RDIR_C/cred/wallet-passphrase" ||
            cj_die "shipping the wallet credential to $CJ_HOST_C failed"
        dht_node_exec "$C_RPC" chmod 600 "$CJ_RDIR_C/cred/wallet-passphrase" ||
            cj_die "credential permissions failed on $CJ_HOST_C"
        dht_node_put "$C_RPC" "$DHT_WORK/master-c.hex" \
            "$CJ_RDIR_C/master-c.hex" ||
            cj_die "shipping node C's master seed failed"
        CJ_SEED_FILE_C="$CJ_RDIR_C/master-c.hex"
    fi
    # C joins while A is still alive, dialing B — the one peer that outlives
    # the publisher. Its own build worker compiles what it admits.
    DHT_BUILDWORKERS=1
    dht_spawn DHT_PGID_C "$DHT_DD_C" "$C_PORT" "$C_RPC" "$C_FS" \
        "$C_HTTPS" "$CJ_PEER_ADDR_B:$B_PORT"
    cj_wait_rpc_or_die "$DHT_DD_C" "$C_RPC" "$DHT_PGID_C" "node C"
}

cj_journey_publisher_disappears() {
    cj_step "12/12  the publisher disappears and the software survives"
    local anchor tip del_c

    # C takes its own anchored identity while A is still here to fund it —
    # the same recipe A and B used, no special role for the latecomer.
    cj_boot_c
    # Let C finish its initial sync BEFORE the anchor blocks exist: new-tip
    # relay (what the next lines exercise) starts from a steady at-tip state,
    # not from mid-IBD.
    local pre_tip
    pre_tip="$(dht_height "$DHT_DD_A" "$A_RPC")"
    [ -n "$pre_tip" ] || cj_die "node A reported no chain height before C joined"
    cj_wait_height "$DHT_DD_C" "$C_RPC" "$pre_tip" "node C (initial sync)"
    # The anchor rides A's wallet, and A was restarted for the overlay phase:
    # re-arm the custody gates (unlock, fresh current-key backup) exactly as
    # cj_identities did before the first anchors.
    DHT_WALLET_PASS="$CJ_WALLET_PASS" dht_unlock_wallet "$DHT_DD_A" "$A_RPC" ||
        cj_die "node A wallet re-unlock failed"
    a_rpc getnewaddress | dht_result >/dev/null ||
        cj_die "node A keypool top-up failed"
    DHT_BACKUP_PASS="$CJ_BACKUP_PASS" dht_backup_wallet "$DHT_DD_A" "$A_RPC" ||
        cj_die "node A custody re-backup failed"
    dht_wait_spendable "$DHT_DD_A" "$A_RPC" ||
        cj_die "node A vault spendable never became positive again"
    CJ_PUB_C="$("$DHT_WORK/journey-peer" pubkey "$CJ_SEED_C")"
    [ "$CJ_PUB_C" != "$CJ_PUB_A" ] && [ "$CJ_PUB_C" != "$CJ_PUB_B" ] ||
        cj_die "node C's master collided with another identity"
    anchor="$(dht_anchor "$DHT_DD_A" "$A_RPC" "$CJ_PUB_C" "journey-anchor-c")" ||
        cj_die "node C anchor failed"
    # The delegate gate requires tip >= anchor_height + 2*ZCL_FINALITY_DEPTH
    # (native_zcode_network_command.c BEACON_PROVISIONAL) — the same rule the
    # 22-block bury gave A and B in cj_identities.
    dht_mine_empty 21
    tip="$(dht_height "$DHT_DD_A" "$A_RPC")"
    [ -n "$tip" ] || cj_die "node A reported no chain height after anchoring C"
    cj_wait_height "$DHT_DD_B" "$B_RPC" "$tip" "node B"
    cj_wait_height "$DHT_DD_C" "$C_RPC" "$tip" "node C"

    del_c="$(cj_c zcode network delegate \
        --input="{\"seed_file\":\"$CJ_SEED_FILE_C\"}")"
    cj_require_ok "node C delegation" "$del_c"
    CJ_NODE_C="$(cj_field data.node_id "$del_c")"
    [ -n "$CJ_NODE_C" ] && [ "$CJ_NODE_C" != "$CJ_NODE_A" ] &&
    [ "$CJ_NODE_C" != "$CJ_NODE_B" ] ||
        cj_die "node C did not derive an independent identity"
    cj_note "node C identity: ${CJ_NODE_C:0:16}…"
    cj_allow_policy c zclassic23.package
    cj_allow_policy c zclassic23.source
    # The fastobj carrier is a fourth service type C must be allowed to
    # discover, store and serve onward — the same opt-in B made in the
    # overlay step, paid before this restart so the rule governs.
    cj_allow_policy c zclassic23.fastobj
    # Policies persist in the datadir; restart C so they govern what it serves
    # and accepts, exactly as the A/B policy restart did.
    dht_kill_group "$DHT_PGID_C"; DHT_PGID_C=""
    DHT_BUILDWORKERS=1
    dht_spawn DHT_PGID_C "$DHT_DD_C" "$C_PORT" "$C_RPC" "$C_FS" \
        "$C_HTTPS" "$CJ_PEER_ADDR_B:$B_PORT"
    cj_wait_rpc_or_die "$DHT_DD_C" "$C_RPC" "$DHT_PGID_C" "node C (policy restart)"

    # The publisher disappears. Not a handoff: the process group is signalled
    # and node A never comes back. Its RPC must stop answering.
    dht_kill_group "$DHT_PGID_A"; DHT_PGID_A=""
    if dht_rpc "$DHT_DD_A" "$A_RPC" getblockcount >/dev/null 2>&1; then
        cj_die "node A still answers RPC after its disappearance"
    fi
    if [ "$CJ_MULTIHOST" = 1 ]; then
        cj_note "host A is gone — node C can now only learn from B"
    else
        cj_note "node A is gone — node C can now only learn from B"
    fi

    # B, the only remaining holder, announces that it serves both packages
    # and the accepted application's source. These records are B's own; A
    # never knew about this leg. The pointer gate binds B exactly as it
    # bound A: B files the distinct rebuild receipt for every testable
    # root it names a pointer for. The two accepted-work transports (the
    # application and the changed aircraft) announce provider + source —
    # the pointer is not a claim a transport can evidence.
    cj_reproduce_package b "$CJ_TEXTSTAT_ROOT"
    cj_reproduce_package b "$CJ_APP_PKG_ROOT"
    cj_reproduce_package b "$CJ_ZPRNG_ROOT"
    cj_announce_package b "$CJ_TEXTSTAT_ROOT" "$CJ_TEXTSTAT_TRANSPORT" 2
    cj_announce_transport b "$CJ_APP_ROOT" "$CJ_APP_TRANSPORT" 2
    # The ordinary package carrying the program is testable, so it earns a
    # pointer from B like the library does.
    cj_announce_package b "$CJ_APP_PKG_ROOT" "$CJ_APP_PKG_TRANSPORT" 2
    # Step 10's two packages travel the same way, from the same surviving
    # holder: the dependency (testable, so it earns a pointer), and the
    # changed version of the aircraft (a transport, so provider + source).
    cj_announce_package b "$CJ_ZPRNG_ROOT" "$CJ_ZPRNG_TRANSPORT" 2
    cj_announce_transport b "$CJ_ZDOG_APP_ROOT" "$CJ_ZDOG_APP_TRANSPORT" 2

    # C and B form an authenticated overlay session — the same discipline the
    # A<->B session had, observed from both ends, with one re-arm for the
    # capability-learning transport swap.
    b_rpc addnode "\"$CJ_PEER_ADDR_C:$C_PORT\"" '"onetry"' >/dev/null || true
    local deadline started rearmed=0 find lookup owner en_b en_c auth_b auth_c
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while :; do
        en_b="$(cj_field data.enabled "$(dht_status "$DHT_DD_B" "$B_RPC")" False)"
        en_c="$(cj_field data.enabled "$(dht_status "$DHT_DD_C" "$C_RPC")" False)"
        [ "$en_b" = True ] && [ "$en_c" = True ] && break
        [ "$(date +%s)" -lt "$deadline" ] ||
            cj_die "B and C DHTs never both enabled"
        sleep 0.5
    done
    find="$(cj_c zcode network find begin --input="{\"node_id\":\"$CJ_NODE_B\"}")"
    cj_require_ok "node C lookup of node B" "$find"
    lookup="$(cj_field data.lookup_id "$find")"
    owner="$(cj_field data.owner_token "$find")"
    started="$(date +%s)"; deadline=$((started + DHT_WAIT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        auth_b="$(cj_field data.connected_authenticated \
            "$(dht_status "$DHT_DD_B" "$B_RPC")" 0)"
        auth_c="$(cj_field data.connected_authenticated \
            "$(dht_status "$DHT_DD_C" "$C_RPC")" 0)"
        if [ "${auth_b:-0}" -ge 1 ] 2>/dev/null &&
           [ "${auth_c:-0}" -ge 1 ] 2>/dev/null; then
            cj_c zcode network find cancel \
                --input="{\"lookup_id\":\"$lookup\",\"owner_token\":\"$owner\"}" \
                >/dev/null || true
            cj_note "authenticated overlay session established B <-> C"
            break
        fi
        if [ "$rearmed" -eq 0 ] && [ "$(date +%s)" -ge $((started + 20)) ]; then
            rearmed=1
            find="$(cj_c zcode network find begin \
                --input="{\"node_id\":\"$CJ_NODE_B\"}")"
            lookup="$(cj_field data.lookup_id "$find" '')"
            owner="$(cj_field data.owner_token "$find" '')"
        fi
        sleep 0.5
    done
    [ "${auth_b:-0}" -ge 1 ] && [ "${auth_c:-0}" -ge 1 ] ||
        cj_die "B and C never formed an authenticated overlay session"

    # The proof itself: with A gone, C discovers, fetches and reproduces the
    # exact accepted source from B, then runs the identical program.
    cj_fetch_package c "$CJ_TEXTSTAT_ROOT" "$CJ_TEXTSTAT_TRANSPORT"
    cj_use_package c "$CJ_TEXTSTAT_ROOT"
    cj_fetch_package c "$CJ_APP_ROOT" "$CJ_APP_TRANSPORT"
    cj_note "node C fetched the accepted application from B ($CJ_FETCH_BYTES bytes) — with A gone"
    cj_reproduce_accepted_source c "$DHT_DD_C"
    cj_consume_source_receipt b "$CJ_NODE_C" "$CJ_APP_ROOT" \
        "$CJ_ACCEPTED_SOURCE"
    cj_use_package c "$CJ_APP_ROOT"
    cj_on c test -d "$DHT_DD_C/zcode/installed/$CJ_APP_ROOT" ||
        cj_die "node C admitted the accepted application but installed nothing"

    # Step 10's carrier crosses the same disappearing-publisher rule the
    # source did: A never knew the cache existed, B is the only node that
    # ever held it, and C — which never compiled this library — fetches it
    # as one ordinary package, unpacks a cache it never filled, and rebuilds
    # with zero compilers and node B's exact receipt.
    cj_fetch_fastobj_carrier c "$CJ_CARRIER_ROOT"
    local cache_c admit_out warm warm_id warm_misses warm_hits
    cache_c="$(cj_node_dir c)/fastobj-cache"
    cj_on c rm -rf "$cache_c"
    admit_out="$("cj_c" zcode package fastobj admit \
        --input="{\"datadir\":\"$DHT_DD_C\",\"package_root\":\"$CJ_CARRIER_ROOT\",\"cache_dir\":\"$cache_c\"}")"
    cj_require_ok "node C admitted the carrier into a fresh cache" "$admit_out"
    printf '%s\n' "$admit_out" >"$DHT_WORK/carrier-admit.json"
    [ "$(cj_field data.entries "$admit_out" 0)" = "$CJ_CARRIER_ENTRIES" ] ||
        cj_die "node C admitted a different entry count than node B compiled: $admit_out"

    # The zero-spawn rebuild. C reproduces the library it holds with the
    # carried cache attached: every TU is a hit, no compiler runs, and the
    # filed receipt is the same bytes node B filed in step 10.
    warm="$("cj_c" zcode package reproduce \
        --input="{\"name_or_root\":\"$CJ_TEXTSTAT_ROOT\",\"datadir\":\"$DHT_DD_C\",\"fast_cache\":\"$cache_c\"}")"
    cj_require_ok "node C cached reproduce (warm, publisher gone)" "$warm"
    printf '%s\n' "$warm" >"$DHT_WORK/carrier-reproduce-warm.json"
    [ "$(cj_field data.reproduced "$warm" False)" = True ] ||
        cj_die "node C's warm rebuild did not match its install build: $warm"
    warm_misses="$(cj_field data.fast_cache.misses "$warm" -1)"
    warm_hits="$(cj_field data.fast_cache.hits "$warm" -1)"
    [ "$warm_misses" = 0 ] 2>/dev/null ||
        cj_die "node C spawned compilers (misses=$warm_misses) on a full cache: $warm"
    [ "$warm_hits" = "$CJ_CARRIER_ENTRIES" ] 2>/dev/null ||
        cj_die "node C hit $warm_hits of $CJ_CARRIER_ENTRIES carried objects — the caches disagree: $warm"
    warm_id="$(cj_field data.receipt_id "$warm")"
    [ "$warm_id" = "$CJ_CARRIER_RECEIPT" ] ||
        cj_die "the two nodes filed different receipts for the same rebuild: $CJ_CARRIER_RECEIPT vs $warm_id"
    [ "$(cj_sha3_on b "$DHT_DD_B/zcode/receipts/$CJ_CARRIER_RECEIPT")" = \
      "$(cj_sha3_on c "$DHT_DD_C/zcode/receipts/$warm_id")" ] ||
        cj_die "the filed carrier receipts are not byte-identical across nodes"
    cj_note "carrier ${CJ_CARRIER_ROOT:0:16}… carried $CJ_CARRIER_ENTRIES objects node-B → node-C — publisher gone"
    cj_note "node C rebuilt with zero compilers: hits=$warm_hits misses=0, identical receipt ${warm_id:0:16}…"

    local src_c bin_c sample_c out_c cc_b cc_c ts_c
    src_c="$(cj_node_dir c)/checkout-c"
    cj_require_ok "node C accepted-source checkout" \
        "$(cj_checkout_accepted c "$src_c")"
    sample_c="$(cj_node_dir c)/sample-c.txt"
    dht_node_put "$C_RPC" "$DHT_WORK/sample.txt" "$sample_c" ||
        cj_die "sample input never reached node C"
    # The program arrives the same way it did on B: the ordinary package,
    # fetched from the only node that still holds it, admitted explicitly,
    # built and installed by C's own worker from C's own verified bytes.
    cj_fetch_package c "$CJ_APP_PKG_ROOT" "$CJ_APP_PKG_TRANSPORT"
    cj_use_package c "$CJ_APP_PKG_ROOT"
    bin_c="$(cj_program_path "$CJ_USE_COMMIT" wordcount)"
    [ -n "$bin_c" ] && cj_on c test -x "$bin_c" ||
        cj_die "node C admitted apps/wordcount but installed no executable program"
    out_c="$(cj_on c "$bin_c" "$sample_c")"
    [ "$out_c" = "$CJ_APP_OUTPUT" ] ||
        cj_die "node C ran the application but answered '$out_c' instead of '$CJ_APP_OUTPUT'"

    # Byte-identical binaries are only a claim when the two hosts compile with
    # the same toolchain; a legitimate cross-host cc difference must narrow the
    # claim, not silently fail it nor silently pass it.
    cc_b="$(cj_on b sh -c 'cc --version | head -1')"
    cc_c="$(cj_on c sh -c 'cc --version | head -1')"
    if [ "$cc_b" = "$cc_c" ]; then
        [ "$(cj_sha3_on b "$CJ_APP_BIN_B")" = \
          "$(cj_sha3_on c "$bin_c")" ] ||
            cj_die "B and C built different programs from the same accepted source"
        ts_c="$DHT_DD_C/zcode/installed/$CJ_TEXTSTAT_ROOT/lib/libtextstat.a"
        [ "$(cj_sha3_on b "$DHT_DD_B/zcode/installed/$CJ_TEXTSTAT_ROOT/lib/libtextstat.a")" = \
          "$(cj_sha3_on c "$ts_c")" ] ||
            cj_die "B and C built different bytes for the reused package"
        cj_note "identical program and library bytes on B and C (same toolchain)"
    else
        cj_note "cc differs between host B and host C; proven here: identical accepted source root, identical carrier, identical behavior"
    fi
    # The step-10 change survives the same disappearance, and the test is the
    # one a person can read: a third machine that never met the publisher runs
    # the changed aircraft and gets the SAME faster number node B measured.
    local src_zc bin_zc rate_c
    cj_fetch_package c "$CJ_ZPRNG_ROOT" "$CJ_ZPRNG_TRANSPORT"
    cj_use_package c "$CJ_ZPRNG_ROOT"
    cj_fetch_package c "$CJ_ZDOG_APP_ROOT" "$CJ_ZDOG_APP_TRANSPORT"
    src_zc="$(cj_node_dir c)/turn-checkout-c"
    cj_require_ok "node C accepted-change checkout" \
        "$(cj_checkout_accepted c "$src_zc" "$CJ_ZDOG_APP_ROOT" \
            "$CJ_ZDOG_ACCEPTED_SOURCE" "$CJ_ZDOG_ACCEPTED_WORK")"
    cj_on c grep -q '^#define ZDOG_YAW_RATE_BRAD 45511' \
        "$src_zc/include/zdogfight/zdogfight.h" ||
        cj_die "node C reconstructed source without the accepted change"
    bin_zc="$(cj_node_dir c)/turnrate-after-c"
    cj_build_zdog_probe c "$src_zc" "$DHT_DD_C" "$bin_zc" ||
        cj_die "the accepted change did not build on node C"
    rate_c="$(cj_zdog_turn_rate c "$bin_zc")"
    [ "$rate_c" = "$CJ_TURN_AFTER" ] ||
        cj_die "node C measured $rate_c deg/s where node B measured $CJ_TURN_AFTER"
    [ "$rate_c" -gt "$CJ_TURN_BEFORE" ] ||
        cj_die "node C did not observe the faster turn: $rate_c vs $CJ_TURN_BEFORE"
    CJ_TURN_SURVIVED=1
    cj_note "with A gone, node C turns at $rate_c deg/s — the same number B measured, from B's bytes alone"

    CJ_PUBLISHER_SURVIVAL=1
    cj_note "the original publisher is gone and the software survives: ${CJ_ACCEPTED_SOURCE:0:16}… on C"
}

# ── the strip and the topology ───────────────────────────────────────────
# The mission's eight stages plus the second lap, printed by the run that
# earned them. The README
# figures are rendered from a recording of one real run; `--strip-labels` is
# how that generator refuses a recording whose stages no longer match this
# script, and `--topology` emits the drawing itself so it cannot go stale.
# One owner, so no figure can describe a journey this file does not run.
CJ_STRIP_LABELS='YOU ASKED
REUSED FROM PEER
CREATED MISSING BEHAVIOR
VISIBLE RESULT
REPRODUCED ON NODE B
TAMPER REFUSED
ACCEPTED
USED
CACHE TRAVELED
CHANGED WHAT EXISTED
PUBLISHER GONE'

cj_strip_row() { printf '  \033[1;36m%-26s\033[0m%s\n' "$1" "$2"; }
cj_strip_cont() { printf '  %-26s\033[2m%s\033[0m\n' "" "$1"; }

cj_strip() {
    printf '  \033[1mYOU ASKED\033[0m → \033[1mREUSED FROM PEER\033[0m → \033[1mCREATED MISSING BEHAVIOR\033[0m → \033[1mVISIBLE RESULT\033[0m →\n'
    printf '  \033[1mREPRODUCED ON NODE B\033[0m → \033[1mTAMPER REFUSED\033[0m → \033[1mACCEPTED\033[0m → \033[1mUSED\033[0m →\n'
    printf '  \033[1mCACHE TRAVELED\033[0m → \033[1mPUBLISHER GONE\033[0m\n\n'
    cj_strip_row "YOU ASKED" "$CJ_GOAL"
    cj_strip_row "REUSED FROM PEER" \
        "z23/textstat ${CJ_TEXTSTAT_ROOT:0:12}… — $CJ_TEXTSTAT_BYTES bytes from node A, no registry"
    cj_strip_row "CREATED MISSING BEHAVIOR" \
        "wordcount_longest_line() — the only code this journey wrote"
    cj_strip_row "VISIBLE RESULT" \
        "built and tested on node A ${CJ_SECS_RESULT}s after the ask, bound to the exact source"
    cj_strip_row "REPRODUCED ON NODE B" \
        "re-derived ${CJ_ACCEPTED_SOURCE:0:12}… in ${CJ_SECS_REPRO}s and signed for it"
    # Four kinds of lie, four refusals. The names go on their own lines
    # because the name is the point: a refusal a person can read.
    cj_strip_row "TAMPER REFUSED" \
        "altered source · unknown dependency · stale acceptance · altered bytes"
    cj_strip_cont "each by name: $CJ_REFUSAL_SOURCE · $CJ_REFUSAL_DEPENDENCY"
    cj_strip_cont "$CJ_REFUSAL_RECEIPT · $CJ_REFUSAL_ARTIFACT"
    cj_strip_row "ACCEPTED" \
        "one exact version, by hand — PROVEN, published as you/wordcount"
    cj_strip_row "USED" "wordcount sample.txt → $CJ_APP_OUTPUT"
    cj_strip_cont "bin/wordcount installed by zcode use — no compiler run by this proof"
    # The tenth stage moves the work, not the source: the compile cache left
    # node B as one ordinary package, and a node that never compiled the
    # application rebuilt it without running a single compiler.
    cj_strip_row "CACHE TRAVELED" \
        "$CJ_CARRIER_ENTRIES objects node-B → node-C as one ordinary package"
    cj_strip_cont "node C rebuilt with zero compilers — same receipt ${CJ_CARRIER_ROOT:0:12}…"
    # The eight stages above built something from nothing. This last row is the
    # harder half of the same promise: the same eight stages run again on
    # software that already existed and that this journey did not write, and
    # the thing you asked to change actually changes: node A measures the
    # package as published, node B measures the accepted change it fetched
    # and rebuilt. One number, two machines, and it moved.
    printf '\n'
    # Every line here stays inside the widest line above it: the README figure
    # is rendered at this width, and a row that overflows shrinks the whole
    # picture for the reader.
    cj_strip_row "CHANGED WHAT EXISTED" \
        "zdogfight — a package this journey did not write, under another key"
    cj_strip_cont "\"make the aircraft turn faster\" — one number, measured twice:"
    cj_strip_cont "${CJ_TURN_BEFORE} deg/s on node A before → ${CJ_TURN_AFTER} deg/s on node B after"
    cj_strip_cont "its own root ${CJ_ZDOG_APP_ROOT:0:12}… — the original is still exactly itself"
    printf '\n'
    cj_strip_row "PUBLISHER GONE" \
        "node A killed; node C fetched, reproduced and ran the exact bytes from B"
    printf '\n  \033[2mthree fresh datadirs · %s bytes over the overlay · A gone · central services contacted: 0\033[0m\n' \
        "$CJ_APP_BYTES"
}

# How the bytes actually travel. Every command path named here is checked
# against the running binary's own registry when the figure is generated, so
# this drawing cannot outlive the commands it names.
cj_topology() {
    cat <<'TOPO'
  NODE A — the person's workshop                NODE B — a second node, nothing installed
  ┌───────────────────────────────────┐         ┌───────────────────────────────────┐
  │ workspace  the accepted work      │         │ store      empty at boot          │
  │ store      the bytes it holds     │         │ installed  empty at boot          │
  │ swarm      serves what it holds   │         │ swarm      serves what it verified│
  └───────────────────────────────────┘         └───────────────────────────────────┘

   1 PUBLISH    zcode.package.publish.commit     accepted source becomes one signed carrier
   2 ANNOUNCE   zcode.network.publish            POINTER: package root → carrier root
                                                 PROVIDER: an authenticated peer holding it
   3 DISCOVER   zcode.network.find               node B asks the overlay who holds that root
   4 FETCH      zcode.package.fetch              bytes arrive from node A — and stay inert
   5 REPRODUCE  zcode.package.source.reproduce   node B re-derives the exact source tree
   6 USE        zcode.package.dev.use            node B admits it — an explicit local decision;
                                                 its worker builds the library AND bin/wordcount,
                                                 both under one build receipt, and hands back
                                                 "run <path>"
   7 CHECKOUT   zcode.workspace.source.package.checkout
                                                 carrier → the accepted source, byte for byte
   8 SERVE      node B answers for the same roots, so the next peer need not ask node A

   9 EXPORT     zcode.package.fastobj.export     node B's compile cache leaves as one ordinary package
  10 CARRY      zcode.package.fetch              the carrier crosses B → C, the publisher already gone
  11 ADMIT      zcode.package.fastobj.admit      node C unpacks a cache it never compiled
  12 REBUILD    zcode.package.reproduce          zero compilers, byte-identical receipt

  no registry · no coordinator · no privileged node · central services contacted: 0
TOPO
}

# SHA3-256 of a file, hex — the same backend tools/release.sh audits release
# archives with, so a recording's hashes are comparable to release evidence.
cj_sha3() {
    openssl dgst -sha3-256 "$1" | awk '{print $NF}'
}

# What this run measured, as plain key = value text. The README's proof figure
# is rendered from this file, so those numbers are a recording of one real run
# on stated hardware — never a claim typed onto a page.
#
# PROVENANCE. Beyond the measurements, the recording names the exact bytes
# that produced it: the source commit (and whether the tree was dirty), the
# node binary, this script, and the content roots the journey minted. The
# final evidence_root binds this file to the strip recorded beside it, so a
# hand edit to either — or a recording kept after the script changed — is
# detectable: `make readme-svg-check` recomputes all of it and refuses stale.
cj_write_facts() {
    local out="$1" strip="$2"
    local cpu commit dirty
    cpu="$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    [ -n "$cpu" ] || cpu="unknown CPU"
    commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    if [ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]; then dirty=yes; else dirty=no; fi
    {
        printf '# Recorded by `make commons-demo`. Every value was measured by that\n'
        printf '# run on the machine named below; nothing here is typed in by hand.\n'
        printf 'recorded_utc          = %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'host_cpu              = %s (%s threads)\n' "$cpu" "$(nproc)"
        printf 'host_os               = %s %s\n' "$(uname -sr)" "$(uname -m)"
        printf 'compiler              = %s\n' "$(${CC:-cc} --version | head -1)"
        printf 'source_git_commit     = %s (dirty: %s)\n' "$commit" "$dirty"
        printf 'z23_binary_sha3       = %s\n' "$(cj_sha3 "$NODE_BIN")"
        printf 'journey_script_sha3   = %s\n' "$(cj_sha3 "$SCRIPT_DIR/commons_journey_acceptance.sh")"
        printf 'conditions            = three fresh isolated regtest datadirs, one physical host, A process killed, C learned from B\n'
        printf 'reused_package_root   = %s\n' "$CJ_TEXTSTAT_ROOT"
        printf 'accepted_source_root  = %s\n' "$CJ_ACCEPTED_SOURCE"
        printf 'accepted_app_root     = %s\n' "$CJ_APP_ROOT"
        printf 'ask_to_visible_result = %s s\n' "$CJ_SECS_RESULT"
        printf 'ask_to_running_program = %s s\n' "$CJ_SECS_RUNNING"
        printf 'remote_reproduction   = %s s\n' "$CJ_SECS_REPRO"
        printf 'reuse_ratio           = %s/%s C23 source bytes (%s.%02d%%), exact-root closure on 2 nodes\n' \
            "$CJ_REUSED_C23_BYTES" "$CJ_C23_CLOSURE_BYTES" \
            "$((CJ_REUSE_RATIO_BPS / 100))" "$((CJ_REUSE_RATIO_BPS % 100))"
        printf 'signed_receipts_used  = %s source-reproduction receipts (B -> A, C -> B)\n' \
            "$CJ_SIGNED_RECEIPTS_CONSUMED"
        printf 'bytes_over_the_wire   = %s (reused package) + %s (accepted application)\n' \
            "$CJ_TEXTSTAT_BYTES" "$CJ_APP_BYTES"
        printf 'reused_package_match  = byte-identical on both nodes (%s bytes)\n' "$CJ_LIB_BYTES"
        printf 'accepted_package_root = %s\n' "$CJ_APP_PKG_ROOT"
        printf 'application_match     = byte-identical program on both nodes (%s bytes)\n' "$CJ_APP_BINARY_BYTES"
        printf 'program_installed_by  = zcode use — recipe program app/main.c -> bin/wordcount, receipt-bound; this proof ran no compiler\n'
        printf 'tamper_refused        = 4 of 4, each by name\n'
        printf 'carrier_root          = %s\n' "$CJ_CARRIER_ROOT"
        printf 'carrier_entries       = %s objects, node-B cache exported as one content.v2 package\n' "$CJ_CARRIER_ENTRIES"
        printf 'carrier_rebuild       = node C reproduced with zero compilers, byte-identical receipt\n'
        printf 'central_services      = 0\n'
        # A 64-hex root plus a parenthetical does not fit the width this file
        # is rendered at, so the naming lives on its own line and the two
        # roots line up under each other where a reader can compare them.
        printf 'changed_package       = zdogfight/zdogfight → pilot/zdogfight-quickturn\n'
        printf 'changed_root_before   = %s\n' "$CJ_ZDOG_ROOT"
        printf 'changed_root_after    = %s\n' "$CJ_ZDOG_APP_ROOT"
        printf 'turn_rate_before      = %s deg/s (node A, the package as published)\n' "$CJ_TURN_BEFORE"
        printf 'turn_rate_after       = %s deg/s (node B, from the bytes it fetched)\n' "$CJ_TURN_AFTER"
        if [ "${CJ_PUBLISHER_SURVIVAL:-0}" = 1 ]; then
            if [ "$CJ_MULTIHOST" = 1 ]; then
                printf 'publisher_survival    = host A killed; host C reproduced and ran the exact accepted bytes from host B\n'
            else
                printf 'publisher_survival    = node A killed; node C reproduced and ran the exact accepted bytes from node B\n'
            fi
        fi
        if [ "${CJ_TURN_SURVIVED:-0}" = 1 ]; then
            printf 'changed_survival      = host C measured %s deg/s from host B, host A killed\n' \
                "$CJ_TURN_AFTER"
        fi
        printf 'whole_journey         = %s s\n' "$CJ_SECS_TOTAL"
        printf 'verdict               = %s — %s of %s steps · %s\n' \
            "$CJ_VERDICT_TOKEN" "$CJ_STEPS_PROVEN" "$CJ_STEPS_TOTAL" "$CJ_VERDICT_SCHEMA"
    } >"$out"
    # Binds this facts body to the strip recorded beside it. Verification
    # removes this one line and recomputes over strip + remaining facts.
    printf 'evidence_root         = %s\n' \
        "$(cat "$strip" "$out" | openssl dgst -sha3-256 | awk '{print $NF}')" >>"$out"
}

# Read-only modes for the README figure generator. They print and exit before
# anything is booted, claimed, mined or written.
case "${1:-}" in
    --strip-labels) printf '%s\n' "$CJ_STRIP_LABELS"; exit 0 ;;
    --topology)     cj_topology; exit 0 ;;
    "") ;;
    *) cj_die "unknown argument '$1' (accepted: --strip-labels, --topology)" ;;
esac

cj_step "bring-up: three fresh isolated datadirs"
cj_boot
cj_build_peer_helper
cj_identities

cj_step "the journey"
CJ_T0="$(date +%s)"
cj_journey_guide
cj_journey_publish_reusable
cj_journey_turn_faster_stage
# The hosting engine that serves package bytes to peers is built at node
# start from the store on disk. Publishing is an ordinary store write, so
# the node that will serve it comes up after the package exists — the same
# ordering every real publisher has: put the software on the machine, then
# run the node that shares it.
cj_overlay
# The reuse-availability proof runs while the published package is still
# un-admitted on A; peer distribution then admits it (the pointer gate makes
# the publisher's own reproduction evidence a precondition of announcing).
cj_journey_work_start_unavailable
cj_journey_peer_distribution
cj_journey_admit_reuse
cj_journey_create_missing
cj_journey_show
CJ_SECS_RESULT=$(( $(date +%s) - CJ_T0 ))
cj_journey_accept
cj_journey_publish_accepted
CJ_T_REPRO="$(date +%s)"
cj_journey_remote_reproduction
CJ_SECS_REPRO=$(( $(date +%s) - CJ_T_REPRO ))
cj_journey_tamper_refusals
cj_journey_use_app
CJ_SECS_RUNNING=$(( $(date +%s) - CJ_T0 ))
# The tenth step moves the work, not the source: the compile cache itself
# leaves node B as one ordinary package, and node C — which never compiled
# this application — rebuilds it with zero compilers and the same receipt.
cj_journey_object_set_carrier
# The eleventh step is the other half of the promise: not "the commons can build
# something new", but "the commons can change something that already works,
# and you keep that exact version". Same nodes, same overlay, same lifecycle.
cj_journey_turn_faster

# The publisher disappears; the software survives on whoever still holds
# it. Same-host kills A's process; multi-host already placed B and C on
# other machines.
CJ_PUBLISHER_SURVIVAL=0
CJ_TURN_SURVIVED=0
cj_journey_publisher_disappears

# The verdict is the whole journey or nothing. Every step above dies on its
# first broken promise, so reaching this line means the journey held on
# three fresh datadirs, A is gone, and C learned only from B.

# The verdict this run earned, built BEFORE the recording is written so the
# recording can bind it. A recording that names its commit, binary, script and
# roots but not its verdict asks the reader to take the PASS on faith from a
# terminal line that is not part of the evidence. One set of variables feeds
# both the facts line and the printed document, so the two cannot disagree.
CJ_VERDICT_SCHEMA=zcl.commons_journey_acceptance.v1
CJ_VERDICT_TOKEN=PASS
CJ_STEPS_PROVEN=12
CJ_STEPS_TOTAL=12
[ "$CJ_SIGNED_RECEIPTS_CONSUMED" -ge 2 ] ||
    cj_die "fewer than two cross-node signed source receipts were consumed"
CJ_VERDICT="{\"schema\":\"$CJ_VERDICT_SCHEMA\",\"verdict\":\"$CJ_VERDICT_TOKEN\",\"steps_proven\":$CJ_STEPS_PROVEN,\"steps_total\":$CJ_STEPS_TOTAL,\"complete\":true,\"reuse_before_creation\":true,\"no_false_reuse_claim\":true,\"peer_to_peer_fetch\":true,\"fetched_source_inert\":true,\"explicit_local_admission\":true,\"independent_remote_build\":true,\"approved_signer_required\":true,\"explicit_human_acceptance\":true,\"accepted_work_published\":true,\"remote_source_reproduced\":true,\"signed_source_reproduction_receipts_consumed\":$CJ_SIGNED_RECEIPTS_CONSUMED,\"ask_to_running_program_seconds\":$CJ_SECS_RUNNING,\"reuse_ratio\":{\"basis\":\"exact_c23_source_closure_bytes\",\"reused_bytes\":$CJ_REUSED_C23_BYTES,\"closure_bytes\":$CJ_C23_CLOSURE_BYTES,\"basis_points\":$CJ_REUSE_RATIO_BPS,\"nodes\":2},\"byte_identical_artifacts\":true,\"tamper_refused_by_name\":[\"source\",\"dependency\",\"receipt\",\"artifact\"],\"application_ran\":true,\"compile_cache_carried_as_package\":true,\"zero_compiler_rebuild\":true,\"carrier_receipt_identical\":true,\"existing_package_changed\":true,\"behavior_change_measured_before_and_after\":true,\"changed_version_is_its_own_root\":true,\"central_services_contacted\":0,\"human_first_terminal_output\":true}"
# The multi-host leg adds its fact only when it actually ran: the publisher
# disappeared and node C still reproduced and ran the exact accepted bytes.
if [ "$CJ_PUBLISHER_SURVIVAL" = 1 ]; then
    CJ_VERDICT="${CJ_VERDICT%\}},\"publisher_disappearance_survived\":true,\"changed_behavior_survived_publisher\":true}"
fi

# The strip: the mission's eight stages, printed by the run that just earned
# them, plus the recording the README figures are rendered from.
# ZCL_COMMONS_DEMO_RECORD=1 updates the committed recording; without it this
# run writes only into its own work directory and changes nothing in the tree.
CJ_SECS_TOTAL=$(( $(date +%s) - CJ_T0 ))
cj_step "what just happened"
# Write the strip to the evidence file first. `cj_strip | tee` under
# pipefail surfaces printf's SIGPIPE 141 after 11/11 already passed, so
# the earned PASS never prints a verdict. A closed stdout cannot un-earn it.
cj_strip > "$DHT_WORK/commons-demo.strip" ||
    cj_die "could not write the journey strip"
cat "$DHT_WORK/commons-demo.strip" || true
cj_write_facts "$DHT_WORK/commons-demo.facts" "$DHT_WORK/commons-demo.strip"
if [ "${ZCL_COMMONS_DEMO_RECORD:-0}" = 1 ]; then
    cp "$DHT_WORK/commons-demo.strip" \
       "$REPO_ROOT/docs/assets/z23-commons-demo.strip"
    cp "$DHT_WORK/commons-demo.facts" \
       "$REPO_ROOT/docs/assets/z23-commons-demo.facts"
    cj_note "recorded docs/assets/z23-commons-demo.{strip,facts}; redraw with: make readme-svg"
fi

cj_step "verdict"
printf '%s\n' "$CJ_VERDICT" || true
