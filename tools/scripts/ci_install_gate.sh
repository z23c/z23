# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# ci_install_gate.sh — the hermetic MVP C1 ("single-binary install") gate.
#
# MVP criterion #1 (docs/quality/MVP.md) is "single-binary install on clean
# Ubuntu/Debian": a fresh operator runs `make install && systemctl --user
# start zclassic23` and the node comes up. That literal claim needs a real
# systemd user session + the live datadir/ports, which CI must NEVER touch.
# This gate is the CI-friendly PROXY for that claim that proves the
# load-bearing half hermetically:
#
#   1. BUILD the node, RPC client, confined package verifier and offline
#      non-wallet package signer from source.
#   2. INSTALL them to a THROWAWAY /tmp prefix with `install -m 755` —
#      exactly the file-copy a `make install` target performs, but to a
#      disposable DESTDIR so nothing lands in ~/.local or the system.
#   3. START ONE node FROM THAT PREFIX as a fully ISOLATED regtest node
#      (unique /tmp datadir + 39xxx non-live ports + -connect=39999 dead
#      sink), reusing the single audited isolation chokepoint
#      tools/scripts/isolated_node_env.sh.
#   4. POLL RPC readiness with a bounded timeout and ASSERT the installed
#      binary actually answers getblockcount.
#   5. ASSERT (defense-in-depth) the node bound ONLY non-live ports.
#   6. CLEAN UP the /tmp prefix + datadir, leaving nothing behind.
#
# It NEVER runs systemctl, NEVER binds a live port (8023/8033/8034 P2P,
# 18232/8232 RPC), and NEVER touches the live datadir — the same hard
# isolation guarantees soak-ci / test-crash-bootstrap rely on. A failure on
# any path exits non-zero with a clear message (no silent skips); success
# prints the sentinel line "=== ci-install: PASSED ===".
#
# This file is *executed* by `make ci-install` (it is NOT in `make ci`,
# because — like ci-stress / soak-ci — it spawns a real process).

set -euo pipefail

# ── Locate the repo root + the audited isolation chokepoint ─────────
# Resolve relative to THIS script so the gate works regardless of the
# caller's cwd (we `cd` into the install prefix before spawning).
GATE_SRC="${BASH_SOURCE[0]}"
GATE_DIR="$(cd "$(dirname "$GATE_SRC")" && pwd)"
REPO_ROOT="$(cd "$GATE_DIR/../.." && pwd)"
HARNESS="$GATE_DIR/isolated_node_env.sh"

gate_die() { echo "ci-install: FATAL: $*" >&2; exit 1; }

[ -r "$HARNESS" ] || gate_die "isolation chokepoint not found: $HARNESS"

# ── Tunables (all overridable for local runs) ───────────────────────
# 39050-band keeps clear of soak-ci (39040) and test-crash (39030) so the
# three can coexist on one host without a port-quad collision.
ISO_PORT_BASE="${ISO_PORT_BASE:-39050}"
RPC_TIMEOUT="${CI_INSTALL_RPC_TIMEOUT:-60}"

# ── Build the artifacts the install step will ship ──────────────────
# `make ci-install` lists these as prerequisites, so they are normally
# already built; build here too so the script is correct when run by hand.
echo "ci-install: building installed node + package author/reproducer tools"
make -C "$REPO_ROOT" -j"$(nproc)" zclassic23 zcl-rpc \
    z23-package-verify z23-package-sign >/dev/null \
    || gate_die "installed product build failed"

SRC_NODE="$REPO_ROOT/build/bin/zclassic23"
SRC_RPC="$REPO_ROOT/build/bin/zcl-rpc"
SRC_VERIFY="$REPO_ROOT/build/bin/z23-package-verify"
SRC_SIGN="$REPO_ROOT/build/bin/z23-package-sign"
[ -x "$SRC_NODE" ] || gate_die "built node missing/!executable: $SRC_NODE"
[ -x "$SRC_RPC" ]  || gate_die "built zcl-rpc missing/!executable: $SRC_RPC"
[ -x "$SRC_VERIFY" ] || gate_die "built package verifier missing/!executable"
[ -x "$SRC_SIGN" ] || gate_die "built package signer missing/!executable"

# ── Install to a THROWAWAY /tmp prefix (the C1 install step) ─────────
# mktemp randomizes the path; the structural /tmp guard below refuses
# anything that somehow resolves outside /tmp before we ever rm -rf it.
PREFIX="$(mktemp -d /tmp/zcl-ci-install.XXXXXX)" \
    || gate_die "mktemp -d for install prefix failed"
case "$PREFIX" in
    /tmp/zcl-ci-install.*) : ;;
    *) gate_die "install prefix resolved outside /tmp: $PREFIX" ;;
esac

# Remove the throwaway prefix on the way out. Only ever rm a path that
# still matches the mktemp shape — never a caller-supplied or empty one.
gate_rm_prefix() {
    case "${PREFIX:-}" in
        /tmp/zcl-ci-install.*)
            [ -d "$PREFIX" ] && rm -rf "$PREFIX" 2>/dev/null || true ;;
    esac
}

# Before the harness is sourced, the ONLY thing to clean is the prefix
# (no datadir exists yet). Once we source the harness and call iso_init,
# the harness installs its OWN `trap iso_cleanup EXIT INT TERM` that
# removes the /tmp DATADIR — and crucially it can abort *inside*
# iso_init (e.g. a live-LISTEN port refusal) with only iso_cleanup armed,
# which would leak our prefix. To make prefix removal survive that, we
# OVERRIDE iso_cleanup after sourcing (below) so the harness's own trap
# also drops the prefix, no matter when it fires.
trap gate_rm_prefix EXIT INT TERM

echo "ci-install: installing via 'make install' to throwaway prefix $PREFIX"
# Exercise the REAL `make install` target (the literal MVP #1 step), staged
# into the throwaway prefix via DESTDIR. PREFIX= empty so binaries land at
# $PREFIX/bin (matching the spawn cwd below); DESTDIR set => the live systemd
# --user unit install is skipped, so this stays fully hermetic.
make -C "$REPO_ROOT" install DESTDIR="$PREFIX" PREFIX= >/dev/null \
    || gate_die "make install -> prefix failed"
[ -x "$PREFIX/bin/zclassic23" ] || gate_die "installed node not executable"
[ -x "$PREFIX/bin/zcl-rpc" ]    || gate_die "installed zcl-rpc not executable"
# Each helper installs under its z23- name and keeps its legacy zclassic23-
# name working (a link), so both must be executable and be the same program.
for helper in package-verify package-sign; do
    [ -x "$PREFIX/bin/z23-$helper" ] \
        || gate_die "installed z23-$helper not executable"
    [ -x "$PREFIX/bin/zclassic23-$helper" ] \
        || gate_die "installed legacy zclassic23-$helper not executable"
    cmp -s "$PREFIX/bin/z23-$helper" "$PREFIX/bin/zclassic23-$helper" \
        || gate_die "zclassic23-$helper is not the same program as z23-$helper"
done

# The package-author identity is separate from every wallet/deployment key.
# Generate it inside the throwaway prefix and prove the installed signer can
# rederive its exact compressed public key through an already-open fd.
AUTHOR_KEY="$PREFIX/package-author.key"
AUTHOR_PUB="$($PREFIX/bin/z23-package-sign --generate "$AUTHOR_KEY")" \
    || gate_die "installed package signer could not generate an author key"
[ "$(stat -c %a "$AUTHOR_KEY")" = "600" ] \
    || gate_die "package author key mode is not 600"
exec 8<"$AUTHOR_KEY"
AUTHOR_PUB_AGAIN="$($PREFIX/bin/z23-package-sign --public --key-fd 8)" \
    || gate_die "installed package signer could not rederive its public key"
exec 8<&-
[ "$AUTHOR_PUB" = "$AUTHOR_PUB_AGAIN" ] \
    || gate_die "package signer public identity changed"
case "$AUTHOR_PUB" in
    02????????????????????????????????????????????????????????????????|\
    03????????????????????????????????????????????????????????????????) : ;;
    *) gate_die "package signer returned a non-canonical compressed key" ;;
esac

# ── Spawn ONE isolated node FROM the install prefix ─────────────────
# Sourcing the audited chokepoint with cwd == $PREFIX/bin makes its
# `./zclassic23` / `./zcl-rpc` resolve to the INSTALLED artifacts, so the
# gate genuinely exercises what `make install` shipped — not the in-tree
# build. iso_init mints the /tmp datadir + 39xxx ports, refuses any live
# port, and arms ITS datadir-cleanup trap (which gate_cleanup chains).
cd "$PREFIX/bin"
export ISO_KIND=install ISO_PORT_BASE
export ISO_NODE_BIN=./zclassic23 ISO_RPC_BIN=./zcl-rpc
# shellcheck source=tools/scripts/isolated_node_env.sh
. "$HARNESS"

# Compose prefix removal INTO the harness's cleanup function itself, so
# however/whenever the harness's `trap iso_cleanup` fires (including an
# abort inside iso_init), the datadir AND the prefix are both removed.
# `iso_cleanup` is the function the harness's trap calls by name, so
# redefining it here is the resilient seam — no fragile trap re-arming.
eval "$(declare -f iso_cleanup | sed '1s/iso_cleanup/__iso_cleanup_orig/')"
iso_cleanup() { __iso_cleanup_orig "$@" || true; gate_rm_prefix; }

iso_init

echo "ci-install: starting installed node ($(pwd)/zclassic23) on rpc=$ISO_RPCPORT"
iso_spawn_node "-nobgvalidation"

if ! iso_wait_rpc_ready "$RPC_TIMEOUT"; then
    echo "ci-install: node did NOT become RPC-ready within ${RPC_TIMEOUT}s" >&2
    echo "ci-install: node.log tail ---------------------------------" >&2
    tail -40 "$ISO_DD/node.log" 2>/dev/null >&2 || true
    gate_die "installed binary failed to come up (see node.log tail above)"
fi

HEIGHT="$(iso_rpc getblockcount | tr -dc '0-9-')"
[ -n "$HEIGHT" ] || gate_die "getblockcount returned no integer height"
echo "ci-install: installed node is RPC-ready at height=$HEIGHT"

# ── Defense-in-depth: prove we bound ONLY non-live ports ────────────
# iso_init already refuses a live port before spawn; this re-asserts the
# RUNNING node's listeners against the live refuse-set so the gate fails
# loud if anything ever regressed the isolation contract.
LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 18034 18232 18234 18243 18244 18245 18246"
NODE_PID="$ISO_NODE_PID"
listeners="$(ss -tlnpH 2>/dev/null | grep -F "pid=$NODE_PID," || true)"
echo "ci-install: node ($NODE_PID) listeners:"
printf '%s\n' "$listeners" | sed 's/^/    /'
for lp in $LIVE_PORTS; do
    if printf '%s\n' "$listeners" | grep -qE "[:.]${lp}[[:space:]]"; then
        gate_die "node is LISTENING on live port $lp — isolation breach, refusing"
    fi
done
# Positively assert the isolated RPC port IS bound (the node is real).
printf '%s\n' "$listeners" | grep -qE "[:.]${ISO_RPCPORT}[[:space:]]" \
    || gate_die "node is not listening on its isolated RPC port $ISO_RPCPORT"

# gate_cleanup (EXIT trap) tears down the process group + removes the
# /tmp datadir and the install prefix.
echo "=== ci-install: PASSED ==="
