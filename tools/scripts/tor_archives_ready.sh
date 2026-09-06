#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Establish the four vendored Tor archives the node link consumes, so that a
# plain `make` produces a node that can actually reach the onion network.
#
# WHY THIS EXISTS. The link selects real Tor when the four archives exist and
# silently falls back to vendor/lib/libtor_stub.a when they do not (Makefile
# TOR_FULL / TOR_LIBS). That fallback is invisible: the build compiles, links,
# and passes the whole suite, and the only symptom is a node whose `-tor` is
# inert -- blind to the onion network this project is built on. A default that
# can only be noticed by inspecting telemetry is not a default, it is a trap.
# So the archives become an ordinary build input, established the same way the
# rest of vendor/ is: present -> use them, absent -> make them.
#
# Three ways to get them, cheapest first:
#   1. Already here.                                     (no work)
#   2. Copy them from a sibling checkout that has them   (milliseconds)
#      -- every `git worktree add` lane shares its object
#      store with a primary checkout that has usually
#      already paid for the build; a reflink shares the
#      blocks, an independent inode either way.
#   3. Build them from the pinned submodule.             (minutes)
#
# THE STUB IS STILL REACHABLE, but only by asking for it by name:
# `make ZCL_TOR=stub ...`. That prints one loud line and produces a binary
# stamped tor=stub, which refuses -tor, the onion flags, and fleet-node mode
# at runtime and is refused by every step that packages a binary.
#
# Exit status is the contract: 0 means "the archives this build will link are
# now established, or the stub was explicitly requested"; non-zero means the
# caller must not proceed to link a node.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The checkout this SCRIPT lives in -- immutable, unlike $ROOT below, which
# the --selftest fixture below deliberately reassigns (in a subshell) to
# point have_all()/link_from() at a fake data directory instead of this real
# one. z23-tor-provenance's own source and binary always live under the real
# checkout, never under a fixture.
SCRIPT_ROOT="$ROOT"
cd "$ROOT"

# shellcheck source=tools/scripts/tor_provenance_lib.sh
. "$SCRIPT_ROOT/tools/scripts/tor_provenance_lib.sh"

# The Makefile's ZCL_TOR_TREE: one host tree, or one tree per cross triple.
TRIPLE="${ZCL_CROSS_TRIPLE:-}"
if [ -n "$TRIPLE" ]; then
    TOR_TREE="vendor/cross/$TRIPLE/tor"
else
    TOR_TREE="vendor/tor"
fi

ARCHIVES=(
    "$TOR_TREE/libtor.a"
    "$TOR_TREE/src/ext/ed25519/donna/libed25519_donna.a"
    "$TOR_TREE/src/ext/ed25519/ref10/libed25519_ref10.a"
    "$TOR_TREE/src/ext/keccak-tiny/libkeccak-tiny.a"
)

# The ambient compiler build_tor_full.sh's default (uninstrumented) host path
# would resolve, mirroring VENDOR_CC/cross-triple precedence there: an
# explicit pin wins, else the ambient $CC, else plain "cc" -- the same
# fallback chain autoconf's own AC_PROG_CC applies.
tor_ambient_compiler() {
    if [ -n "$TRIPLE" ]; then
        printf '%s\n' "${VENDOR_CC:-$TRIPLE-gcc}"
    else
        printf '%s\n' "${VENDOR_CC:-${CC:-cc}}"
    fi
}

have_all() {
    local a
    for a in "${ARCHIVES[@]}"; do
        [ -s "$ROOT/$a" ] || return 1
    done
    # Existence is not enough: bind the archives to the vendor/tor commit,
    # compiler, and configure flags that produced them (see
    # tools/tor_provenance.c). A mismatch here -- a stale libtor.a left over
    # from a different compiler, most concretely -- is treated exactly like
    # a missing archive: fall through to a real rebuild.
    zcl_tor_provenance_ensure_bin "$SCRIPT_ROOT" || return 1
    local cc cid
    cc="$(tor_ambient_compiler)"
    command -v "${cc%% *}" >/dev/null 2>&1 || return 1
    cid="$("$SCRIPT_ROOT/tools/dev/build-epoch-key.sh" compiler-id "$cc" "$cc" 2>/dev/null)" || return 1
    "$(zcl_tor_provenance_bin "$SCRIPT_ROOT")" check "$ROOT/$TOR_TREE" --compiler-id "$cid" >/dev/null 2>&1
}

# The one loud line. Nothing else in a build says "this binary cannot see the
# onion network", so this has to be unmissable and greppable.
STUB_BANNER='tor-ready: ZCL_TOR=stub — LINKING THE OFFLINE TOR STUB. This binary is stamped tor=stub: it cannot reach the onion network, it refuses -tor and fleet-node mode at runtime, and no ship or install step will accept it. Drop ZCL_TOR=stub (or run `make tor-full`) for a real-Tor node.'

# Derive the primary checkout this worktree shares a git object store with.
# Same derivation worktree-prime already uses.
primary_checkout() {
    local gcd
    gcd="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
    case "$gcd" in
        */.git) printf '%s\n' "${gcd%/.git}" ;;
        *) printf '' ;;
    esac
}

# Copy (never hardlink) the archives from a checkout that already has them.
# A shared inode looks free, but it is not, for this tree specifically:
#   1. check-no-hardlink-seeding fails any multiply-linked dependency in a
#      checkout, so every lane that runs make would turn the primary
#      checkout red the moment it links one of these archives.
#   2. The landing leaf refuses a landing worktree whose vendor inputs carry
#      links it cannot explain
#      (proof_generation_dependency_unexplained_links).
#   3. The build's source identity hashes the ctime of tracked sources and
#      transients; a link() or unlink() on a shared inode moves the
#      primary's ctime too, and that has refused ship gates with
#      "source build superseded".
# So each worktree gets its own inode: a reflink where the filesystem can
# share blocks for free, a byte copy otherwise -- that copy is the accepted
# price. Falls back to a copy across filesystems (EXDEV) same as before.
link_from() {
    local src="$1" a linked=0
    [ -n "$src" ] || return 1
    [ "$(cd "$src" 2>/dev/null && pwd -P)" != "$(pwd -P)" ] || return 1
    for a in "${ARCHIVES[@]}"; do
        [ -s "$src/$a" ] || return 1
    done
    # The archives live under a submodule path. Copying bytes into an
    # UNINITIALIZED gitlink is worse than not having them: source-identity
    # capture refuses with "nonempty uninitialized gitlink would omit bytes",
    # and it is right to refuse. Initialize first (objects are already in the
    # shared git dir, so this is offline).
    case "$(git submodule status "$TOR_TREE" 2>/dev/null)" in
        -*) git submodule update --init "$TOR_TREE" >/dev/null 2>&1 || return 1 ;;
    esac
    for a in "${ARCHIVES[@]}"; do
        [ -s "$ROOT/$a" ] && continue
        mkdir -p "$ROOT/${a%/*}"
        if cp -a --reflink=auto -- "$src/$a" "$ROOT/$a" 2>/dev/null; then
            linked=$((linked + 1))
        else
            return 1
        fi
    done
    # Carry the SOURCE's provenance manifest alongside the copied bytes --
    # never write a fresh one here. The bytes did not change, so the record
    # of what produced them (vendor/tor commit, compiler, configure flags)
    # is still true; only the copy destination changed. If the source has no
    # manifest at all (an older checkout that predates this), have_all's
    # provenance check below fails closed and do_ready falls through to a
    # real build, same as any other mismatch.
    if [ -s "$src/$TOR_TREE/.provenance" ]; then
        cp -a --reflink=auto -- "$src/$TOR_TREE/.provenance" "$ROOT/$TOR_TREE/.provenance" 2>/dev/null || true
    fi
    have_all || return 1
    echo "tor-ready: copied $linked vendored Tor archive(s) from $src (independent inodes; real-Tor link, no rebuild)"
    return 0
}

usage() {
    echo "usage: $0 [ready|link-only|check|--selftest]" >&2
    exit 2
}

do_check() {
    if have_all; then
        echo "tor-ready: PASS real Tor archives present tree=$TOR_TREE"
        return 0
    fi
    echo "tor-ready: FAIL no real Tor archives under $TOR_TREE" >&2
    return 1
}

do_ready() {
    if [ "${ZCL_TOR:-full}" = stub ]; then
        echo "$STUB_BANNER" >&2
        echo "$STUB_BANNER"
        return 0
    fi
    if [ "${ZCL_TOR:-full}" != full ]; then
        echo "tor-ready: ZCL_TOR must be 'full' (default) or 'stub', not '${ZCL_TOR}'" >&2
        return 2
    fi
    if have_all; then
        echo "tor-ready: real Tor archives already present ($TOR_TREE)"
        return 0
    fi
    if [ "${1:-}" != no-link ] && link_from "$(primary_checkout)"; then
        return 0
    fi
    if [ "${1:-}" = link-only ]; then
        return 1
    fi
    echo "tor-ready: building the pinned embedded Tor from source (one time, cached under $TOR_TREE)"
    VENDOR_TARGET="$TRIPLE" "$ROOT/tools/scripts/build_tor_full.sh"
    have_all || {
        echo "tor-ready: build_tor_full.sh returned success but $TOR_TREE still has no archives" >&2
        return 1
    }
    return 0
}

case "${1:-ready}" in
    ready) do_ready ;;
    link-only) do_ready link-only ;;
    check) do_check ;;
    --selftest)
        # The banner must name the knob, the stamp, and the way out. A future
        # edit that drops any of the three makes the refusal unactionable.
        for needle in 'ZCL_TOR=stub' 'tor=stub' 'make tor-full' 'refuses -tor'; do
            case "$STUB_BANNER" in
                *"$needle"*) ;;
                *) echo "tor_archives_ready: selftest FAILED — banner lost '$needle'" >&2; exit 1 ;;
            esac
        done
        # ZCL_TOR only accepts the two spellings.
        if ZCL_TOR=yes "$0" ready >/dev/null 2>&1; then
            echo "tor_archives_ready: selftest FAILED — ZCL_TOR=yes was accepted" >&2
            exit 1
        fi
        # link_from must give each worktree its own inode, never a link
        # shared with the primary checkout (see the comment above the
        # function). Build a fixture: a fake primary that has all four
        # archives, and a fake empty worktree, then assert the copy landed
        # with link count 1 and an inode that differs from the source's.
        fixture="$HOME/.local/state/zclassic23/scratch/torlink/selftest.$$"
        cleanup_fixture() { rm -rf -- "$fixture"; }
        trap cleanup_fixture EXIT
        fake_primary="$fixture/primary"
        fake_wt="$fixture/worktree"
        mkdir -p "$fake_primary" "$fake_wt"
        for a in "${ARCHIVES[@]}"; do
            mkdir -p "$fake_primary/${a%/*}"
            printf 'fixture tor archive bytes\n' >"$fake_primary/$a"
        done
        # link_from's have_all() now also checks provenance after the copy,
        # so the fixture primary needs a manifest that matches its own
        # archive bytes and the compiler id have_all() will independently
        # recompute -- exactly what a real checkout's build_tor_full.sh run
        # would have written.
        zcl_tor_provenance_ensure_bin "$SCRIPT_ROOT" || {
            echo "tor_archives_ready: selftest FAILED — could not build z23-tor-provenance" >&2
            exit 1
        }
        selftest_cid="$("$SCRIPT_ROOT/tools/dev/build-epoch-key.sh" compiler-id "$(tor_ambient_compiler)" "$(tor_ambient_compiler)" 2>/dev/null)" || {
            echo "tor_archives_ready: selftest FAILED — could not derive a fixture compiler id" >&2
            exit 1
        }
        "$(zcl_tor_provenance_bin "$SCRIPT_ROOT")" write "$fake_primary/$TOR_TREE" \
            "$(printf '%040x' 1)" "$selftest_cid" \
            "$(printf 'selftest-configure-args' | sha256sum | awk '{print $1}')" >/dev/null || {
            echo "tor_archives_ready: selftest FAILED — could not write fixture provenance manifest" >&2
            exit 1
        }
        (
            ROOT="$fake_wt"
            cd "$fake_wt"
            link_from "$fake_primary" >/dev/null
        )
        for a in "${ARCHIVES[@]}"; do
            dst="$fake_wt/$a"
            src="$fake_primary/$a"
            if [ ! -s "$dst" ]; then
                echo "tor_archives_ready: selftest FAILED — link_from did not populate $a" >&2
                exit 1
            fi
            nlink="$(ls -l "$dst" | awk '{print $2}')"
            if [ "$nlink" != 1 ]; then
                echo "tor_archives_ready: selftest FAILED — $a has link count $nlink, want 1 (shared inode)" >&2
                exit 1
            fi
            if [ "$(ls -i "$dst" | awk '{print $1}')" = "$(ls -i "$src" | awk '{print $1}')" ]; then
                echo "tor_archives_ready: selftest FAILED — $a shares an inode with the primary checkout" >&2
                exit 1
            fi
        done
        # link_from must carry the SOURCE's provenance manifest alongside the
        # archives it copies, never write a fresh one (see the comment above
        # link_from's copy loop).
        if ! cmp -s "$fake_primary/$TOR_TREE/.provenance" "$fake_wt/$TOR_TREE/.provenance"; then
            echo "tor_archives_ready: selftest FAILED — link_from did not carry the source's .provenance manifest byte-for-byte" >&2
            exit 1
        fi
        cleanup_fixture
        trap - EXIT
        echo "tor_archives_ready: selftest PASS"
        ;;
    *) usage ;;
esac
