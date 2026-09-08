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
zcl_tor_prepare_environment tor-ready || exit $?

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

# The exact compiler build_tor_full.sh would record for this tree -- shared
# via zcl_tor_effective_cc (tor_provenance_lib.sh) instead of a private guess,
# because a private guess (plain "${CC:-cc}") drifted from what the host
# build's own `configure` actually resolves CC to (typically "gcc"): same
# binary, different command string, and compiler identity is bound to the
# string (tools/dev/build-epoch-key.sh). That drift made a freshly rebuilt,
# byte-accurate manifest fail its own readiness check.
tor_ambient_compiler() {
    zcl_tor_effective_cc "$ROOT/$TOR_TREE" "$TRIPLE"
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
    # Match build_tor_full.sh's probe directory too: Apple Clang's verbose
    # preprocessing output includes its compilation directory.
    cid="$(cd "$SCRIPT_ROOT" && "$SCRIPT_ROOT/tools/dev/build-epoch-key.sh" compiler-id "$cc" "$cc" 2>/dev/null)" || return 1
    "$(zcl_tor_provenance_bin "$SCRIPT_ROOT")" check "$ROOT/$TOR_TREE" --compiler-id "$cid" >/dev/null 2>&1 || \
        tor_alias_check "$cc"
}

# The manifest records the compiler by the command string vendor/tor's own
# configure resolved CC to when the archives were built (typically "gcc",
# read back from vendor/tor/Makefile by tor_ambient_compiler() above). A
# worktree that got its archives by copy (link_from) never ran configure
# there, so it has no Makefile to read and tor_ambient_compiler() falls back
# to the literal command "cc" -- a different command string for what is
# usually the very same compiler binary. Compiler identity is bound to the
# string (tools/dev/build-epoch-key.sh), so the plain check above rejects a
# tree that is, byte for byte, exactly what the manifest describes. Retry
# with any other command name that resolves to the SAME binary as the
# ambient guess -- never a different one, that would still be a real
# mismatch -- before have_all() gives up.
tor_same_compiler_file() {
    # Darwin's compiler aliases can be hardlinks: realpath keeps their
    # different names. Require one device/inode, never merely equal bytes.
    [ "$1" -ef "$2" ]
}

tor_alias_check() {
    local primary_cc="$1" primary_path cand cand_path tried cid
    primary_path="$(command -v "${primary_cc%% *}" 2>/dev/null)" || return 1
    primary_path="$(realpath -- "$primary_path" 2>/dev/null)" || return 1
    tried=" $primary_cc "
    for cand in gcc cc clang "${CC:-}" "${VENDOR_CC:-}"; do
        [ -n "$cand" ] || continue
        case "$tried" in *" $cand "*) continue ;; esac
        tried="$tried$cand "
        cand_path="$(command -v "$cand" 2>/dev/null)" || continue
        cand_path="$(realpath -- "$cand_path" 2>/dev/null)" || continue
        tor_same_compiler_file "$cand_path" "$primary_path" || continue
        cid="$(cd "$SCRIPT_ROOT" && "$SCRIPT_ROOT/tools/dev/build-epoch-key.sh" compiler-id "$cand" "$cand" 2>/dev/null)" || continue
        "$(zcl_tor_provenance_bin "$SCRIPT_ROOT")" check "$ROOT/$TOR_TREE" --compiler-id "$cid" >/dev/null 2>&1 && return 0
    done
    return 1
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
        # GNU cp can share blocks; BSD cp lacks --reflink. Both paths copy
        # into an independent inode instead of linking the donor's archive.
        if cp -a --reflink=auto -- "$src/$a" "$ROOT/$a" 2>/dev/null ||
           cp -p "$src/$a" "$ROOT/$a"; then
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

# True when every archive is present (non-empty), independent of whether it
# verifies -- used to tell "no archives at all" (a stub tree, or one that
# never built Tor) apart from "archives present but wrong" (corruption, or a
# stale build).
archives_all_present() {
    local a
    for a in "${ARCHIVES[@]}"; do
        [ -s "$ROOT/$a" ] || return 1
    done
    return 0
}

manifest_present() {
    [ -s "$ROOT/$TOR_TREE/.provenance" ]
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
    # have_all() failing means EITHER "no manifest yet" (safe: the archives
    # are real, nothing has recorded what produced them, so establishing one
    # -- by rebuilding, or by copying a sibling's matching archives+manifest
    # -- is an honest repair) OR "a manifest exists and disagrees with the
    # archives on disk" (corruption or tampering: the archive bytes changed
    # out from under a record that used to be true). Only the first case
    # falls through to link_from/build_tor_full.sh below. The second must
    # fail here, loudly, and must NOT reach either: link_from would silently
    # skip re-copying an archive that is merely non-empty (corrupted counts),
    # and build_tor_full.sh's `make libtor.a` no-ops when the corrupted
    # archive's mtime already looks newer than its inputs -- either path
    # would let this function report success while quietly re-hashing (or
    # re-labeling) bytes nothing actually rebuilt. That is exactly the
    # "write a manifest from ambient values inside a check" failure mode
    # this tool exists to prevent.
    if manifest_present && archives_all_present; then
        echo "tor-ready: FAIL $TOR_TREE has a provenance manifest that does not match its archives -- refusing to silently re-establish it; run 'make check-tor-provenance' for the exact mismatch, or 'make tor-full' to rebuild intentionally" >&2
        return 1
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
        fixture="$(mktemp -d "${TMPDIR:-/tmp}/zcl-tor-copy.XXXXXX")"
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
        # would have written. tor_ambient_compiler() itself is not used here:
        # it now reads $ROOT/$TOR_TREE/Makefile (via zcl_tor_effective_cc) to
        # match what the real Tor build's own configure picked, and the real
        # $SCRIPT_ROOT's vendor/tor has one while this fixture's fake trees
        # do not -- calling zcl_tor_effective_cc directly against the
        # fixture path (same as have_all() will do inside the ROOT=$fake_wt
        # subshell below, where there is also no Makefile) keeps this
        # selftest's expectation and have_all()'s recomputation looking at
        # the same absence and landing on the same fallback.
        zcl_tor_provenance_ensure_bin "$SCRIPT_ROOT" || {
            echo "tor_archives_ready: selftest FAILED — could not build z23-tor-provenance" >&2
            exit 1
        }
        selftest_cc="$(zcl_tor_effective_cc "$fake_primary/$TOR_TREE" "$TRIPLE")"
        selftest_cid="$(cd "$SCRIPT_ROOT" && "$SCRIPT_ROOT/tools/dev/build-epoch-key.sh" compiler-id "$selftest_cc" "$selftest_cc" 2>/dev/null)" || {
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
            if ! cmp -s "$src" "$dst"; then
                echo "tor_archives_ready: selftest FAILED — $a differs from the source archive" >&2
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
        # have_all() must fail closed on a tree whose archives are present
        # but whose .provenance manifest is simply absent -- the exact state
        # a checkout ends up in when its archives were built before the
        # manifest writer existed (see the header comment on this script and
        # on tor_provenance.c). Reuse fake_wt: it already holds the four
        # archives link_from just populated, and it also now holds the
        # carried manifest, so delete only the manifest.
        rm -f "$fake_wt/$TOR_TREE/.provenance"
        if (ROOT="$fake_wt"; cd "$fake_wt" && have_all) >/dev/null 2>&1; then
            echo "tor_archives_ready: selftest FAILED — have_all() passed with archives present and no manifest" >&2
            exit 1
        fi
        # link_from must REFUSE a donor that has real archives but no
        # provenance manifest at all -- never propagate a manifest-less
        # donor's bytes into a worktree that then LOOKS established. Build a
        # second, empty worktree and a donor that is a copy of fake_primary
        # minus its .provenance file.
        fake_primary_nomanifest="$fixture/primary_nomanifest"
        fake_wt2="$fixture/worktree2"
        mkdir -p "$fake_primary_nomanifest" "$fake_wt2"
        for a in "${ARCHIVES[@]}"; do
            mkdir -p "$fake_primary_nomanifest/${a%/*}"
            cp -a -- "$fake_primary/$a" "$fake_primary_nomanifest/$a"
        done
        if (ROOT="$fake_wt2"; cd "$fake_wt2" && link_from "$fake_primary_nomanifest") >/dev/null 2>&1; then
            echo "tor_archives_ready: selftest FAILED — link_from accepted a manifest-less donor" >&2
            exit 1
        fi
        if [ -s "$fake_wt2/$TOR_TREE/.provenance" ]; then
            echo "tor_archives_ready: selftest FAILED — link_from wrote a manifest of its own for a manifest-less donor" >&2
            exit 1
        fi
        # Exercise the same-file predicate even on hosts whose installed
        # compilers are not aliases. Equal bytes in a different inode are
        # deliberately insufficient; only actual aliases may be retried.
        compiler_fixture="$fixture/compiler-aliases"
        mkdir -p "$compiler_fixture"
        printf 'fixture compiler bytes\n' > "$compiler_fixture/primary"
        chmod 0755 "$compiler_fixture/primary"
        ln "$compiler_fixture/primary" "$compiler_fixture/hardlink"
        ln -s primary "$compiler_fixture/symlink"
        cp "$compiler_fixture/primary" "$compiler_fixture/distinct"
        if ! tor_same_compiler_file "$compiler_fixture/primary" "$compiler_fixture/hardlink" ||
           ! tor_same_compiler_file "$compiler_fixture/primary" "$compiler_fixture/symlink"; then
            echo "tor_archives_ready: selftest FAILED — a hardlink or symlink compiler alias was rejected" >&2
            exit 1
        fi
        if tor_same_compiler_file "$compiler_fixture/primary" "$compiler_fixture/distinct" ||
           tor_same_compiler_file "$compiler_fixture/primary" "$compiler_fixture/missing"; then
            echo "tor_archives_ready: selftest FAILED — a distinct or missing compiler was accepted as an alias" >&2
            exit 1
        fi
        # have_all() must accept a manifest recorded under one alias for the
        # compiler (e.g. "gcc", what vendor/tor's real configure picked) when
        # the ambient guess in THIS tree resolves to a different alias for
        # the very same binary (e.g. "cc", what tor_ambient_compiler() falls
        # back to with no vendor/tor/Makefile and CC unset -- exactly the
        # state a freshly linked worktree is in; see tor_alias_check() and
        # the header comment on tor_ambient_compiler()). Skip cleanly if this
        # host's gcc and cc are not the same binary, since the fix does not
        # apply there.
        gcc_path="$(command -v gcc 2>/dev/null || true)"
        cc_path="$(command -v cc 2>/dev/null || true)"
        if [ -n "$gcc_path" ] && [ -n "$cc_path" ] && \
           tor_same_compiler_file "$gcc_path" "$cc_path"; then
            fake_wt3="$fixture/worktree3"
            mkdir -p "$fake_wt3"
            for a in "${ARCHIVES[@]}"; do
                mkdir -p "$fake_wt3/${a%/*}"
                printf 'fixture tor archive bytes\n' >"$fake_wt3/$a"
            done
            alias_cid="$(cd "$SCRIPT_ROOT" && "$SCRIPT_ROOT/tools/dev/build-epoch-key.sh" compiler-id gcc gcc 2>/dev/null)" || {
                echo "tor_archives_ready: selftest FAILED — could not derive the gcc alias compiler id" >&2
                exit 1
            }
            "$(zcl_tor_provenance_bin "$SCRIPT_ROOT")" write "$fake_wt3/$TOR_TREE" \
                "$(printf '%040x' 1)" "$alias_cid" \
                "$(printf 'selftest-configure-args' | sha256sum | awk '{print $1}')" >/dev/null || {
                echo "tor_archives_ready: selftest FAILED — could not write the alias fixture manifest" >&2
                exit 1
            }
            if ! (ROOT="$fake_wt3"; cd "$fake_wt3" && unset CC VENDOR_CC; have_all) >/dev/null 2>&1; then
                echo "tor_archives_ready: selftest FAILED — have_all() rejected a manifest recorded under a same-binary compiler alias" >&2
                exit 1
            fi
        else
            echo "tor_archives_ready: selftest SKIP — gcc and cc are not the same binary on this host, cannot exercise the alias path"
        fi
        cleanup_fixture
        trap - EXIT
        echo "tor_archives_ready: selftest PASS"
        ;;
    *) usage ;;
esac
