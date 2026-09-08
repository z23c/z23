# Copyright 2026 Rhett Creighton - Apache License 2.0
# shellcheck shell=bash
# tor_provenance_lib — get to a working z23-tor-provenance binary before Make
# has built anything.
#
# tor_archives_ready.sh's have_all() runs on the FIRST parse of a plain
# `make`, via $(TOR_BOOTSTRAP_MK) (Makefile:1878) -- before the Makefile has
# built a single binary. z23-tor-provenance cannot be assumed to exist yet at
# that point, so this compiles it directly with the same flags as its
# Makefile rule ($(TOR_PROVENANCE_BIN)) whenever the binary is missing or
# older than either of its two sources. Sourced, never executed.

zcl_tor_provenance_bin() {
    printf '%s/build/bin/z23-tor-provenance\n' "$1"
}

# The compiler probe must observe the same deployment target as the build.
# Apple Clang changes its effective target when this variable is set.
zcl_tor_prepare_environment() {
    [ "$(uname -s 2>/dev/null || echo unknown)" = Darwin ] || return 0
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
    if [ "$MACOSX_DEPLOYMENT_TARGET" != 14.0 ]; then
        echo "$1: Darwin requires MACOSX_DEPLOYMENT_TARGET=14.0" >&2
        return 2
    fi
    export MACOSX_DEPLOYMENT_TARGET
}

# The compiler that actually built (or would build) libtor.a under
# <build-dir> -- shared between build_tor_full.sh, which records this in the
# provenance manifest it writes, and tor_archives_ready.sh's have_all(),
# which re-derives it to check that record. Two independent derivations of
# "the ambient compiler" drifted apart once: the host build lets Tor's own
# `configure` run AC_PROG_CC and resolve to `gcc`, while a guess of
# `${CC:-cc}` resolves to the literal string `cc` -- the SAME binary on most
# systems, but compiler identity here is bound to the exact command string
# (see tools/dev/build-epoch-key.sh's compiler-id preimage), so a freshly
# rebuilt, byte-accurate manifest still failed its own readiness check. One
# derivation, called from both sides, so they can never again disagree about
# what "the compiler" was.
zcl_tor_effective_cc() {
    local build_dir="$1" triple="${2:-}" cc
    if [ -n "$triple" ]; then
        printf '%s\n' "${VENDOR_CC:-$triple-gcc}"
        return 0
    fi
    if [ -n "${VENDOR_CC:-}" ]; then
        printf '%s\n' "$VENDOR_CC"
        return 0
    fi
    cc="$(awk -F'=' '/^CC[ \t]*=/{ sub(/^[ \t]*/, "", $2); print $2; exit }' \
        "$build_dir/Makefile" 2>/dev/null || true)"
    [ -n "$cc" ] || cc="${CC:-cc}"
    printf '%s\n' "$cc"
}

# The ONE derivation of "what compiler identity does the Tor provenance
# manifest bind" -- called by build_tor_full.sh (the writer) and every
# reader (tor_archives_ready.sh's have_all()/tor_alias_check(),
# tools/lint/check_tor_provenance.sh). Two independent re-derivations of a
# compiler identity have drifted before (see zcl_tor_effective_cc's comment
# above); this closes the other half of that gap by giving both writer and
# readers the same function, not just the same effective-CC string.
#
# Bytes-only, via build-epoch-key.sh's `compiler-bytes-id` mode: the
# resolved compiler binary's sha256, its `--version` first line, and its
# target triple. Deliberately NOT `compiler-id` (used for cached-object
# epochs elsewhere) -- that mode binds CPATH/LD_LIBRARY_PATH/COMPILER_PATH/
# CCACHE_*/SCCACHE_* and more, so the identical compiler yields a different
# id launched from a systemd unit than from an interactive shell. Tor
# provenance must survive that launch-shape difference; the cached-object
# epoch legitimately must not (those variables DO change resolved object
# bytes via header/library search).
zcl_tor_compiler_identity_for_cc() {
    local root="$1" cc="$2"
    (cd "$root" && "$root/tools/dev/build-epoch-key.sh" compiler-bytes-id "$cc")
}

# Build (or rebuild) the tool if missing or stale. A build failure is loud
# and fails closed (returns 1): every caller of z23-tor-provenance treats
# "cannot verify" the same as "archives absent", never as "archives present".
#
# This goes through the Makefile's own $(TOR_PROVENANCE_BIN) rule instead of
# a hand-rolled compile line: that rule carries -Iplatform/modules/base/include
# and $(ZCL_PLATFORM_CPPFLAGS), which tor_provenance.c needs for base/hex.h.
# A private compile line here drifted from the rule the moment the source
# grew that include, and the drift only shows up as "fatal error: base/hex.h:
# No such file or directory" -- silent everywhere except a bootstrap build.
# One rule, no drift.
zcl_tor_provenance_ensure_bin() {
    local root="$1" bin src1 src2 rel
    bin="$(zcl_tor_provenance_bin "$root")"
    src1="$root/tools/tor_provenance.c"
    src2="$root/contexts/commons/packages/zsha256/src/zsha256.c"
    if [ ! -s "$src1" ] || [ ! -s "$src2" ]; then
        echo "tor-provenance: missing source $src1 or $src2" >&2
        return 1
    fi
    # The lean helper goal has no vendor or Tor bootstrap. Let its canonical
    # rule check the complete source/header closure, rather than letting a
    # two-source timestamp shortcut reuse a stale platform implementation.
    rel="${bin#"$root"/}"
    if ! make -s -C "$root" "$rel"; then
        echo "tor-provenance: could not build $bin via make -C $root $rel" >&2
        return 1
    fi
    return 0
}
