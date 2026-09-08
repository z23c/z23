#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Build the pinned embedded-Tor submodule explicitly. The default node build
# remains offline-friendly and links the stub until an operator asks for this.
#
# HOST SEAM (macOS). Upstream Tor is macOS-capable on its own: configure.ac
# carries darwin* arms and the vendored fork adds no Linux-only syscall. What a
# Mac does not have is the SYSTEM OpenSSL, libevent, and zlib development trees
# that Tor's configure discovers on Linux — macOS ships no /usr/include/openssl
# and no libevent at all — so an unaided ./configure fails at "checking for
# openssl directory" long before any Tor source is compiled. This repository
# already vendors exactly those three as pinned static archives, so on Darwin we
# point Tor's configure at vendor/ instead of admitting a new external
# dependency (a Homebrew openssl/libevent would be one). Everything else here is
# host-independent.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOR_DIR="$ROOT/vendor/tor"

# shellcheck source=tools/scripts/tor_provenance_lib.sh
. "$ROOT/tools/scripts/tor_provenance_lib.sh"
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"

# VENDOR_TARGET=<triple> cross-builds Tor for another platform: the same
# selector tools/scripts/build_vendor.sh already uses for the rest of the
# vendor stack (see its VENDOR_TARGET comment). vendor/tor holds ONE checkout
# shared by every target -- a cross build must not overwrite a host build's
# objects in place, so it gets its own out-of-tree build directory under
# vendor/cross/<triple>/tor, exactly the path ZCL_TOR_TREE in the Makefile
# already reads. Tor's build is one non-recursive automake Makefile (every
# src/**/include.am is `include`d from the top-level Makefile.am), so a plain
# autoconf out-of-tree build -- $srcdir/configure run from an empty directory
# -- is sufficient: no new build logic, only a different working directory,
# --host, and where the vendored OpenSSL/libevent/zlib come from. Empty when
# VENDOR_TARGET is unset, so every existing native path is byte-for-byte
# unchanged.
VENDOR_TARGET="${VENDOR_TARGET:-}"
TOR_BUILD_DIR="$TOR_DIR"
# Where configure lives. The host build configures the submodule IN TREE, so
# vendor/tor gains a config.status; autoconf then REFUSES any out-of-tree
# configure against that same source directory ("source directory already
# configured; run make distclean there first"). A cross build must therefore
# not use vendor/tor as its srcdir at all -- as written, `make tor-full`
# followed by `make ZCL_TARGET=windows-x86_64 tor-full` died there, and
# Windows silently kept the stub. It gets a clean export of the pinned commit
# instead; see the cross block below.
TOR_SRC_DIR="$TOR_DIR"
VENDOR_ROOT_DIR="$ROOT/vendor"
if [ -n "$VENDOR_TARGET" ]; then
    TOR_BUILD_DIR="$ROOT/vendor/cross/$VENDOR_TARGET/tor"
    TOR_SRC_DIR="$ROOT/vendor/cross/$VENDOR_TARGET/tor-src"
    VENDOR_ROOT_DIR="$ROOT/vendor/cross/$VENDOR_TARGET"
fi
zcl_tor_prepare_environment tor-full || exit $?

cd "$ROOT"
if [ ! -e "$TOR_DIR/.git" ]; then
    git submodule update --init vendor/tor
fi

expected="$(git ls-files -s -- vendor/tor | awk 'NR == 1 { print $2 }')"
actual="$(git -C "$TOR_DIR" rev-parse HEAD 2>/dev/null || true)"
if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
    echo "tor-full: submodule checkout differs from the parent pin" >&2
    echo "tor-full: review local Tor work, then run git submodule update --init vendor/tor" >&2
    exit 3
fi

# A cross build gets its own CLEAN export of the pinned commit as srcdir.
#
# `git archive HEAD` writes exactly the tracked bytes at the pin -- no
# config.status, no host objects, nothing the host build left behind -- so
# autoconf's "source directory already configured" refusal cannot fire, and
# the cross build cannot pick up a host artifact by accident. It is also the
# only reason a Windows cross build works at all on a box that already ran
# `make tor-full` for the host, which is every box that develops here.
#
# Re-exported only when the export is absent or its recorded pin differs, so
# the ordinary rerun costs one file read.
if [ -n "$VENDOR_TARGET" ]; then
    pin="$(git -C "$TOR_DIR" rev-parse HEAD)"
    if [ ! -f "$TOR_SRC_DIR/.zcl-tor-pin" ] ||
       [ "$(cat "$TOR_SRC_DIR/.zcl-tor-pin" 2>/dev/null)" != "$pin" ]; then
        echo "tor-full: exporting the pinned Tor source for $VENDOR_TARGET (clean srcdir; the host build configured vendor/tor in place)"
        rm -rf "$TOR_SRC_DIR"
        mkdir -p "$TOR_SRC_DIR"
        git -C "$TOR_DIR" archive --format=tar HEAD | tar -x -C "$TOR_SRC_DIR"
        printf '%s\n' "$pin" > "$TOR_SRC_DIR/.zcl-tor-pin"
    fi
fi

# Tor does not track its generated ./configure (vendor/tor/.gitignore names
# /configure), so a fresh checkout must run autogen.sh. That needs the autotools
# on every host, macOS included; say so by name instead of letting autoreconf
# fail with a message that does not identify what is missing.
if [ ! -x "$TOR_SRC_DIR/configure" ]; then
    missing=""
    for tool in autoconf automake aclocal autoheader; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    # libtool installs its driver as `glibtoolize` on macOS and `libtoolize`
    # elsewhere; either spelling satisfies autoreconf.
    if ! command -v libtoolize >/dev/null 2>&1 &&
       ! command -v glibtoolize >/dev/null 2>&1; then
        missing="$missing libtoolize(glibtoolize)"
    fi
    if [ -n "$missing" ]; then
        echo "tor-full: ${TOR_SRC_DIR#"$ROOT"/} ships no generated ./configure, so autogen.sh must run," >&2
        echo "tor-full: but these autotools are absent:$missing" >&2
        echo "tor-full: install autoconf, automake and libtool for this host, then rerun." >&2
        exit 4
    fi
    (cd "$TOR_SRC_DIR" && ./autogen.sh)
fi

# Compile Tor against the SAME OpenSSL the node links, not the host's.
#
# The C23 node links vendor/lib/libssl.a + libcrypto.a (pinned 3.0.16),
# but Tor's configure searched the host for headers -- so libtor.a was
# compiled against whatever OpenSSL the box happened to have and then
# linked against the pinned one. On this Linux reference box that is
# 3.0.13 headers against a 3.0.16 archive: same 3.0 series, ABI-stable,
# which is why it has always worked and why nothing caught it.
#
# It stops working off this box. Homebrew ships OpenSSL 3.5.x, so a Mac
# would compile libtor.a against 3.5 headers and link it to the pinned
# 3.0.16 archive -- a cross-series mismatch that need not fail at link
# time, which makes it worse than a build error, not better. Pinning the
# directory makes the node and its embedded Tor agree by construction on
# every host, and matches the repo rule that third-party input is an
# exact pinned archive rather than whatever the host offers.
#
# libevent and zlib are NOT pinned the same way: vendor/include has no
# event2/ headers, so Tor still resolves libevent from the host while
# the node links vendor/lib/libevent.a. That is the same latent skew,
# still open, and it needs the headers vendored before it can be closed.
configure_opts=(
    --with-openssl-dir="$VENDOR_ROOT_DIR"
    --disable-asciidoc
    --disable-systemd
    --disable-seccomp
    --disable-lzma
    --disable-zstd
    --disable-libscrypt
)
if [ "$HOST_OS" = "Darwin" ]; then
    # Keep this in config.status's argument record. A checkout configured
    # before the floor existed is then reconfigured and its objects rebuild,
    # rather than an old host-default libtor.a being silently reused.
    configure_opts+=("CFLAGS=-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET")
fi

# configure.ac's own TOR_SEARCH_LIBRARY(libevent, ...) probe already links
# -liphlpapi/-lbcrypt/-lws2_32 and passes. Its LATER AC_SEARCH_LIBS(event_new,
# ...) / AC_SEARCH_LIBS(evdns_base_new, ...) probe of that same libevent only
# seeds LIBS with $TOR_LIB_WS32, so the vendored Windows libevent.a -- which
# calls if_nametoindex (iphlpapi) -- fails to link there and configure aborts
# with "libevent2 is installed but linking it failed". Pre-seeding LIBS here
# reaches that probe's own save_LIBS baseline, so this is a build input (the
# same shape as LIBEVENT_CONFIGURE_LIBS in build_vendor.sh, one probe short
# of the libs its own vendored dependency needs), never a patch to
# configure.ac.
is_windows_target=false
case "$HOST_OS" in MINGW*|MSYS*) is_windows_target=true ;; esac
case "$VENDOR_TARGET" in *mingw*|*windows*) is_windows_target=true ;; esac
if $is_windows_target; then
    configure_opts+=("LIBS=-liphlpapi -lbcrypt -lws2_32")
fi

# A cross build supplies its own host triple and toolchain -- the same
# VENDOR_CC/VENDOR_AR/VENDOR_RANLIB names and $VENDOR_TARGET-<tool> defaults
# tools/scripts/build_vendor.sh already uses, so one triple selects the same
# toolchain everywhere in this repository. tor_cross_env stays empty on every
# native build, so the `env` call below runs configure with the ambient
# environment, unchanged from before this array existed.
tor_cross_env=()
if [ -n "$VENDOR_TARGET" ]; then
    # Tor's own configure.ac refuses a cross build whose discovered tools are
    # not ALL triple-prefixed (its AC_PROG_AR kludge sets ac_tool_warned the
    # moment any one of them, e.g. a system-wide pkg-config, is not) -- a
    # correctly-targeted mingw-w64 CC/AR/RANLIB still trips it. This is Tor's
    # own documented escape hatch for exactly that false positive
    # (configure.ac's error text names the flag), not a new check invented
    # here.
    configure_opts+=(--host="$VENDOR_TARGET" --disable-tool-name-check)
    tor_cross_env=(
        "CC=${VENDOR_CC:-$VENDOR_TARGET-gcc}"
        "AR=${VENDOR_AR:-$VENDOR_TARGET-ar}"
        "RANLIB=${VENDOR_RANLIB:-$VENDOR_TARGET-ranlib}"
    )
elif [ -n "${VENDOR_CC:-}" ]; then
    # A host build normally lets Tor's configure discover the compiler, and
    # that stays the default. But when the CALLER pins one, Tor must use that
    # one. The portable Linux release does exactly this: it rebuilds every
    # vendor archive through tools/scripts/c23_portable_sysroot.sh's wrapper
    # (VENDOR_CC=cc with the wrapper first in PATH) so the whole artifact sits
    # on one ABI floor. Before this arm, Tor was the single input that ignored
    # the pin -- which is precisely why the release used to force the stub
    # instead of carrying a libtor.a compiled to a newer floor than the binary
    # it was linked into.
    #
    # Recorded as a configure ARGUMENT rather than only an environment
    # variable, because the `configured` comparison below reads
    # `config.status --config`: a later CC change must re-run configure and
    # rebuild the objects, not silently reuse a libtor.a built by the other
    # compiler.
    configure_opts+=("CC=$VENDOR_CC")
fi

# Tor's TOR_SEARCH_LIBRARY expands --with-<lib>-dir=D into -ID/include and
# -LD/lib, which is exactly the shape of this repository's vendor tree (host
# vendor/, cross vendor/cross/<triple>/). Fail closed on the pieces that must
# already be there rather than letting configure fall back to a system
# library.
#
# Neither macOS nor an MSYS2/mingw Windows host has a system
# OpenSSL/libevent/zlib that Tor should be linked against here, and a cross
# build has no host libraries to discover at all. On Windows MSYS2 may well
# HAVE those packages, which is worse than not having them: configure would
# silently pick a different OpenSSL from the one the node links, and the skew
# is invisible because both sides compile. Point Tor at the same vendor tree
# the node links for this exact target, on every host/target that needs it.
needs_vendored_deps=false
case "$HOST_OS" in Darwin|MINGW*|MSYS*) needs_vendored_deps=true ;; esac
case "$VENDOR_TARGET" in *mingw*|*windows*|*darwin*) needs_vendored_deps=true ;; esac
if $needs_vendored_deps; then
    vendor_missing=""
    for required in \
        "$VENDOR_ROOT_DIR/lib/libcrypto.a" "$VENDOR_ROOT_DIR/lib/libssl.a" \
        "$VENDOR_ROOT_DIR/lib/libevent.a" "$VENDOR_ROOT_DIR/lib/libz.a" \
        "$VENDOR_ROOT_DIR/include/openssl/ssl.h" "$VENDOR_ROOT_DIR/include/event2/event.h" \
        "$VENDOR_ROOT_DIR/include/zlib.h"
    do
        [ -s "$required" ] || vendor_missing="$vendor_missing ${required#"$ROOT"/}"
    done
    if [ -n "$vendor_missing" ]; then
        echo "tor-full: building the vendored Tor dependencies first (missing:$vendor_missing)"
        VENDOR_TARGET="$VENDOR_TARGET" "$ROOT/tools/scripts/build_vendor.sh" libcrypto.a libssl.a libevent.a libz.a
        vendor_missing=""
        for required in \
            "$VENDOR_ROOT_DIR/lib/libcrypto.a" "$VENDOR_ROOT_DIR/lib/libssl.a" \
            "$VENDOR_ROOT_DIR/lib/libevent.a" "$VENDOR_ROOT_DIR/lib/libz.a" \
            "$VENDOR_ROOT_DIR/include/openssl/ssl.h" "$VENDOR_ROOT_DIR/include/event2/event.h" \
            "$VENDOR_ROOT_DIR/include/zlib.h"
        do
            [ -s "$required" ] || vendor_missing="$vendor_missing ${required#"$ROOT"/}"
        done
    fi
    if [ -n "$vendor_missing" ]; then
        echo "tor-full: ${VENDOR_TARGET:-$HOST_OS} must link the vendored OpenSSL/libevent/zlib," >&2
        echo "tor-full: and they are still absent:$vendor_missing" >&2
        echo "tor-full: run tools/scripts/build_vendor.sh and rerun." >&2
        exit 5
    fi
    configure_opts+=(
        "--with-openssl-dir=$VENDOR_ROOT_DIR"
        "--with-libevent-dir=$VENDOR_ROOT_DIR"
        "--with-zlib-dir=$VENDOR_ROOT_DIR"
    )
fi

mkdir -p "$TOR_BUILD_DIR"

configure_args=""
if [ -x "$TOR_BUILD_DIR/config.status" ]; then
    configure_args="$($TOR_BUILD_DIR/config.status --config 2>/dev/null || true)"
fi
configured=true
for option in "${configure_opts[@]}"; do
    case " $configure_args " in
        *" $option "*) ;;
        *) configured=false ;;
    esac
done

if [ "$configured" != true ]; then
    (cd "$TOR_BUILD_DIR" && \
        ac_cv_lib_cap_cap_init=no ac_cv_func_cap_set_proc=no \
        env ${tor_cross_env[@]+"${tor_cross_env[@]}"} \
        "$TOR_SRC_DIR/configure" "${configure_opts[@]}")
fi

jobs="${ZCL_TOR_JOBS:-$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
case "$jobs" in
    ''|*[!0-9]*) echo "tor-full: ZCL_TOR_JOBS must be a positive integer" >&2; exit 2 ;;
    0) echo "tor-full: ZCL_TOR_JOBS must be greater than zero" >&2; exit 2 ;;
esac
make -C "$TOR_BUILD_DIR" -j"$jobs" libtor.a

for archive in \
    libtor.a \
    src/ext/ed25519/donna/libed25519_donna.a \
    src/ext/ed25519/ref10/libed25519_ref10.a \
    src/ext/keccak-tiny/libkeccak-tiny.a
do
    [ -s "$TOR_BUILD_DIR/$archive" ] || {
        echo "tor-full: missing expected archive $archive" >&2
        exit 1
    }
done

# Bind these bytes to what produced them: the vendor/tor commit (already
# validated above), the compiler that actually built libtor.a, and the
# configure flags. Every existing readiness check downstream (tor_archives_
# ready.sh, ship.sh) only asked "do the archives exist"; this closes that.
#
# The compiler is recorded here, from what configure/make ACTUALLY used,
# rather than assumed from VENDOR_CC/the ambient environment: the ordinary
# host build (VENDOR_TARGET empty, VENDOR_CC unset) lets Tor's own configure
# autodetect CC, and nothing before this recorded which compiler it picked
# (see build_tor_full.sh's own header comment on the cross/pinned-host
# branches above -- this default-host arm was the one gap). Derived by
# zcl_tor_effective_cc so tor_archives_ready.sh's have_all() re-derives the
# identical string when it checks this manifest afterward -- see that
# function's comment for why the two must never drift apart again.
effective_cc="$(zcl_tor_effective_cc "$TOR_BUILD_DIR" "$VENDOR_TARGET")"
zcl_tor_provenance_ensure_bin "$ROOT" || {
    echo "tor-full: could not build the Tor provenance verifier" >&2
    exit 1
}
compiler_id="$(zcl_tor_compiler_identity_for_cc "$ROOT" "$effective_cc")" || {
    echo "tor-full: could not derive a compiler identity for $effective_cc" >&2
    exit 1
}
configure_args_sha256="$(printf '%s\0' "${configure_opts[@]}" | sha256sum | awk '{print $1}')"
"$(zcl_tor_provenance_bin "$ROOT")" write "$TOR_BUILD_DIR" \
    "$actual" "$compiler_id" "$configure_args_sha256" || {
    echo "tor-full: could not write the Tor provenance manifest" >&2
    exit 1
}

commit="$(git -C "$TOR_DIR" rev-parse --short=12 HEAD)"
echo "tor-full: ready commit=$commit archives=4 embedded_profile=self_contained target=${VENDOR_TARGET:-host} host=$HOST_OS dir=${TOR_BUILD_DIR#"$ROOT"/}"
