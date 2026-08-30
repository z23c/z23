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
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
if [ "$HOST_OS" = "Darwin" ]; then
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
    [ "$MACOSX_DEPLOYMENT_TARGET" = "14.0" ] || {
        echo "tor-full: Darwin requires MACOSX_DEPLOYMENT_TARGET=14.0" >&2
        exit 2
    }
    export MACOSX_DEPLOYMENT_TARGET
fi

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

# Tor does not track its generated ./configure (vendor/tor/.gitignore names
# /configure), so a fresh checkout must run autogen.sh. That needs the autotools
# on every host, macOS included; say so by name instead of letting autoreconf
# fail with a message that does not identify what is missing.
if [ ! -x "$TOR_DIR/configure" ]; then
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
        echo "tor-full: vendor/tor ships no generated ./configure, so autogen.sh must run," >&2
        echo "tor-full: but these autotools are absent:$missing" >&2
        echo "tor-full: install autoconf, automake and libtool for this host, then rerun." >&2
        exit 4
    fi
    (cd "$TOR_DIR" && ./autogen.sh)
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
    --with-openssl-dir="$ROOT/vendor"
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

case "$HOST_OS" in
Darwin|MINGW*|MSYS*)
    # Tor's TOR_SEARCH_LIBRARY expands --with-<lib>-dir=D into -ID/include and
    # -LD/lib, which is exactly the shape of this repository's vendor tree. Fail
    # closed on the pieces that must already be there rather than letting
    # configure fall back to a system library.
    #
    # Neither macOS nor an MSYS2/mingw Windows host has a system
    # OpenSSL/libevent/zlib that Tor should be linked against here. On Windows
    # MSYS2 may well HAVE those packages, which is worse than not having them:
    # configure would silently pick a different OpenSSL from the one the node
    # links, and the skew is invisible because both sides compile. Point Tor at
    # the same vendor tree the node uses, on every host that needs it.
    vendor_missing=""
    for required in \
        vendor/lib/libcrypto.a vendor/lib/libssl.a \
        vendor/lib/libevent.a vendor/lib/libz.a \
        vendor/include/openssl/ssl.h vendor/include/event2/event.h \
        vendor/include/zlib.h
    do
        [ -s "$ROOT/$required" ] || vendor_missing="$vendor_missing $required"
    done
    if [ -n "$vendor_missing" ]; then
        echo "tor-full: building the vendored Tor dependencies first (missing:$vendor_missing)"
        "$ROOT/tools/scripts/build_vendor.sh" libcrypto.a libssl.a libevent.a libz.a
        vendor_missing=""
        for required in \
            vendor/lib/libcrypto.a vendor/lib/libssl.a \
            vendor/lib/libevent.a vendor/lib/libz.a \
            vendor/include/openssl/ssl.h vendor/include/event2/event.h \
            vendor/include/zlib.h
        do
            [ -s "$ROOT/$required" ] || vendor_missing="$vendor_missing $required"
        done
    fi
    if [ -n "$vendor_missing" ]; then
        echo "tor-full: $HOST_OS must link the vendored OpenSSL/libevent/zlib," >&2
        echo "tor-full: and they are still absent:$vendor_missing" >&2
        echo "tor-full: run tools/scripts/build_vendor.sh and rerun." >&2
        exit 5
    fi
    configure_opts+=(
        "--with-openssl-dir=$ROOT/vendor"
        "--with-libevent-dir=$ROOT/vendor"
        "--with-zlib-dir=$ROOT/vendor"
    )
    ;;
esac

configure_args=""
if [ -x "$TOR_DIR/config.status" ]; then
    configure_args="$($TOR_DIR/config.status --config 2>/dev/null || true)"
fi
configured=true
for option in "${configure_opts[@]}"; do
    case " $configure_args " in
        *" $option "*) ;;
        *) configured=false ;;
    esac
done

if [ "$configured" != true ]; then
    (cd "$TOR_DIR" && \
        ac_cv_lib_cap_cap_init=no ac_cv_func_cap_set_proc=no \
        ./configure "${configure_opts[@]}")
fi

jobs="${ZCL_TOR_JOBS:-$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
case "$jobs" in
    ''|*[!0-9]*) echo "tor-full: ZCL_TOR_JOBS must be a positive integer" >&2; exit 2 ;;
    0) echo "tor-full: ZCL_TOR_JOBS must be greater than zero" >&2; exit 2 ;;
esac
make -C "$TOR_DIR" -j"$jobs" libtor.a

for archive in \
    libtor.a \
    src/ext/ed25519/donna/libed25519_donna.a \
    src/ext/ed25519/ref10/libed25519_ref10.a \
    src/ext/keccak-tiny/libkeccak-tiny.a
do
    [ -s "$TOR_DIR/$archive" ] || {
        echo "tor-full: missing expected archive $archive" >&2
        exit 1
    }
done

commit="$(git -C "$TOR_DIR" rev-parse --short=12 HEAD)"
echo "tor-full: ready commit=$commit archives=4 embedded_profile=self_contained host=$HOST_OS"
