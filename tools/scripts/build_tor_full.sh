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

configure_opts=(
    --disable-asciidoc
    --disable-systemd
    --disable-seccomp
    --disable-lzma
    --disable-zstd
    --disable-libscrypt
)

if [ "$HOST_OS" = Darwin ]; then
    # Tor's TOR_SEARCH_LIBRARY expands --with-<lib>-dir=D into -ID/include and
    # -LD/lib, which is exactly the shape of this repository's vendor tree. Fail
    # closed on the pieces that must already be there rather than letting
    # configure fall back to a system library macOS does not have.
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
        echo "tor-full: macOS has no system OpenSSL/libevent/zlib to fall back to," >&2
        echo "tor-full: and the vendored replacements are still absent:$vendor_missing" >&2
        echo "tor-full: run tools/scripts/build_vendor.sh and rerun." >&2
        exit 5
    fi
    configure_opts+=(
        "--with-openssl-dir=$ROOT/vendor"
        "--with-libevent-dir=$ROOT/vendor"
        "--with-zlib-dir=$ROOT/vendor"
    )
fi

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

# nproc is GNU coreutils and is NOT present on macOS; under `set -e` the
# unguarded $(nproc) aborted this script before it reached a single compile.
# getconf _NPROCESSORS_ONLN is the portable spelling this repository already
# uses elsewhere and answers correctly on both hosts.
detect_jobs() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
        return
    fi
    getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4
}
jobs="${ZCL_TOR_JOBS:-$(detect_jobs)}"
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
