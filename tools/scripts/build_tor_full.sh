#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Build the pinned embedded-Tor submodule explicitly. The default node build
# remains offline-friendly and links the stub until an operator asks for this.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOR_DIR="$ROOT/vendor/tor"

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

if [ ! -x "$TOR_DIR/configure" ]; then
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
echo "tor-full: ready commit=$commit archives=4 embedded_profile=self_contained"
