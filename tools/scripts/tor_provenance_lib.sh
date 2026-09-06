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

# Build (or rebuild) the tool if missing or stale. A build failure is loud
# and fails closed (returns 1): every caller of z23-tor-provenance treats
# "cannot verify" the same as "archives absent", never as "archives present".
zcl_tor_provenance_ensure_bin() {
    local root="$1" bin src1 src2 cc
    bin="$(zcl_tor_provenance_bin "$root")"
    src1="$root/tools/tor_provenance.c"
    src2="$root/contexts/commons/packages/zsha256/src/zsha256.c"
    if [ ! -s "$src1" ] || [ ! -s "$src2" ]; then
        echo "tor-provenance: missing source $src1 or $src2" >&2
        return 1
    fi
    if [ -x "$bin" ] && [ "$bin" -nt "$src1" ] && [ "$bin" -nt "$src2" ]; then
        return 0
    fi
    cc="${CC:-cc}"
    mkdir -p "$(dirname "$bin")" || return 1
    if ! "$cc" -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
            -D_POSIX_C_SOURCE=200809L \
            -I"$root/contexts/commons/packages/zsha256/include" \
            -o "$bin" "$src1" "$src2"; then
        echo "tor-provenance: could not build $bin with $cc" >&2
        return 1
    fi
    return 0
}
