#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zcc_bootstrap.sh — make the in-tree compile cache available before the first
# object is compiled, and print its path.
#
# The Makefile invokes this at parse time when automatic caching is enabled and
# also through a real file prerequisite when native epoch publication is
# requested explicitly. The warm path only checks the complete bootstrap input
# set. Nothing is fetched.
#
# It NEVER fails a build: if the compile does not work here, the script prints
# nothing, $(CC) is left bare, and the build is merely slower.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SRC="$REPO_ROOT/tools/zcc.c"
SHA3="$REPO_ROOT/lib/sha3/src/sha3.c"
ALLOC="$REPO_ROOT/lib/base/src/safe_alloc.c"
BIN="${ZCL_BIN_DIR:-$REPO_ROOT/build/bin}/zcc"
INPUT_CATALOG="$SCRIPT_DIR/zcc-bootstrap-inputs.list"
BOOTSTRAP_INPUTS=()
while IFS= read -r input || [ -n "$input" ]; do
    case "$input" in
        license=*) ;;
        *) [[ "$input" =~ ^[A-Za-z0-9_./-]+$ ]] || exit 0
           BOOTSTRAP_INPUTS+=("$REPO_ROOT/$input") ;;
    esac
done < "$INPUT_CATALOG"

# The build epoch fingerprints every token of $(CC) and fails CLOSED on a path
# it cannot parse as a plain argv (tools/dev/build-epoch-key.sh, safe_command).
# A clone under a path with a space would therefore turn this optimization into
# a hard build failure. Decline instead: an uncached build is slower, never
# broken.
if [[ ! "$BIN" =~ ^[A-Za-z0-9_./:+,=%-]+$ ]]; then
    exit 0
fi
fresh=1
for input in "${BOOTSTRAP_INPUTS[@]}"; do
    [ -f "$input" ] || exit 0
    if [ ! -x "$BIN" ] || [ ! "$BIN" -nt "$input" ]; then
        fresh=0
    fi
done
if [ "$fresh" = 1 ]; then
    printf '%s\n' "$BIN"
    exit 0
fi

# Build with a bare compiler: the cache cannot be used to build itself.
BOOTSTRAP_CC="${ZCL_BOOTSTRAP_CC:-cc}"
BOOTSTRAP_FLAGS=(-std=c23 -O2 -D_POSIX_C_SOURCE=200809L)
if [ "$(uname -s 2>/dev/null)" = Darwin ]; then
    BOOTSTRAP_FLAGS+=(-D_DARWIN_C_SOURCE -Dst_mtim=st_mtimespec)
fi
mkdir -p "$(dirname "$BIN")" 2>/dev/null || exit 0
tmp="$BIN.build.$$"
if "$BOOTSTRAP_CC" "${BOOTSTRAP_FLAGS[@]}" \
        -I"$REPO_ROOT/lib/sha3/include" -I"$REPO_ROOT/lib/base/include" \
        -o "$tmp" "$SRC" "$SHA3" "$ALLOC" >/dev/null 2>&1; then
    mv -f "$tmp" "$BIN" 2>/dev/null && printf '%s\n' "$BIN"
else
    rm -f "$tmp" 2>/dev/null
fi
exit 0
