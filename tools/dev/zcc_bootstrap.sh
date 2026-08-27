#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zcc_bootstrap.sh — make the in-tree compile cache available before the first
# object is compiled, and print its path.
#
# WHY A SCRIPT AND NOT A MAKE RULE. $(CC) is chosen while the Makefile is
# still being parsed, long before any recipe runs, so a normal rule for
# build/bin/zcc would come too late to wrap the very build that needs it. This
# runs from $(shell ...) at parse time instead. It is deliberately the
# cheapest thing that can be correct: two stat comparisons on the warm path,
# and a single ~0.4 s compile the first time a clone is built. Nothing is
# fetched, so a developer who cloned five minutes ago gets the cache with no
# install step — the same promise the node makes about its own runtime.
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

# The build epoch fingerprints every token of $(CC) and fails CLOSED on a path
# it cannot parse as a plain argv (tools/dev/build-epoch-key.sh, safe_command).
# A clone under a path with a space would therefore turn this optimization into
# a hard build failure. Decline instead: an uncached build is slower, never
# broken.
if [[ ! "$BIN" =~ ^[A-Za-z0-9_./:+,=%-]+$ ]]; then
    exit 0
fi
[ -f "$SRC" ] && [ -f "$SHA3" ] && [ -f "$ALLOC" ] || exit 0

if [ -x "$BIN" ] && [ "$BIN" -nt "$SRC" ] && [ "$BIN" -nt "$SHA3" ] &&
   [ "$BIN" -nt "$ALLOC" ]; then
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
