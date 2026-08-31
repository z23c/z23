#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Build the optional native source-identity batch helper without making source
# capture depend on compiler availability. The caller retains its exact legacy
# implementation when this script prints no path.

set -uo pipefail

SCRIPT_DIR="$(cd "${0%/*}" && pwd)" || exit 0
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)" || exit 0
SRC="$SCRIPT_DIR/source_identity_batch.c"
SHA256="$REPO_ROOT/packages/zsha256/src/zsha256.c"
SHA256_HEADER="$REPO_ROOT/packages/zsha256/include/zsha256/zsha256.h"
ALLOC="$REPO_ROOT/lib/base/src/safe_alloc.c"
ALLOC_HEADER="$REPO_ROOT/lib/base/include/base/safe_alloc.h"
HEX_HEADER="$REPO_ROOT/lib/base/include/base/hex.h"
BIN="${ZCL_BIN_DIR:-$REPO_ROOT/build/bin}/source-identity-batch"
INPUTS=("$0" "$SRC" "$SHA256" "$SHA256_HEADER" "$ALLOC" "$ALLOC_HEADER"
        "$HEX_HEADER")

sha256_stream()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        return 1
    fi
}

sha256_file()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum < "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 < "$1" | awk '{print $1}'
    else
        return 1
    fi
}

INPUT_ID="$({
    for input in "${INPUTS[@]}"; do
        digest="$(sha256_file "$input")" || exit 1
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 1
        printf 'file\0%s\0%s\0' "${input#"$REPO_ROOT"/}" "$digest" ||
            exit 1
    done
} | sha256_stream)" || exit 0
[[ "$INPUT_ID" =~ ^[0-9a-f]{64}$ ]] || exit 0
EXPECTED_IDENTITY="zcl.source_identity_batch.v1 $INPUT_ID"

fresh=1
for input in "${INPUTS[@]}"; do
    [ -f "$input" ] || exit 0
    if [ ! -x "$BIN" ] || [ ! "$BIN" -nt "$input" ]; then
        fresh=0
    fi
done
if [ "$fresh" = 1 ] &&
   [ "$("$BIN" identity 2>/dev/null)" = "$EXPECTED_IDENTITY" ]; then
    printf '%s\n' "$BIN"
    exit 0
fi

BOOTSTRAP_CC="${ZCL_BOOTSTRAP_CC:-cc}"
FLAGS=(-std=c23 -O2 -Wall -Wextra -Werror -pedantic
       -D_POSIX_C_SOURCE=200809L)
if [ "$(uname -s 2>/dev/null)" = Darwin ]; then
    FLAGS+=(-D_DARWIN_C_SOURCE -Dst_mtim=st_mtimespec
            -Dst_ctim=st_ctimespec)
fi
mkdir -p "${BIN%/*}" 2>/dev/null || exit 0
tmp="$BIN.build.$$"
trap 'rm -f "$tmp" 2>/dev/null' EXIT HUP INT TERM
if ! "$BOOTSTRAP_CC" "${FLAGS[@]}" \
        -DZCL_SOURCE_IDENTITY_BATCH_INPUT_ID=\"$INPUT_ID\" \
        -I"$REPO_ROOT/packages/zsha256/include" \
        -I"$REPO_ROOT/lib/base/include" \
        -o "$tmp" "$SRC" "$SHA256" "$ALLOC" >/dev/null 2>&1; then
    exit 0
fi
chmod 0755 "$tmp" 2>/dev/null || exit 0
if [ "$("$tmp" identity 2>/dev/null)" != "$EXPECTED_IDENTITY" ]; then
    exit 0
fi
mv -f "$tmp" "$BIN" 2>/dev/null || exit 0
for input in "${INPUTS[@]}"; do
    [ "$BIN" -nt "$input" ] || exit 0
done
[ "$("$BIN" identity 2>/dev/null)" = "$EXPECTED_IDENTITY" ] || exit 0
printf '%s\n' "$BIN"
