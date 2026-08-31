#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Exact native/coreutils parity and malformed-input tests for source identity.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF_DIR/../.." && pwd)"
SOURCE_IDENTITY="$SELF_DIR/source-identity.sh"
HELPER="$($SELF_DIR/source-identity-batch-bootstrap.sh || true)"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/source-identity-batch.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT HUP INT TERM

fail()
{
    printf 'source-identity-batch-selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

if [ ! -x "$HELPER" ]; then
    cd "$ROOT"
    ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 \
        "$SOURCE_IDENTITY" capture >/dev/null ||
        fail 'portable fallback capture failed'
    printf '%s\n' \
        'source-identity-batch-selftest: PASS native_unavailable=true portable_fallback=true'
    exit 0
fi
[[ "$("$HELPER" identity)" =~ ^zcl\.source_identity_batch\.v1\ [0-9a-f]{64}$ ]] ||
    fail 'native helper did not report its exact input identity'

cd "$SANDBOX"
printf 'plain\n' > plain.c
printf 'space\n' > 'space name.c'
printf 'newline\n' > $'line\nbreak.c'
printf 'utf8\n' > 'lambda-λ.c'
printf '#!/bin/sh\nexit 0\n' > executable.sh
chmod 0755 executable.sh
ln -s plain.c source-link
paths=(plain.c 'space name.c' $'line\nbreak.c' 'lambda-λ.c' executable.sh)
for i in {1..140}; do
    printf 'fixture %s\n' "$i" > "fixture-$i.c"
    paths+=("fixture-$i.c")
done
mode_paths=("${paths[@]}" source-link)
printf '%s\0' "${paths[@]}" > hash-input
printf '%s\0' "${mode_paths[@]}" > mode-input

sha256sum_help="$(sha256sum --help 2>/dev/null || true)"
if command -v sha256sum >/dev/null 2>&1 &&
   [[ "$sha256sum_help" == *--zero* ]] &&
   stat -c '%f' plain.c >/dev/null 2>&1; then
    "$HELPER" hash < hash-input > native-hashes || fail 'native hash failed'
    sha256sum --zero -- "${paths[@]}" > legacy-hashes ||
        fail 'legacy hash failed'
    cmp -s native-hashes legacy-hashes || fail 'hash output differs'
    "$HELPER" mode < mode-input > native-modes || fail 'native mode failed'
    stat -c '%f' -- "${mode_paths[@]}" > legacy-modes ||
        fail 'legacy mode failed'
    cmp -s native-modes legacy-modes || fail 'mode output differs'
fi

printf 'plain.c' > malformed
if "$HELPER" hash < malformed > /dev/null 2>&1; then
    fail 'unterminated NUL record was accepted'
fi
printf '\0' > malformed
if "$HELPER" mode < malformed > /dev/null 2>&1; then
    fail 'empty path record was accepted'
fi
printf 'missing.c\0' > malformed
if "$HELPER" hash < malformed > /dev/null 2>&1; then
    fail 'missing file was accepted'
fi

git init -q
git config user.email source-identity-batch@example.invalid
git config user.name source-identity-batch
git add -- .
git commit -qm fixture
sandbox_native="$(ZCL_SOURCE_IDENTITY_BATCH_SHADOW=1 \
    "$SOURCE_IDENTITY" capture)" || fail 'sandbox native capture failed'
sandbox_legacy="$(ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 \
    "$SOURCE_IDENTITY" capture)" || fail 'sandbox portable capture failed'
[ "$sandbox_native" = "$sandbox_legacy" ] ||
    fail 'adversarial-path native and portable records differ'

cd "$ROOT"
native="$(ZCL_SOURCE_IDENTITY_BATCH_SHADOW=1 \
    "$SOURCE_IDENTITY" capture)" || fail 'whole-tree native capture failed'
legacy="$(ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 \
    "$SOURCE_IDENTITY" capture)" || fail 'whole-tree legacy capture failed'
[ "$native" = "$legacy" ] ||
    fail "whole-tree v2 records differ native=$native legacy=$legacy"

printf 'source-identity-batch-selftest: PASS record=%s malformed_nul=refused\n' \
    "$native"
