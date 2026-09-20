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

# The enumeration submodes (check-tags, split-index, prefix) are shared by
# the native and legacy token paths, so the shadow oracle never compares
# them. These fixtures feed git's own -z byte formats directly and demand
# the shell loop's exact refusal messages and exit status 3.
mkdir enum && cd enum

# check-tags: ordinary tags pass; a skip-worktree or assume-unchanged bit
# (any lowercase tag) refuses exactly like the shell's fail().
printf 'H tracked.c\0M modified.c\0R removed.c\0C changed.c\0K killed.c\0? other.c\0' \
    > tags-clean
"$HELPER" check-tags < tags-clean || fail 'clean index tags were refused'
printf 'H tracked.c\0S hidden.c\0' > tags-skip
if "$HELPER" check-tags < tags-skip > /dev/null 2> tags-err; then
    fail 'skip-worktree tag was accepted'
else
    [ "$?" -eq 3 ] || fail 'skip-worktree refusal exit status was not 3'
fi
printf '%s\n' 'source-identity: hidden Git index bit on path: hidden.c (clear skip-worktree/assume-unchanged before publication)' \
    > tags-expected
cmp -s tags-expected tags-err || fail 'skip-worktree refusal message drifted'
printf 'h assumed.c\0' > tags-assume
if "$HELPER" check-tags < tags-assume > /dev/null 2> tags-err; then
    fail 'assume-unchanged tag was accepted'
else
    [ "$?" -eq 3 ] || fail 'assume-unchanged refusal exit status was not 3'
fi
printf '%s\n' 'source-identity: hidden Git index bit on path: assumed.c (clear skip-worktree/assume-unchanged before publication)' \
    > tags-expected
cmp -s tags-expected tags-err || fail 'assume-unchanged refusal message drifted'
if "$HELPER" check-tags vendor/tor < tags-skip > /dev/null 2> tags-err; then
    fail 'gitlink skip-worktree tag was accepted'
else
    [ "$?" -eq 3 ] || fail 'gitlink tag refusal exit status was not 3'
fi
printf '%s\n' 'source-identity: hidden Git index bit in gitlink path: vendor/tor/hidden.c' \
    > tags-expected
cmp -s tags-expected tags-err || fail 'gitlink tag refusal message drifted'

# split-index: stage-0 regular/exec/symlink records stream to stdout, gitlinks
# to the sidecar, prefixed when asked; unmerged stages and unknown modes
# refuse exactly like the shell's fail().
printf '100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tplain.c\0' \
    > index-stream
printf '100755 1111111111111111111111111111111111111111 0\tRun Script.sh\0' \
    >> index-stream
printf '120000 2222222222222222222222222222222222222222 0\tlink\0' \
    >> index-stream
printf '160000 3333333333333333333333333333333333333333 0\tvendor/x\0' \
    >> index-stream
"$HELPER" split-index gitlinks.out < index-stream > split-out ||
    fail 'native index split failed'
printf 'plain.c\0Run Script.sh\0link\0' > split-expected
cmp -s split-expected split-out || fail 'index split regular paths differ'
printf 'vendor/x\0' > gitlinks-expected
cmp -s gitlinks-expected gitlinks.out || fail 'index split gitlink paths differ'
"$HELPER" split-index gitlinks-prefixed.out sub < index-stream \
    > split-prefixed || fail 'prefixed index split failed'
printf 'sub/plain.c\0sub/Run Script.sh\0sub/link\0' > split-prefixed-expected
cmp -s split-prefixed-expected split-prefixed ||
    fail 'prefixed index split regular paths differ'
printf 'sub/vendor/x\0' > gitlinks-prefixed-expected
cmp -s gitlinks-prefixed-expected gitlinks-prefixed.out ||
    fail 'prefixed index split gitlink paths differ'
: > index-empty
"$HELPER" split-index gitlinks-empty.out < index-empty > split-empty ||
    fail 'empty index stream was refused'
[ ! -s split-empty ] && [ ! -s gitlinks-empty.out ] ||
    fail 'empty index stream produced output'
printf '100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 1\tconflict.c\0' \
    > index-unmerged
if "$HELPER" split-index gitlinks-x.out < index-unmerged \
        > /dev/null 2> split-err; then
    fail 'unmerged index stage was accepted'
else
    [ "$?" -eq 3 ] || fail 'unmerged-stage refusal exit status was not 3'
fi
printf '%s\n' 'source-identity: unmerged index stage 1 for path: conflict.c' \
    > split-expected-err
cmp -s split-expected-err split-err || fail 'unmerged-stage message drifted'
if "$HELPER" split-index gitlinks-x.out sub < index-unmerged \
        > /dev/null 2> split-err; then
    fail 'unmerged gitlink index stage was accepted'
else
    [ "$?" -eq 3 ] || fail 'gitlink unmerged-stage refusal exit status was not 3'
fi
printf '%s\n' 'source-identity: unmerged gitlink index stage 1 for path: sub/conflict.c' \
    > split-expected-err
cmp -s split-expected-err split-err ||
    fail 'gitlink unmerged-stage message drifted'
printf '100600 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tweird.c\0' \
    > index-weird
if "$HELPER" split-index gitlinks-x.out < index-weird \
        > /dev/null 2> split-err; then
    fail 'unsupported index mode was accepted'
else
    [ "$?" -eq 3 ] || fail 'unsupported-mode refusal exit status was not 3'
fi
printf '%s\n' 'source-identity: unsupported tracked index mode 100600 for path: weird.c' \
    > split-expected-err
cmp -s split-expected-err split-err || fail 'unsupported-mode message drifted'

# prefix: the gitlink path join, including the empty stream.
printf 'a.c\0b/b.c\0' | "$HELPER" prefix vendor/tor > prefix-out ||
    fail 'native prefix join failed'
printf 'vendor/tor/a.c\0vendor/tor/b/b.c\0' > prefix-expected
cmp -s prefix-expected prefix-out || fail 'prefix join output differs'
: | "$HELPER" prefix vendor/tor > prefix-empty ||
    fail 'empty prefix stream was refused'
[ ! -s prefix-empty ] || fail 'empty prefix stream produced output'

cd "$SANDBOX"

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

# Mutation records must match too, including nonzero timezone offsets.
# Fixed POSIX zones keep this independent of the host timezone database.
for zone in UTC0 PST8PDT IST-5:30; do
    mutation_native="$(TZ="$zone" ZCL_SOURCE_IDENTITY_BATCH_SHADOW=1 \
        "$SOURCE_IDENTITY" capture-record)" ||
        fail "native mutation parity failed in $zone"
    mutation_legacy="$(TZ="$zone" ZCL_SOURCE_IDENTITY_FORCE_PORTABLE=1 \
        "$SOURCE_IDENTITY" capture-record)" ||
        fail "portable mutation capture failed in $zone"
    [ "$mutation_native" = "$mutation_legacy" ] ||
        fail "mutation records differ in $zone"
done

cd "$ROOT"
native="$(ZCL_SOURCE_IDENTITY_BATCH_SHADOW=1 \
    "$SOURCE_IDENTITY" capture)" || fail 'whole-tree native capture failed'
legacy="$(ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 \
    "$SOURCE_IDENTITY" capture)" || fail 'whole-tree legacy capture failed'
[ "$native" = "$legacy" ] ||
    fail "whole-tree v2 records differ native=$native legacy=$legacy"

printf 'source-identity-batch-selftest: PASS record=%s malformed_nul=refused\n' \
    "$native"
